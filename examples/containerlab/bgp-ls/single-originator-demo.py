#!/usr/bin/env python3
"""Run independent cases against a freshly deployed single-originator lab.

Uses only the Python standard library and the Docker CLI. Deployment/reset is
explicit: this script leaves the resulting lab state available for observation.
The topology expectations below match single-originator/topo1.clab.yaml.
"""

import argparse
import copy
import json
import os
import subprocess
import sys
import time


RIB_COMMAND = "show bgp link-state link-state"
LAN_ADDRESS = "192.168.20.1/24"
LAN_PREFIX = "192.168.20.0/24"
ISIS_PEERS = {
    "r2": {"eth1": "r3", "eth2": "r4"},
    "r3": {"eth1": "r2", "eth2": "r4"},
    "r4": {"eth1": "r2", "eth2": "r3", "eth3": "r5"},
    "r5": {"eth1": "r4"},
}
BGP_PEERS = {"r5": "192.0.2.2", "c1": "192.0.2.1"}
# (router, interface number) pairs for the four IS-IS links.
ISIS_LINKS = (((2, 1), (3, 1)), ((2, 2), (4, 1)),
              ((3, 2), (4, 2)), ((4, 3), (5, 1)))


def docker_exec(lab, node, *command, deadline=None):
    """Run Docker directly, bounded by the current convergence deadline."""
    timeout = 10 if deadline is None else min(10, deadline - time.monotonic())
    argv = ["docker", "exec", "-e", "VTYSH_PAGER=cat", f"clab-{lab}-{node}", *command]
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          text=True, timeout=max(0, timeout), check=True).stdout


def vtysh(lab, node, *commands, deadline=None):
    arguments = ["vtysh"]
    for command in commands:
        arguments.extend(["-c", command])
    output = docker_exec(lab, node, *arguments, deadline=deadline)
    # FRR emits this harmless note when a command leaves configuration unchanged.
    checked = output.replace("% Configuration applied with notes:\nNo changes found to be committed!\n", "")
    if any(line.lstrip().startswith("%") for line in checked.splitlines()):
        raise RuntimeError(f"{node}: vtysh rejected a command:\n{output.strip()}")
    return output


def walk_objects(value):
    """Walk nested FRR JSON arrays/objects without depending on display ordering."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def node_id(router):
    return f"0000.0000.{router:04d}.00"


def nlri_key(nlri):
    """Project FRR 10.7.1 descriptors onto the identities used in this lab."""
    kind = nlri["nlriType"]
    key = (kind, nlri["protocolId"], nlri["identifier"],
           nlri["localNodeDescriptors"]["igpRouterId"])
    if kind == "link":
        key += (nlri["remoteNodeDescriptors"]["igpRouterId"],
                nlri["linkDescriptors"]["ipv4InterfaceAddress"],
                nlri["linkDescriptors"]["ipv4NeighborAddress"])
    elif kind == "ipv4Prefix":
        key += (nlri["prefixDescriptors"]["ipReachabilityInformation"],)
    return key


def expected_baseline():
    expected = {("node", 2, 0, node_id(router)) for router in (2, 3, 4, 5)}
    for first, second in ISIS_LINKS:
        for local, remote in ((first, second), (second, first)):
            local_ip = f"10.{local[0]}.0.{local[1]}"
            remote_ip = f"10.{remote[0]}.0.{remote[1]}"
            expected.add(("link", 2, 0, node_id(local[0]), node_id(remote[0]),
                          local_ip, remote_ip))
            expected.add(("ipv4Prefix", 2, 0, node_id(local[0]), local_ip + "/32"))
    return expected


def read_rib(lab, node, deadline):
    """Return NLRI identities and LS attributes, excluding BGP path metadata."""
    data = json.loads(vtysh(lab, node, RIB_COMMAND + " json", deadline=deadline))
    entries = [entry for entry in walk_objects(data["routes"]) if "nlri" in entry]
    if any(not (entry["valid"] and entry["bestpath"]) for entry in entries):
        return None
    records = {nlri_key(entry["nlri"]): {"nlri": entry["nlri"], "attrs": entry["linkStateAttrs"]}
               for entry in entries}
    if len(records) == len(entries) == data["totalRoutes"] == data["totalPaths"]:
        return records
    return None


def wait_until(description, condition, timeout):
    """Poll until a check returns a truthy result; command failures propagate."""
    print(f"Waiting for {description} (up to {timeout}s)...", file=sys.stderr)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = condition(deadline)
        if result and time.monotonic() <= deadline:
            return result
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(1.0, remaining))
    raise TimeoutError(f"Timed out waiting for {description}")


def sessions_ready(lab, deadline, isis_peers=ISIS_PEERS):
    for node, expected in isis_peers.items():
        data = json.loads(vtysh(lab, node, "show isis neighbor json", deadline=deadline))
        rows = [row for area in data["areas"] if area.get("area") == "CORE"
                for row in walk_objects(area.get("circuits", []))
                if {"interface", "adj", "state"}.issubset(row) and row["state"] == "Up"]
        if len(rows) != len(expected):
            return False
        for port, neighbor in expected.items():
            matches = [row for row in rows if row["interface"] == port]
            aliases = {neighbor, node_id(int(neighbor[1:]))[:-3]}
            if not (len(matches) == 1 and matches[0]["level"] == 2
                    and matches[0]["adj"].lower() in aliases):
                return False
    for node, peer in BGP_PEERS.items():
        data = json.loads(vtysh(lab, node, "show bgp summary json", deadline=deadline))
        peers = data.get("linkState", {}).get("peers", {})
        if set(peers) != {peer} or peers[peer]["state"] != "Established":
            return False
    return True


def verify_ls_rib(lab, expected, deadline, isis_peers=ISIS_PEERS):
    if not sessions_ready(lab, deadline, isis_peers):
        return False
    r5 = read_rib(lab, "r5", deadline)
    c1 = read_rib(lab, "c1", deadline)
    return bool(r5) and r5 == c1 == expected


def verify_baseline(lab, deadline):
    """Check sessions and identities, then capture matching R5/C1 attributes.

    Attributes come from the running lab, not a predefined configuration model.
    Return None while the checks are incomplete.
    """
    if not sessions_ready(lab, deadline):
        return None
    r5 = read_rib(lab, "r5", deadline)
    c1 = read_rib(lab, "c1", deadline)
    if r5 and r5 == c1 and set(r5) == expected_baseline():
        return r5
    return None


def test_advertise_prefix(args):
    """Verify the baseline, advertise the passive LAN, and check its propagation."""
    # Manual commands for topo1, starting from the verified 20-NLRI baseline:
    # docker exec clab-topo1-r2 ip link add lan0 type dummy
    # docker exec clab-topo1-r2 ip link set lan0 up
    # docker exec clab-topo1-r2 vtysh \
    #     -c 'configure terminal' \
    #     -c 'interface lan0' \
    #     -c 'ip address 192.168.20.1/24' \
    #     -c 'ip router isis CORE' \
    #     -c 'isis passive' \
    #     -c 'isis metric 10' \
    #     -c 'end'
    # After convergence, inspect both RIBs; expect the baseline plus R2's prefix:
    # docker exec -e VTYSH_PAGER=cat clab-topo1-r5 vtysh -c 'show bgp link-state link-state'
    # docker exec -e VTYSH_PAGER=cat clab-topo1-c1 vtysh -c 'show bgp link-state link-state'
    links = json.loads(docker_exec(args.lab, "r2", "ip", "-j", "link", "show"))
    config = vtysh(args.lab, "r2", "show running-config")
    if any(link.get("ifname") == "lan0" for link in links) or any(
            line.strip() == "interface lan0" for line in config.splitlines()):
        raise RuntimeError("R2 already has lan0 or its configuration. Recreate the lab before this case.")
    expected = wait_until("the complete 20-NLRI baseline",
                          lambda deadline: verify_baseline(args.lab, deadline), args.timeout)
    expected[("ipv4Prefix", 2, 0, node_id(2), LAN_PREFIX)] = {
        "nlri": {"nlriType": "ipv4Prefix", "protocolId": 2, "identifier": 0,
                 "localNodeDescriptors": {"igpRouterId": node_id(2)},
                 "prefixDescriptors": {"ipReachabilityInformation": LAN_PREFIX}},
        "attrs": {"prefixMetric": 10},
    }

    docker_exec(args.lab, "r2", "ip", "link", "add", "lan0", "type", "dummy")
    docker_exec(args.lab, "r2", "ip", "link", "set", "lan0", "up")
    vtysh(args.lab, "r2", "configure terminal", "interface lan0",
          f"ip address {LAN_ADDRESS}", "ip router isis CORE", "isis passive",
          "isis metric 10", "end")
    wait_until("R2's prefix and metric on R5 and C1",
               lambda deadline: verify_ls_rib(args.lab, expected, deadline), args.timeout)
    print(f"PASS: R5 and C1 contain the original 20 NLRIs plus R2's {LAN_PREFIX}.")
    print("Lab left running for --observe-r5. Recreate it before another case.")


def test_change_metric(args):
    """Change one directional IS-IS metric without changing NLRI identities."""
    # Start from freshly deployed topo1 with the verified 20-NLRI baseline.
    # R2 eth1's link igpMetric and prefixMetric change from 20 to 35:
    # docker exec clab-topo1-r2 vtysh \
    #     -c 'configure terminal' \
    #     -c 'interface eth1' \
    #     -c 'isis metric level-2 35' \
    #     -c 'end'
    # After convergence, expect the same 20 NLRIs and only these two changes.
    # The R3->R2 metric and all other captured attributes remain unchanged.
    # docker exec -e VTYSH_PAGER=cat clab-topo1-r5 vtysh -c 'show bgp link-state link-state json'
    # docker exec -e VTYSH_PAGER=cat clab-topo1-c1 vtysh -c 'show bgp link-state link-state json'
    baseline = wait_until("the complete 20-NLRI baseline",
                          lambda deadline: verify_baseline(args.lab, deadline), args.timeout)
    link = ("link", 2, 0, node_id(2), node_id(3), "10.2.0.1", "10.3.0.1")
    prefix = ("ipv4Prefix", 2, 0, node_id(2), "10.2.0.1/32")
    assert baseline[link]["attrs"]["igpMetric"] == baseline[prefix]["attrs"]["prefixMetric"] == 20
    expected = copy.deepcopy(baseline)
    expected[link]["attrs"]["igpMetric"] = 35
    expected[prefix]["attrs"]["prefixMetric"] = 35

    vtysh(args.lab, "r2", "configure terminal", "interface eth1", "isis metric level-2 35", "end")
    wait_until("R2's directional link and prefix metrics on R5 and C1",
               lambda deadline: verify_ls_rib(args.lab, expected, deadline), args.timeout)
    print("PASS: 20 NLRIs retained; R2->R3 igpMetric and R2 eth1 prefixMetric are 35, reverse unchanged.")
    print("Lab left running for --observe-r5. Recreate it before another case.")


def test_change_te_bandwidth(args):
    """Change one TE attribute on R2's directed link to R3."""
    # Start from freshly deployed topo1 with the verified 20-NLRI baseline.
    # Change R2->R3 maxLinkBandwidth from 1250000 to 2500000 bytes/s:
    # docker exec clab-topo1-r2 vtysh \
    #     -c 'configure terminal' \
    #     -c 'interface eth1' \
    #     -c 'link-params' \
    #     -c 'max-bw 2500000' \
    #     -c 'exit-link-params' \
    #     -c 'end'
    # After convergence, expect the same 20 NLRIs; only this attribute changes.
    # This updates advertised TE information, not a traffic rate limit.
    # docker exec -e VTYSH_PAGER=cat clab-topo1-r5 vtysh -c 'show bgp link-state link-state json'
    # docker exec -e VTYSH_PAGER=cat clab-topo1-c1 vtysh -c 'show bgp link-state link-state json'
    baseline = wait_until("the complete 20-NLRI baseline",
                          lambda deadline: verify_baseline(args.lab, deadline), args.timeout)
    link = ("link", 2, 0, node_id(2), node_id(3), "10.2.0.1", "10.3.0.1")
    assert baseline[link]["attrs"]["maxLinkBandwidth"] == 1250000
    expected = copy.deepcopy(baseline)
    expected[link]["attrs"]["maxLinkBandwidth"] = 2500000

    vtysh(args.lab, "r2", "configure terminal", "interface eth1", "link-params",
          "max-bw 2500000", "exit-link-params", "end")
    wait_until("R2->R3 maximum TE bandwidth on R5 and C1",
               lambda deadline: verify_ls_rib(args.lab, expected, deadline), args.timeout)
    print("PASS: 20 NLRIs retained; only R2->R3 maxLinkBandwidth changed to 2500000 bytes/s.")
    print("Lab left running for --observe-r5. Recreate it before another case.")


def test_change_router_id(args):
    """Change the TE router-ID attribute without changing R3's IS-IS System-ID."""
    # Start from freshly deployed topo1 with the verified 20-NLRI baseline.
    # Change R3's routerIdLocal from 10.3.0.1 to its existing address 10.3.0.2:
    # docker exec clab-topo1-r3 vtysh \
    #     -c 'configure terminal' \
    #     -c 'router isis CORE' \
    #     -c 'mpls-te router-address 10.3.0.2' \
    #     -c 'end'
    # After convergence, expect the same 20 NLRIs; only this attribute changes.
    # R3's IS-IS System-ID and interface addresses remain unchanged.
    # docker exec -e VTYSH_PAGER=cat clab-topo1-r5 vtysh -c 'show bgp link-state link-state json'
    # docker exec -e VTYSH_PAGER=cat clab-topo1-c1 vtysh -c 'show bgp link-state link-state json'
    baseline = wait_until("the complete 20-NLRI baseline",
                          lambda deadline: verify_baseline(args.lab, deadline), args.timeout)
    node = ("node", 2, 0, node_id(3))
    assert baseline[node]["attrs"]["routerIdLocal"] == "10.3.0.1"
    expected = copy.deepcopy(baseline)
    expected[node]["attrs"]["routerIdLocal"] = "10.3.0.2"

    vtysh(args.lab, "r3", "configure terminal", "router isis CORE",
          "mpls-te router-address 10.3.0.2", "end")
    wait_until("R3's TE router-ID attribute on R5 and C1",
               lambda deadline: verify_ls_rib(args.lab, expected, deadline), args.timeout)
    print("PASS: 20 NLRIs retained; only R3's routerIdLocal changed to 10.3.0.2, System-ID unchanged.")
    print("Lab left running for --observe-r5. Recreate it before another case.")


def shutdown_expectation(baseline):
    """Expected RIB and adjacencies with both R2-R4 interfaces down."""
    expected = baseline.copy()
    for local, remote, address, neighbor in ((2, 4, "10.2.0.2", "10.4.0.1"),
                                            (4, 2, "10.4.0.1", "10.2.0.2")):
        del expected[("link", 2, 0, node_id(local), node_id(remote), address, neighbor)]
        del expected[("ipv4Prefix", 2, 0, node_id(local), address + "/32")]
    peers = copy.deepcopy(ISIS_PEERS)
    del peers["r2"]["eth2"]
    del peers["r4"]["eth1"]
    return expected, peers


def set_link_state(lab, state):
    for node, interface in (("r2", "eth2"), ("r4", "eth1")):
        docker_exec(lab, node, "ip", "link", "set", interface, state)


def test_shutdown_interface(args):
    """Shut both R2-R4 endpoints while preserving the alternate path through R3."""
    # Start from freshly deployed topo1 with the verified 20-NLRI baseline.
    # Shut both endpoints so their link records and interface prefixes withdraw:
    # docker exec clab-topo1-r2 ip link set eth2 down
    # docker exec clab-topo1-r4 ip link set eth1 down
    # Wait for 16 NLRIs (4 nodes, 6 directed links, 6 prefixes) on R5 and C1.
    # Both R2-R4 directions and prefixes 10.2.0.2/32 and 10.4.0.1/32 disappear.
    # The alternate path through R3 and all remaining records stay unchanged.
    # docker exec -e VTYSH_PAGER=cat clab-topo1-r5 vtysh -c 'show bgp link-state link-state json'
    # docker exec -e VTYSH_PAGER=cat clab-topo1-c1 vtysh -c 'show bgp link-state link-state json'
    baseline = wait_until("the complete 20-NLRI baseline",
                          lambda deadline: verify_baseline(args.lab, deadline), args.timeout)
    expected, peers = shutdown_expectation(baseline)

    set_link_state(args.lab, "down")
    wait_until("R2-R4 link and interface-prefix withdrawals on R5 and C1",
               lambda deadline: verify_ls_rib(args.lab, expected, deadline, peers), args.timeout)
    print("PASS: 16 NLRIs remain; only both R2-R4 directed links and their interface prefixes were withdrawn.")
    print("Lab left running for --observe-r5. Recreate it before another case.")


def test_restore_interface(args):
    """Verify shutdown and recovery within this independently fresh case."""
    # Start from freshly deployed topo1 with the verified 20-NLRI baseline.
    # This case performs its own shutdown; do not run the shutdown case first.
    # docker exec clab-topo1-r2 ip link set eth2 down
    # docker exec clab-topo1-r4 ip link set eth1 down
    # Wait for and verify 16 NLRIs on both routers before bringing the link up:
    # docker exec -e VTYSH_PAGER=cat clab-topo1-r5 vtysh -c 'show bgp link-state link-state json'
    # docker exec -e VTYSH_PAGER=cat clab-topo1-c1 vtysh -c 'show bgp link-state link-state json'
    # docker exec clab-topo1-r2 ip link set eth2 up
    # docker exec clab-topo1-r4 ip link set eth1 up
    # Wait for the original 20 NLRIs, captured attributes, and adjacencies.
    # Both R2-R4 directions and prefixes 10.2.0.2/32 and 10.4.0.1/32 return.
    # docker exec -e VTYSH_PAGER=cat clab-topo1-r5 vtysh -c 'show bgp link-state link-state json'
    # docker exec -e VTYSH_PAGER=cat clab-topo1-c1 vtysh -c 'show bgp link-state link-state json'
    baseline = wait_until("the complete 20-NLRI baseline",
                          lambda deadline: verify_baseline(args.lab, deadline), args.timeout)
    withdrawn, peers = shutdown_expectation(baseline)

    set_link_state(args.lab, "down")
    wait_until("the independent 16-NLRI shutdown state",
               lambda deadline: verify_ls_rib(args.lab, withdrawn, deadline, peers), args.timeout)
    print("Verified intermediate state: 16 NLRIs after shutting R2-R4.")
    set_link_state(args.lab, "up")
    wait_until("the exact original 20-NLRI baseline and attributes",
               lambda deadline: verify_ls_rib(args.lab, baseline, deadline), args.timeout)
    print("PASS: R2-R4 recovery restored the original 20 NLRIs and their BGP-LS attributes on R5 and C1.")
    print("Lab left running for --observe-r5. Recreate it before another case.")


def observe_r5(args):
    """Print the complete text RIB without baseline checks or state changes."""
    # docker exec -e VTYSH_PAGER=cat clab-topo1-r5 vtysh -c 'show bgp link-state link-state'
    sys.stdout.write(vtysh(args.lab, "r5", RIB_COMMAND))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Operate the already-deployed single-originator BGP-LS lab.",
        epilog="Start each case from a fresh deployment. LAB_NAME overrides topo1. "
               "The lab is left running, including after failures; changes are not saved.")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--test-advertise-prefix", dest="action", action="store_const",
                         const=test_advertise_prefix, help="advertise R2's LAN and verify propagation")
    actions.add_argument("--test-change-metric", dest="action", action="store_const",
                         const=test_change_metric, help="change R2 eth1's directional IS-IS metric")
    actions.add_argument("--test-change-te-bandwidth", dest="action", action="store_const",
                         const=test_change_te_bandwidth, help="change one exported TE bandwidth attribute")
    actions.add_argument("--test-change-router-id", dest="action", action="store_const",
                         const=test_change_router_id, help="change R3's TE router-ID node attribute")
    actions.add_argument("--test-shutdown-interface", dest="action", action="store_const",
                         const=test_shutdown_interface, help="shut both R2-R4 interface endpoints")
    actions.add_argument("--test-restore-interface", dest="action", action="store_const",
                         const=test_restore_interface, help="independently shut and restore R2-R4")
    actions.add_argument("--observe-r5", dest="action", action="store_const",
                         const=observe_r5, help="print R5's complete BGP-LS RIB")
    parser.add_argument("--timeout", type=int, default=180, metavar="SECONDS",
                        help="deadline for each convergence phase (default: 180)")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    args.lab = os.environ.get("LAB_NAME") or "topo1"
    return args


def main(argv=None):
    # python3 single-originator-demo.py --test-advertise-prefix
    # python3 single-originator-demo.py --test-change-metric
    # python3 single-originator-demo.py --test-change-te-bandwidth
    # python3 single-originator-demo.py --test-change-router-id
    # python3 single-originator-demo.py --test-shutdown-interface
    # python3 single-originator-demo.py --test-restore-interface
    # python3 single-originator-demo.py --observe-r5
    # python3 single-originator-demo.py --help
    # Optional: --timeout SECONDS (default 180); LAB_NAME overrides topo1.
    args = parse_args(argv)
    args.action(args)


if __name__ == "__main__":
    main()
