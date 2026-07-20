"""Parity engine: replay malformed BGP UPDATEs against a live FRR and compare
its behavior against the RFC 4271/7606 oracle in bgp_oracle.py.

Each test case flows through seven stages. Only EXECUTE touches the network;
every other stage is pure and can be exercised offline.

    corpus row --[ENCODE]--> update bytes --[EXECUTE]--> observation
         |                                                    |
         +--------[PREDICT]--> ParseResult    [CLASSIFY]------+
                                    |              |
                                    +--[COMPARE]---+
                                           |
                                     [AGGREGATE] --> report

Stage inputs and outputs are documented on each function. Behavior is pinned by
tests/test_characterization.py -- run it after any change to this file.
"""

import json
import socket
import struct
import subprocess
import time

from models.bgpd.malformed_packets.bgp_oracle import (
    parse_attributes, BGPPathAttr, ParseResult,
)

# ── Configuration ────────────────────────────────────────────────────────────

BGP_IP = "127.0.0.1"
BGP_PORT = 1179
FRR_CONTAINER = "frr-lab"
TARGET_PREFIX = "10.0.0.0/24"

CONNECT_TIMEOUT = 3.0
OBSERVE_TIMEOUT = 0.2       # how long to wait for FRR to react to an UPDATE
INTER_CASE_DELAY = 0.01

TESTS_DIR = "models/bgpd/malformed_packets/tests"
REPORT_PATH = "models/bgpd/malformed_packets/parity_report_comprehensive.json"

# (label, corpus file, version, slots to fuzz). `version` and `slot` steer
# ENCODE; see encode_case().
SUITES = (
    ("Suite 1: Strict Teardowns (RFC 4271)", "attr_argdict_extended.txt", 1, (1, 2, 3)),
    ("Suite 2: Soft Faults (RFC 7606)", "attr_argdict_soft.txt", 2, (1, 4)),
    ("Suite 3: Semantic Communities", "attr_argdict_semantic.txt", 3, (4,)),
)

KEEPALIVE_MESSAGE = b'\xff' * 16 + b'\x00\x13\x04'


# ── Stage 1: LOAD ────────────────────────────────────────────────────────────

def load_corpus(filename):
    """IN : corpus filename under TESTS_DIR
    OUT: list[dict] -- one argument dict per row, or [] if the file is absent.
    """
    path = f"{TESTS_DIR}/{filename}"
    try:
        with open(path, "r") as f:
            return [eval(line.strip()) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Could not find {path}")
        return []


def iter_cases(corpus, version, slots):
    """IN : corpus rows, suite version, slots to fuzz
    OUT: yields (index, args, slot) for each executable case.
    """
    for i, args in enumerate(corpus):
        for slot in slots:
            if slot == 4 and "type4" not in args:
                continue
            yield i, args, slot


# ── Stage 2: ENCODE ──────────────────────────────────────────────────────────

def build_bgp_open():
    """OUT: BGP OPEN message advertising MP-BGP IPv4 unicast, route refresh
    (old + new), enhanced route refresh, and 4-byte ASN 65002.
    """
    opt_params = b''
    opt_params += struct.pack('!BB', 2, 6) + struct.pack('!BB', 1, 4) + struct.pack('!HBB', 1, 0, 1)
    opt_params += struct.pack('!BB', 2, 2) + struct.pack('!BB', 128, 0)
    opt_params += struct.pack('!BB', 2, 2) + struct.pack('!BB', 2, 0)
    opt_params += struct.pack('!BB', 2, 2) + struct.pack('!BB', 70, 0)
    opt_params += struct.pack('!BB', 2, 6) + struct.pack('!BB', 65, 4) + struct.pack('!I', 65002)
    open_body = (struct.pack('!BHH', 4, 65002, 90)
                 + socket.inet_aton('192.168.1.1')
                 + struct.pack('!B', len(opt_params)) + opt_params)
    msg_len = 16 + 2 + 1 + len(open_body)
    return b'\xff' * 16 + struct.pack('!HB', msg_len, 1) + open_body


def build_bgp_keepalive():
    return KEEPALIVE_MESSAGE


def encode_case(args, version, slot):
    """IN : argument dict, suite version, slot being fuzzed
    OUT: (update_bytes, attrs_for_oracle) -- the wire form and the model form of
         the same UPDATE.

    Layout: valid AS_PATH + NEXT_HOP + ORIGIN, then the fuzzed attribute packed
    LAST. Suite 2 slot 1 is the exception: ORIGIN is omitted and the fuzzed
    attribute takes its type code, so a malformed ORIGIN can be tested.
    """
    attr_bytes = b''
    attrs_for_oracle = []

    attr_bytes += struct.pack('!BBB', 64, 2, 6) + b'\x02\x01\x00\x00\xfd\xea'
    attrs_for_oracle.append(BGPPathAttr(flags=64, type_code=2, length=6))

    attr_bytes += struct.pack('!BBB', 64, 3, 4) + b'\x01\x01\x01\x01'
    attrs_for_oracle.append(BGPPathAttr(flags=64, type_code=3, length=4))

    fuzzing_origin = (version == 2 and slot == 1)
    if not fuzzing_origin:
        attr_bytes += struct.pack('!BBB', 64, 1, 1) + b'\x00'
        attrs_for_oracle.append(BGPPathAttr(flags=64, type_code=1, length=1))

    f_flags = args[f"flags{slot}"]
    f_type = 1 if fuzzing_origin else args[f"type{slot}"]
    f_len = args[f"len{slot}"]

    attr_bytes += struct.pack('!BB', f_flags, f_type)
    if f_flags & 0x10:                      # extended-length bit -> 2-byte length
        attr_bytes += struct.pack('!H', f_len)
    else:
        attr_bytes += struct.pack('!B', f_len)

    if "payload_hex" in args:
        attr_bytes += bytes.fromhex(args["payload_hex"])
    else:
        attr_bytes += b'\x00' * f_len
    attrs_for_oracle.append(BGPPathAttr(flags=f_flags, type_code=f_type, length=f_len))

    nlri_bytes = b'\x18\x0a\x00\x00'        # 10.0.0.0/24
    update_len = 23 + len(attr_bytes) + len(nlri_bytes)
    update_bytes = (b'\xff' * 16 + struct.pack('!HB', update_len, 2)
                    + b'\x00\x00' + struct.pack('!H', len(attr_bytes))
                    + attr_bytes + nlri_bytes)

    return update_bytes, attrs_for_oracle


# ── Stage 3: PREDICT ─────────────────────────────────────────────────────────

def predict(attrs_for_oracle):
    """IN : list[BGPPathAttr]
    OUT: ParseResult -- what the RFCs say should happen.
    """
    return parse_attributes(attrs_for_oracle)


# ── Stage 4: EXECUTE (the only impure stage) ─────────────────────────────────

def perform_bgp_handshake(s):
    """IN : connected socket. Raises on failure. OUT: None."""
    s.sendall(build_bgp_open())
    resp = s.recv(4096)
    if not resp:
        raise Exception("HandshakeError: Socket closed before OPEN response.")

    got_open = False
    got_keepalive = False
    idx = 0
    while idx + 19 <= len(resp):
        if resp[idx:idx + 16] == b'\xff' * 16:
            r_len = struct.unpack('!H', resp[idx + 16:idx + 18])[0]
            if idx + r_len > len(resp):
                break
            r_type = resp[idx + 18]
            if r_type == 1:
                got_open = True
            elif r_type == 4:
                got_keepalive = True
            elif r_type == 3:
                err = resp[idx + 19] if idx + 20 <= len(resp) else -1
                sub = resp[idx + 20] if idx + 21 <= len(resp) else -1
                raise Exception(f"HandshakeError: FRR sent NOTIFICATION error={err} subcode={sub}")
            idx += r_len
        else:
            idx += 1

    if not got_open:
        raise Exception("HandshakeError: FRR did not send OPEN.")

    s.sendall(build_bgp_keepalive())

    if not got_keepalive:
        resp2 = s.recv(4096)
        if resp2 and len(resp2) >= 19 and resp2[18] == 4:
            got_keepalive = True

    if not got_keepalive:
        raise Exception("HandshakeError: FRR did not send KEEPALIVE.")


def send_update_and_monitor(s, update_bytes):
    """IN : socket, UPDATE bytes
    OUT: (notification_received, session_alive)
    """
    try:
        s.sendall(update_bytes)
    except Exception as e:
        print(f"[-] Failed to send UPDATE packet: {e}")

    notification_received = False
    is_active = True

    s.settimeout(OBSERVE_TIMEOUT)
    try:
        while True:
            data = s.recv(4096)
            if not data:
                is_active = False
                break

            idx = 0
            while idx <= len(data) - 19:
                if data[idx:idx + 16] == b'\xff' * 16:
                    msg_len = struct.unpack('!H', data[idx + 16:idx + 18])[0]
                    if data[idx + 18] == 3:
                        notification_received = True
                        is_active = False
                    idx += msg_len
                else:
                    idx += 1
    except socket.timeout:
        pass
    except ConnectionResetError:
        is_active = False

    return notification_received, is_active


def probe_rib(prefix=None):
    """IN : prefix (defaults to TARGET_PREFIX)
    OUT: True if FRR has the prefix installed.

    NOTE: a probe failure is currently indistinguishable from "route absent".
    """
    prefix = prefix if prefix is not None else TARGET_PREFIX
    try:
        out = subprocess.check_output(
            ["docker", "exec", FRR_CONTAINER, "vtysh", "-c", f"show ip bgp {prefix} json"],
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(out)
        return "paths" in data or "prefix" in data
    except Exception as e:
        print(f"Failed to check RIB state: {e}")
        return False


def execute(update_bytes):
    """IN : UPDATE bytes
    OUT: (reached, notification_received, session_alive, route_installed)

    reached is False when the SUT could not be driven at all (connection refused
    or handshake failure); the remaining fields are meaningless in that case and
    the caller must not score it.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((BGP_IP, BGP_PORT))
    except ConnectionRefusedError:
        return False, False, False, False

    try:
        perform_bgp_handshake(s)
    except Exception as e:
        print(f"\n[!] BGP Handshake Failed: {e}", flush=True)
        s.close()
        return False, False, False, False

    notification_received, is_active = send_update_and_monitor(s, update_bytes)

    installed = False
    if is_active and not notification_received:
        installed = probe_rib()

    s.close()
    time.sleep(INTER_CASE_DELAY)
    return True, notification_received, is_active, installed


# ── Stage 5: CLASSIFY ────────────────────────────────────────────────────────

def classify(notification_received, session_alive, route_installed, oracle_res):
    """IN : observation + oracle prediction
    OUT: str -- the ParseResult name attributed to FRR.

    XXX CIRCULARITY (preserved verbatim from the original; do not build on it).
    The observation carries only three distinguishable states -- session down,
    route installed, route absent -- but this returns one of five labels, and it
    resolves the two ambiguous pairs by consulting `oracle_res`:

        route installed -> VALID            or ATTRIBUTE_DISCARD
        route absent    -> TREAT_AS_WITHDRAW or AFI_SAFI_DISABLE

    Within each pair the answer is therefore *assigned from the prediction*, not
    measured, so those distinctions can never fail. Removing the `oracle_res`
    parameter is the fix; it requires widening the observation first (read the
    NOTIFICATION subcode and the installed path's attributes).
    """
    if notification_received or not session_alive:
        return "SESSION_RESET"
    if route_installed:
        return "ATTRIBUTE_DISCARD" if oracle_res == ParseResult.ATTRIBUTE_DISCARD else "VALID"
    return "AFI_SAFI_DISABLE" if oracle_res == ParseResult.AFI_SAFI_DISABLE else "TREAT_AS_WITHDRAW"


def oracle_label(oracle_res):
    """IN : ParseResult -> OUT: str, the name used in the report."""
    return oracle_res.name


# ── Stage 6: COMPARE ─────────────────────────────────────────────────────────

def compare(oracle_res, frr_result):
    """IN : oracle prediction, FRR's classified behavior
    OUT: (expected_label, matched)
    """
    expected = oracle_label(oracle_res)
    return expected, frr_result == expected


# ── Stage 7: AGGREGATE ───────────────────────────────────────────────────────

MATRIX_ROWS = ("VALID", "SESSION_RESET", "ATTRIBUTE_DISCARD",
               "AFI_SAFI_DISABLE", "TREAT_AS_WITHDRAW")


def new_tally():
    """OUT: a zeroed results tally."""
    return {
        "SESSION_TORN_DOWN": 0,
        "TREAT_AS_WITHDRAW": 0,
        "AFI_SAFI_DISABLE": 0,
        "ROUTES_ILLEGALLY_INSTALLED": 0,
        "LEGITIMATE_ROUTE_INSTALLS": 0,
        "ATTRIBUTE_DISCARD": 0,
        "FRR_CRASH": 0,
        "TOTAL_EXECUTED": 0,
        "VALID": 0,
        "MATRIX": {row: {"TOTAL": 0, "PASS": 0, "FAIL": 0} for row in MATRIX_ROWS},
    }


def record(tally, discrepancies, test_id, args, oracle_res, frr_result):
    """IN : tally + discrepancy list (both mutated), case identity, prediction,
            classified behavior
    OUT: None
    """
    tally["TOTAL_EXECUTED"] += 1

    if frr_result == "SESSION_RESET":
        tally["SESSION_TORN_DOWN"] += 1
    else:
        tally[frr_result] += 1
        # A route reached the RIB. Was it entitled to?
        if frr_result in ("VALID", "ATTRIBUTE_DISCARD"):
            if oracle_res in (ParseResult.VALID, ParseResult.ATTRIBUTE_DISCARD):
                tally["LEGITIMATE_ROUTE_INSTALLS"] += 1
            else:
                tally["ROUTES_ILLEGALLY_INSTALLED"] += 1

    expected, matched = compare(oracle_res, frr_result)

    if not matched:
        discrepancies.append({
            "test_id": test_id,
            "payload_args": args,
            "rfc_expected": expected,
            "frr_actual": frr_result,
            "oracle_state": oracle_res.name,
        })

    tally["MATRIX"][expected]["TOTAL"] += 1
    tally["MATRIX"][expected]["PASS" if matched else "FAIL"] += 1


def render_report(tally, discrepancies):
    """IN : tally, discrepancies -> OUT: None (prints the summary)."""
    print("\n=======================================================================")
    print("                COMPREHENSIVE EMPIRICAL RESULTS SUMMARY                ")
    print("=======================================================================")
    print(f"Total Tests Executed      : {tally['TOTAL_EXECUTED']}")
    print("\n--- Test Categorization (By Expected Behavior) ---")
    print(f"{'Category':<28} | {'Total':>7} | {'PASS':>7} | {'FAIL':>7}")
    print("-" * 55)

    mat = tally['MATRIX']
    for label, row in (("Valid Updates", "VALID"),
                       ("Strict Teardown (RFC 4271)", "SESSION_RESET"),
                       ("Treat-as-Withdraw (RFC 7606)", "TREAT_AS_WITHDRAW"),
                       ("AFI/SAFI Disable (RFC 7606)", "AFI_SAFI_DISABLE"),
                       ("Attribute Discard (RFC 7606)", "ATTRIBUTE_DISCARD")):
        print(f"{label:<28} | {mat[row]['TOTAL']:>7} | {mat[row]['PASS']:>7} | {mat[row]['FAIL']:>7}")

    print("\n--- Critical Metrics ---")
    print(f"Legitimate Route Installs : {tally['LEGITIMATE_ROUTE_INSTALLS']}")
    print(f"Routes Illegally Installed: {tally['ROUTES_ILLEGALLY_INSTALLED']}")
    print(f"FRR Parser Crashes        : {tally['FRR_CRASH']}")
    print("-----------------------------------------------------------------------")
    print(f"Unexpected Protocol Deviations: {len(discrepancies)}")

    if not discrepancies:
        print("\n=> VERDICT: 100% PERFECT PARITY. FRR perfectly implements the selected RFCs.")
    else:
        print(f"\n=> VERDICT: {len(discrepancies)} Protocol Deviations Found.")
        print("Deviant Test IDs:")
        for idx, d in enumerate(discrepancies):
            if idx > 15:
                print("... (truncated)")
                break
            print(f"  - {d['test_id']} (Expected {d['rfc_expected']}, got {d['frr_actual']})")


def write_report(discrepancies, path=None):
    # Resolved at call time, not definition time, so REPORT_PATH stays
    # overridable by tests.
    path = path if path is not None else REPORT_PATH
    with open(path, "w") as f:
        json.dump(discrepancies, f, indent=2)


# ── Orchestration ────────────────────────────────────────────────────────────

def run_case(args, version, slot, test_id, tally, discrepancies):
    """Drive one test case through all seven stages."""
    update_bytes, attrs_for_oracle = encode_case(args, version, slot)   # ENCODE
    oracle_res = predict(attrs_for_oracle)                              # PREDICT

    reached, notification, alive, installed = execute(update_bytes)     # EXECUTE
    if not reached:
        tally["FRR_CRASH"] += 1
        return

    frr_result = classify(notification, alive, installed, oracle_res)   # CLASSIFY
    record(tally, discrepancies, test_id, args, oracle_res, frr_result)  # COMPARE + AGGREGATE


def run_suite(corpus, version, slots, tally, discrepancies):
    """Drive every case in one corpus."""
    total_cases = len(corpus)
    reported_row = -1
    for i, args, slot in iter_cases(corpus, version, slots):
        if i != reported_row:
            reported_row = i
            if (i + 1) % 10 == 0 or (i + 1) == total_cases:
                print(f"    -> Progress: {i + 1} / {total_cases} cases processed...", flush=True)
        run_case(args, version, slot, f"V{version}-{i}-slot{slot}", tally, discrepancies)


def select_suites():
    """OUT: set of suite indices to run, from the interactive prompt."""
    print("\nWhich suite would you like to run?")
    print("  1) Suite 1: Strict Teardowns (RFC 4271)")
    print("  2) Suite 2: Soft Faults (RFC 7606)")
    print("  3) Suite 3: Semantic Communities")
    print("  4) All Suites (Default)")
    try:
        choice = input("Enter choice [1-4]: ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = '4'
        print("4")

    selected = {idx for idx in range(3) if choice in (str(idx + 1), '4', '')}
    if not selected:
        print("Invalid choice, defaulting to All.")
        selected = {0, 1, 2}
    return selected


def execute_comprehensive_suite():
    print("[*] Starting Master Comprehensive Dynamic Fuzzer + Parity Engine")
    print("[!] Scope Limitation: Fuzzed attributes are always packed LAST, after valid mandatory attributes.")
    print("    This isolates the fuzzed variable but does not test malformed attributes in the first or middle positions.")

    corpora = [load_corpus(filename) for _, filename, _, _ in SUITES]
    if not corpora[0] or not corpora[1]:
        return

    tally = new_tally()
    discrepancies = []
    selected = select_suites()

    for idx, (name, _, version, slots) in enumerate(SUITES):
        if idx not in selected:
            continue
        if not corpora[idx]:
            print(f"\n[-] {name} skipped (dictionary not found).")
            continue
        print(f"\n[*] Running {name}")
        run_suite(corpora[idx], version, slots, tally, discrepancies)

    render_report(tally, discrepancies)
    write_report(discrepancies)


if __name__ == "__main__":
    execute_comprehensive_suite()
