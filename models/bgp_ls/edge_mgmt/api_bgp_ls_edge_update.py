"""Executable model of bgpd's link state edge-processing callback
(api_bgp_ls_edge_update).

The four MBT artifacts a tester uses:

* State        — BgpLsLinkState. What bgpd remembers between calls. Based off
                 the Routing Information Base (RIB). Read from and written to
                 by each call.
* Transition   — api_bgp_ls_edge_update(api). The action under test. Returns
                 0 after successfully originating the link; -1 otherwise. Also
                 updates the state.
* Precondition — api_bgp_ls_edge_update(api). Guards the action. Random/
                 symbolic test generators use it to skip or shrink infeasible
                 inputs.
* Invariant    — Must hold at every state the model visits. Checked after each
                 transition.

Scope: api_bgp_ls_edge_update only. Link withdraw and unexpected messages are
out of scope.

"""

from dataclasses import dataclass, field
from enum import IntEnum

from modeling_primitives import (
    no_dup,
    opaque_addr_t,
    opaque_prefix_t,
    uint8_t,
    uint32_t,
)

# COMMENTS: over the TED update -> bgpd processing -> bgp-ls propagation stages,
# there are three levels of data types:
# 1. Input format into bgpd
# 2. bgpd internal representation of the TED topology graph and RIB entries
# 3. BGP UPDATE message emitted to other nodes. Its NLRI and attribute encoding
# is the data layout actually specified in the RFC protocol. Levels 1 and 2 are
# implementation specific.
#
# Domain type definitions will be much cleaner if their top-level declarations
# follow this hierarchy, while sub-fields can still share common type definitions,
# e.g., NLRI.

# ── Domain types ─────────────────────────────────────────────────────────────
# Abstract types that capture key fields relevant to bgpd's handling of link
# state edge updates.


class BEvent(IntEnum):
    """Link State event conveyed by zebra."""

    UNDEF = 0
    SYNC = 1
    ADD = 2
    UPDATE = 3
    DELETE = 4


@dataclass
class BgpLsNode:
    """Node descriptor: identifies a router/node in the topology."""

    asn: uint32_t
    igp_router_id: opaque_addr_t


@dataclass
class BgpLsLink:
    """Link descriptor: identifies a link between two nodes; does not include
    IPv4 addresses. Note that the FRR's link descriptor also specifies
    identifier fields for nodes that do not have IPv4 or IPv6 addresses
    associated with their interfaces."""

    interface: opaque_addr_t  # IPv6 address
    neighbor: opaque_addr_t  # IPv6 address
    remote_asn: uint32_t


@dataclass
class BLinkNlri:
    """Identifies a link between two nodes."""

    source: BgpLsNode
    destination: BgpLsNode
    link: BgpLsLink


@dataclass
class LinkStateEdge:
    """
    Represents a unidirectional link between two nodes in the topology,
    typically tracked in the TED; operational status field not represented for
    now.
    """

    asn: uint32_t
    source: opaque_addr_t
    destination: opaque_addr_t


@dataclass
class BgpRibEntry:
    """One entry in bgpd's RIB: a prefix, link topology, and the set of
    nexthops that reach the originating BGP peer."""

    # COMMENTS: internal implementation details such as synth_prefix may be
    # modeled at any proper abstraction level as we see fit. Its purpose is to
    # identify links (same link -> same key) while leveraging the prefix-keyed
    # RIB data structure. A straightforward choice would be to key directly by
    # the NLRI tuple, instead of FRR's synthetic allocator id.
    synth_prefix: opaque_prefix_t
    ls_nlri: BLinkNlri


# ── API surface ──────────────────────────────────────────────────────────────
# The action under test takes a BApiLinkStateUpdate (what zebra sends) and
# returns 0 after successfully originating the link; -1 otherwise.


@dataclass
class LinkStateNodeId:
    """Link state node identifier: ISO system ID + IS-IS level"""

    iso_sys_id: list[uint8_t]  # 6-byte ID
    level: uint8_t


@dataclass
class LinkStateAttributes:
    """LS attributes: payload carried by zebra."""

    valid: bool
    adv: LinkStateNodeId  # advertising router
    name: str | None
    metric: uint32_t
    local: opaque_addr_t  # local IPv6 address
    remote: opaque_addr_t  # remote IPv6 address


@dataclass
class BApiLinkStateUpdate:
    """Input payload: zebra's link-state message notification. Type info
    omitted; implied to be link in this API."""

    event: BEvent
    remote: opaque_addr_t
    data: LinkStateAttributes


# ── Model: state, contract, transition ───────────────────────────────────────


@dataclass
class BgpLsLinkState:
    """
    The model's overall state. Represents bgpd's memory between API calls.
    Tracks the RIB and uses a ghost state to simulate the TED.
    """

    asn: uint32_t = uint32_t(1)  # arbitrary ASN for now
    # COMMENTS: please double check if bgpd maintains its own TED and uses it for
    # connectivity checks. If so, this is not a ghost state.
    ghost_ted: list[LinkStateEdge] = field(default_factory=list)
    rib: list[BgpRibEntry] = field(default_factory=list)
    next_id: opaque_prefix_t = opaque_prefix_t(0)

    # ── Invariant ────────────────────────────────────────────────────────────
    def invariant(self) -> bool:
        """
        Groups of constraints:
          1. Keys are unique within each table.
          2. RIB entries are well-formed (NLRI includes node and link
             descriptors).
          3. The LSDB/TED and the RIB agree: every edge described in the NLRI
             corresponds to a link entry within the LSDB/TED; however, the
             LSDB/TED may still have entries that the RIB NLRI does not
             contain.

        Future Modeling Notes:
        * Nexthop deduplication: Nexthops should be duplicated if using multi-
          domain (IS-IS and OSPF). Since the current scope is only IS-IS,
          deduplication is pending.
        """

        # ── Uniqueness ───────────────────────────────────────────────────────
        ted_unique = no_dup(edge for edge in self.ghost_ted)
        rib_keys_unique = no_dup(r.synth_prefix for r in self.rib)

        # ── Format ───────────────────────────────────────────────────────────
        nlri_nonnull = all(r.ls_nlri is not None for r in self.rib)
        nlri_nodes_nonnull = all(
            r.ls_nlri.source is not None and r.ls_nlri.destination is not None
            for r in self.rib
        )
        nlri_link_nonnull = all(r.ls_nlri.link is not None for r in self.rib)

        # ── LSDB/TED ─────────────────────────────────────────────────────────
        ted_is_referenced = all(
            any(
                r.ls_nlri.source.igp_router_id == edge.source
                and r.ls_nlri.destination.igp_router_id == edge.destination
                for edge in self.ghost_ted
            )
            for r in self.rib
        )

        return (
            ted_unique
            and rib_keys_unique
            and nlri_nonnull
            and nlri_nodes_nonnull
            and nlri_link_nonnull
            and ted_is_referenced
        )

    # ── Precondition ─────────────────────────────────────────────────────────
    def api_bgp_ls_edge_update_precondition(
        self, api: BApiLinkStateUpdate
    ) -> bool:
        """Action guard. The harness must only call api_bgp_ls_edge_update when
        this returns True. Must start at an empty state."""

        rib_empty = not self.rib
        return rib_empty

    # ── Transition ───────────────────────────────────────────────────────────
    def api_bgp_ls_edge_update(self, api: BApiLinkStateUpdate) -> int:
        """Process one zebra link-state update."""

        # find and link reverse edge only if known event
        if (
            # BUG: always True; should use 'and' here
            api.event != BEvent.SYNC
            or api.event != BEvent.ADD
            or api.event != BEvent.UPDATE
        ):
            return -1

        # two-way connectivity check - in the FRR implementation, it may be the
        # case that
        edge = self._find_edge(api.data.local, api.data.remote)
        reverse = self._find_edge(api.data.remote, api.data.local)

        if not edge:
            self.ghost_ted.append(
                LinkStateEdge(self.asn, api.data.local, api.data.remote)
            )

        if not reverse:
            self.ghost_ted.append(
                LinkStateEdge(self.asn, api.data.remote, api.data.local)
            )

        # validate router ID lengths
        if not self._valid_addr_length(api.data.local, api.data.remote):
            return -1

        # build link NLRI
        source: BgpLsNode = BgpLsNode(self.asn, api.data.local)
        destination: BgpLsNode = BgpLsNode(self.asn, api.data.remote)
        link: BgpLsLink = BgpLsLink(
            interface=api.data.local,
            neighbor=api.data.remote,
            remote_asn=self.asn,
        )

        nlri: BLinkNlri = BLinkNlri(source, destination, link)

        rib_entry: BgpRibEntry = BgpRibEntry(
            self._allocate_new_id(), ls_nlri=nlri
        )

        self.rib.append(rib_entry)

        return 0

    def _find_edge(
        self, local: opaque_addr_t, remote: opaque_addr_t
    ) -> LinkStateEdge | None:
        """Searches for an existing LinkStateEdge corresponding to the `local`
        and `remote` nodes."""
        for e in self.ghost_ted:
            if e.source == local and e.destination == remote:
                return e
        return None

    def _valid_addr_length(
        self, local: opaque_addr_t, remote: opaque_addr_t
    ) -> bool:
        """True iff `local` and `remote` can both be represented as an IPv6
        address."""
        return local.bit_length() <= 128 and remote.bit_length() <= 128

    def _allocate_new_id(self) -> opaque_prefix_t:
        """Allocates a new hash ID (corresponding to the synthetic prefix) for
        an entry within the RIB."""
        prev: opaque_prefix_t = self.next_id
        self.next_id = opaque_prefix_t(self.next_id + 1)
        return prev
