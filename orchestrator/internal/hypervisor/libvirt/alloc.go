package libvirt

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
)

// tapNameMaxLen is the IFNAMSIZ ceiling for the printable tap name: ≤15 chars
// (doc 14 §4, D66; the kernel reserves the 16th byte for the trailing NUL). The
// same ceiling ds-contracts' SessionRef::TAP_NAME_MAX_LEN pins on the Rust side
// — the two derivations must produce byte-identical names.
const tapNameMaxLen = 15

// tapNamePrefix is the `dstap-` literal of the frozen `dstap-<idx>` naming
// contract (D66). Boundary is Accountable for `dstap-<idx>` naming semantics
// (doc 14 §4 RACI); the host agent derives the name to match.
const tapNamePrefix = "dstap-"

// maxTapIndex is the largest host-local index whose `dstap-<idx>` decimal name
// still fits IFNAMSIZ: `dstap-` is 6 chars, leaving 9 decimal digits → 999999999.
// Past it the name overflows IFNAMSIZ; the allocator refuses rather than emit a
// name the kernel would truncate (a truncated name silently breaks the NFT-2
// iifname match — the three-keys-agree rule would fail at runtime).
const maxTapIndex = 999999999

// tapName derives the never-recycled `dstap-<idx>` join key (D66) from the
// host-local index. It is the single sanctioned way to turn an index into a tap
// name in Go; callers never assemble the literal themselves.
func tapName(index uint64) string {
	return tapNamePrefix + strconv.FormatUint(index, 10)
}

// reservedVsockCIDs is the count of AF_VSOCK context ids the transport reserves
// and never hands to a guest: CID 0 (VMADDR_CID_HYPERVISOR), 1
// (VMADDR_CID_LOCAL / loopback), and 2 (VMADDR_CID_HOST). The first guest CID a
// session may take is therefore index-3 (firstAllocatableVsockCID); the
// derivation skips past these so a pinned `<cid auto='no' address=...>` never
// collides with a reserved id (libvirt/qemu reject the reserved CIDs).
const reservedVsockCIDs = 3

// firstAllocatableVsockCID is the lowest CID a session may take — one past the
// three reserved ids (0/1/2). HostSessionIndex 0 derives exactly this CID, so it
// is also the floor binding.validate() asserts a derived (non-zero) CID against.
const firstAllocatableVsockCID uint32 = reservedVsockCIDs

// maxVsockIndex is the largest host-local index whose derived vsock CID still
// fits the AF_VSOCK uint32 context-id space (index + reservedVsockCIDs must not
// overflow uint32). Past it the derivation would wrap; the allocator refuses
// fail-closed rather than hand out a CID that aliases a low/reserved id. (This
// ceiling is far above maxTapIndex, so the tap-name IFNAMSIZ ceiling binds first
// in practice; the guard is belt-and-suspenders against an index space change.)
const maxVsockIndex uint64 = uint64(^uint32(0)) - reservedVsockCIDs

// ErrVsockCIDSpaceExhausted is returned when the host-local index is so large
// that `index + reservedVsockCIDs` would overflow the AF_VSOCK uint32 CID space.
// Fail-closed: the allocator never wraps a CID into the reserved/low range.
var ErrVsockCIDSpaceExhausted = errors.New("libvirt: vsock CID space exhausted (derived CID would overflow uint32)")

// vsockCID derives the deterministic per-session AF_VSOCK guest CID from the
// host-local index, skipping the three reserved CIDs (0/1/2): CID = index + 3.
// It is the single sanctioned index→CID mapping (the sibling of tapName /
// guestIP), so a retried create re-derives the SAME CID (idempotent on the
// index). It fails closed when the derivation would overflow the uint32 CID
// space — a wrapped CID could alias a reserved id and is never emitted.
func vsockCID(index uint64) (uint32, error) {
	if index > maxVsockIndex {
		return 0, ErrVsockCIDSpaceExhausted
	}
	return uint32(index) + reservedVsockCIDs, nil
}

// IndexCounter is the persistent monotonic counter behind host-local index
// allocation (doc 15 §4.1 step 4). Indices are NEVER recycled within the
// flow-log retention window (D66/D44) — a burned index (a create that failed
// after allocation) is gone for good, so the index→session-UUID join the LOG-2
// attribution key rides can never ambiguate. The counter is the authority for
// the never-recycle invariant; persistence is the implementation's job (a
// crash must not hand the same index out twice), so the durable store is a seam.
type IndexCounter interface {
	// Next atomically returns the next never-recycled index and advances the
	// durable counter past it. It must be monotonic and crash-safe: an index
	// returned here is never returned again, even across a host-agent restart.
	Next() (uint64, error)
}

// ErrIndexSpaceExhausted is returned when the persistent counter has advanced
// past the largest index whose tap name still fits IFNAMSIZ. Allocator behavior
// at exhaustion (block new sessions vs extend the naming scheme) is the Stage-5
// open question (doc 14 §4); v0 blocks, fail-closed — it never wraps or recycles.
var ErrIndexSpaceExhausted = errors.New("libvirt: host-local session index space exhausted (tap name would exceed IFNAMSIZ)")

// memCounter is a process-local IndexCounter for tests and the offline skeleton.
// It is NOT crash-safe across restarts — the real host agent backs IndexCounter
// with a persistent monotonic store (the never-recycle invariant requires
// durability). Seeding it lets a test or a recovered host resume past the
// highest index a prior incarnation handed out.
type memCounter struct {
	mu   sync.Mutex
	next uint64
}

// newMemCounter returns a process-local counter whose first Next() yields
// `start`. A recovered host seeds `start` to one past its highest observed
// index so re-adoption never re-hands a live index (the RecoverSessions sibling
// owns observing them; this is the resume point).
func newMemCounter(start uint64) *memCounter {
	return &memCounter{next: start}
}

func (c *memCounter) Next() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := c.next
	c.next++
	return idx, nil
}

// AddressPlan is the host-bring-up fact that turns a host-local index into a
// per-session guest IP deterministically (doc 13 §4: the guest subnet/base is a
// host-config fact, NOT a frozen ds-contracts literal — ds-contracts owns the
// mark layout, not the address pool). The derivation is `base + index` inside the
// host's per-session guest subnet; it is deterministic so the same index always
// yields the same guest IP (idempotency on session_uuid, and the three-keys-agree
// join is reproducible). The plan is per-host config; the derivation rule is the
// contract.
type AddressPlan struct {
	// Subnet is the host's per-session guest subnet (e.g. the routed-tap address
	// range, doc 13 §4 / D66 per-session gateway IP). Both v4 and v6 are accepted
	// (D75 family-agnostic); v0 enables v4, the v6 path round-trips for the
	// dormant Phase-C substrate.
	Subnet netip.Prefix
	// HostOffset is the count of low addresses reserved before the first guest
	// (network address, the per-session gateway, broadcast headroom). The first
	// allocatable guest IP is the subnet base plus this offset; an index of 0
	// lands on it. Derivation is base + HostOffset + index. Consulted ONLY off
	// RoutedTap — see RoutedTap.
	HostOffset uint64
	// RoutedTap selects the per-session guest-IP scheme so the recorded
	// Binding.GuestIP agrees with the egress posture (U10, gated). When TRUE
	// (the routed-tap / nft4 egress path) the guest IP is the routed-tap /31
	// guest end 10.77.<idx>.1 — derived through the SINGLE source netconfig.go
	// (routedTapGuestIP, the same netConfigForIndex U4's ds-net.env and ds-nft's
	// backend.rs key on), so the binding, the guest's applied net config, and the
	// dataplane tap link cannot drift; Subnet/HostOffset are NOT consulted (the
	// /31 is index-keyed in the third octet, fail-closed past 255). When FALSE
	// (the DEFAULT, SLIRP/offline) the historical base+HostOffset+index derivation
	// over Subnet is BYTE-IDENTICAL — the SLIRP path and its pinned 10.42.x tests
	// are unperturbed.
	RoutedTap bool
}

// guestIP derives the deterministic per-session guest address for a host-local
// index (doc 15 §4.1 step 4). The scheme is GATED on RoutedTap (U10): under the
// routed-tap egress posture the guest IP is the routed-tap /31 guest end
// 10.77.<idx>.1 from the SINGLE source netconfig.go (routedTapGuestIP — the same
// netConfigForIndex U4's ds-net.env and ds-nft's backend.rs derive), so the
// recorded Binding.GuestIP, the guest's applied net config, and the dataplane tap
// link cannot drift; off the gate (the default SLIRP/offline path) it is the
// historical base+HostOffset+index over the plan's subnet, BYTE-IDENTICAL. Both
// schemes fail closed on an out-of-range index — the routed-tap /31 past the
// third-octet ceiling (255, where the index would alias another session's /31),
// the SLIRP path when the derived address falls outside the configured subnet
// (an out-of-range guest IP can never satisfy the three-keys-agree rule, so
// emitting one would be a silent attribution bug).
func (p AddressPlan) guestIP(index uint64) (GuestAddress, error) {
	if p.RoutedTap {
		// Routed-tap posture: defer to the ONE Go owner of the per-session /31
		// (netconfig.go). Subnet/HostOffset are intentionally not consulted; the
		// /31 is index-keyed in the third octet and fails closed past 255.
		return routedTapGuestIP(index)
	}
	if !p.Subnet.IsValid() {
		return GuestAddress{}, fmt.Errorf("address plan has no valid subnet")
	}
	base := p.Subnet.Masked().Addr()
	offset := p.HostOffset + index
	addr := addrPlus(base, offset)
	if !addr.IsValid() {
		return GuestAddress{}, fmt.Errorf("guest ip derivation overflowed the address family for index %d", index)
	}
	if !p.Subnet.Contains(addr) {
		return GuestAddress{}, fmt.Errorf("guest ip %s for index %d falls outside subnet %s", addr, index, p.Subnet)
	}
	return guestAddressFromAddr(addr), nil
}

// addrPlus returns addr advanced by `n` host positions, family-preserving. It
// returns the zero Addr (invalid) on overflow past the family's last address.
func addrPlus(addr netip.Addr, n uint64) netip.Addr {
	out := addr
	for i := uint64(0); i < n; i++ {
		out = out.Next()
		if !out.IsValid() {
			return netip.Addr{}
		}
	}
	return out
}

// Allocator allocates the host-local binding for one session (doc 15 §4.1
// step 4, the orchestrator-Accountable half of the tap-create RACI row): it
// draws the never-recycled index from the persistent counter and derives the
// tap name and guest IP deterministically. It produces the (index, tap_name,
// guest_ip) keys; it does NOT touch the kernel — programming the tap and the
// NFT objects is the Boundary-owned primitive the host agent invokes (the
// AttachPrimitive seam).
type Allocator struct {
	counter IndexCounter
	plan    AddressPlan
}

// NewAllocator builds an Allocator over a persistent counter and a host address
// plan. A nil counter or an invalid plan subnet is a programming error surfaced
// at construction, not at allocation time.
func NewAllocator(counter IndexCounter, plan AddressPlan) (*Allocator, error) {
	if counter == nil {
		return nil, fmt.Errorf("libvirt: allocator requires a persistent index counter")
	}
	if !plan.Subnet.IsValid() {
		return nil, fmt.Errorf("libvirt: allocator requires a valid guest subnet")
	}
	return &Allocator{counter: counter, plan: plan}, nil
}

// Allocate draws the next never-recycled index and derives the three agreeing
// keys. It refuses fail-closed when the index space is exhausted (the tap name
// would overflow IFNAMSIZ) — a burned index is never recycled to make room. The
// returned binding has no overlay path yet; that is recorded at step 7.
func (a *Allocator) Allocate() (Binding, error) {
	idx, err := a.counter.Next()
	if err != nil {
		return Binding{}, fmt.Errorf("allocate host-local index: %w", err)
	}
	if idx > maxTapIndex {
		return Binding{}, ErrIndexSpaceExhausted
	}
	gip, err := a.plan.guestIP(idx)
	if err != nil {
		return Binding{}, fmt.Errorf("derive guest ip for index %d: %w", idx, err)
	}
	cid, err := vsockCID(idx)
	if err != nil {
		return Binding{}, fmt.Errorf("derive vsock cid for index %d: %w", idx, err)
	}
	b := Binding{
		HostSessionIndex: idx,
		TapName:          tapName(idx),
		GuestIP:          gip,
		VsockCID:         cid,
	}
	if err := b.validate(); err != nil {
		return Binding{}, fmt.Errorf("derived binding for index %d invalid: %w", idx, err)
	}
	return b, nil
}
