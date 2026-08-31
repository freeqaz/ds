package libvirt

import (
	"errors"
	"net/netip"
	"strconv"
	"testing"
)

func mustPlan(t *testing.T, cidr string, offset uint64) AddressPlan {
	t.Helper()
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", cidr, err)
	}
	return AddressPlan{Subnet: p, HostOffset: offset}
}

func TestTapNameDerivation(t *testing.T) {
	cases := []struct {
		index uint64
		want  string
	}{
		{0, "dstap-0"},
		{42, "dstap-42"},
		{999999999, "dstap-999999999"}, // 15 chars exactly — the IFNAMSIZ ceiling
	}
	for _, tc := range cases {
		got := tapName(tc.index)
		if got != tc.want {
			t.Errorf("tapName(%d) = %q, want %q", tc.index, got, tc.want)
		}
		if len(got) > tapNameMaxLen {
			t.Errorf("tapName(%d) = %q exceeds IFNAMSIZ ceiling (%d chars)", tc.index, got, tapNameMaxLen)
		}
	}
}

func TestAllocateNeverRecycles(t *testing.T) {
	plan := mustPlan(t, "10.42.0.0/16", 2) // .0 network, .1 gateway, guests from .2
	a, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	seen := map[uint64]bool{}
	for i := 0; i < 5; i++ {
		b, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		if seen[b.HostSessionIndex] {
			t.Fatalf("index %d recycled — the never-recycle invariant is broken (D66)", b.HostSessionIndex)
		}
		seen[b.HostSessionIndex] = true
		if got := uint64(i); b.HostSessionIndex != got {
			t.Errorf("Allocate #%d index = %d, want %d (monotonic)", i, b.HostSessionIndex, got)
		}
		if err := b.validate(); err != nil {
			t.Errorf("Allocate #%d binding invalid: %v", i, err)
		}
	}
}

func TestVsockCIDDerivationSkipsReservedCIDs(t *testing.T) {
	// Index 0 lands on the first allocatable CID (one past the three reserved
	// ids 0/1/2 → CID 3); the derivation is index + reservedVsockCIDs and never
	// emits a reserved id.
	cases := []struct {
		index uint64
		want  uint32
	}{
		{0, 3},   // first guest CID — past hypervisor(0)/local(1)/host(2)
		{1, 4},   //
		{42, 45}, //
	}
	for _, tc := range cases {
		got, err := vsockCID(tc.index)
		if err != nil {
			t.Fatalf("vsockCID(%d): %v", tc.index, err)
		}
		if got != tc.want {
			t.Errorf("vsockCID(%d) = %d, want %d", tc.index, got, tc.want)
		}
		// Never a reserved CID (0/1/2).
		if got < firstAllocatableVsockCID {
			t.Errorf("vsockCID(%d) = %d is in the reserved range (< %d)", tc.index, got, firstAllocatableVsockCID)
		}
	}
}

func TestVsockCIDDeterministic(t *testing.T) {
	// The same index always derives the same CID (idempotency, like the tap name).
	a, _ := vsockCID(123456)
	b, _ := vsockCID(123456)
	if a != b {
		t.Fatalf("vsockCID not deterministic: %d vs %d", a, b)
	}
	if a != 123456+reservedVsockCIDs {
		t.Fatalf("vsockCID(123456) = %d, want %d", a, 123456+reservedVsockCIDs)
	}
}

func TestVsockCIDOverflowFailsClosed(t *testing.T) {
	// An index one past the uint32 CID ceiling overflows; the derivation refuses
	// rather than wrap a CID into the low/reserved range.
	if _, err := vsockCID(maxVsockIndex + 1); !errors.Is(err, ErrVsockCIDSpaceExhausted) {
		t.Fatalf("vsockCID past ceiling = %v, want ErrVsockCIDSpaceExhausted", err)
	}
	// The largest in-range index still derives the max uint32 CID.
	got, err := vsockCID(maxVsockIndex)
	if err != nil {
		t.Fatalf("vsockCID(maxVsockIndex): %v", err)
	}
	if got != ^uint32(0) {
		t.Fatalf("vsockCID(maxVsockIndex) = %d, want %d", got, ^uint32(0))
	}
}

func TestAllocatePopulatesDeterministicVsockCID(t *testing.T) {
	plan := mustPlan(t, "10.42.0.0/16", 2)
	a, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	for i := 0; i < 4; i++ {
		b, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		want := uint32(i) + reservedVsockCIDs
		if b.VsockCID != want {
			t.Errorf("Allocate #%d VsockCID = %d, want %d (index %d + reserved %d)", i, b.VsockCID, want, i, reservedVsockCIDs)
		}
		// The recorded binding (with its CID) passes the three-keys-agree check.
		if err := b.validate(); err != nil {
			t.Errorf("Allocate #%d binding invalid: %v", i, err)
		}
	}

	// Determinism across allocator incarnations: index 42 always yields CID 45.
	a2, _ := NewAllocator(newMemCounter(42), plan)
	b, _ := a2.Allocate()
	if b.VsockCID != 42+reservedVsockCIDs {
		t.Errorf("deterministic VsockCID for index 42 = %d, want %d", b.VsockCID, 42+reservedVsockCIDs)
	}
}

func TestAllocateGuestIPDeterministicAndInRange(t *testing.T) {
	plan := mustPlan(t, "10.42.0.0/16", 2)
	a, _ := NewAllocator(newMemCounter(0), plan)
	wantIPs := []string{"10.42.0.2", "10.42.0.3", "10.42.0.4"}
	for i, want := range wantIPs {
		b, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		addr, err := b.GuestIP.Addr()
		if err != nil {
			t.Fatalf("Allocate #%d guest ip: %v", i, err)
		}
		if addr.String() != want {
			t.Errorf("Allocate #%d guest ip = %s, want %s", i, addr, want)
		}
		if b.GuestIP.Family != AddressFamilyIPv4 || len(b.GuestIP.Address) != 4 {
			t.Errorf("Allocate #%d guest ip family/width wrong: family=%d len=%d", i, b.GuestIP.Family, len(b.GuestIP.Address))
		}
	}

	// Determinism: the same index always yields the same guest IP.
	a2, _ := NewAllocator(newMemCounter(42), plan)
	b, _ := a2.Allocate()
	addr, _ := b.GuestIP.Addr()
	if addr.String() != "10.42.0.44" { // base .0 + offset 2 + index 42
		t.Errorf("deterministic guest ip for index 42 = %s, want 10.42.0.44", addr)
	}
}

// mustRoutedPlan builds an AddressPlan with RoutedTap ON. The Subnet/HostOffset are
// present (NewAllocator still requires a valid subnet) but intentionally NOT consulted
// under RoutedTap — the guest IP is the index-keyed routed-tap /31 (10.77.<idx>.1). The
// subnet here is deliberately DIFFERENT from the 10.77 scheme to prove RoutedTap ignores
// it (a leak of the SLIRP derivation would surface as a 10.42.x address).
func mustRoutedPlan(t *testing.T, cidr string, offset uint64) AddressPlan {
	t.Helper()
	p := mustPlan(t, cidr, offset)
	p.RoutedTap = true
	return p
}

// TestAllocateGuestIPRoutedTapMatchesNetConfigAndNFT is the U10 cross-source agreement
// test: under RoutedTap the recorded Binding.GuestIP is the routed-tap /31 guest end
// 10.77.<idx>.1 — IDENTICAL to U4's netConfigForIndex(idx).GuestIP (the ds-net.env the
// guest applies) and to ds-nft backend.rs's documented guest end (the dataplane tap link,
// pinned 10.77.7.1 for index 7). The allocator now consumes the SAME single source
// (netconfig.go), so the binding, the guest's net config, and the dataplane link cannot
// drift. The subnet (10.42.0.0/16) is deliberately NOT the 10.77 scheme to prove it is
// ignored under RoutedTap.
func TestAllocateGuestIPRoutedTapMatchesNetConfigAndNFT(t *testing.T) {
	plan := mustRoutedPlan(t, "10.42.0.0/16", 2)
	for _, idx := range []uint64{0, 1, 7, 255} {
		a, err := NewAllocator(newMemCounter(idx), plan)
		if err != nil {
			t.Fatalf("NewAllocator(idx=%d): %v", idx, err)
		}
		b, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate(idx=%d): %v", idx, err)
		}
		addr, err := b.GuestIP.Addr()
		if err != nil {
			t.Fatalf("Allocate(idx=%d) guest ip: %v", idx, err)
		}
		// Agree with U4's net-config single source (the bytes the guest applies).
		nc, err := netConfigForIndex(idx)
		if err != nil {
			t.Fatalf("netConfigForIndex(%d): %v", idx, err)
		}
		if addr != nc.GuestIP {
			t.Errorf("idx %d: Binding.GuestIP %s != netConfigForIndex guest %s (U4 drift)", idx, addr, nc.GuestIP)
		}
		// Agree with the literal routed-tap /31 guest end (== ds-nft backend.rs's
		// 10.77.<idx>.1, the Rust-side single source keyed on host_session_index).
		want := "10.77." + strconv.FormatUint(idx, 10) + ".1"
		if addr.String() != want {
			t.Errorf("idx %d: Binding.GuestIP = %s, want %s (== ds-nft guest end)", idx, addr, want)
		}
		// The recorded binding still passes the three-keys-agree well-formedness check
		// (10.77.<idx>.1 is a well-formed v4 — binding.validate asserts family/width, not subnet).
		if err := b.validate(); err != nil {
			t.Errorf("idx %d: routed-tap binding invalid: %v", idx, err)
		}
		if b.GuestIP.Family != AddressFamilyIPv4 || len(b.GuestIP.Address) != 4 {
			t.Errorf("idx %d: routed-tap guest ip family/width wrong: family=%d len=%d", idx, b.GuestIP.Family, len(b.GuestIP.Address))
		}
	}
}

// TestAllocateGuestIPRoutedTapFailsClosedPastCeiling asserts the routed-tap scheme
// narrows the guest-IP ceiling to the /31 third-octet (idx ≤ 255): index 255 is the
// last valid index and 256 fails closed (it would alias another session's /31), the
// SAME ceiling netConfigForIndex and ds-net.env enforce. This is a NEW (tighter than
// the tap-name IFNAMSIZ) failure mode specific to RoutedTap hosts at high index.
func TestAllocateGuestIPRoutedTapFailsClosedPastCeiling(t *testing.T) {
	plan := mustRoutedPlan(t, "10.42.0.0/16", 2)
	// 255 still allocates (the last valid /31).
	a255, err := NewAllocator(newMemCounter(255), plan)
	if err != nil {
		t.Fatalf("NewAllocator(255): %v", err)
	}
	if _, err := a255.Allocate(); err != nil {
		t.Fatalf("Allocate(idx=255) under RoutedTap must succeed (last valid /31): %v", err)
	}
	// 256 fails closed (would alias another session's /31).
	a256, err := NewAllocator(newMemCounter(256), plan)
	if err != nil {
		t.Fatalf("NewAllocator(256): %v", err)
	}
	if _, err := a256.Allocate(); err == nil {
		t.Fatal("Allocate(idx=256) under RoutedTap must fail closed (would alias another session's /31)")
	}
}

// TestAllocateGuestIPSlirpPathUnchangedUnderGate is the byte-identical guarantee: the
// DEFAULT (RoutedTap OFF) plan keeps the historical base+HostOffset+index 10.42.x
// derivation exactly — flipping RoutedTap is the ONLY thing that changes the scheme, so
// no existing SLIRP test is perturbed. (Mirrors TestAllocateGuestIPDeterministicAndInRange
// but asserts it explicitly against the gate.)
func TestAllocateGuestIPSlirpPathUnchangedUnderGate(t *testing.T) {
	plan := mustPlan(t, "10.42.0.0/16", 2) // RoutedTap defaults false
	if plan.RoutedTap {
		t.Fatal("default AddressPlan must have RoutedTap OFF (the SLIRP path)")
	}
	a, _ := NewAllocator(newMemCounter(0), plan)
	for i, want := range []string{"10.42.0.2", "10.42.0.3", "10.42.0.4"} {
		b, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		addr, _ := b.GuestIP.Addr()
		if addr.String() != want {
			t.Errorf("SLIRP path Allocate #%d guest ip = %s, want %s (must stay byte-identical)", i, addr, want)
		}
	}
}

func TestGuestIPv6RoundTrips(t *testing.T) {
	// D75 dormant Phase-C substrate must round-trip family-agnostically.
	plan := mustPlan(t, "fd00:dead:beef::/64", 2)
	a, _ := NewAllocator(newMemCounter(0), plan)
	b, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if b.GuestIP.Family != AddressFamilyIPv6 || len(b.GuestIP.Address) != 16 {
		t.Fatalf("v6 guest ip family/width wrong: family=%d len=%d", b.GuestIP.Family, len(b.GuestIP.Address))
	}
	addr, err := b.GuestIP.Addr()
	if err != nil {
		t.Fatalf("v6 guest ip: %v", err)
	}
	if addr.String() != "fd00:dead:beef::2" {
		t.Errorf("v6 guest ip = %s, want fd00:dead:beef::2", addr)
	}
}

func TestGuestIPOutOfSubnetFailsClosed(t *testing.T) {
	// A /30 holds 4 addresses (.0–.3); offset 2 leaves exactly one guest (.2),
	// then index 1 derives .3 (broadcast, still in-prefix) and index 2 overflows.
	plan := mustPlan(t, "10.0.0.0/30", 2)
	a, _ := NewAllocator(newMemCounter(0), plan)
	if _, err := a.Allocate(); err != nil {
		t.Fatalf("Allocate index 0 (.2) should succeed: %v", err)
	}
	if _, err := a.Allocate(); err != nil {
		t.Fatalf("Allocate index 1 (.3) should succeed: %v", err)
	}
	_, err := a.Allocate() // index 2 → .4, outside the /30
	if err == nil {
		t.Fatal("Allocate past the subnet must fail closed, got nil")
	}
}

func TestAllocateExhaustionFailsClosed(t *testing.T) {
	plan := mustPlan(t, "10.0.0.0/8", 0)
	// Seed one past the largest IFNAMSIZ-fitting index.
	a, _ := NewAllocator(newMemCounter(maxTapIndex+1), plan)
	_, err := a.Allocate()
	if !errors.Is(err, ErrIndexSpaceExhausted) {
		t.Fatalf("Allocate at exhaustion = %v, want ErrIndexSpaceExhausted", err)
	}
}

func TestNewAllocatorRejectsBadInputs(t *testing.T) {
	if _, err := NewAllocator(nil, mustPlan(t, "10.0.0.0/8", 0)); err == nil {
		t.Error("NewAllocator(nil counter) should fail")
	}
	if _, err := NewAllocator(newMemCounter(0), AddressPlan{}); err == nil {
		t.Error("NewAllocator(invalid subnet) should fail")
	}
}

func TestBindingValidateThreeKeysAgree(t *testing.T) {
	good := Binding{
		HostSessionIndex: 7,
		TapName:          "dstap-7",
		GuestIP:          GuestAddress{Family: AddressFamilyIPv4, Address: []byte{10, 42, 0, 9}},
		VsockCID:         10, // a well-formed allocatable CID (past the reserved 0/1/2)
	}
	if err := good.validate(); err != nil {
		t.Fatalf("good binding rejected: %v", err)
	}

	// The zero CID is the not-yet-derived sentinel (a pre-Allocate binding) and is
	// tolerated by validate() — the historical bindings carried no CID at all.
	zeroCID := good
	zeroCID.VsockCID = 0
	if err := zeroCID.validate(); err != nil {
		t.Fatalf("zero (not-yet-derived) vsock cid should be tolerated: %v", err)
	}

	bad := []Binding{
		{HostSessionIndex: 7, TapName: "", GuestIP: good.GuestIP},                                                          // no tap
		{HostSessionIndex: 7, TapName: "dstap-8", GuestIP: good.GuestIP},                                                   // tap disagrees with index
		{HostSessionIndex: 7, TapName: "dstap-7", GuestIP: GuestAddress{Family: AddressFamilyIPv4, Address: []byte{1, 2}}}, // malformed ip
		{HostSessionIndex: 7, TapName: "dstap-7", GuestIP: GuestAddress{}},                                                 // unspecified family
		{HostSessionIndex: 1234567890123, TapName: "dstap-1234567890123", GuestIP: good.GuestIP},                           // over IFNAMSIZ
		{HostSessionIndex: 7, TapName: "dstap-7", GuestIP: good.GuestIP, VsockCID: 2},                                      // reserved CID (host)
		{HostSessionIndex: 7, TapName: "dstap-7", GuestIP: good.GuestIP, VsockCID: 1},                                      // reserved CID (local)
	}
	for i, b := range bad {
		if err := b.validate(); err == nil {
			t.Errorf("bad binding #%d should be rejected (three-keys-agree)", i)
		}
	}
}
