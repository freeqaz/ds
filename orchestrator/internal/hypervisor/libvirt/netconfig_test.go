// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"strconv"
	"strings"
	"testing"
)

// TestNetConfigForIndex asserts the per-session guest /31 derives correctly from
// the host-local index: 10.77.<idx>.1 guest, 10.77.<idx>.0 gateway, /31. The third
// octet IS the index (the U4 frozen per-session slash31 derivation, NOT the live
// AddressPlan).
func TestNetConfigForIndex(t *testing.T) {
	cases := []struct {
		index       uint64
		wantGuest   string
		wantGateway string
	}{
		{0, "10.77.0.1", "10.77.0.0"},
		{1, "10.77.1.1", "10.77.1.0"},
		{7, "10.77.7.1", "10.77.7.0"},
		{255, "10.77.255.1", "10.77.255.0"},
	}
	for _, tc := range cases {
		nc, err := netConfigForIndex(tc.index)
		if err != nil {
			t.Fatalf("netConfigForIndex(%d): %v", tc.index, err)
		}
		if got := nc.GuestIP.String(); got != tc.wantGuest {
			t.Errorf("index %d guest = %q, want %q", tc.index, got, tc.wantGuest)
		}
		if got := nc.Gateway.String(); got != tc.wantGateway {
			t.Errorf("index %d gateway = %q, want %q", tc.index, got, tc.wantGateway)
		}
		if nc.PrefixBits != netConfigGuestPrefixBits {
			t.Errorf("index %d prefix = %d, want %d", tc.index, nc.PrefixBits, netConfigGuestPrefixBits)
		}
		// The guest and gateway are the two addresses of the SAME /31 (a point-to-point
		// pair): they differ only in the final bit, so the guest reaches the gateway on-link.
		if nc.GuestIP.Prev() != nc.Gateway {
			t.Errorf("index %d: guest %s and gateway %s are not an adjacent /31 pair", tc.index, nc.GuestIP, nc.Gateway)
		}
	}
}

// TestNetConfigForIndexFailsClosedPastThirdOctet asserts the derivation FAILS CLOSED
// when the index exceeds the third-octet ceiling (255) — a wider index would alias
// another session's /31, so the render refuses rather than emit a colliding address.
func TestNetConfigForIndexFailsClosedPastThirdOctet(t *testing.T) {
	for _, idx := range []uint64{256, 257, 1000, 1 << 20} {
		if _, err := netConfigForIndex(idx); err == nil {
			t.Errorf("netConfigForIndex(%d) must fail closed (would alias another session's /31)", idx)
		}
	}
	// The boundary (255) is still valid; 256 is the first refused index.
	if _, err := netConfigForIndex(255); err != nil {
		t.Errorf("index 255 must be the last valid index, got %v", err)
	}
}

// TestRoutedTapGuestIPSingleSource asserts the U10 single source: routedTapGuestIP
// (the GuestAddress the orchestrator allocator records under RoutedTap) is the SAME
// per-session address as netConfigForIndex's guest end (the ds-net.env the guest
// applies, U4) AND the literal routed-tap /31 guest 10.77.<idx>.1 that ds-nft's
// backend.rs derives from host_session_index (the Rust-side single source — pinned
// 10.77.7.1 for index 7 there). One Go function (netconfig.go) feeds both the binding
// and the guest's net config; the Rust side keys on the same index in the third octet.
// This test is the cross-language anchor that catches drift between the two single
// sources (there is no compile-time link across the C ABI — backend.rs has no guest_ip
// parameter), so it enumerates matching indices.
func TestRoutedTapGuestIPSingleSource(t *testing.T) {
	for _, idx := range []uint64{0, 1, 7, 255} {
		ga, err := routedTapGuestIP(idx)
		if err != nil {
			t.Fatalf("routedTapGuestIP(%d): %v", idx, err)
		}
		addr, err := ga.Addr()
		if err != nil {
			t.Fatalf("routedTapGuestIP(%d) addr: %v", idx, err)
		}
		// Family-tagged v4 (the binding/wire shape D75 speaks).
		if ga.Family != AddressFamilyIPv4 || len(ga.Address) != 4 {
			t.Errorf("idx %d: family/width wrong: family=%d len=%d", idx, ga.Family, len(ga.Address))
		}
		// == U4's net-config single source (guest end + adjacent /31 gateway).
		nc, err := netConfigForIndex(idx)
		if err != nil {
			t.Fatalf("netConfigForIndex(%d): %v", idx, err)
		}
		if addr != nc.GuestIP {
			t.Errorf("idx %d: routedTapGuestIP %s != netConfigForIndex guest %s (single-source drift)", idx, addr, nc.GuestIP)
		}
		// == the literal routed-tap /31 guest end (== ds-nft backend.rs 10.77.<idx>.1,
		// gateway 10.77.<idx>.0 — the Rust-side anchor pins 10.77.7.0/31 + 10.77.7.1).
		wantGuest := "10.77." + strconv.FormatUint(idx, 10) + ".1"
		wantGateway := "10.77." + strconv.FormatUint(idx, 10) + ".0"
		if addr.String() != wantGuest {
			t.Errorf("idx %d: routedTapGuestIP = %s, want %s (ds-nft guest end)", idx, addr, wantGuest)
		}
		if nc.Gateway.String() != wantGateway {
			t.Errorf("idx %d: gateway = %s, want %s (ds-nft host gateway)", idx, nc.Gateway, wantGateway)
		}
	}
}

// TestRoutedTapGuestIPFailsClosedPastCeiling asserts routedTapGuestIP fails closed
// at the SAME third-octet ceiling as netConfigForIndex (255 ok, 256 refused) — the
// allocator's RoutedTap path inherits this ceiling, so a routed-tap host past index
// 255 fails closed rather than recording an aliasing guest IP.
func TestRoutedTapGuestIPFailsClosedPastCeiling(t *testing.T) {
	if _, err := routedTapGuestIP(255); err != nil {
		t.Errorf("routedTapGuestIP(255) must be the last valid index, got %v", err)
	}
	for _, idx := range []uint64{256, 1000, 1 << 20} {
		if _, err := routedTapGuestIP(idx); err == nil {
			t.Errorf("routedTapGuestIP(%d) must fail closed (would alias another session's /31)", idx)
		}
	}
}

// TestRenderNetConfigEnvDeterministic asserts the ds-net.env render is a pure
// function of the index (idempotent — a step-8 retry packs identical bytes) and
// carries the three guest-side keys with the derived values.
func TestRenderNetConfigEnvDeterministic(t *testing.T) {
	a, err := renderNetConfigEnvForIndex(7)
	if err != nil {
		t.Fatalf("renderNetConfigEnvForIndex(7): %v", err)
	}
	b, err := renderNetConfigEnvForIndex(7)
	if err != nil {
		t.Fatalf("renderNetConfigEnvForIndex(7) (2nd): %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("render not deterministic on the index:\n a=%q\n b=%q", a, b)
	}
	rendered := string(a)
	for _, want := range []string{
		"DS_NET_GUEST_IP=10.77.7.1\n",
		"DS_NET_PREFIX=31\n",
		"DS_NET_GATEWAY=10.77.7.0\n",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered ds-net.env missing %q:\n%s", want, rendered)
		}
	}
	// POSIX-sourceable shape: every active line is KEY=VALUE with no spaces around `=`
	// (the guest both `.`-sources and greps it, the m0-image.env convention).
	for _, line := range strings.Split(rendered, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, _, ok := strings.Cut(line, "=")
		if !ok {
			t.Errorf("active line %q is not KEY=VALUE", line)
			continue
		}
		if k == "" || strings.ContainsAny(k, " \t") {
			t.Errorf("active line %q has a malformed key", line)
		}
		if strings.HasPrefix(line, k+" =") || strings.Contains(line, "= ") {
			t.Errorf("active line %q has spaces around '=' (not POSIX-sourceable)", line)
		}
	}
}

// TestRenderNetConfigEnvForIndexFailsClosed asserts the render convenience surfaces
// the fail-closed out-of-range error (no bytes returned) so the create aborts before
// boot rather than booting a guest with a colliding net config under an active tap.
func TestRenderNetConfigEnvForIndexFailsClosed(t *testing.T) {
	raw, err := renderNetConfigEnvForIndex(256)
	if err == nil {
		t.Fatal("renderNetConfigEnvForIndex(256) must fail closed")
	}
	if raw != nil {
		t.Errorf("a fail-closed render must return no bytes, got %q", raw)
	}
}
