// SPDX-License-Identifier: Apache-2.0

// netconfig — the host-side render of the per-session GUEST static network
// config delivered as a SECOND file (ds-net.env) on the EXISTING per-session
// read-only config-drive (configdrive.go). For the VM to egress over the routed
// tap (the nft4 keystone, dataplane lane) the GUEST must configure its tap NIC
// with the static per-session address + default route; the host side (the tap +
// the per-session gateway) is U3. This file owns ONLY the host-side render of
// the guest-facing net config and its deterministic derivation from the recorded
// Binding.HostSessionIndex.
//
// PROTO IS FROZEN — NO PROTO FIELD (the unit brief): the net config is NOT a
// runtimev1.EntrypointConfig field. It rides as a small, deterministic
// key=value file (ds-net.env) the in-guest ds-apply-netcfg.sh reads — config.pb
// is untouched. This keeps the runtime contract frozen while still delivering
// the per-session L3 facts the guest needs.
//
// DERIVATION (frozen per-session slash31, NOT the live AddressPlan — see the U4
// blocker): the guest address is 10.77.<idx>.1 and the per-session gateway is
// 10.77.<idx>.0, a point-to-point /31 pair keyed on the never-recycled
// HostSessionIndex (the same join key the tap name + vsock CID derive from,
// alloc.go). The derivation is TOTAL on idx ≤ 255 (the third octet) and
// FAIL-CLOSED past it — a wider index would silently alias another session's
// /31, so the render refuses rather than emit a colliding address. The host U3
// gateway leg MUST key off this SAME derivation (the open reconciliation blocker
// in the unit report: this is NOT the live AddressPlan's 10.42.0.0/16+offset).
//
// GATED (default-path-unchanged): the second file is emitted ONLY when the
// routed tap is active (LiveConfig.RoutedTap, threaded onto EntrypointFacts).
// Off the gate (the default, SLIRP/offline) NO second file is rendered and the
// config-drive is byte-identical to the historical single-file (config.pb) drive
// — the synthetic/offline boot path is unchanged.
//
// STDLIB-ONLY (the package posture): a pure data→string render; no exec, no
// netlink, no proto. The guest applies it.

package libvirt

import (
	"fmt"
	"net/netip"
	"strings"
)

// netConfigFileName is the file the in-guest ds-apply-netcfg.sh reads off the
// mounted config-drive — the per-session static net config. It is the SECOND
// file on the SAME config-drive as config.pb (configDriveFileName); the guest
// no-ops when it is absent (the SLIRP/offline path), so the file's presence is
// itself the routed-tap signal in-guest. Replicated on the guest side
// (vm/m0-image/m0-image.env M0_NETCFG_FILE), NEVER imported (D80).
const netConfigFileName = "ds-net.env"

// netConfigGuestPrefixBits is the prefix length of the per-session point-to-point
// /31: 10.77.<idx>.0 (gateway, host side) and 10.77.<idx>.1 (guest) are the two
// addresses of a /31 (RFC 3021 point-to-point), so the guest reaches the gateway
// directly on-link with no broadcast/network reservation. A single decision point
// for the prefix; the guest renders `ip addr add <guest>/31`.
const netConfigGuestPrefixBits = 31

// netConfigBaseSecondOctet / netConfigFirstOctet name the 10.77.<idx>.x base the
// per-session /31 derives inside — the frozen per-session slash31 range (NOT the
// live AddressPlan). Kept as named constants so the one derivation is the single
// source the host U3 gateway leg must agree with.
const (
	netConfigFirstOctet       = 10
	netConfigBaseSecondOctet  = 77
	netConfigMaxIndexThirdOct = 255 // idx is the third octet; past it the /31 would alias
)

// netConfig is the host-rendered per-session guest L3 facts: the guest address,
// the per-session gateway, and the prefix. It is a pure value derived from the
// host-local index; the guest applies `ip addr add Guest/Prefix` + `ip route add
// default via Gateway`.
type netConfig struct {
	// GuestIP is the guest's static per-session address (10.77.<idx>.1).
	GuestIP netip.Addr
	// Gateway is the per-session host-side gateway (10.77.<idx>.0) — the U3 leg.
	Gateway netip.Addr
	// PrefixBits is the address prefix length (netConfigGuestPrefixBits).
	PrefixBits int
}

// netConfigForIndex derives the per-session guest net config from the
// never-recycled host-local index (Binding.HostSessionIndex). The third octet IS
// the index: 10.77.<idx>.1 guest, 10.77.<idx>.0 gateway. It FAILS CLOSED when idx
// exceeds the third-octet ceiling (255) — a wider index would alias another
// session's /31, so the render refuses rather than emit a colliding address (the
// same fail-closed posture the allocator takes on an out-of-range derivation).
// Deterministic: the same index always yields the same /31 (idempotent on
// session_uuid, like the tap name + vsock CID).
func netConfigForIndex(index uint64) (netConfig, error) {
	if index > netConfigMaxIndexThirdOct {
		return netConfig{}, fmt.Errorf("net config: host-local index %d exceeds the per-session /31 third-octet ceiling (%d) — the 10.%d.%d.<idx> derivation would alias another session (fail-closed)", index, netConfigMaxIndexThirdOct, netConfigFirstOctet, netConfigBaseSecondOctet)
	}
	third := byte(index)
	gateway := netip.AddrFrom4([4]byte{netConfigFirstOctet, netConfigBaseSecondOctet, third, 0})
	guest := netip.AddrFrom4([4]byte{netConfigFirstOctet, netConfigBaseSecondOctet, third, 1})
	return netConfig{
		GuestIP:    guest,
		Gateway:    gateway,
		PrefixBits: netConfigGuestPrefixBits,
	}, nil
}

// routedTapGuestIP is the SINGLE Go source of the per-session ROUTED-TAP guest
// address (U10). It wraps netConfigForIndex (the ONE owner of the 10.77.<idx>.0
// gateway / 10.77.<idx>.1 guest /31, fail-closed past the third-octet ceiling)
// and lowers the guest end into the family-tagged GuestAddress the AddressPlan and
// Binding speak. The orchestrator allocator (alloc.go) calls THIS under RoutedTap
// rather than re-deriving the literal, so the recorded Binding.GuestIP, the U4
// ds-net.env the guest applies (renderNetConfigEnvForIndex, same netConfigForIndex),
// and the ds-nft routed-tap link (dataplane/crates/ds-nft backend.rs, which derives
// the identical 10.77.<idx>.1 guest end from host_session_index) cannot drift — all
// three key on the index in the third octet. The Rust side has no guest_ip parameter
// across the C ABI (it is the Rust-side single source on the same convention); the
// two single sources agree by construction and a cross-language assertion lives in
// netconfig_test.go (mirroring backend.rs's pinned 10.77.7.x). Fail-closed on an
// out-of-range index, like netConfigForIndex.
func routedTapGuestIP(index uint64) (GuestAddress, error) {
	nc, err := netConfigForIndex(index)
	if err != nil {
		return GuestAddress{}, err
	}
	return guestAddressFromAddr(nc.GuestIP), nil
}

// renderNetConfigEnv renders the per-session net config as the deterministic
// key=value ds-net.env file the in-guest ds-apply-netcfg.sh reads. The shape is a
// POSIX-sourceable KEY=VALUE (no spaces around `=`, one per line) the guest both
// `.`-sources and greps — the same convention m0-image.env uses. The keys are the
// guest-side contract (replicated in vm/m0-image, never imported, D80):
//
//	DS_NET_GUEST_IP   the guest static address  (10.77.<idx>.1)
//	DS_NET_PREFIX     the prefix bits           (31)
//	DS_NET_GATEWAY    the per-session gateway   (10.77.<idx>.0)
//
// The render is byte-deterministic on the index so a step-8 retry packs the same
// bytes; a trailing newline keeps it a well-formed POSIX text file.
func renderNetConfigEnv(nc netConfig) string {
	var b strings.Builder
	b.WriteString("# ds-net.env — per-session GUEST static net config (U4).\n")
	b.WriteString("# Rendered host-side from Binding.HostSessionIndex; applied in-guest by\n")
	b.WriteString("# ds-apply-netcfg.sh BEFORE ds-entrypoint. Absent => SLIRP/offline (no-op).\n")
	b.WriteString("# config.pb is the entrypoint config; THIS file is the L3 net config only.\n")
	fmt.Fprintf(&b, "DS_NET_GUEST_IP=%s\n", nc.GuestIP.String())
	fmt.Fprintf(&b, "DS_NET_PREFIX=%d\n", nc.PrefixBits)
	fmt.Fprintf(&b, "DS_NET_GATEWAY=%s\n", nc.Gateway.String())
	return b.String()
}

// renderNetConfigEnvForIndex is the convenience the EntrypointProducer calls: it
// derives the per-session /31 from the index and renders the ds-net.env bytes
// (fail-closed on an out-of-range index). The bytes are the SECOND config-drive
// file; an error aborts the create before boot rather than booting a guest with a
// colliding/absent net config under an active routed tap.
func renderNetConfigEnvForIndex(index uint64) ([]byte, error) {
	nc, err := netConfigForIndex(index)
	if err != nil {
		return nil, err
	}
	return []byte(renderNetConfigEnv(nc)), nil
}
