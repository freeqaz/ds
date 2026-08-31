package libvirt

import (
	"fmt"
	"net/netip"
)

// AddressFamily tags GuestAddress so the guest address stays family-agnostic
// (D75: family-tagged bytes, never a fixed32 — the dormant Phase-C dual-stack
// substrate must round-trip without a schema break). The values mirror the
// frozen dreamserpent.hypervisor.v1.AddressFamily enum; this package carries the
// binding as DATA (the orchestrator module is stdlib-only until the proto-server
// binding lands — see doc.go and internal/nftbridge's deferred-cgo posture), so
// the host-agent create choreography is implemented here against this in-package
// shape and assembled into CloneFromImageResponse where the seam wires up.
type AddressFamily int32

const (
	// AddressFamilyUnspecified is the zero value — never a valid guest address.
	AddressFamilyUnspecified AddressFamily = 0
	// AddressFamilyIPv4 is a 4-byte guest address.
	AddressFamilyIPv4 AddressFamily = 1
	// AddressFamilyIPv6 is a 16-byte guest address (dormant Phase C, D75).
	AddressFamilyIPv6 AddressFamily = 2
)

// GuestAddress is the family-agnostic per-session guest IP (D75). It mirrors the
// frozen dreamserpent.hypervisor.v1.GuestAddress message exactly (family enum +
// raw bytes) so the in-package value and the wire message stay one shape.
type GuestAddress struct {
	// Family tags the byte width (D75) — 4 bytes for IPv4, 16 for IPv6.
	Family AddressFamily
	// Address is the raw address bytes: 4 (IPV4) or 16 (IPV6), never a fixed32.
	Address []byte
}

// guestAddressFromAddr lowers a netip.Addr into the family-tagged wire shape.
func guestAddressFromAddr(a netip.Addr) GuestAddress {
	if a.Is4() {
		b := a.As4()
		return GuestAddress{Family: AddressFamilyIPv4, Address: append([]byte(nil), b[:]...)}
	}
	b := a.As16()
	return GuestAddress{Family: AddressFamilyIPv6, Address: append([]byte(nil), b[:]...)}
}

// Addr re-reads the GuestAddress as a netip.Addr, validating the byte width
// against the family tag. A width that disagrees with the family is a malformed
// binding (the three-keys-agree precondition can never hold on it).
func (g GuestAddress) Addr() (netip.Addr, error) {
	switch g.Family {
	case AddressFamilyIPv4:
		if len(g.Address) != 4 {
			return netip.Addr{}, fmt.Errorf("ipv4 guest address must be 4 bytes, got %d", len(g.Address))
		}
		return netip.AddrFrom4([4]byte(g.Address)), nil
	case AddressFamilyIPv6:
		if len(g.Address) != 16 {
			return netip.Addr{}, fmt.Errorf("ipv6 guest address must be 16 bytes, got %d", len(g.Address))
		}
		return netip.AddrFrom16([16]byte(g.Address)), nil
	default:
		return netip.Addr{}, fmt.Errorf("guest address family unspecified")
	}
}

// Binding is the authoritative session-index join — the three keys that must
// agree (D44/D66; doc 14 §4): the never-recycled host-local index, the
// `dstap-<idx>` tap name (the authoritative join key — the NFT-2 iifname, the
// NFT-5 ct-mark key, and the LOG-2 attribution key), and the per-session guest
// IP. The host agent records this binding before the session can become routable
// (the frozen §4.1 precedence: "the binding must be recorded before routable, and
// the CloneFromImageResponse carries it"); it is the artifact both the Boundary
// tap-create RACI row and this driver cite (doc 14 §4, doc 15 §5.1).
type Binding struct {
	// HostSessionIndex is the host-local never-recycled index (D66). Its 14-bit
	// residue rides the ct mark as a disambiguator, not the primary key (D76).
	HostSessionIndex uint64
	// TapName is `dstap-<idx>` (≤15 chars IFNAMSIZ) — the authoritative join key.
	TapName string
	// GuestIP is the per-session guest address (D44/D75).
	GuestIP GuestAddress
	// VsockCID is the host-predictable AF_VSOCK guest context id for the attach
	// CONTROL channel (the m1-live-session-transport spike: the attach byte-path
	// rides vsock, no tap/IP/nft). It is derived DETERMINISTICALLY from
	// HostSessionIndex (alloc.go vsockCID), skipping the three reserved CIDs
	// 0 (hypervisor) / 1 (local loopback) / 2 (host) — so the host agent can dial
	// `guestCID:port` without round-tripping a libvirt auto-assignment, and a
	// retried create re-derives the SAME CID (idempotent on the index, like the tap
	// name and guest IP). The session domain XML pins it as
	// `<cid auto='no' address='<VsockCID>'/>` (live.go). Zero is "not yet derived"
	// (the auto-assign / pre-allocate sentinel).
	VsockCID uint32
	// OverlayPath is the per-session qcow2 overlay (D29) — delta store,
	// inspectable artifact, and durability unit. Populated at step 7.
	OverlayPath string
}

// validate asserts the structural invariants a recorded binding must satisfy
// before it can back any src-IP-keyed lookup (the three-keys-agree precondition,
// doc 14 §4): the tap name fits IFNAMSIZ and matches the index, and the guest IP
// is a well-formed family-tagged address. It does NOT assert the kernel-side
// agreement (iif / assigned guest IP / ct mark) — that is the NFT-2 runtime drop
// rule; this is the host-agent's allocation-time well-formedness check.
func (b Binding) validate() error {
	if b.TapName == "" {
		return fmt.Errorf("binding has no tap name")
	}
	if len(b.TapName) > tapNameMaxLen {
		return fmt.Errorf("tap name %q exceeds IFNAMSIZ ceiling (%d chars)", b.TapName, tapNameMaxLen)
	}
	if want := tapName(b.HostSessionIndex); b.TapName != want {
		return fmt.Errorf("tap name %q disagrees with index %d (want %q)", b.TapName, b.HostSessionIndex, want)
	}
	if _, err := b.GuestIP.Addr(); err != nil {
		return fmt.Errorf("binding guest ip: %w", err)
	}
	// The vsock CID, once derived (non-zero), must land in the allocatable range —
	// past the three reserved CIDs (0/1/2, alloc.go firstAllocatableVsockCID). A CID
	// that collides with a reserved id can never be `auto='no' address=<cid>` pinned
	// in the domain XML (libvirt rejects the reserved CIDs), so a sub-range CID is a
	// malformed binding the same way an out-of-range guest IP is. Zero is tolerated
	// here as the not-yet-derived sentinel (a pre-Allocate binding).
	if b.VsockCID != 0 && b.VsockCID < firstAllocatableVsockCID {
		return fmt.Errorf("binding vsock cid %d is in the reserved range (< %d)", b.VsockCID, firstAllocatableVsockCID)
	}
	return nil
}
