// SPDX-License-Identifier: Apache-2.0

//go:build linux

// main_test.go — OFFLINE proof of the vsock carriage-swap pieces of ds-hostbridge's
// serve mode (the host→guest control channel moved from GuestIP:4242 TCP onto AF_VSOCK
// guestCID:port, m1-live-session-transport spike). Two surfaces, both with NO live
// process, NO real vsock, NO KVM/VM/container/claude/cia:
//
//  1. the raw sockaddr_vm encoding (encodeSockaddrVM) — asserted byte-for-byte against
//     the linux/vm_sockets.h struct layout, so the raw-syscall connect path is proven
//     correct WITHOUT ever issuing a connect(2) to a guest (the real AF_VSOCK byte path is
//     operator-validated on the KVM box under DS_HOSTAGENT_LIVE);
//  2. the serve-mode CLI argument validation (runServeUDS) — a missing CID / port / UDS is
//     refused fail-closed before any dial, and the dial seam (cfg.dialGuest) is the vsock
//     dialer the production path wires.
//
// linux-tagged because AF_VSOCK + the raw dialer are linux-only; the serve mode binary
// runs on the Linux KVM host. The cross-platform fake-TCP serve_test.go (untagged) still
// drives the serveUDS core end to end over a loopback socketpair.

package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// TestEncodeSockaddrVM_Layout pins the struct sockaddr_vm byte layout the raw-syscall
// connect feeds the kernel: family (AF_VSOCK=40) at offset 0, port at offset 4, cid at
// offset 8, all native-endian, with the reserved + trailing-zero bytes zero. A wrong
// offset or endianness would silently connect to the wrong CID/port (or fail), so this is
// the load-bearing correctness proof for the dialer WITHOUT a live connect.
func TestEncodeSockaddrVM_Layout(t *testing.T) {
	const (
		cid  = uint32(0x11223344)
		port = uint32(4242)
	)
	sa := encodeSockaddrVM(cid, port)

	if len(sa) != vsockSockaddrLen || vsockSockaddrLen != 16 {
		t.Fatalf("sockaddr_vm len = %d (const %d), want 16 (struct sockaddr_vm size)", len(sa), vsockSockaddrLen)
	}

	ne := nativeEndian()
	if fam := ne.Uint16(sa[0:2]); fam != afVsock || afVsock != 40 {
		t.Errorf("svm_family @0 = %d (afVsock const %d), want 40 (AF_VSOCK)", fam, afVsock)
	}
	// svm_reserved1 @2 must be zero.
	if r := ne.Uint16(sa[2:4]); r != 0 {
		t.Errorf("svm_reserved1 @2 = %d, want 0", r)
	}
	if p := ne.Uint32(sa[4:8]); p != port {
		t.Errorf("svm_port @4 = %d, want %d", p, port)
	}
	if c := ne.Uint32(sa[8:12]); c != cid {
		t.Errorf("svm_cid @8 = %#x, want %#x", c, cid)
	}
	// svm_zero @12..15 must be zero.
	for i := 12; i < 16; i++ {
		if sa[i] != 0 {
			t.Errorf("svm_zero[%d] = %d, want 0", i, sa[i])
		}
	}
}

// TestEncodeSockaddrVM_ZeroValues proves a zero cid/port encode cleanly (only the family
// byte set) — the encoding never injects stray bytes.
func TestEncodeSockaddrVM_ZeroValues(t *testing.T) {
	sa := encodeSockaddrVM(0, 0)
	ne := nativeEndian()
	if ne.Uint16(sa[0:2]) != afVsock {
		t.Errorf("family not set on zero cid/port: %v", sa)
	}
	for i := 2; i < 16; i++ {
		if sa[i] != 0 {
			t.Errorf("byte %d non-zero on zero cid/port: %v", i, sa)
		}
	}
}

// TestRunServeUDS_RejectsMissingArgs proves serve mode fails closed before any dial when a
// required arg is absent: no UDS path, no guest CID, or no guest vsock port is an error
// (never a half-configured serve that would dial CID 0 / port 0).
func TestRunServeUDS_RejectsMissingArgs(t *testing.T) {
	cases := []struct {
		name      string
		uds       string
		cid, port uint32
		wantSub   string
	}{
		{"no-uds", "", 7, 4242, "serve-uds path"},
		{"no-cid", "/tmp/ds-x.sock", 0, 4242, "guest-vsock-cid"},
		{"no-port", "/tmp/ds-x.sock", 7, 0, "guest-vsock-port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// sessionTokenFile is irrelevant — the arg validation runs before the token read.
			err := runServeUDS("sess", tc.uds, tc.cid, tc.port, "")
			if err == nil {
				t.Fatalf("runServeUDS(%+v): expected a fail-closed error", tc)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %v, want it to name %q", err, tc.wantSub)
			}
		})
	}
}

// TestServeUDS_NoDialerFailClosed proves the serveUDS core refuses fail-closed when neither
// a dialGuest seam nor a fallback guestAddr is set (a direct caller must never stand up a
// session with no carriage). A valid token is supplied so the empty-token guard is not what
// fires.
func TestServeUDS_NoDialerFailClosed(t *testing.T) {
	err := serveUDS(t.Context(), serveUDSConfig{
		sessionUUID:  "sess",
		udsPath:      "/tmp/ds-never.sock",
		sessionToken: "deadbeef",
		// dialGuest nil AND guestAddr empty.
	})
	if err == nil {
		t.Fatal("serveUDS with no carriage dialer: expected a fail-closed error")
	}
	if !strings.Contains(err.Error(), "carriage") {
		t.Errorf("error = %v, want it to name the missing carriage dialer", err)
	}
}

// TestServeUDS_DialGuestSeamInvoked proves the production carriage runs through the
// cfg.dialGuest seam (the vsock dialer in production): a dialGuest that returns an error is
// surfaced as the dial fault, confirming serveUDS calls the seam rather than the legacy TCP
// fallback when a dialer is set. No real vsock — the seam returns a synthetic error.
func TestServeUDS_DialGuestSeamInvoked(t *testing.T) {
	// Fail fast: with the boot-race retry the synthetic dial fault must surface at
	// once, not after the production deadline.
	defer func(d time.Duration) { guestCarriageDialDeadline = d }(guestCarriageDialDeadline)
	guestCarriageDialDeadline = 0
	called := false
	err := serveUDS(t.Context(), serveUDSConfig{
		sessionUUID:  "sess",
		udsPath:      "/tmp/ds-never.sock",
		sessionToken: "deadbeef",
		dialGuest: func() (net.Conn, error) {
			called = true
			return nil, errSyntheticDial
		},
	})
	if !called {
		t.Fatal("serveUDS did not invoke the dialGuest seam (the production vsock carriage path)")
	}
	if err == nil || !strings.Contains(err.Error(), "dial guest attach carriage") {
		t.Errorf("error = %v, want the dialGuest fault surfaced", err)
	}
}

// errSyntheticDial is a fixed dial fault the dialGuest seam test returns (no real vsock).
var errSyntheticDial = &dialErr{}

type dialErr struct{}

func (*dialErr) Error() string { return "synthetic dial refused (test seam)" }

// nativeEndian returns the host byte order — the order the kernel reads the sockaddr_vm
// integers in (the C struct fields are host-endian, not network order). It detects the
// order by inspecting the in-memory byte layout of a known uint16, the SAME native write
// encodeSockaddrVM performs via unsafe.Pointer, so the test reads back what the encoder
// wrote regardless of the build host's endianness.
func nativeEndian() binary.ByteOrder {
	x := uint16(0x0102)
	b := (*[2]byte)(unsafe.Pointer(&x))
	if b[0] == 0x02 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}
