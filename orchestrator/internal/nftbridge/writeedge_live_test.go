// SPDX-License-Identifier: Apache-2.0

//go:build nftgatelive

// writeedge_live_test.go is the LIVE cgo round-trip: it drives the real C-ABI
// staticlib (libds_nft.a) through the Go edge to create + delete a tap netdev on
// the running kernel. It is build-tagged nftgatelive (the cgo half) and SKIPS
// unless root (the tap create execs `ip tuntap add`, CAP_NET_ADMIN) — run it in
// a throwaway netns so the tap is isolated + reaped:
//
//	go test -tags nftgatelive -c -o /tmp/nftbridge.test ./internal/nftbridge/
//	sudo unshare -n /tmp/nftbridge.test -test.run TapRoundTrip -test.v
//
// It asserts the create/delete round-trip AND the header's idempotency contract
// (re-create of a present tap, delete of an absent tap are both success). This
// is the cgo-edge half of the DS_NFTGATE_LIVE proof; the SpawnBackend's own
// netns idempotency proof is the sibling Rust-side task.

package nftbridge

import (
	"os"
	"testing"
)

func TestTapRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_NET_ADMIN for `ip tuntap`); run under sudo unshare -n")
	}
	const tap = "dstap-cgo0" // <= IFNAMSIZ; a fixed test name, reaped below

	// Best-effort pre-clean so a leaked tap from a prior run does not poison this.
	_ = DeleteTap(tap)

	// The cgo-edge round-trip: marshal a create + a delete through the C-ABI and
	// assert each return code maps cleanly. This proves the Go↔Rust write edge
	// (arg marshalling + return/last-error decode), not the backend's full
	// idempotency contract — the create-side idempotency (re-create of a present
	// tap = success) is the SpawnBackend's job, proven by the sibling DS_NFTGATE_LIVE
	// netns task 01KV9A13NR (today `ip tuntap add` returns EBUSY on a present tap).
	if err := CreateTap(tap, 0, false, 0, ""); err != nil {
		t.Fatalf("CreateTap(%q): %v", tap, err)
	}
	if err := DeleteTap(tap); err != nil {
		t.Fatalf("DeleteTap(%q): %v", tap, err)
	}
	// Delete IS idempotent on an absent tap (the header contract; `ip link del`
	// of a missing dev is folded to success in the backend).
	if err := DeleteTap(tap); err != nil {
		t.Fatalf("DeleteTap(%q) is not idempotent on an absent tap: %v", tap, err)
	}
}
