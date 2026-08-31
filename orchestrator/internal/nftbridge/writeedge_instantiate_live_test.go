// SPDX-License-Identifier: Apache-2.0

//go:build nftgatelive

// writeedge_instantiate_live_test.go is the LIVE proof of the FULL per-session
// AttachPrimitive nft setup over the cgo edge — CreateTap (with routed addressing)
// + InstantiateSession (the Model-A admit surface). It validates the landed
// inet-ds_filter bootstrap fix (#4991): instantiate self-ensures `table inet
// ds_filter` then creates the two empty per-session allow-sets, so it no longer
// fails on a missing table. It runs ROOTLESS — `unshare -rn` maps the caller to
// root in a fresh user+net namespace, giving CAP_NET_ADMIN with NO sudo and full
// isolation from the host's own networking:
//
//	go test -tags nftgatelive -c -o /tmp/nftbridge.test ./internal/nftbridge/
//	unshare -rn /tmp/nftbridge.test -test.run InstantiateSessionLive -test.v

package nftbridge

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInstantiateSessionLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs CAP_NET_ADMIN — run under `unshare -rn` (rootless, no sudo) or `sudo unshare -n`")
	}
	const (
		idx = uint32(7)
		tap = "dstap-7"
	)
	// Pre-clean (idempotent).
	_ = TeardownSession(tap, idx)
	_ = DeleteTap(tap)

	// 1. CreateTap with the per-session index → tap + 10.77.<idx>.0/31 routing.
	if err := CreateTap(tap, 0, false, idx, ""); err != nil {
		t.Fatalf("CreateTap(%q, idx=%d): %v", tap, idx, err)
	}
	t.Cleanup(func() {
		_ = TeardownSession(tap, idx)
		_ = DeleteTap(tap)
	})

	// 2. InstantiateSession — the load-bearing assertion: with the ds_filter fix it
	// self-ensures the table (no pre-existing `inet ds_filter`) and creates the two
	// empty per-session allow-sets. BEFORE #4991 this failed "nft -f: No such file".
	if err := InstantiateSession(tap, idx); err != nil {
		t.Fatalf("InstantiateSession(%q, idx=%d) — the #4991 ds_filter self-ensure should make this succeed on a host with NO pre-existing inet ds_filter: %v", tap, idx, err)
	}

	// 3. Verify the per-session admit surface exists in inet ds_filter.
	out, err := exec.Command("nft", "list", "table", "inet", "ds_filter").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table inet ds_filter: %v\n%s", err, out)
	}
	for _, set := range []string{"allow4_7", "allow6_7"} {
		if !strings.Contains(string(out), set) {
			t.Errorf("inet ds_filter is missing the per-session set %q; got:\n%s", set, out)
		}
	}

	// 4. Idempotency: a re-instantiate (and a second session's instantiate) must NOT
	// clear the table — re-run and confirm allow4_7 still present.
	if err := InstantiateSession(tap, idx); err != nil {
		t.Fatalf("InstantiateSession re-run (idempotent): %v", err)
	}
	out2, _ := exec.Command("nft", "list", "table", "inet", "ds_filter").CombinedOutput()
	if !strings.Contains(string(out2), "allow4_7") {
		t.Errorf("re-instantiate cleared allow4_7 (the add-table-must-not-clear property); got:\n%s", out2)
	}
}
