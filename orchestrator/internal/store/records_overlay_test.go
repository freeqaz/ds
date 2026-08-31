package store

import (
	"context"
	"testing"
)

// TestIndexEpoch_OverlayPathPersistsAcrossRestart pins the destroy-path durability
// fix: the per-session CoW overlay path (D29) recorded on the open IndexEpoch
// (doc 15 §4.1 step 4/7) round-trips through AppendIndexEpoch → GetSession, so the
// §4.2 teardown can dispose the REAL overlay AFTER a control-plane restart (the
// in-process create-time HostAllocation.OverlayPath does not survive a restart — the
// destroy must read it from the durable record). A "simulated restart" is a fresh
// GetSession that reads ONLY what was persisted (no create-local state in scope).
func TestIndexEpoch_OverlayPathPersistsAcrossRestart(t *testing.T) {
	repo := NewMemoryClock(fixedClock(baseTime))
	ctx := context.Background()

	if _, err := repo.CreateSession(ctx, newSession("sess-ov", "host-a", 1)); err != nil {
		t.Fatalf("create: %v", err)
	}

	const overlay = "/var/lib/ds/overlays/sess-ov.qcow2"
	if _, err := repo.AppendIndexEpoch(ctx, "sess-ov", IndexEpoch{
		HostID:           "host-a",
		HostSessionIndex: 7,
		TapName:          "dstap-7",
		GuestIP:          []byte{10, 0, 0, 7},
		GuestIPFamily:    IPFamilyV4,
		OverlayPath:      overlay,
	}); err != nil {
		t.Fatalf("append index epoch: %v", err)
	}

	// SIMULATED RESTART: a fresh read of the persisted record (no create-local state).
	got, err := repo.GetSession(ctx, "sess-ov")
	if err != nil {
		t.Fatalf("get after append: %v", err)
	}

	// The open (current) epoch must carry the overlay the §4.2 teardown disposes.
	var open *IndexEpoch
	for i := range got.IndexHistory {
		if got.IndexHistory[i].EndedAt == nil {
			open = &got.IndexHistory[i]
		}
	}
	if open == nil {
		t.Fatalf("no open index epoch after append; history=%+v", got.IndexHistory)
	}
	if open.OverlayPath != overlay {
		t.Fatalf("persisted overlay path: got %q, want %q", open.OverlayPath, overlay)
	}
	if open.HostSessionIndex != 7 || open.TapName != "dstap-7" {
		t.Fatalf("open epoch binding lost: idx=%d tap=%q", open.HostSessionIndex, open.TapName)
	}
}

// TestIndexEpoch_OverlayPathDeepCopied proves the store hands out its own copy of the
// epoch history (cloneEpochs), so a caller mutating the returned slice never corrupts
// the persisted overlay path — the store-never-aliases discipline, asserted on the new
// durability field.
func TestIndexEpoch_OverlayPathDeepCopied(t *testing.T) {
	repo := NewMemoryClock(fixedClock(baseTime))
	ctx := context.Background()
	if _, err := repo.CreateSession(ctx, newSession("sess-cp", "host-a", 1)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := repo.AppendIndexEpoch(ctx, "sess-cp", IndexEpoch{
		HostID:           "host-a",
		HostSessionIndex: 3,
		TapName:          "dstap-3",
		GuestIP:          []byte{10, 0, 0, 3},
		GuestIPFamily:    IPFamilyV4,
		OverlayPath:      "/overlays/orig.qcow2",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	first, err := repo.GetSession(ctx, "sess-cp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// Mutate the returned copy — must not affect the store.
	for i := range first.IndexHistory {
		first.IndexHistory[i].OverlayPath = "/overlays/tampered.qcow2"
	}

	second, err := repo.GetSession(ctx, "sess-cp")
	if err != nil {
		t.Fatalf("re-get: %v", err)
	}
	for i := range second.IndexHistory {
		if second.IndexHistory[i].EndedAt == nil && second.IndexHistory[i].OverlayPath != "/overlays/orig.qcow2" {
			t.Fatalf("store overlay path was corrupted by a caller mutation: %q", second.IndexHistory[i].OverlayPath)
		}
	}
}
