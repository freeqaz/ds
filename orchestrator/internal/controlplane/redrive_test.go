package controlplane

// redrive_test.go exercises the §3 rule-b host-side RE-CREATE continuation
// (redrive.go) — specifically the D73 invariant the unit owns: a re-driven MISSING VM
// is declared CONVERGED only when it is FULLY ROUTABLE, i.e. its §4.1 step-6
// session-scoped digests are re-written AND re-acked (doc 15 §4.1: "the session cannot
// become routable until this ack lands"; the §4.1 step-9 routable gate holds only when
// {step 3, step 6} do). The host-side re-create lost its digest state with the missing
// domain, so re-materializing the domain (step 4) without re-acking the digest (step 6)
// would leave a HALF-CONVERGED VM the create gate would have refused.
//
// D50: synthetic fixtures + recording fakes ONLY — no live VM/host-agent/podman. The
// fakes (fakeRegistry/fakeMint/fakeDigest/fakeInject/fakeBoot/newDriverFake) are the
// in-package synthetic seams fixtures_test.go declares; this file adds only the narrow
// launching_user resolver fake the continuation reads.

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// reCreateResolverFake satisfies launchingUserResolverSeam: it reports the record's
// launching principal as STILL LINKED (the re-drive's premise, doc 16 §3.1) unless
// unlinked is set (the nullable/system-session arm the continuation refuses pre-mint).
type reCreateResolverFake struct {
	unlinked bool
	err      error
}

func (r reCreateResolverFake) ResolveLaunchingUserClaim(_ context.Context, _ string) (store.LaunchingUserClaim, bool, error) {
	if r.err != nil {
		return store.LaunchingUserClaim{}, false, r.err
	}
	if r.unlinked {
		return store.LaunchingUserClaim{}, false, nil
	}
	return store.LaunchingUserClaim{Subject: "okta|ada"}, true, nil
}

// reCreateRecord is a host-resident MISSING-VM record (rule b): its SessionRef quartet
// is bound to testHostID, so the host-side re-create has a target. The spine cluster is
// assumed already re-asserted (the continuation's contract); we pass a minimal spine
// result carrying the step-5 mint claims the re-mint consumes.
func reCreateRecord() store.Session {
	return store.Session{
		Ref: store.SessionRef{
			SessionUUID: "sess-redrive-1",
			HostID:      testHostID,
		},
		EnvConfigRef: testEnvRef,
		ImageID:      testImageID,
	}
}

// spineResult is a minimal re-asserted spine result (the SpineRunner's output). The
// continuation reads only spine.MintClaims.{Claims,RoleRef} for the re-mint.
func spineResult() sessions.CreateSpineResult {
	return sessions.CreateSpineResult{
		MintClaims: sessions.CreateStep5Result{RoleRef: "default@2026.06.11-v1"},
	}
}

// newReCreate builds the host-side re-create continuation over the synthetic seams, with
// the §4.1 step-6 digest re-write+re-ack wired (withDigestReAck) — the production-shaped
// construction, only the live edges replaced by fakes (D50).
func newReCreate(t *testing.T, digest *fakeDigest, inject *fakeInject, boot *fakeBoot) hostReCreate {
	t.Helper()
	reg := fakeRegistry{host: testHostID, drv: newDriverFake()}
	return newHostReCreate(reg, &fakeMint{}, inject, boot, reCreateResolverFake{}, nil,
		withDigestReAck(digest))
}

// TestRedriveReWritesAndReAcksDigestBeforeConverged proves the rule-b re-drive
// re-writes + re-ACKS the session-scoped digest (step 6, D73) on the re-create path,
// and only then declares the VM converged (reCreate returns nil) — the re-driven VM is
// ROUTABLE, not half-converged. It also asserts the §4.1 step ordering: the digest
// re-ack precedes the routable-gate steps (inject/boot ran), and the re-mint that
// supplies the digest's CA ref ran first (5 ≺ 6).
func TestRedriveReWritesAndReAcksDigestBeforeConverged(t *testing.T) {
	digest := &fakeDigest{acked: true} // the host ACKs (the routable gate's premise)
	inject := &fakeInject{}
	boot := &fakeBoot{}
	h := newReCreate(t, digest, inject, boot)

	if err := h.reCreate(context.Background(), reCreateRecord(), spineResult()); err != nil {
		t.Fatalf("reCreate (acked digest) should converge, got: %v", err)
	}

	// The digest was re-written + re-acked on the re-drive path (the D73 invariant).
	if digest.calls != 1 {
		t.Fatalf("expected exactly one digest re-write+ack on the re-drive path, got %d", digest.calls)
	}
	// Step ordering held: the routable-gate steps (inject step 7, boot step 8) ran AFTER
	// the digest re-ack — a converged VM is fully routable, not a half-converged one.
	if inject.calls != 1 {
		t.Fatalf("expected CA re-inject (step 7) after the digest re-ack, got %d calls", inject.calls)
	}
	if boot.calls != 1 {
		t.Fatalf("expected re-boot (step 8) after the digest re-ack, got %d calls", boot.calls)
	}
}

// TestRedriveNotConvergedWhenDigestReAckDoesNotLand proves that a re-drive whose digest
// re-ACK does NOT land does NOT declare the VM converged/routable (D73): the write
// succeeds but the host never acks, so reCreate fails with sessions.ErrDigestNotAcked
// (the structural step-9 refusal), the reconciler takes the §3 rule-b fail arm rather
// than declaring a not-routable VM converged. The boot (step 8) must NOT run — the
// re-drive halts at the unacked step-6 gate.
func TestRedriveNotConvergedWhenDigestReAckDoesNotLand(t *testing.T) {
	digest := &fakeDigest{acked: false} // written, but the host NEVER acks
	inject := &fakeInject{}
	boot := &fakeBoot{}
	h := newReCreate(t, digest, inject, boot)

	err := h.reCreate(context.Background(), reCreateRecord(), spineResult())
	if err == nil {
		t.Fatal("reCreate with an UNACKED digest must NOT declare the VM converged (D73)")
	}
	if !errors.Is(err, sessions.ErrDigestNotAcked) {
		t.Fatalf("expected the D73 structural refusal sessions.ErrDigestNotAcked, got: %v", err)
	}
	// The digest write was attempted (step 6), but the routable-gate continuation halted:
	// boot (step 8) never ran on a not-routable VM.
	if digest.calls != 1 {
		t.Fatalf("expected the digest write to be attempted once, got %d", digest.calls)
	}
	if boot.calls != 0 {
		t.Fatalf("re-boot (step 8) must NOT run when the digest re-ack did not land, got %d boots", boot.calls)
	}
}

// TestRedriveDigestReAckFaultFailsConverge proves a digest WRITE fault (the seam errors,
// distinct from a clean write that is not acked) also fails the re-drive — the
// continuation surfaces it so the reconciler does not declare a VM with no re-written
// digest converged.
func TestRedriveDigestReAckFaultFailsConverge(t *testing.T) {
	wantErr := errors.New("identity digest face unreachable")
	digest := &fakeDigest{err: wantErr}
	boot := &fakeBoot{}
	h := newReCreate(t, digest, &fakeInject{}, boot)

	err := h.reCreate(context.Background(), reCreateRecord(), spineResult())
	if err == nil {
		t.Fatal("a digest re-write fault must fail the re-drive, not declare converged")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the digest fault to be surfaced, got: %v", err)
	}
	if boot.calls != 0 {
		t.Fatalf("re-boot (step 8) must NOT run on a digest re-write fault, got %d boots", boot.calls)
	}
}

// TestRedriveDigestReAckIdempotentOnReDrive proves the digest re-write+re-ack is
// idempotent on session_uuid: a SECOND re-drive of the same record (the reconciler's
// next tick) re-writes+re-acks again and re-converges cleanly — never a double-create,
// never a refusal on the already-back VM (the level-triggered convergence contract).
func TestRedriveDigestReAckIdempotentOnReDrive(t *testing.T) {
	digest := &fakeDigest{acked: true}
	h := newReCreate(t, digest, &fakeInject{}, &fakeBoot{})

	rec, spine := reCreateRecord(), spineResult()
	if err := h.reCreate(context.Background(), rec, spine); err != nil {
		t.Fatalf("first re-drive should converge, got: %v", err)
	}
	if err := h.reCreate(context.Background(), rec, spine); err != nil {
		t.Fatalf("second re-drive (idempotent on session_uuid) should re-converge, got: %v", err)
	}
	if digest.calls != 2 {
		t.Fatalf("expected the digest re-ack on BOTH re-drive ticks (idempotent), got %d", digest.calls)
	}
}

// TestRedriveNoBoundHostSkipsDigestReAck proves a record that never reached the
// host-side steps (no bound host) is the spine-cluster-only convergence case: the
// host re-create (and the digest re-ack) is deferred to the next observed cycle, NOT a
// failure. Rule-a/rule-c arms are untouched — this is purely the rule-b no-bound-host
// branch behaving as before the digest re-ack was added.
func TestRedriveNoBoundHostSkipsDigestReAck(t *testing.T) {
	digest := &fakeDigest{acked: true}
	boot := &fakeBoot{}
	h := newReCreate(t, digest, &fakeInject{}, boot)

	rec := reCreateRecord()
	rec.Ref.HostID = "" // never reached step 4: no bound host
	if err := h.reCreate(context.Background(), rec, spineResult()); err != nil {
		t.Fatalf("no-bound-host re-drive is a deferred no-op success, got: %v", err)
	}
	if digest.calls != 0 {
		t.Fatalf("no-bound-host re-drive must NOT re-ack a digest (deferred), got %d", digest.calls)
	}
	if boot.calls != 0 {
		t.Fatalf("no-bound-host re-drive must NOT boot, got %d", boot.calls)
	}
}

// TestRedriveUnlinkedPrincipalRefusesBeforeDigest proves the nullable/system-session
// arm: a record whose launching principal is no longer linked is refused
// (ErrRedriveNoLaunchingUser) BEFORE any re-mint or digest re-write — a dangling link
// never re-acks a digest for a placeholder (doc 16 §3.1).
func TestRedriveUnlinkedPrincipalRefusesBeforeDigest(t *testing.T) {
	digest := &fakeDigest{acked: true}
	reg := fakeRegistry{host: testHostID, drv: newDriverFake()}
	mint := &fakeMint{}
	h := newHostReCreate(reg, mint, &fakeInject{}, &fakeBoot{}, reCreateResolverFake{unlinked: true}, nil,
		withDigestReAck(digest))

	err := h.reCreate(context.Background(), reCreateRecord(), spineResult())
	if !errors.Is(err, sessions.ErrRedriveNoLaunchingUser) {
		t.Fatalf("expected ErrRedriveNoLaunchingUser for an unlinked principal, got: %v", err)
	}
	if mint.calls != 0 {
		t.Fatalf("an unlinked-principal re-drive must NOT re-mint, got %d mints", mint.calls)
	}
	if digest.calls != 0 {
		t.Fatalf("an unlinked-principal re-drive must NOT re-ack a digest, got %d", digest.calls)
	}
}

// TestRedriveWithoutDigestSeamConvergesWithoutReAck pins the pre-D73 convergence-only
// posture: with NO digest seam wired (withDigestReAck omitted — the current production
// wiring closure), the continuation re-materializes the VM but does not re-ack a digest,
// leaving it to the next observed cycle. This documents the seam is OPTIONAL and that
// installing it at the wiring site is what makes a re-driven VM fully routable.
func TestRedriveWithoutDigestSeamConvergesWithoutReAck(t *testing.T) {
	digest := &fakeDigest{acked: true}
	reg := fakeRegistry{host: testHostID, drv: newDriverFake()}
	boot := &fakeBoot{}
	// No withDigestReAck option — the digest seam is unwired.
	h := newHostReCreate(reg, &fakeMint{}, &fakeInject{}, boot, reCreateResolverFake{}, nil)

	if err := h.reCreate(context.Background(), reCreateRecord(), spineResult()); err != nil {
		t.Fatalf("unwired-digest re-drive should still converge host-side, got: %v", err)
	}
	if digest.calls != 0 {
		t.Fatalf("an unwired digest seam must not be driven, got %d", digest.calls)
	}
	if boot.calls != 1 {
		t.Fatalf("the host re-create still boots when the digest seam is unwired, got %d", boot.calls)
	}
}
