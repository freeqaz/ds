// SPDX-License-Identifier: Apache-2.0

// The LIVE re-key orchestration (doc 16 §6.3 default d; §6.1 mint-before-attach).
//
// A live re-key — triggered by a host redeploy (KeyManager.Rekey) or a scheduled
// roll (KeyManager.Rotate) where existing sessions must keep their protection —
// must re-push EVERY live digest under the new key BEFORE the old key is retired,
// so a session never sees a window in which neither key shadows its credentials.
// That is the mint-before-attach invariant applied to a re-key rather than a
// session create: the new-key digests are published + acked first; only then is
// the old key dropped. This file orchestrates that ordering; it computes nothing
// new (the digests come from a Producer minted for the new key) and invents no
// new wire verb (it drives the frozen PublishSession over the §9 seam).
//
// SCOPE FENCE: which sessions are live, and the larger redeploy choreography, are
// the orchestrator's (doc 15). This file consumes a caller-supplied snapshot of
// live sessions and supplies the identity-side re-push + retire ordering — it
// does not enumerate sessions or own the host-redeploy sequence.
package digest

import (
	"context"
	"errors"
	"fmt"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// LiveSession is one session whose digests must survive a live re-key: its UUID
// plus the credentials whose digests are currently live for it. The credentials
// are the SAME inputs the original mint-before-attach publish used (the caller
// holds them in the trust zone for exactly this re-push); their plaintext is
// digested under the new key and dropped, never retained (the Producer contract).
type LiveSession struct {
	SessionUUID string
	Creds       []Credential
}

// RekeyResult reports the outcome of a live re-key. NewKeyID is the key id every
// session was re-pushed under; Republished is the per-session publish results
// (all Routable on success); OldKeyRetired is true iff the old key was dropped
// (only after every re-push acked committed). On any failure OldKeyRetired is
// false and the old key is LEFT live — fail-closed: a partial re-key keeps the
// old digests shadowing the fleet rather than opening a gap.
type RekeyResult struct {
	NewKeyID      string
	OldKeyID      string
	Republished   []PublishResult
	OldKeyRetired bool
}

// LiveRekey re-pushes every live session's digests under the manager's ACTIVE
// (new) key, ack-gating each publish, and retires oldKeyID only after ALL acks
// are committed — preserving mint-before-attach across the flip (doc 16 §6.3
// default d).
//
// Pre-state: the caller has already advanced the manager (Rotate/Rekey), so
// m.Current() is the NEW key and oldKeyID is in the retiring set. LiveRekey
// derives the new-key Producer, publishes each session's set under it, and on
// full success calls RetireKey(oldKeyID). batchIDFor names the publish batch per
// session (so the host-side ack provenance is traceable, doc 16 §6.5).
//
// Fail-closed ordering (the no-gap guarantee):
//  1. Build + publish every session under the NEW key; require each ack
//     committed (PublishSession is itself fail-closed on an uncommitted ack /
//     transport error).
//  2. ONLY after every session acked committed, retire the OLD key.
//
// If any publish fails, LiveRekey returns the error WITHOUT retiring the old key
// — every session is still shadowed by the old digests (no gap), and the caller
// retries or aborts the redeploy. A session is therefore never, at any instant,
// unshadowed by both keys.
func (m *KeyManager) LiveRekey(
	ctx context.Context,
	client identityv1.DigestFeedServiceClient,
	oldKeyID string,
	sessions []LiveSession,
	batchIDFor func(sessionUUID string) string,
) (RekeyResult, error) {
	res := RekeyResult{NewKeyID: m.ActiveKeyID(), OldKeyID: oldKeyID}

	if client == nil {
		return res, errors.New("digest: nil feed client (fail-closed)")
	}
	if oldKeyID == "" {
		return res, errors.New("digest: empty old key id (fail-closed)")
	}
	if oldKeyID == m.ActiveKeyID() {
		return res, errors.New("digest: old key id equals the active key id — advance the manager (Rotate/Rekey) before LiveRekey")
	}
	if _, ok := m.retiring[oldKeyID]; !ok {
		// The old key must be in the retiring set: that is the proof the manager
		// was advanced and the old key is genuinely the one being retired.
		return res, fmt.Errorf("digest: old key %q is not retiring — advance the manager first (fail-closed)", oldKeyID)
	}
	if batchIDFor == nil {
		return res, errors.New("digest: nil batchIDFor (fail-closed)")
	}

	// New-key Producer: every re-pushed entry carries the NEW key id.
	prod, err := m.Producer()
	if err != nil {
		return res, fmt.Errorf("digest: mint new-key producer: %w (fail-closed)", err)
	}

	// STEP 1 — publish every live session under the new key; each ack-gated.
	res.Republished = make([]PublishResult, 0, len(sessions))
	for _, s := range sessions {
		if s.SessionUUID == "" {
			return res, errors.New("digest: empty session uuid in re-key set (fail-closed)")
		}
		if len(s.Creds) == 0 {
			// A live session with no credentials has nothing to shadow; skip it
			// rather than fail the whole re-key (it has no digest to lose).
			continue
		}
		pr, err := PublishSession(ctx, client, prod, s.SessionUUID, s.Creds, batchIDFor(s.SessionUUID))
		if err != nil {
			// Fail-closed: leave the OLD key live (every session still shadowed).
			return res, fmt.Errorf("digest: live re-key re-push for session %q: %w (old key %q NOT retired, no gap)",
				s.SessionUUID, err, oldKeyID)
		}
		res.Republished = append(res.Republished, pr)
	}

	// STEP 2 — every re-push acked committed; now and only now retire the old key.
	if err := m.RetireKey(oldKeyID); err != nil {
		return res, fmt.Errorf("digest: retire old key after re-push: %w", err)
	}
	res.OldKeyRetired = true
	return res, nil
}

// RetireOldKeyViaRevoke is the optional companion to LiveRekey for callers that
// also want the boundary to FLUSH the old-key digests (not merely stop selecting
// them) once the re-push is done — e.g. to bound the §6.3 oracle window on a
// retiring host. It is a thin sequencing helper over the frozen RevokeSession
// verb: revoke the old key id for each session, fail-closed on any uncommitted
// ack (a flush that did not confirm leaves stale digests). It MUST run only
// AFTER LiveRekey returned OldKeyRetired (the new digests are live + acked), so
// the revoke can never open a gap.
//
// It does not itself re-push; it assumes LiveRekey already did. Calling it before
// a successful LiveRekey would flush the only digests shadowing a session — so it
// refuses if oldKeyID is still in the retiring set (i.e. LiveRekey has not run).
func (m *KeyManager) RetireOldKeyViaRevoke(
	ctx context.Context,
	client identityv1.DigestFeedServiceClient,
	oldKeyID string,
	sessions []LiveSession,
) error {
	if client == nil {
		return errors.New("digest: nil feed client (fail-closed)")
	}
	if oldKeyID == "" {
		return errors.New("digest: empty old key id (fail-closed)")
	}
	if _, ok := m.retiring[oldKeyID]; ok {
		return fmt.Errorf("digest: old key %q still retiring — run LiveRekey first so the new digests are live before flushing the old (fail-closed, no gap)", oldKeyID)
	}
	if oldKeyID == m.ActiveKeyID() {
		return errors.New("digest: refusing to revoke the ACTIVE key (fail-closed)")
	}
	for _, s := range sessions {
		if s.SessionUUID == "" || len(s.Creds) == 0 {
			continue
		}
		if err := RevokeSession(ctx, client, s.SessionUUID, []string{oldKeyID}); err != nil {
			return fmt.Errorf("digest: flush old key %q for session %q: %w", oldKeyID, s.SessionUUID, err)
		}
	}
	return nil
}

// ----- fleet-scope re-key leg (the SECOND cadence; doc 16 §6.2, D72) --------
//
// LiveRekey (above) re-pushes SESSION-scope digests over the DigestFeedService
// seam. But fleet-scope forbidden-class digests are NOT session-lifecycle data:
// they are POLICY ARTIFACTS carried under the `policy_log` seq on a different
// cadence (the one-per-host WatchPolicies sweep) — "two cadences, no third
// channel" (D72, doc 16 §6.2). A key rotation/re-key must therefore ALSO
// re-register the fleet-scope digest set under the NEW key over the policy
// stream; without this leg a rotation strands the fleet digests under the
// retired key (matchable nowhere once that key is dropped). This is the leg that
// closes that gap — and it rides the SAME policy-log path the fleet digests
// always rode, never a third channel.
//
// SCOPE FENCE: which forbidden-class credentials make up the fleet set, and the
// larger policy-authoring choreography, are the orchestrator's. This leg
// consumes a caller-supplied snapshot of the live fleet credentials (the same
// inputs the original fleet registration used) and supplies the identity-side
// re-derive + re-register + retire ORDERING over the policy stream.

// FleetRekeyResult reports the outcome of a fleet-scope re-key. NewKeyID is the
// key id the fleet set was re-registered under; NewArtifact is the committed
// policy result for the new-key registration (its assigned `policy_log` seq);
// OldKeyRetired is true iff the old fleet key's artifact was retired (only after
// the new artifact committed). On any failure OldKeyRetired is false and the old
// fleet key is LEFT registered — fail-closed: a partial fleet re-key keeps the
// old fleet digests shadowing rather than opening a gap, exactly like LiveRekey.
type FleetRekeyResult struct {
	NewKeyID      string
	OldKeyID      string
	NewArtifact   FleetPolicyResult
	OldKeyRetired bool
}

// LiveRekeyFleet re-derives the fleet-scope digest set under the manager's
// ACTIVE (new) key and re-registers it as a POLICY ARTIFACT over the policy
// stream, then retires the old fleet key's artifact — new registered + committed
// BEFORE old retired, so the fleet digests are never stranded under a retired
// key (mint-before-attach applied to the fleet cadence, doc 16 §6.2/§6.3).
//
// Pre-state (identical contract to LiveRekey): the caller has already advanced
// the manager (Rotate/Rekey), so m.Current() is the NEW key and oldKeyID is in
// the retiring set. fleetCreds is the live fleet-scope (forbidden-class)
// credential set — every entry MUST carry Scope == DIGEST_SCOPE_FLEET (asserted
// by the producer's FleetBatchEntries; a session-scope entry here is fail-closed,
// honoring D72's no-cadence-crossing). newBatchID / oldBatchID name the policy
// appends for ack provenance (doc 16 §6.5).
//
// Fail-closed ordering (the no-gap guarantee):
//  1. Re-derive the fleet set under the NEW key and append it as a policy
//     artifact; require the apply COMMITTED (PublishFleetPolicy is fail-closed on
//     an uncommitted policy-apply / sink error).
//  2. ONLY after the new artifact committed, retire the OLD fleet key by
//     appending an empty-entry retire artifact (RevokeFleetPolicy), then drop the
//     key from the lifecycle's retiring set (RetireKey).
//
// If the new-key registration fails, the old fleet key is NEITHER revoked NOR
// dropped — the fleet remains shadowed by the old fleet digests (no gap), and the
// caller retries or aborts. The retire-side append running only after step 1
// commits is what guarantees no instant in which the fleet is shadowed by neither
// key.
//
// This leg is INDEPENDENT of LiveRekey's session leg (different cadence, D72): a
// full rotation runs BOTH — LiveRekey for the session digests over
// DigestFeedService, LiveRekeyFleet for the fleet digests over the policy stream
// — and neither touches the other's channel.
func (m *KeyManager) LiveRekeyFleet(
	ctx context.Context,
	sink PolicySink,
	oldKeyID string,
	fleetCreds []Credential,
	newBatchID string,
	oldBatchID string,
) (FleetRekeyResult, error) {
	res := FleetRekeyResult{NewKeyID: m.ActiveKeyID(), OldKeyID: oldKeyID}

	if sink == nil {
		return res, errors.New("digest: nil policy sink (fail-closed)")
	}
	if oldKeyID == "" {
		return res, errors.New("digest: empty old key id (fail-closed)")
	}
	if oldKeyID == m.ActiveKeyID() {
		return res, errors.New("digest: old key id equals the active key id — advance the manager (Rotate/Rekey) before LiveRekeyFleet")
	}
	// Proof the manager was advanced past the old key: the old key must be EITHER
	// still in the retiring set (the common case — neither leg has dropped it yet)
	// OR already dropped while the manager sits at a strictly-advanced coordinate
	// (epoch+generation > 0). The latter is the full-rotation case where the
	// SESSION leg (LiveRekey) already retired the SHARED lifecycle key — the fleet
	// leg must still re-register + retire its own policy-stream artifact, so it
	// proceeds rather than refusing. It never accepts a never-rotated manager
	// (epoch+gen == 0), which would be a phantom old key id.
	if _, retiring := m.retiring[oldKeyID]; !retiring {
		if m.current.Epoch == 0 && m.current.Generation == 0 {
			return res, fmt.Errorf("digest: old key %q is not retiring and the manager never advanced — advance it first (fail-closed)", oldKeyID)
		}
	}
	if len(fleetCreds) == 0 {
		// No fleet digests to carry. Nothing to re-register — and so nothing to
		// strand. Return cleanly WITHOUT touching the old key: the lifecycle's
		// retiring-set bookkeeping for it belongs to the session leg / caller, and
		// silently retiring it here could drop a key the session leg still needs.
		return res, nil
	}

	// New-key Producer: the re-derived fleet set carries the NEW key id.
	prod, err := m.Producer()
	if err != nil {
		return res, fmt.Errorf("digest: mint new-key producer: %w (fail-closed)", err)
	}

	// STEP 1 — re-derive + re-register the fleet set under the NEW key over the
	// policy stream; commit-gated (PublishFleetPolicy fails closed on a
	// non-committed apply / sink error).
	newRes, err := PublishFleetPolicy(ctx, sink, prod, fleetCreds, newBatchID)
	if err != nil {
		// Fail-closed: the OLD fleet key is left registered (the fleet is still
		// shadowed under it — no gap).
		return res, fmt.Errorf("digest: fleet re-key new-key registration: %w (old fleet key %q NOT retired, no gap)",
			err, oldKeyID)
	}
	res.NewArtifact = newRes

	// STEP 2 — the new fleet artifact is applied; now and only now retire the old
	// fleet key's policy artifact. Append the retire (empty-entry) artifact: the
	// policy revocation-sweep drops the old fleet digests.
	if _, err := RevokeFleetPolicy(ctx, sink, oldKeyID, oldBatchID); err != nil {
		// The new key is already live, so the fleet is shadowed; but the retire
		// did not confirm. Surface it — leave the lifecycle's retiring entry so a
		// retry can re-attempt the retire (the new artifact is idempotent on the
		// policy_log: a re-run re-appends the same already-applied set).
		return res, fmt.Errorf("digest: fleet re-key retire of old key %q: %w (new key %q IS live, fleet shadowed)",
			oldKeyID, err, res.NewKeyID)
	}

	// Drop the lifecycle's retiring bookkeeping for the old key. The `retiring`
	// set is SHARED across both cadences (it tracks whether the boundary still
	// needs a key id loaded at all); in a full rotation the SESSION leg (LiveRekey)
	// may have already dropped this key. So a "not in the retiring set" here means
	// the session leg retired it first — that is NOT a fleet-leg failure: the
	// fleet artifact retire above already swept the old fleet digests, which is the
	// no-gap guarantee for THIS cadence. We only treat a genuine refusal (the
	// active key) as fatal.
	if err := m.RetireKey(oldKeyID); err != nil {
		if oldKeyID == m.ActiveKeyID() {
			return res, fmt.Errorf("digest: retire old fleet key after re-register: %w", err)
		}
		// else: already retired by the session leg — the fleet retire still stands.
	}
	res.OldKeyRetired = true
	return res, nil
}

// ----- full-rotation choreography (the redeploy seam; doc 16 §6.2/§6.3) -----
//
// A host redeploy / scheduled roll re-keys BOTH cadences at once — the session
// digests over DigestFeedService (LiveRekey) and the fleet digests over the
// policy stream (LiveRekeyFleet). Each leg is independently gap-free, but an
// operator/auditor running a full rotation needs the two ordered as one unit
// with a single combined outcome. That ordering + outcome is what FullRotation
// supplies. It is the identity-side ORDERING helper for the redeploy the
// orchestrator drives — NOT the orchestrator's session-enumeration or
// host-redeploy sequence (that stays behind the SCOPE FENCE above): the caller
// still supplies the live-session and live-fleet snapshots.
//
// ORDERING (documented, load-bearing): the SESSION leg runs FIRST, the FLEET
// leg SECOND, over the SHARED retiring key id. The session leg
// (LiveRekey) retires the shared lifecycle key on success (RetireKey drops it
// from the retiring set). The fleet leg (LiveRekeyFleet) is deliberately built
// to TOLERATE that: it re-registers + retires its OWN policy-stream artifact and
// treats a "shared key already dropped by the session leg" as benign, so running
// it second is correct rather than a double-retire error.
//
// THE FLEET NO-GAP PROOF IS THE POLICY-LOG RETIRE APPEND, NOT THE SHARED DROP.
// This is the statement the doc must carry (proposed for docs/16 §6.2/§6.3): the
// fleet cadence's gap-free guarantee is the RevokeFleetPolicy append on the
// policy_log — the new-key artifact applied BEFORE the old-key retire artifact —
// NOT the shared retiring-set bookkeeping (which the session leg may have already
// cleared). Reading OldKeyRetired on FleetRekeyResult as "the shared lifecycle
// key was dropped by the fleet leg" would be a misread; it means "the fleet
// artifact retire committed on the policy stream". FullRotation surfaces both
// legs' results separately so an auditor reads each cadence's proof at its own
// channel and never conflates the shared-set bookkeeping with the fleet
// guarantee.
type RotationResult struct {
	// Session is the session-cadence outcome (LiveRekey over DigestFeedService).
	Session RekeyResult
	// Fleet is the fleet-cadence outcome (LiveRekeyFleet over the policy stream).
	// Its OldKeyRetired reflects the policy-log retire append, NOT the shared
	// lifecycle-set drop (see the type comment) — the fleet no-gap proof.
	Fleet FleetRekeyResult
	// Complete is true iff BOTH legs finished successfully: every session was
	// re-pushed + the shared key retired, AND the fleet set was re-registered +
	// its old-key policy artifact retired. On any leg failure it is false and the
	// caller retries or aborts the redeploy (fail-closed).
	Complete bool
}

// FullRotation choreographs a complete host re-key: it runs the SESSION leg
// (LiveRekey) THEN the FLEET leg (LiveRekeyFleet) over the shared retiring key
// id, returning a combined RotationResult (doc 16 §6.2/§6.3). It is the thin
// redeploy-ordering seam an operator invokes to roll both cadences in one motion.
//
// Pre-state (same contract as each leg): the caller has already advanced the
// manager (Rotate/Rekey), so m.Current() is the NEW key and oldKeyID is in the
// retiring set. sessions is the live-session snapshot (session-scope creds);
// fleetCreds is the live fleet-scope (forbidden-class) set. batchIDFor names the
// per-session publish batches; newFleetBatchID / oldFleetBatchID name the fleet
// register/retire policy appends. The caller supplies both snapshots — the SCOPE
// FENCE keeps session-enumeration and the redeploy sequence the orchestrator's.
//
// Fail-closed ordering (the combined no-gap guarantee):
//  1. SESSION leg first: LiveRekey re-pushes every session under the new key and,
//     only on full success, retires the SHARED old key. If it fails, FullRotation
//     returns WITHOUT running the fleet leg — the old key stays live and every
//     session is still shadowed (no gap on either cadence); the fleet set is
//     untouched, still shadowed under the old fleet artifact.
//  2. FLEET leg second: LiveRekeyFleet re-registers the fleet set under the new
//     key as a policy artifact and retires the OLD fleet policy artifact. It
//     TOLERATES the session leg having already dropped the shared retiring key
//     (benign) — its own no-gap proof is the policy-log retire append, not the
//     shared drop. If it fails, the OLD fleet key's artifact is left registered
//     (the fleet stays shadowed); the session cadence already committed.
//
// Complete is true only if both legs succeeded. On a fleet-leg failure the
// returned RotationResult still carries the committed Session result (so the
// caller knows the session cadence rolled) alongside the fleet error — the
// caller retries the fleet leg or aborts. A leg is NEVER run out of order, and
// no instant on either cadence leaves its scope unshadowed by both keys.
//
// This helper computes nothing new and invents no wire verb: it sequences the
// two existing legs. It lives on the digest side (not the orchestrator's) so it
// can drive KeyManager.LiveRekey/LiveRekeyFleet directly — the import-gate-clean
// choice: the orchestrator's only legal cross-tree import is proto/gen/go, so a
// choreographer over the KeyManager types cannot live in orchestrator/; keeping
// it here (the identity-side ordering helper the orchestrator calls across the
// existing cmd/PolicySink bridge) honors that boundary.
func (m *KeyManager) FullRotation(
	ctx context.Context,
	client identityv1.DigestFeedServiceClient,
	sink PolicySink,
	oldKeyID string,
	sessions []LiveSession,
	fleetCreds []Credential,
	batchIDFor func(sessionUUID string) string,
	newFleetBatchID string,
	oldFleetBatchID string,
) (RotationResult, error) {
	var res RotationResult

	// STEP 1 — SESSION leg. LiveRekey validates the pre-state (client, oldKeyID in
	// the retiring set, manager advanced) and re-pushes every session under the
	// new key, retiring the shared old key only on full success. Fail-closed: on
	// error the fleet leg is NOT run and the old key stays live.
	sessRes, err := m.LiveRekey(ctx, client, oldKeyID, sessions, batchIDFor)
	res.Session = sessRes
	if err != nil {
		return res, fmt.Errorf("digest: full rotation session leg: %w (fleet leg NOT run, old key %q left live, no gap)",
			err, oldKeyID)
	}

	// STEP 2 — FLEET leg. LiveRekeyFleet re-registers the fleet set under the new
	// key and retires the old fleet policy artifact. It TOLERATES the shared key
	// having already been dropped by the session leg above (benign RetireKey "not
	// retiring") and proves its own no-gap via the policy-log retire append. On
	// error the old fleet artifact is left registered (fleet still shadowed).
	fleetRes, err := m.LiveRekeyFleet(ctx, sink, oldKeyID, fleetCreds, newFleetBatchID, oldFleetBatchID)
	res.Fleet = fleetRes
	if err != nil {
		return res, fmt.Errorf("digest: full rotation fleet leg: %w (session leg already committed; old fleet key %q left registered, fleet shadowed)",
			err, oldKeyID)
	}

	res.Complete = true
	return res, nil
}
