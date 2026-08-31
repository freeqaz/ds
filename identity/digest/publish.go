// SPDX-License-Identifier: Apache-2.0

// Driving the frozen digest-feed seam (doc 16 §6.1/§9; doc 14 §7; D109).
//
// The production producer pushes the digests it computed over the SAME frozen
// dreamserpent.identity.v1.DigestFeedService seam the Stage-0 fake drove — it
// invents no new cross-service contract (proto bodies are HANDS-OFF). This file
// is the producer's client half of the mint sub-sequence (§6.1):
//
//	digest computation (Producer) → DigestPublish to the boundary host →
//	host-agent ack (DigestPublishResponse.committed) → session routable
//
// FAIL-CLOSED (doc 14 §7): a transport error OR an uncommitted ack means the
// session must NOT be marked routable. PublishSession returns an error in both
// cases — the caller (the orchestrator's create choreography, owned by the
// session-create task, NOT this module) stalls/fails session-create on it.
//
// SCOPE FENCE: the orchestrator-owned create-choreography ordering
// (mint→CA→grants→cred→digest→write→ack→routable) and round2/08 test 6
// end-to-end are session-create's. This file supplies ONLY the identity-side
// publish/revoke verbs the choreography calls; it does not order the larger
// sequence.
package digest

import (
	"context"
	"errors"
	"fmt"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// PublishResult reports the outcome of a session-scoped publish. Routable is
// true iff the boundary acked every entry committed — the single bit the
// caller's "mark session routable?" decision turns on. ConsumerID + BatchID
// carry the ack provenance (which host-side consumer acked, doc 16 §6.5).
type PublishResult struct {
	Routable   bool
	ConsumerID string
	BatchID    string
}

// PublishSession computes the digest set for the session's credentials and
// pushes it over the frozen seam as a session-scoped, mint-before-attach write.
// It is the identity-side verb the orchestrator's create choreography calls
// between cred mint and "mark routable".
//
// Fail-closed: a build error (a credential failed to digest), a transport error,
// or an uncommitted ack all return a non-nil error and a non-routable result —
// the session must not go routable. On success Routable is true.
func PublishSession(
	ctx context.Context,
	client identityv1.DigestFeedServiceClient,
	prod *Producer,
	sessionUUID string,
	creds []Credential,
	batchID string,
) (PublishResult, error) {
	if client == nil {
		return PublishResult{}, errors.New("digest: nil feed client (fail-closed)")
	}
	if prod == nil {
		return PublishResult{}, errors.New("digest: nil producer (fail-closed)")
	}
	if sessionUUID == "" {
		return PublishResult{}, errors.New("digest: empty session uuid (fail-closed)")
	}
	entries, err := prod.BatchEntries(creds)
	if err != nil {
		return PublishResult{}, fmt.Errorf("digest: build entries: %w (fail-closed: session not routable)", err)
	}
	if len(entries) == 0 {
		return PublishResult{}, errors.New("digest: no entries to publish (fail-closed)")
	}
	resp, err := client.DigestPublish(ctx, &identityv1.DigestPublishRequest{
		Session: &identityv1.DigestSessionRef{SessionUuid: sessionUUID},
		Entries: entries,
		BatchId: batchID,
	})
	if err != nil {
		return PublishResult{}, fmt.Errorf("digest: DigestPublish: %w (fail-closed: session not routable)", err)
	}
	res := PublishResult{
		ConsumerID: resp.GetConsumerId(),
		BatchID:    resp.GetBatchId(),
		Routable:   resp.GetCommitted(),
	}
	if !resp.GetCommitted() {
		return res, fmt.Errorf("digest: publish ack uncommitted (consumer=%q batch=%q): fail-closed, session not routable",
			resp.GetConsumerId(), resp.GetBatchId())
	}
	return res, nil
}

// PublishSessionWithManager threads the lifecycle's ACTIVE key/epoch through a
// session publish (doc 16 §6.3): it mints the active-key Producer from the
// KeyManager and delegates to PublishSession, so the caller publishes under
// whatever key the lifecycle currently selects without restating the key id.
// This is the minimal lifecycle-aware publish — the create-choreography path
// (mint-before-attach, §6.1) calls this so a publish always rides the current
// epoch; LiveRekey re-pushes via the same active-Producer path after a flip.
// Fail-closed: a nil manager or a producer-mint failure returns a non-routable
// error before any RPC.
//
// KEY-LIFECYCLE COMPOSITION POINT (reconciliation, doc 16 §6.3 — pinned, not
// rebuilt). This function IS the composition seam of the whole lifecycle: the
// KeyManager (keys.go) owns per-host per-epoch key custody in the D39 trust zone
// (never on the virtual-metal host) and selects the ACTIVE key; a create publish
// rides it here so it always uses the current epoch. On an epoch roll the re-push
// rides KeyManager.LiveRekey (rotation.go): re-publish every live session under
// the NEW active key (this same active-Producer path), ack-gate each, and only
// then retire the old key — RevokeSession-then-republish, ordered so a session is
// never unshadowed by both keys (the no-gap guarantee). The ORCHESTRATOR side of
// this — the create spine calling the fail-closed digest publish BETWEEN cred-mint
// and mark-routable — is now wired in orchestrator/internal/sessions
// (digestpublish.go, flag DS_ORCH_DIGEST_PUBLISH_WIRE) and speaks the frozen
// DigestFeedServiceClient directly (D80: no identity/* import), mirroring this
// verb's fail-closed ack gate. The truncation-length FP-vs-fleet-digest-count
// question stays OPEN under taskdb 01KTWJ4NR0A76YW7SY2CV528AH (see producer.go's
// DefaultTruncationLenBytes); this note links it, does not duplicate it.
func PublishSessionWithManager(
	ctx context.Context,
	client identityv1.DigestFeedServiceClient,
	mgr *KeyManager,
	sessionUUID string,
	creds []Credential,
	batchID string,
) (PublishResult, error) {
	if mgr == nil {
		return PublishResult{}, errors.New("digest: nil key manager (fail-closed)")
	}
	prod, err := mgr.Producer()
	if err != nil {
		return PublishResult{}, fmt.Errorf("digest: mint active-key producer: %w (fail-closed: session not routable)", err)
	}
	return PublishSession(ctx, client, prod, sessionUUID, creds, batchID)
}

// ----- fleet-scope policy-stream path (doc 16 §6.2; D72) -------------------
//
// Fleet-scope forbidden-class digests are POLICY ARTIFACTS carried under the
// `policy_log` seq, NOT session-lifecycle data on the DigestFeedService seam.
// They ride a different cadence — the one-per-host WatchPolicies subscriber,
// covered by the prepare/commit barrier + revocation sweep — and "two cadences,
// no third channel" (D72) forbids inventing a second policy stream or a third
// digest channel for them. So the producer emits a fleet-scope digest batch as
// ONE policy_log append (an org/fleet-block-class row whose payload is the
// DIGEST_SCOPE_FLEET entry set), and the existing policy-stream fan-out delivers
// it. This file supplies the identity-side append verb over that path; the
// policy_log surface itself (orchestrator.v1.PolicyService.AppendPolicy /
// boundary.v1.PolicyStreamService) is the orchestrator's, modeled here behind a
// PolicySink seam so this module stays buildable in-process against a fake (the
// wave's synthetic-fixture rule) without owning the control-plane RPC.

// FleetPolicyArtifact is one fleet-scope digest registration as it is appended
// to the policy_log (doc 16 §6.2). It carries the KeyID the batch was derived
// under (so a re-key's new-key artifact is distinguishable from the retiring
// one), the DIGEST_SCOPE_FLEET entry set, and a producer-chosen BatchID for ack
// provenance — the policy-stream analogue of a DigestPublishRequest's batch_id.
// It is NOT a session publish: there is no DigestSessionRef (a fleet artifact is
// host-wide, not per-session — mirroring the PolicySnapshot, which carries no
// SessionRef).
type FleetPolicyArtifact struct {
	// KeyID is the HMAC key id every entry in this artifact was derived under
	// (all entries share it). A fleet re-key appends the NEW-key artifact before
	// retiring the OLD-key one.
	KeyID string
	// Entries is the DIGEST_SCOPE_FLEET entry set (forbidden-class fleet digests).
	Entries []*identityv1.DigestEntry
	// BatchID correlates the append with its ack (provenance, doc 16 §6.5).
	BatchID string
}

// FleetPolicyResult reports the outcome of one fleet-scope policy append. Seq is
// the assigned `policy_log` bigserial (the single policy version namespace, D72)
// the sink returned; Committed is true iff the barrier confirmed the artifact is
// applied (the policy-stream analogue of DigestPublishResponse.committed). KeyID
// and BatchID echo the request for traceability.
type FleetPolicyResult struct {
	Seq       uint64
	Committed bool
	KeyID     string
	BatchID   string
}

// PolicySink is the identity-side seam onto the policy_log append path (doc 16
// §6.2; D72). It is the ONLY new contract this fleet leg introduces, and it is
// deliberately a Go interface — NOT a new proto/RPC — because the wire surface
// already exists (orchestrator.v1.PolicyService.AppendPolicy → the per-host
// WatchPolicies fan-out): inventing a second one would be the "third channel"
// D72 forbids. The orchestrator's policy-log adapter satisfies this in
// production; an in-process fake satisfies it in tests (no live boundary, the
// wave rule).
//
// AppendFleetDigest appends one fleet-scope digest artifact and returns its
// assigned seq + commit state. Fail-closed: an error OR an uncommitted result
// means the artifact is NOT applied, exactly as an uncommitted DigestPublish ack
// blocks the session path.
type PolicySink interface {
	AppendFleetDigest(ctx context.Context, art FleetPolicyArtifact) (FleetPolicyResult, error)
}

// PublishFleetPolicy emits a fleet-scope digest batch as a policy artifact over
// the policy-stream path (doc 16 §6.2). It is the fleet-cadence analogue of
// PublishSession: it builds the DIGEST_SCOPE_FLEET entry set with the producer
// (asserting fleet scope via FleetBatchEntries) and appends it through the
// PolicySink — NEVER over DigestFeedService (which is session-scope only). The
// producer's plaintext is digested and dropped exactly as on the session path.
//
// Fail-closed: a build error, a sink error, or an uncommitted policy-apply all
// return a non-nil error and a non-committed result — a fleet re-key must not
// treat an unapplied artifact as live (the no-gap guarantee depends on it).
func PublishFleetPolicy(
	ctx context.Context,
	sink PolicySink,
	prod *Producer,
	creds []Credential,
	batchID string,
) (FleetPolicyResult, error) {
	if sink == nil {
		return FleetPolicyResult{}, errors.New("digest: nil policy sink (fail-closed)")
	}
	if prod == nil {
		return FleetPolicyResult{}, errors.New("digest: nil producer (fail-closed)")
	}
	entries, err := prod.FleetBatchEntries(creds)
	if err != nil {
		return FleetPolicyResult{}, fmt.Errorf("digest: build fleet entries: %w (fail-closed: artifact not applied)", err)
	}
	if len(entries) == 0 {
		return FleetPolicyResult{}, errors.New("digest: no fleet entries to publish (fail-closed)")
	}
	res, err := sink.AppendFleetDigest(ctx, FleetPolicyArtifact{
		KeyID:   prod.KeyID(),
		Entries: entries,
		BatchID: batchID,
	})
	if err != nil {
		return FleetPolicyResult{}, fmt.Errorf("digest: AppendFleetDigest: %w (fail-closed: artifact not applied)", err)
	}
	// Carry the producer's key id + the requested batch id through even on a
	// non-commit, so the caller's error log names which artifact did not apply.
	if res.KeyID == "" {
		res.KeyID = prod.KeyID()
	}
	if res.BatchID == "" {
		res.BatchID = batchID
	}
	if !res.Committed {
		return res, fmt.Errorf("digest: fleet policy artifact not committed (key=%q batch=%q seq=%d): fail-closed",
			res.KeyID, res.BatchID, res.Seq)
	}
	return res, nil
}

// RevokeFleetPolicy retires a fleet-scope key's digests over the policy-stream
// path — the fleet analogue of RetireOldKeyViaRevoke's per-session flush, but a
// SINGLE host-wide policy_log append (a fleet artifact is host-wide, doc 16
// §6.2). It appends an EMPTY-entry artifact for oldKeyID: the policy-log
// revocation sweep treats "no entries under this key id" as the retire of that
// key's fleet digests. Fail-closed on an uncommitted apply so a retire that did
// not confirm surfaces as an error (a stale fleet digest under a retired key is
// the matchable-nowhere hazard this whole leg exists to prevent — but only after
// the new key's artifact is live, never before; the caller orders that).
func RevokeFleetPolicy(
	ctx context.Context,
	sink PolicySink,
	oldKeyID string,
	batchID string,
) (FleetPolicyResult, error) {
	if sink == nil {
		return FleetPolicyResult{}, errors.New("digest: nil policy sink (fail-closed)")
	}
	if oldKeyID == "" {
		return FleetPolicyResult{}, errors.New("digest: empty old key id (fail-closed)")
	}
	res, err := sink.AppendFleetDigest(ctx, FleetPolicyArtifact{
		KeyID:   oldKeyID,
		Entries: nil, // empty entry set = retire this key's fleet digests
		BatchID: batchID,
	})
	if err != nil {
		return FleetPolicyResult{}, fmt.Errorf("digest: AppendFleetDigest (revoke): %w", err)
	}
	if res.KeyID == "" {
		res.KeyID = oldKeyID
	}
	if res.BatchID == "" {
		res.BatchID = batchID
	}
	if !res.Committed {
		return res, fmt.Errorf("digest: fleet revoke artifact not committed (key=%q batch=%q): fail-closed",
			res.KeyID, res.BatchID)
	}
	return res, nil
}

// RevokeSession flushes a session's digests by key id over the frozen seam — the
// teardown / kill-mid-flight flush (doc 16 §5.4/§6.1). Session-scope only; fleet
// revocation rides the policy stream (§6.2), never this RPC. Fail-closed on an
// uncommitted ack so a teardown that did not actually clear the digests surfaces
// as an error rather than a silent stale-digest leak.
func RevokeSession(
	ctx context.Context,
	client identityv1.DigestFeedServiceClient,
	sessionUUID string,
	keyIDs []string,
) error {
	if client == nil {
		return errors.New("digest: nil feed client (fail-closed)")
	}
	if sessionUUID == "" {
		return errors.New("digest: empty session uuid (fail-closed)")
	}
	if len(keyIDs) == 0 {
		return errors.New("digest: no key ids to revoke (fail-closed)")
	}
	resp, err := client.DigestRevoke(ctx, &identityv1.DigestRevokeRequest{
		Session: &identityv1.DigestSessionRef{SessionUuid: sessionUUID},
		KeyIds:  keyIDs,
		Scope:   identityv1.DigestScope_DIGEST_SCOPE_SESSION,
	})
	if err != nil {
		return fmt.Errorf("digest: DigestRevoke: %w", err)
	}
	if !resp.GetCommitted() {
		return fmt.Errorf("digest: revoke ack uncommitted (consumer=%q): teardown flush not confirmed",
			resp.GetConsumerId())
	}
	return nil
}
