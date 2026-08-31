// SPDX-License-Identifier: Apache-2.0

// Host-handoff digest-continuity controller (doc 16 §6.3 default d "re-key on
// host redeploy"; doc 15 — the orchestrator-owned redeploy choreography).
//
// THE RESIDUAL THIS OWNS. The identity side proves the SINGLE-consumer re-key
// ordering: a host re-pushes every live digest under the new key and acks it
// BEFORE the old key is retired, so a session is never unshadowed. The scope
// fence in identity/digest/rotation.go leaves the larger redeploy
// choreography — "which sessions are live, and the larger redeploy
// choreography, are the orchestrator's (doc 15)" — explicitly to THIS tree.
// That residual is a TWO-HOST property the single-consumer identity side
// cannot express: when a boundary host is REDEPLOYED, the orchestrator must
// observe the freshly-stood-up NEW host LOADED + ACKED with the re-pushed
// new-key digest set BEFORE the OLD host's digest set is revoked / torn down.
// Otherwise there is an instant in which neither host shadows a live session —
// exactly the mint-before-attach gap, applied across a host swap rather than
// across a key flip on one host.
//
// WHAT THIS CONTROLLER DRIVES. Two distinct boundary-host states each appear
// as a dreamserpent.identity.v1.DigestFeedService consumer (the shape the D109
// host-agent ack-er serves):
//
//   - oldHost — the host being retired, already LOADED with the old-key
//     digests for every live session (the original mint-before-attach
//     publish).
//   - newHost — the freshly redeployed host, starts EMPTY and must be loaded
//     with the new-key digest set and ack committed.
//
// runHostHandoff re-publishes to the NEW host, gates on its COMMITTED ack AND a
// verified loaded set, and ONLY THEN revokes the OLD host. It FAILS CLOSED — no
// revoke — when the new registration is incomplete (an uncommitted ack, a
// transport error, or a short load): the old host is left fully loaded and the
// redeploy is retried or aborted, so a session is never shadowed by neither
// host.
//
// SCOPE. This is an ORCHESTRATOR-OWNED choreography. It does NOT import
// identity/digest (the only legal cross-tree import is proto/gen/go, D80): it
// drives the FROZEN proto seam directly and observes the "no-gap" property from
// the wire, exactly as the orchestrator's redeploy controller does in
// production. The identity-side digest computation + the per-host re-key
// ordering are proven on that side; this controller only routes opaque entries
// and gates on acks, never holding key material (doc 16 §6.3). SYNTHETIC ONLY
// (D50): a live host-redeploy leg (standing up a real KVM host, re-pushing over
// the live endpoint, observing a live host-agent ack) is env-gated and a
// deferred manual step — there is no live host, boundary, or claude here.
//
// The in-process synthetic DigestFeedService stand-in the tests drive this
// controller against (hostConsumer + its shared ordering journal, plus the
// SESSION/RAW synthEntriesFor preload specialization) is TEST-ONLY and lives in
// hosthandoff_fixtures_test.go — it never compiles into the shipped binary. The
// scope/variant entry stamping the controller actually uses in production
// (synthEntriesForVariant/synthAlgo/synthCredClassFor) stays below.

package sessions

import (
	"context"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// ---- the live-session model ----------------------------------------------

// synthLiveSession is one live session whose digests must survive a host
// handoff: its UUID plus the synthetic credential tokens currently shadowed for
// it. The orchestrator (doc 15) is the authority for which sessions are live —
// the residual the identity scope fence leaves to this tree. The credential
// tokens are SYNTHETIC ds-synth-* ids (D50): the controller routes opaque
// entries and never touches real credential material.
type synthLiveSession struct {
	uuid  string
	creds []string // ds-synth-* credential tokens

	// scope / variant let a fixture parameterize the digest set this session is
	// published under — DIGEST_SCOPE_SESSION vs DIGEST_SCOPE_FLEET, and any of the
	// four variant_tag encodings (RAW|BASE64|URLENC|HEX). The controller is OPAQUE
	// to both: it routes entries and gates on acks regardless. Their zero values
	// (DIGEST_SCOPE_UNSPECIFIED / DIGEST_VARIANT_TAG_UNSPECIFIED) mean "use the
	// default SESSION/RAW shape", so existing fixtures that leave them unset are
	// unchanged. sessionScope/sessionVariant resolve the effective values.
	scope   identityv1.DigestScope
	variant identityv1.DigestVariantTag
}

// sessionScope resolves the effective DigestScope for a session: an explicit
// scope, or DIGEST_SCOPE_SESSION when the fixture left it unset (the historical
// default). The controller never branches on it — this only stamps the entries +
// the revoke request so the wire shape is faithful across the SESSION/FLEET axis.
func (s synthLiveSession) sessionScope() identityv1.DigestScope {
	if s.scope == identityv1.DigestScope_DIGEST_SCOPE_UNSPECIFIED {
		return identityv1.DigestScope_DIGEST_SCOPE_SESSION
	}
	return s.scope
}

// sessionVariant resolves the effective variant_tag for a session: an explicit
// encoding, or DIGEST_VARIANT_TAG_RAW when unset (the historical default). Opaque
// to the controller; it only stamps the published entries.
func (s synthLiveSession) sessionVariant() identityv1.DigestVariantTag {
	if s.variant == identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_UNSPECIFIED {
		return identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW
	}
	return s.variant
}

// synthAlgo is the keyed-hash family + truncation length every synthetic entry
// is stamped with (doc 14 §7: "algo (HMAC-SHA-256 + truncation length)"). The
// orchestrator never re-derives a digest, so this is fixture fidelity to the
// frozen wire shape — the boundary matcher reads it to select the key family;
// the controller treats it as opaque. 16 bytes is a shape-faithful synthetic
// truncation length (D50): it is NOT a real keyed-hash output, only the metadata
// the producer would stamp.
func synthAlgo() *identityv1.DigestAlgo {
	return &identityv1.DigestAlgo{
		Family:             identityv1.DigestAlgo_FAMILY_HMAC_SHA256,
		TruncationLenBytes: 16,
	}
}

// synthCredClassFor classifies a synthetic credential token into the frozen doc
// 14 §7 cred_class oneof (ISSUED{service_id} | FORBIDDEN). A `*-canary` token is
// the doc 06 (c) forbidden-class canary (the canary-never-egresses row, D73): it
// is FORBIDDEN. Every other synthetic token is an ISSUED credential tagged with
// a shape-faithful ds-synth-* service_id derived from the token. The
// classification is FIXTURE FIDELITY only: the controller routes entries opaquely
// and never branches on cred_class — this populates the field so the
// routing/continuity test exercises the FULL frozen wire shape, spanning both
// oneof arms (D50; cred_class semantics are the boundary's, not this seam's).
func synthCredClassFor(tok string) *identityv1.DigestCredClass {
	if strings.Contains(tok, "canary") {
		return &identityv1.DigestCredClass{
			Class: &identityv1.DigestCredClass_Forbidden_{
				Forbidden: &identityv1.DigestCredClass_Forbidden{},
			},
		}
	}
	return &identityv1.DigestCredClass{
		Class: &identityv1.DigestCredClass_Issued_{
			Issued: &identityv1.DigestCredClass_Issued{
				ServiceId: "ds-synth-svc-" + tok,
			},
		},
	}
}

// synthEntriesForVariant is the scope/variant-parameterized entry builder the
// controller uses to stamp a publish — the production digest-feed entry shape.
// It mirrors the identity producer's output shape (one entry per credential
// token) WITHOUT recomputing real HMACs — the orchestrator choreography only
// routes opaque entries + observes acks; the digest math is proven
// identity-side. The "digest" bytes are a synthetic, deterministic,
// non-reversible label (keyID|scope|variant|token) so the two hosts' loaded sets
// are distinguishable and a dropped entry is detectable; they are never real
// credential-derived material (D50).
//
// Every entry carries the FULL frozen doc 14 §7 shape: key_id, algo (HMAC-SHA-256
// + truncation length), digest, cred_class (ISSUED{service_id} | FORBIDDEN —
// spanning both oneof arms across the synthetic token set), scope, expiry, and
// variant_tag. algo + cred_class are FIXTURE FIDELITY to the frozen wire — the
// controller stays opaque to them (it never branches on cred_class), so a
// controller mishandling a cred_class-tagged entry would surface, while routing
// semantics are unchanged.
//
// The caller picks the DigestScope (SESSION or FLEET) and the variant_tag
// encoding (RAW|BASE64|URLENC|HEX). The controller routes entries OPAQUELY — it
// never branches on scope or variant_tag — so a handoff/convergence run carrying
// FLEET-scoped, HEX-tagged entries must converge exactly as a SESSION/RAW run
// does. The digest label folds in the scope + variant so the loaded sets stay
// distinguishable across the matrix. The TEST-ONLY SESSION/RAW specialization
// the tests preload with (synthEntriesFor) lives in hosthandoff_fixtures_test.go
// and delegates here, so the two never drift.
func synthEntriesForVariant(keyID string, creds []string, scope identityv1.DigestScope, variant identityv1.DigestVariantTag) []*identityv1.DigestEntry {
	exp := timestamppb.New(time.Now().Add(15 * time.Minute))
	entries := make([]*identityv1.DigestEntry, 0, len(creds))
	for _, tok := range creds {
		entries = append(entries, &identityv1.DigestEntry{
			KeyId:      keyID,
			Algo:       synthAlgo(),
			Digest:     []byte("ds-synth-digest|" + keyID + "|" + scope.String() + "|" + variant.String() + "|" + tok),
			CredClass:  synthCredClassFor(tok),
			Scope:      scope,
			Expiry:     exp,
			VariantTag: variant,
		})
	}
	return entries
}

// ---- the orchestrator-owned host-handoff choreography --------------------

// handoffOutcome reports how far the choreography progressed: whether the new
// host was fully loaded+acked and whether the old host's digests were torn
// down. On a fail-closed leg both stay false (handoff refused, old host
// untouched); the fail-closed error type is incompleteHandoffError, which a
// caller matches on without string-matching.
type handoffOutcome struct {
	newHostHandedOff bool // every live session loaded+acked on the new host
	oldHostRevoked   bool // the old host's digests torn down
}

// runHostHandoff is the orchestrator-side redeploy choreography — the residual
// doc 16 §6.3 / doc 15 fences to this tree. It models a boundary host redeploy:
// a fresh host (newHost) must take over shadowing every live session before the
// retiring host (oldHost) is torn down.
//
// newHostLoadedCount is the per-instant probe (a healthy newHost's
// loadedCountUnder method) the controller uses to VERIFY a committed ack
// actually loaded the FULL digest set for the session under the new key —
// gating on the wire-observable loaded COUNT, not the committed bit alone and
// not a mere ≥1 "shadows" bit, so BOTH a zero-load and a short load (some but
// not all entries dropped) are caught. A partial load that still leaves one
// entry shadowing would otherwise revoke the old host while some of the
// session's credentials go unshadowed on the new host — the exact drop hazard
// this controller exists to prevent.
//
// Fail-closed ORDERING (the no-gap guarantee — the whole point of this
// controller):
//  1. For every live session, re-publish its digest set (under the NEW key) to
//     the NEW host and REQUIRE the ack committed AND the full set loaded. If
//     any session fails to load+ack, STOP — the old host is left fully loaded
//     (every session still shadowed), and the redeploy is retried/aborted.
//  2. ONLY after every session is loaded+acked on the new host, revoke the old
//     host's digests, one session at a time.
//
// At no instant is a session shadowed by neither host: step 1 only ADDS the new
// host's shadow (the old host is untouched), and step 2's revoke for a session
// runs strictly after that session's new-host load+ack. The recorded journal
// makes the ordering checkable.
//
// COMPENSATING / IDEMPOTENT step-2 SEMANTICS (the old-host-revoke contract).
// A revoke failure PARTWAY through step 2 (say session A's revoke committed but
// session B's errors) is NOT a continuity gap: by the time step 2 runs the NEW
// host already shadows EVERY session (step 1 completed for all), so the partially
// torn-down OLD host is pure redundancy — no session is ever unshadowed. The
// controller therefore FAILS CLOSED on the first revoke error: it returns
// incompleteHandoffError and leaves out.oldHostRevoked=false (the old host is
// only PARTIALLY revoked, so it is not "revoked"). The caller's contract is to
// RETRY the whole handoff. That retry is safe because every step is idempotent:
// re-publishing to the already-loaded new host re-confirms the same set (the
// loaded-count verify still passes), and re-revoking the old host is a no-op for
// the sessions already revoked (DigestRevoke deletes an absent key id without
// error) and tears down the rest — so a retry converges to oldHostRevoked=true
// without a double-revoke hazard. The redeploy is never left half-applied in a
// way a retry cannot heal.
func runHostHandoff(
	ctx context.Context,
	newHost, oldHost identityv1.DigestFeedServiceClient,
	newHostLoadedCount func(sessionUUID, keyID string) int,
	sessions []synthLiveSession,
	newKeyID, oldKeyID string,
) (handoffOutcome, error) {
	var out handoffOutcome

	// STEP 1 — load the NEW host for every live session; ack-gated + verified.
	for _, s := range sessions {
		// Stamp the entries under the session's effective scope + variant_tag
		// (default SESSION/RAW). The controller routes them opaquely — it never
		// branches on either — so FLEET-scoped or HEX-tagged sessions flow through
		// the SAME publish/verify/revoke path as the default shape.
		entries := synthEntriesForVariant(newKeyID, s.creds, s.sessionScope(), s.sessionVariant())
		resp, err := newHost.DigestPublish(ctx, &identityv1.DigestPublishRequest{
			Session: &identityv1.DigestSessionRef{SessionUuid: s.uuid},
			Entries: entries,
			BatchId: "handoff-" + s.uuid,
		})
		if err != nil {
			// Fail-closed: the new host never confirmed — leave the OLD host fully
			// loaded (every session still shadowed, no gap).
			return out, errIncompleteHandoff("publish to new host failed: " + err.Error())
		}
		if !resp.GetCommitted() {
			return out, errIncompleteHandoff("new host did not ack committed for session " + s.uuid)
		}
		// Verify the new host loaded the FULL set for the session under the new
		// key — a committed ack that loaded nothing OR only a subset (a short
		// load) is still an incomplete handoff. Checking ≥1 ("shadows") is not
		// enough: a multi-credential session with one entry dropped would still
		// shadow, yet the dropped credential would go unprotected once the old
		// host is revoked.
		want := len(entries)
		if got := newHostLoadedCount(s.uuid, newKeyID); got != want {
			return out, errIncompleteHandoff("new host acked but loaded an incomplete digest set for session " + s.uuid + " (short/empty load)")
		}
	}
	out.newHostHandedOff = true

	// STEP 2 — every session is now shadowed on the new host; AND ONLY NOW tear
	// the old host down. The old host stayed fully loaded throughout step 1, so
	// every session was continuously shadowed by at least one host.
	for _, s := range sessions {
		resp, err := oldHost.DigestRevoke(ctx, &identityv1.DigestRevokeRequest{
			Session: &identityv1.DigestSessionRef{SessionUuid: s.uuid},
			KeyIds:  []string{oldKeyID},
			Scope:   s.sessionScope(),
		})
		if err != nil {
			return out, errIncompleteHandoff("revoke on old host failed: " + err.Error())
		}
		if !resp.GetCommitted() {
			return out, errIncompleteHandoff("old host revoke not committed for session " + s.uuid)
		}
	}
	out.oldHostRevoked = true
	return out, nil
}

// incompleteHandoffError is the fail-closed error type: a caller matches on it
// (without string-matching) to distinguish "the redeploy was refused, the old
// host is untouched, retry/abort" from any other failure.
type incompleteHandoffError struct{ msg string }

func (e incompleteHandoffError) Error() string {
	return "host-handoff incomplete (fail-closed, no gap): " + e.msg
}

func errIncompleteHandoff(msg string) error { return incompleteHandoffError{msg: msg} }

// ---- the retry-to-convergence wrapper ------------------------------------

// handoffRetryPolicy bounds the retry-to-convergence loop. runHostHandoff fails
// CLOSED on a partial step (an incomplete new-host load, or a mid-teardown
// old-host revoke error) and DOCUMENTS that the caller must retry the idempotent
// handoff — but the controller alone drives no retry. This policy is the caller's
// half of that contract: how many attempts to make and how long to back off
// between them. backoff is the wait BEFORE the next attempt after a fail-closed
// outcome; it is realized through the supplied sleep func (the production caller
// passes time.Sleep, a test passes a no-op or a captured fake) so the loop is
// time-source-injectable and never wall-clock-bound in a test.
type handoffRetryPolicy struct {
	maxAttempts int           // >=1; how many runHostHandoff attempts before giving up
	backoff     time.Duration // wait before each retry (realized via the sleep func)
}

// handoffRetryResult reports a retry-to-convergence run: the final outcome, how
// many attempts ran, and the last error observed (nil on convergence). On
// convergence converged is true and out.oldHostRevoked is true; on exhaustion or
// cancellation converged is false and err carries the reason.
type handoffRetryResult struct {
	out       handoffOutcome
	attempts  int
	converged bool
	err       error
}

// runHostHandoffToConvergence drives runHostHandoff to convergence — it re-runs
// the idempotent handoff until oldHostRevoked=true or the attempt budget is
// exhausted, honoring ctx cancellation between (and before) attempts. It is the
// caller the controller's fail-closed contract calls for: every step of
// runHostHandoff is idempotent (re-publishing to the already-loaded new host
// re-confirms the same set, re-revoking the old host is a no-op for sessions
// already revoked), so re-running a partially-applied handoff CONVERGES without a
// double-revoke or duplicate-shadow hazard.
//
// CONVERGENCE GUARANTEE. Each attempt either:
//   - converges (oldHostRevoked=true) — return immediately, converged=true; OR
//   - fails closed with an incompleteHandoffError — back off and retry (the old
//     host is left fully or partially loaded; the new host already shadows every
//     session once step 1 has ever completed, so no attempt opens a gap); OR
//   - fails with a NON-fail-closed error (anything that is not an
//     incompleteHandoffError) — return immediately, converged=false. A surprise
//     error is not something a blind retry should hammer; the caller decides.
//
// CANCELLATION. ctx is checked before every attempt and during the backoff wait;
// a cancelled ctx ends the loop promptly with ctx.Err(). The backoff is realized
// through sleep (nil → a default ctx-aware sleep), so a test can drive the loop
// with no real delay while still exercising the bounded, cancellable shape.
//
// onAttempt, if non-nil, is invoked with the 1-based attempt number BEFORE each
// runHostHandoff call. It is the seam a transient-failure-then-recovery scenario
// uses to flip the synthetic fault-injection knobs (publishErr/ackCommitted/
// dropEntries/revokeErr) between attempts — e.g. clearing a transient transport
// fault so a later attempt converges. Production passes nil.
func runHostHandoffToConvergence(
	ctx context.Context,
	newHost, oldHost identityv1.DigestFeedServiceClient,
	newHostLoadedCount func(sessionUUID, keyID string) int,
	sessions []synthLiveSession,
	newKeyID, oldKeyID string,
	policy handoffRetryPolicy,
	sleep func(context.Context, time.Duration) error,
	onAttempt func(attempt int),
) handoffRetryResult {
	if policy.maxAttempts < 1 {
		policy.maxAttempts = 1
	}
	if sleep == nil {
		sleep = ctxSleep
	}

	var res handoffRetryResult
	for attempt := 1; attempt <= policy.maxAttempts; attempt++ {
		// Honor cancellation BEFORE doing any work on this attempt.
		if err := ctx.Err(); err != nil {
			res.err = err
			return res
		}
		// Back off before every attempt after the first (only retries wait).
		if attempt > 1 && policy.backoff > 0 {
			if err := sleep(ctx, policy.backoff); err != nil {
				res.err = err
				return res
			}
		}
		if onAttempt != nil {
			onAttempt(attempt)
		}

		out, err := runHostHandoff(ctx, newHost, oldHost, newHostLoadedCount, sessions, newKeyID, oldKeyID)
		res.out = out
		res.attempts = attempt
		res.err = err

		if err == nil && out.oldHostRevoked {
			res.converged = true
			return res
		}
		// A non-fail-closed error is not retryable by this loop — surface it.
		if err != nil {
			if _, ok := err.(incompleteHandoffError); !ok {
				return res
			}
		}
		// else: fail-closed (incompleteHandoffError, oldHostRevoked=false) — loop
		// and retry the idempotent handoff after the backoff.
	}
	return res
}

// ctxSleep waits for d or until ctx is cancelled, returning ctx.Err() if the
// context ends first. It is the default backoff realization for
// runHostHandoffToConvergence — a context-aware sleep so the bounded retry loop
// never blocks past a cancellation.
func ctxSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
