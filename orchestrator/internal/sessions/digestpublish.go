// SPDX-License-Identifier: Apache-2.0

package sessions

// digestpublish.go is the FLAG-GATED digest-publish call-site wiring on the create
// side of the sessions package. It closes the last un-wired seam of the doc 16 §6.1
// mint sub-sequence: BETWEEN the step-5 credential mint and "mark session routable"
// the create spine must push the session's secret digests to the boundary host and
// GATE routability on the host-agent ack (D73/D84, doc 14 §7 mint-before-attach). A
// publish/transport error OR an uncommitted ack means the session must NOT be marked
// routable — this file supplies the orchestrator-side seam + fail-closed decision the
// spine drives, and RunCreateSpine calls it after the pin write, before returning the
// cluster result the coordinator turns into READY.
//
// WHY A NEW SEAM, NOT AN IDENTITY IMPORT (D80, the load-bearing boundary). The
// identity side already exposes the fail-closed verb (identity/digest.PublishSession
// over the SAME frozen dreamserpent.identity.v1.DigestFeedService seam), but D80
// forbids the orchestrator importing any identity/* module — the ONLY legal cross-tree
// import is proto/gen/go. So this file declares a NARROW orchestrator-local seam
// (digestPublisher) that the spine depends on, and a PRODUCTION adapter
// (DigestFeedPublisher) that speaks the frozen identityv1.DigestFeedServiceClient
// DIRECTLY via proto/gen/go — reimplementing the same fail-closed ack gate
// (DigestPublish → committed?) orchestrator-side rather than linking identity. This is
// the same data-across-the-seam discipline the launch gate uses (launchGate over local
// mirror types) applied to the digest edge.
//
// TRUST-ZONE CUSTODY (doc 16 §2/§6.3, the key-lifecycle reconciliation). The DIGEST
// BYTES are computed by Identity's Producer INSIDE the D39 secret-store trust zone,
// under the per-host per-epoch HMAC key custodied there — never on the virtual-metal
// host, never by the orchestrator. Plaintext never crosses the seam ("digests, never
// secrets", doc 14 §7): the orchestrator holds only the opaque, plaintext-free
// []*identityv1.DigestEntry proto values Identity handed it and DRIVES the publish +
// gates routable on the ack. The key SOURCE, truncation-length FP analysis, and the
// live re-key re-push (LiveRekey → RevokeSession) all stay identity-side and are pinned
// under open task 01KTWJ4NR0A76YW7SY2CV528AH (see identity/digest-producer/README.md).
//
// FLAG-GATED, DEFAULT OFF (D50). The step arms only when the deployment opts in
// (DigestPublishWireEnabled, env DS_ORCH_DIGEST_PUBLISH_WIRE=1). Off — the wave's
// default — the spine SKIPS the step entirely: RunCreateSpine returns exactly as before
// (no publish, no routable gate), so a non-live create is byte-for-byte unchanged. This
// mirrors the metering-wire precedent this unit builds on: the actual push to a LIVE
// boundary is a live-only step scaffolded behind the env gate. When ARMED, all three
// fail-closed cases (nil publisher, publish/transport error, uncommitted ack) stall the
// create — the session is never marked routable.
//
// SYNTHETIC ONLY (D50). No live boundary, no VM: a publish is driven against a
// programmable in-test DigestFeedServiceClient / seam fake that scripts the ack. The
// tests assert the fail-closed decision (an error prevents the spine's success result)
// and the default-off skip.

import (
	"context"
	"errors"
	"fmt"
	"os"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"google.golang.org/grpc"
)

// DigestPublishWireFlag is the env var that arms the create-side digest-publish step
// (DS_ORCH_DIGEST_PUBLISH_WIRE=1). OFF by default: an unset/any-other value leaves the
// step skipped, so the wave's default create is byte-for-byte the pre-wire behavior
// (no publish, no routable gate) — D50.
const DigestPublishWireFlag = "DS_ORCH_DIGEST_PUBLISH_WIRE"

// DigestPublishWireEnabled reports whether the create-side digest-publish step is armed
// via the process environment (DS_ORCH_DIGEST_PUBLISH_WIRE=1). The spine reads this to
// decide whether to run the step; tests arm it with t.Setenv and never rely on ambient
// env leaking across cases.
func DigestPublishWireEnabled() bool {
	return os.Getenv(DigestPublishWireFlag) == "1"
}

var (
	// ErrDigestPublisherUnwired is the fail-closed sentinel for an ARMED step with no
	// publisher wired (a nil digestPublisher). The mint-before-attach gate cannot be
	// satisfied without a publisher, so an armed-but-unwired create must NOT mark the
	// session routable — it fails closed here rather than silently skipping the gate.
	ErrDigestPublisherUnwired = errors.New("sessions: digest-publish armed but no publisher wired (fail-closed: session not routable)")

	// ErrDigestNotRoutable is the fail-closed sentinel for a publish whose ack came back
	// UNCOMMITTED (DigestPublishResponse.committed=false). doc 14 §7 / doc 16 §6.1: a
	// false ack (or no ack) means the boundary did not register every entry, so the
	// session's digests are not matchable and the session must not become routable.
	ErrDigestNotRoutable = errors.New("sessions: digest publish ack uncommitted (fail-closed: session not routable)")
)

// DigestPublishOutcome is the create-side digest-publish step result — the outcome the
// spine carries onto CreateSpineResult.DigestPublish. Routable is the single bit the
// downstream "mark session routable?" decision turns on: it is true ONLY when the
// boundary acked the batch committed (mint-before-attach satisfied). ConsumerID and
// BatchID carry the ack provenance (which host-side consumer acked which batch — doc 16
// §6.5), so a failed create names the artifact that did not commit.
type DigestPublishOutcome struct {
	// Routable is true iff the boundary acked every entry committed for this session's
	// batch. False on the disarmed / not-reached path and on any fail-closed error.
	Routable bool
	// ConsumerID names the host-side consumer that acked (doc 16 §6.5).
	ConsumerID string
	// BatchID echoes the publish batch id (ack provenance, doc 16 §6.5).
	BatchID string
}

// digestPublisher is the narrow DATA seam the spine drives for the §6.1 digest-publish
// step: it pushes the session's secret digests to the boundary and returns whether the
// host acked them committed (Routable). It is satisfied by the production adapter over
// the frozen identityv1.DigestFeedServiceClient (DigestFeedPublisher, below) and by an
// in-test fake — the spine depends only on this Go interface, never on identity/* (D80).
//
// PublishSessionDigests MUST be fail-closed: a transport error OR an uncommitted ack
// returns a non-nil error and a non-routable outcome, so the spine never proceeds to a
// routable session on a publish that did not land.
type digestPublisher interface {
	PublishSessionDigests(ctx context.Context, sessionUUID string) (DigestPublishOutcome, error)
}

// runCreateDigestPublish is the FLAG-GATED create-side digest-publish call-site the
// spine runs after the step-5 mint assembly and before returning the cluster result
// (the point the doc 16 §6.1 order places between cred-mint and mark-routable).
//
//   - DISARMED (the default): DigestPublishWireEnabled()==false → return the zero
//     outcome and nil, so RunCreateSpine is byte-identical to the pre-wire spine (no
//     publish, no routable gate). This is the D50 byte-identical-when-off contract.
//   - ARMED + nil publisher: fail closed with ErrDigestPublisherUnwired — the gate
//     cannot be satisfied, so the session must not become routable.
//   - ARMED + publish/transport error: surface it (fail-closed) — the session is never
//     marked routable on a failed push.
//   - ARMED + uncommitted ack (outcome.Routable==false): fail closed with
//     ErrDigestNotRoutable, carrying the ack provenance.
//   - ARMED + committed ack: return the routable outcome; the spine proceeds and the
//     downstream mark-routable gate turns on Routable.
func runCreateDigestPublish(ctx context.Context, pub digestPublisher, sessionUUID string) (DigestPublishOutcome, error) {
	if !DigestPublishWireEnabled() {
		// Step disarmed: the create path stays byte-for-byte the pre-wire behavior.
		return DigestPublishOutcome{}, nil
	}
	if pub == nil {
		return DigestPublishOutcome{}, fmt.Errorf("%w (session %s)", ErrDigestPublisherUnwired, sessionUUID)
	}
	out, err := pub.PublishSessionDigests(ctx, sessionUUID)
	if err != nil {
		// A transport error or a publisher-side fail-closed (nil client, no entries, or
		// an uncommitted ack the adapter already classified) — surface it; not routable.
		return DigestPublishOutcome{}, err
	}
	if !out.Routable {
		// Defence in depth: a publisher that returned nil error but a non-routable
		// outcome (an uncommitted ack it did not itself flag) still fails closed here.
		return out, fmt.Errorf("%w (consumer=%q batch=%q)", ErrDigestNotRoutable, out.ConsumerID, out.BatchID)
	}
	return out, nil
}

// DigestFeedPublisher is the PRODUCTION digest-publish adapter: it drives the doc 16
// §6.1 mint-before-attach write over the frozen dreamserpent.identity.v1
// DigestFeedService seam and gates routability on the host-agent ack (D73/D84). It
// speaks the generated identityv1.DigestFeedServiceClient DIRECTLY (proto/gen/go only)
// so the orchestrator never imports identity/* (D80) — it reimplements the same
// fail-closed ack gate identity/digest.PublishSession applies, orchestrator-side.
//
// The entries are the session's plaintext-free DigestEntry set, computed by Identity's
// Producer inside the D39 trust zone under the active per-host per-epoch key and handed
// to the orchestrator as proto DATA (doc 16 §6.3 custody stays identity-side; see the
// file header). This adapter never computes a digest or touches a credential plaintext.
//
// It is NOT wired into main.go here (the sessions package is fenced from process
// bootstrap); a production wiring installs it as CreateSeams.DigestPublisher /
// CreateSpineRequest.DigestPublisher behind DS_ORCH_DIGEST_PUBLISH_WIRE, and the tests
// drive it against a programmable in-memory client fake (D50, no live boundary).
type DigestFeedPublisher struct {
	client  identityv1.DigestFeedServiceClient
	entries []*identityv1.DigestEntry
	batchID string
	opts    []grpc.CallOption
}

// NewDigestFeedPublisher builds the production digest-publish adapter over a frozen
// DigestFeedServiceClient. entries is the session's identity-computed, plaintext-free
// DigestEntry batch (all variants); batchID correlates the publish with its ack (doc 16
// §6.5). A nil client / empty entries are tolerated at construction and fail closed at
// publish time (so a half-wired deployment fails the create rather than routing open).
func NewDigestFeedPublisher(client identityv1.DigestFeedServiceClient, entries []*identityv1.DigestEntry, batchID string, opts ...grpc.CallOption) *DigestFeedPublisher {
	return &DigestFeedPublisher{client: client, entries: entries, batchID: batchID, opts: opts}
}

// PublishSessionDigests pushes the session's digest batch over DigestFeedService.
// DigestPublish and returns Routable iff the boundary acked it committed. Fail-closed:
// a nil client, an empty entry set, a transport error, or an uncommitted ack all return
// a non-nil error and a non-routable outcome — mint-before-attach (doc 16 §6.1) is
// satisfied only on a committed ack.
func (p *DigestFeedPublisher) PublishSessionDigests(ctx context.Context, sessionUUID string) (DigestPublishOutcome, error) {
	if p == nil || p.client == nil {
		return DigestPublishOutcome{}, errors.New("sessions: nil digest-feed client (fail-closed: session not routable)")
	}
	if sessionUUID == "" {
		return DigestPublishOutcome{}, errors.New("sessions: empty session uuid for digest publish (fail-closed)")
	}
	if len(p.entries) == 0 {
		// No digests to register = nothing to gate on; fail closed rather than mark a
		// session routable with no digests shadowing its credentials (doc 14 §7).
		return DigestPublishOutcome{}, errors.New("sessions: no digest entries to publish (fail-closed: session not routable)")
	}
	resp, err := p.client.DigestPublish(ctx, &identityv1.DigestPublishRequest{
		Session: &identityv1.DigestSessionRef{SessionUuid: sessionUUID},
		Entries: p.entries,
		BatchId: p.batchID,
	}, p.opts...)
	if err != nil {
		return DigestPublishOutcome{}, fmt.Errorf("sessions: DigestPublish for session %s: %w (fail-closed: session not routable)", sessionUUID, err)
	}
	out := DigestPublishOutcome{
		ConsumerID: resp.GetConsumerId(),
		BatchID:    resp.GetBatchId(),
		Routable:   resp.GetCommitted(),
	}
	if !resp.GetCommitted() {
		return out, fmt.Errorf("%w (consumer=%q batch=%q)", ErrDigestNotRoutable, resp.GetConsumerId(), resp.GetBatchId())
	}
	return out, nil
}

// ErrIsDigestNotRoutable reports whether err is the fail-closed digest-not-routable
// sentinel (an uncommitted ack or an armed-but-unwired publisher) — exposed so a create
// driver can distinguish a mint-before-attach gate failure (attributable: the digests
// did not land) from a transient transport fault. Paired with the launch/role refusal
// classifiers, it is the digest-axis fail-closed verdict the create sequence surfaces.
func ErrIsDigestNotRoutable(err error) bool {
	return errors.Is(err, ErrDigestNotRoutable) || errors.Is(err, ErrDigestPublisherUnwired)
}
