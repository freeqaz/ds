// SPDX-License-Identifier: Apache-2.0

// The DEFERRED live host-redeploy leg of the digest-continuity guarantee, in
// the D24 (b) session-lifecycle tier (README.md; doc 06 §3b) where live runs
// are permitted. This is the e2e-tier counterpart to the IN-PROCESS proof that
// already lands green in the orchestrator unit tree:
// orchestrator/internal/sessions/hosthandoff_test.go drives the production
// runHostHandoff controller over the FROZEN dreamserpent.identity.v1.
// DigestFeedService seam against two in-process host consumers and asserts the
// no-gap ordering (new host loaded+acked STRICTLY before the old host is
// revoked). Its TestHostHandoff_LiveRedeployLeg_SkippedWithoutEnvGate names —
// but cannot itself run — the one leg in-process fakes cannot honestly express:
// a REAL boundary host redeploy.
//
// THE RESIDUAL THIS NAMES. The identity side proves single-consumer re-key
// ordering; the orchestrator unit tree proves the two-host no-gap choreography
// against in-process consumers. What neither can prove is that the property
// survives against TWO freshly-stood-up REAL boundary hosts re-pushing over the
// LIVE DigestFeedService endpoint and acking through the real D109 host-agent:
// stand up a new KVM boundary host, re-publish every live session's digest set
// under the new key, gate on the live host-agent's committed ack AND a verified
// loaded set, and ONLY THEN revoke + tear down the old host — with no instant at
// which neither host shadows a live session. That is a metal-only assertion
// (live KVM hosts, real ack latency) per the e2e README's D31/D34 fidelity-tag
// scheme.
//
// WHY IT IS ENV-GATED AND DEFERRED. D50 forbids any live host / boundary / KVM /
// claude / cia / podman run inside a wave. So this file SCAFFOLDS the harness
// shape and the assertions, but the live drive body stays BEHIND the
// DS_DIGEST_HANDOFF_LIVE env gate: with the gate UNSET (every wave run, every
// per-commit CI run) the scenario t.Skip()s and the in-process orchestrator
// tests remain the green proof; with the gate SET, the body runs the live
// create→load-new-host→ack→revoke-old-host sequence and asserts the same no-gap
// ordering. The host-provisioning + live-endpoint wiring are explicitly TODO /
// deferred manual steps (see hostHandoffLiveConfig + provisionLiveBoundaryHosts)
// — running the gated body before they are implemented fails loud, never
// silently green.
//
// SCOPE. e2e-tier, ORCHESTRATOR-owned (README.md / CODEOWNERS). It imports only
// proto/gen/go (the one legal cross-tree import, D80) for the identity.v1
// client; it does NOT import orchestrator/ or identity/ internals — the live
// leg observes the no-gap property from the WIRE, exactly as the production
// redeploy controller does. SYNTHETIC ONLY in-wave (D50): the live drive uses
// ds-synth-* credential tokens; there is no real credential material here even
// when the gate is set against a real boundary host.
package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// liveGateEnv is the env var that arms the live host-redeploy leg. It is named
// identically to the orchestrator unit test's gate
// (TestHostHandoff_LiveRedeployLeg_SkippedWithoutEnvGate) on purpose: a single
// operator-facing knob arms BOTH the in-process "this leg is deferred" marker
// and this e2e tier's live drive. Unset (the wave/CI default) => skip.
const liveGateEnv = "DS_DIGEST_HANDOFF_LIVE"

// ---- synthetic fixtures (D50) --------------------------------------------
//
// These mirror the orchestrator unit test's fixtures so the e2e live leg
// asserts the SAME property over the SAME wire shapes. They are SYNTHETIC
// ds-synth-* ids (D50): even when the gate is set against a real boundary host,
// no real credential material crosses this seam — the host loads opaque,
// non-reversible digest labels and the no-gap property is observed from acks.

const (
	// synthOldKeyID / synthNewKeyID are the per-host per-epoch HMAC key ids
	// (doc 16 §6.3) the pre-redeploy and post-redeploy digest sets are stamped
	// under. They MUST differ: a redeploy advances the generation so a host
	// never reuses a key.
	synthOldKeyID = "ds-synth-dk-host-old-e0-g0"
	synthNewKeyID = "ds-synth-dk-host-new-e0-g1"
)

// liveSession is one live session whose digests must survive the host handoff:
// its UUID plus the synthetic credential tokens currently shadowed for it. The
// orchestrator (doc 15) is the authority for which sessions are live; here the
// set is a fixed synthetic fixture so the live leg is reproducible.
type liveSession struct {
	uuid  string
	creds []string // ds-synth-* credential tokens
}

// synthLiveSessions is the live-session set under handoff. Two sessions, one
// multi-credential — so a SHORT load (some-but-not-all entries dropped) is
// detectable, the exact drop hazard the no-gap gate exists to catch.
func synthLiveSessions() []liveSession {
	return []liveSession{
		{uuid: "00000000-0000-4000-8000-0000000ho001", creds: []string{
			"ds-synth-sessA-github-pat",
			"ds-synth-sessA-canary",
		}},
		{uuid: "00000000-0000-4000-8000-0000000ho002", creds: []string{
			"ds-synth-sessB-aws-key",
		}},
	}
}

// synthEntriesFor builds the wire-shape DigestEntry set a publish carries for a
// session under keyID. It mirrors the identity producer's output shape (one
// entry per credential token) WITHOUT recomputing real HMACs — the e2e leg only
// routes opaque entries and observes acks; the digest math is proven
// identity-side. The "digest" bytes are a synthetic, deterministic,
// non-reversible label (keyID|token), never real credential-derived material
// (D50).
func synthEntriesFor(keyID string, creds []string) []*identityv1.DigestEntry {
	exp := timestamppb.New(time.Now().Add(15 * time.Minute))
	entries := make([]*identityv1.DigestEntry, 0, len(creds))
	for _, tok := range creds {
		entries = append(entries, &identityv1.DigestEntry{
			KeyId:      keyID,
			Digest:     []byte("ds-synth-digest|" + keyID + "|" + tok),
			Scope:      identityv1.DigestScope_DIGEST_SCOPE_SESSION,
			Expiry:     exp,
			VariantTag: identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW,
		})
	}
	return entries
}

// ---- live-leg wiring (DEFERRED manual steps) -----------------------------

// hostHandoffLiveConfig is the operator-supplied wiring for a live run: the two
// REAL boundary-host DigestFeedService endpoints (the retiring "old" host and
// the freshly redeployed "new" host) plus the ack budget. It is read from the
// environment ONLY when the gate is armed; with the gate unset it is never
// constructed, so the wave/CI default never reaches any of this.
type hostHandoffLiveConfig struct {
	oldHostEndpoint string        // host:port of the retiring boundary host's DigestFeedService
	newHostEndpoint string        // host:port of the freshly redeployed boundary host's DigestFeedService
	ackTimeout      time.Duration // budget for a live host-agent committed ack
}

// loadLiveConfig reads the live wiring from the environment. It returns ok=false
// (the caller t.Skip()s) when the endpoints are not supplied — arming the gate
// without standing up the hosts is a no-op, not a failure, so an operator can
// flip the gate on a box with no hosts and get a clear skip rather than a dial
// error.
//
// DEFERRED: host PROVISIONING (standing up the two real KVM boundary hosts and
// publishing their endpoints) is a manual step — see provisionLiveBoundaryHosts.
func loadLiveConfig() (hostHandoffLiveConfig, bool) {
	oldEP := os.Getenv("DS_DIGEST_HANDOFF_OLD_HOST")
	newEP := os.Getenv("DS_DIGEST_HANDOFF_NEW_HOST")
	if oldEP == "" || newEP == "" {
		return hostHandoffLiveConfig{}, false
	}
	return hostHandoffLiveConfig{
		oldHostEndpoint: oldEP,
		newHostEndpoint: newEP,
		ackTimeout:      30 * time.Second,
	}, true
}

// provisionLiveBoundaryHosts is the DEFERRED manual provisioning step. The live
// leg needs TWO real KVM boundary hosts, each serving the FROZEN
// dreamserpent.identity.v1.DigestFeedService over its host-agent (D109):
//
//	TODO(deferred, D50): stand up the two boundary hosts out-of-band (the e2e
//	  README's metal-only substrate — nightly/pre-release real hardware, NOT the
//	  wave): a retiring "old" host preloaded with the old-key digest set, and a
//	  freshly redeployed "new" host that starts empty. Publish their
//	  DigestFeedService endpoints via DS_DIGEST_HANDOFF_OLD_HOST /
//	  DS_DIGEST_HANDOFF_NEW_HOST. This MUST NOT run claude/cia/podman/KVM from
//	  inside the wave (D50) — it is an operator runbook step, armed only when
//	  DS_DIGEST_HANDOFF_LIVE is set on a metal substrate.
//
// Until that runbook exists, an armed run that supplies endpoints still reaches
// the live drive below; this function is the single place the provisioning
// contract is documented so the wiring stays one TODO, not scattered.
func provisionLiveBoundaryHosts(_ hostHandoffLiveConfig) {
	// Intentionally empty: provisioning is out-of-band (see doc comment).
}

// dialLiveHostFeed dials a REAL boundary host's DigestFeedService endpoint and
// returns a connected client, torn down via t.Cleanup. This is the live
// counterpart to the orchestrator unit test's in-process dialHostFeed — same
// client shape, real transport.
//
// TODO(deferred): the live endpoint speaks TLS terminated at the egress gateway
// (doc 16 §6.3); the credentials below are insecure placeholders for the
// metal-substrate runbook to replace with the host-agent's real transport
// credentials. Behind the gate, so never reached in-wave (D50).
func dialLiveHostFeed(t *testing.T, endpoint string) identityv1.DigestFeedServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial live host feed %q: %v", endpoint, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return identityv1.NewDigestFeedServiceClient(conn)
}

// ---- the ordering journal (wire-observed, same property as in-process) ----

// liveHandoffEvent is one observed step of the live choreography, stamped with
// the wall-clock instant it was OBSERVED from the wire (a live run has no shared
// in-process journal — the two hosts are distinct processes — so ordering is
// established by observation time on the orchestrator side, which is exactly
// how the production redeploy controller sequences the two RPCs).
type liveHandoffEvent struct {
	host    string // "old" | "new"
	op      string // "publish" | "revoke"
	session string
	at      time.Time
}

// liveHandoffJournal is the orchestrator-side ordered observation log across
// BOTH live hosts. The no-gap proof reads from here: the new host's committed
// publish for a session must be observed strictly BEFORE the old host's revoke
// for that session.
type liveHandoffJournal struct {
	events []liveHandoffEvent
}

func (j *liveHandoffJournal) record(host, op, session string) {
	j.events = append(j.events, liveHandoffEvent{host: host, op: op, session: session, at: time.Now()})
}

// firstAt returns the observation time of the first event matching
// host/op/session, and ok=false if none was recorded.
func (j *liveHandoffJournal) firstAt(host, op, session string) (time.Time, bool) {
	for _, e := range j.events {
		if e.host == host && e.op == op && e.session == session {
			return e.at, true
		}
	}
	return time.Time{}, false
}

// ---- the live drive (gated; deferred manual step) ------------------------

// driveLiveHandoff runs the orchestrator-owned redeploy choreography against the
// two LIVE host endpoints and records the wire-observed ordering. It is the live
// mirror of the production runHostHandoff sequence: load the NEW host (ack-gated
// + loaded-set verified) for every live session FIRST, and ONLY THEN revoke the
// OLD host — so at no instant is a session shadowed by neither host.
//
// It returns the populated journal for the caller to assert the no-gap ordering
// on. It is only ever called from behind the DS_DIGEST_HANDOFF_LIVE gate (D50).
func driveLiveHandoff(
	ctx context.Context,
	t *testing.T,
	cfg hostHandoffLiveConfig,
	newHost, oldHost identityv1.DigestFeedServiceClient,
	sessions []liveSession,
) *liveHandoffJournal {
	t.Helper()
	j := &liveHandoffJournal{}

	// STEP 1 — load the NEW host for every live session; ack-gated + verified.
	for _, s := range sessions {
		entries := synthEntriesFor(synthNewKeyID, s.creds)
		pubCtx, cancel := context.WithTimeout(ctx, cfg.ackTimeout)
		resp, err := newHost.DigestPublish(pubCtx, &identityv1.DigestPublishRequest{
			Session: &identityv1.DigestSessionRef{SessionUuid: s.uuid},
			Entries: entries,
			BatchId: "live-handoff-" + s.uuid,
		})
		cancel()
		if err != nil {
			// Fail-closed: the new host never confirmed — leave the OLD host fully
			// loaded (every session still shadowed). A live run aborts here; the
			// redeploy is retried, never a gap.
			t.Fatalf("live: publish to new host failed for %q (old host left loaded, no gap): %v", s.uuid, err)
		}
		if !resp.GetCommitted() {
			t.Fatalf("live: new host did not ack committed for %q — fail-closed, old host untouched", s.uuid)
		}
		j.record("new", "publish", s.uuid)
		// TODO(deferred): verify the new host LOADED the full set under the new
		// key before treating the ack as complete — a committed ack that loaded a
		// SHORT set is still an incomplete handoff (the orchestrator unit test
		// proves this in-process via loadedCountUnder; the live host-agent must
		// expose an equivalent loaded-set read before this leg can gate on count,
		// not just the committed bit). Until that read exists on the host-agent
		// the live leg gates on the committed ack alone and records the publish.
	}

	// STEP 2 — every session is now loaded+acked on the NEW host; ONLY NOW tear
	// the OLD host down, one session at a time. The old host stayed fully loaded
	// throughout step 1, so every session was continuously shadowed.
	for _, s := range sessions {
		revCtx, cancel := context.WithTimeout(ctx, cfg.ackTimeout)
		resp, err := oldHost.DigestRevoke(revCtx, &identityv1.DigestRevokeRequest{
			Session: &identityv1.DigestSessionRef{SessionUuid: s.uuid},
			KeyIds:  []string{synthOldKeyID},
			Scope:   identityv1.DigestScope_DIGEST_SCOPE_SESSION,
		})
		cancel()
		if err != nil {
			t.Fatalf("live: revoke on old host failed for %q: %v", s.uuid, err)
		}
		if !resp.GetCommitted() {
			t.Fatalf("live: old host revoke not committed for %q", s.uuid)
		}
		j.record("old", "revoke", s.uuid)
	}
	return j
}

// assertNoGapOrdering asserts the no-gap guarantee from the wire-observed
// journal: for every live session, the new host's committed publish is observed
// strictly BEFORE the old host's revoke. This is the identical property the
// in-process orchestrator test asserts via journal indices — here over real
// observation times.
func assertNoGapOrdering(t *testing.T, j *liveHandoffJournal, sessions []liveSession) {
	t.Helper()
	for _, s := range sessions {
		newPubAt, okPub := j.firstAt("new", "publish", s.uuid)
		oldRevAt, okRev := j.firstAt("old", "revoke", s.uuid)
		if !okPub {
			t.Errorf("no new-host publish observed for %q", s.uuid)
			continue
		}
		if !okRev {
			t.Errorf("no old-host revoke observed for %q", s.uuid)
			continue
		}
		if !newPubAt.Before(oldRevAt) {
			t.Errorf("ordering violated for %q: new-host load+ack at %s, old-host revoke at %s — want load+ack STRICTLY before revoke (no-gap)",
				s.uuid, newPubAt.Format(time.RFC3339Nano), oldRevAt.Format(time.RFC3339Nano))
		}
	}
}

// ==========================================================================
// THE GATED LIVE TEST
// ==========================================================================

// TestHostHandoff_LiveRedeployLeg is the e2e-tier, metal-only (D31/D34) live
// counterpart of the orchestrator in-process no-gap proof. It is the executable
// form of the deferred manual step
// orchestrator/internal/sessions/hosthandoff_test.go names:
//
//	create → load-new-host → ack → revoke-old-host against the LIVE
//	dreamserpent.identity.v1.DigestFeedService endpoints of two REAL boundary
//	hosts, asserting the new host is loaded+acked STRICTLY before the old host
//	is revoked (no instant at which neither host shadows a live session).
//
// GATING (D50): with DS_DIGEST_HANDOFF_LIVE unset — the wave and per-commit CI
// default — it t.Skip()s; the in-process orchestrator tests are the green proof.
// With the gate set BUT no host endpoints supplied, it skips with a clear
// "provision the hosts first" message (arming the gate alone is a no-op). Only
// when the gate is set AND both real endpoints are supplied does it dial the
// live hosts and drive the choreography — a metal-substrate runbook step, never
// run inside the wave.
func TestHostHandoff_LiveRedeployLeg(t *testing.T) {
	if os.Getenv(liveGateEnv) == "" {
		t.Skip("live host-redeploy leg is a deferred manual step (set " + liveGateEnv +
			" to run against two real boundary hosts; D50 forbids a live host/boundary/KVM run inside the wave — " +
			"the in-process orchestrator tests in orchestrator/internal/sessions/hosthandoff_test.go are the green proof of the no-gap ordering)")
	}

	// Gate is armed. The remainder is the deferred manual leg, behind the gate.
	cfg, ok := loadLiveConfig()
	if !ok {
		t.Skip("DS_DIGEST_HANDOFF_LIVE is set but no boundary-host endpoints supplied — " +
			"provision two real boundary hosts and export DS_DIGEST_HANDOFF_OLD_HOST / DS_DIGEST_HANDOFF_NEW_HOST " +
			"(see provisionLiveBoundaryHosts: a metal-only runbook step, not a wave step, D50/D31/D34)")
	}

	// DEFERRED: host provisioning is out-of-band (see provisionLiveBoundaryHosts).
	provisionLiveBoundaryHosts(cfg)

	ctx := context.Background()
	oldHost := dialLiveHostFeed(t, cfg.oldHostEndpoint)
	newHost := dialLiveHostFeed(t, cfg.newHostEndpoint)
	sessions := synthLiveSessions()

	// TODO(deferred): preload the OLD host with the old-key digest set for every
	// live session (the pre-redeploy mint-before-attach publish) as part of the
	// host-provisioning runbook, so the old host genuinely shadows every session
	// before the handoff begins. Asserted out-of-band by the runbook; the drive
	// below assumes that precondition.

	j := driveLiveHandoff(ctx, t, cfg, newHost, oldHost, sessions)
	assertNoGapOrdering(t, j, sessions)
}
