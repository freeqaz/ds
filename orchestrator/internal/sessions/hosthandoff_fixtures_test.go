// SPDX-License-Identifier: Apache-2.0

// Synthetic digest-feed fixtures for the host-handoff continuity tests (doc 16
// §6.3 default d; doc 15 — the orchestrator-owned redeploy choreography).
//
// WHY THIS FILE EXISTS. These are TEST-ONLY synthetic stand-ins for the live
// digest-feed wire (D50): an in-process DigestFeedService consumer (the shape
// the D109 host-agent ack-er serves), the shared ordering journal the no-gap
// proof reads from, and the SESSION/RAW entry-builder specialization the test
// preloads with. They are exercised ONLY by hosthandoff_test.go /
// hostredeploy_test.go and must NOT compile into the shipped sessions binary,
// so they live in this `_test.go` file rather than in the production
// hosthandoff.go controller. The PRODUCTION controller (runHostHandoff,
// runHostHandoffToConvergence, the synthLiveSession model + its
// synthEntriesForVariant/synthAlgo/synthCredClassFor entry stamping, the
// fail-closed/retry machinery) stays in hosthandoff.go because the redeploy
// entrypoint hostredeploy.go genuinely depends on it.
//
// SYNTHETIC ONLY (D50): there is no live host, boundary, or claude here — the
// hostConsumer's fault-injection knobs (publishErr/ackCommitted/dropEntries/
// revokeErr) drive the controller's fail-closed legs entirely in-process.

package sessions

import (
	"context"
	"sync"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// ---- the SESSION/RAW entry-builder the tests preload with ------------------

// synthEntriesFor builds the wire-shape DigestEntry set a publish carries for a
// session under keyID. It mirrors the identity producer's output shape (one
// entry per credential token) WITHOUT recomputing real HMACs — the orchestrator
// choreography only routes opaque entries + observes acks; the digest math is
// proven identity-side. The "digest" bytes are a synthetic, deterministic,
// non-reversible label (keyID|token) so the two hosts' loaded sets are
// distinguishable and a dropped entry is detectable; they are never real
// credential-derived material (D50).
//
// Every entry carries the FULL frozen doc 14 §7 shape: key_id, algo (HMAC-SHA-256
// + truncation length), digest, cred_class (ISSUED{service_id} | FORBIDDEN —
// spanning both oneof arms across the synthetic token set), scope, expiry, and
// variant_tag. algo + cred_class are FIXTURE FIDELITY to the frozen wire — the
// controller stays opaque to them (it never branches on cred_class), so a
// controller mishandling a cred_class-tagged entry would now surface, while
// routing semantics are unchanged.
//
// This is the default SESSION-scope / RAW-variant shape the test preloads (the
// pre-redeploy old-host publish + the step-1 new-host load in the step-by-step
// no-gap test) use. The scope/variant-parameterized form lives in the production
// synthEntriesForVariant (hosthandoff.go) — proving the controller is opaque to
// BOTH the scope (SESSION vs FLEET) and all four variant_tag encodings — and
// synthEntriesFor is the SESSION/RAW specialization of it, so the two never drift.
func synthEntriesFor(keyID string, creds []string) []*identityv1.DigestEntry {
	return synthEntriesForVariant(
		keyID, creds,
		identityv1.DigestScope_DIGEST_SCOPE_SESSION,
		identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW,
	)
}

func sessionUUIDOf(ref *identityv1.DigestSessionRef) string {
	if ref == nil {
		return ""
	}
	return ref.GetSessionUuid()
}

// ---- the host consumer (one of the two host states) ----------------------

// hostConsumer is an in-process DigestFeedService consumer standing in for ONE
// boundary host's digest-feed endpoint — the shape the D109 host-agent ack-er
// serves. It records, per session uuid, the entries currently LOADED + acked
// under each key id (the boundary's loaded set), and appends every publish/
// revoke to a SHARED, ordered journal so the cross-host ordering (new host
// loaded+acked BEFORE old host revoked) is observable from the wire.
//
// It can be told to fail or short its ack to exercise the controller's
// fail-closed leg (an incomplete new-host load must NOT trigger the old-host
// revoke). With its fault-injection knobs left at their defaults it is the
// faithful synthetic stand-in for a healthy host-agent ack-er (D50): there is
// no live boundary in this wave.
type hostConsumer struct {
	identityv1.UnimplementedDigestFeedServiceServer

	name    string          // "old" | "new" — for journal provenance
	journal *handoffJournal // shared across both hosts

	mu sync.Mutex
	// loaded[sessionUUID][keyID] = entries acked under that key for that session.
	loaded map[string]map[string][]*identityv1.DigestEntry

	// ackCommitted is the committed bit this host returns on a publish. A
	// freshly redeployed host that has not yet confirmed host-wide visibility
	// returns false here (fail-closed: the controller must not hand off).
	ackCommitted bool
	// publishErr, if set, is returned instead of acking (a transport-style
	// failure reaching the new host) — also fail-closed.
	publishErr error
	// dropEntries, if >0, ACKS committed but silently loads only the first
	// (len-dropEntries) entries — a "the load looked OK but lost an entry"
	// hazard the controller must catch by verifying the loaded set, not just
	// the committed bit.
	dropEntries int
	// revokeErr, if set, is returned from DigestRevoke once revokeErrAfter
	// successful revokes have committed — the OLD-host step-2 analogue of
	// publishErr. It models a mid-teardown transport/host failure: the first
	// revokeErrAfter sessions tear down cleanly, then the next revoke errors.
	// The controller MUST fail closed here (incompleteHandoffError,
	// oldHostRevoked=false) — there is no continuity gap because the new host
	// already shadows every session, but the old host is left PARTIALLY revoked
	// and the redeploy must be retried. The revoke is idempotent (see
	// DigestRevoke), so a retry re-issuing the already-done revokes is a no-op.
	revokeErr error
	// revokeErrAfter is how many revokes commit before revokeErr fires (so a
	// MID-loop failure, not a first-call failure, is exercised). Ignored when
	// revokeErr is nil.
	revokeErrAfter int
	// revokeCount counts committed revokes, to time revokeErr (guarded by mu).
	revokeCount int
}

func newHostConsumer(name string, j *handoffJournal) *hostConsumer {
	return &hostConsumer{
		name:         name,
		journal:      j,
		loaded:       map[string]map[string][]*identityv1.DigestEntry{},
		ackCommitted: true,
	}
}

func (h *hostConsumer) DigestPublish(_ context.Context, req *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
	if h.publishErr != nil {
		h.journal.record(handoffEvent{host: h.name, op: "publish-err", session: sessionUUIDOf(req.GetSession())})
		return nil, h.publishErr
	}
	sess := sessionUUIDOf(req.GetSession())
	loadEntries := req.GetEntries()
	if h.dropEntries > 0 && len(loadEntries) > h.dropEntries {
		loadEntries = loadEntries[:len(loadEntries)-h.dropEntries]
	} else if h.dropEntries > 0 {
		loadEntries = nil
	}
	// A publish is IDEMPOTENT per (session, key_id): it REPLACES that key's loaded
	// set with exactly the entries this request carries, rather than accumulating
	// across calls. A single publish therefore loads exactly its entry set (the
	// historical behavior — every prior caller publishes a given (session, key)
	// once), and a RE-publish of the same set on a retry re-confirms it WITHOUT
	// duplicate-shadowing (the loaded count stays == the set size, not doubled).
	// This is faithful to a host-agent's loaded set, which is keyed by digest key
	// id, not an append-only log. Entries within one request all share a key_id, so
	// they are grouped per key_id and assigned, leaving other keys untouched.
	perKey := map[string][]*identityv1.DigestEntry{}
	for _, e := range loadEntries {
		perKey[e.GetKeyId()] = append(perKey[e.GetKeyId()], e)
	}
	h.mu.Lock()
	byKey := h.loaded[sess]
	if byKey == nil {
		byKey = map[string][]*identityv1.DigestEntry{}
		h.loaded[sess] = byKey
	}
	for kid, ents := range perKey {
		byKey[kid] = ents // replace this key's loaded set (idempotent re-confirm)
	}
	h.mu.Unlock()
	h.journal.record(handoffEvent{host: h.name, op: "publish", session: sess, committed: h.ackCommitted})
	return &identityv1.DigestPublishResponse{
		BatchId:    req.GetBatchId(),
		Session:    req.GetSession(),
		ConsumerId: "synth-host-agent-" + h.name, // the D109 ack-er role, per host
		Committed:  h.ackCommitted,
	}, nil
}

// DigestRevoke tears the named key ids off this host's loaded set for the
// session. It is IDEMPOTENT by construction: revoking a key id that is absent
// (already revoked, or never loaded) deletes nothing and still commits, so the
// controller can safely RETRY a revoke after a mid-teardown failure without a
// double-revoke hazard (deleting an absent map entry is a no-op). When revokeErr
// is configured it fires AFTER revokeErrAfter successful revokes, modelling a
// mid-loop old-host failure — the request that errors does NOT delete and is NOT
// journaled as a committed revoke (it is recorded as "revoke-err").
func (h *hostConsumer) DigestRevoke(_ context.Context, req *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
	sess := sessionUUIDOf(req.GetSession())
	h.mu.Lock()
	if h.revokeErr != nil && h.revokeCount >= h.revokeErrAfter {
		h.mu.Unlock()
		h.journal.record(handoffEvent{host: h.name, op: "revoke-err", session: sess})
		return nil, h.revokeErr
	}
	if byKey := h.loaded[sess]; byKey != nil {
		for _, kid := range req.GetKeyIds() {
			delete(byKey, kid) // idempotent: deleting an absent key id is a no-op
		}
	}
	h.revokeCount++
	h.mu.Unlock()
	h.journal.record(handoffEvent{host: h.name, op: "revoke", session: sess, committed: true})
	return &identityv1.DigestRevokeResponse{
		Session:    req.GetSession(),
		ConsumerId: "synth-host-agent-" + h.name,
		Committed:  true,
	}, nil
}

// shadows reports whether this host currently has at least one entry loaded for
// the session under ANY key — i.e. whether it would shadow that session's
// credentials right now. This is the per-instant "is this session protected?"
// probe the no-gap guarantee turns on.
func (h *hostConsumer) shadows(sessionUUID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ents := range h.loaded[sessionUUID] {
		if len(ents) > 0 {
			return true
		}
	}
	return false
}

// loadedCountUnder returns how many entries this host has loaded for the session
// under keyID — used to confirm the new host received the FULL set (no dropped
// entry) before the handoff completes.
func (h *hostConsumer) loadedCountUnder(sessionUUID, keyID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.loaded[sessionUUID][keyID])
}

// entriesUnder returns a copy of the entry slice this host has loaded for the
// session under keyID — used by the test to assert the FULL frozen doc 14 §7
// shape of what actually crossed the wire and landed in the loaded set (the
// entry pointers are shared, but the slice header is the host's own copy so a
// caller iterating cannot race the loaded map).
func (h *hostConsumer) entriesUnder(sessionUUID, keyID string) []*identityv1.DigestEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	src := h.loaded[sessionUUID][keyID]
	out := make([]*identityv1.DigestEntry, len(src))
	copy(out, src)
	return out
}

// ---- the shared ordering journal -----------------------------------------

type handoffEvent struct {
	host      string // "old" | "new"
	op        string // "publish" | "publish-err" | "revoke"
	session   string
	committed bool
}

// handoffJournal is the single ordered event log across BOTH host consumers.
// The no-gap proof reads from here: the index of the new host's committed
// publish for a session must come strictly BEFORE the index of the old host's
// revoke for that session.
type handoffJournal struct {
	mu     sync.Mutex
	events []handoffEvent
}

func (j *handoffJournal) record(e handoffEvent) {
	j.mu.Lock()
	j.events = append(j.events, e)
	j.mu.Unlock()
}

// firstIndex returns the index of the first event matching host/op/session, or
// -1 if none. The no-gap ordering check compares these indices.
func (j *handoffJournal) firstIndex(host, op, session string, committedOnly bool) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i, e := range j.events {
		if e.host == host && e.op == op && e.session == session {
			if committedOnly && !e.committed {
				continue
			}
			return i
		}
	}
	return -1
}

func (j *handoffJournal) has(host, op, session string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range j.events {
		if e.host == host && e.op == op && e.session == session {
			return true
		}
	}
	return false
}
