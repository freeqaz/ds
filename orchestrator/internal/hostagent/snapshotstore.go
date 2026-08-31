package hostagent

// snapshotstore.go is the host-agent-side ATOMIC SNAPSHOT STORE (POL-4 part 1;
// D36/D72, doc 13 §5, doc 15 §5.3). It sits DOWNSTREAM of the WatchPolicies
// subscription (subscribe.go): the subscription delivers composed
// boundaryv1.PolicySnapshots in seq order, deduplicated against the replay
// cursor; this store VERIFIES each one, PERSISTS it atomically, ACKs it back to
// the orchestrator, and FANS IT OUT on the host-local feed the three consumers
// (ds-dnsgate, ds-tlsproxy, the NFTables programmer) read.
//
// THE FROZEN VERIFY/ACK CONTRACT (D36/D72, doc 13 §5 "Snapshot identity"):
//
//   - Verify snapshot IDENTITY: content_hash MUST equal SHA-256 over the
//     TRANSPORTED document bytes (the produce-once / verify-only anti-drift rule,
//     doc 13 §5.1 — this store HASHES the bytes it received and NEVER
//     re-serializes the document), and the composed document MUST be structurally
//     valid (well-formed POL-1 v0 — the schema/semantic gate). Verification is
//     ALL-OR-NONE per the host (D72).
//   - On verify success: persist atomically via SnapshotPersister, advance the
//     in-memory applied (seq, snapshot) pointer, fan the snapshot out on the
//     host-local feed, and send AckPolicy(seq, content_hash) — EXACTLY ONE ack
//     per newly-applied seq (D36).
//   - On verify FAILURE (hash mismatch or invalid document): NACK = do NOT ack,
//     do NOT persist, do NOT advance the applied pointer, do NOT fan out. The
//     host stays FULLY on vN (the previous applied version) — there is no partial
//     apply (D72). A pinned host can still read its last valid snapshot.
//   - IDEMPOTENT (D72/D36): a snapshot whose seq is not strictly greater than the
//     applied seq is a DEDUP no-op — already-applied seqs are dropped (the
//     subscription cursor already drops most; this is the store's own backstop so
//     a re-delivered current snapshot never re-fans-out or re-acks).
//
// THE HOST-LOCAL FEED is how the three consumers learn of a new applied
// snapshot WITHOUT opening a control-plane policy stream (D72: exactly one
// WatchPolicies subscriber per host = this agent). Consumers also read the
// CURRENT applied snapshot synchronously (Current) — e.g. a consumer that starts
// or reconnects after the latest fan-out reads the live pointer rather than
// missing the edge. applied_seq advancement here is NOT the heartbeat's
// applied_seq: this is the host agent's RECEIVED/persisted version; the
// heartbeat's applied_seq is the post-sweep MIN over the three consumers (D72,
// heartbeat.go) and only ever advances after they finish applying.
//
// NEVER-LOG-THE-SECRET: this store logs nothing — the composed document is
// opaque bytes carried untouched through the frozen PolicySnapshot identity.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// DocumentValidator gates the composed policy document's SCHEMA / SEMANTIC
// validity (doc 13 §5 "Snapshot identity": valid POL-1 v0 per the embedded
// schema, semantically valid per guardrail rules). It is a SEAM: the canonical
// POL-1 v0 schema + structural validators live in ds-contracts (Rust, doc 13
// §3), and the three Rust consumers run the deep parse/evaluate gate in their
// prepare phase. The Go host agent runs a STRUCTURAL well-formedness gate here
// so a document that the consumers would universally reject is NACKed host-wide
// at the store, never persisted or fanned out (fail-closed, D72). The real
// host-side validator is injected; a test fake satisfies it identically.
//
// Validate returns nil for an acceptable document and a non-nil error (naming
// the defect) for one that must be NACKed. It MUST NOT mutate or re-serialize
// the document — it inspects the transported bytes only (the produce-once /
// verify-only rule, doc 13 §5.1).
type DocumentValidator interface {
	Validate(document []byte) error
}

// StructuralValidator is the default DocumentValidator: a stdlib-only,
// dependency-free structural well-formedness gate over the composed POL-1 v0
// document. It is deliberately CONSERVATIVE — it rejects only documents that are
// definitely malformed (empty, or missing the mandatory top-level
// schema_version/layer/posture keys the §3 strawman fixes), leaving the deep
// guardrail-semantic gate to the consumers' embedded ds-contracts policy-core
// (doc 13 §1 rule 1: the consumers' policy-core is the one policy brain — the Go
// store never reimplements composition/evaluation). This keeps the store
// fail-closed against obvious corruption without forking the Rust schema.
//
// A document the validator cannot even read as a mapping with the required keys
// is rejected; one that is structurally a POL-1 v0 layer passes to the consumers
// for the authoritative semantic gate.
type StructuralValidator struct{}

// requiredTopLevelKeys are the mandatory top-level POL-1 v0 keys (doc 13 §3
// strawman). A composed document missing any of these is malformed at the most
// basic level and is NACKed host-wide before persistence — it could not compose
// to a usable evaluator on any consumer.
var requiredTopLevelKeys = []string{"schema_version", "layer", "posture"}

// Validate runs the conservative structural gate. It rejects an empty document
// and one missing a mandatory top-level key. It does NOT parse the full POL-1
// grammar (that lives in ds-contracts / the consumers); it confirms the
// transported bytes are a non-empty document carrying the required top-level
// keys, so an obviously-corrupt or truncated payload NACKs here.
func (StructuralValidator) Validate(document []byte) error {
	if len(bytes.TrimSpace(document)) == 0 {
		return fmt.Errorf("composed policy document is empty")
	}
	for _, key := range requiredTopLevelKeys {
		if !hasTopLevelKey(document, key) {
			return fmt.Errorf("composed policy document is missing mandatory top-level key %q (POL-1 v0, doc 13 §3)", key)
		}
	}
	return nil
}

// hasTopLevelKey reports whether the document has a top-level `<key>:` mapping
// entry — a key at column 0 (no leading indentation), terminated by a colon
// that is followed by end-of-line or a space (a YAML mapping key, not a colon
// inside a value). This mirrors the ds-contracts reader's find-mapping-colon
// rule for the narrow purpose of the structural gate; it is NOT a full parser.
func hasTopLevelKey(document []byte, key string) bool {
	for _, raw := range bytes.Split(document, []byte("\n")) {
		// Top-level keys sit at column 0: a line beginning with whitespace is a
		// nested entry or a list item, never a top-level key.
		if len(raw) == 0 || raw[0] == ' ' || raw[0] == '\t' || raw[0] == '#' || raw[0] == '-' {
			continue
		}
		trimmed := bytes.TrimRight(raw, "\r")
		colon := len(key)
		if len(trimmed) <= colon {
			continue
		}
		if !bytes.Equal(trimmed[:colon], []byte(key)) {
			continue
		}
		// The character right after the key name must be the mapping colon.
		if trimmed[colon] != ':' {
			continue
		}
		// A mapping colon is followed by end-of-line or a space.
		if colon+1 == len(trimmed) || trimmed[colon+1] == ' ' {
			return true
		}
	}
	return false
}

// Compile-time proof the default validator satisfies the seam.
var _ DocumentValidator = StructuralValidator{}

// SnapshotStore is the host-agent atomic snapshot store. It is constructed once
// per host agent with its persistence seam, ack seam, and document validator,
// then driven by Apply for each snapshot the WatchPolicies subscription
// delivers. It owns the in-memory applied pointer (the current verified
// snapshot + seq) and the host-local fan-out feed the three consumers read.
//
// Concurrency: Apply is called from the single subscription pump goroutine, but
// Current/Subscribe may be called concurrently by consumer-facing code, so the
// applied pointer is guarded by a mutex. The fan-out feed is a buffered channel;
// see Subscribe for the slow-consumer contract.
type SnapshotStore struct {
	persister SnapshotPersister
	acker     AckPolicySender
	validator DocumentValidator

	mu         sync.RWMutex
	appliedSeq uint64                     // 0 until the first snapshot is applied (seq is a bigserial ≥ 1)
	applied    *boundaryv1.PolicySnapshot // the current verified+persisted snapshot; nil before the first apply
	hasApplied bool                       // distinguishes "applied seq 0" from "never applied" (seq is ≥1 so this is belt-and-suspenders)
	feed       chan *boundaryv1.PolicySnapshot
}

// SnapshotFeedBuffer is the depth of the host-local fan-out channel Subscribe
// returns. Policy snapshots are low-rate (org edits + fleet blocks + ask grants
// — doc 15 §5.3), so a small buffer absorbs a momentarily-busy consumer without
// unbounded memory; it is a rig-tuned value (doc 15 §10), never frozen.
const SnapshotFeedBuffer = 1

// NewSnapshotStore builds the store with its persistence, ack, and validation
// seams. A nil validator defaults to the conservative StructuralValidator so a
// caller that has no host-side validator yet still gets the fail-closed empty/
// missing-key gate (it never silently accepts an unvalidated document). The
// persister and acker are required.
func NewSnapshotStore(persister SnapshotPersister, acker AckPolicySender, validator DocumentValidator) (*SnapshotStore, error) {
	if persister == nil {
		return nil, fmt.Errorf("hostagent: NewSnapshotStore: nil SnapshotPersister")
	}
	if acker == nil {
		return nil, fmt.Errorf("hostagent: NewSnapshotStore: nil AckPolicySender")
	}
	if validator == nil {
		validator = StructuralValidator{}
	}
	return &SnapshotStore{
		persister: persister,
		acker:     acker,
		validator: validator,
		feed:      make(chan *boundaryv1.PolicySnapshot, SnapshotFeedBuffer),
	}, nil
}

// Apply verifies, persists, fans out, and acks one received snapshot, enforcing
// the full D36/D72 contract. The return values report the outcome:
//
//   - applied=true  → the snapshot verified and is now the applied version; it
//     was persisted, fanned out, and acked. err is nil.
//   - applied=false, err=nil → a DEDUP no-op: snap.Seq is not strictly greater
//     than the current applied seq (an already-applied or stale replay). The
//     host stays on its current version; nothing is persisted, fanned out, or
//     acked.
//   - applied=false, err!=nil → a NACK or a persistence/ack failure. The host
//     STAYS ON vN (the previous applied version) — the applied pointer did NOT
//     advance and the document was NOT fanned out. err names the defect.
//
// Order matters and is fail-closed: VERIFY (hash, then document) → PERSIST →
// advance applied pointer → FAN OUT → ACK. Verification and persistence run
// BEFORE the pointer advances, so any failure leaves the host fully on vN (D72
// all-or-none). The ack is LAST and only for a snapshot that is already durably
// applied — an ack proves the host saw and verified exactly this snapshot.
//
// A nil snapshot is a programming error from the caller (the subscription never
// forwards a nil); it is rejected as a NACK rather than panicking.
func (s *SnapshotStore) Apply(ctx context.Context, snap *boundaryv1.PolicySnapshot) (applied bool, err error) {
	if snap == nil {
		return false, fmt.Errorf("hostagent: snapshot store: nil snapshot")
	}

	// Idempotent dedup (D72/D36): a seq not strictly greater than the applied seq
	// is a no-op — never re-persisted, re-fanned, or re-acked. Read under the lock
	// so a concurrent reader cannot observe a half-updated pointer.
	s.mu.RLock()
	curSeq := s.appliedSeq
	had := s.hasApplied
	s.mu.RUnlock()
	if had && snap.GetSeq() <= curSeq {
		return false, nil
	}

	// VERIFY identity (1): content_hash MUST equal SHA-256 over the TRANSPORTED
	// document bytes. The store hashes the bytes it received and compares; it
	// NEVER re-serializes the document (produce-once / verify-only, doc 13 §5.1).
	// A mismatch is a NACK — the host stays on vN.
	want := snap.GetContentHash()
	got := sha256.Sum256(snap.GetDocument())
	if !bytes.Equal(want, got[:]) {
		return false, fmt.Errorf(
			"hostagent: snapshot store: content_hash mismatch for seq %d (NACK, host stays on vN): want %d bytes, transported bytes hash differs",
			snap.GetSeq(), len(want),
		)
	}

	// VERIFY identity (2): the composed document is structurally / semantically
	// valid (POL-1 v0). An invalid document is a NACK — host stays on vN.
	if verr := s.validator.Validate(snap.GetDocument()); verr != nil {
		return false, fmt.Errorf(
			"hostagent: snapshot store: invalid composed document for seq %d (NACK, host stays on vN): %w",
			snap.GetSeq(), verr,
		)
	}

	// PERSIST atomically BEFORE advancing the applied pointer. A persistence
	// failure aborts the apply (fail-closed): the host stays on vN, never acks,
	// and the pointer does not advance.
	if perr := s.persister.Store(ctx, snap); perr != nil {
		return false, fmt.Errorf(
			"hostagent: snapshot store: persist seq %d (NACK, host stays on vN): %w",
			snap.GetSeq(), perr,
		)
	}

	// ADVANCE the applied pointer under the lock — the snapshot is now durably
	// applied; Current/Subscribe consumers observe the new version atomically.
	s.mu.Lock()
	s.appliedSeq = snap.GetSeq()
	s.applied = snap
	s.hasApplied = true
	s.mu.Unlock()

	// FAN OUT on the host-local feed so a subscribed consumer learns of the new
	// version. A slow consumer blocks the feed rather than silently dropping a
	// version (a dropped snapshot would break the monotone cursor the consumers'
	// applied_seq min depends on); ctx cancel unblocks a wedged send so a host
	// drain is never stuck.
	select {
	case s.feed <- snap:
	case <-ctx.Done():
		// The snapshot IS applied and persisted; the consumer reads it via
		// Current on its next poll. Report the ctx error so the caller knows the
		// fan-out edge was not delivered on the feed (the apply itself succeeded).
		return true, fmt.Errorf("hostagent: snapshot store: fan-out of seq %d interrupted: %w", snap.GetSeq(), ctx.Err())
	}

	// ACK last (D36: exactly one ack per applied seq), AFTER the snapshot is
	// durably applied and fanned out. A failed ack does not un-apply the
	// snapshot — it is already the host's version — but is surfaced so the
	// caller's reconnect/retry policy can re-ack.
	if aerr := s.acker.Ack(ctx, snap.GetSeq(), snap.GetContentHash()); aerr != nil {
		return true, fmt.Errorf("hostagent: snapshot store: ack seq %d: %w", snap.GetSeq(), aerr)
	}
	return true, nil
}

// Current returns the host's CURRENT applied snapshot and its seq for the three
// consumers (ds-dnsgate / ds-tlsproxy / nft-writer) to read synchronously — e.g.
// a consumer that starts or reconnects reads the live pointer rather than
// waiting for the next fan-out edge. ok is false before the first snapshot is
// applied (a booting host serves nothing beyond NFT-1 default-deny until its
// first verified snapshot, D72); in that case snap is nil and seq is 0.
//
// The returned snapshot is the SHARED frozen message — consumers MUST treat it
// as read-only (the store hands out the same pointer it fanned out; callers
// never mutate a PolicySnapshot).
func (s *SnapshotStore) Current() (snap *boundaryv1.PolicySnapshot, seq uint64, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.hasApplied {
		return nil, 0, false
	}
	return s.applied, s.appliedSeq, true
}

// AppliedSeq returns the current applied seq (0 before the first apply). It is
// the host agent's RECEIVED/persisted policy version — distinct from the
// heartbeat's applied_seq, which is the post-sweep MIN over the three consumers
// (D72, heartbeat.go). A consumer uses this to detect whether a newer version
// than the one it has finished applying is available.
func (s *SnapshotStore) AppliedSeq() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.appliedSeq
}

// Subscribe returns the host-local fan-out feed: each newly-applied snapshot is
// sent here in seq order. It is the edge-triggered companion to Current (the
// level read): a consumer ranges over the feed to be woken on each new version,
// and reads Current on start/reconnect to pick up the latest without missing the
// edge. The feed is the SAME channel for all callers (a single host-local feed,
// D72) — the host agent's boundary-service integrations multiplex it to the
// three consumers; it is NOT a per-consumer fan-out the store owns.
//
// A snapshot is NEVER dropped on the feed: Apply blocks on a full feed rather
// than discarding a version (see Apply). The feed is closed only by the host
// agent's shutdown path, not here.
func (s *SnapshotStore) Subscribe() <-chan *boundaryv1.PolicySnapshot {
	return s.feed
}
