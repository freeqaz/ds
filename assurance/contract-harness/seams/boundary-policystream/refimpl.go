// SPDX-License-Identifier: Apache-2.0

package boundarypolicystream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// RefImpl is a minimal honest reference implementation of PolicyStreamService —
// the "real implementation" side of the dual-run. It implements exactly the doc
// 14 §2b / doc 15 §6 contract: a SINGLE append-only policy_log whose bigserial
// seq is THE one policy version namespace, end to end (D36/D72; doc 13 §1 rule
// 3). WatchPolicies serves the composed-document snapshot tail from from_seq
// (snapshot-then-delta), every frame a boundary.v1.PolicySnapshot whose
// (seq, content_hash, document) identity is the frozen shape (doc 13 §5). The
// seqs delivered are MONOTONIC and GAP-FREE — the resumable replay cursor. The
// composed-document body itself is free implementation behind the opaque payload;
// the frozen contract is the (seq, content_hash, document) identity, so the
// reference uses a deterministic synthetic composition that a fake programmed to
// the same derivation reproduces byte-identically.
//
// AckPolicy is the consumer acknowledgement (seq, content_hash): the consumer
// proves it saw and verified EXACTLY the snapshot at that seq before flipping to
// it (doc 13 §5). The reference validates the ack against the snapshot it would
// itself have streamed — an ack for a seq the log never produced, or with a
// content_hash that does not match that seq's composed document, is refused. A
// NACK in the real protocol is the ABSENCE of an ack (doc 14 §7); an ack that
// arrives carrying the wrong hash is a contract violation the seam catches.
//
// This is the M0 stand-in until the production orchestrator policy-stream server
// lands. When that lands it replaces RefImpl as the "real" end and the
// conformance suite is unchanged — which is the whole point: the suite is the
// contract, not the implementation. State is held in-memory; access is
// mutex-guarded so the in-process gRPC server is safe under concurrent calls.
type RefImpl struct {
	boundaryv1.UnimplementedPolicyStreamServiceServer

	mu  sync.Mutex
	log []*logRow // index i holds the row with seq i+1 — gap-free, monotonic
}

// logRow is one appended policy_log entry. seq is the assigned bigserial (THE
// single policy version, D72); document is the synthetic layer contribution this
// row adds to the deny-wins composition the snapshot carries (see
// composedDocumentLocked).
type logRow struct {
	seq      uint64
	document []byte
}

// NewRefImpl returns a reference PolicyStreamService server with an empty
// policy_log.
func NewRefImpl() *RefImpl {
	return &RefImpl{}
}

// WatchPolicies streams composed snapshots from from_seq (doc 14 §2b, D36/D72):
// the snapshot-then-delta tail of the policy_log. For each seq strictly greater
// than from_seq, up to the current tail, the server sends one PolicySnapshot
// frame carrying the composed document AS OF that seq. The seqs delivered are
// MONOTONIC and GAP-FREE (the gap-free bigserial is the resumable replay
// cursor), and the stream is RESUMABLE from any from_seq (the host agent's last
// persisted applied seq). A from_seq at or past the tail yields an empty
// catch-up — there is nothing newer to apply — which the host agent observes as
// "already current". from_seq = 0 replays the whole log from the start.
//
// Server-streaming is drained by the client the way the hypervisor seam drains
// ExportDiskDelta (suite.go's snapshotStreamObservation): Recv until io.EOF.
//
// The STREAM LIFECYCLE (mid-stream cancel, deadline expiry, slow-consumer
// back-pressure) is hardened separately — driven through the shared dualrun
// streaming affordance against dedicated bounded-park / eager-complete honest ends
// (streaming.go), not against this seeded-log reference. So this method serves only
// the genuine policy_log catch-up; there is no test-only reserved cursor.
func (s *RefImpl) WatchPolicies(req *boundaryv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[boundaryv1.WatchPoliciesResponse]) error {
	for _, snap := range s.SnapshotsFrom(req.GetFromSeq()) {
		if err := stream.Send(&boundaryv1.WatchPoliciesResponse{Snapshot: snap}); err != nil {
			return err
		}
	}
	return nil
}

// AckPolicy validates and records a consumer acknowledgement (doc 14 §2b, doc 13
// §5). The ack must echo a (seq, content_hash) the log actually produced: the
// seq must be in-range (1..tail) and the content_hash must equal the SHA-256
// over that seq's composed document. The ack PROVES the consumer verified
// exactly this snapshot before flipping to it — so an ack for a seq never
// streamed, or with a mismatched hash, is refused (the dishonest-ack case). The
// response envelope is deliberately empty (additive-extensible post-freeze).
func (s *RefImpl) AckPolicy(_ context.Context, req *boundaryv1.AckPolicyRequest) (*boundaryv1.AckPolicyResponse, error) {
	seq := req.GetSeq()
	if seq == 0 {
		return nil, status.Error(codes.InvalidArgument, "AckPolicyRequest.seq is required (the ack echoes PolicySnapshot.seq)")
	}
	s.mu.Lock()
	tail := uint64(len(s.log))
	var want []byte
	if seq <= tail {
		want = contentHash(s.composedDocumentLocked(seq))
	}
	s.mu.Unlock()
	if seq > tail {
		return nil, status.Errorf(codes.OutOfRange, "AckPolicyRequest.seq=%d past the policy_log tail=%d (cannot ack a snapshot that was never streamed)", seq, tail)
	}
	if !bytes.Equal(req.GetContentHash(), want) {
		return nil, status.Errorf(codes.FailedPrecondition, "AckPolicyRequest.content_hash does not match the snapshot at seq=%d (the ack must prove the consumer verified exactly this snapshot)", seq)
	}
	return &boundaryv1.AckPolicyResponse{}, nil
}

// Register registers the reference impl on a grpc.ServiceRegistrar.
func (s *RefImpl) Register(reg grpc.ServiceRegistrar) {
	boundaryv1.RegisterPolicyStreamServiceServer(reg, s)
}

// SeedRow appends a synthetic row directly, pre-loading the policy_log with
// history a WatchPolicies(from_seq) catch-up must replay. It is a test affordance
// on the reference impl — not a contract verb — used by the suite's dialers to
// stand up a non-empty log identically on both ends so the snapshot tail and the
// resumability cursor are stable regardless of scenario order. Synthetic fixtures
// only (D50).
func (s *RefImpl) SeedRow(document []byte) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := uint64(len(s.log)) + 1
	s.log = append(s.log, &logRow{seq: seq, document: document})
	return seq
}

// AskGrantMarker is the obviously-synthetic substring carried inside an
// ask-grant-with-TTL row's contribution to the composed document. The suite
// asserts it survives into the streamed snapshot's `document` payload, so the
// POL-5 grant-delivery vehicle (doc 16 §8.2: approvals return as session-scoped
// TTL'd allow grants delivered ON THE POLICY STREAM as composed-document content,
// not a second response contract — D18/D45/D53) is contract-checked, not just the
// (seq, content_hash, document) envelope. The document body's on-wire encoding is
// free implementation behind the opaque payload (doc 13 §5; the frozen contract is
// the snapshot identity), so this is a deterministic synthetic shape a fake
// programmed to the same derivation reproduces byte-identically.
const AskGrantMarker = "ds-synthetic-ask-grant-allow-once"

// AskGrantBody builds the synthetic ask-grant-with-TTL contribution a POL-5
// approval appends to the policy_log (doc 16 §8.2: an approval returns as a
// session-scoped TTL'd allow grant delivered on the policy stream, composed into
// the deny-wins document — the boundary never grows a second approval-response
// contract). The shape is the TTL/expiry envelope an allow-once grant carries:
// a synthetic grant id, the domain scope, an allow-once posture, the clamped TTL
// (doc 13 §4 admission timers), and the derived expiry. Deny ALWAYS wins over
// this allow in composition (doc 13 §1 rule 2), so the grant rides inside — never
// overrides — the deny-wins payload. Synthetic only (D50): no real grant ids,
// domains, sessions, or clocks.
//
// The document-schema specifics (field names/order/encoding) are intentionally
// NOT pinned here as a contract: they bind only once the deny-wins composed-document
// schema is fixed (POL-1 v0 lives in the policy-schema skeleton, doc 13 §3, never
// in this proto package). The suite asserts only that the grant's TTL/expiry shape
// SURVIVES end to end as opaque composed-document content — the grant-delivery
// vehicle — which is the part of the contract this seam owns.
func AskGrantBody() []byte {
	// answer_time + clamp(chain-min TTL, FLOOR, CEIL): a synthetic session-lifetime
	// allow-once TTL and the expiry it derives (deterministic, no wall clock).
	const synthAnswerTime = uint64(1000)
	const synthTTLSeconds = uint64(900) // ttl_ceil default (doc 13 §4 admission timers)
	expiry := synthAnswerTime + synthTTLSeconds
	return []byte(fmt.Sprintf(
		"%s|grant_id=ds-synthetic-grant-0001|scope=domain:ds-synthetic.example|posture=allow-once|ttl_s=%d|expiry=%d",
		AskGrantMarker, synthTTLSeconds, expiry,
	))
}

// SeedAskGrantRow appends a synthetic ask-grant-with-TTL row to the policy_log —
// the POL-5 vehicle: a returned approval composed into the deny-wins document and
// delivered on the WatchPolicies stream (doc 16 §8.2). It is a test affordance, not
// a contract verb; the suite installs it identically on both dual-run ends so the
// grant body rides the snapshot tail stably. Synthetic fixtures only (D50).
func (s *RefImpl) SeedAskGrantRow() uint64 {
	return s.SeedRow(AskGrantBody())
}

// CurrentSeq reports the tail seq of the policy_log (0 if empty). A test
// affordance for the suite's resumability and ack scenarios (the past-the-tail
// from_seq is CurrentSeq, observed identically on both ends).
func (s *RefImpl) CurrentSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint64(len(s.log))
}

// SnapshotAt returns the composed PolicySnapshot for a single in-range seq (or
// nil when out of range). It is a test affordance the suite uses to discover the
// exact (seq, content_hash) a downstream consumer would ack — the honest ack
// payload — without re-deriving the composition in the suite. Synthetic only.
func (s *RefImpl) SnapshotAt(seq uint64) *boundaryv1.PolicySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq == 0 || seq > uint64(len(s.log)) {
		return nil
	}
	doc := s.composedDocumentLocked(seq)
	return &boundaryv1.PolicySnapshot{
		Seq:         seq,
		ContentHash: contentHash(doc),
		Document:    doc,
	}
}

// SnapshotsFrom returns the composed snapshots for every seq strictly greater
// than fromSeq, up to the tail — the snapshot-then-delta catch-up. The slice is
// empty when fromSeq is at or past the tail. It is exported so the negative
// drift-gate dialer (external _test) can build the honest catch-up before
// injecting its seq-skip drift.
func (s *RefImpl) SnapshotsFrom(fromSeq uint64) []*boundaryv1.PolicySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	tail := uint64(len(s.log))
	out := make([]*boundaryv1.PolicySnapshot, 0, tail)
	for seq := fromSeq + 1; seq <= tail; seq++ {
		doc := s.composedDocumentLocked(seq)
		out = append(out, &boundaryv1.PolicySnapshot{
			Seq:         seq,
			ContentHash: contentHash(doc),
			Document:    doc,
		})
	}
	return out
}

// composedDocumentLocked produces the deny-wins composed document AS OF the given
// seq (doc 13 §1 rule 2). The caller holds s.mu. The composition here is a
// deterministic synthetic concatenation of each row's contribution up to seq, so
// a fake programmed to the same derivation produces byte-identical snapshots —
// the real composition is control-plane work behind this opaque payload (the
// frozen contract is the (seq, content_hash, document) identity, not the body).
func (s *RefImpl) composedDocumentLocked(seq uint64) []byte {
	doc := []byte("ds-synthetic-composed-policy")
	for i := uint64(0); i < seq && i < uint64(len(s.log)); i++ {
		doc = append(doc, '|')
		doc = append(doc, s.log[i].document...)
	}
	return doc
}

// contentHash is SHA-256 over the composed document — snapshot identity's
// content_hash (doc 13 §5; the produce-once / verify-only anti-drift rule). It is
// returned as the raw 32-byte digest so the observation records its length and
// the deterministic value collapses to one byte string across both ends.
func contentHash(document []byte) []byte {
	sum := sha256.Sum256(document)
	return sum[:]
}
