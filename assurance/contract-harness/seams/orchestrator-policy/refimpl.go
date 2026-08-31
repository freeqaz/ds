// SPDX-License-Identifier: Apache-2.0

package orchestratorpolicy

import (
	"context"
	"crypto/sha256"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// RefImpl is a minimal honest reference implementation of PolicyService — the
// "real implementation" side of the dual-run. It implements exactly the doc 15
// §5.3 contract: a SINGLE append-only policy_log whose bigserial seq is THE one
// policy version namespace (D36/D72). AppendPolicy and ApproveAsk both append a
// row, each assigned the next monotonic, gap-free seq from that one log; the log
// IS the audit trail (D36), so every row records its actor. WatchPolicies serves
// the composed-document snapshot tail from from_seq: snapshot-then-delta, every
// frame a boundary.v1.PolicySnapshot whose (seq, content_hash, document) identity
// is the frozen shape (the message is boundary-owned and imported, never
// re-declared — doc 15 §5.3 ownership mark).
//
// This is the M0 stand-in until the production orchestrator policy server lands.
// When that lands it replaces RefImpl as the "real" end and the conformance suite
// is unchanged — which is the whole point: the suite is the contract, not the
// implementation. State is held in-memory; access is mutex-guarded so the
// in-process gRPC server is safe under concurrent calls.
type RefImpl struct {
	orchestratorv1.UnimplementedPolicyServiceServer

	mu  sync.Mutex
	log []*logRow // index i holds the row with seq i+1 — gap-free, monotonic
}

// logRow is one appended policy_log entry. seq is the assigned bigserial (THE
// single policy version, D72); the composed document is the deny-wins composition
// the snapshot carries (here, the deterministic synthetic composition of the rows
// up to and including this seq — see composedDocument). kind/actor are the audit
// attributes (D36).
type logRow struct {
	seq      uint64
	actor    string
	kind     orchestratorv1.PolicyRowKind
	document []byte
}

// NewRefImpl returns a reference PolicyService server with an empty policy_log.
func NewRefImpl() *RefImpl {
	return &RefImpl{}
}

// AppendPolicy appends an authored policy row (doc 15 §5.3, D36). The actor is
// recorded — the log IS the audit trail. The row is assigned the next monotonic
// bigserial seq (THE single policy version namespace, D72) and returned.
func (s *RefImpl) AppendPolicy(_ context.Context, req *orchestratorv1.AppendPolicyRequest) (*orchestratorv1.AppendPolicyResponse, error) {
	if req.GetActor() == "" {
		return nil, status.Error(codes.InvalidArgument, "AppendPolicyRequest.actor is required (the log IS the audit trail, D36)")
	}
	row := s.appendLocked(req.GetActor(), orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ORG_EDIT, req.GetDocument())
	return &orchestratorv1.AppendPolicyResponse{Row: row}, nil
}

// ApproveAsk appends a §4.3 ask-grant row (doc 15 §5.3, POL-5): TTL'd,
// session-scoped, recorded under the SAME monotonic seq log as AppendPolicy —
// ask-grants are policy artifacts under the policy_log seq (doc 15 §4.3), not a
// second namespace. The actor (approver) is recorded for audit attribution (D36).
func (s *RefImpl) ApproveAsk(_ context.Context, req *orchestratorv1.ApproveAskRequest) (*orchestratorv1.ApproveAskResponse, error) {
	if req.GetActor() == "" {
		return nil, status.Error(codes.InvalidArgument, "ApproveAskRequest.actor is required (audit attribution, D36)")
	}
	if req.GetSessionUuid() == "" {
		return nil, status.Error(codes.InvalidArgument, "ApproveAskRequest.session_uuid is required (the grant is session-scoped)")
	}
	// The grant's contribution is derived from the ask correlation so a fake
	// programmed to the same derivation composes byte-identically.
	doc := grantContribution(req.GetSessionUuid(), req.GetToolUseId(), req.GetGrantScope())
	row := s.appendLocked(req.GetActor(), orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ASK_GRANT, doc)
	return &orchestratorv1.ApproveAskResponse{Row: row}, nil
}

// WatchPolicies streams composed snapshots from from_seq (doc 15 §5.3, D36/D72):
// the snapshot-then-delta tail of the policy_log. For each seq strictly greater
// than from_seq, up to the current tail, the server sends one PolicySnapshot
// frame carrying the composed document AS OF that seq. The seqs delivered are
// MONOTONIC and GAP-FREE (the gap-free bigserial is the resumable replay cursor),
// and the stream is RESUMABLE from any from_seq (the host agent's last persisted
// applied seq). A from_seq at or past the tail yields an empty catch-up — there
// is nothing newer to apply — which the host agent observes as "already current".
//
// Server-streaming is drained by the client the way the hypervisor seam drains
// ExportDiskDelta (suite.go's snapshotStreamObservation): Recv until io.EOF.
func (s *RefImpl) WatchPolicies(req *orchestratorv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[orchestratorv1.WatchPoliciesResponse]) error {
	if req.GetHostId() == "" {
		return status.Error(codes.InvalidArgument, "WatchPoliciesRequest.host_id is required (EXACTLY ONE subscriber per host, D72)")
	}
	for _, snap := range s.SnapshotsFrom(req.GetFromSeq()) {
		if err := stream.Send(&orchestratorv1.WatchPoliciesResponse{Snapshot: snap}); err != nil {
			return err
		}
	}
	return nil
}

// Register registers the reference impl on a grpc.ServiceRegistrar.
func (s *RefImpl) Register(reg grpc.ServiceRegistrar) {
	orchestratorv1.RegisterPolicyServiceServer(reg, s)
}

// SeedRow appends a synthetic row directly, pre-loading the policy_log with
// history a WatchPolicies(from_seq) catch-up must replay. It is a test affordance
// on the reference impl — not a contract verb — used by the suite's dialers to
// stand up a non-empty log identically on both ends so the snapshot tail and the
// resumability cursor are stable regardless of scenario order. Synthetic fixtures
// only (D50).
func (s *RefImpl) SeedRow(actor string, kind orchestratorv1.PolicyRowKind, document []byte) uint64 {
	return s.appendLocked(actor, kind, document).GetSeq()
}

// CurrentSeq reports the tail seq of the policy_log (0 if empty). A test
// affordance for the suite's resumability scenarios (the past-the-tail from_seq
// is CurrentSeq, observed identically on both ends).
func (s *RefImpl) CurrentSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint64(len(s.log))
}

// appendLocked appends one row under a fresh monotonic seq and returns the
// PolicyLogRow contract view. seq = len(log) after the append, so it is gap-free
// and strictly increasing (the bigserial invariant, D72).
func (s *RefImpl) appendLocked(actor string, kind orchestratorv1.PolicyRowKind, document []byte) *orchestratorv1.PolicyLogRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := uint64(len(s.log)) + 1
	row := &logRow{seq: seq, actor: actor, kind: kind, document: document}
	s.log = append(s.log, row)
	return &orchestratorv1.PolicyLogRow{
		Seq:         seq,
		Actor:       actor,
		AppendedAt:  appendedAt(seq),
		ContentHash: contentHash(s.composedDocumentLocked(seq)),
		Kind:        kind,
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

// --- deterministic synthetic derivations (D50) ------------------------------
//
// All of the following are obviously-synthetic, deterministic functions of the
// row contents so the reference impl and a fake programmed to the same contract
// observe identically. None contains a real policy body, actor, or session id.

// grantContribution derives a synthetic ask-grant policy contribution from the
// ask correlation keys. Deterministic so the composed snapshot is stable.
func grantContribution(sessionUUID, toolUseID, grantScope string) []byte {
	return []byte("grant:" + sessionUUID + "/" + toolUseID + "=" + grantScope)
}

// contentHash is SHA-256 over the composed document — snapshot identity's
// content_hash (doc 13 §5; the produce-once / verify-only anti-drift rule). It is
// returned as the raw 32-byte digest so the observation records its length and
// the deterministic value collapses to one byte string across both ends.
func contentHash(document []byte) []byte {
	sum := sha256.Sum256(document)
	return sum[:]
}

// appendedAt derives a deterministic synthetic unix-seconds stamp from the seq so
// the PolicyLogRow comparison is stable across real and fake (a wall clock would
// diverge between two independent processes). Obviously-synthetic epoch base.
func appendedAt(seq uint64) uint64 {
	const synthEpochBase = uint64(1_700_000_000) // obviously-synthetic fixed base
	return synthEpochBase + seq
}
