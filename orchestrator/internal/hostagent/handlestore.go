package hostagent

// handlestore.go declares the two SEAMS the POL-4 snapshot store (snapshotstore.go)
// drives outward: the on-host atomic snapshot persistence and the consumer ACK
// path back to the orchestrator. Both are interfaces (the package's pinned-later
// seam idiom — like HandleStore and HeartbeatDialer): a test fake satisfies each
// in-memory; the real on-host / generated-client impls are owner-landed.
//
// Per D72/D36 these two seams are the ONLY outward effects the store has:
//   - SnapshotPersister writes the verified, versioned snapshot to host-local
//     durable storage ATOMICALLY (no torn write — a reader on the host-local feed
//     never observes a half-written snapshot). This is the on-host substrate the
//     three consumers' prepare/commit barrier reads from; it is LOCAL host state,
//     distinct from control-plane Postgres (D6).
//   - AckPolicySender sends AckPolicy(seq, content_hash) back to the orchestrator
//     AFTER a snapshot verifies and persists (D36: exactly one ACK per seq; D72:
//     a NACK is the ABSENCE of an ACK — a verification failure simply never acks,
//     and the host stays on vN).
//
// NEVER-LOG-THE-SECRET: neither seam logs the composed document; it crosses as
// opaque bytes inside the frozen PolicySnapshot identity.

import (
	"context"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// SnapshotPersister is the host-LOCAL atomic snapshot persistence seam (the
// HandleStore seam doc.go names for on-host persistence; doc 15 §5.6). The store
// writes each VERIFIED snapshot here before it advances the in-memory applied
// pointer and acks, so a host-agent restart can recover its last applied version
// from durable storage rather than from the control plane (D6: control-plane
// state never lives on hosts).
//
// Store MUST be ATOMIC: an implementation writes to a temp path and renames, or
// equivalent, so a concurrent read on the host never observes a torn snapshot.
// An error from Store ABORTS the apply for that seq — the store does NOT ack and
// does NOT advance the applied pointer (fail-closed: the host stays on vN, D72).
//
// It is a SEAM: a test fake satisfies it in-memory; the real on-host durable
// impl is owner-landed. Data crosses as the frozen boundaryv1.PolicySnapshot,
// never an on-disk type.
type SnapshotPersister interface {
	// Store atomically persists snap as the versioned snapshot for snap.Seq. It
	// MUST NOT partially write. An error is fatal to this seq's apply (the caller
	// stays on vN and never acks).
	Store(ctx context.Context, snap *boundaryv1.PolicySnapshot) error
}

// AckPolicySender sends the consumer ACK (seq, content_hash) back to the
// orchestrator over the boundary.v1 PolicyStreamService.AckPolicy seam
// (D36/D72). The store calls it EXACTLY ONCE per newly-applied seq, AFTER the
// snapshot verifies and persists — never before (an ack proves the host saw and
// verified exactly this snapshot). A NACK is modelled by simply NOT calling Ack
// (D72: the absence of an ack for a seq is the negative; there is no nack field).
//
// It is satisfied natively by the generated PolicyStreamServiceClient (via
// NewAckPolicySender below) and identically by a test fake, so the store is
// exercised without a live grpc dial.
type AckPolicySender interface {
	// Ack acknowledges (seq, content_hash). An error is surfaced to the caller —
	// the snapshot is already persisted and applied locally, but a failed ack
	// means the orchestrator did not record this host's acknowledgement; the
	// caller's reconnect/retry policy (rig-tuned) decides whether to re-ack.
	Ack(ctx context.Context, seq uint64, contentHash []byte) error
}

// ackPolicySender wires the GENERATED boundary.v1 PolicyStreamServiceClient (the
// production path) into the AckPolicySender seam: Ack builds the frozen
// AckPolicyRequest(seq, content_hash) and invokes the RPC. The generated client
// satisfies the seam, so the fake the tests use and the production client are
// interchangeable behind the store.
type ackPolicySender struct {
	client boundaryv1.PolicyStreamServiceClient
}

// NewAckPolicySender adapts the generated PolicyStreamServiceClient into the
// AckPolicySender seam the snapshot store drives. The host agent constructs the
// client from its host-local UDS gRPC dial back to the orchestrator (the §5.3
// default transport) and hands it here; the store then acks through the same
// seam the tests exercise with a fake.
func NewAckPolicySender(client boundaryv1.PolicyStreamServiceClient) AckPolicySender {
	return ackPolicySender{client: client}
}

// Ack sends the frozen AckPolicyRequest(seq, content_hash) (D36/D72). The
// response envelope is intentionally discarded — AckPolicyResponse is an empty
// envelope reserved for additive growth; the contract is that a non-error return
// means the orchestrator recorded the ACK.
func (s ackPolicySender) Ack(ctx context.Context, seq uint64, contentHash []byte) error {
	_, err := s.client.AckPolicy(ctx, &boundaryv1.AckPolicyRequest{
		Seq:         seq,
		ContentHash: contentHash,
	})
	return err
}

// Compile-time proof that the adapter satisfies the AckPolicySender seam and
// that the GENERATED PolicyStreamServiceClient backs it. If a proto/grpc regen
// ever changed the AckPolicy signature, NewAckPolicySender stops compiling
// rather than letting the production ack path rot silently.
var (
	_ AckPolicySender                                            = ackPolicySender{}
	_ func(boundaryv1.PolicyStreamServiceClient) AckPolicySender = NewAckPolicySender
)
