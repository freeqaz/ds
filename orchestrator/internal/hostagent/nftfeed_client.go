// SPDX-License-Identifier: Apache-2.0

package hostagent

// nftfeed_client.go is the host agent's NFT-PROGRAMMER CLIENT leg of the D72
// two-phase apply barrier (POL-4 part 2; D72/D36, doc 13 §5, doc 15 §5.2) — the Go
// half that drives the ds-nft enforcer consumer (the nft-writer, one of the three
// host-side policy consumers, dataplane/crates/ds-nft) through PREPARE/COMMIT.
//
// THE GAP THIS CLOSES (the live wiring the SCOPE names). The ds-nft enforcer
// (apply::PolicyConsumer) implements the whole D72 barrier, and its
// Consumer::prepare_verified is the NON-VACUOUS, verify-the-SEPARATELY-transported-
// hash-BEFORE-parse gate (a transported hash CAN NACK; re-hashing the bytes and
// comparing to their own hash never can). The dataplane-internal route into that gate
// is ds_nft::ingest::ingest_snapshot, which threads a (seq, content_hash, document)
// NftSnapshotIngest into prepare_verified. But the PRODUCTION fan-out reaches the
// programmer through the host agent: this leg is the missing producer that THREADS the
// host-pinned, separately-transported content_hash (snap.GetContentHash()) ALONGSIDE
// the bytes (snap.GetDocument()) into that gate — mirroring the ds-dnsgate decorator
// approach (main.rs PrepareVerifiedGate) on the Go side. A transported-hash mismatch
// makes the programmer's prepare NACK (HashMismatch) BEFORE any parse / stage /
// allow-set re-derivation, so the programmer stays on vN and the host aborts host-wide.
//
// WHY A SEAM, NOT FFI. There is no generated Go↔Rust bridge for policy ingest: the one
// cgo write edge (orchestrator/internal/nftbridge) carries tap/flush MECHANISM, not
// policy versions, and the dataplane workspace has no tonic/gRPC (D40/D67). The host
// agent reaches the ds-nft consumer over a host-local UDS transport carrying the
// (seq, content_hash, document) identity tuple as plain bytes — the SAME produce-once /
// verify-only shape the Rust NftSnapshotIngest consumes (no framework type crosses the
// seam, doc 14 §6). That transport is the NftProgrammer seam below: a test fake
// satisfies it in-memory; the real host-local UDS client to the ds-nft consumer is
// owner-landed (the analog of ConsumerBarrier's other consumer clients). The producer's
// job here is to build the identity tuple HONESTLY and hand it to the gate; the gate's
// prepare_verified does the authoritative verify-before-parse on the consumer side, so a
// torn carrier that slipped past this producer guard still NACKs host-wide downstream.
//
// THREADS THE PRODUCER-PINNED HASH (never re-derived). The §5.1 identity tuple's
// content_hash is the SHA-256 the PRODUCER pinned over the produce-once serialization of
// the document; the snapshot store already verified it against the transported bytes on
// receipt (snapshotstore.go Accept, verify-before-fan-out) and NACKed any mismatch, so by
// the time a snapshot reaches this fan-out its hash is present and consistent. This leg
// transports snap.GetContentHash() VERBATIM (Prepare never recomputes it — re-deriving
// would make the downstream gate vacuous, the exact bug the non-vacuous gate exists to
// avoid). The one producer-side guard below recomputes the hash ONLY to refuse to ship a
// locally-torn carrier (a SchemaFailure / ContentHashMismatch classification mirroring
// feedwriter.go), never to replace the producer's pinned hash on the wire.
//
// ENFORCER, NOT ADMITTER. nft-writer is one of the two ENFORCERS (with ds-tlsproxy): it
// COMMITS BEFORE the admitter (ds-dnsgate) so every transient mixed-version window is
// fail-closed (D72 make-before-break). prepare_verified only STAGES (parks the validated
// vN+1 derivation input while serving vN); the atomic netlink flip + the post-commit
// revocation sweep stay with the ds-nft consumer + the host driver (apply.go). This leg
// satisfies the apply.go ConsumerBarrier seam, so OrderBarriers / NewApplyCoordinator
// place it in the FIXED admitter-last commit order.
//
// NEVER-LOG-THE-SECRET: nothing here logs the composed document; the bytes cross the
// seam opaquely and every error names only the seq + the structural defect (D73).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// NftProgrammer is the host agent's host-local TRANSPORT seam onto the ds-nft enforcer
// consumer's two-phase apply (the Rust apply::PolicyConsumer behind
// ds_nft::ingest::ingest_snapshot). It is the NFT-writer analog of the per-consumer UDS
// clients the other two ConsumerBarriers wrap: PrepareVerified maps to the Rust
// Consumer::prepare_verified (the non-vacuous verify-before-parse identity gate that
// STAGES vN+1 while serving vN), Commit maps to the atomic netlink flip to vN+1.
//
// It is a SEAM (interface), the package's pinned-later idiom: a test fake satisfies it
// in-memory; the real host-local UDS client to the ds-nft consumer is owner-landed. The
// snapshot crosses as the plain (seq, content_hash, document) §5.1 identity tuple — NO
// framework type, matching the Rust NftSnapshotIngest the consumer reads (doc 14 §6).
//
// CONTRACT (mirroring the Rust seam):
//
//   - PrepareVerified(ctx, seq, contentHash, document) routes the bytes AND the
//     producer-pinned, separately-transported contentHash into the consumer's
//     prepare_verified gate. The gate VERIFIES the bytes against contentHash BEFORE
//     parse: a mismatch returns a HashMismatch error (errors.Is(err, ErrNftHashMismatch))
//     and NOTHING is staged (the allow-set is never re-derived; the programmer stays on
//     vN). On a match it parses + validates + STAGES the vN+1 derivation input and returns
//     an opaque NftPreparedSnapshot handle (Commit consumes it). A prepare error — a
//     HashMismatch NACK included — is fatal to the WHOLE host apply (all-or-none).
//   - Commit(ctx, prepared) atomically flips the programmer to the prepared vN+1 input as
//     ONE netlink transaction (D72). Called ONLY with a handle this programmer's own
//     PrepareVerified returned, and ONLY after EVERY consumer prepared.
type NftProgrammer interface {
	// PrepareVerified threads the producer-pinned, separately-transported contentHash
	// into the ds-nft consumer's non-vacuous prepare_verified gate (verify-before-parse).
	// A transported-hash mismatch returns a HashMismatch error and stages NOTHING.
	PrepareVerified(ctx context.Context, seq uint64, contentHash, document []byte) (NftPreparedSnapshot, error)

	// Commit atomically flips the programmer to the prepared vN+1 derivation input (one
	// netlink txn). Called only with a handle this programmer's PrepareVerified returned.
	Commit(ctx context.Context, prepared NftPreparedSnapshot) error
}

// NftPreparedSnapshot is the opaque handle the NFT programmer's PrepareVerified returns
// and its own Commit consumes — the staged-but-not-flipped vN+1 derivation input (the Go
// analog of the Rust ApplyToken). The coordinator never inspects it; it only routes the
// handle back to the programmer that produced it, preserving the per-consumer atomic-flip
// contract (D72). An empty interface so the real UDS client (or a test fake) can carry
// whatever staged state its flip needs (typically the returned ApplyToken bytes).
type NftPreparedSnapshot interface{}

// ErrNftHashMismatch is the sentinel a NftProgrammer.PrepareVerified returns (or wraps)
// when the transported bytes do not hash to the producer-pinned, separately-transported
// content_hash — the NON-VACUOUS identity gate NACK (the Rust PrepareError::HashMismatch,
// D120). It is fail-closed: nothing is staged, the programmer stays on vN, and the host
// aborts the apply host-wide (all-or-none). A caller separates it from a SchemaInvalid /
// stage fault with errors.Is(err, ErrNftHashMismatch).
var ErrNftHashMismatch = fmt.Errorf("hostagent: nft-writer: transported content_hash does not match the snapshot bytes (HashMismatch, non-vacuous identity gate NACK)")

// NftProgrammerBarrier is the host-agent ConsumerBarrier for the nft-writer enforcer
// consumer (the Go client leg this file adds). It wraps a NftProgrammer transport and
// drives it through the D72 barrier so OrderBarriers / NewApplyCoordinator can place it in
// the FIXED admitter-last commit order (the two enforcers — ds-tlsproxy + nft-writer —
// commit BEFORE the admitter ds-dnsgate). It is the production fan-out call-site that
// routes the host-pinned content_hash into the ds-nft live ingest's prepare_verified gate.
type NftProgrammerBarrier struct {
	programmer NftProgrammer
}

// NewNftProgrammerBarrier wraps a NftProgrammer transport as the nft-writer
// ConsumerBarrier. A nil programmer is a wiring bug rejected at construction (fail-closed:
// the coordinator must never be built with a consumer it cannot prepare).
func NewNftProgrammerBarrier(programmer NftProgrammer) (*NftProgrammerBarrier, error) {
	if programmer == nil {
		return nil, fmt.Errorf("hostagent: NewNftProgrammerBarrier: nil NftProgrammer transport (the nft-writer client leg has nothing to drive)")
	}
	return &NftProgrammerBarrier{programmer: programmer}, nil
}

// Name is the consumer's stable identity — BoundaryNFTWriter (the nft-writer enforcer).
// It is what NewApplyCoordinator / OrderBarriers key the FIXED admitter-last commit order
// on (heartbeat.go); it never feeds policy evaluation.
func (b *NftProgrammerBarrier) Name() string { return BoundaryNFTWriter }

// Prepare threads the WHOLE snapshot — the transported document bytes (snap.GetDocument())
// AND the producer-pinned, separately-transported content_hash (snap.GetContentHash()) —
// into the ds-nft consumer's NON-VACUOUS prepare_verified gate (the Rust
// Consumer::prepare_verified via ingest_snapshot). The content_hash is NEVER re-derived
// here (re-deriving would make the gate vacuous); it is transported VERBATIM so the gate's
// verify-before-parse can NACK a tampered transport.
//
// A producer-side integrity guard refuses to SHIP a locally-torn carrier (it never feeds
// a decision — the consumer's gate is authoritative — but it keeps the on-the-wire tuple
// honest and gives the operator the §5.1-separable reason): an empty document is a
// SchemaFailure (no produce-once carrier to ship), and a present-but-WRONG content_hash is
// a ContentHashMismatch (a torn identity tuple). Both abort the host apply (all-or-none)
// just as the downstream HashMismatch would. On a clean tuple it hands the bytes + the
// producer-pinned hash to the programmer's prepare_verified; a HashMismatch NACK there is
// surfaced wrapped (errors.Is(err, ErrNftHashMismatch) holds) and is fatal to the whole
// host apply, with NOTHING staged (the programmer stays on vN).
func (b *NftProgrammerBarrier) Prepare(ctx context.Context, snap *boundaryv1.PolicySnapshot) (PreparedSnapshot, error) {
	if snap == nil {
		return nil, fmt.Errorf("hostagent: nft-writer barrier: nil snapshot (no produce-once carrier to prepare)")
	}
	seq := snap.GetSeq()
	document := snap.GetDocument()
	contentHash := snap.GetContentHash()

	// SchemaFailure: a version with no transportable document was never composed into a
	// produce-once carrier — there is nothing to verify/stage. Distinct from a hash
	// mismatch so the operator does not read a missing carrier as a transport tamper.
	if len(document) == 0 {
		return nil, fmt.Errorf(
			"hostagent: nft-writer barrier: seq %d carries no document bytes (%s: no produce-once carrier to ingest)",
			seq, ReasonSchemaFailure,
		)
	}

	// ContentHashMismatch (producer-side guard): if the carrier pins a content_hash it
	// MUST equal SHA-256 over the transported bytes (the §5.1 identity tuple, the SAME
	// single source of wire hashing the consumer recomputes). A present-but-WRONG hash is
	// a torn carrier we refuse to ship — the host aborts host-wide rather than transport a
	// tuple whose two halves disagree. (The snapshot store already verified this on
	// receipt, so on the production path this never fires; the guard keeps a buggy
	// in-process producer from shipping a torn version. An EMPTY pinned hash is rejected
	// too: the host fan-out always carries the producer-pinned hash, and shipping bytes
	// with no transported hash would leave the downstream gate with nothing to verify —
	// fail closed.)
	if len(contentHash) == 0 {
		return nil, fmt.Errorf(
			"hostagent: nft-writer barrier: seq %d carries no content_hash (%s: the §5.1 identity tuple is incomplete; refusing to ingest a snapshot the non-vacuous gate could not verify)",
			seq, ReasonContentHashMismatch,
		)
	}
	got := sha256.Sum256(document)
	if !bytesEqual(contentHash, got[:]) {
		return nil, fmt.Errorf(
			"hostagent: nft-writer barrier: seq %d content_hash does not match its transported bytes (%s: torn carrier, not ingested)",
			seq, ReasonContentHashMismatch,
		)
	}

	// Thread the bytes + the PRODUCER-PINNED content_hash (verbatim, never re-derived)
	// into the ds-nft consumer's non-vacuous prepare_verified gate. A HashMismatch NACK
	// there means the transported bytes do not hash to the producer's pinned hash (a
	// tampered/torn transport the producer guard above did not catch — e.g. a tamper on the
	// transport AFTER this producer): it is fail-closed, NOTHING is staged, the programmer
	// stays on vN, and the apply aborts host-wide. The error is surfaced wrapped so a
	// caller separates the HashMismatch NACK (errors.Is ErrNftHashMismatch) from a
	// schema/stage fault.
	prepared, err := b.programmer.PrepareVerified(ctx, seq, contentHash, document)
	if err != nil {
		return nil, fmt.Errorf(
			"hostagent: nft-writer barrier: prepare_verified of seq %d NACKed (host stays on vN, no consumer committed): %w",
			seq, err,
		)
	}
	return prepared, nil
}

// Commit atomically flips the nft-writer programmer to the prepared vN+1 derivation input
// (one netlink txn, D72). It is called only with a handle this barrier's own Prepare
// returned (the NftPreparedSnapshot the programmer's PrepareVerified produced), and only
// after EVERY consumer prepared — the apply.go coordinator routes the PreparedSnapshot
// back to this same barrier. The opaque coordinator handle (PreparedSnapshot, interface{})
// IS the programmer's NftPreparedSnapshot (also interface{}); it is routed through to the
// transport's Commit unchanged. A commit error is a programmer-internal fault AFTER the
// host committed to advancing (every consumer already prepared); it is surfaced, but the
// already-flipped enforcers stay on vN+1 (at-least-as-strict — fail-closed).
func (b *NftProgrammerBarrier) Commit(ctx context.Context, prepared PreparedSnapshot) error {
	if err := b.programmer.Commit(ctx, NftPreparedSnapshot(prepared)); err != nil {
		return fmt.Errorf(
			"hostagent: nft-writer barrier: commit (netlink flip to vN+1) failed (already-committed enforcers stay on vN+1, fail-closed): %w",
			err,
		)
	}
	return nil
}

// ── producer-bind: the nft-writer live ingest fan-out as a post-commit Sweeper ──
//
// nftFeedSweeper adapts the NftProgrammerBarrier (a ConsumerBarrier: Prepare/Commit)
// into the apply.go Sweeper seam so the host agent's daemon can compose the nft-writer
// LIVE ingest fan-out into the post-commit SweeperChain (feedwriter.go BindFeedProducers)
// behind DS_DNSGATE_HOST_AGENT_FEED=uds:, alongside the file feed and the WatchPolicies
// carrier. It is the nft-writer analog of FeedWriter.Sweep / WatchPoliciesCarrier.Sweep:
// a single Sweep(ctx, snap) the coordinator invokes ONLY after the admitter-LAST commit
// (doc 13 §5.2), so the live nft ingest is driven EXACTLY behind the prepare/commit
// barrier.
//
// WHY A POST-COMMIT FAN-OUT, NOT THE BARRIER'S OWN PREPARE/COMMIT. The host agent's
// PRIMARY nft-writer integration is the per-consumer ConsumerBarrier the ApplyCoordinator
// drives in PHASE 1/2 (Prepare stages vN+1 while serving vN; Commit flips, D72). This
// Sweeper is the SEPARATE host-local FAN-OUT producer leg (the nftfeed analog of the
// dnsfeed carrier): it re-routes the just-committed (seq, content_hash, document) identity
// tuple into the ds-nft LIVE ingest's non-vacuous prepare_verified gate so a deployment
// that runs the live ds-nft consumer (behind the same gate) re-receives the committed
// version host-locally. Because it runs as a Sweeper (post-commit), driving its own
// Prepare→Commit here re-applies the SAME committed version the barrier already flipped —
// the verify-before-parse gate is idempotent on a version it already holds (it re-stages
// and re-flips the identical vN+1 derivation input). A fan-out failure HOLDS apply_seq at
// the prior version (the coordinator does not advance past a version it could not fan out),
// exactly like the other producers.
//
// NEVER-LOG-THE-SECRET: the underlying barrier names only the seq + the structural defect
// (D73); this adapter adds no logging of the composed document.
type nftFeedSweeper struct {
	barrier *NftProgrammerBarrier
}

// newNftFeedSweeper wraps a NftProgrammer transport as the nft-writer fan-out Sweeper.
// A nil programmer is rejected at construction by NewNftProgrammerBarrier (fail-closed:
// the chain must never carry a producer it cannot drive).
func newNftFeedSweeper(programmer NftProgrammer) (*nftFeedSweeper, error) {
	barrier, err := NewNftProgrammerBarrier(programmer)
	if err != nil {
		return nil, fmt.Errorf("hostagent: nft feed sweeper: %w", err)
	}
	return &nftFeedSweeper{barrier: barrier}, nil
}

// Sweep fans the just-committed version into the ds-nft LIVE ingest's prepare_verified
// gate post-commit: it runs the barrier's Prepare (verify-before-parse on the
// separately-transported content_hash, NACK host-wide on a HashMismatch) then Commit
// (the atomic netlink flip), and returns snap.GetSeq() as the swept seq so the
// coordinator advances apply_seq post-fan-out. A nil snapshot is a programming error; a
// Prepare/Commit fault is returned so the coordinator HOLDS apply_seq at the prior
// version (a committed version that could not be fanned out must not advance the resume
// cursor the consumers read). The error wraps ErrNftHashMismatch on a transported-hash
// NACK (errors.Is holds), preserving the §5.1-separable reason host-ward.
func (s *nftFeedSweeper) Sweep(ctx context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	if snap == nil {
		return 0, fmt.Errorf("hostagent: nft feed sweeper: Sweep on nil snapshot")
	}
	prepared, err := s.barrier.Prepare(ctx, snap)
	if err != nil {
		return 0, fmt.Errorf("hostagent: nft feed sweeper: fan out seq %d: %w", snap.GetSeq(), err)
	}
	if err := s.barrier.Commit(ctx, prepared); err != nil {
		return 0, fmt.Errorf("hostagent: nft feed sweeper: commit seq %d: %w", snap.GetSeq(), err)
	}
	return snap.GetSeq(), nil
}

// ── the REAL host-local UDS NftProgrammer client (the production transport) ──
//
// UDSNftProgrammer is the REAL host-local UDS NftProgrammer client: the production
// transport this file's NftProgrammer seam was pinned for. It DIALS the ds-nft
// enforcer consumer's host-local ingest socket and drives the (seq, content_hash,
// document) §5.1 identity tuple through the consumer's two-phase apply
// (prepare_verified → commit) over a HAND-ROLLED length-prefixed wire — the SAME
// no-shared-crate, no-FFI, no-gRPC discipline as the revocation-delta producer and
// the WatchPolicies carrier (D40/D67: the dataplane workspace has no tonic, and the
// one cgo edge — orchestrator/internal/nftbridge — carries tap/flush MECHANISM, never
// policy versions). The consumer reads the SAME tuple ds_nft::ingest::NftSnapshotIngest
// holds and routes it into ds_nft::ingest::ingest_snapshot → Consumer::prepare_verified
// (the non-vacuous verify-the-separately-transported-hash-BEFORE-parse gate).
//
// THE CROSS-PROCESS NFT-INGEST WIRE CONTRACT (binding — the producer half of the
// frame a host-local ds-nft ingest consumer mirrors; single-sourced through the
// conformance fixture exactly as the revocation-delta and carrier frames are). Every
// message is a length-prefixed FRAME: a 4-byte BIG-ENDIAN body length, then the body.
// A body over nftIngestFrameMaxBody is a malformed frame the consumer drops
// fail-closed, so the producer refuses to emit one. There are TWO request frames and
// ONE response frame, all big-endian:
//
//   - PREPARE request (client → consumer), body:
//       op:            u8  (nftWireOpPrepare = 1)
//       seq:           u64
//       content_hash:  len(u32) + bytes   (the producer-pinned, separately-transported hash)
//       document:      len(u32) + bytes   (the produce-once transported canonical wire form)
//     The consumer threads (document, version=seq, content_hash) into prepare_verified.
//   - COMMIT request (client → consumer), body:
//       op:     u8  (nftWireOpCommit = 2)
//       seq:    u64
//       token:  len(u32) + bytes          (the opaque ApplyToken the PREPARE response carried)
//     The consumer flips to the staged vN+1 derivation input as one netlink txn.
//   - RESPONSE (consumer → client), body:
//       status: u8  (0=ACK · 1=HASH_MISMATCH · 2=SCHEMA_INVALID · 3=STAGE_FAULT · 4=COMMIT_FAULT)
//       token:  len(u32) + bytes          (ONLY on an ACK to a PREPARE; empty otherwise)
//     A non-ACK status is fail-closed: PrepareVerified maps HASH_MISMATCH to
//     ErrNftHashMismatch (the §5.1-separable NACK errors.Is keys on) and any other
//     non-ACK to a generic prepare/commit fault. The whole exchange (one PREPARE then
//     one COMMIT) rides ONE connection so the consumer holds the staged token between
//     the two; the client closes the connection after the COMMIT response.
//
// NEVER-LOG-THE-SECRET (D73): nothing here logs the composed document or the token
// bytes; the bytes cross the wire opaquely and every error names only the seq + the
// structural defect. The hash is threaded VERBATIM — UDSNftProgrammer never re-derives
// it (re-deriving would make the consumer's gate vacuous, the exact bug it exists to
// avoid).

// nftIngestFrameMaxBody is the hard cap on one nft-ingest frame body. A PREPARE frame
// is a seq + a 32-byte content_hash + the composed POL-1 document; a composed document
// is small (human/policy-push cadence, never per-query, doc 11 §1). 4 MiB bounds a
// malformed / over-long frame. A consumer that mirrors this wire MUST cap at the same
// value (the conformance fixture pins it).
const nftIngestFrameMaxBody = 4 * 1024 * 1024

// nft-ingest request opcodes (the first body byte of a request frame).
const (
	nftWireOpPrepare byte = 1
	nftWireOpCommit  byte = 2
)

// nft-ingest response status codes (the first body byte of a response frame). 0 is the
// ACK; every non-zero status is a fail-closed NACK the client surfaces.
const (
	nftWireStatusACK           byte = 0
	nftWireStatusHashMismatch  byte = 1 // the consumer's prepare_verified verify-before-parse NACK
	nftWireStatusSchemaInvalid byte = 2
	nftWireStatusStageFault    byte = 3
	nftWireStatusCommitFault   byte = 4
)

// defaultNftIngestDialTimeout bounds the live UDS connect so a wedged / absent ds-nft
// ingest listener never hangs the post-commit fan-out indefinitely. The dial is a
// host-LOCAL UDS connect (no network), so a healthy listener connects in microseconds;
// a few seconds is a generous ceiling that still fails the fan-out promptly (fail-closed:
// the host holds apply_seq and re-drives) when the listener is down.
const defaultNftIngestDialTimeout = 3 * time.Second

// nftPreparedUDS is the opaque NftPreparedSnapshot the UDS client's PrepareVerified
// returns and its own Commit consumes — the staged-but-not-flipped vN+1 handle. It
// carries the consumer-returned ApplyToken bytes (routed back VERBATIM on Commit) plus
// the seq + the live connection the PREPARE/COMMIT exchange rides (the consumer holds
// the staged token on that one connection between the two phases). The coordinator never
// inspects it (NftPreparedSnapshot is interface{}); it only hands it back to this
// programmer's Commit.
type nftPreparedUDS struct {
	seq   uint64
	token []byte
	conn  net.Conn
}

// UDSNftProgrammer is the production NftProgrammer: a host-local UDS client to the ds-nft
// enforcer consumer's ingest socket. It is the nft-writer analog of RevocationProducer's
// dialing leg + the WatchPolicies carrier's serving leg — the third hand-rolled
// cross-process datapath into the dataplane, here a CLIENT that drives the consumer's
// two-phase apply.
//
// DEFAULT-OFF: the live dial is reached ONLY when the daemon wires this transport behind
// the DS_DNSGATE_HOST_AGENT_FEED "uds:" gate (feedwriter.go WithNftProgrammer) — off that
// gate the nft leg is never appended and no socket is dialed, so the gate-unset daemon is
// byte-identical.
type UDSNftProgrammer struct {
	// endpoint is the host-local UDS path the client dials (the ds-nft ingest socket the
	// consumer binds). A deployment single-sources it with the consumer's listen path.
	endpoint string
	// dialTimeout bounds the live UDS connect.
	dialTimeout time.Duration
}

// NewUDSNftProgrammer builds the real UDS NftProgrammer client over endpoint — the
// host-local ds-nft ingest socket the consumer binds. An empty endpoint is rejected
// fail-closed (a client with no path could never deliver an ingest). The dial timeout
// defaults to defaultNftIngestDialTimeout.
func NewUDSNftProgrammer(endpoint string) (*UDSNftProgrammer, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("hostagent: NewUDSNftProgrammer: empty ds-nft ingest endpoint (no path to dial)")
	}
	return &UDSNftProgrammer{endpoint: endpoint, dialTimeout: defaultNftIngestDialTimeout}, nil
}

// Endpoint returns the host-local UDS path this client dials — the value a deployment
// must single-source with the ds-nft ingest consumer's listen path.
func (p *UDSNftProgrammer) Endpoint() string { return p.endpoint }

// PrepareVerified dials the ds-nft ingest socket, sends ONE PREPARE frame carrying the
// (seq, producer-pinned content_hash, document) §5.1 identity tuple VERBATIM, and reads
// the consumer's response. On an ACK it returns an opaque nftPreparedUDS handle (the
// ApplyToken bytes + the live connection the COMMIT rides). A HASH_MISMATCH status is
// the consumer's verify-before-parse NACK: it is surfaced wrapped so errors.Is(err,
// ErrNftHashMismatch) holds (NOTHING is staged, the connection is closed). Any other
// non-ACK status is a schema/stage fault (also fail-closed). The hash is threaded
// VERBATIM — never re-derived (re-deriving would make the consumer's gate vacuous).
func (p *UDSNftProgrammer) PrepareVerified(ctx context.Context, seq uint64, contentHash, document []byte) (NftPreparedSnapshot, error) {
	// Build the PREPARE body BEFORE the dial so an encode defect (an over-cap field)
	// fails without touching the socket.
	body, err := encodeNftPrepare(seq, contentHash, document)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: p.dialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", p.endpoint)
	if err != nil {
		return nil, fmt.Errorf("hostagent: nft ingest client: dial %q for seq %d: %w", p.endpoint, seq, err)
	}
	// Bound the write/read by the ctx deadline when one is set (a wedged consumer never
	// hangs the fan-out); a SetDeadline error is non-fatal (some conns may not support
	// it) — the I/O below still fails loud on a real fault.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := writeNftFrame(conn, body); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("hostagent: nft ingest client: write PREPARE for seq %d: %w", seq, err)
	}
	status, token, err := readNftResponse(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("hostagent: nft ingest client: read PREPARE response for seq %d: %w", seq, err)
	}
	if status != nftWireStatusACK {
		_ = conn.Close()
		return nil, classifyNftPrepareStatus(seq, status)
	}
	// ACK: the consumer staged vN+1 and holds the token on this connection. Keep the
	// connection open so the COMMIT rides the SAME exchange (the consumer holds the
	// staged token between the two phases). Copy the token so a later wire-buffer reuse
	// can never mutate the held handle.
	return &nftPreparedUDS{seq: seq, token: append([]byte(nil), token...), conn: conn}, nil
}

// Commit sends ONE COMMIT frame carrying the staged ApplyToken back to the consumer over
// the SAME connection the PREPARE rode, then reads the consumer's response and closes the
// connection. It is called only with a handle this client's own PrepareVerified returned
// (the coordinator routes it back unchanged). A non-ACK commit response is a
// programmer-internal fault AFTER the host committed to advancing; it is surfaced
// fail-closed (the already-flipped enforcers stay on vN+1, at-least-as-strict). A handle
// of the wrong concrete type is a wiring bug rejected fail-closed.
func (p *UDSNftProgrammer) Commit(ctx context.Context, prepared NftPreparedSnapshot) error {
	h, ok := prepared.(*nftPreparedUDS)
	if !ok || h == nil {
		return fmt.Errorf("hostagent: nft ingest client: Commit got a handle this client did not produce (%T)", prepared)
	}
	// Close the connection the PREPARE opened once the COMMIT exchange finishes
	// (success or fault) so a held UDS slot is never leaked.
	defer func() {
		if h.conn != nil {
			_ = h.conn.Close()
		}
	}()
	if h.conn == nil {
		return fmt.Errorf("hostagent: nft ingest client: Commit on seq %d with no live prepare connection", h.seq)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = h.conn.SetDeadline(deadline)
	}
	body, err := encodeNftCommit(h.seq, h.token)
	if err != nil {
		return err
	}
	if err := writeNftFrame(h.conn, body); err != nil {
		return fmt.Errorf("hostagent: nft ingest client: write COMMIT for seq %d: %w", h.seq, err)
	}
	status, _, err := readNftResponse(h.conn)
	if err != nil {
		return fmt.Errorf("hostagent: nft ingest client: read COMMIT response for seq %d: %w", h.seq, err)
	}
	if status != nftWireStatusACK {
		return fmt.Errorf("hostagent: nft ingest client: COMMIT for seq %d NACKed (status %d, netlink flip not confirmed)", h.seq, status)
	}
	return nil
}

// Compile-time proof the UDS client satisfies the NftProgrammer seam the
// NftProgrammerBarrier drives.
var _ NftProgrammer = (*UDSNftProgrammer)(nil)

// ── the nft-ingest wire codec (the producer half of the cross-process frame) ──

// encodeNftPrepare encodes a PREPARE request body (NO frame length prefix): op || seq ||
// content_hash (len+bytes) || document (len+bytes). The content_hash + document are
// written VERBATIM (the producer-pinned hash is never re-derived). A field whose length
// does not fit a u32 is rejected (the len-prefixes are u32) — unreachable for a real
// hash/document, guarded so an oversized input fails loud rather than wrapping.
func encodeNftPrepare(seq uint64, contentHash, document []byte) ([]byte, error) {
	if len(contentHash) > maxU32 {
		return nil, fmt.Errorf("hostagent: nft ingest client: content_hash length %d exceeds u32", len(contentHash))
	}
	if len(document) > maxU32 {
		return nil, fmt.Errorf("hostagent: nft ingest client: document length %d exceeds u32", len(document))
	}
	out := make([]byte, 0, 1+8+4+len(contentHash)+4+len(document))
	out = append(out, nftWireOpPrepare)
	out = binary.BigEndian.AppendUint64(out, seq)
	out = binary.BigEndian.AppendUint32(out, uint32(len(contentHash)))
	out = append(out, contentHash...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(document)))
	out = append(out, document...)
	return out, nil
}

// encodeNftCommit encodes a COMMIT request body (NO frame length prefix): op || seq ||
// token (len+bytes). The token is the opaque ApplyToken the PREPARE response carried,
// routed back verbatim.
func encodeNftCommit(seq uint64, token []byte) ([]byte, error) {
	if len(token) > maxU32 {
		return nil, fmt.Errorf("hostagent: nft ingest client: token length %d exceeds u32", len(token))
	}
	out := make([]byte, 0, 1+8+4+len(token))
	out = append(out, nftWireOpCommit)
	out = binary.BigEndian.AppendUint64(out, seq)
	out = binary.BigEndian.AppendUint32(out, uint32(len(token)))
	out = append(out, token...)
	return out, nil
}

// classifyNftPrepareStatus maps a non-ACK PREPARE response status into a fail-closed
// error. HASH_MISMATCH is the consumer's verify-before-parse NACK — wrapped so
// errors.Is(err, ErrNftHashMismatch) holds (the §5.1-separable reason). Every other
// non-ACK status is a schema/stage fault that also aborts the host apply host-wide.
func classifyNftPrepareStatus(seq uint64, status byte) error {
	switch status {
	case nftWireStatusHashMismatch:
		return fmt.Errorf("hostagent: nft ingest client: seq %d: %w", seq, ErrNftHashMismatch)
	case nftWireStatusSchemaInvalid:
		return fmt.Errorf("hostagent: nft ingest client: seq %d PREPARE NACKed (schema invalid, nothing staged)", seq)
	case nftWireStatusStageFault:
		return fmt.Errorf("hostagent: nft ingest client: seq %d PREPARE NACKed (stage fault, nothing staged)", seq)
	default:
		return fmt.Errorf("hostagent: nft ingest client: seq %d PREPARE NACKed (status %d, nothing staged)", seq, status)
	}
}

// writeNftFrame writes ONE length-prefixed frame (a 4-byte big-endian body length + the
// body) — the SAME framing the revocation-delta + carrier producers use. A body over the
// cap is rejected BEFORE any byte is written (a consumer would drop it fail-closed).
func writeNftFrame(w io.Writer, body []byte) error {
	if len(body) > nftIngestFrameMaxBody {
		return fmt.Errorf("hostagent: nft ingest client: frame body %d over cap %d", len(body), nftIngestFrameMaxBody)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

// readNftFrame reads ONE length-prefixed frame body (the 4-byte length, then the body).
// A clean EOF before the length prefix is io.EOF; a length over the cap is a malformed
// frame the reader rejects fail-closed (never allocating an unbounded buffer).
func readNftFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > nftIngestFrameMaxBody {
		return nil, fmt.Errorf("hostagent: nft ingest client: frame length %d over cap %d", n, nftIngestFrameMaxBody)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// readNftResponse reads ONE response frame and parses it into (status, token). The body
// is status (u8) || token (len(u32) + bytes); the token is non-empty ONLY on an ACK to a
// PREPARE. A truncated body (too short for the status, or a token length past the body)
// is a malformed response the reader rejects fail-closed — verify-before-use: the bytes
// are validated before any field is read.
func readNftResponse(r io.Reader) (status byte, token []byte, err error) {
	body, err := readNftFrame(r)
	if err != nil {
		return 0, nil, err
	}
	if len(body) < 1 {
		return 0, nil, fmt.Errorf("hostagent: nft ingest client: response frame too short for a status byte")
	}
	status = body[0]
	rest := body[1:]
	if len(rest) < 4 {
		return 0, nil, fmt.Errorf("hostagent: nft ingest client: response frame too short for a token length")
	}
	n := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if uint64(n) > uint64(len(rest)) {
		return 0, nil, fmt.Errorf("hostagent: nft ingest client: response token length %d past frame body %d", n, len(rest))
	}
	// Copy the token out of the frame buffer so it outlives the read buffer reuse.
	token = append([]byte(nil), rest[:n]...)
	return status, token, nil
}

// ── the env-resolved ds-nft ingest endpoint (single-sourced with the consumer) ──

// nftIngestEndpointEnv is the env var that single-sources the ds-nft ingest UDS endpoint
// path the host-local client dials. Unset/empty => DefaultNftIngestEndpoint. A host-local
// ds-nft ingest consumer that mirrors this wire MUST bind the SAME path (the conformance
// fixture + this constant are the single source).
const nftIngestEndpointEnv = "DS_NFT_INGEST_LISTEN"

// DefaultNftIngestEndpoint is the default host-local UDS the client dials and a ds-nft
// ingest consumer binds when neither side overrides it. Co-located under the host-local
// feed directory the host agent owns (DefaultHostAgentFeedDir) so the §5 reload is one
// directory.
const DefaultNftIngestEndpoint = DefaultHostAgentFeedDir + "/nft-ingest.sock"

// NftIngestEndpoint resolves the UDS endpoint the host-local nft-writer client dials — the
// env override (nftIngestEndpointEnv) when set non-empty, else DefaultNftIngestEndpoint.
// The ONE place the path resolves on the producer side, so the client dials the path the
// ds-nft ingest consumer binds.
func NftIngestEndpoint() string {
	if v := os.Getenv(nftIngestEndpointEnv); v != "" {
		return v
	}
	return DefaultNftIngestEndpoint
}
