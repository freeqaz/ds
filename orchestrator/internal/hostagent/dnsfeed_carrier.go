// SPDX-License-Identifier: Apache-2.0

package hostagent

// dnsfeed_carrier.go is the host agent's CROSS-PROCESS PRODUCER half of the LIVE
// host-local `WatchPolicies(from_seq)` carrier — the PRODUCTION transport the
// file+atomic-rename feed (feedwriter.go) is the doc 13 §8.4 v0 fallback for
// (doc 11 §5.3, doc 13 §5, D72/D36/D120).
//
// The host's ONE upstream `WatchPolicies(from_seq)` subscriber (the Go D35 host
// agent — ds-dnsgate NEVER opens a control-plane stream, doc 11 §5.3) fans each
// COMMITTED version out HOST-LOCALLY. This carrier SERVES a host-local UDS socket
// that ds-dnsgate's dataplane consumer (server.rs WatchPoliciesCarrierSource) DIALS;
// ds-dnsgate reads the server-stream of committed versions off it. The READER lives
// OUTSIDE this module, in the Rust dataplane workspace
// (dataplane/services/ds-dnsgate/src/server.rs WatchPoliciesCarrierSource +
// serve_watch_policies_connection, the in-tree reference producer this file mirrors).
// The two halves share ONLY the on-the-wire frame shape below — there is no gRPC/
// tonic (none exist in the dataplane workspace, D40/D67), no FFI, no shared type;
// this producer must match the bytes-on-the-wire shape EXACTLY or the consumer drops
// the stream fail-closed.
//
// THE CROSS-PROCESS WATCH-POLICIES CARRIER WIRE CONTRACT (binding — mirrored from the
// Rust consumer's WatchPoliciesFrame doc in server.rs):
//
//   - Transport: a tokio/`net` Unix stream. Every message is a length-prefixed FRAME:
//     a 4-byte BIG-ENDIAN body length, then the body. A body length over
//     watchFrameMaxBody is a malformed frame (the peer drops the stream).
//   - Handshake (consumer -> producer): ONE frame whose body is the 8-byte big-endian
//     `from_seq` resume cursor — the `WatchPolicies(from_seq)` request (D36). The
//     producer replays only committed versions with `seq > from_seq`.
//   - Stream (producer -> consumer): ZERO OR MORE version frames, each body =
//     seq (8B BE) || content_hash_len (4B BE) || content_hash bytes ||
//     document_len (4B BE) || document bytes. The bytes ARE the produce-once
//     transported canonical wire form (snap.GetDocument()) and the producer-pinned
//     content_hash (snap.GetContentHash()), the §5.1 identity tuple — this producer
//     NEVER re-serializes the document (produce-once / verify-only, doc 13 §5.1).
//   - End of stream: the producer CLOSES the connection (EOF) once it has replayed the
//     committed history past `from_seq`. The consumer then yields None (the stream is
//     exhausted), the §5.3 end-of-stream — the publisher drops the feed and the
//     subscriber drains.
//
// WHERE IT IS DRIVEN (the prepare/commit barrier, doc 13 §5.2 / apply.go): a version is
// admitted into the carrier's replay buffer ONLY after the host completes the D72
// two-phase apply admitter-LAST (all three consumers committed vN+1). WatchPoliciesCarrier
// therefore satisfies the apply.go Sweeper seam EXACTLY like FeedWriter: ApplyCoordinator
// invokes Sweep(ctx, snap) only on a fully-successful commit, so wiring this carrier as the
// coordinator's post-commit sweeper (or composing it after the real revocation Sweeper via
// SweeperChain) places the fan-out behind the commit barrier — a version never reaches a
// dialing consumer before the host is serving it.
//
// FORWARD-ONLY / INTEGRITY classification mirrors feedwriter.go: a version with no
// document (the produce-once carrier was never composed) is a ReasonSchemaFailure and is
// NOT buffered; a present-but-wrong content_hash is a ReasonContentHashMismatch (a torn
// carrier) and is NOT buffered; a seq at or below the buffer cursor is a benign forward-only
// re-delivery (ReasonNone) dropped from the buffer. The dataplane consumer re-verifies the
// content_hash against the transported bytes authoritatively (verify-before-parse), so a
// buggy in-process producer that slipped a torn carrier past this guard would still NACK
// host-wide at the consumer — this producer-side guard keeps the on-the-wire frames honest.
//
// NEVER-LOG-THE-SECRET: nothing here logs the composed document; the bytes cross the wire
// opaquely and the error paths name only the seq + the structural defect (D73).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// DefaultHostAgentFeedSock is the host-local UDS endpoint the host agent serves the
// WatchPolicies(from_seq) carrier on when the deployment does not override it. It is the
// SINGLE cross-process default both halves resolve (mirrors DEFAULT_HOST_AGENT_FEED_SOCK in
// dataplane/services/ds-dnsgate/src/main.rs); the dataplane consumer dials it when its
// DS_DNSGATE_HOST_AGENT_FEED env is set to a bare "uds:" with no explicit path. The socket
// is co-located under the host-local feed directory the host agent owns (DefaultHostAgentFeedDir),
// so the §5 reload is one directory.
const DefaultHostAgentFeedSock = DefaultHostAgentFeedDir + "/watch.sock"

// watchFrameMaxBody is the hard cap on a single carrier frame body (bytes). A version frame
// is a seq + a 32-byte content_hash + the composed POL-1 document; a composed document is
// small (human/policy-push cadence, never per-query, doc 11 §1). 4 MiB bounds a malformed /
// over-long frame. MUST match WATCH_POLICIES_MAX_FRAME_BODY in the dataplane consumer (server.rs).
const watchFrameMaxBody = 4 * 1024 * 1024

// carrierVersion is one committed version buffered for replay: the (seq, content_hash,
// transported document) §5.1 identity tuple. The bytes are the produce-once canonical wire
// form (snap.GetDocument()), held verbatim — never re-serialized.
type carrierVersion struct {
	seq         uint64
	contentHash []byte
	document    []byte
}

// WatchPoliciesCarrier is the host-local committed-snapshot carrier PRODUCER (doc 11 §5.3):
// it buffers each committed policy version (forward-only) and SERVES the WatchPolicies(from_seq)
// server-stream to dialing dataplane consumers (ds-dnsgate's WatchPoliciesCarrierSource),
// matching the cross-process frame contract the consumer reads.
//
// It is the WRITE/SERVE side ONLY: the read/drain/verify side lives in the Rust dataplane
// workspace. The two share only the on-the-wire frame shape (the constants above).
//
// FORWARD-ONLY: WriteCommitted refuses a seq that is not strictly greater than the last
// buffered version, so a re-delivered or out-of-order version never rewinds the carrier (the
// consumer is forward-only too; this keeps the producer honest so a buggy upstream re-fan-out
// cannot serve a backward version). Concurrency: the buffer is guarded by a mutex so a
// concurrent Serve connection (replaying the buffer) never observes a half-appended version.
//
// REPLAY semantics: a dialing consumer sends its from_seq; the carrier replays the buffered
// versions with seq > from_seq, in order, then closes the connection (EOF). v0 replays the
// in-memory buffer the host agent accumulated since this process started; a longer durable
// history is the file feed's job (feedwriter.go persists every version to disk). A consumer
// that needs a version below the buffer floor resumes from the co-located file feed — the two
// transports share the same applied_seq cursor, so they are interchangeable resume points.
type WatchPoliciesCarrier struct {
	mu sync.Mutex
	// versions is the forward-only replay buffer (ascending seq). Appended by WriteCommitted
	// behind the commit barrier; read (cloned) by each Serve connection.
	versions []carrierVersion
	// cursor is the highest seq buffered. A version at or below it is a forward-only re-delivery
	// dropped from the buffer. 0 before the first WriteCommitted.
	cursor uint64
}

// NewWatchPoliciesCarrier builds an empty carrier. A booting host before its first committed
// version serves an EMPTY stream (a consumer that dials gets an immediate EOF — the §5 "no
// version => no snapshot" posture, the consumer treats it as an exhausted stream).
func NewWatchPoliciesCarrier() *WatchPoliciesCarrier {
	return &WatchPoliciesCarrier{}
}

// Cursor returns the highest seq this carrier has buffered (the in-memory replay cursor).
// Before the first WriteCommitted it is 0.
func (c *WatchPoliciesCarrier) Cursor() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cursor
}

// WriteCommitted buffers ONE committed version for replay over the carrier. It returns the
// SnapshotReason classifying the version (heartbeat.go), the SAME classification feedwriter.go
// applies on its write path so the two transports surface the same separable operator telemetry
// (doc 13 §5.1):
//
//   - ReasonNone on success (the version is now in the replay buffer; the cursor advanced).
//   - ReasonSchemaFailure when the version carries NO transportable document (empty bytes — the
//     produce-once carrier was never composed): there is nothing valid to serve, so it is NOT
//     buffered. The reason token carries the SchemaFailure separability host-ward.
//   - ReasonContentHashMismatch when the snapshot carries a content_hash that does NOT match
//     SHA-256 over its OWN transported bytes — a producer-side integrity check mirroring the
//     consumer's verify-before-parse: a mismatch means the §5.1 identity tuple is torn, so it is
//     NOT buffered. (The snapshot store already verified this on receipt, so on the production
//     path the hash is consistent and this never fires; the guard keeps a buggy in-process
//     producer from serving a torn version.)
//
// A nil snapshot is a programming error rejected as a SchemaFailure. A seq that is not strictly
// greater than the cursor is a forward-only re-delivery (ReasonNone with a non-nil error — a
// benign dedup, not a content defect): the buffer is unchanged.
func (c *WatchPoliciesCarrier) WriteCommitted(snap *boundaryv1.PolicySnapshot) (SnapshotReason, error) {
	if snap == nil {
		return ReasonSchemaFailure, fmt.Errorf("hostagent: watch-policies carrier: nil snapshot (no produce-once carrier to serve)")
	}
	seq := snap.GetSeq()
	document := snap.GetDocument()

	// SchemaFailure: a version with no transportable document was never composed into a
	// produce-once carrier — there is nothing to serve. Distinct from a hash mismatch.
	if len(document) == 0 {
		return ReasonSchemaFailure, fmt.Errorf(
			"hostagent: watch-policies carrier: seq %d carries no document bytes (schema failure: no produce-once carrier to serve)",
			seq,
		)
	}

	// ContentHashMismatch: if the carrier pins a content_hash, it MUST equal SHA-256 over the
	// transported bytes (the §5.1 identity tuple, the SAME single source of wire hashing the
	// consumer recomputes). A carrier with an EMPTY hash is accepted (some in-process producers do
	// not pin it; the consumer recomputes authoritatively either way) — only a PRESENT-but-WRONG
	// hash is a torn carrier we refuse to serve. The buffered content_hash is then the producer's
	// pinned hash, transported verbatim so the consumer's non-vacuous verify-before-parse gate can
	// NACK a tampered transport.
	contentHash := snap.GetContentHash()
	if len(contentHash) > 0 {
		got := sha256.Sum256(document)
		if !bytesEqual(contentHash, got[:]) {
			return ReasonContentHashMismatch, fmt.Errorf(
				"hostagent: watch-policies carrier: seq %d content_hash does not match its transported bytes (content_hash mismatch: torn carrier, not buffered)",
				seq,
			)
		}
	} else {
		// No producer-pinned hash: derive it so the wire frame carries the §5.1 identity tuple the
		// consumer's verify-before-parse gate keys on (the consumer recomputes it authoritatively
		// regardless; supplying it keeps the frame shape complete).
		got := sha256.Sum256(document)
		contentHash = got[:]
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// FORWARD-ONLY: a seq at or below the cursor is a re-delivered / out-of-order version dropped
	// from the buffer (the consumer is forward-only too). NOT a content defect — ReasonNone with a
	// non-nil error so the caller logs the benign dedup without flagging a schema failure.
	if seq <= c.cursor {
		return ReasonNone, fmt.Errorf(
			"hostagent: watch-policies carrier: seq %d not past buffer cursor %d (forward-only: re-delivered/out-of-order version dropped, buffer unchanged)",
			seq, c.cursor,
		)
	}

	// Copy the transported bytes + hash so a later caller mutation can never alter a buffered frame
	// (the buffer is the authoritative replay source).
	doc := make([]byte, len(document))
	copy(doc, document)
	hash := make([]byte, len(contentHash))
	copy(hash, contentHash)
	c.versions = append(c.versions, carrierVersion{seq: seq, contentHash: hash, document: doc})
	c.cursor = seq
	return ReasonNone, nil
}

// Sweep makes WatchPoliciesCarrier satisfy the apply.go Sweeper seam so it can be wired as the
// ApplyCoordinator's POST-COMMIT hook (or composed after the real revocation Sweeper via
// SweeperChain): the coordinator invokes Sweep(ctx, snap) ONLY after a fully-successful commit
// (all three consumers flipped vN+1 admitter-LAST), which is EXACTLY the barrier point a version
// must be buffered behind (doc 13 §5.2). It buffers the just-committed version (WriteCommitted)
// and returns snap.GetSeq() as the swept seq so the coordinator advances apply_seq post-buffer.
//
// A buffering failure is returned so the coordinator HOLDS apply_seq at the prior version (a
// committed version that could not be buffered must not advance the resume cursor consumers read).
func (c *WatchPoliciesCarrier) Sweep(_ context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	if snap == nil {
		return 0, fmt.Errorf("hostagent: watch-policies carrier: Sweep on nil snapshot")
	}
	if _, err := c.WriteCommitted(snap); err != nil {
		return 0, err
	}
	return snap.GetSeq(), nil
}

// pending returns a CLONE of the buffered versions with seq > fromSeq, in ascending order — the
// replay set for one WatchPolicies(from_seq) connection. Cloned under the lock so a concurrent
// WriteCommitted never races a replay walk.
func (c *WatchPoliciesCarrier) pending(fromSeq uint64) []carrierVersion {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]carrierVersion, 0, len(c.versions))
	for _, v := range c.versions {
		if v.seq > fromSeq {
			out = append(out, v)
		}
	}
	return out
}

// Serve runs the carrier's UDS accept loop on listener until ctx is cancelled or the listener
// errors fatally: it accepts each connection, reads the WatchPolicies(from_seq) handshake, replays
// the buffered versions past from_seq as frames, and closes the connection (EOF) to end the stream.
// Each connection is handled on its own goroutine so a slow/hung consumer never blocks the accept
// loop (mirroring the dataplane re-resolve server's per-connection isolation). A per-connection
// fault (a malformed handshake, a consumer hang-up mid-stream) is isolated to that connection —
// logged and dropped, never fatal to the listener.
//
// The caller binds the listener (net.Listen("unix", endpoint)) and owns its lifecycle; Serve
// returns when ctx is done (it closes the listener to unblock Accept) or Accept errors fatally.
func (c *WatchPoliciesCarrier) Serve(ctx context.Context, listener net.Listener) error {
	// Close the listener when ctx is cancelled so the blocking Accept below returns.
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// Shutdown: the ctx-driven Close unblocked Accept — a clean stop, not a fault.
				return ctx.Err()
			}
			return fmt.Errorf("hostagent: watch-policies carrier: accept: %w", err)
		}
		go func() {
			if serveErr := c.serveConn(conn); serveErr != nil {
				// A per-connection fault is isolated — never fatal to the listener.
				// NEVER-LOG-THE-SECRET: serveConn errors name only the structural defect.
				_ = serveErr
			}
		}()
	}
}

// serveConn handles ONE WatchPolicies(from_seq) connection: read the handshake, replay the
// buffered versions past from_seq, close. It is the producer mirror of the dataplane reference
// serve_watch_policies_connection (server.rs) — the SAME frame shape.
func (c *WatchPoliciesCarrier) serveConn(conn net.Conn) error {
	defer conn.Close()
	// Read the WatchPolicies(from_seq) handshake (the 8-byte big-endian resume cursor).
	body, err := readWatchFrame(conn)
	if err != nil {
		return fmt.Errorf("hostagent: watch-policies carrier: read handshake: %w", err)
	}
	if len(body) != 8 {
		return fmt.Errorf("hostagent: watch-policies carrier: handshake is not an 8-byte from_seq (got %d bytes)", len(body))
	}
	fromSeq := binary.BigEndian.Uint64(body)

	// Replay the buffered versions past the resume cursor, in order, then close (EOF).
	for _, v := range c.pending(fromSeq) {
		frame := encodeWatchVersion(v.seq, v.contentHash, v.document)
		if err := writeWatchFrame(conn, frame); err != nil {
			// The consumer hung up — stop this connection's stream early (not fatal to the listener).
			return fmt.Errorf("hostagent: watch-policies carrier: write seq %d: %w", v.seq, err)
		}
	}
	// Returning closes the conn (deferred) → the consumer reads EOF and yields None (§5.3 EOS).
	return nil
}

// encodeWatchVersion encodes one version frame body (the (seq, content_hash, document) identity
// tuple) — the exact inverse of the consumer's WatchPoliciesFrame::decode_version (server.rs):
// seq (8B BE) || content_hash_len (4B BE) || content_hash || document_len (4B BE) || document.
func encodeWatchVersion(seq uint64, contentHash, document []byte) []byte {
	out := make([]byte, 0, 8+4+len(contentHash)+4+len(document))
	out = binary.BigEndian.AppendUint64(out, seq)
	out = binary.BigEndian.AppendUint32(out, uint32(len(contentHash)))
	out = append(out, contentHash...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(document)))
	out = append(out, document...)
	return out
}

// writeWatchFrame writes ONE length-prefixed frame (a 4-byte big-endian body length + the body)
// to the connection — the SAME framing the dataplane consumer's read_watch_frame expects. A body
// over the cap is rejected (never partially written).
func writeWatchFrame(w io.Writer, body []byte) error {
	if uint64(len(body)) > watchFrameMaxBody {
		return fmt.Errorf("hostagent: watch-policies carrier: frame body %d over cap %d", len(body), watchFrameMaxBody)
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

// readWatchFrame reads ONE length-prefixed frame body (the 4-byte length, then the body) — the
// mirror of the consumer's read_watch_frame. A clean EOF before the length prefix is returned as
// io.EOF (end of stream); a length over the cap is a malformed frame.
func readWatchFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		// io.EOF here is a clean end-of-stream before a frame; io.ErrUnexpectedEOF is a torn prefix.
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > watchFrameMaxBody {
		return nil, fmt.Errorf("hostagent: watch-policies carrier: frame length %d over cap %d", n, watchFrameMaxBody)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}
