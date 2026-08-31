// SPDX-License-Identifier: Apache-2.0

package hostagent

// nftfeed_client_test.go is the SYNTHETIC in-process proof of the host agent's
// nft-writer fan-out leg (nftfeed_client.go): the NftProgrammerBarrier that threads the
// producer-pinned, separately-transported content_hash into the ds-nft LIVE ingest's
// non-vacuous prepare_verified gate, and the nftFeedSweeper that composes that barrier
// into the post-commit SweeperChain (feedwriter.go BindFeedProducers). There is no live
// claude/cia/qemu/podman and no Rust here — a test fake NftProgrammer satisfies the seam
// in-memory and the test asserts the §5.1 identity-tuple handling: a torn carrier is
// refused producer-side, a clean tuple is threaded verbatim (never re-derived), a
// transported-hash NACK separates as ErrNftHashMismatch, and the Sweeper drives
// Prepare→Commit ONLY behind the commit barrier.
//
// snapAt is shared with feedwriter_test.go (same package).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// fakeNftProgrammer is an in-memory NftProgrammer: it records the (seq, content_hash,
// document) tuple each PrepareVerified received (so a test proves the producer threads
// the PRODUCER-PINNED hash verbatim, never re-derived), can be forced to NACK with a
// HashMismatch, and records each Commit. It is the nft-writer analog of the dnsfeed
// fakes — a synthetic stand-in for the owner-landed host-local UDS client to ds-nft.
type fakeNftProgrammer struct {
	// prepareErr, when non-nil, is returned by PrepareVerified (e.g. ErrNftHashMismatch
	// to model the consumer's verify-before-parse NACK).
	prepareErr error
	commitErr  error

	// gotSeq / gotHash / gotDoc capture the LAST tuple PrepareVerified received.
	gotSeq  uint64
	gotHash []byte
	gotDoc  []byte

	prepareN int
	commitN  int
	// committed holds the handles Commit consumed, in order (proves Commit got the
	// SAME handle this programmer's PrepareVerified returned).
	committed []NftPreparedSnapshot
}

// nftHandle is the opaque staged-input handle the fake's PrepareVerified returns and its
// own Commit asserts it receives back — the Go analog of the Rust ApplyToken.
type nftHandle struct{ seq uint64 }

func (f *fakeNftProgrammer) PrepareVerified(_ context.Context, seq uint64, contentHash, document []byte) (NftPreparedSnapshot, error) {
	f.prepareN++
	f.gotSeq = seq
	f.gotHash = append([]byte(nil), contentHash...)
	f.gotDoc = append([]byte(nil), document...)
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}
	return nftHandle{seq: seq}, nil
}

func (f *fakeNftProgrammer) Commit(_ context.Context, prepared NftPreparedSnapshot) error {
	f.commitN++
	f.committed = append(f.committed, prepared)
	return f.commitErr
}

// nftSnap builds a committed PolicySnapshot at seq whose content_hash is the SHA-256 over
// the document bytes (the §5.1 identity tuple the snapshot store already verified on
// receipt) — so the barrier's producer-side guard is consistent on the happy path.
func nftSnap(seq uint64, document string) *boundaryv1.PolicySnapshot {
	// Reuse snapAt (feedwriter_test.go): it pins ContentHash = sha256(document).
	return snapAt(seq, document)
}

func TestNftProgrammerBarrierThreadsPinnedHash(t *testing.T) {
	t.Run("CleanTupleThreadedVerbatimThenCommitted", func(t *testing.T) {
		prog := &fakeNftProgrammer{}
		barrier, err := NewNftProgrammerBarrier(prog)
		if err != nil {
			t.Fatalf("NewNftProgrammerBarrier: %v", err)
		}
		if got := barrier.Name(); got != BoundaryNFTWriter {
			t.Fatalf("Name() = %q, want %q", got, BoundaryNFTWriter)
		}

		snap := nftSnap(7, "nft-doc")
		prepared, err := barrier.Prepare(context.Background(), snap)
		if err != nil {
			t.Fatalf("Prepare clean tuple: %v", err)
		}
		if prog.prepareN != 1 {
			t.Fatalf("PrepareVerified called %d times, want 1", prog.prepareN)
		}
		if prog.gotSeq != 7 {
			t.Fatalf("threaded seq = %d, want 7", prog.gotSeq)
		}
		// The PRODUCER-PINNED hash is threaded VERBATIM (never re-derived): it equals
		// snap.GetContentHash() byte-for-byte.
		if !bytesEqual(prog.gotHash, snap.GetContentHash()) {
			t.Fatalf("threaded content_hash is not the producer-pinned snap.GetContentHash() verbatim")
		}
		if string(prog.gotDoc) != "nft-doc" {
			t.Fatalf("threaded document = %q, want the verbatim transported bytes", prog.gotDoc)
		}

		if err := barrier.Commit(context.Background(), prepared); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if prog.commitN != 1 {
			t.Fatalf("Commit called %d times, want 1", prog.commitN)
		}
		// Commit received the SAME handle this barrier's Prepare produced.
		if h, ok := prog.committed[0].(nftHandle); !ok || h.seq != 7 {
			t.Fatalf("Commit got handle %#v, want the nftHandle{seq:7} Prepare returned", prog.committed[0])
		}
	})

	t.Run("NilSnapshotIsRejected", func(t *testing.T) {
		prog := &fakeNftProgrammer{}
		barrier, _ := NewNftProgrammerBarrier(prog)
		if _, err := barrier.Prepare(context.Background(), nil); err == nil {
			t.Fatal("Prepare on a nil snapshot must error")
		}
		if prog.prepareN != 0 {
			t.Fatalf("a nil snapshot must NOT reach the transport (prepareN=%d)", prog.prepareN)
		}
	})

	t.Run("EmptyDocumentIsSchemaFailureNotShipped", func(t *testing.T) {
		prog := &fakeNftProgrammer{}
		barrier, _ := NewNftProgrammerBarrier(prog)
		if _, err := barrier.Prepare(context.Background(), &boundaryv1.PolicySnapshot{Seq: 8}); err == nil {
			t.Fatal("an empty-document snapshot must fail (schema failure)")
		}
		if prog.prepareN != 0 {
			t.Fatalf("a schema-failure snapshot must NOT be shipped to the transport (prepareN=%d)", prog.prepareN)
		}
	})

	t.Run("MissingContentHashIsRejectedFailClosed", func(t *testing.T) {
		prog := &fakeNftProgrammer{}
		barrier, _ := NewNftProgrammerBarrier(prog)
		// Present bytes but NO producer-pinned hash: the host fan-out always carries the
		// pinned hash, so shipping bytes with nothing to verify is fail-closed.
		noHash := &boundaryv1.PolicySnapshot{Seq: 9, Document: []byte("bytes-no-hash")}
		if _, err := barrier.Prepare(context.Background(), noHash); err == nil {
			t.Fatal("a snapshot with no content_hash must be rejected (the gate would have nothing to verify)")
		}
		if prog.prepareN != 0 {
			t.Fatalf("a no-hash snapshot must NOT be shipped (prepareN=%d)", prog.prepareN)
		}
	})

	t.Run("PresentButWrongHashIsTornCarrierNotShipped", func(t *testing.T) {
		prog := &fakeNftProgrammer{}
		barrier, _ := NewNftProgrammerBarrier(prog)
		torn := nftSnap(10, "real-bytes")
		torn.ContentHash = make([]byte, 32) // all-zero != sha256(real-bytes)
		if _, err := barrier.Prepare(context.Background(), torn); err == nil {
			t.Fatal("a present-but-wrong content_hash is a torn carrier and must be refused producer-side")
		}
		if prog.prepareN != 0 {
			t.Fatalf("a torn carrier must NOT reach the transport (prepareN=%d)", prog.prepareN)
		}
	})

	t.Run("TransportHashMismatchSeparatesAsErrNftHashMismatch", func(t *testing.T) {
		// The transport (the consumer's verify-before-parse gate) NACKs with a HashMismatch
		// — a tamper AFTER the producer guard. The barrier surfaces it wrapped so a caller
		// separates the NACK from a schema/stage fault with errors.Is.
		prog := &fakeNftProgrammer{prepareErr: ErrNftHashMismatch}
		barrier, _ := NewNftProgrammerBarrier(prog)
		_, err := barrier.Prepare(context.Background(), nftSnap(11, "doc"))
		if err == nil {
			t.Fatal("a transport HashMismatch NACK must surface as an error")
		}
		if !errors.Is(err, ErrNftHashMismatch) {
			t.Fatalf("err = %v, want errors.Is(err, ErrNftHashMismatch)", err)
		}
	})

	t.Run("NilTransportRejectedAtConstruction", func(t *testing.T) {
		if _, err := NewNftProgrammerBarrier(nil); err == nil {
			t.Fatal("NewNftProgrammerBarrier(nil) must fail closed")
		}
	})
}

func TestNftFeedSweeperDrivesBarrierAsPostCommitSweeper(t *testing.T) {
	t.Run("CleanFanOutPreparesCommitsAndReportsSeq", func(t *testing.T) {
		prog := &fakeNftProgrammer{}
		sw, err := newNftFeedSweeper(prog)
		if err != nil {
			t.Fatalf("newNftFeedSweeper: %v", err)
		}
		gotSeq, err := sw.Sweep(context.Background(), nftSnap(21, "nft-doc"))
		if err != nil {
			t.Fatalf("Sweep clean: %v", err)
		}
		if gotSeq != 21 {
			t.Fatalf("swept seq = %d, want 21", gotSeq)
		}
		if prog.prepareN != 1 || prog.commitN != 1 {
			t.Fatalf("Sweep must drive Prepare→Commit once each (prepareN=%d commitN=%d)", prog.prepareN, prog.commitN)
		}
	})

	t.Run("NilSnapshotErrors", func(t *testing.T) {
		sw, _ := newNftFeedSweeper(&fakeNftProgrammer{})
		if _, err := sw.Sweep(context.Background(), nil); err == nil {
			t.Fatal("Sweep on a nil snapshot must error")
		}
	})

	t.Run("PrepareNACKHoldsApplySeqAndSeparates", func(t *testing.T) {
		prog := &fakeNftProgrammer{prepareErr: ErrNftHashMismatch}
		sw, _ := newNftFeedSweeper(prog)
		gotSeq, err := sw.Sweep(context.Background(), nftSnap(22, "doc"))
		if err == nil {
			t.Fatal("a prepare NACK must surface so apply_seq holds")
		}
		if gotSeq != 0 {
			t.Fatalf("a failed fan-out must report swept seq 0 (apply_seq holds), got %d", gotSeq)
		}
		if !errors.Is(err, ErrNftHashMismatch) {
			t.Fatalf("err = %v, want errors.Is(err, ErrNftHashMismatch)", err)
		}
		if prog.commitN != 0 {
			t.Fatalf("a prepare NACK must NOT commit (commitN=%d)", prog.commitN)
		}
	})

	t.Run("CommitFaultHoldsApplySeq", func(t *testing.T) {
		prog := &fakeNftProgrammer{commitErr: errors.New("netlink flip failed")}
		sw, _ := newNftFeedSweeper(prog)
		gotSeq, err := sw.Sweep(context.Background(), nftSnap(23, "doc"))
		if err == nil {
			t.Fatal("a commit fault must surface so apply_seq holds")
		}
		if gotSeq != 0 {
			t.Fatalf("a commit fault must report swept seq 0, got %d", gotSeq)
		}
		if prog.prepareN != 1 {
			t.Fatalf("Prepare must have run before the commit fault (prepareN=%d)", prog.prepareN)
		}
	})

	t.Run("NilTransportRejectedAtConstruction", func(t *testing.T) {
		if _, err := newNftFeedSweeper(nil); err == nil {
			t.Fatal("newNftFeedSweeper(nil) must fail closed")
		}
	})
}

// ── the REAL UDS NftProgrammer client over a synthetic in-process ds-nft consumer ──
//
// These tests drive the REAL UDSNftProgrammer (the production host-local UDS client)
// against a SYNTHETIC in-process consumer that mirrors the cross-process nft-ingest wire
// (the producer half nftfeed_client.go encodes). There is no live ds-nft / qemu / podman
// — the synthetic consumer decodes the PREPARE/COMMIT request frames with a Go
// re-implementation of the wire (decodeNftPrepareForTest), so a frame-shape drift in the
// producer makes the decode fail (the conformance unit single-sources the cross-PROCESS
// fixture; this test is the producer's own in-process round-trip proof).

// decodedNftPrepare is the producer's PREPARE frame parsed back — proves the encoder
// threaded the (seq, content_hash, document) §5.1 identity tuple verbatim.
type decodedNftPrepare struct {
	seq         uint64
	contentHash []byte
	document    []byte
}

// decodeNftPrepareForTest parses a PREPARE request body (op || seq || content_hash(len+bytes)
// || document(len+bytes)) — the Go re-implementation of the consumer's decode, so a
// drift in encodeNftPrepare fails here. Returns false on any malformed/truncated frame.
func decodeNftPrepareForTest(body []byte) (decodedNftPrepare, bool) {
	if len(body) < 1 || body[0] != nftWireOpPrepare {
		return decodedNftPrepare{}, false
	}
	rest := body[1:]
	if len(rest) < 8 {
		return decodedNftPrepare{}, false
	}
	seq := binary.BigEndian.Uint64(rest[:8])
	rest = rest[8:]
	hash, rest, ok := takeWireBytesForTest(rest)
	if !ok {
		return decodedNftPrepare{}, false
	}
	doc, rest, ok := takeWireBytesForTest(rest)
	if !ok || len(rest) != 0 {
		return decodedNftPrepare{}, false
	}
	return decodedNftPrepare{seq: seq, contentHash: hash, document: doc}, true
}

// decodeNftCommitForTest parses a COMMIT request body (op || seq || token(len+bytes)).
func decodeNftCommitForTest(body []byte) (seq uint64, token []byte, ok bool) {
	if len(body) < 1 || body[0] != nftWireOpCommit {
		return 0, nil, false
	}
	rest := body[1:]
	if len(rest) < 8 {
		return 0, nil, false
	}
	seq = binary.BigEndian.Uint64(rest[:8])
	rest = rest[8:]
	tok, rest, ok := takeWireBytesForTest(rest)
	if !ok || len(rest) != 0 {
		return 0, nil, false
	}
	return seq, tok, true
}

// takeWireBytesForTest reads one len(u32 BE)+bytes field — the mirror of the producer's
// AppendUint32 + bytes layout.
func takeWireBytesForTest(b []byte) (out, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if uint64(n) > uint64(len(b)) {
		return nil, nil, false
	}
	return b[:n], b[n:], true
}

// nftConsumerScript controls the synthetic consumer's responses so a test can model the
// real ds-nft consumer's verify-before-parse gate: it can ACK (with a token), or NACK a
// PREPARE with a chosen status (e.g. HASH_MISMATCH).
type nftConsumerScript struct {
	// prepareStatus is the status the consumer answers a PREPARE with (ACK on 0).
	prepareStatus byte
	// commitStatus is the status the consumer answers a COMMIT with (ACK on 0).
	commitStatus byte
	// verifyHash, when true, makes the consumer recompute sha256(document) and answer
	// HASH_MISMATCH if it does not equal the transported content_hash — the synthetic
	// model of the real prepare_verified verify-before-parse gate.
	verifyHash bool
	// token is the opaque ApplyToken the consumer returns on a PREPARE ACK.
	token []byte
}

// syntheticNftConsumer binds a temp UDS and serves ONE PREPARE+COMMIT exchange per
// connection per the script — the synthetic stand-in for the real ds-nft ingest consumer.
type syntheticNftConsumer struct {
	t      *testing.T
	ln     net.Listener
	script nftConsumerScript

	mu       sync.Mutex
	gotPrep  *decodedNftPrepare // the LAST PREPARE the consumer decoded (nil until one arrives)
	gotToken []byte             // the token the consumer received on the LAST COMMIT
	commitN  int
}

// startSyntheticNftConsumer binds endpoint and runs the accept loop until the listener is
// closed (t.Cleanup). It decodes each connection's PREPARE (one exchange per conn) and
// answers per the script, then reads the COMMIT and answers per the script.
func startSyntheticNftConsumer(t *testing.T, endpoint string, script nftConsumerScript) *syntheticNftConsumer {
	t.Helper()
	ln, err := net.Listen("unix", endpoint)
	if err != nil {
		t.Fatalf("bind synthetic nft consumer at %q: %v", endpoint, err)
	}
	c := &syntheticNftConsumer{t: t, ln: ln, script: script}
	t.Cleanup(func() { _ = ln.Close() })
	go c.acceptLoop()
	return c
}

func (c *syntheticNftConsumer) acceptLoop() {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			return // listener closed on cleanup
		}
		go c.serveConn(conn)
	}
}

func (c *syntheticNftConsumer) serveConn(conn net.Conn) {
	defer conn.Close()
	// PREPARE
	prepBody, err := readNftFrameForTest(conn)
	if err != nil {
		return
	}
	prep, ok := decodeNftPrepareForTest(prepBody)
	if !ok {
		// A malformed PREPARE: drop fail-closed (a frame-shape drift surfaces here).
		_ = writeNftResponseForTest(conn, nftWireStatusSchemaInvalid, nil)
		return
	}
	c.mu.Lock()
	c.gotPrep = &prep
	c.mu.Unlock()

	status := c.script.prepareStatus
	if c.script.verifyHash {
		got := sha256.Sum256(prep.document)
		if !bytesEqual(prep.contentHash, got[:]) {
			status = nftWireStatusHashMismatch
		}
	}
	if status != nftWireStatusACK {
		_ = writeNftResponseForTest(conn, status, nil)
		return // a NACK ends the exchange — no COMMIT follows
	}
	if err := writeNftResponseForTest(conn, nftWireStatusACK, c.script.token); err != nil {
		return
	}

	// COMMIT
	commitBody, err := readNftFrameForTest(conn)
	if err != nil {
		return
	}
	_, token, ok := decodeNftCommitForTest(commitBody)
	if !ok {
		_ = writeNftResponseForTest(conn, nftWireStatusCommitFault, nil)
		return
	}
	c.mu.Lock()
	c.commitN++
	c.gotToken = token
	c.mu.Unlock()
	_ = writeNftResponseForTest(conn, c.script.commitStatus, nil)
}

// readNftFrameForTest / writeNftResponseForTest mirror the producer's framing so the
// synthetic consumer reads requests and writes responses with the SAME shape.
func readNftFrameForTest(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeNftResponseForTest(w io.Writer, status byte, token []byte) error {
	body := make([]byte, 0, 1+4+len(token))
	body = append(body, status)
	body = binary.BigEndian.AppendUint32(body, uint32(len(token)))
	body = append(body, token...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func TestUDSNftProgrammerDeliversIngestFrameAndCommits(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "nft-ingest.sock")
	consumer := startSyntheticNftConsumer(t, endpoint, nftConsumerScript{
		verifyHash: true, // model the real prepare_verified gate
		token:      []byte("apply-token-vN+1"),
	})

	prog, err := NewUDSNftProgrammer(endpoint)
	if err != nil {
		t.Fatalf("NewUDSNftProgrammer: %v", err)
	}
	if prog.Endpoint() != endpoint {
		t.Fatalf("Endpoint() = %q, want %q", prog.Endpoint(), endpoint)
	}

	// Drive the FULL fan-out through the NftProgrammerBarrier so the test exercises the
	// production call path (barrier.Prepare threads the producer-pinned hash into the
	// real UDS client, which delivers the ingest frame).
	barrier, err := NewNftProgrammerBarrier(prog)
	if err != nil {
		t.Fatalf("NewNftProgrammerBarrier: %v", err)
	}
	snap := nftSnap(42, "pol1/v0 nft document bytes")
	prepared, err := barrier.Prepare(context.Background(), snap)
	if err != nil {
		t.Fatalf("Prepare over the real UDS client: %v", err)
	}

	// The consumer decoded the ingest frame and saw the (seq, producer-pinned hash, document)
	// tuple VERBATIM (the encoder did not re-derive the hash).
	consumer.mu.Lock()
	gotPrep := consumer.gotPrep
	consumer.mu.Unlock()
	if gotPrep == nil {
		t.Fatal("the synthetic consumer never decoded a PREPARE frame")
	}
	if gotPrep.seq != 42 {
		t.Fatalf("consumer decoded seq %d, want 42", gotPrep.seq)
	}
	if !bytesEqual(gotPrep.contentHash, snap.GetContentHash()) {
		t.Fatal("the delivered content_hash is not the producer-pinned snap.GetContentHash() verbatim")
	}
	if string(gotPrep.document) != "pol1/v0 nft document bytes" {
		t.Fatalf("the delivered document = %q, want the verbatim transported bytes", gotPrep.document)
	}

	// Commit routes the consumer-returned ApplyToken back over the SAME connection.
	if err := barrier.Commit(context.Background(), prepared); err != nil {
		t.Fatalf("Commit over the real UDS client: %v", err)
	}
	consumer.mu.Lock()
	commitN, gotToken := consumer.commitN, consumer.gotToken
	consumer.mu.Unlock()
	if commitN != 1 {
		t.Fatalf("consumer saw %d commits, want 1", commitN)
	}
	if string(gotToken) != "apply-token-vN+1" {
		t.Fatalf("COMMIT carried token %q, want the PREPARE-ACK token routed back verbatim", gotToken)
	}
}

func TestUDSNftProgrammerTransportHashMismatchFailsClosed(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "nft-ingest.sock")
	// The synthetic consumer's verify-before-parse gate NACKs a torn transport.
	startSyntheticNftConsumer(t, endpoint, nftConsumerScript{verifyHash: true, token: []byte("tok")})

	prog, err := NewUDSNftProgrammer(endpoint)
	if err != nil {
		t.Fatalf("NewUDSNftProgrammer: %v", err)
	}

	// Build a snapshot whose transported content_hash does NOT match the bytes — modelling
	// a tamper on the transport AFTER the producer guard. We call PrepareVerified DIRECTLY
	// (bypassing the barrier's producer-side guard) so the TRANSPORT's verify-before-parse
	// NACK is what fails the exchange, exactly the consumer's prepare_verified gate.
	bytesDoc := []byte("real-document-bytes")
	wrongHash := make([]byte, sha256.Size) // all-zero != sha256(real-document-bytes)
	_, err = prog.PrepareVerified(context.Background(), 7, wrongHash, bytesDoc)
	if err == nil {
		t.Fatal("a transported-hash mismatch must fail-close (the consumer's verify-before-parse NACK)")
	}
	if !errors.Is(err, ErrNftHashMismatch) {
		t.Fatalf("err = %v, want errors.Is(err, ErrNftHashMismatch) — the §5.1-separable NACK", err)
	}
}

func TestUDSNftProgrammerDialFailureFailsClosed(t *testing.T) {
	// No listener bound at the endpoint: the dial must fail-close (the host holds apply_seq
	// and re-drives), never hang.
	prog, err := NewUDSNftProgrammer(filepath.Join(t.TempDir(), "absent.sock"))
	if err != nil {
		t.Fatalf("NewUDSNftProgrammer: %v", err)
	}
	doc := []byte("doc")
	h := sha256.Sum256(doc)
	if _, err := prog.PrepareVerified(context.Background(), 3, h[:], doc); err == nil {
		t.Fatal("PrepareVerified against an absent listener must error (fail-closed)")
	}
}

func TestNewUDSNftProgrammerRejectsEmptyEndpoint(t *testing.T) {
	if _, err := NewUDSNftProgrammer(""); err == nil {
		t.Fatal("NewUDSNftProgrammer(\"\") must fail closed (no path to dial)")
	}
}

func TestNftIngestEndpointResolvesEnvOverride(t *testing.T) {
	if got := NftIngestEndpoint(); got != DefaultNftIngestEndpoint {
		t.Fatalf("unset env: NftIngestEndpoint() = %q, want the default %q", got, DefaultNftIngestEndpoint)
	}
	t.Setenv(nftIngestEndpointEnv, "/run/custom/nft.sock")
	if got := NftIngestEndpoint(); got != "/run/custom/nft.sock" {
		t.Fatalf("env override: NftIngestEndpoint() = %q, want the override", got)
	}
}

// TestWithNftProgrammerHardensStaleSliceFootgun proves the stale-slice footgun is closed:
// after a caller RETAINS the chain via Sweeper(), a later WithNftProgrammer must NOT mutate
// the retained slice's backing array — the nft leg lands ONLY in the fresh chain the
// FeedProducers now serves. A bare `append(fp.chain, sweeper)` into BindFeedProducers's
// spare capacity would rewrite the retained slice's tail; the defensive copy prevents it.
func TestWithNftProgrammerHardensStaleSliceFootgun(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(hostAgentFeedEnv, "uds:"+filepath.Join(dir, "watch.sock"))

	fp := BindFeedProducers(dir, nil)
	// A caller retains the chain BEFORE the nft leg is wired (the hand-off the footgun
	// would corrupt). Capture its length + a clone of its current members.
	retained := fp.Sweeper().(SweeperChain)
	retainedLen := len(retained)
	retainedSnapshot := append(SweeperChain(nil), retained...)

	// Now wire the nft leg — a bare append could write into the retained slice's backing array.
	if _, err := fp.WithNftProgrammer(&fakeNftProgrammer{}); err != nil {
		t.Fatalf("WithNftProgrammer: %v", err)
	}

	// The retained slice is UNCHANGED: same length, same members (the nft leg did not
	// leak into its backing array past the hand-off).
	if len(retained) != retainedLen {
		t.Fatalf("the retained chain length changed from %d to %d (stale-slice footgun)", retainedLen, len(retained))
	}
	for i := range retained {
		if retained[i] != retainedSnapshot[i] {
			t.Fatalf("the retained chain member %d was mutated after hand-off (stale-slice footgun)", i)
		}
	}

	// The FeedProducers now serves a LONGER chain (the nft leg landed in the fresh slice).
	if got := len(fp.Sweeper().(SweeperChain)); got != retainedLen+1 {
		t.Fatalf("the served chain has %d members, want %d (nft leg appended to the fresh chain)", got, retainedLen+1)
	}
}
