package hostagent

// feedwriter.go is the host agent's CROSS-PROCESS PRODUCER half of the POL-4
// host-local committed-snapshot feed (doc 11 §5.3, doc 13 §5 / §8.4, D72/D36).
//
// The host's ONE WatchPolicies(from_seq) subscriber (the Go D35 host agent —
// ds-dnsgate NEVER opens a control-plane stream, doc 11 §5.3) fans each COMMITTED
// version out HOST-LOCALLY by writing the produce-once canonical wire bytes into a
// shared feed directory; the dataplane consumers (ds-dnsgate's HostLocalFeedSource,
// and the other boundary services that resume from the same directory) read those
// files forward-only. This file is the WRITER of that directory; the READER lives
// OUTSIDE this module, in the Rust dataplane workspace
// (dataplane/services/ds-dnsgate/src/server.rs HostLocalFeedSource +
// AppliedSeqStore). The two halves share ONLY the on-disk contract below — there is
// no FFI, no shared type; this writer must match the bytes-on-disk shape EXACTLY or
// the consumer silently skips the file.
//
// THE CROSS-PROCESS ON-DISK CONTRACT (binding — mirrored from the consumer):
//
//   - Feed dir: DefaultHostAgentFeedDir (/run/ds-dnsgate/policy-feed) unless the
//     caller overrides it. The consumer resolves the SAME default
//     (DEFAULT_HOST_AGENT_FEED_DIR in dataplane main.rs).
//   - Per-version file: "<seq:020>.snapshot" — the seq zero-padded to 20 digits so
//     a lexicographic directory sort IS forward-seq order (the consumer's drain
//     sorts by name). The file's bytes ARE the produce-once transported canonical
//     wire form (snap.GetDocument()); the consumer recomputes the D120 content_hash
//     off these exact bytes and re-verifies, so this writer NEVER re-serializes the
//     document (produce-once / verify-only, doc 13 §5.1).
//   - Atomic publish: write a temp file under the SAME directory, then rename() it
//     into the final "<seq:020>.snapshot" name (atomic on one filesystem). The
//     consumer's seq parser (seq_of: strip ".snapshot", parse) skips any name that
//     is not "<digits>.snapshot", so a half-written temp file is never mis-read as a
//     version — but the rename is what makes a final name appear only once its bytes
//     are durable.
//   - Cursor: "<dir>/applied_seq" holding the decimal applied seq as a bare string
//     (no newline), written via the SAME temp+rename discipline. This is the
//     persisted WatchPolicies(from_seq) RESUME point the consumer's AppliedSeqStore
//     reads (trim + parse::<u64>, fail-open to 0). The host agent advances it AFTER
//     the per-version file is durable.
//
// WHERE IT IS DRIVEN (the prepare/commit barrier, doc 13 §5.2 / apply.go): the feed
// is written ONLY after the host completes the D72 two-phase apply admitter-LAST —
// i.e. after all three consumers have committed vN+1. FeedWriter therefore satisfies
// the apply.go Sweeper seam: ApplyCoordinator invokes Sweep(ctx, snap) only on a
// fully-successful commit (the make-before-break flip already happened), so wiring
// the FeedWriter as the coordinator's post-commit sweeper places the host-local
// fan-out EXACTLY behind the commit barrier — a version never reaches the on-disk
// feed before the host is serving it. (A real revocation Sweeper composes BEFORE
// this via SweeperChain so the host both sweeps AND fans out post-commit.)
//
// REASON-TOKEN SEPARABILITY (doc 13 §5.1, carried to heartbeat.go): the dataplane
// consumer separates a SchemaFailure (verified bytes that do not PARSE) from a
// ContentHashMismatch (the transported bytes do not match the separately-transported
// hash) — both NACK host-wide, but the operator telemetry must tell them apart. This
// producer-side writer classifies the SAME failure on the WRITE path (a version it
// is asked to fan out whose bytes are empty / unparseable vs. a hash that does not
// match its bytes) into the SnapshotReason token (heartbeat.go), so the
// separability the dataplane drop sink already has is surfaced host-ward in the
// heartbeat an operator queries — it does not stop at the dataplane in-process drop.
// NO proto enum is widened (that is freeze-gated, proto/FREEZE.md): the token rides
// the existing free-text ServiceHealth.Detail (heartbeat.go), never a new wire enum.
//
// NEVER-LOG-THE-SECRET: nothing here logs the composed document; the bytes cross to
// disk opaquely and the error paths name only the seq + the structural defect.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// DefaultHostAgentFeedDir is the host-local committed-snapshot feed directory the
// host agent fans versions out into and the dataplane consumer reads from when its
// DS_DNSGATE_HOST_AGENT_FEED env is set without an explicit path. It is the SINGLE
// cross-process default both halves resolve (mirrors DEFAULT_HOST_AGENT_FEED_DIR in
// dataplane/services/ds-dnsgate/src/main.rs); a deployment that relocates the feed
// passes an explicit dir to NewFeedWriter AND DS_DNSGATE_HOST_AGENT_FEED so the two
// stay single-sourced.
const DefaultHostAgentFeedDir = "/run/ds-dnsgate/policy-feed"

// hostLocalFeedSuffix is the per-version file-name suffix
// ("<seq:020>.snapshot") the consumer's seq parser strips. MUST match
// HOST_LOCAL_FEED_SUFFIX in the dataplane consumer (server.rs).
const hostLocalFeedSuffix = ".snapshot"

// appliedSeqFile is the cursor file name under the feed directory. MUST match
// APPLIED_SEQ_FILE in the dataplane consumer (server.rs).
const appliedSeqFile = "applied_seq"

// feedSeqWidth is the zero-pad width of the seq in a feed file name
// ("<seq:020>.snapshot"). MUST match the dataplane consumer's "{seq:020}" so a
// lexicographic directory sort IS forward-seq order. u64 max (20 digits) fits
// exactly in 20 columns, so no version ever overflows the padding.
const feedSeqWidth = 20

// FeedWriter is the host-local committed-snapshot feed PRODUCER (doc 11 §5.3): it
// turns each committed policy version into a "<seq:020>.snapshot" file via atomic
// rename and advances the on-disk applied_seq cursor, matching the cross-process
// contract the dataplane consumer (HostLocalFeedSource + AppliedSeqStore) reads.
//
// It is the WRITE side ONLY: the read/drain/verify side lives in the Rust dataplane
// workspace. The two share only the bytes-on-disk shape (the constants above).
//
// FORWARD-ONLY: WriteCommitted refuses a seq that is not strictly greater than the
// last cursor value it advanced to, so a re-delivered or out-of-order version never
// rewinds the feed (the consumer is forward-only on its side too; this keeps the
// PRODUCER honest so a buggy upstream re-fan-out cannot publish a backward version).
// The first write seeds the cursor from the on-disk value (a restart resumes rather
// than replaying), so the host agent survives a restart without re-fanning history.
type FeedWriter struct {
	// dir is the feed directory both the per-version files and the applied_seq
	// cursor live under (one host-local directory the host agent owns, co-located so
	// the §5 reload is one directory).
	dir string

	mu sync.Mutex
	// cursor is the highest seq this writer has fanned out + advanced the on-disk
	// cursor to. Seeded lazily from the on-disk applied_seq on the first write
	// (loaded == true) so a restart resumes; thereafter it is the in-memory truth the
	// forward-only guard reads. Distinct from the apply.go applied pointer (this is
	// the FEED cursor, the consumer's resume point).
	cursor uint64
	loaded bool

	// reasonHook, when non-nil, is invoked with the (SnapshotReason, seq) EVERY
	// WriteCommitted classifies a version — the seam that routes the writer's
	// per-version separability (heartbeat.go) host-ward. It is the writer that lives
	// INSIDE the fp.chain (BindFeedProducers), so wiring the hook here surfaces the
	// authoritative chain's reason WITHOUT substituting a fresh writer for the one the
	// chain already sweeps (the carrier/nft-preserving restore). Set via
	// FeedProducers.SetReasonHook; nil (every default path) is a no-op — the write path
	// is byte-identical. Guarded by w.mu so a concurrent SetReasonHook/WriteCommitted
	// never races.
	reasonHook ReasonHook
}

// ReasonHook is the host-ward routing seam for a FeedWriter's per-version
// SnapshotReason: it is invoked with (consumer, reason, seq) each time the writer
// classifies a committed version, so the daemon can stamp the separable cause onto
// the boundary consumer's free-text ServiceHealth.Detail (heartbeat.go) an operator
// queries. consumer is the boundary name the reason is attributed to (the fed
// consumer, BoundaryDNSGate). The hook must be cheap + non-blocking (it runs on the
// post-commit sweep path); a nil hook is never invoked.
type ReasonHook func(consumer string, reason SnapshotReason, seq uint64)

// NewFeedWriter binds a FeedWriter to dir (empty => DefaultHostAgentFeedDir). The
// directory need not exist yet — WriteCommitted creates it on the first fan-out (a
// booting host before its first committed version has written nothing, the §5
// "no file => no snapshot" posture the consumer honors by treating a missing/empty
// directory as an exhausted stream).
func NewFeedWriter(dir string) *FeedWriter {
	if dir == "" {
		dir = DefaultHostAgentFeedDir
	}
	return &FeedWriter{dir: dir}
}

// Dir returns the feed directory this writer fans versions out into — the value a
// deployment must hand the dataplane consumer (DS_DNSGATE_HOST_AGENT_FEED) so the
// two halves resolve the same directory.
func (w *FeedWriter) Dir() string { return w.dir }

// FeedCursor returns the highest seq this writer has fanned out (the in-memory feed
// cursor). Before the first WriteCommitted it is 0; it reflects the on-disk
// applied_seq once a write has loaded it. Distinct from the apply.go applied
// pointer — this is the PRODUCER's view of the consumer's resume point.
func (w *FeedWriter) FeedCursor() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cursor
}

// setReasonHook installs (or clears, with nil) the host-ward reason-routing hook
// WriteCommitted invokes with each classified version's (reason, seq). Guarded by w.mu
// so a concurrent WriteCommitted reading the hook never races the install. Package-
// private: the daemon installs it through FeedProducers.SetReasonHook so the writer
// that lives INSIDE the fp.chain is the one wired.
func (w *FeedWriter) setReasonHook(hook ReasonHook) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reasonHook = hook
}

// WriteCommitted fans ONE committed version out into the host-local feed: it writes
// the transported document bytes to "<seq:020>.snapshot" via atomic rename, then
// advances the "<dir>/applied_seq" cursor — both via temp-file + rename so a
// concurrent consumer scan / a crash mid-write never observes a torn file (the prior
// state stays readable). The bytes are the produce-once canonical wire form
// (snap.GetDocument()); this writer NEVER re-serializes them.
//
// It returns the SnapshotReason classifying the version (heartbeat.go):
//
//   - ReasonNone on success (the version is now in the feed; the cursor advanced).
//   - ReasonSchemaFailure when the version carries NO transportable document (empty
//     bytes — the produce-once carrier was never composed): there is nothing valid
//     to fan out, so the feed is NOT written and the cursor is NOT advanced (the host
//     stays on its prior fed version). The error names the seq + the structural
//     defect; the reason token carries the SchemaFailure separability host-ward.
//   - ReasonContentHashMismatch when the snapshot carries a content_hash that does
//     NOT match SHA-256 over its OWN transported bytes — a producer-side integrity
//     check that mirrors the consumer's verify-before-parse: a mismatch means the
//     carrier is internally inconsistent (the §5.1 identity tuple is torn), so the
//     feed is NOT written. (The snapshot store already verified this on receipt, so
//     on the production path the hash is consistent and this never fires; the guard
//     keeps a buggy in-process producer from publishing a torn version.)
//
// A nil snapshot is a programming error from the caller and is rejected as a
// SchemaFailure (no valid carrier). A seq that is not strictly greater than the
// current cursor is rejected as an out-of-order fan-out (ReasonNone with a non-nil
// error — it is not a content defect, it is a re-delivery the forward-only feed
// drops): the file is not rewritten and the cursor is unchanged.
func (w *FeedWriter) WriteCommitted(snap *boundaryv1.PolicySnapshot) (reason SnapshotReason, err error) {
	// Route the classified per-version reason host-ward on EVERY exit (the reason-hook
	// seam): a non-nil hook is invoked with the final (reason, seq) after this call
	// settles, so the daemon can stamp DetailFor(seq) onto the fed consumer's
	// ServiceHealth.Detail. Deferred so the SINGLE hook call covers every return path
	// (schema failure / hash mismatch / forward-only dedup / clean fan-out) without
	// duplicating it at each. seq is captured below (0 for a nil snapshot — a
	// programming error the hook still sees as a SchemaFailure at seq 0).
	var hookSeq uint64
	defer func() {
		w.mu.Lock()
		hook := w.reasonHook
		w.mu.Unlock()
		if hook != nil {
			hook(BoundaryDNSGate, reason, hookSeq)
		}
	}()
	if snap == nil {
		return ReasonSchemaFailure, fmt.Errorf("hostagent: feed writer: nil snapshot (no produce-once carrier to fan out)")
	}
	seq := snap.GetSeq()
	hookSeq = seq
	document := snap.GetDocument()

	// SchemaFailure: a version with no transportable document was never composed into
	// a produce-once carrier — there is nothing to fan out. Distinct from a hash
	// mismatch (the bytes are present but inconsistent with their hash); the operator
	// must tell the two apart (doc 13 §5.1), so they map to distinct reason tokens.
	if len(document) == 0 {
		return ReasonSchemaFailure, fmt.Errorf(
			"hostagent: feed writer: seq %d carries no document bytes (schema failure: no produce-once carrier to fan out)",
			seq,
		)
	}

	// ContentHashMismatch: if the carrier pins a content_hash, it MUST equal SHA-256
	// over the transported bytes (the §5.1 identity tuple, the SAME single source of
	// wire hashing the consumer recomputes). A carrier with an EMPTY hash is accepted
	// (some in-process producers do not pin it; the consumer recomputes authoritatively
	// either way) — only a PRESENT-but-WRONG hash is a torn carrier we refuse to
	// publish. The host stays on its prior fed version.
	if want := snap.GetContentHash(); len(want) > 0 {
		got := sha256.Sum256(document)
		if !bytesEqual(want, got[:]) {
			return ReasonContentHashMismatch, fmt.Errorf(
				"hostagent: feed writer: seq %d content_hash does not match its transported bytes (content_hash mismatch: torn carrier, not fanned out)",
				seq,
			)
		}
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Seed the forward-only cursor from the on-disk applied_seq on the first write so a
	// restart resumes the feed rather than re-fanning committed history below the
	// persisted cursor. Fail-open to 0 (a fresh host, or an unreadable cursor) exactly
	// like the consumer's AppliedSeqStore::load.
	if !w.loaded {
		w.cursor = w.loadCursor()
		w.loaded = true
	}

	// FORWARD-ONLY: a seq at or below the cursor is a re-delivered / out-of-order
	// version the feed drops (the consumer is forward-only too; this keeps the producer
	// from publishing a backward version). It is NOT a content defect — ReasonNone with
	// a non-nil error so the caller can log the benign dedup without flagging a schema
	// failure.
	if seq <= w.cursor {
		return ReasonNone, fmt.Errorf(
			"hostagent: feed writer: seq %d not past feed cursor %d (forward-only: re-delivered/out-of-order version dropped, feed unchanged)",
			seq, w.cursor,
		)
	}

	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		return ReasonNone, fmt.Errorf("hostagent: feed writer: create feed dir %q: %w", w.dir, err)
	}

	// 1) Write the per-version file: temp under the SAME dir, then atomic rename into
	// "<seq:020>.snapshot". The bytes are the produce-once transported document,
	// written verbatim (no re-serialization).
	finalName := feedFileName(seq)
	finalPath := filepath.Join(w.dir, finalName)
	if err := w.atomicWrite(finalName, finalPath, document); err != nil {
		return ReasonNone, fmt.Errorf("hostagent: feed writer: fan out seq %d to %q: %w", seq, finalPath, err)
	}

	// 2) Advance the cursor file AFTER the version file is durable, so a crash between
	// the two never publishes a cursor past a version that is not on disk (the consumer
	// would then resume past a version it never saw). The reverse order is the only
	// torn one; this order is safe (a crash leaves a version file with no cursor bump —
	// the consumer re-scans and re-drains it, idempotent).
	if err := w.persistCursor(seq); err != nil {
		// The version file is durable; only the cursor bump failed. The consumer still
		// drains the file (it scans the directory, the cursor is only the resume point),
		// so this is best-effort — but surface it so the operator sees the cursor lag.
		return ReasonNone, fmt.Errorf(
			"hostagent: feed writer: seq %d fanned out but applied_seq cursor not advanced (consumer still drains the file; cursor lags): %w",
			seq, err,
		)
	}
	w.cursor = seq
	return ReasonNone, nil
}

// Sweep makes FeedWriter satisfy the apply.go Sweeper seam so it can be wired as the
// ApplyCoordinator's POST-COMMIT hook: the coordinator invokes Sweep(ctx, snap) ONLY
// after a fully-successful commit (all three consumers flipped vN+1 admitter-LAST),
// which is EXACTLY the barrier point the host-local feed must be written behind (doc
// 13 §5.2). It fans the just-committed version out (WriteCommitted) and returns
// snap.GetSeq() as the swept seq so the coordinator advances apply_seq post-fan-out
// (the FeedWriter is the producer half; a real revocation Sweeper composes BEFORE it
// via SweeperChain).
//
// The ctx is accepted to satisfy the seam (the file write is local + fast, so it is
// not threaded into the os calls); a fan-out failure is returned so the coordinator
// HOLDS apply_seq at the prior version (a committed version that could not be fanned
// out must not advance the resume cursor the consumers read).
func (w *FeedWriter) Sweep(_ context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	if snap == nil {
		return 0, fmt.Errorf("hostagent: feed writer: Sweep on nil snapshot")
	}
	if _, err := w.WriteCommitted(snap); err != nil {
		return 0, err
	}
	return snap.GetSeq(), nil
}

// loadCursor reads the on-disk applied_seq, fail-open to 0 — the SAME fail-open the
// consumer's AppliedSeqStore::load uses (no cursor yet / unreadable / garbled => a
// fresh resume from 0, never a panic). Caller holds w.mu.
func (w *FeedWriter) loadCursor() uint64 {
	raw, err := os.ReadFile(filepath.Join(w.dir, appliedSeqFile))
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(trimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// persistCursor writes seq as the applied_seq cursor via temp+rename, matching the
// consumer's AppliedSeqStore::persist (a per-pid temp name + rename; the bytes are
// the bare decimal seq, no newline, exactly seq.to_string()). Caller holds w.mu.
func (w *FeedWriter) persistCursor(seq uint64) error {
	tmpName := fmt.Sprintf("%s.%d.tmp", appliedSeqFile, os.Getpid())
	tmpPath := filepath.Join(w.dir, tmpName)
	finalPath := filepath.Join(w.dir, appliedSeqFile)
	if err := os.WriteFile(tmpPath, []byte(strconv.FormatUint(seq, 10)), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// atomicWrite writes data to a temp file under w.dir (a per-pid temp name derived
// from the final name, so a name ending in ".snapshot.tmp" the consumer's seq parser
// never mis-reads as a version) and renames it into finalPath — the atomic publish
// the cross-process consumer relies on (a final "<seq:020>.snapshot" name appears
// only once its full bytes are durable). Caller holds w.mu.
func (w *FeedWriter) atomicWrite(finalName, finalPath string, data []byte) error {
	// "<seq:020>.snapshot.<pid>.tmp" — does NOT end in ".snapshot", so the consumer's
	// seq_of (strip ".snapshot", parse) skips it; the pid keeps a restart-leftover temp
	// from colliding with a live write.
	tmpPath := filepath.Join(w.dir, fmt.Sprintf("%s.%d.tmp", finalName, os.Getpid()))
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// feedFileName renders the per-version feed file name "<seq:020>.snapshot" — the
// zero-padded form whose lexicographic sort IS forward-seq order, matching the
// consumer's format!("{seq:020}.snapshot").
func feedFileName(seq uint64) string {
	return fmt.Sprintf("%0*d%s", feedSeqWidth, seq, hostLocalFeedSuffix)
}

// SweeperChain composes an ordered list of Sweepers into ONE Sweeper that runs each
// in turn on a committed version, stopping at the first error (and reporting its
// swept seq as the chain's). It is the seam that lets the host run the REAL
// revocation sweep AND the host-local feed fan-out post-commit in one coordinator
// hook: build it as SweeperChain{revocationSweeper, feedWriter} so the revocation
// sweep runs FIRST (apply_seq advances post-sweep, D72) and the feed is fanned out
// only after the host is fully swept onto vN+1.
//
// With a single member it is a pass-through; an empty chain is a no-op that reports
// snap.GetSeq() (the caller advances seq through its own path). The chain returns the
// LAST member's swept seq on full success (each member is expected to return the same
// committed seq); a member error stops the chain and is surfaced so the coordinator
// holds apply_seq.
type SweeperChain []Sweeper

// Sweep runs each member in order, returning the last member's swept seq on success
// or the first member's error (with the prior swept seq dropped — the coordinator
// holds apply_seq at the prior version on any member failure).
func (c SweeperChain) Sweep(ctx context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	if snap == nil {
		return 0, fmt.Errorf("hostagent: sweeper chain: nil snapshot")
	}
	swept := snap.GetSeq()
	for i, s := range c {
		if s == nil {
			return 0, fmt.Errorf("hostagent: sweeper chain: nil sweeper at position %d", i)
		}
		got, err := s.Sweep(ctx, snap)
		if err != nil {
			return 0, fmt.Errorf("hostagent: sweeper chain: member %d failed: %w", i, err)
		}
		swept = got
	}
	return swept, nil
}

// bytesEqual is a constant-time-irrelevant byte compare (the content_hash compare is
// not a secret-bearing equality — both sides are public wire hashes; an early-exit
// compare is fine and avoids pulling in crypto/subtle for a non-secret).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// trimSpace trims leading/trailing ASCII whitespace from s (matching the consumer's
// AppliedSeqStore::load trim before parse), without pulling strings into this file's
// import set for one call.
func trimSpace(s string) string {
	start := 0
	for start < len(s) && isSpace(s[start]) {
		start++
	}
	end := len(s)
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

// ── producer-bind: wiring the live feed PRODUCERS into the host-agent daemon ──
//
// BindFeedProducers is the host-agent daemon's single composition point for the
// POL-4 host-local committed-snapshot fan-out PRODUCERS (doc 11 §5.3, doc 13 §5):
// the on-disk file feed (FeedWriter, the doc 13 §8.4 v0 transport, ALWAYS bound),
// and — ONLY when DS_DNSGATE_HOST_AGENT_FEED selects the LIVE UDS carrier (a
// "uds:" value) — the live WatchPolicies(from_seq) carrier (WatchPoliciesCarrier,
// dnsfeed_carrier.go) and the nft-writer live ingest fan-out (NftProgrammerBarrier,
// nftfeed_client.go). All bound producers are composed into ONE post-commit
// SweeperChain the caller hands to NewApplyCoordinator, so each fans the version
// out EXACTLY behind the prepare/commit barrier (the coordinator invokes the
// sweeper only after the admitter-LAST commit, doc 13 §5.2).
//
// THE ENV GATE (single-sourced with the dataplane consumer). The selection mirrors
// the ds-dnsgate consumer's host_agent_policy_source (dataplane/services/
// ds-dnsgate/src/main.rs):
//
//   - DS_DNSGATE_HOST_AGENT_FEED UNSET → the default-OFF launch path. ONLY the file
//     feed is bound (byte-identical to the pre-producer-bind daemon: the file feed
//     fanned out on EVERY committed apply, offline included). The live carrier UDS
//     listener is NOT bound, NO goroutine is started, and a deployment that does not
//     run the dataplane consumer simply leaves the files unread. This path touches
//     no socket and spawns no serve loop — the gate-unset daemon is unchanged.
//   - DS_DNSGATE_HOST_AGENT_FEED="uds:<path>" (or a bare "uds:" → DefaultHostAgentFeedSock)
//     → the LIVE carrier is selected (exactly the value the consumer parses with
//     parse_carrier_endpoint). The file feed STAYS bound (the durable resume point
//     the carrier's from_seq cursor rides), and the WatchPoliciesCarrier + the
//     nft-writer barrier are composed AFTER it in the chain. The UDS listener is bound
//     and Serve started only when Start is called (the live dial — DEFERRED-MANUAL,
//     see Start).
//   - Any OTHER value (a bare "1", a directory path) → the file feed only (the v0
//     gate-ON file-feed path the consumer also keeps), no live carrier. The carrier is
//     PURELY ADDITIVE behind the explicit "uds:" opt-in.
//
// COMPOSED AFTER THE REVOCATION SWEEP. The caller passes the REAL post-commit
// revocation Sweeper (the separate revoc-producer leg) as revocation; it is composed
// FIRST in the chain so the host is SWEPT onto vN+1 (apply_seq advances post-sweep,
// D72) BEFORE any version is fanned out. A nil revocation composes the producers
// alone (the M0 path with no revocation sweep wired yet).
//
// feedDir empty => DefaultHostAgentFeedDir; the carrier UDS endpoint is co-located
// under it (DefaultHostAgentFeedSock) unless the gate names an explicit "uds:<path>".
func BindFeedProducers(feedDir string, revocation Sweeper) *FeedProducers {
	writer := NewFeedWriter(feedDir)
	fp := &FeedProducers{
		writer:    writer,
		gateValue: os.Getenv(hostAgentFeedEnv),
	}

	// The chain is composed in fan-out order: the revocation sweep (if wired) FIRST so
	// the host is swept onto vN+1 before any version reaches a consumer (D72), then the
	// durable file feed, then — only behind the "uds:" gate — the live producers.
	chain := SweeperChain{}
	if revocation != nil {
		chain = append(chain, revocation)
	}
	chain = append(chain, writer)

	if endpoint, live := parseHostAgentFeedEndpoint(fp.gateValue); live {
		fp.carrier = NewWatchPoliciesCarrier()
		fp.carrierEndpoint = endpoint
		// The carrier buffers each committed version post-commit (its Sweep), so a
		// dialing dataplane consumer replays the forward-only history past its from_seq.
		chain = append(chain, fp.carrier)
		// The nft-writer live ingest fan-out, composed as a post-commit Sweeper too — but
		// ONLY when a real NftProgrammer transport is wired (WithNftProgrammer). Off a real
		// transport the leg is not appended (the live nft UDS client is owner-landed; the
		// daemon scaffolds it behind the same gate, DEFERRED-MANUAL).
	}

	fp.chain = chain
	return fp
}

// WithNftProgrammer adds the nft-writer live ingest fan-out (NftProgrammerBarrier
// over programmer) to the producer chain as a post-commit Sweeper, behind the SAME
// "uds:" gate the carrier rides. It is a no-op (and returns fp unchanged) when the
// gate did not select the live carrier or programmer is nil — the gate-unset /
// no-transport path stays free of the nft leg, byte-identical. It returns fp so the
// daemon can chain WithNftProgrammer onto BindFeedProducers; a construction error
// (a nil programmer rejected by NewNftProgrammerBarrier) is surfaced.
//
// The real host-local UDS NftProgrammer client to the ds-nft consumer (UDSNftProgrammer,
// nftfeed_client.go) is the production transport; the daemon supplies it behind the live
// gate (NftIngestEndpoint). A test fake satisfies the seam in-memory
// (nftfeed_client_test.go).
//
// STALE-SLICE FOOTGUN (hardened). Appending the nft leg with a bare
// `fp.chain = append(fp.chain, sweeper)` is a footgun: BindFeedProducers built fp.chain
// with `append`, so it can carry SPARE CAPACITY. A bare append into that spare capacity
// writes the nft sweeper into the SAME backing array a prior fp.Sweeper() caller already
// retained — mutating a slice AFTER hand-off (a caller that read Sweeper() before
// WithNftProgrammer would see its backing array's tail silently rewritten, or two
// FeedProducers built off a cloned chain would alias one array). The fix is an OWNERSHIP
// TRANSFER: copy the current chain into a fresh, exactly-sized backing array and append
// the nft leg to THAT, so the installed chain never aliases an array any prior caller
// holds. fp.chain is reassigned to the fresh slice; the old slice (and anything that read
// it) is now immutable from here.
func (fp *FeedProducers) WithNftProgrammer(programmer NftProgrammer) (*FeedProducers, error) {
	if fp.carrier == nil || programmer == nil {
		// Gate not live, or no transport: leave the chain untouched (default-OFF stays byte-identical).
		return fp, nil
	}
	sweeper, err := newNftFeedSweeper(programmer)
	if err != nil {
		return fp, err
	}
	fp.nftSweeper = sweeper
	// Defensive copy / ownership transfer: build a FRESH, exactly-sized backing array so
	// appending the nft leg can never mutate a chain a prior Sweeper() caller retained
	// (a bare append into BindFeedProducers's spare capacity would write past the
	// hand-off). make(len+1) then copy guarantees the new slice has NO shared backing
	// array with the old fp.chain.
	next := make(SweeperChain, len(fp.chain), len(fp.chain)+1)
	copy(next, fp.chain)
	fp.chain = append(next, sweeper)
	return fp, nil
}

// FeedProducers is the bound set of POL-4 fan-out producers + their composition into
// ONE post-commit SweeperChain (Sweeper). It is built once per host agent by
// BindFeedProducers and handed to NewApplyCoordinator; the daemon also calls Start to
// bring up the live carrier's UDS serve loop when the gate selected it.
type FeedProducers struct {
	writer  *FeedWriter           // the on-disk file feed (always bound)
	carrier *WatchPoliciesCarrier // the live UDS carrier (nil unless the "uds:" gate is set)
	// nftSweeper is the nft-writer live ingest fan-out (nil unless WithNftProgrammer wired a transport).
	nftSweeper *nftFeedSweeper
	chain      SweeperChain

	gateValue       string // the raw DS_DNSGATE_HOST_AGENT_FEED value (for diagnostics)
	carrierEndpoint string // the resolved carrier UDS path (empty when not live)
}

// Sweeper returns the composed post-commit SweeperChain the daemon hands to
// NewApplyCoordinator — the revocation sweep (if wired) + the file feed + (behind the
// "uds:" gate) the live carrier and nft-writer fan-out, in fan-out order. It is the
// single value the coordinator invokes post-commit (doc 13 §5.2).
func (fp *FeedProducers) Sweeper() Sweeper { return fp.chain }

// SetReasonHook routes the per-version SnapshotReason of the file-feed writer that
// lives INSIDE this producer's chain host-ward: it installs hook on fp.writer so each
// committed version the chain sweeps also records its separability (heartbeat.go) onto
// the boundary consumer's ServiceHealth.Detail (via the daemon's tracker). It is the
// seam that keeps the carrier/nft fan-out fully intact — the daemon drives the
// AUTHORITATIVE fp.Sweeper() chain (never a substituted fresh writer) AND still routes
// the reason — closing the round-1 veto (the fresh-writer substitution silently dropped
// the carrier + nft legs). A nil hook clears it (the default, no-op). Threading it onto
// the writer that the chain already runs means the reason is recorded for the EXACT
// version the carrier + nft legs also fan out, in one post-commit sweep.
func (fp *FeedProducers) SetReasonHook(hook ReasonHook) {
	fp.writer.setReasonHook(hook)
}

// CarrierCursor returns the highest seq the live WatchPolicies carrier has buffered
// for replay (the carrier's in-memory cursor), or 0 when no live carrier is bound (the
// default-OFF / file-only paths, where fp.carrier is nil). It is the accessor a test
// (or an operator diagnostic) uses to assert the carrier buffered a committed version
// WITHOUT reaching past fp into the carrier directly — the carrier leg's fan-out is
// otherwise only observable cross-process by a dialing consumer.
func (fp *FeedProducers) CarrierCursor() uint64 {
	if fp.carrier == nil {
		return 0
	}
	return fp.carrier.Cursor()
}

// LiveCarrier reports whether the "uds:" gate selected the live WatchPolicies carrier
// (so the daemon must Start its serve loop). False on the default-OFF / file-only
// paths.
func (fp *FeedProducers) LiveCarrier() bool { return fp.carrier != nil }

// CarrierEndpoint returns the resolved carrier UDS endpoint ("uds:<path>" → <path>, a
// bare "uds:" → DefaultHostAgentFeedSock). Empty when the live carrier is not selected.
func (fp *FeedProducers) CarrierEndpoint() string { return fp.carrierEndpoint }

// FeedDir returns the on-disk feed directory the file feed fans into — the value the
// daemon must single-source with the dataplane consumer's DS_DNSGATE_HOST_AGENT_FEED.
func (fp *FeedProducers) FeedDir() string { return fp.writer.Dir() }

// Start brings up the LIVE carrier's UDS serve loop when the "uds:" gate selected it:
// it binds a Unix listener at CarrierEndpoint (creating the parent dir, removing any
// stale socket from a prior run) and runs WatchPoliciesCarrier.Serve on a goroutine,
// draining when ctx is cancelled. It is a NO-OP (returns nil) on the default-OFF /
// file-only paths — Start never touches a socket unless the gate explicitly opted into
// the live carrier, so the gate-unset daemon spawns no serve loop.
//
// DEFERRED-MANUAL (the live dial). Binding the host-local UDS and serving the
// WatchPolicies(from_seq) stream to a dialing dataplane consumer is the LIVE leg: a
// real ds-dnsgate consumer must dial CarrierEndpoint with DS_DNSGATE_HOST_AGENT_FEED
// =uds:<same path> to exercise it end to end (no live claude/cia/qemu here). The serve
// loop itself is unit-proven in-process over a real UDS (dnsfeed_carrier_test.go); the
// cross-process live dial is the deferred manual step an operator runs against a
// running ds-dnsgate.
//
// The returned channel delivers the serve loop's terminal error (a clean ctx-cancel
// shutdown returns context.Canceled, not a fault) so the daemon can join it on drain;
// it is closed after Serve returns. On the no-op path it returns a nil channel.
func (fp *FeedProducers) Start(ctx context.Context) (<-chan error, error) {
	if fp.carrier == nil {
		// Default-OFF / file-only: nothing to serve. No socket touched, no goroutine spawned.
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(fp.carrierEndpoint), 0o755); err != nil {
		return nil, fmt.Errorf("hostagent: bind feed producers: create carrier dir for %q: %w", fp.carrierEndpoint, err)
	}
	// Remove a stale socket from a prior run so the bind does not fail with EADDRINUSE
	// (a leftover UDS inode is never a live listener once this process owns the path).
	if err := removeStaleSock(fp.carrierEndpoint); err != nil {
		return nil, fmt.Errorf("hostagent: bind feed producers: clear stale carrier socket %q: %w", fp.carrierEndpoint, err)
	}
	listener, err := net.Listen("unix", fp.carrierEndpoint)
	if err != nil {
		return nil, fmt.Errorf("hostagent: bind feed producers: listen on carrier UDS %q: %w", fp.carrierEndpoint, err)
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		done <- fp.carrier.Serve(ctx, listener)
	}()
	return done, nil
}

// hostAgentFeedEnv is the env gate that selects the live host-local UDS carrier vs.
// the default-OFF / file-only paths. MUST match HOST_AGENT_FEED_ENV in the dataplane
// consumer (dataplane/services/ds-dnsgate/src/main.rs) so the producer and consumer
// agree on the SAME switch.
const hostAgentFeedEnv = "DS_DNSGATE_HOST_AGENT_FEED"

// hostAgentFeedUDSPrefix is the value prefix that opts INTO the live UDS carrier — the
// SAME "uds:" prefix the consumer's parse_carrier_endpoint strips. A bare "uds:" with
// no path falls back to DefaultHostAgentFeedSock; any other value selects the file
// feed (so the carrier is purely additive behind an explicit opt-in).
const hostAgentFeedUDSPrefix = "uds:"

// parseHostAgentFeedEndpoint resolves a DS_DNSGATE_HOST_AGENT_FEED value to a live
// carrier UDS endpoint, mirroring the dataplane consumer's parse_carrier_endpoint
// (dataplane/services/ds-dnsgate/src/main.rs): a "uds:<path>" value selects the live
// carrier at <path>; a bare "uds:" selects DefaultHostAgentFeedSock; ANY other value
// (unset, "1", a directory path) selects the file feed (live=false). The two halves
// MUST resolve the SAME endpoint, so this is the producer mirror of the consumer's
// parser — single-sourcing the "uds:" convention across the cross-process seam.
func parseHostAgentFeedEndpoint(value string) (endpoint string, live bool) {
	rest, ok := strings.CutPrefix(value, hostAgentFeedUDSPrefix)
	if !ok {
		return "", false
	}
	if rest == "" {
		return DefaultHostAgentFeedSock, true
	}
	return rest, true
}

// removeStaleSock removes a leftover UDS path from a prior run so a fresh Listen does
// not fail with "address already in use". A path that does not exist is fine (nothing
// to clear); any other stat/remove error is surfaced so the caller fails closed rather
// than racing an unknown filesystem object.
func removeStaleSock(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return os.Remove(path)
}
