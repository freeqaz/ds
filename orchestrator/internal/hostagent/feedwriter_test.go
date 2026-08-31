package hostagent

// feedwriter_test.go is the SYNTHETIC in-process proof of the POL-4 host-local feed
// PRODUCER (feedwriter.go) against the CROSS-PROCESS on-disk contract the dataplane
// consumer (dataplane/services/ds-dnsgate/src/server.rs HostLocalFeedSource +
// AppliedSeqStore) reads. There is no live claude/cia/qemu/podman and no Rust here —
// the test drives the Go writer over a temp directory and asserts the EXACT bytes-on-
// disk shape the consumer's own test (host_agent_fan_out) produces:
//
//   - the per-version file name is "<seq:020>.snapshot" (20-digit zero-padded so a
//     lexicographic sort IS forward-seq order — the consumer's drain order);
//   - the file bytes ARE the produce-once transported document, byte-for-byte (no
//     re-serialization);
//   - the cursor file "<dir>/applied_seq" holds the bare decimal seq (no newline),
//     advanced AFTER the version file is durable;
//   - the publish is atomic-rename (no leftover ".tmp" the consumer's seq parser
//     would skip but a directory listing should not retain);
//   - and — the barrier proof — when the FeedWriter is wired as the
//     ApplyCoordinator's POST-COMMIT sweeper, the feed is written ONLY after the
//     admitter-LAST commit (ds-dnsgate commits last, then the feed appears).
//
// The eventLog / fakeConsumer / threeConsumers / firstIndexOf helpers are shared with
// apply_test.go (same package).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// snapAt builds a committed PolicySnapshot at seq with the given document bytes and a
// content_hash that is the SHA-256 over those bytes (the §5.1 identity tuple the
// snapshot store already verified on receipt — so the feed writer's internal hash
// guard is consistent and never fires on the happy path).
func snapAt(seq uint64, document string) *boundaryv1.PolicySnapshot {
	sum := sha256.Sum256([]byte(document))
	return &boundaryv1.PolicySnapshot{
		Seq:         seq,
		Document:    []byte(document),
		ContentHash: sum[:],
	}
}

// readCursor reads the on-disk applied_seq cursor the dataplane consumer's
// AppliedSeqStore::load reads (trim + parse), returning (value, present).
func readCursor(t *testing.T, dir string) (uint64, bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "applied_seq"))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		t.Fatalf("applied_seq cursor %q is not a decimal seq: %v", raw, err)
	}
	return v, true
}

// finalFeedFiles returns the sorted "<...>.snapshot" file names in dir (the names the
// consumer's drain sorts lexicographically), EXCLUDING any temp file (a ".tmp" the
// atomic rename should have removed) and the cursor.
func finalFeedFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read feed dir %q: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") {
			t.Fatalf("feed dir retained a temp file %q — atomic rename should leave no .tmp behind", name)
		}
		if strings.HasSuffix(name, ".snapshot") {
			names = append(names, name)
		}
	}
	return names
}

// TestFeedWriterOnDiskContract proves the produced files match the cross-process
// shape the dataplane consumer reads: the "<seq:020>.snapshot" name, the verbatim
// document bytes, and the advanced applied_seq cursor.
func TestFeedWriterOnDiskContract(t *testing.T) {
	dir := t.TempDir()
	w := NewFeedWriter(dir)

	if got := w.Dir(); got != dir {
		t.Fatalf("Dir() = %q, want the bound dir %q", got, dir)
	}
	// A booting host before its first fan-out: no files, cursor absent (the §5
	// "no file => no snapshot" posture the consumer treats as an exhausted stream).
	if names := finalFeedFiles(t, dir); len(names) != 0 {
		t.Fatalf("fresh feed dir should hold no version files, got %v", names)
	}
	if _, present := readCursor(t, dir); present {
		t.Fatal("fresh feed dir should hold no applied_seq cursor")
	}

	// Fan out a committed version at seq 3.
	const docV1 = `{"schema_version":1,"layer":"sub","posture":"v1"}`
	reason, err := w.WriteCommitted(snapAt(3, docV1))
	if err != nil {
		t.Fatalf("WriteCommitted(seq=3): %v", err)
	}
	if reason != ReasonNone {
		t.Fatalf("clean fan-out reason = %v, want ReasonNone", reason)
	}

	// The version file name is EXACTLY the 20-digit zero-padded "<seq:020>.snapshot"
	// the consumer's format!("{seq:020}.snapshot") produces.
	wantName := "00000000000000000003.snapshot"
	names := finalFeedFiles(t, dir)
	if len(names) != 1 || names[0] != wantName {
		t.Fatalf("feed files = %v, want exactly [%s] (the cross-process <seq:020>.snapshot name)", names, wantName)
	}
	// The file bytes ARE the produce-once transported document, byte-for-byte.
	gotBytes, err := os.ReadFile(filepath.Join(dir, wantName))
	if err != nil {
		t.Fatalf("read version file: %v", err)
	}
	if string(gotBytes) != docV1 {
		t.Fatalf("version file bytes = %q, want the verbatim transported document %q (no re-serialization)", gotBytes, docV1)
	}
	// The cursor advanced to 3 (the consumer's resume point).
	if v, present := readCursor(t, dir); !present || v != 3 {
		t.Fatalf("applied_seq cursor = (%d, present=%v), want 3 present", v, present)
	}
	if fc := w.FeedCursor(); fc != 3 {
		t.Fatalf("FeedCursor() = %d, want 3", fc)
	}

	// Fan out a SECOND forward version at seq 9: the lexicographic name sort keeps the
	// two in forward-seq order, exactly as the consumer drains them.
	const docV2 = `{"schema_version":1,"layer":"sub","posture":"v2"}`
	if _, err := w.WriteCommitted(snapAt(9, docV2)); err != nil {
		t.Fatalf("WriteCommitted(seq=9): %v", err)
	}
	names = finalFeedFiles(t, dir)
	want2 := []string{"00000000000000000003.snapshot", "00000000000000000009.snapshot"}
	if len(names) != 2 || names[0] != want2[0] || names[1] != want2[1] {
		t.Fatalf("feed files (sorted) = %v, want %v (forward-seq order by zero-padded name)", names, want2)
	}
	if v, _ := readCursor(t, dir); v != 9 {
		t.Fatalf("applied_seq cursor after seq 9 = %d, want 9", v)
	}
}

// TestFeedWriterForwardOnly proves a re-delivered / out-of-order version is dropped
// (the feed never rewinds) and the cursor is unchanged — and that a RESTART resumes
// from the on-disk cursor rather than re-fanning history.
func TestFeedWriterForwardOnly(t *testing.T) {
	dir := t.TempDir()
	w := NewFeedWriter(dir)

	if _, err := w.WriteCommitted(snapAt(5, "v5")); err != nil {
		t.Fatalf("WriteCommitted(seq=5): %v", err)
	}
	// A re-delivered seq 5 (and an out-of-order seq 4) are dropped: ReasonNone (a
	// benign forward-only dedup, not a content defect) WITH a non-nil error.
	for _, seq := range []uint64{5, 4} {
		reason, err := w.WriteCommitted(snapAt(seq, "stale"))
		if err == nil {
			t.Fatalf("WriteCommitted(seq=%d) should be dropped forward-only (non-nil err)", seq)
		}
		if reason != ReasonNone {
			t.Fatalf("forward-only drop of seq %d reason = %v, want ReasonNone (benign dedup, not a schema/hash defect)", seq, reason)
		}
	}
	// The seq-5 file's bytes were NOT overwritten by the stale re-delivery, and the
	// cursor stayed at 5.
	got, err := os.ReadFile(filepath.Join(dir, "00000000000000000005.snapshot"))
	if err != nil {
		t.Fatalf("read seq-5 file: %v", err)
	}
	if string(got) != "v5" {
		t.Fatalf("seq-5 file bytes = %q, want the original \"v5\" (a stale re-delivery must not overwrite)", got)
	}
	if v, _ := readCursor(t, dir); v != 5 {
		t.Fatalf("cursor = %d, want 5 (unchanged by the dropped re-deliveries)", v)
	}

	// RESTART: a fresh writer over the SAME dir seeds its forward-only cursor from the
	// persisted applied_seq (5), so it drops a re-delivered seq 5 but accepts seq 6.
	w2 := NewFeedWriter(dir)
	if _, err := w2.WriteCommitted(snapAt(5, "replay")); err == nil {
		t.Fatal("a restarted writer must drop a re-delivered seq 5 (cursor resumed from disk)")
	}
	if _, err := w2.WriteCommitted(snapAt(6, "v6")); err != nil {
		t.Fatalf("a restarted writer must accept the forward seq 6: %v", err)
	}
	if v, _ := readCursor(t, dir); v != 6 {
		t.Fatalf("cursor after restart+seq6 = %d, want 6", v)
	}
}

// TestFeedWriterReasonSeparability proves the SchemaFailure-vs-ContentHashMismatch
// reason token the producer carries to heartbeat.go: a version with no transportable
// document is a SchemaFailure (not fanned out), and a torn carrier (content_hash that
// does not match its own bytes) is a ContentHashMismatch (not fanned out) — distinct
// tokens an operator can tell apart (doc 13 §5.1), neither writing a feed file.
func TestFeedWriterReasonSeparability(t *testing.T) {
	dir := t.TempDir()
	w := NewFeedWriter(dir)

	// SchemaFailure: empty document — no produce-once carrier to fan out.
	reason, err := w.WriteCommitted(&boundaryv1.PolicySnapshot{Seq: 7})
	if err == nil {
		t.Fatal("WriteCommitted with no document bytes must fail (schema failure)")
	}
	if reason != ReasonSchemaFailure {
		t.Fatalf("empty-document reason = %v, want ReasonSchemaFailure", reason)
	}
	if reason.String() != "schema_failure" {
		t.Fatalf("ReasonSchemaFailure token = %q, want the cross-language \"schema_failure\"", reason.String())
	}

	// ContentHashMismatch: present bytes, but a content_hash that does not match them
	// (a torn §5.1 identity tuple). The host stays on its prior fed version.
	torn := &boundaryv1.PolicySnapshot{
		Seq:         8,
		Document:    []byte("real-bytes"),
		ContentHash: []byte("not-the-hash-of-real-bytes-xxxxx"), // wrong, 32 bytes
	}
	reason, err = w.WriteCommitted(torn)
	if err == nil {
		t.Fatal("WriteCommitted with a mismatched content_hash must fail (content hash mismatch)")
	}
	if reason != ReasonContentHashMismatch {
		t.Fatalf("mismatched-hash reason = %v, want ReasonContentHashMismatch", reason)
	}
	if reason.String() != "content_hash_mismatch" {
		t.Fatalf("ReasonContentHashMismatch token = %q, want the cross-language \"content_hash_mismatch\"", reason.String())
	}
	// The two distinct reasons surface distinct operator Detail tokens (the
	// heartbeat.go free-text carrier, no proto enum widened).
	if d := ReasonSchemaFailure.DetailFor(7); d != "schema_failure at seq 7" {
		t.Fatalf("SchemaFailure DetailFor(7) = %q, want \"schema_failure at seq 7\"", d)
	}
	if d := ReasonContentHashMismatch.DetailFor(8); d != "content_hash_mismatch at seq 8" {
		t.Fatalf("ContentHashMismatch DetailFor(8) = %q, want \"content_hash_mismatch at seq 8\"", d)
	}
	if d := ReasonNone.DetailFor(9); d != "" {
		t.Fatalf("ReasonNone DetailFor(9) = %q, want empty (a clean version stamps no Detail)", d)
	}

	// Neither failing version was fanned out: the feed dir holds no version file and
	// no cursor (the host stayed on nothing — the §5 "no file => no snapshot" posture).
	if names := finalFeedFiles(t, dir); len(names) != 0 {
		t.Fatalf("a SchemaFailure / ContentHashMismatch must write NO feed file, got %v", names)
	}
	if _, present := readCursor(t, dir); present {
		t.Fatal("a failed fan-out must not advance the applied_seq cursor")
	}
}

// recordingFeedSweeper wraps the FeedWriter's Sweep with an eventLog "feedwrite"
// marker so the barrier test can assert the feed is written AFTER the admitter-last
// commit (the marker is appended just before the real fan-out runs).
type recordingFeedSweeper struct {
	log *eventLog
	w   *FeedWriter
}

func (r *recordingFeedSweeper) Sweep(ctx context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	r.log.record("feedwrite")
	return r.w.Sweep(ctx, snap)
}

// TestFeedWriterBehindCommitBarrier proves the load-bearing wiring invariant: when
// the FeedWriter is the ApplyCoordinator's POST-COMMIT sweeper, the feed is written
// ONLY after the admitter-LAST commit (ds-dnsgate commits last, THEN the feed file
// appears) — a version never reaches the on-disk feed before the host serves it.
func TestFeedWriterBehindCommitBarrier(t *testing.T) {
	dir := t.TempDir()
	log := &eventLog{}
	_, _, _, order := threeConsumers(log)
	w := NewFeedWriter(dir)
	coord, err := NewApplyCoordinator(order, &recordingFeedSweeper{log: log, w: w})
	if err != nil {
		t.Fatalf("NewApplyCoordinator with the feed writer sweeper: %v", err)
	}

	// Before any apply: the host has fanned out nothing.
	if names := finalFeedFiles(t, dir); len(names) != 0 {
		t.Fatalf("no apply yet, but the feed dir holds %v", names)
	}

	out, err := coord.Apply(context.Background(), snapAt(11, "committed-doc"))
	if err != nil {
		t.Fatalf("Apply(seq=11): %v", err)
	}
	if !out.Committed || !out.Swept {
		t.Fatalf("Apply outcome = %+v, want Committed && Swept", out)
	}
	if out.AppliedSeq != 11 {
		t.Fatalf("AppliedSeq = %d, want 11 (apply_seq advances post-fan-out)", out.AppliedSeq)
	}

	// The barrier proof: the "feedwrite" event comes AFTER the admitter-last commit
	// (commit:ds-dnsgate). The two enforcers + the admitter all commit BEFORE the feed
	// is written — the host is serving vN+1 by the time the file lands.
	events := log.snapshot()
	dnsCommit := firstIndexOf(events, "commit:"+BoundaryDNSGate)
	feedWrite := firstIndexOf(events, "feedwrite")
	if dnsCommit < 0 || feedWrite < 0 {
		t.Fatalf("missing barrier events in %v (want commit:%s and feedwrite)", events, BoundaryDNSGate)
	}
	if feedWrite < dnsCommit {
		t.Fatalf("feed written BEFORE the admitter-last commit (feedwrite@%d < commit:ds-dnsgate@%d) in %v — violates the prepare/commit barrier", feedWrite, dnsCommit, events)
	}
	// And every commit precedes the feed write (no consumer flips after the feed lands).
	for _, name := range []string{BoundaryTLSProxy, BoundaryNFTWriter, BoundaryDNSGate} {
		if c := firstIndexOf(events, "commit:"+name); c < 0 || c > feedWrite {
			t.Fatalf("commit:%s did not precede the feed write in %v", name, events)
		}
	}

	// The committed version is now on disk in the cross-process shape the consumer
	// drains: "<seq:020>.snapshot" + the advanced cursor.
	names := finalFeedFiles(t, dir)
	if len(names) != 1 || names[0] != "00000000000000000011.snapshot" {
		t.Fatalf("post-apply feed files = %v, want [00000000000000000011.snapshot]", names)
	}
	if v, _ := readCursor(t, dir); v != 11 {
		t.Fatalf("post-apply cursor = %d, want 11", v)
	}
}

// TestSweeperChainPostCommit proves the SweeperChain composition: a revocation
// sweeper runs BEFORE the feed writer (so the host is swept onto vN+1 before the feed
// is fanned out), and both run post-commit in one coordinator hook.
func TestSweeperChainPostCommit(t *testing.T) {
	dir := t.TempDir()
	log := &eventLog{}
	_, _, _, order := threeConsumers(log)
	w := NewFeedWriter(dir)

	chain := SweeperChain{
		&fakeSweeper{log: log},                // the revocation sweep (records "sweep")
		&recordingFeedSweeper{log: log, w: w}, // the feed fan-out (records "feedwrite")
	}
	coord, err := NewApplyCoordinator(order, chain)
	if err != nil {
		t.Fatalf("NewApplyCoordinator with the sweeper chain: %v", err)
	}

	out, err := coord.Apply(context.Background(), snapAt(13, "doc"))
	if err != nil {
		t.Fatalf("Apply(seq=13): %v", err)
	}
	if out.AppliedSeq != 13 || !out.Swept {
		t.Fatalf("Apply outcome = %+v, want AppliedSeq=13 Swept", out)
	}

	events := log.snapshot()
	sweep := firstIndexOf(events, "sweep")
	feedWrite := firstIndexOf(events, "feedwrite")
	dnsCommit := firstIndexOf(events, "commit:"+BoundaryDNSGate)
	if sweep < 0 || feedWrite < 0 || dnsCommit < 0 {
		t.Fatalf("missing chain events in %v", events)
	}
	if !(dnsCommit < sweep && sweep < feedWrite) {
		t.Fatalf("chain order = commit:ds-dnsgate@%d, sweep@%d, feedwrite@%d in %v; want commit < sweep < feedwrite", dnsCommit, sweep, feedWrite, events)
	}
	if names := finalFeedFiles(t, dir); len(names) != 1 || names[0] != "00000000000000000013.snapshot" {
		t.Fatalf("feed files = %v, want [00000000000000000013.snapshot]", names)
	}
}

// TestParseHostAgentFeedEndpoint proves the producer mirror of the dataplane
// consumer's parse_carrier_endpoint (ds-dnsgate/src/main.rs): a "uds:<path>" value
// selects the live carrier at <path>; a bare "uds:" selects DefaultHostAgentFeedSock;
// ANY other value (unset, "1", a directory path) selects the file feed (live=false).
func TestParseHostAgentFeedEndpoint(t *testing.T) {
	cases := []struct {
		value    string
		wantEP   string
		wantLive bool
	}{
		{"", "", false},  // unset → file feed
		{"1", "", false}, // bare-set → file feed
		{"/run/ds-dnsgate/policy-feed", "", false},         // a dir path → file feed
		{"uds:", DefaultHostAgentFeedSock, true},           // bare uds: → default sock
		{"uds:/tmp/custom.sock", "/tmp/custom.sock", true}, // explicit path
	}
	for _, tc := range cases {
		ep, live := parseHostAgentFeedEndpoint(tc.value)
		if live != tc.wantLive || ep != tc.wantEP {
			t.Fatalf("parseHostAgentFeedEndpoint(%q) = (%q, %v), want (%q, %v)", tc.value, ep, live, tc.wantEP, tc.wantLive)
		}
	}
}

// TestBindFeedProducersGateOffIsFileFeedOnly proves the DEFAULT-OFF launch path: with
// DS_DNSGATE_HOST_AGENT_FEED unset (or a non-"uds:" value) BindFeedProducers binds ONLY
// the file feed — no live carrier, and Start is a no-op that touches no socket and
// spawns no serve loop (the gate-unset daemon is byte-identical to before producer-bind).
func TestBindFeedProducersGateOffIsFileFeedOnly(t *testing.T) {
	for _, gate := range []string{"", "1", "/run/ds-dnsgate/policy-feed"} {
		t.Run("gate="+gate, func(t *testing.T) {
			t.Setenv(hostAgentFeedEnv, gate)
			if gate == "" {
				os.Unsetenv(hostAgentFeedEnv) // model truly-unset (t.Setenv with "" still sets it)
			}
			dir := t.TempDir()
			fp := BindFeedProducers(dir, nil)
			if fp.LiveCarrier() {
				t.Fatalf("gate %q must NOT select the live carrier", gate)
			}
			if ep := fp.CarrierEndpoint(); ep != "" {
				t.Fatalf("gate %q carrier endpoint = %q, want empty (no live carrier)", gate, ep)
			}
			if fp.FeedDir() != dir {
				t.Fatalf("FeedDir() = %q, want %q", fp.FeedDir(), dir)
			}

			// Start is a no-op on the file-only path: a nil channel, no error, no socket.
			done, err := fp.Start(context.Background())
			if err != nil {
				t.Fatalf("Start on the gate-off path must not error: %v", err)
			}
			if done != nil {
				t.Fatal("Start on the gate-off path must return a nil channel (no serve loop)")
			}

			// The composed Sweeper still fans the version to the FILE feed behind the barrier
			// — byte-identical to the pre-producer-bind newFeedWritingApplyCoordinator path.
			_, _, _, order := threeConsumers(&eventLog{})
			coord, err := NewApplyCoordinator(order, fp.Sweeper())
			if err != nil {
				t.Fatalf("NewApplyCoordinator with the gate-off sweeper: %v", err)
			}
			out, err := coord.Apply(context.Background(), snapAt(4, "doc"))
			if err != nil || !out.Committed || !out.Swept || out.AppliedSeq != 4 {
				t.Fatalf("Apply outcome = %+v err=%v, want Committed&&Swept AppliedSeq=4", out, err)
			}
			names := finalFeedFiles(t, dir)
			if len(names) != 1 || names[0] != "00000000000000000004.snapshot" {
				t.Fatalf("file feed = %v, want [00000000000000000004.snapshot]", names)
			}
		})
	}
}

// TestBindFeedProducersGateOffWithRevocationComposesChain proves a wired revocation
// Sweeper is composed FIRST in the chain (the host is swept onto vN+1 BEFORE the file
// feed fans out, D72) even on the gate-off path.
func TestBindFeedProducersGateOffWithRevocationComposesChain(t *testing.T) {
	os.Unsetenv(hostAgentFeedEnv)
	dir := t.TempDir()
	log := &eventLog{}
	revoc := &fakeSweeper{log: log}
	fp := BindFeedProducers(dir, revoc)

	_, _, _, order := threeConsumers(log)
	coord, err := NewApplyCoordinator(order, fp.Sweeper())
	if err != nil {
		t.Fatalf("NewApplyCoordinator: %v", err)
	}
	if _, err := coord.Apply(context.Background(), snapAt(5, "doc")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if revoc.sweepCount() != 1 {
		t.Fatalf("revocation sweep ran %d times, want 1", revoc.sweepCount())
	}
	// The revocation sweep precedes the file fan-out (the file appeared, so the chain ran
	// the writer too, but only AFTER the revocation sweep — the SweeperChain order).
	events := log.snapshot()
	sweep := firstIndexOf(events, "sweep")
	dnsCommit := firstIndexOf(events, "commit:"+BoundaryDNSGate)
	if sweep < 0 || dnsCommit < 0 || !(dnsCommit < sweep) {
		t.Fatalf("revocation sweep must run post-commit, after commit:ds-dnsgate, in %v", events)
	}
	if v, _ := readCursor(t, dir); v != 5 {
		t.Fatalf("file feed cursor = %d, want 5 (the writer fanned out after the revocation sweep)", v)
	}
}

// TestBindFeedProducersLiveCarrierServesOverUDS proves the "uds:" gate brings up the
// live WatchPolicies carrier: BindFeedProducers selects it, composes it into the chain
// AFTER the file feed, and Start serves a real UDS a dialing consumer reads the
// forward-only frame stream off. The cross-process LIVE dial (a running ds-dnsgate) is
// the DEFERRED-MANUAL step; this drives the producer in-process over a real UDS with a
// hand-decoded reader mirroring the Rust consumer's frame codec.
func TestBindFeedProducersLiveCarrierServesOverUDS(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "watch.sock")
	t.Setenv(hostAgentFeedEnv, "uds:"+sock)

	fp := BindFeedProducers(dir, nil)
	if !fp.LiveCarrier() {
		t.Fatal("the uds: gate must select the live carrier")
	}
	if ep := fp.CarrierEndpoint(); ep != sock {
		t.Fatalf("CarrierEndpoint() = %q, want %q", ep, sock)
	}

	// Drive a committed apply through the composed chain: the file feed AND the live
	// carrier both buffer the version behind the commit barrier.
	_, _, _, order := threeConsumers(&eventLog{})
	coord, err := NewApplyCoordinator(order, fp.Sweeper())
	if err != nil {
		t.Fatalf("NewApplyCoordinator: %v", err)
	}
	for _, seq := range []uint64{1, 2, 3} {
		if _, err := coord.Apply(context.Background(), snapAt(seq, carrierDoc)); err != nil {
			t.Fatalf("Apply(seq=%d): %v", seq, err)
		}
	}
	// The file feed advanced (the writer is bound on the live path too).
	if v, _ := readCursor(t, dir); v != 3 {
		t.Fatalf("file feed cursor on the live path = %d, want 3", v)
	}

	// Start the live serve loop and read the forward-only stream off the UDS.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, err := fp.Start(ctx)
	if err != nil {
		t.Fatalf("Start the live carrier: %v", err)
	}
	if done == nil {
		t.Fatal("Start on the live path must return a serve-loop error channel")
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial the live carrier UDS: %v", err)
	}
	defer conn.Close()

	var fromSeq [8]byte
	binary.BigEndian.PutUint64(fromSeq[:], 1) // from_seq=1 → consumer sees seq 2, 3 only
	if err := writeWatchFrame(conn, fromSeq[:]); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	for _, wantSeq := range []uint64{2, 3} {
		body, err := readCarrierFrame(t, conn)
		if err != nil {
			t.Fatalf("read frame for seq %d: %v", wantSeq, err)
		}
		seq, _, doc := decodeCarrierVersion(t, body)
		if seq != wantSeq || string(doc) != carrierDoc {
			t.Fatalf("frame = (seq %d, doc %q), want (%d, the produce-once carrierDoc)", seq, doc, wantSeq)
		}
	}
	if _, err := readCarrierFrame(t, conn); err != io.EOF {
		t.Fatalf("after the forward-only replay the producer must EOF; got %v", err)
	}

	// Clean shutdown: ctx-cancel closes the listener; Serve returns context.Canceled.
	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatalf("the carrier serve loop returned a non-shutdown error: %v", err)
	}
}

// TestBindFeedProducersWithNftProgrammer proves the nft-writer fan-out leg is composed
// into the chain ONLY behind the "uds:" gate AND only when a real transport is wired:
// off the gate WithNftProgrammer is a no-op (the chain stays free of the nft leg,
// byte-identical), on the gate it appends the nftFeedSweeper so a committed apply drives
// the ds-nft live ingest post-commit.
func TestBindFeedProducersWithNftProgrammer(t *testing.T) {
	t.Run("GateOffIsNoOp", func(t *testing.T) {
		os.Unsetenv(hostAgentFeedEnv)
		prog := &fakeNftProgrammer{}
		fp, err := BindFeedProducers(t.TempDir(), nil).WithNftProgrammer(prog)
		if err != nil {
			t.Fatalf("WithNftProgrammer off the gate must not error: %v", err)
		}
		_, _, _, order := threeConsumers(&eventLog{})
		coord, _ := NewApplyCoordinator(order, fp.Sweeper())
		if _, err := coord.Apply(context.Background(), snapAt(6, "doc")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if prog.prepareN != 0 {
			t.Fatalf("off the gate the nft leg must NOT run (prepareN=%d)", prog.prepareN)
		}
	})

	t.Run("GateOnDrivesTheNftFanOutPostCommit", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv(hostAgentFeedEnv, "uds:"+filepath.Join(dir, "watch.sock"))
		prog := &fakeNftProgrammer{}
		fp, err := BindFeedProducers(dir, nil).WithNftProgrammer(prog)
		if err != nil {
			t.Fatalf("WithNftProgrammer on the gate: %v", err)
		}
		_, _, _, order := threeConsumers(&eventLog{})
		coord, err := NewApplyCoordinator(order, fp.Sweeper())
		if err != nil {
			t.Fatalf("NewApplyCoordinator: %v", err)
		}
		out, err := coord.Apply(context.Background(), snapAt(7, carrierDoc))
		if err != nil || !out.Committed || out.AppliedSeq != 7 {
			t.Fatalf("Apply outcome = %+v err=%v, want Committed AppliedSeq=7", out, err)
		}
		if prog.prepareN != 1 || prog.commitN != 1 {
			t.Fatalf("the nft fan-out must drive Prepare→Commit once post-commit (prepareN=%d commitN=%d)", prog.prepareN, prog.commitN)
		}
		// The fan-out threaded the producer-pinned hash for the committed seq.
		if prog.gotSeq != 7 {
			t.Fatalf("nft fan-out threaded seq %d, want 7", prog.gotSeq)
		}
	})

	t.Run("GateOnNilProgrammerIsNoOp", func(t *testing.T) {
		t.Setenv(hostAgentFeedEnv, "uds:")
		fp, err := BindFeedProducers(t.TempDir(), nil).WithNftProgrammer(nil)
		if err != nil {
			t.Fatalf("WithNftProgrammer(nil) must be a no-op, not an error: %v", err)
		}
		if fp.nftSweeper != nil {
			t.Fatal("a nil programmer must not add an nft leg")
		}
	})
}

// TestBindFeedProducersWarmRestartDegradesToFileFeed proves the WARM-RESTART guard
// (the scope's deterministic-fallback deliverable): a restarted host agent's LIVE
// carrier comes up with an EMPTY in-memory replay buffer (the buffer is process-local
// — only the file feed is durable, dnsfeed_carrier.go REPLAY semantics), so a dialing
// consumer that resumes from a LOW from_seq (below the versions committed BEFORE the
// restart) must NOT hang or fault: the carrier EOFs IMMEDIATELY (an empty buffer => the
// §5.3 exhausted stream), and the consumer DETERMINISTICALLY resumes from the
// co-located file feed — which is ALWAYS bound on the live path (composed before the
// carrier in the chain) and persisted every version's bytes + applied_seq cursor to
// disk across the restart. This is the "degrade to the file feed rather than silently
// fail" invariant: the two transports share the same applied_seq cursor, so the file
// feed is the durable resume point a warm-restarted carrier falls back to.
func TestBindFeedProducersWarmRestartDegradesToFileFeed(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "watch.sock")
	t.Setenv(hostAgentFeedEnv, "uds:"+sock)

	// ── PRE-RESTART: the original host agent fans three committed versions out. The
	// file feed persists each version's bytes + the applied_seq cursor to disk; the
	// carrier buffers them in memory.
	{
		fp := BindFeedProducers(dir, nil)
		if !fp.LiveCarrier() {
			t.Fatal("the uds: gate must select the live carrier")
		}
		_, _, _, order := threeConsumers(&eventLog{})
		coord, err := NewApplyCoordinator(order, fp.Sweeper())
		if err != nil {
			t.Fatalf("NewApplyCoordinator (pre-restart): %v", err)
		}
		for _, seq := range []uint64{1, 2, 3} {
			if _, err := coord.Apply(context.Background(), snapAt(seq, carrierDoc)); err != nil {
				t.Fatalf("pre-restart Apply(seq=%d): %v", seq, err)
			}
		}
		// The DURABLE file feed retains all three versions + the cursor at 3.
		if v, _ := readCursor(t, dir); v != 3 {
			t.Fatalf("pre-restart file feed cursor = %d, want 3", v)
		}
		if names := finalFeedFiles(t, dir); len(names) != 3 {
			t.Fatalf("pre-restart file feed should hold 3 durable version files, got %v", names)
		}
	}

	// ── RESTART: a FRESH producer set over the SAME dir. The new carrier's in-memory
	// replay buffer is EMPTY (the buffer never persists — only the file feed does); the
	// file feed's FeedWriter resumes its forward-only cursor from the on-disk applied_seq
	// (3) so it never re-fans history.
	fp := BindFeedProducers(dir, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, err := fp.Start(ctx)
	if err != nil {
		t.Fatalf("Start the warm-restarted carrier: %v", err)
	}
	if done == nil {
		t.Fatal("Start on the live path must return a serve-loop error channel")
	}

	// A consumer dials the restarted carrier and resumes from a LOW from_seq=0 (it last
	// saw nothing, or saw a version below the restarted buffer's empty floor). The
	// carrier must EOF IMMEDIATELY — an empty buffer yields NO version frames, never a
	// hang or a fault — so the consumer reads the stream as exhausted and falls back to
	// the durable file feed (deterministic degrade, not a silent failure).
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial the warm-restarted carrier UDS: %v", err)
	}
	defer conn.Close()
	var fromSeq [8]byte
	binary.BigEndian.PutUint64(fromSeq[:], 0) // resume from the bottom: the empty buffer has nothing past 0
	if err := writeWatchFrame(conn, fromSeq[:]); err != nil {
		t.Fatalf("write warm-restart handshake: %v", err)
	}
	if _, err := readCarrierFrame(t, conn); err != io.EOF {
		t.Fatalf("a warm-restarted carrier with an empty buffer must EOF immediately on a low from_seq (deterministic file-feed fallback); got %v", err)
	}

	// The DETERMINISTIC fallback target: the co-located file feed still holds all three
	// pre-restart versions + the cursor at 3, the durable resume point the consumer
	// drains instead. The warm restart degraded to the file feed — it did NOT silently
	// drop the versions the empty carrier buffer could not replay.
	if v, _ := readCursor(t, dir); v != 3 {
		t.Fatalf("post-restart file feed cursor = %d, want 3 (the durable fallback resume point)", v)
	}
	names := finalFeedFiles(t, dir)
	want := []string{
		"00000000000000000001.snapshot",
		"00000000000000000002.snapshot",
		"00000000000000000003.snapshot",
	}
	if len(names) != 3 || names[0] != want[0] || names[1] != want[1] || names[2] != want[2] {
		t.Fatalf("post-restart file feed = %v, want the 3 durable versions %v (the warm-restart fallback)", names, want)
	}

	// A NEW committed version after the restart buffers in the now-live carrier AND
	// appends to the file feed forward-only from the resumed cursor (4, not a re-fan of
	// 1..3) — proving the restarted producer set resumes cleanly rather than replaying.
	_, _, _, order := threeConsumers(&eventLog{})
	coord, err := NewApplyCoordinator(order, fp.Sweeper())
	if err != nil {
		t.Fatalf("NewApplyCoordinator (post-restart): %v", err)
	}
	if _, err := coord.Apply(context.Background(), snapAt(4, carrierDoc)); err != nil {
		t.Fatalf("post-restart Apply(seq=4): %v", err)
	}
	// The restarted carrier now replays the POST-restart version to a fresh dial past
	// from_seq=3 (the buffer is no longer empty for the new version), while the file feed
	// advanced to 4 without re-fanning 1..3.
	if v, _ := readCursor(t, dir); v != 4 {
		t.Fatalf("post-restart+seq4 file feed cursor = %d, want 4 (forward-only resume, no re-fan)", v)
	}
	conn2, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial the carrier after the post-restart commit: %v", err)
	}
	defer conn2.Close()
	binary.BigEndian.PutUint64(fromSeq[:], 3) // resume past the pre-restart history
	if err := writeWatchFrame(conn2, fromSeq[:]); err != nil {
		t.Fatalf("write post-restart handshake: %v", err)
	}
	body, err := readCarrierFrame(t, conn2)
	if err != nil {
		t.Fatalf("read the post-restart version frame: %v", err)
	}
	if seq, _, doc := decodeCarrierVersion(t, body); seq != 4 || string(doc) != carrierDoc {
		t.Fatalf("post-restart carrier frame = (seq %d, doc %q), want (4, the produce-once carrierDoc)", seq, doc)
	}
	if _, err := readCarrierFrame(t, conn2); err != io.EOF {
		t.Fatalf("the carrier must EOF after replaying the single post-restart version; got %v", err)
	}

	// Clean shutdown.
	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatalf("the warm-restart carrier serve loop returned a non-shutdown error: %v", err)
	}
}
