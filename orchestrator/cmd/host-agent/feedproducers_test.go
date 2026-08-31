// SPDX-License-Identifier: Apache-2.0

package main

// feedproducers_test.go pins the daemon's POL-4 fan-out producer wiring
// (buildFeedProducers, policy.go) + the production ApplyCoordinator that drives it
// (newFeedWritingApplyCoordinator, main.go): the REAL vN→vN+1 RevocationProducer +
// BindFeedProducers composed behind DS_DNSGATE_HOST_AGENT_FEED / DS_REVOCATION_FEED_LIVE,
// with the DEFAULT-OFF launch byte-identical to the prior bare-FeedWriter sweeper.
//
// There is no live claude/cia/qemu/podman here — the producers are bound + the coordinator
// driven entirely in-process over a temp feed directory, the way the internal/hostagent
// producer tests are built. The live carrier UDS bind + the cross-process revocation dial
// are the deferred-manual legs an operator runs against a running dataplane consumer.

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// snapAt builds a committed PolicySnapshot at seq with the given document bytes + the
// SHA-256 over them (the §5.1 identity tuple the snapshot store already verified, so the
// feed writer's internal hash guard is consistent and never fires on the happy path).
func snapAt(seq uint64, document string) *boundaryv1.PolicySnapshot {
	sum := sha256.Sum256([]byte(document))
	return &boundaryv1.PolicySnapshot{Seq: seq, Document: []byte(document), ContentHash: sum[:]}
}

// unsetGate removes a PRESENCE-ONLY env gate (e.g. DS_REVOCATION_FEED_LIVE — armed iff the
// var EXISTS, value ignored) for the duration of a test, restoring the prior value on
// cleanup. t.Setenv(key, "") would make the var PRESENT (== armed) — the wrong thing for the
// default-OFF path — so the gates that read os.LookupEnv must be truly ABSENT.
func unsetGate(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// TestBuildFeedProducersDefaultOffBindsOnlyFileFeed pins the default-OFF posture: with
// BOTH fan-out gates unset (every default / CI / unit-test path) buildFeedProducers binds
// EXACTLY the on-disk file feed — no live carrier (LiveCarrier false), no carrier endpoint —
// so the chain the coordinator sweeps is behaviorally identical to the prior bare FeedWriter.
func TestBuildFeedProducersDefaultOffBindsOnlyFileFeed(t *testing.T) {
	t.Setenv("DS_DNSGATE_HOST_AGENT_FEED", "") // carrier gate OFF (value-based: "" != "uds:")
	unsetGate(t, "DS_REVOCATION_FEED_LIVE")    // revocation gate OFF (presence-only: must be ABSENT)

	dir := t.TempDir()
	fp, err := buildFeedProducers(dir)
	if err != nil {
		t.Fatalf("buildFeedProducers: %v", err)
	}
	if fp.LiveCarrier() {
		t.Error("default-OFF must NOT select the live WatchPolicies carrier")
	}
	if fp.CarrierEndpoint() != "" {
		t.Errorf("default-OFF carrier endpoint = %q, want empty", fp.CarrierEndpoint())
	}
	if fp.FeedDir() != dir {
		t.Errorf("FeedDir = %q, want %q", fp.FeedDir(), dir)
	}
	// Start is a clean no-op off the "uds:" gate — no socket bound, a nil channel returned.
	ch, err := fp.Start(context.Background())
	if err != nil {
		t.Fatalf("default-OFF Start must be a no-op, got err: %v", err)
	}
	if ch != nil {
		t.Error("default-OFF Start must return a nil channel (no serve loop spawned)")
	}
}

// TestBuildFeedProducersRevocationGateArmsTheLeg proves DS_REVOCATION_FEED_LIVE arms the
// REAL revocation producer leg: the producers still bind (construction succeeds — the diff
// engine over the deferred decoder is reachable + fail-closed), and the carrier stays unset
// (the revocation gate is independent of the "uds:" carrier gate).
func TestBuildFeedProducersRevocationGateArmsTheLeg(t *testing.T) {
	t.Setenv("DS_DNSGATE_HOST_AGENT_FEED", "") // carrier gate still OFF
	t.Setenv("DS_REVOCATION_FEED_LIVE", "1")   // revocation gate ON (presence-only)

	fp, err := buildFeedProducers(t.TempDir())
	if err != nil {
		t.Fatalf("buildFeedProducers (revocation armed): %v", err)
	}
	if !hostagent.RevocationFeedLiveEnabled() {
		t.Fatal("DS_REVOCATION_FEED_LIVE set but RevocationFeedLiveEnabled() is false")
	}
	if fp.LiveCarrier() {
		t.Error("the revocation gate must NOT select the live carrier (independent gates)")
	}
}

// TestBuildFeedProducersCarrierGateSelectsLiveCarrier proves DS_DNSGATE_HOST_AGENT_FEED
// ="uds:<path>" selects the live WatchPolicies carrier at the named endpoint, and that a
// bind+serve via Start brings up + cleanly drains the serve loop (the in-process proof of
// the live carrier leg; the cross-process consumer dial is the deferred-manual step).
func TestBuildFeedProducersCarrierGateSelectsLiveCarrier(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "watch.sock")
	t.Setenv("DS_DNSGATE_HOST_AGENT_FEED", "uds:"+sock)
	unsetGate(t, "DS_REVOCATION_FEED_LIVE")

	fp, err := buildFeedProducers(t.TempDir())
	if err != nil {
		t.Fatalf("buildFeedProducers (carrier live): %v", err)
	}
	if !fp.LiveCarrier() {
		t.Fatal("DS_DNSGATE_HOST_AGENT_FEED=uds: must select the live carrier")
	}
	if fp.CarrierEndpoint() != sock {
		t.Errorf("carrier endpoint = %q, want %q", fp.CarrierEndpoint(), sock)
	}

	// Start binds the UDS + serves on a goroutine; a cancelled ctx drains it cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := fp.Start(ctx)
	if err != nil {
		t.Fatalf("Start live carrier: %v", err)
	}
	if ch == nil {
		t.Fatal("live carrier Start must return a non-nil serve-result channel")
	}
	if _, err := os.Stat(sock); err != nil {
		t.Errorf("live carrier did not bind its UDS at %q: %v", sock, err)
	}
	cancel()
	<-ch // the serve loop drained on the cancelled ctx (a clean context.Canceled / nil)
}

// TestProductionCoordinatorDefaultOffDrivesFeedBehindCommitBarrier is the byte-identical
// acceptance: the production newFeedWritingApplyCoordinator (default-OFF, both gates unset)
// fans each committed version out to the on-disk feed EXACTLY behind the prepare/commit
// barrier — a version reaches the "<seq:020>.snapshot" file + the applied_seq cursor only
// after the admitter-LAST commit, identical to the prior bare-FeedWriter sweeper. It drives
// the SAME ApplyCoordinator the daemon wires (cfg.feedProducers nil → the builder binds the
// gate-aware default).
func TestProductionCoordinatorDefaultOffDrivesFeedBehindCommitBarrier(t *testing.T) {
	t.Setenv("DS_DNSGATE_HOST_AGENT_FEED", "") // value-based carrier gate OFF
	unsetGate(t, "DS_REVOCATION_FEED_LIVE")    // presence-only revocation gate OFF (must be ABSENT)

	dir := t.TempDir()
	cfg := defaultTestConfig()
	cfg.feedDir = dir
	// cfg.feedProducers nil → newFeedWritingApplyCoordinator builds the gate-aware default
	// (EXACTLY [FeedWriter] off the gates), the byte-identical posture.
	coord, fp, err := newFeedWritingApplyCoordinator(cfg)
	if err != nil {
		t.Fatalf("newFeedWritingApplyCoordinator: %v", err)
	}
	if fp.LiveCarrier() {
		t.Fatal("default-OFF production coordinator must not bind a live carrier")
	}

	// Before any apply the feed dir holds no version file and no cursor.
	if files := snapshotFiles(t, dir); len(files) != 0 {
		t.Fatalf("feed dir non-empty before any apply: %v", files)
	}

	// Drive one committed apply through the production coordinator (the offline barriers
	// commit no-op, then the post-commit sweeper — the file feed — fans the version out).
	out, err := coord.Apply(context.Background(), snapAt(11, "doc-v11"))
	if err != nil {
		t.Fatalf("Apply(seq=11): %v", err)
	}
	if !out.Committed {
		t.Fatal("apply did not commit (the offline barriers must all commit)")
	}
	if out.AppliedSeq != 11 {
		t.Errorf("applied seq = %d, want 11 (apply_seq advances post-fan-out)", out.AppliedSeq)
	}

	// The version reached the on-disk feed (the cross-process file the dataplane consumer
	// reads) — proving the feed is written behind the commit barrier on the default path.
	files := snapshotFiles(t, dir)
	if len(files) != 1 {
		t.Fatalf("after commit: %d snapshot files, want 1 (%v)", len(files), files)
	}
	const wantName = "00000000000000000011.snapshot" // seq 11 zero-padded to 20 digits
	if files[0] != wantName {
		t.Errorf("snapshot file = %q, want %q", files[0], wantName)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "applied_seq"))
	if err != nil {
		t.Fatalf("read applied_seq cursor: %v", err)
	}
	if strings.TrimSpace(string(raw)) != "11" {
		t.Errorf("applied_seq cursor = %q, want 11", strings.TrimSpace(string(raw)))
	}
}

// ── reason-routing: the FeedWriter drop reason → heartbeat ServiceHealth.Detail ──

// TestReasonRoutingSurfacesDropReasonOnHeartbeatDetail proves the reason-routing seam
// (part 1): a FeedWriter that withholds a version (SchemaFailure / ContentHashMismatch)
// records its SnapshotReason onto the shared reasonTracker, and coordStateSource.Snapshot
// stamps DetailFor(seq) onto the fed consumer's (BoundaryDNSGate) ServiceHealth.Detail in
// the emitted BuildHeartbeat — while a clean version CLEARS any stale token. The health
// STATE stays HEALTHY throughout (the Detail is a diagnostic, not a state transition), and
// no proto enum is widened (the token rides the free-text Detail).
func TestReasonRoutingSurfacesDropReasonOnHeartbeatDetail(t *testing.T) {
	t.Setenv("DS_DNSGATE_HOST_AGENT_FEED", "") // carrier gate OFF (file feed only)
	unsetGate(t, "DS_REVOCATION_FEED_LIVE")    // revocation gate OFF

	dir := t.TempDir()
	fp, err := buildFeedProducers(dir)
	if err != nil {
		t.Fatalf("buildFeedProducers: %v", err)
	}
	reasons := newReasonTracker()
	fp.SetReasonHook(reasons.Record)

	coord, err := newFeedWritingApplyCoordinatorFor(fp)
	if err != nil {
		t.Fatalf("build coordinator: %v", err)
	}
	src := &coordStateSource{hostID: "host-reason", coord: coord, reasons: reasons}

	// Detail is a helper: the ServiceHealth.Detail for a named consumer on the current beat.
	detailOf := func(name string) (*hostagentv1.ServiceHealth, string) {
		t.Helper()
		st, err := src.Snapshot(context.Background())
		if err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		hb := hostagent.BuildHeartbeat(st)
		for _, sh := range hb.GetBoundary() {
			if sh.GetName() == name {
				return sh, sh.GetDetail()
			}
		}
		t.Fatalf("consumer %q absent from the heartbeat boundary list", name)
		return nil, ""
	}

	// Before any apply: every Detail is empty (no reason recorded), the prior behavior.
	if _, d := detailOf(hostagent.BoundaryDNSGate); d != "" {
		t.Fatalf("pre-apply Detail = %q, want empty", d)
	}

	// A SchemaFailure version (empty document) is WITHHELD: the writer records
	// ReasonSchemaFailure at its seq. Sweep returns an error (the coordinator would HOLD
	// apply_seq), but the reason is still routed host-ward via the hook.
	if _, err := fp.Sweeper().Sweep(context.Background(), snapAt(4, "")); err == nil {
		t.Fatal("a SchemaFailure (empty document) must be withheld with an error")
	}
	sh, d := detailOf(hostagent.BoundaryDNSGate)
	if want := "schema_failure at seq 4"; d != want {
		t.Fatalf("after SchemaFailure: ds-dnsgate Detail = %q, want %q", d, want)
	}
	if sh.GetState() != hostagentv1.HealthState_HEALTH_STATE_HEALTHY {
		t.Fatalf("reason routing must NOT change the health state; got %v, want HEALTHY", sh.GetState())
	}

	// A ContentHashMismatch version (a present-but-wrong content_hash) is WITHHELD too:
	// last-writer-wins, the Detail now carries the content_hash_mismatch token.
	torn := &boundaryv1.PolicySnapshot{Seq: 5, Document: []byte("real-doc"), ContentHash: []byte("not-the-hash-of-real-doc-000000")}
	if _, err := fp.Sweeper().Sweep(context.Background(), torn); err == nil {
		t.Fatal("a ContentHashMismatch (torn carrier) must be withheld with an error")
	}
	if _, d := detailOf(hostagent.BoundaryDNSGate); d != "content_hash_mismatch at seq 5" {
		t.Fatalf("after ContentHashMismatch: Detail = %q, want %q", d, "content_hash_mismatch at seq 5")
	}

	// A CLEAN version fans out and records ReasonNone → the stale token is CLEARED (empty).
	if _, err := fp.Sweeper().Sweep(context.Background(), snapAt(6, "clean-doc")); err != nil {
		t.Fatalf("clean version must fan out: %v", err)
	}
	if _, d := detailOf(hostagent.BoundaryDNSGate); d != "" {
		t.Fatalf("after a clean apply, the stale Detail token must CLEAR; got %q, want empty", d)
	}

	// The OTHER two consumers were never fed by the file writer (the file feed attributes to
	// BoundaryDNSGate), so their Detail stays empty throughout — reason routing is per-consumer.
	if _, d := detailOf(hostagent.BoundaryTLSProxy); d != "" {
		t.Fatalf("ds-tlsproxy Detail = %q, want empty (never a fed-consumer reason)", d)
	}
}

// TestNilReasonTrackerLeavesDetailEmpty pins the nil-safe default: a coordStateSource
// with no reason tracker (the offline / smoke path) emits every ServiceHealth.Detail
// empty — the pre-reason-routing behavior, byte-identical.
func TestNilReasonTrackerLeavesDetailEmpty(t *testing.T) {
	t.Setenv("DS_DNSGATE_HOST_AGENT_FEED", "")
	unsetGate(t, "DS_REVOCATION_FEED_LIVE")

	fp, err := buildFeedProducers(t.TempDir())
	if err != nil {
		t.Fatalf("buildFeedProducers: %v", err)
	}
	coord, err := newFeedWritingApplyCoordinatorFor(fp)
	if err != nil {
		t.Fatalf("build coordinator: %v", err)
	}
	src := &coordStateSource{hostID: "host-nil-reasons", coord: coord} // reasons nil
	st, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	for _, sh := range hostagent.BuildHeartbeat(st).GetBoundary() {
		if sh.GetDetail() != "" {
			t.Fatalf("nil-tracker consumer %q Detail = %q, want empty", sh.GetName(), sh.GetDetail())
		}
	}
}

// ── SweeperChain: revocation BEFORE the feed fan-out, apply_seq post-sweep (part 2) ──

// recordingRevocationSweeper is an in-memory revocation Sweeper (the gate-aware/offline
// stand-in the daemon composes ahead of the feed) that records the ORDER it ran in a
// shared slice so a test can assert it swept BEFORE the feed fan-out. It returns the
// committed seq (a real revocation sweep advances the host onto vN+1 before fan-out).
type recordingRevocationSweeper struct {
	order *[]string
}

func (s *recordingRevocationSweeper) Sweep(_ context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	*s.order = append(*s.order, "revocation")
	return snap.GetSeq(), nil
}

// TestSweeperChainRevocationBeforeFanout proves part 2 at the daemon composition level:
// BindFeedProducers composes the revocation sweep FIRST, so driving the bound
// coordinator's chain runs revocation BEFORE the file feed fan-out, and apply_seq
// advances ONLY post-sweep (the feed file appears after the revocation leg ran).
func TestSweeperChainRevocationBeforeFanout(t *testing.T) {
	t.Setenv("DS_DNSGATE_HOST_AGENT_FEED", "") // carrier gate OFF
	unsetGate(t, "DS_REVOCATION_FEED_LIVE")    // presence-only revocation gate OFF (the real leg is offline)

	dir := t.TempDir()
	var order []string
	// The bound producer chain, with an explicit recording revocation sweep composed
	// FIRST (BindFeedProducers puts revocation ahead of the file feed).
	fp := hostagent.BindFeedProducers(dir, &recordingRevocationSweeper{order: &order})
	// Record when the file feed fans out by installing the reason hook (fires on the
	// writer INSIDE the chain, after the revocation leg in fan-out order).
	fp.SetReasonHook(func(consumer string, _ hostagent.SnapshotReason, _ uint64) {
		order = append(order, "feed:"+consumer)
	})

	coord, err := newFeedWritingApplyCoordinatorFor(fp)
	if err != nil {
		t.Fatalf("build coordinator: %v", err)
	}

	// apply_seq is 0 before any apply.
	if got := coord.AppliedSeq(); got != 0 {
		t.Fatalf("pre-apply AppliedSeq = %d, want 0", got)
	}
	out, err := coord.Apply(context.Background(), snapAt(9, "chain-doc"))
	if err != nil {
		t.Fatalf("Apply(seq=9): %v", err)
	}
	if !out.Committed || out.AppliedSeq != 9 {
		t.Fatalf("apply outcome = %+v, want Committed AppliedSeq=9", out)
	}
	// apply_seq advanced ONLY post-sweep: the coordinator's AppliedSeq now reflects 9.
	if got := coord.AppliedSeq(); got != 9 {
		t.Fatalf("post-apply AppliedSeq = %d, want 9 (advances only post-sweep)", got)
	}
	// Order: revocation ran BEFORE the feed fan-out.
	revIdx, feedIdx := -1, -1
	for i, e := range order {
		if e == "revocation" && revIdx < 0 {
			revIdx = i
		}
		if e == "feed:"+hostagent.BoundaryDNSGate && feedIdx < 0 {
			feedIdx = i
		}
	}
	if revIdx < 0 || feedIdx < 0 || !(revIdx < feedIdx) {
		t.Fatalf("sweep order = %v, want revocation@%d BEFORE feed@%d", order, revIdx, feedIdx)
	}
	// The feed file is on disk (fan-out completed post-sweep).
	if files := snapshotFiles(t, dir); len(files) != 1 || files[0] != "00000000000000000009.snapshot" {
		t.Fatalf("feed files = %v, want [00000000000000000009.snapshot]", files)
	}
}

// ── carrier-ON regression: the veto fix (part 3) ──────────────────────────────

// fakeNftProgrammer is an in-memory hostagent.NftProgrammer for the carrier-ON regression
// test: it records each PrepareVerified + Commit so the test proves the nft fan-out leg
// FIRED post-commit. It is the cmd-level analog of internal/hostagent's fake — the
// owner-landed host-local UDS client to ds-nft is the production transport.
type fakeNftProgrammer struct {
	prepareN int
	commitN  int
	lastSeq  uint64
}

func (f *fakeNftProgrammer) PrepareVerified(_ context.Context, seq uint64, _, _ []byte) (hostagent.NftPreparedSnapshot, error) {
	f.prepareN++
	f.lastSeq = seq
	return seq, nil
}

func (f *fakeNftProgrammer) Commit(_ context.Context, _ hostagent.NftPreparedSnapshot) error {
	f.commitN++
	return nil
}

// TestCarrierOnCoordinatorFansOutCarrierNftAndReason is the round-1 VETO REGRESSION
// (part 3). The round-1 attempt substituted a FRESH FeedWriter for the writer inside
// fp.chain, silently dropping the live WatchPolicies carrier + the nft-writer fan-out
// legs from the post-commit sweep whenever DS_DNSGATE_HOST_AGENT_FEED=uds: is set — the
// whole test suite only exercised the carrier-OFF path, so the drop passed green.
//
// This test drives newFeedWritingApplyCoordinatorFor over the AUTHORITATIVE fp.Sweeper()
// chain with the carrier gate ON (uds:<path>) and a fake NftProgrammer wired via
// WithNftProgrammer, then applies a committed version and asserts ALL THREE fan-out legs
// bit: (a) the carrier buffered the version (CarrierCursor advanced), (b) the nft leg
// PrepareVerified + Commit fired, AND (c) the reason still reached the tracker's Detail.
// It FAILS on the naive substituted chain (which drives a fresh writer, so the carrier
// never buffers and the nft leg never fires) and PASSES with the fp.Sweeper() reason-hook
// restore.
func TestCarrierOnCoordinatorFansOutCarrierNftAndReason(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "watch.sock")
	t.Setenv("DS_DNSGATE_HOST_AGENT_FEED", "uds:"+sock) // carrier gate ON
	unsetGate(t, "DS_REVOCATION_FEED_LIVE")

	dir := t.TempDir()
	fp, err := buildFeedProducers(dir)
	if err != nil {
		t.Fatalf("buildFeedProducers (carrier live): %v", err)
	}
	if !fp.LiveCarrier() {
		t.Fatal("DS_DNSGATE_HOST_AGENT_FEED=uds: must select the live carrier")
	}
	// Wire the nft-writer fan-out leg behind the SAME "uds:" gate (WithNftProgrammer).
	nft := &fakeNftProgrammer{}
	if _, err := fp.WithNftProgrammer(nft); err != nil {
		t.Fatalf("WithNftProgrammer: %v", err)
	}
	// Route the reason host-ward through the tracker (the same seam run() installs).
	reasons := newReasonTracker()
	fp.SetReasonHook(reasons.Record)

	// The coordinator drives fp.Sweeper() — the AUTHORITATIVE chain [file feed, carrier,
	// nft], NOT a substituted fresh writer. A naive substitution would drop the carrier +
	// nft legs, and this test would fail on (a)/(b).
	coord, err := newFeedWritingApplyCoordinatorFor(fp)
	if err != nil {
		t.Fatalf("build coordinator: %v", err)
	}

	out, err := coord.Apply(context.Background(), snapAt(12, "carrier-on-doc"))
	if err != nil {
		t.Fatalf("Apply(seq=12): %v", err)
	}
	if !out.Committed || out.AppliedSeq != 12 {
		t.Fatalf("apply outcome = %+v, want Committed AppliedSeq=12", out)
	}

	// (a) the carrier buffered the committed version (its replay cursor advanced) — the
	// live carrier leg is still in the swept chain.
	if got := fp.CarrierCursor(); got != 12 {
		t.Fatalf("carrier cursor = %d, want 12 (the live carrier leg must still fan out post-commit)", got)
	}
	// (b) the nft-writer leg fired post-commit (prepare + commit) — the nft fan-out leg is
	// still in the swept chain.
	if nft.prepareN != 1 || nft.commitN != 1 {
		t.Fatalf("nft leg fired prepareN=%d commitN=%d, want 1/1 (the nft fan-out leg must still fire post-commit)", nft.prepareN, nft.commitN)
	}
	if nft.lastSeq != 12 {
		t.Fatalf("nft leg saw seq %d, want 12", nft.lastSeq)
	}
	// (c) the reason still reached the tracker (a clean apply → empty Detail; a stale token
	// would never have been set, but the hook DID fire — prove by withholding next).
	if d := reasons.DetailFor(hostagent.BoundaryDNSGate); d != "" {
		t.Fatalf("clean apply Detail = %q, want empty", d)
	}
	// A withheld version now surfaces its reason through the SAME live chain — proving the
	// reason hook rides the authoritative writer, not a dropped substitute.
	if _, err := fp.Sweeper().Sweep(context.Background(), snapAt(13, "")); err == nil {
		t.Fatal("a SchemaFailure must be withheld with an error")
	}
	if d := reasons.DetailFor(hostagent.BoundaryDNSGate); d != "schema_failure at seq 13" {
		t.Fatalf("withheld-through-live-chain Detail = %q, want %q", d, "schema_failure at seq 13")
	}
}

// snapshotFiles returns the sorted "<...>.snapshot" file names in dir (excluding the cursor
// + any leftover temp), the names the dataplane consumer's drain sorts lexicographically.
func snapshotFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read feed dir %q: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".snapshot") {
			out = append(out, name)
		}
	}
	return out
}
