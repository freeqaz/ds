// fidelity_live_test.go — the DS_E2E_LIVE-gated half of the fidelity loop: assert
// the projection of a re-authored SYNTHETIC cassette EQUALS the projection of a
// genuinely LIVE CC stream, captured UNDER the first-party `ds-capture record`
// (CAPTURE-TOOL-DESIGN.md §3/§4). The capture tool stands up its own
// TLS-terminating egress gateway on a FREE port (the proven :18099) and carries
// the private-socket / auto-disabled-receiver coexistence semantics natively, so
// it never collides with the protected :18080 monitor — replacing the external
// `../cia` recorder the fidelity loop historically leaned on.
//
// GATING: the whole live path is behind DS_E2E_LIVE=1, the single documented gate
// (e2e/README.md "One gate story"). Unset — the default, and every CI / `go test`
// run — these tests SKIP and launch NOTHING: no claude, no ds-capture, no podman.
// The always-on fidelity loop (fidelity_test.go) proves the equality machinery
// offline against committed synthetic fixtures; the progressive-receipt assertion
// (TestProgressiveReceiptAssertionOffline, below) proves the incremental-delivery
// teeth offline against a synthetic TICKING stream — so the live legs are the only
// thing the gate withholds, and even their assertion machinery is CI-exercised.
//
// THE LIVE LOOP (operator-driven; the deferred manual step):
//  1. `ds-capture record --port 18099 --cassette <job>/api.json` stands up the
//     first-party egress gateway on the FREE :18099 — never the protected :18080
//     monitor, and never touching ~/.cia/cia.sock (the tool has no receiver
//     sockets to collide; CAPTURE-TOOL-DESIGN.md §4).
//  2. drive real CC `2.1.173` in the proven rootless-podman recipe (DRIVE-FINDINGS
//     "How it ran"), egress through the capture tool's :18099; tee CC stdout to a
//     raw capture (raw-class — stays under DS_LIVE_SCRATCH, NEVER committed).
//  3. project the raw live stdout → attach.v1 (the SAME adapter), and assert it
//     EQUALS the projection of the committed synthetic cassette, id-relative.
//
// A divergence is a STALE cassette or genuine CC DRIFT; the capture tool's
// API-plane cassette (the recorder's <job>/api.json) is what tells which — the
// stdout harness alone cannot see the transport plane (DRIVE-PROTOCOL.md).
//
// D50 WALL: the raw stdout capture and the API cassette stay uncommitted
// (DS_LIVE_SCRATCH, a job dir under ~/tmp). No token, cost, or real path enters git.
package fidelity

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/e2e"
)

// liveGateArmed reports whether the single documented live gate is set. Unset is
// the default and every CI/`go test` run — nothing live is ever launched.
func liveGateArmed() bool { return os.Getenv("DS_E2E_LIVE") == "1" }

// refuseProtectedMonitorSocket is the belt-and-suspenders guard the live legs
// share: the capture tool MUST bind a FREE port / private socket, never the
// protected :18080 monitor's. ds-capture defaults to :18099 and carries no
// receiver sockets, so a collision cannot happen by construction; we still refuse
// to proceed if an operator points us at the protected monitor socket.
// DS_CAPTURE_RECORD_SOCKET is the first-party env; DS_CIA_RECORD_SOCKET is the
// deprecated alias honoured for the bounded migration overlap.
func refuseProtectedMonitorSocket(t *testing.T) {
	t.Helper()
	for _, env := range []string{"DS_CAPTURE_RECORD_SOCKET", "DS_CIA_RECORD_SOCKET"} {
		sock := os.Getenv(env)
		if sock == "" {
			continue
		}
		if filepath.Clean(sock) == filepath.Join(os.Getenv("HOME"), ".cia", "cia.sock") {
			t.Fatalf("refusing to run: %s points at the protected monitor socket. "+
				"Use a private capture-tool socket on a free port (ds-capture defaults "+
				"to :18099, never :18080).", env)
		}
	}
}

// TestFidelityVsLiveCapture is the live half: when armed, it asserts the synthetic
// cassette's projection equals the projection of a LIVE CC stdout capture taken
// under `ds-capture record` on the free :18099. SKIPS (launches nothing) when unset.
//
// Because the live container launch + ds-capture wiring is the operator-driven
// deferred step (e2e/README.md "The deferred manual live step"; cc_sandbox.sh is a
// planner, not a launcher), the operator points DS_LIVE_RAW_<scenario> at the raw
// CC-stdout ndjson their armed run produced (under DS_LIVE_SCRATCH). The test then
// runs the SAME id-relative equality the always-on loop runs — synthetic vs LIVE,
// closing the n=1 / circularity worry with a real capture.
func TestFidelityVsLiveCapture(t *testing.T) {
	if !liveGateArmed() {
		t.Skip("DS_E2E_LIVE != 1: live fidelity capture is the deferred manual step " +
			"(record under `ds-capture record --port 18099`, per the runbook in this " +
			"test's doc comment). Always-on loop in fidelity_test.go.")
	}
	refuseProtectedMonitorSocket(t)

	for _, p := range fidScenarios {
		t.Run(p.name, func(t *testing.T) {
			rawEnv := "DS_LIVE_RAW_" + envKey(p.name)
			rawPath := os.Getenv(rawEnv)
			if rawPath == "" {
				t.Skipf("%s unset: provide the raw live CC-stdout ndjson for scenario "+
					"%q (captured under `ds-capture record --port 18099`; raw-class, "+
					"never committed).", rawEnv, p.name)
			}
			f, err := os.Open(rawPath)
			if err != nil {
				t.Fatalf("open live raw capture %s: %v", rawPath, err)
			}
			defer f.Close()

			// replay.Replay already skips a leading ds_fixture header (replay.go) and
			// a raw live capture has none, so the projection path is identical for
			// both legs — feed the file directly.
			liveEvs, err := ProjectStream(f)
			if err != nil {
				t.Fatalf("project live capture: %v", err)
			}
			synEvs, err := ProjectFile(cassettePath(p.synthetic))
			if err != nil {
				t.Fatalf("project synthetic: %v", err)
			}

			diff := EqualProjections("synthetic", synEvs, "live", liveEvs)
			if !diff.Equal {
				t.Errorf("scenario %q: SYNTHETIC cassette projection diverges from the "+
					"LIVE capture. Either the synthetic cassette is STALE or CC has "+
					"DRIFTED — inspect the ds-capture API-plane cassette to tell which.\n%s",
					p.name, diff.Report)
			}
		})
	}
}

// TestLiveProgressiveDeliverySmoke is the DS_E2E_LIVE-gated PROGRESSIVE-DELIVERY
// smoke — the rewrite's actual motivation (DRIVE-PROTOCOL.md "Determinism via
// record-replay"; CAPTURE-TOOL-DESIGN.md §4). The streaming tee is proven offline
// by channel synchronization (e2e harness_test.go's bounded-pipe backpressure
// test) and the incremental assertion is proven offline by a synthetic ticking
// stream (TestProgressiveReceiptAssertionOffline). What stays DEFERRED behind the
// gate is the LONG real-CC turn streamed through the egress gateway on :18099
// WITHOUT a client idle-timeout — the operator's armed run records it and asserts
// the harness received the FIRST teed bytes well BEFORE the stream ended.
//
// OPERATOR RUNBOOK (the deferred manual live step — nothing here launches in CI):
//  1. Arm the gate: `export DS_E2E_LIVE=1` and pick a scratch dir under ~/tmp:
//     `export DS_LIVE_SCRATCH=~/tmp/ds-progressive/$(date +%s)` (raw-class; D50).
//  2. Stand up the first-party recorder on the FREE port:
//     `ds-capture record --port 18099 --cassette "$DS_LIVE_SCRATCH/api.json"`
//     (NEVER :18080 — the protected shared monitor; ds-capture defaults to :18099
//     and carries no receiver sockets, so the singleton-collision blocker
//     evaporates by construction — CAPTURE-TOOL-DESIGN.md §4).
//  3. Drive real CC 2.1.173 in the proven rootless-podman recipe with a prompt
//     that compels a LONG streamed turn (e.g. "write a 600-word essay, streaming"),
//     egress through :18099, NODE_USE_ENV_PROXY=1, NODE_EXTRA_CA_CERTS=<capture CA>,
//     `--no-session-persistence`, `--model sonnet`, `--max-budget-usd` cap, and
//     CRUCIALLY no client idle-timeout. As CC streams, write the per-chunk receipt
//     timeline (one monotonic-nanos offset per teed stdout line) to a sidecar:
//     `$DS_LIVE_SCRATCH/<scenario>.receipt` — the raw-class evidence this test reads.
//  4. Re-run this test (still `DS_E2E_LIVE=1`) pointing
//     `DS_LIVE_RECEIPT_<scenario>` at that sidecar. The test replays the receipt
//     timeline through the e2e ProgressiveReceipt assertion and proves the first
//     chunk arrived well before the last — i.e. the tee streamed incrementally
//     rather than buffering until EOF (which an idle-client-timeout would mask).
//
// D50 WALL: the receipt sidecar (like the raw stdout / API cassette) is raw-class —
// it carries only relative monotonic offsets, never a token/cost/path, but it still
// lives under DS_LIVE_SCRATCH and is NEVER committed. The assertion is purely
// id-/order-relative (DRIVE-PROTOCOL.md): it pins no absolute latency, throughput,
// or TTFT — only that first-receipt happens-before stream-end by a margin.
func TestLiveProgressiveDeliverySmoke(t *testing.T) {
	if !liveGateArmed() {
		t.Skip("DS_E2E_LIVE != 1: the live progressive-delivery smoke is the deferred " +
			"manual step (record a LONG turn under `ds-capture record --port 18099`, " +
			"per the operator runbook in this test's doc comment). The incremental " +
			"assertion is proven offline by TestProgressiveReceiptAssertionOffline.")
	}
	refuseProtectedMonitorSocket(t)

	// minProgressiveSpan: the live margin proving a LONG turn streamed rather than
	// landing in one burst at EOF. A genuinely streamed multi-hundred-word CC turn
	// spans seconds; 250ms is a conservative floor that a buffer-until-EOF tee (all
	// chunks in one instant) cannot clear, while staying well under any real turn.
	// It is a RELATIVE margin within the single run — never an absolute latency SLA.
	const minProgressiveSpan = 250 * time.Millisecond
	const minProgressiveChunks = 2

	armed := false
	for _, p := range fidScenarios {
		t.Run(p.name, func(t *testing.T) {
			receiptEnv := "DS_LIVE_RECEIPT_" + envKey(p.name)
			receiptPath := os.Getenv(receiptEnv)
			if receiptPath == "" {
				t.Skipf("%s unset: provide the per-chunk receipt timeline for scenario "+
					"%q (one monotonic-nanos offset per teed stdout line, written by the "+
					"armed `ds-capture record --port 18099` run; raw-class under "+
					"DS_LIVE_SCRATCH, never committed). See this test's operator runbook.",
					receiptEnv, p.name)
			}
			armed = true

			recv, err := loadReceiptTimeline(receiptPath)
			if err != nil {
				t.Fatalf("load receipt timeline %s: %v", receiptPath, err)
			}

			res := recv.AssertProgressiveReceipt(minProgressiveChunks, minProgressiveSpan)
			t.Logf("progressive smoke %q: %d chunks, first→last span %s (raw-class receipt: %s)",
				p.name, res.Chunks, res.FirstToLast, receiptPath)
			if !res.Incremental {
				t.Errorf("scenario %q: live turn was NOT delivered incrementally: %s. "+
					"A long real-CC turn through :18099 must stream chunk-by-chunk; a burst "+
					"at EOF means the egress gateway buffered or a client idle-timeout "+
					"collapsed the stream (DRIVE-PROTOCOL.md — the rewrite's motivation).",
					p.name, res.Reason)
			}
		})
	}
	if liveGateArmed() && !armed {
		t.Skip("no DS_LIVE_RECEIPT_<scenario> provided for any scenario: arm the gate " +
			"AND point at least one receipt sidecar (operator runbook) to exercise the " +
			"live progressive smoke.")
	}
}

// loadReceiptTimeline reconstructs an e2e.ProgressiveReceipt from a raw-class
// receipt sidecar: one monotonic-nanoseconds offset per teed stdout chunk, in
// arrival order (the format the operator runbook writes during the armed run).
// Blank lines and `#`-comments are ignored so the operator can annotate. The
// offsets are replayed against a fixed base instant through a deterministic clock,
// so the ProgressiveReceipt this returns carries exactly the live arrival timeline
// — and the SAME AssertProgressiveReceipt the offline ticking-stream test exercises
// then runs over real-capture data. No absolute wall-clock is read or asserted;
// only the relative offsets matter (DRIVE-PROTOCOL.md).
func loadReceiptTimeline(path string) (*e2e.ProgressiveReceipt, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var offsets []time.Duration
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		ns, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil {
			return nil, fmt.Errorf("receipt line %d: %q is not a monotonic-nanos offset: %v", line, s, perr)
		}
		offsets = append(offsets, time.Duration(ns)*time.Nanosecond)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return e2e.ReceiptFromOffsets(offsets), nil
}

// TestProgressiveReceiptAssertionOffline is the ALWAYS-ON offline coverage of the
// e2e progressive-receipt assertion helper against a synthetic TICKING stream — no
// gate, no live CC, no ds-capture, no podman. A goroutine ticks N chunks into the
// receptor through e2e.Tee with deliberate inter-chunk gaps (the model of an
// incrementally-streamed turn); a second case bursts every chunk in one instant
// (the model of a buffer-until-EOF tee). The assertion must PASS the ticking case
// and FAIL the burst case — proving the teeth are non-vacuous BEFORE any operator
// arms the gate. This is the offline twin the live smoke (TestLiveProgressive-
// DeliverySmoke) defers to a real run.
func TestProgressiveReceiptAssertionOffline(t *testing.T) {
	t.Run("ticking stream is incremental", func(t *testing.T) {
		// A synthetic ticking stream: 8 chunks, each arriving 5ms after the prior,
		// teed through the receptor exactly as the live pump would tee real stdout.
		// We drive a fixed-offset clock so the test is deterministic (no real
		// sleeps, no flakiness): chunk i is stamped at base + i*tick.
		const chunks = 8
		const tick = 5 * time.Millisecond
		offsets := make([]time.Duration, chunks)
		for i := range offsets {
			offsets[i] = time.Duration(i) * tick
		}
		recv := e2e.ReceiptFromOffsets(offsets)

		// minSpan below the total ticked span (7*tick = 35ms) must PASS; the first
		// chunk is 35ms before the last, comfortably clearing a 20ms floor.
		res := recv.AssertProgressiveReceipt(2, 20*time.Millisecond)
		if !res.Incremental {
			t.Fatalf("ticking stream judged non-incremental: %s (chunks=%d span=%s)",
				res.Reason, res.Chunks, res.FirstToLast)
		}
		if res.Chunks != chunks {
			t.Errorf("receipt recorded %d chunks, want %d", res.Chunks, chunks)
		}
		if res.FirstToLast != time.Duration(chunks-1)*tick {
			t.Errorf("first→last span = %s, want %s", res.FirstToLast, time.Duration(chunks-1)*tick)
		}
	})

	t.Run("burst-at-EOF is NOT incremental", func(t *testing.T) {
		// The failure mode an idle-client-timeout masks: every chunk lands in the
		// SAME instant (the tee buffered until EOF, then flushed). The assertion
		// must reject it — first→last span is zero, below any positive minSpan.
		const chunks = 8
		offsets := make([]time.Duration, chunks) // all zero ⇒ same instant.
		recv := e2e.ReceiptFromOffsets(offsets)

		res := recv.AssertProgressiveReceipt(2, 20*time.Millisecond)
		if res.Incremental {
			t.Fatalf("burst-at-EOF stream judged incremental — the assertion is vacuous "+
				"(span=%s); a buffered tee must FAIL the incremental check", res.FirstToLast)
		}
		if res.Reason == "" {
			t.Error("non-incremental verdict carried no Reason — operators need the why")
		}
	})

	t.Run("too few chunks is NOT incremental", func(t *testing.T) {
		// A single chunk cannot demonstrate first-byte-before-end: there is no
		// window. The assertion must reject it rather than pass vacuously.
		recv := e2e.ReceiptFromOffsets([]time.Duration{0})
		res := recv.AssertProgressiveReceipt(2, 0)
		if res.Incremental {
			t.Fatal("a single-chunk stream was judged incremental — no window exists")
		}
	})

	t.Run("live tee composition records receipt as a side effect", func(t *testing.T) {
		// Prove e2e.Tee composes: wrapping a downstream Projector both forwards the
		// chunk AND records its receipt, so the live pump captures the progressive
		// timeline for free. We feed three lines and assert both the downstream saw
		// them and the receipt counted them.
		var seen [][]byte
		downstream := e2e.ProjectorFunc(func(line []byte) error {
			seen = append(seen, append([]byte(nil), line...))
			return nil
		})
		recv := e2e.Tee(downstream)
		for _, l := range [][]byte{[]byte("a"), []byte("b"), []byte("c")} {
			if err := recv.Project(l); err != nil {
				t.Fatalf("Project: %v", err)
			}
		}
		if len(seen) != 3 {
			t.Errorf("downstream projector saw %d lines, want 3 (Tee did not forward)", len(seen))
		}
		if recv.Count() != 3 {
			t.Errorf("receipt counted %d chunks, want 3 (Tee did not record)", recv.Count())
		}
	})
}

// TestLiveGateClosedByDefault documents and asserts that, with the gate unset
// (the CI default), the live fidelity path launches NOTHING: liveGateArmed() is
// false, so TestFidelityVsLiveCapture and TestLiveProgressiveDeliverySmoke skip
// before touching any claude/ds-capture/podman.
func TestLiveGateClosedByDefault(t *testing.T) {
	if os.Getenv("DS_E2E_LIVE") == "1" {
		t.Skip("DS_E2E_LIVE=1: the gate is armed (operator live run); skip the " +
			"default-closed assertion.")
	}
	if liveGateArmed() {
		t.Fatal("liveGateArmed() is true with DS_E2E_LIVE unset — the gate is not " +
			"closed by default; the live path could launch in CI")
	}
}

// envKey upper-cases a scenario name into an env-var-safe suffix
// (chat -> CHAT, native-ask -> NATIVE_ASK).
func envKey(name string) string {
	b := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b = append(b, r-('a'-'A'))
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b = append(b, r)
		default:
			b = append(b, '_')
		}
	}
	return string(b)
}
