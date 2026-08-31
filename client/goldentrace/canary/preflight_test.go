// preflight_test.go — proves the detection-machinery pre-flight is NON-VACUOUS:
// when every detector bites the pre-flight passes, and when a detector is
// NEUTERED the pre-flight FAILS LOUDLY with the distinct OutcomeMachineryBlind —
// so a canary whose detector is broken never passes vacuously (taskdb
// 01KTXRJ2RQ).
//
// These tests pass repoRoot="" so the SUBPROCESS self-test layer is skipped
// (running `go test` of the replay/fidelity packages from inside this test would
// not exercise the neutered-detector path and would slow the unit run): the
// in-process probe is the layer under test here, and it is the one that proves
// the equality ENGINE bites. The subprocess layer is exercised by command (the
// `canary preflight`/`lane` runs, and the workflow's always-on lane).
package canary

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPreflightPassesWhenDetectorsBite proves the happy path: against the
// committed cassettes the in-process probe flags every planted drift, so the
// pre-flight returns nil.
func TestPreflightPassesWhenDetectorsBite(t *testing.T) {
	var log bytes.Buffer
	err := RunPreflight(context.Background(), pkgLayout(), "", func(s string) { log.WriteString(s + "\n") })
	if err != nil {
		t.Fatalf("pre-flight failed against unmodified fixtures (detectors should bite):\n%v\nlog:\n%s", err, log.String())
	}
	// Each probe must have logged a catch (reviewable diff or projection error).
	if !strings.Contains(log.String(), "caught") {
		t.Errorf("pre-flight log shows no probe catches:\n%s", log.String())
	}
}

// TestPreflightFailsWhenDetectorNeutered is the NON-VACUOUS proof. We model a
// neutered detector by handing the probe a fixtures dir whose target cassette
// has had the probe's anchor REMOVED — so the planted drift can no longer change
// the cassette bytes, exactly the "the early-warning system went blind"
// condition (a re-authored cassette slid the anchor out from under the probe).
// The pre-flight MUST fail with OutcomeMachineryBlind, never silently pass.
func TestPreflightFailsWhenDetectorNeutered(t *testing.T) {
	src := pkgLayout()
	tmp := t.TempDir()
	fixturesDir := filepath.Join(tmp, "fixtures")
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Copy every committed cassette into the temp fixtures dir, but for the
	// first probe's target cassette, DELETE the anchor — neutering that probe.
	srcDir := strings.TrimSuffix(src.FixturesGlob, "*"+cassetteSuffix)
	cassettes, err := src.discover()
	if err != nil {
		t.Fatal(err)
	}
	neuteredProbe := probes[0]
	for _, c := range cassettes {
		b, err := os.ReadFile(c)
		if err != nil {
			t.Fatal(err)
		}
		if base(c) == neuteredProbe.cassette {
			// Remove the anchor entirely so the probe's planted mutation is a no-op
			// (the stale-anchor guard must fire — the detector has gone blind).
			b = bytes.ReplaceAll(b, []byte(neuteredProbe.anchor), []byte("NEUTERED_ANCHOR_REMOVED"))
		}
		if err := os.WriteFile(filepath.Join(fixturesDir, filepath.Base(c)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = srcDir

	neutered := Layout{
		FixturesGlob: filepath.Join(fixturesDir, "*"+cassetteSuffix),
		GoldenDir:    filepath.Join(tmp, "testdata"),
	}
	err = RunPreflight(context.Background(), neutered, "", nil)
	if err == nil {
		t.Fatal("PRE-FLIGHT WENT VACUOUS: a neutered detector (anchor removed) did NOT fail " +
			"the pre-flight — the canary would pass with a blind detector, the exact regression " +
			"this guard exists to catch")
	}
	if !IsMachineryBlind(err) {
		t.Errorf("neutered detector produced a non-machinery-blind error %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "DETECTION MACHINERY BLIND") {
		t.Errorf("blind-detector failure is not clearly labelled:\n%v", err)
	}
}

// TestMachineryBlindIsDistinctFromDrift asserts the pre-flight failure carries
// the OutcomeMachineryBlind verdict — DISTINCT from OutcomeDriftDetected — so an
// operator never confuses "detector broken" with "drift found".
func TestMachineryBlindIsDistinctFromDrift(t *testing.T) {
	e := &machineryBlindError{probe: "x", detail: "y"}
	if e.Outcome() != OutcomeMachineryBlind {
		t.Errorf("machineryBlindError.Outcome() = %q, want %q", e.Outcome(), OutcomeMachineryBlind)
	}
	if OutcomeMachineryBlind == OutcomeDriftDetected {
		t.Error("OutcomeMachineryBlind must be DISTINCT from OutcomeDriftDetected")
	}
}

// TestProbesNonVacuous guards the probe catalogue itself: every probe's anchor
// must occur in its cassette and the mutation must change the bytes — a vacuous
// probe (anchor re-authored away) is a hard failure, the same stale-anchor
// discipline the owned suites enforce.
func TestProbesNonVacuous(t *testing.T) {
	dir := strings.TrimSuffix(pkgLayout().FixturesGlob, "*"+cassetteSuffix)
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			b, err := os.ReadFile(dir + p.cassette + cassetteSuffix)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(b, []byte(p.anchor)) {
				t.Fatalf("stale anchor %q not in %s — re-pin the probe (a vacuous probe is a hard failure)",
					p.anchor, p.cassette)
			}
			if bytes.Equal(bytes.Replace(b, []byte(p.anchor), []byte(p.mutation), 1), b) {
				t.Fatalf("probe %q mutation is a no-op", p.name)
			}
		})
	}
}

// TestLaneAbortsOnBlindDetector proves the lane ORCHESTRATION: a blind detector
// aborts the lane with OutcomeMachineryBlind BEFORE the drift check runs (the
// pre-flight-first ordering), so a neutered canary fails the lane rather than
// reporting a vacuous "no drift".
func TestLaneAbortsOnBlindDetector(t *testing.T) {
	src := pkgLayout()
	tmp := t.TempDir()
	fixturesDir := filepath.Join(tmp, "fixtures")
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cassettes, err := src.discover()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cassettes {
		b, err := os.ReadFile(c)
		if err != nil {
			t.Fatal(err)
		}
		if base(c) == probes[0].cassette {
			b = bytes.ReplaceAll(b, []byte(probes[0].anchor), []byte("NEUTERED"))
		}
		if err := os.WriteFile(filepath.Join(fixturesDir, filepath.Base(c)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	l := Layout{
		FixturesGlob: filepath.Join(fixturesDir, "*"+cassetteSuffix),
		GoldenDir:    filepath.Join(tmp, "testdata"),
	}
	var out bytes.Buffer
	// repoRoot="" so the subprocess layer is skipped; the in-process probe alone
	// must abort the lane.
	res := RunOffline(context.Background(), l, "", &out)
	if res.Outcome != OutcomeMachineryBlind {
		t.Fatalf("lane outcome = %q, want %q (a blind detector must abort the lane):\n%s",
			res.Outcome, OutcomeMachineryBlind, out.String())
	}
	if !strings.Contains(out.String(), "CANARY ABORTED") {
		t.Errorf("lane did not announce the abort:\n%s", out.String())
	}
}
