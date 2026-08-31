// preflight.go — the DETECTION-MACHINERY PRE-FLIGHT.
//
// The canary's value is its verdict: "CC-latest still projects the way the
// committed cassettes do." That verdict is only trustworthy if the DETECTORS
// still bite — a canary whose perturbation/fidelity detector has been neutered
// passes VACUOUSLY (it reports "no drift" because it can no longer see drift).
// "The early-warning system went blind" must surface on the SAME cadence as
// real drift (doc 06 §5 / D49; taskdb 01KTXRJ2RQ), with a DISTINCT outcome so
// an operator never confuses "detector broken" with "no drift today".
//
// So the canary lane runs the pre-flight FIRST and only proceeds to the real
// drift check if it passes. Two layers, both fleet-safe (offline, fixture-only,
// no gate, no live claude/ds-capture/podman):
//
//  1. INVOKE THE EXISTING SELF-TESTS as a subprocess. The canary does NOT
//     re-implement or edit perturbation_test.go (owned elsewhere) — it RUNS
//     them: `go test -run TestPerturbationDriftIsCaught` over the replay
//     package (the fidelity 4-class catch + Branch-C warning-as-drift) and
//     `go test -run TestPerturbationCaughtAsReviewableDiff` over the fidelity
//     package. A non-zero exit means a detector is broken → the lane fails with
//     OutcomeMachineryBlind, NOT OutcomeDriftDetected.
//
//  2. AN IN-PROCESS NEUTERED-DETECTOR PROBE. Independently of the subprocess,
//     re-plant a known drift into a committed cassette in memory and assert the
//     fidelity equality engine FLAGS it. This is the canary's own teeth-check:
//     if a future change made fidelity.EqualProjections tolerate a planted
//     drift, this probe catches it even if the subprocess test binary could not
//     build — defence in depth against a neutered detector.
package canary

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/fidelity"
)

// Outcome is the canary lane's verdict class. The pre-flight failure
// (OutcomeMachineryBlind) is DELIBERATELY DISTINCT from a real drift
// (OutcomeDriftDetected): a blind detector means the canary's verdicts are not
// trustworthy until the detection machinery is fixed — a different remediation
// than reviewing a CC drift diff.
type Outcome string

const (
	// OutcomeFaithful — every detector bites AND the regen/drift check is clean.
	OutcomeFaithful Outcome = "faithful"
	// OutcomeMachineryBlind — a detector is neutered: the pre-flight failed.
	// The lane STOPS here; the drift verdict is not trustworthy.
	OutcomeMachineryBlind Outcome = "detection-machinery-blind"
	// OutcomeDriftDetected — detectors bite but a regen/drift diff appeared: a
	// STALE cassette or genuine CC drift, queued for review (D49).
	OutcomeDriftDetected Outcome = "drift-detected"
)

// preflightProbe is one in-process neutered-detector check: a planted drift on
// a committed cassette that the fidelity equality engine MUST flag.
type preflightProbe struct {
	name     string
	cassette string // base name under fixtures/
	anchor   string // must occur in the cassette (stale-anchor guard)
	mutation string // the planted drift
	why      string // the CC-drift class this probe stands in for
}

// probes plants drift on DISTINCT high-value surfaces — the same blind spots
// the owned perturbation suites target (DRIVE-PROTOCOL.md "three gaps"): chat
// content, the result terminal, and the native control channel. If the fidelity
// engine tolerates ANY of these, it has gone blind and the canary must not run.
var probes = []preflightProbe{
	{
		name:     "chat-content-blind",
		cassette: "baseline-chat",
		anchor:   "Hello! How can I help you today?",
		mutation: "Greetings, drifted output here.",
		why:      "assistant chat content drift — the most visible class a customer sees first",
	},
	{
		name:     "control-behavior-blind",
		cassette: "ask-control",
		anchor:   `"subtype":"can_use_tool"`,
		mutation: `"subtype":"can_use_tool_DRIFTED"`,
		why:      "native control-channel discriminator drift — gap 2, the costliest blind spot",
	},
}

// RunPreflight runs both pre-flight layers. It returns nil iff every detector
// bites; otherwise a machineryBlindError whose Outcome is OutcomeMachineryBlind.
// The in-process probe runs first (it needs no subprocess and proves the engine
// directly); the subprocess self-test invocation runs second (it proves the
// OWNED perturbation suites still pass on their cadence). reportf receives
// human-readable progress lines for the lane log.
//
// repoRoot is the directory the subprocess `go test` runs in (the client module
// root). When repoRoot is empty the subprocess layer is SKIPPED (the in-process
// probe still runs) — used by the unit tests, which prove the probe logic
// without spawning a `go test` of themselves (which would recurse).
func RunPreflight(ctx context.Context, l Layout, repoRoot string, reportf func(string)) error {
	if reportf == nil {
		reportf = func(string) {}
	}

	// Layer 1: the in-process neutered-detector probe.
	reportf("pre-flight: in-process neutered-detector probe (fidelity engine must flag planted drift)")
	if err := runProbes(l, reportf); err != nil {
		return err
	}

	// Layer 2: invoke the OWNED perturbation self-tests as a subprocess.
	if repoRoot == "" {
		reportf("pre-flight: subprocess self-test invocation SKIPPED (no repoRoot; in-process probe stands)")
		return nil
	}
	reportf("pre-flight: invoking the owned perturbation self-tests (go test -run …)")
	if err := runSelfTests(ctx, repoRoot, reportf); err != nil {
		return err
	}
	reportf("pre-flight: PASS — every detector bites; the canary verdict is trustworthy")
	return nil
}

// runProbes re-plants each probe's drift into its cassette in memory and asserts
// the fidelity equality engine flags it. A tolerated probe is a BLIND detector:
// the canary must fail with OutcomeMachineryBlind rather than ever report "no
// drift" from an engine that can no longer see it.
//
// Nothing is written to disk — the mutation is confined to memory, so no D50
// provenance header is needed and the committed cassettes are untouched
// (HARDENING-NOTES §2.3).
func runProbes(l Layout, reportf func(string)) error {
	dir := strings.TrimSuffix(l.FixturesGlob, "*"+cassetteSuffix)
	for _, p := range probes {
		cassettePath := dir + p.cassette + cassetteSuffix
		pristine, err := os.ReadFile(cassettePath)
		if err != nil {
			return &machineryBlindError{
				probe:  p.name,
				detail: fmt.Sprintf("cannot read cassette %s for the probe: %v", cassettePath, err),
			}
		}

		// Stale-anchor guard: the planted drift MUST change bytes, else the probe
		// is a vacuous no-op (a cassette re-authored out from under it) — itself a
		// hard failure, exactly the discipline the owned suites enforce.
		if !bytes.Contains(pristine, []byte(p.anchor)) {
			return &machineryBlindError{
				probe: p.name,
				detail: fmt.Sprintf("stale anchor %q no longer occurs in %s — the probe can "+
					"no longer plant %q; re-pin it (a vacuous probe is a hard failure)",
					p.anchor, p.cassette, p.why),
			}
		}
		mutant := bytes.Replace(pristine, []byte(p.anchor), []byte(p.mutation), 1)
		if bytes.Equal(mutant, pristine) {
			return &machineryBlindError{
				probe:  p.name,
				detail: fmt.Sprintf("planted mutation %q was a no-op (bytes unchanged)", p.name),
			}
		}

		pristineEvs, err := fidelity.ProjectStream(bytes.NewReader(pristine))
		if err != nil {
			return &machineryBlindError{
				probe:  p.name,
				detail: fmt.Sprintf("pristine %s failed to project: %v", p.cassette, err),
			}
		}
		mutantEvs, perr := fidelity.ProjectStream(bytes.NewReader(mutant))
		if perr != nil {
			// A parse error on the drifted shape is ALSO a valid catch (the adapter
			// refusing to project the drift is a loud signal). The detector bit.
			reportf(fmt.Sprintf("  probe %-22s caught (projection error — a valid catch): %s", p.name, p.why))
			continue
		}

		diff := fidelity.EqualProjections("pristine", pristineEvs, "planted-drift", mutantEvs)
		if diff.Equal {
			// BLIND: the engine tolerated a planted drift. Fail the lane.
			return &machineryBlindError{
				probe: p.name,
				detail: fmt.Sprintf("the fidelity equality engine did NOT flag a planted %s drift "+
					"(%s) — the projections still compare EQUAL. The canary's detector has gone "+
					"BLIND to this class; its 'no drift' verdict is not trustworthy.", p.cassette, p.why),
			}
		}
		if strings.TrimSpace(diff.Report) == "" {
			return &machineryBlindError{
				probe: p.name,
				detail: fmt.Sprintf("probe %s diverged but produced an EMPTY report — a catch "+
					"must be reviewable for the canary to be useful", p.name),
			}
		}
		reportf(fmt.Sprintf("  probe %-22s caught (reviewable diff): %s", p.name, p.why))
	}
	return nil
}

// selfTestSpec names one owned perturbation self-test the pre-flight invokes —
// the package path and the -run pattern. The canary INVOKES these; it never
// edits them (they are owned by the branch-c-accounting / fidelity units).
type selfTestSpec struct {
	pkg    string // package path relative to the client module root
	run    string // -run pattern
	detail string // what this self-test proves
}

// selfTests is the owned-self-test set the pre-flight runs. TestPerturbation-
// DriftIsCaught (replay) is the 4-class fidelity catch plus the Branch-C
// warning-as-drift detector; TestPerturbationCaughtAsReviewableDiff (fidelity)
// is the goldentrace perturbation self-test over the projection-equality engine.
var selfTests = []selfTestSpec{
	{
		pkg:    "./goldentrace/replay",
		run:    "TestPerturbationDriftIsCaught",
		detail: "the fidelity 4-class catch + Branch-C warning-as-drift (replay perturbation self-test)",
	},
	{
		pkg:    "./goldentrace/fidelity",
		run:    "TestPerturbationCaughtAsReviewableDiff",
		detail: "the goldentrace perturbation self-test over the projection-equality engine",
	},
}

// runSelfTests invokes each owned perturbation self-test as a `go test -run …`
// subprocess. A non-zero exit means a detector is broken → the lane fails with
// OutcomeMachineryBlind. The subprocess is offline and fixture-only: these tests
// never launch claude/ds-capture/podman (they perturb committed cassettes in memory),
// so running them needs no gate and is fleet-safe.
func runSelfTests(ctx context.Context, repoRoot string, reportf func(string)) error {
	for _, st := range selfTests {
		// -count=1 defeats the test cache so a real re-run proves the detector
		// bites NOW, not that it once did. -run pins exactly the self-test.
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", "^"+st.run+"$", st.pkg)
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			return &machineryBlindError{
				probe: st.run,
				detail: fmt.Sprintf("the owned self-test %s (%s) FAILED — %s proves the detector "+
					"no longer bites. The canary cannot trust its drift verdict.\n%s\n%s",
					st.run, st.pkg, st.detail, err, indent(string(out))),
			}
		}
		reportf(fmt.Sprintf("  self-test %-32s PASS — %s", st.run, st.detail))
	}
	return nil
}

func indent(s string) string {
	var sb strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		sb.WriteString("    ")
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}

// machineryBlindError is the pre-flight failure: a detector is neutered. Its
// Outcome is OutcomeMachineryBlind so the lane reports a DISTINCT failure class
// from a real drift (OutcomeDriftDetected).
type machineryBlindError struct {
	probe  string
	detail string
}

func (e *machineryBlindError) Error() string {
	return fmt.Sprintf("DETECTION MACHINERY BLIND [%s]: %s", e.probe, e.detail)
}

// Outcome reports the verdict class — always OutcomeMachineryBlind for this
// error type, so callers can branch on the distinct failure.
func (e *machineryBlindError) Outcome() Outcome { return OutcomeMachineryBlind }

// IsMachineryBlind reports whether err is a pre-flight (detector-neutered)
// failure, so a caller can distinguish it from a drift outcome.
func IsMachineryBlind(err error) bool {
	_, ok := err.(*machineryBlindError)
	return ok
}
