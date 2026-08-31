// runner.go — the BY-COMMAND projection-equality runner over the cassette set.
//
// The fidelity loop is runnable two ways, both "by command":
//
//   - as a test:  cd client && go test ./goldentrace/fidelity -run TestFidelityProjectionEquality
//   - as a tool:  cd client && go run ./goldentrace/fidelity/cmd/fidcheck
//
// The tool (cmd/fidcheck) is for operators and the live-record orchestration: it
// projects each (synthetic, twin) pair, runs the id-relative equality, and prints
// a reviewable report + a non-zero exit on any divergence. It is the always-on
// half; the live half (synthetic vs a real `cia record` capture) rides
// DS_E2E_LIVE in fidelity_live_test.go.
package fidelity

import (
	"fmt"
	"io"
	"path/filepath"
)

// Pair names one fidelity scenario: the canonical synthetic cassette and the leg
// it is checked against (a re-authored live-equiv twin, or — under the live gate —
// a real capture path).
type Pair struct {
	Name string
	A    string // path to leg A (the synthetic cassette)
	B    string // path to leg B (the live-equiv twin / live capture)
}

// fidScenario is one (synthetic, live-equiv) cassette-base pair. This is the
// canonical fidelity scenario set — the re-authored synthetic cassette and a
// "-live-equiv" twin authored with DIFFERENT ids/timing/cost (the stand-in a
// real `cia record` capture replaces under DS_E2E_LIVE). Lives in non-test code
// so both the runner command and the tests share one source of truth.
type fidScenario struct {
	name      string
	synthetic string
	liveEquiv string
}

var fidScenarios = []fidScenario{
	{"chat", "drive-fid-chat", "drive-fid-chat-live-equiv"},
	{"native-ask", "drive-fid-native-ask", "drive-fid-native-ask-live-equiv"},
	{"multiturn", "drive-fid-multiturn", "drive-fid-multiturn-live-equiv"},
}

// fixturesDirFromClientRoot is the fixtures dir relative to the client module
// root (where `go run ./goldentrace/fidelity/cmd/fidcheck` executes).
const fixturesDirFromClientRoot = "fixtures"

// DefaultPairs returns the committed fidelity scenario set as cassette paths
// relative to the client module root (the package's own fixtures dir).
func DefaultPairs() []Pair {
	pairs := make([]Pair, 0, len(fidScenarios))
	for _, p := range fidScenarios {
		pairs = append(pairs, Pair{
			Name: p.name,
			A:    filepath.Join(fixturesDirFromClientRoot, p.synthetic+".cc-wire.ndjson"),
			B:    filepath.Join(fixturesDirFromClientRoot, p.liveEquiv+".cc-wire.ndjson"),
		})
	}
	return pairs
}

// RunEquality runs the projection-equality check over the given pairs, writing a
// per-scenario PASS/FAIL line (and the diff on failure) to w. It returns the
// number of divergent scenarios — zero means the whole set is faithful.
func RunEquality(w io.Writer, pairs []Pair) (failures int) {
	for _, p := range pairs {
		diff, err := EqualFiles(p.A, p.B)
		if err != nil {
			fmt.Fprintf(w, "ERROR  %-14s %v\n", p.Name, err)
			failures++
			continue
		}
		if diff.Equal {
			fmt.Fprintf(w, "PASS   %-14s synthetic ≡ live-equiv (id-relative)\n", p.Name)
			continue
		}
		fmt.Fprintf(w, "FAIL   %-14s projections DIVERGE\n%s\n", p.Name, diff.Report)
		failures++
	}
	fmt.Fprintf(w, "\nfidelity: %d/%d scenarios faithful\n", len(pairs)-failures, len(pairs))
	return failures
}
