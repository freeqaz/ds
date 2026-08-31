// live_test.go — proves the live CC-latest leg is GATED and never launches in
// the fleet: with DS_E2E_LIVE unset (the CI/fleet default) DriftAgainstLatest
// returns ErrLiveGateUnset and captures nothing. Also pins the cassette suffix
// to the shared goldentrace constant so this package's discovery can never drift
// from the golden suffix (verify-and-extend discipline).
package canary

import (
	"errors"
	"os"
	"testing"
)

// TestLiveGateClosedByDefault asserts the single-gate story: with DS_E2E_LIVE
// unset, the live leg launches NOTHING and returns the gate-unset signal. This
// is the fleet default — no claude/cia/podman is ever touched here.
func TestLiveGateClosedByDefault(t *testing.T) {
	if os.Getenv(LiveGateEnv) == "1" {
		t.Skip("DS_E2E_LIVE=1: an operator armed the gate; skip the default-closed assertion.")
	}
	if LiveGateArmed() {
		t.Fatal("LiveGateArmed() is true with DS_E2E_LIVE unset — the gate is not closed by default")
	}
	_, _, err := DriftAgainstLatest(DefaultLayout())
	if !errors.Is(err, ErrLiveGateUnset) {
		t.Fatalf("DriftAgainstLatest with the gate unset returned %v, want ErrLiveGateUnset "+
			"(the live leg must not run in the fleet)", err)
	}
}

// TestCassetteSuffixAgreesWithGolden pins this package's cassette suffix to the
// value the replay golden machinery uses. The goldens, fidelity, and this canary
// all key on ".cc-wire.ndjson"; if the golden suffix ever changes, this fails so
// the canary's discovery is re-pointed in lockstep (it cannot import the
// test-only constant, so the value is pinned here against the documented one).
func TestCassetteSuffixAgreesWithGolden(t *testing.T) {
	const goldenSuffix = ".cc-wire.ndjson"
	if cassetteSuffix != goldenSuffix {
		t.Errorf("cassetteSuffix = %q, want %q (the goldentrace golden suffix) — the canary's "+
			"cassette discovery drifted from the golden suffix", cassetteSuffix, goldenSuffix)
	}
}

// TestLiveScenarioGoldensExist proves every live scenario points at a committed
// canon golden the operator's CC-latest capture is diffed against — so an armed
// live run has a golden to compare to (no dangling scenario).
func TestLiveScenarioGoldensExist(t *testing.T) {
	l := pkgLayout()
	for _, s := range liveScenarios {
		golden := l.goldenPath(s.Golden + cassetteSuffix)
		if _, err := os.Stat(golden); err != nil {
			t.Errorf("live scenario %q references canon golden %s which does not exist: %v",
				s.Name, golden, err)
		}
	}
}
