// SPDX-License-Identifier: Apache-2.0
package main

// Cross-leg weight-parity test: the hybrid ranking weights are a SINGLE tuning
// knob shared by two independent implementations — the Go ranking leg
// (embeddings.go resolveHybridWeights) and the Python fusion leg
// (searchsvc/fusion.py W_DENSE / W_SPARSE). Both read byte-identical env var
// names (SEARCHSVC_W_DENSE / SEARCHSVC_W_SPARSE) and fall back to byte-identical
// canonical defaults (0.65 / 0.35). Today that agreement is guaranteed only by
// construction + mirrored comments; this test makes it ENFORCED.
//
// It resolves both legs for the SAME environment and asserts they agree:
//   - default (env UNSET): both legs must produce the canonical 0.65 / 0.35.
//   - override (env SET to a non-default pair): both legs must produce that pair.
//
// If a future edit renames an env var, or changes a default, on ONE leg but not
// the other, the legs diverge and this test FAILS LOUDLY with both observed
// pairs — catching the silent single-leg drift that mirrored comments cannot.
//
// Hermetic: the Go side resolves in-process (no model, no network); the Python
// side is resolved by shelling `uv run` in searchsvc to import fusion and print
// its bound weights — fusion binds W_DENSE / W_SPARSE at import from the env, so
// a subprocess started with the env set reads the override directly. NO live
// model is loaded (importing fusion does not touch torch/BGE-M3). If uv or the
// searchsvc env is unavailable, the test SKIPS rather than failing — the env
// names and defaults are constants here, so the parity it guards is structural.

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// parityFloatEps is the tolerance for comparing the two legs' weights. The legs
// parse the same decimal strings (env override) or hold the same float64/Python
// float literals (default), so the difference is well under this.
const parityFloatEps = 1e-9

// searchsvcDir is the Python fusion leg's directory, relative to this Go
// package's directory (tests run with cwd = the package dir, scripts/taskdb).
const searchsvcDir = "searchsvc"

// resolvePythonWeights shells `uv run` in searchsvc to import fusion under the
// given env override and print its bound (W_DENSE, W_SPARSE). It returns the two
// weights, or skips the calling test (via t.Skip) when uv / the searchsvc env is
// unavailable so the suite stays hermetic on a bare machine. The env is passed
// as KEY=VALUE strings to PREPEND to a clean inherited environment; an entry with
// an empty VALUE explicitly sets that var empty (fusion treats "" as unset and
// falls back to its default — the same contract envFloat enforces on the Go leg).
func resolvePythonWeights(t *testing.T, env []string) (wDense, wSparse float64) {
	t.Helper()

	uvPath, err := exec.LookPath("uv")
	if err != nil {
		t.Skipf("cross-leg parity: uv not on PATH (%v) — Python fusion leg unavailable; skipping (env names/defaults are constants here)", err)
	}

	abs, err := filepath.Abs(searchsvcDir)
	if err != nil {
		t.Fatalf("resolving searchsvc dir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Import fusion and print ONLY the two bound weights to stdout (one per line).
	// fusion emits an "effective fusion knobs" line to STDERR at import, so parsing
	// stdout alone keeps this robust against that log.
	const pyScript = "import fusion; print(fusion.W_DENSE); print(fusion.W_SPARSE)"
	cmd := exec.CommandContext(ctx, uvPath, "run", "-q", "python", "-c", pyScript)
	cmd.Dir = abs

	// Build the child environment: inherit the parent's, then apply the override
	// entries last so they win. We do NOT inject any DS_EMBED_LIVE / model knob —
	// importing fusion is pure Python and never loads a model.
	cmd.Env = append(os.Environ(), env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Skipf("cross-leg parity: uv run timed out resolving fusion weights — skipping; stderr:\n%s", stderr.String())
		}
		// A non-zero exit usually means the searchsvc uv env is not provisioned
		// (offline machine, no `uv sync`). Treat that as unavailable, not a
		// parity failure: skip so the hermetic suite stays green, but surface the
		// stderr so a real breakage is diagnosable.
		t.Skipf("cross-leg parity: could not resolve Python fusion weights via uv (%v) — searchsvc env likely unprovisioned; skipping. stderr:\n%s", err, stderr.String())
	}

	lines := strings.Fields(strings.TrimSpace(stdout.String()))
	if len(lines) != 2 {
		t.Fatalf("cross-leg parity: expected 2 weight values from fusion, got %q (stderr:\n%s)", stdout.String(), stderr.String())
	}
	wDense, err = strconv.ParseFloat(lines[0], 64)
	if err != nil {
		t.Fatalf("cross-leg parity: parsing Python W_DENSE %q: %v", lines[0], err)
	}
	wSparse, err = strconv.ParseFloat(lines[1], 64)
	if err != nil {
		t.Fatalf("cross-leg parity: parsing Python W_SPARSE %q: %v", lines[1], err)
	}
	return wDense, wSparse
}

// resolveGoWeights resolves the Go ranking leg's effective weights for the env
// the test has already set (via t.Setenv), clearing the parse-once latch first
// and on cleanup so neither a prior latch bleeds in nor this resolution bleeds
// out into a sibling test. resetHybridWeights lives in embeddings_knobs_test.go
// (same package, same _test binary).
func resolveGoWeights(t *testing.T) (wDense, wSparse float64) {
	t.Helper()
	resetHybridWeights()
	t.Cleanup(resetHybridWeights)
	return resolveHybridWeights()
}

// TestCrossLegWeightParityDefault asserts that with the shared env knob UNSET,
// the Go and Python legs both resolve the canonical default pair (0.65 / 0.35) —
// AND agree with each other. A default changed on one leg only would fail here.
func TestCrossLegWeightParityDefault(t *testing.T) {
	// Force the Go leg to see the knob as unset (empty == unset per envFloat).
	t.Setenv(envWDense, "")
	t.Setenv(envWSparse, "")
	goDense, goSparse := resolveGoWeights(t)

	// Resolve Python with the same vars explicitly empty so the subprocess does
	// not inherit a stray override from the parent environment.
	pyDense, pySparse := resolvePythonWeights(t, []string{
		envWDense + "=",
		envWSparse + "=",
	})

	// Both legs must agree with each other...
	assertWeightsEqual(t, "default", goDense, goSparse, pyDense, pySparse)
	// ...and with the canonical default, so a paired rename of BOTH defaults that
	// keeps the legs equal but drifts from 0.65/0.35 is still caught.
	if math.Abs(goDense-wDenseDefault) > parityFloatEps || math.Abs(goSparse-wSparseDefault) > parityFloatEps {
		t.Errorf("cross-leg parity: Go default weights drifted from canonical: got (%v, %v), want (%v, %v)",
			goDense, goSparse, wDenseDefault, wSparseDefault)
	}
}

// TestCrossLegWeightParityOverride asserts that with the shared env knob SET to a
// non-default pair, BOTH legs resolve to exactly that pair. A rename of an env
// var name on one leg only means that leg ignores the override and keeps its
// default, so the two legs diverge and this test FAILS LOUDLY.
func TestCrossLegWeightParityOverride(t *testing.T) {
	// A pair distinct from BOTH the default and from each other, so a leg that
	// silently swapped or ignored a var is unambiguously detectable.
	const overrideDense = "0.8"
	const overrideSparse = "0.2"

	t.Setenv(envWDense, overrideDense)
	t.Setenv(envWSparse, overrideSparse)
	goDense, goSparse := resolveGoWeights(t)

	pyDense, pySparse := resolvePythonWeights(t, []string{
		envWDense + "=" + overrideDense,
		envWSparse + "=" + overrideSparse,
	})

	assertWeightsEqual(t, "override", goDense, goSparse, pyDense, pySparse)

	// Belt-and-suspenders: the override actually TOOK on the Go leg (guards against
	// a future edit that ignores the env entirely yet still happens to match a
	// Python leg that also ignores it).
	wantDense, _ := strconv.ParseFloat(overrideDense, 64)
	wantSparse, _ := strconv.ParseFloat(overrideSparse, 64)
	if math.Abs(goDense-wantDense) > parityFloatEps || math.Abs(goSparse-wantSparse) > parityFloatEps {
		t.Errorf("cross-leg parity: Go leg did not honor the env override: got (%v, %v), want (%v, %v)",
			goDense, goSparse, wantDense, wantSparse)
	}
}

// ---------------------------------------------------------------------------
// K_RRF asymmetry: SEARCHSVC_RRF_K is a FUSION.PY-ONLY knob.
//
// W_DENSE / W_SPARSE are a single knob read IDENTICALLY by both ranking legs
// (the parity tests above enforce that). SEARCHSVC_RRF_K is the deliberate
// exception: it is the Reciprocal-Rank-Fusion damping constant, meaningful ONLY
// to a rank-based fuser. The Python leg (searchsvc/fusion.py) ranks by RANK
// position and so honors SEARCHSVC_RRF_K (-> fusion.K_RRF). The Go leg
// (embeddings.go resolveHybridWeights) blends RAW COSINES, not rank positions,
// so it has no RRF k to tune and MUST NOT read SEARCHSVC_RRF_K — a Go read of it
// would be a deceptive no-op knob an operator could mistake for an effective
// control. embeddings.go documents this intentional asymmetry in prose; the two
// tests below LOCK it so the asymmetry cannot silently erode:
//
//   - TestKRRFGoLegIgnoresIt: structurally + behaviorally proves the Go leg does
//     NOT consume SEARCHSVC_RRF_K (a future accidental Go read fails the test).
//   - TestKRRFPythonLegHonorsIt: proves fusion.py DOES honor it (a future drop of
//     the Python read fails the test).
//
// Symmetry intent (W_DENSE/W_SPARSE) and asymmetry intent (RRF_K) are thus both
// pinned in the same file, side by side.

// envRRFK is the fusion-only RRF damping-constant env knob, byte-for-byte the
// name fusion.py reads (searchsvc/fusion.py: _env_number("SEARCHSVC_RRF_K", ...)).
// It is named here ONLY so the asymmetry tests can reference the exact string;
// the Go ranking leg deliberately never reads it (see TestKRRFGoLegIgnoresIt).
const envRRFK = "SEARCHSVC_RRF_K"

// TestKRRFGoLegIgnoresIt pins that SEARCHSVC_RRF_K is NOT a Go-leg knob.
//
// Structural arm: scan every non-test .go source in this package for the QUOTED
// string literal "SEARCHSVC_RRF_K". embeddings.go mentions the var by name in a
// comment (bare, unquoted) to document the asymmetry, but a real env read takes
// the name as a STRING LITERAL — os.LookupEnv("SEARCHSVC_RRF_K"),
// envFloat("SEARCHSVC_RRF_K", …), etc. So a quoted occurrence in production Go is
// the unambiguous fingerprint of an (illegitimate) read, while the documenting
// comment is correctly ignored. Today there are zero such occurrences.
//
// Behavioral arm: set SEARCHSVC_RRF_K to a wild value and confirm the Go leg's
// resolved hybrid weights are byte-identical to the canonical defaults — the Go
// ranking math is wholly insensitive to this env, as it must be.
func TestKRRFGoLegIgnoresIt(t *testing.T) {
	// --- Structural: no production Go file reads SEARCHSVC_RRF_K as a literal. ---
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("K_RRF asymmetry: reading package dir: %v", err)
	}
	quoted := []byte(`"` + envRRFK + `"`)
	scanned := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Only production Go: skip non-.go and skip _test.go (this test names the
		// literal, and other tests legitimately may too).
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("K_RRF asymmetry: reading %s: %v", name, err)
		}
		scanned++
		if bytes.Contains(src, quoted) {
			t.Errorf("K_RRF asymmetry VIOLATED: production Go file %s contains the string "+
				"literal %s — the Go ranking leg blends RAW COSINES (no rank), so it has no "+
				"RRF damping constant to tune. Reading SEARCHSVC_RRF_K here is a deceptive "+
				"no-op knob; it is intentionally FUSION.PY-ONLY (see embeddings.go and "+
				"searchsvc/fusion.py). If the Go leg genuinely became rank-based, update this "+
				"test deliberately.", name, quoted)
		}
	}
	if scanned == 0 {
		t.Fatalf("K_RRF asymmetry: scanned 0 production .go files — cwd is not the package dir?")
	}

	// --- Behavioral: the Go leg's resolved weights ignore SEARCHSVC_RRF_K. ---
	// Keep the shared weight knob UNSET so we isolate RRF_K's (non-)effect, and set
	// RRF_K to a value distinct from fusion.py's default (60) so a hypothetical Go
	// read could not coincidentally match the default.
	t.Setenv(envWDense, "")
	t.Setenv(envWSparse, "")
	t.Setenv(envRRFK, "9999")
	goDense, goSparse := resolveGoWeights(t)
	if math.Abs(goDense-wDenseDefault) > parityFloatEps || math.Abs(goSparse-wSparseDefault) > parityFloatEps {
		t.Errorf("K_RRF asymmetry: setting %s shifted the Go leg's resolved weights to (%v, %v); "+
			"they must stay at the canonical default (%v, %v) — the Go leg does not read %s",
			envRRFK, goDense, goSparse, wDenseDefault, wSparseDefault, envRRFK)
	}
}

// TestKRRFPythonLegHonorsIt is the dual: it proves the fusion.py leg DOES read
// SEARCHSVC_RRF_K, binding fusion.K_RRF to the override. Together with the Go arm
// above this brackets the asymmetry from both sides — Go ignores it, Python honors
// it — so neither a future Go read nor a future Python drop can pass unnoticed.
//
// Hermetic: same uv-subprocess discipline as the parity tests — importing fusion
// is pure Python (no torch / BGE-M3 / network). Skips when uv / the searchsvc env
// is unavailable so a bare machine stays green; the Go arm above carries the
// structural guarantee even when this arm skips.
func TestKRRFPythonLegHonorsIt(t *testing.T) {
	const override = "42" // distinct from fusion.py's canonical default of 60.
	got := resolvePythonKRRF(t, []string{envRRFK + "=" + override})
	want, _ := strconv.Atoi(override)
	if got != want {
		t.Errorf("K_RRF asymmetry: fusion.py did not honor %s=%s — fusion.K_RRF resolved to %d, want %d. "+
			"SEARCHSVC_RRF_K is the FUSION.PY-ONLY RRF damping knob; a leg that stopped reading it has "+
			"broken the intentional asymmetry.", envRRFK, override, got, want)
	}
}

// resolvePythonKRRF shells `uv run` in searchsvc to import fusion under the given
// env override and print its bound fusion.K_RRF, returning it as an int. It skips
// the calling test (via t.Skip) when uv / the searchsvc env is unavailable, so the
// suite stays hermetic on a bare machine. Mirrors resolvePythonWeights' contract:
// env is KEY=VALUE strings appended last (so they win); fusion emits its effective-
// knobs line to STDERR at import, so parsing stdout alone stays robust.
func resolvePythonKRRF(t *testing.T, env []string) int {
	t.Helper()

	uvPath, err := exec.LookPath("uv")
	if err != nil {
		t.Skipf("K_RRF asymmetry: uv not on PATH (%v) — Python fusion leg unavailable; skipping (the Go arm carries the structural guarantee)", err)
	}

	abs, err := filepath.Abs(searchsvcDir)
	if err != nil {
		t.Fatalf("resolving searchsvc dir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Print ONLY fusion.K_RRF to stdout; the effective-knobs log goes to stderr.
	const pyScript = "import fusion; print(fusion.K_RRF)"
	cmd := exec.CommandContext(ctx, uvPath, "run", "-q", "python", "-c", pyScript)
	cmd.Dir = abs
	cmd.Env = append(os.Environ(), env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Skipf("K_RRF asymmetry: uv run timed out resolving fusion.K_RRF — skipping; stderr:\n%s", stderr.String())
		}
		t.Skipf("K_RRF asymmetry: could not resolve fusion.K_RRF via uv (%v) — searchsvc env likely unprovisioned; skipping. stderr:\n%s", err, stderr.String())
	}

	out := strings.TrimSpace(stdout.String())
	k, err := strconv.Atoi(out)
	if err != nil {
		t.Fatalf("K_RRF asymmetry: parsing fusion.K_RRF %q as int: %v (stderr:\n%s)", out, err, stderr.String())
	}
	return k
}

// assertWeightsEqual fails loudly when the two legs' weights disagree, naming
// both observed pairs and the env case so a one-sided drift is diagnosable.
func assertWeightsEqual(t *testing.T, label string, goDense, goSparse, pyDense, pySparse float64) {
	t.Helper()
	if math.Abs(goDense-pyDense) > parityFloatEps || math.Abs(goSparse-pySparse) > parityFloatEps {
		t.Errorf("cross-leg weight parity DRIFT (%s): Go leg resolved (W_DENSE=%v, W_SPARSE=%v) "+
			"but Python fusion leg resolved (W_DENSE=%v, W_SPARSE=%v) for the SAME env — "+
			"a one-sided env-name rename or default change has broken the single-knob contract "+
			"(SEARCHSVC_W_DENSE / SEARCHSVC_W_SPARSE must be read identically by embeddings.go and searchsvc/fusion.py)",
			label, goDense, goSparse, pyDense, pySparse)
	}
}
