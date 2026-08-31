// SPDX-License-Identifier: Apache-2.0
package main

// Hermetic tests for the SINGLE TUNING KNOB shared by the Go ranking leg
// (embeddings.go) and the Python fusion leg (searchsvc/fusion.py): the Go
// hybrid-rank weights are sourced from the SAME env var names fusion.py reads
// (SEARCHSVC_W_DENSE / SEARCHSVC_W_SPARSE), falling back to the SAME canonical
// defaults (0.65 / 0.35), with the same parse-once + loud-fallback discipline.
//
// No model, no network: these exercise the pure-Go weight resolution and its
// effect on hybridScore directly.
//
// Coverage:
//   - TestHybridWeightsDefaultWhenUnset: no env -> canonical 0.65 / 0.35.
//   - TestHybridWeightsEnvOverride: an env override changes the EFFECTIVE Go
//     weights, and that change flows through hybridScore (the override produces a
//     blended score distinct from the default-weight score, and the FULL ordering
//     of two chunks flips when the lexical leg is weighted up).
//   - TestHybridWeightsBadValueLoudFallback: a present-but-unparseable value falls
//     back to the canonical default AND emits a loud line on embedWarnOut.
//   - TestHybridWeightsParseOnce: a mutation after the first resolve does NOT shift
//     the latched weights (parse-once, mirroring fusion.py's import-time bind).

import (
	"bytes"
	"math"
	"strings"
	"sync"
	"testing"
)

// resetHybridWeights clears the parse-once latch so each test resolves the env
// afresh. Reassigning the sync.Once and zeroing the cached values is safe here
// because the package's tests run serially within a process; production never
// resets the latch.
func resetHybridWeights() {
	hybridWeightsOnce = sync.Once{}
	wDenseEffective = 0
	wSparseEffective = 0
}

const floatEps = 1e-9

// withCleanLatch resets the parse-once latch BEFORE the test resolves and again
// on cleanup, so neither a previously-latched value bleeds INTO this test nor this
// test's latched override bleeds OUT into a later test (e.g. embeddings_hybrid's
// default-weight assertions). t.Setenv already restores env on cleanup; this
// restores the resolution latch to match.
func withCleanLatch(t *testing.T) {
	t.Helper()
	resetHybridWeights()
	t.Cleanup(resetHybridWeights)
}

func TestHybridWeightsDefaultWhenUnset(t *testing.T) {
	withCleanLatch(t)
	t.Setenv(envWDense, "")
	t.Setenv(envWSparse, "")
	resetHybridWeights()

	wDense, wSparse := resolveHybridWeights()
	if math.Abs(wDense-wDenseDefault) > floatEps {
		t.Fatalf("wDense default: got %v want %v", wDense, wDenseDefault)
	}
	if math.Abs(wSparse-wSparseDefault) > floatEps {
		t.Fatalf("wSparse default: got %v want %v", wSparse, wSparseDefault)
	}
}

func TestHybridWeightsEnvOverride(t *testing.T) {
	withCleanLatch(t)
	// A query and chunk that SHARE a lexical term so the sparse leg is active.
	qsparse := map[int]float32{1: 1, 2: 1}
	csparse := map[int]float32{1: 1, 2: 1} // identical -> sparseCosine == 1
	const dense = 0.5

	// Effective sparseCosine for identical non-empty maps is exactly 1.0, so the
	// expected hybridScore is wDense*dense + wSparse*1.0 — fully determined by the
	// weights, which lets us assert the override actually moved the score.
	if got := sparseCosine(qsparse, csparse); math.Abs(got-1.0) > floatEps {
		t.Fatalf("precondition: sparseCosine of identical maps = %v want 1.0", got)
	}

	// Default weights.
	t.Setenv(envWDense, "")
	t.Setenv(envWSparse, "")
	resetHybridWeights()
	def := hybridScore(dense, qsparse, csparse)
	wantDef := wDenseDefault*dense + wSparseDefault*1.0
	if math.Abs(def-wantDef) > floatEps {
		t.Fatalf("default hybridScore: got %v want %v", def, wantDef)
	}

	// Override: weight the lexical leg far up, the dense leg down.
	t.Setenv(envWDense, "0.1")
	t.Setenv(envWSparse, "0.9")
	resetHybridWeights()
	wDense, wSparse := resolveHybridWeights()
	if math.Abs(wDense-0.1) > floatEps || math.Abs(wSparse-0.9) > floatEps {
		t.Fatalf("override weights: got (%v,%v) want (0.1,0.9)", wDense, wSparse)
	}
	over := hybridScore(dense, qsparse, csparse)
	wantOver := 0.1*dense + 0.9*1.0
	if math.Abs(over-wantOver) > floatEps {
		t.Fatalf("override hybridScore: got %v want %v", over, wantOver)
	}
	if math.Abs(over-def) <= floatEps {
		t.Fatalf("override produced same score as default (%v) — knob had no effect", over)
	}

	// FULL ordering flip: chunk A is the stronger DENSE match (no lexical overlap),
	// chunk B the weaker dense but PERFECT lexical match. Under default (dense-led)
	// weights A outranks B; under the lexical-led override B overtakes A. Asserting
	// BOTH orderings proves the shared knob steers which signal leads, end to end.
	const denseA = 0.9 // A: great dense, no sparse overlap -> pure dense score
	const denseB = 0.3 // B: weak dense, full lexical overlap (sparseCosine == 1)
	bShared := map[int]float32{1: 1}

	// Default weights: A (dense-led) wins.
	t.Setenv(envWDense, "")
	t.Setenv(envWSparse, "")
	resetHybridWeights()
	scoreA := hybridScore(denseA, nil, nil)
	scoreB := hybridScore(denseB, bShared, bShared)
	if !(scoreA > scoreB) {
		t.Fatalf("default ordering: expected A(%v) > B(%v)", scoreA, scoreB)
	}

	// Lexical-led override: B overtakes A.
	t.Setenv(envWDense, "0.05")
	t.Setenv(envWSparse, "0.95")
	resetHybridWeights()
	scoreA = hybridScore(denseA, nil, nil)
	scoreB = hybridScore(denseB, bShared, bShared)
	if !(scoreB > scoreA) {
		t.Fatalf("lexical-led override ordering: expected B(%v) > A(%v)", scoreB, scoreA)
	}
}

func TestHybridWeightsBadValueLoudFallback(t *testing.T) {
	withCleanLatch(t)
	var buf bytes.Buffer
	saved := embedWarnOut
	embedWarnOut = &buf
	defer func() { embedWarnOut = saved }()

	t.Setenv(envWDense, "not-a-number")
	t.Setenv(envWSparse, "") // valid (unset) -> default
	resetHybridWeights()

	wDense, wSparse := resolveHybridWeights()
	if math.Abs(wDense-wDenseDefault) > floatEps {
		t.Fatalf("bad value should fall back: got wDense %v want %v", wDense, wDenseDefault)
	}
	if math.Abs(wSparse-wSparseDefault) > floatEps {
		t.Fatalf("wSparse: got %v want %v", wSparse, wSparseDefault)
	}
	out := buf.String()
	if !strings.Contains(out, envWDense) || !strings.Contains(out, "not-a-number") {
		t.Fatalf("expected a loud fallback line naming %s and the bad value; got %q", envWDense, out)
	}
}

func TestHybridWeightsParseOnce(t *testing.T) {
	withCleanLatch(t)
	t.Setenv(envWDense, "0.2")
	t.Setenv(envWSparse, "0.8")
	resetHybridWeights()

	wDense1, wSparse1 := resolveHybridWeights()
	if math.Abs(wDense1-0.2) > floatEps || math.Abs(wSparse1-0.8) > floatEps {
		t.Fatalf("first resolve: got (%v,%v) want (0.2,0.8)", wDense1, wSparse1)
	}

	// Mutate the env AFTER the first resolve. Parse-once must ignore it.
	t.Setenv(envWDense, "0.99")
	t.Setenv(envWSparse, "0.01")
	wDense2, wSparse2 := resolveHybridWeights()
	if math.Abs(wDense2-0.2) > floatEps || math.Abs(wSparse2-0.8) > floatEps {
		t.Fatalf("parse-once violated: post-mutation resolve gave (%v,%v), want latched (0.2,0.8)", wDense2, wSparse2)
	}
}
