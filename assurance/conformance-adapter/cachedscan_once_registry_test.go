// SPDX-License-Identifier: Apache-2.0

package conformanceadapter

// cachedscan_once_registry_test.go is the CROSS-SEAM, registry-level assertion that
// every cached-scan sync.Once carrying an expensive deterministic-per-binary type-aware
// scan across the conformance-adapter seams (OTHER than resolverlock) is paired with a
// strengthened, ORDER-INDEPENDENT compute-once pin — the shared sibling of the inline
// pin resolverlock owns for its own file (resolverlock/drift_corpus_test.go's
// TestCachedScanOncesAreComputeOncePinned + the alias/init arm).
//
// The reconciliation machinery is FACTORED into the shared onceguard package
// (assurance/conformance-adapter/onceguard) so the trap + the AST/registry sweep are
// declared once and cannot drift between seams; this file is the cross-seam APPLICATION:
// it points the shared sweep at the conformance-adapter seam sources EXCLUDING
// resolverlock and onceguard's own self-tests, and reconciles the discovered cached-scan
// Onces against cachedScanOnceRegistry below.
//
// TODAY the honest discovery over those seams is EMPTY: the only sync.Once outside
// resolverlock is recordingSuspendSignaler.once in tlsproxy_http_policy_test.go — a
// one-shot SIGNAL Once (it closes a channel once), NOT a cached-scan compute-once guard,
// and it is a struct FIELD, not a package-level var, so the AST scan (which keys on
// package-level var declarations) does not see it. An empty registry + empty discovery is
// the HONEST state the reconciliation allows (no vacuous skip). The value is
// FORWARD-LOOKING: the moment a future seam hoists an expensive type-aware scan behind a
// package-level sync.Once WITHOUT a compute-once counter + registry row, this sweep fails
// LOUDLY, naming the offending var — the same self-enforcing discipline resolverlock
// already carries for its own file, now extended across the sibling seams.
//
// Test-only, in-process, offline (D50): it reads the seam sources via a
// runtime.Caller-anchored directory walk and go/parser, touches NO production-crate file,
// and adds NO dependency.

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/assurance/conformance-adapter/onceguard"
)

// cachedScanOneRegistryExclusions are the conformance-adapter subdirectories the
// cross-seam sweep deliberately does NOT scan:
//   - resolverlock: owns its OWN inline cached-scan-Once pin (the origin); the shared
//     sweep is for the OTHER seams, and double-covering resolverlock would duplicate the
//     pin this unit deliberately FACTORS rather than copies.
//   - onceguard: the shared helper's own self-tests parse SYNTHETIC sync.Once snippets
//     (string literals + temp files) to prove the trap fires; they are not real
//     conformance-adapter seam guards and must not be reconciled as such.
var cachedScanOneRegistryExclusions = map[string]bool{
	"resolverlock": true,
	"onceguard":    true,
}

// cachedScanOnceRegistry is the REGISTRY of every package-level cached-scan sync.Once
// guard across the conformance-adapter seams OTHER than resolverlock, each paired with the
// compute-once COUNTER var and the GUARD TEST that asserts it == 1. It is EMPTY today: no
// such guard exists outside resolverlock (see the file header). A future cached-scan Once
// in any swept seam MUST add a row here (and a counter==1 pin) or
// TestCachedScanOncesAcrossSeamsAreComputeOncePinned fails, naming it.
var cachedScanOnceRegistry = map[string]onceguard.OncePin{}

// conformanceAdapterRootDir returns the absolute path of the conformance-adapter module
// root, anchored off THIS test file's location via runtime.Caller so the seam walk works
// under `go test` from any cwd (the same cwd-independent technique resolverlock uses).
func conformanceAdapterRootDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed — cannot locate this test source to anchor the cross-seam sync.Once sweep")
	}
	return filepath.Dir(thisFile)
}

// sweptSeamGoSources walks the conformance-adapter module root and returns the SORTED set
// of .go source files to reconcile: the root-level .go files PLUS every non-excluded seam
// subdirectory's .go files. resolverlock and onceguard (per cachedScanOneRegistryExclusions)
// are skipped. A walk/read failure is a HARD error so the sweep never vacuously passes over
// a directory it could not read.
func sweptSeamGoSources(t *testing.T) []string {
	t.Helper()
	root := conformanceAdapterRootDir(t)

	rootEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading the conformance-adapter root %s for the cross-seam sync.Once sweep: %v (a read failure is a HARD failure — the sweep must not vacuously pass)", root, err)
	}

	var sources []string
	for _, e := range rootEntries {
		name := e.Name()
		if e.IsDir() {
			if cachedScanOneRegistryExclusions[name] {
				continue
			}
			subDir := filepath.Join(root, name)
			subEntries, serr := os.ReadDir(subDir)
			if serr != nil {
				t.Fatalf("reading seam dir %s for the cross-seam sync.Once sweep: %v (a read failure is a HARD failure)", subDir, serr)
			}
			for _, se := range subEntries {
				if se.IsDir() || !strings.HasSuffix(se.Name(), ".go") {
					continue
				}
				sources = append(sources, filepath.Join(subDir, se.Name()))
			}
			continue
		}
		// Root-level .go files (incl. this one and tlsproxy_http_policy_test.go).
		if strings.HasSuffix(name, ".go") {
			sources = append(sources, filepath.Join(root, name))
		}
	}
	sort.Strings(sources)
	return sources
}

// TestCachedScanOncesAcrossSeamsAreComputeOncePinned is the cross-seam application of the
// shared onceguard registry reconciliation. It sweeps every conformance-adapter seam
// source OTHER than resolverlock + onceguard, AST-discovers every package-level cached-scan
// sync.Once guard, and reconciles the discovered set against cachedScanOnceRegistry — both
// directions (forward: every declared cached-scan Once is registered; reverse: every
// registry row is declared; self-consistency: every row names a counter + guard test).
//
// NO-VACUOUS-PASS ANCHOR: the sweep MUST actually have parsed a non-trivial set of seam
// sources. An empty file list would mean the runtime.Caller anchor or the directory walk
// broke, in which case an empty discovery would let an UNPINNED cached-scan Once slip
// through unseen. The anchor pins that the walk found the known root file
// (tlsproxy_http_policy_test.go), so a structural regression cannot silently blind the
// sweep.
func TestCachedScanOncesAcrossSeamsAreComputeOncePinned(t *testing.T) {
	sources := sweptSeamGoSources(t)

	// ANCHOR: the walk must have found the known root seam source. A zero/short result is a
	// structural regression, not a clean bill of health.
	const anchorFile = "tlsproxy_http_policy_test.go"
	foundAnchor := false
	for _, src := range sources {
		if filepath.Base(src) == anchorFile {
			foundAnchor = true
			break
		}
	}
	if !foundAnchor {
		t.Fatalf("the cross-seam sweep parsed %d sources %v but NOT the known root seam file %q — the runtime.Caller anchor or the directory walk regressed, so an empty discovery could mask an UNPINNED cached-scan Once. Restore the walk", len(sources), sources, anchorFile)
	}

	// Reconcile the discovered cached-scan Onces against the registry (fail-closed, both
	// directions). Today this passes over an empty discovery + empty registry (the honest
	// state); it fires the moment a swept seam adds an unpinned cached-scan Once.
	onceguard.ReconcileCachedScanOnceRegistry(t, sources, cachedScanOnceRegistry)
}
