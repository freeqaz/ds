// SPDX-License-Identifier: Apache-2.0

package onceguard_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/assurance/conformance-adapter/onceguard"
)

// fatalCapture is an onceguard.FatalReporter that records the FIRST Fatalf and unwinds
// via runtime.Goexit (mirroring *testing.T.Fatalf) so a guard-under-test stops at the
// fatal site. Driven on its OWN goroutine (run*) so the Goexit unwinds only that
// goroutine; the meta-test stays green when the guard fires as expected.
type fatalCapture struct {
	fired bool
	msg   string
}

func (c *fatalCapture) Helper() {}

func (c *fatalCapture) Fatalf(format string, args ...any) {
	c.fired = true
	c.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func runCapturing(fn func(fr onceguard.FatalReporter)) *fatalCapture {
	fc := &fatalCapture{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(fc)
	}()
	<-done
	return fc
}

// ── ReDriveStable trap ───────────────────────────────────────────────────────────

// TestReDriveStable_PassesOnAHealthyOnce is the POSITIVE control: a probe modeling a
// healthy compute-once cache (counter pinned at 1, same backing address both drives,
// non-empty) must NOT fire. Without it the negative cases could pass merely because
// the trap fires unconditionally.
func TestReDriveStable_PassesOnAHealthyOnce(t *testing.T) {
	probe := func(callIndex int) onceguard.ScanProbe {
		return onceguard.ScanProbe{Len: 3, BackingAddr: "0xCAFE", ComputeCount: 1}
	}
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReDriveStable(fr, "healthy", probe)
	})
	if got.fired {
		t.Fatalf("ReDriveStable fired on a HEALTHY once (count==1 both drives, stable backing): %s", got.msg)
	}
}

// TestReDriveStable_CatchesADroppedOnceByCountBump is the load-bearing trap: a dropped
// Once recomputes on the SECOND drive, bumping the compute counter. The trap must fire
// regardless of which guard ran first (order-independence).
func TestReDriveStable_CatchesADroppedOnceByCountBump(t *testing.T) {
	// Model a dropped Once: each drive recomputes, so the counter increments per call.
	count := 0
	probe := func(callIndex int) onceguard.ScanProbe {
		count++ // a healthy Once would NOT recompute on the second drive
		return onceguard.ScanProbe{Len: 3, BackingAddr: "0xCAFE", ComputeCount: count}
	}
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReDriveStable(fr, "dropped-count", probe)
	})
	if !got.fired {
		t.Fatalf("ReDriveStable did NOT fire on a dropped Once whose compute counter bumps across the re-drive")
	}
	if !strings.Contains(got.msg, "re-drive") && !strings.Contains(got.msg, "EXACTLY 1") {
		t.Fatalf("dropped-count fatal was not the compute-once diagnostic: %q", got.msg)
	}
}

// TestReDriveStable_CatchesADroppedOnceByCacheReassignment proves the cache-identity
// fingerprint: a dropped Once REASSIGNS the cache on the second drive (the counter
// happens to stay 1 in this model, isolating the address axis), caught by a changed
// backing address.
func TestReDriveStable_CatchesADroppedOnceByCacheReassignment(t *testing.T) {
	addrs := []string{"0xAAAA", "0xBBBB"} // a reassigned cache on the second drive
	probe := func(callIndex int) onceguard.ScanProbe {
		return onceguard.ScanProbe{Len: 3, BackingAddr: addrs[callIndex], ComputeCount: 1}
	}
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReDriveStable(fr, "dropped-cache", probe)
	})
	if !got.fired {
		t.Fatalf("ReDriveStable did NOT fire on a dropped Once that reassigned the cache backing storage")
	}
	if !strings.Contains(got.msg, "cache identity") {
		t.Fatalf("dropped-cache fatal was not the cache-identity diagnostic: %q", got.msg)
	}
}

// TestReDriveStable_RefusesAVacuousResult proves the no-vacuous-pass guard: an empty
// scan result must FAIL rather than letting the compute-once invariant be asserted over
// nothing (which would mask a dropped Once).
func TestReDriveStable_RefusesAVacuousResult(t *testing.T) {
	probe := func(callIndex int) onceguard.ScanProbe {
		return onceguard.ScanProbe{Len: 0, BackingAddr: "0xCAFE", ComputeCount: 1}
	}
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReDriveStable(fr, "vacuous", probe)
	})
	if !got.fired {
		t.Fatalf("ReDriveStable did NOT fire on a VACUOUS (empty) scan result")
	}
	if !strings.Contains(got.msg, "VACUOUS") {
		t.Fatalf("vacuous fatal was not the no-vacuous-pass diagnostic: %q", got.msg)
	}
}

// TestReDriveStable_CatchesANeverFiredCompute proves the first-drive count guard: a
// counter != 1 on the first drive (the Once never fired, or fired more than once) is
// caught immediately.
func TestReDriveStable_CatchesANeverFiredCompute(t *testing.T) {
	probe := func(callIndex int) onceguard.ScanProbe {
		return onceguard.ScanProbe{Len: 3, BackingAddr: "0xCAFE", ComputeCount: 0}
	}
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReDriveStable(fr, "never-fired", probe)
	})
	if !got.fired {
		t.Fatalf("ReDriveStable did NOT fire when the compute counter is 0 on the first drive")
	}
	if !strings.Contains(got.msg, "EXACTLY 1") {
		t.Fatalf("never-fired fatal was not the count diagnostic: %q", got.msg)
	}
}

// ── AST classification ─────────────────────────────────────────────────────────────

// firstValueSpec parses a synthetic one-var source snippet and returns its FIRST
// package-level *ast.ValueSpec. Test-only (D50): in-memory snippet, no real file.
func firstValueSpec(t *testing.T, src string) *ast.ValueSpec {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parsing synthetic snippet %q: %v", src, err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok {
				return vs
			}
		}
	}
	t.Fatalf("synthetic snippet %q declared no package-level var spec", src)
	return nil
}

// TestClassifySyncOnceVarSpec pins the INITIALIZER ground truth: the degenerate
// `var x sync.Once = sync.Once{}` form is recognized DETERMINISTICALLY as its own kind,
// not silently swept into the canonical match. Drives synthetic snippets over every axis.
func TestClassifySyncOnceVarSpec(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		want      onceguard.SyncOnceVarKind
		wantGuard bool
	}{
		{"canonical value", "package p\nimport \"sync\"\nvar x sync.Once", onceguard.SyncOnceVarCanonical, true},
		{"canonical pointer", "package p\nimport \"sync\"\nvar x *sync.Once", onceguard.SyncOnceVarCanonical, true},
		{"canonical embedding", "package p\nimport \"sync\"\nvar x struct{ sync.Once }", onceguard.SyncOnceVarCanonical, true},
		{"degenerate initialized value", "package p\nimport \"sync\"\nvar x sync.Once = sync.Once{}", onceguard.SyncOnceVarDegenerateInitialized, true},
		{"degenerate initialized pointer", "package p\nimport \"sync\"\nvar x *sync.Once = &sync.Once{}", onceguard.SyncOnceVarDegenerateInitialized, true},
		{"nil-type initialized (type-resolved owns it)", "package p\nimport \"sync\"\nvar x = sync.Once{}", onceguard.SyncOnceVarNotAGuard, false},
		{"non-Once typed", "package p\nvar x int", onceguard.SyncOnceVarNotAGuard, false},
		{"non-Once typed-and-initialized", "package p\nvar x int = 7", onceguard.SyncOnceVarNotAGuard, false},
		{"named field is not an embed", "package p\nimport \"sync\"\nvar x struct{ once sync.Once }", onceguard.SyncOnceVarNotAGuard, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vs := firstValueSpec(t, tc.src)
			if got := onceguard.ClassifySyncOnceVarSpec(vs); got != tc.want {
				t.Fatalf("ClassifySyncOnceVarSpec(%q) = %d, want %d", tc.src, got, tc.want)
			}
			if got := onceguard.IsDeclaredSyncOnceGuard(vs); got != tc.wantGuard {
				t.Fatalf("IsDeclaredSyncOnceGuard(%q) = %v, want %v", tc.src, got, tc.wantGuard)
			}
		})
	}
}

// writeSyntheticFile writes src to a temp .go file and returns its path. The temp dir
// is cleaned by the testing framework. Synthetic fixtures only (D50).
func writeSyntheticFile(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "synthetic_test.go")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	return p
}

// TestDeclaredSyncOnceVars_DiscoversEveryForm proves the AST scan finds value, pointer,
// embedding, and degenerate-initialized cached-scan Once guards (sorted), and SKIPS a
// named field and a non-Once var.
func TestDeclaredSyncOnceVars_DiscoversEveryForm(t *testing.T) {
	src := "package p\n" +
		"import \"sync\"\n" +
		"var aValue sync.Once\n" +
		"var bPointer *sync.Once\n" +
		"var cEmbed struct{ sync.Once }\n" +
		"var dInit sync.Once = sync.Once{}\n" +
		"var notAGuard int\n" +
		"var namedField struct{ once sync.Once }\n"
	p := writeSyntheticFile(t, src)
	got := onceguard.DeclaredSyncOnceVars(t, p)
	want := []string{"aValue", "bPointer", "cEmbed", "dInit"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("DeclaredSyncOnceVars = %v, want %v", got, want)
	}
}

// TestDeclaredSyncOnceVars_HardFailsOnAParseError proves the no-vacuous-pass discipline:
// a file that does not parse is a HARD failure, not an empty (vacuous) discovery.
func TestDeclaredSyncOnceVars_HardFailsOnAParseError(t *testing.T) {
	p := writeSyntheticFile(t, "package p\nvar x sync.Once = (((\n") // unbalanced — will not parse
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.DeclaredSyncOnceVars(fr, p)
	})
	if !got.fired {
		t.Fatalf("DeclaredSyncOnceVars did NOT hard-fail on a non-parsing file — a parse error must not yield a vacuous empty discovery")
	}
	if !strings.Contains(got.msg, "parse error") {
		t.Fatalf("parse-failure fatal was not the parse diagnostic: %q", got.msg)
	}
}

// ── Registry reconciliation ────────────────────────────────────────────────────────

// TestReconcile_PassesOnAMatchedRegistry is the POSITIVE control: a registry that
// exactly covers the discovered cached-scan Onces (and whose rows are complete) passes.
func TestReconcile_PassesOnAMatchedRegistry(t *testing.T) {
	p := writeSyntheticFile(t, "package p\nimport \"sync\"\nvar scanOnce sync.Once\n")
	reg := map[string]onceguard.OncePin{
		"scanOnce": {CounterVar: "scanComputeCount", GuardTest: "TestScanRunsOnce"},
	}
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReconcileCachedScanOnceRegistry(fr, []string{p}, reg)
	})
	if got.fired {
		t.Fatalf("Reconcile fired on a fully-matched registry: %s", got.msg)
	}
}

// TestReconcile_PassesOnAnHonestlyEmptySeam proves an empty registry + empty discovery
// (a seam with NO cached-scan Once) is the HONEST state, allowed without a vacuous-skip.
func TestReconcile_PassesOnAnHonestlyEmptySeam(t *testing.T) {
	p := writeSyntheticFile(t, "package p\nvar notAOnce int\n")
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReconcileCachedScanOnceRegistry(fr, []string{p}, map[string]onceguard.OncePin{})
	})
	if got.fired {
		t.Fatalf("Reconcile fired on an honestly-empty seam (no cached-scan Once, empty registry): %s", got.msg)
	}
}

// TestReconcile_CatchesAnUnpinnedOnce is the FORWARD direction: a cached-scan Once
// declared but NOT registered fails LOUDLY, naming it.
func TestReconcile_CatchesAnUnpinnedOnce(t *testing.T) {
	p := writeSyntheticFile(t, "package p\nimport \"sync\"\nvar unpinnedOnce sync.Once\n")
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReconcileCachedScanOnceRegistry(fr, []string{p}, map[string]onceguard.OncePin{})
	})
	if !got.fired {
		t.Fatalf("Reconcile did NOT fire on an UNPINNED cached-scan Once (declared, not registered)")
	}
	if !strings.Contains(got.msg, "unpinnedOnce") || !strings.Contains(got.msg, "NOT registered") {
		t.Fatalf("forward fatal did not name the unpinned Once: %q", got.msg)
	}
}

// TestReconcile_CatchesAStaleRow is the REVERSE direction: a registry row with no
// matching declaration (a renamed/removed Once) fails LOUDLY, so the registry cannot rot
// into a false claim of coverage.
func TestReconcile_CatchesAStaleRow(t *testing.T) {
	p := writeSyntheticFile(t, "package p\nvar notAOnce int\n") // no sync.Once at all
	reg := map[string]onceguard.OncePin{
		"goneOnce": {CounterVar: "goneCount", GuardTest: "TestGoneRunsOnce"},
	}
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReconcileCachedScanOnceRegistry(fr, []string{p}, reg)
	})
	if !got.fired {
		t.Fatalf("Reconcile did NOT fire on a STALE registry row (registered but not declared)")
	}
	if !strings.Contains(got.msg, "goneOnce") || !strings.Contains(got.msg, "STALE") {
		t.Fatalf("reverse fatal did not name the stale row: %q", got.msg)
	}
}

// TestReconcile_CatchesAnIncompleteRow is the SELF-CONSISTENCY direction: a registry row
// missing its counter var or guard test is an unverifiable claim and fails LOUDLY.
func TestReconcile_CatchesAnIncompleteRow(t *testing.T) {
	p := writeSyntheticFile(t, "package p\nimport \"sync\"\nvar scanOnce sync.Once\n")
	reg := map[string]onceguard.OncePin{
		"scanOnce": {CounterVar: "", GuardTest: "TestScanRunsOnce"}, // missing counter
	}
	got := runCapturing(func(fr onceguard.FatalReporter) {
		onceguard.ReconcileCachedScanOnceRegistry(fr, []string{p}, reg)
	})
	if !got.fired {
		t.Fatalf("Reconcile did NOT fire on an INCOMPLETE registry row (empty CounterVar)")
	}
	if !strings.Contains(got.msg, "incomplete") {
		t.Fatalf("self-consistency fatal was not the incomplete-row diagnostic: %q", got.msg)
	}
}
