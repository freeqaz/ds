// SPDX-License-Identifier: Apache-2.0

// Package onceguard is the SHARED dropped-Once re-drive trap + registry-level
// cached-scan-Once reconciliation the conformance-adapter seam tests use to PIN the
// compute-once discipline ORDER-INDEPENDENTLY.
//
// ORIGIN + WHY SHARED. The trap was first built inline in the resolverlock seam
// (resolverlock/drift_corpus_test.go), where an expensive, deterministic-per-binary
// go/types scan is hoisted behind a package-level sync.Once and shared across
// multiple guards. Pinning that hoist with a bare "the compute counter == 1"
// assertion has a TEST-ORDER blind spot: if every guard calls the cached accessor
// exactly once, whichever runs FIRST sees the counter at 1 even if the Once were
// dropped — a single compute leaves the counter at 1 regardless. The fix is to drive
// the cached scan through MULTIPLE callers WITHIN ONE test and pin two fingerprints a
// dropped Once flips: (1) COUNT STABILITY across a re-drive, and (2) CACHE
// BACKING-SLICE IDENTITY (the same backing array serves both calls). A second hole:
// a purely-SYNTACTIC `var x sync.Once` scan misses alias (`type onceT = sync.Once`)
// and degenerate-initialized (`var x sync.Once = sync.Once{}`) forms — so the
// registry must also reconcile against a TYPE-RESOLVED view.
//
// Rather than hand-copy the trap per seam (where the copies drift), this package
// FACTORS the order-independent re-drive trap (ReDriveStable) and the
// cached-scan-Once AST/registry reconciliation (DeclaredSyncOnceVars +
// ReconcileCachedScanOnceRegistry) once, exported, so every conformance-adapter seam
// consumes the SAME proven trap and the SAME structural reconciliation. The
// resolverlock origin file keeps its own (richer, type-resolved) inline pin; this
// package is the shared home for the OTHER seams (and for the cross-seam,
// AST-syntactic registry sweep).
//
// Test-only support code (synthetic fixtures only, D50). It is an ordinary
// (non-_test) package so any seam's `_test.go` can import and share it; it pulls in
// nothing but the stdlib (go/ast, go/parser, go/token, runtime, sort).
package onceguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
)

// FatalReporter is the narrow {Helper, Fatalf} subset of *testing.T the helpers use,
// so a negative meta-test can drive them with a fatal-CAPTURING recorder (observing
// the guard fires WITHOUT failing the meta-test) while real seam tests pass their
// *testing.T (which satisfies this interface). The variadic uses any to match
// testing.T.Fatalf exactly.
type FatalReporter interface {
	Helper()
	Fatalf(format string, args ...any)
}

// ScanProbe is the cached-scan accessor a ReDriveStable trap drives. Each call must
// return the scan's result length (its non-vacuousness fingerprint), the address of
// the SHARED cache backing element (so a recompute that REASSIGNS the cache is caught
// by a changed address — pass 0/nil-equivalent only when the cache is empty, which
// ReDriveStable treats as a vacuous-result failure), and the current value of the
// compute-once counter incremented INSIDE the Once closure. The accessor MUST drive
// the real cached path (call the production accessor) so a dropped Once recomputes
// here.
type ScanProbe struct {
	// Len is the length of the scan result on this call; a zero length is a vacuous
	// result the trap refuses to pin a compute-once invariant over.
	Len int
	// BackingAddr is a stable identity of the cache's backing storage — typically
	// fmt.Sprintf("%p", &cache.names[0]) captured by the caller. ReDriveStable compares
	// it across the re-drive: a changed address means the second call recomputed and
	// REASSIGNED the cache, i.e. the Once was dropped.
	BackingAddr string
	// ComputeCount is the compute-once counter's current value (incremented inside the
	// Once closure). ReDriveStable asserts it is STABLE across the re-drive and == 1.
	ComputeCount int
}

// ReDriveStable is the ORDER-INDEPENDENT, SELF-CONTAINED dropped-Once trap. It drives
// the cached scan through TWO callers WITHIN this one assertion (via probe, which the
// caller wires to the real production accessor) and pins the fingerprints a dropped
// Once flips, so the trap fires no matter which guard ran first:
//
//   - NON-VACUOUS: both drives must return a non-empty result; an empty re-drive
//     means the compute is broken, and pinning compute-once over a vacuous result
//     would mask a dropped Once.
//   - COUNT STABILITY across the re-drive: the compute counter must be EQUAL before
//     and after the second drive — drop the Once and the second call recomputes,
//     bumping it. AND it must be EXACTLY 1: one compute backs every caller.
//   - CACHE BACKING IDENTITY: the cache backing address must be UNCHANGED across the
//     two drives — a changed address means the second call recomputed and REASSIGNED
//     the cache.
//
// label names the pinned scan for a self-locating failure. probe(callIndex) is called
// twice (0 then 1); each call must drive the real cached accessor and return a fresh
// ScanProbe snapshot. Test-only; synthetic fixtures only (D50).
func ReDriveStable(t FatalReporter, label string, probe func(callIndex int) ScanProbe) {
	t.Helper()

	first := probe(0)
	if first.Len == 0 {
		t.Fatalf("%s: the cached scan returned a VACUOUS (empty) result on the FIRST drive — refusing to assert the compute-once invariant over an empty result, which would mask a dropped Once", label)
	}
	if first.ComputeCount != 1 {
		t.Fatalf("%s: compute-once invariant BROKEN — the compute counter is %d after the first drive, want EXACTLY 1; a count != 1 means the cached scan ran more (or fewer) than once, i.e. the sync.Once was dropped or never fired", label, first.ComputeCount)
	}

	second := probe(1)
	if second.Len == 0 {
		t.Fatalf("%s: the cached scan returned a VACUOUS (empty) result on the SECOND drive — the cached scan must serve a stable non-empty result to every caller; an empty re-drive means the compute is broken", label)
	}
	if second.ComputeCount != first.ComputeCount {
		t.Fatalf("%s: compute-once invariant BROKEN (re-drive) — a SECOND drive bumped the compute counter from %d to %d; the Once must serve the cached result to every caller WITHOUT recomputing. A bump means the sync.Once was dropped (or the compute moved out from under once.Do). This re-drive makes the trap ORDER-INDEPENDENT: it fires no matter which guard ran first", label, first.ComputeCount, second.ComputeCount)
	}
	if second.ComputeCount != 1 {
		t.Fatalf("%s: compute-once invariant BROKEN — after driving the cached scan through TWO callers the compute counter is %d, want EXACTLY 1; any other value means the Once-guarded single compute regressed", label, second.ComputeCount)
	}
	if second.BackingAddr != first.BackingAddr {
		t.Fatalf("%s: compute-once invariant BROKEN (cache identity) — the cache backing address changed across two drives (%s -> %s); the cached result must be the SAME backing storage for every caller. A changed address means the second drive recomputed and REASSIGNED the cache, i.e. the sync.Once was dropped", label, first.BackingAddr, second.BackingAddr)
	}
}

// ── Cached-scan sync.Once AST discovery (the registry-level reconciliation) ──────

// isSyncOnceSelector reports whether an expression is the bare selector `sync.Once`.
// It is the CORE shape every cached-scan-guard form reduces to: the value form IS this
// selector, the pointer form wraps it in a StarExpr, the embedding form carries it as
// an anonymous struct field's type.
func isSyncOnceSelector(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "sync" && sel.Sel.Name == "Once"
}

// structEmbedsSyncOnce reports whether a struct type EMBEDS sync.Once — an ANONYMOUS
// field (empty Names) whose type is the `sync.Once` selector or `*sync.Once`. An
// embedded Once promotes its Do method, so `var g someStruct` with such an embed is a
// cached-scan-guard candidate exactly like a bare `var g sync.Once`. A NAMED field
// (`struct{ once sync.Once }`) does not promote Do and is not the guard var itself.
func structEmbedsSyncOnce(st *ast.StructType) bool {
	if st.Fields == nil {
		return false
	}
	for _, field := range st.Fields.List {
		if len(field.Names) != 0 {
			continue // a named field is not an embed
		}
		switch ft := field.Type.(type) {
		case *ast.SelectorExpr:
			if isSyncOnceSelector(ft) {
				return true
			}
		case *ast.StarExpr:
			if isSyncOnceSelector(ft.X) {
				return true
			}
		}
	}
	return false
}

// isSyncOnceType reports whether a ValueSpec type expression is a cached-scan-GUARD
// candidate built on sync.Once. It recognizes the THREE forms a package-level var can
// use to carry a sync.Once that guards a cached scan, so none slips the registry:
//
//   - VALUE form `var foo sync.Once`: the bare SelectorExpr `sync.Once`;
//   - POINTER form `var foo *sync.Once`: a StarExpr wrapping the selector;
//   - EMBEDDING form `var foo struct{ sync.Once; ... }`: a StructType with an anonymous
//     field whose type is the selector (or a StarExpr over it).
//
// It deliberately does NOT match an ALIASED `sync` import; the three concrete forms
// above are the shapes this syntactic scan covers (a future alias form is the
// type-resolved companion's job, owned by the seam that has such a guard).
func isSyncOnceType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		return isSyncOnceSelector(t)
	case *ast.StarExpr:
		return isSyncOnceSelector(t.X)
	case *ast.StructType:
		return structEmbedsSyncOnce(t)
	default:
		return false
	}
}

// SyncOnceVarKind classifies an *ast.ValueSpec by the sync.Once cached-scan-GUARD
// shape it carries, making the INITIALIZER ground truth EXPLICIT: a purely-syntactic
// scan that matched any non-nil Type and silently relied on "no initializer" would
// sweep a DEGENERATE `var x sync.Once = sync.Once{}` in under an UNSTATED premise. This
// classifier asserts vs.Values == nil for the canonical form and returns the
// initialized form as a DISTINCT kind so the degenerate form is recognized
// DETERMINISTICALLY, not silently.
type SyncOnceVarKind int

const (
	// SyncOnceVarNotAGuard: the spec's declared type is NOT a sync.Once cached-scan-guard
	// shape (or has no explicit type — the `var x = sync.Once{}` form, owned by a
	// type-resolved companion, not this syntactic scan). Skipped.
	SyncOnceVarNotAGuard SyncOnceVarKind = iota
	// SyncOnceVarCanonical: the canonical NO-INITIALIZER guard `var x sync.Once` (or the
	// pointer / embedding forms isSyncOnceType accepts), vs.Values == nil.
	SyncOnceVarCanonical
	// SyncOnceVarDegenerateInitialized: a typed guard carrying an explicit INITIALIZER —
	// `var x sync.Once = sync.Once{}` (non-nil Type isSyncOnceType accepts AND non-nil
	// vs.Values). A real guard the registry must still cover, but flagged as its own kind
	// rather than silently folded into the canonical match.
	SyncOnceVarDegenerateInitialized
)

// ClassifySyncOnceVarSpec is the PURE per-spec decision DeclaredSyncOnceVars makes for
// every package-level var spec: given an *ast.ValueSpec it reports WHICH sync.Once-guard
// shape the spec carries, on two explicit axes — TYPE (non-nil and isSyncOnceType-accepted)
// and INITIALIZER (vs.Values == nil is canonical; vs.Values != nil is degenerate
// initialized). Both guard kinds are CAPTURED (the registry must cover both) but returned
// as DISTINCT kinds so the initialized form is recognized deterministically.
func ClassifySyncOnceVarSpec(vs *ast.ValueSpec) SyncOnceVarKind {
	if vs == nil || vs.Type == nil || !isSyncOnceType(vs.Type) {
		return SyncOnceVarNotAGuard
	}
	if vs.Values != nil {
		return SyncOnceVarDegenerateInitialized
	}
	return SyncOnceVarCanonical
}

// IsDeclaredSyncOnceGuard folds ClassifySyncOnceVarSpec to the boolean
// DeclaredSyncOnceVars needs: TRUE for BOTH the canonical and the degenerate-initialized
// guard kinds (both are real guards the registry must cover), FALSE for a non-guard spec.
func IsDeclaredSyncOnceGuard(vs *ast.ValueSpec) bool {
	return ClassifySyncOnceVarSpec(vs) != SyncOnceVarNotAGuard
}

// DeclaredSyncOnceVars parses the named source file and returns the SORTED set of
// package-level var names whose declared type is a sync.Once cached-scan-GUARD candidate
// (value, pointer, or embedding form; canonical OR degenerate-initialized). Using
// go/parser + go/ast makes discovery STRUCTURAL, not a brittle grep: a guard renamed,
// added, or removed is reflected automatically. A PARSE error is a HARD failure (the
// reconciliation must not vacuously pass over a file that does not parse). Test-only;
// synthetic fixtures / own sources only (D50).
func DeclaredSyncOnceVars(t FatalReporter, srcPath string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("onceguard: parsing %s for the cached-scan sync.Once self-scan: %v (a parse error is a HARD failure — the registry reconciliation must not vacuously pass on a file that does not parse)", srcPath, err)
	}
	var out []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if !IsDeclaredSyncOnceGuard(vs) {
				continue
			}
			// A `var a, b sync.Once` block declares BOTH names with the one type.
			for _, id := range vs.Names {
				out = append(out, id.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// OncePin is one registry row: the compute-once COUNTER var incremented inside the Once
// closure and the GUARD TEST that asserts it == 1. The pairing the registry CLAIMS is
// auditable in one place; an empty field is a meaningless (unverifiable) claim.
type OncePin struct {
	CounterVar string
	GuardTest  string
}

// ReconcileCachedScanOnceRegistry is the FAIL-CLOSED, both-directions reconciliation that
// makes the compute-once discipline SELF-ENFORCING across a set of seam source files. It
// AST-discovers every package-level cached-scan sync.Once guard declared across srcPaths
// (DeclaredSyncOnceVars over each) and reconciles the discovered set against registry:
//
//   - FORWARD: every declared cached-scan Once MUST be registered (an UNPINNED new Once is
//     caught, named, with the remedy spelled out);
//   - REVERSE: every registry row MUST be a declared cached-scan Once (a STALE row after a
//     rename/removal is caught, so the registry cannot rot into a false claim of coverage);
//   - SELF-CONSISTENCY: every registry row must name a non-empty counter var AND guard test.
//
// It reports EVERY violation (t.Fatalf on the first per category is avoided in favour of a
// caller-side accumulation pattern) — but because FatalReporter only exposes Fatalf, this
// helper emits the FIRST violation it finds per the order above and stops; the meta-tests
// drive each category in isolation so each is proven to fire. The discovered set being
// empty is NOT a vacuous pass: an empty registry + empty discovery is the HONEST state of a
// seam with no cached-scan Once, and is allowed; a registry row with no matching declaration
// (reverse) still fails. Test-only; synthetic fixtures / own sources only (D50).
func ReconcileCachedScanOnceRegistry(t FatalReporter, srcPaths []string, registry map[string]OncePin) {
	t.Helper()

	declaredSet := make(map[string]bool)
	var declared []string
	for _, src := range srcPaths {
		for _, name := range DeclaredSyncOnceVars(t, src) {
			if !declaredSet[name] {
				declaredSet[name] = true
				declared = append(declared, name)
			}
		}
	}
	sort.Strings(declared)

	// SELF-CONSISTENCY first, in sorted order for determinism: a row pointing at nothing is
	// a meaningless claim regardless of discovery.
	regNames := make([]string, 0, len(registry))
	for name := range registry {
		regNames = append(regNames, name)
	}
	sort.Strings(regNames)
	for _, name := range regNames {
		pin := registry[name]
		if pin.CounterVar == "" || pin.GuardTest == "" {
			t.Fatalf("onceguard: registry row %q is incomplete — CounterVar=%q GuardTest=%q; a compute-once pin must name BOTH the counter var incremented inside the Once closure and the test that asserts it == 1, or the registry records an empty (unverifiable) claim of coverage", name, pin.CounterVar, pin.GuardTest)
		}
	}

	// FORWARD: every declared cached-scan Once must be registered.
	for _, name := range declared {
		if _, ok := registry[name]; !ok {
			t.Fatalf("onceguard: package-level cached-scan sync.Once %q is declared in the scanned seam sources but is NOT registered — every sync.Once that guards a cached type-aware scan must be paired with a COMPUTE-ONCE COUNTER asserted == 1 and registered here. An unpinned cached-scan Once silently re-introduces the per-caller cost the cache removes, with no test going red. Add a counter incremented INSIDE %s.Do(...), a Test asserting it == 1, and a registry row {%q: {CounterVar, GuardTest}}", name, name, name)
		}
	}

	// REVERSE: every registry row must still be a declared cached-scan Once.
	for _, name := range regNames {
		if !declaredSet[name] {
			t.Fatalf("onceguard: the registry registers %q but the AST self-scan of the seam sources found NO package-level cached-scan sync.Once by that name (declared: %v) — the registry row is STALE (the Once was renamed or removed). Update the registry so it cannot falsely claim compute-once coverage for a Once that no longer exists", name, declared)
		}
	}
}
