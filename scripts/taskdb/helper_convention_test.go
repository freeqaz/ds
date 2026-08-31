// SPDX-License-Identifier: Apache-2.0
package main

// TestHelperConvention and TestSharedHelperConvention are static lint checks
// enforced as Go tests.
//
// RULE 1 (t.Helper misuse): t.Helper() must NOT appear directly in the body
// of a top-level TestXxx(t *testing.T) function. It belongs in named non-Test
// helper functions (which legitimately call t.Helper() so that failure lines
// point at the call-site rather than the helper body).
//
// Rationale: a t.Helper() directly inside a Test* func implies the func is
// treated as a shared helper, which is a misuse — Test* funcs are entry
// points, not helpers. The violation was historically found in
// TestThawRestoreClaimsIndexMatchesTestFuncs and removed in wave17b
// (thelper-cleanup); this check prevents it from recurring.
//
// RULE 2 (shared-helper misuse): A top-level TestXxx function must not be
// called from within another top-level TestXxx function body. Calling a
// Test* func from another Test* func makes the callee act as a shared helper
// — a misuse of the Test* naming convention. Such helpers must be renamed to
// a lowercase non-Test function and optionally call t.Helper().
//
// Rationale: the Go testing framework calls Test* functions directly; a
// Test* func invoked from sibling code is not a test entry point, it is a
// helper with a misleading name. Rule 1 catches the symptom (t.Helper()); Rule
// 2 catches the direct structural misuse earlier, regardless of whether
// t.Helper() is present.
//
// IMPORTANT DESIGN NUANCE — nested func literals:
// Both rules share a FuncLit-boundary guard. A t.Helper() or a Test* call
// inside a closure defined *within* a Test func (e.g.
//   assertLock := func(label string) { t.Helper(); ... }
// at thaw_test.go:686 inside TestThawLockSurvivesThaw) is LEGITIMATE: the
// closure itself acts as an anonymous helper. When walking a top-level Test
// func's AST, we do NOT descend into nested *ast.FuncLit nodes. Only the
// Test func's own immediate statement list is checked.
//
// RULE 2 HARDENING — subtest closures and go/defer dispatch:
// The blanket FuncLit guard above is correct for *anonymous-helper* closures
// (the assertLock exemption is load-bearing and must hold), but it created two
// blind spots for Rule 2's shared-helper detection:
//
//  1. `t.Run(name, func(t *testing.T) { TestXxx(t) })` — a subtest closure is
//     NOT an anonymous helper; it is a directly-dispatched test body. A Test*
//     call inside it is the same shared-helper misuse as a bare call in the
//     parent body, just one t.Run frame down. We therefore descend into the
//     FuncLit that is the final argument of a `*.Run(name, fn)` call (and only
//     that one — `subtestRunBody` keys on the `.Run` selector + trailing
//     FuncLit, so the assertLock AssignStmt-RHS FuncLit is never touched).
//
//  2. `go TestXxx(t)` / `defer TestXxx(t)` — the callee is a bare Test* ident,
//     so the call dispatches the named Test func as a goroutine/deferred
//     helper. stmtTestCalls now inspects GoStmt/DeferStmt's Call.Fun for a
//     bare Test* identifier. We deliberately do NOT descend into an
//     *immediately-invoked* FuncLit inside go/defer (`go func(){ TestXxx(t) }()`),
//     keeping that consistent with the anonymous-closure exemption.
//
// This hardening is additive for Rule 2 only (the t.Helper() walk for Rule 1
// keeps its original GoStmt/DeferStmt/FuncLit skips — t.Helper() inside a
// go/defer/subtest closure binds to that nested frame and is legitimate).
//
// RULE 2 HARDENING — indirect shared-helper aliasing:
// The detection above keys on an *ast.CallExpr whose .Fun is a bare Test*
// ident (TestXxx(t)). That still missed two indirect forms in which a Test*
// func is consumed as a *value* rather than called directly:
//
//  1. `h := TestXxx; h(t)` — the Test* func is bound to a local variable and
//     the variable is then invoked. The invocation `h(t)` is a call through a
//     non-Test ident, so testCallName never sees it; the misuse signal is the
//     reference `TestXxx` on the AssignStmt RHS.
//
//  2. `t.Run(name, TestXxx)` — the Test* func is passed as a *named func
//     value* (the trailing argument is an *ast.Ident, not a closure literal).
//     subtestRunBody only descends into a trailing *ast.FuncLit, so a named
//     func value slips past it; again the misuse signal is the `TestXxx`
//     reference, here as a call argument.
//
// Both reduce to the same observable: a top-level Test* function name appearing
// as a VALUE (not as the direct .Fun of a call) somewhere in a Test func body.
// collectTestValueRefs detects exactly that — a bare Test* ident used as a
// value — and is wired into the AssignStmt-RHS and call-argument scan. It does
// NOT descend into *ast.FuncLit bodies, so legitimate higher-order plumbing
// that passes an *anonymous* closure (`t.Run(name, func(t *testing.T){...})`,
// `h := func(){...}`) stays exempt: a closure literal is not a Test* ident.
// A verified scan of the real tree finds ZERO Test* funcs used as a value, so
// this addition keeps the production lint green while closing the gap.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// isTopLevelTestFunc returns true if the given FuncDecl has the shape
// TestXxx(t *testing.T) — name starts with "Test", exactly one parameter,
// and the parameter type is *testing.T.
func isTopLevelTestFunc(fn *ast.FuncDecl) bool {
	if fn.Name == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
		return false
	}
	if fn.Type == nil || fn.Type.Params == nil {
		return false
	}
	fields := fn.Type.Params.List
	if len(fields) != 1 {
		return false
	}
	star, ok := fields[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "testing" && sel.Sel.Name == "T"
}

// containsHelperCallDirect inspects a list of statements for a direct
// t.Helper() call expression statement. It does NOT recurse into nested
// *ast.FuncLit nodes, so closures that call t.Helper() inside a Test func
// body are not flagged.
func containsHelperCallDirect(stmts []ast.Stmt) bool {
	for _, stmt := range stmts {
		if found := stmtHasHelperCall(stmt); found {
			return true
		}
	}
	return false
}

// stmtHasHelperCall looks for a t.Helper() call at the top level of a single
// statement. Compound statements (if/for/switch/select/etc.) are walked
// shallowly; func literals encountered anywhere stop the descent for that
// branch (their contents are out-of-scope for this check).
func stmtHasHelperCall(stmt ast.Stmt) bool {
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		return isHelperCall(s.X)

	case *ast.BlockStmt:
		if s != nil {
			return containsHelperCallDirect(s.List)
		}

	case *ast.IfStmt:
		// Check init, body, and else branch — a t.Helper() inside any branch of
		// an if statement that's directly in a Test func body is still a violation.
		if s.Init != nil && stmtHasHelperCall(s.Init) {
			return true
		}
		if s.Body != nil && containsHelperCallDirect(s.Body.List) {
			return true
		}
		if s.Else != nil && stmtHasHelperCall(s.Else) {
			return true
		}

	case *ast.ForStmt:
		if s.Body != nil && containsHelperCallDirect(s.Body.List) {
			return true
		}

	case *ast.RangeStmt:
		if s.Body != nil && containsHelperCallDirect(s.Body.List) {
			return true
		}

	case *ast.SwitchStmt:
		if s.Body != nil && containsHelperCallDirect(s.Body.List) {
			return true
		}

	case *ast.CaseClause:
		return containsHelperCallDirect(s.Body)

	case *ast.TypeSwitchStmt:
		if s.Body != nil && containsHelperCallDirect(s.Body.List) {
			return true
		}

	case *ast.SelectStmt:
		if s.Body != nil && containsHelperCallDirect(s.Body.List) {
			return true
		}

	case *ast.CommClause:
		return containsHelperCallDirect(s.Body)

	case *ast.AssignStmt:
		// e.g.   x := func(){ t.Helper() }  — the RHS is a FuncLit; stop here.
		// We intentionally skip descending into RHS FuncLit values so that
		// anonymous closure helpers are not flagged.
		// (Nothing on the LHS can be a t.Helper() call.)

	case *ast.ReturnStmt:
		// No t.Helper() call appears in a return statement in practice; skip.

	case *ast.GoStmt:
		// go func(){ t.Helper() }() — treat as nested func scope; skip.

	case *ast.DeferStmt:
		// defer func(){ t.Helper() }() — treat as nested func scope; skip.
	}
	return false
}

// isHelperCall returns true if expr is the call expression `t.Helper()`,
// where "t" is any identifier (typically the testing.T parameter name).
// We match on the selector name "Helper" and zero arguments; we do not
// constrain the receiver name so renamed parameters (e.g. `tb`) are also
// caught.
func isHelperCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	if len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Helper"
}

// collectTestFuncNames returns a set of all top-level TestXxx function names
// declared across all provided parsed files.
func collectTestFuncNames(files []*ast.File) map[string]bool {
	names := make(map[string]bool)
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if isTopLevelTestFunc(fn) {
				names[fn.Name.Name] = true
			}
		}
	}
	return names
}

// collectTestCallsDirect searches stmts for direct calls to any function whose
// name appears in testNames. It does NOT descend into nested *ast.FuncLit
// nodes (FuncLit-boundary guard, same as the t.Helper() check).
// It returns the names of all Test* funcs called directly.
func collectTestCallsDirect(stmts []ast.Stmt, testNames map[string]bool) []string {
	var found []string
	for _, stmt := range stmts {
		found = append(found, stmtTestCalls(stmt, testNames)...)
	}
	return found
}

// stmtTestCalls looks for bare calls to Test* functions at the top level of a
// single statement. Compound statements are walked shallowly; func literals
// stop the descent (FuncLit-boundary guard).
func stmtTestCalls(stmt ast.Stmt, testNames map[string]bool) []string {
	var found []string
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		if name := testCallName(s.X, testNames); name != "" {
			found = append(found, name)
		}
		// Rule 2 hardening: descend into a subtest closure, i.e. the trailing
		// FuncLit of a `t.Run(name, func(t *testing.T){...})` call. A subtest
		// body is a dispatched test, not an anonymous helper, so a Test* call
		// inside it is the same shared-helper misuse one t.Run frame down.
		// subtestRunBody keys strictly on the `.Run` selector + trailing
		// FuncLit, so the assertLock AssignStmt-RHS FuncLit stays exempt.
		if body := subtestRunBody(s.X); body != nil {
			found = append(found, collectTestCallsDirect(body.List, testNames)...)
		}
		// Rule 2 indirect-aliasing hardening: catch a Test* func passed as a
		// named func VALUE (e.g. `t.Run(name, TestXxx)`), where the trailing
		// arg is a bare Test* ident rather than a closure literal — subtestRunBody
		// only descends into a *literal*, so this form slips past it otherwise.
		found = append(found, collectTestValueRefs(s.X, testNames)...)

	case *ast.AssignStmt:
		// Check RHS expressions for Test* calls (e.g. result := TestFoo(t)).
		// RHS FuncLit values are skipped because isTestCall only matches
		// *ast.CallExpr, not *ast.FuncLit.
		for _, rhs := range s.Rhs {
			if name := testCallName(rhs, testNames); name != "" {
				found = append(found, name)
			}
			// Rule 2 indirect-aliasing hardening: catch a Test* func bound to a
			// variable as a value (e.g. `h := TestXxx`). The later `h(t)`
			// invocation is a call through a non-Test ident and is invisible to
			// testCallName, so the RHS reference is the load-bearing signal.
			found = append(found, collectTestValueRefs(rhs, testNames)...)
		}

	case *ast.BlockStmt:
		if s != nil {
			found = append(found, collectTestCallsDirect(s.List, testNames)...)
		}

	case *ast.IfStmt:
		if s.Init != nil {
			found = append(found, stmtTestCalls(s.Init, testNames)...)
		}
		if s.Body != nil {
			found = append(found, collectTestCallsDirect(s.Body.List, testNames)...)
		}
		if s.Else != nil {
			found = append(found, stmtTestCalls(s.Else, testNames)...)
		}

	case *ast.ForStmt:
		if s.Body != nil {
			found = append(found, collectTestCallsDirect(s.Body.List, testNames)...)
		}

	case *ast.RangeStmt:
		if s.Body != nil {
			found = append(found, collectTestCallsDirect(s.Body.List, testNames)...)
		}

	case *ast.SwitchStmt:
		if s.Body != nil {
			found = append(found, collectTestCallsDirect(s.Body.List, testNames)...)
		}

	case *ast.CaseClause:
		found = append(found, collectTestCallsDirect(s.Body, testNames)...)

	case *ast.TypeSwitchStmt:
		if s.Body != nil {
			found = append(found, collectTestCallsDirect(s.Body.List, testNames)...)
		}

	case *ast.SelectStmt:
		if s.Body != nil {
			found = append(found, collectTestCallsDirect(s.Body.List, testNames)...)
		}

	case *ast.CommClause:
		found = append(found, collectTestCallsDirect(s.Body, testNames)...)

	case *ast.GoStmt:
		// Rule 2 hardening: `go TestXxx(t)` dispatches the named Test func as a
		// goroutine — a shared-helper misuse. Inspect the call's callee for a
		// bare Test* identifier. An immediately-invoked FuncLit body
		// (`go func(){ TestXxx(t) }()`) is left exempt, consistent with the
		// anonymous-closure guard: s.Call.Fun is then a *ast.FuncLit, not an
		// *ast.Ident, so testCallName returns "".
		if name := testCallName(s.Call, testNames); name != "" {
			found = append(found, name)
		}

	case *ast.DeferStmt:
		// Rule 2 hardening: `defer TestXxx(t)` dispatches the named Test func as
		// a deferred call — same shared-helper misuse as the go case above.
		if name := testCallName(s.Call, testNames); name != "" {
			found = append(found, name)
		}

		// *ast.ReturnStmt — non-problematic scope; skip.
	}
	return found
}

// subtestRunBody returns the body of a subtest closure if expr is a call of
// the shape `recv.Run(name, func(...){ ... })` whose final argument is a
// *ast.FuncLit — i.e. a t.Run / b.Run / sub.Run subtest. It returns nil for
// any other expression, including the assertLock-style `x := func(){...}`
// pattern (that FuncLit is an AssignStmt RHS, never a `.Run` argument) and a
// `.Run` whose final arg is a named func value rather than a literal.
//
// Keying on the `.Run` selector name (not on the receiver being literally "t")
// means renamed subtest receivers and nested t.Run frames are both covered,
// while the FuncLit-boundary guard for genuine anonymous helpers is preserved:
// only subtest *literals* are descended into, nothing else.
func subtestRunBody(expr ast.Expr) *ast.BlockStmt {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Run" {
		return nil
	}
	if len(call.Args) == 0 {
		return nil
	}
	lit, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
	if !ok || lit.Body == nil {
		return nil
	}
	return lit.Body
}

// testCallName returns the callee name if expr is a bare call to a Test*
// function (i.e. a plain identifier call, not a method call), and that name
// appears in testNames. Returns "" otherwise.
func testCallName(expr ast.Expr, testNames map[string]bool) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		// Selector calls (t.Foo(), pkg.Foo()) are not Test* sibling calls.
		return ""
	}
	if testNames[ident.Name] {
		return ident.Name
	}
	return ""
}

// collectTestValueRefs returns the names of any top-level Test* functions that
// expr references as a VALUE — i.e. a bare Test* identifier appearing anywhere
// other than the direct .Fun position of a call expression. This is the signal
// for indirect shared-helper aliasing:
//
//	h := TestXxx        // RHS ident → value ref (caught here)
//	t.Run(name, TestXxx) // call argument ident → value ref (caught here)
//
// It deliberately does NOT descend into *ast.FuncLit bodies, so an anonymous
// closure passed as higher-order plumbing (`t.Run(name, func(t *testing.T){})`,
// `h := func(){...}`) is never reported (a closure literal is not a Test*
// ident). For a call expression it skips the direct .Fun ident (that is a
// *call*, handled by testCallName / the go|defer cases) but DOES scan the
// callee receiver chain and every argument, so `t.Run(name, TestXxx)` is
// covered while `TestXxx(t)` is not double-counted as a value ref.
func collectTestValueRefs(expr ast.Expr, testNames map[string]bool) []string {
	var found []string
	switch e := expr.(type) {
	case nil:
		return nil

	case *ast.Ident:
		// A bare Test* identifier used in value position.
		if testNames[e.Name] {
			found = append(found, e.Name)
		}

	case *ast.ParenExpr:
		found = append(found, collectTestValueRefs(e.X, testNames)...)

	case *ast.CallExpr:
		// The direct .Fun ident of a call is a call, not a value reference;
		// skip it (testCallName / go|defer handle direct Test* calls). But a
		// non-ident callee (e.g. a selector's receiver) and every argument may
		// still carry a Test* value ref, so scan those.
		if _, isIdent := e.Fun.(*ast.Ident); !isIdent {
			found = append(found, collectTestValueRefs(e.Fun, testNames)...)
		}
		for _, arg := range e.Args {
			found = append(found, collectTestValueRefs(arg, testNames)...)
		}

	case *ast.SelectorExpr:
		// x.Sel — Sel is a field/method name, never a Test* value ref; the
		// receiver x may be one (unusual but harmless to scan).
		found = append(found, collectTestValueRefs(e.X, testNames)...)

	case *ast.IndexExpr:
		found = append(found, collectTestValueRefs(e.X, testNames)...)
		found = append(found, collectTestValueRefs(e.Index, testNames)...)

	case *ast.CompositeLit:
		// e.g. []func(*testing.T){TestXxx} — a Test* func value in a literal.
		for _, elt := range e.Elts {
			found = append(found, collectTestValueRefs(elt, testNames)...)
		}

	case *ast.KeyValueExpr:
		found = append(found, collectTestValueRefs(e.Value, testNames)...)

		// *ast.FuncLit — anonymous closure; NOT a Test* ident value, and we do
		// not descend (FuncLit-boundary guard preserves higher-order plumbing).
		// *ast.BasicLit and other leaf exprs carry no Test* ident; skip.
	}
	return found
}

// TestHelperConvention parses all *_test.go files in the package directory
// and asserts that no t.Helper() call appears directly in the body of a
// top-level TestXxx(t *testing.T) function.
func TestHelperConvention(t *testing.T) {
	// Locate the package directory: the directory containing this file.
	// In Go test execution the working directory is the package directory.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	pattern := filepath.Join(dir, "*_test.go")
	testFiles, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	if len(testFiles) == 0 {
		t.Fatalf("no *_test.go files found under %s", dir)
	}

	fset := token.NewFileSet()
	var violations []string

	for _, path := range testFiles {
		// Skip this file itself to avoid bootstrapping paradoxes; this file
		// intentionally does NOT place t.Helper() in any Test func.
		if filepath.Base(path) == "helper_convention_test.go" {
			continue
		}

		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if !isTopLevelTestFunc(fn) {
				continue
			}
			if containsHelperCallDirect(fn.Body.List) {
				pos := fset.Position(fn.Pos())
				violations = append(violations, pos.String()+": "+fn.Name.Name)
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("t.Helper() found directly in top-level Test* func body (move it to a named non-Test helper):\n  %s",
			strings.Join(violations, "\n  "))
	}
}

// TestSharedHelperConvention parses all *_test.go files in the package
// directory and asserts that no top-level TestXxx function is called from
// within another top-level TestXxx function body.
//
// Calling a Test* func from a sibling Test* func makes the callee a shared
// helper with a misleading name. Rename it to a lowercase non-Test function
// and add t.Helper() there.
//
// The same FuncLit-boundary guard as TestHelperConvention applies: calls
// inside closures defined within a Test func are not flagged.
func TestSharedHelperConvention(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	pattern := filepath.Join(dir, "*_test.go")
	testFiles, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	if len(testFiles) == 0 {
		t.Fatalf("no *_test.go files found under %s", dir)
	}

	fset := token.NewFileSet()

	// Parse all test files first so we can build the full set of Test* names
	// across the package (a Test* in one file could be called from another).
	var parsedFiles []*ast.File
	for _, path := range testFiles {
		if filepath.Base(path) == "helper_convention_test.go" {
			continue
		}
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		parsedFiles = append(parsedFiles, f)
	}

	// Collect the full set of Test* function names in this package.
	testNames := collectTestFuncNames(parsedFiles)

	var violations []string

	for _, f := range parsedFiles {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if !isTopLevelTestFunc(fn) {
				continue
			}
			callerName := fn.Name.Name
			called := collectTestCallsDirect(fn.Body.List, testNames)
			for _, callee := range called {
				if callee == callerName {
					// Self-recursion in a Test* func is a separate smell but not the
					// shared-helper pattern; skip to avoid false positives on unusual
					// but conceivable recursive test patterns.
					continue
				}
				pos := fset.Position(fn.Pos())
				violations = append(violations,
					pos.String()+": "+callerName+" calls Test* func "+callee+
						" (rename "+callee+" to a lowercase helper)")
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("Test* func called from another Test* func body (shared-helper misuse):\n  %s",
			strings.Join(violations, "\n  "))
	}
}

// analyzeRule2Source parses one synthetic Go source string and runs the Rule 2
// shared-helper walk over every top-level Test* func it declares, returning a
// map from caller-name to the sorted list of Test* callees the walk reports
// (self-recursion excluded, matching TestSharedHelperConvention). It is a
// lowercase non-Test helper so it neither trips Rule 1/2 itself nor gets
// collected as a Test* name.
func analyzeRule2Source(t *testing.T, src string) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic_test.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	files := []*ast.File{f}
	testNames := collectTestFuncNames(files)

	out := make(map[string][]string)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !isTopLevelTestFunc(fn) {
			continue
		}
		callerName := fn.Name.Name
		var callees []string
		for _, callee := range collectTestCallsDirect(fn.Body.List, testNames) {
			if callee == callerName {
				continue // self-recursion excluded, mirroring the production check
			}
			callees = append(callees, callee)
		}
		sort.Strings(callees)
		out[callerName] = callees
	}
	return out
}

// TestRule2SubtestAndDispatchDetection exercises the Rule 2 hardening: Test*
// calls inside a t.Run subtest closure and via go/defer dispatch must be
// detected, while the assertLock-style anonymous-helper FuncLit exemption (and
// nested anonymous closures generally) must still be honored.
func TestRule2SubtestAndDispatchDetection(t *testing.T) {
	const src = `package p

import "testing"

func TestHelperA(t *testing.T) {}
func TestHelperB(t *testing.T) {}
func TestHelperC(t *testing.T) {}
func TestHelperD(t *testing.T) {}

// Calls TestHelperA from inside a t.Run subtest closure — MUST be detected.
func TestCallsInSubtest(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		TestHelperA(t)
	})
}

// Nested t.Run frames + a renamed subtest receiver — MUST be detected.
func TestCallsInNestedSubtest(t *testing.T) {
	t.Run("outer", func(t *testing.T) {
		t.Run("inner", func(tt *testing.T) {
			TestHelperB(tt)
		})
	})
}

// go / defer dispatch of a bare Test* func — MUST both be detected.
func TestGoDeferDispatch(t *testing.T) {
	go TestHelperC(t)
	defer TestHelperD(t)
}

// assertLock-style anonymous helper closure that itself calls a Test* func —
// MUST NOT be detected (the FuncLit-boundary exemption is load-bearing).
func TestAnonHelperExempt(t *testing.T) {
	assertThing := func() {
		TestHelperA(t)
	}
	assertThing()
}

// Immediately-invoked FuncLit inside go/defer — MUST NOT be detected
// (consistent with the anonymous-closure exemption).
func TestGoDeferFuncLitExempt(t *testing.T) {
	go func() { TestHelperB(t) }()
	defer func() { TestHelperC(t) }()
}

// A bare top-level sibling call — the original Rule 2 behavior, still detected.
func TestBareSiblingCall(t *testing.T) {
	TestHelperA(t)
}
`

	got := analyzeRule2Source(t, src)

	want := map[string][]string{
		"TestHelperA":              nil,
		"TestHelperB":              nil,
		"TestHelperC":              nil,
		"TestHelperD":              nil,
		"TestCallsInSubtest":       {"TestHelperA"},
		"TestCallsInNestedSubtest": {"TestHelperB"},
		"TestGoDeferDispatch":      {"TestHelperC", "TestHelperD"},
		"TestAnonHelperExempt":     nil, // FuncLit exemption holds
		"TestGoDeferFuncLitExempt": nil, // IIFE in go/defer stays exempt
		"TestBareSiblingCall":      {"TestHelperA"},
	}

	for caller, wantCallees := range want {
		gotCallees, ok := got[caller]
		if !ok {
			t.Errorf("caller %s: not analyzed (missing from result)", caller)
			continue
		}
		if !equalStringSlices(gotCallees, wantCallees) {
			t.Errorf("caller %s: Rule 2 callees = %v, want %v", caller, gotCallees, wantCallees)
		}
	}

	// Guard against the walk inventing callers we did not declare.
	for caller := range got {
		if _, ok := want[caller]; !ok {
			t.Errorf("unexpected analyzed caller %s: %v", caller, got[caller])
		}
	}
}

// equalStringSlices compares two string slices for element equality, treating
// nil and empty as equal (a Test* func with no detected callees).
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRule2IndirectAliasingDetection exercises the indirect shared-helper
// aliasing hardening: a Test* func consumed as a *value* (bound to a variable,
// or passed as a named func value) must be detected, while legitimate
// higher-order plumbing that passes an *anonymous* closure must stay exempt.
func TestRule2IndirectAliasingDetection(t *testing.T) {
	const src = `package p

import "testing"

func TestHelperA(t *testing.T) {}
func TestHelperB(t *testing.T) {}
func TestHelperC(t *testing.T) {}
func TestHelperD(t *testing.T) {}

// Variable-assigned Test* func value, then invoked via the alias — MUST be
// detected. The invocation h(t) is a call through a non-Test ident (invisible
// to testCallName); the RHS reference TestHelperA is the load-bearing signal.
func TestVarAliasInvoke(t *testing.T) {
	h := TestHelperA
	h(t)
}

// Test* func passed as a named func value to t.Run (trailing arg is a bare
// ident, not a closure literal) — MUST be detected. subtestRunBody only
// descends into a FuncLit, so this slips past it; the arg reference catches it.
func TestNamedFuncValueToRun(t *testing.T) {
	t.Run("sub", TestHelperB)
}

// Test* func value inside a slice literal of funcs, later ranged over — the
// reference in the composite literal MUST be detected.
func TestSliceOfTestFuncs(t *testing.T) {
	fns := []func(*testing.T){TestHelperC}
	for _, fn := range fns {
		fn(t)
	}
}

// Test* func passed as a value argument to a plain (non-.Run) helper call —
// MUST be detected (it is still consumed as a shared helper by reference).
func TestPassedAsArg(t *testing.T) {
	runWith(t, TestHelperD)
}

// Legitimate higher-order plumbing: an ANONYMOUS closure passed to t.Run —
// MUST NOT be detected (a closure literal is not a Test* ident; the FuncLit
// boundary guard holds). The Test* call lives one subtest frame down and is
// reported via the existing subtest descent, exactly as before.
func TestAnonClosureToRun(t *testing.T) {
	t.Run("sub", func(t *testing.T) {})
}

// Legitimate anonymous helper bound to a variable then invoked — MUST NOT be
// detected (RHS is a FuncLit, not a Test* ident; assertLock exemption holds).
// The closure body deliberately references a Test* func VALUE (_ = TestHelperA)
// so this case is load-bearing for the FuncLit-boundary guard: collectTestValueRefs
// must NOT descend into the closure literal. With an empty body the guard could
// silently regress (a descent would find nothing); the inner reference forces the
// test to fail the instant the boundary is breached.
func TestAnonVarHelper(t *testing.T) {
	h := func(t *testing.T) { _ = TestHelperA }
	h(t)
}

func runWith(t *testing.T, fn func(*testing.T)) { fn(t) }
`

	got := analyzeRule2Source(t, src)

	want := map[string][]string{
		"TestHelperA":             nil,
		"TestHelperB":             nil,
		"TestHelperC":             nil,
		"TestHelperD":             nil,
		"TestVarAliasInvoke":      {"TestHelperA"},
		"TestNamedFuncValueToRun": {"TestHelperB"},
		"TestSliceOfTestFuncs":    {"TestHelperC"},
		"TestPassedAsArg":         {"TestHelperD"},
		"TestAnonClosureToRun":    nil, // anonymous closure stays exempt
		"TestAnonVarHelper":       nil, // anonymous var helper stays exempt
	}

	for caller, wantCallees := range want {
		gotCallees, ok := got[caller]
		if !ok {
			t.Errorf("caller %s: not analyzed (missing from result)", caller)
			continue
		}
		if !equalStringSlices(gotCallees, wantCallees) {
			t.Errorf("caller %s: Rule 2 callees = %v, want %v", caller, gotCallees, wantCallees)
		}
	}

	for caller := range got {
		if _, ok := want[caller]; !ok {
			t.Errorf("unexpected analyzed caller %s: %v", caller, got[caller])
		}
	}
}

// TestRule2RecursionArmsAndStorageDetection pins the indirect-aliasing
// recursion arms of collectTestValueRefs that TestRule2IndirectAliasingDetection
// did not exercise in isolation, plus the multi-step storage indirection forms
// (a Test* func stored into a struct field or map value and invoked later
// through that indirection). For every case the load-bearing signal is the
// Test* func used as a VALUE, not the eventual call through the alias (the call
// goes through a selector/index .Fun and is invisible to testCallName).
//
// Each case is constructed so that deleting the corresponding recursion/storage
// arm of collectTestValueRefs neuters exactly that case:
//
//   - selector-receiver chain `TestSelRecv.Method(t)`: the CallExpr .Fun is a
//     *ast.SelectorExpr, so collectTestValueRefs recurses into .Fun and then
//     into SelectorExpr.X to reach the Test* ident. Dropping the SelectorExpr.X
//     recursion arm loses this ref. (This is the realistic method-receiver-chain
//     value reference.)
//   - index expression on the Test* value `TestIdxRecv[0]`: the IndexExpr.X arm
//     reaches the Test* ident in the indexed-expression position. Dropping the
//     IndexExpr.X recursion arm loses it.
//   - index expression keyed BY the Test* value `arr[TestIdxKey]`: the
//     IndexExpr.Index arm reaches the Test* ident in the index position.
//     Dropping the IndexExpr.Index recursion arm loses it.
//   - struct-field assignment `s.fn = TestStored`: the AssignStmt-RHS scan in
//     stmtTestCalls hands the bare Test* RHS ident to collectTestValueRefs.
//     Dropping that RHS collectTestValueRefs call (the storage-arm wiring) loses
//     it; the later s.fn(t) call is a selector-callee, invisible to testCallName.
//   - map-value assignment `m["k"] = TestStored`: identical AssignStmt-RHS bare
//     Test* ident storage signal; the later m["k"](t) is an index-callee.
//   - struct composite literal `S{fn: TestStoredC}` and map composite literal
//     `map[...]{"k": TestStoredM}`: the Test* value rides a *ast.KeyValueExpr
//     inside an *ast.CompositeLit. Dropping either the CompositeLit element walk
//     or the KeyValueExpr.Value walk loses these storage refs.
//
// The anonymous-closure / FuncLit-boundary exemption is asserted intact: a
// Test* func value referenced *inside* a closure stored into a struct field
// must NOT be reported (collectTestValueRefs never descends into a FuncLit), and
// a struct literal whose field is an anonymous closure must stay clean.
func TestRule2RecursionArmsAndStorageDetection(t *testing.T) {
	const src = `package p

import "testing"

func TestSelRecv(t *testing.T) {}
func TestIdxRecv(t *testing.T) {}
func TestIdxKey(t *testing.T) {}
func TestStored(t *testing.T) {}
func TestStoredMap(t *testing.T) {}
func TestStoredC(t *testing.T) {}
func TestStoredM(t *testing.T) {}
func TestInClosure(t *testing.T) {}

// SelectorExpr.X recursion arm: a Test* func value used as the receiver of a
// selector-chain call. The call dispatches through TestSelRecv.Method, so the
// .Fun ident is never bare; the value ref is TestSelRecv in SelectorExpr.X.
// MUST be detected.
func TestUseSelectorReceiver(t *testing.T) {
	TestSelRecv.Method(t)
}

// IndexExpr.X recursion arm: a Test* func value in the indexed-expression
// position. MUST be detected.
func TestUseIndexX(t *testing.T) {
	_ = TestIdxRecv[0]
}

// IndexExpr.Index recursion arm: a Test* func value in the index position.
// MUST be detected.
func TestUseIndexKey(t *testing.T) {
	var arr [99]int
	_ = arr[TestIdxKey]
}

// Struct-field storage: a Test* func stored into a struct field, then invoked
// later via that field. The store s.fn = TestStored is the load-bearing value
// ref (the later s.fn(t) is a selector-callee, invisible to testCallName).
// MUST be detected.
func TestUseStructFieldStore(t *testing.T) {
	type S struct{ fn func(*testing.T) }
	var s S
	s.fn = TestStored
	s.fn(t)
}

// Map-value storage: a Test* func stored into a map value, then invoked later
// via that key. The store m["k"] = TestStoredMap is the value ref (the later
// m["k"](t) is an index-callee, invisible to testCallName). MUST be detected.
func TestUseMapValueStore(t *testing.T) {
	m := map[string]func(*testing.T){}
	m["k"] = TestStoredMap
	m["k"](t)
}

// Struct composite literal: a Test* func stored as a struct field at
// construction, riding a KeyValueExpr inside a CompositeLit. MUST be detected.
func TestUseStructComposite(t *testing.T) {
	type S struct{ fn func(*testing.T) }
	s := S{fn: TestStoredC}
	s.fn(t)
}

// Map composite literal: a Test* func stored as a map value at construction,
// also a KeyValueExpr inside a CompositeLit. MUST be detected.
func TestUseMapComposite(t *testing.T) {
	m := map[string]func(*testing.T){"k": TestStoredM}
	m["k"](t)
}

// FuncLit-boundary exemption (storage form): a struct field assigned an
// ANONYMOUS closure that references a Test* func value inside its body. The
// closure body's TestInClosure reference MUST NOT be reported — collectTestValueRefs
// does not descend into the FuncLit. This is load-bearing: were the boundary
// breached, the inner ref would leak. MUST NOT be detected.
func TestStoreAnonClosureExempt(t *testing.T) {
	type S struct{ fn func(*testing.T) }
	var s S
	s.fn = func(t *testing.T) { _ = TestInClosure }
	s.fn(t)
}
`

	got := analyzeRule2Source(t, src)

	want := map[string][]string{
		"TestSelRecv":                nil,
		"TestIdxRecv":                nil,
		"TestIdxKey":                 nil,
		"TestStored":                 nil,
		"TestStoredMap":              nil,
		"TestStoredC":                nil,
		"TestStoredM":                nil,
		"TestInClosure":              nil,
		"TestUseSelectorReceiver":    {"TestSelRecv"},   // SelectorExpr.X arm
		"TestUseIndexX":              {"TestIdxRecv"},   // IndexExpr.X arm
		"TestUseIndexKey":            {"TestIdxKey"},    // IndexExpr.Index arm
		"TestUseStructFieldStore":    {"TestStored"},    // RHS-ident storage signal
		"TestUseMapValueStore":       {"TestStoredMap"}, // RHS-ident storage signal
		"TestUseStructComposite":     {"TestStoredC"},   // CompositeLit/KeyValueExpr arm
		"TestUseMapComposite":        {"TestStoredM"},   // CompositeLit/KeyValueExpr arm
		"TestStoreAnonClosureExempt": nil,               // FuncLit boundary holds
	}

	for caller, wantCallees := range want {
		gotCallees, ok := got[caller]
		if !ok {
			t.Errorf("caller %s: not analyzed (missing from result)", caller)
			continue
		}
		if !equalStringSlices(gotCallees, wantCallees) {
			t.Errorf("caller %s: Rule 2 callees = %v, want %v", caller, gotCallees, wantCallees)
		}
	}

	for caller := range got {
		if _, ok := want[caller]; !ok {
			t.Errorf("unexpected analyzed caller %s: %v", caller, got[caller])
		}
	}
}

// analyzeRule1Source parses one synthetic Go source string and runs the Rule 1
// t.Helper()-misuse walk (containsHelperCallDirect / stmtHasHelperCall) over
// every top-level Test* func it declares, returning the set of Test func names
// the walk flags as containing a *direct* t.Helper() call in their immediate
// body. It mirrors analyzeRule2Source and is a lowercase non-Test helper so it
// is neither flagged by Rule 1/2 itself nor collected as a Test* name.
func analyzeRule1Source(t *testing.T, src string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic_rule1_test.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	flagged := make(map[string]bool)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !isTopLevelTestFunc(fn) {
			continue
		}
		flagged[fn.Name.Name] = containsHelperCallDirect(fn.Body.List)
	}
	return flagged
}

// TestRule1HelperDetection is the synthetic-source counterpart for Rule 1,
// mirroring TestRule2SubtestAndDispatchDetection. Until now Rule 1 was only
// validated implicitly by scanning the real tree; this pins its exact contract
// over controlled source. Critically it locks the FuncLit-boundary guard: a
// t.Helper() inside a subtest / go / defer / anonymous closure is LEGITIMATE
// (the closure is itself an anonymous helper) and must stay UNflagged, while a
// t.Helper() directly in a Test func's own statement list — including inside
// its own if/for/switch/select control flow — IS the misuse and must be
// flagged. This guards against a future guard-lift that starts wrongly flagging
// legitimate subtest t.Helper() calls.
func TestRule1HelperDetection(t *testing.T) {
	const src = `package p

import "testing"

// Direct t.Helper() in the body — MUST be flagged (the canonical misuse).
func TestDirectHelper(t *testing.T) {
	t.Helper()
}

// t.Helper() directly inside the Test func's own if-body — still its immediate
// control flow, MUST be flagged.
func TestHelperInIf(t *testing.T) {
	if true {
		t.Helper()
	}
}

// t.Helper() inside the Test func's own for-loop — MUST be flagged.
func TestHelperInFor(t *testing.T) {
	for i := 0; i < 1; i++ {
		t.Helper()
	}
}

// t.Helper() inside the Test func's own switch case — MUST be flagged.
func TestHelperInSwitch(t *testing.T) {
	switch {
	case true:
		t.Helper()
	}
}

// Renamed receiver (tb) — receiver name is not constrained, MUST be flagged.
func TestHelperRenamedRecv(tb *testing.T) {
	tb.Helper()
}

// t.Helper() inside a subtest closure — LEGITIMATE (the closure is an
// anonymous helper); the Rule 1 walk does NOT descend into the t.Run FuncLit.
// MUST NOT be flagged.
func TestHelperInSubtest(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		t.Helper()
	})
}

// assertLock-style anonymous helper closure calling t.Helper() — LEGITIMATE,
// the load-bearing exemption. MUST NOT be flagged.
func TestHelperInAnonClosure(t *testing.T) {
	assertThing := func() {
		t.Helper()
	}
	assertThing()
}

// t.Helper() inside go / defer closures — nested frames, LEGITIMATE.
// MUST NOT be flagged.
func TestHelperInGoDefer(t *testing.T) {
	go func() { t.Helper() }()
	defer func() { t.Helper() }()
}

// No t.Helper() at all — MUST NOT be flagged.
func TestNoHelper(t *testing.T) {
	_ = 1
}
`

	got := analyzeRule1Source(t, src)

	want := map[string]bool{
		"TestDirectHelper":        true,
		"TestHelperInIf":          true,
		"TestHelperInFor":         true,
		"TestHelperInSwitch":      true,
		"TestHelperRenamedRecv":   true,
		"TestHelperInSubtest":     false, // FuncLit-boundary guard: subtest closure
		"TestHelperInAnonClosure": false, // assertLock exemption is load-bearing
		"TestHelperInGoDefer":     false, // go/defer nested frames stay exempt
		"TestNoHelper":            false,
	}

	for fn, wantFlagged := range want {
		gotFlagged, ok := got[fn]
		if !ok {
			t.Errorf("func %s: not analyzed (missing from result)", fn)
			continue
		}
		if gotFlagged != wantFlagged {
			t.Errorf("func %s: Rule 1 flagged = %v, want %v", fn, gotFlagged, wantFlagged)
		}
	}

	for fn := range got {
		if _, ok := want[fn]; !ok {
			t.Errorf("unexpected analyzed func %s: flagged=%v", fn, got[fn])
		}
	}
}
