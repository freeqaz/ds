// SPDX-License-Identifier: Apache-2.0

package conformanceadapter

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

// srclinks_sweep_test.go is the MODULE-ROOT enforcement that makes the per-package
// srclink test-cache pattern self-enforcing: every offline conformance pin that reads a
// sibling tree's source does so through a tracked `testdata/srclinks/<link>` symlink
// (never a raw ../../<tree>/… path), because cmd/go's computeTestInputsID hashes only
// files opened at paths lexically inside this module's root — a direct cross-tree read
// would let a warm cache serve a stale PASS after the sibling tree changed. Each such
// package guards its farm with a trio of tests (resolve / coverage / literal-scan). This
// sweep walks the whole module for `testdata/srclinks` farms and asserts EACH one's
// package carries all three, so a future conversion cannot ship a link farm that silently
// omits a guard and reopens the stale-cache hole.

// guardTrio is the set of guard test functions every srclink-farm package must declare.
// The names are the canonical pattern established in resolverlock / quic-fallback /
// hostbridgewire:
//   - TestSourceLinksResolve         — every link is a symlink to ../../../../../<target>
//   - TestSourceLinksCoverEveryCrossTreeRead — reader constants ↔ SourceLinks, both ways
//   - TestNoRawParentDirStringLiterals — no raw "../" literal reintroduces the hole
var guardTrio = []string{
	"TestSourceLinksResolve",
	"TestSourceLinksCoverEveryCrossTreeRead",
	"TestNoRawParentDirStringLiterals",
}

// knownFarms is the floor of srclink-farm package directories (module-relative) that MUST
// be discovered by the walk. It exists so a broken/empty walk cannot vacuously PASS: if
// the sweep found zero farms it would trivially satisfy "every farm carries the trio".
// A NEW farm need not be listed here (the walk discovers it and the trio check bites); a
// REMOVED farm is a deliberate edit that updates this list.
var knownFarms = []string{
	"hostbridgewire",
	"quic-fallback",
	"resolverlock",
}

// TestAllSrcLinkFarmsCarryGuardTrio walks the module for testdata/srclinks farms and
// asserts each owning package declares the full guard trio.
func TestAllSrcLinkFarmsCarryGuardTrio(t *testing.T) {
	// go test runs with cwd = the package dir, which for a root-package test is the
	// module root (assurance/conformance-adapter) — so "." is the module.
	farms := discoverSrcLinkFarms(t, ".")
	if len(farms) == 0 {
		t.Fatal("no testdata/srclinks farms discovered — the sweep walked nothing and would vacuously pass (walk root wrong?)")
	}

	found := make(map[string]bool, len(farms))
	for pkgDir := range farms {
		found[pkgDir] = true
		funcs := packageTestFuncs(t, pkgDir)
		for _, want := range guardTrio {
			if !funcs[want] {
				t.Errorf("srclink farm %s: package is missing guard %s() — a testdata/srclinks farm without the full resolve/coverage/literal-scan trio can reopen the warm-cache stale-PASS hole (add it, mirroring resolverlock/srclinks_test.go)", pkgDir, want)
			}
		}
	}

	// Non-vacuity floor: the known farms MUST all have been discovered, so a walk that
	// silently returns nothing (or the wrong root) fails loudly instead of passing.
	for _, want := range knownFarms {
		if !found[want] {
			t.Errorf("known srclink farm %q was not discovered by the module walk — the sweep is not seeing the real farms (walk/pathing regression); discovered: %v", want, sortedKeys(farms))
		}
	}
}

// discoverSrcLinkFarms walks root and returns the set of package directories (module-
// relative, forward-slash) that own a `testdata/srclinks` directory. A farm at
// `<pkg>/testdata/srclinks` maps to package dir `<pkg>`.
func discoverSrcLinkFarms(t *testing.T, root string) map[string]struct{} {
	t.Helper()
	farms := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || d.Name() != "srclinks" {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) != "testdata" {
			return nil
		}
		// path == <pkg>/testdata/srclinks → strip the two trailing segments.
		pkgDir := filepath.Dir(filepath.Dir(path))
		pkgDir = filepath.ToSlash(filepath.Clean(pkgDir))
		farms[pkgDir] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for srclink farms: %v (a walk error is a HARD failure — the sweep must not vacuously pass)", root, err)
	}
	return farms
}

// packageTestFuncs parses every *_test.go file in dir and returns the set of top-level
// function names declared across them.
func packageTestFuncs(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading srclink-farm package dir %s: %v", dir, err)
	}
	funcs := make(map[string]bool)
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s for the guard-trio scan: %v", filepath.Join(dir, name), perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil {
				continue
			}
			funcs[fn.Name.Name] = true
		}
	}
	return funcs
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
