// SPDX-License-Identifier: Apache-2.0

package resolverlock

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// srcLinksDirRel is this package's cross-tree source-link directory, relative to the
// package dir (go test runs with cwd = package dir).
const srcLinksDirRel = "testdata/srclinks"

// srcLinksRepoRootPrefix is the fixed relative prefix from testdata/srclinks up to the
// repo root: srclinks → testdata → resolverlock → conformance-adapter → assurance →
// repo-root is five parents. Every link's target is this prefix + its repo-relative
// dataplane path.
const srcLinksRepoRootPrefix = "../../../../../"

// TestSourceLinksResolve guards the symlink farm itself: every registered link must BE
// a symlink whose target is exactly ../../../../../<repo-relative dataplane file>, and
// must be readable (the real file exists). A link replaced by a stale file COPY (which
// would freeze the offline reader against a dead snapshot, defeating the whole
// one-artifact-two-readers guarantee) or retargeted at the wrong file turns RED here —
// so the test-cache-correctness reroute cannot silently rot.
func TestSourceLinksResolve(t *testing.T) {
	for link, target := range SourceLinks {
		path := filepath.Join(srcLinksDirRel, link)
		got, err := os.Readlink(path)
		if err != nil {
			t.Errorf("%s: not a symlink (a stale copy would freeze the offline pin against a dead dataplane snapshot): %v", path, err)
			continue
		}
		want := filepath.FromSlash(srcLinksRepoRootPrefix + target)
		if got != want {
			t.Errorf("%s -> %q; want %q (link retargeted — the reader would read the wrong artifact)", path, got, want)
		}
		// os.Stat FOLLOWS the link: proves the real dataplane target exists and is
		// readable (so the read, and its test-cache hashing, actually bite).
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: target unreadable (dataplane file moved/removed?): %v", path, err)
		}
	}
}

// TestSourceLinksCoverEveryCrossTreeRead pins that the srclink registry stays in
// lockstep with the readers: every relative-path constant a reader anchors on MUST be a
// "testdata/srclinks/<registered link>" path, and every registered link must be used.
// A new cross-tree read added with a raw ../../../dataplane/… path (the test-cache hole)
// would NOT appear here and the reviewer would catch it; conversely a dead link that no
// reader references fails too. This binds the audit so a future edit cannot reintroduce
// the direct-read hole in this package unseen.
func TestSourceLinksCoverEveryCrossTreeRead(t *testing.T) {
	// The exact set of reader relative-path constants across the package's files
	// (resolverlock.go, nft4_closure.go, nft4_closure_test.go, drift_corpus_test.go).
	// Each MUST route through a registered srclink.
	readerPaths := map[string]string{
		"shippedPackRelPath (resolverlock.go)":  shippedPackRelPath,
		"nft4ArtifactRelPath (nft4_closure.go)": nft4ArtifactRelPath,
		"nft1ArtifactRelPath (test)":            nft1ArtifactRelPath,
		"nft2ArtifactRelPath (test)":            nft2ArtifactRelPath,
		"nft3ArtifactRelPath (test)":            nft3ArtifactRelPath,
		"packDriftCorpusRelPath (test)":         packDriftCorpusRelPath,
	}
	used := make(map[string]bool, len(SourceLinks))
	for name, rel := range readerPaths {
		dir, link := filepath.Split(filepath.ToSlash(rel))
		if dir != srcLinksDirRel+"/" {
			t.Errorf("%s = %q does not route through %s/ — a raw cross-tree read defeats the test cache (reroute it through a tracked srclink)", name, rel, srcLinksDirRel)
			continue
		}
		if _, ok := SourceLinks[link]; !ok {
			t.Errorf("%s = %q names srclink %q which is not registered in SourceLinks", name, rel, link)
			continue
		}
		used[link] = true
	}
	for link := range SourceLinks {
		if !used[link] {
			t.Errorf("SourceLinks entry %q is registered but no reader references it (dead link — remove it or wire the reader)", link)
		}
	}
}

// TestNoRawParentDirStringLiterals is the REINTRODUCTION guard the registry tests above
// cannot provide: TestSourceLinksCoverEveryCrossTreeRead validates only the constants it
// already knows about, so a brand-new reader added with a raw "../../../dataplane/…"
// path (the exact test-cache hole this package's srclinks exist to close — cmd/go
// computeTestInputsID hashes only paths lexically inside the module root) would slip
// past it unseen. This test parses every .go file in the package and fails on ANY
// string LITERAL containing "../" — after the srclinks conversion the package has
// exactly one legitimate parent-relative literal, srcLinksRepoRootPrefix in THIS file
// (the guard's own expected link target). Comments mentioning ../../../dataplane/… in
// prose are untouched (the scan walks string literals, not source bytes). To add a new
// cross-tree read: add a tracked symlink under testdata/srclinks, register it in
// SourceLinks, and route the reader constant through "testdata/srclinks/" + <link>.
func TestNoRawParentDirStringLiterals(t *testing.T) {
	// The needle is built by concatenation so this guard's own source never contains
	// the flagged substring as a single literal (each piece is inert on its own).
	rawParentDirNeedle := ".." + "/"
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir for the raw-read scan: %v (a read failure is a HARD failure — the scan must not vacuously pass)", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s for the raw-read scan: %v", name, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if !strings.Contains(val, rawParentDirNeedle) {
				return true
			}
			if name == "srclinks_test.go" && val == srcLinksRepoRootPrefix {
				return true // the guard's own expected-target prefix
			}
			t.Errorf("%s: string literal %q escapes the package via a parent-relative path — a raw cross-tree read defeats Go's test cache (warm-cache stale PASS); route it through a tracked testdata/srclinks link registered in SourceLinks", fset.Position(lit.Pos()), val)
			return true
		})
	}
}
