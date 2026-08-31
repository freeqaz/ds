// SPDX-License-Identifier: Apache-2.0

package quicfallback

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
// repo root: srclinks → testdata → quic-fallback → conformance-adapter → assurance →
// repo-root is five parents.
const srcLinksRepoRootPrefix = "../../../../../"

// TestSourceLinksResolve guards the symlink farm: the NFT-4 link must BE a symlink
// whose target is exactly ../../../../../<repo-relative dataplane file> and must be
// readable. A link replaced by a stale COPY (which would freeze the offline
// dormant-v6-twin reader against a dead snapshot) or retargeted turns RED here.
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
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: target unreadable (dataplane file moved/removed?): %v", path, err)
		}
	}
}

// TestSourceLinksCoverEveryCrossTreeRead pins that the reader's relative-path constant
// routes through the registered srclink, so a future edit cannot reintroduce a raw
// ../../../dataplane/… read (the test-cache hole) in this package unseen.
func TestSourceLinksCoverEveryCrossTreeRead(t *testing.T) {
	dir, link := filepath.Split(filepath.ToSlash(nft4ArtifactRelPath))
	if dir != srcLinksDirRel+"/" {
		t.Fatalf("nft4ArtifactRelPath = %q does not route through %s/ — a raw cross-tree read defeats the test cache (reroute it through a tracked srclink)", nft4ArtifactRelPath, srcLinksDirRel)
	}
	if _, ok := SourceLinks[link]; !ok {
		t.Fatalf("nft4ArtifactRelPath = %q names srclink %q which is not registered in SourceLinks", nft4ArtifactRelPath, link)
	}
}

// TestNoRawParentDirStringLiterals is the REINTRODUCTION guard the registry test above
// cannot provide: TestSourceLinksCoverEveryCrossTreeRead validates only the constant it
// already knows about, so a brand-new reader added with a raw "../../../dataplane/…"
// path (the exact test-cache hole this package's srclink exists to close) would slip
// past it unseen. This test parses every .go file in the package and fails on ANY
// string LITERAL containing "../" — the only legitimate parent-relative literal is
// srcLinksRepoRootPrefix in THIS file (the guard's own expected link target). To add a
// new cross-tree read: add a tracked symlink under testdata/srclinks, register it in
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
