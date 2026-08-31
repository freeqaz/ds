// SPDX-License-Identifier: Apache-2.0

package quicfallback

// srclinks.go is the TEST-CACHE-CORRECTNESS seam for this package's one cross-tree
// read: the shipped NFT-4 resolver-bypass-closure artifact (dataplane/artifacts/nft/
// nft-4-resolver-closure.nft), which the offline dormant-v6-twin shape reader scans.
//
// That file lives OUTSIDE this Go module (dataplane/**), and Go's test cache (cmd/go
// computeTestInputsID: "Do not recheck files outside the module") hashes only files
// opened at paths lexically inside the module root. A direct ../../../dataplane/… read
// therefore lets a WARM cache serve a stale PASS after the shipped ruleset changes —
// exactly the drift this offline reader exists to catch. Routing the read through a
// tracked in-module symlink under testdata/srclinks puts the opened path inside the
// module (so it IS hashed), while os.ReadFile FOLLOWS the link so the tracked
// size+mtime are the REAL artifact's and the read re-runs the moment it changes.
//
// This is the SAME artifact resolverlock reads (resolverlock/testdata/srclinks/
// dataplane_nft4_resolver_closure) — one artifact, multiple readers, each through its
// own package-local tracked link. TestSourceLinksResolve (srclinks_test.go) guards the
// target. dataplane/** is READ-ONLY here.

// srcLinkNFT4Closure is the leaf filename of the tracked symlink under testdata/srclinks
// pointing at the shipped NFT-4 artifact. icmp_capture.go's nft4ArtifactRelPath is
// "testdata/srclinks/" + this.
const srcLinkNFT4Closure = "dataplane_nft4_resolver_closure"

// SourceLinks maps each tracked symlink under testdata/srclinks (the ONLY path this
// package reads a cross-tree dataplane artifact through) to the repo-relative file it
// must point at. TestSourceLinksResolve asserts the link resolves to exactly this
// target.
var SourceLinks = map[string]string{
	srcLinkNFT4Closure: "dataplane/artifacts/nft/nft-4-resolver-closure.nft",
}
