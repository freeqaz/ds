// SPDX-License-Identifier: Apache-2.0

package resolverlock

// srclinks.go is the TEST-CACHE-CORRECTNESS seam for this package's cross-tree
// reads. resolverlock reads several SHIPPED dataplane artifacts (the POL-2 baseline
// pack, and the NFT-1/2b/3b/4 rulesets) plus the authoritative Rust drift corpus.
// Those files live OUTSIDE this Go module (dataplane/**), and Go's test cache
// (cmd/go computeTestInputsID: "Do not recheck files outside the module") hashes
// only files opened at paths lexically inside the module root. So a direct
// ../../../dataplane/… read lets a WARM cache serve a stale PASS after the shipped
// artifact changes — exactly the drift these offline conformance readers exist to
// catch — since the changed cross-tree file never enters the test's input hash.
//
// The fix, per the pattern documented in
// assurance/conformance-adapter/hostbridgewire/doc.go: every cross-tree read goes
// THROUGH a tracked in-module symlink under testdata/srclinks. The link path is
// lexically inside the module (so it IS hashed), and os.ReadFile/os.Stat FOLLOW the
// link, so the tracked size+mtime are the REAL dataplane file's — the read re-runs
// the moment that file changes (verified empirically: with a warm GOCACHE, mutating
// a scraped source REDs the converted pin). The readers keep their existing
// runtime.Caller anchoring; only the relative-path CONSTANT now names the in-module
// link instead of ../../../dataplane/…, so the resolved absolute path lands inside
// the module root.
//
// TestSourceLinksResolve (srclinks_test.go) guards the farm: every link must BE a
// symlink whose target is exactly the documented repo-relative dataplane file, so a
// link silently replaced by a stale COPY (which would freeze a reader against a dead
// snapshot) turns RED.
//
// dataplane/** is READ-ONLY from the conformance adapter: these links only READ the
// shipped artifacts, never edit them.

// Link-name constants: the leaf filenames of the tracked symlinks under
// testdata/srclinks. Each reader's relative-path constant is
// "testdata/srclinks/" + one of these.
const (
	srcLinkPol2BaselinePack = "dataplane_pol2_baseline_pack"
	srcLinkNFT4Closure      = "dataplane_nft4_resolver_closure"
	srcLinkNFT1Bootstrap    = "dataplane_nft1_bootstrap"
	srcLinkNFT2bSpike       = "dataplane_nft2b_spike"
	srcLinkNFT3bOutput      = "dataplane_nft3b_output"
	srcLinkPackDriftCorpus  = "dataplane_pack_drift_corpus"
)

// SourceLinks maps each tracked symlink under testdata/srclinks (the ONLY path this
// package reads a cross-tree dataplane artifact through) to the repo-relative file it
// must point at. TestSourceLinksResolve asserts each link resolves to exactly this
// target (via the fixed ../../../../../ prefix from testdata/srclinks to the repo
// root), so a stale copy or a retarget turns the guard RED.
var SourceLinks = map[string]string{
	srcLinkPol2BaselinePack: "dataplane/artifacts/policy-packs/pol2-system-baseline.pol1.yaml",
	srcLinkNFT4Closure:      "dataplane/artifacts/nft/nft-4-resolver-closure.nft",
	srcLinkNFT1Bootstrap:    "dataplane/artifacts/nft/nft-1-bootstrap.nft",
	srcLinkNFT2bSpike:       "dataplane/artifacts/nft/nft-2b-spike.nft",
	srcLinkNFT3bOutput:      "dataplane/artifacts/nft/nft-3b-output.nft",
	srcLinkPackDriftCorpus:  "dataplane/crates/policy-core/tests/pack_drift_corpus.rs",
}
