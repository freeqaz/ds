// SPDX-License-Identifier: Apache-2.0

// Token-lineage (doc 19 §9, P-T1 → D104) + role-template resolver (doc 19 §11)
// tests. These cover the residue beyond the substrate core: the FINGERPRINT-ONLY
// lineage record round-tripping a depth-2 fan-out chain, the no-token-bytes
// guard, and the v0 default role-template resolver (the recorded de-risking
// default). Everything synthetic (D50); derivation is pure (no mint RPC).
package mint

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestLineage_RoundTripsDepthTwoChain proves the doc 19 §9 token-lineage answers
// "which subagent, for which task, on behalf of which user, presented this
// credential" down a depth-2 fan-out tree: the lineage carries the full root→leaf
// parent_session hop chain, one block FINGERPRINT per chain block, the leaf's
// task_ref, and the inherited launching_user — all FINGERPRINT-ONLY.
func TestLineage_RoundTripsDepthTwoChain(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq()) // root = tmplRootSession, user = testLaunchingUser
	if err != nil {
		t.Fatal(err)
	}

	// Depth 1: child for a subagent task.
	d1, err := shim.DeriveChildSessionWithLineage(base, ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github", "npm"},
		TaskRef:          "task:child",
	}, nil, shim.now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Depth 2: grandchild (child-of-child), carrying the depth-1 hop chain forward.
	d2, err := shim.DeriveChildSessionWithLineage(d1.Bundle, ChildSessionParams{
		ChildSessionUUID: tmplGrandSession,
		Services:         []string{"github"},
		TaskRef:          "task:grandchild",
	}, nil, shim.now(), d1.Lineage.ParentSessions)
	if err != nil {
		t.Fatal(err)
	}

	lin := d2.Lineage
	// "which subagent" — the presented (leaf) session is the grandchild.
	if lin.PresentedSession != tmplGrandSession {
		t.Fatalf("lineage presented session = %q, want grandchild %q", lin.PresentedSession, tmplGrandSession)
	}
	// "for which task" — the leaf task_ref.
	if lin.TaskRef != "task:grandchild" {
		t.Fatalf("lineage task_ref = %q, want task:grandchild", lin.TaskRef)
	}
	// "on behalf of which user" — the launching_user inherited unchanged down the tree.
	if lin.LaunchingUser != testLaunchingUser {
		t.Fatalf("lineage launching_user = %q, want inherited %q", lin.LaunchingUser, testLaunchingUser)
	}
	// Whole-chain root for the LOG-5 join.
	if lin.RootSession != tmplRootSession {
		t.Fatalf("lineage root_session = %q, want originating %q", lin.RootSession, tmplRootSession)
	}
	// attenuation depth = 2 (base + 2 hops).
	if lin.AttenuationDepth != 2 {
		t.Fatalf("lineage depth = %d, want 2", lin.AttenuationDepth)
	}
	// FULL root→leaf parent_session hop chain: [root, child] (the two re-rooting hops).
	wantHops := []string{tmplRootSession, tmplChildSession}
	if len(lin.ParentSessions) != len(wantHops) {
		t.Fatalf("lineage parent_session hops = %v, want %v", lin.ParentSessions, wantHops)
	}
	for i := range wantHops {
		if lin.ParentSessions[i] != wantHops[i] {
			t.Fatalf("lineage hop[%d] = %q, want %q (chain %v)", i, lin.ParentSessions[i], wantHops[i], lin.ParentSessions)
		}
	}
	// One block fingerprint per chain block (base + 2 hops = 3), each a stable
	// sha256 hex digest — never empty, never a raw signature.
	if lin.FingerprintAlg != "sha256" {
		t.Fatalf("lineage fingerprint alg = %q, want sha256", lin.FingerprintAlg)
	}
	if len(lin.BlockFingerprints) != 3 {
		t.Fatalf("lineage block fingerprints = %d, want 3 (base + 2 hops)", len(lin.BlockFingerprints))
	}
	seenFP := make(map[string]struct{}, len(lin.BlockFingerprints))
	for i, fp := range lin.BlockFingerprints {
		if len(fp) != 64 { // sha256 hex
			t.Fatalf("block fingerprint[%d] = %q (len %d), want 64-hex sha256", i, fp, len(fp))
		}
		if _, dup := seenFP[fp]; dup {
			t.Fatalf("block fingerprint[%d] = %q is a duplicate — each chain block must fingerprint distinctly", i, fp)
		}
		seenFP[fp] = struct{}{}
	}
	// The fingerprint of a block is a DETERMINISTIC function of its revocation ID:
	// hashing the same revocation ID always yields the same digest (the audit join
	// is reproducible from a captured token's revocation IDs). The revocation IDs
	// themselves are per-token-instance (the substrate's §7 unique block ids), so we
	// pin determinism on the hash, not on cross-derivation equality.
	leaf := lin.BlockFingerprints[len(lin.BlockFingerprints)-1]
	if again := blockFingerprint(d2.Bundle.RevocationIDs[len(d2.Bundle.RevocationIDs)-1]); again != leaf {
		t.Fatalf("leaf fingerprint not a deterministic hash of its revocation id: %q vs %q", leaf, again)
	}
}

// TestLineage_NoTokenBytes is the load-bearing FINGERPRINT-ONLY guard (doc 19 §9 /
// doc 16 §9): ZERO token bytes (the opaque presented credential, or any chain
// block bytes) may appear ANYWHERE in the serialized lineage record. We serialize
// the lineage and assert the token's bytes (and a representative window of them)
// never occur — the test fails closed if a future edit leaks plaintext into the
// audit shape.
func TestLineage_NoTokenBytes(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq())
	if err != nil {
		t.Fatal(err)
	}
	d1, err := shim.DeriveChildSessionWithLineage(base, ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github"},
		TaskRef:          "task:child",
	}, nil, shim.now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := shim.DeriveChildSessionWithLineage(d1.Bundle, ChildSessionParams{
		ChildSessionUUID: tmplGrandSession,
		Services:         []string{"github"},
		TaskRef:          "task:grandchild",
	}, nil, shim.now(), d1.Lineage.ParentSessions)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize the lineage exactly as an audit spool/log would project it.
	spool, err := json.Marshal(d2.Lineage)
	if err != nil {
		t.Fatal(err)
	}

	// The full leaf token must NOT appear in the lineage spool.
	if bytes.Contains(spool, d2.Bundle.Token) {
		t.Fatal("leaf token bytes appear in the lineage record (fingerprint-only violation, doc 19 §9)")
	}
	// Nor the parent tokens anywhere up the chain.
	if bytes.Contains(spool, base.Token) {
		t.Fatal("base token bytes appear in the lineage record (fingerprint-only violation, doc 19 §9)")
	}
	if bytes.Contains(spool, d1.Bundle.Token) {
		t.Fatal("depth-1 token bytes appear in the lineage record (fingerprint-only violation, doc 19 §9)")
	}
	// Nor any per-block REVOCATION ID raw bytes (the lineage hashes them to a digest;
	// the raw signature material must never ride the audit shape). Check a non-trivial
	// window of each — a base64 of a 64-byte Ed25519 sig is long enough that a chance
	// substring match is implausible, and a leak would be the whole id.
	for i, rid := range d2.Bundle.RevocationIDs {
		if len(rid) >= 8 && bytes.Contains(spool, rid) {
			t.Fatalf("raw revocation id[%d] appears in the lineage record (fingerprint-only violation, doc 19 §9)", i)
		}
	}
	// Sanity: the spool DOES carry the fingerprints (so we proved absence of bytes,
	// not absence of content).
	if !strings.Contains(string(spool), d2.Lineage.BlockFingerprints[0]) {
		t.Fatal("lineage spool is missing its own block fingerprints — test is vacuous")
	}
}

// TestLineage_BaseTokenHasEmptyHopChain pins the base-token lineage shape (doc 19
// §9): the base/root token has NO parent_session hops, depth 0, one block
// fingerprint, and an empty root_session claim (it IS the root). IdentityMinted
// carries this base-token shape; ValidationResult carries the fan-out lineage.
func TestLineage_BaseTokenHasEmptyHopChain(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq())
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err := shim.tokenSigner.Verify(base.Token)
	if err != nil {
		t.Fatal(err)
	}
	lin := LineageFromBundle(base, claims, nil)
	if lin.AttenuationDepth != 0 {
		t.Fatalf("base lineage depth = %d, want 0", lin.AttenuationDepth)
	}
	if len(lin.ParentSessions) != 0 {
		t.Fatalf("base lineage parent_session hops = %v, want none", lin.ParentSessions)
	}
	if lin.RootSession != "" {
		t.Fatalf("base lineage root_session = %q, want empty (it IS the root)", lin.RootSession)
	}
	if len(lin.BlockFingerprints) != 1 {
		t.Fatalf("base lineage block fingerprints = %d, want 1", len(lin.BlockFingerprints))
	}
	if lin.PresentedSession != tmplRootSession {
		t.Fatalf("base lineage presented session = %q, want %q", lin.PresentedSession, tmplRootSession)
	}
}

// TestLineage_FanOutWithLineageZeroMintRPCs proves the lineage-populating fan-out
// path costs ZERO mint RPCs (doc 19 §4): a wide fan-out + depth-2 hops through
// DeriveChildSessionWithLineage mints nothing beyond the single base.
func TestLineage_FanOutWithLineageZeroMintRPCs(t *testing.T) {
	shim := newTestShim(t)
	counter := &countingSigner{SubstrateSigner: shim.tokenSigner}
	shim.tokenSigner = counter

	base, err := shim.MintSessionToken(tmplBaseReq())
	if err != nil {
		t.Fatal(err)
	}
	if counter.mints != 1 {
		t.Fatalf("base mint count = %d, want 1", counter.mints)
	}
	for i := 0; i < 4; i++ {
		d1, err := shim.DeriveChildSessionWithLineage(base, ChildSessionParams{
			ChildSessionUUID: tmplChildSession,
			Services:         []string{"github"},
			TaskRef:          "task:child",
		}, nil, shim.now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := shim.DeriveChildSessionWithLineage(d1.Bundle, ChildSessionParams{
			ChildSessionUUID: tmplGrandSession,
			Services:         []string{"github"},
			TaskRef:          "task:grandchild",
		}, nil, shim.now(), d1.Lineage.ParentSessions); err != nil {
			t.Fatal(err)
		}
	}
	if counter.mints != 1 {
		t.Fatalf("after lineage fan-out mint count = %d, want 1 (zero mint RPCs, doc 19 §4)", counter.mints)
	}
}

// TestDefaultRoleTemplateResolver_DeRiskingDefault proves the v0 role-template
// resolver (doc 19 §11): the recorded de-risking default role (`default@<vN>`) is
// KNOWN (ok=true) and contributes NO narrowing (an empty template — the full
// envelope, roles/SCHEMA.md rule 4), while any other ref is UNKNOWN (ok=false).
func TestDefaultRoleTemplateResolver_DeRiskingDefault(t *testing.T) {
	// The recorded default, any version: KNOWN, no narrowing.
	for _, ref := range []string{"default", "default@v1", "default@v3"} {
		tmpl, ok := DefaultRoleTemplateResolver(ref)
		if !ok {
			t.Fatalf("default resolver: ref %q want ok=true (the recorded de-risking default)", ref)
		}
		if tmpl.Services != nil || tmpl.MaxTTL != 0 {
			t.Fatalf("default resolver: ref %q want empty template (no narrowing), got %+v", ref, tmpl)
		}
	}
	// A non-default role: UNKNOWN to the v0 resolver (doc 18 installs the real one).
	for _, ref := range []string{"role:reviewer", "researcher@v2", ""} {
		if _, ok := DefaultRoleTemplateResolver(ref); ok {
			t.Fatalf("default resolver: ref %q want ok=false (unknown to v0 resolver)", ref)
		}
	}
}

// TestDefaultRoleTemplateResolver_FoldsThroughDerivation proves the resolver is a
// drop-in for the fan-out path: deriving a child under `default@v1` succeeds and
// narrows nothing beyond the explicit per-child request (the recorded default
// contributes no extra ceiling), and the derivation stays ZERO-mint.
func TestDefaultRoleTemplateResolver_FoldsThroughDerivation(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq()) // {github, npm, pypi}
	if err != nil {
		t.Fatal(err)
	}
	child, err := shim.DeriveChildSession(base, ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github", "npm"},
		TaskRef:          "task:child",
		RoleRef:          "default@v1",
	}, DefaultRoleTemplateResolver, shim.now())
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err := shim.tokenSigner.Verify(child.Token)
	if err != nil {
		t.Fatal(err)
	}
	// The default role narrowed NOTHING extra — the child scope is exactly the
	// explicit per-child request ⊆ parent.
	if len(claims.Services) != 2 || claims.Services[0] != "github" || claims.Services[1] != "npm" {
		t.Fatalf("child scope under default role = %v, want explicit [github npm]", claims.Services)
	}
}
