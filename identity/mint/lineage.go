// SPDX-License-Identifier: Apache-2.0

// Token lineage on the identity-plane audit events (doc 19 §9; P-T1 → D104).
//
// THE AUDIT STORY THIS CLOSES. doc 04 §5's attribution promise ("attributed to
// the launching user") extended down the D18 fan-out tree: LOG-5 must answer
// "WHICH SUBAGENT, spawned for WHICH TASK, on behalf of WHICH USER, presented
// this credential, WHEN." IdentityMinted already covers base-token issuance
// (doc 16 §9); doc 19 §9 requires `ValidationResult` ALSO carry the TOKEN LINEAGE
// — the chain of block/caveat FINGERPRINTS (or revocation IDs), the
// parent_session hops, and the attenuation depth — so a single Validate verdict
// is self-describing down the whole derivation path.
//
// FINGERPRINT-ONLY, NO TOKEN BYTES (doc 16 §9 / doc 19 §9). Like every identity
// event, the lineage carries ONLY fingerprints — never a token, a block, or a raw
// signature. A lineage record is built from a token's per-block revocation
// identifiers (the chain fingerprints the §7 fleet list already keys on) hashed
// into stable hex digests, plus the parent_session hops decoded from the token's
// own claims. The token bytes themselves never enter the record (and so never a
// log/spool/golden); LineageNoTokenBytes (lineage_test.go) is the executable
// guard that asserts this.
//
// PROTO POSTURE (P-T1 → D104, doc 19 §9). The lineage FIELD NUMBERS were reserved
// on `IdentityMinted` / `ValidationResult` before the `dreamserpent.identity.v1`
// Stage-0 freeze (proto/.../log_events.proto: `reserved 16, 17, 18, 19` on both,
// RESERVE-ONLY, no bodies). This file populates the TYPED Go-side lineage record
// and the LOG-5 join shape ONLY — it makes NO proto edit. The audit pipeline
// projects TokenLineage onto those reserved numbers when doc 19 retention binds;
// the wire-field assignment is a one-line projection there, never a body here
// (proto freezes are one-shot; a stub body before the flip is forbidden).
package mint

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// lineageFingerprintAlg names the digest used for a lineage fingerprint, recorded
// alongside the chain so an auditor knows how the hex digests were derived
// (parallels the identity-event fingerprint discipline, doc 16 §9). SHA-256 over
// the per-block revocation identifier — never over the token bytes.
const lineageFingerprintAlg = "sha256"

// TokenLineage is the typed doc 19 §9 token-lineage record carried alongside a
// ValidationResult (and recordable on IdentityMinted for the base token). It is
// the LOG-5 join payload — "which subagent, for which task, on behalf of which
// user, presented this credential, when" — answerable from this record joined
// against the session→principal store on RootSession / launching_user (doc 04 §5).
//
// FINGERPRINT-ONLY (doc 16 §9 / doc 19 §9): every field here is a fingerprint, a
// session_uuid, a depth, or a task/user reference. NO token bytes, NO raw block
// bytes, NO raw signatures — the BlockFingerprints are SHA-256 digests of the
// per-block revocation identifiers, not the identifiers themselves and never the
// token. This record is the DATA the audit pipeline projects onto the reserved
// `ValidationResult` / `IdentityMinted` fields (16-19); it is not the proto type.
type TokenLineage struct {
	// FingerprintAlg names the digest used for BlockFingerprints (lineageFingerprintAlg).
	FingerprintAlg string
	// BlockFingerprints is the chain of per-block fingerprints, base→leaf: one for
	// the base token's authority block and one per attenuation hop. Each is the
	// SHA-256 hex digest of that block's revocation identifier (the §7 chain
	// fingerprint) — never the raw identifier and never the token bytes. len ==
	// AttenuationDepth+1 for a well-formed chain.
	BlockFingerprints []string
	// ParentSessions is the chain of parent_session hops appended down the fan-out
	// tree, root→leaf (doc 19 §4/§9). It is EMPTY on the base token (no parent) and
	// gains one entry per attenuation hop that re-rooted the session identity. These
	// are session_uuids (identity-lineage references), never credential material.
	ParentSessions []string
	// AttenuationDepth is 0 for the base token; each fan-out hop +1 (doc 19 §4). It
	// names how deep in the derivation tree the presented credential sits.
	AttenuationDepth int
	// PresentedSession is the session_uuid the presented (leaf) token scopes to —
	// the subagent that presented the credential (the "which subagent" axis).
	PresentedSession string
	// RootSession is the chain's ORIGINATING session_uuid (doc 19 §7): empty when
	// the presented token IS the base/root, else the root the whole chain inherits.
	// LOG-5 joins whole-chain attribution on it.
	RootSession string
	// TaskRef is the presented (leaf) token's task reference (doc 19 §4): the
	// recorded prompt/plan the subagent runs (the "for which task" axis, doc 04 §3).
	TaskRef string
	// LaunchingUser is the root-attribution claim carried unchanged down the whole
	// chain (doc 04 §5): the user the credential is attributed to (the "on behalf of
	// which user" axis). Inherited, never widened or forked at a fan-out hop.
	LaunchingUser string
}

// blockFingerprint is the stable fingerprint of one chain block: the SHA-256 hex
// digest of its revocation identifier. The revocation identifier is itself a
// chain fingerprint / unique block id (doc 19 §7) — not token plaintext — but we
// hash it to a fixed-width hex digest so the lineage carries NO raw signature
// bytes into a log (defense-in-depth on the fingerprint-only rule, doc 16 §9).
func blockFingerprint(revocationID []byte) string {
	sum := sha256.Sum256(revocationID)
	return hex.EncodeToString(sum[:])
}

// LineageFromBundle builds the doc 19 §9 token-lineage record for a presented
// token, given its bundle (carrying the per-block revocation IDs + attenuation
// depth) and the leaf claims read from the token via the substrate Verify. It is
// PURE and FINGERPRINT-ONLY: it derives the block fingerprints from the bundle's
// revocation identifiers and reads the parent_session/root/identity axes from the
// already-verified claims — the token bytes (bundle.Token) are NEVER read here.
//
// The caller supplies leafClaims (the Verify output for the presented token) so
// this function performs no crypto and no token parse: the audit path verifies
// once, then records lineage from the verified claims. parentChain is the
// root→leaf parent_session hop list reconstructed by the caller (a single token
// only exposes its leaf parent_session; the full hop list is assembled as a token
// is derived down the tree — see AppendChildLineage).
func LineageFromBundle(b *SessionTokenBundle, leafClaims SessionTokenClaims, parentChain []string) TokenLineage {
	if b == nil {
		return TokenLineage{FingerprintAlg: lineageFingerprintAlg}
	}
	fps := make([]string, 0, len(b.RevocationIDs))
	for _, rid := range b.RevocationIDs {
		fps = append(fps, blockFingerprint(rid))
	}
	var parents []string
	if len(parentChain) > 0 {
		parents = append([]string(nil), parentChain...)
	}
	return TokenLineage{
		FingerprintAlg:    lineageFingerprintAlg,
		BlockFingerprints: fps,
		ParentSessions:    parents,
		AttenuationDepth:  b.AttenuationDepth,
		PresentedSession:  leafClaims.SessionUUID,
		RootSession:       leafClaims.RootSession,
		TaskRef:           leafClaims.TaskRef,
		LaunchingUser:     leafClaims.LaunchingUser,
	}
}

// AppendChildLineage extends a parent's parent_session hop chain by the hop a
// fan-out derivation just added: when the child re-rooted the session identity
// (its leaf SessionUUID differs from the parent's), the PARENT's session_uuid is
// the new next hop. It is the bookkeeping that lets a leaf token's lineage carry
// the FULL root→leaf parent_session chain even though a single token claim only
// exposes its immediate parent_session — the audit path threads this as it walks
// the derivation, never re-deriving from token bytes.
//
// parentChain is the parent token's hop chain (root→…→parent's-parent); parentSession
// is the parent token's own session_uuid; childSession is the child's. A hop that
// did NOT re-root (childSession == parentSession: pure scope/TTL narrowing) adds
// no parent_session hop, matching the substrate's applyRootPin rule (doc 19 §7).
func AppendChildLineage(parentChain []string, parentSession, childSession string) []string {
	out := append([]string(nil), parentChain...)
	if childSession == "" || childSession == parentSession {
		return out
	}
	return append(out, parentSession)
}

// ChildDerivation bundles the fan-out output a caller threads to the audit path: a
// derived child token bundle AND its FINGERPRINT-ONLY lineage (doc 19 §9). The
// orchestrator/wrapper records Lineage onto the ValidationResult at each child's
// first presentation, and hands Bundle.Token to the child VM's step-8 entrypoint
// slot (doc 19 §4) — never logging the token (Lineage is what the audit carries).
type ChildDerivation struct {
	Bundle  *SessionTokenBundle
	Lineage TokenLineage
}

// DeriveChildSessionWithLineage is the fan-out entrypoint that ALSO populates the
// doc 19 §9 lineage: it derives one strictly-narrower child token from the parent
// (DeriveChildSession — pure, ZERO mint RPCs) and returns it WITH its full
// root→leaf lineage record, threading the parent's hop chain through. It is the
// mint-side surface the orchestrator's CreateChildSession leg drives across the
// proto seam (carried as DATA): one call yields both the opaque child token (for
// the step-8 entrypoint slot) and the fingerprint-only lineage (for LOG-5).
//
// parentChain is the parent token's root→…→parent's-parent hop chain (empty when
// the parent IS the base/root token). The returned lineage's ParentSessions is that
// chain extended by this hop (AppendChildLineage), so a leaf derived N levels deep
// carries all N parent_session hops even though the token itself only claims its
// immediate parent. resolver may be nil (v0: no role default); derivedNow zero uses
// the shim clock. FINGERPRINT-ONLY: the child token bytes are NEVER read into the
// lineage — block fingerprints come from the bundle's revocation IDs (doc 16 §9).
func (s *Shim) DeriveChildSessionWithLineage(
	parent *SessionTokenBundle,
	p ChildSessionParams,
	resolver RoleTemplateResolver,
	derivedNow time.Time,
	parentChain []string,
) (ChildDerivation, error) {
	if parent == nil || len(parent.Token) == 0 {
		return ChildDerivation{}, errNoParentToken
	}
	// Read the parent's own session_uuid from its claims so the appended hop is the
	// real parent identity (not a caller assertion). This is the same substrate
	// signature check DeriveChildSession already runs — still no mint RPC, no network.
	parentClaims, _, err := s.tokenSigner.Verify(parent.Token)
	if err != nil {
		return ChildDerivation{}, err
	}
	child, err := s.DeriveChildSession(parent, p, resolver, derivedNow)
	if err != nil {
		return ChildDerivation{}, err
	}
	childClaims, _, err := s.tokenSigner.Verify(child.Token)
	if err != nil {
		return ChildDerivation{}, err
	}
	hops := AppendChildLineage(parentChain, parentClaims.SessionUUID, childClaims.SessionUUID)
	return ChildDerivation{
		Bundle:  child,
		Lineage: LineageFromBundle(child, childClaims, hops),
	}, nil
}
