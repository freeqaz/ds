package policylog

// This file is the CONTROL-PLANE policy COMPOSITION leg (doc 15 §5.3, doc 13 §1
// rule 2 / §5): the layers system-baseline → org → repo/session compose with
// DENY-OVERRIDES, and the composed document — never a single layer — is what the
// WatchPolicies snapshot carries (D36/D72). Composition is the orchestrator's
// job, not the consumer's: hosts receive the deny-wins composed OUTPUT, never
// raw layers to compose themselves (doc 13 §1 rule 1, the one-evaluator rule).
//
// Snapshot identity is the §5 tuple (seq, content_hash, composed policy): the
// composed document is serialized produce-once via the nftbridge canonicalizer
// (doc 13 §5.1, D120) and hashed with nftbridge.HashPayload — the SAME
// canonicalizer the host agent and ds-contracts cross-check, so the snapshot the
// control plane composes hashes on the identical path the consumers verify.
//
// Per-session sections (doc 13 §5 composite reading, D120): the composed host
// document is shared system/org material plus a repeated per-session section
// keyed by session_id, each carrying that session's deny-wins composed policy
// folded with its live TTL'd ask-grants (§4.3). The composite rollup is
// nftbridge.ComposeHostDocument; this file builds the layer model it consumes.
//
// What is opaque here: the POL-1 v0 field inventory lives in ds-contracts (doc
// 13 §2/§3) — this control-plane composition operates on the deny-overrides
// rule-set STRUCTURE (the layer's allow/deny rule keys), not the full field
// schema. The structural deny-wins fold is the frozen invariant (doc 13 §1 rule
// 2); the per-rule field shape is the consumer-side evaluator's concern.
//
// Governing decisions: D36 (audit/version), D72 (topology/snapshot identity),
// D120 (content_hash canonicalization). Primary doc: docs/15 §5.3, docs/13 §1/§5.

import (
	"encoding/hex"
	"sort"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nftbridge"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// LayerScope names where a policy layer applies in the deny-overrides stack (doc
// 13 §1 rule 2): system-baseline → org → repo/session, composed in that order.
// The order is fixed; deny-wins makes the composed result independent of layer
// order for denies, but the stack order is recorded for provenance (POL-3) and
// so an allow at a narrower scope can never re-admit what a broader layer denied.
type LayerScope string

const (
	// LayerSystemBaseline is the broadest layer: the system baseline pack every
	// session inherits (doc 13 §1 rule 2, the leftmost layer).
	LayerSystemBaseline LayerScope = "system_baseline"
	// LayerOrg is the org-wide layer composed over the baseline.
	LayerOrg LayerScope = "org"
	// LayerRepoSession is the narrowest layer: repo/session-scoped policy composed
	// last. It can ADD allows and ADD denies, but never re-admit a broader deny
	// (deny-overrides, doc 13 §1 rule 2).
	LayerRepoSession LayerScope = "repo_session"
)

// layerOrder is the fixed compose order (broad → narrow). A layer with an
// unrecognized scope sorts after the known ones so an unknown layer can still
// only ADD denies (fail-closed), never re-admit.
var layerOrder = map[LayerScope]int{
	LayerSystemBaseline: 0,
	LayerOrg:            1,
	LayerRepoSession:    2,
}

func scopeRank(s LayerScope) int {
	if r, ok := layerOrder[s]; ok {
		return r
	}
	return len(layerOrder) // unknown scopes compose last (still deny-only effect)
}

// Layer is one policy layer's structural contribution to the deny-overrides
// composition: the rule keys it ALLOWS and the rule keys it DENIES at its scope.
// The full POL-1 field shape of each rule is opaque to the control plane (it
// lives in ds-contracts, doc 13 §3); composition here folds the allow/deny rule
// SETS, which is what deny-overrides operates on (doc 13 §1 rule 2). A rule key
// is the matched-rule id the consumer-side evaluator keys on (POL-3 provenance).
type Layer struct {
	Scope LayerScope // where it applies in the stack (broad → narrow)
	Allow []string   // rule keys this layer admits
	Deny  []string   // rule keys this layer blocks (deny ALWAYS wins, doc 13 §1 rule 2)
}

// ComposedPolicy is the deny-overrides result of composing a layer stack (doc 13
// §1 rule 2): the effective allow set (every allowed rule key that NO layer
// denies) and the union of every layer's denies. Deny-wins makes Deny a pure
// union; an allow survives only if it is admitted by some layer AND denied by
// none. This is the composed OUTPUT the snapshot carries — never the raw layers.
type ComposedPolicy struct {
	// Allow is the effective allow set: rule keys admitted by some layer and
	// denied by no layer, sorted (deterministic for the canonical hash).
	Allow []string
	// Deny is the union of every layer's denies, sorted. A deny here overrides any
	// allow for the same key at any scope (doc 13 §1 rule 2).
	Deny []string
}

// ComposeLayers folds a layer stack into its deny-overrides ComposedPolicy (doc
// 13 §1 rule 2). The fold is order-independent for the RESULT (deny is a union;
// an allow survives iff denied nowhere), but layers are composed broad → narrow
// so the operation matches the frozen stack semantics and an unknown-scope layer
// can only contribute denies. The composed document — this output — is what the
// snapshot carries; raw layers never reach the host (doc 13 §1 rule 1).
func ComposeLayers(layers []Layer) ComposedPolicy {
	// Compose in fixed broad → narrow order. Copy so the caller's slice is intact.
	ordered := make([]Layer, len(layers))
	copy(ordered, layers)
	sort.SliceStable(ordered, func(i, j int) bool {
		return scopeRank(ordered[i].Scope) < scopeRank(ordered[j].Scope)
	})

	denySet := map[string]struct{}{}
	allowSet := map[string]struct{}{}
	for _, l := range ordered {
		for _, d := range l.Deny {
			denySet[d] = struct{}{}
		}
		for _, a := range l.Allow {
			allowSet[a] = struct{}{}
		}
	}

	// Deny-overrides: an allow survives only if NO layer denies it (doc 13 §1
	// rule 2 — blocklists always win, regardless of which scope admits).
	allow := make([]string, 0, len(allowSet))
	for a := range allowSet {
		if _, denied := denySet[a]; denied {
			continue // deny wins
		}
		allow = append(allow, a)
	}
	deny := make([]string, 0, len(denySet))
	for d := range denySet {
		deny = append(deny, d)
	}
	sort.Strings(allow)
	sort.Strings(deny)
	return ComposedPolicy{Allow: allow, Deny: deny}
}

// composed-document field keys. Fixed by this composition (doc 13 §5.1: keyed
// collections are explicit, never per-library proto-JSON defaults); the
// canonicalizer emits members in UTF-16 key order, so these names are part of
// the hashed structure.
const (
	keyAllow  = "allow"
	keyDeny   = "deny"
	keyGrants = "grants"
	keyRule   = "rule"
	keyExpiry = "expires_at_unix"
	// keyFleetForbidden is the host-document SHARED-block member carrying the POL-4
	// fleet-scope forbidden-digest set (the enforcement clock, doc 16 §6.2). It is
	// host-wide (fleet-scope, never per-session), so it rides the shared material the
	// composite host document already carries — folded into the SAME produce-once
	// hashed document so a revoke changes the content_hash within one compose cycle.
	keyFleetForbidden = "fleet_forbidden"
	// keyFleetKey / keyFleetEntry are the two members of one forbidden-digest object:
	// the HMAC key id it was derived under and the hex content-id of the entry (D73).
	keyFleetKey   = "key"
	keyFleetEntry = "entry"
)

// asValue renders a ComposedPolicy as a canonical nftbridge.Value: an object
// {allow, deny} of sorted string arrays. This is the per-section composed policy
// body the composite host document carries (doc 13 §5 composite reading) — the
// deny-overrides output, never raw layers. Grant folding is layered on top by
// SessionComposite so the live ask-grants ride the same hashed section.
func (c ComposedPolicy) asValue() nftbridge.Value {
	allowArr := nftbridge.NewArray()
	for _, a := range c.Allow {
		allowArr.Append(nftbridge.Str(a))
	}
	denyArr := nftbridge.NewArray()
	for _, d := range c.Deny {
		denyArr.Append(nftbridge.Str(d))
	}
	return nftbridge.NewObject().
		Set(keyAllow, allowArr).
		Set(keyDeny, denyArr)
}

// SessionComposite is one session's contribution to the composite host document
// (doc 13 §5, D120): its session_id, the deny-overrides composed policy for it,
// and the live TTL'd ask-grants (§4.3) that ride the same per-session section.
// Ask-grants are policy artifacts under the policy_log seq — swept derived state
// folded into the composed section, not a second contract (doc 15 §4.3).
type SessionComposite struct {
	SessionID string
	Composed  ComposedPolicy
	// Grants are the session's live (non-expired) ask-grant rule keys, sorted; the
	// section folds them as an explicit `grants` member so a granted allow rides
	// the same hashed section as the composed policy. A grant denied by a broader
	// layer does NOT re-admit (deny-overrides applies to grants too).
	Grants []LiveGrant
}

// LiveGrant is one live ask-grant folded into a session section: the matched
// rule key it admits and its TTL expiry (unix seconds; 0 = no expiry recorded).
// The grant body itself (the POL-1 contribution) is opaque; the snapshot folds
// the rule key + expiry so the composed section is deterministic and the grant's
// liveness is auditable in the hashed document.
type LiveGrant struct {
	Rule        string
	ExpiresUnix int64
}

// asSection renders a SessionComposite as an nftbridge.SessionSection: the
// composed {allow, deny} object extended with a sorted `grants` array of
// {rule, expires_at_unix}. Deny-overrides applies to grants — a grant whose rule
// is denied by the composed policy is dropped (a grant can never re-admit what a
// layer denies, doc 13 §1 rule 2 / §8 "expiry is not revocation").
func (s SessionComposite) asSection() nftbridge.SessionSection {
	policy := s.Composed.asValue().(*nftbridge.Object)

	denied := map[string]struct{}{}
	for _, d := range s.Composed.Deny {
		denied[d] = struct{}{}
	}
	grants := make([]LiveGrant, 0, len(s.Grants))
	for _, g := range s.Grants {
		if _, isDenied := denied[g.Rule]; isDenied {
			continue // deny wins over a grant too
		}
		grants = append(grants, g)
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Rule != grants[j].Rule {
			return grants[i].Rule < grants[j].Rule
		}
		return grants[i].ExpiresUnix < grants[j].ExpiresUnix
	})
	grantArr := nftbridge.NewArray()
	for _, g := range grants {
		grantArr.Append(nftbridge.NewObject().
			Set(keyRule, nftbridge.Str(g.Rule)).
			Set(keyExpiry, nftbridge.Int64String(g.ExpiresUnix)))
	}
	policy.Set(keyGrants, grantArr)
	return nftbridge.SessionSection{SessionID: s.SessionID, Policy: policy}
}

// Snapshot is the §5 snapshot identity (seq, content_hash, composed policy
// document) — the composed OUTPUT the WatchPolicies stream carries (D36/D72).
// Seq is the policy_log bigserial (THE single policy version namespace); Document
// is the produce-once canonical bytes of the composite host document; ContentHash
// is SHA-256 over exactly those bytes (doc 13 §5.1, D120). Sections are the
// per-session sub-hashes so a one-session change re-hashes one section.
type Snapshot struct {
	Seq         int64
	ContentHash nftbridge.ContentHash
	Document    []byte
	Sections    []nftbridge.SectionHash
	// FleetForbidden is the POL-4 fleet-scope forbidden-digest set folded into this
	// snapshot's shared block (the enforcement clock, doc 16 §6.2): the live,
	// latest-per-key forbidden digests the host must drop from the enforced set.
	// Carried on the snapshot (not only inside Document) so a caller can observe the
	// enforced set directly; the load-bearing copy is the one hashed into Document.
	FleetForbidden []ForbiddenDigest
	// FleetRevoked is the sorted set of HMAC key ids whose latest fleet-digest
	// artifact retired their digests — the revocation effect this snapshot enforces.
	FleetRevoked []string
}

// ComposeSnapshot builds the §5 snapshot for seq from the shared system/org
// composed material and the per-session composites (doc 13 §5 composite reading,
// D120). It serializes the composite host document EXACTLY ONCE via
// nftbridge.ComposeHostDocument (the produce-once / verify-only rule, doc 13
// §5.1) and stamps seq onto the resulting (seq, content_hash, document) tuple —
// the snapshot identity the one per-host subscriber applies. Pass the shared
// composed policy (system-baseline + org, the host-wide material) as `shared`.
func ComposeSnapshot(seq int64, shared ComposedPolicy, sessions []SessionComposite) Snapshot {
	return ComposeSnapshotWithSweep(seq, shared, sessions, FleetSweep{})
}

// ComposeSnapshotWithSweep builds the §5 snapshot AND folds the POL-4 fleet-digest
// revocation sweep into it (the enforcement clock, doc 16 §6.2; D68/D72). The
// sweep's live forbidden-digest set is host-wide (fleet-scope, never per-session),
// so it folds into the SHARED block of the composite host document — the same
// produce-once hashed material ComposeHostDocument already carries — under a
// `fleet_forbidden` member. Because the forbidden set rides the produce-once bytes,
// a revoke (a sweep that drops a key's digests) changes the content_hash within one
// compose cycle, so the retired digests leave the enforced set the host applies. An
// empty sweep folds nothing (the member is omitted, §5.1 absent==omitted), so a log
// with no fleet-digest rows hashes identically to the pre-POL-4 document — the wiring
// is invisible until a fleet-digest artifact lands.
func ComposeSnapshotWithSweep(seq int64, shared ComposedPolicy, sessions []SessionComposite, sweep FleetSweep) Snapshot {
	sections := make([]nftbridge.SessionSection, 0, len(sessions))
	for _, s := range sessions {
		sections = append(sections, s.asSection())
	}
	doc := nftbridge.ComposeHostDocument(sharedWithSweep(shared, sweep), sections)
	return Snapshot{
		Seq:            seq,
		ContentHash:    doc.ContentHash,
		Document:       doc.Payload,
		Sections:       doc.Sections,
		FleetForbidden: sweep.Forbidden,
		FleetRevoked:   sweep.Revoked,
	}
}

// sharedWithSweep renders the shared host-wide material (the {allow, deny}
// deny-overrides object) extended with the POL-4 `fleet_forbidden` member when the
// sweep carries live forbidden digests. The member is a sorted array of
// {entry, key} objects — the SweepFleetDigests output is already sorted by
// (KeyID, EntryHex), so the array order is deterministic and the hashed document is
// stable. An empty forbidden set OMITS the member entirely (absent == omitted,
// §5.1) so the snapshot identity is unchanged until a fleet artifact lands; this is
// also why a REVOKE that empties the set hashes back to the no-fleet document.
func sharedWithSweep(shared ComposedPolicy, sweep FleetSweep) nftbridge.Value {
	obj := shared.asValue().(*nftbridge.Object)
	if len(sweep.Forbidden) == 0 {
		return obj
	}
	arr := nftbridge.NewArray()
	for _, f := range sweep.Forbidden {
		arr.Append(nftbridge.NewObject().
			Set(keyFleetEntry, nftbridge.Str(f.EntryHex)).
			Set(keyFleetKey, nftbridge.Str(f.KeyID)))
	}
	obj.Set(keyFleetForbidden, arr)
	return obj
}

// liveGrantsFrom projects the live (non-expired as of now) ask-grant rule keys a
// session carries, from its grant rule keys and expiries. It is the small helper
// the service uses to fold store.LiveGrants output into SessionComposite.Grants;
// kept here so the §8 "expiry gates new flows" liveness rule lives with the
// composition it feeds. A nil ExpiresUnix-equivalent (0) is treated as live (no
// recorded TTL); a non-zero expiry at or before now is dropped.
func liveGrantsFrom(grants []LiveGrant, now time.Time) []LiveGrant {
	nowUnix := now.Unix()
	out := make([]LiveGrant, 0, len(grants))
	for _, g := range grants {
		if g.ExpiresUnix != 0 && g.ExpiresUnix <= nowUnix {
			continue // expired: gates no new flow (doc 13 §1 rule 8)
		}
		out = append(out, g)
	}
	return out
}

// ---------------------------------------------------------------------------
// POL-4 fleet-digest revocation sweep (doc 16 §6.2; D72/D73/D84).
//
// FleetDigestKind rows (appended by the landed FleetDigestSink, fleetdigestsink.go)
// carry the fleet-scope FORBIDDEN digest set keyed by the HMAC key id every entry
// was derived under. They ride the SAME policy_log seq namespace as composed
// appends and ask-grants (D72 — no third channel) and are swept by the POL-4
// revocation sweep here: the composer classifies a row as a fleet-digest artifact
// by its FleetDigestKind tag (never by parsing the body), then this sweep folds
// the rows into the currently-enforced forbidden-digest set the host snapshot must
// carry.
//
// Sweep semantics (doc 16 §6.2/§6.3):
//   - Rows are folded in seq order. The LATEST artifact under a given key id is
//     authoritative for that key (a re-key / re-push appends the new artifact;
//     a later artifact under the same key id supersedes the earlier one — D73's
//     "digest-set version is a content id" property, expressed as last-write-wins
//     per key id over the single seq namespace).
//   - An EMPTY-entries artifact under a key id is a REVOKE: it retires that key's
//     fleet digests (digest.RevokeFleetPolicy's shape). The swept output drops the
//     key id's digests and records it in Revoked.
//   - The output FleetForbidden set is the UNION of every live (non-revoked,
//     latest-per-key) artifact's forbidden digests — the entries the boundary
//     enforces fleet-wide. It is deterministic (sorted) so it folds into the same
//     produce-once hashed document path as the rest of composition.
//
// What is opaque here: the per-entry POL-1 field schema (ds-contracts, doc 13 §3).
// The sweep reads only the fleet-digest envelope this package itself produces
// (fleetdigestsink.go's ds.fleet_digest.v1 framing) — the key id, the batch id, and
// the length-framed marshaled entry bytes. It identifies a forbidden digest by its
// canonical (key id, entry bytes) identity, which is exactly the content-id D73
// guarantees is stable for an equal entry.

// ForbiddenDigest is one currently-enforced fleet-scope forbidden digest as the
// POL-4 sweep emits it: the HMAC key id it was derived under and the canonical
// marshaled DigestEntry bytes (hex-encoded for a stable, comparable, sortable
// identity). The entry bytes are the produce-once content id (D73) — two equal
// entries always share this identity regardless of which producer appended them.
type ForbiddenDigest struct {
	// KeyID is the HMAC key id the entry was derived under (doc 16 §6.3). The
	// boundary selects the matching key by this id; a re-key re-pushes every live
	// digest under the new key id.
	KeyID string
	// EntryHex is the hex encoding of the canonical (deterministic) marshaled
	// DigestEntry bytes — the content-id identity (D73). Hex (not raw bytes) so the
	// value is directly sortable/comparable for a deterministic swept output.
	EntryHex string
}

// FleetSweep is the POL-4 revocation-sweep result over a run of FleetDigestKind
// rows (doc 16 §6.2). Forbidden is the currently-enforced fleet-scope forbidden
// digest set (the union of every live, latest-per-key artifact's entries), sorted
// deterministically. Revoked is the sorted set of key ids whose latest artifact
// retired their fleet digests (an empty-entries artifact). HighSeq is the greatest
// fleet-digest row seq folded (0 if none) — the policy version this sweep reflects.
type FleetSweep struct {
	// Forbidden is the live fleet-scope forbidden digest set, sorted by
	// (KeyID, EntryHex) for a deterministic, hashable output.
	Forbidden []ForbiddenDigest
	// Revoked is the sorted set of key ids whose latest fleet-digest artifact was a
	// revoke (empty entries) — recorded so the sweep's revocation effect is auditable.
	Revoked []string
	// HighSeq is the greatest FleetDigestKind row seq this sweep folded; 0 if the
	// run carried no fleet-digest rows.
	HighSeq int64
}

// SweepFleetDigests folds the FleetDigestKind rows in a policy_log run into the
// POL-4 revocation-sweep result (doc 16 §6.2). It IGNORES every non-fleet-digest
// row (composed appends, ask-grants, deny memos — they ride their own composition
// legs), classifying purely on the FleetDigestKind tag, and reads only the
// fleet-digest envelope the producer wrote (fleetdigestsink.go). Rows are folded in
// seq order so the LATEST artifact under each key id wins; an empty-entries
// artifact revokes that key's digests. A row whose body cannot be parsed is skipped
// (fail-closed: an unreadable fleet-digest artifact contributes no forbidden digest
// AND no spurious revoke — it simply does not advance that key's state).
func SweepFleetDigests(rows []store.PolicyLogRow) FleetSweep {
	// Fold in seq order so last-write-wins is well defined even if the caller hands
	// rows out of order. Copy so the caller's slice is untouched.
	fleet := make([]store.PolicyLogRow, 0, len(rows))
	for _, r := range rows {
		if r.Kind == FleetDigestKind {
			fleet = append(fleet, r)
		}
	}
	sort.SliceStable(fleet, func(i, j int) bool { return fleet[i].Seq < fleet[j].Seq })

	// latest[keyID] = the most recent artifact's entry-hex set under that key id.
	// A revoke (empty entries) sets the entry set to empty, which drops the key from
	// the live forbidden union AND marks it revoked.
	latest := map[string][]string{}
	order := []string{} // key ids in first-seen order (provenance; output re-sorts)
	seen := map[string]struct{}{}
	var highSeq int64

	for _, r := range fleet {
		if r.Seq > highSeq {
			highSeq = r.Seq
		}
		keyID, entries, ok := parseFleetEnvelope(r.Payload)
		if !ok {
			continue // fail-closed: unreadable artifact does not advance any key's state
		}
		if _, s := seen[keyID]; !s {
			seen[keyID] = struct{}{}
			order = append(order, keyID)
		}
		latest[keyID] = entries // last-write-wins; empty slice == revoke
	}

	sweep := FleetSweep{HighSeq: highSeq}
	for _, keyID := range order {
		entries := latest[keyID]
		if len(entries) == 0 {
			sweep.Revoked = append(sweep.Revoked, keyID)
			continue // revoked: no live forbidden digest under this key id
		}
		for _, e := range entries {
			sweep.Forbidden = append(sweep.Forbidden, ForbiddenDigest{KeyID: keyID, EntryHex: e})
		}
	}

	sort.Strings(sweep.Revoked)
	sort.Slice(sweep.Forbidden, func(i, j int) bool {
		if sweep.Forbidden[i].KeyID != sweep.Forbidden[j].KeyID {
			return sweep.Forbidden[i].KeyID < sweep.Forbidden[j].KeyID
		}
		return sweep.Forbidden[i].EntryHex < sweep.Forbidden[j].EntryHex
	})
	return sweep
}

// parseFleetEnvelope reads a FleetDigestKind row payload back into its key id and
// the canonical hex-encoded entry set. It is a thin hex-encoding adapter over the
// SHARED ds.fleet_digest.v1 codec (decodeFleetEnvelope, fleetdigestsink.go) — the
// exact inverse of the writer's marshalFleetArtifact, which routes through the same
// codec's encode half, so the sweep can never drift from the producer's framing. It
// returns ok=false on any framing violation (fail-closed: a malformed artifact
// advances no key's state). The sweep keys forbidden digests on a sortable,
// comparable content-id identity (D73), so the raw entry frames the codec returns
// are hex-encoded here. An entries=0 envelope decodes ok with an EMPTY entry set:
// the legitimate REVOKE shape, distinct from a parse failure.
func parseFleetEnvelope(payload []byte) (keyID string, entriesHex []string, ok bool) {
	keyID, rawEntries, ok := decodeFleetEnvelope(payload)
	if !ok {
		return "", nil, false
	}
	out := make([]string, len(rawEntries))
	for i, raw := range rawEntries {
		out[i] = hex.EncodeToString(raw)
	}
	return keyID, out, true
}
