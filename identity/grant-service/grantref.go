// SPDX-License-Identifier: Apache-2.0

// The GrantRef contract — the READER side of the cross-module seam (doc 16 §9
// grant-fetch row, §5.1) — and the in-process grant RECORD model repointed onto
// the FROZEN dreamserpent.identity.v1.Grant generated type (D80; proto/FREEZE.md
// 2026-06-13; proto/dreamserpent/identity/v1/grants.proto).
//
// grant_ref is the ONLY string this standalone GOWORK=off module and the
// standalone identity/mint module agree on. The mint side WRITES it
// (mint.FormatGrantRef → GrantSet → RegisterSession); THIS side READS it
// (Service.Fetch keys the D39 store lookup on the exact same string). There is no
// compile- or test-time link between the two modules, so a unilateral format
// change on either side would silently break the per-session fetch with no build
// error.
//
// The contract MECHANISM is a committed golden round-trip fixture
// (testdata/grantref-golden.json) carried IDENTICALLY in both modules: the mint
// side's test asserts FormatGrantRef(session, service) == golden ref (writer);
// THIS module's grantref_test.go asserts ParseGrantRef(golden ref) ==
// {session, service} (reader). FormatGrantRef/ParseGrantRef below are vendored
// identically to the mint side's pair and MUST stay byte-for-byte the same wire
// shape; if this side edits them unilaterally, ITS OWN golden test fails — the
// drift breaks loudly at test time instead of silently at fetch time.
//
// THE RECORD REPOINT (this file + backend.go). The §9 grant-FETCH wire froze
// additively in dreamserpent.identity.v1; wire.go already repoints the FETCH
// surface (FetchedCredential/GrantFetchResponse) onto those generated types. But
// doc 16 §5.1 also defines the typed grant RECORD — identity × service × scope ×
// TTL — and the ISSUED{service_id} digest-tag derivation (§6). That record froze
// alongside the fetch reply as identityv1.Grant (grants.pb.go, the same package
// as grant_fetch.pb.go). GrantRecord below is a type alias onto it, so the whole
// grant model in this module speaks the frozen contract, not just the fetch reply
// — the cached-grant key (Service.Fetch keys on Grant.GrantRef) and the digest
// fact (ISSUED{Grant.ServiceId}) are now expressed in the generated record's own
// vocabulary. This is a Go-side repoint ONLY: no proto change (the record is
// already frozen), and the grant_ref/ISSUED derivations are re-expressed in terms
// of the same byte-for-byte FormatGrantRef/ParseGrantRef the golden pins, so every
// fetch/cache/lifecycle behavior is unchanged.
package grantservice

import (
	"strings"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// GrantRecord is the in-process name for one typed grant record — the doc 16 §5.1
// shape verbatim (identity × service × scope × TTL) — repointed onto the FROZEN
// dreamserpent.identity.v1.Grant generated type so the grant-service model speaks
// the same contract the mint side WRITES and the §9 fetch reply already speaks
// (wire.go). It is an alias, not a parallel struct: there is exactly one grant
// record shape in the system, the frozen one. The fields the swap path keys on
// are Grant.GrantRef (the D39 store-lookup key, the cross-module contract handle
// below) and Grant.ServiceId (the service axis the ISSUED{service_id} digest tag
// derives from). Synthetic only here (D50) — the record carries a reference, never
// secret material (the secret lives behind the Backend seam, backend.go).
type GrantRecord = identityv1.Grant

const (
	// grantRefPrefix + grantRefSep define the wire shape "grant:<session>:<service>".
	// Identical to the mint side's constants — the shared contract.
	grantRefPrefix = "grant:"
	grantRefSep    = ":"

	// issuedTagPrefix + issuedTagSuffix wrap the ISSUED{service_id} digest tag — the
	// doc 16 §6 / §5.1 cred-class fact a grant record DERIVES (never asserts
	// independently). Identical to the mint side's mint.IssuedDigestTag =
	// "ISSUED{" + service_id + "}".
	issuedTagPrefix = "ISSUED{"
	issuedTagSuffix = "}"
)

// FormatGrantRef builds the deterministic, secret-free grant handle for a
// session×service binding — vendored identically to mint.FormatGrantRef so this
// reader side and the mint writer side produce the same string. ParseGrantRef is
// its inverse; the committed golden fixture pins the round trip on both sides.
func FormatGrantRef(sessionUUID, serviceID string) string {
	return grantRefPrefix + sessionUUID + grantRefSep + serviceID
}

// ParseGrantRef is the inverse of FormatGrantRef: it splits a grant_ref back into
// its session and service axes. It is the READER half this module keys its fetch
// on. ok is false for any string that is not a well-formed grant_ref (wrong
// prefix, wrong field count, empty axis) — fail-closed parsing, identical to the
// mint side.
func ParseGrantRef(ref string) (sessionUUID, serviceID string, ok bool) {
	if !strings.HasPrefix(ref, grantRefPrefix) {
		return "", "", false
	}
	body := ref[len(grantRefPrefix):]
	sep := strings.Index(body, grantRefSep)
	if sep < 0 {
		return "", "", false
	}
	sessionUUID = body[:sep]
	serviceID = body[sep+len(grantRefSep):]
	if sessionUUID == "" || serviceID == "" {
		return "", "", false
	}
	if strings.Contains(serviceID, grantRefSep) {
		return "", "", false
	}
	return sessionUUID, serviceID, true
}

// grantRefMatches reports whether a grant_ref is the contract handle for exactly
// this (sessionUUID, serviceID) binding. Fetch uses it to reject a ref that does
// not parse to the session×service it is being fetched for — a format drift on
// the writer side surfaces here as a definitive non-match (fail-closed) rather
// than a silently wrong store lookup.
func grantRefMatches(ref, sessionUUID, serviceID string) bool {
	gotSession, gotService, ok := ParseGrantRef(ref)
	return ok && gotSession == sessionUUID && gotService == serviceID
}

// IssuedDigestTag derives the doc 16 §6 / §5.1 cred-class digest tag —
// ISSUED{service_id} — from a frozen grant RECORD. The intended service of a
// digest is a grant FACT: the tag is COMPUTED FROM the record's ServiceId, never
// asserted independently (the §11.1 step-7 invariant, "the tag is derived from the
// grant record"). It mirrors mint.IssuedDigestTag byte-for-byte and equals the
// record's own pre-derived CredClassDigestTag field when that field is populated;
// this helper recomputes it from ServiceId so a reader can derive the fact from
// the axis alone. A nil record yields the empty-service tag (ISSUED{}), the
// fail-closed zero — never a panic.
func IssuedDigestTag(g *GrantRecord) string {
	return issuedTagPrefix + g.GetServiceId() + issuedTagSuffix
}

// grantRecordRef is the D39 store-lookup key for a grant record: the record's own
// grant_ref. The repoint expresses the cached-grant key (Service.Fetch keys the
// backend lookup on grant_ref) in the frozen record's vocabulary — a record IS
// what carries the grant_ref the fetch presents. A nil record yields the empty
// string (no key), which fails closed through the existing fetch guards.
func grantRecordRef(g *GrantRecord) string {
	return g.GetGrantRef()
}

// grantRecordMatches reports whether a grant RECORD is the contract handle for
// exactly this (sessionUUID, serviceID) binding — the record-typed form of
// grantRefMatches: a record whose grant_ref parses back to this session×service.
// It lets the reader-side fail-closed guard be expressed against the frozen
// record, not just the raw string, while keeping the identical fail-closed
// semantics (a drifted or mis-bound record is a definitive non-match).
func grantRecordMatches(g *GrantRecord, sessionUUID, serviceID string) bool {
	return grantRefMatches(grantRecordRef(g), sessionUUID, serviceID)
}
