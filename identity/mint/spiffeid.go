// SPDX-License-Identifier: Apache-2.0

// The typed SPIFFE-ID / URI-SAN model (doc 16 §3.1).
//
// §3.1 adopts the SPIFFE-compatible URI-SAN naming scheme
// `spiffe://<org>/session/<session_uuid>` for the workload identity document, "so
// the M3 SPIRE migration is a pure substrate swap." This file gives that string a
// TYPED home: a SpiffeID{TrustDomain, Path} value with a parser and a Build helper
// that reproduces the legacy spiffeURI output BYTE-FOR-BYTE — the M1<->SPIFFE
// naming correspondence the swap relies on.
//
// The correspondence is exact and load-bearing: the M1 own-CA substrate stamps the
// org as the SPIFFE trust domain and `session/<session_uuid>` as the path, and a
// SPIRE-backed substrate swapping in beside it (behind the WorkloadAuthority seam,
// mint.go) MUST name workloads identically or the swap stops being pure. So Build
// and ParseSpiffeID round-trip, and Build matches spiffeURI character for
// character. This is a NAMING model only — no key material, no live SPIFFE Workload
// API, no go-spiffe dependency (D50 synthetic posture: the substrate swap is faked
// from documented wire shapes, never live SPIRE infra).
package mint

import (
	"errors"
	"strings"
)

// spiffeScheme is the fixed SPIFFE URI scheme (`spiffe`). A SPIFFE ID is always
// `spiffe://<trust-domain>/<path>` per the SPIFFE-ID spec, which doc 16 §3.1
// adopts wholesale.
const spiffeScheme = "spiffe"

// spiffeSessionSegment is the first path segment doc 16 §3.1 fixes for a session
// workload: `spiffe://<org>/session/<session_uuid>`. The org is the trust domain,
// `session` groups the per-session leaf path.
const spiffeSessionSegment = "session"

// SpiffeID is the typed SPIFFE identity (doc 16 §3.1) the workload-identity URI
// SAN and the JWT `sub` both name. TrustDomain is the authority component
// (`<org>` in the §3.1 scheme); Path is the hierarchical name within it
// (`/session/<session_uuid>`), ALWAYS leading-slash-prefixed when non-empty, so
// String() reassembles the canonical `spiffe://<trust-domain><path>` form
// byte-for-byte. The split is the SPIFFE-ID model proper, decoupled from the M1
// own-CA string-concatenation so a SPIRE-backed substrate (behind the
// WorkloadAuthority seam) can produce the SAME name without re-deriving the format.
type SpiffeID struct {
	// TrustDomain is the SPIFFE trust domain — the org at M0/M1 (doc 16 §3.1).
	// Non-empty for any valid ID.
	TrustDomain string
	// Path is the workload path within the trust domain, leading-slash-prefixed
	// (e.g. `/session/<session_uuid>`). Empty path is a bare trust-domain ID.
	Path string
}

// String renders the canonical SPIFFE URI `spiffe://<trust-domain><path>`. For a
// session workload built via Build this is identical to the legacy spiffeURI
// output byte-for-byte (the M1<->SPIFFE naming correspondence the swap relies on).
func (id SpiffeID) String() string {
	return spiffeScheme + "://" + id.TrustDomain + id.Path
}

var (
	// errSpiffeScheme is returned when the URI is not a spiffe:// URI.
	errSpiffeScheme = errors.New("mint: not a spiffe:// uri")
	// errSpiffeTrustDomain is returned when the trust domain (authority) is empty.
	errSpiffeTrustDomain = errors.New("mint: spiffe uri has empty trust domain")
)

// ParseSpiffeID parses a SPIFFE URI string into the typed SpiffeID, validating
// scheme=spiffe and a non-empty trust domain (doc 16 §3.1). It does NOT use
// net/url so it cannot silently accept percent-encoded or userinfo-bearing
// authorities the SPIFFE-ID spec forbids — the format is owned here (the M0
// "format owned behind the seam" posture, doc 16 §12). The path is preserved
// verbatim including its leading slash, so ParseSpiffeID(Build(org, session))
// round-trips: the resulting SpiffeID.String() equals the input.
func ParseSpiffeID(uri string) (SpiffeID, error) {
	const prefix = spiffeScheme + "://"
	if !strings.HasPrefix(uri, prefix) {
		return SpiffeID{}, errSpiffeScheme
	}
	rest := uri[len(prefix):]
	// The authority runs to the first slash (the start of the path) or the end of
	// the string (a bare trust-domain ID). Everything from that slash on is the
	// path, kept verbatim incl. the leading slash so String() reassembles exactly.
	var trustDomain, path string
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		trustDomain, path = rest[:i], rest[i:]
	} else {
		trustDomain = rest
	}
	if trustDomain == "" {
		return SpiffeID{}, errSpiffeTrustDomain
	}
	return SpiffeID{TrustDomain: trustDomain, Path: path}, nil
}

// BuildSessionSpiffeID builds the §3.1 session workload SpiffeID: trust domain =
// org, path = `/session/<session_uuid>`. It is the typed constructor for the
// naming scheme the M1 own-CA substrate stamps and a SPIRE-backed substrate must
// reproduce.
func BuildSessionSpiffeID(org, sessionUUID string) SpiffeID {
	return SpiffeID{TrustDomain: org, Path: "/" + spiffeSessionSegment + "/" + sessionUUID}
}

// Build reproduces the legacy spiffeURI(org, sessionUUID) output BYTE-FOR-BYTE
// (`spiffe://<org>/session/<session_uuid>`), now via the typed model. It is the
// single naming helper the M1 own-CA mint and any swapped-in SPIRE-backed mint
// share, so the URI SAN, the JWT `sub`, and the grant identity axis stay
// identical across the substrate swap (doc 16 §3.1 — the swap stays pure). The
// equality Build(org, s) == spiffeURI(org, s) is asserted in the round-trip test.
func Build(org, sessionUUID string) string {
	return BuildSessionSpiffeID(org, sessionUUID).String()
}
