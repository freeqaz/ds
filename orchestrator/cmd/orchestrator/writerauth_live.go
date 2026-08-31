// SPDX-License-Identifier: Apache-2.0

package main

// writerauth_live.go supplies the production adapters main.go's liveDeps wires
// onto the W2 WriterRelayService auth seams (controlplane.IdentityAssertionValidator +
// controlplane.AttachAuthValidator, declared narrow in internal/controlplane/writerrelay.go
// because the orchestrator may not import the identity/SSO or host-agent runtime modules
// directly — the only legal cross-tree import is proto/gen/go). They are the writer-seat
// twins of the Mint/Digest/Inject/Boot live edges: constructed ONLY under DS_ORCH_LIVE=1
// (a non-live run never resolves liveDeps, D50), fail-CLOSED when their backing is absent
// (a nil seam leaves RequestWriterSeat refusing Unauthenticated/PermissionDenied — no seat
// without a wired human-identity + attach check), and exercised OFFLINE by unit tests over
// synthetic fixtures (D50: no live VM/host-agent/SSO service in CI).
//
//  (1) attachTokenAuthValidator adapts the host-side per-session attach-token store
//      (internal/hypervisor/libvirt.fileAttachTokenStore, the D39 AttachTokenSource the
//      IssueAttachHandle minter issues from) onto AttachAuthValidator: a RequestWriterSeat's
//      attach_auth is validated against the SAME token file the handle carried.
//
//  (2) mvpIdentityAssertionValidator is the single-box, no-auth MVP IdentityAssertionValidator
//      (maintainer-approved, fenced behind DS_ORCH_FAKE_IDENTITY exactly as fakeidentity.go fences the
//      MVP mint). It resolves the identity_assertion — a principal the web/SSO tier already
//      verified — to the driver_identity that becomes the seat attribution.
//
//  (3) ssoIdentityAssertionValidator + liveSSOVerifier are the REAL D55/SSO identity face on
//      the same seam: selected by DS_ORCH_SSO_ISSUER, armed by DS_ORCH_SSO_LIVE, verifying
//      the assertion by OIDC discovery + JWKS signature verification (D134). Only the
//      validation against a REAL production issuer remains an operator-gated manual step.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// --- (1) D39 attach-auth: the fileAttachTokenStore adapter ---------------------------

// attachTokenAuthValidator adapts a libvirt.AttachTokenSource (the production
// fileAttachTokenStore — one host-readable JSON token file per session under
// <OverlayDir>/.ds-attach-tokens) onto controlplane.AttachAuthValidator. A
// RequestWriterSeat carries the v1 AttachHandle.AuthMaterial.token the host-agent's
// IssueAttachHandle minter issued from this SAME store (attachminter.go); this adapter
// re-reads that store and constant-time-compares the presented token against the live
// one, so a seat is granted ONLY to a caller already holding a valid, short-lived,
// session-scoped attach to THIS session (D39).
//
// The production path reads through the store's READ-ONLY libvirt.AttachTokenPeeker
// (TokenPeek): a peek returns the live persisted token the handle carried but NEVER mints
// or rewrites, so a validation for an unknown OR expired session touches no disk. This is
// what closed the anti-spray + re-mint hole: TokenFor (idempotent within the TTL) also
// MINTS a fresh token when none exists AND re-mints when the persisted one has expired, so
// validating on it turned a sprayed or stale session UUID into a disk WRITE (a caller past
// the identity gate could fill the host overlay dir; a real session's expired token got
// silently re-minted on validate). TokenPeek makes both a clean read-only refusal — no
// os.Stat pre-gate needed. The fixture path (a synthetic libvirt.AttachTokenSource with no
// on-disk store) still reads through TokenFor, which mints only in-memory.
type attachTokenAuthValidator struct {
	// peek is the read-only production store view (TokenPeek); set by the overlay
	// constructor. When non-nil it is used exclusively — no mint on any validate.
	peek libvirt.AttachTokenPeeker
	// tokens is the fixture path (a synthetic AttachTokenSource); used only when peek is nil.
	tokens libvirt.AttachTokenSource
	// now stamps the expiry comparison (defense-in-depth; the real store only ever
	// returns a live token, but a fixture may return a past expiry). nil ⇒ time.Now.
	now func() time.Time
}

// newAttachTokenAuthValidator builds the adapter over a synthetic attach-token SOURCE (the
// fixture path — TokenFor, no on-disk store). The production overlay constructor wires the
// read-only peeker instead.
//
// PEEKER PREFERENCE (defense in depth): if the injected source ALSO implements the
// read-only libvirt.AttachTokenPeeker (as the production fileAttachTokenStore does — it
// satisfies BOTH interfaces), the adapter binds the peek arm, so liveToken routes through
// TokenPeek and NEVER mints on validate. This makes the read-only posture structural for a
// FUTURE direct wiring of a real on-disk store through this constructor: today only
// newAttachTokenAuthValidatorForOverlay is peek-safe by convention, but a caller that
// threaded a real store in here (e.g. a wiring refactor) would otherwise silently
// reintroduce the mint-on-validate spray/re-mint hole TokenPeek was added to close. A pure
// fixture source (TokenFor only, no peeker) keeps the in-memory mint arm — its TokenFor
// mints nothing to disk.
func newAttachTokenAuthValidator(tokens libvirt.AttachTokenSource) *attachTokenAuthValidator {
	v := &attachTokenAuthValidator{tokens: tokens}
	if peek, ok := tokens.(libvirt.AttachTokenPeeker); ok {
		v.peek = peek
	}
	return v
}

// newAttachTokenAuthValidatorForOverlay builds the adapter over the production
// fileAttachTokenStore rooted at the host's overlay dir (the SAME dir the co-located
// host-agent mints attach tokens under — libvirt.NewFileAttachTokenStore). It is the
// single-box MVP wiring: with DS_ORCH_OVERLAY_DIR set, the orchestrator validates
// attach_auth against the very files the host-agent issued handles from. A zero ttl takes
// the store's default (attachHandleTTL). An empty overlayDir is a caller error (liveDeps
// only calls this inside the DS_ORCH_OVERLAY_DIR block).
func newAttachTokenAuthValidatorForOverlay(overlayDir string) (*attachTokenAuthValidator, error) {
	if overlayDir == "" {
		return nil, fmt.Errorf("writer attach-auth validator: empty overlay dir")
	}
	store, err := libvirt.NewFileAttachTokenStore(overlayDir, 0)
	if err != nil {
		return nil, fmt.Errorf("writer attach-auth validator: %w", err)
	}
	// The store is read through its READ-ONLY peeker: a validation for a session the
	// host-agent never issued a handle for (or whose token expired) is a clean refusal that
	// mints NOTHING — no disk write on a sprayed or stale UUID, no os.Stat pre-gate needed.
	return &attachTokenAuthValidator{peek: store}, nil
}

// ValidateAttachAuth validates the presented attach_auth token for sessionUUID against the
// store's live token. ok=false is a clean refusal (empty inputs, an expired stored token,
// or a mismatch — the handler maps it to PermissionDenied); a non-nil err is a transient
// store fault (the handler surfaces Unavailable). It NEVER returns ok=true on an empty
// presented token (fail-closed) and compares in constant time (no timing oracle on the
// D39 credential).
func (v *attachTokenAuthValidator) ValidateAttachAuth(ctx context.Context, sessionUUID string, token []byte) (bool, error) {
	if v == nil || (v.peek == nil && v.tokens == nil) {
		return false, nil
	}
	if sessionUUID == "" || len(token) == 0 {
		return false, nil
	}
	want, expiresAt, ok, err := v.liveToken(ctx, sessionUUID)
	if err != nil {
		return false, fmt.Errorf("resolve attach token for session %q: %w", sessionUUID, err)
	}
	// No live token: a session the host-agent never issued a handle for, or an expired one.
	// A clean refusal — and, on the production peek path, one that minted/rewrote NOTHING.
	if !ok {
		return false, nil
	}
	// Defense-in-depth expiry gate: the peek path already filters expired, but a fixture
	// source may hand back a past expiry — treat it as a clean refusal, never accepted.
	if !expiresAt.IsZero() && !v.clock().Before(expiresAt) {
		return false, nil
	}
	if subtle.ConstantTimeCompare(token, want) != 1 {
		return false, nil
	}
	return true, nil
}

// liveToken resolves the session's live token through the read-only production peeker when
// wired (TokenPeek — never mints, ok=false for an unknown/expired session), else through
// the fixture source (TokenFor — mints only in-memory; a non-empty token is treated as
// live and the caller's expiry gate arbitrates).
func (v *attachTokenAuthValidator) liveToken(ctx context.Context, sessionUUID string) (token []byte, expiresAt time.Time, ok bool, err error) {
	if v.peek != nil {
		return v.peek.TokenPeek(ctx, sessionUUID)
	}
	tok, exp, ferr := v.tokens.TokenFor(ctx, sessionUUID)
	if ferr != nil {
		return nil, time.Time{}, false, ferr
	}
	return tok, exp, len(tok) > 0, nil
}

func (v *attachTokenAuthValidator) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

var _ controlplane.AttachAuthValidator = (*attachTokenAuthValidator)(nil)

// --- (2) D22/D55 human identity: the single-box MVP assertion validator --------------

// mvpIdentityAssertionValidator is the single-box, no-auth MVP
// controlplane.IdentityAssertionValidator (maintainer-approved, fenced behind
// DS_ORCH_FAKE_IDENTITY, reachable only under DS_ORCH_LIVE=1 — D50). It treats the
// identity_assertion as a principal the web/SSO tier already verified and resolves it to
// the driver_identity that becomes the seat attribution (doc 15 §5.4 / D8 / D55). It runs
// in one of two modes:
//
//   - allow-map (fixtures): only the mapped assertions are accepted, each resolving to its
//     configured driver_identity — a CLOSED principal set for a contained dev box.
//   - passthrough (allow-map nil/empty): any non-empty, trimmed assertion is accepted and
//     resolves to itself (the pure no-auth posture — no real principal check, the honest
//     MVP contract, NO real credential is validated).
//
// An empty/whitespace assertion, or one absent from a non-empty allow-map, is a clean
// refusal (ok=false → the handler refuses Unauthenticated). It NEVER returns a transient
// err (there is no backend to fault). The REAL D55/SSO identity face — a validator dialing
// a live SSO/OIDC issuer to verify the assertion and resolve the principal — slots onto
// this SAME seam: ssoIdentityAssertionValidator below, selected by DS_ORCH_SSO_ISSUER
// (which takes precedence over this fake gate).
type mvpIdentityAssertionValidator struct {
	// allow maps a verified assertion → the resolved driver_identity. nil/empty selects
	// passthrough mode (any non-empty assertion resolves to itself).
	allow map[string]string
}

// newMVPIdentityAssertionValidator builds the MVP validator. A nil/empty allow map selects
// passthrough (no-auth) mode; a non-empty map is a closed fixture set (only its assertions
// are accepted). Keys/values are trimmed; empty keys or values are dropped (a malformed
// entry never fabricates a wildcard or an empty-driver grant).
func newMVPIdentityAssertionValidator(allow map[string]string) *mvpIdentityAssertionValidator {
	if len(allow) == 0 {
		return &mvpIdentityAssertionValidator{}
	}
	clean := make(map[string]string, len(allow))
	for k, val := range allow {
		k, val = strings.TrimSpace(k), strings.TrimSpace(val)
		if k == "" || val == "" {
			continue
		}
		clean[k] = val
	}
	if len(clean) == 0 {
		return &mvpIdentityAssertionValidator{}
	}
	return &mvpIdentityAssertionValidator{allow: clean}
}

// ValidateAssertion resolves the identity_assertion to the seat's driver_identity. In
// passthrough mode a non-empty trimmed assertion resolves to itself; in allow-map mode the
// trimmed assertion must be a mapped key. An empty/whitespace assertion, or an unmapped one
// (allow-map mode), returns ok=false — a clean refusal the handler maps to Unauthenticated.
// err is always nil (no backend to fault).
func (m *mvpIdentityAssertionValidator) ValidateAssertion(_ context.Context, _ string, assertion string) (string, bool, error) {
	principal := strings.TrimSpace(assertion)
	if principal == "" {
		return "", false, nil
	}
	if len(m.allow) == 0 {
		// Passthrough (no-auth): the assertion IS the pre-verified principal.
		return principal, true, nil
	}
	driver, ok := m.allow[principal]
	if !ok {
		return "", false, nil
	}
	return driver, true, nil
}

var _ controlplane.IdentityAssertionValidator = (*mvpIdentityAssertionValidator)(nil)

// --- (3) D55/SSO human identity: the dialed SSO/OIDC assertion validator --------------

// assertionVerifier is the NARROW dial seam the production SSO validator verifies a
// RequestWriterSeat's identity_assertion through. In production it is a client that dials
// the real SSO/OIDC identity face (liveSSOVerifier); in tests it is a synthetic fixture,
// so ssoIdentityAssertionValidator's accept/reject/fault arms are exercised OFFLINE with
// no live SSO (D50). It is declared here (not in controlplane) because the dial adapter is
// the cross-tree edge the orchestrator keeps in main — the only legal cross-tree import is
// proto/gen/go (D80), so a real SSO client slots in here without leaking into the seam.
//
// Verify returns the resolved principal (the driver_identity attribution) on a VALID
// assertion (ok=true); a clean rejection of an invalid/expired assertion (ok=false, nil
// err — the validator maps it to Unauthenticated); or a non-nil err for a transient
// dial/verify FAULT (SSO unreachable, a malformed response — the validator fails CLOSED,
// surfacing it so the handler returns Unavailable and NO seat is granted on an
// unverified assertion).
type assertionVerifier interface {
	Verify(ctx context.Context, sessionUUID, assertion string) (principal string, ok bool, err error)
}

// ssoIdentityAssertionValidator is the production controlplane.IdentityAssertionValidator
// that resolves a RequestWriterSeat's identity_assertion by DIALING the real D55/SSO/OIDC
// identity face (through the injected assertionVerifier seam) rather than trusting an
// already-verified principal like the single-box MVP validator does. It is the deferred
// live edge slotting onto the SAME seam: fail-CLOSED on every uncertainty — an empty
// assertion is refused WITHOUT dialing (a clean Unauthenticated), a nil verifier refuses
// (no SSO wired ⇒ no seat), a dial/verify FAULT is surfaced (Unavailable — never an
// accepted seat on an unverified assertion), and a rejection or empty resolved principal
// is a clean Unauthenticated. Only a verifier that affirmatively resolved a non-empty
// principal yields ok=true.
type ssoIdentityAssertionValidator struct {
	verifier assertionVerifier
}

// newSSOIdentityAssertionValidator builds the dialed SSO validator over an
// assertionVerifier (the real SSO/OIDC dial adapter in production, a synthetic fixture in
// tests). A nil verifier is permitted (the validator then fails CLOSED — every assertion
// is refused), so a half-wired deployment never grants an unverified seat.
func newSSOIdentityAssertionValidator(verifier assertionVerifier) *ssoIdentityAssertionValidator {
	return &ssoIdentityAssertionValidator{verifier: verifier}
}

// ValidateAssertion verifies the identity_assertion through the SSO dial seam and resolves
// it to the seat's driver_identity. It runs the identity_assertion SHAPE pre-gate FIRST
// (identityAssertionShapeErr — the token-shape contract pinned at this validator edge): an
// empty/whitespace OR structurally-malformed assertion (not a compact OIDC ID-token JWS) is
// refused WITHOUT ever dialing the verifier (ok=false, nil err ⇒ Unauthenticated — no wasted
// dial/verify on a credential that cannot be a valid ID token). Past the pre-gate: a nil
// verifier fails CLOSED (ok=false ⇒ refusal); a transient dial/verify fault is surfaced as a
// non-nil err (the handler returns Unavailable, no seat); a rejection or an empty resolved
// principal is a clean refusal (ok=false ⇒ Unauthenticated). Only an affirmatively-verified,
// non-empty principal returns ok=true.
func (v *ssoIdentityAssertionValidator) ValidateAssertion(ctx context.Context, sessionUUID string, assertion string) (string, bool, error) {
	assertion = strings.TrimSpace(assertion)
	if assertion == "" {
		return "", false, nil
	}
	// SHAPE PRE-GATE (defense in depth, at the validator edge): refuse a structurally
	// malformed assertion BEFORE any dial — a clean Unauthenticated refusal, never a
	// transient fault (a bad-shaped credential is the caller's error, not the SSO face's).
	// This pins the identity_assertion token shape wcidentsrc documents on the sender side.
	if err := identityAssertionShapeErr(assertion); err != nil {
		return "", false, nil
	}
	if v == nil || v.verifier == nil {
		// Fail CLOSED: no SSO dial wired ⇒ no seat on an unverified assertion.
		return "", false, nil
	}
	principal, ok, err := v.verifier.Verify(ctx, sessionUUID, assertion)
	if err != nil {
		// Transient dial/verify FAULT: fail closed, surface it so the handler returns
		// Unavailable. A seat is NEVER granted on an assertion the SSO face did not verify.
		return "", false, fmt.Errorf("dial SSO to verify identity assertion for session %q: %w", sessionUUID, err)
	}
	if !ok {
		return "", false, nil
	}
	principal = strings.TrimSpace(principal)
	if principal == "" {
		// SSO verified the assertion but resolved no principal — refuse (never an empty
		// driver attribution on a granted seat, D8/D55).
		return "", false, nil
	}
	return principal, true, nil
}

var _ controlplane.IdentityAssertionValidator = (*ssoIdentityAssertionValidator)(nil)

// --- The identity_assertion token-shape contract (pinned here, cited by wcidentsrc) ------
//
// THE ASSERTION SHAPE (single source of truth for the writer-seat identity_assertion; the
// paid/webclient sender documents this shape citing THIS comment, wave unit wcidentsrc):
//
//	identity_assertion := an OIDC ID token in JWS COMPACT serialization —
//	    BASE64URL(UTF8(ProtectedHeader)) "." BASE64URL(Payload) "." BASE64URL(Signature)
//	    (three non-empty, unpadded base64url segments separated by two '.').
//
//	ProtectedHeader (JSON object):
//	    alg  REQUIRED, one of {"RS256","ES256"} (the D134 allowlist; "none"/any other alg
//	         is a hard refusal). kid REQUIRED (resolves the verifying key in the issuer's
//	         discovered JWKS — D134: JWKS-only, never a self-declared jku/x5u/x5c). typ, if
//	         present, MUST be "JWT" (the typ-confusion defense; any other typ is refused).
//	         A non-empty "crit" is refused (no critical extension is understood — D134).
//
//	Payload (JSON claims):
//	    iss  REQUIRED, MUST equal DS_ORCH_SSO_ISSUER (the configured issuer; exact match).
//	    sub  REQUIRED — the stable subject; it becomes the resolved driver_identity
//	         attribution (D8/D55). An empty sub is refused (no empty attribution).
//	    exp  REQUIRED — the token MUST NOT be expired (now < exp, with the leeway below).
//	    nbf  OPTIONAL — if present the token MUST be active (now >= nbf - leeway).
//	    aud  OPTIONAL to verify: enforced (aud MUST contain the value) only when the
//	         operator pins DS_ORCH_SSO_AUDIENCE; unset ⇒ aud is not checked (documented gap).
//
// The signature is verified over ASCII(header) "." ASCII(payload) with the JWKS key the
// header's kid selects. EVERY uncertainty fails CLOSED (refuse; never pass-through).

const (
	// ssoHTTPTimeout bounds each discovery / JWKS fetch (a slow or hung issuer must not
	// wedge a RequestWriterSeat — it fails closed to Unavailable instead).
	ssoHTTPTimeout = 10 * time.Second
	// ssoMaxBodyBytes caps a discovery/JWKS response so a hostile/misbehaving issuer cannot
	// balloon orchestrator memory (fail closed on a body that exceeds it).
	ssoMaxBodyBytes = 1 << 20 // 1 MiB
	// ssoClockLeeway tolerates small clock skew between the orchestrator and the issuer on
	// the exp/nbf gates (defense against false rejections; small enough to stay fail-closed).
	ssoClockLeeway = 60 * time.Second
)

// liveSSOVerifier is the PRODUCTION assertionVerifier that verifies an identity_assertion
// (an OIDC ID-token JWS) against the configured SSO/OIDC issuer (DS_ORCH_SSO_ISSUER) by
// OIDC discovery + JWKS signature verification, then resolves the principal from the token
// subject. The verify is implemented HERE with the standard library only (no importable SSO
// client — D80: the orchestrator consumes only proto/gen/go across trees; no auth-sdk), and
// follows the D134 IdP-ID-token contract: the verifying key is sourced from the issuer's
// DISCOVERED JWKS resolved by the header kid (never a self-declared jku/x5u/x5c), the
// accepted alg is the fixed {RS256,ES256} allowlist, and alg:none / an unknown alg / an
// unrecognized crit member / a typ naming a distinct JOSE object are hard refusals checked
// before key resolution.
//
// It fails CLOSED on EVERY fault path — discovery failure, JWKS fetch failure, a kid that
// resolves no key, a bad signature, an expired/not-yet-valid/malformed token, an issuer or
// audience mismatch → a transient fault (surfaced as a non-nil err ⇒ handler Unavailable)
// or a clean rejection (ok=false ⇒ Unauthenticated); a seat is NEVER granted on an assertion
// this verify did not affirmatively accept.
//
// The dial is armed by DS_ORCH_SSO_LIVE=1: when unarmed the verifier faults immediately (the
// seam is wired but not dialing), so a deployment that set DS_ORCH_SSO_ISSUER without arming
// grants no seat. In CI the accept/reject/fault arms are exercised OFFLINE against a
// synthetic httptest issuer+JWKS (D50: no live SSO); validation against a REAL production
// issuer is the operator-gated deferred manual step (recorded as a taskdb note).
type liveSSOVerifier struct {
	// issuerURL is the configured SSO/OIDC issuer whose discovery doc + JWKS the handshake
	// verifies against (DS_ORCH_SSO_ISSUER). The token's iss claim MUST equal it exactly.
	issuerURL string
	// audience, when non-empty (DS_ORCH_SSO_AUDIENCE), is enforced: the token's aud claim
	// MUST contain it. Empty ⇒ aud is not checked (a documented hardening gap, not a live run).
	audience string
	// live arms the real handshake (DS_ORCH_SSO_LIVE=1). When false the verifier faults
	// immediately — the seam is wired but the dial is not armed.
	live bool
	// httpClient dials discovery + JWKS; nil ⇒ a default client with ssoHTTPTimeout. Tests
	// inject an httptest-backed client so the arms run OFFLINE (never a real network dial).
	httpClient *http.Client
	// now stamps the exp/nbf gates; nil ⇒ time.Now (tests inject a fixed clock).
	now func() time.Time
}

// Verify performs the live OIDC discovery + JWKS signature verification for assertion
// against issuerURL and resolves the token subject as the principal. When unarmed
// (DS_ORCH_SSO_LIVE unset) it faults immediately (fail-closed: seam wired, dial not armed).
// A transient dial/verify fault (discovery/JWKS unreachable or malformed) returns a non-nil
// err ⇒ the dialed validator surfaces Unavailable. A structurally/ cryptographically invalid
// or expired token, or an issuer/audience mismatch, is a clean rejection (ok=false, nil err)
// ⇒ Unauthenticated. Only an affirmatively-verified token with a non-empty subject returns
// (subject, true, nil).
func (v *liveSSOVerifier) Verify(ctx context.Context, _ string, assertion string) (string, bool, error) {
	if !v.live {
		return "", false, fmt.Errorf("SSO identity verify seam wired but not armed (set DS_ORCH_SSO_LIVE=1 to dial %q; operator-gated live edge)", v.issuerURL)
	}
	if strings.TrimSpace(v.issuerURL) == "" {
		return "", false, fmt.Errorf("SSO verify armed with no issuer (DS_ORCH_SSO_ISSUER empty)")
	}

	header, signingInput, sig, claims, err := parseCompactJWS(assertion)
	if err != nil {
		// A structurally-invalid token that slipped past the edge pre-gate: a clean rejection.
		return "", false, nil
	}
	// D134 header gate (checked BEFORE key resolution): alg allowlist, typ-confusion, crit.
	if err := checkJWSHeader(header); err != nil {
		return "", false, nil
	}

	// OIDC discovery (transient faults fail closed with a surfaced err).
	disc, err := v.discover(ctx)
	if err != nil {
		return "", false, fmt.Errorf("SSO discovery for issuer %q: %w", v.issuerURL, err)
	}
	// The discovery doc's own issuer MUST match the configured issuer (issuer-confusion
	// defense) — a mismatch is a hard, surfaced fault (misconfiguration, not a bad token).
	if disc.Issuer != v.issuerURL {
		return "", false, fmt.Errorf("SSO discovery issuer mismatch: doc says %q, configured %q", disc.Issuer, v.issuerURL)
	}

	// JWKS fetch + key resolution by kid (D134: JWKS-only key source).
	keys, err := v.fetchJWKS(ctx, disc.JWKSURI)
	if err != nil {
		return "", false, fmt.Errorf("SSO JWKS fetch from %q: %w", disc.JWKSURI, err)
	}
	pub, err := resolveJWK(keys, header.Kid, header.Alg)
	if err != nil {
		// A kid that resolves no matching key: a clean rejection (an unverifiable token),
		// NOT a transient fault — the JWKS was fetched fine, the token just isn't signed by
		// a published key.
		return "", false, nil
	}

	// Signature verification over ASCII(header)"."ASCII(payload).
	if err := verifyJWSSignature(header.Alg, pub, signingInput, sig); err != nil {
		return "", false, nil
	}

	// Claims: iss (exact), exp/nbf (with leeway), aud (iff configured), sub (non-empty).
	if claims.Iss != v.issuerURL {
		return "", false, nil
	}
	now := v.clock()
	if claims.Exp <= 0 || !now.Add(-ssoClockLeeway).Before(time.Unix(claims.Exp, 0)) {
		return "", false, nil // expired (or no exp) — refuse
	}
	if claims.Nbf > 0 && now.Add(ssoClockLeeway).Before(time.Unix(claims.Nbf, 0)) {
		return "", false, nil // not yet valid — refuse
	}
	if v.audience != "" && !claims.audienceContains(v.audience) {
		return "", false, nil // aud mismatch — refuse
	}
	sub := strings.TrimSpace(claims.Sub)
	if sub == "" {
		return "", false, nil // no subject ⇒ no driver attribution — refuse
	}
	return sub, true, nil
}

func (v *liveSSOVerifier) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

func (v *liveSSOVerifier) client() *http.Client {
	if v.httpClient != nil {
		return v.httpClient
	}
	return &http.Client{Timeout: ssoHTTPTimeout}
}

// oidcDiscovery is the subset of the OIDC provider metadata (RFC 8414 /
// openid-configuration) the verify consumes.
type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discover fetches <issuer>/.well-known/openid-configuration.
func (v *liveSSOVerifier) discover(ctx context.Context) (oidcDiscovery, error) {
	url := strings.TrimRight(v.issuerURL, "/") + "/.well-known/openid-configuration"
	var disc oidcDiscovery
	if err := v.getJSON(ctx, url, &disc); err != nil {
		return oidcDiscovery{}, err
	}
	if disc.JWKSURI == "" {
		return oidcDiscovery{}, errors.New("discovery doc has no jwks_uri")
	}
	return disc, nil
}

// fetchJWKS fetches and parses the issuer's JWKS.
func (v *liveSSOVerifier) fetchJWKS(ctx context.Context, jwksURI string) ([]jsonWebKey, error) {
	var set jsonWebKeySet
	if err := v.getJSON(ctx, jwksURI, &set); err != nil {
		return nil, err
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("JWKS has no keys")
	}
	return set.Keys, nil
}

// getJSON GETs url and decodes a (size-capped) JSON body into out. Any non-200, transport
// error, oversized body, or decode failure is a surfaced fault (fail-closed upstream).
func (v *liveSSOVerifier) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client().Do(req)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ssoMaxBodyBytes))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

var _ assertionVerifier = (*liveSSOVerifier)(nil)

// --- JWS/JWKS verification primitives (standard-library only, D134-aligned) ---------------

// ssoAllowedAlgs is the D134 signing-alg allowlist. alg:none, an unknown alg, or an
// alg/JWKS-key-type mismatch are hard refusals.
var ssoAllowedAlgs = map[string]struct{}{"RS256": {}, "ES256": {}}

// jwsHeader is the JWS protected header (the members the D134 gate inspects).
type jwsHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
}

// idTokenClaims is the subset of the OIDC ID-token payload the verify checks.
type idTokenClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"` // string OR []string per RFC 7519
	Exp int64           `json:"exp"`
	Nbf int64           `json:"nbf"`
	Iat int64           `json:"iat"`
}

// audienceContains reports whether the aud claim (a string or an array of strings) contains
// want. A malformed/absent aud contains nothing (fail-closed when an audience is enforced).
func (c idTokenClaims) audienceContains(want string) bool {
	if len(c.Aud) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(c.Aud, &single); err == nil {
		return single == want
	}
	var many []string
	if err := json.Unmarshal(c.Aud, &many); err == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// jsonWebKey / jsonWebKeySet mirror the JWK / JWKS shapes (RFC 7517) for the RSA + EC keys
// the {RS256,ES256} allowlist admits.
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

// identityAssertionShapeErr is the token-shape pre-gate (documented in the shape contract
// above): it refuses an assertion that is not a well-formed compact JWS — three non-empty
// unpadded-base64url segments, the first decoding to a JSON object that carries a signing
// alg. It performs NO cryptographic check (that is the verifier's job); it only rejects the
// structurally-impossible BEFORE any dial, so a garbage credential wastes no verify.
func identityAssertionShapeErr(assertion string) error {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return fmt.Errorf("identity_assertion is not a compact JWS: want 3 dot-separated segments, got %d", len(parts))
	}
	for i, p := range parts {
		if p == "" {
			return fmt.Errorf("identity_assertion segment %d is empty", i)
		}
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			return fmt.Errorf("identity_assertion segment %d is not unpadded base64url: %w", i, err)
		}
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("identity_assertion header decode: %w", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return fmt.Errorf("identity_assertion header is not a JSON object: %w", err)
	}
	if strings.TrimSpace(hdr.Alg) == "" {
		return errors.New("identity_assertion header carries no alg")
	}
	return nil
}

// parseCompactJWS splits + decodes a compact JWS into its header, signing input
// (ASCII(header)"."ASCII(payload)), raw signature, and decoded claims. It assumes the shape
// pre-gate already passed but re-validates defensively.
func parseCompactJWS(token string) (hdr jwsHeader, signingInput, sig []byte, claims idTokenClaims, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return hdr, nil, nil, claims, errors.New("not a compact JWS")
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return hdr, nil, nil, claims, fmt.Errorf("header decode: %w", err)
	}
	if err = json.Unmarshal(hdrJSON, &hdr); err != nil {
		return hdr, nil, nil, claims, fmt.Errorf("header unmarshal: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return hdr, nil, nil, claims, fmt.Errorf("payload decode: %w", err)
	}
	if err = json.Unmarshal(payloadJSON, &claims); err != nil {
		return hdr, nil, nil, claims, fmt.Errorf("payload unmarshal: %w", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return hdr, nil, nil, claims, fmt.Errorf("signature decode: %w", err)
	}
	signingInput = []byte(parts[0] + "." + parts[1])
	return hdr, signingInput, sig, claims, nil
}

// checkJWSHeader enforces the D134 header contract before any key resolution: the alg is in
// the {RS256,ES256} allowlist (alg:none / unknown ⇒ refuse); a non-empty crit is refused (no
// critical extension is understood); a present typ MUST be "JWT" (the typ-confusion defense);
// and a kid MUST be present (the JWKS-only key is resolved by it).
func checkJWSHeader(hdr jwsHeader) error {
	if _, ok := ssoAllowedAlgs[hdr.Alg]; !ok {
		return fmt.Errorf("alg %q not in the {RS256,ES256} allowlist", hdr.Alg)
	}
	if len(hdr.Crit) != 0 {
		return fmt.Errorf("unrecognized crit header member(s) %v", hdr.Crit)
	}
	if hdr.Typ != "" && !strings.EqualFold(hdr.Typ, "JWT") {
		return fmt.Errorf("typ %q is not a JWT (typ-confusion)", hdr.Typ)
	}
	if strings.TrimSpace(hdr.Kid) == "" {
		return errors.New("header carries no kid (JWKS key cannot be resolved)")
	}
	return nil
}

// resolveJWK finds the JWK matching kid and builds its public key, enforcing that the key
// type agrees with the header alg (RS256⇒RSA, ES256⇒EC/P-256 — the D134 alg/key-type match).
func resolveJWK(keys []jsonWebKey, kid, alg string) (crypto.PublicKey, error) {
	for _, k := range keys {
		if k.Kid != kid {
			continue
		}
		switch alg {
		case "RS256":
			if k.Kty != "RSA" {
				return nil, fmt.Errorf("kid %q kty %q mismatches alg RS256", kid, k.Kty)
			}
			return rsaPublicKeyFromJWK(k)
		case "ES256":
			if k.Kty != "EC" {
				return nil, fmt.Errorf("kid %q kty %q mismatches alg ES256", kid, k.Kty)
			}
			return ecPublicKeyFromJWK(k)
		default:
			return nil, fmt.Errorf("unsupported alg %q", alg)
		}
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

func rsaPublicKeyFromJWK(k jsonWebKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil || len(nBytes) == 0 {
		return nil, fmt.Errorf("bad RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil || len(eBytes) == 0 {
		return nil, fmt.Errorf("bad RSA exponent: %w", err)
	}
	// Left-pad the exponent to 8 bytes for a uint64, then narrow to int.
	var eBuf [8]byte
	copy(eBuf[8-len(eBytes):], eBytes)
	e := binary.BigEndian.Uint64(eBuf[:])
	if e == 0 || e > uint64(^uint32(0)) {
		return nil, fmt.Errorf("RSA exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}, nil
}

func ecPublicKeyFromJWK(k jsonWebKey) (*ecdsa.PublicKey, error) {
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported EC curve %q (want P-256 for ES256)", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(xBytes) == 0 {
		return nil, fmt.Errorf("bad EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil || len(yBytes) == 0 {
		return nil, fmt.Errorf("bad EC y: %w", err)
	}
	x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, errors.New("EC point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// verifyJWSSignature verifies sig over signingInput with pub under alg. A verification
// failure (or a key/alg mismatch) is a non-nil error ⇒ a clean rejection upstream.
func verifyJWSSignature(alg string, pub crypto.PublicKey, signingInput, sig []byte) error {
	digest := sha256.Sum256(signingInput)
	switch alg {
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("RS256 over a non-RSA key")
		}
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig)
	case "ES256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ES256 over a non-EC key")
		}
		// JOSE ES256 signature = R||S, each 32 bytes (fixed-width, big-endian).
		if len(sig) != 64 {
			return fmt.Errorf("ES256 signature length %d, want 64", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecPub, digest[:], r, s) {
			return errors.New("ES256 signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported alg %q", alg)
	}
}

// writerIdentityMode is the TYPED discriminator resolveWriterIdentityValidator returns so
// liveDeps dispatches its log line on the enum — not a brittle string prefix. It replaces
// the former free-text mode string (whose "dialed SSO" prefix main.go matched); the typed
// value cannot drift out from under the log discriminator, and its String() supplies the
// human label for the log's "mode" field.
type writerIdentityMode int

const (
	// writerIdentityNone: the seam is nil (gate off) — RequestWriterSeat fails closed.
	writerIdentityNone writerIdentityMode = iota
	// writerIdentityDialedSSO: the PRODUCTION dialed D55/SSO/OIDC validator (DS_ORCH_SSO_ISSUER).
	writerIdentityDialedSSO
	// writerIdentityMVPPassthrough: the in-process MVP validator, passthrough (no fixture set).
	writerIdentityMVPPassthrough
	// writerIdentityMVPAllowMap: the in-process MVP validator, closed DS_ORCH_MVP_IDENTITY set.
	writerIdentityMVPAllowMap
)

func (m writerIdentityMode) String() string {
	switch m {
	case writerIdentityDialedSSO:
		return "dialed SSO/OIDC (DS_ORCH_SSO_ISSUER; fail-closed until DS_ORCH_SSO_LIVE arms)"
	case writerIdentityMVPPassthrough:
		return "MVP passthrough (any non-empty assertion → itself)"
	case writerIdentityMVPAllowMap:
		return "MVP allow-map (DS_ORCH_MVP_IDENTITY fixture set)"
	default:
		return "none (seam nil, fail-closed)"
	}
}

// resolveWriterIdentityValidator resolves the W2 identity seam (Deps.WriterIdentity)
// from the environment gates — the offline-testable slice of liveDeps' wiring. getenv is
// injected (os.Getenv in main, a map lookup in tests). It resolves in precedence order:
//
//   - DS_ORCH_SSO_ISSUER set ⇒ the PRODUCTION dialed SSO/OIDC validator (takes precedence
//     over the fake gate — an issuer signals production intent). It verifies the assertion
//     by OIDC discovery + JWKS signature verification and fails CLOSED on every fault; the
//     live handshake is armed by DS_ORCH_SSO_LIVE, so until armed RequestWriterSeat stays
//     Unauthenticated/Unavailable — no seat on an unverified assertion. DS_ORCH_SSO_AUDIENCE,
//     when set, is enforced against the token aud.
//   - else DS_ORCH_FAKE_IDENTITY=1 ⇒ the single-box in-process MVP validator (passthrough,
//     or a closed allow-map when DS_ORCH_MVP_IDENTITY pins assertion=driver pairs); a
//     malformed DS_ORCH_MVP_IDENTITY is a loud error (a run that MEANT to pin a closed
//     principal set must not degrade to accept-any).
//   - else a NIL validator and writerIdentityNone: liveDeps leaves the seam nil and the
//     WriterRelayService refuses Unauthenticated fail-closed (no seat without a wired
//     human-identity check — the correct production posture until the SSO edge lands).
//
// The second return is the TYPED mode liveDeps dispatches + logs on.
func resolveWriterIdentityValidator(getenv func(string) string) (controlplane.IdentityAssertionValidator, writerIdentityMode, error) {
	// Production D55/SSO path takes precedence: the dialed validator over the real SSO/OIDC
	// face. Selected by DS_ORCH_SSO_ISSUER (the issuer URL); the live handshake is armed by
	// DS_ORCH_SSO_LIVE. This slots the real identity face onto the same seam.
	if issuer := strings.TrimSpace(getenv("DS_ORCH_SSO_ISSUER")); issuer != "" {
		v := newSSOIdentityAssertionValidator(&liveSSOVerifier{
			issuerURL: issuer,
			audience:  strings.TrimSpace(getenv("DS_ORCH_SSO_AUDIENCE")),
			live:      getenv("DS_ORCH_SSO_LIVE") == "1",
		})
		return v, writerIdentityDialedSSO, nil
	}
	if getenv("DS_ORCH_FAKE_IDENTITY") != "1" {
		// A typed-nil pointer must never leave here inside the interface (it would
		// defeat the handler's `identity == nil` fail-closed check), so the gate-off
		// arm returns the untyped nil interface value directly.
		return nil, writerIdentityNone, nil
	}
	allow, err := parseMVPIdentityAllow(getenv("DS_ORCH_MVP_IDENTITY"))
	if err != nil {
		return nil, writerIdentityNone, err
	}
	mode := writerIdentityMVPPassthrough
	if len(allow) > 0 {
		mode = writerIdentityMVPAllowMap
	}
	return newMVPIdentityAssertionValidator(allow), mode, nil
}

// parseMVPIdentityAllow parses the DS_ORCH_MVP_IDENTITY env value into an allow map. The
// format is a comma-separated list of `assertion=driver_identity` pairs (mirroring
// DS_ORCH_SEED_ENV_CONFIG's ref=value shape); an empty value selects passthrough mode
// (returns nil). A malformed pair (no `=`, empty side) is a loud misconfiguration rather
// than a silent drop — a live run that MEANT to pin a closed principal set must not
// degrade silently to accept-any.
func parseMVPIdentityAllow(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	allow := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		assertion, driver, ok := strings.Cut(pair, "=")
		assertion, driver = strings.TrimSpace(assertion), strings.TrimSpace(driver)
		if !ok || assertion == "" || driver == "" {
			return nil, fmt.Errorf("malformed DS_ORCH_MVP_IDENTITY pair %q (want assertion=driver_identity)", pair)
		}
		allow[assertion] = driver
	}
	return allow, nil
}
