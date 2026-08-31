// SPDX-License-Identifier: Apache-2.0

// The identity-mint service shim core (doc 16 §2/§4; D22/D39/D82/D85).
//
// Shim is the substrate of the Identity mint service — a SEPARATE service from the
// orchestrator (D39: dedicated instance, an orchestrator compromise never yields
// keys; doc 02 §7). It holds the two D82 root hierarchies and an in-memory session
// record store.
//
// M1 OWN-MINIMAL-CA SUBSTRATE (D22): the two D82 roots are PERSISTED in the D39
// secret-store trust zone (a local-file CAStore at the OSS tier, D85; castore.go)
// and LOADED at startup, not regenerated per-process — so a restart re-attaches to
// the same trust material rather than orphaning live sessions. The per-session
// interception CA is an INTERMEDIATE issued under the persistent interception root
// (never a fresh root), proxy-bound and destroyed at teardown (the bounded D76
// exposure, doc 16 §4). Session records stay in-memory and disposable (the D72
// session-lifecycle class); every key is synthetic (D50).
//
// Surface:
//   - MintWorkloadIdentity — hierarchy 1: an X.509 leaf with a SPIFFE-compatible
//     URI SAN + the parallel JWT presentation, the §3.1 claim set. (native)
//   - MintInterceptionCA   — hierarchy 2: a per-session interception INTERMEDIATE
//     CA issued under the persistent interception root (D82). (generated Stage-0 seam)
//   - TeardownSession      — destroys the per-session interception key + evicts the
//     session record (the doc 16 §4 teardown lifecycle / §5.4 active eviction). (native)
//   - RevokeSession        — marks the in-memory session record; Validate then
//     fails CLOSED (verdict DENY, the D77 in-band-403 shape). (native)
//   - Validate             — signature + freshness + session liveness + grant
//     lookup; the D22 seam. (generated Stage-0 seam; see validate.go)
package mint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// rootValidity bounds the synthetic persistent roots. Generous: an M1 root
	// persists across process restarts (it is loaded from the secret store, not
	// regenerated per-process), so its validity spans many session lifetimes.
	rootValidity = 365 * 24 * time.Hour
	// defaultSessionTTL is the workload-identity TTL when the caller passes none.
	// TTL = session lifetime (§3.1); the caller normally supplies the real
	// session lifetime.
	defaultSessionTTL = 8 * time.Hour
	// defaultInterceptionTTL bounds the per-session interception CA. Lifetime =
	// session (doc 16 §4); dies at teardown.
	defaultInterceptionTTL = 8 * time.Hour
	// issuerName is the JWT `iss` for the M0 shim.
	issuerName = "ds-m0-mint-shim"
)

// PrincipalResolver resolves a session's launching_user claim (doc 16 §3.1, the
// doc 04 §5 attribution promise) from whatever principal store the deployment
// runs. It is a function seam, NOT an import: the orchestrator's
// internal/store.principals is a different module that must stay untouched, so
// the linkage is injected here rather than imported (closing the
// orch3/principal-store done-when at integration without coupling the modules).
// A nil resolver means "trust the caller-supplied launching_user verbatim",
// which is the M0 stub posture (doc 16 §11.2: the human-auth step is a stub at
// M0, real IdP-asserted subject arrives at M1).
type PrincipalResolver func(sessionUUID, launchingUserHint string) (string, error)

// sessionState is the liveness bit RevokeSession flips and Validate reads.
type sessionState int

const (
	sessionLive sessionState = iota
	sessionRevoked
)

// sessionRecord is the in-memory per-session record, keyed by session UUID in
// Shim.sessions. It holds the liveness bit + revoke reason, the expiry, the
// minted workload-identity public key (for token verification on the Validate
// path), the per-session interception root (hierarchy 2, isolated per session),
// and the grant set. All disposable (D22).
type sessionRecord struct {
	state        sessionState
	expiry       time.Time
	revokeReason string

	// workloadPub verifies the presented JWT at the Validate seam.
	workloadPub *ecdsa.PublicKey
	// interceptionCA is THIS session's per-session interception intermediate CA
	// (hierarchy 2): an intermediate issued under the persistent interception root,
	// with its own key (the proxy-bound, destroyable D76 material). Its cert is also
	// the per-session trust anchor pinned in the session VM, so session A's leaves
	// never validate in session B's trust context — the §13 per-session-CA-isolation
	// property — even though both intermediates chain to the one shared root. Nil
	// until MintInterceptionCA runs; cleared+zeroed at TeardownSession.
	interceptionCA *sessionInterceptionCA
	// grants maps service_id -> grant_ref. The grant lookup at Validate (§4) is
	// a deterministic map read (no Cedar in v0, §5.1).
	grants map[string]string
	// grantRecords carries the TYPED grant record (§5.1, identity×service×scope×
	// TTL) keyed by service_id — the source the ISSUED{service_id} digest tag
	// derives from (§6) and the TTL the placeholder leg of Validate checks.
	grantRecords map[string]Grant
	// placeholders maps service_id -> the opaque per-service placeholder token
	// the agent holds (§5.1 brief gap 9). A placeholder presentation validates at
	// the D22 seam for its service ONLY, and never as workload identity.
	placeholders map[string]string
	// identity is the session's SPIFFE-compatible workload identity name (§3.1),
	// captured at MintWorkloadIdentity so the grant's identity axis is the
	// minted name rather than reconstructed.
	identity string
	// hasSessionToken records that MintSessionToken issued a doc 19 §3 scoped base
	// token for this session. A session-token presentation at Validate is rejected
	// (ReasonUnknownSession) if no token was issued for the session, so a token
	// minted for one session never validates under another's ref.
	hasSessionToken bool
}

// Shim is the M0 mint service substrate.
type Shim struct {
	now      func() time.Time
	resolver PrincipalResolver

	// tokenSigner is the doc 19 §3 scoped-base-token substrate (the THIRD signing
	// context, D99). Default is Biscuit (D98 primary); a deployment swaps it via
	// WithSubstrateSigner. It owns ONLY the third signing context — never a D82
	// hierarchy, never session liveness/grants (those resolve at the D22 seam).
	tokenSigner SubstrateSigner

	// caStore is the D39 secret-store backend the two persistent D82 roots load
	// from / mint into (a local-file CAStore at the OSS tier, D85; castore.go). The
	// higher-tier customer Vault/OpenBao store (D55 window) is a different CAStore
	// behind this same seam. Defaults to an ephemeral temp-dir store when no
	// WithCAStore option is supplied (the test/throwaway posture) so the roots still
	// persist across a restart of the SAME store.
	caStore CAStore

	// workloadRoot is hierarchy 1 (D82): the single persistent workload-identity
	// root all session leaves chain to. (Per-session ISOLATION for workload identity
	// is the SPIFFE-name uniqueness; the interception hierarchy isolates per-session
	// at the intermediate-CA level, the stronger property the §13 row tests.)
	workloadRoot *rootHierarchy

	// interceptionRoot is hierarchy 2 (D82): the single persistent interception root
	// that ISSUES each session's intermediate CA. It lives off-host in the secret
	// store (D39) and is NEVER delivered to ds-tlsproxy — only the per-session
	// intermediate is (the bounded D76 exposure, doc 16 §4). Structurally disjoint
	// from workloadRoot: an interception-root signature never validates as workload
	// identity (the §13 hierarchy-separation property).
	interceptionRoot *rootHierarchy

	// workloadAuthority is the NARROW seam the workload-identity mint+verify routes
	// through (doc 16 §2/§9; the "substrate swap behind a frozen contract" of doc 05
	// §7 edge 5). Default is the M1 own-CA impl (ownCAWorkloadAuthority) wrapping the
	// hierarchy-1 root above; a deployment swaps in a SPIRE-backed impl via
	// WithWorkloadAuthority WITHOUT touching the frozen D24 Validate contract — the
	// workload leg of Validate calls authority.VerifyPresented (validate.go), and
	// MintWorkloadIdentity calls authority.MintWorkload. Behavior-preserving: the
	// own-CA impl mints + verifies byte-for-byte as before the extraction.
	workloadAuthority WorkloadAuthority

	// registry is the org services[] capability catalog (§5.1); IssueGrants
	// intersects the env spec against it. Optional — absent it, IssueGrants
	// fails closed (errNoRegistry) rather than minting capability from nothing.
	registry *ServiceRegistry

	// placeholderKey is the per-shim synthetic HMAC key the per-service
	// placeholder tokens are minted under (§5.1). A THIRD keyed context, never a
	// signing key for either D82 hierarchy: a placeholder must never validate as
	// workload identity or interception material. Synthetic (D50).
	placeholderKey []byte

	mu       sync.Mutex
	sessions map[string]*sessionRecord
}

// Option configures a Shim.
type Option func(*Shim)

// WithClock pins the shim's clock (tests use this for freshness/liveness).
func WithClock(now func() time.Time) Option {
	return func(s *Shim) { s.now = now }
}

// WithPrincipalResolver injects the launching_user resolution seam (see
// PrincipalResolver). Optional; absent it, the caller's hint is trusted (M0).
func WithPrincipalResolver(r PrincipalResolver) Option {
	return func(s *Shim) { s.resolver = r }
}

// WithCAStore pins the D39 secret store the two persistent D82 roots load from /
// mint into (the M1 own-minimal-CA persistence, doc 16 §2/§4). A production OSS
// deployment passes NewFileCAStore(dir) so the roots survive a process restart; a
// higher tier passes a Vault-backed CAStore behind the same seam (DEFERRED — not
// built here). Absent this option, NewShim falls back to an ephemeral temp-dir
// file store (the throwaway/test posture): roots still persist + reload across a
// restart of the SAME store within that dir.
func WithCAStore(store CAStore) Option {
	return func(s *Shim) { s.caStore = store }
}

// WithWorkloadAuthority swaps the workload-identity mint+verify substrate behind
// the frozen D22 Validate seam (the "substrate swap behind a frozen contract, not
// a rebuild" of doc 05 §7 edge 5). Absent this option, NewShim installs the M1
// own-CA impl (ownCAWorkloadAuthority) over hierarchy 1 — the DEFAULT, identical in
// behavior to the pre-extraction inline path. A SPIRE-backed authority passes
// through here to swap in BESIDE the own-CA impl without changing the Validate
// contract: it must name workloads with the SAME §3.1 SPIFFE scheme (use Build /
// BuildSessionSpiffeID, spiffeid.go) and present a credential the workload leg of
// Validate routes through its VerifyPresented. Mirrors WithCAStore /
// WithSubstrateSigner: a narrow fakeable seam, synthetic only (D50) — no live SPIRE
// Workload API is reachable in-wave.
func WithWorkloadAuthority(a WorkloadAuthority) Option {
	return func(s *Shim) { s.workloadAuthority = a }
}

// WithSpireAuthority selects the M3 SPIRE-backed substrate (spire_authority.go) over
// a narrow SVIDSource, BESIDE the M1 own-CA default — the third step of the D22
// substrate progression (M0 shim -> M1 own CA -> M3 SPIFFE/SPIRE) as "a substrate
// swap behind a frozen contract, not a rebuild" (doc 05 §7 edge 5). It is sugar for
// WithWorkloadAuthority(NewSpireWorkloadAuthority(src)): a deployment selects the
// SPIRE substrate WITHOUT touching MintWorkloadIdentity or Validate (the swap is
// pure — the SPIRE-backed name is the SAME §3.1 spiffe:// name via Build, and the
// Validate workload leg routes through the authority's VerifyPresented unchanged).
// In-wave src is the synthetic SPIRE fake (NewFakeSVIDSource); a live deployment
// passes a Workload-API-backed SVIDSource behind the same seam (DialSpireWorkloadAPI,
// a DEFERRED env-gated step — no live SPIRE in-wave, D50). Mirrors WithCAStore /
// WithSubstrateSigner: a narrow fakeable DI knob, synthetic only.
func WithSpireAuthority(src SVIDSource) Option {
	return func(s *Shim) { s.workloadAuthority = NewSpireWorkloadAuthority(src) }
}

// NewShim builds the mint shim and LOADS both persistent D82 roots from the D39
// secret store (the M1 own-minimal-CA substrate, doc 16 §2/§4): hierarchy 1
// (workload-identity) and hierarchy 2 (interception). On first run the store mints
// + persists fresh synthetic roots (D50); on every later run it loads the SAME
// material, so the roots are NOT regenerated per-process. Absent a WithCAStore
// option, an ephemeral temp-dir file store is used (the throwaway/test posture).
// All key material is synthetic (D50).
func NewShim(opts ...Option) (*Shim, error) {
	s := &Shim{
		now:      time.Now,
		sessions: make(map[string]*sessionRecord),
	}
	for _, o := range opts {
		o(s)
	}
	// Default to an ephemeral temp-dir file store when none was supplied. This keeps
	// the M1 persistence MECHANISM on every path (roots reload across a restart of
	// the SAME store) while a production deployment passes WithCAStore(NewFileCAStore
	// (dir)) for a durable location and a higher tier passes a Vault-backed store.
	if s.caStore == nil {
		dir, err := os.MkdirTemp("", "ds-mint-castore-*")
		if err != nil {
			return nil, fmt.Errorf("mint: create default CA store dir: %w", err)
		}
		store, err := NewFileCAStore(dir)
		if err != nil {
			return nil, err
		}
		s.caStore = store
	}

	now := s.now()
	// Hierarchy 1 (workload-identity): the persistent root all session leaves chain
	// to. Loaded from / minted into the secret store (NOT regenerated per-process).
	wr, err := s.caStore.LoadOrMintRoot(
		"workload",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		false,
		func() (*rootHierarchy, error) {
			return newRootHierarchy("workload", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false, now)
		},
	)
	if err != nil {
		return nil, err
	}
	s.workloadRoot = wr

	// The DEFAULT workload-identity authority is the M1 own-CA impl over hierarchy 1
	// (doc 16 §2): it mints the SPIFFE-SAN leaf + parallel JWT and verifies a
	// presented JWS against the session's minted key — behavior-preserving vs the
	// pre-extraction inline path. WithWorkloadAuthority overrides it (e.g. a
	// SPIRE-backed substrate) WITHOUT touching the frozen D24 Validate contract.
	if s.workloadAuthority == nil {
		s.workloadAuthority = &ownCAWorkloadAuthority{shim: s}
	}

	// Hierarchy 2 (interception): the persistent root that ISSUES each session's
	// intermediate CA. Structurally disjoint from the workload root (D82). Loaded
	// from / minted into the secret store, off-host, never delivered to the proxy.
	ir, err := s.caStore.LoadOrMintRoot(
		"interception",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		true,
		func() (*rootHierarchy, error) {
			return newRootHierarchy("interception", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true, now)
		},
	)
	if err != nil {
		return nil, err
	}
	s.interceptionRoot = ir
	// A per-shim synthetic placeholder-token key (D50) — the third keyed context
	// (§5.1), never under either D82 root hierarchy.
	s.placeholderKey = make([]byte, 32)
	if _, err := rand.Read(s.placeholderKey); err != nil {
		return nil, fmt.Errorf("mint: generate placeholder key: %w", err)
	}
	// The doc 19 §3 scoped-base-token substrate signer (the THIRD signing context,
	// D99) — default Biscuit (D98 primary) unless WithSubstrateSigner overrode it.
	// Its Ed25519 key is synthetic (D50) and structurally distinct from both D82
	// X.509 root hierarchies: a session-token signature never validates as
	// workload identity or interception material (doc 19 §13).
	if s.tokenSigner == nil {
		signer, err := newBiscuitSigner()
		if err != nil {
			return nil, err
		}
		s.tokenSigner = signer
	}
	return s, nil
}

// WorkloadIdentityRequest is the native MintWorkloadIdentity input — the §3.1
// claim inputs (doc 16 §4 sketch: session_uuid, launching_principal, org,
// repo_branch, runtime, parent_session?).
type WorkloadIdentityRequest struct {
	SessionUUID   string
	LaunchingUser string // resolved via PrincipalResolver if one is set
	Org           string
	RepoBranch    string
	Runtime       string
	ParentSession string
	// TTL is the workload-identity lifetime; zero means defaultSessionTTL.
	// TTL = session lifetime (§3.1).
	TTL time.Duration
}

// WorkloadIdentityBundle is the native MintWorkloadIdentity output: the X.509
// leaf (SPIFFE SAN, hierarchy 1) plus the parallel JWT presentation (§3.1).
type WorkloadIdentityBundle struct {
	// CertDER is the workload-identity leaf, chained to hierarchy 1.
	CertDER []byte
	// SPIFFEURI is the URI SAN spiffe://<org>/session/<session_uuid> (§3.1).
	SPIFFEURI string
	// JWT is the parallel ES256 JWS presentation for header-carried use (§3.1).
	JWT string
	// Expiry is the bundle horizon; TTL = session lifetime.
	Expiry time.Time
}

var errEmptySession = errors.New("mint: empty session_uuid")

// WorkloadMintRequest is the WorkloadAuthority.MintWorkload input — the fully
// resolved §3.1 claim inputs (launching_user already run through the
// PrincipalResolver) plus the computed SPIFFE name and validity window. It is the
// narrow seam input, distinct from the public WorkloadIdentityRequest: the Shim
// owns request normalization (TTL default, principal resolution, SPIFFE naming) so
// every authority impl — own-CA today, SPIRE-backed tomorrow — sees the same
// already-resolved shape and only owns the substrate mint.
type WorkloadMintRequest struct {
	SessionUUID   string
	LaunchingUser string // already resolved via PrincipalResolver
	Org           string
	RepoBranch    string
	Runtime       string
	ParentSession string
	// Spiffe is the §3.1 SPIFFE name (spiffe://<org>/session/<uuid>); the leaf URI
	// SAN and the JWT `sub` both carry it. Computed by the Shim via Build so it is
	// identical across substrates.
	Spiffe string
	// NotBefore / NotAfter bound the credential; NotAfter is the session-lifetime
	// horizon (TTL = session lifetime, §3.1).
	NotBefore time.Time
	NotAfter  time.Time
}

// WorkloadMintResult is the WorkloadAuthority.MintWorkload output: the X.509 leaf
// (SPIFFE SAN, hierarchy 1 under the own-CA impl), the parallel JWT presentation,
// the workload public key (the own-CA impl records it on the session record so the
// Validate workload leg can verify against it), and the expiry. A SPIRE-backed
// impl returns the same shape; PublicKey MAY be nil if its VerifyPresented does
// not need a per-session key on record (it verifies against the SPIRE trust
// bundle) — the Shim stores whatever is returned.
type WorkloadMintResult struct {
	CertDER   []byte
	JWT       string
	PublicKey *ecdsa.PublicKey
	Expiry    time.Time
}

// WorkloadAuthority is the NARROW fakeable seam the workload-identity mint+verify
// routes through (doc 16 §2/§9). It mirrors the established WithCAStore /
// WithSubstrateSigner DI pattern: the M1 own-CA impl (ownCAWorkloadAuthority) is
// the DEFAULT, and a SPIRE-backed impl swaps in via WithWorkloadAuthority WITHOUT
// touching the frozen D24 Validate contract — "a substrate swap behind a frozen
// contract, not a rebuild" (doc 05 §7 edge 5).
//
// Both methods are FORMAT-OPAQUE about the presented credential, exactly like
// presented_credential at the D22 seam (doc 16 §9; doc 19 §5): MintWorkload emits
// whatever the substrate presents (a JWS for the own-CA impl, a JWT-SVID for a
// SPIRE-backed one), and VerifyPresented consumes that same opaque blob. The
// caller (validate.go / MintWorkloadIdentity) never inspects the bytes — so a swap
// is never a contract event.
type WorkloadAuthority interface {
	// MintWorkload mints the workload identity for a normalized request: the X.509
	// leaf + parallel JWT presentation + public key + expiry. The Shim records the
	// result on the session record (workloadPub for the own-CA impl's verify leg).
	MintWorkload(req WorkloadMintRequest) (WorkloadMintResult, error)
	// VerifyPresented verifies a presented credential is a live, well-formed
	// workload credential naming expectedSpiffe at time `at`, returning the decoded
	// §3.1 claim set. It is format-opaque (the own-CA impl parses a JWS; a
	// SPIRE-backed impl validates a JWT-SVID against the trust bundle). It does NOT
	// decide session liveness or grants — those stay in Validate (validate.go), so
	// the seam is purely the signature+claims half of the frozen check. A returned
	// error is mapped to the right D77 DENY reason by the caller.
	VerifyPresented(presentedCredential []byte, expectedSpiffe string, at time.Time) (jwtClaims, error)
}

// ownCAWorkloadAuthority is the M1 own-minimal-CA WorkloadAuthority (D22; doc 16
// §2/§4): it mints a hierarchy-1 leaf under the persistent workload root + the
// parallel ES256 JWS, and verifies a presented JWS against the session's minted
// key. It is the DEFAULT impl, behavior-identical to the pre-extraction inline
// path. It holds a back-reference to the Shim for the one piece of per-session
// state its verify leg needs — the session's minted workloadPub — and for the
// hierarchy-1 root + clock its mint leg signs with. A SPIRE-backed impl needs none
// of this Shim state (it verifies against the SPIRE trust bundle), which is exactly
// why the seam is narrow and the swap pure.
type ownCAWorkloadAuthority struct {
	shim *Shim
}

// MintWorkload signs the hierarchy-1 leaf (SPIFFE URI SAN, §3.1) under the
// persistent workload root and the parallel ES256 JWS over the §3.1 claim set,
// both with the SAME freshly generated leaf key — so the cert and the token are two
// presentations of one identity (doc 16 §3.1; byte-for-byte the pre-extraction
// path).
func (a *ownCAWorkloadAuthority) MintWorkload(req WorkloadMintRequest) (WorkloadMintResult, error) {
	s := a.shim
	if s.workloadRoot == nil {
		return WorkloadMintResult{}, errNotInitialized
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return WorkloadMintResult{}, fmt.Errorf("mint: generate workload leaf key: %w", err)
	}
	sanURI, err := url.Parse(req.Spiffe)
	if err != nil {
		return WorkloadMintResult{}, fmt.Errorf("mint: parse spiffe uri: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return WorkloadMintResult{}, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   req.SessionUUID,
			Organization: []string{req.Org},
		},
		URIs:        []*url.URL{sanURI}, // the SPIFFE-compatible URI SAN (§3.1)
		NotBefore:   req.NotBefore,
		NotAfter:    req.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, s.workloadRoot.cert, &leafKey.PublicKey, s.workloadRoot.key)
	if err != nil {
		return WorkloadMintResult{}, fmt.Errorf("mint: sign workload leaf: %w", err)
	}

	claims := jwtClaims{
		Subject:          req.Spiffe,
		Issuer:           issuerName,
		IssuedAt:         toUnix(req.NotBefore.Add(time.Minute)), // iat = the mint instant (NotBefore = mint - 1m)
		NotBefore:        toUnix(req.NotBefore),
		Expiry:           toUnix(req.NotAfter),
		SessionUUID:      req.SessionUUID,
		LaunchingUser:    req.LaunchingUser,
		Org:              req.Org,
		RepoBranch:       req.RepoBranch,
		Runtime:          req.Runtime,
		ParentSession:    req.ParentSession,
		ServicePrincipal: false, // RESERVED D16 marker, always the agent face at M0
	}
	token, err := signJWT(leafKey, claims)
	if err != nil {
		return WorkloadMintResult{}, err
	}
	return WorkloadMintResult{
		CertDER:   leafDER,
		JWT:       token,
		PublicKey: &leafKey.PublicKey,
		Expiry:    req.NotAfter,
	}, nil
}

// VerifyPresented verifies the presented JWS against the session's minted workload
// key (the own-CA impl's per-session state) and confirms it names expectedSpiffe.
// It is the extracted signature+claims half of the Validate workload leg: liveness,
// freshness, and grants stay in Validate (validate.go). errNoWorkloadKey signals
// "no minted key for this session" so the caller maps it to signature_invalid (the
// pre-extraction pub==nil branch). expectedSpiffe is the §3.1 name the caller
// derives from the presentation context; an empty value skips the name binding (the
// caller binds on session_uuid instead, as the legacy path did).
func (a *ownCAWorkloadAuthority) VerifyPresented(presented []byte, expectedSpiffe string, _ time.Time) (jwtClaims, error) {
	parts := splitSpiffePath(expectedSpiffe)
	pub := a.shim.workloadPubForSession(parts)
	if pub == nil {
		return jwtClaims{}, errNoWorkloadKey
	}
	claims, err := verifyJWT(pub, string(presented))
	if err != nil {
		return jwtClaims{}, err
	}
	if expectedSpiffe != "" && claims.Subject != expectedSpiffe {
		return jwtClaims{}, errJWTSignature
	}
	return claims, nil
}

// errNoWorkloadKey is the own-CA authority's "this session has no minted workload
// key" signal — the caller maps it to ReasonSignatureInvalid (the legacy pub==nil
// branch), keeping the workload leg fail-closed.
var errNoWorkloadKey = errors.New("mint: no workload key for session")

// splitSpiffePath extracts the session_uuid tail of a §3.1 SPIFFE name
// (spiffe://<org>/session/<uuid>) for the own-CA verify key lookup, which is keyed
// on session_uuid. A name that does not parse / has no /session/ segment yields
// "" — the caller's pub lookup then misses and fails closed.
func splitSpiffePath(spiffe string) string {
	id, err := ParseSpiffeID(spiffe)
	if err != nil {
		return ""
	}
	const seg = "/" + spiffeSessionSegment + "/"
	if strings.HasPrefix(id.Path, seg) {
		return id.Path[len(seg):]
	}
	return ""
}

// workloadPubForSession resolves a session's minted workload public key by session
// UUID under the lock — the own-CA authority's verify-leg state. Returns nil when
// the session is unknown or never minted a workload key.
func (s *Shim) workloadPubForSession(sessionUUID string) *ecdsa.PublicKey {
	if sessionUUID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.sessions[sessionUUID]
	if rec == nil {
		return nil
	}
	return rec.workloadPub
}

// MintWorkloadIdentity mints hierarchy-1 workload identity: an X.509 leaf with a
// SPIFFE-compatible URI SAN plus a parallel JWT presentation carrying the §3.1
// claim set (incl. the reserved service_principal marker). Native Go (no
// generated server yet — MintWorkloadIdentity is RESERVED-only in the proto).
//
// The Shim normalizes the request (principal resolution, TTL default, SPIFFE
// naming, validity window) then delegates the substrate mint to the
// WorkloadAuthority seam — the M1 own-CA impl by default, a SPIRE-backed impl when
// WithWorkloadAuthority swapped it (doc 05 §7 edge 5; the swap is pure). It then
// registers/refreshes the in-memory session record so the workload key is available
// for the Validate seam and the session is live.
func (s *Shim) MintWorkloadIdentity(req WorkloadIdentityRequest) (*WorkloadIdentityBundle, error) {
	if s.workloadAuthority == nil {
		return nil, errNotInitialized
	}
	if req.SessionUUID == "" {
		return nil, errEmptySession
	}
	launchingUser := req.LaunchingUser
	if s.resolver != nil {
		resolved, err := s.resolver(req.SessionUUID, req.LaunchingUser)
		if err != nil {
			return nil, fmt.Errorf("mint: resolve launching_user: %w", err)
		}
		launchingUser = resolved
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	now := s.now()
	notAfter := now.Add(ttl)
	spiffe := spiffeURI(req.Org, req.SessionUUID)

	result, err := s.workloadAuthority.MintWorkload(WorkloadMintRequest{
		SessionUUID:   req.SessionUUID,
		LaunchingUser: launchingUser,
		Org:           req.Org,
		RepoBranch:    req.RepoBranch,
		Runtime:       req.Runtime,
		ParentSession: req.ParentSession,
		Spiffe:        spiffe,
		NotBefore:     now.Add(-time.Minute),
		NotAfter:      notAfter,
	})
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	rec := s.sessions[req.SessionUUID]
	if rec == nil {
		rec = &sessionRecord{grants: make(map[string]string)}
		s.sessions[req.SessionUUID] = rec
	}
	rec.state = sessionLive
	rec.expiry = notAfter
	rec.workloadPub = result.PublicKey
	rec.identity = spiffe // the §3.1 SPIFFE name = the grant's identity axis (§5.1)
	s.mu.Unlock()

	return &WorkloadIdentityBundle{
		CertDER:   result.CertDER,
		SPIFFEURI: spiffe,
		JWT:       result.JWT,
		Expiry:    notAfter,
	}, nil
}

// InterceptionCABundle is the native MintInterceptionCA output before it is
// marshaled onto the generated proto response (server.go does that mapping).
type InterceptionCABundle struct {
	CACertDER []byte
	CAKeyDER  []byte
	Expiry    time.Time
}

// mintInterceptionCA mints a per-session interception INTERMEDIATE CA issued UNDER
// the persistent interception root (hierarchy 2, D82) — the M1 posture: the
// interception ROOT issues a per-session intermediate, never the reverse, and the
// root never leaves the secret store (doc 16 §4). The per-session intermediate is
// stored on the session record (destroyable, the bounded D76 exposure) and is ALSO
// the per-session trust anchor pinned in the session VM, so session A's interception
// material never validates in session B's trust context — the §13
// per-session-CA-isolation property.
//
// The minted CA cert is itself a path-len-0 CA, since ds-tlsproxy uses it to mint
// per-origin leaves on the fly (doc 16 §4). The returned cert+key are the proxy-
// bound delivery material; the WIRE delivery to ds-tlsproxy is a SEPARATE seam
// (DEFERRED — this method mints + lifecycles the key, the delivery is elsewhere).
func (s *Shim) mintInterceptionCA(sessionUUID string) (*InterceptionCABundle, error) {
	if sessionUUID == "" {
		return nil, errEmptySession
	}
	if s.interceptionRoot == nil {
		return nil, errNotInitialized
	}
	now := s.now()
	notAfter := now.Add(defaultInterceptionTTL)

	// The proxy-bound per-session interception CA: an intermediate issued under the
	// PERSISTENT interception root (hierarchy 2), with its own destroyable key.
	ca, err := issueSessionInterceptionCA(s.interceptionRoot, sessionUUID, now, defaultInterceptionTTL)
	if err != nil {
		return nil, err
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, fmt.Errorf("mint: marshal interception ca key: %w", err)
	}

	s.mu.Lock()
	rec := s.sessions[sessionUUID]
	if rec == nil {
		rec = &sessionRecord{grants: make(map[string]string)}
		s.sessions[sessionUUID] = rec
	}
	// Replace any prior interception CA, destroying the old key first (re-mint case).
	if rec.interceptionCA != nil {
		rec.interceptionCA.destroy()
	}
	rec.interceptionCA = ca
	if rec.expiry.IsZero() {
		rec.expiry = notAfter
	}
	s.mu.Unlock()

	return &InterceptionCABundle{
		CACertDER: ca.certDER,
		CAKeyDER:  caKeyDER,
		Expiry:    notAfter,
	}, nil
}

// TeardownSession destroys a session's per-session interception-CA key and evicts
// the session record (the doc 16 §4 "destroyed at teardown" interception lifecycle
// + the §5.4 active-eviction half of revocation). After teardown a stolen-but-
// still-time-valid workload cert fails Validate IMMEDIATELY (unknown_session — the
// record is gone), exactly like a kill-mid-flight, WITHOUT any change to the
// Validate contract. The interception key's private scalar is zeroed in place so no
// recoverable signing material survives. Idempotent: tearing down an unknown or
// already-torn-down session is a no-op. reason is recorded so a concurrent in-flight
// Validate that races the eviction still sees a revoked record (defense in depth).
func (s *Shim) TeardownSession(sessionUUID string) error {
	if sessionUUID == "" {
		return errEmptySession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.sessions[sessionUUID]
	if rec == nil {
		return nil
	}
	if rec.interceptionCA != nil {
		rec.interceptionCA.destroy()
	}
	// Active eviction: drop the record so Validate fails closed (unknown_session)
	// for any still-time-valid credential presented after teardown (doc 16 §5.4).
	delete(s.sessions, sessionUUID)
	return nil
}

// RevokeSession marks the in-memory session record revoked. Validate then fails
// CLOSED for that session: verdict DENY with a machine-readable reason in the
// D77 in-band-403 shape (doc 16 §5.4: active eviction, liveness-as-revocation —
// the minimal CA ships no CRL/OCSP). Native Go (RESERVED-only in the proto).
//
// reason is the operator-supplied cause; it is surfaced verbatim as the
// machine_readable_reason on subsequent Validate denials. Revoking an unknown
// session creates a tombstone record so a later mint/validate races closed, not
// open.
func (s *Shim) RevokeSession(sessionUUID, reason string) error {
	if sessionUUID == "" {
		return errEmptySession
	}
	if reason == "" {
		reason = "session_revoked"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.sessions[sessionUUID]
	if rec == nil {
		rec = &sessionRecord{grants: make(map[string]string)}
		s.sessions[sessionUUID] = rec
	}
	rec.state = sessionRevoked
	rec.revokeReason = reason
	return nil
}

// WorkloadRootDER returns the hierarchy-1 (workload-identity) root certificate
// in DER. Exposed so the §13 hierarchy-separation assertion can build a pool
// seeded with ONLY the workload root and prove an interception-hierarchy cert
// never validates against it (D82). Read-only accessor; mints nothing.
func (s *Shim) WorkloadRootDER() []byte {
	if s.workloadRoot == nil {
		return nil
	}
	return s.workloadRoot.certDER
}

// InterceptionRootDER returns a session's per-session interception trust anchor in
// DER (the per-session intermediate CA cert pinned in the session VM, doc 16 §4),
// or nil if no interception CA was minted for it (or the session was torn down).
// Exposed for the §13 per-session-CA-isolation and hierarchy-separation assertions:
// session A's anchor differs from session B's (so A's leaves never validate under
// B's anchor), and neither validates against the workload root. Read-only accessor;
// mints nothing.
func (s *Shim) InterceptionRootDER(sessionUUID string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.sessions[sessionUUID]
	if rec == nil || rec.interceptionCA == nil {
		return nil
	}
	return rec.interceptionCA.trustAnchorDER
}

// InterceptionRootCADER returns the PERSISTENT interception root (hierarchy 2)
// certificate in DER, or nil if uninitialized. Exposed for the §13
// hierarchy-separation assertion (the persistent interception root is structurally
// disjoint from the workload root) and to prove the per-session intermediate chains
// to it (provenance). The root SIGNING KEY is never exposed — only the cert.
// Read-only accessor; mints nothing.
func (s *Shim) InterceptionRootCADER() []byte {
	if s.interceptionRoot == nil {
		return nil
	}
	return s.interceptionRoot.certDER
}

// GrantSession records a grant (service_id -> grant_ref) for a session so the
// Validate grant lookup (§4) can resolve it. Grants are typed deterministic
// records (no Cedar, §5.1); this is the minimal M0 shape — identity x service.
// Synthetic only (D50); the real grant model freezes with the M1 swap design.
func (s *Shim) GrantSession(sessionUUID, serviceID, grantRef string) error {
	if sessionUUID == "" || serviceID == "" {
		return fmt.Errorf("mint: grant needs session and service")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.sessions[sessionUUID]
	if rec == nil {
		rec = &sessionRecord{grants: make(map[string]string)}
		s.sessions[sessionUUID] = rec
	}
	rec.grants[serviceID] = grantRef
	return nil
}
