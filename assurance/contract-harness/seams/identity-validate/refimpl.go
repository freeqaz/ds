// SPDX-License-Identifier: Apache-2.0

package identityvalidate

import (
	"context"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// machine-readable DENY reasons (doc 16 §4 `DENY{machine_readable_reason}`).
// These are the stable, honest reject codes a swap executor routes on (doc 16
// §11.1 step 3, D77 reason-on-the-densest-channel). Synthetic but contract-shaped.
const (
	reasonMalformedCredential = "malformed_credential"
	reasonSessionNotLive      = "session_not_live"
	reasonCredentialExpired   = "credential_expired"
	reasonOutOfGrant          = "out_of_grant"
)

// RefImpl is a minimal honest reference implementation of the D22
// IdentityValidationService.Validate seam — the "real implementation" side of
// the dual-run. It implements exactly the doc 16 §4 / §9 validation contract:
// a Validate call passes iff (signature + freshness + SESSION LIVENESS + grant
// lookup) all hold, with the grant lookup INTERSECTED against the presented
// credential's attenuated scope — grant-intersection evaluated AT Validate
// (doc 16 §5.1, doc 19 §5/§8). Anything else is an honest, machine-readable
// DENY (an over-scoped, expired, or against-a-dead-session presentation), never
// a silent zero-value ALLOW.
//
// This is the M0/M1 stand-in behind the frozen D22 seam (doc 16 §2: M0
// throwaway shim -> M1 minimal CA -> M3 SPIFFE/SPIRE, all behind this one
// contract). When a production validator lands it replaces RefImpl as the
// "real" end and the conformance suite is unchanged — the suite is the contract,
// not the implementation.
//
// State is held in-memory, keyed by session uuid; access is mutex-guarded so the
// in-process gRPC server is safe under concurrent calls. The presented
// credential is FORMAT-OPAQUE at the seam (doc 16 §4, doc 19 §5/§6): the
// reference impl parses the synthetic token shape this seam fixes (see token.go
// helpers in suite.go) purely to exercise the contract; a substrate flip
// (Biscuit/macaroon/X.509) is a Validate-internal property, never a contract
// event. Synthetic fixtures only (D50).
type RefImpl struct {
	identityv1.UnimplementedIdentityValidationServiceServer

	mu       sync.Mutex
	sessions map[string]*sessionState
}

// sessionState is the per-session validator view: liveness plus the live grant
// set (service_id -> grant). This is the session-cached grant set the swap
// executor holds <= session (doc 16 §5.1/§5.4); the reference impl models it
// in-memory so Validate can do the deterministic grant lookup the contract
// promises (no policy evaluation — D52: grants are typed records, a lookup, not
// an expression-language decision).
type sessionState struct {
	live   bool
	grants map[string]grant // keyed by service_id
}

// grant is the typed identity x service x scope x TTL record (doc 16 §5.1). The
// reference impl carries the fields Validate turns on: the opaque grant_ref it
// returns on ALLOW and the grant's own expiry horizon (the TTL that, intersected
// with the token's, bounds the ALLOW).
type grant struct {
	ref              string
	expiryUnixSecond int64
}

// NewRefImpl returns a reference validator with an empty session store.
func NewRefImpl() *RefImpl {
	return &RefImpl{sessions: map[string]*sessionState{}}
}

// Validate authorizes one swap-path credential presentation (doc 16 §4 / §9).
//
// The verdict is ALLOW iff every check holds, else an honest DENY carrying a
// machine-readable reason (never a silent drop, never a verdict-UNSPECIFIED):
//
//  1. signature/shape   — the presented credential must parse as a well-formed
//     session token (the format-opaque substrate's "signature + freshness"
//     leg). A malformed/unsigned credential is reasonMalformedCredential.
//  2. session liveness, TWO-KEY   — the referenced session must be live. A
//     killed / suspended / admin-revoked / unknown session is
//     reasonSessionNotLive: the minimal CA ships no CRL/OCSP, so liveness — not
//     revocation — is what makes a stolen-but-unexpired credential fail
//     immediately (doc 16 §5.4). For a CHAINED (descendant) token (doc 19 §7),
//     liveness is two-key: whole-chain liveness keys on the inherited
//     root_session (revoking the root fails every descendant closed, even while
//     the descendant's own session is independently live), per-child revocation
//     keys on the descendant's own session_uuid, and a root the host has no
//     record of (cross-host) is governed by the descendant's own liveness alone.
//  3. freshness          — the token (and the matched grant) must be unexpired
//     as of nowUnixSeconds. An expired presentation is reasonCredentialExpired.
//  4. grant lookup, INTERSECTED — the requested service_id must be BOTH in the
//     session's live grant set AND in the token's attenuated scope. The
//     intersection is what narrows: a token that omits a service the session is
//     otherwise granted cannot reach it (over-scope is refused), and the
//     returned expiry is min(grant TTL, token TTL) — the tighter horizon wins
//     (doc 16 §5.1, doc 19 §5/§8). A miss on either side is reasonOutOfGrant.
//
// Validation is idempotent and side-effect-free: re-presenting the same
// credential against the same session yields the same verdict/grant_ref/expiry
// (no nonce burn at the seam — the swap path may re-validate per the latency
// budget, doc 16 §4).
func (s *RefImpl) Validate(_ context.Context, req *identityv1.ValidateRequest) (*identityv1.ValidateResponse, error) {
	sessionRef := req.GetSessionRef()
	if sessionRef == nil || sessionRef.GetSessionUuid() == "" {
		return nil, status.Error(codes.InvalidArgument, "ValidateRequest.session_ref.session_uuid is required")
	}
	if req.GetServiceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "ValidateRequest.service_id is required")
	}

	// signature/shape: parse the format-opaque credential. (The per-session
	// binding, liveness, freshness, and grant-intersection legs all live in the
	// shared HonestDecision core below — this is the only leg that needs the
	// production token parse.)
	tok, ok := parseToken(req.GetPresentedCredential())
	if !ok {
		return deny(reasonMalformedCredential), nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// The honest decision is the ONE shared core (signature binding -> TWO-KEY
	// liveness -> freshness -> grant-intersection -> ALLOW-with-tighter-expiry,
	// doc 16 §4/§5.1, doc 19 §7/§8). The reference impl supplies the core its
	// in-memory session/grant store (mutex already held) as the liveness and
	// grant lookups, and the synthetic now-fence; the contract LOGIC lives in
	// HonestDecision so it cannot drift from the test-side honest responder.
	now := s.nowLocked()
	return HonestDecision(
		sessionRef.GetSessionUuid(),
		req.GetServiceId(),
		HonestToken{
			SessionUUID:      tok.sessionUUID,
			ExpiryUnixSecond: tok.expiryUnixSecond,
			RootSession:      tok.rootSession,
			ScopeContains:    tok.scopeContains,
		},
		now,
		func(uuid string) (live, known bool) {
			st, ok := s.sessions[uuid]
			if !ok {
				return false, false
			}
			return st.live, true
		},
		func(serviceID string) (ref string, expiry int64, granted bool) {
			st, ok := s.sessions[sessionRef.GetSessionUuid()]
			if !ok {
				return "", 0, false
			}
			g, ok := st.grants[serviceID]
			if !ok {
				return "", 0, false
			}
			return g.ref, g.expiryUnixSecond, true
		},
	), nil
}

// deny synthesizes the honest DENY verdict carrying a machine-readable reason
// (doc 16 §4). grant_ref/expiry stay zero on DENY — they are ALLOW-only fields.
func deny(reason string) *identityv1.ValidateResponse {
	return &identityv1.ValidateResponse{
		Verdict:               identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY,
		MachineReadableReason: reason,
	}
}

// --- shared honest decision core (single source of truth) --------------------
//
// HonestDecision is the ONE honest Validate decision body the seam keeps — the
// doc 16 §4 / §9 contract restated exactly once: signature/shape (per-session
// binding) -> TWO-KEY liveness (whole-chain root cascade + own-session) ->
// freshness -> grant-intersection (session grant AND token scope) -> ALLOW with
// the tighter (grant TTL, token TTL) horizon, else an honest machine-readable
// DENY carrying one of the reason* constants. RefImpl.Validate routes through it
// (production side) and the dual-run test's honestValidateResponder routes
// through it (the *Recorded() fake-accessor anchors), so the honest copy can no
// longer drift between the two. The DRIFTED test fakes (the non-cascading and
// blanket-ALLOW negative drift-gates) deliberately do NOT route through here —
// their divergence is the gate.
//
// The core is parameterized over the inputs that differ between callers — the
// already-parsed token view, the session-liveness lookup, the grant lookup, and
// the validation now-fence — so it carries the contract LOGIC and nothing about
// how a particular caller stores its sessions/grants or parses its token bytes.
// Synthetic fixtures only (D50).
func HonestDecision(
	sessionUUID, serviceID string,
	tok HonestToken,
	now int64,
	liveness LivenessLookup,
	grants GrantLookup,
) *identityv1.ValidateResponse {
	// 1. signature/shape: the token must be bound to the session it is presented
	// against — a token minted for session A is useless against session B
	// (doc 16 §4 per-session binding).
	if tok.SessionUUID != sessionUUID {
		return deny(reasonMalformedCredential)
	}

	// 2. session liveness — TWO-KEY, chained-token aware (doc 19 §7).
	//
	// Whole-chain liveness keys on the inherited ROOT: a root the host KNOWS to
	// be dead cascades to every descendant, even while the descendant's own
	// session is independently live. A root the host has no RECORD of (cross-host)
	// is NOT evidence of revocation — it falls through to the descendant's own
	// liveness below. A token with no inherited root is governed by its own
	// session alone.
	if tok.RootSession != "" && tok.RootSession != sessionUUID {
		if rootLive, rootKnown := liveness(tok.RootSession); rootKnown && !rootLive {
			return deny(reasonSessionNotLive)
		}
		// rootKnown==false (cross-host root) falls through to own-session liveness.
	}
	// Per-child / own-session liveness.
	if live, known := liveness(sessionUUID); !known || !live {
		return deny(reasonSessionNotLive)
	}

	// 3. freshness: the token itself must be unexpired as of now.
	if tok.ExpiryUnixSecond <= now {
		return deny(reasonCredentialExpired)
	}

	// 4. grant lookup, INTERSECTED with the token's attenuated scope. The
	// requested service must be BOTH in the session's live grant set AND in the
	// token's attenuated scope (doc 16 §5.1, doc 19 §5/§8). A miss on either side
	// is out_of_grant.
	ref, grantExpiry, granted := grants(serviceID)
	if !granted || !tok.ScopeContains(serviceID) {
		return deny(reasonOutOfGrant)
	}
	// The grant's own TTL must also be fresh.
	if grantExpiry <= now {
		return deny(reasonCredentialExpired)
	}

	// ALLOW. The expiry is the INTERSECTION horizon — the tighter of the grant
	// TTL and the token TTL (doc 16 §5.1; doc 19 §8 attenuation narrows).
	expiry := grantExpiry
	if tok.ExpiryUnixSecond < expiry {
		expiry = tok.ExpiryUnixSecond
	}
	return &identityv1.ValidateResponse{
		Verdict:           identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW,
		GrantRef:          ref,
		ExpiryUnixSeconds: expiry,
	}
}

// HonestToken is the parsed, format-opaque credential view HonestDecision turns
// on: the session it is bound to, its freshness horizon, its inherited chain
// origin (root_session; "" => non-chained), and whether its attenuated scope
// covers a service. It is the contract-shaped subset of the parsed token both
// callers project into the shared core (the production token and the test's
// TestToken alike). Synthetic fixtures only (D50).
type HonestToken struct {
	SessionUUID      string
	ExpiryUnixSecond int64
	RootSession      string
	ScopeContains    func(serviceID string) bool
}

// LivenessLookup reports a session's liveness by uuid: live is its liveness bit,
// known is whether the validating host has any record of the session at all
// (an unknown root is not evidence of revocation — doc 19 §7 cross-host).
type LivenessLookup func(uuid string) (live, known bool)

// GrantLookup resolves the grant a session holds for a service: ref is the
// opaque grant_ref returned on ALLOW, expiry is the grant's own TTL horizon, and
// granted reports whether the session holds any grant for the service at all.
type GrantLookup func(serviceID string) (ref string, expiry int64, granted bool)

// SeedSession installs a live session and its grant set directly, so the suite
// can stand up a validatable session without a separate mint verb (the mint seam
// is a sibling module, never imported here). It is a test affordance — not a
// contract verb. grants maps service_id -> (grant_ref, grant expiry). Synthetic
// fixtures only (D50).
func (s *RefImpl) SeedSession(uuid string, live bool, grants map[string]grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	gs := make(map[string]grant, len(grants))
	for k, v := range grants {
		gs[k] = v
	}
	s.sessions[uuid] = &sessionState{live: live, grants: gs}
}

// nowLocked returns the synthetic monotonic validation clock. It is a fixed
// fence (synthNow) so expiry checks are deterministic across the dual-run: a
// token/grant with expiry <= synthNow is expired, one with expiry > synthNow is
// fresh. The caller holds s.mu. Synthetic fixtures only (D50).
func (s *RefImpl) nowLocked() int64 {
	return synthNow
}

// Register registers the reference validator on a grpc.ServiceRegistrar.
func (s *RefImpl) Register(reg grpc.ServiceRegistrar) {
	identityv1.RegisterIdentityValidationServiceServer(reg, s)
}

// --- format-opaque synthetic token (D50) ------------------------------------
//
// The presented credential is FORMAT-OPAQUE at the D22 seam (doc 16 §4, doc 19
// §5/§6). This seam fixes one obviously-synthetic token shape purely so the
// contract can be exercised end-to-end: a token is the bytes
//
//	"tok-synthetic|<session_uuid>|<expiry_unix>|<svc1,svc2,...>"
//
// where the trailing comma-list is the token's ATTENUATED SCOPE — the subset of
// service ids this credential may reach (the doc 19 attenuation the Validate
// intersection narrows against). A substrate flip (Biscuit/macaroon/X.509) would
// change only this parse; the contract above is unchanged.
//
// A CHAINED (descendant) token (doc 19 §7) carries one optional trailing field
// — its inherited root_session — so the bytes become
//
//	"tok-synthetic|<session_uuid>|<expiry_unix>|<svc1,svc2,...>|<root_session>"
//
// The 4-part shape (no trailing root) is a non-chained presentation: an unrooted
// credential governed by its own session alone. The 5-part shape re-roots
// session_uuid to a descendant while naming the chain origin in root_session;
// whole-chain liveness keys on that root (see Validate step 2). There is NO
// first-class root_session proto field on ValidateRequest (verified: it carries
// only {presented_credential, session_ref, service_id}), so the chain is encoded
// here, INSIDE the format-opaque credential the refimpl interprets — exactly the
// substrate-internal property a Biscuit/macaroon caveat would carry.

const tokenPrefix = "tok-synthetic"

type token struct {
	sessionUUID      string
	expiryUnixSecond int64
	scope            []string // the attenuated scope (service ids)
	rootSession      string   // inherited chain origin ("" => non-chained)
}

// scopeContains reports whether the token's attenuated scope covers serviceID.
func (t token) scopeContains(serviceID string) bool {
	for _, s := range t.scope {
		if s == serviceID {
			return true
		}
	}
	return false
}

// MintToken builds the obviously-synthetic format-opaque credential bytes for a
// session, expiry, and attenuated scope. Exported so the suite and the external
// _test package construct presentations identically (the seam, not a real mint).
// This is the NON-chained (unrooted) shape — governed by its own session alone.
// Synthetic fixtures only (D50).
func MintToken(sessionUUID string, expiryUnixSecond int64, scope ...string) []byte {
	return []byte(tokenPrefix + "|" + sessionUUID + "|" + decimalSigned(expiryUnixSecond) + "|" + strings.Join(scope, ","))
}

// MintChainedToken builds a CHAINED (descendant) credential (doc 19 §7): a token
// whose own session_uuid is re-rooted to a descendant but which inherits a
// root_session naming the chain origin. Whole-chain liveness keys on the root, so
// revoking rootSession fails every descendant closed even while sessionUUID is
// itself live (see Validate). The chain is encoded INSIDE the format-opaque
// credential — there is no root_session proto field on ValidateRequest.
// Synthetic fixtures only (D50).
func MintChainedToken(sessionUUID string, rootSession string, expiryUnixSecond int64, scope ...string) []byte {
	return []byte(tokenPrefix + "|" + sessionUUID + "|" + decimalSigned(expiryUnixSecond) + "|" + strings.Join(scope, ",") + "|" + rootSession)
}

// TestToken is the exported view of the synthetic format-opaque credential the
// external _test package programs a hand-built fake against (the negative
// drift-gate test and the *Recorded() assertions). It mirrors the unexported
// token so the test re-derives the same intersection contract without importing
// internals. Synthetic fixtures only (D50).
type TestToken struct {
	SessionUUID      string
	ExpiryUnixSecond int64
	Scope            []string
	RootSession      string // inherited chain origin ("" => non-chained)
}

// ScopeContains reports whether the token's attenuated scope covers serviceID.
func (t TestToken) ScopeContains(serviceID string) bool {
	for _, s := range t.Scope {
		if s == serviceID {
			return true
		}
	}
	return false
}

// ParseTokenForTest exposes parseToken to the external _test package so it can
// drive an honest hand-built fake against the same format-opaque credential the
// suite mints (MintToken). Synthetic fixtures only (D50).
func ParseTokenForTest(b []byte) (TestToken, bool) {
	tok, ok := parseToken(b)
	if !ok {
		return TestToken{}, false
	}
	return TestToken{
		SessionUUID:      tok.sessionUUID,
		ExpiryUnixSecond: tok.expiryUnixSecond,
		Scope:            tok.scope,
		RootSession:      tok.rootSession,
	}, true
}

// parseToken parses the synthetic format-opaque credential. ok==false on any
// shape it does not recognize — the "signature/shape" leg of validation. Both
// the 4-part non-chained shape and the 5-part chained shape (a trailing
// root_session, doc 19 §7) parse; any other arity is malformed.
func parseToken(b []byte) (token, bool) {
	parts := strings.Split(string(b), "|")
	if (len(parts) != 4 && len(parts) != 5) || parts[0] != tokenPrefix {
		return token{}, false
	}
	if parts[1] == "" {
		return token{}, false
	}
	exp, ok := atoiSigned(parts[2])
	if !ok {
		return token{}, false
	}
	var scope []string
	if parts[3] != "" {
		scope = strings.Split(parts[3], ",")
		sort.Strings(scope)
	}
	var root string
	if len(parts) == 5 {
		// A 5-part token MUST name a non-empty root — an empty trailing field is
		// a malformed chain claim, not an unrooted token.
		if parts[4] == "" {
			return token{}, false
		}
		root = parts[4]
	}
	return token{sessionUUID: parts[1], expiryUnixSecond: exp, scope: scope, rootSession: root}, true
}

// --- tiny stdlib-free integer codecs (the module is stdlib-only here) -------

// decimalSigned renders a signed int64 in base 10. Used to serialize the
// synthetic token's expiry into the format-opaque credential bytes.
func decimalSigned(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// atoiSigned parses a base-10 signed int64. ok==false on any non-numeric input —
// part of the token's shape check. No leading-zero or overflow subtleties matter
// for the synthetic fixtures this seam uses.
func atoiSigned(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	neg := false
	i := 0
	if s[0] == '-' {
		neg = true
		i = 1
		if len(s) == 1 {
			return 0, false
		}
	}
	var n int64
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}
