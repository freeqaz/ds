// SPDX-License-Identifier: Apache-2.0

// MintSessionToken — the scoped per-session base token (doc 19 §3; D97/D98/D99).
//
// Doc 19 ratified (D97) a scoped, offline-attenuable agent-credential class
// behind the FROZEN D22 `Validate` seam: one per-session base token minted on
// behalf of the launching user at create step 5 (D99), delivered through the
// existing doc 15 §4.1 step-8 entrypoint slot — NO new choreography step. This
// file implements `MintSessionToken(MintSessionTokenReq) (SessionTokenBundle)`,
// the RPC named in the doc 16 §4 mint skeleton (landed by the doc 19
// ratification batch; RESERVED-only in the proto, so it runs natively here like
// MintWorkloadIdentity / MintGrants).
//
// THE THIRD SIGNING CONTEXT (D99, doc 19 §3). The token signing key is a THIRD
// signing context in the D39 secret-store trust zone — beside but NEVER under
// either D82 root hierarchy (workload-identity / interception), and never on the
// virtual-metal host. The D82 separation property extends to it: a session-token
// signature must NEVER validate as workload identity NOR as interception
// material (doc 19 §13, mirrored as an executable isolation test in
// sessiontoken_test.go). The separation here is STRUCTURAL, not coincidental:
// the token is an Ed25519-signed Biscuit, a different cryptosystem and wire shape
// than the ECDSA/P-256 X.509 certs both D82 hierarchies issue — neither a cert
// pool nor the workload JWS verifier can even parse it.
//
// SUBSTRATE (D98, doc 19 §6). Biscuit is the ratified primary — public-key
// verification (the verifier holds only a public key, never forge-capable
// material) and Datalog blocks. The M1 flip-trigger spike (tasks 01KTWJ72WR /
// 01KTWJ73W0) recorded that NO §6 flip trigger fires: core block-append
// attenuation parity holds Go-side (biscuit-go v2.2.0), Rust verify cost sits far
// under the sync swap-path budget, and per-block revocation IDs serve the §7
// fleet list directly — so this lands on Biscuit, not the macaroon fallback. The
// substrate is reached through a clean `SubstrateSigner` seam (so the flip, if it
// ever fires, is a seam-internal change, and a deployment that cannot ship a
// Datalog engine can swap the stdlib Ed25519 default in) — exactly the
// `presented_credential`-is-format-opaque posture of the D22 seam (doc 19 §5).
//
// D52 DISCIPLINE (doc 19 §4). The claim set is emitted as TYPED Biscuit facts
// built programmatically — never hand-authored Datalog strings — mirroring the
// doc 16 §3.1 workload-identity claim set so the two credentials join trivially
// in audit (doc 19 §9). Attenuation content (Attenuate) is likewise generated
// from the typed claim vocabulary, the no-Cedar/no-free-form-caveat posture
// carried (D52, doc 16 §5.1).
//
// ISSUANCE IS OSS-RUNNABLE (P-R7/D103): base-token issuance, the attenuation
// path, and the Validate-side verification path are all here in the OSS mint —
// no paid-side import. biscuit-go is Apache-2.0.
package mint

import (
	"errors"
	"fmt"
	"time"
)

// Session-token claim fact names. Each is a typed Biscuit fact (D52, doc 19 §4):
// the launching_user/session_uuid/org/repo-branch/role_ref/task_ref/
// parent_session/expiry claim set mirrors the doc 16 §3.1 workload-identity set
// so the two credentials join in audit (doc 19 §9). These are the v0 typed-
// template vocabulary — the ceiling the attenuator stays far under (doc 19 §4).
const (
	factLaunchingUser = "launching_user" // root attribution (doc 04 §5)
	factSessionUUID   = "session"        // scoping: keys session liveness at Validate
	factOrg           = "org"
	factRepoBranch    = "repo_branch"
	factRoleRef       = "role_ref"       // opaque reference (doc 19 §11 seam — not designed here)
	factTaskRef       = "task_ref"       // reference to the recorded prompt/plan (doc 04 §3)
	factParentSession = "parent_session" // EMPTY on the base token; populated down the chain (doc 19 §4)
	factRootSession   = "root_session"   // the chain's ORIGINATING session; inherited unchanged (doc 19 §7)
	factExpiry        = "expiry"         // TTL = session lifetime (doc 19 §3)
	factService       = "service"        // grant-relevant service scope (one fact per service)
)

// SessionTokenClaims is the doc 19 §3 base-token claim set, the typed record the
// substrate signer turns into facts. It deliberately mirrors the doc 16 §3.1
// workload-identity claim set (jwtClaims) field-for-field where the two overlap,
// so an auditor joins the X.509/JWT identity and the scoped token on
// session_uuid + launching_user (doc 19 §9).
type SessionTokenClaims struct {
	LaunchingUser string // root attribution = IdP subject (doc 04 §5)
	SessionUUID   string // scoping; keys Validate session liveness
	Org           string
	RepoBranch    string
	RoleRef       string // opaque reference (doc 19 §11)
	TaskRef       string // reference to the recorded prompt/plan (doc 04 §3 control-plane DB)
	ParentSession string // EMPTY on the base token (doc 19 §3); a fan-out hop populates it (doc 19 §4)
	// RootSession is the chain's ORIGINATING session_uuid. On the base token it is
	// EMPTY (the base IS the root — SessionUUID names it); every attenuation hop
	// pins it to the parent's effective root (the parent's RootSession, or the
	// parent's SessionUUID when the parent is itself the base) and then NEVER
	// changes it. Validate keys WHOLE-CHAIN liveness on it (doc 19 §7): RevokeSession
	// on the root fails every descendant token closed immediately, while per-child
	// revocation still keys on the child's own SessionUUID (doc 19 §7 two-key rule).
	RootSession string
	// Services is the grant-relevant service scope carried in the token. On the
	// base token this is the session's full requested set; an attenuated child
	// narrows it (⊆ parent), and Validate intersects grants ∩ token scope (doc 19
	// §8). Empty means "no service scope asserted by the token" (grants govern).
	Services []string
	// Scopes is the D127 token scope taxonomy set the token carries (doc 23 §6,
	// the `ds_scopes` claim): the coarse-grained capability scopes (e.g.
	// `v1:network:egress`, `v1:code:write`) the D22 Validate seam asserts a
	// requested operation is covered by. Like Services it is MONOTONIC under
	// attenuation — a child set is ⊆ the parent's, so a holder can only drop
	// scopes, never add them (doc 19 §4). `omitempty` keeps the serialized claim
	// bytes IDENTICAL to a pre-scope token when no scopes are asserted, so an
	// unscoped base token round-trips unchanged (the biscuit-render golden holds).
	Scopes []string `json:",omitempty"`
	// Expiry is the token horizon. TTL = session lifetime (doc 19 §3); a child's
	// expiry is shorter-or-equal (doc 19 §4).
	Expiry time.Time
}

// MintSessionTokenReq is the MintSessionToken input (doc 16 §4 skeleton: the
// scoped per-session base token, minted on behalf of the launching user). The
// org registry / principal resolver are shim-wide; this carries the per-session
// scoping inputs. parent_session is intentionally NOT an input — the BASE token
// always has an empty parent_session (doc 19 §3); a child hop is produced by
// AttenuateSessionToken, not by a second mint call (doc 19 §4: zero mint RPCs at
// fan-out).
type MintSessionTokenReq struct {
	SessionUUID   string
	LaunchingUser string // resolved via PrincipalResolver if one is set (as MintWorkloadIdentity)
	Org           string
	RepoBranch    string
	RoleRef       string
	TaskRef       string
	Services      []string
	// Scopes is the D127 token scope taxonomy set the base token carries (doc 23
	// §6). The orchestrator seeds it from the role/task grant at mint; a fan-out
	// hop can only narrow it (doc 19 §4). Empty asserts no scope (grants govern).
	Scopes []string
	// TTL is the token lifetime; zero means defaultSessionTTL. TTL = session
	// lifetime (doc 19 §3).
	TTL time.Duration
}

// SessionTokenBundle is the MintSessionToken output (doc 16 §4: SessionTokenBundle).
// Token is the format-opaque presented credential (a serialized Biscuit under the
// default substrate); it rides the existing D22 Validate seam unchanged (doc 19
// §5). RevocationIDs are the per-block chain fingerprints the doc 19 §7 fleet
// revocation list keys on (fingerprint-only — token bytes never appear in a log,
// doc 16 §9 / doc 19 §9).
type SessionTokenBundle struct {
	// Token is the opaque presented value. Never logged (fingerprint-only, §9).
	Token []byte
	// Expiry is the token horizon (TTL = session lifetime).
	Expiry time.Time
	// SessionUUID echoes the root scoping claim Validate keys liveness on.
	SessionUUID string
	// RevocationIDs are the per-block chain fingerprints (the doc 19 §7 fleet
	// revocation identifiers); one for the base token, +1 per attenuation hop.
	RevocationIDs [][]byte
	// AttenuationDepth is 0 for the base token; each AttenuateSessionToken hop +1.
	AttenuationDepth int
}

// SubstrateSigner is the doc 19 §5/§6 substrate seam: the credential FORMAT lives
// behind it, exactly as `presented_credential` is format-opaque at the frozen D22
// seam. The default is Biscuit (D98 primary); a deployment that cannot ship a
// Datalog engine (the §6 security-review flip trigger) or that flips to macaroons
// installs a different signer here without touching MintSessionToken or Validate.
//
// All three operations are PURE w.r.t. the shim's session store — the signer
// owns ONLY the third signing context (doc 19 §3), never session liveness or
// grant state, which always resolve at the D22 seam (doc 19 §5).
type SubstrateSigner interface {
	// Name identifies the substrate for audit/diagnostics (e.g. "biscuit-v2").
	Name() string
	// Mint signs the claim set into an opaque token (the per-session base token).
	Mint(claims SessionTokenClaims) (token []byte, revocationIDs [][]byte, err error)
	// Verify checks the token signature against the third-context public key and
	// returns the decoded claims. It performs SIGNATURE + the token's own
	// authorization (the embedded scope checks) ONLY — never session liveness or
	// grants, which Validate owns. depth is the attenuation depth (0 = base).
	Verify(token []byte) (claims SessionTokenClaims, depth int, err error)
	// Attenuate derives a strictly-narrower child token OFFLINE (no mint
	// round-trip, doc 19 §4): it appends a narrowing block. narrow.ParentSession
	// is the appended next hop; narrow.Services must be ⊆ the parent's; the child
	// expiry is shorter-or-equal. Monotonic: a holder can only remove authority.
	Attenuate(parent []byte, narrow SessionTokenAttenuation) (child []byte, revocationIDs [][]byte, err error)
	// PublicKeyDER returns the third-context verification public key. Exposed so
	// the isolation tests can prove it is NOT either D82 root and that a session
	// token never validates as workload identity / interception material.
	PublicKeyDER() []byte
}

// SessionTokenAttenuation is the typed narrowing applied at a fan-out hop (doc 19
// §4). Generated from the typed claim vocabulary only (D52) — never a hand-
// authored caveat. It can only NARROW: a child session_uuid (the next
// parent_session hop), a service set ⊆ the parent's, and a shorter-or-equal
// expiry.
type SessionTokenAttenuation struct {
	// ChildSessionUUID becomes the child token's session scope and is appended as
	// the chain's next parent_session hop (the identity lineage, doc 19 §4/§9).
	ChildSessionUUID string
	// Services is the narrowed service scope (⊆ the parent's). Nil keeps the
	// parent's scope.
	Services []string
	// Scopes is the narrowed D127 scope set (⊆ the parent's, doc 23 §6 / doc 19
	// §4). Nil keeps the parent's scopes; a non-subset request fails closed
	// (errSessionTokenScope) — a holder can only REMOVE scopes at a fan-out hop.
	Scopes []string
	// Expiry shortens the horizon; zero keeps the parent's.
	Expiry time.Time
	// TaskRef is the child's task reference (doc 19 §4).
	TaskRef string
}

var (
	errNoSigner          = errors.New("mint: no substrate signer configured")
	errSessionTokenScope = errors.New("mint: attenuation would widen token scope")
	errNoParentToken     = errors.New("mint: attenuate needs a parent token")
	errNoChildSession    = errors.New("mint: child session derivation needs a child session_uuid")
)

// WithSubstrateSigner installs a session-token substrate signer (doc 19 §6 seam).
// Absent it, NewShim mints the Biscuit default (D98). A deployment flips
// substrates — or drops to the stdlib Ed25519 fallback — by passing one here,
// with no change to MintSessionToken or Validate (the format-opaque D22 posture,
// doc 19 §5).
func WithSubstrateSigner(s SubstrateSigner) Option {
	return func(sh *Shim) { sh.tokenSigner = s }
}

// MintSessionToken mints the scoped per-session base token on behalf of the
// launching user (doc 19 §3, D99). It is the doc 15 §4.1 step-5 issuance,
// delivered through the existing step-8 entrypoint slot — no new choreography.
//
// The base token always has an EMPTY parent_session (doc 19 §3); the lineage hop
// is appended by AttenuateSessionToken at fan-out, never by a second mint
// (doc 19 §4: zero mint RPCs as the tree widens). The token registers on the
// in-memory session record so the existing Validate seam re-checks session
// liveness on every presentation (doc 16 §5.4 / doc 19 §7) and an expired or
// revoked session fails it closed.
//
// launching_user is resolved through the same PrincipalResolver seam as
// MintWorkloadIdentity (the orchestrator principal-store linkage, doc 04 §5),
// so the two credentials carry the SAME root attribution and join in audit
// (doc 19 §9).
func (s *Shim) MintSessionToken(req MintSessionTokenReq) (*SessionTokenBundle, error) {
	if s.tokenSigner == nil {
		return nil, errNoSigner
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

	claims := SessionTokenClaims{
		LaunchingUser: launchingUser,
		SessionUUID:   req.SessionUUID,
		Org:           req.Org,
		RepoBranch:    req.RepoBranch,
		RoleRef:       req.RoleRef,
		TaskRef:       req.TaskRef,
		ParentSession: "", // EMPTY on the base token (doc 19 §3)
		Services:      append([]string(nil), req.Services...),
		Scopes:        append([]string(nil), req.Scopes...),
		Expiry:        notAfter,
	}
	token, revIDs, err := s.tokenSigner.Mint(claims)
	if err != nil {
		return nil, fmt.Errorf("mint: sign session token: %w", err)
	}

	// Register/refresh the session record so Validate re-checks liveness against
	// it (doc 16 §5.4). A session that only ran MintSessionToken (no workload
	// identity) is still a live record the token's liveness check keys on.
	s.mu.Lock()
	rec := s.sessions[req.SessionUUID]
	if rec == nil {
		rec = &sessionRecord{grants: make(map[string]string)}
		s.sessions[req.SessionUUID] = rec
	}
	if rec.state != sessionRevoked {
		rec.state = sessionLive
	}
	// Track the token horizon, but never SHORTEN an existing session expiry the
	// workload identity already set (the token TTL = session lifetime; they agree
	// in normal use, but a record's expiry is the session's, not one credential's).
	if rec.expiry.IsZero() || notAfter.After(rec.expiry) {
		rec.expiry = notAfter
	}
	rec.hasSessionToken = true
	s.mu.Unlock()

	return &SessionTokenBundle{
		Token:            token,
		Expiry:           notAfter,
		SessionUUID:      req.SessionUUID,
		RevocationIDs:    revIDs,
		AttenuationDepth: 0,
	}, nil
}

// AttenuateSessionToken derives a strictly-narrower CHILD token OFFLINE at a D18
// fan-out hop (doc 19 §4, D100) — no mint round-trip. It is exposed so the
// orchestrator/wrapper (a different module) can derive one child token per
// subagent VM without calling the mint; identity lineage becomes a cryptographic
// property of the credential (the killer fit, doc 19 §1/§4). Monotonic: a child
// can only REMOVE authority (narrower service set, shorter expiry, a child
// session scope appended as the next parent_session hop). A widening request
// fails closed (errSessionTokenScope).
//
// It does NOT register a record or call the mint — attenuation is a pure,
// issuer-free derivation (doc 19 §4); the child VM's own session record is
// established by its create choreography, and Validate keys liveness on the
// child's session_uuid claim (doc 19 §7).
func (s *Shim) AttenuateSessionToken(parent *SessionTokenBundle, narrow SessionTokenAttenuation) (*SessionTokenBundle, error) {
	if s.tokenSigner == nil {
		return nil, errNoSigner
	}
	if parent == nil || len(parent.Token) == 0 {
		return nil, errNoParentToken
	}
	child, revIDs, err := s.tokenSigner.Attenuate(parent.Token, narrow)
	if err != nil {
		return nil, err
	}
	childExpiry := parent.Expiry
	if !narrow.Expiry.IsZero() && narrow.Expiry.Before(parent.Expiry) {
		childExpiry = narrow.Expiry
	}
	childSession := parent.SessionUUID
	if narrow.ChildSessionUUID != "" {
		childSession = narrow.ChildSessionUUID
	}
	return &SessionTokenBundle{
		Token:            child,
		Expiry:           childExpiry,
		SessionUUID:      childSession,
		RevocationIDs:    revIDs,
		AttenuationDepth: parent.AttenuationDepth + 1,
	}, nil
}

// effectiveRoot returns a claim set's chain-originating session_uuid (doc 19 §7):
// its RootSession when set, else its SessionUUID (the base token IS the root, so it
// carries no separate root claim). Used to PIN the root on a child during
// attenuation and to KEY whole-chain liveness at Validate.
func effectiveRoot(c SessionTokenClaims) string {
	if c.RootSession != "" {
		return c.RootSession
	}
	return c.SessionUUID
}

// applyRootPin sets the child's RootSession to the parent's effective root, but
// ONLY when the hop actually re-roots the session identity (a new
// ChildSessionUUID). A hop that leaves SessionUUID unchanged (pure scope/TTL
// narrowing) does not start a new descendant identity, so the root claim is left
// as-is (empty on a still-base token). Shared by every substrate's Attenuate so the
// root-pinning rule lives in one place (doc 19 §7).
func applyRootPin(child *SessionTokenClaims, parent SessionTokenClaims, narrow SessionTokenAttenuation) {
	if narrow.ChildSessionUUID == "" {
		return
	}
	child.RootSession = effectiveRoot(parent)
}

// IsSessionToken reports whether a presented value is structurally a session
// token (it carries the substrate's domain-separation marker). Used by Validate
// to route the session-token leg — and, critically, to REFUSE to treat a session
// token as a workload JWT (the doc 19 §13 negative property, enforced
// structurally: the routing never lets a session token reach the workload-key
// verifier).
func (s *Shim) IsSessionToken(presented []byte) bool {
	if s.tokenSigner == nil {
		return false
	}
	_, _, err := s.tokenSigner.Verify(presented)
	return err == nil
}
