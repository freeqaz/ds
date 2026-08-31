package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// ErrAuth is returned when launch-time human auth cannot yield an IdP-backed
// principal: an unauthenticated launch (no resolved auth), a resolved auth with
// no IdP subject, or a role outside the §3.2 vocabulary. It maps to "launch
// refused" — the launch gate never proceeds without a principal.
var ErrAuth = errors.New("auth: launch-time human auth failed")

// ResolvedAuth is the orchestrator-local mirror of the identity/idp module's
// AuthResult — the DATA an IdP flow (device-code or redirect) produced after
// validating the human's ID token (doc 16 §11.2 step 4). It is mirrored here
// rather than imported because identity/idp is a SEPARATE Go module (only
// proto/gen/go is a legal cross-tree import); the value crosses the boundary as
// data, exactly the discipline sessions.MintWorkloadIdentityClaims uses across
// the proto seam.
//
// Subject is the OIDC `sub` — the §3.2 IdP-subject key and the `launching_user`
// claim VALUE; it MUST be present (an empty subject is a refused, never
// self-declared, launch). Roles are the §11.2 group→role mapping RESULT (already
// derived from the asserted groups by the IdP side); this package writes them as
// the principal's role set, so a removed group drops its role at the next auth
// (the offboarding ladder). Email/DisplayName are display metadata only.
type ResolvedAuth struct {
	Org         string                // the org the subject is asserted within (§3.2 business key)
	Subject     string                // the OIDC `sub` — the §3.2 key / launching_user value
	Roles       []store.PrincipalRole // the §11.2 group→role mapping result (derived, not an ACL)
	DisplayName string                // display metadata only (never the identity key)
}

// validate checks the resolved auth's launch-gate preconditions: a subject and
// org must be present (the §3.2 business key), and every role must be in the
// §3.2 vocabulary. A role typo / out-of-vocabulary role fails closed here rather
// than reaching the store's CHECK, so the launch refusal is attributable to the
// auth input.
func (r ResolvedAuth) validate() error {
	if r.Subject == "" {
		return fmt.Errorf("%w: resolved auth carries no IdP subject", ErrAuth)
	}
	if r.Org == "" {
		return fmt.Errorf("%w: resolved auth carries no org", ErrAuth)
	}
	for _, role := range r.Roles {
		if !role.Valid() {
			return fmt.Errorf("%w: resolved role %q is outside the doc 16 §3.2 vocabulary", ErrAuth, role)
		}
	}
	return nil
}

// principalStore is the NARROW slice of store.Repository the principal-upsert
// path consumes (doc 16 §3.2 exported APIs). It is dependency-injected, not the
// full Repository, so the upsert depends only on the four methods it calls and a
// test fake or either store impl (*store.Memory / *store.Postgres) satisfies it.
// The orchestrator/internal/store SHARED FILES STAY FROZEN — this package only
// calls these existing exported methods; it adds no store method and no column.
type principalStore interface {
	GetPrincipalByIdP(ctx context.Context, idpSubject, org string) (store.Principal, error)
	CreatePrincipal(ctx context.Context, p store.Principal) (store.Principal, error)
	SetPrincipalRoles(ctx context.Context, id string, roles []store.PrincipalRole) (store.Principal, error)
}

// Resolver upserts an IdP-authenticated human into the control-plane principal
// record (doc 16 §3.2/§11.2). It holds the principal store seam and an ID
// generator for newly-created principals (the store requires the caller to
// supply Principal.ID; existing rows keep their ID).
type Resolver struct {
	store principalStore
	newID func() string
}

// Option tunes a Resolver (test seam: a deterministic ID generator).
type Option func(*Resolver)

// WithIDGen injects the principal-ID generator (deterministic in tests).
func WithIDGen(gen func() string) Option { return func(r *Resolver) { r.newID = gen } }

// NewResolver constructs a principal Resolver over the store seam. By default it
// mints a fresh random principal ID for newly-seen subjects (crypto/rand hex);
// WithIDGen overrides it in tests.
func NewResolver(s principalStore, opts ...Option) *Resolver {
	r := &Resolver{store: s, newID: randomPrincipalID}
	for _, o := range opts {
		o(r)
	}
	return r
}

// ResolvePrincipal upserts the IdP-authenticated human and returns the stored
// principal whose role set reflects the FRESHLY-asserted groups (doc 16 §11.2).
//
// Upsert semantics:
//   - Existing (IdPSubject, Org): the principal's role set is REPLACED with the
//     freshly-mapped roles (SetPrincipalRoles), so a group added/removed at the
//     IdP is reflected at this auth — roles are derived from the asserted groups
//     every time, never a stale parallel ACL (§11.2). The IdP subject and org
//     are the immutable business key; only roles (and the record's UpdatedAt)
//     change.
//   - New subject: a fresh principal is created (CreatePrincipal) with a minted
//     ID, the IdP subject as the §3.2 key, and the mapped role set.
//
// A resolved auth with no subject/org, or an out-of-vocabulary role, is refused
// (ErrAuth) before any store write — the launch gate proceeds only on a clean
// principal.
func (r *Resolver) ResolvePrincipal(ctx context.Context, ra ResolvedAuth) (store.Principal, error) {
	if err := ra.validate(); err != nil {
		return store.Principal{}, err
	}

	existing, err := r.store.GetPrincipalByIdP(ctx, ra.Subject, ra.Org)
	switch {
	case err == nil:
		// Known human: re-derive roles from the freshly asserted groups. Replace
		// the role set so a removed group drops its role at this auth (§11.2).
		updated, serr := r.store.SetPrincipalRoles(ctx, existing.ID, ra.Roles)
		if serr != nil {
			return store.Principal{}, fmt.Errorf("auth: update roles for principal %s: %w", existing.ID, serr)
		}
		return updated, nil
	case errors.Is(err, store.ErrNotFound):
		// New human: create the §3.2 record keyed on the IdP subject.
		created, cerr := r.store.CreatePrincipal(ctx, store.Principal{
			ID:          r.newID(),
			IdPSubject:  ra.Subject,
			Org:         ra.Org,
			Roles:       ra.Roles,
			DisplayName: ra.DisplayName,
		})
		if cerr != nil {
			return store.Principal{}, fmt.Errorf("auth: create principal for subject %q: %w", ra.Subject, cerr)
		}
		return created, nil
	default:
		// A store fault (e.g. ErrUnavailable in the degraded mode) is surfaced —
		// the launch gate stalls rather than proceeding without a principal.
		return store.Principal{}, fmt.Errorf("auth: look up principal for subject %q: %w", ra.Subject, err)
	}
}

// randomPrincipalID mints a fresh, unique-by-construction principal ID. It is a
// 16-byte crypto/rand hex string (stdlib-only — the orchestrator module stays
// stdlib-only); the store treats the ID as an opaque stable handle, so any
// collision-resistant value works. The (IdPSubject, Org) UNIQUE business key —
// not this ID — is what dedupes a human, so a never-colliding ID generator is
// all the create path needs.
func randomPrincipalID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read does not fail in practice; a panic here is correct —
		// the orchestrator must not mint a non-random principal ID.
		panic("auth: crypto/rand failed: " + err.Error())
	}
	return "prn_" + hex.EncodeToString(b[:])
}
