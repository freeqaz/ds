package sessions

// roleref.go is the doc 15 §4.1 STEPS 1–2 role_ref RESOLUTION + PINNING stage of
// the create choreography (doc 18 §6 projection table row "1–2", D89–D96). It is
// the create-sequence point where the requested role is resolved against the org
// catalog and PINNED for the session lifetime; the pinned value is what step-5
// (createstep5.go / AssembleStep5MintRequest) stamps into the mint claims and what
// the doc 19 §11 role-template seam keys on, and it flows as DATA to the
// childsession.go fan-out so children inherit the parent's pinned role unless the
// template narrows.
//
// WHAT THIS STAGE IS AND IS NOT:
//   - IS: the §4.1 steps-1–2 resolution that turns a requested role_ref (the
//     verbatim `<name>@<version>` / catalog-UUID token, or the absent posture)
//     into a PinnedRole — the immutable (role_name, role_version,
//     role_content_hash) triple the never-recycled session record carries (doc 18
//     §7, D66). It is the work the createstep5.go header deferred to "taskdb
//     01KTWJ5A88" — now landed here.
//   - IS NOT: the role ENGINE. Role semantics, authority, lifecycle, and the
//     catalog write path live entirely in doc 18 (the agent-roles design) and the
//     roles/ tree; this stage only RESOLVES + PINS through a RoleResolver seam.
//     The real org-catalog-backed resolver is doc 18's — installed behind this
//     same seam WITHOUT changing this shape (the precedent: identity/mint's
//     DefaultRoleTemplateResolver is the v0 default-only resolver behind the doc
//     19 §11 hook; this is the orchestrator-side analog at steps 1–2).
//   - IS NOT: the doc 19 §11 attenuation TEMPLATE resolver (that is mint-side,
//     RoleAttenuationTemplate keyed on role_ref). This stage produces the PIN; the
//     mint-side template seam consumes the pinned ref. The two are distinct seams
//     on the same role_ref (this one pins identity+widening posture for the
//     session record; the mint one folds a narrowing template at a fan-out hop).
//
// DOC 18 §11 RUNTIME-ROW EVIDENCE (which §11 checks run AT CREATE TIME, recorded
// here because this is the create-time stage that carries them — see the §11
// status cells the doc edit marks):
//   - PIN-AND-AUDIT: ResolveAndPinRole writes the (name, version, content_hash)
//     triple into the PinnedRole the session record carries; absent role_ref
//     records `default@<current>` EXPLICITLY (RoleResolver.Default), never null
//     (doc 18 §7: "Default is recorded, not null"). A catalog update mid-flight
//     does not change a pinned session's triple — the pin is taken once, here, at
//     create (doc 18 §7: "Pinned at create, never retro-applied").
//   - WIDENING-GATE: a role whose widenings are UNRATIFIED is NOT a refusal — the
//     create PROCEEDS with the widenings riding INERT (PinnedRole.InertWidenings,
//     admitting nothing) plus a logged warning (the doc 13 §1 rule-7 pattern,
//     D91). Only post-ratification (RoleResolution.WideningsRatified) does the
//     widening admit; the ratification event is actor-recorded in the catalog
//     (doc 18 §7), not here.
//   - NARROWING-HOLDS and DENY-OVERRIDES are ENFORCEMENT-PLANE rows, NOT decided
//     at this create-time stage: a role can only narrow (intersection at the
//     grant template, doc 18 §6 step 5 / doc 19 §11) and an org blocklist
//     structurally wins (deny-overrides, doc 13 §1 rule 2). This stage carries the
//     pinned role forward so those checks have a pinned subject; it never relaxes
//     them. The pin is the input to enforcement, never its trust boundary.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// defaultRoleName is the recorded default role (doc 18 §7: a create without an
// explicit role_ref records `default@<current>`, never null). It mirrors
// identity/mint's defaultRoleName — one recorded default name across the seam, not
// two — without importing the mint module (the only legal cross-tree import is
// proto/gen/go; this name is a documented constant, not a shared type).
const defaultRoleName = "default"

// ErrRoleRefRefused is the structural refusal of the §4.1 steps-1–2 role stage:
// an unknown role, a schema-invalid role, or an unresolvable ref refuses the
// create FAIL-CLOSED — the same posture as the D56 two-key check (doc 18 §6
// projection table row "1–2"). It is distinct from a resolver fault (a catalog
// read error) so the create driver can tell "the ref is bad" (refuse, attributably)
// from "the catalog is unreachable" (a transient stall the rollback note covers).
var ErrRoleRefRefused = errors.New("sessions: role_ref refused (unknown/schema-invalid/unresolvable)")

// PinnedRole is the IMMUTABLE role identity the create choreography pins into the
// never-recycled session record at §4.1 steps 1–2 (doc 18 §7, D66/D89–D96). It is
// the in-package projection of exactly the doc 18 §7 pinned triple plus the
// widening posture the §9 gate carries — the DATA step-5 stamps into the mint
// claims and that flows to the childsession.go fan-out. It is never a catalog
// handle and never the roles/ YAML; the resolution happened here, and downstream
// stages consume the pin as a value.
type PinnedRole struct {
	// Name is the role name (doc 18 §7's `role_name`); `default` for the recorded
	// de-risking default. Always non-empty for a pinned role.
	Name string
	// Version is the role's content identifier (doc 18 §7's `role_version`,
	// roles/SCHEMA.md rule 5: a content identifier, NEVER a second version
	// namespace). E.g. `2026.06.11-v1`. Always non-empty for a pinned role —
	// `default@<current>` resolves to the recorded current default version.
	Version string
	// ContentHash is the role's `role_content_hash` (doc 18 §7 / roles/SCHEMA.md
	// rule 5): the same canonical-serialization machinery the PolicySnapshot
	// content_hash uses (one canonicalization spec, not two). Pins the EXACT role
	// bytes, so a catalog update to the same (name, version) is still a distinct
	// pin. Always non-empty for a pinned role.
	ContentHash string
	// InertWidenings is the role's UNRATIFIED widening requests, riding INERT (doc
	// 18 §9, D91): the create proceeded WITH them present but ADMITTING NOTHING
	// (the doc 13 §1 rule-7 pattern). They are recorded on the pin for the audit
	// trail and the logged warning; they are NOT a refusal and NOT enforced — the
	// substrate / deny-overrides admit nothing on their behalf until the role
	// version is org-ratified. Empty when the role has no widenings or its
	// widenings are ratified.
	InertWidenings []string
	// WideningsRatified is true when the resolved role's widenings are org-ratified
	// (the actor-recorded catalog act, doc 18 §9/§7) — only then do they admit. A
	// role with no widenings is trivially "ratified" (nothing to gate). When false
	// AND InertWidenings is non-empty, the create proceeded with the widenings
	// inert + a logged warning (the widening-gate row).
	WideningsRatified bool
}

// Ref returns the canonical recorded `<name>@<version>` form of the pin (doc 18
// §7's recorded ref). It is what step-5 stamps and what the childsession.go fan-out
// carries as ChildSessionDerivation.RoleRef so children inherit the parent's pinned
// role. For the recorded default this is `default@<current>` — the explicit,
// auditable form, never the empty string.
func (p PinnedRole) Ref() string {
	if p.Name == "" {
		return ""
	}
	if p.Version == "" {
		return p.Name
	}
	return p.Name + "@" + p.Version
}

// RoleResolution is the RoleResolver's verbatim outcome for one role_ref: the
// resolved role's pinned identity (name/version/content_hash) plus its widening
// posture. ok=false means the ref is UNKNOWN/unresolvable to the resolver — a
// structural refusal at this stage (distinct from a resolver fault, which is an
// error). It mirrors the (template, ok) shape of identity/mint's
// RoleTemplateResolver so the two seams read the same way.
type RoleResolution struct {
	// Name/Version/ContentHash are the resolved role's pinned triple (doc 18 §7).
	// All three MUST be populated for a resolved (ok=true) role — a resolver that
	// returns ok=true with an empty triple is a schema-invalid catalog entry and is
	// refused fail-closed by ResolveAndPinRole.
	Name        string
	Version     string
	ContentHash string
	// Widenings is the role's widening requests (extra allowlist entries, pack-family
	// tier flips — doc 18 §9). Empty for a role that requests no widening (the
	// `default` role, the narrowing-only security-engineer role). When non-empty and
	// NOT ratified, they ride inert + logged warning (the widening-gate row).
	Widenings []string
	// WideningsRatified is whether an org admin has ratified this role version's
	// widened envelope (the actor-recorded catalog act, doc 18 §9). Meaningful only
	// when Widenings is non-empty.
	WideningsRatified bool
}

// RoleResolver is the doc 15 §4.1 steps-1–2 role-catalog seam (doc 18 §6): it turns
// a requested role_ref into its RoleResolution (resolved pin + widening posture), or
// reports the ref unknown (ok=false → structural refusal). It is the
// orchestrator-side analog of identity/mint's RoleTemplateResolver hook: v0 ships a
// DEFAULT-ONLY resolver (DefaultRoleResolver) that recognizes the recorded default
// and nothing else; doc 18 installs the real org-catalog-backed resolver (at M0 it
// may read the checked-in roles/ YAML directly) WITHOUT changing this shape.
//
// Resolve(ref) resolves a NON-EMPTY requested ref; ok=false = unknown/unresolvable.
// Default() returns the recorded current default (`default@<current>`) for the
// absent-role_ref posture — recorded explicitly so "no role" and "default role" are
// the same auditable fact (doc 18 §7). A resolver fault (catalog unreachable) is the
// error return on Resolve; Default never faults (the recorded default is a constant
// of the catalog the resolver is configured with).
type RoleResolver interface {
	Resolve(ctx context.Context, ref string) (RoleResolution, bool, error)
	Default(ctx context.Context) (RoleResolution, error)
}

// ResolveAndPinRole is the §4.1 steps-1–2 stage: it resolves the requested role_ref
// against the catalog seam and PINS the result (doc 18 §6 row "1–2", §7, D89–D96).
// It is fail-closed on a bad ref and lenient on an unratified widening, per the doc
// 18 §11 widening-gate / pin-and-audit rows:
//
//   - ABSENT ref (requestedRef == ""): resolves the recorded default
//     (RoleResolver.Default) and pins `default@<current>` EXPLICITLY — never null
//     (doc 18 §7 "Default is recorded, not null"; the pin-and-audit row).
//   - RESOLVED ref: pins the (name, version, content_hash) triple. If the role's
//     widenings are UNRATIFIED, the create PROCEEDS with them inert + a logged
//     warning (the widening-gate row, doc 18 §9 / D91) — NOT a refusal.
//   - UNKNOWN/unresolvable ref (resolver ok=false): structural REFUSAL,
//     ErrRoleRefRefused (the §4.1 D56-posture refusal). Fail-closed.
//   - SCHEMA-INVALID resolution (ok=true but an empty pinned triple): also a
//     structural refusal — a resolver that "resolved" a ref to an unpinnable role
//     is treated as the schema-invalid refusal the doc 18 §6 row names, not as a
//     silently-empty pin.
//   - RESOLVER FAULT (Resolve/Default error): surfaced verbatim (NOT
//     ErrRoleRefRefused) — a catalog read fault is the transient the §4.1 rollback
//     note covers, attributably distinct from a bad ref.
//
// logger receives the widening-gate warning (a nil logger uses slog.Default). The
// returned PinnedRole is the DATA the create choreography threads to step-5 and to
// the childsession.go fan-out.
func ResolveAndPinRole(ctx context.Context, r RoleResolver, requestedRef string, logger *slog.Logger) (PinnedRole, error) {
	if r == nil {
		return PinnedRole{}, fmt.Errorf("sessions: ResolveAndPinRole: no role resolver configured")
	}
	if logger == nil {
		logger = slog.Default()
	}

	requestedRef = strings.TrimSpace(requestedRef)

	var (
		res RoleResolution
		ok  bool
		err error
	)
	if requestedRef == "" {
		// Absent role_ref: record `default@<current>` explicitly (the pin-and-audit
		// row, doc 18 §7). Default never reports "unknown" — the recorded default is
		// a constant of the configured catalog.
		res, err = r.Default(ctx)
		ok = err == nil
	} else {
		res, ok, err = r.Resolve(ctx, requestedRef)
	}
	if err != nil {
		// A catalog read fault — NOT a bad ref. Surfaced verbatim so the create
		// driver can stall/retry (the §4.1 rollback note) rather than attributing a
		// refusal to the requester.
		return PinnedRole{}, fmt.Errorf("sessions: resolve role_ref %q: %w", requestedRef, err)
	}
	if !ok {
		// Unknown / unresolvable ref: structural refusal, fail-closed (doc 18 §6 row
		// "1–2", the D56 two-key posture).
		return PinnedRole{}, fmt.Errorf("%w: %q", ErrRoleRefRefused, requestedRef)
	}
	if res.Name == "" || res.Version == "" || res.ContentHash == "" {
		// Schema-invalid: the resolver "resolved" the ref but could not produce the
		// pinned triple. Refuse fail-closed rather than carry an unpinnable role into
		// the session record (the pin-and-audit row requires a complete triple).
		return PinnedRole{}, fmt.Errorf("%w: %q resolved to an incomplete pin (name=%q version=%q content_hash=%q)",
			ErrRoleRefRefused, requestedRef, res.Name, res.Version, res.ContentHash)
	}

	pin := PinnedRole{
		Name:              res.Name,
		Version:           res.Version,
		ContentHash:       res.ContentHash,
		WideningsRatified: res.WideningsRatified,
	}

	// WIDENING-GATE (doc 18 §9, §11 widening-gate row, D91): a role with UNRATIFIED
	// widenings is NOT a refusal. The create proceeds with the widenings riding
	// INERT (recorded on the pin, admitting nothing) plus a logged warning — the doc
	// 13 §1 rule-7 pattern (inert-with-logged-warning, never silently admitting).
	if len(res.Widenings) > 0 && !res.WideningsRatified {
		pin.InertWidenings = append([]string(nil), res.Widenings...)
		logger.WarnContext(ctx, "session create: role carries unratified widenings — riding inert, admitting nothing (doc 18 §9 widening-gate)",
			slog.String("role_ref", pin.Ref()),
			slog.String("role_content_hash", pin.ContentHash),
			slog.Int("inert_widening_count", len(pin.InertWidenings)),
			slog.Any("inert_widenings", pin.InertWidenings),
		)
	}

	return pin, nil
}

// DefaultRoleResolver is the v0 default-only RoleResolver (doc 15 §4.1 steps 1–2):
// it recognizes ONLY the recorded de-risking default role (`default@<currentVersion>`)
// and reports every other ref UNKNOWN (ok=false → structural refusal). It is the
// orchestrator-side analog of identity/mint's DefaultRoleTemplateResolver: doc 18
// installs the real org-catalog-backed resolver behind the RoleResolver seam WITHOUT
// changing this shape. The default's pinned triple is recorded explicitly (doc 18 §7)
// — its content_hash is a fixed v0 marker until the real catalog computes the
// canonical hash (roles/SCHEMA.md rule 5); the default role narrows nothing and
// requests no widening, so its widening posture is trivially ratified.
type DefaultRoleResolver struct {
	// CurrentVersion is the recorded current default version (doc 18 §7's
	// `default@<current>`), e.g. roles/default.yaml's "2026.06.11-v1". Required.
	CurrentVersion string
	// ContentHash is the recorded default role's `role_content_hash`. A v0 marker
	// until the real catalog computes the canonical hash; required (the pin-and-audit
	// row needs a complete triple).
	ContentHash string
}

// Resolve recognizes only `default` (any version reduces to the recorded current —
// the v0 resolver pins the recorded default, not an arbitrary requested version);
// every other ref is unknown (ok=false). An explicit `default@<version>` that does
// not match the recorded current is unknown — v0 pins exactly the recorded default.
func (d DefaultRoleResolver) Resolve(_ context.Context, ref string) (RoleResolution, bool, error) {
	name, version := splitRoleRef(ref)
	if name != defaultRoleName {
		return RoleResolution{}, false, nil
	}
	if version != "" && version != d.CurrentVersion {
		// An explicit default@<other> the v0 resolver does not recognize. The real
		// catalog resolves historical versions; v0 pins only the recorded current.
		return RoleResolution{}, false, nil
	}
	res, err := d.Default(context.Background())
	if err != nil {
		return RoleResolution{}, false, err
	}
	return res, true, nil
}

// Default returns the recorded current default (`default@<CurrentVersion>`) — the
// explicit, auditable default-role pin (doc 18 §7). The default role narrows nothing
// and requests no widening (roles/default.yaml), so WideningsRatified is trivially
// true (nothing to gate).
func (d DefaultRoleResolver) Default(_ context.Context) (RoleResolution, error) {
	if d.CurrentVersion == "" || d.ContentHash == "" {
		return RoleResolution{}, fmt.Errorf("sessions: DefaultRoleResolver misconfigured: empty current version or content hash")
	}
	return RoleResolution{
		Name:              defaultRoleName,
		Version:           d.CurrentVersion,
		ContentHash:       d.ContentHash,
		WideningsRatified: true,
	}, nil
}

// compile-time assertion: the v0 default resolver satisfies the steps-1–2 seam.
var _ RoleResolver = DefaultRoleResolver{}

// splitRoleRef splits a `<name>@<version>` role_ref into its name and version (doc
// 18 §7's recorded form, e.g. `default@2026.06.11-v1`). A ref with no `@` is taken
// whole as the name (empty version); a catalog-UUID ref (no `@`) is likewise the
// name. It mirrors identity/mint's roleNameOf split so the two seams parse the same
// recorded form.
func splitRoleRef(ref string) (name, version string) {
	ref = strings.TrimSpace(ref)
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}
