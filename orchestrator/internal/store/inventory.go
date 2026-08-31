package store

// This file carries the doc 16 §3.3 agent-inventory READ PATH and the
// `launching_user` RESOLVER seam at the orchestrator boundary — the two read-side
// consumers of the principal record + session→launching_principal linkage that
// 0006_principals.sql / principals.go already landed. D45/D56/D57/D62.
//
// These methods are defined on the existing *Memory and *Postgres types (same
// package, new file) and are DELIBERATELY NOT part of the Repository interface:
// they are read-path projections layered over the persisted record, not new
// mutators of it, so adding them never reopens the frozen Repository surface
// (repository.go). Callers that need them take the concrete store or a narrower
// read-side interface they own.
//
// Scope discipline: this is the MINIMAL inventory the §3.3 D62 obligation needs —
// "who launched what, attributed to the launching user, joined to the D7 env
// config." The full seat/viewer roster (D57/D61 multiplayer) is NOT surfaced; the
// inventory pins the 1:1 launching-principal shape (the doc 04 §5 single-root
// `launching_user` claim) so M4 multiplayer extends it additively rather than
// retrofitting an agent-only model.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
)

// InventoryRow is one row of the doc 16 §3.3 agent inventory: a session joined to
// the principal that launched it (the §3.1 `launching_user` attribution) and to
// its D7 env config. It is the read-projection the paid dashboard layer renders;
// a dedicated inventory API is a v0 non-goal (§3.3), so this is a value shape, not
// an RPC.
//
// The launching-principal fields are ZERO when the session has no launching
// principal (the nullable pre-mint / system-session case): LaunchingPrincipalID,
// LaunchingUser, Org, and DisplayName are all empty. The inventory still lists
// such a session — attribution is "unknown yet", never a dropped row.
//
// RESERVED shape (M4, D57/D61): exactly ONE launching principal per row (the
// single-root attribution claim). The multiplayer seat/viewer roster is a later
// additive field set, never a second launcher on this row.
type InventoryRow struct {
	SessionUUID       string
	HostID            string
	HostSessionIndex  uint64
	State             SessionState
	ParentSessionUUID string
	SessionCreatedAt  string // RFC3339; rendered, not parsed by the dashboard

	// Attribution (the §3.1 `launching_user` claim, resolved to the principal).
	LaunchingPrincipalID string
	LaunchingUser        string // the principal's IdP subject — the claim VALUE
	Org                  string
	DisplayName          string

	// D7 env config join.
	EnvConfigRef string
	ImageID      string
}

// InventoryFilter narrows the agent-inventory sweep. Zero value matches all.
// Org scopes to one org (the dashboard's per-org sweep); LaunchingPrincipalID
// scopes to the sessions one principal launched (the per-principal drill-down the
// composite 0007 index serves). IncludeDestroyed mirrors SessionFilter: DESTROYED
// rows are omitted unless asked for.
type InventoryFilter struct {
	Org                  string
	LaunchingPrincipalID string
	IncludeDestroyed     bool
}

// AgentInventory returns the doc 16 §3.3 inventory rows matching f, newest first.
// This is the orchestrator-internal read path that the paid dashboard layer
// renders over control-plane Postgres (the §3.3 join), surfaced here as a typed
// method so the in-memory and Postgres stores answer it identically. It joins
// sessions → principals (launching attribution) → env_configs (the D7 env), with
// the launching-principal and env-config joins both LEFT so a session missing
// either still lists.
func (m *Memory) AgentInventory(ctx context.Context, f InventoryFilter) ([]InventoryRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []InventoryRow
	for _, s := range m.sessions {
		if !f.IncludeDestroyed && s.State == SessionDestroyed {
			continue // mirrors SessionFilter's destroyed-omitted default
		}
		principalID := m.launchingPrincipal[s.Ref.SessionUUID]
		if f.LaunchingPrincipalID != "" && principalID != f.LaunchingPrincipalID {
			continue
		}
		row := InventoryRow{
			SessionUUID:          s.Ref.SessionUUID,
			HostID:               s.Ref.HostID,
			HostSessionIndex:     s.Ref.HostSessionIndex,
			State:                s.State,
			ParentSessionUUID:    s.ParentSessionUUID,
			SessionCreatedAt:     s.CreatedAt.UTC().Format(inventoryTimeLayout),
			LaunchingPrincipalID: principalID,
			EnvConfigRef:         s.EnvConfigRef,
		}
		// LEFT JOIN principals: a present link resolves the §3.1 claim value.
		if principalID != "" {
			if pr, ok := m.principals[principalID]; ok {
				row.LaunchingUser = pr.IdPSubject
				row.Org = pr.Org
				row.DisplayName = pr.DisplayName
			}
		}
		// Org filter is on the PRINCIPAL's org (attribution scope): a session with
		// no launching principal has no org and is excluded from an org-scoped
		// sweep, but is included in an unscoped (f.Org == "") sweep.
		if f.Org != "" && row.Org != f.Org {
			continue
		}
		// LEFT JOIN env_configs: a pruned env config leaves ImageID empty.
		if env, ok := m.envs[s.EnvConfigRef]; ok {
			row.ImageID = env.ImageID
		}
		out = append(out, row)
	}
	// Newest first, then session_uuid for a stable total order (mirrors the
	// VIEW's ORDER BY the Postgres path applies).
	sort.Slice(out, func(i, j int) bool {
		if out[i].SessionCreatedAt != out[j].SessionCreatedAt {
			return out[i].SessionCreatedAt > out[j].SessionCreatedAt
		}
		return out[i].SessionUUID > out[j].SessionUUID
	})
	return out, nil
}

// ResolveLaunchingUserClaim is the `launching_user` RESOLVER seam at the
// orchestrator boundary (doc 16 §3.1/§3.2). Given a session, it resolves the
// linked launching principal to the CLAIM VALUE the mint call stamps into the
// workload identity's `launching_user` claim — the principal's IdP subject, the
// doc 04 §5 attribution promise made concrete.
//
// This is the resolve-side counterpart of SetSessionLaunchingPrincipal: that
// method records WHICH principal launched the session; this method yields the
// VALUE the mint surface needs. It is the seam the orchestrator calls so that
// identity/mint — a SEPARATE Go module that must not be imported here (proto/gen/go
// is the only legal cross-tree import) — never reaches into the store: the
// orchestrator resolves the claim value HERE and passes it across the proto seam
// as the MintWorkloadIdentityReq.launching_principal field (doc 16 §4 skeleton).
//
// Returns:
//   - ok == false, no error: the session exists but has no launching principal
//     (the nullable pre-mint / system-session case). The caller mints with no
//     resolved launching_user — never a fabricated subject.
//   - ErrNotFound: the session itself is unknown.
//   - ErrInvalid: the link names a principal that no longer exists (a dangling
//     reference the soft-FK guard should have prevented; surfaced rather than
//     silently treated as "no claim", so the inconsistency is loud).
func (m *Memory) ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (LaunchingUserClaim, bool, error) {
	if err := ctx.Err(); err != nil {
		return LaunchingUserClaim{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[sessionUUID]; !ok {
		return LaunchingUserClaim{}, false, wrap(ErrNotFound, "session %s", sessionUUID)
	}
	principalID := m.launchingPrincipal[sessionUUID]
	if principalID == "" {
		return LaunchingUserClaim{}, false, nil // nullable / no launching principal
	}
	pr, ok := m.principals[principalID]
	if !ok {
		return LaunchingUserClaim{}, false, wrap(ErrInvalid, "session %s links to unknown principal %s", sessionUUID, principalID)
	}
	return claimFromPrincipal(principalID, *pr), true, nil
}

// ResolveOrgAdminAcceptor is the ORG-ADMIN ACCEPTOR resolver seam at the
// orchestrator boundary (doc 16 §8.2, D45). Given an asking session, it resolves an
// eligible ORG-ADMIN that an ALLOW-ALWAYS ask escalates to: "Allow-always escalates
// to org-admin acceptance, delegable by posture." It is the resolve-side counterpart
// to ResolveLaunchingUserClaim — that method yields the launching-user DEFAULT
// approver; this one yields the org-admin acceptor the allow-always escalation
// requires — and like it, this is a READ-PROJECTION layered over the persisted
// record, NOT part of the frozen Repository.
//
// The eligible acceptor is a principal IN THE ASKING SESSION'S ORG that MayApprove()
// admits via RoleOrgAdmin (principalroles.go): the org is the launching principal's
// org (the §3.1 attribution scope), and the acceptor is the org's org-admin. Among
// several eligible org-admins the LOWEST principal ID is chosen, so the resolution is
// deterministic and the Memory + Postgres paths agree (mirroring the inventory's
// total-order tie-break). The election/posture delegation of WHICH org-admin is a
// later org-layer concern (D45 "delegable by posture"); this resolves the eligible
// acceptor the routing escalates to.
//
// Returns (mirroring the orgAdminResolver seam the policylog routing consumes):
//   - ok == true: an eligible org-admin exists; the returned Principal is the acceptor
//     the allow-always grant is attributed to.
//   - ok == false, no error: the FAIL-CLOSED case (D45) — the session exists but has
//     no org context (no launching principal, so no org to scope to) OR no eligible
//     org-admin in that org. The routing refuses to resolve an approver; allow-always
//     must NOT silently fall back to the launching user.
//   - ErrNotFound: the session itself is unknown.
//   - ErrInvalid: the link names a principal that no longer exists (a dangling
//     reference the soft-FK guard should have prevented; surfaced loudly, the same as
//     ResolveLaunchingUserClaim).
func (m *Memory) ResolveOrgAdminAcceptor(ctx context.Context, sessionUUID string) (Principal, bool, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[sessionUUID]; !ok {
		return Principal{}, false, wrap(ErrNotFound, "session %s", sessionUUID)
	}
	principalID := m.launchingPrincipal[sessionUUID]
	if principalID == "" {
		return Principal{}, false, nil // no launching principal → no org context (fail-closed)
	}
	launcher, ok := m.principals[principalID]
	if !ok {
		return Principal{}, false, wrap(ErrInvalid, "session %s links to unknown principal %s", sessionUUID, principalID)
	}
	org := launcher.Org

	// Deterministic election: lowest eligible org-admin ID in the session's org. This
	// is the documented FAIL-CLOSED DEFAULT (D45) — the first of the id-ascending
	// eligible set. A posture layer that wants to override WHICH eligible org-admin is
	// elected plugs in at the routing boundary via PostureElection (consulted ahead of
	// this default in askroute_resolve.go); absent that override the behavior here is
	// byte-identical to before.
	elig := m.eligibleOrgAdmins(org)
	if len(elig) == 0 {
		return Principal{}, false, nil // no eligible org-admin in the org (fail-closed, D45)
	}
	return elig[0], true, nil // already cloned + id-ascending → lowest-id default
}

// PostureElection is the RESERVED posture-delegation hook shape (doc 16 §8.2, D45:
// "Allow-always escalates to org-admin acceptance, DELEGABLE BY POSTURE"). It is the
// seam a future ORG/POSTURE layer implements to OVERRIDE which eligible org-admin an
// allow-always ask routes to — WITHOUT re-touching the store's lowest-id resolver
// (ResolveOrgAdminAcceptor) below. The store hardcodes the deterministic lowest-id
// election as the documented FAIL-CLOSED DEFAULT; this interface is the additive
// override seat that a posture layer plugs into.
//
// Given the asking session and the ELIGIBLE candidate set the store already computed
// (every org-admin in the session's org that MayApprove() admits via RoleOrgAdmin,
// the same set the lowest-id default picks from), an implementation returns WHICH of
// them the posture delegation elects:
//
//   - ok == true: the posture layer elected acceptor (which MUST be drawn from the
//     supplied eligible set — the posture layer narrows WHICH eligible org-admin, it
//     never invents an ineligible one or escapes the §3.1 org scope).
//   - ok == false, no error: NO posture override for this session — the caller falls
//     back to the store's lowest-id default (the documented fail-closed election).
//   - non-nil error: a posture-lookup failure — surfaced, never swallowed into the
//     default (a posture layer that errors must not silently degrade to lowest-id).
//
// NOTE: this is a RESERVED shape — no live store implements it yet. The store keeps
// lowest-id as the only behavior on the wire today (ResolveOrgAdminAcceptor is
// byte-identical to before); the policylog routing consults an injected posture seam
// AHEAD of the store default (askroute_resolve.go), so the override point lives at
// the routing boundary, exactly where D45 places the org/posture concern. The
// candidate-set shape here documents the contract a store-resident posture hook
// would honor if a future change moves the election inside the store.
type PostureElection interface {
	ElectOrgAdminAcceptor(ctx context.Context, sessionUUID string, eligible []Principal) (Principal, bool, error)
}

// eligibleOrgAdmins returns every principal in org that MayApprove() admits via
// RoleOrgAdmin, id-ascending — the candidate set BOTH the lowest-id default and a
// PostureElection override draw from. It is the single source of the eligibility
// predicate (HasRole(RoleOrgAdmin) && MayApprove()) the in-memory election applies,
// factored out so the reserved posture-delegation hook shape (PostureElection) and
// the fail-closed default agree on the candidate set by construction. ABSENT a
// posture override, ResolveOrgAdminAcceptor's behavior is byte-identical to before:
// it takes the first (lowest-id) of this set.
func (m *Memory) eligibleOrgAdmins(org string) []Principal {
	var elig []Principal
	for _, p := range m.principals {
		if p.Org != org {
			continue
		}
		if !(p.HasRole(RoleOrgAdmin) && p.MayApprove()) {
			continue
		}
		elig = append(elig, clonePrincipal(*p))
	}
	sort.Slice(elig, func(i, j int) bool { return elig[i].ID < elig[j].ID })
	return elig
}

// LaunchingUserClaim is the resolved value the `launching_user` resolver hands to
// the mint call (doc 16 §3.1/§4). Subject is the claim VALUE itself (the
// principal's IdP subject); PrincipalID and Org travel with it so the mint
// surface's MintWorkloadIdentityReq.{launching_principal, org} fields are
// populated from one resolve (doc 16 §4 skeleton). It is a passed-by-value claim,
// NOT a store handle — the orchestrator carries it across the proto seam to
// identity/mint, which this module never imports.
type LaunchingUserClaim struct {
	PrincipalID string // the principal's stable ID (MintReq.launching_principal)
	Subject     string // the IdP subject — the `launching_user` claim VALUE (§3.1)
	Org         string // the org the subject is asserted within (MintReq.org)
}

// claimFromPrincipal projects a resolved principal onto the mint-bound claim.
func claimFromPrincipal(principalID string, p Principal) LaunchingUserClaim {
	return LaunchingUserClaim{
		PrincipalID: principalID,
		Subject:     p.IdPSubject,
		Org:         p.Org,
	}
}

// inventoryTimeLayout is the RFC3339-with-nanos layout the in-memory inventory
// renders created_at in, so its string ordering matches chronological ordering
// (the Postgres path orders on the native timestamptz column).
const inventoryTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// --- Postgres read path ---

// sqlAgentInventory reads the 0007 agent_inventory VIEW with the optional org and
// launching-principal filters ($1, $2; NULL = no filter on each) and the
// include-destroyed flag ($3), newest first. The VIEW already encodes the
// sessions ⋈ principals ⋈ env_configs join shape (0007_principal_roles.sql).
const sqlAgentInventory = `
SELECT session_uuid, host_id, host_session_index, state, parent_session_uuid,
       session_created_at, launching_principal_id, launching_user, org,
       launching_display_name, env_config_ref, image_id
FROM agent_inventory
WHERE ($1::text IS NULL OR org = $1)
  AND ($2::text IS NULL OR launching_principal_id = $2)
  AND ($3 OR state <> 'DESTROYED')
ORDER BY session_created_at DESC, session_uuid DESC`

// sqlResolveLaunchingUser resolves a session's launching principal to the claim
// value in one round trip: the session must exist (left side), and the principal
// columns are NULL when the link is unset (the nullable case) or dangling.
const sqlResolveLaunchingUser = `
SELECT s.launching_principal, p.idp_subject, p.org
FROM sessions s
LEFT JOIN principals p ON s.launching_principal = p.id
WHERE s.session_uuid = $1`

// sqlResolveSessionOrg resolves the asking session's ORG (its launching principal's
// org) in one round trip, the org-admin acceptor scope key. The session must exist
// (left side); launching_principal is NULL (no org context) when the link is unset,
// and the principal's org column is NULL when the link dangles — the two fail-closed
// / loud cases the resolver distinguishes from the row shape.
const sqlResolveSessionOrg = `
SELECT s.launching_principal, p.org
FROM sessions s
LEFT JOIN principals p ON s.launching_principal = p.id
WHERE s.session_uuid = $1`

// sqlOrgPrincipals reads every principal in one org (the org-admin candidate set),
// id-ordered so the lowest eligible org-admin is the first MayApprove() match — the
// deterministic election the in-memory path mirrors. Role eligibility is filtered in
// Go against the SAME MayApprove() predicate the Memory path uses, so the roles jsonb
// needs no array/jsonb driver operator and the module stays stdlib-only (the same
// driver-agnostic choice scanPrincipalRow makes for the roles column).
const sqlOrgPrincipals = `
SELECT id, idp_subject, org, roles, display_name, created_at, updated_at
FROM principals WHERE org = $1 ORDER BY id`

// AgentInventory is the Postgres read path for the doc 16 §3.3 inventory. It reads
// the 0007 agent_inventory VIEW, applying f's filters, newest first.
func (p *Postgres) AgentInventory(ctx context.Context, f InventoryFilter) ([]InventoryRow, error) {
	rows, err := p.db.QueryContext(ctx, sqlAgentInventory,
		nullStr(f.Org), nullStr(f.LaunchingPrincipalID), f.IncludeDestroyed)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()

	var out []InventoryRow
	for rows.Next() {
		var (
			r           InventoryRow
			idx         int64
			state       string
			parent      sql.NullString
			created     sql.NullTime
			principalID sql.NullString
			user        sql.NullString
			org         sql.NullString
			display     sql.NullString
			envRef      sql.NullString
			imageID     sql.NullString
		)
		if err := rows.Scan(
			&r.SessionUUID, &r.HostID, &idx, &state, &parent,
			&created, &principalID, &user, &org, &display, &envRef, &imageID,
		); err != nil {
			return nil, mapErr(err)
		}
		r.HostSessionIndex = uint64(idx)
		r.State = SessionState(state)
		if parent.Valid {
			r.ParentSessionUUID = parent.String
		}
		if created.Valid {
			r.SessionCreatedAt = created.Time.UTC().Format(inventoryTimeLayout)
		}
		if principalID.Valid {
			r.LaunchingPrincipalID = principalID.String
		}
		if user.Valid {
			r.LaunchingUser = user.String
		}
		if org.Valid {
			r.Org = org.String
		}
		if display.Valid {
			r.DisplayName = display.String
		}
		if envRef.Valid {
			r.EnvConfigRef = envRef.String
		}
		if imageID.Valid {
			r.ImageID = imageID.String
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

// ResolveLaunchingUserClaim is the Postgres `launching_user` resolver seam (doc 16
// §3.1/§3.2). See the *Memory method for the contract; the Postgres path resolves
// the join in one query and distinguishes the three outcomes from the row shape.
func (p *Postgres) ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (LaunchingUserClaim, bool, error) {
	var (
		principalID sql.NullString
		subject     sql.NullString
		org         sql.NullString
	)
	err := p.db.QueryRowContext(ctx, sqlResolveLaunchingUser, sessionUUID).Scan(&principalID, &subject, &org)
	if err != nil {
		return LaunchingUserClaim{}, false, mapErr(err) // ErrNotFound for an unknown session
	}
	if !principalID.Valid {
		return LaunchingUserClaim{}, false, nil // nullable / no launching principal
	}
	if !subject.Valid {
		// The link is set but the principal row is gone: a dangling reference. The
		// soft-FK guard on SetSessionLaunchingPrincipal should prevent this; surface
		// it loudly rather than treating it as "no claim".
		return LaunchingUserClaim{}, false, wrap(ErrInvalid, "session %s links to unknown principal %s", sessionUUID, principalID.String)
	}
	return LaunchingUserClaim{
		PrincipalID: principalID.String,
		Subject:     subject.String,
		Org:         orgOrEmpty(org),
	}, true, nil
}

// orgOrEmpty unwraps a nullable org column to "" when absent.
func orgOrEmpty(org sql.NullString) string {
	if org.Valid {
		return org.String
	}
	return ""
}

// ResolveOrgAdminAcceptor is the Postgres ORG-ADMIN ACCEPTOR resolver seam (doc 16
// §8.2, D45). See the *Memory method for the contract; the Postgres path resolves the
// session's org in one query, then reads that org's principals id-ordered and returns
// the lowest one MayApprove() admits via RoleOrgAdmin — the SAME eligibility predicate
// and deterministic election the in-memory path applies, so the two impls agree.
func (p *Postgres) ResolveOrgAdminAcceptor(ctx context.Context, sessionUUID string) (Principal, bool, error) {
	var (
		principalID sql.NullString
		org         sql.NullString
	)
	err := p.db.QueryRowContext(ctx, sqlResolveSessionOrg, sessionUUID).Scan(&principalID, &org)
	if err != nil {
		return Principal{}, false, mapErr(err) // ErrNotFound for an unknown session
	}
	if !principalID.Valid {
		return Principal{}, false, nil // no launching principal → no org context (fail-closed)
	}
	if !org.Valid {
		// The link is set but the principal row is gone: a dangling reference. The
		// soft-FK guard on SetSessionLaunchingPrincipal should prevent this; surface
		// it loudly rather than treating it as "no acceptor".
		return Principal{}, false, wrap(ErrInvalid, "session %s links to unknown principal %s", sessionUUID, principalID.String)
	}

	rows, err := p.db.QueryContext(ctx, sqlOrgPrincipals, org.String)
	if err != nil {
		return Principal{}, false, mapErr(err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			pr      Principal
			roles   []byte
			display sql.NullString
		)
		if err := rows.Scan(&pr.ID, &pr.IdPSubject, &pr.Org, &roles, &display, &pr.CreatedAt, &pr.UpdatedAt); err != nil {
			return Principal{}, false, mapErr(err)
		}
		if display.Valid {
			pr.DisplayName = display.String
		}
		if len(roles) > 0 {
			if err := json.Unmarshal(roles, &pr.Roles); err != nil {
				return Principal{}, false, fmt.Errorf("unmarshal roles: %w", err)
			}
		}
		// First (lowest-id, ORDER BY id) eligible org-admin wins — the same election
		// the Memory path makes, evaluated against the SAME MayApprove() predicate.
		if pr.HasRole(RoleOrgAdmin) && pr.MayApprove() {
			if err := rows.Err(); err != nil {
				return Principal{}, false, mapErr(err)
			}
			return pr, true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return Principal{}, false, mapErr(err)
	}
	return Principal{}, false, nil // no eligible org-admin in the org (fail-closed, D45)
}
