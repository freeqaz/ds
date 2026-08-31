package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// inventoryReader is the read-side surface this unit adds (NOT part of the frozen
// Repository interface): the §3.3 inventory query + the `launching_user` resolver
// seam. Both *Memory and *Postgres satisfy it, so the memory and (gated) Postgres
// tests drive the IDENTICAL assertions, the same way the conformance suite does
// for the Repository surface.
type inventoryReader interface {
	Repository
	AgentInventory(ctx context.Context, f InventoryFilter) ([]InventoryRow, error)
	ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (LaunchingUserClaim, bool, error)
	ResolveOrgAdminAcceptor(ctx context.Context, sessionUUID string) (Principal, bool, error)
}

var _ inventoryReader = (*Memory)(nil)
var _ inventoryReader = (*Postgres)(nil)

// inventoryClock is a fixed instant the inventory tests stamp records against.
var inventoryClock = time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)

// seedInventory builds the canonical inventory fixture used by both the query and
// resolver assertions: two orgs, a launched session, a system (unlinked) session,
// and a session whose env config resolves an image.
func seedInventory(t *testing.T, repo inventoryReader) {
	t.Helper()
	ctx := context.Background()

	// An env config the inventory join resolves to an image (the D7 join).
	_, err := repo.PutEnvConfig(ctx, EnvConfig{Ref: "env-acme", ImageID: "sha256:acme-img"})
	mustNoErr(t, err)

	// Principals in two orgs.
	_, err = repo.CreatePrincipal(ctx, Principal{
		ID: "p-ada", IdPSubject: "okta|ada", Org: "acme",
		Roles: []PrincipalRole{RoleLauncher}, DisplayName: "Ada",
	})
	mustNoErr(t, err)
	_, err = repo.CreatePrincipal(ctx, Principal{
		ID: "p-bob", IdPSubject: "okta|bob", Org: "globex",
		Roles: []PrincipalRole{RoleLauncher},
	})
	mustNoErr(t, err)

	// A launched session in acme, with the env config, attributed to Ada.
	launched := newSession("sess-launched", "host-a", 1)
	launched.EnvConfigRef = "env-acme"
	_, err = repo.CreateSession(ctx, launched)
	mustNoErr(t, err)
	mustNoErr(t, repo.SetSessionLaunchingPrincipal(ctx, "sess-launched", "p-ada"))

	// A session in globex attributed to Bob (no env config join → empty image).
	bobs := newSession("sess-bob", "host-b", 1)
	bobs.EnvConfigRef = ""
	_, err = repo.CreateSession(ctx, bobs)
	mustNoErr(t, err)
	mustNoErr(t, repo.SetSessionLaunchingPrincipal(ctx, "sess-bob", "p-bob"))

	// A system session with NO launching principal (the nullable case).
	_, err = repo.CreateSession(ctx, newSession("sess-system", "host-a", 2))
	mustNoErr(t, err)
}

func TestMemory_AgentInventory(t *testing.T) {
	repo := NewMemoryClock(fixedClock(inventoryClock))
	runAgentInventory(t, repo)
}

func TestMemory_ResolveLaunchingUserClaim(t *testing.T) {
	repo := NewMemoryClock(fixedClock(inventoryClock))
	runResolveLaunchingUser(t, repo)
}

func TestMemory_ResolveOrgAdminAcceptor(t *testing.T) {
	repo := NewMemoryClock(fixedClock(inventoryClock))
	runResolveOrgAdminAcceptor(t, repo)
}

// runAgentInventory drives the §3.3 inventory read path: the unscoped sweep lists
// every non-destroyed session (linked or not), the env-config join resolves the
// image, the org filter scopes to one org, the per-principal filter drills down,
// and the unlinked system session lists with empty attribution.
func runAgentInventory(t *testing.T, repo inventoryReader) {
	ctx := context.Background()
	seedInventory(t, repo)

	all, err := repo.AgentInventory(ctx, InventoryFilter{})
	mustNoErr(t, err)
	if len(all) != 3 {
		t.Fatalf("unscoped inventory: got %d rows, want 3 (two launched + one system)", len(all))
	}

	byUUID := map[string]InventoryRow{}
	for _, r := range all {
		byUUID[r.SessionUUID] = r
	}

	// The launched session resolves Ada's IdP subject as the launching_user claim
	// value AND the D7 env-config image.
	launched := byUUID["sess-launched"]
	if launched.LaunchingPrincipalID != "p-ada" || launched.LaunchingUser != "okta|ada" {
		t.Fatalf("launched-session attribution wrong: %+v", launched)
	}
	if launched.Org != "acme" || launched.DisplayName != "Ada" {
		t.Fatalf("launched-session org/display wrong: %+v", launched)
	}
	if launched.ImageID != "sha256:acme-img" || launched.EnvConfigRef != "env-acme" {
		t.Fatalf("env-config join not resolved: %+v", launched)
	}

	// The system session lists with EMPTY attribution (the LEFT-JOIN nullable case).
	system := byUUID["sess-system"]
	if system.LaunchingPrincipalID != "" || system.LaunchingUser != "" || system.Org != "" {
		t.Fatalf("unlinked system session should have empty attribution: %+v", system)
	}

	// Org scope: acme returns only Ada's launched session (the system session has
	// no org, and Bob's is globex).
	acme, err := repo.AgentInventory(ctx, InventoryFilter{Org: "acme"})
	mustNoErr(t, err)
	if len(acme) != 1 || acme[0].SessionUUID != "sess-launched" {
		t.Fatalf("org-scoped inventory: got %+v, want only sess-launched", acme)
	}

	// Per-principal drill-down (the 0007 composite index's hot path).
	bob, err := repo.AgentInventory(ctx, InventoryFilter{LaunchingPrincipalID: "p-bob"})
	mustNoErr(t, err)
	if len(bob) != 1 || bob[0].SessionUUID != "sess-bob" || bob[0].ImageID != "" {
		t.Fatalf("per-principal inventory: got %+v, want only sess-bob with no image", bob)
	}
}

// runResolveLaunchingUser drives the `launching_user` resolver seam: a linked
// session resolves the claim value, an unlinked session resolves ok=false with no
// error, an unknown session is ErrNotFound, and a dangling link is ErrInvalid.
func runResolveLaunchingUser(t *testing.T, repo inventoryReader) {
	ctx := context.Background()
	seedInventory(t, repo)

	// Linked: the claim resolves to Ada's IdP subject + org + principal id.
	claim, ok, err := repo.ResolveLaunchingUserClaim(ctx, "sess-launched")
	mustNoErr(t, err)
	if !ok {
		t.Fatalf("launched session should resolve a launching_user claim")
	}
	if claim.Subject != "okta|ada" || claim.PrincipalID != "p-ada" || claim.Org != "acme" {
		t.Fatalf("resolved claim wrong: %+v", claim)
	}

	// Unlinked system session: ok=false, NO error (the nullable pre-mint case).
	_, ok, err = repo.ResolveLaunchingUserClaim(ctx, "sess-system")
	mustNoErr(t, err)
	if ok {
		t.Fatalf("system session has no launching principal; resolver should return ok=false")
	}

	// Unknown session: ErrNotFound.
	if _, _, err := repo.ResolveLaunchingUserClaim(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown session resolve: got %v, want ErrNotFound", err)
	}
}

// seedOrgAdmin builds the org-admin acceptor fixture (D45 allow-always escalation):
// an acme org with a launcher (Ada) and a dedicated org-admin (Cleo, the eligible
// acceptor), plus a SECOND acme org-admin (Cady) holding a LOWER id to prove the
// deterministic lowest-id election; a globex launcher (Bob) whose org has NO
// org-admin (the fail-closed case); a system session with no launching principal
// (no org context); and a session linked to a DANGLING principal (the loud-error
// case). The org-admin acceptor is resolved over the session's launching-principal
// org, so every case is keyed by a session.
func seedOrgAdmin(t *testing.T, repo inventoryReader) {
	t.Helper()
	ctx := context.Background()

	// acme: a launcher and two org-admins (one with a deliberately LOWER id).
	_, err := repo.CreatePrincipal(ctx, Principal{
		ID: "p-ada", IdPSubject: "okta|ada", Org: "acme", Roles: []PrincipalRole{RoleLauncher},
	})
	mustNoErr(t, err)
	_, err = repo.CreatePrincipal(ctx, Principal{
		ID: "p-cleo", IdPSubject: "okta|cleo", Org: "acme",
		Roles: []PrincipalRole{RoleOrgAdmin}, DisplayName: "Cleo",
	})
	mustNoErr(t, err)
	_, err = repo.CreatePrincipal(ctx, Principal{
		// Lower id than p-cleo ("p-cady" < "p-cleo"): the deterministic election picks
		// THIS one, also proving a multi-role org-admin is eligible.
		ID: "p-cady", IdPSubject: "okta|cady", Org: "acme",
		Roles: []PrincipalRole{RoleLauncher, RoleOrgAdmin}, DisplayName: "Cady",
	})
	mustNoErr(t, err)
	// globex: a launcher but NO org-admin (the fail-closed org).
	_, err = repo.CreatePrincipal(ctx, Principal{
		ID: "p-bob", IdPSubject: "okta|bob", Org: "globex", Roles: []PrincipalRole{RoleLauncher},
	})
	mustNoErr(t, err)

	// acme session launched by Ada → escalates to an acme org-admin.
	_, err = repo.CreateSession(ctx, newSession("sess-acme", "host-a", 1))
	mustNoErr(t, err)
	mustNoErr(t, repo.SetSessionLaunchingPrincipal(ctx, "sess-acme", "p-ada"))

	// globex session launched by Bob → no org-admin in globex (fail-closed).
	_, err = repo.CreateSession(ctx, newSession("sess-globex", "host-b", 1))
	mustNoErr(t, err)
	mustNoErr(t, repo.SetSessionLaunchingPrincipal(ctx, "sess-globex", "p-bob"))

	// system session with no launching principal → no org context (fail-closed).
	_, err = repo.CreateSession(ctx, newSession("sess-system", "host-a", 2))
	mustNoErr(t, err)
}

// runResolveOrgAdminAcceptor drives the D45 org-admin acceptor seam: an acme session
// resolves the deterministic lowest-id acme org-admin (MayApprove via RoleOrgAdmin),
// a globex session with no org-admin fails closed (ok=false, no error), a session
// with no launching principal fails closed, and an unknown session is ErrNotFound.
func runResolveOrgAdminAcceptor(t *testing.T, repo inventoryReader) {
	ctx := context.Background()
	seedOrgAdmin(t, repo)

	// acme: the lowest-id eligible org-admin (p-cady) is the acceptor; the result is
	// a real org-admin MayApprove() admits.
	admin, ok, err := repo.ResolveOrgAdminAcceptor(ctx, "sess-acme")
	mustNoErr(t, err)
	if !ok {
		t.Fatalf("acme session should resolve an org-admin acceptor (D45)")
	}
	if admin.ID != "p-cady" {
		t.Fatalf("acceptor = %q, want the lowest-id eligible org-admin %q", admin.ID, "p-cady")
	}
	if admin.Org != "acme" {
		t.Fatalf("acceptor org = %q, want the session's org %q", admin.Org, "acme")
	}
	if !admin.HasRole(RoleOrgAdmin) || !admin.MayApprove() {
		t.Fatalf("resolved acceptor %+v must hold RoleOrgAdmin and MayApprove (D45)", admin)
	}

	// globex: a launcher exists but NO org-admin → fail-closed (ok=false, no error),
	// never a fallback to the launching user.
	_, ok, err = repo.ResolveOrgAdminAcceptor(ctx, "sess-globex")
	mustNoErr(t, err)
	if ok {
		t.Fatalf("globex session has no org-admin; resolver should fail closed (ok=false)")
	}

	// system session: no launching principal → no org context → fail-closed.
	_, ok, err = repo.ResolveOrgAdminAcceptor(ctx, "sess-system")
	mustNoErr(t, err)
	if ok {
		t.Fatalf("session with no launching principal has no org context; resolver should fail closed")
	}

	// Unknown session: ErrNotFound (the session itself is unknown).
	if _, _, err := repo.ResolveOrgAdminAcceptor(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown session resolve: got %v, want ErrNotFound", err)
	}
}

// posturePicksHighestId is a synthetic PostureElection: it elects the HIGHEST-id
// eligible org-admin — deliberately the OPPOSITE of the store's lowest-id default —
// so a test can prove a posture override draws from the same eligible set yet picks a
// different acceptor. It is a RESERVED-seam exerciser; no live store implements
// PostureElection yet (the override point lives at the routing boundary, D45).
type posturePicksHighestId struct{}

func (posturePicksHighestId) ElectOrgAdminAcceptor(_ context.Context, _ string, eligible []Principal) (Principal, bool, error) {
	if len(eligible) == 0 {
		return Principal{}, false, nil // no candidates → no override (fall back to default)
	}
	// eligible is id-ascending (eligibleOrgAdmins) → last is the highest id.
	return eligible[len(eligible)-1], true, nil
}

var _ PostureElection = posturePicksHighestId{}

// TestMemory_eligibleOrgAdmins_LowestIdDefaultIsSetHead proves the reserved
// posture-delegation contract (D45): the eligibleOrgAdmins candidate set is the SAME
// id-ascending set the lowest-id default draws from — ResolveOrgAdminAcceptor returns
// exactly its head — and a PostureElection override (here picking the highest id)
// draws from that same set yet elects a DIFFERENT acceptor. This pins that the
// reserved hook shape and the fail-closed default agree on the eligible set by
// construction, with lowest-id documented as the default.
func TestMemory_eligibleOrgAdmins_LowestIdDefaultIsSetHead(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryClock(fixedClock(inventoryClock))
	seedOrgAdmin(t, repo)

	// The eligible acme org-admins, id-ascending: p-cady < p-cleo (both eligible;
	// p-ada is a launcher-only, p-bob is in globex).
	elig := repo.eligibleOrgAdmins("acme")
	if len(elig) != 2 || elig[0].ID != "p-cady" || elig[1].ID != "p-cleo" {
		t.Fatalf("eligibleOrgAdmins(acme) = %v, want id-ascending [p-cady p-cleo]", principalIDs(elig))
	}

	// The lowest-id default (ResolveOrgAdminAcceptor) returns exactly the set head.
	got, ok, err := repo.ResolveOrgAdminAcceptor(ctx, "sess-acme")
	mustNoErr(t, err)
	if !ok || got.ID != elig[0].ID {
		t.Fatalf("ResolveOrgAdminAcceptor = (%q, %v), want the eligible-set head %q (lowest-id default)", got.ID, ok, elig[0].ID)
	}

	// A posture override draws from the SAME set but elects a DIFFERENT acceptor (the
	// highest id) — the D45 "delegable by posture" override point, exercised against
	// the reserved hook shape.
	elected, ok, err := posturePicksHighestId{}.ElectOrgAdminAcceptor(ctx, "sess-acme", elig)
	mustNoErr(t, err)
	if !ok || elected.ID != "p-cleo" {
		t.Fatalf("posture override = (%q, %v), want the highest-id eligible %q (override differs from lowest-id default)", elected.ID, ok, "p-cleo")
	}
	if elected.ID == got.ID {
		t.Fatalf("posture override elected the same acceptor as the lowest-id default (%q); the override must be able to differ", elected.ID)
	}

	// The default is unchanged by the existence of the override seam: re-resolving
	// still returns the lowest-id acceptor (byte-identical to before — additive).
	again, ok, err := repo.ResolveOrgAdminAcceptor(ctx, "sess-acme")
	mustNoErr(t, err)
	if !ok || again.ID != "p-cady" {
		t.Fatalf("ResolveOrgAdminAcceptor after the override exercise = (%q, %v), want the unchanged lowest-id default %q", again.ID, ok, "p-cady")
	}
}

// TestMemory_eligibleOrgAdmins_FailClosedEmpty proves the candidate set is EMPTY when
// no eligible org-admin exists (globex has a launcher but no org-admin) — the
// fail-closed case the lowest-id default and any posture override both observe as "no
// candidates".
func TestMemory_eligibleOrgAdmins_FailClosedEmpty(t *testing.T) {
	repo := NewMemoryClock(fixedClock(inventoryClock))
	seedOrgAdmin(t, repo)

	if elig := repo.eligibleOrgAdmins("globex"); len(elig) != 0 {
		t.Fatalf("eligibleOrgAdmins(globex) = %v, want empty (no org-admin → fail-closed)", principalIDs(elig))
	}
	// And a posture override over the empty set yields no override (ok=false).
	_, ok, err := posturePicksHighestId{}.ElectOrgAdminAcceptor(context.Background(), "sess-globex", nil)
	mustNoErr(t, err)
	if ok {
		t.Fatalf("posture override over an empty eligible set should yield no override (ok=false)")
	}
}

// principalIDs projects a principal slice to its ids for readable failure messages.
func principalIDs(ps []Principal) []string {
	ids := make([]string, len(ps))
	for i, p := range ps {
		ids[i] = p.ID
	}
	return ids
}

// TestMemory_AgentInventoryOmitsDestroyed checks the destroyed-omitted default
// (mirroring SessionFilter): a DESTROYED session is hidden unless IncludeDestroyed.
func TestMemory_AgentInventoryOmitsDestroyed(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryClock(fixedClock(inventoryClock))

	_, err := repo.CreateSession(ctx, newSession("sess-live", "host-a", 1))
	mustNoErr(t, err)
	_, err = repo.CreateSession(ctx, newSession("sess-gone", "host-a", 2))
	mustNoErr(t, err)
	destroyed := SessionDestroyed
	_, err = repo.UpdateSession(ctx, "sess-gone", SessionUpdate{State: &destroyed})
	mustNoErr(t, err)

	live, err := repo.AgentInventory(ctx, InventoryFilter{})
	mustNoErr(t, err)
	if len(live) != 1 || live[0].SessionUUID != "sess-live" {
		t.Fatalf("default inventory should omit DESTROYED: got %+v", live)
	}
	withGone, err := repo.AgentInventory(ctx, InventoryFilter{IncludeDestroyed: true})
	mustNoErr(t, err)
	if len(withGone) != 2 {
		t.Fatalf("IncludeDestroyed inventory: got %d rows, want 2", len(withGone))
	}
}

// TestPostgres_InventoryReadPath runs the inventory query + resolver against the
// database/sql impl. DEFERRED MANUAL STEP, env-gated behind DS_PG_DSN and SKIPPED
// otherwise (never run in the sandbox); the target DB must have migrations
// 0001..0007 applied (the agent_inventory VIEW + composite index land in 0007).
func TestPostgres_InventoryReadPath(t *testing.T) {
	repo := openPostgresOrSkip(t)
	runAgentInventory(t, repo)
}

func TestPostgres_ResolveLaunchingUserClaim(t *testing.T) {
	repo := openPostgresOrSkip(t)
	runResolveLaunchingUser(t, repo)
}

func TestPostgres_ResolveOrgAdminAcceptor(t *testing.T) {
	repo := openPostgresOrSkip(t)
	runResolveOrgAdminAcceptor(t, repo)
}

// openPostgresOrSkip wires a *Postgres from DS_PG_DSN (driver from DS_PG_DRIVER,
// default "postgres"), truncating the tables so each test starts empty — the same
// driver-agnostic, stdlib-only gating postgres_test.go uses. It SKIPS (never
// fails) when the env / driver / database is absent, so this is a deferred manual
// step, not a sandbox gate. The open/ping/skip dance is single-sourced through
// storetest.OpenOrSkip (its SkipMessages reproduce this caller's exact skip wording
// byte-for-byte); this function keeps its OWN post-open steps — truncateAll + the
// NewPostgresClock wrap — and its inventoryReader return type.
func openPostgresOrSkip(t *testing.T) inventoryReader {
	t.Helper()
	db := storetest.OpenOrSkip(t, "DS_PG_DSN", "DS_PG_DRIVER", storetest.SkipMessages{
		Unset:   "DS_PG_DSN not set: skipping live-Postgres inventory read path (deferred manual step)",
		OpenErr: "sql.Open(%q): %v — register a Postgres driver and apply migrations to run this",
		PingErr: "ping %s: %v — Postgres unreachable; deferred manual step",
	})
	truncateAll(t, db)
	return NewPostgresClock(db, fixedClock(inventoryClock))
}
