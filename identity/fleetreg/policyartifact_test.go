// SPDX-License-Identifier: Apache-2.0

package fleetreg

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/identity/digest"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// ----- test doubles --------------------------------------------------------

// memSource is an in-memory DigestSource over a flat synthetic tree (D50).
type memSource struct {
	secrets map[string][]byte // canonical "mount/path" → synthetic plaintext
}

func (s *memSource) ListLeaves(_ context.Context, mount, prefix string) ([]string, error) {
	want := canonPath(mount, prefix)
	var out []string
	for full := range s.secrets {
		if full == want || prefixContains(want, full) {
			out = append(out, trimMount(mount, full))
		}
	}
	return out, nil
}

func (s *memSource) ReadSecret(_ context.Context, mount, path string) ([]byte, error) {
	pt, ok := s.secrets[canonPath(mount, path)]
	if !ok {
		return nil, errors.New("memSource: no secret at " + canonPath(mount, path))
	}
	return pt, nil
}

func trimMount(mount, full string) string {
	m := canonPath(mount, "")
	if full == m {
		return ""
	}
	return full[len(m)+1:]
}

// spySink records every appended fleet artifact — the assurance anchor for
// "register/revoke ride the policy_log artifact shape". It assigns monotonic
// seqs and commits unless failNext is set (fail-closed leg).
type spySink struct {
	appends  []digest.FleetPolicyArtifact
	seq      uint64
	failNext bool
}

func (s *spySink) AppendFleetDigest(_ context.Context, art digest.FleetPolicyArtifact) (digest.FleetPolicyResult, error) {
	s.appends = append(s.appends, art)
	if s.failNext {
		s.failNext = false
		return digest.FleetPolicyResult{KeyID: art.KeyID, BatchID: art.BatchID, Committed: false}, nil
	}
	s.seq++
	return digest.FleetPolicyResult{Seq: s.seq, Committed: true, KeyID: art.KeyID, BatchID: art.BatchID}, nil
}

func newTestManager(t *testing.T, src DigestSource, sink digest.PolicySink) *Manager {
	t.Helper()
	prod, err := digest.NewProducer("test-epoch", []byte("ds-synth-test-hmac-key"), 0)
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	m, err := NewManager(Config{Producer: prod, Source: src, Sink: sink})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

var (
	orgAdmin = Principal{Subject: "admin@idp", Roles: []Role{RoleOrgAdmin}}
	devAlice = Principal{Subject: "alice@idp", Roles: []Role{RoleDeveloper}}
)

// ----- tests ---------------------------------------------------------------

// TestNewManagerFailClosed: nil producer/source/sink are rejected.
func TestNewManagerFailClosed(t *testing.T) {
	prod, _ := digest.NewProducer("e", []byte("ds-synth-k"), 0)
	cases := []struct {
		name string
		cfg  Config
	}{
		{"nil producer", Config{Source: &memSource{}, Sink: &spySink{}}},
		{"nil source", Config{Producer: prod, Sink: &spySink{}}},
		{"nil sink", Config{Producer: prod, Source: &memSource{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewManager(tc.cfg); err == nil {
				t.Fatalf("expected fail-closed error for %s", tc.name)
			}
		})
	}
}

// TestDesignatePrefixRidesPolicyLog: designating a prefix digests its leaves and
// rides the policy_log as ONE fleet artifact (the §6.2 artifact shape, D72) — the
// artifact carries the producer's key id, FLEET-scope FORBIDDEN entries, and a
// committed seq.
func TestDesignatePrefixRidesPolicyLog(t *testing.T) {
	src := &memSource{secrets: map[string][]byte{
		"secret/data/dreamserpent/github": []byte("ds-synth-github"),
		"secret/data/dreamserpent/aws":    []byte("ds-synth-aws"),
		"secret/data/teams/ci/deploy":     []byte("ds-synth-ci"), // outside the prefix
	}}
	sink := &spySink{}
	m := newTestManager(t, src, sink)

	res, err := m.DesignatePrefix(context.Background(), orgAdmin,
		Designation{Mount: "secret", Prefix: "data/dreamserpent", Ownership: OwnershipOrg}, "batch-1")
	if err != nil {
		t.Fatalf("DesignatePrefix: %v", err)
	}
	if res.Coverage != CoveragePrefix {
		t.Fatalf("coverage = %v, want prefix", res.Coverage)
	}
	if !res.Fleet.Committed || res.Fleet.Seq == 0 {
		t.Fatalf("expected committed artifact with a seq, got %+v", res.Fleet)
	}
	if len(res.Paths) != 2 {
		t.Fatalf("expected 2 covered leaves (github,aws), got %v", res.Paths)
	}

	// Exactly one policy_log append, carrying the producer key id and only
	// FLEET-scope FORBIDDEN entries (the §6.2 cadence + the §7 keyed-forbidden class).
	if len(sink.appends) != 1 {
		t.Fatalf("expected 1 policy_log append, got %d", len(sink.appends))
	}
	art := sink.appends[0]
	if art.KeyID != "test-epoch" {
		t.Fatalf("artifact key id = %q, want the producer key", art.KeyID)
	}
	if art.BatchID != "batch-1" {
		t.Fatalf("artifact batch id = %q, want batch-1", art.BatchID)
	}
	// 2 creds × 4 variants (RAW/BASE64/URLENC/HEX).
	if len(art.Entries) != 2*4 {
		t.Fatalf("expected 8 digest entries (2 creds × 4 variants), got %d", len(art.Entries))
	}
	for _, e := range art.Entries {
		if e.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_FLEET {
			t.Fatalf("fleet registration emitted a non-FLEET entry: %v", e.GetScope())
		}
		if e.GetCredClass().GetForbidden() == nil {
			t.Fatalf("fleet digest must be FORBIDDEN class (keyed-forbidden, §7)")
		}
		if len(e.GetDigest()) == 0 {
			t.Fatalf("digest entry carries no digest bytes")
		}
	}
}

// TestRegisterSecretRidesPolicyLog: a per-secret escape hatch digests one path as
// one fleet artifact.
func TestRegisterSecretRidesPolicyLog(t *testing.T) {
	src := &memSource{secrets: map[string][]byte{
		"secret/data/teams/ci/deploy": []byte("ds-synth-ci-deploy"),
	}}
	sink := &spySink{}
	m := newTestManager(t, src, sink)

	res, err := m.RegisterSecret(context.Background(), orgAdmin,
		Secret{Mount: "secret", Path: "data/teams/ci/deploy", Ownership: OwnershipOrg}, "batch-esc")
	if err != nil {
		t.Fatalf("RegisterSecret: %v", err)
	}
	if res.Coverage != CoverageEscapeHatch {
		t.Fatalf("coverage = %v, want escape-hatch", res.Coverage)
	}
	if len(sink.appends) != 1 || len(sink.appends[0].Entries) != 4 {
		t.Fatalf("expected 1 append with 4 variant entries, got %d appends", len(sink.appends))
	}
	if !m.Registry().Covers("secret", "data/teams/ci/deploy") {
		t.Fatalf("registered secret should be covered")
	}
}

// TestAuthorityEnforcedAtEntrypoint: an unauthorized actor's registration is
// refused with NOTHING appended to policy_log and NOTHING recorded in the consent
// surface (the fail-closed no-row shape, doc 16 §6.4 / §8.2).
func TestAuthorityEnforcedAtEntrypoint(t *testing.T) {
	src := &memSource{secrets: map[string][]byte{
		"secret/data/org/billing": []byte("ds-synth-billing"),
		"secret/data/alice/token": []byte("ds-synth-alice"),
	}}

	t.Run("developer cannot designate an org prefix", func(t *testing.T) {
		sink := &spySink{}
		m := newTestManager(t, src, sink)
		_, err := m.DesignatePrefix(context.Background(), devAlice,
			Designation{Mount: "secret", Prefix: "data/org", Ownership: OwnershipOrg}, "b")
		if !isUnauthorized(err) {
			t.Fatalf("expected ErrUnauthorized, got %v", err)
		}
		if len(sink.appends) != 0 {
			t.Fatalf("unauthorized registration must append NOTHING; got %d", len(sink.appends))
		}
		if !m.Registry().Empty() {
			t.Fatalf("unauthorized registration must record NOTHING in the consent surface")
		}
	})

	t.Run("developer can register a credential they own", func(t *testing.T) {
		sink := &spySink{}
		m := newTestManager(t, src, sink)
		_, err := m.RegisterSecret(context.Background(), devAlice,
			Secret{Mount: "secret", Path: "data/alice/token", Ownership: OwnershipDeveloper, Owner: "alice@idp"}, "b")
		if err != nil {
			t.Fatalf("owner should be authorized: %v", err)
		}
		if len(sink.appends) != 1 {
			t.Fatalf("authorized registration should append once")
		}
	})

	t.Run("developer cannot register someone else's credential", func(t *testing.T) {
		sink := &spySink{}
		m := newTestManager(t, src, sink)
		_, err := m.RegisterSecret(context.Background(), devAlice,
			Secret{Mount: "secret", Path: "data/org/billing", Ownership: OwnershipDeveloper, Owner: "bob@idp"}, "b")
		if !isUnauthorized(err) {
			t.Fatalf("expected ErrUnauthorized, got %v", err)
		}
		if len(sink.appends) != 0 {
			t.Fatalf("unauthorized registration must append NOTHING")
		}
	})
}

// TestRevokeRidesPolicyLogAndAuthority: revoke retires the entry from the consent
// surface AND appends an empty-entry retire artifact (the §6.2 retire shape); the
// same D84 authority gates it.
func TestRevokeRidesPolicyLog(t *testing.T) {
	src := &memSource{secrets: map[string][]byte{
		"secret/data/dreamserpent/github": []byte("ds-synth-github"),
	}}
	sink := &spySink{}
	m := newTestManager(t, src, sink)

	if _, err := m.DesignatePrefix(context.Background(), orgAdmin,
		Designation{Mount: "secret", Prefix: "data/dreamserpent", Ownership: OwnershipOrg}, "reg"); err != nil {
		t.Fatalf("DesignatePrefix: %v", err)
	}

	// A developer cannot revoke an org designation.
	if _, err := m.Revoke(context.Background(), devAlice, "secret", "data/dreamserpent", "rev"); !isUnauthorized(err) {
		t.Fatalf("developer revoke of org prefix should be unauthorized, got %v", err)
	}
	if m.Registry().Empty() {
		t.Fatalf("an unauthorized revoke must not have removed the designation")
	}

	// Org admin revokes: the designation is removed and a retire artifact is
	// appended (empty entry set under the producer key id, the §6.2 retire shape).
	beforeAppends := len(sink.appends)
	fr, err := m.Revoke(context.Background(), orgAdmin, "secret", "data/dreamserpent", "rev")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !fr.Committed {
		t.Fatalf("revoke artifact should be committed")
	}
	if !m.Registry().Empty() {
		t.Fatalf("authorized revoke must remove the designation (back to default-none)")
	}
	if len(sink.appends) != beforeAppends+1 {
		t.Fatalf("revoke should append exactly one retire artifact")
	}
	retire := sink.appends[len(sink.appends)-1]
	if len(retire.Entries) != 0 {
		t.Fatalf("retire artifact must carry an EMPTY entry set (the §6.2 retire shape), got %d", len(retire.Entries))
	}
	if retire.KeyID != "test-epoch" {
		t.Fatalf("retire must ride the producer key id, got %q", retire.KeyID)
	}

	// Revoking an already-absent target fails (nothing to retire) and appends nothing.
	n := len(sink.appends)
	if _, err := m.Revoke(context.Background(), orgAdmin, "secret", "data/dreamserpent", "rev2"); err == nil {
		t.Fatalf("revoke of an absent target should error")
	}
	if len(sink.appends) != n {
		t.Fatalf("a no-op revoke must append nothing")
	}
}

// TestRevokeIsExactTargetNotPrefixLeaf: a revoke retires a registered UNIT (the
// designated prefix or an exact escape-hatch secret), NOT an arbitrary leaf that
// merely falls under a designated prefix. Revoking a leaf-under-a-prefix must
// fail-closed — refuse, leave the designation intact, and append NOTHING — rather
// than silently no-op the removal yet still emit a host-wide retire artifact.
func TestRevokeIsExactTargetNotPrefixLeaf(t *testing.T) {
	src := &memSource{secrets: map[string][]byte{
		"secret/data/dreamserpent/github": []byte("ds-synth-github"),
	}}
	sink := &spySink{}
	m := newTestManager(t, src, sink)

	if _, err := m.DesignatePrefix(context.Background(), orgAdmin,
		Designation{Mount: "secret", Prefix: "data/dreamserpent", Ownership: OwnershipOrg}, "reg"); err != nil {
		t.Fatalf("DesignatePrefix: %v", err)
	}
	appendsAfterDesignate := len(sink.appends)

	// A leaf UNDER the prefix is read-covered (inheritance) but was never itself
	// registered: revoking it must be refused with nothing removed and nothing
	// appended — otherwise the operator is told a leaf was retired while the
	// designation still re-digests it on the next Sync.
	if _, err := m.Revoke(context.Background(), orgAdmin, "secret", "data/dreamserpent/github", "rev-leaf"); err == nil {
		t.Fatalf("revoking a leaf under a designated prefix must be refused (exact-target only)")
	}
	if !m.Registry().Covers("secret", "data/dreamserpent/github") {
		t.Fatalf("a refused leaf-revoke must leave the designation (and its coverage) intact")
	}
	if len(sink.appends) != appendsAfterDesignate {
		t.Fatalf("a refused leaf-revoke must append NOTHING; got %d new appends", len(sink.appends)-appendsAfterDesignate)
	}

	// Naming the prefix EXACTLY retires it (the operator's explicit decision).
	if _, err := m.Revoke(context.Background(), orgAdmin, "secret", "data/dreamserpent", "rev-prefix"); err != nil {
		t.Fatalf("revoking the exact designated prefix should succeed: %v", err)
	}
	if !m.Registry().Empty() {
		t.Fatalf("revoking the exact prefix must remove the designation")
	}
	if len(sink.appends) != appendsAfterDesignate+1 {
		t.Fatalf("exact-prefix revoke should append exactly one retire artifact")
	}
}

// TestRevokeEscapeHatchWinsOverCoincidentPrefix: when a path is registered as an
// escape-hatch secret AND also equals a designated prefix's canonical key, an
// exact revoke of that path retires the SECRET and leaves the broader designation
// intact (ExactTarget's escape-hatch-wins tie-break).
func TestRevokeEscapeHatchWinsOverCoincidentPrefix(t *testing.T) {
	src := &memSource{secrets: map[string][]byte{
		"secret/data/shared": []byte("ds-synth-shared"),
	}}
	sink := &spySink{}
	m := newTestManager(t, src, sink)

	if _, err := m.DesignatePrefix(context.Background(), orgAdmin,
		Designation{Mount: "secret", Prefix: "data/shared", Ownership: OwnershipOrg}, "reg-prefix"); err != nil {
		t.Fatalf("DesignatePrefix: %v", err)
	}
	if _, err := m.RegisterSecret(context.Background(), orgAdmin,
		Secret{Mount: "secret", Path: "data/shared", Ownership: OwnershipOrg}, "reg-secret"); err != nil {
		t.Fatalf("RegisterSecret: %v", err)
	}

	if _, err := m.Revoke(context.Background(), orgAdmin, "secret", "data/shared", "rev"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// The escape-hatch secret is gone; the designation survives (it still covers
	// the path via the prefix).
	if got := len(m.Registry().Secrets()); got != 0 {
		t.Fatalf("the escape-hatch secret should be retired, got %d secrets", got)
	}
	if got := len(m.Registry().Designations()); got != 1 {
		t.Fatalf("the coincident designation must survive an exact secret-revoke, got %d designations", got)
	}
}

// TestSyncInheritance: a secret newly written under a designated prefix is picked
// up by Sync without re-designation (doc 16 §11.3 step 4) — the inheritance
// mechanism, the property per-secret-only registration cannot give.
func TestSyncInheritance(t *testing.T) {
	src := &memSource{secrets: map[string][]byte{
		"secret/data/dreamserpent/github": []byte("ds-synth-github"),
	}}
	sink := &spySink{}
	m := newTestManager(t, src, sink)

	if _, err := m.DesignatePrefix(context.Background(), orgAdmin,
		Designation{Mount: "secret", Prefix: "data/dreamserpent", Ownership: OwnershipOrg}, "reg"); err != nil {
		t.Fatalf("DesignatePrefix: %v", err)
	}
	// Initial designation digested 1 secret → 4 entries.
	if got := len(sink.appends[0].Entries); got != 4 {
		t.Fatalf("initial designation should digest 1 secret (4 entries), got %d", got)
	}

	// A NEW secret is written under the prefix (the store grows). It was never
	// re-designated, yet Sync covers it — inheritance.
	src.secrets["secret/data/dreamserpent/newly-added"] = []byte("ds-synth-new")

	res, err := m.Sync(context.Background(), "sync-1")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Paths) != 2 {
		t.Fatalf("Sync should now cover 2 secrets (inheritance picked up the new one), got %v", res.Paths)
	}
	last := sink.appends[len(sink.appends)-1]
	if len(last.Entries) != 2*4 {
		t.Fatalf("Sync artifact should carry 2 secrets × 4 variants = 8 entries, got %d", len(last.Entries))
	}
}

// TestSyncDefaultNoneIsNoOp: with nothing designated, Sync publishes nothing and
// is not an error (an unconfigured surface designates nothing, step 1).
func TestSyncDefaultNoneIsNoOp(t *testing.T) {
	sink := &spySink{}
	m := newTestManager(t, &memSource{secrets: map[string][]byte{"secret/data/x": []byte("ds-synth-x")}}, sink)
	res, err := m.Sync(context.Background(), "sync-empty")
	if err != nil {
		t.Fatalf("default-none Sync should not error: %v", err)
	}
	if len(res.Paths) != 0 || len(sink.appends) != 0 {
		t.Fatalf("default-none Sync must publish nothing; paths=%v appends=%d", res.Paths, len(sink.appends))
	}
}

// TestUncommittedAppendFailsClosed: an uncommitted policy-apply surfaces as an
// error (fail-closed) so the security team is not told a registration landed when
// it did not.
func TestUncommittedAppendFailsClosed(t *testing.T) {
	src := &memSource{secrets: map[string][]byte{"secret/data/x": []byte("ds-synth-x")}}
	sink := &spySink{failNext: true}
	m := newTestManager(t, src, sink)
	_, err := m.RegisterSecret(context.Background(), orgAdmin,
		Secret{Mount: "secret", Path: "data/x", Ownership: OwnershipOrg}, "b")
	if err == nil {
		t.Fatalf("an uncommitted policy-apply must surface as an error (fail-closed)")
	}
}

// TestReadScopeBoundToConsent: the Manager never reads plaintext outside the
// consent surface — collectCovered/readOne only touch Covers-approved paths.
// Here a leaf physically present under a prefix that is NOT designated is never
// read by Sync.
func TestReadScopeBoundToConsent(t *testing.T) {
	src := &recordingSource{memSource: memSource{secrets: map[string][]byte{
		"secret/data/designated/a":   []byte("ds-synth-a"),
		"secret/data/undesignated/b": []byte("ds-synth-b"),
	}}}
	sink := &spySink{}
	m := newTestManager(t, src, sink)
	if _, err := m.DesignatePrefix(context.Background(), orgAdmin,
		Designation{Mount: "secret", Prefix: "data/designated", Ownership: OwnershipOrg}, "reg"); err != nil {
		t.Fatalf("DesignatePrefix: %v", err)
	}
	if _, err := m.Sync(context.Background(), "sync"); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	for _, p := range src.read {
		if p == "secret/data/undesignated/b" {
			t.Fatalf("Manager read plaintext outside the consent surface: %s", p)
		}
	}
	if len(src.read) == 0 {
		t.Fatalf("expected the designated leaf to have been read")
	}
}

// recordingSource records which canonical paths ReadSecret touched.
type recordingSource struct {
	memSource
	read []string
}

func (s *recordingSource) ReadSecret(ctx context.Context, mount, path string) ([]byte, error) {
	s.read = append(s.read, canonPath(mount, path))
	return s.memSource.ReadSecret(ctx, mount, path)
}
