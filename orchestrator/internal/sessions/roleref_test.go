package sessions

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// roleResolverFake is a synthetic RoleResolver: it scripts a per-ref resolution
// (or ok=false / error), plus the recorded default, so the steps-1–2 stage's
// outcomes — resolved / unknown / schema-invalid / fault / default / unratified-
// widening — are driven without a catalog. It records the refs it was asked to
// resolve so the test can assert the stage consulted the catalog.
type roleResolverFake struct {
	byRef       map[string]RoleResolution // ref -> resolution (presence => ok=true)
	resolveErr  error                     // a catalog read fault on Resolve
	dflt        RoleResolution            // the recorded default
	defaultErr  error                     // a fault on Default
	resolveSeen []string
}

func (f *roleResolverFake) Resolve(_ context.Context, ref string) (RoleResolution, bool, error) {
	f.resolveSeen = append(f.resolveSeen, ref)
	if f.resolveErr != nil {
		return RoleResolution{}, false, f.resolveErr
	}
	res, ok := f.byRef[ref]
	return res, ok, nil
}

func (f *roleResolverFake) Default(_ context.Context) (RoleResolution, error) {
	if f.defaultErr != nil {
		return RoleResolution{}, f.defaultErr
	}
	return f.dflt, nil
}

func recordedDefault() RoleResolution {
	return RoleResolution{
		Name:              "default",
		Version:           "2026.06.11-v1",
		ContentHash:       "sha256:default-v0-marker",
		WideningsRatified: true,
	}
}

// TestResolveAndPinRole_AbsentRecordsDefaultExplicitly proves the pin-and-audit row
// (doc 18 §7/§11): an ABSENT role_ref records `default@<current>` EXPLICITLY — never
// null, never the empty ref. "No role" and "default role" are the same auditable
// fact: the pin carries the full default triple and Ref() is `default@2026.06.11-v1`.
func TestResolveAndPinRole_AbsentRecordsDefaultExplicitly(t *testing.T) {
	f := &roleResolverFake{dflt: recordedDefault()}
	pin, err := ResolveAndPinRole(context.Background(), f, "", nil)
	if err != nil {
		t.Fatalf("ResolveAndPinRole(absent): unexpected error: %v", err)
	}
	if pin.Name != "default" || pin.Version != "2026.06.11-v1" {
		t.Errorf("absent role_ref must pin the recorded default explicitly, got %+v", pin)
	}
	if pin.ContentHash == "" {
		t.Error("absent role_ref must record a content hash (recorded, not null)")
	}
	if pin.Ref() != "default@2026.06.11-v1" {
		t.Errorf("Ref() = %q, want explicit default@<current>, never empty", pin.Ref())
	}
	// An absent ref must NOT have been routed through Resolve — it goes through Default.
	if len(f.resolveSeen) != 0 {
		t.Errorf("absent role_ref must resolve via Default, not Resolve; Resolve saw %v", f.resolveSeen)
	}
}

// TestResolveAndPinRole_ResolvedPinsTriple proves a known ref pins its full
// (name, version, content_hash) triple (the pin-and-audit row) and that the stage
// consulted the catalog with the verbatim ref.
func TestResolveAndPinRole_ResolvedPinsTriple(t *testing.T) {
	f := &roleResolverFake{
		byRef: map[string]RoleResolution{
			"developer@2026.06.11-v1": {
				Name: "developer", Version: "2026.06.11-v1", ContentHash: "sha256:dev-abc",
				WideningsRatified: true,
			},
		},
		dflt: recordedDefault(),
	}
	pin, err := ResolveAndPinRole(context.Background(), f, "developer@2026.06.11-v1", nil)
	if err != nil {
		t.Fatalf("ResolveAndPinRole(developer): %v", err)
	}
	if pin.Name != "developer" || pin.Version != "2026.06.11-v1" || pin.ContentHash != "sha256:dev-abc" {
		t.Errorf("pinned triple = %+v, want developer/2026.06.11-v1/sha256:dev-abc", pin)
	}
	if len(f.resolveSeen) != 1 || f.resolveSeen[0] != "developer@2026.06.11-v1" {
		t.Errorf("stage must consult the catalog with the verbatim ref, saw %v", f.resolveSeen)
	}
	if len(pin.InertWidenings) != 0 {
		t.Errorf("developer requests no widening, want no inert widenings, got %v", pin.InertWidenings)
	}
}

// TestResolveAndPinRole_UnknownRefusesFailClosed proves the §4.1 steps-1–2
// structural refusal (doc 18 §6 row "1–2"): an UNKNOWN/unresolvable ref refuses the
// create FAIL-CLOSED with ErrRoleRefRefused — the D56 two-key posture, attributable
// to the bad ref. No pin is returned.
func TestResolveAndPinRole_UnknownRefusesFailClosed(t *testing.T) {
	f := &roleResolverFake{byRef: map[string]RoleResolution{}, dflt: recordedDefault()}
	pin, err := ResolveAndPinRole(context.Background(), f, "ghost@9", nil)
	if !errors.Is(err, ErrRoleRefRefused) {
		t.Fatalf("unknown ref error = %v, want ErrRoleRefRefused (fail-closed structural refusal)", err)
	}
	if pin.Name != "" {
		t.Errorf("a refused create must return no pin, got %+v", pin)
	}
	if !ErrIsRoleRefused(err) {
		t.Error("ErrIsRoleRefused must classify the refusal")
	}
}

// TestResolveAndPinRole_SchemaInvalidRefusesFailClosed proves a resolver that
// "resolved" a ref to an INCOMPLETE pin (missing version/content_hash — a
// schema-invalid catalog entry) is refused fail-closed, not carried as a silently
// empty pin. The pin-and-audit row requires a complete triple.
func TestResolveAndPinRole_SchemaInvalidRefusesFailClosed(t *testing.T) {
	f := &roleResolverFake{
		byRef: map[string]RoleResolution{
			// ok=true but no content hash — schema-invalid.
			"broken@1": {Name: "broken", Version: "1"},
		},
		dflt: recordedDefault(),
	}
	_, err := ResolveAndPinRole(context.Background(), f, "broken@1", nil)
	if !errors.Is(err, ErrRoleRefRefused) {
		t.Fatalf("schema-invalid resolution error = %v, want ErrRoleRefRefused", err)
	}
}

// TestResolveAndPinRole_UnratifiedWideningsRideInert proves the widening-gate row
// (doc 18 §9/§11, D91): a role whose widenings are UNRATIFIED is NOT a refusal — the
// create PROCEEDS, the widenings ride INERT on the pin (admitting nothing), and a
// warning is LOGGED (the doc 13 §1 rule-7 pattern). This is the researcher-role
// worked example (a requested-but-inert wider read-only web envelope).
func TestResolveAndPinRole_UnratifiedWideningsRideInert(t *testing.T) {
	f := &roleResolverFake{
		byRef: map[string]RoleResolution{
			"researcher@2026.06.11-v1": {
				Name: "researcher", Version: "2026.06.11-v1", ContentHash: "sha256:res-xyz",
				Widenings:         []string{"en.wikipedia.org:443", "arxiv.org:443"},
				WideningsRatified: false,
			},
		},
		dflt: recordedDefault(),
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	pin, err := ResolveAndPinRole(context.Background(), f, "researcher@2026.06.11-v1", logger)
	if err != nil {
		t.Fatalf("unratified widenings must NOT refuse the create, got error: %v", err)
	}
	if pin.Name != "researcher" || pin.ContentHash != "sha256:res-xyz" {
		t.Errorf("researcher pin = %+v, want the resolved triple", pin)
	}
	if pin.WideningsRatified {
		t.Error("WideningsRatified = true, want false (the widenings are inert)")
	}
	if len(pin.InertWidenings) != 2 {
		t.Fatalf("InertWidenings = %v, want both widenings recorded inert", pin.InertWidenings)
	}
	// The widening-gate row REQUIRES a logged warning (admitting nothing).
	logged := buf.String()
	if !strings.Contains(logged, "unratified widenings") {
		t.Errorf("widening-gate must emit a logged warning, log was: %q", logged)
	}
	if !strings.Contains(logged, "level=WARN") {
		t.Errorf("widening-gate warning must be at WARN level, log was: %q", logged)
	}
}

// TestResolveAndPinRole_RatifiedWideningsNotInert proves the post-ratification side
// of the widening-gate row: once a role's widenings are org-ratified, they are NOT
// recorded inert and NO warning is logged — the widening now admits (enforced
// downstream; this stage just carries the ratified posture).
func TestResolveAndPinRole_RatifiedWideningsNotInert(t *testing.T) {
	f := &roleResolverFake{
		byRef: map[string]RoleResolution{
			"researcher@2026.06.11-v1": {
				Name: "researcher", Version: "2026.06.11-v1", ContentHash: "sha256:res-xyz",
				Widenings:         []string{"en.wikipedia.org:443"},
				WideningsRatified: true,
			},
		},
		dflt: recordedDefault(),
	}
	var buf bytes.Buffer
	pin, err := ResolveAndPinRole(context.Background(), f, "researcher@2026.06.11-v1", slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatalf("ratified widenings: %v", err)
	}
	if !pin.WideningsRatified {
		t.Error("WideningsRatified = false, want true")
	}
	if len(pin.InertWidenings) != 0 {
		t.Errorf("ratified widenings must NOT ride inert, got %v", pin.InertWidenings)
	}
	if strings.Contains(buf.String(), "unratified") {
		t.Errorf("ratified widenings must not log the inert-widening warning, log: %q", buf.String())
	}
}

// TestResolveAndPinRole_ResolverFaultSurfacedNotRefusal proves a catalog READ FAULT
// is surfaced verbatim (NOT ErrRoleRefRefused) — a transient the §4.1 rollback note
// covers, attributably distinct from a bad ref (a refusal). The create driver must
// be able to tell "catalog unreachable, stall/retry" from "bad ref, refuse".
func TestResolveAndPinRole_ResolverFaultSurfacedNotRefusal(t *testing.T) {
	catalogDown := errors.New("catalog: connection refused")
	f := &roleResolverFake{resolveErr: catalogDown, dflt: recordedDefault()}
	_, err := ResolveAndPinRole(context.Background(), f, "developer@1", nil)
	if err == nil {
		t.Fatal("a catalog fault must surface an error")
	}
	if errors.Is(err, ErrRoleRefRefused) {
		t.Errorf("a catalog fault must NOT be a structural refusal, got %v", err)
	}
	if !errors.Is(err, catalogDown) {
		t.Errorf("the catalog fault must be surfaced verbatim, got %v", err)
	}
}

// TestResolveAndPinRole_NilResolverFailsClosed proves the stage fails closed when no
// resolver is configured (a misconfiguration, not a refusal of a specific ref).
func TestResolveAndPinRole_NilResolverFailsClosed(t *testing.T) {
	if _, err := ResolveAndPinRole(context.Background(), nil, "developer@1", nil); err == nil {
		t.Fatal("a nil resolver must fail closed")
	}
}

// TestDefaultRoleResolver_DefaultOnlyPosture proves the v0 default-only resolver
// (the orchestrator-side analog of identity/mint's DefaultRoleTemplateResolver):
// it recognizes ONLY the recorded default (Default + Resolve("default")) and reports
// every other ref UNKNOWN (ok=false → the steps-1–2 structural refusal). doc 18
// installs the real catalog-backed resolver behind the same seam.
func TestDefaultRoleResolver_DefaultOnlyPosture(t *testing.T) {
	r := DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: "sha256:default-v0-marker"}

	// Default() yields the recorded default, explicitly.
	d, err := r.Default(context.Background())
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if d.Name != "default" || d.Version != "2026.06.11-v1" || d.ContentHash == "" {
		t.Errorf("Default = %+v, want the recorded default triple", d)
	}
	if !d.WideningsRatified || len(d.Widenings) != 0 {
		t.Error("the default role narrows nothing and requests no widening (trivially ratified)")
	}

	// Bare `default` and the recorded `default@<current>` resolve; an explicit
	// historical default version and any other role are UNKNOWN at v0.
	cases := []struct {
		ref     string
		wantOK  bool
		wantVer string
	}{
		{"default", true, "2026.06.11-v1"},
		{"default@2026.06.11-v1", true, "2026.06.11-v1"},
		{"default@2025.01.01-v0", false, ""}, // historical version: real catalog only
		{"developer@1", false, ""},
		{"ghost@9", false, ""},
		{"", false, ""}, // bare empty: the caller routes absent via ResolveAndPinRole → Default
	}
	for _, tc := range cases {
		res, ok, err := r.Resolve(context.Background(), tc.ref)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.ref, err)
		}
		if ok != tc.wantOK {
			t.Errorf("Resolve(%q) ok = %v, want %v", tc.ref, ok, tc.wantOK)
		}
		if ok && res.Version != tc.wantVer {
			t.Errorf("Resolve(%q) version = %q, want %q", tc.ref, res.Version, tc.wantVer)
		}
	}
}

// TestDefaultRoleResolver_WiredThroughResolveAndPin proves the v0 resolver composes
// with the steps-1–2 stage end to end: absent pins default explicitly; an unknown
// ref refuses fail-closed — the two behaviors the acceptance names, against the real
// v0 resolver rather than a fake.
func TestDefaultRoleResolver_WiredThroughResolveAndPin(t *testing.T) {
	r := DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: "sha256:default-v0-marker"}

	pin, err := ResolveAndPinRole(context.Background(), r, "", nil)
	if err != nil {
		t.Fatalf("absent via v0 resolver: %v", err)
	}
	if pin.Ref() != "default@2026.06.11-v1" {
		t.Errorf("absent pin Ref() = %q, want default@2026.06.11-v1", pin.Ref())
	}

	if _, err := ResolveAndPinRole(context.Background(), r, "researcher@1", nil); !errors.Is(err, ErrRoleRefRefused) {
		t.Errorf("unknown ref via v0 resolver = %v, want ErrRoleRefRefused", err)
	}
}

// TestPinnedRole_RefForms pins the recorded-ref forms PinnedRole.Ref() produces:
// name@version for a normal pin, name-only when version is empty, and empty for the
// zero pin (the unresolved sentinel).
func TestPinnedRole_RefForms(t *testing.T) {
	cases := []struct {
		pin  PinnedRole
		want string
	}{
		{PinnedRole{Name: "default", Version: "2026.06.11-v1"}, "default@2026.06.11-v1"},
		{PinnedRole{Name: "catalog-uuid-abc"}, "catalog-uuid-abc"},
		{PinnedRole{}, ""},
	}
	for _, tc := range cases {
		if got := tc.pin.Ref(); got != tc.want {
			t.Errorf("Ref(%+v) = %q, want %q", tc.pin, got, tc.want)
		}
	}
}

// TestSplitRoleRef pins the `<name>@<version>` parse the steps-1–2 stage shares with
// identity/mint's roleNameOf split (one recorded form, parsed the same on both
// sides of the seam).
func TestSplitRoleRef(t *testing.T) {
	cases := []struct {
		ref, name, ver string
	}{
		{"default@2026.06.11-v1", "default", "2026.06.11-v1"},
		{"developer", "developer", ""},
		{"  researcher@2  ", "researcher", "2"},
		{"", "", ""},
		{"catalog-uuid-no-at", "catalog-uuid-no-at", ""},
	}
	for _, tc := range cases {
		n, v := splitRoleRef(tc.ref)
		if n != tc.name || v != tc.ver {
			t.Errorf("splitRoleRef(%q) = (%q,%q), want (%q,%q)", tc.ref, n, v, tc.name, tc.ver)
		}
	}
}
