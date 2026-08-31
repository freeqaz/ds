// SPDX-License-Identifier: Apache-2.0

// The GrantRef cross-module contract — READER side (doc 16 §9 grant-fetch row,
// §5.1) — and the §6.1 composition seam consumed from the grant-service side.
//
// This module is the READER of the grant_ref string: the mint side WROTE it,
// this side keys Service.Fetch on it. The committed golden fixture
// (testdata/grantref-golden.json) is carried IDENTICALLY in both modules; the
// mint side's test pins the WRITER (FormatGrantRef == golden ref), and the test
// below pins the READER (ParseGrantRef(golden ref) == {session, service}). A
// unilateral format change on EITHER side fails THAT side's suite against the
// shared golden, so the drift breaks loudly at test time instead of silently at
// fetch time. Everything synthetic (D50).
package grantservice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// grantRefGolden mirrors the committed golden fixture shape (identical to the
// mint side's loader). This module is the READER side of the seam.
type grantRefGolden struct {
	Format string `json:"format"`
	Cases  []struct {
		Session string `json:"session"`
		Service string `json:"service"`
		Ref     string `json:"ref"`
	} `json:"cases"`
}

func loadGrantRefGolden(t *testing.T) grantRefGolden {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "grantref-golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g grantRefGolden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(g.Cases) == 0 {
		t.Fatal("golden fixture has no cases")
	}
	return g
}

// TestGrantRef_GoldenContract_ReaderSide is the grant-service half of the
// cross-module GrantRef contract (doc 16 §9 grant-fetch row). This side READS the
// grant_ref the mint side wrote; Service.Fetch keys the D39 store lookup on it.
// The committed golden fixture is the contract: if this side changes
// ParseGrantRef/FormatGrantRef unilaterally, the reader no longer parses the
// golden ref back to its session×service and THIS suite fails — the drift breaks
// loudly at test time instead of silently at fetch time. (The mint module carries
// the identical golden and asserts the WRITER half; both must hold to compose.)
func TestGrantRef_GoldenContract_ReaderSide(t *testing.T) {
	g := loadGrantRefGolden(t)
	for _, c := range g.Cases {
		// READER: ParseGrantRef must recover exactly the golden session×service from
		// the golden ref. A unilateral format change here fails this assertion.
		gotSession, gotService, ok := ParseGrantRef(c.Ref)
		if !ok || gotSession != c.Session || gotService != c.Service {
			t.Fatalf("ParseGrantRef(%q) = (%q,%q,%v), want golden (%q,%q,true) (grant-ref format drift breaks the cross-module fetch)",
				c.Ref, gotSession, gotService, ok, c.Session, c.Service)
		}
		// And the round trip is closed: FormatGrantRef (vendored identically to the
		// mint writer) re-emits exactly the golden ref the writer produced.
		if got := FormatGrantRef(c.Session, c.Service); got != c.Ref {
			t.Fatalf("FormatGrantRef(%q,%q) = %q, want golden %q", c.Session, c.Service, got, c.Ref)
		}
		// And the reader-side fetch guard agrees: the golden ref matches its own
		// session×service binding (so a real Fetch for this binding passes the guard).
		if !grantRefMatches(c.Ref, c.Session, c.Service) {
			t.Fatalf("golden ref %q must match its own binding (%q,%q)", c.Ref, c.Session, c.Service)
		}
	}
}

// TestFetch_GrantRefMismatchFailsClosed proves the reader-side fail-closed of the
// §9 GrantRef contract: a grant_ref that does not parse to the (session, service)
// being fetched is a definitive ErrGrantRefMismatch — never a silently-wrong
// store lookup. This is what makes a writer-side format drift loud at the seam.
func TestFetch_GrantRefMismatchFailsClosed(t *testing.T) {
	svc, _, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))

	cases := []struct {
		name         string
		service, ref string
	}{
		{"malformed ref (no separator)", "github", "grant:nope"},
		{"wrong prefix", "github", "notgrant:" + testSession + ":github"},
		{"ref for a different session", "github", FormatGrantRef("other-session", "github")},
		{"ref for a different service", "github", FormatGrantRef(testSession, "npm")},
		{"empty ref", "github", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Fetch(testSession, tc.service, tc.ref, now.Add(time.Hour)); err != ErrGrantRefMismatch {
				t.Fatalf("Fetch with %s must fail ErrGrantRefMismatch, got: %v", tc.name, err)
			}
		})
	}
}

// TestComposition_GrantSetToRegisterSessionToFetch is the grant-service half of
// the doc 16 §6.1 composition seam. The mint module proves
// MintGrants→IssuedDigestTag; this proves the SAME GrantSet drives the
// grant-service side: a session registered (RegisterSession) with the GrantSet's
// session deadline, then Fetch keyed on the GrantSet's grant_ref (the contract
// string the mint side wrote) resolves the credential from the D39 store. The two
// halves compose across the seam BECAUSE both sides key on the same grant_ref
// (FormatGrantRef here equals mint.FormatGrantRef by the identically-vendored
// contract, pinned by the shared golden).
//
// This is the seam + conformance test the production digest producer
// (task 01KTWJ4KSGT58J8RVBF1PGSTFY) builds on — NOT that producer. The GrantSet
// is synthesized here (the grant-service module cannot import mint), modeling the
// exact records MintGrants emits: {session, service, grant_ref, expiry}.
func TestComposition_GrantSetToRegisterSessionToFetch(t *testing.T) {
	// A synthetic GrantSet as MintGrants would emit it: one grant per service,
	// each carrying the contract grant_ref and a TTL. The store holds the real
	// (synthetic, D50) credential under exactly that grant_ref.
	session := "00000000-0000-4000-8000-000000000001"
	type syntheticGrant struct {
		service string
		ref     string
		expiry  time.Time
	}
	clock := fixedClock()
	now := clock()
	sessionDeadline := now.Add(time.Hour)
	grantSet := []syntheticGrant{
		{service: "github", ref: FormatGrantRef(session, "github"), expiry: now.Add(30 * time.Minute)},
		{service: "npm", ref: FormatGrantRef(session, "npm"), expiry: now.Add(30 * time.Minute)},
	}

	store := map[string]Credential{}
	for _, g := range grantSet {
		store[g.ref] = Credential{Secret: []byte("SYNTHETIC-CRED-" + g.service + "-DO-NOT-USE"), Location: "Authorization"}
	}
	svc := New(NewInMemoryBackend(store), WithClock(clock))

	// RegisterSession (the §6.1 hand-off point: the mint sub-sequence hands the
	// session's grant set to the swap path with a session-lifetime deadline).
	svc.RegisterSession(session, sessionDeadline)

	for _, g := range grantSet {
		// Fetch keyed on the GrantSet's grant_ref — the exact string the mint side
		// wrote. The reader-side guard passes precisely because the ref is the
		// contract handle for this session×service.
		cred, err := svc.Fetch(session, g.service, g.ref, g.expiry)
		if err != nil {
			t.Fatalf("composition fetch for %s failed: %v", g.service, err)
		}
		want := "SYNTHETIC-CRED-" + g.service + "-DO-NOT-USE"
		if string(cred.Secret) != want {
			t.Fatalf("composition fetch for %s served %q, want %q", g.service, cred.Secret, want)
		}
		// The §6.1 ISSUED{service_id} digest tag is a GRANT FACT — its service is the
		// grant's service, recoverable from the grant_ref the fetch keyed on. This is
		// the same derivation the mint side proves; here it closes the loop on the
		// reader side (the service the digest names is the service we fetched for).
		_, gotService, ok := ParseGrantRef(g.ref)
		if !ok || gotService != g.service {
			t.Fatalf("grant_ref %q does not carry service %q for the ISSUED tag", g.ref, g.service)
		}
		wantTag := "ISSUED{" + g.service + "}"
		if gotTag := "ISSUED{" + gotService + "}"; gotTag != wantTag {
			t.Fatalf("digest tag derived from grant_ref = %q, want %q", gotTag, wantTag)
		}
	}
}

// TestGrantRecord_FrozenContract pins the RECORD repoint: the grant-service model
// now speaks the frozen dreamserpent.identity.v1.Grant type (grantref.go's
// GrantRecord alias), not just the §9 fetch reply. It proves the record-typed
// derivations — grant_ref key, ISSUED{service_id} digest tag, fail-closed binding
// guard — agree FIELD-FOR-FIELD with the same byte-for-byte string contract the
// golden round-trip pins, so the frozen RECORD is the one grant shape the whole
// module keys on. A drift between the record-typed helpers and the string contract
// (or a unilateral ISSUED-tag change) fails here at test time.
func TestGrantRecord_FrozenContract(t *testing.T) {
	g := loadGrantRefGolden(t)
	for _, c := range g.Cases {
		// A frozen grant RECORD as the mint side mints it: the §5.1 identity × service
		// × scope × TTL shape, carrying the contract grant_ref and the pre-derived
		// ISSUED{service_id} tag. GrantRecord is identityv1.Grant — there is exactly
		// one record shape in the system, the frozen one.
		rec := &GrantRecord{
			Identity:           "spiffe://acme/session/" + c.Session,
			ServiceId:          c.Service,
			Scope:              identityv1.GrantScope_GRANT_SCOPE_SESSION,
			GrantRef:           c.Ref,
			CredClassDigestTag: "ISSUED{" + c.Service + "}",
		}

		// The record's grant_ref IS the D39 store key, and it matches its own binding
		// through the record-typed fail-closed guard (the same guard Fetch keys on,
		// expressed against the frozen record).
		if got := grantRecordRef(rec); got != c.Ref {
			t.Fatalf("grantRecordRef = %q, want golden ref %q", got, c.Ref)
		}
		if !grantRecordMatches(rec, c.Session, c.Service) {
			t.Fatalf("frozen record for (%q,%q) must match its own binding", c.Session, c.Service)
		}

		// The ISSUED{service_id} digest tag DERIVED from the record (ServiceId axis
		// alone) equals the record's own pre-derived field and the string-contract
		// form — the §11.1 step-7 "tag is derived from the grant record" invariant,
		// now on the frozen type.
		gotTag := IssuedDigestTag(rec)
		if gotTag != rec.GetCredClassDigestTag() {
			t.Fatalf("IssuedDigestTag(record) = %q, want record's CredClassDigestTag %q", gotTag, rec.GetCredClassDigestTag())
		}
		if want := "ISSUED{" + c.Service + "}"; gotTag != want {
			t.Fatalf("IssuedDigestTag(record) = %q, want %q", gotTag, want)
		}

		// And the record-keyed Backend adapter resolves the same credential the bare
		// grant_ref does — FetchForGrant is a thin record-shaped entry point over
		// Fetch, never a new fetch path.
		wantSecret := "SYNTHETIC-CRED-" + c.Service + "-DO-NOT-USE"
		be := NewInMemoryBackend(map[string]Credential{
			c.Ref: {Secret: []byte(wantSecret), Location: "Authorization"},
		})
		cred, err := FetchForGrant(be, rec)
		if err != nil {
			t.Fatalf("FetchForGrant(record) failed: %v", err)
		}
		if string(cred.Secret) != wantSecret {
			t.Fatalf("FetchForGrant served %q, want %q", cred.Secret, wantSecret)
		}
		if direct, err := be.Fetch(c.Ref); err != nil || string(direct.Secret) != string(cred.Secret) {
			t.Fatalf("FetchForGrant must equal Fetch(grant_ref): record=%q direct=(%q,%v)", cred.Secret, direct.Secret, err)
		}
	}
}

// TestGrantRecord_FailsClosed pins the fail-closed edges of the record repoint: a
// nil record, a record with no grant_ref, and a record whose grant_ref is for a
// different binding are all definitive non-matches / not-found — never a silently
// wrong store lookup. This is the record-typed mirror of
// TestFetch_GrantRefMismatchFailsClosed.
func TestGrantRecord_FailsClosed(t *testing.T) {
	if IssuedDigestTag(nil) != "ISSUED{}" {
		t.Fatalf("IssuedDigestTag(nil) = %q, want fail-closed empty-service tag ISSUED{}", IssuedDigestTag(nil))
	}
	if grantRecordRef(nil) != "" {
		t.Fatalf("grantRecordRef(nil) = %q, want empty key", grantRecordRef(nil))
	}
	if grantRecordMatches(nil, testSession, testService) {
		t.Fatal("nil record must not match any binding")
	}

	cases := []struct {
		name string
		rec  *GrantRecord
	}{
		{"empty grant_ref", &GrantRecord{ServiceId: testService}},
		{"wrong session", &GrantRecord{ServiceId: testService, GrantRef: FormatGrantRef("other-session", testService)}},
		{"wrong service", &GrantRecord{ServiceId: testService, GrantRef: FormatGrantRef(testSession, "npm")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if grantRecordMatches(tc.rec, testSession, testService) {
				t.Fatalf("record %s must be a definitive non-match for (%q,%q)", tc.name, testSession, testService)
			}
		})
	}

	// A record whose grant_ref is unknown to the store fails closed as not-found
	// (the deny half of the §5.1 split), not a stall.
	be := NewInMemoryBackend(map[string]Credential{})
	if _, err := FetchForGrant(be, &GrantRecord{GrantRef: FormatGrantRef(testSession, testService)}); err != ErrGrantNotFound {
		t.Fatalf("FetchForGrant for an unstored record must be ErrGrantNotFound, got %v", err)
	}
}
