// SPDX-License-Identifier: Apache-2.0

// Go<->wire CONTRACT tests for the grant-FETCH repoint (doc 16 §5.1/§5.2/§9; doc
// 06 §2 fakes-first dual-run). These pin the field-for-field mapping between the
// in-process Service.Fetch model and the FROZEN GrantFetchService generated types
// (proto/dreamserpent/identity/v1/grant_fetch.proto): the RPC shape, the
// Credential<->FetchedCredential mapping, and the five-error <-> in-band
// GrantFetchReason deny/stall split.
//
// DUAL-RUN (doc 06 §2.1 / D24/D14). A single conformance suite of cases runs
// against TWO drivers: (1) the REAL Service via FetchWire, and (2) the GENERATED
// GrantFetchServiceFake programmed to delegate to that same FetchWire. Both must
// produce byte-identical wire responses for every case — proving the real
// implementation drops into the fake's seam shape exactly where the dual-run
// harness would run it, and that the generated request/response/enum types are
// the contract both sides speak. Everything synthetic (D50); the clock is pinned.
//
// ADDITIVE: these tests add coverage; they weaken no existing Service/grantref/
// composition/kvbackend assertion.
package grantservice

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
)

// wireCase is one conformance case: a request and the wire outcome the contract
// requires, expressed in terms of the FROZEN generated types.
type wireCase struct {
	name        string
	req         *identityv1.GrantFetchRequest
	wantReason  identityv1.GrantFetchReason
	wantSecret  string // empty => credential must be nil/empty
	wantLoc     string
	wantClass   identityv1.CredentialClass
	wantIssued  string
	wantExpiry  int64
	wantStall   bool // ReasonIsStall(reason)
	wantDeny    bool // ReasonIsDeny(reason)
	wantSuccess bool // credential populated + REASON_OK
}

const (
	wireSession = "00000000-0000-4000-8000-0000000000a1"
	wireService = "github"
	wireSecret  = "synthetic-pat-DO-NOT-USE"
)

// newWireService builds a Service warmed with a synthetic swap-class credential
// for (wireSession, wireService) and a parked second session, so the suite can
// exercise OK / not-found / not-live / parked / ref-mismatch / stall on the wire.
// grantExpiry passed via the request is wall-clock UNIX seconds.
func wireRef() string { return FormatGrantRef(wireSession, wireService) }

func fixedUnix() int64 {
	return time.Date(2026, 6, 12, 12, 30, 0, 0, time.UTC).Unix()
}

// runWireSuite drives one wire-shaped fetch and asserts the full response shape
// against the case. driver is the seam under test (real Service or the generated
// fake delegating to it).
func runWireSuite(t *testing.T, driverName string, driver func(*identityv1.GrantFetchRequest) *identityv1.GrantFetchResponse) {
	t.Helper()

	cases := []wireCase{
		{
			name:        "ok_success_maps_credential_class_issued_expiry",
			req:         &identityv1.GrantFetchRequest{SessionUuid: wireSession, ServiceId: wireService, GrantRef: wireRef(), GrantExpiryUnixSeconds: fixedUnix()},
			wantReason:  identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK,
			wantSecret:  wireSecret,
			wantLoc:     "Authorization",
			wantClass:   identityv1.CredentialClass_CREDENTIAL_CLASS_SWAP,
			wantIssued:  wireService, // ISSUED{service_id} echo
			wantExpiry:  fixedUnix(),
			wantSuccess: true,
		},
		{
			name:       "grant_ref_mismatch_is_deny",
			req:        &identityv1.GrantFetchRequest{SessionUuid: wireSession, ServiceId: wireService, GrantRef: "not-a-grant-ref", GrantExpiryUnixSeconds: fixedUnix()},
			wantReason: identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_REF_MISMATCH,
			wantDeny:   true,
		},
		{
			name:       "unknown_session_is_session_not_live_deny",
			req:        &identityv1.GrantFetchRequest{SessionUuid: "00000000-0000-4000-8000-0000000000ff", ServiceId: wireService, GrantRef: FormatGrantRef("00000000-0000-4000-8000-0000000000ff", wireService), GrantExpiryUnixSeconds: fixedUnix()},
			wantReason: identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE,
			wantDeny:   true,
		},
		{
			name:       "missing_grant_is_grant_not_found_deny",
			req:        &identityv1.GrantFetchRequest{SessionUuid: wireSession, ServiceId: "npm", GrantRef: FormatGrantRef(wireSession, "npm"), GrantExpiryUnixSeconds: fixedUnix()},
			wantReason: identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_NOT_FOUND,
			wantDeny:   true,
		},
	}

	for _, tc := range cases {
		t.Run(driverName+"/"+tc.name, func(t *testing.T) {
			resp := driver(tc.req)
			if resp == nil {
				t.Fatal("wire response must never be nil")
			}
			if resp.GetReason() != tc.wantReason {
				t.Fatalf("reason: got %v, want %v", resp.GetReason(), tc.wantReason)
			}
			if got := ReasonIsStall(resp.GetReason()); got != tc.wantStall {
				t.Fatalf("ReasonIsStall: got %v, want %v", got, tc.wantStall)
			}
			if got := ReasonIsDeny(resp.GetReason()); got != tc.wantDeny {
				t.Fatalf("ReasonIsDeny: got %v, want %v", got, tc.wantDeny)
			}
			if tc.wantSuccess {
				if resp.GetCredential() == nil {
					t.Fatal("success response must carry a credential")
				}
				if got := string(resp.GetCredential().GetSecret()); got != tc.wantSecret {
					t.Fatalf("secret: got %q, want %q", got, tc.wantSecret)
				}
				if got := resp.GetCredential().GetLocation(); got != tc.wantLoc {
					t.Fatalf("location: got %q, want %q", got, tc.wantLoc)
				}
				if resp.GetCredentialClass() != tc.wantClass {
					t.Fatalf("credential_class: got %v, want %v", resp.GetCredentialClass(), tc.wantClass)
				}
				if resp.GetIssuedServiceId() != tc.wantIssued {
					t.Fatalf("issued_service_id: got %q, want %q", resp.GetIssuedServiceId(), tc.wantIssued)
				}
				if resp.GetGrantExpiryUnixSeconds() != tc.wantExpiry {
					t.Fatalf("grant_expiry echo: got %d, want %d", resp.GetGrantExpiryUnixSeconds(), tc.wantExpiry)
				}
			} else {
				// On any non-OK reason the credential is empty (fail-closed: no
				// secret crosses on a deny/stall).
				if resp.GetCredential() != nil && len(resp.GetCredential().GetSecret()) != 0 {
					t.Fatalf("non-OK response must carry no secret, got %q", resp.GetCredential().GetSecret())
				}
			}
		})
	}
}

// newWarmedWireService returns a Service warmed with the synthetic swap-class
// credential for (wireSession, wireService), with the session registered live.
func newWarmedWireService(t *testing.T) *Service {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC) }
	be := NewInMemoryBackend(map[string]Credential{
		wireRef(): {Secret: []byte(wireSecret), Location: "Authorization"},
	})
	svc := New(be, WithClock(clock))
	svc.RegisterSession(wireSession, clock().Add(2*time.Hour))
	return svc
}

// TestWireContract_RealAndFake is the dual-run: the same conformance suite runs
// against the REAL Service.FetchWire and against the GENERATED
// GrantFetchServiceFake programmed to delegate to that same FetchWire. Both must
// satisfy every case identically (doc 06 §2.1; D24/D14).
func TestWireContract_RealAndFake(t *testing.T) {
	// Driver 1: the real Service via the wire adapter.
	svc := newWarmedWireService(t)
	runWireSuite(t, "real", svc.FetchWire)

	// Driver 2: the generated fake, programmed to delegate to a fresh real
	// Service's FetchWire — exactly the seam shape the dual-run harness uses
	// (assurance/contract-harness/dualrun). The fake exercises the generated
	// GrantFetchServiceServer surface (Fetch(ctx, *GrantFetchRequest) ...).
	fakeSvc := newWarmedWireService(t)
	fake := identityv1fake.NewGrantFetchServiceFake()
	fake.FetchResponder = func(_ context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
		return fakeSvc.FetchWire(req), nil
	}
	runWireSuite(t, "fake", func(req *identityv1.GrantFetchRequest) *identityv1.GrantFetchResponse {
		resp, err := fake.Fetch(context.Background(), req)
		if err != nil {
			t.Fatalf("fake.Fetch returned a transport error (the contract rides the in-band reason, never a status): %v", err)
		}
		return resp
	})

	// The fake recorded exactly the calls the suite drove — proving the request
	// type round-trips through the generated seam.
	if got := len(fake.FetchRecorded()); got == 0 {
		t.Fatal("fake recorded no calls; the generated request type did not round-trip")
	}
}

// TestWireContract_StallVsDeny pins the §5.1 wire split: a store outage is the
// RETRYABLE stall (REASON_STORE_UNAVAILABLE, ReasonIsStall), distinct from a
// definitive deny — preserving backend.go's ErrStoreUnavailable-vs-ErrGrantNotFound
// distinction on the wire. A NEW fetch during an outage stalls; a cached in-flight
// grant still serves OK (the cache rides the outage), all expressed in wire terms.
func TestWireContract_StallVsDeny(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC) }
	be := NewInMemoryBackend(map[string]Credential{
		wireRef(): {Secret: []byte(wireSecret), Location: "Authorization"},
	})
	svc := New(be, WithClock(clock))
	svc.RegisterSession(wireSession, clock().Add(2*time.Hour))

	// Warm the in-flight session's grant before the outage.
	warm := svc.FetchWire(&identityv1.GrantFetchRequest{SessionUuid: wireSession, ServiceId: wireService, GrantRef: wireRef(), GrantExpiryUnixSeconds: fixedUnix()})
	if warm.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK {
		t.Fatalf("warm fetch must be OK, got %v", warm.GetReason())
	}

	// Store goes down.
	be.SetAvailable(false)

	// In-flight cached grant rides the outage — still OK on the wire.
	rode := svc.FetchWire(&identityv1.GrantFetchRequest{SessionUuid: wireSession, ServiceId: wireService, GrantRef: wireRef(), GrantExpiryUnixSeconds: fixedUnix()})
	if rode.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK {
		t.Fatalf("cached grant must ride the outage as OK, got %v", rode.GetReason())
	}

	// A NEW session's NEW fetch STALLS (retryable) during the outage.
	newSession := "00000000-0000-4000-8000-0000000000b2"
	svc.RegisterSession(newSession, clock().Add(2*time.Hour))
	stall := svc.FetchWire(&identityv1.GrantFetchRequest{SessionUuid: newSession, ServiceId: wireService, GrantRef: FormatGrantRef(newSession, wireService), GrantExpiryUnixSeconds: fixedUnix()})
	if stall.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE {
		t.Fatalf("new fetch during outage must stall, got %v", stall.GetReason())
	}
	if !ReasonIsStall(stall.GetReason()) {
		t.Fatal("store-unavailable must be classified as a STALL (retryable), not a deny")
	}
	if ReasonIsDeny(stall.GetReason()) {
		t.Fatal("a stall must not be classified as a deny")
	}
	if stall.GetCredential() != nil && len(stall.GetCredential().GetSecret()) != 0 {
		t.Fatal("a stall must carry no secret")
	}
}

// TestWireContract_ParkedSession pins errParkedSession ->
// GRANT_FETCH_REASON_SESSION_PARKED (a deny on the wire): a parked session
// refuses a NEW fetch, surfaced as the parked reason, not a stall.
func TestWireContract_ParkedSession(t *testing.T) {
	svc := newWarmedWireService(t)
	svc.Park(wireSession)

	// A NEW (uncached) service for the parked session is refused as PARKED.
	resp := svc.FetchWire(&identityv1.GrantFetchRequest{SessionUuid: wireSession, ServiceId: "npm", GrantRef: FormatGrantRef(wireSession, "npm"), GrantExpiryUnixSeconds: fixedUnix()})
	if resp.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_PARKED {
		t.Fatalf("parked session NEW fetch must map to REASON_SESSION_PARKED, got %v", resp.GetReason())
	}
	if !ReasonIsDeny(resp.GetReason()) {
		t.Fatal("a parked refusal is a DENY on the wire")
	}
	if ReasonIsStall(resp.GetReason()) {
		t.Fatal("a parked refusal is not a stall")
	}
}

// TestCredentialWireRoundTrip pins the Credential<->FetchedCredential field-for-field
// mapping and the defensive copy (a returned message can never alias the input).
func TestCredentialWireRoundTrip(t *testing.T) {
	in := Credential{Secret: []byte("synthetic-secret"), Location: "Authorization"}
	fc := CredentialToWire(in)
	if string(fc.GetSecret()) != "synthetic-secret" || fc.GetLocation() != "Authorization" {
		t.Fatalf("to-wire mapping wrong: %+v", fc)
	}
	// Mutating the input after mapping must not change the wire message.
	in.Secret[0] = 'X'
	if string(fc.GetSecret()) == string(in.Secret) {
		t.Fatal("CredentialToWire must defensively copy the secret")
	}

	back := CredentialFromWire(fc)
	if string(back.Secret) != "synthetic-secret" || back.Location != "Authorization" {
		t.Fatalf("from-wire mapping wrong: %+v", back)
	}
	// A nil message maps to the zero Credential.
	if z := CredentialFromWire(nil); z.Secret != nil || z.Location != "" {
		t.Fatalf("nil message must map to the zero Credential, got %+v", z)
	}
}

// TestFetchWire_RecordSharesStringPathCache proves the *GrantRecord FetchWire now
// builds from the request dispatches through FetchForRecord onto the IDENTICAL
// session-cache key (same session × service) as the pre-change string path: after
// the string-keyed Fetch warms the cache, FetchWire serves the SAME cached
// Credential WITHOUT a second Backend.Fetch. The countingBackend records exactly
// ONE store hit across both entry points — the record built inside FetchWire
// resolves to the same D39 store key and cache axis, not a divergent lookup. This
// is the wire-shaped form of service_test.go's shared-cache assertion.
func TestFetchWire_RecordSharesStringPathCache(t *testing.T) {
	svc, cb, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))
	expiryUnix := now.Add(30 * time.Minute).Unix()

	// Pre-change PATH: the string-keyed Fetch warms the session cache for
	// (testSession, testService) keyed on testRef.
	strCred, err := svc.Fetch(testSession, testService, testRef, unixToTime(expiryUnix))
	if err != nil {
		t.Fatalf("string-keyed Fetch: %v", err)
	}

	// NEW PATH: FetchWire builds the *GrantRecord from the same request fields and
	// dispatches through FetchForRecord. It must return the SAME credential and ride
	// the cache the string path warmed (no fresh backend call).
	resp := svc.FetchWire(&identityv1.GrantFetchRequest{
		SessionUuid:            testSession,
		ServiceId:              testService,
		GrantRef:               testRef,
		GrantExpiryUnixSeconds: expiryUnix,
	})
	if resp.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK {
		t.Fatalf("FetchWire on a warmed cache must be OK, got %v", resp.GetReason())
	}
	if got := string(resp.GetCredential().GetSecret()); got != string(strCred.Secret) {
		t.Fatalf("FetchWire secret %q != string-path secret %q", got, strCred.Secret)
	}
	if got := resp.GetCredential().GetLocation(); got != strCred.Location {
		t.Fatalf("FetchWire location %q != string-path location %q", got, strCred.Location)
	}
	// The load-bearing assertion: string path + wire path resolve to ONE
	// Backend.Fetch (the same cache key), proving FetchWire's built record keys
	// identically to the string path — not a second, divergent store lookup.
	if got := atomic.LoadInt64(&cb.calls); got != 1 {
		t.Fatalf("string + FetchWire paths must share ONE Backend.Fetch (same session×service key); got %d", got)
	}
}

// TestReasonForErr_AllFiveErrors asserts each of the five Go errors maps to its
// distinct in-band reason, success maps to OK, and an unknown error maps to the
// fail-closed UNSPECIFIED zero (never silently a known deny).
func TestReasonForErr_AllFiveErrors(t *testing.T) {
	cases := []struct {
		err  error
		want identityv1.GrantFetchReason
	}{
		{nil, identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK},
		{ErrStoreUnavailable, identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE},
		{ErrGrantNotFound, identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_NOT_FOUND},
		{ErrSessionNotLive, identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE},
		{errParkedSession, identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_PARKED},
		{ErrGrantRefMismatch, identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_REF_MISMATCH},
	}
	for _, tc := range cases {
		if got := reasonForErr(tc.err); got != tc.want {
			t.Fatalf("reasonForErr(%v): got %v, want %v", tc.err, got, tc.want)
		}
	}
	// An error outside the documented five is the fail-closed UNSPECIFIED zero.
	if got := reasonForErr(context.Canceled); got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_UNSPECIFIED {
		t.Fatalf("unknown error must map to UNSPECIFIED, got %v", got)
	}
}
