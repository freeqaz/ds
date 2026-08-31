package controlplane

// identityseams_test.go exercises the MintClient seam's ADDITIVE mint/CA expiry surface
// (D22/D82; doc 16 §5.4 park/resume — "expired creds re-mint"). The bare MintClient.Mint
// tuple drops the mint-response expiry (token TTL / CA expiry); the seam now carries it
// out as a TYPED field (MintReply.Expiry) so the create coordinator can record it for the
// routable-window + teardown bookkeeping. These tests prove, with SYNTHETIC fixtures (D50
// — no live mint/Identity dial):
//
//   - a mint client that surfaces the expiry (MintExpiryClient) propagates it through the
//     minter adapter onto the typed MintReply (the expiry is no longer dropped at the seam);
//   - the absent-expiry case (a bare MintClient that does NOT surface an expiry) is handled
//     gracefully — MintReply.Expiry is the zero value (not-set), never the epoch;
//   - the change is additive: the existing sessions.MintResult path (Minter.Mint) is
//     unchanged for current callers (IdentityRef/CARef preserved), and a mint fault is
//     surfaced through both the typed and the bare path so the §4.1 step-5 rollback fires.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
)

// fakeMintWithExpiry is a synthetic MintExpiryClient: it returns synthetic identity/CA
// refs AND a mint/CA expiry (the token TTL / CA expiry the bare seam dropped). It is the
// expiry-aware shape the production adapter takes once it reads
// identity.v1 MintInterceptionCAResponse.expiry_unix_seconds (D22/D82).
type fakeMintWithExpiry struct {
	expiry time.Time
	err    error
	calls  int
}

func (m *fakeMintWithExpiry) Mint(_ context.Context, _ sessions.MintWorkloadIdentityClaims, _ string) (string, string, error) {
	m.calls++
	if m.err != nil {
		return "", "", m.err
	}
	return "id-ref-exp", "ca-ref-exp", nil
}

func (m *fakeMintWithExpiry) MintWithExpiry(_ context.Context, _ sessions.MintWorkloadIdentityClaims, _ string) (MintReply, error) {
	m.calls++
	if m.err != nil {
		return MintReply{}, m.err
	}
	return MintReply{IdentityRef: "id-ref-exp", CARef: "ca-ref-exp", Expiry: m.expiry}, nil
}

// fakeMintWithExpiry must be usable wherever a MintClient is, AND surface the expiry
// extension — the additive contract this unit adds.
var (
	_ MintClient       = (*fakeMintWithExpiry)(nil)
	_ MintExpiryClient = (*fakeMintWithExpiry)(nil)
)

// TestMintReply_CarriesExpiryFromExpiryAwareClient proves the seam carries the mint/CA
// expiry OUT of the mint when the client surfaces it (D22/D82): the expiry is no longer
// dropped at the seam, so the routable-window/teardown bookkeeping can record it
// (doc 16 §5.4 — a session whose minted credential expires is torn down / re-minted).
func TestMintReply_CarriesExpiryFromExpiryAwareClient(t *testing.T) {
	want := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	c := &fakeMintWithExpiry{expiry: want}

	reply, err := mintReply(context.Background(), c, sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-exp"}, "role-ref")
	if err != nil {
		t.Fatalf("mintReply: %v", err)
	}
	if reply.IdentityRef != "id-ref-exp" || reply.CARef != "ca-ref-exp" {
		t.Fatalf("mintReply refs = id=%q ca=%q, want id=%q ca=%q",
			reply.IdentityRef, reply.CARef, "id-ref-exp", "ca-ref-exp")
	}
	if reply.Expiry.IsZero() {
		t.Fatal("mintReply dropped the mint/CA expiry: Expiry is the zero value, want it carried from the mint response")
	}
	if !reply.Expiry.Equal(want) {
		t.Errorf("mintReply Expiry = %v, want %v", reply.Expiry, want)
	}
}

// TestMintReply_AbsentExpiryIsZeroValue proves the absent-expiry case is handled
// gracefully: a bare MintClient (no MintExpiryClient extension) yields a MintReply whose
// Expiry is the ZERO value (not-set), never the epoch — the "no TTL bookkeeping for this
// mint" posture (doc 16 §5.4). fakeMint (fixtures_test.go) is the bare seam.
func TestMintReply_AbsentExpiryIsZeroValue(t *testing.T) {
	c := &fakeMint{}

	reply, err := mintReply(context.Background(), c, sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-noexp"}, "")
	if err != nil {
		t.Fatalf("mintReply: %v", err)
	}
	if reply.IdentityRef != "id-ref-1" || reply.CARef != "ca-ref-1" {
		t.Fatalf("mintReply refs = id=%q ca=%q, want id=%q ca=%q",
			reply.IdentityRef, reply.CARef, "id-ref-1", "ca-ref-1")
	}
	if !reply.Expiry.IsZero() {
		t.Errorf("mintReply Expiry = %v, want the zero value for an absent-expiry mint", reply.Expiry)
	}
	// Guard the footgun the doc 16 §5.4 bookkeeping must avoid: not-set must be the zero
	// time, NOT the unix epoch (a zero int64 expiry from a proto-int field misread as a time).
	if reply.Expiry.Equal(time.Unix(0, 0)) {
		t.Error("mintReply mapped an absent expiry onto the unix epoch; want the zero time.Time (not-set)")
	}
}

// TestMinterAdapter_PreservesMintResultAndExposesExpiry proves the WIRED production path
// (minter{c:...}, the adapter wiring.go/redrive.go construct and the create coordinator
// calls via sessions.Minter.Mint) now CARRIES the mint/CA expiry onto sessions.MintResult
// (D22/D82; doc 16 §5.4 — st.mintExpiry / onMintExpiry record the routable-window +
// teardown horizon, "expired creds re-mint"). The carry is ADDITIVE: IdentityRef/CARef are
// preserved for current callers, AND res.Expiry equals the lifted MintReply.Expiry so the
// live mint/CA TTL flows to the coordinator instead of being dropped at the seam. The
// adapter is itself an expiry-aware MintClient whose MintWithExpiry exposes the same expiry.
func TestMinterAdapter_PreservesMintResultAndExposesExpiry(t *testing.T) {
	want := time.Date(2026, 6, 13, 13, 30, 0, 0, time.UTC)
	m := minter{c: &fakeMintWithExpiry{expiry: want}}

	// The wired sessions.Minter path: same refs current callers consume, NOW carrying the
	// mint/CA expiry onto MintResult.Expiry (the dropped-expiry bug this asserts against).
	res, err := m.Mint(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-add"}, "role-ref")
	if err != nil {
		t.Fatalf("minter.Mint: %v", err)
	}
	if res.IdentityRef != "id-ref-exp" || res.CARef != "ca-ref-exp" {
		t.Fatalf("minter.Mint MintResult = id=%q ca=%q, want id=%q ca=%q",
			res.IdentityRef, res.CARef, "id-ref-exp", "ca-ref-exp")
	}
	if res.Expiry.IsZero() {
		t.Fatal("minter.Mint dropped the mint/CA expiry: MintResult.Expiry is the zero value, want it carried from the mint response")
	}
	if !res.Expiry.Equal(want) {
		t.Errorf("minter.Mint MintResult.Expiry = %v, want %v (the lifted MintReply.Expiry)", res.Expiry, want)
	}

	// The additive accessor the follow-up consumer reads: same refs PLUS the expiry.
	reply, err := m.MintWithExpiry(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-add"}, "role-ref")
	if err != nil {
		t.Fatalf("minter.MintWithExpiry: %v", err)
	}
	if reply.IdentityRef != res.IdentityRef || reply.CARef != res.CARef {
		t.Errorf("minter.MintWithExpiry refs = id=%q ca=%q, want they match MintResult id=%q ca=%q",
			reply.IdentityRef, reply.CARef, res.IdentityRef, res.CARef)
	}
	if !reply.Expiry.Equal(want) {
		t.Errorf("minter.MintWithExpiry Expiry = %v, want %v", reply.Expiry, want)
	}
}

// TestMinterAdapter_AbsentExpiryStaysGraceful proves the adapter over a bare MintClient
// surfaces a zero expiry through BOTH the wired sessions.Minter.Mint path (MintResult.Expiry)
// and the additive accessor (the not-set case), so the create coordinator's bookkeeping sees
// "no TTL" — the ZERO time, NEVER a bogus epoch — and schedules no teardown (doc 16 §5.4).
func TestMinterAdapter_AbsentExpiryStaysGraceful(t *testing.T) {
	m := minter{c: &fakeMint{}}

	// The wired path: MintResult.Expiry must be the zero time (not-set), never the epoch,
	// so the coordinator's st.mintExpiry/onMintExpiry gate treats it as "no TTL to track".
	res, err := m.Mint(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-add-noexp"}, "")
	if err != nil {
		t.Fatalf("minter.Mint: %v", err)
	}
	if !res.Expiry.IsZero() {
		t.Errorf("minter.Mint MintResult.Expiry = %v, want the zero time for a bare (no-expiry) mint client", res.Expiry)
	}
	if res.Expiry.Equal(time.Unix(0, 0)) {
		t.Error("minter.Mint mapped an absent expiry onto the unix epoch; want the zero time.Time (not-set)")
	}

	reply, err := m.MintWithExpiry(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-add-noexp"}, "")
	if err != nil {
		t.Fatalf("minter.MintWithExpiry: %v", err)
	}
	if reply.IdentityRef != "id-ref-1" || reply.CARef != "ca-ref-1" {
		t.Fatalf("minter.MintWithExpiry refs = id=%q ca=%q, want id=%q ca=%q",
			reply.IdentityRef, reply.CARef, "id-ref-1", "ca-ref-1")
	}
	if !reply.Expiry.IsZero() {
		t.Errorf("minter.MintWithExpiry Expiry = %v, want zero for a bare (no-expiry) mint client", reply.Expiry)
	}
}

// TestMintReply_SurfacesFault proves a mint fault is surfaced through BOTH the typed
// (expiry-aware) and the bare seam path, so the §4.1 step-5 rollback (identity/CA
// revocation) can compensate — the expiry surface never swallows a mint failure.
func TestMintReply_SurfacesFault(t *testing.T) {
	wantErr := errors.New("mint backend down")

	// Expiry-aware client fault.
	if _, err := mintReply(context.Background(), &fakeMintWithExpiry{err: wantErr},
		sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-fault-exp"}, ""); !errors.Is(err, wantErr) {
		t.Errorf("mintReply (expiry-aware) error = %v, want it to surface %v", err, wantErr)
	}

	// Bare client fault (fallback path).
	if _, err := mintReply(context.Background(), &fakeMint{err: wantErr},
		sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-fault-bare"}, ""); !errors.Is(err, wantErr) {
		t.Errorf("mintReply (bare) error = %v, want it to surface %v", err, wantErr)
	}

	// The minter adapter wraps the fault (so the rollback note can match) on both paths.
	m := minter{c: &fakeMintWithExpiry{err: wantErr}}
	if _, err := m.MintWithExpiry(context.Background(),
		sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-fault-adapter"}, ""); !errors.Is(err, wantErr) {
		t.Errorf("minter.MintWithExpiry error = %v, want it to surface %v", err, wantErr)
	}
}
