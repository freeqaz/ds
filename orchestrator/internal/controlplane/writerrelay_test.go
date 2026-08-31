package controlplane

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// fakeIdentity is a test IdentityAssertionValidator: it accepts a fixed assertion and
// resolves it to a fixed driver identity, refusing anything else.
type fakeIdentity struct {
	wantAssertion string
	driver        string
	err           error
}

func (f fakeIdentity) ValidateAssertion(_ context.Context, _ string, assertion string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	if assertion != f.wantAssertion {
		return "", false, nil
	}
	return f.driver, true, nil
}

// fakeAttachAuth is a test AttachAuthValidator: it accepts a fixed token, refusing
// anything else.
type fakeAttachAuth struct {
	wantToken string
	err       error
}

func (f fakeAttachAuth) ValidateAttachAuth(_ context.Context, _ string, token []byte) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return string(token) == f.wantToken, nil
}

// newRelay builds a WriterRelayService over a seeded memory store + a real Fanout +
// the supplied auth seams. No drive sink is wired (the arbitration tests do not drive);
// the W3 drive tests use newDriveRelay.
func newRelay(t *testing.T, identity IdentityAssertionValidator, attachAuth AttachAuthValidator) (*WriterRelayService, *store.Memory) {
	t.Helper()
	repo := store.NewMemory()
	_, err := repo.CreateSession(context.Background(), store.Session{
		Ref:   store.SessionRef{SessionUUID: "sess-1", HostID: "host-a", HostSessionIndex: 1, TapName: "tap-1"},
		State: store.SessionPending,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	fanout := attach.NewFanout(0)
	arb := attach.NewSeatArbiter(repo, fanout, attach.WithAttendednessProbe(writerSeatAttendedness(repo)))
	return newWriterRelayService(arb, fanout, nil, identity, attachAuth, nil), repo
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("err code = %v (%v), want %v", status.Code(err), err, want)
	}
}

// TestWriterRelay_GrantWithValidAuth proves a request with a valid identity + attach
// auth is granted, attributed to the resolved driver identity (D8/D55), at a non-zero
// granted_seq.
func TestWriterRelay_GrantWithValidAuth(t *testing.T) {
	svc, _ := newRelay(t,
		fakeIdentity{wantAssertion: "sso-token", driver: "alice@org"},
		fakeAttachAuth{wantToken: "attach-tok"},
	)
	resp, err := svc.RequestWriterSeat(context.Background(), &attachv1.RequestWriterSeatRequest{
		SessionUuid:       "sess-1",
		IdentityAssertion: "sso-token",
		AttachAuth:        []byte("attach-tok"),
	})
	if err != nil {
		t.Fatalf("RequestWriterSeat: %v", err)
	}
	g := resp.GetGrant()
	if g.GetDriverIdentity() != "alice@org" {
		t.Fatalf("grant driver = %q, want alice@org (the validated identity, D8/D55)", g.GetDriverIdentity())
	}
	if g.GetWriterSeatId() == "" || g.GetGrantedSeq() == 0 {
		t.Fatalf("grant must carry a seat id + non-zero granted_seq; got %+v", g)
	}
}

// TestWriterRelay_MissingIdentityUnauthenticated proves a request with no/invalid
// identity assertion is refused Unauthenticated (no seat without a valid human
// identity, D22/D55) — even when the attach auth is valid.
func TestWriterRelay_MissingIdentityUnauthenticated(t *testing.T) {
	svc, repo := newRelay(t,
		fakeIdentity{wantAssertion: "sso-token", driver: "alice@org"},
		fakeAttachAuth{wantToken: "attach-tok"},
	)
	// Empty assertion → Unauthenticated.
	_, err := svc.RequestWriterSeat(context.Background(), &attachv1.RequestWriterSeatRequest{
		SessionUuid: "sess-1",
		AttachAuth:  []byte("attach-tok"),
	})
	wantCode(t, err, codes.Unauthenticated)
	// Invalid assertion → Unauthenticated.
	_, err = svc.RequestWriterSeat(context.Background(), &attachv1.RequestWriterSeatRequest{
		SessionUuid:       "sess-1",
		IdentityAssertion: "wrong-token",
		AttachAuth:        []byte("attach-tok"),
	})
	wantCode(t, err, codes.Unauthenticated)
	// No seat was recorded — auth rejection never mutates the record.
	got, _ := repo.GetSession(context.Background(), "sess-1")
	if got.WriterSeat != "" {
		t.Fatalf("record seat = %q after auth rejection, want empty", got.WriterSeat)
	}
}

// TestWriterRelay_MissingAttachAuthPermissionDenied proves a request with a valid
// identity but no/invalid attach auth is refused PermissionDenied (the seat requires a
// valid session-scoped attach, D39).
func TestWriterRelay_MissingAttachAuthPermissionDenied(t *testing.T) {
	svc, _ := newRelay(t,
		fakeIdentity{wantAssertion: "sso-token", driver: "alice@org"},
		fakeAttachAuth{wantToken: "attach-tok"},
	)
	// Absent token → PermissionDenied.
	_, err := svc.RequestWriterSeat(context.Background(), &attachv1.RequestWriterSeatRequest{
		SessionUuid:       "sess-1",
		IdentityAssertion: "sso-token",
	})
	wantCode(t, err, codes.PermissionDenied)
	// Wrong token → PermissionDenied.
	_, err = svc.RequestWriterSeat(context.Background(), &attachv1.RequestWriterSeatRequest{
		SessionUuid:       "sess-1",
		IdentityAssertion: "sso-token",
		AttachAuth:        []byte("wrong-tok"),
	})
	wantCode(t, err, codes.PermissionDenied)
}

// TestWriterRelay_SecondWriterAlreadyExists proves the D61 one-writer loser is refused
// AlreadyExists over the RPC surface (never a second live seat).
func TestWriterRelay_SecondWriterAlreadyExists(t *testing.T) {
	svc, _ := newRelay(t,
		multiIdentity{"sso-a": "alice@org", "sso-b": "bob@org"},
		fakeAttachAuth{wantToken: "attach-tok"},
	)
	ctx := context.Background()
	if _, err := svc.RequestWriterSeat(ctx, &attachv1.RequestWriterSeatRequest{
		SessionUuid: "sess-1", IdentityAssertion: "sso-a", AttachAuth: []byte("attach-tok"),
	}); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	_, err := svc.RequestWriterSeat(ctx, &attachv1.RequestWriterSeatRequest{
		SessionUuid: "sess-1", IdentityAssertion: "sso-b", AttachAuth: []byte("attach-tok"),
	})
	wantCode(t, err, codes.AlreadyExists)
}

// TestWriterRelay_StealAttendedPermissionDenied proves a force_steal of an attended
// seat is refused PermissionDenied over the RPC surface (D138 default-refuse). The
// seeded session counts as attended once the first writer holds the seat (the
// writer-attached-only interim).
func TestWriterRelay_StealAttendedPermissionDenied(t *testing.T) {
	svc, _ := newRelay(t,
		multiIdentity{"sso-a": "alice@org", "sso-b": "bob@org"},
		fakeAttachAuth{wantToken: "attach-tok"},
	)
	ctx := context.Background()
	if _, err := svc.RequestWriterSeat(ctx, &attachv1.RequestWriterSeatRequest{
		SessionUuid: "sess-1", IdentityAssertion: "sso-a", AttachAuth: []byte("attach-tok"),
	}); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	// alice now holds the seat → the record reads ATTENDED (writer-attached-only). A
	// force_steal must be refused PermissionDenied.
	_, err := svc.RequestWriterSeat(ctx, &attachv1.RequestWriterSeatRequest{
		SessionUuid: "sess-1", IdentityAssertion: "sso-b", AttachAuth: []byte("attach-tok"), ForceSteal: true,
	})
	wantCode(t, err, codes.PermissionDenied)
}

// TestWriterRelay_YieldReleasesReleasedSeq proves YieldWriterSeat releases the held
// seat and returns a non-zero released_seq over the RPC surface.
func TestWriterRelay_YieldReleasesReleasedSeq(t *testing.T) {
	svc, repo := newRelay(t,
		fakeIdentity{wantAssertion: "sso-token", driver: "alice@org"},
		fakeAttachAuth{wantToken: "attach-tok"},
	)
	ctx := context.Background()
	resp, err := svc.RequestWriterSeat(ctx, &attachv1.RequestWriterSeatRequest{
		SessionUuid: "sess-1", IdentityAssertion: "sso-token", AttachAuth: []byte("attach-tok"),
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	yResp, err := svc.YieldWriterSeat(ctx, &attachv1.YieldWriterSeatRequest{
		SessionUuid:  "sess-1",
		WriterSeatId: resp.GetGrant().GetWriterSeatId(),
	})
	if err != nil {
		t.Fatalf("yield: %v", err)
	}
	if yResp.GetReleasedSeq() <= resp.GetGrant().GetGrantedSeq() {
		t.Fatalf("released_seq = %d, want > granted_seq %d", yResp.GetReleasedSeq(), resp.GetGrant().GetGrantedSeq())
	}
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "" {
		t.Fatalf("record seat = %q after yield, want empty", got.WriterSeat)
	}
}

// TestWriterRelay_NilSeamsFailClosed pins the gate-off fail-closed posture DIRECTLY at
// the WriterRelayService: a service constructed with NIL auth seams (the DS_ORCH_LIVE run
// that wired no identity/attach validator — the production default until the dialed
// D22/D55 SSO edge lands, exactly what resolveWriterIdentityValidator returns gate-off)
// refuses every RequestWriterSeat, and the refusal never mutates the record.
//
//   - Both seams nil: identity is validated FIRST, so a nil identity seam refuses
//     Unauthenticated (no seat without a wired human-identity check, D22/D55).
//   - Identity wired (accepting) but the attach seam nil: refused PermissionDenied (the
//     seat still requires a valid session-scoped attach, D39) — a half-wired deployment
//     never grants an unauthenticated seat.
//
// This is the RPC-surface twin of the nil-seam resolution: the seam owner refuses here,
// so the fail-closed contract holds wherever the seams are left unwired.
func TestWriterRelay_NilSeamsFailClosed(t *testing.T) {
	ctx := context.Background()

	// (1) Both seams nil → identity checked first → Unauthenticated; no seat recorded.
	svc, repo := newRelay(t, nil, nil)
	_, err := svc.RequestWriterSeat(ctx, &attachv1.RequestWriterSeatRequest{
		SessionUuid:       "sess-1",
		IdentityAssertion: "any-assertion",
		AttachAuth:        []byte("any-token"),
	})
	wantCode(t, err, codes.Unauthenticated)
	got, gerr := repo.GetSession(ctx, "sess-1")
	if gerr != nil {
		t.Fatalf("GetSession after nil-seam refusal: %v", gerr)
	}
	if got.WriterSeat != "" {
		t.Fatalf("record seat = %q after nil-seam refusal, want empty (fail-closed never mutates)", got.WriterSeat)
	}

	// (2) Identity wired (accepting), attach seam nil → PermissionDenied (the seat requires
	// a valid attach, D39). Pins that a half-wired deployment refuses on the attach key.
	svc2, _ := newRelay(t, fakeIdentity{wantAssertion: "any-assertion", driver: "alice@org"}, nil)
	_, err = svc2.RequestWriterSeat(ctx, &attachv1.RequestWriterSeatRequest{
		SessionUuid:       "sess-1",
		IdentityAssertion: "any-assertion",
		AttachAuth:        []byte("any-token"),
	})
	wantCode(t, err, codes.PermissionDenied)
}

// multiIdentity is a test IdentityAssertionValidator mapping assertion → driver.
type multiIdentity map[string]string

func (m multiIdentity) ValidateAssertion(_ context.Context, _ string, assertion string) (string, bool, error) {
	d, ok := m[assertion]
	return d, ok, nil
}
