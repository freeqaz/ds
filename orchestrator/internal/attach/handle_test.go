package attach

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestIssue_WriterHandleTakesSeatAndCarriesFrozenShape(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)

	at := time.Unix(1_700_000_000, 0).UTC()
	iss := NewIssuer(repo,
		WithEndpointResolver(EndpointResolverFunc(func(_ context.Context, s string) (string, string, bool, error) {
			return "host-a.internal:7443", "sess-1.attach.ds.local", true, nil
		})),
		WithClock(fixedClock(at)),
		WithHandleTTL(5*time.Minute),
		WithTokenGen(func() []byte { return []byte("test-token") }),
	)

	h, grant, err := iss.Issue(ctx, "sess-1", "writer-a", attachv1.Role_ROLE_WRITER, false)
	if err != nil {
		t.Fatalf("Issue WRITER: %v", err)
	}
	// Frozen attach.v1.AttachHandle shape (doc 15 §5.4): session, endpoints, auth,
	// role, expiry.
	if h.GetSessionUuid() != "sess-1" {
		t.Fatalf("handle session = %q, want sess-1", h.GetSessionUuid())
	}
	if h.GetRole() != attachv1.Role_ROLE_WRITER {
		t.Fatalf("handle role = %v, want WRITER", h.GetRole())
	}
	wantExpiry := uint64(at.Add(5 * time.Minute).Unix())
	if h.GetExpiresAt() != wantExpiry {
		t.Fatalf("handle expiry = %d, want %d", h.GetExpiresAt(), wantExpiry)
	}
	if h.GetAuth() == nil || string(h.GetAuth().GetToken()) != "test-token" {
		t.Fatalf("handle auth = %+v, want short-lived session token", h.GetAuth())
	}
	if h.GetAuth().GetExpiresAt() > h.GetExpiresAt() {
		t.Fatalf("auth expiry %d exceeds handle expiry %d (D39: credential <= handle)", h.GetAuth().GetExpiresAt(), h.GetExpiresAt())
	}
	// M0: exactly the DIRECT endpoint candidate.
	if len(h.GetEndpoints()) != 1 {
		t.Fatalf("handle endpoints = %d, want exactly 1 (M0 DIRECT only)", len(h.GetEndpoints()))
	}
	ep := h.GetEndpoints()[0]
	if ep.GetTransport() != attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT {
		t.Fatalf("endpoint transport = %v, want DIRECT", ep.GetTransport())
	}
	if ep.GetAddress() != "host-a.internal:7443" || ep.GetServerName() != "sess-1.attach.ds.local" {
		t.Fatalf("endpoint = (%q,%q), want the resolved direct address/SNI", ep.GetAddress(), ep.GetServerName())
	}
	// The seat took (the handle and the record agree on the writer).
	if grant.Role != attachv1.Role_ROLE_WRITER || grant.SeatID != "writer-a" {
		t.Fatalf("grant = %+v, want WRITER writer-a", grant)
	}
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "writer-a" {
		t.Fatalf("record writer seat = %q, want writer-a (handle issuance took the seat)", got.WriterSeat)
	}
}

func TestIssue_WriterHandleRefusedWhenSeatHeld(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	iss := NewIssuer(repo)

	if _, _, err := iss.Issue(ctx, "sess-1", "writer-a", attachv1.Role_ROLE_WRITER, false); err != nil {
		t.Fatalf("first WRITER Issue: %v", err)
	}
	_, _, err := iss.Issue(ctx, "sess-1", "writer-b", attachv1.Role_ROLE_WRITER, false)
	if !errors.Is(err, ErrWriterSeatHeld) {
		t.Fatalf("second WRITER Issue err = %v, want ErrWriterSeatHeld (D61 one-writer)", err)
	}
}

func TestIssue_ReaderHandleNeverNeedsSeat(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	iss := NewIssuer(repo)

	// A writer holds the seat; readers still issue freely (the N of one-writer/
	// N-reader) and carry the READER role.
	if _, _, err := iss.Issue(ctx, "sess-1", "writer-a", attachv1.Role_ROLE_WRITER, false); err != nil {
		t.Fatalf("WRITER Issue: %v", err)
	}
	for i := 0; i < 3; i++ {
		h, grant, err := iss.Issue(ctx, "sess-1", "", attachv1.Role_ROLE_READER, false)
		if err != nil {
			t.Fatalf("READER Issue #%d: %v", i, err)
		}
		if h.GetRole() != attachv1.Role_ROLE_READER || grant.Role != attachv1.Role_ROLE_READER {
			t.Fatalf("reader handle/grant role = (%v,%v), want READER", h.GetRole(), grant.Role)
		}
	}
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "writer-a" {
		t.Fatalf("reader handles displaced the writer seat: %q", got.WriterSeat)
	}
}

func TestIssue_UnknownRoleRefused(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	iss := NewIssuer(repo)
	if _, _, err := iss.Issue(ctx, "sess-1", "x", attachv1.Role_ROLE_UNSPECIFIED, false); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("unspecified-role err = %v, want ErrUnknownRole", err)
	}
}

func TestIssue_NoEndpointResolverYieldsNoCandidate(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	iss := NewIssuer(repo) // no endpoint resolver

	h, _, err := iss.Issue(ctx, "sess-1", "writer-a", attachv1.Role_ROLE_WRITER, false)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(h.GetEndpoints()) != 0 {
		t.Fatalf("endpoints = %d with no resolver, want 0 (no fabricated address)", len(h.GetEndpoints()))
	}
	// Seat + auth still issue.
	if h.GetAuth() == nil || len(h.GetAuth().GetToken()) == 0 {
		t.Fatalf("handle missing auth material")
	}
}

func TestIssue_UnresolvedEndpointYieldsNoCandidate(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	iss := NewIssuer(repo, WithEndpointResolver(EndpointResolverFunc(
		func(_ context.Context, _ string) (string, string, bool, error) { return "", "", false, nil },
	)))
	h, _, err := iss.Issue(ctx, "sess-1", "writer-a", attachv1.Role_ROLE_WRITER, false)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(h.GetEndpoints()) != 0 {
		t.Fatalf("endpoints = %d for an unplaced session, want 0", len(h.GetEndpoints()))
	}
}

func TestIssue_DefaultTokenIsRandomAndNonEmpty(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	seedSession(t, repo, "sess-2", 2)
	iss := NewIssuer(repo)

	h1, _, err := iss.Issue(ctx, "sess-1", "w", attachv1.Role_ROLE_WRITER, false)
	if err != nil {
		t.Fatalf("Issue sess-1: %v", err)
	}
	h2, _, err := iss.Issue(ctx, "sess-2", "w", attachv1.Role_ROLE_WRITER, false)
	if err != nil {
		t.Fatalf("Issue sess-2: %v", err)
	}
	t1, t2 := h1.GetAuth().GetToken(), h2.GetAuth().GetToken()
	if len(t1) == 0 || len(t2) == 0 {
		t.Fatalf("empty default token(s)")
	}
	if string(t1) == string(t2) {
		t.Fatalf("default tokens collided across sessions: %q", t1)
	}
}

func TestIssue_HandoffViaIssuerChangesWriter(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	iss := NewIssuer(repo)

	if _, _, err := iss.Issue(ctx, "sess-1", "writer-a", attachv1.Role_ROLE_WRITER, false); err != nil {
		t.Fatalf("first WRITER Issue: %v", err)
	}
	_, grant, err := iss.Issue(ctx, "sess-1", "writer-b", attachv1.Role_ROLE_WRITER, true)
	if err != nil {
		t.Fatalf("handoff Issue: %v", err)
	}
	if !grant.HandedOff || grant.PriorWriter != "writer-a" {
		t.Fatalf("handoff grant = %+v, want handed-off from writer-a", grant)
	}
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "writer-b" {
		t.Fatalf("record writer = %q after handoff, want writer-b", got.WriterSeat)
	}
}
