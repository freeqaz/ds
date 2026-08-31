package attach

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// seedSession creates a minimal PENDING session row so the seat arbitration has a
// record to mutate (GetSession/UpdateSession require the session to exist).
func seedSession(t *testing.T, repo *store.Memory, uuid string, idx uint64) {
	t.Helper()
	_, err := repo.CreateSession(context.Background(), store.Session{
		Ref: store.SessionRef{
			SessionUUID:      uuid,
			HostID:           "host-a",
			HostSessionIndex: idx,
			TapName:          "tap-" + uuid,
		},
		State: store.SessionPending,
	})
	if err != nil {
		t.Fatalf("CreateSession(%s): %v", uuid, err)
	}
}

func TestAcquireWriter_GrantsUnheldSeat(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)

	grant, err := AcquireWriter(ctx, repo, "sess-1", "writer-a", false)
	if err != nil {
		t.Fatalf("AcquireWriter: %v", err)
	}
	if grant.Role != attachv1.Role_ROLE_WRITER || grant.SeatID != "writer-a" || grant.HandedOff {
		t.Fatalf("grant = %+v, want WRITER seat writer-a not-handed-off", grant)
	}
	// The seat must live in the RECORD (the server-side D61 invariant), not just in
	// the returned grant.
	got, err := repo.GetSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.WriterSeat != "writer-a" || got.WriterRole != store.RoleWriter {
		t.Fatalf("record seat = (%q,%q), want (writer-a,WRITER)", got.WriterSeat, got.WriterRole)
	}
	if got.AttachState != store.RoleWriter {
		t.Fatalf("AttachState = %q, want WRITER", got.AttachState)
	}
}

func TestAcquireWriter_SecondWriterRefusedWithoutHandoff(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)

	if _, err := AcquireWriter(ctx, repo, "sess-1", "writer-a", false); err != nil {
		t.Fatalf("first AcquireWriter: %v", err)
	}
	_, err := AcquireWriter(ctx, repo, "sess-1", "writer-b", false)
	if !errors.Is(err, ErrWriterSeatHeld) {
		t.Fatalf("second writer err = %v, want ErrWriterSeatHeld", err)
	}
	// The record must still name the FIRST writer — a refused acquisition never
	// mutates the seat.
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "writer-a" {
		t.Fatalf("record seat = %q after refused acquire, want writer-a", got.WriterSeat)
	}
}

func TestAcquireWriter_HandoffChangesHandsWithAttribution(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)

	if _, err := AcquireWriter(ctx, repo, "sess-1", "writer-a", false); err != nil {
		t.Fatalf("first AcquireWriter: %v", err)
	}
	grant, err := AcquireWriter(ctx, repo, "sess-1", "writer-b", true)
	if err != nil {
		t.Fatalf("handoff AcquireWriter: %v", err)
	}
	if !grant.HandedOff || grant.PriorWriter != "writer-a" || grant.SeatID != "writer-b" {
		t.Fatalf("handoff grant = %+v, want handed-off from writer-a to writer-b", grant)
	}
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "writer-b" || got.WriterRole != store.RoleWriter {
		t.Fatalf("record seat = (%q,%q) after handoff, want (writer-b,WRITER)", got.WriterSeat, got.WriterRole)
	}
}

func TestAcquireWriter_IdempotentForSameHolder(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)

	if _, err := AcquireWriter(ctx, repo, "sess-1", "writer-a", false); err != nil {
		t.Fatalf("first AcquireWriter: %v", err)
	}
	grant, err := AcquireWriter(ctx, repo, "sess-1", "writer-a", false)
	if err != nil {
		t.Fatalf("re-acquire by same writer: %v", err)
	}
	if grant.HandedOff {
		t.Fatalf("re-acquire by same holder reported a handoff: %+v", grant)
	}
}

func TestAcquireWriter_EmptySeatRefused(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	if _, err := AcquireWriter(ctx, repo, "sess-1", "", false); !errors.Is(err, ErrSeatIdentityRequired) {
		t.Fatalf("empty-seat err = %v, want ErrSeatIdentityRequired", err)
	}
}

func TestAcquireReader_UnboundedAndNeverDisplacesWriter(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)

	if _, err := AcquireWriter(ctx, repo, "sess-1", "writer-a", false); err != nil {
		t.Fatalf("AcquireWriter: %v", err)
	}
	// Many readers admit without arbitration; none touches the writer seat.
	for i := 0; i < 5; i++ {
		grant, err := AcquireReader(ctx, repo, "sess-1")
		if err != nil {
			t.Fatalf("AcquireReader #%d: %v", i, err)
		}
		if grant.Role != attachv1.Role_ROLE_READER {
			t.Fatalf("reader grant role = %v, want READER", grant.Role)
		}
	}
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "writer-a" || got.WriterRole != store.RoleWriter {
		t.Fatalf("writer seat displaced by readers: (%q,%q)", got.WriterSeat, got.WriterRole)
	}
	if got.AttachState != store.RoleReader {
		t.Fatalf("AttachState = %q after reader attach, want READER", got.AttachState)
	}
}

func TestReleaseWriter_ClearsSeatAndIsNoOpForNonHolder(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)

	if _, err := AcquireWriter(ctx, repo, "sess-1", "writer-a", false); err != nil {
		t.Fatalf("AcquireWriter: %v", err)
	}
	// A non-holder release is a no-op success (never displaces the holder).
	if err := ReleaseWriter(ctx, repo, "sess-1", "writer-b"); err != nil {
		t.Fatalf("non-holder ReleaseWriter: %v", err)
	}
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "writer-a" {
		t.Fatalf("non-holder release cleared the seat: %q", got.WriterSeat)
	}
	// The holder releases: the seat clears.
	if err := ReleaseWriter(ctx, repo, "sess-1", "writer-a"); err != nil {
		t.Fatalf("holder ReleaseWriter: %v", err)
	}
	got, _ = repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "" || got.WriterRole != store.RoleNone {
		t.Fatalf("seat not cleared after holder release: (%q,%q)", got.WriterSeat, got.WriterRole)
	}
	// After release the seat is re-acquirable by a different writer.
	if _, err := AcquireWriter(ctx, repo, "sess-1", "writer-b", false); err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
}

func TestAcquireWriter_UnknownSessionSurfacesStoreError(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	_, err := AcquireWriter(ctx, repo, "nope", "writer-a", false)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown-session err = %v, want store.ErrNotFound", err)
	}
}
