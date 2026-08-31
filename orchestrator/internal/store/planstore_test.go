package store

import (
	"context"
	"errors"
	"testing"
)

// These tests cover the ONE plan-store read path (doc 05 §7 edge 7; doc 17
// §3.3) over the in-memory Repository: the SAME projection serves the
// board-shaped consumer (console D61 read-only boards) and the card-shaped
// consumer (canvas plan cards), and the seam exposes NO write-back surface.

// seedPlans creates two sessions and three plans (two for one session, one for
// the other) through the WRITE path (Repository.PutPlan — the system of record),
// then returns a read-only PlanStoreReader over the same store. The reader never
// touches PutPlan, proving the read path is a pure projection.
//
// BOTH owning sessions are provisioned first: PutPlan now mirrors the live
// nullable FK plans.session_uuid REFERENCES sessions(session_uuid) (0004) and
// rejects an orphan write (a non-empty session_uuid with no sessions row) with
// ErrInvalid, exactly as Postgres does — so the cross-session card (sess-x) must
// reference a real session, the same row the live conformance run provisions.
func seedPlans(t *testing.T) (PlanStoreReader, *Memory) {
	t.Helper()
	repo := NewMemoryClock(fixedClock(baseTime))
	ctx := context.Background()
	if _, err := repo.CreateSession(ctx, newSession("sess-pl", "host-a", 21)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := repo.CreateSession(ctx, newSession("sess-x", "host-a", 22)); err != nil {
		t.Fatalf("CreateSession(sess-x): %v", err)
	}
	for _, p := range []Plan{
		{ID: "plan-b", SessionUUID: "sess-pl", Title: "second", Body: []byte("steps-b")},
		{ID: "plan-a", SessionUUID: "sess-pl", Title: "first", Body: []byte("steps-a")},
		{ID: "plan-other", SessionUUID: "sess-x", Title: "elsewhere", Body: []byte("x")},
	} {
		if _, err := repo.PutPlan(ctx, p); err != nil {
			t.Fatalf("PutPlan(%s): %v", p.ID, err)
		}
	}
	return NewPlanStoreReader(repo), repo
}

// TestPlanStore_CardShapedConsumer covers the canvas plan-card read path
// (doc 05 §7 edge 7): GetPlanCard by opaque plan-id and ListPlanCards by session.
func TestPlanStore_CardShapedConsumer(t *testing.T) {
	reader, _ := seedPlans(t)
	ctx := context.Background()

	card, err := reader.GetPlanCard(ctx, "plan-a")
	if err != nil {
		t.Fatalf("GetPlanCard: %v", err)
	}
	// The card carries the opaque plan-id, the attributed session, and the body.
	if card.PlanID != "plan-a" || card.SessionUUID != "sess-pl" || card.Title != "first" {
		t.Fatalf("card projection wrong: %+v", card)
	}
	if string(card.Body) != "steps-a" {
		t.Fatalf("card body wrong: %q", card.Body)
	}

	cards, err := reader.ListPlanCards(ctx, "sess-pl")
	if err != nil {
		t.Fatalf("ListPlanCards: %v", err)
	}
	if len(cards) != 2 {
		t.Fatalf("want 2 cards for sess-pl, got %d", len(cards))
	}
	// Stable plan-id order regardless of insert order.
	if cards[0].PlanID != "plan-a" || cards[1].PlanID != "plan-b" {
		t.Fatalf("cards not plan-id-ordered: %+v", cards)
	}
	// Attribution holds: a card never leaks across sessions.
	for _, c := range cards {
		if c.SessionUUID != "sess-pl" {
			t.Fatalf("card leaked across sessions: %+v", c)
		}
	}
}

// TestPlanStore_BoardShapedConsumer covers the console D61 read-only plan board
// read path over the SAME projection.
func TestPlanStore_BoardShapedConsumer(t *testing.T) {
	reader, _ := seedPlans(t)
	ctx := context.Background()

	board, err := reader.ListPlanBoard(ctx, "sess-pl")
	if err != nil {
		t.Fatalf("ListPlanBoard: %v", err)
	}
	if board.SessionUUID != "sess-pl" {
		t.Fatalf("board scoped wrong: %+v", board)
	}
	if len(board.Entries) != 2 {
		t.Fatalf("want 2 board entries, got %d", len(board.Entries))
	}
	if board.Entries[0].PlanID != "plan-a" || board.Entries[0].Title != "first" {
		t.Fatalf("board entry order/shape wrong: %+v", board.Entries)
	}
}

// TestPlanStore_OneProjectionBothConsumers pins the doc 17 §3.3 invariant: ONE
// projection serves both consumers, so the board's embedded card is byte-for-byte
// the card the card-shaped path returns. If the two ever diverged, board and
// canvas would render different plan truth.
func TestPlanStore_OneProjectionBothConsumers(t *testing.T) {
	reader, _ := seedPlans(t)
	ctx := context.Background()

	card, err := reader.GetPlanCard(ctx, "plan-a")
	if err != nil {
		t.Fatalf("GetPlanCard: %v", err)
	}
	board, err := reader.ListPlanBoard(ctx, "sess-pl")
	if err != nil {
		t.Fatalf("ListPlanBoard: %v", err)
	}
	var boardCard PlanCard
	for _, e := range board.Entries {
		if e.PlanID == "plan-a" {
			boardCard = e.Card
		}
	}
	if boardCard.PlanID != card.PlanID || boardCard.Title != card.Title ||
		boardCard.SessionUUID != card.SessionUUID || string(boardCard.Body) != string(card.Body) {
		t.Fatalf("board and card consumers see different projections:\n board=%+v\n card =%+v", boardCard, card)
	}
}

// TestPlanStore_BoardRequiresSession pins that a board is always session-scoped.
func TestPlanStore_BoardRequiresSession(t *testing.T) {
	reader, _ := seedPlans(t)
	if _, err := reader.ListPlanBoard(context.Background(), ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unscoped board: got %v, want ErrInvalid", err)
	}
}

// TestPlanStore_NotFound covers a missing plan-id on the read path.
func TestPlanStore_NotFound(t *testing.T) {
	reader, _ := seedPlans(t)
	if _, err := reader.GetPlanCard(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPlanCard miss: got %v, want ErrNotFound", err)
	}
}

// TestPlanStore_NoWriteBackSurface is the doc 17 §3.3 / OQ8 guarantee, enforced
// STRUCTURALLY: the read seam exposes only read methods. A canvas annotation
// mutating a returned card must NOT reach the stored plan — the card is a value
// snapshot whose Body is a fresh copy, and there is no Put/Update/Delete on
// PlanStoreReader to write it back. This test mutates a returned card's body and
// confirms the stored plan is untouched (the plan row stays the system of record).
func TestPlanStore_NoWriteBackSurface(t *testing.T) {
	reader, repo := seedPlans(t)
	ctx := context.Background()

	card, err := reader.GetPlanCard(ctx, "plan-a")
	if err != nil {
		t.Fatalf("GetPlanCard: %v", err)
	}
	// "Annotate" the card in place (the canvas-local edit doc 17 §3.3 describes).
	card.Title = "ANNOTATED"
	if len(card.Body) > 0 {
		card.Body[0] = 'Z'
	}

	// The stored plan is untouched: the read path handed out a snapshot, not an
	// alias, and exposes no write-back. (Compile-time: PlanStoreReader has no
	// write method, so there is literally no surface to push the annotation back.)
	stored, err := repo.GetPlan(ctx, "plan-a")
	if err != nil {
		t.Fatalf("GetPlan: %v", err)
	}
	if stored.Title != "first" {
		t.Fatalf("write-back leaked: stored title %q, want unchanged 'first'", stored.Title)
	}
	if string(stored.Body) != "steps-a" {
		t.Fatalf("write-back leaked into body: %q, want unchanged 'steps-a'", stored.Body)
	}
}
