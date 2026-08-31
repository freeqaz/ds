package store

import (
	"context"
	"sort"
)

// This file is the M2 plan-store READ PATH (doc 05 §5 M2; doc 05 §7 edge 7
// "plan store → plan-card projection"; doc 15 §5.6; doc 17 §3.3). It exposes the
// ONE read path that serves BOTH consumers of plan truth:
//
//   - the console's D61 READ-ONLY plan boards (doc 17 §3.3 — "plan boards ship
//     read-only from the M2 plan store"), and
//   - the canvas PLAN-CARD projection (doc 05 §7 edge 7; doc 17 §3.3 — "one
//     projection pipeline serves both the console's read-only boards and canvas
//     plan cards").
//
// IN-PROCESS Go interface ONLY. The future wire home is the RESERVED
// dreamserpent.planstore.v1 package (proto/FREEZE.md row 23; doc 15 §5.6). That
// package is RESERVED — no .proto body exists, freezes are one-shot, and stub
// bodies are forbidden pre-freeze — so NOTHING here touches proto/. The names
// below are chosen so the eventual proto mapping is MECHANICAL:
//
//   PlanStoreReader   -> service dreamserpent.planstore.v1.PlanStore (read-only)
//   GetPlanCard       -> rpc GetPlanCard(GetPlanCardRequest) returns (PlanCard)
//   ListPlanCards     -> rpc ListPlanCards(ListPlanCardsRequest) returns (ListPlanCardsResponse)
//   ListPlanBoard     -> rpc ListPlanBoard(ListPlanBoardRequest) returns (PlanBoard)
//   PlanCard / PlanBoardEntry / PlanBoard -> the corresponding messages
//
// READ-ONLY BY CONSTRUCTION (doc 17 §3.3 / D61 / D86): the interface exposes NO
// write-back surface. "Editing" a plan card on the canvas creates canvas-local
// annotation objects layered OVER this projection; the plan row stays untouched.
// Plan write-back is UNDEFINED without a new ratified decision row (doc 17 §3.3,
// OQ8) — so this seam has no Put/Update/Delete, and the write path stays on
// Repository.PutPlan (the system of record), never here.

// PlanCard is the canvas plan-card projection of one plan (doc 05 §7 edge 7;
// doc 17 §3.3). It is the card-shaped consumer's view: an opaque plan-id the
// board anchors a card on (doc 17 §3.3(a) — by opaque plan-id, never a foreign
// key), the owning session for attribution (doc 02 §8 / doc 04 §5), and the
// plan title/body the card renders. It is a value snapshot — annotating it never
// writes back (the canvas is never a second writer).
//
// Maps mechanically to message dreamserpent.planstore.v1.PlanCard.
type PlanCard struct {
	// PlanID is the OPAQUE control-plane plan-id a board references (doc 17
	// §3.3(a)). It is a token, never a SQL foreign key into plan-store tables.
	PlanID      string
	SessionUUID string // owning session — attribution (doc 02 §8); empty when unscoped
	Title       string
	Body        []byte
}

// PlanBoardEntry is one row of a D61 read-only plan board (doc 17 §3.3). The
// board lists plans for a session; each entry carries the same opaque plan-id
// and title the board renders, plus the card-shaped projection so the board and
// the canvas read the SAME projection (one pipeline, doc 17 §3.3).
//
// Maps mechanically to message dreamserpent.planstore.v1.PlanBoardEntry.
type PlanBoardEntry struct {
	PlanID string
	Title  string
	Card   PlanCard // the same card the canvas plan-card consumer reads
}

// PlanBoard is the D61 read-only plan board for a session: the session it is
// scoped to plus its plan entries in stable order (doc 17 §3.3). It is the
// board-shaped consumer's view over the SAME read path the card-shaped consumer
// uses.
//
// Maps mechanically to message dreamserpent.planstore.v1.PlanBoard.
type PlanBoard struct {
	SessionUUID string
	Entries     []PlanBoardEntry
}

// PlanStoreReader is the in-process plan-store READ seam (D33-style replaceable),
// the M2 read path doc 05 §7 edge 7's plan-card projection pipeline consumes and
// the console's D61 read-only boards read. It is the in-process stand-in for the
// RESERVED dreamserpent.planstore.v1 service; the method names map mechanically
// (see file header).
//
// READ-ONLY: there is deliberately NO write surface here. The write path is
// Repository.PutPlan (the system of record); canvas annotation never writes back
// (doc 17 §3.3, OQ8).
type PlanStoreReader interface {
	// GetPlanCard returns the canvas plan-card projection of one plan by its
	// opaque plan-id, or ErrNotFound. The card-shaped read path (doc 05 §7 edge 7).
	GetPlanCard(ctx context.Context, planID string) (PlanCard, error)

	// ListPlanCards returns the plan-card projections for a session in stable
	// (plan-id) order — the card-shaped consumer's per-session view. An empty
	// sessionUUID lists across sessions (the unscoped board case).
	ListPlanCards(ctx context.Context, sessionUUID string) ([]PlanCard, error)

	// ListPlanBoard returns the D61 read-only plan board for a session — the
	// board-shaped consumer's view over the SAME projection the cards use. An
	// empty sessionUUID returns ErrInvalid (a board is always session-scoped).
	ListPlanBoard(ctx context.Context, sessionUUID string) (PlanBoard, error)
}

// planReader is the read-only projection over the plan rows the Repository
// fronts (records.go Plan + the *Plan methods). It holds a Repository but
// exposes ONLY the read seam — the type assertion on construction guarantees no
// write method leaks through, so this remains a pure projection (doc 17 §3.3).
type planReader struct {
	repo planRepoReads
}

// planRepoReads is the minimal READ slice of Repository the projection needs.
// Narrowing to the read methods makes the read-only posture structural: the
// projection literally cannot call PutPlan (it is not in this interface), so the
// no-write-back guarantee holds at the type level, not just by convention.
type planRepoReads interface {
	GetPlan(ctx context.Context, id string) (Plan, error)
	ListPlans(ctx context.Context, sessionUUID string) ([]Plan, error)
}

// NewPlanStoreReader returns the read-only plan-store projection over repo. Both
// Memory and Postgres satisfy planRepoReads (they implement Repository), so the
// SAME read path serves whichever store backs the plans.
func NewPlanStoreReader(repo planRepoReads) PlanStoreReader {
	return &planReader{repo: repo}
}

var _ PlanStoreReader = (*planReader)(nil)

// planToCard projects a stored Plan onto the card-shaped view. It is the single
// projection point both consumers route through, so board and card can never
// drift (doc 17 §3.3 — one pipeline).
func planToCard(p Plan) PlanCard {
	return PlanCard{
		PlanID:      p.ID,
		SessionUUID: p.SessionUUID,
		Title:       p.Title,
		Body:        cloneBytes(p.Body),
	}
}

func (r *planReader) GetPlanCard(ctx context.Context, planID string) (PlanCard, error) {
	p, err := r.repo.GetPlan(ctx, planID)
	if err != nil {
		return PlanCard{}, err
	}
	return planToCard(p), nil
}

func (r *planReader) ListPlanCards(ctx context.Context, sessionUUID string) ([]PlanCard, error) {
	plans, err := r.repo.ListPlans(ctx, sessionUUID)
	if err != nil {
		return nil, err
	}
	out := make([]PlanCard, 0, len(plans))
	for _, p := range plans {
		out = append(out, planToCard(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PlanID < out[j].PlanID })
	return out, nil
}

func (r *planReader) ListPlanBoard(ctx context.Context, sessionUUID string) (PlanBoard, error) {
	if sessionUUID == "" {
		return PlanBoard{}, wrap(ErrInvalid, "ListPlanBoard requires a session_uuid (a board is session-scoped)")
	}
	cards, err := r.ListPlanCards(ctx, sessionUUID)
	if err != nil {
		return PlanBoard{}, err
	}
	board := PlanBoard{SessionUUID: sessionUUID, Entries: make([]PlanBoardEntry, 0, len(cards))}
	for _, c := range cards {
		board.Entries = append(board.Entries, PlanBoardEntry{
			PlanID: c.PlanID,
			Title:  c.Title,
			Card:   c,
		})
	}
	return board, nil
}
