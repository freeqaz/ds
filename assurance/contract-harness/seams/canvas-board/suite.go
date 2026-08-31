// SPDX-License-Identifier: Apache-2.0

package canvasboard

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	canvasv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/canvas/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/canvas/v1/canvasv1fake"
)

// Synthetic fixtures (D50). Every identifier is obviously-synthetic — no real
// org, principal, session, or board content. Each scenario stands up its OWN
// board(s) from scratch and observes only contract facts that are stable by
// construction: the assigned ids are deterministic functions of a per-store
// monotonic counter, so the real impl and the fake mirror (which replay the same
// scenarios in the same declaration order) observe byte-identically. NO scenario
// depends on absolute id values reached by cross-scenario growth — each records
// either round-tripped input (name/description/role/target_ref) or relational
// invariants (grant updated-in-place, pin removed, history non-empty).
const (
	synthOrg        = "org-synthetic-canvas-01"
	synthOrgOther   = "org-synthetic-canvas-02"
	synthPrincipalA = "prin-synthetic-alice"
	synthPrincipalB = "prin-synthetic-bob"
	synthBoardName  = "board-synthetic-arrangement"
	synthBoardDesc  = "synthetic read-only projection surface"
	synthTargetRef  = "ses-synthetic-9ra919ra-tile"
)

// Suite is the canvas.v1 BoardService seam's single conformance suite (doc 06
// §3a: one suite, run against real + fake). Every scenario is stated purely in
// terms of the frozen BoardService contract (doc 17 §10) so the same suite is
// meaningful against any faithful implementation: org-scoped board CRUD, role
// grants riding org RBAC (D61, no parallel ACL — re-grant updates in place),
// read-only projection-pin management (doc 17 §3.1), and the product-history
// listing (doc 17 §9, NOT the audit chain). BoardService is all-13-verbs-unary,
// so it runs through the existing dualrun runner with no machinery change.
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "canvas<->board(canvas.v1.BoardService)",
		Scenarios: scenarios(),
	}
}

func scenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			// Board CRUD round-trip: CreateBoard then GetBoard returns the same
			// product metadata under the creating org; created_at == updated_at on a
			// fresh board; the assigned board_id is the deterministic synthetic shape.
			Name: "board-crud/create-then-get-round-trips-metadata",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				created, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{
					OrgId:       synthOrg,
					Name:        synthBoardName,
					Description: synthBoardDesc,
				})
				if err != nil {
					return errObservation(err), nil
				}
				got, err := cl.GetBoard(ctx, &canvasv1.GetBoardRequest{BoardId: created.GetBoard().GetBoardId()})
				if err != nil {
					return errObservation(err), nil
				}
				b := got.GetBoard()
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("org_id", b.GetOrgId())
				obs.Set("name", b.GetName())
				obs.Set("description", b.GetDescription())
				obs.Set("board_id", b.GetBoardId())
				obs.Setf("created_eq_updated_on_fresh", "%t", b.GetCreatedAt() == b.GetUpdatedAt())
				obs.Setf("created_at", "%d", b.GetCreatedAt())
				return obs, nil
			},
		},
		{
			// UpdateBoard mutates product metadata and ADVANCES updated_at past
			// created_at — arrangement is canvas-truth, not a write into any
			// projected session (the structural invariant, doc 17 §5).
			Name: "board-crud/update-advances-updated-at-and-metadata",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				created, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrg, Name: synthBoardName, Description: synthBoardDesc})
				if err != nil {
					return errObservation(err), nil
				}
				id := created.GetBoard().GetBoardId()
				updated, err := cl.UpdateBoard(ctx, &canvasv1.UpdateBoardRequest{BoardId: id, Name: "board-synthetic-renamed", Description: "renamed-desc"})
				if err != nil {
					return errObservation(err), nil
				}
				b := updated.GetBoard()
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("name", b.GetName())
				obs.Set("description", b.GetDescription())
				obs.Setf("updated_after_created", "%t", b.GetUpdatedAt() > b.GetCreatedAt())
				obs.Setf("board_id_stable", "%t", b.GetBoardId() == id)
				return obs, nil
			},
		},
		{
			// DeleteBoard removes the board: a subsequent GetBoard is NotFound, and
			// a delete of an absent board is NotFound. Delete of a missing board and
			// get-after-delete are the contract refusals a faithful fake must mirror.
			Name: "board-crud/delete-then-get-is-not-found",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				created, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrg, Name: synthBoardName})
				if err != nil {
					return errObservation(err), nil
				}
				id := created.GetBoard().GetBoardId()
				if _, err := cl.DeleteBoard(ctx, &canvasv1.DeleteBoardRequest{BoardId: id}); err != nil {
					return errObservation(err), nil
				}
				_, getErr := cl.GetBoard(ctx, &canvasv1.GetBoardRequest{BoardId: id})
				_, redeleteErr := cl.DeleteBoard(ctx, &canvasv1.DeleteBoardRequest{BoardId: id})
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("get_after_delete_status", status.Code(getErr).String())
				obs.Set("redelete_status", status.Code(redeleteErr).String())
				return obs, nil
			},
		},
		{
			// ListBoards is org-scoped (D61): two boards created in one org and one
			// in another, then ListBoards(org) returns exactly the two, ordered
			// deterministically by board_id, with the other org's board excluded.
			Name: "board-crud/list-is-org-scoped-and-ordered",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				if _, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrg, Name: "list-a"}); err != nil {
					return errObservation(err), nil
				}
				if _, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrg, Name: "list-b"}); err != nil {
					return errObservation(err), nil
				}
				if _, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrgOther, Name: "list-other"}); err != nil {
					return errObservation(err), nil
				}
				listed, err := cl.ListBoards(ctx, &canvasv1.ListBoardsRequest{OrgId: synthOrg})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("count", "%d", len(listed.GetBoards()))
				inOrg, ordered := true, true
				var prevID string
				names := ""
				for i, b := range listed.GetBoards() {
					if b.GetOrgId() != synthOrg {
						inOrg = false
					}
					if i > 0 && b.GetBoardId() <= prevID {
						ordered = false
					}
					prevID = b.GetBoardId()
					if i > 0 {
						names += ","
					}
					names += b.GetName()
				}
				obs.Setf("all_in_org", "%t", inOrg)
				obs.Setf("ordered_by_board_id", "%t", ordered)
				obs.Set("names", names)
				obs.Set("next_page_token", listed.GetNextPageToken())
				return obs, nil
			},
		},
		{
			// Grants ride org RBAC (D61, no parallel ACL): grant VIEWER to a
			// principal, then RE-grant the SAME principal as EDITOR — the role is
			// UPDATED IN PLACE (one grant row, not two), and ListBoardGrants reflects
			// the new role. A faithful fake mirrors the no-parallel-ACL semantics.
			Name: "grants/regrant-updates-role-in-place",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				board, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrg, Name: synthBoardName})
				if err != nil {
					return errObservation(err), nil
				}
				id := board.GetBoard().GetBoardId()
				if _, err := cl.GrantBoardRole(ctx, &canvasv1.GrantBoardRoleRequest{BoardId: id, PrincipalId: synthPrincipalA, Role: canvasv1.BoardRole_BOARD_ROLE_VIEWER}); err != nil {
					return errObservation(err), nil
				}
				regrant, err := cl.GrantBoardRole(ctx, &canvasv1.GrantBoardRoleRequest{BoardId: id, PrincipalId: synthPrincipalA, Role: canvasv1.BoardRole_BOARD_ROLE_EDITOR})
				if err != nil {
					return errObservation(err), nil
				}
				grants, err := cl.ListBoardGrants(ctx, &canvasv1.ListBoardGrantsRequest{BoardId: id})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("regrant_role", regrant.GetGrant().GetRole().String())
				obs.Setf("grant_count_after_regrant", "%d", len(grants.GetGrants()))
				obs.Set("roles", rolesSummary(grants.GetGrants()))
				return obs, nil
			},
		},
		{
			// RevokeBoardRole removes a principal's grant; a revoke of a principal
			// with no grant is NotFound. Two principals granted, one revoked: the
			// remaining grant set is exactly the other principal.
			Name: "grants/revoke-removes-grant-and-absent-is-not-found",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				board, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrg, Name: synthBoardName})
				if err != nil {
					return errObservation(err), nil
				}
				id := board.GetBoard().GetBoardId()
				if _, err := cl.GrantBoardRole(ctx, &canvasv1.GrantBoardRoleRequest{BoardId: id, PrincipalId: synthPrincipalA, Role: canvasv1.BoardRole_BOARD_ROLE_OWNER}); err != nil {
					return errObservation(err), nil
				}
				if _, err := cl.GrantBoardRole(ctx, &canvasv1.GrantBoardRoleRequest{BoardId: id, PrincipalId: synthPrincipalB, Role: canvasv1.BoardRole_BOARD_ROLE_VIEWER}); err != nil {
					return errObservation(err), nil
				}
				if _, err := cl.RevokeBoardRole(ctx, &canvasv1.RevokeBoardRoleRequest{BoardId: id, PrincipalId: synthPrincipalA}); err != nil {
					return errObservation(err), nil
				}
				_, absentErr := cl.RevokeBoardRole(ctx, &canvasv1.RevokeBoardRoleRequest{BoardId: id, PrincipalId: synthPrincipalA})
				grants, err := cl.ListBoardGrants(ctx, &canvasv1.ListBoardGrantsRequest{BoardId: id})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("revoke_absent_status", status.Code(absentErr).String())
				obs.Setf("grant_count_after_revoke", "%d", len(grants.GetGrants()))
				obs.Set("roles", rolesSummary(grants.GetGrants()))
				return obs, nil
			},
		},
		{
			// Projection pins are read-only projections (doc 17 §3.1): add a
			// SESSION_TILE pin, update its position (rearrangement is canvas-truth,
			// NOT a write into the projected session — the structural invariant),
			// then list — the pin reflects the updated position and the read-only
			// kind/target_ref round-trip.
			Name: "pins/add-update-position-then-list",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				board, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrg, Name: synthBoardName})
				if err != nil {
					return errObservation(err), nil
				}
				id := board.GetBoard().GetBoardId()
				added, err := cl.AddProjectionPin(ctx, &canvasv1.AddProjectionPinRequest{
					BoardId:   id,
					Kind:      canvasv1.ProjectionKind_PROJECTION_KIND_SESSION_TILE,
					TargetRef: synthTargetRef,
					Position:  &canvasv1.PinPosition{X: 1, Y: 2, Width: 10, Height: 20},
				})
				if err != nil {
					return errObservation(err), nil
				}
				pinID := added.GetPin().GetPinId()
				updated, err := cl.UpdateProjectionPin(ctx, &canvasv1.UpdateProjectionPinRequest{
					PinId:    pinID,
					Position: &canvasv1.PinPosition{X: 3, Y: 4, Width: 30, Height: 40},
				})
				if err != nil {
					return errObservation(err), nil
				}
				pins, err := cl.ListProjectionPins(ctx, &canvasv1.ListProjectionPinsRequest{BoardId: id})
				if err != nil {
					return errObservation(err), nil
				}
				p := updated.GetPin()
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("kind", p.GetKind().String())
				obs.Set("target_ref", p.GetTargetRef())
				obs.Setf("updated_x", "%g", p.GetPosition().GetX())
				obs.Setf("updated_height", "%g", p.GetPosition().GetHeight())
				obs.Setf("pin_count", "%d", len(pins.GetPins()))
				obs.Setf("pin_id_stable", "%t", len(pins.GetPins()) == 1 && pins.GetPins()[0].GetPinId() == pinID)
				return obs, nil
			},
		},
		{
			// RemoveProjectionPin removes a pin: list is empty afterward, and a
			// remove of an absent pin is NotFound. Two pins added, one removed: the
			// surviving pin is the other one.
			Name: "pins/remove-leaves-survivor-and-absent-is-not-found",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				board, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrg, Name: synthBoardName})
				if err != nil {
					return errObservation(err), nil
				}
				id := board.GetBoard().GetBoardId()
				first, err := cl.AddProjectionPin(ctx, &canvasv1.AddProjectionPinRequest{BoardId: id, Kind: canvasv1.ProjectionKind_PROJECTION_KIND_FLEET_TREE_NODE, TargetRef: "fleet-node-synthetic"})
				if err != nil {
					return errObservation(err), nil
				}
				second, err := cl.AddProjectionPin(ctx, &canvasv1.AddProjectionPinRequest{BoardId: id, Kind: canvasv1.ProjectionKind_PROJECTION_KIND_PLAN_CARD, TargetRef: "plan-card-synthetic"})
				if err != nil {
					return errObservation(err), nil
				}
				if _, err := cl.RemoveProjectionPin(ctx, &canvasv1.RemoveProjectionPinRequest{PinId: first.GetPin().GetPinId()}); err != nil {
					return errObservation(err), nil
				}
				_, absentErr := cl.RemoveProjectionPin(ctx, &canvasv1.RemoveProjectionPinRequest{PinId: first.GetPin().GetPinId()})
				pins, err := cl.ListProjectionPins(ctx, &canvasv1.ListProjectionPinsRequest{BoardId: id})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("remove_absent_status", status.Code(absentErr).String())
				obs.Setf("pin_count_after_remove", "%d", len(pins.GetPins()))
				obs.Setf("survivor_is_second", "%t", len(pins.GetPins()) == 1 && pins.GetPins()[0].GetPinId() == second.GetPin().GetPinId())
				obs.Set("survivor_kind", surviveKind(pins.GetPins()))
				return obs, nil
			},
		},
		{
			// ListBoardHistory is a PRODUCT feature, NOT the audit chain (doc 17 §9):
			// a create + update produce history entries, ordered deterministically by
			// entry_id, each carrying the board_id and a non-empty summary. The
			// observation records the COUNT and well-formedness, not the audit
			// semantics (there are none — this is product history).
			Name: "history/create-and-update-produce-product-history",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				board, err := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: synthOrg, Name: synthBoardName})
				if err != nil {
					return errObservation(err), nil
				}
				id := board.GetBoard().GetBoardId()
				if _, err := cl.UpdateBoard(ctx, &canvasv1.UpdateBoardRequest{BoardId: id, Name: "history-renamed"}); err != nil {
					return errObservation(err), nil
				}
				hist, err := cl.ListBoardHistory(ctx, &canvasv1.ListBoardHistoryRequest{BoardId: id})
				if err != nil {
					return errObservation(err), nil
				}
				entries := hist.GetEntries()
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("entry_count", "%d", len(entries))
				wellFormed, ordered := true, true
				var prevID string
				for i, e := range entries {
					if e.GetBoardId() != id || e.GetSummary() == "" || e.GetActorPrincipalId() == "" {
						wellFormed = false
					}
					if i > 0 && e.GetEntryId() <= prevID {
						ordered = false
					}
					prevID = e.GetEntryId()
				}
				obs.Setf("entries_well_formed", "%t", wellFormed)
				obs.Setf("entries_ordered_by_id", "%t", ordered)
				obs.Set("next_page_token", hist.GetNextPageToken())
				return obs, nil
			},
		},
		{
			// Argument validation is part of the contract surface a faithful fake
			// must mirror: CreateBoard with no org_id is refused (org RBAC scope,
			// D61); GrantBoardRole / AddProjectionPin / GetBoard with missing
			// required keys are refused; a get of an unknown board is NotFound. Each
			// refusal's gRPC status code is recorded so the fake and real impl must
			// agree on the whole refusal surface.
			Name: "validation/missing-required-fields-refused",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := canvasv1.NewBoardServiceClient(conn)
				_, noOrg := cl.CreateBoard(ctx, &canvasv1.CreateBoardRequest{Name: synthBoardName})
				_, noGrantPrin := cl.GrantBoardRole(ctx, &canvasv1.GrantBoardRoleRequest{BoardId: "brd-synthetic-unknown", Role: canvasv1.BoardRole_BOARD_ROLE_VIEWER})
				_, noPinBoard := cl.AddProjectionPin(ctx, &canvasv1.AddProjectionPinRequest{Kind: canvasv1.ProjectionKind_PROJECTION_KIND_SESSION_TILE, TargetRef: synthTargetRef})
				_, noGetID := cl.GetBoard(ctx, &canvasv1.GetBoardRequest{})
				_, unknownBoard := cl.GetBoard(ctx, &canvasv1.GetBoardRequest{BoardId: "brd-synthetic-unknown"})
				obs := dualrun.NewObservation()
				obs.Set("create_no_org_status", status.Code(noOrg).String())
				obs.Set("grant_no_principal_status", status.Code(noGrantPrin).String())
				obs.Set("addpin_no_board_status", status.Code(noPinBoard).String())
				obs.Set("get_no_id_status", status.Code(noGetID).String())
				obs.Set("get_unknown_board_status", status.Code(unknownBoard).String())
				return obs, nil
			},
		},
	}
}

// surviveKind renders the single surviving pin's kind (or "none") as a stable
// observation field.
func surviveKind(pins []*canvasv1.ProjectionPin) string {
	if len(pins) != 1 {
		return "none"
	}
	return pins[0].GetKind().String()
}

// --- observation builders ----------------------------------------------------

func errObservation(err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", status.Code(err).String())
	return obs
}

// --- dialers: real reference impl AND the generated fake --------------------
//
// Both dialers stand up the SAME honest BoardService behavior — the only thing
// that varies across the two dual-run passes is which server is registered. The
// fake is programmed at a fresh mirror RefImpl so its canned responders ARE the
// honest reference behavior, driven only through the fake's responder surface
// (doc 06 §2.1). The dual-run proves the fake is observationally identical to the
// real impl on every scenario.

// RealDialer returns the dual-run Dialer for the reference impl.
func RealDialer() dualrun.Dialer {
	impl := NewRefImpl()
	return dualrun.InProcess(impl.Register)
}

// FakeDialer returns the dual-run Dialer for the GENERATED programmable fake,
// programmed to the same contract by routing its per-verb responders at a mirror
// RefImpl — so the fake and the real impl share one honest behavior definition.
func FakeDialer() dualrun.Dialer {
	f := ProgrammedFake(NewRefImpl())
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		canvasv1fake.RegisterBoardService(s, f)
	})
}

// ProgrammedFake programs the generated BoardServiceFake at the given mirror
// RefImpl so every per-verb responder IS the honest reference behavior. It is
// exported so the negative drift-gate dialer (external _test) can build the same
// honestly-programmed fake before injecting its single drift on one responder.
func ProgrammedFake(mirror *RefImpl) *canvasv1fake.BoardServiceFake {
	f := canvasv1fake.NewBoardServiceFake()
	f.CreateBoardResponder = mirror.CreateBoard
	f.GetBoardResponder = mirror.GetBoard
	f.UpdateBoardResponder = mirror.UpdateBoard
	f.DeleteBoardResponder = mirror.DeleteBoard
	f.ListBoardsResponder = mirror.ListBoards
	f.GrantBoardRoleResponder = mirror.GrantBoardRole
	f.RevokeBoardRoleResponder = mirror.RevokeBoardRole
	f.ListBoardGrantsResponder = mirror.ListBoardGrants
	f.AddProjectionPinResponder = mirror.AddProjectionPin
	f.UpdateProjectionPinResponder = mirror.UpdateProjectionPin
	f.RemoveProjectionPinResponder = mirror.RemoveProjectionPin
	f.ListProjectionPinsResponder = mirror.ListProjectionPins
	f.ListBoardHistoryResponder = mirror.ListBoardHistory
	return f
}
