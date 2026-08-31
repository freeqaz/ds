// SPDX-License-Identifier: Apache-2.0

package canvasboard_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	canvasboard "github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/canvas-board"

	canvasv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/canvas/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/canvas/v1/canvasv1fake"
)

// TestSeam_RealVsGeneratedFake is the per-commit gate for the canvas.v1
// BoardService seam (doc 17 §10, doc 06 §2.1): the seam's conformance suite runs
// against BOTH the real reference implementation AND the generated programmable
// fake, and the seam is green only if every scenario observes the same thing on
// both. The suite exercises all thirteen unary verbs (board CRUD, role grants
// riding org RBAC, read-only projection-pin management, product-history listing)
// and the properties the board seam turns on — org-scoped CRUD, grants
// updated-in-place under the no-parallel-ACL rule (D61), pins as read-only
// projections (doc 17 §3.1), and history as a product feature not the audit chain
// (doc 17 §9).
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := canvasboard.Suite().Run(context.Background(), canvasboard.RealDialer(), canvasboard.FakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("canvas<->board seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_HarnessCatchesADriftedFake is the negative proof: a fake that drifts
// from the contract — here, a GetBoard responder that MUTATES the returned
// board's name, a contract-observable divergence the CRUD round-trip scenario
// asserts — must fail the seam. Without this, a green dual-run would be
// meaningless: it could be passing because the gate never fires. The drift is
// injected only in this test's local fake, never in the committed generated fake.
func TestSeam_HarnessCatchesADriftedFake(t *testing.T) {
	res, err := canvasboard.Suite().Run(context.Background(), canvasboard.RealDialer(), driftedGetBoardFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a drifted fake passed the seam — the dual-run gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or fake error, got report:\n%s", res.Report())
	}
}

// TestRecordedViaFakeAccessors asserts the board contract directly against the
// generated fake's per-verb *Recorded() call-capture accessors (doc 06 §2.1):
// every CreateBoard / GrantBoardRole that hits the fake is recorded with its
// request, so a downstream consumer can verify "the board was created in this
// org, then granted to this principal with this role". This is the assertion the
// dual-run alone cannot make: the dual-run compares end-observable outcomes; the
// recorded-call surface is what lets a consumer verify the call sequence.
func TestRecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()
	mirror := canvasboard.NewRefImpl()
	f := canvasboard.ProgrammedFake(mirror)

	const org = "org-synthetic-canvas-01"
	const principal = "prin-synthetic-alice"

	created, err := f.CreateBoard(ctx, &canvasv1.CreateBoardRequest{OrgId: org, Name: "board-synthetic-arrangement"})
	if err != nil {
		t.Fatalf("CreateBoard: %v", err)
	}
	if _, err := f.GrantBoardRole(ctx, &canvasv1.GrantBoardRoleRequest{
		BoardId:     created.GetBoard().GetBoardId(),
		PrincipalId: principal,
		Role:        canvasv1.BoardRole_BOARD_ROLE_EDITOR,
	}); err != nil {
		t.Fatalf("GrantBoardRole: %v", err)
	}

	createCalls := f.CreateBoardRecorded()
	if len(createCalls) != 1 {
		t.Fatalf("CreateBoardRecorded: want 1, got %d", len(createCalls))
	}
	if got := createCalls[0].Req.GetOrgId(); got != org {
		t.Fatalf("CreateBoardRecorded[0].org_id = %q, want %q", got, org)
	}
	grantCalls := f.GrantBoardRoleRecorded()
	if len(grantCalls) != 1 {
		t.Fatalf("GrantBoardRoleRecorded: want 1, got %d", len(grantCalls))
	}
	if got := grantCalls[0].Req.GetPrincipalId(); got != principal {
		t.Fatalf("GrantBoardRoleRecorded[0].principal_id = %q, want %q", got, principal)
	}
	if got := grantCalls[0].Req.GetRole(); got != canvasv1.BoardRole_BOARD_ROLE_EDITOR {
		t.Fatalf("GrantBoardRoleRecorded[0].role = %v, want EDITOR", got)
	}
}

// driftedGetBoardFakeDialer programs the generated fake honestly on every verb
// EXCEPT GetBoard, whose responder MUTATES the returned board's name — so the
// CRUD round-trip scenario (CreateBoard then GetBoard) observes a different name
// on the fake than on the real impl. All other verbs are programmed honestly so
// the divergence is attributable to the injected GetBoard drift, isolating
// exactly one defect.
func driftedGetBoardFakeDialer() dualrun.Dialer {
	mirror := canvasboard.NewRefImpl()
	f := canvasboard.ProgrammedFake(mirror)
	honestGet := f.GetBoardResponder
	f.GetBoardResponder = func(ctx context.Context, req *canvasv1.GetBoardRequest) (*canvasv1.GetBoardResponse, error) {
		resp, err := honestGet(ctx, req)
		if err != nil {
			return resp, err
		}
		// DRIFT: corrupt the round-tripped product metadata — the board the fake
		// returns no longer matches what was created, which the CRUD round-trip
		// scenario's recorded name field catches.
		if resp.GetBoard() != nil {
			resp.Board.Name = resp.Board.GetName() + "-DRIFTED"
		}
		return resp, nil
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		canvasv1fake.RegisterBoardService(s, f)
	})
}
