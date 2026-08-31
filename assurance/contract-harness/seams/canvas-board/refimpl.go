// SPDX-License-Identifier: Apache-2.0

package canvasboard

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	canvasv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/canvas/v1"
)

// RefImpl is a minimal honest reference implementation of BoardService — the
// "real implementation" side of the dual-run. It implements exactly the doc 17
// §10 contract: org-scoped board CRUD; role grants that ride org RBAC (D61, no
// parallel ACL — a re-grant updates the role in place); read-only projection-pin
// management (doc 17 §3.1 — every pin is a read-only projection, never a writer
// seam); and a board-history listing that is a PRODUCT feature, not the audit
// chain (doc 17 §9). The structural invariant holds: no BoardService message
// carries session input (doc 17 §7), so RefImpl never reads or writes any session
// channel.
//
// This is the M0/M2 stand-in until the production paid/canvas/ BoardService
// server lands (D87 CONTRACTS-NOW, BUILD-AT-M2). When that lands it replaces
// RefImpl as the "real" end and the conformance suite is unchanged — which is the
// whole point: the suite is the contract, not the implementation.
//
// All identifiers (board_id, pin_id, history entry_id, timestamps) are
// DETERMINISTIC functions of a per-store monotonic counter, so two independent
// processes (the real impl and a fake mirror) that replay the same scenarios in
// the same order observe byte-identically — a wall clock or random UUID would
// diverge across the two dual-run passes (D50, synthetic fixtures only). State is
// held in-memory; access is mutex-guarded so the in-process gRPC server is safe
// under concurrent calls.
type RefImpl struct {
	canvasv1.UnimplementedBoardServiceServer

	mu sync.Mutex

	seq     uint64 // monotonic id/timestamp source (deterministic, not a wall clock)
	boards  map[string]*canvasv1.Board
	grants  map[string][]*canvasv1.BoardGrant    // board_id -> grants (insertion order)
	pins    map[string][]*canvasv1.ProjectionPin // board_id -> pins (insertion order)
	history map[string][]*canvasv1.BoardHistoryEntry
}

// NewRefImpl returns a reference BoardService server with empty state.
func NewRefImpl() *RefImpl {
	return &RefImpl{
		boards:  map[string]*canvasv1.Board{},
		grants:  map[string][]*canvasv1.BoardGrant{},
		pins:    map[string][]*canvasv1.ProjectionPin{},
		history: map[string][]*canvasv1.BoardHistoryEntry{},
	}
}

// Register registers the reference impl on a grpc.ServiceRegistrar.
func (s *RefImpl) Register(reg grpc.ServiceRegistrar) {
	canvasv1.RegisterBoardServiceServer(reg, s)
}

// --- deterministic synthetic derivations (D50) ------------------------------
//
// nextSeq advances the per-store monotonic counter under s.mu and returns the new
// value. Every synthetic id and timestamp is derived from it, so the reference
// impl and a fake mirror that replay the same scenarios in the same order produce
// byte-identical observations.
func (s *RefImpl) nextSeq() uint64 {
	s.seq++
	return s.seq
}

// synthEpochBase is an obviously-synthetic fixed unix-seconds base; timestamps
// are base+seq so the Board.created_at/updated_at comparison is stable across the
// real impl and the fake (a wall clock would diverge between two processes).
const synthEpochBase = uint64(1_700_000_000)

func boardIDFor(seq uint64) string   { return fmt.Sprintf("brd-synthetic-%08d", seq) }
func pinIDFor(seq uint64) string     { return fmt.Sprintf("pin-synthetic-%08d", seq) }
func historyIDFor(seq uint64) string { return fmt.Sprintf("bhe-synthetic-%08d", seq) }
func synthStamp(seq uint64) uint64   { return synthEpochBase + seq }

// recordHistoryLocked appends a synthetic product-history entry for a board
// mutation (doc 17 §9 — a product feature, NOT the audit chain). Caller holds
// s.mu.
func (s *RefImpl) recordHistoryLocked(boardID, actorPrincipal, summary string) {
	seq := s.nextSeq()
	s.history[boardID] = append(s.history[boardID], &canvasv1.BoardHistoryEntry{
		EntryId:          historyIDFor(seq),
		BoardId:          boardID,
		ActorPrincipalId: actorPrincipal,
		Summary:          summary,
		At:               synthStamp(seq),
	})
}

// --- Board CRUD -------------------------------------------------------------

// CreateBoard creates an org-scoped arrangement surface (doc 17 §10). org_id is
// required — the board scopes to org RBAC (D61, no parallel ACL); the board is
// assigned a deterministic synthetic id and creation/update stamps.
func (s *RefImpl) CreateBoard(_ context.Context, req *canvasv1.CreateBoardRequest) (*canvasv1.CreateBoardResponse, error) {
	if req.GetOrgId() == "" {
		return nil, status.Error(codes.InvalidArgument, "CreateBoardRequest.org_id is required (org RBAC scope, D61)")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "CreateBoardRequest.name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.nextSeq()
	id := boardIDFor(seq)
	board := &canvasv1.Board{
		BoardId:     id,
		OrgId:       req.GetOrgId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		CreatedAt:   synthStamp(seq),
		UpdatedAt:   synthStamp(seq),
	}
	s.boards[id] = board
	s.recordHistoryLocked(id, req.GetOrgId(), "board created")
	return &canvasv1.CreateBoardResponse{Board: cloneBoard(board)}, nil
}

// GetBoard reads a board by id (doc 17 §10). A missing board is NotFound.
func (s *RefImpl) GetBoard(_ context.Context, req *canvasv1.GetBoardRequest) (*canvasv1.GetBoardResponse, error) {
	if req.GetBoardId() == "" {
		return nil, status.Error(codes.InvalidArgument, "GetBoardRequest.board_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	board, ok := s.boards[req.GetBoardId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "board %q not found", req.GetBoardId())
	}
	return &canvasv1.GetBoardResponse{Board: cloneBoard(board)}, nil
}

// UpdateBoard updates a board's product metadata (name/description) — arrangement
// is canvas-truth, NOT a write into any projected session (doc 17 §5, the
// structural invariant). updated_at advances to the new monotonic stamp.
func (s *RefImpl) UpdateBoard(_ context.Context, req *canvasv1.UpdateBoardRequest) (*canvasv1.UpdateBoardResponse, error) {
	if req.GetBoardId() == "" {
		return nil, status.Error(codes.InvalidArgument, "UpdateBoardRequest.board_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	board, ok := s.boards[req.GetBoardId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "board %q not found", req.GetBoardId())
	}
	board.Name = req.GetName()
	board.Description = req.GetDescription()
	board.UpdatedAt = synthStamp(s.nextSeq())
	s.recordHistoryLocked(board.GetBoardId(), board.GetOrgId(), "board updated")
	return &canvasv1.UpdateBoardResponse{Board: cloneBoard(board)}, nil
}

// DeleteBoard deletes a board and its grants/pins/history (doc 17 §10). A missing
// board is NotFound.
func (s *RefImpl) DeleteBoard(_ context.Context, req *canvasv1.DeleteBoardRequest) (*canvasv1.DeleteBoardResponse, error) {
	if req.GetBoardId() == "" {
		return nil, status.Error(codes.InvalidArgument, "DeleteBoardRequest.board_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.boards[req.GetBoardId()]; !ok {
		return nil, status.Errorf(codes.NotFound, "board %q not found", req.GetBoardId())
	}
	delete(s.boards, req.GetBoardId())
	delete(s.grants, req.GetBoardId())
	delete(s.pins, req.GetBoardId())
	delete(s.history, req.GetBoardId())
	return &canvasv1.DeleteBoardResponse{}, nil
}

// ListBoards lists the boards in an org (doc 17 §10), ordered deterministically
// by board_id so the observation is stable across both ends. Pagination is the
// frozen page_size/page_token shape; this reference serves a single page (the
// synthetic fixtures never exceed it) and returns an empty next_page_token.
func (s *RefImpl) ListBoards(_ context.Context, req *canvasv1.ListBoardsRequest) (*canvasv1.ListBoardsResponse, error) {
	if req.GetOrgId() == "" {
		return nil, status.Error(codes.InvalidArgument, "ListBoardsRequest.org_id is required (org RBAC scope, D61)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*canvasv1.Board, 0, len(s.boards))
	for _, b := range s.boards {
		if b.GetOrgId() == req.GetOrgId() {
			out = append(out, cloneBoard(b))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetBoardId() < out[j].GetBoardId() })
	return &canvasv1.ListBoardsResponse{Boards: out}, nil
}

// --- Role grants / sharing (org RBAC, D61 — no parallel ACL) -----------------

// GrantBoardRole grants a board-scoped role to a principal (doc 17 §10). Grants
// ride org RBAC (D61, no parallel ACL system): a re-grant of the SAME principal
// UPDATES the role in place rather than appending a second grant row.
func (s *RefImpl) GrantBoardRole(_ context.Context, req *canvasv1.GrantBoardRoleRequest) (*canvasv1.GrantBoardRoleResponse, error) {
	if req.GetBoardId() == "" {
		return nil, status.Error(codes.InvalidArgument, "GrantBoardRoleRequest.board_id is required")
	}
	if req.GetPrincipalId() == "" {
		return nil, status.Error(codes.InvalidArgument, "GrantBoardRoleRequest.principal_id is required")
	}
	if req.GetRole() == canvasv1.BoardRole_BOARD_ROLE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "GrantBoardRoleRequest.role must be specified")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.boards[req.GetBoardId()]; !ok {
		return nil, status.Errorf(codes.NotFound, "board %q not found", req.GetBoardId())
	}
	grants := s.grants[req.GetBoardId()]
	for _, g := range grants {
		if g.GetPrincipalId() == req.GetPrincipalId() {
			g.Role = req.GetRole() // in-place update — no parallel ACL (D61)
			return &canvasv1.GrantBoardRoleResponse{Grant: cloneGrant(g)}, nil
		}
	}
	grant := &canvasv1.BoardGrant{
		BoardId:     req.GetBoardId(),
		PrincipalId: req.GetPrincipalId(),
		Role:        req.GetRole(),
	}
	s.grants[req.GetBoardId()] = append(grants, grant)
	return &canvasv1.GrantBoardRoleResponse{Grant: cloneGrant(grant)}, nil
}

// RevokeBoardRole revokes a principal's grant on a board (doc 17 §10). A revoke
// of a principal with no grant is NotFound (the grant must exist to be revoked).
func (s *RefImpl) RevokeBoardRole(_ context.Context, req *canvasv1.RevokeBoardRoleRequest) (*canvasv1.RevokeBoardRoleResponse, error) {
	if req.GetBoardId() == "" {
		return nil, status.Error(codes.InvalidArgument, "RevokeBoardRoleRequest.board_id is required")
	}
	if req.GetPrincipalId() == "" {
		return nil, status.Error(codes.InvalidArgument, "RevokeBoardRoleRequest.principal_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	grants := s.grants[req.GetBoardId()]
	for i, g := range grants {
		if g.GetPrincipalId() == req.GetPrincipalId() {
			s.grants[req.GetBoardId()] = append(grants[:i:i], grants[i+1:]...)
			return &canvasv1.RevokeBoardRoleResponse{}, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "no grant for principal %q on board %q", req.GetPrincipalId(), req.GetBoardId())
}

// ListBoardGrants lists a board's grants (doc 17 §10), ordered deterministically
// by principal_id so the observation is stable across both ends.
func (s *RefImpl) ListBoardGrants(_ context.Context, req *canvasv1.ListBoardGrantsRequest) (*canvasv1.ListBoardGrantsResponse, error) {
	if req.GetBoardId() == "" {
		return nil, status.Error(codes.InvalidArgument, "ListBoardGrantsRequest.board_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.grants[req.GetBoardId()]
	out := make([]*canvasv1.BoardGrant, 0, len(src))
	for _, g := range src {
		out = append(out, cloneGrant(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetPrincipalId() < out[j].GetPrincipalId() })
	return &canvasv1.ListBoardGrantsResponse{Grants: out}, nil
}

// --- Projection-pin management (read-only projections, doc 17 §3.1) ----------

// AddProjectionPin adds a read-only projection pin to a board (doc 17 §3.1 —
// SESSION_TILE / FLEET_TREE_NODE / PLAN_CARD; none is a writer seam). The pin is
// assigned a deterministic synthetic id.
func (s *RefImpl) AddProjectionPin(_ context.Context, req *canvasv1.AddProjectionPinRequest) (*canvasv1.AddProjectionPinResponse, error) {
	if req.GetBoardId() == "" {
		return nil, status.Error(codes.InvalidArgument, "AddProjectionPinRequest.board_id is required")
	}
	if req.GetKind() == canvasv1.ProjectionKind_PROJECTION_KIND_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "AddProjectionPinRequest.kind must be specified (read-only projection, doc 17 §3.1)")
	}
	if req.GetTargetRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "AddProjectionPinRequest.target_ref is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.boards[req.GetBoardId()]; !ok {
		return nil, status.Errorf(codes.NotFound, "board %q not found", req.GetBoardId())
	}
	pin := &canvasv1.ProjectionPin{
		PinId:     pinIDFor(s.nextSeq()),
		BoardId:   req.GetBoardId(),
		Kind:      req.GetKind(),
		TargetRef: req.GetTargetRef(),
		Position:  clonePosition(req.GetPosition()),
	}
	s.pins[req.GetBoardId()] = append(s.pins[req.GetBoardId()], pin)
	return &canvasv1.AddProjectionPinResponse{Pin: clonePin(pin)}, nil
}

// UpdateProjectionPin updates a pin's position (rearrangement is canvas-truth,
// NOT a write into the projected target — the structural invariant holds, doc 17
// §5). A missing pin is NotFound.
func (s *RefImpl) UpdateProjectionPin(_ context.Context, req *canvasv1.UpdateProjectionPinRequest) (*canvasv1.UpdateProjectionPinResponse, error) {
	if req.GetPinId() == "" {
		return nil, status.Error(codes.InvalidArgument, "UpdateProjectionPinRequest.pin_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if pin := s.findPinLocked(req.GetPinId()); pin != nil {
		pin.Position = clonePosition(req.GetPosition())
		return &canvasv1.UpdateProjectionPinResponse{Pin: clonePin(pin)}, nil
	}
	return nil, status.Errorf(codes.NotFound, "pin %q not found", req.GetPinId())
}

// RemoveProjectionPin removes a pin (doc 17 §10). A missing pin is NotFound.
func (s *RefImpl) RemoveProjectionPin(_ context.Context, req *canvasv1.RemoveProjectionPinRequest) (*canvasv1.RemoveProjectionPinResponse, error) {
	if req.GetPinId() == "" {
		return nil, status.Error(codes.InvalidArgument, "RemoveProjectionPinRequest.pin_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for boardID, pins := range s.pins {
		for i, p := range pins {
			if p.GetPinId() == req.GetPinId() {
				s.pins[boardID] = append(pins[:i:i], pins[i+1:]...)
				return &canvasv1.RemoveProjectionPinResponse{}, nil
			}
		}
	}
	return nil, status.Errorf(codes.NotFound, "pin %q not found", req.GetPinId())
}

// ListProjectionPins lists a board's pins (doc 17 §10), ordered deterministically
// by pin_id so the observation is stable across both ends.
func (s *RefImpl) ListProjectionPins(_ context.Context, req *canvasv1.ListProjectionPinsRequest) (*canvasv1.ListProjectionPinsResponse, error) {
	if req.GetBoardId() == "" {
		return nil, status.Error(codes.InvalidArgument, "ListProjectionPinsRequest.board_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.pins[req.GetBoardId()]
	out := make([]*canvasv1.ProjectionPin, 0, len(src))
	for _, p := range src {
		out = append(out, clonePin(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetPinId() < out[j].GetPinId() })
	return &canvasv1.ListProjectionPinsResponse{Pins: out}, nil
}

// --- Board history (PRODUCT feature, NOT the audit chain, doc 17 §9) ---------

// ListBoardHistory lists a board's product-history entries (doc 17 §9 — a product
// feature, explicitly NOT the audit chain), ordered deterministically by entry_id
// so the observation is stable across both ends.
func (s *RefImpl) ListBoardHistory(_ context.Context, req *canvasv1.ListBoardHistoryRequest) (*canvasv1.ListBoardHistoryResponse, error) {
	if req.GetBoardId() == "" {
		return nil, status.Error(codes.InvalidArgument, "ListBoardHistoryRequest.board_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.history[req.GetBoardId()]
	out := make([]*canvasv1.BoardHistoryEntry, 0, len(src))
	for _, e := range src {
		out = append(out, cloneHistory(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetEntryId() < out[j].GetEntryId() })
	return &canvasv1.ListBoardHistoryResponse{Entries: out}, nil
}

// findPinLocked returns the live pin with the given id, or nil. Caller holds s.mu.
func (s *RefImpl) findPinLocked(pinID string) *canvasv1.ProjectionPin {
	for _, pins := range s.pins {
		for _, p := range pins {
			if p.GetPinId() == pinID {
				return p
			}
		}
	}
	return nil
}

// --- defensive clones -------------------------------------------------------
//
// Every contract response returns a clone of the stored proto so a client that
// mutates a returned message cannot corrupt the reference impl's state — and so
// the fake mirror, which shares this RefImpl, observes the same isolation.

func cloneBoard(b *canvasv1.Board) *canvasv1.Board {
	if b == nil {
		return nil
	}
	return &canvasv1.Board{
		BoardId:     b.GetBoardId(),
		OrgId:       b.GetOrgId(),
		Name:        b.GetName(),
		Description: b.GetDescription(),
		CreatedAt:   b.GetCreatedAt(),
		UpdatedAt:   b.GetUpdatedAt(),
	}
}

func cloneGrant(g *canvasv1.BoardGrant) *canvasv1.BoardGrant {
	if g == nil {
		return nil
	}
	return &canvasv1.BoardGrant{
		BoardId:     g.GetBoardId(),
		PrincipalId: g.GetPrincipalId(),
		Role:        g.GetRole(),
	}
}

func clonePosition(p *canvasv1.PinPosition) *canvasv1.PinPosition {
	if p == nil {
		return nil
	}
	return &canvasv1.PinPosition{
		X:      p.GetX(),
		Y:      p.GetY(),
		Width:  p.GetWidth(),
		Height: p.GetHeight(),
	}
}

func clonePin(p *canvasv1.ProjectionPin) *canvasv1.ProjectionPin {
	if p == nil {
		return nil
	}
	return &canvasv1.ProjectionPin{
		PinId:     p.GetPinId(),
		BoardId:   p.GetBoardId(),
		Kind:      p.GetKind(),
		TargetRef: p.GetTargetRef(),
		Position:  clonePosition(p.GetPosition()),
	}
}

func cloneHistory(e *canvasv1.BoardHistoryEntry) *canvasv1.BoardHistoryEntry {
	if e == nil {
		return nil
	}
	return &canvasv1.BoardHistoryEntry{
		EntryId:          e.GetEntryId(),
		BoardId:          e.GetBoardId(),
		ActorPrincipalId: e.GetActorPrincipalId(),
		Summary:          e.GetSummary(),
		At:               e.GetAt(),
	}
}

// rolesSummary renders a board's grants as a deterministic principal=role list,
// a helper the suite uses to record the grant set as one stable observation field
// regardless of map ordering.
func rolesSummary(grants []*canvasv1.BoardGrant) string {
	parts := make([]string, 0, len(grants))
	for _, g := range grants {
		parts = append(parts, g.GetPrincipalId()+"="+g.GetRole().String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
