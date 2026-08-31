// SPDX-License-Identifier: Apache-2.0

// The in-process gRPC server adapter that BINDS the FROZEN GrantFetchService onto
// this module's Service (doc 16 §4 step-4 / §5.1/§9; D39/D55/D80).
//
// WHAT THIS IS. wire.go repointed the in-process Go model onto the frozen
// GrantFetchService generated types (FetchWire: GrantFetchRequest ->
// GrantFetchResponse), but registered/served NO GrantFetchServiceServer — the
// dual-run there delegated through the generated *fake*, never an actual served
// RPC. This file closes that loop: a thin GrantFetchServiceServer adapter that
// embeds proto/gen/go's UnimplementedGrantFetchServiceServer (the D-style
// forward-compatibility embed the generated RegisterGrantFetchServiceServer
// requires) and delegates Fetch field-for-field to Service.FetchWire. Registered
// on a grpc.Server, this is the EXACT substrate the ds-tlsproxy SWAP EXECUTOR
// calls over the wire (doc 16 §9 grant-fetch row: "Consumers: ds-tlsproxy swap
// executor"; doc 16 §4 step-4 / §5.1 — the per-session cache-miss fetch leg).
//
// PURE ADAPTER — NO ADDED BEHAVIOR. The handler is a one-line delegation to
// FetchWire, which is itself a pure adapter over Service.Fetch. Every
// cache/outage/lifecycle property the existing Service and wire tests pin
// (service.go, wire_test.go) therefore holds UNCHANGED through the served RPC.
//
// IN-BAND FAILURE SURFACE (open-question default #2; wire.go). The five Go errors
// already fold into GrantFetchResponse.reason inside FetchWire, so this handler
// NEVER returns a gRPC status error for a documented deny/stall — it returns
// (response, nil) and lets the caller branch via ReasonIsStall/ReasonIsDeny. A
// gRPC status from this server would mean a genuine transport fault, not a
// fetch-domain outcome. The contract therefore rides the response, exactly as the
// generated fake's Fetch did in wire_test.go.
//
// PROTO FROZEN / D80. The generated types arrive via the one legal cross-tree
// import (proto/gen/go, require+replace in go.mod); this file consumes them and
// touches no proto body. SYNTHETIC only (D50) — the adapter is transport-agnostic;
// server_test.go exercises it over an in-process bufconn pipe, never a live
// off-box transport.
package grantservice

import (
	"context"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// Server is the GrantFetchServiceServer adapter binding the frozen
// GrantFetchService RPC surface onto a Service. It embeds
// UnimplementedGrantFetchServiceServer (required by the generated
// RegisterGrantFetchServiceServer for forward compatibility) and holds the
// Service it delegates to. Construct it with NewServer and register it with
// identityv1.RegisterGrantFetchServiceServer.
type Server struct {
	identityv1.UnimplementedGrantFetchServiceServer
	svc *Service
}

// NewServer wraps a Service in the GrantFetchServiceServer adapter. The Service
// carries the session caches and backend; the returned Server is a stateless
// shim that delegates each Fetch RPC to Service.FetchWire.
func NewServer(svc *Service) *Server {
	return &Server{svc: svc}
}

// Fetch is the served GrantFetchService.Fetch RPC. It delegates field-for-field
// to Service.FetchWire — the same in-process wire adapter the dual-run model
// uses — and returns the response with a nil error: the deny/stall split rides
// GrantFetchResponse.reason in-band (open-question default #2; wire.go), never a
// gRPC status. A served RPC thus yields byte-identical results to the in-process
// FetchWire call, which server_test.go's bufconn dual-run proves.
//
// FetchWire tolerates a nil request (it maps to an all-zero request that fails
// closed through the existing Fetch guards), so this handler adds no nil check of
// its own — keeping it a pure pass-through.
func (s *Server) Fetch(_ context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
	return s.svc.FetchWire(req), nil
}
