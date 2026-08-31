// SPDX-License-Identifier: Apache-2.0

// Served-RPC dual-run for the GrantFetchService bind (doc 16 §4 step-4 / §5.1/§9;
// doc 06 §2.1 fakes-first dual-run; D24/D14/D50).
//
// WHAT THIS PROVES. wire_test.go's dual-run ran the conformance suite against the
// in-process Service.FetchWire and against the generated *fake* delegating to it.
// This file adds the THIRD driver the wave exists for: the ACTUAL served RPC. The
// Server adapter (server.go) is registered on a real grpc.Server over an
// in-process bufconn pipe, and a real GrantFetchServiceClient dials it. The same
// conformance suite (runWireSuite, shared from wire_test.go) then runs against
// both the in-process model and the served RPC; both must produce field-for-field
// identical GrantFetchResponses for every case — closing the loop from "the seam
// SHAPE is right" to "the served RPC the ds-tlsproxy swap executor calls is right".
//
// SYNTHETIC ONLY (D50). bufconn is an in-memory pipe — no socket, no off-box
// transport, no live KV. The credentials are the same synthetic swap-class
// fixtures wire_test.go warms. The only thing that varies between the two suite
// passes is whether the request crosses the bufconn-served grpc.Server or is
// handed straight to FetchWire — so any divergence is attributable to the bind,
// not the plumbing (the assurance/contract-harness/dualrun InProcess principle).
//
// ADDITIVE: this file adds coverage; it weakens no existing Service / wire /
// grantref / kvbackend assertion. It reuses wire_test.go's wireCase, runWireSuite,
// newWarmedWireService, wireRef, fixedUnix, and the wire* constants.
package grantservice

import (
	"context"
	"net"
	"testing"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// bufServeGrantFetch stands the Server adapter up on a real grpc.Server over an
// in-process bufconn listener and dials a real GrantFetchServiceClient at it. It
// returns the client and a cleanup func. The transport is an in-memory pipe
// (D50 — no off-box socket); only the registered server distinguishes this from
// the in-process model, so a divergence is attributable to the bind.
func bufServeGrantFetch(t *testing.T, svc *Service) (identityv1.GrantFetchServiceClient, func()) {
	t.Helper()

	const bufSize = 1 << 20 // 1 MiB in-process pipe buffer
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	identityv1.RegisterGrantFetchServiceServer(srv, NewServer(svc))

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		<-serveErr
		t.Fatalf("bufconn dial: %v", err)
	}

	stop := func() {
		_ = conn.Close()
		srv.GracefulStop()
		<-serveErr
		_ = lis.Close()
	}
	return identityv1.NewGrantFetchServiceClient(conn), stop
}

// TestServedRPC_DualRun is the served-RPC dual-run: the shared conformance suite
// (runWireSuite, from wire_test.go) runs against the in-process Service.FetchWire
// AND against the SAME logical Service exposed through the bufconn-served Server
// adapter. Both must satisfy every case identically — proving the registered
// GrantFetchServiceServer delegates to FetchWire field-for-field over a real RPC
// (doc 06 §2.1; D24/D14).
func TestServedRPC_DualRun(t *testing.T) {
	// Driver 1: the in-process model — the real Service via the wire adapter.
	model := newWarmedWireService(t)
	runWireSuite(t, "model", model.FetchWire)

	// Driver 2: the ACTUAL served RPC — a fresh, identically-warmed Service bound
	// behind the Server adapter and reached over bufconn by a real generated
	// client. The closure adapts the (ctx, req)->(resp, err) client surface to the
	// suite's req->resp shape, asserting the transport never errors: the deny/stall
	// split rides GrantFetchResponse.reason in-band (open-question default #2), so a
	// gRPC status here would be a genuine transport fault, not a fetch outcome.
	served := newWarmedWireService(t)
	client, stop := bufServeGrantFetch(t, served)
	defer stop()

	runWireSuite(t, "served", func(req *identityv1.GrantFetchRequest) *identityv1.GrantFetchResponse {
		resp, err := client.Fetch(context.Background(), req)
		if err != nil {
			t.Fatalf("served Fetch returned a transport error (the contract rides the in-band reason, never a status): %v", err)
		}
		return resp
	})
}

// TestServedRPC_MatchesInProcessFieldForField pins that, for one canonical
// success case, the served RPC response equals the in-process FetchWire response
// field-for-field — the explicit "served == model" claim the dual-run makes per
// case, asserted here on every field of the success path (the only path carrying a
// credential/class/issued/expiry to compare).
func TestServedRPC_MatchesInProcessFieldForField(t *testing.T) {
	req := &identityv1.GrantFetchRequest{
		SessionUuid:            wireSession,
		ServiceId:              wireService,
		GrantRef:               wireRef(),
		GrantExpiryUnixSeconds: fixedUnix(),
	}

	model := newWarmedWireService(t)
	want := model.FetchWire(req)

	served := newWarmedWireService(t)
	client, stop := bufServeGrantFetch(t, served)
	defer stop()

	got, err := client.Fetch(context.Background(), req)
	if err != nil {
		t.Fatalf("served Fetch errored: %v", err)
	}

	if got.GetReason() != want.GetReason() {
		t.Fatalf("reason: served %v, model %v", got.GetReason(), want.GetReason())
	}
	if got.GetCredentialClass() != want.GetCredentialClass() {
		t.Fatalf("credential_class: served %v, model %v", got.GetCredentialClass(), want.GetCredentialClass())
	}
	if got.GetIssuedServiceId() != want.GetIssuedServiceId() {
		t.Fatalf("issued_service_id: served %q, model %q", got.GetIssuedServiceId(), want.GetIssuedServiceId())
	}
	if got.GetGrantExpiryUnixSeconds() != want.GetGrantExpiryUnixSeconds() {
		t.Fatalf("grant_expiry echo: served %d, model %d", got.GetGrantExpiryUnixSeconds(), want.GetGrantExpiryUnixSeconds())
	}
	if string(got.GetCredential().GetSecret()) != string(want.GetCredential().GetSecret()) {
		t.Fatalf("secret: served %q, model %q", got.GetCredential().GetSecret(), want.GetCredential().GetSecret())
	}
	if got.GetCredential().GetLocation() != want.GetCredential().GetLocation() {
		t.Fatalf("location: served %q, model %q", got.GetCredential().GetLocation(), want.GetCredential().GetLocation())
	}
}

// TestServedRPC_StallVsDeny pins that the §5.1 stall-vs-deny split survives the
// served RPC: a NEW fetch during a store outage stalls (REASON_STORE_UNAVAILABLE,
// ReasonIsStall) while an in-flight cached grant rides the outage as OK — both
// observed over the real RPC, never via the in-process model. This guards that
// the bind preserves backend.go's ErrStoreUnavailable-vs-deny distinction in-band
// across the transport.
func TestServedRPC_StallVsDeny(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC) }
	be := NewInMemoryBackend(map[string]Credential{
		wireRef(): {Secret: []byte(wireSecret), Location: "Authorization"},
	})
	svc := New(be, WithClock(clock))
	svc.RegisterSession(wireSession, clock().Add(2*time.Hour))

	client, stop := bufServeGrantFetch(t, svc)
	defer stop()
	ctx := context.Background()

	// Warm the in-flight session's grant over the wire before the outage.
	warm, err := client.Fetch(ctx, &identityv1.GrantFetchRequest{SessionUuid: wireSession, ServiceId: wireService, GrantRef: wireRef(), GrantExpiryUnixSeconds: fixedUnix()})
	if err != nil {
		t.Fatalf("warm served fetch errored: %v", err)
	}
	if warm.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK {
		t.Fatalf("warm served fetch must be OK, got %v", warm.GetReason())
	}

	// Store goes down.
	be.SetAvailable(false)

	// In-flight cached grant rides the outage — still OK over the wire.
	rode, err := client.Fetch(ctx, &identityv1.GrantFetchRequest{SessionUuid: wireSession, ServiceId: wireService, GrantRef: wireRef(), GrantExpiryUnixSeconds: fixedUnix()})
	if err != nil {
		t.Fatalf("ride served fetch errored: %v", err)
	}
	if rode.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK {
		t.Fatalf("cached grant must ride the outage as OK over the wire, got %v", rode.GetReason())
	}

	// A NEW session's NEW fetch STALLS (retryable) during the outage, in-band.
	newSession := "00000000-0000-4000-8000-0000000000b2"
	svc.RegisterSession(newSession, clock().Add(2*time.Hour))
	stall, err := client.Fetch(ctx, &identityv1.GrantFetchRequest{SessionUuid: newSession, ServiceId: wireService, GrantRef: FormatGrantRef(newSession, wireService), GrantExpiryUnixSeconds: fixedUnix()})
	if err != nil {
		t.Fatalf("stall served fetch returned a transport error; the stall must ride the in-band reason: %v", err)
	}
	if stall.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE {
		t.Fatalf("new fetch during outage must stall over the wire, got %v", stall.GetReason())
	}
	if !ReasonIsStall(stall.GetReason()) {
		t.Fatal("served store-unavailable must classify as a STALL (retryable)")
	}
	if ReasonIsDeny(stall.GetReason()) {
		t.Fatal("a served stall must not classify as a deny")
	}
	if stall.GetCredential() != nil && len(stall.GetCredential().GetSecret()) != 0 {
		t.Fatal("a served stall must carry no secret")
	}
}
