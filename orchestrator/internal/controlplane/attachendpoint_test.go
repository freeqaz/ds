// SPDX-License-Identifier: Apache-2.0

package controlplane

// attachendpoint_test.go proves the gap-3 orchestrator endpoint resolver
// (attachendpoint.go) and its wiring into the Attach RPC (wiring.go):
//
//   - the resolver renders the host-local UDS DIRECT candidate for a PLACED +
//     servable session, with an empty ServerName (the host-local hop has no SNI);
//   - a not-yet-placed / tearing-down session yields ok==false (no fabricated
//     endpoint), and a missing record is no-candidate-no-error (the seat
//     arbitration is the not-found authority), while a real store fault surfaces;
//   - a crafted session UUID can never escape the socket dir (sanitization);
//   - END TO END through the fully-wired ControlPlane: an in-process Attach RPC
//     returns a handle carrying a servable DIRECT (UDS) candidate, so a WRITER
//     seat is offered (not reader-only). This is the acceptance criterion.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// fakeModeReader is a narrow sessionModeReader double: it returns a programmed mode (or a
// programmed error) so the resolver's transport-tag selection is exercised without a real
// on-disk marker store.
type fakeModeReader struct {
	mode  libvirt.SessionMode
	found bool
	err   error
}

func (f fakeModeReader) ModeFor(_ context.Context, _ string) (libvirt.SessionMode, bool, error) {
	return f.mode, f.found, f.err
}

// TestEndpointResolver_TerminalSessionRendersRawTerminal is the U-CPWIRE acceptance: a
// session the host resolved to TERMINAL mode (the shared .ds-session-mode marker) makes the
// orchestrator control-plane resolver tag the endpoint RAW_TERMINAL — on the SAME host-local
// UDS path it would otherwise advertise as DIRECT. Without this the handle carries DIRECT and
// `serpent claude --vm --raw on` falls back to the structured loop (the live-found bug). The
// address render is identical to the structured case (only the transport enum differs).
func TestEndpointResolver_TerminalSessionRendersRawTerminal(t *testing.T) {
	const sess = "sess-terminal-1"
	r, err := NewSessionEndpointResolver(
		fakeEndpointStore{rec: store.Session{State: store.SessionReady}},
		"/run/ds/attach",
		WithSessionModeReader(fakeModeReader{mode: libvirt.SessionModeTerminal, found: true}),
	)
	if err != nil {
		t.Fatalf("NewSessionEndpointResolver: %v", err)
	}
	// The candidate address is unchanged (the host-local UDS path).
	addr, _, ok, derr := r.DirectEndpoint(context.Background(), sess)
	if derr != nil || !ok {
		t.Fatalf("DirectEndpoint: ok=%v err=%v", ok, derr)
	}
	if want := "/run/ds/attach/" + sess + ".sock"; addr != want {
		t.Errorf("terminal candidate address = %q, want the SAME host-local UDS %q (only the transport differs)", addr, want)
	}
	// The transport tag is RAW_TERMINAL (the fix).
	tr, terr := r.EndpointTransport(context.Background(), sess)
	if terr != nil {
		t.Fatalf("EndpointTransport: %v", terr)
	}
	if tr != attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL {
		t.Errorf("terminal session transport = %v, want RAW_TERMINAL", tr)
	}
}

// TestEndpointResolver_StructuredAndAbsentRenderDirect pins the INVARIANT the fix must not
// disturb: a session resolved to STRUCTURED, a session whose marker is ABSENT (found=false),
// and a resolver with NO mode source wired at all (nil reader — DS_ORCH_OVERLAY_DIR unset)
// ALL tag DIRECT (or UNSPECIFIED ⇒ the issuer keeps DIRECT). This is the byte-identical
// structured path the existing DIRECT assertions depend on.
func TestEndpointResolver_StructuredAndAbsentRenderDirect(t *testing.T) {
	const sess = "sess-structured-1"
	cases := []struct {
		name string
		opt  endpointResolverOption
		want attachv1.EndpointTransport
	}{
		{"explicit structured", WithSessionModeReader(fakeModeReader{mode: libvirt.SessionModeStructured, found: true}), attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT},
		{"absent marker", WithSessionModeReader(fakeModeReader{mode: libvirt.SessionModeStructured, found: false}), attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT},
		// No mode source at all (no overlay dir): UNSPECIFIED ⇒ the issuer keeps DIRECT.
		{"no mode source (nil reader)", func(*sessionEndpointResolver) {}, attachv1.EndpointTransport_ENDPOINT_TRANSPORT_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewSessionEndpointResolver(fakeEndpointStore{rec: store.Session{State: store.SessionReady}}, "/run/ds/attach", tc.opt)
			if err != nil {
				t.Fatalf("NewSessionEndpointResolver: %v", err)
			}
			tr, terr := r.EndpointTransport(context.Background(), sess)
			if terr != nil {
				t.Fatalf("EndpointTransport: %v", terr)
			}
			if tr != tc.want {
				t.Errorf("transport = %v, want %v", tr, tc.want)
			}
		})
	}
}

// TestEndpointResolver_CorruptModeMarkerSurfaces proves a host-written marker the resolver
// cannot interpret is FAIL-LOUD (an error) — never a silent downgrade to DIRECT that would
// mis-route a terminal client onto the wrong carrier.
func TestEndpointResolver_CorruptModeMarkerSurfaces(t *testing.T) {
	sentinel := errors.New("corrupt marker")
	r, _ := NewSessionEndpointResolver(
		fakeEndpointStore{rec: store.Session{State: store.SessionReady}},
		"/run/ds/attach",
		WithSessionModeReader(fakeModeReader{err: sentinel}),
	)
	if _, err := r.EndpointTransport(context.Background(), "sess-corrupt"); !errors.Is(err, sentinel) {
		t.Errorf("EndpointTransport (corrupt marker): err = %v, want wrapping the read fault", err)
	}
}

// TestIssuer_TerminalResolverRendersRawTerminalCandidate is the END-TO-END proof through the
// REAL attach.Issuer (the exact path serpent-tui's Attach takes): with the terminal-tagging
// resolver wired via WithEndpointResolver, an issued WRITER handle carries a RAW_TERMINAL
// candidate; with a structured-tagging resolver it carries DIRECT — same UDS address. This is
// the seam the U-HOST-SERVE minter already satisfies; the fix makes the control-plane resolver
// satisfy it too, so the single-box MVP routes terminal correctly.
func TestIssuer_TerminalResolverRendersRawTerminalCandidate(t *testing.T) {
	repo := store.NewMemory()
	const sess = "sess-issuer-terminal"
	if _, err := repo.CreateSession(context.Background(), store.Session{
		Ref:   store.SessionRef{SessionUUID: sess, HostID: "host-cpwire", HostSessionIndex: 1, TapName: "dstap-1"},
		State: store.SessionReady,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	for _, tc := range []struct {
		name string
		mode libvirt.SessionMode
		want attachv1.EndpointTransport
	}{
		{"terminal", libvirt.SessionModeTerminal, attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL},
		{"structured", libvirt.SessionModeStructured, attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver, err := NewSessionEndpointResolver(repo, "/run/ds/attach", WithSessionModeReader(fakeModeReader{mode: tc.mode, found: true}))
			if err != nil {
				t.Fatalf("NewSessionEndpointResolver: %v", err)
			}
			iss := attach.NewIssuer(repo, attach.WithEndpointResolver(resolver))
			h, _, err := iss.Issue(context.Background(), sess, "writer-a", attachv1.Role_ROLE_WRITER, false)
			if err != nil {
				t.Fatalf("Issue WRITER: %v", err)
			}
			eps := h.GetEndpoints()
			if len(eps) != 1 {
				t.Fatalf("handle carries %d candidates, want exactly 1", len(eps))
			}
			if got := eps[0].GetTransport(); got != tc.want {
				t.Errorf("issued candidate transport = %v, want %v", got, tc.want)
			}
			if want := "/run/ds/attach/" + sess + ".sock"; eps[0].GetAddress() != want {
				t.Errorf("issued candidate address = %q, want the SAME host-local UDS %q", eps[0].GetAddress(), want)
			}
		})
	}
}

// TestEndpointResolver_SingleSourcedWithBridge is the SINGLE-SOURCE acceptance: the
// orchestrator endpoint resolver and the host-agent AttachBridge render the EXACT SAME
// per-session UDS path for the same session — so a DIRECT candidate the resolver advertises
// resolves to exactly the socket the bridge serves. Both consume the ONE
// hostagent.DefaultAttachSocketDir (the resolver's defaultAttachSocketDir is defined as that
// constant), so a drift would have to change one home, which both read.
func TestEndpointResolver_SingleSourcedWithBridge(t *testing.T) {
	// Both sides on their respective defaults (empty dir): the resolver falls back to
	// defaultAttachSocketDir (== hostagent.DefaultAttachSocketDir); the bridge falls back to
	// hostagent.DefaultAttachSocketDir. Single-sourced ⇒ they MUST agree.
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate off: the bridge renders the path but launches nothing.

	const sess = "sess-single-source-7"
	r, err := NewSessionEndpointResolver(fakeEndpointStore{rec: store.Session{State: store.SessionReady}}, "")
	if err != nil {
		t.Fatalf("NewSessionEndpointResolver: %v", err)
	}
	resolverAddr, _, ok, err := r.DirectEndpoint(context.Background(), sess)
	if err != nil || !ok {
		t.Fatalf("DirectEndpoint: ok=%v err=%v", ok, err)
	}

	bridge := hostagent.NewAttachBridge(hostagent.AttachBridgeConfig{})                    // empty dir → the same default
	out, err := bridge.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured) // offline: renders, no launch (CID irrelevant)
	if err != nil {
		t.Fatalf("AttachBridge.Serve (offline): %v", err)
	}
	if out.Launched {
		t.Error("offline AttachBridge.Serve launched a child; want no-launch")
	}
	if resolverAddr != out.UDSPath {
		t.Errorf("single-source VIOLATED: resolver advertises %q but bridge serves %q — a client would dial a socket no bridge binds", resolverAddr, out.UDSPath)
	}
	// And the shared default home is the one constant both consumed.
	if defaultAttachSocketDir != hostagent.DefaultAttachSocketDir {
		t.Errorf("resolver default dir %q != bridge default dir %q (not single-sourced)", defaultAttachSocketDir, hostagent.DefaultAttachSocketDir)
	}
}

// TestEndpointResolver_SingleSourcedWithBridge_Override proves the single-source agreement
// holds under an explicit per-host override too: when BOTH sides are pointed at the same
// custom dir (the daemon root passes one config value to both), the rendered paths still
// match for the same session.
func TestEndpointResolver_SingleSourcedWithBridge_Override(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "")
	const dir = "/run/custom/attach"
	const sess = "sess-override"

	r, err := NewSessionEndpointResolver(fakeEndpointStore{rec: store.Session{State: store.SessionReady}}, dir)
	if err != nil {
		t.Fatalf("NewSessionEndpointResolver: %v", err)
	}
	resolverAddr, _, ok, err := r.DirectEndpoint(context.Background(), sess)
	if err != nil || !ok {
		t.Fatalf("DirectEndpoint: ok=%v err=%v", ok, err)
	}
	bridge := hostagent.NewAttachBridge(hostagent.AttachBridgeConfig{SocketDir: dir})
	out, err := bridge.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured)
	if err != nil {
		t.Fatalf("AttachBridge.Serve: %v", err)
	}
	if resolverAddr != out.UDSPath {
		t.Errorf("override single-source VIOLATED: resolver %q != bridge %q", resolverAddr, out.UDSPath)
	}
}

// fakeEndpointStore is a narrow endpointSessionReader double: it returns a programmed
// record (or a programmed error) for GetSession so the resolver's servability gate and
// fault handling are exercised without a full store.
type fakeEndpointStore struct {
	rec store.Session
	err error
}

func (f fakeEndpointStore) GetSession(_ context.Context, _ string) (store.Session, error) {
	if f.err != nil {
		return store.Session{}, f.err
	}
	return f.rec, nil
}

func TestEndpointResolver_RequiresStore(t *testing.T) {
	if _, err := NewSessionEndpointResolver(nil, ""); err == nil {
		t.Fatal("NewSessionEndpointResolver(nil): expected a fail-closed error (no record authority)")
	}
}

func TestEndpointResolver_ServableRendersUDSCandidate(t *testing.T) {
	const sess = "sess-abc-123"
	for _, st := range []store.SessionState{store.SessionReady, store.SessionAttached, store.SessionWorking} {
		r, err := NewSessionEndpointResolver(fakeEndpointStore{rec: store.Session{State: st}}, "/run/ds/attach")
		if err != nil {
			t.Fatalf("NewSessionEndpointResolver: %v", err)
		}
		addr, sni, ok, derr := r.DirectEndpoint(context.Background(), sess)
		if derr != nil {
			t.Fatalf("DirectEndpoint(%s): %v", st, derr)
		}
		if !ok {
			t.Fatalf("DirectEndpoint(%s): ok=false, want a servable candidate", st)
		}
		if want := "/run/ds/attach/" + sess + ".sock"; addr != want {
			t.Errorf("DirectEndpoint(%s) address = %q, want %q", st, addr, want)
		}
		if sni != "" {
			t.Errorf("DirectEndpoint(%s) serverName = %q, want empty (host-local hop has no SNI)", st, sni)
		}
	}
}

func TestEndpointResolver_UnservableStatesYieldNoCandidate(t *testing.T) {
	// Pre-placement, mid-lifecycle, and torn-down states must NOT fabricate an endpoint.
	for _, st := range []store.SessionState{
		store.SessionPending, store.SessionCreating, store.SessionSnapshotting,
		store.SessionMigrating, store.SessionParked, store.SessionSuspended,
		store.SessionResuming, store.SessionDestroying, store.SessionDestroyed,
	} {
		r, _ := NewSessionEndpointResolver(fakeEndpointStore{rec: store.Session{State: st}}, "/run/ds/attach")
		addr, _, ok, err := r.DirectEndpoint(context.Background(), "sess-x")
		if err != nil {
			t.Fatalf("DirectEndpoint(%s): unexpected error %v", st, err)
		}
		if ok || addr != "" {
			t.Errorf("DirectEndpoint(%s): ok=%v addr=%q, want no candidate (state not servable)", st, ok, addr)
		}
	}
}

func TestEndpointResolver_MissingRecordIsNoCandidateNoError(t *testing.T) {
	// A missing record is the seat arbitration's authority, not the resolver's: skip the
	// candidate fail-closed, do NOT surface an error.
	r, _ := NewSessionEndpointResolver(fakeEndpointStore{err: store.ErrNotFound}, "")
	addr, _, ok, err := r.DirectEndpoint(context.Background(), "sess-gone")
	if err != nil {
		t.Fatalf("DirectEndpoint (not found): want no error, got %v", err)
	}
	if ok || addr != "" {
		t.Errorf("DirectEndpoint (not found): ok=%v addr=%q, want no candidate", ok, addr)
	}
}

func TestEndpointResolver_StoreFaultSurfaces(t *testing.T) {
	// A real store fault (the record authority stalled) must surface — the issuer must not
	// advertise an endpoint it could not gate.
	r, _ := NewSessionEndpointResolver(fakeEndpointStore{err: store.ErrUnavailable}, "")
	_, _, ok, err := r.DirectEndpoint(context.Background(), "sess-y")
	if err == nil {
		t.Fatal("DirectEndpoint (store fault): want an error, got nil")
	}
	if !errors.Is(err, store.ErrUnavailable) {
		t.Errorf("DirectEndpoint (store fault): err = %v, want wrapping store.ErrUnavailable", err)
	}
	if ok {
		t.Error("DirectEndpoint (store fault): ok=true, want false")
	}
}

func TestEndpointResolver_EmptySessionIsNoCandidate(t *testing.T) {
	r, _ := NewSessionEndpointResolver(fakeEndpointStore{rec: store.Session{State: store.SessionReady}}, "")
	_, _, ok, err := r.DirectEndpoint(context.Background(), "")
	if err != nil || ok {
		t.Errorf("DirectEndpoint(\"\"): ok=%v err=%v, want no candidate, no error", ok, err)
	}
}

func TestEndpointResolver_DefaultSocketDir(t *testing.T) {
	r, _ := NewSessionEndpointResolver(fakeEndpointStore{rec: store.Session{State: store.SessionReady}}, "")
	addr, _, ok, _ := r.DirectEndpoint(context.Background(), "sess-default")
	if !ok || !strings.HasPrefix(addr, defaultAttachSocketDir+"/") {
		t.Errorf("DirectEndpoint default dir: addr = %q, want under %q", addr, defaultAttachSocketDir)
	}
}

func TestEndpointResolver_SanitizesTraversal(t *testing.T) {
	// A crafted UUID with separators must never escape the socket dir.
	r, _ := NewSessionEndpointResolver(fakeEndpointStore{rec: store.Session{State: store.SessionReady}}, "/run/ds/attach")
	addr, _, ok, err := r.DirectEndpoint(context.Background(), "../../etc/passwd")
	if err != nil || !ok {
		t.Fatalf("DirectEndpoint (crafted): ok=%v err=%v", ok, err)
	}
	if !strings.HasPrefix(addr, "/run/ds/attach/") {
		t.Errorf("DirectEndpoint (crafted) escaped the socket dir: %q", addr)
	}
	// The load-bearing safety property: the per-session filename is a SINGLE path
	// component with no separator, so the path cannot escape the socket dir ('.' bytes
	// alone are harmless inside a filename — only a '/' would traverse).
	if comp := strings.TrimPrefix(addr, "/run/ds/attach/"); strings.Contains(comp, "/") {
		t.Errorf("DirectEndpoint (crafted) path traversal not sanitized (separator leaked): %q", addr)
	}
}

// TestAttachRPC_WiredResolverCarriesServableCandidate is the ACCEPTANCE test: with the
// resolver wired into NewIssuer (wiring.go), an in-process Attach RPC over the fully-wired
// ControlPlane returns a handle carrying a servable DIRECT (UDS) candidate — so serpent-tui
// maps it to its TransportUnix carrier and a WRITER seat is offered (not reader-only).
func TestAttachRPC_WiredResolverCarriesServableCandidate(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-attach-direct"
	seedSession(t, f, sess) // a READY session (servable)

	resp, err := f.cp.Sessions.Attach(context.Background(), &orchestratorv1.AttachRequest{
		SessionUuid: sess,
		Role:        attachv1.Role_ROLE_WRITER,
	})
	if err != nil {
		t.Fatalf("Attach WRITER: %v", err)
	}
	h := resp.GetHandle()

	eps := h.GetEndpoints()
	if len(eps) != 1 {
		t.Fatalf("handle carries %d endpoint candidates, want exactly 1 (the servable DIRECT) — got %+v", len(eps), eps)
	}
	ep := eps[0]
	if ep.GetTransport() != attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT {
		t.Errorf("candidate transport = %v, want DIRECT (serpent-tui maps it to TransportUnix)", ep.GetTransport())
	}
	if want := defaultAttachSocketDir + "/" + sess + ".sock"; ep.GetAddress() != want {
		t.Errorf("candidate address = %q, want the host-local UDS path %q", ep.GetAddress(), want)
	}
	if ep.GetServerName() != "" {
		t.Errorf("candidate serverName = %q, want empty (host-local hop)", ep.GetServerName())
	}
	// The writer seat still landed (the endpoint wiring is additive to seat arbitration).
	if h.GetRole() != attachv1.Role_ROLE_WRITER {
		t.Errorf("handle role = %v, want WRITER", h.GetRole())
	}
}

// TestAttachRPC_UnplacedSessionNoCandidate proves the wired resolver still degrades: an
// Attach against a CREATING (not-yet-placed) session returns a handle with the seat + auth
// but NO endpoint candidate (no fabricated address).
func TestAttachRPC_UnplacedSessionNoCandidate(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-attach-unplaced"
	if _, err := f.st.CreateSession(context.Background(), store.Session{
		Ref:   store.SessionRef{SessionUUID: sess, HostID: testHostID, HostSessionIndex: 2, TapName: "dstap-2"},
		State: store.SessionCreating,
	}); err != nil {
		t.Fatalf("seed creating session: %v", err)
	}

	resp, err := f.cp.Sessions.Attach(context.Background(), &orchestratorv1.AttachRequest{
		SessionUuid: sess,
		Role:        attachv1.Role_ROLE_READER,
	})
	if err != nil {
		t.Fatalf("Attach READER (unplaced): %v", err)
	}
	if eps := resp.GetHandle().GetEndpoints(); len(eps) != 0 {
		t.Errorf("unplaced session handle carries %d candidates, want 0 (no fabricated endpoint)", len(eps))
	}
}
