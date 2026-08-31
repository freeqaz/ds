package libvirt

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// fakeAttach records invocations of the boundary-owned tap-create primitive and
// can be made to fail at a chosen method to exercise per-step surfacing.
type fakeAttach struct {
	tapErr   error
	nftErr   error
	flushErr error
	taps     []Binding
	nfts     []string
	flushed  []string
}

func (f *fakeAttach) CreateTap(_ context.Context, b Binding) error {
	if f.tapErr != nil {
		return f.tapErr
	}
	f.taps = append(f.taps, b)
	return nil
}

func (f *fakeAttach) InstantiateSessionNFT(_ context.Context, sessionUUID string, _ Binding) error {
	if f.nftErr != nil {
		return f.nftErr
	}
	f.nfts = append(f.nfts, sessionUUID)
	return nil
}

func (f *fakeAttach) FlushSession(_ context.Context, sessionUUID string, _ Binding) error {
	f.flushed = append(f.flushed, sessionUUID)
	return f.flushErr
}

type fakeOverlay struct {
	createErr  error
	disposeErr error
	path       string
	disposed   []string
}

func (f *fakeOverlay) CreateOverlay(_ context.Context, sessionUUID, _ string) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	if f.path == "" {
		return "/var/lib/ds/overlays/" + sessionUUID + ".qcow2", nil
	}
	return f.path, nil
}

func (f *fakeOverlay) DisposeOverlay(_ context.Context, overlayPath string) error {
	f.disposed = append(f.disposed, overlayPath)
	return f.disposeErr
}

type fakeCA struct {
	injectErr error
	injected  []string
}

func (f *fakeCA) InjectCA(_ context.Context, overlayPath, _ string) error {
	if f.injectErr != nil {
		return f.injectErr
	}
	f.injected = append(f.injected, overlayPath)
	return nil
}

type fakeBooter struct {
	bootErr error
	booted  []string
}

func (f *fakeBooter) Boot(_ context.Context, sessionUUID, _, _, _ string, _ uint32) (string, error) {
	if f.bootErr != nil {
		return "", f.bootErr
	}
	f.booted = append(f.booted, sessionUUID)
	return "domain-" + sessionUUID, nil
}

type fakeGate struct {
	acked    bool
	ackErr   error
	fresh    bool
	freshErr error
}

func (f *fakeGate) DigestAcked(_ context.Context, _ string) (bool, error) {
	return f.acked, f.ackErr
}

func (f *fakeGate) PolicyFresh(_ context.Context) (bool, error) {
	return f.fresh, f.freshErr
}

func newTestAgent(t *testing.T, attach AttachPrimitive, overlay OverlayStore, ca CAInjector, booter Booter, gate RoutabilityGate) *HostAgent {
	t.Helper()
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	a, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	h, err := NewHostAgent(a, attach, overlay, ca, booter, gate)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	return h
}

func goodReq() CreateRequest {
	return CreateRequest{
		SessionUUID:         "sess-1",
		ImageID:             "img-abc",
		EntrypointConfigRef: "entry-ref",
		CABundleRef:         "ca-ref",
	}
}

func TestCreateSessionHappyPath(t *testing.T) {
	attach := &fakeAttach{}
	overlay := &fakeOverlay{}
	ca := &fakeCA{}
	booter := &fakeBooter{}
	gate := &fakeGate{acked: true, fresh: true}
	h := newTestAgent(t, attach, overlay, ca, booter, gate)

	res, err := h.CreateSession(context.Background(), goodReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if !res.Routable {
		t.Error("happy-path create should be routable")
	}
	if res.DomainUUID != "domain-sess-1" {
		t.Errorf("DomainUUID = %q, want domain-sess-1", res.DomainUUID)
	}
	// The three-keys-agree binding is recorded and well-formed.
	if err := res.Binding.validate(); err != nil {
		t.Errorf("recorded binding invalid: %v", err)
	}
	if res.Binding.TapName != "dstap-0" {
		t.Errorf("tap name = %q, want dstap-0", res.Binding.TapName)
	}
	if res.Binding.OverlayPath == "" {
		t.Error("recorded binding should carry the overlay path (D29)")
	}
	// Ordering: tap + nft instantiated, CA injected before boot.
	if len(attach.taps) != 1 || len(attach.nfts) != 1 {
		t.Errorf("expected one tap + one nft instantiation, got %d/%d", len(attach.taps), len(attach.nfts))
	}
	if len(ca.injected) != 1 || len(booter.booted) != 1 {
		t.Errorf("expected one CA inject + one boot, got %d/%d", len(ca.injected), len(booter.booted))
	}
}

func TestCreateSessionRefusesWithoutCABundleRef(t *testing.T) {
	h := newTestAgent(t, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true})
	req := goodReq()
	req.CABundleRef = "" // step-7 injection is fail-closed (D17)

	_, err := h.CreateSession(context.Background(), req)
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	if ce.Step != StepNone {
		t.Errorf("missing CA ref should refuse pre-allocation (StepNone), got %s", ce.Step)
	}
	if ce.HasBinding {
		t.Error("a pre-step-4 refusal must not claim a host-side binding exists")
	}
}

func TestCreateSessionCAInjectionFailsClosed(t *testing.T) {
	overlay := &fakeOverlay{}
	ca := &fakeCA{injectErr: errors.New("trust-store write failed")}
	booter := &fakeBooter{}
	h := newTestAgent(t, &fakeAttach{}, overlay, ca, booter, &fakeGate{acked: true, fresh: true})

	_, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	if ce.Step != StepOverlay {
		t.Errorf("CA injection failure should surface at StepOverlay, got %s", ce.Step)
	}
	// FAIL-CLOSED: the create must NOT have booted.
	if len(booter.booted) != 0 {
		t.Error("CA injection failure must fail the create before boot (D17)")
	}
	// The overlay exists and must be available to rollback for disposal.
	if ce.OverlayPath == "" {
		t.Error("step-7 failure must surface the overlay path so rollback can dispose it")
	}
	if !ce.HasBinding {
		t.Error("step-7 failure must surface the binding so rollback can flush_session")
	}
}

func TestCreateSessionDigestAckGate(t *testing.T) {
	booter := &fakeBooter{}
	h := newTestAgent(t, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, booter, &fakeGate{acked: false, fresh: true})

	_, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	if ce.Step != StepDigestAck {
		t.Errorf("un-acked digest should surface at StepDigestAck, got %s", ce.Step)
	}
	// Mint-before-attach: no overlay/boot may happen before the ack (D73).
	if len(booter.booted) != 0 {
		t.Error("create must not boot before the session-scoped digest is acked (D73)")
	}
	if !ce.HasBinding {
		t.Error("step-6 failure must surface the binding for rollback")
	}
}

func TestCreateSessionRoutableGateStructural(t *testing.T) {
	// Booted but the host is policy-stale → NOT routable, surfaced at step 9.
	booter := &fakeBooter{}
	h := newTestAgent(t, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, booter, &fakeGate{acked: true, fresh: false})

	res, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	if ce.Step != StepRoutable {
		t.Errorf("stale policy should surface at StepRoutable, got %s", ce.Step)
	}
	// The binding is recorded and the domain booted even on a non-routable
	// result (binding-recorded-before-routable; the precedence is honored).
	if res.Routable {
		t.Error("a policy-stale session must NOT be routable")
	}
	if res.DomainUUID == "" {
		t.Error("the booted domain should still be surfaced for the reconciler")
	}
	if err := res.Binding.validate(); err != nil {
		t.Errorf("binding must be recorded even when not routable: %v", err)
	}
}

func TestCreateSessionTapFailureSurfacesBindingForRollback(t *testing.T) {
	attach := &fakeAttach{tapErr: errors.New("tap create EBUSY")}
	h := newTestAgent(t, attach, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true})

	_, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	if ce.Step != StepAllocate {
		t.Errorf("tap failure should surface at StepAllocate, got %s", ce.Step)
	}
	if !ce.HasBinding || ce.Binding.TapName == "" {
		t.Error("tap failure must surface the (burned-index) binding so rollback can flush_session(legs=all) (D66)")
	}
}

func TestCreateSessionBootFailureSurfacesOverlayAndBinding(t *testing.T) {
	booter := &fakeBooter{bootErr: errors.New("libvirt domain define failed")}
	h := newTestAgent(t, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, booter, &fakeGate{acked: true, fresh: true})

	_, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	if ce.Step != StepBoot {
		t.Errorf("boot failure should surface at StepBoot, got %s", ce.Step)
	}
	if ce.OverlayPath == "" || !ce.HasBinding {
		t.Error("boot failure must surface overlay + binding so rollback destroys the overlay then unwinds step 4 (§4.1)")
	}
}

func TestCreateSessionDigestAckErrorSurfaced(t *testing.T) {
	h := newTestAgent(t, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{ackErr: errors.New("ack lookup failed")})
	_, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) || ce.Step != StepDigestAck {
		t.Fatalf("digest-ack error should surface at StepDigestAck, got %v", err)
	}
}

// refCapturingBooter records the entrypointConfigRef, the per-session vsockCID, AND the
// per-session tapName each Boot received so a test can assert the create path threads the
// opaque ref (the producer's build+deliver is additive — the Booter still gets the ref),
// the recorded binding's deterministic VsockCID (so the live render can pin it), and the
// recorded binding's `dstap-<idx>` TapName (so a gate-on live render can wire the routed
// tap as the egress NIC's `<target dev='<tapName>'/>`) through to the Booter.
type refCapturingBooter struct {
	bootErr error
	refs    []string
	cids    []uint32
	taps    []string
}

func (f *refCapturingBooter) Boot(_ context.Context, sessionUUID, _, entrypointConfigRef, tapName string, vsockCID uint32) (string, error) {
	if f.bootErr != nil {
		return "", f.bootErr
	}
	f.refs = append(f.refs, entrypointConfigRef)
	f.cids = append(f.cids, vsockCID)
	f.taps = append(f.taps, tapName)
	return "domain-" + sessionUUID, nil
}

// recordingDeliverer records each (session, configPB, netConfigPB) BuildConfigDrive received so
// a test can assert the create path delivered config.pb (+ the optional U4 ds-net.env second
// file) into the guest. It fail-closes on an empty config exactly as the production deliverers do.
type recordingDeliverer struct {
	calls    []recordedDelivery
	deliErr  error
	overlayD string
}

type recordedDelivery struct {
	session     string
	configPB    []byte
	netConfigPB []byte
}

func (d *recordingDeliverer) BuildConfigDrive(_ context.Context, sessionUUID string, configPB, netConfigPB []byte) (string, error) {
	if d.deliErr != nil {
		return "", d.deliErr
	}
	if sessionUUID == "" {
		return "", errors.New("recording deliverer: empty session uuid")
	}
	if len(configPB) == 0 {
		return "", errors.New("recording deliverer: empty config.pb (fail-closed)")
	}
	d.calls = append(d.calls, recordedDelivery{
		session:     sessionUUID,
		configPB:    append([]byte(nil), configPB...),
		netConfigPB: append([]byte(nil), netConfigPB...),
	})
	return configDrivePathFor(d.overlayD, sessionUUID), nil
}

// TestCreateSessionGap1ProducerBuildsAndDelivers is the gap-1 acceptance: with the
// EntrypointProducer wired, the create choreography fetches the opaque role-overlay bytes via
// the OFFLINE fake source, assembles+marshals the structured EntrypointConfig, and delivers
// config.pb through the deliverer — all BEFORE Boot, and the opaque ref is still threaded to
// the Booter. No live touch (offline fakes only).
func TestCreateSessionGap1ProducerBuildsAndDelivers(t *testing.T) {
	const ref = "entry-ref"
	// The offline fake source serves the opaque role-overlay bytes for the ref the create
	// carries (the fixture the offline create path exercises, D50).
	source := NewFakeEntrypointConfigSource(map[string][]byte{ref: []byte("opaque-role-overlay-bytes")})
	deliver := &recordingDeliverer{}
	producer, err := NewEntrypointProducer(source, deliver, EntrypointFacts{
		HostID:          "host-local",
		Launch:          LaunchSpecInput{Command: "/usr/local/bin/ds-entrypoint"},
		Posture:         runtimevPostureLocked(),
		EventSocketPath: "/run/ds/attach.sock",
	})
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}

	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	booter := &refCapturingBooter{}
	h, err := NewHostAgentWithEntrypoint(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, booter, &fakeGate{acked: true, fresh: true}, nil, producer, nil)
	if err != nil {
		t.Fatalf("NewHostAgentWithEntrypoint: %v", err)
	}

	res, err := h.CreateSession(context.Background(), goodReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if !res.Routable {
		t.Error("gap-1 wired happy-path create should still be routable")
	}
	// The producer delivered config.pb exactly once, for this session, with non-empty bytes.
	if len(deliver.calls) != 1 {
		t.Fatalf("expected exactly one config-drive delivery, got %d", len(deliver.calls))
	}
	if deliver.calls[0].session != "sess-1" {
		t.Errorf("delivered config drive for session %q, want sess-1", deliver.calls[0].session)
	}
	if len(deliver.calls[0].configPB) == 0 {
		t.Error("delivered an empty config.pb (the build should marshal a non-empty structured config)")
	}
	// RoutedTap is UNSET on these facts (the default SLIRP path) → NO ds-net.env second
	// file is rendered; the config-drive carries config.pb alone (byte-identical to before U4).
	if len(deliver.calls[0].netConfigPB) != 0 {
		t.Errorf("RoutedTap unset must deliver NO net config second file, got %q", deliver.calls[0].netConfigPB)
	}
	// The opaque ref is STILL threaded to the Booter (the producer step is additive).
	if len(booter.refs) != 1 || booter.refs[0] != ref {
		t.Errorf("Booter received refs %v, want exactly [%q] (the ref is still threaded)", booter.refs, ref)
	}
}

// TestCreateSessionGap1ProducerRoutedTapDeliversNetConfig is the U4 acceptance: with
// RoutedTap set on the facts, the create choreography ALSO renders the per-session guest static
// net config (ds-net.env) onto the config-drive as a second file — derived from the recorded
// binding's HostSessionIndex (10.77.<idx>.1/31 via 10.77.<idx>.0). config.pb is still delivered;
// the second file is additive. No live touch (offline fakes only).
func TestCreateSessionGap1ProducerRoutedTapDeliversNetConfig(t *testing.T) {
	const ref = "entry-ref"
	source := NewFakeEntrypointConfigSource(map[string][]byte{ref: []byte("opaque-role-overlay-bytes")})
	deliver := &recordingDeliverer{}
	producer, err := NewEntrypointProducer(source, deliver, EntrypointFacts{
		HostID:          "host-local",
		Launch:          LaunchSpecInput{Command: "/usr/local/bin/ds-entrypoint"},
		Posture:         runtimevPostureLocked(),
		EventSocketPath: "/run/ds/attach.sock",
		RoutedTap:       true, // the routed-tap posture (U4): emit the second file
	})
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}

	// newMemCounter(0) → the first allocation is index 0, so the guest is 10.77.0.1 via 10.77.0.0.
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	booter := &refCapturingBooter{}
	h, err := NewHostAgentWithEntrypoint(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, booter, &fakeGate{acked: true, fresh: true}, nil, producer, nil)
	if err != nil {
		t.Fatalf("NewHostAgentWithEntrypoint: %v", err)
	}

	if _, err := h.CreateSession(context.Background(), goodReq()); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if len(deliver.calls) != 1 {
		t.Fatalf("expected exactly one config-drive delivery, got %d", len(deliver.calls))
	}
	// config.pb is STILL delivered (the entrypoint config is untouched by the second file).
	if len(deliver.calls[0].configPB) == 0 {
		t.Error("routed-tap delivery dropped config.pb (the entrypoint config must still ride)")
	}
	// The ds-net.env second file is rendered, carrying the index-0 /31.
	net := string(deliver.calls[0].netConfigPB)
	if net == "" {
		t.Fatal("RoutedTap set must deliver a non-empty ds-net.env second file")
	}
	for _, want := range []string{
		"DS_NET_GUEST_IP=10.77.0.1",
		"DS_NET_PREFIX=31",
		"DS_NET_GATEWAY=10.77.0.0",
	} {
		if !strings.Contains(net, want) {
			t.Errorf("rendered ds-net.env missing %q:\n%s", want, net)
		}
	}
}

// TestCreateSessionGap1ProducerNilIsByteIdentical proves the create path is unchanged when no
// producer is wired (the historical default): nothing is built/delivered and the Booter still
// gets the ref — the prod path is byte-identical when the seam is unset.
func TestCreateSessionGap1ProducerNilIsByteIdentical(t *testing.T) {
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, _ := NewAllocator(newMemCounter(0), plan)
	booter := &refCapturingBooter{}
	// nil producer, nil hook → the historical NewHostAgent shape.
	h, err := NewHostAgentWithEntrypoint(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, booter, &fakeGate{acked: true, fresh: true}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewHostAgentWithEntrypoint(nil producer): %v", err)
	}
	if _, err := h.CreateSession(context.Background(), goodReq()); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if len(booter.refs) != 1 || booter.refs[0] != "entry-ref" {
		t.Errorf("Booter received refs %v, want [\"entry-ref\"] (ref still threaded with no producer)", booter.refs)
	}
	// The create path threads the recorded binding's deterministic VsockCID through to
	// the Booter so the live render can PIN the AF_VSOCK control channel (alloc.go =
	// index + reservedVsockCIDs; the first allocation off newMemCounter(0) is index 0 →
	// CID reservedVsockCIDs). Without this, a LIVE domain would get an auto-assigned CID
	// the host agent could not dial.
	wantCID := uint32(0) + reservedVsockCIDs
	if len(booter.cids) != 1 || booter.cids[0] != wantCID {
		t.Errorf("Booter received vsock cids %v, want [%d] (binding.VsockCID threaded through)", booter.cids, wantCID)
	}
	// The create path also threads the recorded binding's `dstap-<idx>` TapName through
	// to the Booter so a GATE-ON live render can attach the per-session routed tap as the
	// egress NIC's `<target dev='<tapName>'/>` (the U2 host-XML half). The first allocation
	// off newMemCounter(0) is index 0 → TapName "dstap-0". Without this, a gate-on LIVE
	// domain could not name the tap to attach.
	if len(booter.taps) != 1 || booter.taps[0] != "dstap-0" {
		t.Errorf("Booter received tap names %v, want [\"dstap-0\"] (binding.TapName threaded through)", booter.taps)
	}
}

// TestCreateSessionGap1ProducerFailClosed proves a producer fault (a missing orchestrator
// drop / fail-closed fetch) FAILS the create at the boot step BEFORE Boot — no guest boots on
// a config it cannot read (D38). The fake source has no fixture for the ref, so the fetch
// fails closed.
func TestCreateSessionGap1ProducerFailClosed(t *testing.T) {
	source := NewFakeEntrypointConfigSource(nil) // empty store → every named-ref fetch fails closed
	producer, err := NewEntrypointProducer(source, &recordingDeliverer{}, EntrypointFacts{
		HostID:          "host-local",
		Launch:          LaunchSpecInput{Command: "/usr/local/bin/ds-entrypoint"},
		Posture:         runtimevPostureLocked(),
		EventSocketPath: "/run/ds/attach.sock",
	})
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, _ := NewAllocator(newMemCounter(0), plan)
	booter := &refCapturingBooter{}
	h, err := NewHostAgentWithEntrypoint(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, booter, &fakeGate{acked: true, fresh: true}, nil, producer, nil)
	if err != nil {
		t.Fatalf("NewHostAgentWithEntrypoint: %v", err)
	}

	_, err = h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	if ce.Step != StepBoot {
		t.Errorf("a producer fail-closed should surface at StepBoot, got %s", ce.Step)
	}
	// FAIL-CLOSED: no guest booted on an unbuildable config.
	if len(booter.refs) != 0 {
		t.Error("a producer fail-closed must abort BEFORE Boot (D38)")
	}
	if ce.OverlayPath == "" || !ce.HasBinding {
		t.Error("the producer fail-closed must surface overlay + binding so rollback disposes the overlay")
	}
}

// TestCreateSessionPostBootHookRunsBestEffort proves the post-boot hook fires for a booted
// session with the recorded binding, and that a hook ERROR is NON-FATAL (the create still
// succeeds — the attach serving leg is distinct from boot).
func TestCreateSessionPostBootHookRunsBestEffort(t *testing.T) {
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, _ := NewAllocator(newMemCounter(0), plan)

	var got struct {
		session string
		tap     string
		ran     bool
	}
	hook := func(_ context.Context, sessionUUID string, b Binding) error {
		got.session = sessionUUID
		got.tap = b.TapName
		got.ran = true
		return errors.New("serve failed — must be swallowed (non-fatal)")
	}
	h, err := NewHostAgentWithEntrypoint(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true}, nil, nil, hook)
	if err != nil {
		t.Fatalf("NewHostAgentWithEntrypoint: %v", err)
	}
	res, err := h.CreateSession(context.Background(), goodReq())
	if err != nil {
		t.Fatalf("a post-boot hook error must NOT fail the create: %v", err)
	}
	if !res.Routable {
		t.Error("create with a (non-fatal) failing hook should still be routable")
	}
	if !got.ran {
		t.Fatal("post-boot hook did not run")
	}
	if got.session != "sess-1" {
		t.Errorf("hook session = %q, want sess-1", got.session)
	}
	if got.tap != "dstap-0" {
		t.Errorf("hook got binding tap %q, want dstap-0 (the recorded binding is passed)", got.tap)
	}
}

// TestCreateSessionPostBootHookFaultSurfacesOutOfBand proves the OUT-OF-BAND observability seam:
// a swallowed post-boot hook fault is surfaced through the HookFaultObserver (with the structured
// hook kind + session + error) WITHOUT changing the create verdict — the create still succeeds and
// the result is byte-identical to the no-observer path. The fault is observable only out-of-band.
func TestCreateSessionPostBootHookFaultSurfacesOutOfBand(t *testing.T) {
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, _ := NewAllocator(newMemCounter(0), plan)

	hookErr := errors.New("serve failed — swallowed from verdict, surfaced out-of-band")
	hook := func(_ context.Context, _ string, _ Binding) error { return hookErr }

	var observed []HookFault
	h, err := NewHostAgentWithEntrypoint(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true}, nil, nil, hook)
	if err != nil {
		t.Fatalf("NewHostAgentWithEntrypoint: %v", err)
	}
	h.WithHookFaultObserver(func(obs HookFault) { observed = append(observed, obs) })

	// The VERDICT is unchanged: a swallowed hook fault must NOT fail the create.
	res, err := h.CreateSession(context.Background(), goodReq())
	if err != nil {
		t.Fatalf("a swallowed post-boot hook fault must NOT change the create verdict: %v", err)
	}
	if !res.Routable || res.DomainUUID != "domain-sess-1" {
		t.Errorf("verdict diverged: routable=%v domain=%q (want true/domain-sess-1)", res.Routable, res.DomainUUID)
	}

	// The fault is observable OUT-OF-BAND: exactly one structured observation, attributed to the
	// post-boot hook, for this session, carrying the swallowed error.
	if len(observed) != 1 {
		t.Fatalf("swallowed hook fault should surface exactly one out-of-band observation, got %d", len(observed))
	}
	if observed[0].Hook != HookPostBoot {
		t.Errorf("observation hook = %v, want HookPostBoot", observed[0].Hook)
	}
	if observed[0].SessionUUID != "sess-1" {
		t.Errorf("observation session = %q, want sess-1", observed[0].SessionUUID)
	}
	if !errors.Is(observed[0].Err, hookErr) {
		t.Errorf("observation should carry the swallowed error, got %v", observed[0].Err)
	}
}

// TestCreateSessionPostBootHookCleanEmitsNoObservation proves the out-of-band seam fires ONLY on
// an actual fault: a hook that returns nil emits NO observation (the happy path is byte-identical),
// and the verdict is unchanged.
func TestCreateSessionPostBootHookCleanEmitsNoObservation(t *testing.T) {
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, _ := NewAllocator(newMemCounter(0), plan)

	ran := false
	hook := func(_ context.Context, _ string, _ Binding) error { ran = true; return nil }

	var observed []HookFault
	h, err := NewHostAgentWithEntrypoint(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true}, nil, nil, hook)
	if err != nil {
		t.Fatalf("NewHostAgentWithEntrypoint: %v", err)
	}
	h.WithHookFaultObserver(func(obs HookFault) { observed = append(observed, obs) })

	res, err := h.CreateSession(context.Background(), goodReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if !res.Routable {
		t.Error("a clean hook should leave the create routable")
	}
	if !ran {
		t.Fatal("post-boot hook did not run")
	}
	if len(observed) != 0 {
		t.Errorf("a clean hook must emit NO out-of-band observation, got %d", len(observed))
	}
}

// TestCreateSessionNoHookEmitsNoObservation proves the historical path (no post-boot hook wired)
// emits no out-of-band observation — the observer is silent when there is no hook to swallow.
func TestCreateSessionNoHookEmitsNoObservation(t *testing.T) {
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, _ := NewAllocator(newMemCounter(0), plan)

	var observed []HookFault
	h, err := NewHostAgentWithEntrypoint(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewHostAgentWithEntrypoint: %v", err)
	}
	h.WithHookFaultObserver(func(obs HookFault) { observed = append(observed, obs) })

	if _, err := h.CreateSession(context.Background(), goodReq()); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if len(observed) != 0 {
		t.Errorf("no wired hook must emit no out-of-band observation, got %d", len(observed))
	}
}

// TestHostAgentInstallsDefaultHookFaultObserver proves the constructor installs a non-nil default
// observer (so a swallowed hook fault is never silently dropped even when no observer is injected),
// and that WithHookFaultObserver(nil) keeps that default rather than nil-ing it.
func TestHostAgentInstallsDefaultHookFaultObserver(t *testing.T) {
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, _ := NewAllocator(newMemCounter(0), plan)
	h, err := NewHostAgent(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true})
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	if h.hookFault == nil {
		t.Fatal("constructor must install a default hook-fault observer (a swallowed fault must never be silently dropped)")
	}
	if got := h.WithHookFaultObserver(nil); got.hookFault == nil {
		t.Error("WithHookFaultObserver(nil) must keep the default observer, not nil it")
	}
}

// TestHookKindString pins the human-readable hook attribution the default observer renders.
func TestHookKindString(t *testing.T) {
	if got := HookPostBoot.String(); got != "post-boot-serving-leg" {
		t.Errorf("HookPostBoot.String() = %q, want post-boot-serving-leg", got)
	}
	if got := HookPostDestroy.String(); got != "post-destroy-serving-leg-reap" {
		t.Errorf("HookPostDestroy.String() = %q, want post-destroy-serving-leg-reap (a §4.2 reap fault must not render as the unknown-kind fallback)", got)
	}
	if got := HookKind(0).String(); got != "hook0" {
		t.Errorf("unknown HookKind.String() = %q, want hook0", got)
	}
}

// runtimevPostureLocked is the concrete posture the gap-1 builder requires (UNSPECIFIED is
// rejected). Declared as a tiny helper so the create tests do not import the proto package
// directly (the package's own validateEntrypointConfig is the authority on the enum).
func runtimevPostureLocked() runtimev1.PermissionPosture {
	return runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED
}

func TestNewHostAgentRejectsNilSeams(t *testing.T) {
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	a, _ := NewAllocator(newMemCounter(0), plan)
	if _, err := NewHostAgent(nil, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{}); err == nil {
		t.Error("nil allocator should be rejected")
	}
	if _, err := NewHostAgent(a, nil, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{}); err == nil {
		t.Error("nil attach primitive should be rejected")
	}
	if _, err := NewHostAgent(a, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, nil); err == nil {
		t.Error("nil routability gate should be rejected")
	}
}

// ── host-WIDE BoundaryReadiness gate (pre-step-4 admission, D63/D69) ──────────

// fakeReadiness is a recording BoundaryReadiness stand-in: it returns the configured
// (ready, detail, err) and counts Probe calls so a test can assert the gate ran exactly
// once at the top of CreateSession (mirroring fakeGate).
type fakeReadiness struct {
	ready  bool
	detail string
	err    error
	calls  int
}

func (f *fakeReadiness) Probe(_ context.Context) (bool, string, error) {
	f.calls++
	return f.ready, f.detail, f.err
}

// countingCounter wraps a memCounter to record how many times Next() was drawn, so a
// negative gate test can prove NO index was burned (the counter never advanced) when the
// pre-step-4 boundary-readiness gate refuses before h.alloc.Allocate.
type countingCounter struct {
	inner *memCounter
	draws int
}

func (c *countingCounter) Next() (uint64, error) {
	c.draws++
	return c.inner.Next()
}

// newTestAgentWithReadiness assembles a host agent carrying the OPTIONAL BoundaryReadiness
// seam plus a countingCounter-backed allocator (so a test can assert no index was burned).
// newTestAgent's signature is left untouched so all existing tests compile unchanged.
func newTestAgentWithReadiness(t *testing.T, attach AttachPrimitive, overlay OverlayStore, ca CAInjector, booter Booter, gate RoutabilityGate, readiness BoundaryReadiness) (*HostAgent, *countingCounter) {
	t.Helper()
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	cc := &countingCounter{inner: newMemCounter(0)}
	a, err := NewAllocator(cc, plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	h, err := NewHostAgentWithReadiness(a, attach, overlay, ca, booter, gate, nil, nil, nil, readiness)
	if err != nil {
		t.Fatalf("NewHostAgentWithReadiness: %v", err)
	}
	return h, cc
}

// TestCreateSessionNilReadinessIsReady proves the historical default: a host agent built
// via the legacy NewHostAgent (readiness nil) creates exactly as the happy path — nil=ready,
// byte-identical to today.
func TestCreateSessionNilReadinessIsReady(t *testing.T) {
	attach := &fakeAttach{}
	overlay := &fakeOverlay{}
	ca := &fakeCA{}
	booter := &fakeBooter{}
	h := newTestAgent(t, attach, overlay, ca, booter, &fakeGate{acked: true, fresh: true})

	res, err := h.CreateSession(context.Background(), goodReq())
	if err != nil {
		t.Fatalf("CreateSession (nil readiness): %v", err)
	}
	if !res.Routable {
		t.Error("nil readiness create should be routable (nil=ready, historical default)")
	}
	if len(attach.taps) != 1 || len(attach.nfts) != 1 || len(booter.booted) != 1 {
		t.Errorf("nil readiness path must be byte-identical to happy path, got taps=%d nfts=%d booted=%d", len(attach.taps), len(attach.nfts), len(booter.booted))
	}
}

// TestCreateSessionReadyBoundaryUnchanged proves a READY probe is transparent: the same
// CreateResult and the same recorded side-effect sequence as the nil path, with the probe
// called exactly once.
func TestCreateSessionReadyBoundaryUnchanged(t *testing.T) {
	attach := &fakeAttach{}
	overlay := &fakeOverlay{}
	ca := &fakeCA{}
	booter := &fakeBooter{}
	readiness := &fakeReadiness{ready: true}
	h, _ := newTestAgentWithReadiness(t, attach, overlay, ca, booter, &fakeGate{acked: true, fresh: true}, readiness)

	res, err := h.CreateSession(context.Background(), goodReq())
	if err != nil {
		t.Fatalf("CreateSession (ready boundary): %v", err)
	}
	if !res.Routable || res.DomainUUID != "domain-sess-1" {
		t.Errorf("ready probe should be transparent: routable=%v domain=%q", res.Routable, res.DomainUUID)
	}
	if readiness.calls != 1 {
		t.Errorf("boundary-readiness probe should run exactly once, ran %d", readiness.calls)
	}
	// Same side-effect sequence as the nil/happy path.
	if len(attach.taps) != 1 || len(attach.nfts) != 1 || len(ca.injected) != 1 || len(booter.booted) != 1 {
		t.Errorf("ready probe side effects diverged: taps=%d nfts=%d injected=%d booted=%d", len(attach.taps), len(attach.nfts), len(ca.injected), len(booter.booted))
	}
}

// TestCreateSessionRefusesWhenBoundaryNotReady is the LOAD-BEARING fail-closed test: a
// not-ready probe (a definitively missing table) refuses the create at StepNone with NO
// host-side side effects — no index burned, no tap/nft, no overlay, no boot.
func TestCreateSessionRefusesWhenBoundaryNotReady(t *testing.T) {
	attach := &fakeAttach{}
	overlay := &fakeOverlay{}
	ca := &fakeCA{}
	booter := &fakeBooter{}
	const detail = "nft table inet ds_resolver_closure not present"
	readiness := &fakeReadiness{ready: false, detail: detail}
	h, cc := newTestAgentWithReadiness(t, attach, overlay, ca, booter, &fakeGate{acked: true, fresh: true}, readiness)

	_, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	// (a) StepNone — pre-step-4, the rollback "failure at 1–3" cell.
	if ce.Step != StepNone {
		t.Errorf("not-ready boundary should refuse at StepNone, got %s", ce.Step)
	}
	// (b) the message names the specific failing check.
	if !strings.Contains(ce.Error(), detail) {
		t.Errorf("error should name the failing check %q, got %q", detail, ce.Error())
	}
	// (c)-(e) NO host-side mutation.
	if len(attach.taps) != 0 || len(attach.nfts) != 0 {
		t.Errorf("not-ready boundary must not attach a tap/nft, got taps=%d nfts=%d", len(attach.taps), len(attach.nfts))
	}
	if len(overlay.disposed) != 0 {
		t.Errorf("not-ready boundary must touch no overlay, disposed=%d", len(overlay.disposed))
	}
	if len(booter.booted) != 0 {
		t.Error("not-ready boundary must not boot (fail-closed: no VM started)")
	}
	// (f) the allocator index counter did NOT advance (no index burned, D66).
	if cc.draws != 0 {
		t.Errorf("not-ready boundary must not burn an index, allocator drew %d", cc.draws)
	}
	// A pre-step-4 refusal must not claim a host-side binding exists.
	if ce.HasBinding {
		t.Error("a pre-step-4 boundary refusal must not claim a host-side binding")
	}
}

// TestCreateSessionFailClosedOnProbeError proves an UNCERTAIN probe (err != nil) is treated
// identically to not-ready: StepNone, the uncertain-probe wrap, and no boot.
func TestCreateSessionFailClosedOnProbeError(t *testing.T) {
	booter := &fakeBooter{}
	readiness := &fakeReadiness{err: errors.New("nft list table failed")}
	h, cc := newTestAgentWithReadiness(t, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, booter, &fakeGate{acked: true, fresh: true}, readiness)

	_, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	if ce.Step != StepNone {
		t.Errorf("uncertain probe should refuse at StepNone, got %s", ce.Step)
	}
	if !strings.Contains(ce.Error(), "uncertain") {
		t.Errorf("uncertain probe error should cite the uncertain-probe wrap, got %q", ce.Error())
	}
	if !errors.Is(err, readiness.err) {
		t.Error("uncertain probe should wrap the underlying probe error")
	}
	if len(booter.booted) != 0 {
		t.Error("uncertain probe must not boot (uncertain ⇒ no VM, same posture as not-ready)")
	}
	if cc.draws != 0 {
		t.Errorf("uncertain probe must not burn an index, allocator drew %d", cc.draws)
	}
}

// TestCreateSessionBoundaryFailureSources parameterizes the not-ready failure sources — a
// missing table, ds-dnsgate down, ds-tlsproxy down — and asserts each aborts at StepNone
// with no boot and no index burned.
func TestCreateSessionBoundaryFailureSources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		detail string
	}{
		{"missing-table", "nft table inet ds_boundary not present"},
		{"ds-dnsgate-down", "ds-dnsgate did not answer at 127.0.0.1:53"},
		{"ds-tlsproxy-down", "ds-tlsproxy did not answer at 127.0.0.1:18443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			booter := &fakeBooter{}
			readiness := &fakeReadiness{ready: false, detail: tc.detail}
			h, cc := newTestAgentWithReadiness(t, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, booter, &fakeGate{acked: true, fresh: true}, readiness)

			_, err := h.CreateSession(context.Background(), goodReq())
			var ce *CreateError
			if !errors.As(err, &ce) || ce.Step != StepNone {
				t.Fatalf("%s should refuse at StepNone, got %v", tc.name, err)
			}
			if !strings.Contains(ce.Error(), tc.detail) {
				t.Errorf("%s error should name %q, got %q", tc.name, tc.detail, ce.Error())
			}
			if len(booter.booted) != 0 {
				t.Errorf("%s must not boot", tc.name)
			}
			if cc.draws != 0 {
				t.Errorf("%s must not burn an index", tc.name)
			}
		})
	}
}

// TestCreateSessionReadinessDominatesValidate proves the gate's ordering: a VALID request
// with a not-ready probe refuses at StepNone BEFORE allocate (the allocator counter is
// unadvanced), so the gate sits between validate and step 4.
func TestCreateSessionReadinessDominatesValidate(t *testing.T) {
	readiness := &fakeReadiness{ready: false, detail: "nft table inet ds_proxy_out not present"}
	h, cc := newTestAgentWithReadiness(t, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true}, readiness)

	// goodReq() is a VALID request — validate() passes, so the only refusal is the gate.
	_, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) || ce.Step != StepNone {
		t.Fatalf("valid request + not-ready probe should refuse at StepNone, got %v", err)
	}
	if readiness.calls != 1 {
		t.Errorf("probe should run exactly once even on a valid request, ran %d", readiness.calls)
	}
	if cc.draws != 0 {
		t.Error("the boundary gate must sit BEFORE allocate (no index drawn)")
	}
}

// recordingCreateRecordStore is an in-memory SessionRecordStore that captures every
// record the create path Put, so a test can assert WHAT was persisted (not merely that a
// write happened).
type recordingCreateRecordStore struct {
	put []SessionRecord
}

func (s *recordingCreateRecordStore) Put(_ context.Context, rec SessionRecord) error {
	s.put = append(s.put, rec)
	return nil
}

func (s *recordingCreateRecordStore) Get(_ context.Context, _ string) (SessionRecord, bool, error) {
	return SessionRecord{}, false, nil
}

func (s *recordingCreateRecordStore) Remove(_ context.Context, _ string) error { return nil }

var _ SessionRecordStore = (*recordingCreateRecordStore)(nil)

// TestCreateSessionRecordsCABundleRef: the durable record a successful create Puts carries
// the request's CABundleRef alongside the domain + binding. It is the ONLY durable carrier
// of that ref, so without it a converged §4.2 Destroy cannot resolve — and cannot dispose —
// the host-readable CA bundle (cert + proxy-bound private key) the orchestrator producer
// dropped under .ds-ca-bundles, and D82's "the CA is destroyed at teardown" is false.
func TestCreateSessionRecordsCABundleRef(t *testing.T) {
	records := &recordingCreateRecordStore{}
	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	h, err := NewHostAgentWithRecords(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &fakeBooter{}, &fakeGate{acked: true, fresh: true}, records)
	if err != nil {
		t.Fatalf("NewHostAgentWithRecords: %v", err)
	}

	req := goodReq()
	req.CABundleRef = "ca:sess-1"
	if _, err := h.CreateSession(context.Background(), req); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if len(records.put) != 1 {
		t.Fatalf("expected exactly one durable record Put, got %d", len(records.put))
	}
	rec := records.put[0]
	if rec.CABundleRef != "ca:sess-1" {
		t.Errorf("persisted CABundleRef = %q, want %q — the §4.2 CA-bundle disposal would be skipped", rec.CABundleRef, "ca:sess-1")
	}
	if rec.SessionUUID != req.SessionUUID || rec.DomainUUID == "" {
		t.Errorf("record must still carry the session + booted domain: %+v", rec)
	}
}
