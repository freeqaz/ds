// SPDX-License-Identifier: Apache-2.0

package libvirt

// posture_thread_test exercises the additive per-session permission-posture override
// threaded from CreateRequest into the gap-1 EntrypointConfig (doc 13 §2): the
// orchestrator-resolved per-create posture WINS when concrete; an UNSPECIFIED per-create
// posture falls back to the daemon-pinned EntrypointFacts.Posture (the M0 default-deny
// LOCKED). The builder's UNSPECIFIED-rejection invariant is unchanged, and the production
// path is byte-identical when no posture is supplied. Offline twins only (the package
// posture): synthetic fixture source + recording deliverer, no KVM/libvirt/exec/network.
//
// Helpers REUSED from the package's sibling test files (same `libvirt` package):
// NewFakeEntrypointConfigSource, recordingDeliverer, produceTestBinding, newMemCounter,
// fakeAttach/fakeOverlay/fakeCA/refCapturingBooter/fakeGate, goodReq.

import (
	"bytes"
	"context"
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// postureProducer builds an offline EntrypointProducer whose facts pin factsPosture as the
// daemon fallback and whose fixture source serves the opaque role-overlay bytes for ref. The
// deliver recorder is the caller's so it can read back the delivered config.pb.
func postureProducer(t *testing.T, factsPosture runtimev1.PermissionPosture, ref string, deliver *recordingDeliverer) *EntrypointProducer {
	t.Helper()
	source := NewFakeEntrypointConfigSource(map[string][]byte{ref: []byte("opaque-role-overlay-bytes")})
	p, err := NewEntrypointProducer(source, deliver, EntrypointFacts{
		HostID:          "host-local",
		Launch:          LaunchSpecInput{Command: "/usr/local/bin/ds-entrypoint"},
		Posture:         factsPosture,
		EventSocketPath: "/run/ds/attach.sock",
	})
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}
	return p
}

// decodeDeliveredPosture unmarshals a delivered config.pb and returns its permission posture.
func decodeDeliveredPosture(t *testing.T, raw []byte) runtimev1.PermissionPosture {
	t.Helper()
	var cfg runtimev1.EntrypointConfig
	if err := proto.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("proto.Unmarshal config.pb: %v", err)
	}
	return cfg.GetPosture()
}

// createSessionWithPosture drives the full §4.1 create choreography (offline fakes) with a
// CreateRequest carrying reqPosture, against a producer whose facts pin factsPosture as the
// fallback, and returns the result + the recording deliverer (with exactly one delivery).
func createSessionWithPosture(t *testing.T, reqPosture, factsPosture runtimev1.PermissionPosture) (CreateResult, *recordingDeliverer) {
	t.Helper()
	const ref = "entry-ref" // == goodReq().EntrypointConfigRef, so the source fixture resolves
	deliver := &recordingDeliverer{}
	producer := postureProducer(t, factsPosture, ref, deliver)

	plan := AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := NewAllocator(newMemCounter(0), plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	h, err := NewHostAgentWithEntrypoint(alloc, &fakeAttach{}, &fakeOverlay{}, &fakeCA{}, &refCapturingBooter{}, &fakeGate{acked: true, fresh: true}, nil, producer, nil)
	if err != nil {
		t.Fatalf("NewHostAgentWithEntrypoint: %v", err)
	}

	req := goodReq()
	req.Posture = reqPosture
	res, err := h.CreateSession(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if len(deliver.calls) != 1 {
		t.Fatalf("expected exactly one config-drive delivery, got %d", len(deliver.calls))
	}
	return res, deliver
}

// TestCreateSessionConcretePostureWins is the headline acceptance: a create whose
// CreateRequest carries a CONCRETE permission posture produces a config.pb with THAT posture,
// overriding the daemon-pinned LOCKED fallback.
func TestCreateSessionConcretePostureWins(t *testing.T) {
	res, deliver := createSessionWithPosture(t,
		runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD, // orchestrator-resolved per-create
		runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED,   // daemon-pinned fallback
	)
	if !res.Routable {
		t.Error("a happy-path create carrying a concrete posture should still be routable")
	}
	if got := decodeDeliveredPosture(t, deliver.calls[0].configPB); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD {
		t.Errorf("config.pb posture = %v, want STANDARD (the per-create override WINS over the daemon LOCKED fallback)", got)
	}
}

// TestCreateSessionUnspecifiedPostureFallsBackToDaemonLocked is the M0 default-deny guard: a
// create whose CreateRequest leaves the posture UNSPECIFIED falls back to the daemon-pinned
// LOCKED — so a create that supplies no posture is locked-down exactly as today.
func TestCreateSessionUnspecifiedPostureFallsBackToDaemonLocked(t *testing.T) {
	_, deliver := createSessionWithPosture(t,
		runtimev1.PermissionPosture_PERMISSION_POSTURE_UNSPECIFIED, // none supplied
		runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED,      // daemon-pinned fallback
	)
	if got := decodeDeliveredPosture(t, deliver.calls[0].configPB); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED {
		t.Errorf("config.pb posture = %v, want LOCKED (UNSPECIFIED per-create falls back to the daemon default-deny pin — M0 default-deny intact)", got)
	}
}

// TestProduceConfigConcretePostureWinsOverFacts proves the precedence is a TRUE override (not
// merely "non-LOCKED wins"): a concrete per-create OPEN beats a concrete facts STANDARD.
func TestProduceConfigConcretePostureWinsOverFacts(t *testing.T) {
	const ref = "role-ref"
	deliver := &recordingDeliverer{}
	p := postureProducer(t, runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD, ref, deliver)
	if _, err := p.ProduceConfig(context.Background(), ProduceInput{
		SessionUUID:         "sess-open",
		Binding:             produceTestBinding(2),
		EntrypointConfigRef: ref,
		Posture:             runtimev1.PermissionPosture_PERMISSION_POSTURE_OPEN,
	}); err != nil {
		t.Fatalf("ProduceConfig: %v", err)
	}
	if got := decodeDeliveredPosture(t, deliver.calls[0].configPB); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_OPEN {
		t.Errorf("config.pb posture = %v, want OPEN (a concrete per-create posture WINS even over a concrete facts fallback)", got)
	}
}

// TestProduceConfigUnspecifiedFallsBackToFacts proves the fallback arm at the producer seam:
// an UNSPECIFIED per-create posture resolves to the daemon-pinned facts posture.
func TestProduceConfigUnspecifiedFallsBackToFacts(t *testing.T) {
	const ref = "role-ref"
	deliver := &recordingDeliverer{}
	p := postureProducer(t, runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED, ref, deliver)
	if _, err := p.ProduceConfig(context.Background(), ProduceInput{
		SessionUUID:         "sess-fallback",
		Binding:             produceTestBinding(4),
		EntrypointConfigRef: ref,
		// Posture left UNSPECIFIED ⇒ fall back to facts.Posture (LOCKED).
	}); err != nil {
		t.Fatalf("ProduceConfig: %v", err)
	}
	if got := decodeDeliveredPosture(t, deliver.calls[0].configPB); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED {
		t.Errorf("config.pb posture = %v, want LOCKED (UNSPECIFIED per-create falls back to facts.Posture)", got)
	}
}

// TestProduceConfigNoPostureByteIdenticalToLegacyProduce pins the byte-identity guarantee: the
// legacy Produce (no per-create posture) and ProduceConfig with an UNSPECIFIED per-create
// posture marshal the SAME config.pb — the no-posture production path is byte-for-byte
// unchanged, and both carry the daemon default-deny LOCKED posture.
func TestProduceConfigNoPostureByteIdenticalToLegacyProduce(t *testing.T) {
	const ref = "role-ref"
	deliver := &recordingDeliverer{}
	p := postureProducer(t, runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED, ref, deliver)
	binding := produceTestBinding(7)

	// Legacy positional Produce (the historical call site, no posture arg).
	if _, err := p.Produce(context.Background(), "sess-bi", binding, ref); err != nil {
		t.Fatalf("Produce: %v", err)
	}
	// ProduceConfig with an UNSPECIFIED per-create posture (the production path when the
	// orchestrator supplies none). Same session + binding + ref so only the seam differs.
	if _, err := p.ProduceConfig(context.Background(), ProduceInput{
		SessionUUID:         "sess-bi",
		Binding:             binding,
		EntrypointConfigRef: ref,
	}); err != nil {
		t.Fatalf("ProduceConfig: %v", err)
	}
	if len(deliver.calls) != 2 {
		t.Fatalf("expected two deliveries, got %d", len(deliver.calls))
	}
	if !bytes.Equal(deliver.calls[0].configPB, deliver.calls[1].configPB) {
		t.Error("config.pb differs between legacy Produce and ProduceConfig(UNSPECIFIED): the no-posture production path must be BYTE-IDENTICAL")
	}
	if got := decodeDeliveredPosture(t, deliver.calls[1].configPB); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED {
		t.Errorf("no-posture config.pb posture = %v, want LOCKED (the daemon default-deny pin)", got)
	}
}

// TestProduceConfigFinalUnspecifiedFailsClosed proves BuildEntrypointConfig's
// UNSPECIFIED-rejection invariant is unchanged: when BOTH the per-create posture AND the facts
// fallback are UNSPECIFIED, the resolved posture stays UNSPECIFIED and the build fails closed —
// no config-drive is delivered.
func TestProduceConfigFinalUnspecifiedFailsClosed(t *testing.T) {
	const ref = "role-ref"
	deliver := &recordingDeliverer{}
	p := postureProducer(t, runtimev1.PermissionPosture_PERMISSION_POSTURE_UNSPECIFIED, ref, deliver)
	_, err := p.ProduceConfig(context.Background(), ProduceInput{
		SessionUUID:         "sess-bad",
		Binding:             produceTestBinding(1),
		EntrypointConfigRef: ref,
		Posture:             runtimev1.PermissionPosture_PERMISSION_POSTURE_UNSPECIFIED,
	})
	if err == nil {
		t.Fatal("ProduceConfig must FAIL CLOSED when the resolved posture is UNSPECIFIED (both per-create and facts unset) — BuildEntrypointConfig rejects it")
	}
	if len(deliver.calls) != 0 {
		t.Error("a fail-closed build must abort BEFORE delivering the config-drive")
	}
}
