// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// validInput returns a fully-populated, valid build input — a fixture the
// individual tests mutate to exercise a single invariant. NO vm/entrypoint import
// (D80): the validity invariants are asserted purely against the in-tree builder.
func validInput() EntrypointBuildInput {
	return EntrypointBuildInput{
		SessionUUID: "01HXSESSIONUUID0000000000",
		HostID:      "host-aaa",
		Binding: Binding{
			HostSessionIndex: 7,
			TapName:          tapName(7),
			GuestIP:          GuestAddress{Family: AddressFamilyIPv4, Address: []byte{10, 0, 0, 7}},
			OverlayPath:      "/var/lib/ds/overlays/sess.qcow2",
		},
		Launch: LaunchSpecInput{
			Command:    "/usr/local/bin/ds-cc-launch",
			Args:       []string{"--headless", "--attach"},
			Env:        []string{"DS_ROLE=builder", "HOME=/home/agent"},
			WorkingDir: "/work/repo",
		},
		Posture: runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD,
		Budget: BudgetInput{
			WallClockSeconds: 3600,
			TokenMicroUnits:  5_000_000,
		},
		EventSocketPath: "/run/ds/attach.sock",
		Egress: EgressWiringInput{
			HTTPProxy:    "10.0.0.1:18080",
			HTTPSProxy:   "10.0.0.1:18080",
			NoProxy:      []string{"10.0.0.2", "mirror.ds.local"},
			CABundlePath: "/usr/local/share/ca-certificates/ds-interception.crt",
		},
		RoleOverlayRef:       []byte("opaque-overlay-blob-\x00\x01\x02"),
		SessionTokenEndpoint: "http://169.254.0.1:8200/token",
	}
}

// TestBuildEntrypointConfig_RoundTrip asserts the built config marshals and
// unmarshals byte-stably and preserves every host-resolved field — the offline
// build→marshal→unmarshal round-trip the acceptance names.
func TestBuildEntrypointConfig_RoundTrip(t *testing.T) {
	in := validInput()
	cfg, err := BuildEntrypointConfig(in)
	if err != nil {
		t.Fatalf("BuildEntrypointConfig: %v", err)
	}

	raw, err := proto.Marshal(cfg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("marshalled config is empty")
	}

	var got runtimev1.EntrypointConfig
	if err := proto.Unmarshal(raw, &got); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if !proto.Equal(cfg, &got) {
		t.Fatalf("round-trip mismatch:\n built = %v\n got   = %v", cfg, &got)
	}

	// Spot-check the join quartet + the structured surface survived the round-trip.
	if got.GetSessionRef().GetSessionUuid() != in.SessionUUID {
		t.Errorf("session_uuid = %q, want %q", got.GetSessionRef().GetSessionUuid(), in.SessionUUID)
	}
	if got.GetSessionRef().GetHostId() != in.HostID {
		t.Errorf("host_id = %q, want %q", got.GetSessionRef().GetHostId(), in.HostID)
	}
	if got.GetSessionRef().GetHostSessionIndex() != in.Binding.HostSessionIndex {
		t.Errorf("host_session_index = %d, want %d", got.GetSessionRef().GetHostSessionIndex(), in.Binding.HostSessionIndex)
	}
	if got.GetSessionRef().GetTapName() != in.Binding.TapName {
		t.Errorf("tap_name = %q, want %q", got.GetSessionRef().GetTapName(), in.Binding.TapName)
	}
	if got.GetLaunch().GetCommand() != in.Launch.Command {
		t.Errorf("launch.command = %q, want %q", got.GetLaunch().GetCommand(), in.Launch.Command)
	}
	if got.GetPosture() != in.Posture {
		t.Errorf("posture = %v, want %v", got.GetPosture(), in.Posture)
	}
	if got.GetAttach().GetEventSocketPath() != in.EventSocketPath {
		t.Errorf("event_socket_path = %q, want %q", got.GetAttach().GetEventSocketPath(), in.EventSocketPath)
	}
	if got.GetEgress().GetCaBundlePath() != in.Egress.CABundlePath {
		t.Errorf("ca_bundle_path = %q, want %q", got.GetEgress().GetCaBundlePath(), in.Egress.CABundlePath)
	}
	if got.GetSessionTokenEndpoint() != in.SessionTokenEndpoint {
		t.Errorf("session_token_endpoint = %q, want %q", got.GetSessionTokenEndpoint(), in.SessionTokenEndpoint)
	}
}

// TestBuildEntrypointConfig_RoleOverlayOpaquePassThrough asserts the role overlay
// rides as OPAQUE bytes pass-through, byte-identical across the round-trip, and is
// COPIED (not aliased) into the message so a later caller mutation cannot leak in.
func TestBuildEntrypointConfig_RoleOverlayOpaquePassThrough(t *testing.T) {
	in := validInput()
	overlay := []byte("opaque-role-overlay-bytes")
	in.RoleOverlayRef = overlay

	cfg, err := BuildEntrypointConfig(in)
	if err != nil {
		t.Fatalf("BuildEntrypointConfig: %v", err)
	}
	if string(cfg.GetRoleOverlayRef()) != string(overlay) {
		t.Errorf("role_overlay_ref = %q, want %q", cfg.GetRoleOverlayRef(), overlay)
	}

	// Mutate the caller's slice; the built message must be unaffected (copied in).
	overlay[0] = 'X'
	if string(cfg.GetRoleOverlayRef()) == string(overlay) {
		t.Error("role_overlay_ref aliased the caller slice; want a defensive copy")
	}

	raw, err := proto.Marshal(cfg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	var got runtimev1.EntrypointConfig
	if err := proto.Unmarshal(raw, &got); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if string(got.GetRoleOverlayRef()) != "opaque-role-overlay-bytes" {
		t.Errorf("round-tripped role_overlay_ref = %q, want %q", got.GetRoleOverlayRef(), "opaque-role-overlay-bytes")
	}
}

// TestBuildEntrypointConfig_EmptyRoleOverlayAllowed asserts an empty/nil overlay is
// valid (the role's `runtime: null` — no overlay).
func TestBuildEntrypointConfig_EmptyRoleOverlayAllowed(t *testing.T) {
	in := validInput()
	in.RoleOverlayRef = nil
	cfg, err := BuildEntrypointConfig(in)
	if err != nil {
		t.Fatalf("BuildEntrypointConfig with no overlay: %v", err)
	}
	if len(cfg.GetRoleOverlayRef()) != 0 {
		t.Errorf("role_overlay_ref = %q, want empty", cfg.GetRoleOverlayRef())
	}
}

// TestBuildEntrypointConfigBytes_RoundTrip asserts the convenience marshals to the
// config.pb payload the in-guest ds-entrypoint reads, and the bytes decode to an
// equal message.
func TestBuildEntrypointConfigBytes_RoundTrip(t *testing.T) {
	in := validInput()
	raw, err := BuildEntrypointConfigBytes(in)
	if err != nil {
		t.Fatalf("BuildEntrypointConfigBytes: %v", err)
	}
	var got runtimev1.EntrypointConfig
	if err := proto.Unmarshal(raw, &got); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	want, err := BuildEntrypointConfig(in)
	if err != nil {
		t.Fatalf("BuildEntrypointConfig: %v", err)
	}
	if !proto.Equal(want, &got) {
		t.Fatalf("bytes round-trip mismatch:\n want = %v\n got  = %v", want, &got)
	}
}

// TestBuildEntrypointConfig_NoCredentialInRefs asserts the built config carries no
// credential MATERIAL on any reference field — both the positive (a clean config
// has none) and the negative (a smuggled PEM/key on a ref field fails closed).
func TestBuildEntrypointConfig_NoCredentialInRefs(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
	key := "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"

	cases := []struct {
		name  string
		mutga func(*EntrypointBuildInput)
	}{
		{"ca_bundle_path PEM", func(in *EntrypointBuildInput) { in.Egress.CABundlePath = pem }},
		{"http_proxy PEM", func(in *EntrypointBuildInput) { in.Egress.HTTPProxy = pem }},
		{"https_proxy key", func(in *EntrypointBuildInput) { in.Egress.HTTPSProxy = key }},
		{"session_token_endpoint key", func(in *EntrypointBuildInput) { in.SessionTokenEndpoint = key }},
		{"role_overlay_ref PEM", func(in *EntrypointBuildInput) { in.RoleOverlayRef = []byte(pem) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.mutga(&in)
			if _, err := BuildEntrypointConfig(in); err == nil {
				t.Fatalf("expected a fail-closed rejection for credential material in %s; got nil", tc.name)
			} else if !strings.Contains(err.Error(), "credential material") {
				t.Errorf("error %q does not name the credential-material rejection", err)
			}
		})
	}
}

// TestBuildEntrypointConfig_Invariants exercises the in-tree validity invariants
// (replicated from vm/entrypoint, NOT imported): a missing command, a relative or
// empty event-socket path, a relative ca_bundle_path, an unspecified posture, a
// missing session uuid, and a malformed env entry each fail closed.
func TestBuildEntrypointConfig_Invariants(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*EntrypointBuildInput)
		want string
	}{
		{"empty command", func(in *EntrypointBuildInput) { in.Launch.Command = "" }, "launch.command is required"},
		{"empty event socket", func(in *EntrypointBuildInput) { in.EventSocketPath = "" }, "attach.event_socket_path is required"},
		{"relative event socket", func(in *EntrypointBuildInput) { in.EventSocketPath = "run/ds/attach.sock" }, "must be absolute"},
		{"relative ca bundle", func(in *EntrypointBuildInput) { in.Egress.CABundlePath = "certs/ca.crt" }, "must be absolute"},
		{"unspecified posture", func(in *EntrypointBuildInput) {
			in.Posture = runtimev1.PermissionPosture_PERMISSION_POSTURE_UNSPECIFIED
		}, "posture must be a concrete"},
		{"missing session uuid", func(in *EntrypointBuildInput) { in.SessionUUID = "" }, "session_ref.session_uuid is required"},
		{"env not KEY=VALUE", func(in *EntrypointBuildInput) { in.Launch.Env = []string{"NOEQUALS"} }, "not KEY=VALUE"},
		{"env NUL byte", func(in *EntrypointBuildInput) { in.Launch.Env = []string{"K=v\x00x"} }, "NUL byte"},
		{"env empty key", func(in *EntrypointBuildInput) { in.Launch.Env = []string{"=novalue"} }, "not KEY=VALUE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.mut(&in)
			_, err := BuildEntrypointConfig(in)
			if err == nil {
				t.Fatalf("expected a fail-closed rejection for %q; got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// TestBuildEntrypointConfig_AbsoluteEventSocketAndNoCABundleAllowed asserts the
// permissive edges of the invariants: an absolute event socket passes, and an
// EMPTY ca_bundle_path is allowed (a session with no egress CA).
func TestBuildEntrypointConfig_AbsoluteEventSocketAndNoCABundleAllowed(t *testing.T) {
	in := validInput()
	in.Egress.CABundlePath = "" // no egress CA — allowed
	if _, err := BuildEntrypointConfig(in); err != nil {
		t.Fatalf("an empty ca_bundle_path must be allowed: %v", err)
	}
}

// produceTestBinding is a valid recorded binding for an index, the per-session
// artifact Produce folds in. The U4 net config derives off binding.HostSessionIndex.
func produceTestBinding(index uint64) Binding {
	return Binding{
		HostSessionIndex: index,
		TapName:          tapName(index),
		GuestIP:          GuestAddress{Family: AddressFamilyIPv4, Address: []byte{10, 0, 0, byte(index)}},
	}
}

// produceTestFacts is a minimal valid EntrypointFacts; routedTap toggles the U4 posture.
func produceTestFacts(routedTap bool) EntrypointFacts {
	return EntrypointFacts{
		HostID:          "host-aaa",
		Launch:          LaunchSpecInput{Command: "/usr/local/bin/ds-entrypoint"},
		Posture:         runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED,
		EventSocketPath: "/run/ds/attach.sock",
		RoutedTap:       routedTap,
	}
}

// TestProduceRoutedTapRendersNetConfig asserts Produce renders + passes the U4
// ds-net.env second file to the deliverer when RoutedTap is set, derived from the
// recorded binding's HostSessionIndex (10.77.<idx>.1/31 via 10.77.<idx>.0). The
// entrypoint config.pb is still delivered.
func TestProduceRoutedTapRendersNetConfig(t *testing.T) {
	const ref = "role-ref"
	src := NewFakeEntrypointConfigSource(map[string][]byte{ref: []byte("opaque-overlay")})
	deliver := &recordingDeliverer{}
	p, err := NewEntrypointProducer(src, deliver, produceTestFacts(true))
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}
	if _, err := p.Produce(context.Background(), "sess-rt", produceTestBinding(9), ref); err != nil {
		t.Fatalf("Produce: %v", err)
	}
	if len(deliver.calls) != 1 {
		t.Fatalf("expected one delivery, got %d", len(deliver.calls))
	}
	if len(deliver.calls[0].configPB) == 0 {
		t.Error("Produce dropped config.pb under RoutedTap")
	}
	net := string(deliver.calls[0].netConfigPB)
	for _, want := range []string{"DS_NET_GUEST_IP=10.77.9.1", "DS_NET_PREFIX=31", "DS_NET_GATEWAY=10.77.9.0"} {
		if !strings.Contains(net, want) {
			t.Errorf("Produce ds-net.env missing %q:\n%s", want, net)
		}
	}
}

// TestProduceNoRoutedTapPassesNilNetConfig asserts Produce passes a nil/empty net
// config when RoutedTap is unset (the default SLIRP path) — so the config-drive is
// byte-identical to the historical single-file (config.pb) drive.
func TestProduceNoRoutedTapPassesNilNetConfig(t *testing.T) {
	const ref = "role-ref"
	src := NewFakeEntrypointConfigSource(map[string][]byte{ref: []byte("opaque-overlay")})
	deliver := &recordingDeliverer{}
	p, err := NewEntrypointProducer(src, deliver, produceTestFacts(false))
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}
	if _, err := p.Produce(context.Background(), "sess-slirp", produceTestBinding(3), ref); err != nil {
		t.Fatalf("Produce: %v", err)
	}
	if len(deliver.calls) != 1 {
		t.Fatalf("expected one delivery, got %d", len(deliver.calls))
	}
	if len(deliver.calls[0].netConfigPB) != 0 {
		t.Errorf("RoutedTap unset must pass NO net config, got %q", deliver.calls[0].netConfigPB)
	}
}

// TestProduceRoutedTapFailClosedOnOutOfRangeIndex asserts Produce fails closed (no
// delivery) when the routed-tap net-config derivation overflows the per-session /31
// third-octet ceiling — a guest must not boot with a colliding net config under an
// active tap.
func TestProduceRoutedTapFailClosedOnOutOfRangeIndex(t *testing.T) {
	const ref = "role-ref"
	src := NewFakeEntrypointConfigSource(map[string][]byte{ref: []byte("opaque-overlay")})
	deliver := &recordingDeliverer{}
	p, err := NewEntrypointProducer(src, deliver, produceTestFacts(true))
	if err != nil {
		t.Fatalf("NewEntrypointProducer: %v", err)
	}
	if _, err := p.Produce(context.Background(), "sess-big", produceTestBinding(256), ref); err == nil {
		t.Fatal("Produce must fail closed when the routed-tap /31 derivation overflows the third octet")
	}
	if len(deliver.calls) != 0 {
		t.Error("a fail-closed net-config render must abort BEFORE delivering the config-drive")
	}
}
