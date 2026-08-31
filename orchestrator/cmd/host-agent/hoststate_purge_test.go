// SPDX-License-Identifier: Apache-2.0

// hoststate_purge_test.go — the composition-root pins for the §4.2 PER-SESSION HOST-STATE
// purge (doc 15 §4.2; the doc 06 §(b) clean-teardown row's "no leftover minted identity").
//
// The libvirt package proves each disposal seam in isolation (attachminter_test.go,
// sessionmodestore_test.go, configdrive_test.go) and the service-level fault/ordering
// posture against fakes (service_test.go). What THOSE cannot reach is the daemon's actual
// composition: buildDriverServiceWithBridge must hand the DriverService the SAME token
// store the create-path mint writes, the SAME mode store the EntrypointProducer wrote, and
// a config-drive disposer on the SAME side of the DS_HOSTAGENT_LIVE gate the create path
// built the drive with — otherwise the purge is wired to a store nobody writes and every
// destroyed session still leaks its credential-bearing artifacts.
//
// Two levels, mirroring capturedref_live_test.go: an ALWAYS-ON offline pin (the
// unconditionally-wired config-drive disposer must leave the offline teardown a no-touch
// no-op) and a DS_HOSTAGENT_LIVE-gated rehearsal that seeds all three artifacts under a
// temp OverlayDir and asserts a real Destroy through the real composition removes them.
// Neither touches libvirt/KVM/network.
//
// Plus the recordDestroyResolver mapping pins: the daemon-root adapter is the ONLY carrier
// of the durable record's columns into the DestroyState the §4.2 ordering unwinds, so a
// column the adapter forgets is an artifact the teardown cannot reach (the CA bundle's ref
// is the live case — D82).

package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// hostStatePurgeSession is the synthetic session the rehearsal seeds host state for.
const hostStatePurgeSession = "00000000-0000-4000-8000-0000000d15f0"

// TestDaemonHostStatePurgeOfflineIsNoTouch is the OFFLINE composition pin: off
// DS_HOSTAGENT_LIVE the token store and the mode store are nil (nothing was ever written,
// so the service's purges are unwired) and the config-drive disposer — the ONE seam the
// root wires unconditionally, because NewConfigDriveDisposer returns a non-nil no-touch
// value off the gate (the NewDomainDestroyer posture) — must make NO filesystem call. So a
// Destroy through the real offline composition converges cleanly AND leaves a pre-existing
// file at the session's deterministic config-drive path untouched: byte-identical to the
// historical offline teardown.
func TestDaemonHostStatePurgeOfflineIsNoTouch(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate OFF (the default offline substrate)

	overlayDir := t.TempDir()
	cfg, err := parseConfig([]string{"-overlay-dir", overlayDir, "-host-id", "host-offline-purge"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	svc, _, bridge, _, _, err := buildDriverServiceWithBridge(cfg, newSessionCIDRegistry())
	if err != nil {
		t.Fatalf("buildDriverServiceWithBridge (offline): %v", err)
	}
	defer bridge.Shutdown()

	// A file at the path the OFFLINE deliverer would only ever RENDER (it writes nothing),
	// so any removal here is a no-touch violation.
	image := filepath.Join(overlayDir, trustpath.Sanitize(hostStatePurgeSession)+".config.iso")
	if err := os.WriteFile(image, []byte("not ours"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := svc.Destroy(context.Background(), &hypervisorv1.DestroyRequest{SessionUuid: hostStatePurgeSession}); err != nil {
		t.Fatalf("offline Destroy must converge cleanly with the host-state purges wired: %v", err)
	}
	if _, err := os.Stat(image); err != nil {
		t.Fatalf("the offline teardown must touch NOTHING under the overlay dir, stat = %v", err)
	}
}

// TestDaemonHostStatePurgeThroughLiveComposition is the DS_HOSTAGENT_LIVE-gated rehearsal
// of the whole arc through buildDriverServiceWithBridge's real wiring: seed the three
// per-session artifacts a booted session leaves under the OverlayDir — the attach TOKEN
// (the D39 bearer credential, whose TTL is the store's only revocation mechanism, doc 19
// §7), the config DRIVE (image + the staging dir holding config.pb 0400 with the injected
// env credentials), and the resolved-mode MARKER — then drive a Destroy through the
// composed DriverService and assert all three are gone. Before this wiring every one of
// them survived every teardown. It touches only a temp dir: no libvirt, no KVM, no network
// (the §4.2 domain destroy of a never-booted session is the seam's clean no-op).
func TestDaemonHostStatePurgeThroughLiveComposition(t *testing.T) {
	if !libvirt.LiveEnabled() {
		t.Skipf("offline default: %s unset — skipping the live host-state purge rehearsal (a DEFERRED MANUAL/CI step; set %s=1 to run the synthetic-filesystem purge arc, no libvirt/VM/network needed)", libvirt.EnvHostAgentLive, libvirt.EnvHostAgentLive)
	}
	// Keep the live composition OFF the real libguestfs CA-inject path (the
	// capturedref_live_test.go posture): the synthetic CA stand-in needs no host trust
	// tooling, and it does not touch the purge arc under test.
	t.Setenv("DS_HOSTAGENT_SKIP_CA_INJECT", "1")

	overlayDir := t.TempDir()
	cfg, err := parseConfig([]string{
		"-overlay-dir", overlayDir,
		"-overlay-create-script", filepath.Join(overlayDir, "overlay-create.sh"),
		"-base-image", filepath.Join(overlayDir, "base.raw"),
		"-virsh-bin", writeSyntheticVirsh(t, hostStatePurgeSession),
		"-host-id", "host-hoststate-purge",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	liveCfg := libvirt.LiveConfig{
		OverlayCreateScript: cfg.overlayCreateScript,
		OverlayDir:          cfg.overlayDir,
		BaseImage:           cfg.baseImage,
		VirshBin:            cfg.virshBin,
	}
	ctx := context.Background()

	// ── SEED the three artifacts a booted session leaves behind ──────────────────────
	// Through the SAME production stores the create path writes through, so the rehearsal
	// asserts against the real on-disk shape (not a hand-rendered path).
	tokens, err := libvirt.NewAttachTokenStore(liveCfg)
	if err != nil || tokens == nil {
		t.Fatalf("NewAttachTokenStore (live) = (%v, %v), want a non-nil store", tokens, err)
	}
	if _, _, err := tokens.TokenFor(ctx, hostStatePurgeSession); err != nil {
		t.Fatalf("mint the per-session attach token (the create-path post-boot mint): %v", err)
	}
	modes, err := libvirt.NewSessionModeStore(liveCfg)
	if err != nil || modes == nil {
		t.Fatalf("NewSessionModeStore (live) = (%v, %v), want a non-nil store", modes, err)
	}
	if err := modes.PutMode(ctx, hostStatePurgeSession, libvirt.SessionModeTerminal); err != nil {
		t.Fatalf("persist the resolved-mode marker (the create-path producer write): %v", err)
	}
	tokenFile := trustpath.AttachTokenPath(overlayDir, hostStatePurgeSession)
	marker := trustpath.SessionModePath(overlayDir, hostStatePurgeSession)
	image := trustpath.ConfigDriveImagePath(overlayDir, hostStatePurgeSession)
	staging := trustpath.ConfigDriveStagingPath(overlayDir, hostStatePurgeSession)
	// The config drive is seeded directly (its live build shells out to genisoimage, which
	// this rehearsal deliberately does not require): the staging dir with config.pb at the
	// same 0400 the live writer uses, plus the packed image beside it.
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatalf("seed config-drive staging dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staging, "config.pb"), []byte("rendered-entrypoint-config"), 0o400); err != nil {
		t.Fatalf("seed staged config.pb: %v", err)
	}
	if err := os.WriteFile(image, []byte("iso9660"), 0o400); err != nil {
		t.Fatalf("seed config-drive image: %v", err)
	}
	for _, p := range []string{tokenFile, marker, image, staging} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("precondition: %s must exist before the teardown: %v", p, err)
		}
	}

	// ── DESTROY through the real composition ─────────────────────────────────────────
	svc, _, bridge, _, _, err := buildDriverServiceWithBridge(cfg, newSessionCIDRegistry())
	if err != nil {
		t.Fatalf("buildDriverServiceWithBridge (live): %v", err)
	}
	defer bridge.Shutdown()
	if _, err := svc.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: hostStatePurgeSession}); err != nil {
		t.Fatalf("Destroy through the live composition: %v", err)
	}

	for _, p := range []string{tokenFile, marker, image, staging} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("the §4.2 teardown must dispose %s; stat err = %v", p, err)
		}
	}
	// Idempotent: a re-drive over the already-purged session still converges (every
	// disposal treats an absent artifact as a clean no-op).
	if _, err := svc.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: hostStatePurgeSession}); err != nil {
		t.Fatalf("Destroy (re-drive over already-purged host state): %v", err)
	}
}

// stubRecordStore is an in-memory SessionRecordStore for the resolver mapping pins: the
// adapter under test is pure lowering, so the durable file store (and its DS_HOSTAGENT_LIVE
// gate) is not part of what is being asserted.
type stubRecordStore struct {
	recs map[string]libvirt.SessionRecord
}

func (s stubRecordStore) Put(ctx context.Context, rec libvirt.SessionRecord) error {
	s.recs[rec.SessionUUID] = rec
	return nil
}

func (s stubRecordStore) Get(ctx context.Context, sessionUUID string) (libvirt.SessionRecord, bool, error) {
	rec, ok := s.recs[sessionUUID]
	return rec, ok, nil
}

func (s stubRecordStore) Remove(ctx context.Context, sessionUUID string) error {
	delete(s.recs, sessionUUID)
	return nil
}

// TestRecordDestroyResolverCarriesCABundleRef pins the durable-record → DestroyState
// lowering for the §4.2 CA-bundle purge. The frozen DestroyRequest carries ONLY the
// session_uuid and the in-memory clone cache is empty after a restart, so the record is the
// ref's LAST durable carrier at destroy time: drop it here and the teardown has no leaf name
// to dispose, and the per-session interception CA — cert plus proxy-bound private key —
// survives (D82). The pre-existing columns are re-asserted alongside so a future field add
// cannot quietly displace them.
func TestRecordDestroyResolverCarriesCABundleRef(t *testing.T) {
	const sessionUUID = "00000000-0000-4000-8000-0000000d15f1"
	binding := libvirt.Binding{
		HostSessionIndex: 7,
		TapName:          "dstap-7",
		OverlayPath:      "/does/not/exist/" + sessionUUID + ".qcow2",
	}
	store := stubRecordStore{recs: map[string]libvirt.SessionRecord{
		sessionUUID: {
			SessionUUID: sessionUUID,
			DomainUUID:  "domain-" + sessionUUID,
			Binding:     binding,
			CABundleRef: "ca:test-uuid",
		},
	}}

	state, found, err := recordDestroyResolver{records: store}.ResolveDestroy(context.Background(), sessionUUID)
	if err != nil || !found {
		t.Fatalf("ResolveDestroy = (_, %v, %v), want (state, true, nil)", found, err)
	}
	if state.CABundleRef != "ca:test-uuid" {
		t.Errorf("DestroyState.CABundleRef = %q, want the record's ref %q", state.CABundleRef, "ca:test-uuid")
	}
	if state.DomainUUID != "domain-"+sessionUUID {
		t.Errorf("DestroyState.DomainUUID = %q, want %q", state.DomainUUID, "domain-"+sessionUUID)
	}
	if state.OverlayPath != binding.OverlayPath {
		t.Errorf("DestroyState.OverlayPath = %q, want the binding's overlay %q", state.OverlayPath, binding.OverlayPath)
	}
	if !reflect.DeepEqual(state.Binding, binding) {
		t.Errorf("DestroyState.Binding = %+v, want %+v", state.Binding, binding)
	}
}

// TestRecordDestroyResolverPreUpgradeRecordHasNoCABundleRef pins the ROLLING-UPGRADE case: a
// record written by a build that predates the ca_bundle_ref column (the field is
// omitempty, so it is simply absent from the JSON) lowers to an EMPTY ref. The disposer must
// then treat the session as having no bundle to purge — a destroy of a pre-upgrade session
// must still converge, not fail-loud on a leaf name derived from "".
func TestRecordDestroyResolverPreUpgradeRecordHasNoCABundleRef(t *testing.T) {
	const sessionUUID = "00000000-0000-4000-8000-0000000d15f2"
	store := stubRecordStore{recs: map[string]libvirt.SessionRecord{
		sessionUUID: {
			SessionUUID: sessionUUID,
			DomainUUID:  "domain-" + sessionUUID,
			Binding:     libvirt.Binding{HostSessionIndex: 8, TapName: "dstap-8"},
		},
	}}

	state, found, err := recordDestroyResolver{records: store}.ResolveDestroy(context.Background(), sessionUUID)
	if err != nil || !found {
		t.Fatalf("ResolveDestroy = (_, %v, %v), want (state, true, nil)", found, err)
	}
	if state.CABundleRef != "" {
		t.Errorf("a pre-upgrade record must lower to an empty DestroyState.CABundleRef, got %q", state.CABundleRef)
	}
}
