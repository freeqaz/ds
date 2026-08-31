// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── PURE arg-construction (always runs; touches no substrate) ────────────────

// TestConfigDriveImageArgs asserts the genisoimage command line is built by a PURE
// function — the exact arg split, with no subprocess launched. Mirrors
// TestOverlayCreateArgs / TestDomainDefineAndLookupArgs.
func TestConfigDriveImageArgs(t *testing.T) {
	name, args := configDriveImageArgs("genisoimage", "/var/lib/ds/overlays/sess-1.config.iso", configDriveVolumeLabel, "/var/lib/ds/overlays/sess-1.config.d")
	if name != "genisoimage" {
		t.Fatalf("genisoimage bin = %q, want genisoimage", name)
	}
	got := strings.Join(args, " ")
	want := "-output /var/lib/ds/overlays/sess-1.config.iso -volid " + configDriveVolumeLabel +
		" -input-charset utf-8 -rational-rock -joliet /var/lib/ds/overlays/sess-1.config.d"
	if got != want {
		t.Fatalf("genisoimage args = %q, want %q", got, want)
	}
}

// TestConfigDriveImageArgsDefaultsBin: an empty bin falls back to "genisoimage" so
// the offline module never hardcodes a host path (the cfg-fact convention).
func TestConfigDriveImageArgsDefaultsBin(t *testing.T) {
	name, _ := configDriveImageArgs("", "/x.iso", "L", "/x.d")
	if name != "genisoimage" {
		t.Fatalf("empty bin should default to genisoimage, got %q", name)
	}
}

// TestConfigDrivePathDeterministic asserts the per-session config-drive path is a
// pure function of (overlayDir, session) — idempotent on session_uuid — and that a
// session id with a path separator is sanitized so it can never escape the dir.
func TestConfigDrivePathDeterministic(t *testing.T) {
	a := configDrivePathFor("/var/lib/ds/overlays", "sess-9")
	b := configDrivePathFor("/var/lib/ds/overlays", "sess-9")
	if a != b {
		t.Fatalf("config-drive path not deterministic: %q vs %q", a, b)
	}
	if a != "/var/lib/ds/overlays/sess-9.config.iso" {
		t.Fatalf("config-drive path = %q, want /var/lib/ds/overlays/sess-9.config.iso", a)
	}
	// An empty overlay dir falls back to the stable in-package convention.
	if p := configDrivePathFor("", "sess-1"); p != "/var/lib/ds/overlays/sess-1.config.iso" {
		t.Fatalf("bare config-drive path = %q", p)
	}
	// A separator-bearing session id is sanitized into the dir (no ../ escape).
	dir := "/var/lib/ds/overlays"
	if got := configDrivePathFor(dir, "../../etc/escape"); filepath.Dir(got) != dir {
		t.Fatalf("config-drive path %q escaped the overlay dir %q", got, dir)
	}
}

// ── domainDefineXML 2nd-disk block (pure; always runs) ───────────────────────

// TestDomainDefineXMLConfigDriveSecondDisk asserts the config-drive form emits a
// READ-ONLY second <disk> sourced at the config-drive image, alongside the
// unchanged overlay vda — the deliverable invariant.
func TestDomainDefineXMLConfigDriveSecondDisk(t *testing.T) {
	cfg := liveTestConfig()
	overlay := "/var/lib/ds/overlays/sess-7.qcow2"
	drive := "/var/lib/ds/overlays/sess-7.config.iso"
	// Empty tap name ⇒ the legitimate no-tap nil-err path; mustXMLDrive (live_test.go)
	// fails the test on any unexpected error from the (string,error) render signature.
	xml := mustXMLDrive(t, cfg, "sess-7", overlay, "entry-ref", drive, "", 0)

	// The overlay vda disk is still the writable root.
	if !strings.Contains(xml, "<source file='"+overlay+"'/>") {
		t.Fatalf("config-drive xml dropped the overlay disk:\n%s", xml)
	}
	if !strings.Contains(xml, "<target dev='vda' bus='virtio'/>") {
		t.Fatalf("config-drive xml dropped the overlay vda target:\n%s", xml)
	}
	// The config-drive is wired as a 2nd disk at the drive image.
	if !strings.Contains(xml, "<source file='"+drive+"'/>") {
		t.Fatalf("config-drive xml does not wire the drive as a disk source:\n%s", xml)
	}
	if !strings.Contains(xml, "<target dev='vdb' bus='virtio'/>") {
		t.Fatalf("config-drive xml missing the 2nd-disk vdb target:\n%s", xml)
	}
	// It MUST be read-only (the carrier can never be written back through).
	if !strings.Contains(xml, "<readonly/>") {
		t.Fatalf("config-drive 2nd disk is not read-only:\n%s", xml)
	}
	// It is a READ-ONLY virtio-blk DISK, NOT a cdrom: virtio-blk does not support
	// ejectable/cdrom media, so `device='cdrom' bus='virtio'` is rejected live by libvirt
	// ("disk type of 'vdb' does not support ejectable media"). The <readonly/> above + the
	// inherently read-only iso9660 fs keep the carrier write-protected; the guest mounts it
	// by LABEL, so the device class is immaterial to the mount.
	if strings.Contains(xml, "device='cdrom'") {
		t.Fatalf("config-drive disk must NOT be a virtio cdrom (libvirt rejects ejectable virtio media live):\n%s", xml)
	}
	if n := strings.Count(xml, "device='disk'"); n != 2 {
		t.Fatalf("expected the overlay AND the read-only config-drive both as device='disk', got %d:\n%s", n, xml)
	}
	// There must be exactly TWO disks (the overlay + the config-drive), not three.
	if n := strings.Count(xml, "</disk>"); n != 2 {
		t.Fatalf("expected exactly 2 disks (overlay + config-drive), got %d:\n%s", n, xml)
	}
	// The raw base is still never referenced directly (D29 preserved).
	if strings.Contains(xml, cfg.BaseImage) {
		t.Fatalf("config-drive xml references the raw base directly (D29 violation):\n%s", xml)
	}
}

// TestDomainDefineXMLNoConfigDriveUnchanged asserts the no-config-drive form is
// byte-identical to the historical single-disk domainDefineXML — the existing path
// is undisturbed when there is no drive to attach.
func TestDomainDefineXMLNoConfigDriveUnchanged(t *testing.T) {
	cfg := liveTestConfig()
	overlay := "/var/lib/ds/overlays/sess-3.qcow2"
	withEmpty := mustXMLDrive(t, cfg, "sess-3", overlay, "ref", "", "", 0)
	historical := mustXML(t, cfg, "sess-3", overlay, "ref", 0)
	if withEmpty != historical {
		t.Fatalf("empty config-drive must yield the historical single-disk XML.\n got=%q\nwant=%q", withEmpty, historical)
	}
	// And the single-disk form has exactly one disk + no readonly carrier.
	if n := strings.Count(historical, "</disk>"); n != 1 {
		t.Fatalf("single-disk XML should have exactly 1 disk, got %d:\n%s", n, historical)
	}
	if strings.Contains(historical, "<readonly/>") {
		t.Fatalf("single-disk XML must not carry a read-only config-drive:\n%s", historical)
	}
}

// ── offline deliverer: NO-TOUCH (always runs) ────────────────────────────────

// TestOfflineEntrypointDelivererNoTouch asserts the offline deliverer returns the
// deterministic path and writes NOTHING to disk (no image, no staging dir).
func TestOfflineEntrypointDelivererNoTouch(t *testing.T) {
	dir := t.TempDir()
	d := offlineEntrypointDeliverer{overlayDir: dir}

	path, err := d.BuildConfigDrive(context.Background(), "sess-7", []byte("config.pb-bytes"), nil)
	if err != nil {
		t.Fatalf("offline BuildConfigDrive: %v", err)
	}
	want := filepath.Join(dir, "sess-7.config.iso")
	if path != want {
		t.Fatalf("offline config-drive path = %q, want %q", path, want)
	}
	// NO image, NO staging dir — the offline path is no-touch.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("offline deliverer wrote a config-drive image (must be no-touch): stat err=%v", err)
	}
	if _, err := os.Stat(configDriveStagingDir(dir, "sess-7")); !os.IsNotExist(err) {
		t.Fatalf("offline deliverer created a staging dir (must be no-touch)")
	}
	// The temp dir contains nothing the deliverer wrote.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("offline deliverer touched disk: dir has %d entries: %v", len(entries), entries)
	}
}

// TestOfflineEntrypointDelivererFailClosed asserts the offline deliverer fail-closes
// on an empty session/config exactly as the live writer would (no silent
// empty-drive success).
func TestOfflineEntrypointDelivererFailClosed(t *testing.T) {
	d := offlineEntrypointDeliverer{overlayDir: t.TempDir()}
	if _, err := d.BuildConfigDrive(context.Background(), "", []byte("x"), nil); err == nil {
		t.Fatal("expected an error for an empty session uuid; got nil")
	}
	if _, err := d.BuildConfigDrive(context.Background(), "sess-1", nil, nil); err == nil {
		t.Fatal("expected a fail-closed error for empty config.pb; got nil")
	}
	if _, err := d.BuildConfigDrive(context.Background(), "sess-1", []byte{}, nil); err == nil {
		t.Fatal("expected a fail-closed error for empty config.pb; got nil")
	}
	// A non-empty net-config second file does NOT excuse an empty config.pb — the
	// entrypoint config is still the required payload (fail-closed regardless).
	if _, err := d.BuildConfigDrive(context.Background(), "sess-1", nil, []byte("DS_NET_GUEST_IP=10.77.0.1\n")); err == nil {
		t.Fatal("expected a fail-closed error for empty config.pb even with a net-config second file; got nil")
	}
}

// ── gate-aware constructor: offline default must NOT touch substrate ──────────

func TestNewEntrypointDelivererOffline(t *testing.T) {
	if LiveEnabled() {
		t.Skip("DS_HOSTAGENT_LIVE set: this asserts the offline default; live path covered by the gated test")
	}
	d, err := NewEntrypointDeliverer(LiveConfig{OverlayDir: "/var/lib/ds/overlays"})
	if err != nil {
		t.Fatalf("NewEntrypointDeliverer (offline): %v", err)
	}
	if _, ok := d.(offlineEntrypointDeliverer); !ok {
		t.Fatalf("offline default deliverer = %T, want offlineEntrypointDeliverer", d)
	}
}

// ── live deliverer via the fake runner (gated; no subprocess) ────────────────

// TestLiveEntrypointDelivererBuildsImage drives the live deliverer over a recording
// runner: it writes config.pb into the staging dir and packs it with the asserted
// genisoimage command line — WITHOUT launching a subprocess (the recordingRunner
// records the call). Gated on DS_HOSTAGENT_LIVE so the default offline path is the
// only one the sandbox / CI exercises.
func TestLiveEntrypointDelivererBuildsImage(t *testing.T) {
	requireLiveGate(t)
	dir := t.TempDir()
	cfg := LiveConfig{OverlayDir: dir}
	rr := &recordingRunner{}
	d := &liveEntrypointDeliverer{cfg: cfg, run: rr}

	configPB := []byte("marshaled-entrypoint-config")
	path, err := d.BuildConfigDrive(context.Background(), "sess-9", configPB, nil)
	if err != nil {
		t.Fatalf("live BuildConfigDrive: %v", err)
	}
	wantPath := filepath.Join(dir, "sess-9.config.iso")
	if path != wantPath {
		t.Fatalf("live config-drive path = %q, want %q", path, wantPath)
	}
	// The staging dir holds config.pb with the marshaled bytes.
	staged := filepath.Join(configDriveStagingDir(dir, "sess-9"), configDriveFileName)
	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("read staged config.pb: %v", err)
	}
	if string(got) != string(configPB) {
		t.Fatalf("staged config.pb = %q, want %q", got, configPB)
	}
	// With a nil net config (the SLIRP/offline default) the second file is ABSENT —
	// the drive carries config.pb alone, byte-identical to the historical single-file drive.
	if _, err := os.Stat(filepath.Join(configDriveStagingDir(dir, "sess-9"), configDriveNetConfigFileName)); !os.IsNotExist(err) {
		t.Fatalf("a nil net config must NOT stage a %s second file: stat err=%v", configDriveNetConfigFileName, err)
	}
	// Exactly one genisoimage invocation, with the asserted command line.
	if len(rr.calls) != 1 {
		t.Fatalf("expected 1 exec (genisoimage), got %d: %v", len(rr.calls), rr.calls)
	}
	wantName, wantArgs := configDriveImageArgs("", wantPath, configDriveVolumeLabel, configDriveStagingDir(dir, "sess-9"))
	want := strings.Join(append([]string{wantName}, wantArgs...), " ")
	if got := strings.Join(rr.calls[0], " "); got != want {
		t.Fatalf("genisoimage invocation = %q, want %q", got, want)
	}
}

// TestLiveEntrypointDelivererImageBuildFailureSurfaces asserts a genisoimage failure
// surfaces (fail-closed — no half-built drive returned).
func TestLiveEntrypointDelivererImageBuildFailureSurfaces(t *testing.T) {
	requireLiveGate(t)
	dir := t.TempDir()
	rr := &recordingRunner{errs: []error{errors.New("genisoimage: no space left")}}
	d := &liveEntrypointDeliverer{cfg: LiveConfig{OverlayDir: dir}, run: rr}
	if _, err := d.BuildConfigDrive(context.Background(), "sess-x", []byte("cfg"), nil); err == nil {
		t.Fatal("expected BuildConfigDrive to surface the genisoimage failure")
	}
}

// TestLiveEntrypointDelivererStagesNetConfigSecondFile asserts the U4 second file
// (ds-net.env) is staged ALONGSIDE config.pb when the producer passes net-config bytes,
// so genisoimage packs BOTH onto the one per-session drive. Gated on DS_HOSTAGENT_LIVE.
func TestLiveEntrypointDelivererStagesNetConfigSecondFile(t *testing.T) {
	requireLiveGate(t)
	dir := t.TempDir()
	rr := &recordingRunner{}
	d := &liveEntrypointDeliverer{cfg: LiveConfig{OverlayDir: dir}, run: rr}

	configPB := []byte("marshaled-entrypoint-config")
	netPB := []byte("DS_NET_GUEST_IP=10.77.5.1\nDS_NET_PREFIX=31\nDS_NET_GATEWAY=10.77.5.0\n")
	if _, err := d.BuildConfigDrive(context.Background(), "sess-net", configPB, netPB); err != nil {
		t.Fatalf("live BuildConfigDrive: %v", err)
	}
	staging := configDriveStagingDir(dir, "sess-net")
	// config.pb is staged unchanged.
	if got, err := os.ReadFile(filepath.Join(staging, configDriveFileName)); err != nil || string(got) != string(configPB) {
		t.Fatalf("staged config.pb = %q (err=%v), want %q", got, err, configPB)
	}
	// ds-net.env is staged alongside it with the rendered bytes.
	got, err := os.ReadFile(filepath.Join(staging, configDriveNetConfigFileName))
	if err != nil {
		t.Fatalf("read staged %s: %v", configDriveNetConfigFileName, err)
	}
	if string(got) != string(netPB) {
		t.Fatalf("staged %s = %q, want %q", configDriveNetConfigFileName, got, netPB)
	}
	// Exactly one genisoimage invocation over the SAME staging dir (both files packed at once).
	if len(rr.calls) != 1 {
		t.Fatalf("expected 1 exec (genisoimage), got %d", len(rr.calls))
	}
}

// TestNewLiveEntrypointDelivererRequiresOverlayDir asserts the live deliverer
// refuses to construct without the state dir the image lives under (mirroring the
// other live bindings — never a silent fall-through). Always runs (construction
// only; no substrate).
func TestNewLiveEntrypointDelivererRequiresOverlayDir(t *testing.T) {
	if _, err := NewLiveEntrypointDeliverer(LiveConfig{}); err == nil {
		t.Fatal("expected NewLiveEntrypointDeliverer to require an overlay/state dir")
	}
}

// ── §4.2 teardown disposal (ConfigDriveDisposer) ─────────────────────────────
//
// These drive the REAL liveEntrypointDeliverer disposal path over the package
// recordingRunner (no genisoimage, no subprocess): the build stages config.pb + packs the
// image through the fake runner, then the disposal removes BOTH artifacts.

// TestLiveConfigDrive_RemoveDisposesImageAndStaging asserts the §4.2 teardown removes the
// per-session config-drive image AND the credential-bearing staging dir (doc 15 §4.2; the
// doc 06 §(b) "no leftover minted identity" row — the staging dir holds config.pb 0400,
// the rendered EntrypointConfig with the session's injected env credentials). Before this
// seam both survived every destroy and were reclaimed only by `ds-serve-stack.sh down
// --purge`. A sibling session's drive is untouched.
func TestLiveConfigDrive_RemoveDisposesImageAndStaging(t *testing.T) {
	dir := t.TempDir()
	rr := &recordingRunner{}
	d := &liveEntrypointDeliverer{cfg: LiveConfig{OverlayDir: dir}, run: rr}
	ctx := context.Background()

	// The fake runner does not actually pack an iso, so stage the image the way a real
	// genisoimage run would leave it — the disposal must remove BOTH leaves.
	for _, sess := range []string{"sess-gone", "sess-live"} {
		if _, err := d.BuildConfigDrive(ctx, sess, []byte("config-pb"), nil); err != nil {
			t.Fatalf("BuildConfigDrive(%s): %v", sess, err)
		}
		if err := os.WriteFile(configDrivePathFor(dir, sess), []byte("iso"), 0o400); err != nil {
			t.Fatalf("stage image for %s: %v", sess, err)
		}
	}
	staging := configDriveStagingDir(dir, "sess-gone")
	if _, err := os.Stat(filepath.Join(staging, configDriveFileName)); err != nil {
		t.Fatalf("precondition: staged config.pb must exist before the teardown: %v", err)
	}

	if err := d.RemoveConfigDrive(ctx, "sess-gone"); err != nil {
		t.Fatalf("RemoveConfigDrive: %v", err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("the credential-bearing staging dir must be gone, stat err = %v", err)
	}
	if _, err := os.Stat(configDrivePathFor(dir, "sess-gone")); !os.IsNotExist(err) {
		t.Fatalf("the config-drive image must be gone, stat err = %v", err)
	}
	if _, err := os.Stat(configDriveStagingDir(dir, "sess-live")); err != nil {
		t.Fatalf("a sibling session's staging dir must survive the purge: %v", err)
	}
	if _, err := os.Stat(configDrivePathFor(dir, "sess-live")); err != nil {
		t.Fatalf("a sibling session's image must survive the purge: %v", err)
	}
}

// TestLiveConfigDrive_RemoveAbsentIsCleanNoOp: ABSENT artifacts are a clean success — a
// session that never reached step 8 and a §4.2 RE-DRIVE over an already-disposed session
// both converge (the idempotent-on-session_uuid contract every teardown seam holds).
func TestLiveConfigDrive_RemoveAbsentIsCleanNoOp(t *testing.T) {
	dir := t.TempDir()
	d := &liveEntrypointDeliverer{cfg: LiveConfig{OverlayDir: dir}, run: &recordingRunner{}}
	ctx := context.Background()
	if err := d.RemoveConfigDrive(ctx, "never-built"); err != nil {
		t.Fatalf("RemoveConfigDrive(absent) = %v, want a clean no-op success", err)
	}
	if _, err := d.BuildConfigDrive(ctx, "sess-r", []byte("config-pb"), nil); err != nil {
		t.Fatalf("BuildConfigDrive: %v", err)
	}
	if err := d.RemoveConfigDrive(ctx, "sess-r"); err != nil {
		t.Fatalf("RemoveConfigDrive: %v", err)
	}
	if err := d.RemoveConfigDrive(ctx, "sess-r"); err != nil {
		t.Fatalf("RemoveConfigDrive (re-drive) = %v, want a clean no-op success", err)
	}
}

// TestLiveConfigDrive_RemoveFaultPropagates: a genuine removal fault is NEVER swallowed —
// credential-bearing material the host could not delete must surface so the §4.2 Destroy
// is truthful and the reconciler re-drives. Staged as a read-only OverlayDir, so the
// unlink inside it fails with EACCES rather than ENOENT.
func TestLiveConfigDrive_RemoveFaultPropagates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only dir does not deny unlink")
	}
	dir := t.TempDir()
	d := &liveEntrypointDeliverer{cfg: LiveConfig{OverlayDir: dir}, run: &recordingRunner{}}
	ctx := context.Background()
	if _, err := d.BuildConfigDrive(ctx, "sess-wedged", []byte("config-pb"), nil); err != nil {
		t.Fatalf("BuildConfigDrive: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod overlay dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := d.RemoveConfigDrive(ctx, "sess-wedged")
	if err == nil {
		t.Fatal("a genuine removal fault must propagate, never a swallowed clean success")
	}
	if !strings.Contains(err.Error(), "sess-wedged") {
		t.Fatalf("error %q must name the session for the §4.2 destroy_error", err)
	}
}

// TestLiveConfigDrive_RemoveEmptySessionIsRejected: an empty session id is the SAME
// fail-closed caller error BuildConfigDrive returns (Sanitize would otherwise collapse it
// onto a shared leaf and dispose an unrelated session's drive).
func TestLiveConfigDrive_RemoveEmptySessionIsRejected(t *testing.T) {
	dir := t.TempDir()
	d := &liveEntrypointDeliverer{cfg: LiveConfig{OverlayDir: dir}, run: &recordingRunner{}}
	if err := d.RemoveConfigDrive(context.Background(), ""); err == nil {
		t.Fatal("an empty session uuid must be a caller error")
	}
	if err := (offlineEntrypointDeliverer{overlayDir: dir}).RemoveConfigDrive(context.Background(), ""); err == nil {
		t.Fatal("the offline disposer must pin the SAME fail-closed caller-error contract")
	}
}

// TestOfflineConfigDrive_RemoveIsNoTouch: the offline deliverer WROTE nothing, so its
// disposal touches nothing — the offlineDomainDestroyer posture (offline.go), which keeps
// the offline/CI teardown byte-identical. A pre-existing file at the deterministic path
// (which offline could not have written) is left exactly as-is, proving no-touch.
func TestOfflineConfigDrive_RemoveIsNoTouch(t *testing.T) {
	dir := t.TempDir()
	d := offlineEntrypointDeliverer{overlayDir: dir}
	image := configDrivePathFor(dir, "sess-1")
	if err := os.WriteFile(image, []byte("not ours"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := d.RemoveConfigDrive(context.Background(), "sess-1"); err != nil {
		t.Fatalf("offline RemoveConfigDrive = %v, want a clean no-op success", err)
	}
	if _, err := os.Stat(image); err != nil {
		t.Fatalf("the offline disposer must touch NOTHING, stat = %v", err)
	}
}

// TestNewConfigDriveDisposerGateOffReturnsOfflineNoOp / …GateOn assert the gate-aware
// constructor rides the SAME NewEntrypointDeliverer selection the create path built the
// drive with — so the builder and the disposer are never on opposite sides of the gate
// (a re-implemented gate check here could dispose through the offline no-op on a live
// host, i.e. a silent credential leak). BOTH paths return a NON-NIL disposer (the
// NewDomainDestroyer posture), so the composition root wires it unconditionally.
func TestNewConfigDriveDisposerGateOffReturnsOfflineNoOp(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "")
	d, err := NewConfigDriveDisposer(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewConfigDriveDisposer (gate off): %v", err)
	}
	if d == nil {
		t.Fatal("gate off must still return a NON-nil disposer (the no-touch no-op)")
	}
	if _, ok := d.(offlineEntrypointDeliverer); !ok {
		t.Fatalf("gate off returned %T, want offlineEntrypointDeliverer", d)
	}
	if err := d.RemoveConfigDrive(context.Background(), "sess-1"); err != nil {
		t.Fatalf("offline disposal must be a no-op success, got %v", err)
	}
}

func TestNewConfigDriveDisposerGateOnReturnsLive(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1")
	d, err := NewConfigDriveDisposer(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewConfigDriveDisposer (gate on): %v", err)
	}
	if _, ok := d.(*liveEntrypointDeliverer); !ok {
		t.Fatalf("gate on returned %T, want *liveEntrypointDeliverer", d)
	}
}

// TestNewConfigDriveDisposerGateOnRequiresOverlayDir: the live path fails CONSTRUCTION
// without an overlay dir (the NewLiveEntrypointDeliverer contract it delegates to) rather
// than silently disposing nothing at the first teardown.
func TestNewConfigDriveDisposerGateOnRequiresOverlayDir(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1")
	if _, err := NewConfigDriveDisposer(LiveConfig{}); err == nil {
		t.Fatal("a live disposer with no overlay dir must be a construction error")
	}
}
