// SPDX-License-Identifier: Apache-2.0

// configdrive — the in-guest delivery of the host-agent's structured
// runtimev1.EntrypointConfig (the gap-1 carrier; D38, doc 15 §4.1 step 8). The
// host agent builds the config.pb bytes (entrypointconfig.go BuildEntrypointConfig,
// pre-materialized to the per-session ref store the EntrypointConfigSource reads),
// and this seam delivers those bytes INTO the guest as a per-session READ-ONLY
// config-drive — a second disk the boot attaches alongside the qcow2 overlay. The
// in-guest ds-entrypoint mounts that drive and reads config.pb from it (the guest
// mount unit + the UDS↔TCP forwarder are U5, NOT this wave); here we only BUILD the
// drive image + WIRE it as the 2nd <disk> in the domain XML.
//
// WHY A CONFIG-DRIVE, NOT THE OVERLAY (the architecture, frozen — do not
// re-litigate): the per-session qcow2 overlay is the durable delta store (D29); we
// NEVER mutate it to inject config, and we NEVER pull libguestfs into the boot
// path. A read-only second disk (vfat/iso9660) is the cloud-init-style config-drive
// convention — built once per session from the config.pb bytes, attached read-only,
// thrown away with the session. The image build shells out to the proven
// genisoimage primitive through the SAME os/exec runner seam live.go uses for
// overlay-create.sh / virsh (no cgo, no libguestfs).
//
// LIVE-GATING (the live.go / cabundlesource.go / entrypointconfigsource.go posture):
// the real image build is reachable ONLY under DS_HOSTAGENT_LIVE — the operator-host
// posture. Off the gate (the default; the only path in the sandbox / CI / unit
// tests) the deliverer is the offline NO-TOUCH stand-in: it derives the same
// deterministic per-session config-drive path the live writer would (so the boot
// step + the domain XML see a consistent value) but writes NOTHING to disk. No
// genisoimage, no mount, no KVM is ever touched off the gate.
//
// PURE-FUNCTION ARG CONSTRUCTION (mirroring overlayCreateArgs / domainDefineArgs):
// the genisoimage / mkfs.vfat command line is built by a PURE function
// (configDriveImageArgs) split out from the exec, so the gated unit test can assert
// the exact arg split WITHOUT launching a subprocess.
//
// STDLIB-ONLY (doc.go / seams.go posture preserved): no cgo, no libvirt-go, no
// libguestfs — only os/os-exec through the runner seam.

package libvirt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// configDriveFileName is the file the in-guest ds-entrypoint reads off the mounted
// config-drive — the binary-serialized runtimev1.EntrypointConfig (config.pb). It
// MUST match the guest-side convention (vm/entrypoint reads "config.pb" from
// DS_ENTRYPOINT_CONFIG_DIR, the directory the U5 mount unit points at the drive);
// the constant is replicated here, NEVER imported (D80: this NON-test code crosses
// trees only via proto/gen/go).
const configDriveFileName = "config.pb"

// configDriveVolumeLabel is the filesystem volume label stamped onto the config
// drive so the U5 guest mount unit can find it by LABEL (the cloud-init-style
// config-drive convention) rather than by a fragile device-node guess. ≤16 bytes so
// it is legal on both iso9660 (volume id) and vfat (11-char limit is widened by the
// long-name extension, but we stay short).
const configDriveVolumeLabel = "DS_ENTRYPOINT"

// configDriveNetConfigFileName is the OPTIONAL second file packed onto the SAME
// per-session config-drive alongside config.pb: the per-session guest static net
// config (ds-net.env, rendered host-side by netconfig.go) the in-guest
// ds-apply-netcfg.sh reads to address the routed tap. It is emitted ONLY when the
// host runs the routed tap (LiveConfig.RoutedTap); off the gate the drive carries
// config.pb alone and is byte-identical to the historical single-file drive. It
// MUST match the guest convention (vm/m0-image M0_NETCFG_FILE), replicated here,
// NEVER imported (D80). Aliased to netConfigFileName (the netconfig.go constant)
// so the two names cannot drift.
const configDriveNetConfigFileName = netConfigFileName

// EntrypointDeliverer delivers the host-built config.pb bytes into the guest via a
// per-session READ-ONLY config-drive (a second disk the boot attaches). It is the
// host-agent's drive-producer side: BuildConfigDrive writes the bytes onto a
// per-session image and returns its host path so the boot step can wire it as the
// 2nd <disk> in the domain XML. Kept as a seam so the boot path is offline-fakeable:
// the live impl builds a real iso9660/vfat image via the runner seam; the offline
// fake derives the deterministic path and touches nothing (D50).
//
// FAIL-CLOSED: an empty config.pb is a caller error (there is nothing to deliver to
// the guest — the guest would fail-closed on an absent/empty config.pb), never a
// silent empty-drive success. Idempotent on session_uuid: the image path is a pure
// function of the session, so a step-8 retry re-derives the same path and the live
// writer overwrites it deterministically.
type EntrypointDeliverer interface {
	// BuildConfigDrive writes the binary config.pb (a marshaled
	// runtimev1.EntrypointConfig the host agent built) onto a per-session read-only
	// config-drive image and returns its host path. An empty sessionUUID or empty
	// configPB is a caller error (fail-closed). On the live path the returned path
	// is a real image on disk; off the gate it is the deterministic path with
	// nothing written.
	//
	// netConfigPB is the OPTIONAL per-session guest static net config (ds-net.env,
	// rendered host-side by netconfig.go) packed as a SECOND file on the SAME drive
	// alongside config.pb — emitted ONLY when the host runs the routed tap (U4). A
	// nil/empty netConfigPB packs config.pb alone, byte-identical to the historical
	// single-file drive (the SLIRP/offline default path). config.pb is untouched by
	// the second file either way.
	BuildConfigDrive(ctx context.Context, sessionUUID string, configPB, netConfigPB []byte) (configDrivePath string, err error)
}

// ConfigDriveDisposer removes the per-session config-drive artifacts at the §4.2
// TEARDOWN (doc 15 §4.2): the read-only iso9660 image
// (<OverlayDir>/<sanitize(uuid)>.config.iso) and the staging directory
// (<OverlayDir>/<sanitize(uuid)>.config.d) the live writer packed it from. It is the
// disposal half of the same seam that BUILT them — the EntrypointDeliverer owns both
// directions, so the write and the removal derive their paths from one place
// (configDrivePathFor / configDriveStagingDir) and cannot drift.
//
// WHY IT IS A TEARDOWN OBLIGATION, NOT HOUSEKEEPING (doc 06 §(b) "clean teardown …
// no leftover minted identity"): the STAGING dir holds config.pb at 0400 — the rendered
// runtimev1.EntrypointConfig, which carries the session's INJECTED ENV CREDENTIALS and the
// egress/token wiring. Until this seam existed those bytes survived every destroy and were
// only ever cleaned by an operator running `ds-serve-stack.sh down --purge`, so a host that
// ran a hundred sessions held a hundred sessions' credential-bearing config drives. The
// image is the same material packed read-only. Both die with the session, exactly like the
// per-session overlay §4.2 step 3 disposes.
//
// It is a NARROW seam kept separate from EntrypointDeliverer (rather than a widening of
// it) so the create-path consumers and their fakes are untouched; the two production
// bodies satisfy both, and NewConfigDriveDisposer re-uses the SAME gate-aware selection
// NewEntrypointDeliverer makes, so the builder and the disposer can never land on
// opposite sides of the gate.
type ConfigDriveDisposer interface {
	// RemoveConfigDrive deletes the session's config-drive image AND staging directory.
	// IDEMPOTENT on session_uuid: ABSENT artifacts (a session that never reached step 8,
	// an offline create that wrote nothing, a §4.2 re-drive over an already-purged
	// session) are a CLEAN SUCCESS, never an error. A genuine removal fault (an
	// unremovable file, a read-only OverlayDir) surfaces — a credential-bearing artifact
	// the host could not delete must never be reported as cleanly torn down.
	RemoveConfigDrive(ctx context.Context, sessionUUID string) error
}

// configDrivePathFor names the per-session config-drive image deterministically
// (under OverlayDir, sibling to the overlay) so a step-8 retry re-derives the same
// path (idempotent on session_uuid) and so the offline + live paths name the drive
// alike. When no overlay dir is configured it falls back to the same stable
// in-package convention offlineOverlayStore uses, so a bare offline default still
// yields a usable path. The session id is sanitized (the trustanchor.go convention)
// so it can never escape the dir.
func configDrivePathFor(overlayDir, sessionUUID string) string {
	dir := overlayDir
	if dir == "" {
		dir = "/var/lib/ds/overlays"
	}
	// The sanitize + ".config.iso" leaf transform is single-sourced through trustpath;
	// this consumer carries no inline extension render of its own. The image lives
	// directly under dir (a sibling of the overlay), so no subdir is joined.
	return trustpath.ConfigDriveImagePath(dir, sessionUUID)
}

// configDriveStagingDir is the per-session staging directory the live writer drops
// config.pb into before genisoimage packs it into the read-only image. A sibling of
// the image (under OverlayDir), keyed + sanitized on the session so two sessions
// never collide.
func configDriveStagingDir(overlayDir, sessionUUID string) string {
	dir := overlayDir
	if dir == "" {
		dir = "/var/lib/ds/overlays"
	}
	// The sanitize + ".config.d" leaf transform is single-sourced through trustpath; this
	// consumer carries no inline extension render of its own. The staging dir lives
	// directly under dir (a sibling of the image), so no subdir is joined.
	return trustpath.ConfigDriveStagingPath(dir, sessionUUID)
}

// configDriveImageArgs is the PURE arg-construction for the genisoimage invocation
// that packs the staging dir (holding config.pb) into the per-session read-only
// iso9660 config-drive — split out from the exec so the gated unit test can assert
// the exact command line WITHOUT running it (mirroring overlayCreateArgs /
// domainDefineArgs). iso9660 (not vfat) is chosen so the build is a single
// genisoimage call with no privileged loop-mount: `-o <image> -V <label> -input-charset
// utf-8 -r -J <stagingDir>` produces a read-only image with a findable volume label
// and Rock-Ridge/Joliet long names for config.pb. The drive is mounted read-only
// in-guest (U5); iso9660 is read-only by construction, so the read-only invariant
// holds even before the <readonly/> disk flag.
func configDriveImageArgs(genisoimageBin, imagePath, label, stagingDir string) (name string, args []string) {
	if genisoimageBin == "" {
		genisoimageBin = "genisoimage"
	}
	return genisoimageBin, []string{
		"-output", imagePath,
		"-volid", label,
		"-input-charset", "utf-8",
		"-rational-rock",
		"-joliet",
		stagingDir,
	}
}

// ── offline (default, env-unset) — NO-TOUCH ──────────────────────────────────

// offlineEntrypointDeliverer is the default no-touch EntrypointDeliverer: it
// derives the deterministic per-session config-drive path (so the boot step + the
// domain XML see a consistent value) but writes NOTHING to disk — no genisoimage, no
// staging dir, no image. It still fail-closes on an empty session/config so a test
// against the offline path asserts the SAME caller-error contract the live writer
// enforces.
type offlineEntrypointDeliverer struct {
	overlayDir string
}

// BuildConfigDrive returns the deterministic per-session config-drive path without
// touching disk. An empty session/config is the same fail-closed caller error the
// live writer returns (so the offline default never papers over a missing drop).
// The OPTIONAL netConfigPB (the U4 second file) is honored for the SAME fail-closed
// contract but writes nothing here (no-touch); the path is identical with or
// without it (the second file rides the same per-session image).
func (d offlineEntrypointDeliverer) BuildConfigDrive(_ context.Context, sessionUUID string, configPB, netConfigPB []byte) (string, error) {
	_ = netConfigPB // no-touch: the offline deliverer derives the path, writes nothing
	if sessionUUID == "" {
		return "", fmt.Errorf("config drive: empty session uuid")
	}
	if len(configPB) == 0 {
		return "", fmt.Errorf("config drive for session %s: empty config.pb (nothing to deliver to the guest) — fail-closed (D38)", sessionUUID)
	}
	return configDrivePathFor(d.overlayDir, sessionUUID), nil
}

// RemoveConfigDrive is a no-touch no-op offline: BuildConfigDrive wrote NOTHING (no
// staging dir, no image — only a rendered path), so there is nothing to dispose and the
// §4.2 teardown converges without a single filesystem call. This is the SAME posture
// offlineDomainDestroyer takes for step 1 (offline.go): the no-op IS the correct
// idempotent behavior for an absent artifact, and it keeps the offline/CI teardown
// byte-identical. An empty session is still the fail-closed caller error the live body
// returns, so the two paths pin one contract.
func (d offlineEntrypointDeliverer) RemoveConfigDrive(_ context.Context, sessionUUID string) error {
	if sessionUUID == "" {
		return fmt.Errorf("config drive: empty session uuid")
	}
	return nil
}

var _ EntrypointDeliverer = offlineEntrypointDeliverer{}
var _ ConfigDriveDisposer = offlineEntrypointDeliverer{}

// ── live (DS_HOSTAGENT_LIVE) — real read-only config-drive image ─────────────

// liveEntrypointDeliverer is the production EntrypointDeliverer: BuildConfigDrive
// writes config.pb into a per-session staging dir and packs it into a read-only
// iso9660 config-drive image via the proven genisoimage primitive through the
// os/exec runner seam (no cgo, no libguestfs, no privileged loop-mount). Reachable
// only on the live path (behind DS_HOSTAGENT_LIVE); the offline default uses the
// no-touch fake.
type liveEntrypointDeliverer struct {
	cfg LiveConfig
	run runner
}

// NewLiveEntrypointDeliverer builds the real deliverer from the host facts. It is
// reachable only on the live path; the offline default uses the package's fake. A
// missing OverlayDir is a construction error (the image + staging dir live under it,
// mirroring the other live bindings — never a silent fall-through).
func NewLiveEntrypointDeliverer(cfg LiveConfig) (EntrypointDeliverer, error) {
	if cfg.OverlayDir == "" {
		return nil, fmt.Errorf("live entrypoint deliverer requires an overlay/state dir for the config drive (DS_HOSTAGENT_LIVE)")
	}
	return &liveEntrypointDeliverer{cfg: cfg, run: execRunner{}}, nil
}

// BuildConfigDrive writes config.pb into a per-session staging dir and packs it into
// the read-only config-drive image, returning the image's host path. Fail-closed on
// an empty session/config (nothing to deliver). Idempotent on session_uuid: the
// staging dir is reset and the image overwritten deterministically, so a step-8
// retry converges on the same drive.
//
// When netConfigPB is non-empty (the U4 routed-tap path) it is written as a SECOND
// file (ds-net.env) into the SAME staging dir alongside config.pb, so genisoimage
// packs BOTH onto the one per-session drive. A nil/empty netConfigPB stages config.pb
// alone — byte-identical to the historical single-file drive.
func (d *liveEntrypointDeliverer) BuildConfigDrive(ctx context.Context, sessionUUID string, configPB, netConfigPB []byte) (string, error) {
	if sessionUUID == "" {
		return "", fmt.Errorf("config drive: empty session uuid")
	}
	if len(configPB) == 0 {
		return "", fmt.Errorf("config drive for session %s: empty config.pb (nothing to deliver to the guest) — fail-closed (D38)", sessionUUID)
	}

	staging := configDriveStagingDir(d.cfg.OverlayDir, sessionUUID)
	imagePath := configDrivePathFor(d.cfg.OverlayDir, sessionUUID)

	// Reset the staging dir so a retry never packs stale bytes alongside the fresh
	// config.pb, then write config.pb under the guest-expected filename.
	if err := os.RemoveAll(staging); err != nil {
		return "", fmt.Errorf("config drive for session %s: reset staging dir: %w", sessionUUID, err)
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return "", fmt.Errorf("config drive for session %s: stage dir: %w", sessionUUID, err)
	}
	if err := os.WriteFile(filepath.Join(staging, configDriveFileName), configPB, 0o400); err != nil {
		return "", fmt.Errorf("config drive for session %s: write %s: %w", sessionUUID, configDriveFileName, err)
	}
	// OPTIONAL second file: the per-session guest static net config (U4). Only when
	// the routed tap is active (the producer passes non-empty bytes); the staging dir
	// was reset above so a routed-tap→SLIRP retry never leaves a stale ds-net.env.
	if len(netConfigPB) > 0 {
		if err := os.WriteFile(filepath.Join(staging, configDriveNetConfigFileName), netConfigPB, 0o400); err != nil {
			return "", fmt.Errorf("config drive for session %s: write %s: %w", sessionUUID, configDriveNetConfigFileName, err)
		}
	}

	name, args := configDriveImageArgs(d.cfg.GenisoimageBin, imagePath, configDriveVolumeLabel, staging)
	if _, err := d.run.run(ctx, name, args...); err != nil {
		return "", fmt.Errorf("config drive for session %s: build image: %w", sessionUUID, err)
	}
	return imagePath, nil
}

// RemoveConfigDrive disposes the session's config-drive artifacts (the §4.2 teardown):
// the CREDENTIAL-BEARING staging dir first (it holds config.pb 0400 — the rendered
// EntrypointConfig with the injected env credentials), then the read-only image packed
// from it. STAGING FIRST is deliberate: if the second removal faults, the residue left on
// disk is the read-only iso — never the plaintext staging tree — which is the strictly
// safer half to leave behind for the re-drive.
//
// Both are derived from the SAME pure path helpers BuildConfigDrive wrote through
// (configDriveStagingDir / configDrivePathFor), so the disposal cannot name a different
// file than the build. ABSENT artifacts are a clean no-op success: os.RemoveAll already
// returns nil for a missing tree, and the image removal folds os.IsNotExist into success —
// so a session that never reached step 8 and a §4.2 re-drive over an already-purged
// session both converge. Every OTHER fault surfaces (fail-closed), because a
// credential-bearing artifact the host could not delete must not read as a clean teardown.
func (d *liveEntrypointDeliverer) RemoveConfigDrive(_ context.Context, sessionUUID string) error {
	if sessionUUID == "" {
		return fmt.Errorf("config drive: empty session uuid")
	}
	staging := configDriveStagingDir(d.cfg.OverlayDir, sessionUUID)
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("config drive for session %s: remove staging dir: %w", sessionUUID, err)
	}
	imagePath := configDrivePathFor(d.cfg.OverlayDir, sessionUUID)
	if err := os.Remove(imagePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("config drive for session %s: remove image: %w", sessionUUID, err)
	}
	return nil
}

var _ EntrypointDeliverer = (*liveEntrypointDeliverer)(nil)
var _ ConfigDriveDisposer = (*liveEntrypointDeliverer)(nil)

// NewEntrypointDeliverer is the gate-aware constructor (the NewOverlayStore /
// NewBooter template): the real iso9660 config-drive writer under DS_HOSTAGENT_LIVE,
// the no-touch offline fake otherwise (the sandbox / CI / every unit test). The
// live/offline choice rides the single EnvHostAgentLive source of truth; off the
// gate the config's OverlayDir still seeds the deterministic offline path so both
// paths name the drive alike.
func NewEntrypointDeliverer(cfg LiveConfig) (EntrypointDeliverer, error) {
	if LiveEnabled() {
		return NewLiveEntrypointDeliverer(cfg)
	}
	return offlineEntrypointDeliverer{overlayDir: cfg.OverlayDir}, nil
}

// NewConfigDriveDisposer is the gate-aware §4.2 config-drive disposal constructor: the
// real image+staging removal under DS_HOSTAGENT_LIVE, the no-touch offline no-op
// otherwise. It DELEGATES the gate decision to NewEntrypointDeliverer rather than
// re-reading LiveEnabled(), so the body that BUILT the drive and the body that DISPOSES
// it are always the same side of the single EnvHostAgentLive source of truth — a
// re-implemented gate check here could drift into disposing through the offline no-op on
// a live host (a silent credential leak).
//
// Like the DomainDestroyer (offline.go NewDomainDestroyer) — and UNLIKE the OPTIONAL
// lifecycle seams — BOTH paths return a NON-NIL disposer, because off the gate the
// no-touch no-op IS the correct behavior for artifacts that were never written; the
// composition root can therefore wire it unconditionally and the offline §4.2 teardown
// stays byte-identical (no filesystem call is made). A deliverer that does not satisfy
// the disposal role is a construction-time programming error, surfaced here rather than
// at the first teardown.
func NewConfigDriveDisposer(cfg LiveConfig) (ConfigDriveDisposer, error) {
	deliverer, err := NewEntrypointDeliverer(cfg)
	if err != nil {
		return nil, err
	}
	disposer, ok := deliverer.(ConfigDriveDisposer)
	if !ok {
		return nil, fmt.Errorf("config drive disposer: entrypoint deliverer %T does not dispose config drives", deliverer)
	}
	return disposer, nil
}
