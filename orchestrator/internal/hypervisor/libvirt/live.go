// SPDX-License-Identifier: Apache-2.0

// live — the production OverlayStore + Booter seam bindings for the libvirt
// host-agent create path (doc 15 §4.1 steps 7–8). These drive the REAL
// substrate: step 7's overlay clone shells out to vm/cow/overlay-create.sh (the
// proven D29 primitive — a per-session qcow2 overlay over the read-only raw
// golden base, exercised live in the golden bake leg), and step 8's boot defines
// + starts a libvirt domain over that overlay via virsh.
//
// LIVE-GATING (additive, default-path-unchanged): the real bindings are reachable
// ONLY when DS_HOSTAGENT_LIVE=1 — the operator-host posture. With the env unset
// (the default, and the only path in the sandbox / CI / unit tests) the
// constructors return the existing offline FAKE bindings, so the conformance
// suite and every unit test stay green against fakes (D50). No libvirt/KVM/qemu
// is ever touched off the gate.
//
// STDLIB-ONLY (doc.go / seams.go posture preserved): the live path does NOT pull
// in libvirt-go or any cgo — it shells out to the already-proven scripts/tools
// (overlay-create.sh, virsh) through os/exec, exactly the deferred-binding
// posture the package documents. The arg-construction is a PURE function
// (overlayCreateArgs / domainDefineArgs) split out from the exec so the gated
// unit test can assert the command line without ever running it.
//
// FAIL-CLOSED ORDERING (unchanged): the create path still injects the
// interception CA between CloneFromImage and boot (step 7 ≺ step 8, cainject.go);
// these bindings only realize the clone + boot mechanism behind that ordering.

package libvirt

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// EnvHostAgentLive is the operator-host live gate. UNSET (the default) keeps the
// tested offline/fake path; set to "1" on the operator host to reach the real
// overlay-create.sh clone + virsh boot. It is read ONCE at construction so a
// process either runs live or offline for its whole lifetime — never a per-call
// flip that could split the create choreography across substrates.
const EnvHostAgentLive = "DS_HOSTAGENT_LIVE"

// LiveEnabled reports whether the operator-host live gate is set. The default
// (unset) is the offline/fake path; only an exact "1" turns on the real
// substrate. Exported so the daemon composition root (cmd/host-agent) can branch
// its wiring on the same single source of truth.
func LiveEnabled() bool {
	return os.Getenv(EnvHostAgentLive) == "1"
}

// EnvRoutedTap is the per-session routed-tap render gate. UNSET (the default)
// keeps the historical usermode SLIRP egress NIC the live domain has always
// carried (byte-identical output); set to "1" on the operator host to render the
// per-session routed tap (`dstap-<idx>` ethernet NIC) instead. Like
// EnvHostAgentLive it is read ONCE at construction (NewLiveBooter) so a process
// either renders SLIRP or the routed tap for its whole lifetime — never a per-call
// flip. It is intentionally NOT a cmd/host-agent flag: the toggle is env-sourced
// in-package, exactly like LiveEnabled, so main.go need not be touched. The tap
// carries no egress until U3 (host routing) + U4 (guest IP) land, so gated-off
// (and even gated-on, until U3/U4) this is the inert host-XML half.
const EnvRoutedTap = "DS_ROUTED_TAP"

// RoutedTapEnabled reports whether the per-session routed-tap render gate is set.
// The default (unset) renders the historical usermode SLIRP egress NIC; only an
// exact "1" renders the per-session routed tap (`dstap-<idx>` ethernet NIC). Read
// ONCE at construction (NewLiveBooter populates LiveConfig.RoutedTap from it),
// mirroring LiveEnabled — never a per-call env read.
func RoutedTapEnabled() bool {
	return os.Getenv(EnvRoutedTap) == "1"
}

// Direct-kernel boot env sources (ADDITIVE + GATED). UNSET (the default, the
// zero value) keeps the historical disk-boot `<os>` block byte-identical — the
// canonical grub-image path is untouched. Set DS_KERNEL_PATH to render a libvirt
// direct-kernel `<os>` (`<kernel>/<initrd>/<cmdline>`) so a ROOTLESS (grub-less)
// M0 image — one built via `mke2fs -d` with NO bootloader — boots under
// qemu/libvirt by having the host hand qemu the kernel+initrd directly. The
// kernel then mounts the SAME per-session overlay (vda) as root; only the `<os>`
// block changes. Sourced ONCE at construction (NewLiveBooter), env-OR-explicit-
// field, exactly like RoutedTap (RoutedTapEnabled) and VirshBin.
const (
	// EnvKernelPath is the absolute path to the bzImage/vmlinuz the direct-kernel
	// boot hands to qemu. Empty (unset) keeps the historical disk-boot `<os>`.
	EnvKernelPath = "DS_KERNEL_PATH"
	// EnvInitrdPath is the absolute path to the initrd/initramfs the direct-kernel
	// boot hands to qemu. Consumed only when EnvKernelPath is set.
	EnvInitrdPath = "DS_INITRD_PATH"
	// EnvKernelCmdline is the kernel command line the direct-kernel boot appends.
	// Empty (with a kernel path set) falls back to DefaultKernelCmdline.
	EnvKernelCmdline = "DS_KERNEL_CMDLINE"
	// EnvSerialLog is the OPTIONAL host directory the per-session serial console is
	// logged to. UNSET (the default) renders NO serial/console device — the live
	// domain XML is byte-identical to the historical render. Set it to a writable host
	// directory to add a gated `<serial type='file'>`/`<console>` so the in-guest boot
	// + ds-entrypoint/ds-attachfwd/CC launch are observable from the host (a diagnostic
	// only — the attach byte-path rides vsock, never the serial console).
	EnvSerialLog = "DS_SERIAL_LOG"
	// EnvWorkspaceDisk is the OPTIONAL host path to the GOLDEN workspace filesystem
	// image (built by scripts/host-bringup/ds-make-workspace.sh). UNSET (the default)
	// attaches no third disk and the domain XML is byte-identical to the historical
	// render. When set, the booter CLONES the golden per session (reflink cp into
	// "<OverlayDir>/<sessionUUID>.workspace.ext4", workspacePathFor) and attaches the
	// CLONE as the third read-write disk (vdc) — the golden itself is never attached
	// to any domain, so two concurrent sessions can never mount one ext4 read-write
	// from two kernels (the 01KYRGC5NC corruption case, ruled out structurally rather
	// than by convention). The host materializes the workspace precisely so no forge
	// credential has to enter the VM (D22). The guest mounts it by LABEL.
	EnvWorkspaceDisk = "DS_WORKSPACE_DISK"
	// EnvVMMemoryMiB OVERRIDES the per-session guest RAM (the `<memory>` element).
	// UNSET (or non-positive) takes DefaultVMMemoryMiB. The historical 2048 MiB is too
	// small for a real Claude Code launch: CC's bundled Node/V8 single-executable holds
	// a multi-GB transient working set at cold start, so a 2 GB no-swap guest OOM-kills
	// it ~seconds in (the in-guest "cc stdout: connection reset by peer" the host bridge
	// sees) even with NODE_OPTIONS heap-capped. DefaultVMMemoryMiB matches the
	// proven-working drive headroom.
	EnvVMMemoryMiB = "DS_VM_MEMORY_MIB"
)

// DefaultVMMemoryMiB is the per-session guest RAM when no override is configured. It
// is sized for a real CC launch: the proven headless drive (ds-test-cc-drive.sh) boots
// the SAME M0 image with 8192 MiB and CC completes a turn; the historical 2048 MiB
// OOM-kills CC at cold start. A rig-tuned VALUE (doc 15 §10), overridable per host via
// DS_VM_MEMORY_MIB.
const DefaultVMMemoryMiB = 8192

// DefaultKernelCmdline is the cmdline a direct-kernel boot uses when KernelPath
// is set but KernelCmdline is empty. It mounts the per-session overlay (vda) as
// root by the M0 base's ext4 LABEL (DS_M0ROOT — the label the rootless mke2fs -d
// base carries), routes the console to the first serial port (so the boot is
// observable on `<serial type='file'>`), and mounts rw (the overlay is the sole
// writable surface, D29). It deliberately mounts by LABEL not by /dev path so the
// same cmdline works regardless of the virtio disk enumeration order.
const DefaultKernelCmdline = "root=LABEL=DS_M0ROOT console=ttyS0,115200 rw"

// DirectKernelEnabled reports whether the direct-kernel boot gate is set via env.
// The default (DS_KERNEL_PATH unset) keeps the historical disk-boot `<os>`; any
// non-empty DS_KERNEL_PATH turns on direct-kernel rendering. Read ONCE at
// construction (NewLiveBooter ORs the env into LiveConfig.KernelPath), mirroring
// RoutedTapEnabled — never a per-call env read.
func DirectKernelEnabled() bool {
	return os.Getenv(EnvKernelPath) != ""
}

// LiveConfig carries the host-side facts the live bindings need: where the proven
// overlay-create.sh lives, where per-session overlays are written, the raw golden
// base they clone onto, and the virsh binary. These are host-bring-up FACTS
// (doc 13 §4) supplied by the daemon composition root on the operator host; they
// are never hardcoded into the offline module.
type LiveConfig struct {
	// OverlayCreateScript is the absolute path to vm/cow/overlay-create.sh (the
	// D29 clone primitive). Required for the live OverlayStore.
	OverlayCreateScript string
	// OverlayDir is the directory per-session overlays are written into; the
	// overlay is named "<OverlayDir>/<sessionUUID>.qcow2" (matching the
	// sessionFromOverlay convention cainject.go recovers the session key from).
	OverlayDir string
	// BaseImage is the absolute path to the read-only raw M0 golden base the
	// overlay backs onto (e.g. .../ds-build/m0-base-bookworm-cc2.1.173.qcow2 on
	// the operator host). Required for the live OverlayStore.
	BaseImage string
	// VirshBin is the virsh binary the live Booter drives (default "virsh" via
	// PATH when empty). Required-by-default for the live Booter.
	VirshBin string
	// GenisoimageBin is the binary the live EntrypointDeliverer drives to pack the
	// per-session config.pb into a read-only iso9660 config-drive image (default
	// "genisoimage" via PATH when empty; configdrive.go). A host bring-up FACT (doc
	// 13 §4); 0-value falls back to the default so the offline module never hardcodes
	// a host path. Consumed only by the live EntrypointDeliverer.
	GenisoimageBin string
	// AttachPort is the fixed in-guest runtime attach port the M0 DIRECT attach
	// endpoint names (doc 15 §5.4; the standing M0-minimal endpoint = guest IP +
	// fixed runtime port). A host bring-up FACT (doc 13 §4); 0 falls back to
	// DefaultAttachPort so the offline module never hardcodes a wire port. Consumed
	// only by the live AttachHandleMinter (attachminter.go).
	AttachPort uint16
	// RoutedTap is the per-session ROUTED-TAP egress posture (the nft4 keystone path)
	// vs the M0-minimal usermode SLIRP NIC. A host bring-up FACT (doc 13 §4), DEFAULT
	// false. It gates TWO things in lockstep so the live boot is consistent:
	//   (U2) the live domain render — ON emits `<interface type='ethernet'>` with
	//        `<target dev='<tapName>'/>` from Binding.TapName; OFF keeps the historical
	//        SLIRP `<interface type='user'>` block byte-identical;
	//   (U4) the per-session guest net config (ds-net.env, netconfig.go) — ON writes
	//        the static 10.77.<idx>.1/31 (via 10.77.<idx>.0) as a SECOND config-drive
	//        file the guest applies; OFF stages only config.pb (byte-identical drive).
	// SOURCE (single value, both gates agree): the -routed-tap flag OR the
	// DS_ROUTED_TAP env (RoutedTapEnabled) — NewLiveBooter ORs the env into the
	// passed value, and the daemon root threads the same OR onto EntrypointFacts.
	// The tap carries no egress until U3 (host routing) + the 10.77/10.42 address
	// reconciliation land, so it is inert + safe even gated-on until then.
	RoutedTap bool
	// KernelPath is the DIRECT-KERNEL boot gate (ADDITIVE, DEFAULT ""). A host
	// bring-up FACT (doc 13 §4): the absolute path to the bzImage/vmlinuz qemu is
	// handed directly so a ROOTLESS (grub-less) M0 image — built via `mke2fs -d`
	// with NO bootloader — can boot under qemu/libvirt. ZERO VALUE ("") keeps the
	// historical disk-boot `<os>` block byte-identical (the canonical grub-image
	// path is untouched); non-empty renders the libvirt direct-kernel `<os>`
	// (`<kernel>/<initrd>/<cmdline>`), and the kernel mounts the SAME per-session
	// overlay (vda) as root — only the `<os>` block changes. SOURCE: the
	// DS_KERNEL_PATH env (DirectKernelEnabled) OR an explicit field — NewLiveBooter
	// ORs the env into the passed value, exactly like RoutedTap/VirshBin.
	KernelPath string
	// InitrdPath is the absolute path to the initrd/initramfs the direct-kernel
	// boot hands to qemu (the `<initrd>` element). Consumed ONLY when KernelPath is
	// set; ignored (and the `<os>` is the historical disk-boot block) otherwise.
	// SOURCE: the DS_INITRD_PATH env OR an explicit field (NewLiveBooter ORs in).
	InitrdPath string
	// KernelCmdline is the kernel command line the direct-kernel boot appends (the
	// `<cmdline>` element, XML-escaped at render). Consumed ONLY when KernelPath is
	// set. Empty (with KernelPath set) falls back to DefaultKernelCmdline
	// (`root=LABEL=DS_M0ROOT console=ttyS0,115200 rw` — mount the overlay root by
	// the rootless M0 ext4 LABEL, console on ttyS0, rw). SOURCE: the
	// DS_KERNEL_CMDLINE env OR an explicit field (NewLiveBooter ORs in).
	KernelCmdline string
	// SerialLogPath is the OPTIONAL host directory the per-session serial console is
	// logged to (the `<serial type='file'>` source). A host bring-up FACT (doc 13 §4),
	// DEFAULT "". ZERO VALUE renders NO serial/console device — the live domain XML is
	// byte-identical to the historical render (additive + off by default). When set,
	// the domain gets a `<serial type='file'><source path='<dir>/ds-<uuid>.serial.log'/>`
	// plus a `<console>`, so the in-guest boot + ds-entrypoint/CC launch are observable
	// from the host (a DIAGNOSTIC only — the attach byte-path rides vsock, never serial).
	// SOURCE: the DS_SERIAL_LOG env OR an explicit field (NewLiveBooter ORs in).
	SerialLogPath string
	// MemoryMiB OVERRIDES the per-session guest RAM (the `<memory>` element). A host
	// bring-up FACT (doc 13 §4), DEFAULT 0 ⇒ DefaultVMMemoryMiB. Sized so a real CC
	// launch does not OOM-kill at cold start (the historical 2048 MiB is too small —
	// see EnvVMMemoryMiB). SOURCE: the DS_VM_MEMORY_MIB env OR an explicit field
	// (NewLiveBooter fills it), <=0 takes the default.
	MemoryMiB int
	// WorkspaceDisk is the OPTIONAL host path to the GOLDEN workspace filesystem
	// image. A host bring-up FACT (doc 13 §4), DEFAULT "" ⇒ NO third disk and a
	// byte-identical historical render (additive + off by default, exactly like
	// SerialLogPath). NON-EMPTY ⇒ the booter reflink-CLONES it per session
	// (workspacePathFor: "<OverlayDir>/<sessionUUID>.workspace.ext4") and attaches
	// the CLONE as the third disk (vdc); the golden is only ever a copy SOURCE and
	// is never referenced by any domain XML. That per-session clone is what makes
	// two concurrent sessions safe: before this, one image attached raw+read-write
	// to every session, and two guests mounting the same ext4 from two kernels is
	// filesystem corruption, not just attribution confusion (01KYRGC5NC).
	//
	// WHY A DISK: the workspace carries the repo the session works on, and the two
	// alternatives are both closed — an in-guest `git clone` of a PRIVATE repo needs
	// a forge credential inside the VM (D22: long-lived credentials never enter the
	// VM), and there is no host->guest file channel other than a disk. The host holds
	// the repo and the credential already, so it hands over a filesystem and the
	// guest needs no credential at all. Built by scripts/host-bringup/
	// ds-make-workspace.sh; mounted by LABEL at /work by the guest's work.mount.
	//
	// UNLIKE the config-drive this is READ-WRITE: the agent edits code here, and this
	// disk is the reviewable record of what it changed (the host reads it back after
	// the session). The overlay therefore stops being the SOLE writable surface — a
	// deliberate change, because a workspace the agent cannot write is not a
	// workspace, and confining its edits to a disk the host can inspect offline is
	// easier to review than a diff of the whole root filesystem.
	//
	// SOURCE: the DS_WORKSPACE_DISK env OR an explicit field (NewLiveBooter ORs in).
	WorkspaceDisk string
}

// validate asserts the live config carries the host facts the real bindings
// need. It is only consulted on the live path (constructed under the env gate);
// the offline default never reaches it.
func (c LiveConfig) validate() error {
	if c.OverlayCreateScript == "" {
		return fmt.Errorf("live config requires the overlay-create.sh path (DS_HOSTAGENT_LIVE)")
	}
	if c.OverlayDir == "" {
		return fmt.Errorf("live config requires an overlay directory (DS_HOSTAGENT_LIVE)")
	}
	if c.BaseImage == "" {
		return fmt.Errorf("live config requires the raw golden base image path (DS_HOSTAGENT_LIVE)")
	}
	return nil
}

// runner abstracts the single os/exec edge so the gated unit test can assert the
// constructed command line without launching a subprocess (no virsh, no
// overlay-create.sh, no KVM in the sandbox). The production runner is execRunner.
type runner interface {
	run(ctx context.Context, name string, args ...string) (stdout string, err error)
}

// execRunner is the production runner: it shells out for real. It is only ever
// installed on the live path (behind DS_HOSTAGENT_LIVE).
type execRunner struct{}

func (execRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ── OverlayStore (step 7 clone) ──────────────────────────────────────────────

// liveOverlayStore is the production OverlayStore: CreateOverlay shells out to
// the proven vm/cow/overlay-create.sh to clone the read-only raw golden base into
// a per-session qcow2 overlay (the D29 invariant the bake leg proved). The script
// is idempotent on the overlay path, so a step-7 retry converges (the seams.go
// idempotency contract). DisposeOverlay removes the per-session overlay on
// rollback; it never touches the shared read-only base.
type liveOverlayStore struct {
	cfg LiveConfig
	run runner
}

// NewLiveOverlayStore builds the real OverlayStore from the host facts. It is
// reachable only on the live path; the offline default uses the package's fake.
func NewLiveOverlayStore(cfg LiveConfig) (OverlayStore, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &liveOverlayStore{cfg: cfg, run: execRunner{}}, nil
}

// overlayPathFor names the per-session overlay deterministically so a retry
// re-derives the same path (idempotent on session_uuid) and so cainject.go's
// sessionFromOverlay can recover the session key from the path.
func (s *liveOverlayStore) overlayPathFor(sessionUUID string) string {
	return filepath.Join(s.cfg.OverlayDir, sessionUUID+".qcow2")
}

// overlayCreateArgs is the PURE arg-construction for the overlay-create.sh
// invocation — split out from the exec so the gated unit test can assert the
// exact command line without running it. The script clones BaseImage (the raw
// read-only golden) into the per-session overlay; it asserts the read-only
// backing invariant itself (D29) and is idempotent on --overlay.
func overlayCreateArgs(cfg LiveConfig, overlayPath string) (name string, args []string) {
	return cfg.OverlayCreateScript, []string{
		"--base", cfg.BaseImage,
		"--overlay", overlayPath,
	}
}

func (s *liveOverlayStore) CreateOverlay(ctx context.Context, sessionUUID, imageID string) (string, error) {
	if sessionUUID == "" {
		return "", fmt.Errorf("create overlay: empty session uuid")
	}
	// imageID is content-addressed (doc 15 §5.1); on the operator host it resolves
	// to the raw golden base configured at bring-up. The v0 single-base host wires
	// BaseImage directly; a multi-base host would map imageID → base here. We carry
	// imageID through for that future resolution and to keep the seam signature.
	_ = imageID
	overlayPath := s.overlayPathFor(sessionUUID)
	name, args := overlayCreateArgs(s.cfg, overlayPath)
	if _, err := s.run.run(ctx, name, args...); err != nil {
		return "", fmt.Errorf("overlay-create clone for session %s: %w", sessionUUID, err)
	}
	return overlayPath, nil
}

func (s *liveOverlayStore) DisposeOverlay(ctx context.Context, overlayPath string) error {
	if overlayPath == "" {
		return nil
	}
	// Defense in depth: never let a rollback unwind delete anything but a
	// per-session overlay under the configured overlay dir — the shared read-only
	// raw base must never be touched by a dispose.
	if filepath.Dir(overlayPath) != filepath.Clean(s.cfg.OverlayDir) {
		return fmt.Errorf("refuse to dispose overlay outside %s: %s", s.cfg.OverlayDir, overlayPath)
	}
	if overlayPath == s.cfg.BaseImage {
		return fmt.Errorf("refuse to dispose the shared raw base as an overlay: %s", overlayPath)
	}
	if err := os.Remove(overlayPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("dispose overlay %s: %w", overlayPath, err)
	}
	return nil
}

// ── per-session workspace clone (01KYRGC5NC) ─────────────────────────────────

// workspacePathFor names the per-session WORKSPACE disk deterministically, next
// to the session's qcow2 overlay and keyed the same way (idempotent on
// session_uuid): "<OverlayDir>/<sessionUUID>.workspace.ext4". Deterministic
// naming is what lets a step-8 retry and a post-crash recovery re-boot converge
// on the SAME clone (preserving the session's edits) and what lets the host-side
// readback (stack-up-host.sh workspace-out → ds-make-workspace.sh diff) find the
// disk for a specific session after teardown. The §4.2 destroy deliberately does
// NOT purge it — the disk is the only way work leaves a gated session (D22: the
// guest holds no forge credential and cannot push), so it must outlive the
// domain until the operator reads it back.
func workspacePathFor(overlayDir, sessionUUID string) string {
	return filepath.Join(overlayDir, sessionUUID+".workspace.ext4")
}

// workspaceCloneArgs is the PURE arg-construction for the per-session workspace
// clone — split out from the exec (like overlayCreateArgs) so the gated unit
// test can assert the command line without running it. `cp --reflink=auto` is
// effectively free on the btrfs/XFS hosts this runs on (a 24 GiB image clones in
// milliseconds) and degrades to a full copy elsewhere; either way the clone is a
// PRIVATE writable copy, never a shared block device.
func workspaceCloneArgs(goldenPath, perSessionPath string) (name string, args []string) {
	return "cp", []string{"--reflink=auto", goldenPath, perSessionPath}
}

// ── Booter (step 8 boot) ─────────────────────────────────────────────────────

// liveBooter is the production Booter: Boot defines + starts a transient libvirt
// domain over the per-session overlay via virsh (doc 15 §4.1 step 8, the D38
// entrypoint contract). It uses `virsh create` with a generated transient domain
// XML so the domain need not be persisted across host reboots — the level-
// triggered reconciler re-creates from the durable overlay (D29). The local event
// socket is terminated host-side (the heartbeat reports observed state); virsh is
// only the define+boot mechanism. Idempotent on session_uuid: a domain that is
// already running for the session is reported back rather than double-booted.
type liveBooter struct {
	cfg LiveConfig
	run runner
	// The per-session config.pb config-drive is built ONCE, upstream, by the
	// create-path EntrypointProducer (create.go → Produce → BuildEntrypointConfigBytes
	// → EntrypointDeliverer) — the single owner that holds the recorded Binding + host
	// facts needed to assemble the STRUCTURED runtimev1.EntrypointConfig. The booter
	// does NOT (re)build it: it only ATTACHES the producer's already-delivered drive,
	// found at the deterministic per-session path configDrivePathFor(OverlayDir,uuid).
	// The booter holding its own ref→bytes source/deliver was the live-found gap-1
	// regression — it wrote the raw opaque ROLE-OVERLAY fragment (un-decodable as a
	// proto) over the producer's good config.pb, so ds-entrypoint fail-closed on
	// "decode entrypoint config: cannot parse invalid wire-format data" and never
	// connected the attach socket. Owner is upstream; the booter only references.
}

// NewLiveBooter builds the real Booter. Reachable only on the live path; the
// offline default uses the package's fake. The config-drive delivery seams
// (EntrypointConfigSource ref→bytes + EntrypointDeliverer image build) are
// constructed gate-aware from the same LiveConfig so the step-8 boot delivers the
// host-built config.pb into the guest via a read-only second disk.
func NewLiveBooter(cfg LiveConfig) (Booter, error) {
	virsh := cfg.VirshBin
	if virsh == "" {
		virsh = "virsh"
	}
	cfg.VirshBin = virsh
	// Resolve the routed-tap render gate ONCE at construction (the same construction-
	// time fill pattern used for VirshBin just above) so a process either renders SLIRP
	// or the per-session routed tap for its whole lifetime — never a per-call env flip.
	// The daemon root may ALSO set cfg.RoutedTap from the -routed-tap flag; we OR the
	// DS_ROUTED_TAP env in so EITHER source enables it, and the booter's render gate
	// then agrees with the EntrypointFacts net-config gate (the daemon root threads the
	// same flag-OR-env value onto EntrypointFacts).
	cfg.RoutedTap = cfg.RoutedTap || RoutedTapEnabled()
	// Resolve the DIRECT-KERNEL boot gate ONCE at construction, env-OR-explicit-field,
	// the same flag-OR-env reconciliation RoutedTap uses just above: an unset env keeps
	// the field the daemon root passed, a set env fills it. ZERO (all three empty) keeps
	// the historical disk-boot `<os>` byte-identical (the grub-image path). Default the
	// cmdline to DefaultKernelCmdline only when a kernel path is set but no cmdline was
	// given, so the rootless overlay mounts root by LABEL with the console on ttyS0.
	if cfg.KernelPath == "" {
		cfg.KernelPath = os.Getenv(EnvKernelPath)
	}
	if cfg.InitrdPath == "" {
		cfg.InitrdPath = os.Getenv(EnvInitrdPath)
	}
	if cfg.KernelCmdline == "" {
		cfg.KernelCmdline = os.Getenv(EnvKernelCmdline)
	}
	if cfg.KernelPath != "" && cfg.KernelCmdline == "" {
		cfg.KernelCmdline = DefaultKernelCmdline
	}
	// Resolve the OPTIONAL serial-console log gate ONCE at construction (env-OR-explicit-
	// field, the same pattern as the gates above). ZERO (unset) renders NO serial/console
	// device — the XML stays byte-identical. A diagnostic only; never on the attach path.
	if cfg.SerialLogPath == "" {
		cfg.SerialLogPath = os.Getenv(EnvSerialLog)
	}
	// Resolve the OPTIONAL per-session WORKSPACE disk the same way. ZERO (unset)
	// attaches no third disk, so a session with no workspace renders exactly as before.
	if cfg.WorkspaceDisk == "" {
		cfg.WorkspaceDisk = os.Getenv(EnvWorkspaceDisk)
	}
	// Resolve the per-session guest RAM ONCE at construction: an explicit positive field
	// wins; otherwise DS_VM_MEMORY_MIB (if a positive integer); otherwise DefaultVMMemoryMiB.
	// Sized so a real CC launch does not OOM at cold start (see EnvVMMemoryMiB).
	if cfg.MemoryMiB <= 0 {
		if v, err := strconv.Atoi(os.Getenv(EnvVMMemoryMiB)); err == nil && v > 0 {
			cfg.MemoryMiB = v
		} else {
			cfg.MemoryMiB = DefaultVMMemoryMiB
		}
	}
	// No config-drive carrier seams here: the create-path EntrypointProducer is the
	// SINGLE owner of build+deliver (it alone holds the recorded Binding + host facts
	// to assemble the structured config). The booter only attaches the drive the
	// producer already wrote at the deterministic configDrivePathFor(OverlayDir,uuid).
	return &liveBooter{cfg: cfg, run: execRunner{}}, nil
}

// domainName derives a stable transient-domain name from the session uuid so an
// idempotent retry keys on the same domain (the seams.go idempotency contract).
func domainName(sessionUUID string) string {
	return "ds-" + sessionUUID
}

// domainDefineXML renders the minimal transient-domain XML the live boot defines
// over the per-session overlay. It is a PURE function (no exec) so the gated unit
// test can assert the overlay is wired as the disk source and the base is never
// referenced directly (the qcow2 backing chain carries the read-only base, D29).
// The entrypointConfigRef rides as domain metadata so the D38 entrypoint contract
// has a host-side referent; the entrypoint itself is realized in-guest. It is the
// no-config-drive form (the single-disk XML); domainDefineXMLWithConfigDrive adds
// the read-only config-drive 2nd disk the step-8 boot delivers (configdrive.go).
//
// vsockCID is the deterministic per-session AF_VSOCK guest CID (binding.go /
// alloc.go vsockCID): non-zero pins it as `<cid auto='no' address=<cid>/>`; zero
// is the auto-assign sentinel (`<cid auto='yes'/>`), preserving the historical
// byte-output when no CID is threaded.
func domainDefineXML(cfg LiveConfig, sessionUUID, overlayPath, entrypointConfigRef string, vsockCID uint32) (string, error) {
	return domainDefineXMLWithConfigDrive(cfg, sessionUUID, overlayPath, entrypointConfigRef, "", "", vsockCID)
}

// xmlEscape escapes a string for safe interpolation into an XML element body
// (used for the direct-kernel `<cmdline>`, which may carry & < > or quoted args).
// It uses the stdlib encoding/xml escaper so the escaping matches libvirt's XML
// parser exactly; the other elements here interpolate host-controlled paths/ids
// and keep their existing direct Fprintf form.
func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// domainDefineXMLWithConfigDrive is domainDefineXML plus the per-session READ-ONLY
// config-drive (configdrive.go built) wired as a SECOND <disk>: the in-guest
// ds-entrypoint mounts it and reads config.pb off it (the mount unit is U5). It is a
// PURE function (no exec) so the offline unit test can assert the 2nd-disk block
// exactly without touching any substrate. The drive is marked <readonly/> AND
// device='cdrom' with the raw driver so neither the guest nor a misbehaving qemu can
// write back through it — the overlay (vda) stays the SOLE writable surface; the
// config-drive is a throwaway carrier. An empty configDrivePath omits the 2nd disk
// entirely (the no-config / offline path), so the single-disk XML is byte-identical
// to the historical domainDefineXML output when there is no drive to attach.
//
// vsockCID is the deterministic per-session AF_VSOCK guest CID (binding.go /
// alloc.go vsockCID): non-zero pins the control-channel device as
// `<cid auto='no' address=<cid>/>` so the host agent can dial a host-predictable
// guestCID:port; zero falls back to `<cid auto='yes'/>` (the libvirt auto-assign
// sentinel), keeping the output byte-identical to the historical no-CID form.
//
// tapName is the session's Binding.TapName (`dstap-<idx>`), threaded only to drive
// the egress-NIC render. When cfg.RoutedTap is ON and tapName is non-empty the NIC
// renders as the per-session routed tap (`<interface type='ethernet'><target
// dev='<tapName>'/>`); OTHERWISE — gate OFF, OR an empty tapName even with the gate
// on — it renders the historical usermode SLIRP NIC byte-identically. The empty-tap
// fallback is deliberate: a gate-on boot with no tap name must NOT emit
// `<target dev=”/>` (a malformed NIC), it falls back to SLIRP instead.
//
// FAIL-CLOSED (the error return): when the gate is ON with a NON-EMPTY tapName that
// macForTapName cannot render a deterministic MAC for (an over-ceiling index >255 or
// an unparseable `dstap-<idx>`), this REFUSES with an error rather than silently
// downgrading to the UNGATED SLIRP NIC — a routed-tap session that names a tap must
// come up on that tap or not at all (D66: no partial boundary; a render-layer
// fail-open would un-gate a session with no per-session NFT). This case is unreachable
// via Allocate() today (alloc.go applies the same third-octet ceiling fail-closed
// BEFORE a Binding/tapName exists), but a non-allocator tapName reaching the render (a
// future caller, a hand-built LiveConfig) must not un-gate. The two LEGITIMATE SLIRP
// arms stay error-free and byte-identical: (a) gate-OFF (!cfg.RoutedTap), and (b)
// RoutedTap with an EMPTY tapName (the documented 'no binding yet' fall-through).
func domainDefineXMLWithConfigDrive(cfg LiveConfig, sessionUUID, overlayPath, entrypointConfigRef, configDrivePath, tapName string, vsockCID uint32) (string, error) {
	var b strings.Builder
	b.WriteString("<domain type='kvm'>\n")
	fmt.Fprintf(&b, "  <name>%s</name>\n", domainName(sessionUUID))
	// Per-session guest RAM. Sized for a real CC launch (DefaultVMMemoryMiB, overridable
	// via DS_VM_MEMORY_MIB) — the historical 2048 MiB OOM-killed CC at cold start
	// (multi-GB V8 transient). A non-positive MemoryMiB (a render not routed through
	// NewLiveBooter's fill) falls back to the default so the guest is never undersized.
	memMiB := cfg.MemoryMiB
	if memMiB <= 0 {
		memMiB = DefaultVMMemoryMiB
	}
	fmt.Fprintf(&b, "  <memory unit='MiB'>%d</memory>\n", memMiB)
	b.WriteString("  <vcpu>2</vcpu>\n")
	// CPU passthrough (UNCONDITIONAL correctness requirement). Without a <cpu>
	// element libvirt/qemu default to the qemu64 CPU model, which lacks AVX2/AVX512.
	// Modern self-contained binaries — notably Claude Code's bundled Node/V8 single-
	// executable (claude.exe) — issue AVX2 instructions and die ~13s in with SIGILL
	// ("trap invalid opcode") on a qemu64 guest (LIVE-FOUND 2026-06-18 driving real
	// CC in the rootless KVM VM; NOT an OOM). `host-passthrough` is the libvirt
	// equivalent of qemu `-cpu host`: it exposes the real host CPU's feature set
	// (incl. AVX2) to the guest. check='none' skips libvirt's per-feature ABI check
	// (we want the host's features verbatim, not a stable named model). This applies
	// to ALL real workloads on this single-host M0 hypervisor, not just CC; the
	// fakes/conformance paths never render this XML.
	b.WriteString("  <cpu mode='host-passthrough' check='none'/>\n")
	b.WriteString("  <metadata>\n")
	fmt.Fprintf(&b, "    <ds:session xmlns:ds='urn:dreamserpent' uuid='%s' entrypoint='%s'/>\n", sessionUUID, entrypointConfigRef)
	b.WriteString("  </metadata>\n")
	if cfg.KernelPath != "" {
		// DIRECT-KERNEL boot (gate-ON, ADDITIVE): hand qemu the kernel+initrd+cmdline
		// directly so a ROOTLESS (grub-less) M0 overlay boots (the base was built via
		// `mke2fs -d` with NO bootloader, so it can ONLY boot direct-kernel). The kernel
		// mounts the SAME per-session overlay (vda) as root — ONLY the `<os>` block
		// changes; the disk(s), config-drive, vsock, and NIC all render exactly as the
		// disk-boot path does below. The cmdline is XML-escaped (it may carry & < > and
		// quoted args); NewLiveBooter has already defaulted it to DefaultKernelCmdline
		// when a kernel path was set with no cmdline.
		fmt.Fprintf(&b, "  <os><type arch='x86_64'>hvm</type><kernel>%s</kernel><initrd>%s</initrd><cmdline>%s</cmdline></os>\n",
			cfg.KernelPath, cfg.InitrdPath, xmlEscape(cfg.KernelCmdline))
	} else {
		// DISK boot (gate-OFF, the DEFAULT): the historical single-line `<os>` — qemu
		// boots the vda overlay's own bootloader (the canonical grub golden-image path).
		// Byte-identical to the pre-direct-kernel render.
		b.WriteString("  <os><type arch='x86_64'>hvm</type></os>\n")
	}
	b.WriteString("  <devices>\n")
	b.WriteString("    <disk type='file' device='disk'>\n")
	b.WriteString("      <driver name='qemu' type='qcow2'/>\n")
	fmt.Fprintf(&b, "      <source file='%s'/>\n", overlayPath)
	b.WriteString("      <target dev='vda' bus='virtio'/>\n")
	b.WriteString("    </disk>\n")
	if configDrivePath != "" {
		// The per-session config-drive: the read-only iso9660 image attached as a 2nd
		// disk. A READ-ONLY virtio-blk disk (not a cdrom): virtio-blk does not support
		// ejectable/cdrom media, so `device='cdrom' bus='virtio'` is rejected by libvirt
		// (`disk type of 'vdb' does not support ejectable media`). The carrier is still
		// write-protected by the explicit <readonly/> (qemu presents it read-only) PLUS
		// the inherently read-only iso9660 filesystem, so the guest can never write it
		// back through; the in-guest run-ds-entrypoint.mount finds it by LABEL
		// (DS_ENTRYPOINT), so the device class is immaterial to the mount (U5). raw
		// driver — the iso is raw bytes.
		b.WriteString("    <disk type='file' device='disk'>\n")
		b.WriteString("      <driver name='qemu' type='raw'/>\n")
		fmt.Fprintf(&b, "      <source file='%s'/>\n", configDrivePath)
		b.WriteString("      <target dev='vdb' bus='virtio'/>\n")
		b.WriteString("      <readonly/>\n")
		b.WriteString("    </disk>\n")
	}
	if cfg.WorkspaceDisk != "" {
		// The per-session WORKSPACE disk (vdc): a READ-WRITE raw ext4 filesystem the
		// host built with the repo already on it. Deliberately NOT <readonly/> — the
		// agent edits code here, which is the whole point, and the host reads the disk
		// back afterwards to review what changed.
		//
		// Attached UNCONDITIONALLY of the config-drive: the two are independent
		// carriers (config-drive = instructions, fail-closed; workspace = code,
		// fail-open), so a workspace must attach even on a session with no config
		// drive. Target letters are fixed rather than sequential — vdc is the workspace
		// whether or not vdb is present — because the guest mounts by LABEL and a
		// shifting device letter is exactly the fragility that convention avoids.
		b.WriteString("    <disk type='file' device='disk'>\n")
		b.WriteString("      <driver name='qemu' type='raw'/>\n")
		fmt.Fprintf(&b, "      <source file='%s'/>\n", cfg.WorkspaceDisk)
		b.WriteString("      <target dev='vdc' bus='virtio'/>\n")
		b.WriteString("    </disk>\n")
	}
	// The AF_VSOCK control channel: a virtio-vsock device carrying the host-agent's
	// attach byte-path — no tap, no guest IP, no nft rule (the attach control channel
	// is settled on vsock; box-capability-validated against libvirt 9.0.0 +
	// /dev/vhost-vsock). It rides on EVERY live domain (single-disk and config-drive
	// forms alike), so the host-agent can serve the attach leg over vsock regardless
	// of whether a config-drive is attached. When a deterministic per-session CID is
	// threaded (vsockCID != 0, alloc.go), it is PINNED as `auto='no' address=<cid>`
	// so the host agent can dial a host-predictable guestCID:port without
	// round-tripping a libvirt auto-assignment; vsockCID == 0 falls back to
	// `auto='yes'` (libvirt-assigned), keeping the historical byte-output.
	b.WriteString("    <vsock model='virtio'>\n")
	if vsockCID != 0 {
		fmt.Fprintf(&b, "      <cid auto='no' address='%d'/>\n", vsockCID)
	} else {
		b.WriteString("      <cid auto='yes'/>\n")
	}
	b.WriteString("    </vsock>\n")
	mac, macOK := macForTapName(tapName)
	if cfg.RoutedTap && tapName != "" && !macOK {
		// FAIL-CLOSED: the gate is ON and a per-session tap is NAMED, but its
		// `dstap-<idx>` index is unparseable or past the macIndexMaxOctet (255)
		// ceiling, so macForTapName cannot render the deterministic MAC that the
		// routed-tap NIC requires. REFUSE the domain-define rather than fall through
		// to the UNGATED SLIRP NIC below: a routed-tap session must attach to its
		// named tap (with a per-session NFT in place, D66) or not boot at all — a
		// silent SLIRP downgrade would un-gate the session's egress with no per-session
		// boundary (a render-layer fail-open in the no-partial-boundary sense). This is
		// distinct from the two LEGITIMATE SLIRP arms (gate-OFF, or gate-ON with an
		// EMPTY tapName), which are reached only when NO tap is named and thus keep
		// their byte-identical fall-through below.
		return "", fmt.Errorf("domainDefineXML session %s: routed-tap gate ON with tap %q whose index is unparseable or past the %d ceiling: refusing to un-gate to SLIRP", sessionUUID, tapName, macIndexMaxOctet)
	}
	if cfg.RoutedTap && tapName != "" && macOK {
		// U2 host-XML half: the per-session ROUTED TAP egress NIC. type='ethernet'
		// with `<target dev='<tapName>' managed='no'/>` attaches the VM to the
		// boundary-owned `dstap-<idx>` tap (Binding.TapName) instead of the usermode
		// SLIRP NIC, so a later per-session NFT can govern its egress. managed='no' is
		// REQUIRED: the tap is created by the AttachPrimitive (liveAttach.CreateTap, the
		// ds-nft cgo edge) at step-4 BEFORE boot — so the per-session NFT is in place
		// before the VM has a NIC (D66; no partial-boundary window). Without managed='no'
		// libvirt tries to create the tap itself and fails closed on the already-existing
		// dstap-<idx> ("Requested operation is not valid: The dstap-N interface already
		// exists"). Gated behind cfg.RoutedTap (DS_ROUTED_TAP, populated at construction
		// by NewLiveBooter): default-OFF the historical SLIRP block below renders
		// byte-identically. An EMPTY tapName falls through to SLIRP (the 'no binding yet'
		// path) rather than emit a malformed `<target dev=''/>`; a NON-EMPTY tapName whose
		// index is unparseable or over-ceiling is refused ABOVE (fail-closed), never
		// un-gated to SLIRP.
		//
		// The DETERMINISTIC `<mac>` is the load-bearing addition (macForTapName →
		// macForIndex): without it libvirt auto-assigns a RANDOM MAC and the fat L2
		// image's MAC-matched systemd-networkd drop-in (05-l2-routedtap.network, MAC
		// 52:54:00:77:07:01 for index 7) never fires, so the guest comes up with NO IP.
		// Pinning `52:54:00:77:<idx>:01` (byte-identical to l2-up.sh's manual qemu
		// `-device ...,mac=...`) makes the SAME proven fat image self-configure
		// 10.77.<idx>.1/31 by construction. The MAC is recovered from the tap name's
		// `dstap-<idx>` index, so the render stays a pure function of its existing args.
		b.WriteString("    <interface type='ethernet'>\n")
		fmt.Fprintf(&b, "      <target dev='%s' managed='no'/>\n", tapName)
		fmt.Fprintf(&b, "      <mac address='%s'/>\n", mac)
		b.WriteString("      <model type='virtio'/>\n")
		b.WriteString("    </interface>\n")
	} else {
		// Minimal egress NIC: a usermode (SLIRP) virtio interface. type='user' is
		// qemu's built-in userspace NAT — it needs NO host tap, bridge, or privileged
		// network setup, so it works under qemu:///session and gives the in-guest CC a
		// route to the egress gateway (the M0-minimal egress path of the
		// m1-live-session-transport spike). This is NOT the per-session default-deny /
		// dnsgate / tlsproxy enforcement — that is the parallel nft4 keystone (a routed
		// tap + per-session NFT), owned in the dataplane lane, NOT here. It rides on
		// EVERY live domain (both disk forms), like the vsock control channel. This is
		// the gate-OFF default — byte-identical to the historical render.
		b.WriteString("    <interface type='user'>\n")
		b.WriteString("      <model type='virtio'/>\n")
		b.WriteString("    </interface>\n")
	}
	// OPTIONAL serial console (gated on cfg.SerialLogPath, DEFAULT off). When a host
	// log dir is configured, attach a `<serial type='file'>` writing the guest's ttyS0
	// to a per-session file plus a `<console>` aliased to it, so the in-guest boot —
	// systemd reaching multi-user, ds-attachfwd bridging vsock:4242, ds-entrypoint
	// launching CC, and CC's stream-json on stdout — is observable from the HOST. The
	// direct-kernel cmdline already routes the console to ttyS0 (DefaultKernelCmdline),
	// so this captures the full boot. It is a DIAGNOSTIC: the attach byte-path rides
	// vsock, never the serial console. Empty path renders nothing (byte-identical XML).
	if cfg.SerialLogPath != "" {
		serialPath := serialLogPathFor(cfg.SerialLogPath, sessionUUID)
		b.WriteString("    <serial type='file'>\n")
		fmt.Fprintf(&b, "      <source path='%s'/>\n", xmlEscape(serialPath))
		b.WriteString("      <target type='isa-serial' port='0'/>\n")
		b.WriteString("    </serial>\n")
		b.WriteString("    <console type='file'>\n")
		fmt.Fprintf(&b, "      <source path='%s'/>\n", xmlEscape(serialPath))
		b.WriteString("      <target type='serial' port='0'/>\n")
		b.WriteString("    </console>\n")
	}
	b.WriteString("  </devices>\n")
	b.WriteString("</domain>\n")
	return b.String(), nil
}

// serialLogPathFor is the deterministic per-session serial-log file path under the
// configured host log directory: "<dir>/ds-<sessionUUID>.serial.log". A per-session
// file (keyed on the session UUID, sanitized like the domain name) keeps concurrent
// sessions' consoles from clobbering one log. PURE — split out so the gated XML test
// asserts the path shape without a host filesystem.
func serialLogPathFor(dir, sessionUUID string) string {
	return filepath.Join(dir, "ds-"+sanitizeAnchorComponent(sessionUUID)+".serial.log")
}

// macForIndex derives the DETERMINISTIC routed-tap NIC MAC from the host-session
// index, BYTE-IDENTICAL to the manual nested-testbed path
// (scripts/nested-testbed/inside-l1/l2-up.sh:
// `mac=52:54:00:77:$(printf '%02x' "$IDX"):01`) so the SAME proven fat L2 image's
// MAC-matched systemd-networkd drop-in (l1.Containerfile 05-l2-routedtap.network,
// MAC 52:54:00:77:07:01 for index 7) self-configures its static routed-tap IP
// (10.77.<idx>.1/31) WITHOUT us having to script the in-guest net. Without a pinned
// MAC libvirt auto-assigns a RANDOM one, the [Match] never fires, and the L2 guest
// never gets an IP. The prefix is the locally-administered QEMU OUI `52:54:00:77`
// (the `:77` distinguishes the routed-tap family); the last octet is fixed `:01`
// (the guest end of the /31). Only the routed-tap branch emits this; SLIRP/m0 are
// unaffected (m0 derives its IP from the config-drive ds-net.env, not the MAC, so a
// deterministic MAC is harmless there).
//
// CEILING — option (a), reconciled with netConfigForIndex's /31 third-octet ceiling
// (netconfig.go netConfigMaxIndexThirdOct=255): the index is rendered as the 5th
// octet in TWO HEX DIGITS (`%02x`), so it is a well-formed octet for the WHOLE
// supported range idx 0..255 — the SAME range netConfigForIndex admits for the
// 10.77.<idx>.x /31. libvirt accepts hex octets (`ff` is a valid MAC byte), so this
// stays a single, correct octet where the old `%02d` (decimal) went to three digits
// at idx 100 and emitted a MALFORMED octet (`52:54:00:77:100:01`) that libvirt
// rejects at domain-define — even though the /31 was valid. The two ceilings now
// AGREE by construction: a routed-tap session that gets a valid 10.77.<idx>.1/31
// also gets a well-formed MAC. Rendering is byte-STABLE across the change at every
// two-hex-digit-equals-two-decimal-digit index, notably the pinned demo index 7
// ("07" in both bases), so the baked fat-L2 image's idx-7 static drop-in
// (l1.Containerfile 05-l2-routedtap.network, MAC 52:54:00:77:07:01) needs NO rebake;
// only idx 10..99 (whose hex differs from decimal, e.g. idx 10 -> "0a") and idx
// 100..255 (previously malformed) change render. macForTapName caps the parseable
// index at this same 255 ceiling and returns ok=false past it; the render then REFUSES
// (fail-closed) rather than emit a MAC out of the /31's range OR un-gate the named tap
// to SLIRP — only an EMPTY tap name legitimately falls back to SLIRP. The
// three script sources that must byte-match this render — l2-up.sh's
// `printf '%02x'` mac= line, l1.Containerfile's + orchestrator-boot-l2.sh's idx-7
// literals (byte-stable at "07") — are kept in hex lockstep with this render.
const macIndexMaxOctet = netConfigMaxIndexThirdOct // 255: same ceiling as the /31 third octet

func macForIndex(index uint64) string {
	return fmt.Sprintf("52:54:00:77:%02x:01", index)
}

// macForTapName derives the deterministic routed-tap MAC from the session's
// `dstap-<idx>` tap name by recovering the host-session index (the same join key
// alloc.go's tapName encodes) and feeding macForIndex. It returns ok=false when the
// name does not carry a parseable `dstap-<idx>` index (an empty or malformed tap
// name) OR the index is past the macIndexMaxOctet (255) ceiling — the SAME ceiling
// netConfigForIndex fail-closes on for the /31 third octet. For a NON-EMPTY tap name
// this ok=false makes the routed-tap render REFUSE the domain-define (fail-closed)
// rather than emit a deterministic MAC out of the /31's range (which would also alias
// another session's derivation) or un-gate the named tap to SLIRP; an EMPTY tap name
// is the one case that legitimately falls back to SLIRP (the 'no binding yet' path).
// An over-ceiling index cannot reach here via the sanctioned path:
// Allocate() derives the guest IP through the same netConfigForIndex and fails
// closed BEFORE a Binding with such a tap name exists. Recovering the
// index from the tap name keeps the render a PURE function of its existing args (no
// new index parameter threaded through the whole boot path).
func macForTapName(tapName string) (string, bool) {
	idxStr := strings.TrimPrefix(tapName, tapNamePrefix)
	if idxStr == "" || idxStr == tapName {
		return "", false
	}
	idx, err := strconv.ParseUint(idxStr, 10, 64)
	if err != nil {
		return "", false
	}
	if idx > macIndexMaxOctet {
		return "", false
	}
	return macForIndex(idx), true
}

// domainDefineArgs is the PURE arg-construction for the `virsh create` invocation
// — split out from the exec for the gated unit test. The transient-domain XML is
// passed by file path (written to a temp file at exec time), so this returns the
// virsh subcommand shape; the XML body is asserted separately via domainDefineXML.
func domainDefineArgs(cfg LiveConfig, xmlPath string) (name string, args []string) {
	return cfg.VirshBin, []string{"create", xmlPath}
}

// domainLookupArgs is the PURE arg-construction for the idempotent
// already-running probe (`virsh domuuid <name>`).
func domainLookupArgs(cfg LiveConfig, sessionUUID string) (name string, args []string) {
	return cfg.VirshBin, []string{"domuuid", domainName(sessionUUID)}
}

func (b *liveBooter) Boot(ctx context.Context, sessionUUID, overlayPath, entrypointConfigRef, tapName string, vsockCID uint32) (string, error) {
	if sessionUUID == "" {
		return "", fmt.Errorf("boot: empty session uuid")
	}
	if overlayPath == "" {
		return "", fmt.Errorf("boot session %s: empty overlay path (step 7 ≺ step 8)", sessionUUID)
	}

	// Idempotent short-circuit: if the domain is already defined+running for this
	// session, return its uuid rather than re-defining (a retry must converge).
	lookupName, lookupArgs := domainLookupArgs(b.cfg, sessionUUID)
	if out, err := b.run.run(ctx, lookupName, lookupArgs...); err == nil {
		if uuid := strings.TrimSpace(out); uuid != "" {
			return uuid, nil
		}
	}

	// ── step-8 config-drive ATTACH (D38; before define) ──────────────────────
	// The structured config.pb config-drive was already built+delivered upstream by
	// the create-path EntrypointProducer (create.go Produce, BEFORE this Boot) — the
	// single owner that holds the recorded Binding + host facts. The booter does NOT
	// rebuild it from the raw opaque ref (that wrote the un-decodable role-overlay
	// fragment over the good config.pb, the live-found gap-1 regression). It only
	// ATTACHES the producer's drive as the 2nd <disk>, found at the deterministic
	// per-session path configDrivePathFor(OverlayDir,uuid) the producer's deliverer
	// wrote (both sides share the one configdrive.go path function + the same
	// LiveConfig.OverlayDir). When there is no ref, or the drive is absent (no
	// producer wired), the boot proceeds single-disk — byte-identical to the historical
	// no-config path. The attach precedes virsh define so the domain XML can reference
	// the carrier the producer already materialized.
	configDrivePath := ""
	if entrypointConfigRef != "" {
		candidate := configDrivePathFor(b.cfg.OverlayDir, sessionUUID)
		if fi, statErr := os.Stat(candidate); statErr == nil && !fi.IsDir() {
			configDrivePath = candidate
		}
	}

	// ── per-session WORKSPACE disk clone (01KYRGC5NC; before render) ─────────
	// When a golden workspace image is configured, clone it to the deterministic
	// per-session path and attach the CLONE — the golden is only ever a copy
	// source. This is the structural fix for the two-sessions-one-ext4 corruption:
	// after it, NO code path exists that puts one filesystem image into two
	// domains' XML, so the refusal the task asks for ("a create that would share a
	// live disk read-write is refused") holds by construction rather than by a
	// registry check. An EXISTING clone is reused, not re-cloned: a step-8 retry
	// and a recovery re-boot must converge on the session's own edits, and
	// clobbering them with a fresh golden copy would silently destroy the one
	// artifact the session exists to produce. FAIL-CLOSED on a clone/stat fault:
	// a session configured to have a workspace must not boot into an empty /work
	// and burn a turn discovering it (work.mount is fail-open for the NO-workspace
	// boot; a configured-but-broken workspace is a different, loud case).
	renderCfg := b.cfg
	if b.cfg.WorkspaceDisk != "" {
		wsPath := workspacePathFor(b.cfg.OverlayDir, sessionUUID)
		if _, statErr := os.Stat(wsPath); statErr == nil {
			// already cloned for this session: reuse (edits live here)
		} else if os.IsNotExist(statErr) {
			cloneName, cloneArgs := workspaceCloneArgs(b.cfg.WorkspaceDisk, wsPath)
			if _, err := b.run.run(ctx, cloneName, cloneArgs...); err != nil {
				return "", fmt.Errorf("boot session %s: clone workspace disk %s -> %s: %w", sessionUUID, b.cfg.WorkspaceDisk, wsPath, err)
			}
		} else {
			return "", fmt.Errorf("boot session %s: stat workspace disk %s: %w", sessionUUID, wsPath, statErr)
		}
		renderCfg.WorkspaceDisk = wsPath
	}

	// Render + materialize the transient-domain XML (with the config-drive 2nd disk
	// when one was built), then define+boot it. The CONTROL-channel CID is PINNED from
	// the per-session vsockCID the create path threads from the recorded Binding
	// (binding.go / alloc.go = HostSessionIndex + reservedVsockCIDs): non-zero renders
	// `<cid auto='no' address='<vsockCID>'/>` so the host agent dials a host-predictable
	// guestCID:port. When vsockCID is 0 (the not-yet-derived / offline sentinel) it
	// falls back to `<cid auto='yes'/>`, keeping the render byte-identical to the
	// historical no-CID form.
	//
	// The egress NIC renders from (b.cfg.RoutedTap, tapName): gate-ON with a non-empty
	// per-session tapName (Binding.TapName = `dstap-<idx>`) attaches the routed tap
	// (`<interface type='ethernet'><target dev='<tapName>'/>`); gate-OFF (the default)
	// renders the historical usermode SLIRP NIC byte-identically. The tap carries no
	// egress until U3/U4 land, so gated-off this is inert.
	xml, err := domainDefineXMLWithConfigDrive(renderCfg, sessionUUID, overlayPath, entrypointConfigRef, configDrivePath, tapName, vsockCID)
	if err != nil {
		return "", fmt.Errorf("boot session %s: render domain xml: %w", sessionUUID, err)
	}
	xmlFile, err := os.CreateTemp("", "ds-domain-"+sessionUUID+"-*.xml")
	if err != nil {
		return "", fmt.Errorf("boot session %s: stage domain xml: %w", sessionUUID, err)
	}
	xmlPath := xmlFile.Name()
	defer os.Remove(xmlPath)
	if _, err := xmlFile.WriteString(xml); err != nil {
		xmlFile.Close()
		return "", fmt.Errorf("boot session %s: write domain xml: %w", sessionUUID, err)
	}
	if err := xmlFile.Close(); err != nil {
		return "", fmt.Errorf("boot session %s: close domain xml: %w", sessionUUID, err)
	}

	defineName, defineArgs := domainDefineArgs(b.cfg, xmlPath)
	if _, err := b.run.run(ctx, defineName, defineArgs...); err != nil {
		return "", fmt.Errorf("boot session %s: virsh create: %w", sessionUUID, err)
	}

	// Read back the domain uuid (the handle the heartbeat's observed-state reports).
	out, err := b.run.run(ctx, lookupName, lookupArgs...)
	if err != nil {
		return "", fmt.Errorf("boot session %s: read domain uuid after create: %w", sessionUUID, err)
	}
	uuid := strings.TrimSpace(out)
	if uuid == "" {
		return "", fmt.Errorf("boot session %s: domain created but no uuid returned", sessionUUID)
	}
	return uuid, nil
}
