// SPDX-License-Identifier: Apache-2.0

// capturedref_live_test.go — the DS_HOSTAGENT_LIVE gated rehearsal for the
// captured-ref DURABILITY LOOP through the REAL daemon composition
// (buildDriverServiceWithBridge), the last untested link in the D29/D30 producer arc.
//
// The wave-1 capturedref-host-wire unit proved the store+decorator arc in the
// libvirt package against a FAKED inner recoverer (capturedrefstore_host_test.go).
// What that offline unit could NOT reach is the daemon's ACTUAL composition root:
// buildDriverServiceWithBridge builds the durable CapturedRefStore + the
// captured-ref-aware SessionRecoverer (NewSessionRecoverer → the live recoverer
// DECORATED with NewSessionRecovererWithCapturedRefs) over a real on-disk
// <OverlayDir>/.ds-sessions area, and that end-to-end wiring — Snapshot's durable
// write on one incarnation, a driver restart, then RecoverSessions reading the ref
// back into RecoveredSession.SnapshotRefs on the next — only comes alive under
// DS_HOSTAGENT_LIVE. This rehearsal closes that link.
//
// SYNTHETIC-FILESYSTEM, NO LIBVIRT (D50): it needs NO libvirt domain, NO VM, NO
// network, NO qemu. The OverlayDir is a t.TempDir; the "resident domain" the
// recoverer joins comes from a SYNTHETIC virsh stand-in (a tiny shell script that
// prints one `ds-<session>` line for `virsh list --name`) pointed at via -virsh-bin,
// so the real liveSessionRecoverer runs its real code path without any hypervisor.
// The Snapshot durable write is stood in by writing the captured ref straight to the
// SAME durable CapturedRefStore the composition wires (both resolve
// <OverlayDir>/.ds-sessions), which is byte-for-byte what DriverService.Snapshot
// records on disk — so the read-back exercises the production recoverer over exactly
// the bytes production would have written.
//
// LIVE-GATING DISCIPLINE (additive, default-path-unchanged): the whole test SKIPS
// cleanly when DS_HOSTAGENT_LIVE is unset (the sandbox / CI / every `go test ./...`),
// so an ordinary offline run never constructs the live composition. It is documented
// as a DEFERRED MANUAL / CI step: set DS_HOSTAGENT_LIVE=1 to run it (no other operator
// fact is required — the synthetic virsh + temp OverlayDir supply everything, and
// DS_HOSTAGENT_SKIP_CA_INJECT keeps the CA-inject seam off libguestfs). See
// cmd/host-agent/LIVE-SMOKE.md for the operator live legs.

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// capturedRefRehearsalSession is a fixed v4-shaped session uuid for the rehearsal;
// it names the synthetic resident domain (ds-<uuid>) and keys the durable record +
// captured-ref set the composition reads back.
const capturedRefRehearsalSession = "00000000-0000-4000-8000-00000000cafe"

// capturedRefRehearsalRef is the synthetic captured snapshot_ref written on the
// "first incarnation" (the Snapshot durable write) that the reconstructed
// composition's recoverer must read back into RecoveredSession.SnapshotRefs.
const capturedRefRehearsalRef = "snap-cafe-1"

// writeSyntheticVirsh writes a tiny executable stand-in for virsh that prints a
// single `ds-<session>` line for `virsh list --name` (the resident-domain probe the
// liveSessionRecoverer runs) and nothing for any other invocation. It is the D50
// synthetic fixture that lets the REAL recoverer run its real code path with NO
// libvirt/KVM/qemu — the recoverer only shells out to `virsh list --name`, so this
// one line is all it observes. Returns the absolute path to hand to -virsh-bin.
func writeSyntheticVirsh(t *testing.T, session string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "virsh-stub.sh")
	// `list --name` -> one resident ds-domain; anything else -> empty (the recoverer
	// only ever calls `list --name`, but stay quiet on other args for robustness).
	script := "#!/bin/sh\nif [ \"$1\" = \"list\" ]; then\n  echo \"ds-" + session + "\"\nfi\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write synthetic virsh stub: %v", err)
	}
	return path
}

// TestCapturedRefDurabilityThroughLiveComposition is the gated end-to-end rehearsal
// of the captured-ref durability loop through buildDriverServiceWithBridge's real
// store+recoverer arc. Offline (the default) it SKIPS before constructing anything;
// under DS_HOSTAGENT_LIVE it writes a captured ref on a first incarnation, RECONSTRUCTS
// the composition (a driver restart), and asserts the recoverer reads the ref back into
// RecoveredSession.SnapshotRefs — all over a temp-dir OverlayDir with a synthetic virsh,
// touching no libvirt/network.
func TestCapturedRefDurabilityThroughLiveComposition(t *testing.T) {
	if !libvirt.LiveEnabled() {
		t.Skipf("offline default: %s unset — skipping the captured-ref live durability rehearsal (a DEFERRED MANUAL/CI step; set %s=1 to run the synthetic-filesystem store+recoverer arc, no libvirt/VM/network needed)", libvirt.EnvHostAgentLive, libvirt.EnvHostAgentLive)
	}

	// Keep the live composition OFF the real libguestfs CA-inject path: the synthetic
	// CA stand-in (the SAME parseable placeholder used off the gate) needs no host
	// trust tooling, so construction succeeds on a box without libguestfs. This is the
	// maintainer-approved single-box MVP posture (seams.go newGatedCAInjector); it does not
	// touch the captured-ref arc under test.
	t.Setenv("DS_HOSTAGENT_SKIP_CA_INJECT", "1")

	overlayDir := t.TempDir()
	virsh := writeSyntheticVirsh(t, capturedRefRehearsalSession)

	// The live-facts config: a temp OverlayDir plus SYNTHETIC (non-empty) overlay-create
	// script + base-image paths. LiveConfig.validate requires those two non-empty under
	// the gate, but NOTHING execs them here — the rehearsal never CloneFromImage/boots, so
	// the fake paths are never resolved. -virsh-bin points the recoverer's resident-domain
	// probe at the synthetic virsh. parseConfig supplies every other default (session-mode
	// "structured", guest subnet, offsets) so the config matches a real daemon bring-up.
	cfg, err := parseConfig([]string{
		"-overlay-dir", overlayDir,
		"-overlay-create-script", filepath.Join(overlayDir, "overlay-create.sh"),
		"-base-image", filepath.Join(overlayDir, "base.raw"),
		"-virsh-bin", virsh,
		"-host-id", "host-capturedref-rehearsal",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}

	// The LiveConfig the durable stores are built from MIRRORS the one
	// buildDriverServiceWithBridge assembles (same OverlayDir → same
	// <OverlayDir>/.ds-sessions area), so the record + captured-ref set written here land
	// in exactly the files the reconstructed composition's recoverer reads.
	liveCfg := libvirt.LiveConfig{
		OverlayCreateScript: cfg.overlayCreateScript,
		OverlayDir:          cfg.overlayDir,
		BaseImage:           cfg.baseImage,
		VirshBin:            cfg.virshBin,
	}

	ctx := context.Background()

	// ── FIRST INCARNATION: persist the session's binding record + Snapshot's durable
	// captured ref ─────────────────────────────────────────────────────────────────
	// The create path Puts a SessionRecord at boot (the binding the domain XML does not
	// carry); DriverService.Snapshot records each captured ref via the CapturedRefStore.
	// We stand both in by writing to the SAME durable stores the composition wires — the
	// on-disk bytes are byte-identical to what a real boot + Snapshot would leave — so the
	// read-back below exercises the production recoverer over production-shaped state.
	records, err := libvirt.NewSessionRecordStore(liveCfg)
	if err != nil {
		t.Fatalf("NewSessionRecordStore (live): %v", err)
	}
	const recoveredIndex = 5
	rec := libvirt.SessionRecord{
		SessionUUID: capturedRefRehearsalSession,
		DomainUUID:  "domain-" + capturedRefRehearsalSession,
		Binding: libvirt.Binding{
			HostSessionIndex: recoveredIndex,
			TapName:          tapNameFor(recoveredIndex),
			GuestIP:          libvirt.GuestAddress{Family: libvirt.AddressFamilyIPv4, Address: []byte{10, 42, 0, 5}},
			OverlayPath:      filepath.Join(overlayDir, capturedRefRehearsalSession+".qcow2"),
		},
	}
	if err := records.Put(ctx, rec); err != nil {
		t.Fatalf("persist session record (first incarnation boot): %v", err)
	}

	refs, err := libvirt.NewCapturedRefStore(liveCfg)
	if err != nil {
		t.Fatalf("NewCapturedRefStore (live): %v", err)
	}
	if err := refs.RecordCapturedRef(ctx, capturedRefRehearsalSession, capturedRefRehearsalRef); err != nil {
		t.Fatalf("record captured ref (first incarnation Snapshot durable write): %v", err)
	}

	// ── RESTART: reconstruct the daemon composition ──────────────────────────────────
	// A fresh buildDriverServiceWithBridge over the SAME cfg is exactly what a host-agent
	// restart yields — the in-memory snapshotRefs registry + clone cache are gone, and the
	// durable CapturedRefStore + captured-ref-aware SessionRecoverer are rebuilt from disk.
	_, _, bridge, recoverer, admissionSeg, err := buildDriverServiceWithBridge(cfg, newSessionCIDRegistry())
	if err != nil {
		t.Fatalf("reconstruct composition (buildDriverServiceWithBridge under %s): %v", libvirt.EnvHostAgentLive, err)
	}
	// The bridge launched nothing (no create ran), so Shutdown is a clean no-op; call it
	// to mirror run()'s drain and keep the rehearsal self-contained.
	defer bridge.Shutdown()
	if recoverer == nil {
		t.Fatalf("composition returned a nil SessionRecoverer under %s — the crash-matrix re-adoption leg (and its captured-ref decorator) must be wired on the live path", libvirt.EnvHostAgentLive)
	}
	if admissionSeg == nil {
		t.Fatalf("composition returned a nil AdmissionSegment — it must always be returned so run() can Create/Unlink it")
	}

	// ── READ-BACK: RecoverSessions layers the durable captured ref onto SnapshotRefs ──
	recovered, err := recoverer.RecoverSessions(ctx, cfg.hostID)
	if err != nil {
		t.Fatalf("RecoverSessions (read-back through the reconstructed composition): %v", err)
	}
	if len(recovered) != 1 {
		t.Fatalf("RecoverSessions returned %d sessions, want exactly 1 (the synthetic resident ds-domain joined to its durable record); got %+v", len(recovered), recovered)
	}
	got := recovered[0]
	if got.SessionUUID != capturedRefRehearsalSession {
		t.Errorf("recovered session uuid = %q, want %q", got.SessionUUID, capturedRefRehearsalSession)
	}
	// The load-bearing assertion: the captured ref written on the first incarnation
	// survived the restart and was read back into SnapshotRefs by the composition's
	// captured-ref-aware recoverer — the exact durability the D29/D30 producer arc closes
	// (a bare live recoverer would leave SnapshotRefs empty and a post-restart
	// ExportDiskDelta rooted at the still-live point-in-time would falsely fail NotFound).
	if len(got.SnapshotRefs) != 1 || got.SnapshotRefs[0] != capturedRefRehearsalRef {
		t.Errorf("recovered SnapshotRefs = %v, want [%s] read back through the real composition (the durable captured ref must survive the reconstruct)", got.SnapshotRefs, capturedRefRehearsalRef)
	}
}

// tapNameFor renders the `dstap-<idx>` tap name the recorded binding must carry (the
// frozen naming the libvirt package's unexported tapName also produces). Kept local
// to the rehearsal so the package-main test needs no unexported libvirt helper; the
// recoverer returns the recorded binding verbatim, so this only has to match the
// `dstap-<idx>` convention a real boot would have persisted.
func tapNameFor(index uint64) string {
	return "dstap-" + strconv.FormatUint(index, 10)
}
