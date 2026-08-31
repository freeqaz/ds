// SPDX-License-Identifier: Apache-2.0

// snapshot_libvirt — the production SnapshotStore seam binding (seams.go), the
// host-side body of the §5.1 Snapshot verb over the D29 durability unit (doc 15
// §5.1, §10 / D29/D30). It is the real counterpart of the in-memory fake the
// service tests use (service_test.go): the seam + fake prove the deterministic,
// idempotent, OPAQUE-ref contract offline (D50); THIS file realizes the libvirt
// external-snapshot capture of the per-session qcow2 overlay on the operator
// host — the host-side twin of liveOverlayStore / liveBooter (live.go),
// liveSuspender (suspender_libvirt.go), and liveTrustStoreWriter
// (trustanchor.go).
//
// Same posture as live.go / suspender_libvirt.go: the real binding is ALWAYS
// compiled (no build tag) but only reachable behind the DS_HOSTAGENT_LIVE gate
// the daemon composition root reads (LiveEnabled) — the host-agent wiring that
// SELECTS this impl (passes it to NewDriverServiceWithSnapshot) is a SEPARATE
// task. Off the gate / in the sandbox / in CI a DriverService is built WITHOUT a
// SnapshotStore and Snapshot answers an honest codes.Unimplemented (service.go),
// so every unit test stays green against the fake. STDLIB-ONLY (doc.go /
// seams.go): it shells out to virsh through the package's os/exec `runner` seam
// (live.go) — NO libvirt-go / cgo enters orchestrator/go.mod.
//
// THE EXTERNAL DISK SNAPSHOT (D29): CreateSnapshot drives virsh
// snapshot-create-as --disk-only --atomic --no-metadata on the named session
// domain — an EXTERNAL disk snapshot that pivots the live disk onto a fresh
// qcow2 delta and freezes the prior state as the durable point-in-time (the D29
// per-session overlay IS the durability unit; this is its named capture). It is
// disk-only (no RAM image — the snapshot is a disk delta, not a save-state),
// atomic (the pivot is all-or-nothing), and no-metadata (libvirt keeps no
// snapshot bookkeeping — we name the capture ourselves deterministically, so the
// control plane owns the lifecycle through the OPAQUE ref, not libvirt's
// metadata store). The capability GetCapabilities advertises
// (supports_disk_delta_export=true) is exactly this substrate, surfaced as a
// named snapshot the later ExportDiskDelta.since_snapshot_ref names back.
//
// DETERMINISTIC + IDEMPOTENT on (sessionUUID, label) (the seams.go contract,
// doc 15 §5.1): the snapshot name is derived purely from (sessionUUID, label),
// so a retry re-derives the SAME name. We query existence FIRST (virsh
// snapshot-list --name): an ALREADY-PRESENT snapshot returns the SAME opaque ref
// with NO second snapshot-create-as (a retried Snapshot after a control-plane
// blip re-names the same point-in-time, it does not fork a duplicate durable
// snapshot); an ABSENT one is captured. A DIFFERENT label derives a DISTINCT
// name → a DISTINCT point-in-time → a DISTINCT opaque ref; an EMPTY label is the
// unlabeled-capture case (still deterministic on the session).
//
// OPAQUE REF / zero-leakage (doc 15 §5.1, §10 / D29/D30): the returned reference
// is "ds-snap://<sessionUUID>/<label>" — an overlay/delta handle the control
// plane carries and later names back, NEVER a libvirt snapshot-XML, a qcow2
// path, or any QEMU monitor type. The libvirt/qcow2 external-snapshot mechanics
// stay BEHIND this seam, so SnapshotResponse.snapshot_ref leaks zero driver
// internals — the same invariant cloneResponse enforces for the binding.
//
// FAIL-CLOSED: a missing domain, a snapshot-list failure that is NOT a clean
// "absent", or a snapshot-create-as write failure surfaces as a non-nil error
// the caller re-drives (the service maps it to codes.Internal — service.go); a
// session with no recorded binding is already NotFound-gated UPSTREAM in
// service.go (we do not duplicate that here). A genuine host fault is NEVER
// swallowed.

package libvirt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// snapshotRefScheme is the OPAQUE-ref scheme the SnapshotStore returns. It names
// a session+label point-in-time the control plane carries and later names back
// (ExportDiskDelta.since_snapshot_ref) WITHOUT exposing any libvirt/qcow2
// internal — the D29/D30 zero-leakage invariant.
const snapshotRefScheme = "ds-snap://"

// liveSnapshotStore is the production SnapshotStore: CreateSnapshot drives virsh
// snapshot-create-as --disk-only --atomic --no-metadata of the named session
// domain (the D29 external disk snapshot of the per-session qcow2 overlay), with
// an EXPLICIT external snapshot file path so the deterministic idempotent
// no-op-on-repeat contract is checked by FILE existence (os.Stat), NOT virsh
// snapshot-list. A live e2e (01KV6PDSEF) proved snapshot-list cannot back the
// idempotency check here: the liveBooter boots a TRANSIENT domain (virsh create,
// D29) which cannot persist snapshot metadata, so the capture MUST use
// --no-metadata and --no-metadata snapshots never appear in snapshot-list — the
// list probe always reported "absent" and a retry re-ran snapshot-create-as,
// which then failed because the external snapshot FILE already existed. Probing
// the deterministic snapshot file directly fixes the idempotency. Reachable only
// on the live path (DS_HOSTAGENT_LIVE); a DriverService built off the gate has no
// SnapshotStore and answers Snapshot with codes.Unimplemented (service.go).
type liveSnapshotStore struct {
	// virshBin is the virsh binary the live store drives (default "virsh" via
	// PATH; reuses LiveConfig.VirshBin, the same field liveBooter / liveSuspender
	// drive).
	virshBin string
	// overlayDir is where per-session overlays (and their external snapshot files)
	// live (LiveConfig.OverlayDir, the same dir liveOverlayStore writes); the
	// deterministic snapshot file path is derived under it so the idempotency
	// probe and the explicit --diskspec file= agree.
	overlayDir string
	// run is the single os/exec edge (live.go runner seam); the production value
	// is execRunner{} and the offline tests install a recordingRunner so the
	// command line + branch behavior is asserted WITHOUT launching virsh.
	run runner
}

// NewLiveSnapshotStore builds the real SnapshotStore over virsh on PATH,
// mirroring NewLiveBooter / NewLiveSuspender: it resolves the virsh binary
// (default "virsh" when empty) and installs the production execRunner. The
// returned value satisfies the seams.go SnapshotStore seam, so the host-agent
// composition root can pass it to NewDriverServiceWithSnapshot on the live path
// (the same place it constructs NewLiveBooter / NewLiveSuspender) — that wiring
// is a SEPARATE task.
func NewLiveSnapshotStore(cfg LiveConfig) (SnapshotStore, error) {
	virsh := cfg.VirshBin
	if virsh == "" {
		virsh = "virsh"
	}
	return &liveSnapshotStore{
		virshBin:   virsh,
		overlayDir: cfg.OverlayDir,
		run:        execRunner{},
	}, nil
}

// sanitizeSnapshotLabel reduces a label to a safe libvirt snapshot-name
// component ([A-Za-z0-9._-]) so it can never inject a virsh flag or collide on
// the name separator. An empty label is the unlabeled-capture case and maps to a
// stable sentinel so the unlabeled capture is itself deterministic on the
// session (the seams.go empty-label contract). The same sanitize convention
// trustanchor.go's sanitizeAnchorComponent uses for the session id.
func sanitizeSnapshotLabel(label string) string {
	var b strings.Builder
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		// The unlabeled-capture case: a stable sentinel keeps the empty-label
		// snapshot deterministic on the session (a retry re-derives the same name).
		return "unlabeled"
	}
	return b.String()
}

// snapshotName derives the DETERMINISTIC libvirt snapshot name from
// (sessionUUID, label): "ds-snap-<sessionUUID>-<sanitized label>". A retry with
// the same (session, label) re-derives the SAME name (so snapshot-list finds the
// prior capture and we no-op); a different label derives a DISTINCT name (a
// distinct point-in-time). Keyed under the session so one session's labels never
// collide with another's.
func snapshotName(sessionUUID, label string) string {
	return "ds-snap-" + sessionUUID + "-" + sanitizeSnapshotLabel(label)
}

// snapshotRefFor renders the OPAQUE overlay/delta reference for (sessionUUID,
// label) — "ds-snap://<sessionUUID>/<label>". It is derived purely from the
// inputs (so a retry returns the SAME ref) and carries NO libvirt snapshot-XML /
// qcow2 path / QEMU internal (D29/D30 zero-leakage). The control plane carries
// it and later names it back (ExportDiskDelta.since_snapshot_ref); it is never a
// driver internal. The label rides RAW (not the sanitized form) so the ref round
// -trips the caller's exact label — the sanitized form is only the libvirt name.
func snapshotRefFor(sessionUUID, label string) string {
	return snapshotRefScheme + sessionUUID + "/" + label
}

// snapshotFilePath is the deterministic external-snapshot file the capture writes
// and the idempotency probe stats: <overlayDir>/<sessionUUID>.<snapName>, the stem
// of the per-session overlay (<overlayDir>/<sessionUUID>.qcow2) joined with the
// snapshot name. A repeat (session,label) re-derives the SAME path, so an os.Stat
// of it is the deterministic idempotency check (snapshot-list cannot be — the
// transient domain's --no-metadata snapshots never appear there; taskdb 01KV6PDSEF).
func snapshotFilePath(overlayDir, sessionUUID, snapName string) string {
	return filepath.Join(overlayDir, sessionUUID+"."+snapName)
}

// snapshotCreateArgs is the PURE arg-construction for the durable capture: virsh
// snapshot-create-as <domain> --name <snapname> --disk-only --atomic
// --no-metadata --diskspec vda,snapshot=external,file=<snapFile> — an EXTERNAL
// disk snapshot of the per-session qcow2 overlay (the D29 durability unit).
// --disk-only captures the disk delta with no RAM image; --atomic makes the pivot
// all-or-nothing; --no-metadata keeps libvirt out of snapshot-lifecycle
// bookkeeping (required for a TRANSIENT domain, which cannot persist that
// metadata). The EXPLICIT --diskspec file= pins the snapshot file to the
// deterministic snapshotFilePath the idempotency probe stats. Split out from the
// exec for the offline test.
func snapshotCreateArgs(virshBin, sessionUUID, snapName, snapFile string) (name string, args []string) {
	return virshBin, []string{
		"snapshot-create-as", domainName(sessionUUID),
		"--name", snapName,
		"--disk-only",
		"--atomic",
		"--no-metadata",
		"--diskspec", "vda,snapshot=external,file=" + snapFile,
	}
}

// CreateSnapshot captures a durable point-in-time of sessionUUID's per-session
// qcow2 overlay (D29) under the optional label, returning an OPAQUE overlay/delta
// reference. It is DETERMINISTIC and IDEMPOTENT on (sessionUUID, label): the
// snapshot name is derived purely from (session, label), so it queries existence
// FIRST (virsh snapshot-list --name) and branches — an ALREADY-PRESENT snapshot
// returns the SAME opaque ref with NO snapshot-create-as call (a retried Snapshot
// re-names the same point-in-time, never a second durable snapshot); an ABSENT
// one is captured with virsh snapshot-create-as --disk-only --atomic
// --no-metadata (the D29 external disk snapshot of the overlay). A DIFFERENT label
// derives a DISTINCT name → a DISTINCT point-in-time → a DISTINCT ref; an EMPTY
// label is the unlabeled-capture case (still deterministic on the session). The
// returned ref is OPAQUE (ds-snap://<session>/<label>) — never a libvirt/qcow2
// internal (D29/D30 zero-leakage). A missing domain / snapshot-list failure /
// snapshot-create-as write failure surfaces as a non-nil error the caller
// re-drives (the service maps to codes.Internal); a session with no recorded
// binding is already NotFound-gated upstream in service.go (not duplicated here).
func (s *liveSnapshotStore) CreateSnapshot(ctx context.Context, sessionUUID, label string) (string, error) {
	if sessionUUID == "" {
		return "", fmt.Errorf("create snapshot: empty session uuid")
	}

	snapName := snapshotName(sessionUUID, label)
	ref := snapshotRefFor(sessionUUID, label)
	snapFile := snapshotFilePath(s.overlayDir, sessionUUID, snapName)

	// Probe existence FIRST and branch (the seams.go deterministic-idempotent
	// contract): if THIS (session,label) snapshot file already exists, return the
	// SAME opaque ref WITHOUT recreating — a retry must converge, never fork a
	// second durable snapshot (and never re-run snapshot-create-as, which errors
	// when the external snapshot file already exists). The check is on the
	// deterministic snapshot FILE rather than virsh snapshot-list, which cannot see
	// the --no-metadata snapshots a transient domain requires (taskdb 01KV6PDSEF).
	// A stat error that is NOT a clean "not exist" is a genuine host fault.
	if _, err := os.Stat(snapFile); err == nil {
		return ref, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("create snapshot session %s: probe snapshot file %q: %w", sessionUUID, snapFile, err)
	}

	// Absent: capture the durable external disk snapshot of the per-session
	// overlay (the D29 durability unit) to the explicit snapshot file. A write
	// failure is a genuine host fault surfaced non-nil so the caller re-drives —
	// NEVER swallowed.
	createName, createArgs := snapshotCreateArgs(s.virshBin, sessionUUID, snapName, snapFile)
	if _, err := s.run.run(ctx, createName, createArgs...); err != nil {
		return "", fmt.Errorf("create snapshot session %s: virsh snapshot-create-as: %w", sessionUUID, err)
	}
	return ref, nil
}

// Compile-time assertion: the live snapshot store satisfies the seam the service
// wires (NewDriverServiceWithSnapshot).
var _ SnapshotStore = (*liveSnapshotStore)(nil)
