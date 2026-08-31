// SPDX-License-Identifier: Apache-2.0

// offline — the default (env-unset) OverlayStore + Booter bindings, and the
// gate-aware constructors the daemon composition root (cmd/host-agent) calls to
// pick live vs offline behind DS_HOSTAGENT_LIVE.
//
// These offline bindings are the PRODUCTION default path: with DS_HOSTAGENT_LIVE
// unset (the sandbox / CI / every unit test), the create choreography runs over
// these no-touch stand-ins instead of the real overlay-create.sh clone + virsh
// boot. They never touch the substrate — no qemu-img, no virsh, no KVM — so the
// conformance suite and unit tests stay green offline (D50), exactly mirroring
// the in-package fakes the tests already exercise. The live bindings (live.go)
// take over only when the operator sets the gate on the host.

package libvirt

import (
	"context"
	"path/filepath"
)

// offlineOverlayStore is the default no-touch OverlayStore: it derives the same
// deterministic per-session overlay path the live store would (so the rest of the
// choreography — CA injection's sessionFromOverlay, the recorded binding's
// OverlayPath — sees a consistent value) but creates nothing on disk. Idempotent
// on session_uuid by construction (the path is a pure function of the inputs).
type offlineOverlayStore struct {
	overlayDir string
}

// CreateOverlay returns the deterministic per-session overlay path without
// touching disk. When no overlay dir is configured it falls back to a stable
// in-package convention so a bare offline default still yields a usable path.
func (s offlineOverlayStore) CreateOverlay(_ context.Context, sessionUUID, _ string) (string, error) {
	dir := s.overlayDir
	if dir == "" {
		dir = "/var/lib/ds/overlays"
	}
	return filepath.Join(dir, sessionUUID+".qcow2"), nil
}

// DisposeOverlay is a no-op offline: nothing was created on disk to dispose.
func (s offlineOverlayStore) DisposeOverlay(_ context.Context, _ string) error {
	return nil
}

// offlineBooter is the default no-touch Booter: it returns a deterministic
// pseudo-domain handle keyed on the session without defining a libvirt domain.
// Idempotent on session_uuid (the handle is a pure function of the input).
type offlineBooter struct{}

// Boot returns a deterministic offline domain handle without touching libvirt.
// vsockCID is accepted for seam parity (the live render pins it) but ignored
// offline: no domain is defined, so there is no CID to assign. tapName is likewise
// accepted for seam parity (the live render wires it as the routed-tap NIC under
// the DS_ROUTED_TAP gate) but ignored offline: the offline booter defines no
// domain, so there is no NIC to attach a tap to.
func (offlineBooter) Boot(_ context.Context, sessionUUID, _, _, _ string, _ uint32) (string, error) {
	return "offline-domain-" + sessionUUID, nil
}

// offlineDomainDestroyer is the default no-touch DomainDestroyer (destroy.go §4.2
// step 1): it destroys nothing, which is ALSO the correct idempotent behavior for
// an absent/already-gone domain (the seam's documented contract) — offline no
// domain was ever defined, so the session is already-destroyed, the §4.2
// unconditional flush still runs (D68) and the teardown converges. Idempotent on
// session_uuid by construction.
type offlineDomainDestroyer struct{}

// DestroyDomain is a no-op success offline: no libvirt domain was ever defined, so
// there is nothing to destroy.
func (offlineDomainDestroyer) DestroyDomain(_ context.Context, _, _ string) error {
	return nil
}

// NewOverlayStore returns the gate-aware OverlayStore: the real overlay-create.sh
// clone when DS_HOSTAGENT_LIVE=1, the no-touch offline default otherwise. The
// daemon composition root calls this so the live/offline choice rides the single
// EnvHostAgentLive source of truth, never a scattered env check. On the live path
// the LiveConfig is validated (a missing host fact is a construction error, not a
// silent fall-through to offline); off the gate the config's OverlayDir still
// seeds the deterministic offline path so both paths name overlays alike.
func NewOverlayStore(cfg LiveConfig) (OverlayStore, error) {
	if LiveEnabled() {
		return NewLiveOverlayStore(cfg)
	}
	return offlineOverlayStore{overlayDir: cfg.OverlayDir}, nil
}

// NewBooter returns the gate-aware Booter: the real virsh define+boot when
// DS_HOSTAGENT_LIVE=1, the no-touch offline default otherwise.
func NewBooter(cfg LiveConfig) (Booter, error) {
	if LiveEnabled() {
		return NewLiveBooter(cfg)
	}
	return offlineBooter{}, nil
}

// NewDomainDestroyer returns the gate-aware DomainDestroyer (doc 15 §4.2 step 1):
// the real virsh destroy of the session's transient domain
// (destroyer_libvirt.go) when DS_HOSTAGENT_LIVE=1, the no-touch offline stand-in
// otherwise. Like OverlayStore/Booter — and UNLIKE the OPTIONAL lifecycle seams
// (Suspender/SnapshotStore, which are nil off the gate) — the destroyer is
// REQUIRED: NewDestroyer rejects a nil domain destroyer (destroy.go), so both
// paths return a non-nil value and the §4.2 ordering always has a step 1 to drive.
// Off the gate that step is the idempotent no-op success an already-destroyed
// session warrants, keeping the offline/CI teardown byte-identical.
func NewDomainDestroyer(cfg LiveConfig) (DomainDestroyer, error) {
	if LiveEnabled() {
		return NewLiveDomainDestroyer(cfg)
	}
	return offlineDomainDestroyer{}, nil
}

// NewSuspender returns the gate-aware Suspender: the real virsh managedsave/start
// pause+restore (suspender_libvirt.go) when DS_HOSTAGENT_LIVE=1, nil otherwise.
// Unlike OverlayStore/Booter (required by the create path, so they fall back to a
// no-touch offline stand-in), the Suspender is OPTIONAL: off the gate the
// composition root passes nil and the DriverService answers Suspend/Resume with
// honest codes.Unimplemented — an offline host has no real domain to pause. The
// live/offline choice rides the single EnvHostAgentLive source of truth.
func NewSuspender(cfg LiveConfig) (Suspender, error) {
	if LiveEnabled() {
		return NewLiveSuspender(cfg)
	}
	return nil, nil
}

// NewSnapshotStore returns the gate-aware SnapshotStore: the real virsh
// external-snapshot capture of the per-session overlay (snapshot_libvirt.go) when
// DS_HOSTAGENT_LIVE=1, nil otherwise. Optional like the Suspender: off the gate
// the composition root passes nil and the DriverService answers Snapshot with
// honest codes.Unimplemented (no real overlay to capture).
func NewSnapshotStore(cfg LiveConfig) (SnapshotStore, error) {
	if LiveEnabled() {
		return NewLiveSnapshotStore(cfg)
	}
	return nil, nil
}

// indexCounterFile is the per-host durable index store filename (under OverlayDir,
// the host's per-session state area). D66 never-recycle requires the index survive
// a host-agent restart; this file is where the live durableCounter persists it.
const indexCounterFile = "ds-host-index.counter"

// NewIndexCounter returns the gate-aware never-recycled index counter (D66): the
// crash-safe file-backed durableCounter (durablecounter.go) when DS_HOSTAGENT_LIVE=1
// — so a restart resumes past every index already handed and never collides with a
// resident session — or the process-local in-memory memCounter otherwise (the
// sandbox/CI default, where there is no real host to survive a restart of). Unlike
// the OPTIONAL lifecycle seams, the counter is REQUIRED (the Allocator draws every
// index from it), so both paths return a non-nil IndexCounter. The live durable
// counter is the SAME instance a future NewDriverServiceWithRecovery wires as the
// ReseedableCounter (it implements both), so the create-path draw and the
// crash-matrix re-seed share one monotonic source. The persisted index lives at
// <OverlayDir>/ds-host-index.counter; a missing OverlayDir on the live path is a
// construction error (LiveConfig.validate, mirroring the other live bindings).
func NewIndexCounter(cfg LiveConfig) (IndexCounter, error) {
	if LiveEnabled() {
		if err := cfg.validate(); err != nil {
			return nil, err
		}
		return NewDurableCounter(filepath.Join(cfg.OverlayDir, indexCounterFile))
	}
	return newMemCounter(0), nil
}

// NewSessionRecordStore returns the gate-aware durable session-record store
// (sessionrecord.go): the file store under <OverlayDir>/.ds-sessions when
// DS_HOSTAGENT_LIVE=1 (so a booted session's binding survives a restart for the
// SessionRecoverer to re-adopt), or nil otherwise. nil off the gate is intentional:
// the create path's record write is nil-guarded (NewHostAgentWithRecords with a nil
// store skips it), and the sandbox/CI path has no real host to recover. A missing
// OverlayDir on the live path is a construction error (LiveConfig.validate).
func NewSessionRecordStore(cfg LiveConfig) (SessionRecordStore, error) {
	if LiveEnabled() {
		if err := cfg.validate(); err != nil {
			return nil, err
		}
		return NewFileSessionRecordStore(cfg.OverlayDir)
	}
	return nil, nil
}

// NewCapturedRefStore returns the gate-aware durable captured-ref store
// (capturedrefstore_host.go): the file store under <OverlayDir>/.ds-sessions (beside
// the SessionRecord it annotates) when DS_HOSTAGENT_LIVE=1 — so a session's captured
// snapshot_refs survive a driver restart for the SessionRecoverer to read back into
// RecoveredSession.SnapshotRefs — or nil otherwise. nil off the gate is intentional
// and byte-identical to today: the DriverService's durable-write is nil-guarded
// (service.go: a nil CapturedRefStore skips the record and keeps the in-memory-only
// posture), and the sandbox/CI path has no real host to recover. A missing OverlayDir
// on the live path is a construction error (LiveConfig.validate).
func NewCapturedRefStore(cfg LiveConfig) (CapturedRefStore, error) {
	if LiveEnabled() {
		if err := cfg.validate(); err != nil {
			return nil, err
		}
		return NewFileCapturedRefStore(cfg.OverlayDir)
	}
	return nil, nil
}

// NewSessionRecoverer returns the gate-aware SessionRecoverer (recoverer.go): the
// real virsh-list + record-store recoverer, DECORATED with the durable captured-ref
// read-back, when DS_HOSTAGENT_LIVE=1, or nil otherwise (the DriverService answers
// RecoverSessions with codes.Unimplemented off the gate). records is the SAME store
// the create path writes (so the recoverer reads back exactly what was booted); on
// the live path it must be non-nil. The captured-ref decorator
// (NewSessionRecovererWithCapturedRefs) layers each session's durable captured-ref
// set onto RecoveredSession.SnapshotRefs — the read side of the producer arc the
// DriverService's write side (NewCapturedRefStore, wired at the composition root)
// completes — so a captured ref survives re-adoption and still roots an incremental
// ExportDiskDelta. Off the gate this is nil, byte-identical to today.
func NewSessionRecoverer(cfg LiveConfig, records SessionRecordStore) (SessionRecoverer, error) {
	if !LiveEnabled() {
		return nil, nil
	}
	inner, err := NewLiveSessionRecoverer(cfg, records)
	if err != nil {
		return nil, err
	}
	refs, err := NewCapturedRefStore(cfg)
	if err != nil {
		return nil, err
	}
	return NewSessionRecovererWithCapturedRefs(inner, refs)
}

// NewAttachHandleMinter returns the gate-aware AttachHandleMinter: the real M0 minter
// (the guest-IP DIRECT endpoint + a host-readable per-session auth token,
// attachminter.go) when DS_HOSTAGENT_LIVE=1, nil otherwise. Optional like the
// Suspender/SnapshotStore: off the gate the composition root passes nil and the
// DriverService answers IssueAttachHandle with honest codes.Unimplemented — an
// offline host has no real guest binding to point a DIRECT endpoint at, and no
// per-session token store on disk. The live/offline choice rides the single
// EnvHostAgentLive source of truth.
func NewAttachHandleMinter(cfg LiveConfig) (AttachHandleMinter, error) {
	if LiveEnabled() {
		return NewLiveAttachHandleMinter(cfg)
	}
	return nil, nil
}
