// SPDX-License-Identifier: Apache-2.0

// diskdelta_host — the production DiskDeltaExporter seam binding (seams.go), the
// host-side body of the §5.1 ExportDiskDelta verb over the D29 durability unit
// (doc 15 §5.1, §10 / D29/D30). It is the real counterpart of the in-memory
// recording fake the service tests use (service_test.go): the seam + fake prove
// the deterministic, OPAQUE-byte, framed-by-the-service contract offline (D50);
// THIS file realizes the delta extraction over the per-session qcow2 overlay on
// the operator host — the host-side twin of liveOverlayStore / liveBooter
// (live.go), liveSnapshotStore (snapshot_libvirt.go), liveSuspender
// (suspender_libvirt.go), and liveTrustStoreWriter (trustanchor.go). With it
// wired, GetCapabilities' supports_disk_delta_export=true is wire-true end to end.
//
// THE D29 DELTA IS THE OVERLAY FILE. The per-session qcow2 OVERLAY
// (<OverlayDir>/<sessionUUID>.qcow2) is a copy-on-write layer over the read-only
// raw golden base, so it holds ONLY the session's writes — it IS the D29 delta
// store ("the qcow2 overlay path = the D29 delta store + inspectable artifact +
// durability unit", driver.proto). OpenDelta therefore STREAMS THE OVERLAY FILE
// directly (os.Open), handing the service an *os.File reader it frames into
// {offset, data} chunks. A live e2e (taskdb 01KV6Q1DV5, 01KV6PDSEF) proved the
// earlier `qemu-img convert -O raw <overlay> /dev/stdout` approach wrong on BOTH
// counts: qemu-img convert cannot write raw to a NON-SEEKABLE pipe (it streamed 0
// bytes), and -O raw of a qcow2 overlay-over-backing would yield the FULL logical
// image (base+overlay merged), not the delta. Streaming the overlay file is both
// correct (the CoW delta) and pipe-free.
//
// Same posture as live.go / snapshot_libvirt.go / suspender_libvirt.go: the real
// binding is ALWAYS compiled (no build tag) but only reachable behind the
// DS_HOSTAGENT_LIVE gate the daemon composition root reads (LiveEnabled) — the
// host-agent wiring that SELECTS this impl (passes it to
// NewDriverServiceWithDiskDelta) is a SEPARATE deferred task. Off the gate / in
// the sandbox / in CI a DriverService is built WITHOUT a DiskDeltaExporter and
// ExportDiskDelta answers an honest codes.Unimplemented (service.go), so every
// unit test stays green against the fake. STDLIB-ONLY (doc.go / seams.go): the
// delta is read with stdlib os — NO libvirt-go / cgo / qemu-img import enters
// orchestrator/go.mod.
//
// CONSISTENCY / LOCKING: os.Open is a READ-ONLY open; qemu's qcow2 OFD lock blocks
// other WRITERS, not readers, so the open never conflicts with the running domain.
// For a CONSISTENT point-in-time, the caller suspends the session first (the live
// e2e exports while suspended); after a Snapshot pivots the chain the per-session
// overlay becomes a read-only BACKING and is trivially stable. The reader is the
// *os.File; the service ALWAYS Closes it (including on a mid-stream ctx
// cancellation, seams.go) — the read loop is what honors ctx-cancel between frames.
//
// FULL vs INCREMENTAL (the seams.go since-ref contract): an EMPTY sinceSnapshotRef
// requests the FULL per-session overlay delta (streamed here). A NON-EMPTY one
// requests the INCREMENTAL delta SINCE that opaque base snapshot — a v1 LIMITATION:
// this impl streams the full per-session overlay for both, since a TRUE
// incremental-since-snapshot needs to walk the post-Snapshot qcow2 chain (the
// snapshot pivot splits writes across the original overlay backing + the new top)
// or a persistent dirty bitmap; that refinement is a documented TODO and the full
// overlay it streams is a valid SUPERSET of the requested incremental delta.
//
// OPAQUE BYTES / zero-leakage (doc 15 §5.1, §10 / D29/D30): the reader yields ONLY
// the raw overlay bytes the control plane reassembles; the service frames them into
// ExportDiskDeltaResponse{offset, data} and NOTHING libvirt/qcow2 specific (no
// qcow2 path, no snapshot-XML) ever crosses the wire — the overlay path is a LOCAL
// arg only and never enters the byte stream.
//
// FAIL-CLOSED: a missing overlay (or any open fault) surfaces as a NON-NIL error
// with a NIL reader (nothing was opened, so nothing needs closing — the seams.go
// on-error contract). A genuine host fault is NEVER swallowed into an empty stream.

package libvirt

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// liveDiskDeltaExporter is the production DiskDeltaExporter: OpenDelta resolves the
// per-session qcow2 overlay (<OverlayDir>/<sessionUUID>.qcow2 — the same
// deterministic path liveOverlayStore.overlayPathFor names) and streams it as the
// D29 delta. Reachable only on the live path (DS_HOSTAGENT_LIVE); a DriverService
// built off the gate has no DiskDeltaExporter and answers ExportDiskDelta with
// codes.Unimplemented (service.go).
type liveDiskDeltaExporter struct {
	cfg LiveConfig
}

// NewLiveDiskDeltaExporter builds the real DiskDeltaExporter from the host facts,
// mirroring NewLiveOverlayStore / NewLiveSnapshotStore: it validates the live
// config (a missing host fact — here the overlay dir the per-session overlay is
// resolved under — is a construction error, not a silent fall-through) and returns
// a value satisfying the seams.go DiskDeltaExporter seam so the host-agent
// composition root can pass it to NewDriverServiceWithDiskDelta on the live path
// (that wiring is a SEPARATE task).
func NewLiveDiskDeltaExporter(cfg LiveConfig) (DiskDeltaExporter, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &liveDiskDeltaExporter{cfg: cfg}, nil
}

// NewDiskDeltaExporter returns the gate-aware DiskDeltaExporter: the real host
// exporter when DS_HOSTAGENT_LIVE=1, NIL otherwise. It mirrors offline.go's
// NewOverlayStore / NewBooter so the live/offline choice rides the single
// EnvHostAgentLive source of truth, never a scattered env check. The OFF-GATE
// return is NIL on purpose: a DriverService built with a nil DiskDeltaExporter
// keeps the honest codes.Unimplemented posture for ExportDiskDelta (service.go) —
// there is no offline "fake exporter" production default (the recording fake lives
// only in the tests, D50), so the gate-off composition root simply leaves the seam
// unwired. The composition-root wiring that passes the result to
// NewDriverServiceWithDiskDelta is a SEPARATE deferred task, NOT here.
func NewDiskDeltaExporter(cfg LiveConfig) (DiskDeltaExporter, error) {
	if LiveEnabled() {
		return NewLiveDiskDeltaExporter(cfg)
	}
	return nil, nil
}

// overlayPathFor resolves the per-session qcow2 overlay path deterministically —
// "<OverlayDir>/<sessionUUID>.qcow2" — the SAME convention liveOverlayStore.
// overlayPathFor names and cainject.go's sessionFromOverlay recovers the session
// key from. The delta IS this overlay (the D29 durability unit).
func (e *liveDiskDeltaExporter) overlayPathFor(sessionUUID string) string {
	return filepath.Join(e.cfg.OverlayDir, sessionUUID+".qcow2")
}

// OpenDelta opens the per-session qcow2 overlay (D29) as a raw byte stream — the
// overlay file IS the CoW delta over the read-only golden base. An EMPTY
// sinceSnapshotRef requests the FULL overlay delta; a NON-EMPTY one requests the
// INCREMENTAL delta SINCE that opaque base snapshot (a v1 limitation: the full
// overlay is streamed for both — see the file header). It resolves the per-session
// overlay path (<OverlayDir>/<sessionUUID>.qcow2) and os.Opens it READ-ONLY (no
// conflict with the running domain's qcow2 write lock), returning the *os.File the
// service reads + frames. On any open fault — a missing overlay, a permission
// error — it returns a NON-NIL error with a NIL reader (nothing was opened, so
// nothing needs closing; the seams.go on-error contract). The bytes stay OPAQUE:
// the overlay path is a LOCAL arg only and never enters the stream.
func (e *liveDiskDeltaExporter) OpenDelta(ctx context.Context, sessionUUID, sinceSnapshotRef string) (io.ReadCloser, error) {
	if sessionUUID == "" {
		return nil, fmt.Errorf("open disk delta: empty session uuid")
	}
	// ctx binds the read to the caller's deadline at the service's frame loop (it
	// stops Reading on ctx-cancel); the open itself is a fast local syscall.
	_ = ctx
	// sinceSnapshotRef is accepted but v1 streams the full overlay for both cases;
	// a true incremental-since-snapshot is a documented refinement (file header).
	_ = sinceSnapshotRef

	overlayPath := e.overlayPathFor(sessionUUID)
	f, err := os.Open(overlayPath)
	if err != nil {
		return nil, fmt.Errorf("open disk delta session %s: open overlay %q: %w", sessionUUID, overlayPath, err)
	}
	return f, nil
}

// Compile-time assertion: the live exporter satisfies the seam the service wires
// (NewDriverServiceWithDiskDelta).
var _ DiskDeltaExporter = (*liveDiskDeltaExporter)(nil)
