// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests drive the REAL liveDiskDeltaExporter WITHOUT libvirt/qemu-img/KVM:
// OpenDelta os.Opens the per-session overlay FILE (the D29 CoW delta), so the tests
// stage a real overlay file in a t.TempDir() and assert the streamed bytes equal
// it. The real-overlay byte-equality against a booted session is the DEFERRED
// operator step on the DS_HOSTAGENT_LIVE box (diskdelta_host.go runbook note).

// diskDeltaTestConfig is a host-fact config pointing at placeholder paths — NO file
// is touched by the constructor/gate assertions. OpenDelta tests override OverlayDir
// to a t.TempDir() and stage the per-session overlay there.
func diskDeltaTestConfig() LiveConfig {
	return LiveConfig{
		OverlayCreateScript: "/opt/ds/vm/cow/overlay-create.sh",
		OverlayDir:          "/var/lib/ds/overlays",
		BaseImage:           "/var/lib/libvirt/images/ds-build/m0-base.qcow2",
		VirshBin:            "virsh",
	}
}

// newTestExporter builds a live exporter over a REAL temp overlay dir; returns the
// dir so a test can stage the per-session overlay file the delta is read from.
func newTestExporter(t *testing.T) (*liveDiskDeltaExporter, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := diskDeltaTestConfig()
	cfg.OverlayDir = dir
	return &liveDiskDeltaExporter{cfg: cfg}, dir
}

// TestOverlayPathForDeterministic: the per-session overlay resolves to
// <OverlayDir>/<sessionUUID>.qcow2 — the same deterministic convention
// liveOverlayStore names (so the delta is read from the recorded session's
// overlay). It is purely a function of the inputs (a retry re-derives it).
func TestOverlayPathForDeterministic(t *testing.T) {
	e := &liveDiskDeltaExporter{cfg: LiveConfig{OverlayDir: "/ov"}}
	if got := e.overlayPathFor("sess-7"); got != "/ov/sess-7.qcow2" {
		t.Fatalf("overlay path = %q, want /ov/sess-7.qcow2", got)
	}
	if a, b := e.overlayPathFor("sess-7"), e.overlayPathFor("sess-7"); a != b {
		t.Fatalf("overlay path not deterministic: %q vs %q", a, b)
	}
}

// ── Gate-aware constructor (offline.go NewOverlayStore mirror) ───────────────

// TestNewDiskDeltaExporterGateOffReturnsNil: the DEFAULT (gate unset) returns NIL —
// a DriverService built with a nil DiskDeltaExporter keeps the honest
// codes.Unimplemented posture for ExportDiskDelta (service.go).
func TestNewDiskDeltaExporterGateOffReturnsNil(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "")
	exp, err := NewDiskDeltaExporter(diskDeltaTestConfig())
	if err != nil {
		t.Fatalf("NewDiskDeltaExporter (gate off): %v", err)
	}
	if exp != nil {
		t.Fatalf("gate off must return a nil DiskDeltaExporter, got %T", exp)
	}
}

// TestNewDiskDeltaExporterGateOnReturnsLive: with DS_HOSTAGENT_LIVE=1 the
// constructor returns a NON-NIL live exporter, mirroring offline.go's NewOverlayStore
// live branch. The live config is validated, so a complete host-fact config
// constructs cleanly.
func TestNewDiskDeltaExporterGateOnReturnsLive(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1")
	exp, err := NewDiskDeltaExporter(diskDeltaTestConfig())
	if err != nil {
		t.Fatalf("NewDiskDeltaExporter (gate on): %v", err)
	}
	if exp == nil {
		t.Fatal("gate on must return a non-nil live DiskDeltaExporter")
	}
	if _, ok := exp.(*liveDiskDeltaExporter); !ok {
		t.Fatalf("gate on returned %T, want *liveDiskDeltaExporter", exp)
	}
}

// TestNewLiveDiskDeltaExporterValidatesConfig: a missing host fact (the overlay dir
// the per-session overlay is resolved under) is a CONSTRUCTION error, not a silent
// fall-through — mirroring NewLiveOverlayStore's validate.
func TestNewLiveDiskDeltaExporterValidatesConfig(t *testing.T) {
	if _, err := NewLiveDiskDeltaExporter(LiveConfig{OverlayCreateScript: "x", BaseImage: "y"}); err == nil {
		t.Fatal("expected NewLiveDiskDeltaExporter to reject a config missing the overlay dir")
	}
	exp, err := NewLiveDiskDeltaExporter(diskDeltaTestConfig())
	if err != nil {
		t.Fatalf("NewLiveDiskDeltaExporter (complete config): %v", err)
	}
	if exp == nil {
		t.Fatal("a complete live config must construct a non-nil exporter")
	}
}

// ── OpenDelta streams the per-session overlay FILE ───────────────────────────

// TestOpenDeltaStreamsOverlayFile: OpenDelta os.Opens the per-session overlay and
// streams its bytes byte-for-byte; the full (empty since) and incremental cases
// both stream the overlay (v1 — see the file header). Close releases the *os.File.
func TestOpenDeltaStreamsOverlayFile(t *testing.T) {
	e, dir := newTestExporter(t)
	payload := []byte("QCOW2-OVERLAY-DELTA-BYTES-0123456789\x00\x01\x02")
	if err := os.WriteFile(filepath.Join(dir, "sess-1.qcow2"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, since := range []string{"", "ds-snap://sess-1/v1"} {
		rc, err := e.OpenDelta(context.Background(), "sess-1", since)
		if err != nil {
			t.Fatalf("OpenDelta(since=%q): %v", since, err)
		}
		if rc == nil {
			t.Fatalf("OpenDelta(since=%q) returned a nil reader on success", since)
		}
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read delta stream (since=%q): %v", since, err)
		}
		if string(got) != string(payload) {
			t.Fatalf("delta bytes (since=%q) = %q, want %q", since, got, payload)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("Close (since=%q): %v", since, err)
		}
	}
}

// TestOpenDeltaOpaqueStream: the streamed bytes are the overlay content ONLY — the
// overlay PATH / dir never enter the stream (the D29/D30 zero-leakage invariant; the
// service frames only the opaque delta bytes).
func TestOpenDeltaOpaqueStream(t *testing.T) {
	e, dir := newTestExporter(t)
	payload := []byte("OPAQUE-DELTA-NO-PATH")
	if err := os.WriteFile(filepath.Join(dir, "sess-opaque.qcow2"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	rc, err := e.OpenDelta(context.Background(), "sess-opaque", "")
	if err != nil {
		t.Fatalf("OpenDelta: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(got), ".qcow2") || strings.Contains(string(got), e.cfg.OverlayDir) {
		t.Fatalf("delta stream leaked a driver-internal qcow2 path: %q", got)
	}
}

// TestOpenDeltaMissingOverlayNilReader: a missing overlay file surfaces as a NON-NIL
// error with a NIL reader — nothing was opened, so nothing needs closing (the
// seams.go on-error contract).
func TestOpenDeltaMissingOverlayNilReader(t *testing.T) {
	e, _ := newTestExporter(t) // the temp overlay dir is empty — no overlay staged
	rc, err := e.OpenDelta(context.Background(), "sess-missing", "")
	if err == nil {
		t.Fatal("expected an error for a missing overlay file")
	}
	if rc != nil {
		t.Fatalf("on error the reader must be nil (nothing to close), got %T", rc)
	}
}

// TestOpenDeltaRejectsEmptySession: a missing session uuid is an input fault — no
// file is opened (nil reader, non-nil error).
func TestOpenDeltaRejectsEmptySession(t *testing.T) {
	e, _ := newTestExporter(t)
	rc, err := e.OpenDelta(context.Background(), "", "")
	if err == nil {
		t.Fatal("expected OpenDelta to reject an empty session uuid")
	}
	if rc != nil {
		t.Fatalf("empty-session call must return a nil reader, got %T", rc)
	}
}
