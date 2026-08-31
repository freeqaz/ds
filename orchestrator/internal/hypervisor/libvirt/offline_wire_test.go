// SPDX-License-Identifier: Apache-2.0

// Gate-aware tests for the optional lifecycle-seam constructors NewSuspender /
// NewSnapshotStore (offline.go), mirroring TestNewDiskDeltaExporterGateOff/On.
// Off the gate (the default sandbox/CI/unit-test path) they return NIL so the
// composition root passes nil and the DriverService answers Suspend/Resume/
// Snapshot with honest codes.Unimplemented; on the gate they return the real
// virsh-backed live impl. NO virsh/KVM/sudo is touched (constructors only).

package libvirt

import (
	"context"
	"testing"
)

func wireTestConfig() LiveConfig {
	return LiveConfig{
		OverlayCreateScript: "/opt/ds/vm/cow/overlay-create.sh",
		OverlayDir:          "/var/lib/ds/overlays",
		BaseImage:           "/var/lib/libvirt/images/ds-build/m0-base.qcow2",
		VirshBin:            "virsh",
	}
}

// TestNewDomainDestroyerGateOff/On: unlike the OPTIONAL lifecycle seams, the
// DomainDestroyer is REQUIRED (NewDestroyer rejects a nil one), so BOTH paths
// return a non-nil value — the no-touch offline stand-in off the gate (whose no-op
// IS the correct idempotent behavior for an absent domain) and the real virsh
// destroyer on it.
func TestNewDomainDestroyerGateOffReturnsOfflineNoOp(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "")
	d, err := NewDomainDestroyer(wireTestConfig())
	if err != nil {
		t.Fatalf("NewDomainDestroyer (gate off): %v", err)
	}
	if d == nil {
		t.Fatal("gate off must still return a NON-nil DomainDestroyer (NewDestroyer rejects nil)")
	}
	if _, ok := d.(offlineDomainDestroyer); !ok {
		t.Fatalf("gate off returned %T, want offlineDomainDestroyer", d)
	}
	if err := d.DestroyDomain(context.Background(), "sess-1", "dom-1"); err != nil {
		t.Fatalf("offline DestroyDomain must be a no-op success, got %v", err)
	}
}

func TestNewDomainDestroyerGateOnReturnsLive(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1")
	d, err := NewDomainDestroyer(wireTestConfig())
	if err != nil {
		t.Fatalf("NewDomainDestroyer (gate on): %v", err)
	}
	if _, ok := d.(*liveDomainDestroyer); !ok {
		t.Fatalf("gate on returned %T, want *liveDomainDestroyer", d)
	}
}

func TestNewSuspenderGateOffReturnsNil(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "")
	s, err := NewSuspender(wireTestConfig())
	if err != nil {
		t.Fatalf("NewSuspender (gate off): %v", err)
	}
	if s != nil {
		t.Fatalf("gate off must return a nil Suspender, got %T", s)
	}
}

func TestNewSuspenderGateOnReturnsLive(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1")
	s, err := NewSuspender(wireTestConfig())
	if err != nil {
		t.Fatalf("NewSuspender (gate on): %v", err)
	}
	if s == nil {
		t.Fatal("gate on must return a non-nil live Suspender")
	}
	if _, ok := s.(*liveSuspender); !ok {
		t.Fatalf("gate on returned %T, want *liveSuspender", s)
	}
}

func TestNewSnapshotStoreGateOffReturnsNil(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "")
	s, err := NewSnapshotStore(wireTestConfig())
	if err != nil {
		t.Fatalf("NewSnapshotStore (gate off): %v", err)
	}
	if s != nil {
		t.Fatalf("gate off must return a nil SnapshotStore, got %T", s)
	}
}

func TestNewSnapshotStoreGateOnReturnsLive(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1")
	s, err := NewSnapshotStore(wireTestConfig())
	if err != nil {
		t.Fatalf("NewSnapshotStore (gate on): %v", err)
	}
	if s == nil {
		t.Fatal("gate on must return a non-nil live SnapshotStore")
	}
	if _, ok := s.(*liveSnapshotStore); !ok {
		t.Fatalf("gate on returned %T, want *liveSnapshotStore", s)
	}
}

// ── §4.2 teardown seams: the gate-aware stores the daemon root hands the service ──

// TestNewAttachTokenStoreGateOffIsNilNoDisposer asserts the OFF-by-default posture the
// composition root relies on for the §4.2 token purge: off DS_HOSTAGENT_LIVE the token
// store is nil, so the root's type assertion to AttachTokenDisposer yields NO disposer and
// the DriverService's purge is skipped — byte-identical to the historical destroy (no
// token was ever minted off the gate, so there is nothing to remove).
func TestNewAttachTokenStoreGateOffIsNilNoDisposer(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "")
	tokens, err := NewAttachTokenStore(wireTestConfig())
	if err != nil {
		t.Fatalf("NewAttachTokenStore (gate off): %v", err)
	}
	if tokens != nil {
		t.Fatalf("gate off returned %T, want nil (no token store offline)", tokens)
	}
	// The composition root's upgrade: a nil source asserts to NO disposer, which the
	// service treats as unwired.
	if _, ok := tokens.(AttachTokenDisposer); ok {
		t.Fatal("a nil token store must NOT assert to a disposer (the purge stays unwired offline)")
	}
}

// TestNewAttachTokenStoreGateOnIsDisposable asserts the live token store the root wires
// DOES satisfy the teardown role, so the §4.2 purge is actually reachable on a live host.
// This is the assertion that would break if the store's role set ever drifted — the token
// would then silently outlive every destroy again.
func TestNewAttachTokenStoreGateOnIsDisposable(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1")
	tokens, err := NewAttachTokenStore(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewAttachTokenStore (gate on): %v", err)
	}
	disposer, ok := tokens.(AttachTokenDisposer)
	if !ok {
		t.Fatalf("gate on returned %T, which does NOT dispose tokens at teardown", tokens)
	}
	// Idempotent on an absent token: a clean no-op, never an error.
	if err := disposer.RemoveToken(context.Background(), "sess-never-minted"); err != nil {
		t.Fatalf("RemoveToken(absent) = %v, want a clean no-op success", err)
	}
}

// TestNewSessionModeStoreGateOnRemovesMarkers asserts the live mode store the root hands
// the service satisfies the §4.2 marker purge (the gate-OFF nil case is pinned by
// TestNewSessionModeStore_OfflineNil in sessionmodestore_test.go).
func TestNewSessionModeStoreGateOnRemovesMarkers(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1")
	modes, err := NewSessionModeStore(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSessionModeStore (gate on): %v", err)
	}
	if modes == nil {
		t.Fatal("gate on must return a non-nil mode store")
	}
	ctx := context.Background()
	if err := modes.PutMode(ctx, "sess-1", SessionModeTerminal); err != nil {
		t.Fatalf("PutMode: %v", err)
	}
	if err := modes.RemoveMode(ctx, "sess-1"); err != nil {
		t.Fatalf("RemoveMode: %v", err)
	}
	if _, found, err := modes.ModeFor(ctx, "sess-1"); err != nil || found {
		t.Fatalf("ModeFor after the teardown purge = (found=%v, err=%v), want a clean miss", found, err)
	}
}
