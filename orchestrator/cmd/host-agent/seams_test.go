// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// TestNewBoundaryReadinessOfflineIsDeferred asserts the composition-root selector returns
// the always-ready deferred no-op off DS_HOSTAGENT_LIVE: with the gate unset, an EMPTY
// LiveReadinessConfig (no dnsgate/tlsproxy addr) must NOT error and Probe must yield
// (true, _, nil) — so an offline daemon's create path is byte-identical to today (no
// host-boundary precondition, no kernel/socket touch). The FAIL-CLOSED default-preservation
// at the seam-selection layer, mirroring TestNewAdmissionSegmentSelectorGateOffNoTouch.
func TestNewBoundaryReadinessOfflineIsDeferred(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate OFF

	readiness, err := newBoundaryReadiness(libvirt.LiveReadinessConfig{}, nil)
	if err != nil {
		t.Fatalf("offline newBoundaryReadiness should never error (deferred no-op), got %v", err)
	}
	ready, _, err := readiness.Probe(context.Background())
	if err != nil {
		t.Fatalf("offline boundary-readiness Probe should never error, got %v", err)
	}
	if !ready {
		t.Error("offline boundary-readiness must be always-ready (the no-touch no-op); an offline create path must be byte-identical to today")
	}
}

// TestNewBoundaryReadinessOfflineIgnoresMissingAddrs is the explicit fail-OPEN-OFFLINE twin:
// even with NO ds-dnsgate/ds-tlsproxy addresses and NO required tables, the gate-off path
// never validates them (it returns the deferred no-op), so an operator who has not armed the
// live gate is never blocked by the construction fail-closed that ONLY applies on the live
// privileged path (newBoundaryReadiness selects libvirt.NewBoundaryReadiness only under
// LiveEnabled && a constructed ds-nethelper client — the D148 re-key off the
// permanently-false nftbridge.Built const the untagged agent now carries).
func TestNewBoundaryReadinessOfflineIgnoresMissingAddrs(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate OFF

	readiness, err := newBoundaryReadiness(libvirt.LiveReadinessConfig{
		// Deliberately empty: no DNSGateAddr, no TLSProxyAddr, no TablesRequired.
	}, nil)
	if err != nil {
		t.Fatalf("gate-off must not validate addrs/tables (deferred no-op), got %v", err)
	}
	ready, _, err := readiness.Probe(context.Background())
	if err != nil || !ready {
		t.Errorf("gate-off probe should be always-ready, got ready=%v err=%v", ready, err)
	}
}
