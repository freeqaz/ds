// SPDX-License-Identifier: Apache-2.0

//go:build linux

package libvirt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// newProbeForTest builds a liveReadiness with INJECTED nftRunner + dialer so the probe
// logic is exercised WITHOUT ever execing real `nft` or dialing a real socket (D50
// no-sudo/no-VM). It uses the three single-sourced required tables.
func newProbeForTest(nftRunner func(ctx context.Context, table string) error, dialer func(ctx context.Context, addr string) error) *liveReadiness {
	return &liveReadiness{
		tables:       RequiredBoundaryTables(),
		dnsGateAddr:  "127.0.0.1:53",
		tlsProxyAddr: "127.0.0.1:18443",
		timeout:      DefaultProbeTimeout,
		nftRunner:    nftRunner,
		dialer:       dialer,
	}
}

func TestLiveReadinessAllPresentReady(t *testing.T) {
	probe := newProbeForTest(
		func(_ context.Context, _ string) error { return nil },
		func(_ context.Context, _ string) error { return nil },
	)
	ready, detail, err := probe.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe err: %v", err)
	}
	if !ready {
		t.Errorf("all tables present + both dials succeed should be ready, got detail=%q", detail)
	}
	if detail != "" {
		t.Errorf("ready probe should have empty detail, got %q", detail)
	}
}

func TestLiveReadinessMissingTableNotReady(t *testing.T) {
	// The SECOND required table (ds_resolver_closure) is absent.
	probe := newProbeForTest(
		func(_ context.Context, table string) error {
			if table == tableDsResolverClosure {
				return errors.New("No such file or directory")
			}
			return nil
		},
		func(_ context.Context, _ string) error { return nil },
	)
	ready, detail, err := probe.Probe(context.Background())
	if err != nil {
		t.Fatalf("an absent table is an HONEST not-ready (err must be nil), got %v", err)
	}
	if ready {
		t.Error("a missing table must be not-ready")
	}
	if !strings.Contains(detail, tableDsResolverClosure) {
		t.Errorf("detail should name the missing table %q, got %q", tableDsResolverClosure, detail)
	}
}

func TestLiveReadinessNftFaultNotReady(t *testing.T) {
	// A mechanism fault (nft missing / timeout) is also fail-closed not-ready (no VM).
	probe := newProbeForTest(
		func(_ context.Context, _ string) error { return context.DeadlineExceeded },
		func(_ context.Context, _ string) error { return nil },
	)
	ready, detail, err := probe.Probe(context.Background())
	if err != nil {
		t.Fatalf("a mechanism fault is reported as not-ready (err nil), got %v", err)
	}
	if ready {
		t.Error("an nft mechanism fault must be not-ready (uncertain ⇒ no VM)")
	}
	if detail == "" {
		t.Error("a not-ready verdict should carry a detail")
	}
}

func TestLiveReadinessDnsGateDownNotReady(t *testing.T) {
	probe := newProbeForTest(
		func(_ context.Context, _ string) error { return nil },
		func(_ context.Context, addr string) error {
			if addr == "127.0.0.1:53" {
				return errors.New("connection refused")
			}
			return nil
		},
	)
	ready, detail, err := probe.Probe(context.Background())
	if err != nil {
		t.Fatalf("a non-answering service is an honest not-ready, got %v", err)
	}
	if ready {
		t.Error("ds-dnsgate down must be not-ready")
	}
	if !strings.Contains(detail, "ds-dnsgate") {
		t.Errorf("detail should name ds-dnsgate, got %q", detail)
	}
}

func TestLiveReadinessTlsProxyDownNotReady(t *testing.T) {
	probe := newProbeForTest(
		func(_ context.Context, _ string) error { return nil },
		func(_ context.Context, addr string) error {
			if addr == "127.0.0.1:18443" {
				return errors.New("connection refused")
			}
			return nil
		},
	)
	ready, detail, err := probe.Probe(context.Background())
	if err != nil {
		t.Fatalf("a non-answering service is an honest not-ready, got %v", err)
	}
	if ready {
		t.Error("ds-tlsproxy down must be not-ready")
	}
	if !strings.Contains(detail, "ds-tlsproxy") {
		t.Errorf("detail should name ds-tlsproxy, got %q", detail)
	}
}

// TestLiveReadinessMissingTableShortCircuitsBeforeDial proves a missing FIRST table
// short-circuits before ANY dial is attempted (the dialer call count is 0).
func TestLiveReadinessMissingTableShortCircuitsBeforeDial(t *testing.T) {
	dialCalls := 0
	probe := newProbeForTest(
		func(_ context.Context, table string) error {
			if table == tableDsBoundary { // the FIRST required table
				return errors.New("absent")
			}
			return nil
		},
		func(_ context.Context, _ string) error {
			dialCalls++
			return nil
		},
	)
	ready, _, err := probe.Probe(context.Background())
	if err != nil || ready {
		t.Fatalf("a missing first table must be not-ready, ready=%v err=%v", ready, err)
	}
	if dialCalls != 0 {
		t.Errorf("a missing first table must short-circuit before any dial, dialCalls=%d", dialCalls)
	}
}

// TestNewLiveReadinessFailsClosed proves construction rejects an empty dnsgate addr, an
// empty tlsproxy addr, or an empty required-table set — never a vacuously-passing live gate.
func TestNewLiveReadinessFailsClosed(t *testing.T) {
	base := LiveReadinessConfig{
		TablesRequired: RequiredBoundaryTables(),
		DNSGateAddr:    "127.0.0.1:53",
		TLSProxyAddr:   "127.0.0.1:18443",
	}

	noDNS := base
	noDNS.DNSGateAddr = ""
	if _, err := newLiveReadiness(noDNS); err == nil {
		t.Error("empty DNSGateAddr must fail construction closed")
	}

	noTLS := base
	noTLS.TLSProxyAddr = ""
	if _, err := newLiveReadiness(noTLS); err == nil {
		t.Error("empty TLSProxyAddr must fail construction closed")
	}

	noTables := base
	noTables.TablesRequired = nil
	if _, err := newLiveReadiness(noTables); err == nil {
		t.Error("empty TablesRequired must fail construction closed")
	}
}

// TestNewLiveReadinessDefaultsTimeout proves a <=0 ProbeTimeout takes DefaultProbeTimeout
// (the live gate is never unbounded).
func TestNewLiveReadinessDefaultsTimeout(t *testing.T) {
	r, err := newLiveReadiness(LiveReadinessConfig{
		TablesRequired: RequiredBoundaryTables(),
		DNSGateAddr:    "127.0.0.1:53",
		TLSProxyAddr:   "127.0.0.1:18443",
		ProbeTimeout:   0,
	})
	if err != nil {
		t.Fatalf("newLiveReadiness: %v", err)
	}
	lr, ok := r.(*liveReadiness)
	if !ok {
		t.Fatalf("expected *liveReadiness, got %T", r)
	}
	if lr.timeout != DefaultProbeTimeout {
		t.Errorf("zero ProbeTimeout should default to %v, got %v", DefaultProbeTimeout, lr.timeout)
	}
}

// TestNewBoundaryReadinessOfflineIsDeferred proves that off DS_HOSTAGENT_LIVE,
// NewBoundaryReadiness returns the always-ready deferred no-op (no construction validation,
// no kernel/socket touch) even with an EMPTY config — the offline create path is unchanged.
func TestNewBoundaryReadinessOfflineIsDeferred(t *testing.T) {
	if LiveEnabled() {
		t.Skip("DS_HOSTAGENT_LIVE is set; this asserts the offline default")
	}
	r, err := NewBoundaryReadiness(LiveReadinessConfig{})
	if err != nil {
		t.Fatalf("offline NewBoundaryReadiness should never error, got %v", err)
	}
	ready, _, err := r.Probe(context.Background())
	if err != nil || !ready {
		t.Errorf("offline boundary-readiness should be always-ready, got ready=%v err=%v", ready, err)
	}
}

// TestLiveReadinessRespectsContextDeadline is a light guard that the per-op timeout wiring
// composes with the caller context (a probe under an already-cancelled context still
// resolves to not-ready, never hangs).
func TestLiveReadinessRespectsContextDeadline(t *testing.T) {
	probe := newProbeForTest(
		func(ctx context.Context, _ string) error { return ctx.Err() },
		func(_ context.Context, _ string) error { return nil },
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	ready, _, err := probe.Probe(ctx)
	if err != nil || ready {
		t.Fatalf("a deadline-exceeded probe must be not-ready, ready=%v err=%v", ready, err)
	}
}

// TestLiveReadinessUsesInjectedTableRunner pins the D148 seam: when
// LiveReadinessConfig.TableRunner is set, the probe must use it INSTEAD of the
// in-process `nft list` exec, and must fall back to the exec when it is nil.
//
// Why this matters: under the ROOT-HELPER model the agent runs unprivileged, and
// `nft list` needs CAP_NET_ADMIN merely to initialise its netlink cache
// ("Operation not permitted (you must be root)"). If a future edit drops the
// injection, the probe silently reports EVERY floor table absent and refuses
// every CreateSession for a floor that is actually installed — while the helper's
// own probe passes, which makes it very hard to diagnose from the symptom.
func TestLiveReadinessUsesInjectedTableRunner(t *testing.T) {
	var seen []string
	cfg := LiveReadinessConfig{
		TablesRequired: RequiredBoundaryTables(),
		DNSGateAddr:    "127.0.0.1:53",
		TLSProxyAddr:   "127.0.0.1:18443",
		TableRunner: func(_ context.Context, table string) error {
			seen = append(seen, table)
			return nil
		},
	}
	r, err := newLiveReadiness(cfg)
	if err != nil {
		t.Fatalf("newLiveReadiness: %v", err)
	}
	lr, ok := r.(*liveReadiness)
	if !ok {
		t.Fatalf("expected *liveReadiness, got %T", r)
	}
	// Drive the runner directly: it must be the injected one, not execNftListTable.
	for _, tbl := range RequiredBoundaryTables() {
		if err := lr.nftRunner(context.Background(), tbl); err != nil {
			t.Fatalf("injected runner returned %v for %s", err, tbl)
		}
	}
	if len(seen) != len(RequiredBoundaryTables()) {
		t.Errorf("injected TableRunner was not used for every table: saw %v, want %v",
			seen, RequiredBoundaryTables())
	}

	// Nil TableRunner must keep the historical in-process exec default, so the
	// root/dev path is unchanged.
	cfg.TableRunner = nil
	r2, err := newLiveReadiness(cfg)
	if err != nil {
		t.Fatalf("newLiveReadiness (nil runner): %v", err)
	}
	lr2, ok := r2.(*liveReadiness)
	if !ok {
		t.Fatalf("expected *liveReadiness, got %T", r2)
	}
	if lr2.nftRunner == nil {
		t.Error("nil TableRunner must fall back to the default exec runner, got nil")
	}
}
