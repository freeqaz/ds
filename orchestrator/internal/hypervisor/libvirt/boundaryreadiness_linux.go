// SPDX-License-Identifier: Apache-2.0

//go:build linux

// boundaryreadiness_linux.go is the LIVE (Linux-only) body of the host-WIDE
// BoundaryReadiness probe (the BoundaryReadiness seam, seams.go). It is compiled
// ONLY on Linux (the nft-list shell-out + the boundary-service dials are the
// operator-host posture); the non-Linux compile target takes
// boundaryreadiness_stub.go (the no-touch deferred stand-in) so a cross-platform
// build still compiles — mirroring admissionshm_{linux,other}.go.
//
// PRESENCE via read-only `nft list table inet <name>` (NOT a cgo read verb): the
// ds-nft cgo edge (internal/nftbridge) is WRITE-ONLY by charter (doc 14 §6), and
// adding a read export would widen the trusted ds-nft write contract + force
// ds_nft.h / writeedge_contract_test.go churn. The `nft list` shell-out is the SAME
// sanctioned `nft` mechanism the bootstrap unit uses (doc 09 §3), read-only, behind
// the Linux+live build path, with the offline path a no-op. A future kernel-native
// read could replace it BEHIND this seam without touching the CreateSession call site.
//
// STDLIB-ONLY (no cgo): the probe shells out via os/exec (the SAME deferred-binding
// posture live.go's overlay-create/virsh take — cgo is isolated in internal/nftbridge)
// and dials via net.DialTimeout. Both edges are INJECTABLE function fields so the
// mechanism is unit-testable in the D50 no-sudo/no-VM lane (never exec real nft /
// dial real sockets in tests).
//
// LIVENESS via a bounded TCP dial: a bare dial is a liveness FLOOR (the listener
// accepts), not a deep health check — a future health-RPC can replace it behind the
// same seam. The dial MUST target tcp (ds-dnsgate listens on udp/53 too, and a UDP
// "dial" never refuses, so it could not prove liveness); the addresses are
// config-supplied (no hardcoded wire port).

package libvirt

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"
)

// liveReadiness is the production BoundaryReadiness: it verifies the three required
// host-boundary nft tables are present (a read-only `nft list table inet <name>` per
// table, first-failure short-circuits) then dials the two boundary-service endpoints
// (ds-dnsgate, ds-tlsproxy). It is constructed ONLY on the live path
// (newLiveReadiness, behind DS_HOSTAGENT_LIVE) with the host-supplied
// LiveReadinessConfig. Mechanism edges are injectable so the unit test asserts the
// probe logic without ever running nft or opening a socket.
type liveReadiness struct {
	// tables is the required host-boundary nft table set (the unit-v3 install
	// set; RequiredBoundaryTables() by default). Validated non-empty at construction.
	tables []string
	// dnsGateAddr / tlsProxyAddr are the TCP endpoints the probe dials to prove
	// ds-dnsgate / ds-tlsproxy answer. Validated non-empty at construction.
	dnsGateAddr  string
	tlsProxyAddr string
	// timeout bounds each nftRunner shell-out and each dialer call.
	timeout time.Duration
	// nftRunner verifies a single `inet <table>` is present, returning nil when
	// present, a non-nil error when absent / on a mechanism fault. The default is
	// the os/exec `nft list table inet <table>` runner (a bounded-context exec);
	// the test injects a fake to assert the probe logic offline.
	nftRunner func(ctx context.Context, table string) error
	// dialer verifies a single TCP endpoint answers, returning nil when it
	// connected, a non-nil error otherwise. The default is net.DialTimeout "tcp";
	// the test injects a fake.
	dialer func(ctx context.Context, addr string) error
}

// newLiveReadiness builds the live BoundaryReadiness from the host facts. It FAILS
// CLOSED at construction if the table set is empty OR either service addr is empty
// (never a vacuously-passing live gate / never a silently always-ready service half).
// It touches no kernel object and no socket yet (Probe does that, per create). The
// table set is copied so a later mutation of the caller's slice cannot change what
// the probe requires.
func newLiveReadiness(cfg LiveReadinessConfig) (BoundaryReadiness, error) {
	if len(cfg.TablesRequired) == 0 {
		return nil, fmt.Errorf("boundary-readiness: requires a non-empty required-table set (fail-closed: never a vacuously-passing nft-table half, D63/D69)")
	}
	if cfg.DNSGateAddr == "" {
		return nil, fmt.Errorf("boundary-readiness: requires a ds-dnsgate probe address (fail-closed: never a vacuously-passing service half, D63)")
	}
	if cfg.TLSProxyAddr == "" {
		return nil, fmt.Errorf("boundary-readiness: requires a ds-tlsproxy probe address (fail-closed: never a vacuously-passing service half, D63)")
	}
	timeout := cfg.ProbeTimeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	tables := make([]string, len(cfg.TablesRequired))
	copy(tables, cfg.TablesRequired)
	// D148: prefer an injected runner (the ds-nethelper-backed one on the live
	// unprivileged path — see LiveReadinessConfig.TableRunner). Falls back to the
	// in-process exec, which only works when this process holds CAP_NET_ADMIN.
	runner := cfg.TableRunner
	if runner == nil {
		runner = execNftListTable
	}
	return &liveReadiness{
		tables:       tables,
		dnsGateAddr:  cfg.DNSGateAddr,
		tlsProxyAddr: cfg.TLSProxyAddr,
		timeout:      timeout,
		nftRunner:    runner,
		dialer:       dialTCP,
	}, nil
}

// execNftListTable is the production nftRunner: a read-only `nft list table inet
// <table>` under a bounded context. A non-zero exit (the table is absent) OR an exec
// fault (nft missing from PATH, a timeout) returns a non-nil error; the caller
// distinguishes "absent" (a not-ready verdict) from "mechanism fault" (an uncertain
// probe) by whether the table was the cause — see Probe. The output is discarded
// (presence is the exit code); nothing is mutated (read-only list).
func execNftListTable(ctx context.Context, table string) error {
	// `nft list table inet <table>` exits non-zero if the table does not exist.
	cmd := exec.CommandContext(ctx, "nft", "list", "table", "inet", table)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft list table inet %s: %w (output: %s)", table, err, string(out))
	}
	return nil
}

// dialTCP is the production dialer: a bounded TCP connect to addr. It targets tcp
// explicitly (a UDP "dial" never refuses, so it could not prove a service answers),
// and closes the connection immediately (liveness is the successful connect, not a
// held session). The context deadline is honored via net.Dialer.DialContext.
func dialTCP(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Probe runs the three nftRunner table-presence checks in order then dials the two
// boundary-service endpoints. First failure short-circuits. The not-ready vs
// uncertain split is the load-bearing fail-closed contract (BOTH are refused at the
// call site, but the operator-facing detail/err differ):
//   - a table that is ABSENT (its nftRunner returned an error) ⇒ (false, "nft table
//     inet <name> not present", nil) — an HONEST not-ready, naming the table;
//   - a service that did not ANSWER (its dialer returned an error) ⇒ (false,
//     "ds-dnsgate did not answer at <addr>" / "ds-tlsproxy did not answer at <addr>",
//     nil) — an honest not-ready, naming the service.
//
// Note: an nft-list / dial fault and a genuinely-absent table / down service are
// indistinguishable at this edge (both surface as a non-nil error from the injected
// mechanism), so Probe reports them all as an HONEST not-ready (false, detail, nil)
// — which is fail-closed (no VM) either way and gives the operator a specific reason.
// A nil error from a mechanism is the only "passed" signal. err!=nil from Probe is
// reserved for a config/usage fault the live gate should never reach (it is validated
// closed at construction), so in steady state Probe returns (true,"",nil) or a named
// (false, detail, nil); the err return keeps the seam contract uniform with a future
// mechanism that can distinguish uncertainty.
func (r *liveReadiness) Probe(ctx context.Context) (bool, string, error) {
	for _, table := range r.tables {
		tctx, cancel := context.WithTimeout(ctx, r.timeout)
		err := r.nftRunner(tctx, table)
		cancel()
		if err != nil {
			// Absent table OR an nft-exec fault: both are fail-closed not-ready,
			// naming the specific table so the operator (re)starts ds-nft-bootstrap.
			return false, fmt.Sprintf("nft table inet %s not present", table), nil
		}
	}
	if err := r.dialOne(ctx, r.dnsGateAddr); err != nil {
		return false, fmt.Sprintf("ds-dnsgate did not answer at %s", r.dnsGateAddr), nil
	}
	if err := r.dialOne(ctx, r.tlsProxyAddr); err != nil {
		return false, fmt.Sprintf("ds-tlsproxy did not answer at %s", r.tlsProxyAddr), nil
	}
	return true, "", nil
}

// dialOne runs a single service dial under the probe timeout.
func (r *liveReadiness) dialOne(ctx context.Context, addr string) error {
	dctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.dialer(dctx, addr)
}
