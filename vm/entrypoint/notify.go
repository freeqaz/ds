// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"fmt"
	"io"
	"net"
	"os"
)

// notify.go implements readiness/exit reporting at the D81 boot-to-entrypoint
// boundary.
//
// DESIGN CALL — sd_notify is the LOAD-BEARING readiness signal; EntrypointService
// is the (optional) application report.
//
// ds-entrypoint.service is `Type=notify`, so systemd holds the unit in
// "activating" until the binary sends READY=1 over $NOTIFY_SOCKET. That signal
// is what makes the boot-to-entrypoint segment observable to the init system and
// what lets `After=ds-entrypoint.service` ordering mean "the runtime is up". It
// is mandatory: without it the unit eventually times out and systemd treats the
// boot as failed (fail-closed at the init layer). So readiness MUST go through
// sd_notify.
//
// The runtime/v1 EntrypointService.ReportReady/ReportExit is the GUEST ->
// host-agent application-level report (doc 15 §4.1 step 8). It is a coordination/
// observability input, never a guardrail (D20/D38, doc 16 §12 — a guest that
// never reports is bounded by the host agent's own boot timeout). We wire it as a
// BEST-EFFORT additional reporter when the host agent is reachable; it does not
// gate the boot. Keeping it best-effort is consistent with the contract: the §3
// state machine + D46 clock are the lifecycle authority, not these calls.
//
// stdlib only (the vm module's dependency policy): the sd_notify wire is a single
// datagram to a UNIX socket — no library needed.

// reporter is the readiness/exit sink the supervisor drives. It abstracts the
// concrete transport so the supervisor stays proto- and systemd-agnostic and so
// tests can inject a recording reporter.
type reporter interface {
	// ReportReady signals the entrypoint is up and the runtime launched — the
	// close of the boot-to-entrypoint segment (D81).
	ReportReady() error
	// ReportExit signals the runtime process terminated, with an observability
	// classification, the process exit code, and a free-text detail (never
	// credential material, D39).
	ReportExit(reason exitReason, code int, detail string) error
}

// sdNotifier is the systemd sd_notify reporter (the load-bearing one). It writes
// service-manager notifications to $NOTIFY_SOCKET per the sd_notify(3) protocol.
// When NOTIFY_SOCKET is unset (running outside systemd — e.g. a test or a manual
// invocation) every call is a no-op success, so the binary runs identically off
// the init system.
type sdNotifier struct {
	// socketPath is $NOTIFY_SOCKET (empty => no-op). A leading '@' denotes the
	// abstract namespace, which we translate to a NUL-prefixed address.
	socketPath string
	// dial is overridable in tests; defaults to net.Dial.
	dial func(network, addr string) (net.Conn, error)
}

// newSDNotifier builds the sd_notify reporter from the process environment.
func newSDNotifier(getenv func(string) string) *sdNotifier {
	return &sdNotifier{
		socketPath: getenv("NOTIFY_SOCKET"),
		dial:       net.Dial,
	}
}

// ReportReady sends READY=1 to systemd.
func (n *sdNotifier) ReportReady() error {
	return n.send("READY=1")
}

// ReportExit sends a STOPPING=1 + STATUS line to systemd. systemd has no
// structured exit-reason channel, so the classification rides the human-readable
// STATUS= line; the actual process exit code is conveyed by this binary's own
// exit status (the supervisor exits nonzero on an abnormal runtime exit).
func (n *sdNotifier) ReportExit(reason exitReason, code int, detail string) error {
	status := fmt.Sprintf("STATUS=runtime exited: reason=%s code=%d", reason, code)
	if detail != "" {
		status += " detail=" + sanitizeStatus(detail)
	}
	return n.send("STOPPING=1\n" + status)
}

// send writes one sd_notify datagram. A no-op when NOTIFY_SOCKET is unset.
func (n *sdNotifier) send(payload string) error {
	if n.socketPath == "" {
		return nil
	}
	addr := n.socketPath
	if len(addr) > 0 && addr[0] == '@' {
		// Abstract namespace socket: the kernel address starts with a NUL byte.
		addr = "\x00" + addr[1:]
	}
	conn, err := n.dial("unixgram", addr)
	if err != nil {
		return fmt.Errorf("sd_notify dial %q: %w", n.socketPath, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("sd_notify write: %w", err)
	}
	return nil
}

// sanitizeStatus strips newlines from a STATUS= detail so it cannot inject extra
// sd_notify fields.
func sanitizeStatus(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' {
			r = ' '
		}
		out = append(out, r)
	}
	return string(out)
}

// multiReporter fans a readiness/exit report out to several reporters. The first
// reporter (the load-bearing sd_notify) is authoritative for the returned error;
// the rest are best-effort (their errors are logged by the supervisor, not
// fatal). This lets the supervisor treat "systemd readiness failed" as fatal
// while "the host-agent app report didn't go through" is non-fatal.
type multiReporter struct {
	primary reporter
	// best are best-effort reporters (e.g. the EntrypointService client). A nil
	// error from primary is returned even if a best-effort reporter failed; the
	// supervisor surfaces best-effort failures via onBestEffortErr.
	best            []reporter
	onBestEffortErr func(error)
}

func (m *multiReporter) ReportReady() error {
	for _, r := range m.best {
		if err := r.ReportReady(); err != nil && m.onBestEffortErr != nil {
			m.onBestEffortErr(fmt.Errorf("best-effort ReportReady: %w", err))
		}
	}
	if m.primary != nil {
		return m.primary.ReportReady()
	}
	return nil
}

func (m *multiReporter) ReportExit(reason exitReason, code int, detail string) error {
	for _, r := range m.best {
		if err := r.ReportExit(reason, code, detail); err != nil && m.onBestEffortErr != nil {
			m.onBestEffortErr(fmt.Errorf("best-effort ReportExit: %w", err))
		}
	}
	if m.primary != nil {
		return m.primary.ReportExit(reason, code, detail)
	}
	return nil
}

// stderrLogf is the supervisor's diagnostic logger target type.
type stderrLogf func(format string, args ...any)

// defaultLogf logs to the process stderr.
func defaultLogf(format string, args ...any) {
	writeLogf(os.Stderr, format, args...)
}

// writeLogf writes a prefixed diagnostic line to the given sink. A nil sink
// drops the line.
func writeLogf(sink io.Writer, format string, args ...any) {
	if sink == nil {
		return
	}
	fmt.Fprintf(sink, "ds-entrypoint: "+format+"\n", args...)
}
