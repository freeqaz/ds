// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// transport.go bridges the launched runtime's stdio onto the VM-local host-agent
// event socket (AttachWiring.event_socket_path, a guest-local UDS that
// terminates host-side at the host agent, doc 15 §5.4). It is the D38 attach
// byte-path: io.Copy in BOTH directions and NOTHING else.
//
// RUNTIME-AGNOSTIC (D20/D38): this code never parses the bytes. It does not know
// or care whether the runtime speaks stream-json, line protocol, or raw text;
// it moves bytes between the runtime's stdout/stdin and the UDS. All protocol
// knowledge lives in the consumer at the other end of the socket and in
// client/wrapper/adapters/claude-code/, never here. If a parser ever appears in
// this file it is a bug.

// runtimeStdio is the launched runtime's three pipes the transport bridges.
// stdout flows runtime -> socket; the socket flows socket -> stdin. stderr is
// drained separately (never onto the event socket — it is diagnostic, not the
// attach event stream).
type runtimeStdio struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	// ptyMaster is the raw pty master fd in PTY launch mode, nil in PIPES mode.
	// The bridge does NOT touch it (it copies via stdin/stdout like any other
	// launcher); it is the seam the U-GUEST-WIRE leg uses to drive live resize
	// (TIOCSWINSZ) and raw terminal framing over the attach plane. Leaving it on
	// runtimeStdio keeps the byte-copy path (transport.go) runtime-agnostic — the
	// pipes path leaves it nil and behaves byte-identically.
	ptyMaster *os.File
}

// eventSocketDialDeadline bounds how long dialEventSocket waits for the forwarder
// to bind its UDS before failing closed. A package var so offline tests can shrink
// it (the production dialer is unixDialerImpl; tests inject dialerHook and never
// reach this).
var eventSocketDialDeadline = 30 * time.Second

// dialEventSocket connects to the guest-local event-socket UDS the host agent
// is listening on (served in-guest by ds-attachfwd, which splices it onto the
// AF_VSOCK carriage the host-agent dials). Fail-closed: a persistent dial error
// aborts (no socket => no attach path => the runtime must not run unobserved).
//
// BOOT-RACE RETRY (live-found 2026-06-16): ds-attachfwd is ordered Before this
// entrypoint, but systemd ordering does not wait for it to have BOUND its UDS
// (Type=simple is "started" at exec), so a fast entrypoint can dial before the
// listener exists and fail-close a session whose carriage is merely a beat behind.
// Retry with a short backoff up to eventSocketDialDeadline; only then fail closed.
func dialEventSocket(path string) (net.Conn, error) {
	dl := time.Now().Add(eventSocketDialDeadline)
	for attempt := 1; ; attempt++ {
		conn, err := net.Dial("unix", path)
		if err == nil {
			return conn, nil
		}
		if time.Now().After(dl) {
			return nil, fmt.Errorf("dial event socket %q (after %s, %d attempts): %w", path, eventSocketDialDeadline, attempt, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// bridge wires the runtime's stdio onto the event-socket connection with io.Copy
// in both directions, plus a stderr drain to errSink (the entrypoint's own
// stderr — diagnostics, never the event stream). It returns when BOTH attach
// directions have finished (the runtime closed stdout, or the socket closed),
// which is the signal the attach byte-path is done. The first error from either
// direction is returned (nil on clean EOF).
//
// bridge takes the io interfaces (not *exec.Cmd, not net.Conn directly) so it is
// unit-testable with in-memory pipes and a fake socket — no real process or UDS
// required (the OFFLINE test contract).
func bridge(stdio runtimeStdio, socket io.ReadWriteCloser, errSink io.Writer) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	record := func(err error) {
		if err == nil || err == io.EOF {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	// runtime stdout -> socket (events out). When the runtime closes stdout we
	// half-close the write side toward the host agent so it sees EOF.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(socket, stdio.stdout)
		record(wrapCopyErr("stdout->socket", err))
		if hc, ok := socket.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
	}()

	// socket -> runtime stdin (commands in). When the host agent closes the
	// socket we close the runtime's stdin so it sees EOF on its input.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stdio.stdin, socket)
		record(wrapCopyErr("socket->stdin", err))
		_ = stdio.stdin.Close()
	}()

	// runtime stderr -> entrypoint stderr (diagnostics, NOT the event stream).
	if stdio.stderr != nil && errSink != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(errSink, stdio.stderr)
		}()
	}

	wg.Wait()
	return firstErr
}

func wrapCopyErr(dir string, err error) error {
	if err == nil || err == io.EOF || isPTYHangup(err) {
		return nil
	}
	return fmt.Errorf("attach copy %s: %w", dir, err)
}

// isPTYHangup reports whether err is the pty-master hangup: reading a pty master
// AFTER its child has exited (and the last slave reference is closed) returns
// Linux EIO, not io.EOF. That is the NORMAL end of a pty session — the runtime
// hung up — so the bridge treats it as a clean EOF, never a bridge error, and the
// runtime's own exit code (proc.wait) is unaffected. On the pipes path EIO never
// arises (a closed pipe yields io.EOF), so this is a no-op there.
func isPTYHangup(err error) bool {
	return errors.Is(err, syscall.EIO)
}
