// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"bytes"
	"io"
	"sync"
	"testing"
)

// fakeSocket is an in-memory bidirectional ReadWriteCloser standing in for the
// guest-local event-socket UDS: bytes written by the bridge land in toHost; bytes
// the test queues in fromHost are read by the bridge. CloseWrite half-closes the
// to-host direction (mirrors a UDS CloseWrite).
type fakeSocket struct {
	toHost   *bytes.Buffer // bridge writes here (runtime stdout -> socket)
	fromHost *io.PipeReader
	mu       sync.Mutex
	wclosed  bool
}

func (f *fakeSocket) Read(p []byte) (int, error) { return f.fromHost.Read(p) }

func (f *fakeSocket) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.toHost.Write(p)
}

func (f *fakeSocket) Close() error { return f.fromHost.Close() }

func (f *fakeSocket) CloseWrite() error {
	f.mu.Lock()
	f.wclosed = true
	f.mu.Unlock()
	return nil
}

// TestBridge_RuntimeStdoutToSocket: runtime stdout -> socket (events out).
func TestBridge_RuntimeStdoutToSocket(t *testing.T) {
	// runtime stdout carries the bytes the agent emits.
	stdoutR, stdoutW := io.Pipe()
	// runtime stdin sink (the bridge writes host->runtime here).
	var stdinSink writeCloserBuf
	// host->runtime queue (empty; we close it so the socket->stdin copy ends).
	fromHostR, fromHostW := io.Pipe()

	sock := &fakeSocket{toHost: &bytes.Buffer{}, fromHost: fromHostR}
	var errSink bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- bridge(runtimeStdio{
			stdin:  &stdinSink,
			stdout: stdoutR,
			stderr: nil,
		}, sock, &errSink)
	}()

	// Emit some runtime output, then close both directions to end the bridge.
	if _, err := stdoutW.Write([]byte("hello-from-runtime")); err != nil {
		t.Fatal(err)
	}
	_ = stdoutW.Close()   // runtime closed stdout (EOF) -> stdout->socket copy ends
	_ = fromHostW.Close() // host closed socket -> socket->stdin copy ends

	if err := <-done; err != nil {
		t.Fatalf("bridge returned error: %v", err)
	}
	if got := sock.toHost.String(); got != "hello-from-runtime" {
		t.Errorf("socket received %q; want %q", got, "hello-from-runtime")
	}
	if !sock.wclosed {
		t.Error("bridge should CloseWrite the socket when runtime stdout EOFs")
	}
}

// TestBridge_SocketToRuntimeStdin: socket -> runtime stdin (commands in).
func TestBridge_SocketToRuntimeStdin(t *testing.T) {
	stdoutR, stdoutW := io.Pipe()
	var stdinSink writeCloserBuf
	fromHostR, fromHostW := io.Pipe()

	sock := &fakeSocket{toHost: &bytes.Buffer{}, fromHost: fromHostR}

	done := make(chan error, 1)
	go func() {
		done <- bridge(runtimeStdio{stdin: &stdinSink, stdout: stdoutR, stderr: nil}, sock, io.Discard)
	}()

	// Host sends a command down the socket.
	if _, err := fromHostW.Write([]byte("command-to-runtime")); err != nil {
		t.Fatal(err)
	}
	_ = fromHostW.Close() // end socket->stdin copy
	_ = stdoutW.Close()   // end stdout->socket copy

	if err := <-done; err != nil {
		t.Fatalf("bridge error: %v", err)
	}
	if got := stdinSink.String(); got != "command-to-runtime" {
		t.Errorf("runtime stdin received %q; want %q", got, "command-to-runtime")
	}
	if !stdinSink.closed {
		t.Error("bridge should close runtime stdin when the socket EOFs")
	}
}

// TestBridge_StderrDrainNotOnSocket: stderr is drained to errSink, never onto the
// event socket (it is diagnostic, not the attach event stream).
func TestBridge_StderrDrainNotOnSocket(t *testing.T) {
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	var stdinSink writeCloserBuf
	fromHostR, fromHostW := io.Pipe()

	sock := &fakeSocket{toHost: &bytes.Buffer{}, fromHost: fromHostR}
	var errSink bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- bridge(runtimeStdio{stdin: &stdinSink, stdout: stdoutR, stderr: stderrR}, sock, &errSink)
	}()

	if _, err := stderrW.Write([]byte("diagnostic-noise")); err != nil {
		t.Fatal(err)
	}
	_ = stderrW.Close()
	_ = stdoutW.Close()
	_ = fromHostW.Close()

	if err := <-done; err != nil {
		t.Fatalf("bridge error: %v", err)
	}
	if errSink.String() != "diagnostic-noise" {
		t.Errorf("stderr drain = %q; want diagnostic-noise", errSink.String())
	}
	if sock.toHost.Len() != 0 {
		t.Errorf("stderr must NOT flow onto the event socket; got %q", sock.toHost.String())
	}
}

// writeCloserBuf is an in-memory io.WriteCloser recording writes and close.
type writeCloserBuf struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (w *writeCloserBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *writeCloserBuf) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

func (w *writeCloserBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
