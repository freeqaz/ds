// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSDNotify_NoSocket_IsNoop(t *testing.T) {
	n := newSDNotifier(func(string) string { return "" })
	if err := n.ReportReady(); err != nil {
		t.Errorf("ReportReady with no NOTIFY_SOCKET should be a no-op: %v", err)
	}
	if err := n.ReportExit(exitReasonCompleted, 0, ""); err != nil {
		t.Errorf("ReportExit with no NOTIFY_SOCKET should be a no-op: %v", err)
	}
}

func TestSDNotify_SendsReadyDatagram(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "notify.sock")

	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unixgram: %v", err)
	}
	defer conn.Close()
	defer os.Remove(sockPath)

	got := make(chan string, 2)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for i := 0; i < 2; i++ {
			nn, _, err := conn.ReadFromUnix(buf)
			if err != nil {
				return
			}
			got <- string(buf[:nn])
		}
	}()

	n := newSDNotifier(func(k string) string {
		if k == "NOTIFY_SOCKET" {
			return sockPath
		}
		return ""
	})
	if err := n.ReportReady(); err != nil {
		t.Fatalf("ReportReady: %v", err)
	}
	if err := n.ReportExit(exitReasonError, 3, "boom\nwith-newline"); err != nil {
		t.Fatalf("ReportExit: %v", err)
	}
	wg.Wait()
	close(got)

	var msgs []string
	for m := range got {
		msgs = append(msgs, m)
	}
	if len(msgs) < 2 {
		t.Fatalf("expected 2 datagrams, got %d: %v", len(msgs), msgs)
	}
	if msgs[0] != "READY=1" {
		t.Errorf("first datagram = %q; want READY=1", msgs[0])
	}
	if !strings.Contains(msgs[1], "STOPPING=1") || !strings.Contains(msgs[1], "reason=error") || !strings.Contains(msgs[1], "code=3") {
		t.Errorf("exit datagram missing fields: %q", msgs[1])
	}
	// Newlines in the detail must be sanitized so they cannot inject sd_notify fields.
	if strings.Contains(msgs[1], "boom\nwith-newline") {
		t.Errorf("detail newline not sanitized: %q", msgs[1])
	}
}

func TestMultiReporter_PrimaryFatal_BestEffortNonFatal(t *testing.T) {
	primary := &recordingReporter{}
	best := &recordingReporter{readyErr: fmt.Errorf("app report down")}
	var bestErrs []error
	m := &multiReporter{
		primary:         primary,
		best:            []reporter{best},
		onBestEffortErr: func(e error) { bestErrs = append(bestErrs, e) },
	}
	// Best-effort failure must NOT propagate (primary succeeded).
	if err := m.ReportReady(); err != nil {
		t.Errorf("ReportReady should ignore best-effort failure: %v", err)
	}
	if len(bestErrs) != 1 {
		t.Errorf("best-effort error not surfaced: %v", bestErrs)
	}
	if primary.ready != 1 {
		t.Errorf("primary not called: %d", primary.ready)
	}

	// A primary failure IS fatal.
	primary.readyErr = fmt.Errorf("notify gone")
	if err := m.ReportReady(); err == nil {
		t.Error("primary readiness failure must propagate")
	}
}
