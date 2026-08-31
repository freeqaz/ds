// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/token"
)

// TestStartExpiryWarnDaemon exercises the DS_AUTHSDK_LIVE-gated daemon leg that
// launches ExpiryWarnScheduler.Run joined to the server lifecycle. It proves the
// loud-skip default (gate-off starts nothing, byte-identical behaviour) and the
// armed path (gate-on with a mock clock actually sweeps, then cancellation joins
// the goroutine without a leak).
func TestStartExpiryWarnDaemon(t *testing.T) {
	newServer := func(sched *ExpiryWarnScheduler) *SessionServer {
		kp, err := token.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		return NewSessionServer(NewRegistry(), kp, token.NewRevocationSet(),
			WithExpiryWarnScheduler(sched))
	}

	// gate-off: with DS_AUTHSDK_LIVE unset (t.Setenv "" clears it for the subtest),
	// no daemon starts, no goroutine sweeps, and ShutdownDaemons returns at once.
	t.Run("gate-off/no-op", func(t *testing.T) {
		t.Setenv(envExpiryWarnLive, "")
		clock := newMockClock(1_000)
		sink := &RecordingEventSink{}
		sched := NewExpiryWarnScheduler(sink, WithExpiryNow(clock.now))
		// Register a token squarely inside the (exp-300s) window: were the daemon
		// to run, it WOULD warn — so a zero count proves the loop never started.
		sched.Register(ExpiryWarnEntry{JTI: "jti-off", ExpiresAt: 1_100})
		srv := newServer(sched)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if started := srv.StartExpiryWarnDaemon(ctx, time.Millisecond); started {
			t.Fatal("StartExpiryWarnDaemon returned true with gate unset, want false (loud-skip)")
		}
		// Give any (erroneously started) loop ample time to fire.
		time.Sleep(20 * time.Millisecond)
		if got := len(sink.EventsOfKind(EventTokenExpiryWarn)); got != 0 {
			t.Fatalf("gate-off emitted %d expiry_warn events, want 0 (daemon must not run)", got)
		}
		// ShutdownDaemons must not block when nothing was started.
		done := make(chan struct{})
		go func() { srv.ShutdownDaemons(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("ShutdownDaemons blocked though no daemon was started")
		}
	})

	// gate-on: with DS_AUTHSDK_LIVE armed, exactly one goroutine runs Run; the mock
	// clock keeps a registered token inside the window so a sweep emits, proving Run
	// was invoked. Cancelling ctx + ShutdownDaemons must join the goroutine (a leak
	// would hang the WaitGroup and time out this subtest).
	t.Run("gate-on/runs-and-joins", func(t *testing.T) {
		t.Setenv(envExpiryWarnLive, "1")
		clock := newMockClock(2_000)
		sink := &RecordingEventSink{}
		sched := NewExpiryWarnScheduler(sink, WithExpiryNow(clock.now))
		sched.Register(ExpiryWarnEntry{JTI: "jti-on", Subject: "u@example.com", ExpiresAt: 2_100})
		srv := newServer(sched)

		ctx, cancel := context.WithCancel(context.Background())
		if started := srv.StartExpiryWarnDaemon(ctx, time.Millisecond); !started {
			t.Fatal("StartExpiryWarnDaemon returned false with gate armed + scheduler wired, want true")
		}
		// A second call is idempotent: no second goroutine.
		if again := srv.StartExpiryWarnDaemon(ctx, time.Millisecond); again {
			t.Fatal("second StartExpiryWarnDaemon returned true, want false (at most one daemon)")
		}

		// Poll until the ticker-driven Sweep emits the token's warning (Run invoked).
		deadline := time.After(2 * time.Second)
		for {
			if len(sink.EventsOfKind(EventTokenExpiryWarn)) >= 1 {
				break
			}
			select {
			case <-deadline:
				t.Fatal("no expiry_warn emitted: daemon goroutine did not invoke Run/Sweep")
			case <-time.After(2 * time.Millisecond):
			}
		}

		// Cancel + join: the goroutine must return so ShutdownDaemons unblocks.
		cancel()
		done := make(chan struct{})
		go func() { srv.ShutdownDaemons(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("ShutdownDaemons did not return after cancel: goroutine leaked")
		}
	})
}
