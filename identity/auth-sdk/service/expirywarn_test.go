// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/attenuation"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/token"
	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
)

// mockClock is an injectable clock for deterministic expiry-warn timing.
type mockClock struct{ unix atomic.Int64 }

func (c *mockClock) set(unix int64) { c.unix.Store(unix) }
func (c *mockClock) now() time.Time { return time.Unix(c.unix.Load(), 0) }
func newMockClock(unix int64) *mockClock {
	c := &mockClock{}
	c.set(unix)
	return c
}

// TestExpiryWarn_WindowBoundary is the acceptance test: at exp-301s no warning
// fires (remaining 301 > 300 lead); at exp-299s the auth.token.expiry_warn fires
// exactly once, carrying {jti, sub, session_ref, remaining_seconds}.
func TestExpiryWarn_WindowBoundary(t *testing.T) {
	ctx := context.Background()
	const exp = int64(1_000_000)

	clock := newMockClock(exp - 301) // 301s before expiry: outside the 300s window
	sink := &RecordingEventSink{}
	sched := NewExpiryWarnScheduler(sink, WithExpiryNow(clock.now))

	sched.Register(ExpiryWarnEntry{
		JTI:        "jti-warn-1",
		Subject:    "user@example.com",
		SessionRef: "sess-uuid-1",
		OrgID:      "org-1",
		ExpiresAt:  exp,
	})

	// exp-301s: remaining_seconds == 301 > 300 → no event.
	if n := sched.Sweep(ctx); n != 0 {
		t.Fatalf("Sweep at exp-301s emitted %d warnings, want 0", n)
	}
	if got := len(sink.EventsOfKind(EventTokenExpiryWarn)); got != 0 {
		t.Fatalf("expiry_warn events at exp-301s = %d, want 0", got)
	}

	// exp-299s: remaining_seconds == 299 <= 300 → exactly one warning.
	clock.set(exp - 299)
	if n := sched.Sweep(ctx); n != 1 {
		t.Fatalf("Sweep at exp-299s emitted %d warnings, want 1", n)
	}
	evs := sink.EventsOfKind(EventTokenExpiryWarn)
	if len(evs) != 1 {
		t.Fatalf("expiry_warn events at exp-299s = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.JTI != "jti-warn-1" {
		t.Errorf("event JTI = %q, want %q", ev.JTI, "jti-warn-1")
	}
	if ev.Fields["sub"] != "user@example.com" {
		t.Errorf("event sub = %q, want %q", ev.Fields["sub"], "user@example.com")
	}
	if ev.Fields["session_ref"] != "sess-uuid-1" {
		t.Errorf("event session_ref = %q, want %q", ev.Fields["session_ref"], "sess-uuid-1")
	}
	if ev.SessionID != "sess-uuid-1" {
		t.Errorf("event SessionID = %q, want %q", ev.SessionID, "sess-uuid-1")
	}
	if ev.Fields["remaining_seconds"] != "299" {
		t.Errorf("event remaining_seconds = %q, want %q", ev.Fields["remaining_seconds"], "299")
	}

	// A second sweep inside the window must NOT re-emit (warn is once-only).
	if n := sched.Sweep(ctx); n != 0 {
		t.Errorf("second Sweep re-emitted %d warnings, want 0 (once-only)", n)
	}
}

// TestExpiryWarn_PastExpiryNoWarn confirms a token already past expiry is dropped
// without a warning — the warn is a strictly pre-expiry signal.
func TestExpiryWarn_PastExpiryNoWarn(t *testing.T) {
	const exp = int64(2_000_000)
	clock := newMockClock(exp + 5) // already expired
	sink := &RecordingEventSink{}
	sched := NewExpiryWarnScheduler(sink, WithExpiryNow(clock.now))
	sched.Register(ExpiryWarnEntry{JTI: "jti-expired", ExpiresAt: exp})
	if n := sched.Sweep(context.Background()); n != 0 {
		t.Fatalf("Sweep past expiry emitted %d warnings, want 0", n)
	}
}

// TestExpiryWarn_RemoveStopsWarning confirms Remove (called on revocation)
// prevents a subsequent warning.
func TestExpiryWarn_RemoveStopsWarning(t *testing.T) {
	const exp = int64(3_000_000)
	clock := newMockClock(exp - 100) // inside the window
	sink := &RecordingEventSink{}
	sched := NewExpiryWarnScheduler(sink, WithExpiryNow(clock.now))
	sched.Register(ExpiryWarnEntry{JTI: "jti-removed", ExpiresAt: exp})
	sched.Remove("jti-removed")
	if n := sched.Sweep(context.Background()); n != 0 {
		t.Fatalf("Sweep after Remove emitted %d warnings, want 0", n)
	}
}

// TestExpiryWarn_CustomLead confirms WithExpiryLead moves the window boundary.
func TestExpiryWarn_CustomLead(t *testing.T) {
	const exp = int64(4_000_000)
	clock := newMockClock(exp - 45)
	sink := &RecordingEventSink{}
	// 60s lead: remaining 45 <= 60 → warns.
	sched := NewExpiryWarnScheduler(sink, WithExpiryNow(clock.now), WithExpiryLead(60*time.Second))
	sched.Register(ExpiryWarnEntry{JTI: "jti-lead", ExpiresAt: exp})
	if n := sched.Sweep(context.Background()); n != 1 {
		t.Fatalf("Sweep with 60s lead at exp-45s emitted %d, want 1", n)
	}
}

// TestExpiryWarn_WiredToMint proves the SessionServer wiring: a minted token is
// registered for its (exp-300s) warning, and revocation deregisters it so no
// warning ever fires for a revoked token.
func TestExpiryWarn_WiredToMint(t *testing.T) {
	ctx := context.Background()
	const serverNow = int64(5_000_000) // mint sets exp = serverNow + 900 (D125)
	const expUnix = serverNow + 900

	kp, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	clock := newMockClock(0)
	sink := &RecordingEventSink{}
	sched := NewExpiryWarnScheduler(sink, WithExpiryNow(clock.now))
	lin := attenuation.NewLineageStore()

	srv := NewSessionServer(NewRegistry(), kp, token.NewRevocationSet(),
		WithNow(func() time.Time { return time.Unix(serverNow, 0) }),
		WithEventSink(sink),
		WithLineageStore(lin),
		WithSeveringRegistry(&fakeSeveringRegistry{}),
		WithExpiryWarnScheduler(sched),
	)

	resp, err := srv.mintUserAuthToken(ctx, "org-1", "user@example.com", nil, "sess-mint-1")
	if err != nil {
		t.Fatalf("mintUserAuthToken: %v", err)
	}
	if resp.GetExpiresAtUnix() != expUnix {
		t.Fatalf("minted exp = %d, want %d", resp.GetExpiresAtUnix(), expUnix)
	}

	// Just outside the window: no warning.
	clock.set(expUnix - 301)
	if n := sched.Sweep(ctx); n != 0 {
		t.Fatalf("Sweep at mint exp-301s emitted %d, want 0", n)
	}
	// Inside the window: the minted token warns.
	clock.set(expUnix - 200)
	if n := sched.Sweep(ctx); n != 1 {
		t.Fatalf("Sweep at mint exp-200s emitted %d, want 1", n)
	}
	warns := sink.EventsOfKind(EventTokenExpiryWarn)
	if len(warns) != 1 || warns[0].Fields["sub"] != "user@example.com" {
		t.Fatalf("expiry_warn = %+v, want one for user@example.com", warns)
	}

	// Now mint a second token and REVOKE it: the scheduler must deregister it so
	// it never warns.
	if _, err := srv.mintUserAuthToken(ctx, "org-1", "user2@example.com", nil, "sess-mint-2"); err != nil {
		t.Fatalf("mintUserAuthToken(2): %v", err)
	}
	// The minted jti is carried on the EventTokenIssued emission (never returned
	// in the response), so recover the second token's jti from the recording sink.
	issued := sink.EventsOfKind(EventTokenIssued)
	if len(issued) != 2 {
		t.Fatalf("issued events = %d, want 2", len(issued))
	}
	jti2 := issued[1].JTI
	if _, err := srv.RevokeToken(ctx, &authv1.RevokeTokenRequest{Jti: jti2}); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	clock.set(expUnix - 100) // inside the window for token 2 as well
	before := len(sink.EventsOfKind(EventTokenExpiryWarn))
	sched.Sweep(ctx)
	after := len(sink.EventsOfKind(EventTokenExpiryWarn))
	if after != before {
		t.Errorf("revoked token still warned: expiry_warn count %d -> %d", before, after)
	}
}
