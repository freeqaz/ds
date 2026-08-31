// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"sync"
	"testing"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/attenuation"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/token"
	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
)

// recordingPushSink is a synthetic PushSink (D50) recording every event pushed.
type recordingPushSink struct {
	mu     sync.Mutex
	events []TokenEvent
}

func (p *recordingPushSink) Push(_ context.Context, ev TokenEvent) error {
	p.mu.Lock()
	p.events = append(p.events, ev)
	p.mu.Unlock()
	return nil
}

func (p *recordingPushSink) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.events)
}

// TestNotifyRouter_ScopeGatesPush is the acceptance test for push routing: an
// auth.token.* event is delivered ONLY to subscribers whose active sub-token
// carries v1:notify:receive. A subscriber without the scope receives no push.
func TestNotifyRouter_ScopeGatesPush(t *testing.T) {
	ctx := context.Background()
	router := NewNotifyRouter()

	withScope := &recordingPushSink{}
	noScope := &recordingPushSink{}

	router.Subscribe(NotifySubscriber{
		JTI:    "agent-with-scope",
		Scopes: []string{token.ScopeCodeRead, token.ScopeNotifyRecv},
		Sink:   withScope,
	})
	router.Subscribe(NotifySubscriber{
		JTI:    "agent-no-scope",
		Scopes: []string{token.ScopeCodeRead}, // NO v1:notify:receive
		Sink:   noScope,
	})

	n := router.Route(ctx, TokenEvent{Kind: EventTokenRevoked, JTI: "parent-1"})
	if n != 1 {
		t.Fatalf("Route delivered to %d subscribers, want 1 (only the scoped one)", n)
	}
	if withScope.count() != 1 {
		t.Errorf("scoped subscriber pushes = %d, want 1", withScope.count())
	}
	if noScope.count() != 0 {
		t.Errorf("unscoped subscriber pushes = %d, want 0", noScope.count())
	}
}

// TestNotifyRouter_IgnoresNonTokenEvents confirms only auth.token.* kinds route.
func TestNotifyRouter_IgnoresNonTokenEvents(t *testing.T) {
	router := NewNotifyRouter()
	sink := &recordingPushSink{}
	router.Subscribe(NotifySubscriber{JTI: "a", Scopes: []string{token.ScopeNotifyRecv}, Sink: sink})

	if n := router.Route(context.Background(), TokenEvent{Kind: "some.other.event", JTI: "x"}); n != 0 {
		t.Errorf("Route of non-token event delivered %d, want 0", n)
	}
	if sink.count() != 0 {
		t.Errorf("subscriber received %d non-token pushes, want 0", sink.count())
	}
}

// TestNotifyRouter_Unsubscribe confirms a removed subscriber no longer receives.
func TestNotifyRouter_Unsubscribe(t *testing.T) {
	router := NewNotifyRouter()
	sink := &recordingPushSink{}
	router.Subscribe(NotifySubscriber{JTI: "gone", Scopes: []string{token.ScopeNotifyRecv}, Sink: sink})
	router.Unsubscribe("gone")
	if n := router.Route(context.Background(), TokenEvent{Kind: EventTokenIssued, JTI: "y"}); n != 0 {
		t.Errorf("Route after Unsubscribe delivered %d, want 0", n)
	}
}

// TestNotifyRouter_OrgFilterNarrows proves the optional per-subscriber filter
// narrows (never widens) delivery, AND-composed after the scope gate: an
// org-filtered subscriber receives ONLY its own org's events, an unfiltered
// subscriber still receives every scoped event (default broadcast preserved),
// and a scope-denied subscriber receives nothing regardless of its filter.
func TestNotifyRouter_OrgFilterNarrows(t *testing.T) {
	ctx := context.Background()
	router := NewNotifyRouter()

	orgAScoped := &recordingPushSink{}     // scoped + filtered to org-A
	unfiltered := &recordingPushSink{}     // scoped, no filter -> all events
	deniedFiltered := &recordingPushSink{} // filter admits org-A but LACKS the scope

	router.Subscribe(NotifySubscriber{
		JTI:    "org-a-observer",
		Scopes: []string{token.ScopeNotifyRecv},
		Sink:   orgAScoped,
		Filter: OrgFilter("org-A"),
	})
	router.Subscribe(NotifySubscriber{
		JTI:    "all-observer",
		Scopes: []string{token.ScopeNotifyRecv},
		Sink:   unfiltered, // nil Filter -> receives all scoped events
	})
	router.Subscribe(NotifySubscriber{
		JTI:    "org-a-but-no-scope",
		Scopes: []string{token.ScopeCodeRead}, // NO v1:notify:receive
		Sink:   deniedFiltered,
		Filter: OrgFilter("org-A"), // filter can never widen past the scope gate
	})

	evA := TokenEvent{Kind: EventTokenRevoked, JTI: "jti-a", OrgID: "org-A"}
	evB := TokenEvent{Kind: EventTokenRevoked, JTI: "jti-b", OrgID: "org-B"}

	// org-A event: org-A subscriber + the unfiltered one receive it; denied gets none.
	if n := router.Route(ctx, evA); n != 2 {
		t.Fatalf("Route(org-A) delivered to %d, want 2 (org-A filtered + unfiltered)", n)
	}
	// org-B event: ONLY the unfiltered subscriber receives it (org-A filter narrows).
	if n := router.Route(ctx, evB); n != 1 {
		t.Fatalf("Route(org-B) delivered to %d, want 1 (only unfiltered)", n)
	}

	if orgAScoped.count() != 1 {
		t.Errorf("org-A filtered subscriber pushes = %d, want 1 (its org only)", orgAScoped.count())
	}
	if unfiltered.count() != 2 {
		t.Errorf("unfiltered subscriber pushes = %d, want 2 (broadcast preserved)", unfiltered.count())
	}
	if deniedFiltered.count() != 0 {
		t.Errorf("scope-denied subscriber pushes = %d, want 0 (filter cannot widen past scope)", deniedFiltered.count())
	}
}

// TestNotifyRouter_NilFilterIsBroadcast pins that the default (nil Filter) path
// is byte-identical to the pre-filter broadcast: every scoped subscriber gets
// every routable event regardless of its org/lineage.
func TestNotifyRouter_NilFilterIsBroadcast(t *testing.T) {
	ctx := context.Background()
	router := NewNotifyRouter()
	a := &recordingPushSink{}
	b := &recordingPushSink{}
	router.Subscribe(NotifySubscriber{JTI: "a", Scopes: []string{token.ScopeNotifyRecv}, Sink: a})
	router.Subscribe(NotifySubscriber{JTI: "b", Scopes: []string{token.ScopeNotifyRecv}, Sink: b})

	if n := router.Route(ctx, TokenEvent{Kind: EventTokenIssued, JTI: "j1", OrgID: "org-X"}); n != 2 {
		t.Fatalf("Route delivered to %d, want 2 (nil filters broadcast)", n)
	}
	if n := router.Route(ctx, TokenEvent{Kind: EventTokenIssued, JTI: "j2", OrgID: "org-Y"}); n != 2 {
		t.Fatalf("Route delivered to %d, want 2 (nil filters broadcast, any org)", n)
	}
	if a.count() != 2 || b.count() != 2 {
		t.Errorf("broadcast counts a=%d b=%d, want 2 each", a.count(), b.count())
	}
}

// TestNotifyRouter_LineageFilterNarrows proves LineageFilter admits only events
// matching a subscriber's own jti or session lineage, and an empty key set
// yields a nil (no-op) filter that broadcasts.
func TestNotifyRouter_LineageFilterNarrows(t *testing.T) {
	ctx := context.Background()
	router := NewNotifyRouter()

	byJTI := &recordingPushSink{}
	bySession := &recordingPushSink{}
	emptyKeys := &recordingPushSink{}

	router.Subscribe(NotifySubscriber{
		JTI:    "sub-jti",
		Scopes: []string{token.ScopeNotifyRecv},
		Sink:   byJTI,
		Filter: LineageFilter("my-token-jti"),
	})
	router.Subscribe(NotifySubscriber{
		JTI:    "sub-session",
		Scopes: []string{token.ScopeNotifyRecv},
		Sink:   bySession,
		Filter: LineageFilter("sess-123"),
	})
	router.Subscribe(NotifySubscriber{
		JTI:    "sub-empty",
		Scopes: []string{token.ScopeNotifyRecv},
		Sink:   emptyKeys,
		Filter: LineageFilter("", ""), // empty -> nil filter -> broadcast
	})

	// Event matching by JTI lineage key.
	router.Route(ctx, TokenEvent{Kind: EventTokenRevoked, JTI: "my-token-jti", SessionID: "sess-999"})
	// Event matching by SessionID lineage key.
	router.Route(ctx, TokenEvent{Kind: EventTokenRevoked, JTI: "other", SessionID: "sess-123"})

	if byJTI.count() != 1 {
		t.Errorf("jti-lineage subscriber pushes = %d, want 1", byJTI.count())
	}
	if bySession.count() != 1 {
		t.Errorf("session-lineage subscriber pushes = %d, want 1", bySession.count())
	}
	if emptyKeys.count() != 2 {
		t.Errorf("empty-key (nil) filter subscriber pushes = %d, want 2 (broadcast)", emptyKeys.count())
	}
}

// TestNotifyRouter_UnscopedAgentSeveredButNoPush is the headline integration: on
// revocation, an agent WITHOUT v1:notify:receive is STILL severed at the
// SeveringRegistry seam, yet receives NO lifecycle push. Wiring the NotifyRouter
// as the SessionServer's EventSink routes the emitted auth.token.revoked event
// through the same scope gate, so the unscoped agent is severed-but-silent while
// a scoped agent gets the push.
func TestNotifyRouter_UnscopedAgentSeveredButNoPush(t *testing.T) {
	ctx := context.Background()
	const parentJTI = "parent-sever-1"
	const unscopedJTI = "agent-no-scope-1"

	// Lineage: the parent plus one derived agent sub-token WITHOUT the notify scope.
	lin := attenuation.NewLineageStore()
	lin.Record(attenuation.DerivedRecord{
		DerivedJTI:       unscopedJTI,
		ParentJTI:        parentJTI,
		HostSessionIndex: 0,
		Scopes:           []string{token.ScopeCodeRead}, // no v1:notify:receive
		IssuedAt:         1,
		ExpiresAt:        1 << 40,
	})

	// Router with the unscoped agent AND a scoped observer subscribed.
	router := NewNotifyRouter()
	unscopedPush := &recordingPushSink{}
	scopedPush := &recordingPushSink{}
	router.Subscribe(NotifySubscriber{
		JTI:    unscopedJTI,
		Scopes: []string{token.ScopeCodeRead},
		Sink:   unscopedPush,
	})
	router.Subscribe(NotifySubscriber{
		JTI:    "observer-scoped",
		Scopes: []string{token.ScopeNotifyRecv},
		Sink:   scopedPush,
	})

	fake := &fakeSeveringRegistry{}
	// The router IS the event sink, so RevokeToken's emitted event is push-routed.
	srv := newSessionServerForRevoke(t, lin, fake, router)

	if _, err := srv.RevokeToken(ctx, &authv1.RevokeTokenRequest{Jti: parentJTI, Reason: "session-ended"}); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// The unscoped agent WAS severed (its jti reached the SeveringRegistry seam).
	if fake.counts()[unscopedJTI] != 1 {
		t.Errorf("unscoped agent severed %d times, want 1 (severing is scope-independent)", fake.counts()[unscopedJTI])
	}
	// ...but received NO push (routing is scope-gated).
	if unscopedPush.count() != 0 {
		t.Errorf("unscoped agent received %d pushes, want 0", unscopedPush.count())
	}
	// The scoped observer DID receive the revoke push.
	if scopedPush.count() != 1 {
		t.Errorf("scoped observer received %d pushes, want 1", scopedPush.count())
	}
}
