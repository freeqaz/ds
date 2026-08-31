// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"sort"
	"sync"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/token"
)

// notifyEventPrefix gates which D128 events are push-routed: only auth.token.*
// lifecycle events are delivered to subscribers (doc 23 §8). Any other event
// kind is ignored by the router.
const notifyEventPrefix = "auth.token."

// PushSink delivers a routed D128 token event to a single subscriber's push
// channel. Production wires this to the agent's server-stream; tests record.
// Implementations must be safe for the router to call concurrently.
type PushSink interface {
	Push(ctx context.Context, ev TokenEvent) error
}

// NotifyFilter is an OPTIONAL per-subscriber predicate that narrows delivery
// AFTER the scope gate has already passed. It receives the routable event and
// reports whether this subscriber should receive it. It can only narrow: a nil
// filter (the default) is a no-op that preserves broadcast-to-all-scope-holders
// behavior byte-for-byte. The scope check always runs first; the filter is
// AND-composed after it, so a filter never widens delivery to an unscoped
// subscriber. Predicates are pure and must be safe for concurrent calls.
type NotifyFilter func(ev TokenEvent) bool

// OrgFilter builds a NotifyFilter that admits only events whose OrgID matches
// orgID. An empty orgID yields a nil filter (no narrowing) so callers can opt
// out uniformly without a special case.
func OrgFilter(orgID string) NotifyFilter {
	if orgID == "" {
		return nil
	}
	return func(ev TokenEvent) bool { return ev.OrgID == orgID }
}

// LineageFilter builds a NotifyFilter that admits only events whose JTI or
// SessionID matches one of the supplied lineage keys (a subscriber's own
// sub-token jti and/or the ds_session_ref it belongs to). An empty key set
// yields a nil filter (no narrowing).
func LineageFilter(keys ...string) NotifyFilter {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k != "" {
			set[k] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return func(ev TokenEvent) bool {
		if _, ok := set[ev.JTI]; ok {
			return true
		}
		_, ok := set[ev.SessionID]
		return ok
	}
}

// NotifySubscriber is one push-eligible consumer of D128 auth.token.* events,
// identified by the jti of its active sub-token and the scope set that token
// carries. Routing is SCOPE-GATED: a subscriber receives a push only while its
// active sub-token carries v1:notify:receive (token.ScopeNotifyRecv, D127). An
// agent WITHOUT the scope is still severed on revocation (that path is the
// SeveringRegistry sweep in RevokeToken, independent of push) — it simply
// receives no lifecycle push.
//
// Filter is OPTIONAL and narrows delivery further, AND-composed AFTER the scope
// gate: when nil (the default) the subscriber receives every scoped event, so
// existing broadcast behavior is unchanged. When set, the subscriber receives
// only scoped events the predicate also admits (e.g. its own org/lineage).
type NotifySubscriber struct {
	JTI    string       // jti of the subscriber's active sub-token
	Scopes []string     // scope set carried in that sub-token
	Sink   PushSink     // where an eligible event is delivered
	Filter NotifyFilter // optional post-scope narrowing predicate; nil = receive all scoped events
}

// hasNotifyReceive reports whether scopes contains v1:notify:receive (D127).
func hasNotifyReceive(scopes []string) bool {
	for _, sc := range scopes {
		if sc == token.ScopeNotifyRecv {
			return true
		}
	}
	return false
}

// NotifyRouter fans D128 auth.token.* lifecycle events out to subscribers,
// gating delivery on the v1:notify:receive scope. It is the push-routing half of
// the token lifecycle: revocation severing is handled separately by RevokeToken,
// so an agent without the scope gets no push yet is still severed. Safe for
// concurrent use. NotifyRouter also satisfies EventSink, so it can be composed
// as (or fanned into) a SessionServer sink.
type NotifyRouter struct {
	mu   sync.RWMutex
	subs map[string]*NotifySubscriber // keyed by jti
}

// NewNotifyRouter allocates an empty router.
func NewNotifyRouter() *NotifyRouter {
	return &NotifyRouter{subs: make(map[string]*NotifySubscriber)}
}

// Subscribe registers (or replaces) a push subscriber keyed by its jti. A
// subscriber with an empty jti or nil sink is ignored.
func (r *NotifyRouter) Subscribe(sub NotifySubscriber) {
	if sub.JTI == "" || sub.Sink == nil {
		return
	}
	s := sub // copy the scope slice header so later caller mutation is contained
	r.mu.Lock()
	r.subs[sub.JTI] = &s
	r.mu.Unlock()
}

// Unsubscribe removes a subscriber (e.g. once its sub-token is revoked). Removing
// an unknown jti is a no-op.
func (r *NotifyRouter) Unsubscribe(jti string) {
	if jti == "" {
		return
	}
	r.mu.Lock()
	delete(r.subs, jti)
	r.mu.Unlock()
}

// Route delivers ev to every subscriber whose active sub-token carries
// v1:notify:receive AND whose optional Filter admits the event, returning the
// number of pushes delivered. Non-auth.token.* events and subscribers lacking
// the scope are skipped; the scope gate always runs first and the per-subscriber
// filter is AND-composed after it, so a filter can only narrow delivery, never
// widen it (a nil filter admits every scoped event — the default broadcast).
// Delivery is order-stable (by jti). A per-subscriber Push error does not abort
// the fan-out — the routed count reflects only successful deliveries — so one
// slow/failed consumer never blinds the rest.
func (r *NotifyRouter) Route(ctx context.Context, ev TokenEvent) int {
	if !isNotifyRoutable(ev.Kind) {
		return 0
	}
	r.mu.RLock()
	eligible := make([]*NotifySubscriber, 0, len(r.subs))
	for _, s := range r.subs {
		if hasNotifyReceive(s.Scopes) && (s.Filter == nil || s.Filter(ev)) {
			eligible = append(eligible, s)
		}
	}
	r.mu.RUnlock()

	sort.Slice(eligible, func(i, j int) bool { return eligible[i].JTI < eligible[j].JTI })

	delivered := 0
	for _, s := range eligible {
		if err := s.Sink.Push(ctx, ev); err == nil {
			delivered++
		}
	}
	return delivered
}

// EmitTokenEvent satisfies EventSink: it routes the event through the same
// scope-gated fan-out as Route, discarding the count. This lets a NotifyRouter
// be wired directly as a SessionServer sink (or one leg of a fan-out sink).
func (r *NotifyRouter) EmitTokenEvent(ctx context.Context, ev TokenEvent) error {
	r.Route(ctx, ev)
	return nil
}

// isNotifyRoutable reports whether an event kind is an auth.token.* lifecycle
// event eligible for push routing.
func isNotifyRoutable(kind EventKind) bool {
	k := string(kind)
	return len(k) >= len(notifyEventPrefix) && k[:len(notifyEventPrefix)] == notifyEventPrefix
}
