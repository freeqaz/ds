// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"
)

// D128 expiry-warning lead time: an auth.token.expiry_warn fires once a token is
// within this window of its expiry (exp-300s, doc 23 §8 / events.go).
const defaultExpiryWarnLead = 300 * time.Second

// ExpiryWarnEntry is one active token tracked by the expiry-warn scheduler. It
// carries only the fingerprint + metadata that the D128 auth.token.expiry_warn
// payload needs — NEVER the token bytes/string (D73).
type ExpiryWarnEntry struct {
	JTI        string // jti fingerprint of the active token
	Subject    string // sub claim (the authenticated principal)
	SessionRef string // ds_session_ref UUID from the token claims
	OrgID      string // org the token belongs to
	ExpiresAt  int64  // Unix-second expiry (exp claim)
}

// expiryWarnState pairs an entry with a once-only warned flag so a token warns
// exactly once even across repeated sweeps.
type expiryWarnState struct {
	entry  ExpiryWarnEntry
	warned bool
}

// ExpiryWarnScheduler schedules and emits the D128 auth.token.expiry_warn event
// for each active token at (exp - lead). It is driven by an INJECTABLE clock so
// the timing is deterministic under test: Sweep emits a warn for every tracked
// token whose expiry is within the lead window of the current clock time and
// that has not already warned. A production deployment drives Sweep from a
// ticker via Run; tests drive it directly with a mock clock. Safe for concurrent
// use.
type ExpiryWarnScheduler struct {
	sink EventSink
	now  func() time.Time
	lead time.Duration

	mu      sync.Mutex
	tracked map[string]*expiryWarnState // keyed by jti
}

// ExpiryWarnOption tunes an ExpiryWarnScheduler (clock + lead injection).
type ExpiryWarnOption func(*ExpiryWarnScheduler)

// WithExpiryNow injects the clock the scheduler reads. Tests pass a mock clock;
// production leaves the default (time.Now).
func WithExpiryNow(f func() time.Time) ExpiryWarnOption {
	return func(s *ExpiryWarnScheduler) {
		if f != nil {
			s.now = f
		}
	}
}

// WithExpiryLead overrides the pre-expiry warning window (default 300s). A
// non-positive lead is ignored so the D128 exp-300s default always stands.
func WithExpiryLead(d time.Duration) ExpiryWarnOption {
	return func(s *ExpiryWarnScheduler) {
		if d > 0 {
			s.lead = d
		}
	}
}

// NewExpiryWarnScheduler builds a scheduler emitting to sink. A nil sink is
// replaced with DiscardEventSink so the zero configuration never panics.
func NewExpiryWarnScheduler(sink EventSink, opts ...ExpiryWarnOption) *ExpiryWarnScheduler {
	s := &ExpiryWarnScheduler{
		sink:    sink,
		now:     time.Now,
		lead:    defaultExpiryWarnLead,
		tracked: make(map[string]*expiryWarnState),
	}
	if s.sink == nil {
		s.sink = DiscardEventSink{}
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Register begins tracking an active token for its expiry warning. Re-registering
// the same jti replaces the entry and re-arms the warn (e.g. on token refresh).
// An empty jti is ignored.
func (s *ExpiryWarnScheduler) Register(entry ExpiryWarnEntry) {
	if entry.JTI == "" {
		return
	}
	s.mu.Lock()
	s.tracked[entry.JTI] = &expiryWarnState{entry: entry}
	s.mu.Unlock()
}

// Remove stops tracking a token (e.g. on revocation, so a revoked token never
// emits an expiry warning). Removing an unknown jti is a no-op.
func (s *ExpiryWarnScheduler) Remove(jti string) {
	if jti == "" {
		return
	}
	s.mu.Lock()
	delete(s.tracked, jti)
	s.mu.Unlock()
}

// Sweep emits an auth.token.expiry_warn for every tracked token that has entered
// the lead window at the current clock time and has not already warned, returning
// the number of warnings emitted. A token that is already past its expiry is
// dropped without a warn (the warning is a PRE-expiry signal). Each warned token
// is flipped once so a later sweep does not re-emit. The scan is order-stable
// (by jti) for deterministic emission.
func (s *ExpiryWarnScheduler) Sweep(ctx context.Context) int {
	nowUnix := s.now().Unix()
	leadSecs := int64(s.lead / time.Second)

	s.mu.Lock()
	jtis := make([]string, 0, len(s.tracked))
	for jti := range s.tracked {
		jtis = append(jtis, jti)
	}
	sort.Strings(jtis)

	type due struct {
		entry     ExpiryWarnEntry
		remaining int64
	}
	var ready []due
	for _, jti := range jtis {
		st := s.tracked[jti]
		if st.warned {
			continue
		}
		remaining := st.entry.ExpiresAt - nowUnix
		// Warn only inside the window (0, lead]: not yet expired, but within lead.
		if remaining <= 0 || remaining > leadSecs {
			continue
		}
		st.warned = true
		ready = append(ready, due{entry: st.entry, remaining: remaining})
	}
	s.mu.Unlock()

	at := s.now()
	for _, d := range ready {
		_ = s.sink.EmitTokenEvent(ctx, TokenEvent{
			Kind:      EventTokenExpiryWarn,
			JTI:       d.entry.JTI,
			OrgID:     d.entry.OrgID,
			SessionID: d.entry.SessionRef,
			At:        at,
			Fields: map[string]string{
				"sub":               d.entry.Subject,
				"session_ref":       d.entry.SessionRef,
				"remaining_seconds": strconv.FormatInt(d.remaining, 10),
			},
		})
	}
	return len(ready)
}

// Run drives Sweep on an interval until ctx is cancelled — the production daemon
// leg. It is a thin ticker loop over the injectable clock's Sweep and returns
// when ctx is done. A non-positive interval defaults to one second.
func (s *ExpiryWarnScheduler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep(ctx)
		}
	}
}
