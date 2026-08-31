// SPDX-License-Identifier: Apache-2.0

// Package service wires the oidc/, saml/, token/, and attenuation/ packages
// into the full dreamserpent.auth.v1 gRPC service implementations
// (AuthSessionService + TokenAttenuationService; D129).
package service

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// EventKind names a D128 auth token lifecycle event.
type EventKind string

const (
	// EventTokenIssued fires when a user auth token (D125) or agent sub-token (D126) is minted.
	EventTokenIssued EventKind = "auth.token.issued"
	// EventTokenExpiryWarn fires when a token is within 5 minutes of expiry (exp-300s).
	EventTokenExpiryWarn EventKind = "auth.token.expiry_warn"
	// EventTokenRevoked fires when a token is explicitly revoked; cascade count is in Fields["cascade"].
	EventTokenRevoked EventKind = "auth.token.revoked"
)

// TokenEvent is a single D128 auth token lifecycle emission.
// Credentials are NEVER included — only the jti fingerprint and metadata.
type TokenEvent struct {
	Kind      EventKind
	JTI       string // jti of the affected token (never the token bytes/string)
	OrgID     string // org the token belongs to
	SessionID string // ds_session_ref UUID from the token claims
	At        time.Time
	Fields    map[string]string // extra context (e.g. "cascade":"3" for revoke)
}

func (e TokenEvent) String() string {
	return fmt.Sprintf("TokenEvent{kind=%s jti=%s org=%s}", e.Kind, e.JTI, e.OrgID)
}

// EventSink is the single egress for D128 auth token lifecycle events (doc 23 §8).
// Production wires this to the ds-telemetry EventSink; the zero-value
// implementation is DiscardEventSink. Interface kept minimal so the auth-sdk
// module does not depend on any telemetry package directly.
type EventSink interface {
	EmitTokenEvent(ctx context.Context, ev TokenEvent) error
}

// DiscardEventSink drops all events. Useful as a zero-value default.
type DiscardEventSink struct{}

func (DiscardEventSink) EmitTokenEvent(_ context.Context, _ TokenEvent) error { return nil }

// RecordingEventSink records all events for test assertions. Thread-safe.
type RecordingEventSink struct {
	events []TokenEvent
	mu     sync.Mutex
}

func (r *RecordingEventSink) EmitTokenEvent(_ context.Context, ev TokenEvent) error {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	return nil
}

// Events returns a copy of all recorded events.
func (r *RecordingEventSink) Events() []TokenEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TokenEvent, len(r.events))
	copy(out, r.events)
	return out
}

// EventsOfKind filters recorded events by kind.
func (r *RecordingEventSink) EventsOfKind(kind EventKind) []TokenEvent {
	all := r.Events()
	out := make([]TokenEvent, 0)
	for _, ev := range all {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}
