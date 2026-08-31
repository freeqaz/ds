// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// recordingSink is a synthetic metering.Sink that records every appended event
// and collapses by EventID exactly as the real store does (an identical body
// under the same key is a no-op success; a differing body under the same key is a
// conflict) — so the test can assert the idempotent re-emit property without a
// live store (D50).
type recordingSink struct {
	byID map[string]store.MeteringEvent
	seq  []store.MeteringEvent
	err  error // when non-nil, every append fails (the fault-path assertion)
}

func newRecordingSink() *recordingSink {
	return &recordingSink{byID: make(map[string]store.MeteringEvent)}
}

func (s *recordingSink) AppendMeteringEvent(_ context.Context, e store.MeteringEvent) error {
	if s.err != nil {
		return s.err
	}
	if prior, ok := s.byID[e.EventID]; ok {
		if prior.State != e.State || prior.SessionUUID != e.SessionUUID {
			return store.ErrConflict
		}
		return nil // identical body, same key: idempotent no-op success
	}
	s.byID[e.EventID] = e
	s.seq = append(s.seq, e)
	return nil
}

func TestMeteringWireDisabledIsInertNoOp(t *testing.T) {
	sink := newRecordingSink()
	// Disabled even with a sink wired: arming requires the flag too.
	w := NewMeteringWire(sink, false)
	if w.Enabled() {
		t.Fatal("wire reported Enabled with the flag off")
	}
	if err := w.EmitStateTransition(context.Background(), "sess-1", store.SessionWorking, time.Unix(100, 0)); err != nil {
		t.Fatalf("disabled EmitStateTransition: unexpected err %v", err)
	}
	if len(sink.seq) != 0 {
		t.Fatalf("disabled wire appended %d events, want 0", len(sink.seq))
	}
}

func TestMeteringWireFlagOnButNilSinkStaysDisabled(t *testing.T) {
	w := NewMeteringWire(nil, true)
	if w.Enabled() {
		t.Fatal("flag-on but sink-nil wire reported Enabled; want disabled")
	}
	if err := w.EmitStateTransition(context.Background(), "sess-1", store.SessionReady, time.Unix(1, 0)); err != nil {
		t.Fatalf("nil-sink EmitStateTransition: unexpected err %v", err)
	}
}

func TestMeteringWireEmitsWhenArmed(t *testing.T) {
	sink := newRecordingSink()
	w := NewMeteringWire(sink, true)
	if !w.Enabled() {
		t.Fatal("armed wire (sink + flag) reported disabled")
	}
	at := time.Unix(1000, 0)
	if err := w.EmitStateTransition(context.Background(), "sess-1", store.SessionWorking, at); err != nil {
		t.Fatalf("armed EmitStateTransition: %v", err)
	}
	if len(sink.seq) != 1 {
		t.Fatalf("armed wire appended %d events, want 1", len(sink.seq))
	}
	got := sink.seq[0]
	if got.SessionUUID != "sess-1" || got.State != store.SessionWorking {
		t.Fatalf("appended event mismatch: %+v", got)
	}
	if got.Kind != "state_transition" {
		t.Fatalf("appended event kind = %q, want state_transition", got.Kind)
	}
}

func TestMeteringWireReEmitIsIdempotent(t *testing.T) {
	sink := newRecordingSink()
	w := NewMeteringWire(sink, true)
	at := time.Unix(2000, 0)
	for i := 0; i < 3; i++ {
		if err := w.EmitStateTransition(context.Background(), "sess-9", store.SessionReady, at); err != nil {
			t.Fatalf("re-emit %d: %v", i, err)
		}
	}
	if len(sink.seq) != 1 {
		t.Fatalf("re-emitting one logical transition appended %d rows, want 1 (idempotent)", len(sink.seq))
	}
}

func TestMeteringWireEmptyUUIDIsNoOp(t *testing.T) {
	sink := newRecordingSink()
	w := NewMeteringWire(sink, true)
	if err := w.EmitStateTransition(context.Background(), "", store.SessionWorking, time.Unix(5, 0)); err != nil {
		t.Fatalf("empty-uuid EmitStateTransition: unexpected err %v", err)
	}
	if len(sink.seq) != 0 {
		t.Fatalf("empty-uuid append produced %d rows, want 0", len(sink.seq))
	}
}

func TestMeteringWireEmitSessionEntryReadsRecordState(t *testing.T) {
	sink := newRecordingSink()
	w := NewMeteringWire(sink, true)
	rec := store.Session{Ref: store.SessionRef{SessionUUID: "sess-rec"}, State: store.SessionSuspended}
	if err := w.EmitSessionEntry(context.Background(), rec, time.Unix(42, 0)); err != nil {
		t.Fatalf("EmitSessionEntry: %v", err)
	}
	if len(sink.seq) != 1 || sink.seq[0].State != store.SessionSuspended || sink.seq[0].SessionUUID != "sess-rec" {
		t.Fatalf("EmitSessionEntry recorded wrong event: %+v", sink.seq)
	}
}

func TestMeteringWireSurfacesSinkFault(t *testing.T) {
	sink := newRecordingSink()
	sink.err = errors.New("boom")
	w := NewMeteringWire(sink, true)
	err := w.EmitStateTransition(context.Background(), "sess-1", store.SessionWorking, time.Unix(1, 0))
	if err == nil {
		t.Fatal("armed wire swallowed a sink fault; want it surfaced")
	}
}
