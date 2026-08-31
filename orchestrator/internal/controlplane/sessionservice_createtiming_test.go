// SPDX-License-Identifier: Apache-2.0

package controlplane

// sessionservice_createtiming_test.go pins the createtiming-feed observability leg the
// SessionService hosts: the FLAG-GATED D81 §8 create-timing fold through the create path
// (folded via the reconcile loop's RecordCreateTiming under DS_ORCH_CREATETIMING_WIRE), the
// admin/observability CreateTimingServerSpanTrend read surface (client RTT excluded), and the
// D57 ListMeteringEvents read surface. All synthetic; no live VM/host-agent (D50).

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestSessionService_CreateTiming_DefaultOffInert is the byte-identical default-off pin: with
// DS_ORCH_CREATETIMING_WIRE UNSET, a create through the wired handler folds NOTHING into the
// trend recorder even when the fold sink IS installed — the create still succeeds, and
// CreateTimingServerSpanTrend reads an empty trend (Count 0). This is the measure-not-gate
// default-off inertness the wave gate requires.
func TestSessionService_CreateTiming_DefaultOffInert(t *testing.T) {
	// Flag deliberately unset (the default).
	f := newFixture(t, fixtureOpts{})
	// Wire the fold sink to the reconcile loop even though the flag is off — proving the fold is
	// inert on the FLAG, not merely on the missing wiring.
	f.cp.Sessions.SetCreateTimingServing(f.cp.Reconcile)

	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession (flag off): %v", err)
	}
	if created.GetSession().GetSessionUuid() == "" {
		t.Fatal("CreateSession returned no session (flag off)")
	}

	if trend := f.cp.Sessions.CreateTimingServerSpanTrend(); trend.Count != 0 {
		t.Errorf("flag-off server-span trend Count = %d, want 0 (the fold is inert with DS_ORCH_CREATETIMING_WIRE unset)", trend.Count)
	}
}

// TestSessionService_CreateTiming_FlagOnFeedsTrend is the headline createtiming-feed acceptance:
// with DS_ORCH_CREATETIMING_WIRE=1, a synthetic create through the wired handler folds its
// MEASURED §8 create→attach decomposition into the reconcile loop's trend recorder, so the
// admin/observability CreateTimingServerSpanTrend read surface reports a NON-EMPTY server-span
// trend (one folded create) — the (b)-row "trends are recorded" producer, live behind the flag.
func TestSessionService_CreateTiming_FlagOnFeedsTrend(t *testing.T) {
	t.Setenv(CreateTimingWireFlag, "1") // armed BEFORE newFixture so the loop self-arms its wire.

	f := newFixture(t, fixtureOpts{})
	if f.cp.Reconcile == nil {
		t.Fatal("fixture has no reconcile loop")
	}
	// The loop self-armed its create-timing wire from the flag (read at construction).
	if trend := f.cp.Reconcile.CreateTimingServerSpanTrend(); trend.Count != 0 {
		t.Fatalf("pre-create loop trend Count = %d, want 0 (nothing folded yet)", trend.Count)
	}
	f.cp.Sessions.SetCreateTimingServing(f.cp.Reconcile)

	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession (flag on): %v", err)
	}
	if created.GetSession().GetSessionUuid() == "" {
		t.Fatal("CreateSession returned no session (flag on)")
	}

	// The fold produced a non-empty server-span trend readable via the observability surface.
	trend := f.cp.Sessions.CreateTimingServerSpanTrend()
	if trend.Count != 1 {
		t.Fatalf("flag-on server-span trend Count = %d, want 1 (one synthetic create folded)", trend.Count)
	}

	// The SAME trend is visible directly on the loop (one shared recorder — no second recorder
	// forked into the handler).
	if loopTrend := f.cp.Reconcile.CreateTimingServerSpanTrend(); loopTrend.Count != trend.Count {
		t.Errorf("loop server-span trend Count = %d, handler surface Count = %d, want equal (one shared recorder)", loopTrend.Count, trend.Count)
	}
}

// TestSessionService_ListMeteringEvents_ReturnsRecordedD57Events proves the D57 read surface: the
// metering events recorded on the store (as the metering-wire appends them) are returned for a
// session through the admin/observability ListMeteringEvents surface, which the fixture wires
// automatically off the single backing store (SetDestroyServing).
func TestSessionService_ListMeteringEvents_ReturnsRecordedD57Events(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	const sessionUUID = "sess-metering-1"
	// Append two synthetic D57 events (what the metering-wire records: a billing state
	// transition + a D37 sample) plus one for a DIFFERENT session (must be filtered out).
	events := []store.MeteringEvent{
		{EventID: "ev-1", SessionUUID: sessionUUID, Kind: "state_transition", State: store.SessionAttached, OccurredAt: time.Unix(1_700_000_001, 0).UTC()},
		{EventID: "ev-2", SessionUUID: sessionUUID, Kind: "sample", OccurredAt: time.Unix(1_700_000_002, 0).UTC()},
		{EventID: "ev-other", SessionUUID: "sess-other", Kind: "sample", OccurredAt: time.Unix(1_700_000_003, 0).UTC()},
	}
	for _, e := range events {
		if err := f.st.AppendMeteringEvent(context.Background(), e); err != nil {
			t.Fatalf("seed metering event %s: %v", e.EventID, err)
		}
	}

	got, err := f.cp.Sessions.ListMeteringEvents(context.Background(), sessionUUID)
	if err != nil {
		t.Fatalf("ListMeteringEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListMeteringEvents returned %d events, want 2 (the session's two recorded events, the other session filtered)", len(got))
	}
	for _, e := range got {
		if e.SessionUUID != sessionUUID {
			t.Errorf("ListMeteringEvents leaked event %s for session %q (want only %q)", e.EventID, e.SessionUUID, sessionUUID)
		}
	}
}

// TestSessionService_ListMeteringEvents_UnwiredAndInvalid pins the clean degrades: an empty
// session_uuid is InvalidArgument; an UNWIRED metering read leg (a test-narrowed handler that
// never received the store) refuses Unavailable rather than silently returning an empty stream.
func TestSessionService_ListMeteringEvents_UnwiredAndInvalid(t *testing.T) {
	// A narrowed handler with NO store wired (meteringRecords nil).
	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)

	if _, err := svc.ListMeteringEvents(context.Background(), ""); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := svc.ListMeteringEvents(context.Background(), "sess-x"); status.Code(err) != codes.Unavailable {
		t.Errorf("unwired metering read leg: code = %v, want Unavailable", status.Code(err))
	}
}

// TestSessionService_CreateTimingServerSpanTrend_UnwiredEmpty proves the read surface degrades
// cleanly when the fold leg is not installed: an empty trend (Count 0), never a panic.
func TestSessionService_CreateTimingServerSpanTrend_UnwiredEmpty(t *testing.T) {
	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	if trend := svc.CreateTimingServerSpanTrend(); trend.Count != 0 {
		t.Errorf("unwired fold leg: server-span trend Count = %d, want 0", trend.Count)
	}
}
