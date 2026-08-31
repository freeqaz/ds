package flowlog

// LOG-4 — Reconciliation: the boundary audits itself. Every byte that left a
// VM interface must be explained by a proxy session or an in-force
// escape-hatch allowance; anything else is a typed ALARM, not a log line.

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// reconcilerHarness wires a Reconciler over static fakes of its neighbors
// (doc 06 §2): kernel flow source, proxy event source, programmable admission
// index, allowance source, and a recording alarm sink.
type reconcilerHarness struct {
	rec    Reconciler
	alarms *recordingAlarmSink
	reg    SessionRegistry
	clock  *fakeClock
	events *recordingSpool // the reconciler's ordinary-event output stream
}

func newReconcilerHarness(t *testing.T, kernel []ConntrackFlow, proxy []Event, idx AdmissionIndex, allow staticAllowances, grace time.Duration) *reconcilerHarness {
	t.Helper()
	clock := newFakeClock(t0)
	alarms := &recordingAlarmSink{}
	reg := NewSessionRegistry()
	events := &recordingSpool{bound: 8 << 20}
	if idx == nil {
		idx = newFakeAdmissionIndex()
	}
	if allow == nil {
		allow = staticAllowances{}
	}
	rec := NewReconciler(ReconcilerConfig{
		Kernel:             staticFlowSource(kernel),
		Proxy:              staticEventSource(proxy),
		Index:              idx,
		Allowances:         allow,
		Registry:           reg,
		Alarms:             alarms,
		Events:             events,
		Grace:              grace,
		ByteToleranceBytes: DefaultByteToleranceBytes,
		Now:                clock.Now,
	})
	return &reconcilerHarness{rec: rec, alarms: alarms, reg: reg, clock: clock, events: events}
}

// settle advances the injected clock past the reconciliation window plus the
// join grace, so a faithful skew-tolerant implementation — one that refuses
// to judge a window that has not yet closed relative to its clock
// (Now < To+Grace, the LOG-4.f rationale) — sees a coherent clock and fails
// only for guardrail reasons.
func (h *reconcilerHarness) settle(w Window, grace time.Duration) {
	h.clock.Advance(w.To.Add(grace + time.Second).Sub(h.clock.Now()))
}

// mkMatchingHTTP builds proxy telemetry whose accounting matches a kernel flow.
func mkMatchingHTTP(ref SessionRef, host string, f ConntrackFlow, at time.Time) HttpEvent {
	ev := validHttpEvent(ref, host, at)
	ev.ReqBytes = f.BytesOrig
	ev.RespBytes = f.BytesReply
	return ev
}

// planRef: doc 09 §7 LOG-4 ("every byte that left a VM interface must be explained")
func TestReconcile_AllExplained_CleanReport(t *testing.T) {
	refA := mkRef("sess-a")
	refB := mkRef("sess-b")

	idx := newFakeAdmissionIndex()
	idx.add(refA, "registry.npmjs.org", netip.MustParseAddr("104.16.0.5"), t0, t0.Add(10*time.Minute))
	idx.add(refB, "github.com", netip.MustParseAddr("140.82.112.3"), t0, t0.Add(10*time.Minute))

	flowA := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "104.16.0.5:443", 4096, 100<<10, t0.Add(time.Second), t0.Add(10*time.Second))
	flowB := ctFlow(0xB002, refB.Iface, "10.40.0.3:50113", "140.82.112.3:443", 8192, 200<<10, t0.Add(2*time.Second), t0.Add(12*time.Second))
	httpA := mkMatchingHTTP(refA, "registry.npmjs.org", flowA, t0.Add(time.Second))
	httpB := mkMatchingHTTP(refB, "github.com", flowB, t0.Add(2*time.Second))

	h := newReconcilerHarness(t, []ConntrackFlow{flowA, flowB}, []Event{httpA, httpB}, idx, nil, 30*time.Second)
	mustRegister(t, h.reg, refA, 0xA001, refA.Iface)
	mustRegister(t, h.reg, refB, 0xB002, refB.Iface)

	w := Window{From: t0, To: t0.Add(time.Minute)}
	h.settle(w, 30*time.Second)
	rep, err := h.rec.Reconcile(bg, w)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(rep.Unexplained) != 0 {
		t.Fatalf("fully proxied window must reconcile to zero unexplained, got %d: %+v", len(rep.Unexplained), rep.Unexplained)
	}
	if len(rep.Explained) != 2 {
		t.Fatalf("want both flows explained, got %d explanations", len(rep.Explained))
	}
	wantRef := map[uint32]SessionRef{0xA001: refA, 0xB002: refB}
	seen := map[uint32]bool{}
	for _, ex := range rep.Explained {
		if ex.Kind != ExplanationProxySession {
			t.Errorf("flow %#x explained by %v, want ExplanationProxySession", ex.Flow.CtMark, ex.Kind)
		}
		if want := wantRef[ex.Flow.CtMark]; ex.Ref != want {
			t.Errorf("flow %#x explained against session %+v, want %+v", ex.Flow.CtMark, ex.Ref, want)
		}
		seen[ex.Flow.CtMark] = true
	}
	if !seen[0xA001] || !seen[0xB002] {
		t.Errorf("every kernel flow must appear in Explained; saw %v", seen)
	}
	if h.alarms.count() != 0 {
		t.Errorf("AlarmSink.Raise called %d times on a clean window, want 0", h.alarms.count())
	}
}

// planRef: doc 09 §7 LOG-4 ("... or an explicit escape-hatch allowance"); §6 POL-5 [ADVERSARIAL]
func TestReconcile_EscapeHatchFlow_ExplainedByAllowance(t *testing.T) {
	refA := mkRef("sess-a")
	refB := mkRef("sess-b")
	// A direct (non-proxied) tcp/22 flow FROM SESSION A.
	flow := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "192.0.2.10:22", 1024, 2048, t0, t0.Add(5*time.Second))

	rows := []struct {
		name          string
		allowance     Allowance
		grantedTo     SessionRef // whose allowance store holds it (defaults to A)
		wantExplained bool
	}{
		{
			name: "live_session_scoped_allowance_port_protocol_match",
			allowance: Allowance{
				ID: "esc-ssh-1", Session: refA, Protocol: ProtoTCP, Port: 22,
				ValidFrom: t0.Add(-time.Hour), ValidUntil: t0.Add(time.Hour),
				Detail: "ops ssh escape hatch",
			},
			wantExplained: true,
		},
		{
			name: "expired_allowance_explains_nothing",
			allowance: Allowance{
				ID: "esc-ssh-2", Session: refA, Protocol: ProtoTCP, Port: 22,
				ValidFrom: t0.Add(-time.Hour), ValidUntil: t0.Add(-10 * time.Minute),
				Detail: "expired",
			},
			wantExplained: false,
		},
		{
			name: "port_mismatch_allowance_explains_nothing",
			allowance: Allowance{
				ID: "esc-alt-1", Session: refA, Protocol: ProtoTCP, Port: 2222,
				ValidFrom: t0.Add(-time.Hour), ValidUntil: t0.Add(time.Hour),
				Detail: "different port",
			},
			wantExplained: false,
		},
		{
			name: "other_sessions_allowance_explains_nothing_session_scope_enforced",
			// The ONLY allowance in force belongs to session B (live, port and
			// protocol matching): A's direct flow must NOT borrow it.
			allowance: Allowance{
				ID: "esc-ssh-b", Session: refB, Protocol: ProtoTCP, Port: 22,
				ValidFrom: t0.Add(-time.Hour), ValidUntil: t0.Add(time.Hour),
				Detail: "session B's ssh escape hatch",
			},
			grantedTo:     refB,
			wantExplained: false,
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			owner := row.grantedTo
			if owner.SessionID == "" {
				owner = refA
			}
			h := newReconcilerHarness(t, []ConntrackFlow{flow}, nil, nil,
				staticAllowances{owner.SessionID: {row.allowance}}, 30*time.Second)
			mustRegister(t, h.reg, refA, 0xA001, refA.Iface)
			mustRegister(t, h.reg, refB, 0xB002, refB.Iface)

			w := Window{From: t0, To: t0.Add(time.Minute)}
			h.settle(w, 30*time.Second)
			rep, err := h.rec.Reconcile(bg, w)
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			if row.wantExplained {
				if len(rep.Unexplained) != 0 {
					t.Fatalf("flow with a live matching allowance must be explained, got unexplained: %+v", rep.Unexplained)
				}
				if len(rep.Explained) != 1 {
					t.Fatalf("want exactly one explanation, got %d", len(rep.Explained))
				}
				ex := rep.Explained[0]
				if ex.Kind != ExplanationEscapeHatch {
					t.Errorf("explanation kind %v, want ExplanationEscapeHatch", ex.Kind)
				}
				if ex.Ref != refA {
					t.Errorf("explanation cites session %+v, want A", ex.Ref)
				}
				if !strings.Contains(ex.Detail, row.allowance.ID) {
					t.Errorf("explanation must cite the allowance (%q), got detail %q", row.allowance.ID, ex.Detail)
				}
				if h.alarms.count() != 0 {
					t.Errorf("allowance-explained flow must not alarm, got %d raises", h.alarms.count())
				}
				return
			}

			if len(rep.Unexplained) != 1 || rep.Unexplained[0] != flow {
				t.Fatalf("an expired or mismatched allowance explains nothing; want the flow unexplained, report: %+v", rep)
			}
			alarms := h.alarms.all()
			if len(alarms) != 1 {
				t.Fatalf("unexplained direct flow must raise exactly one alarm, got %d", len(alarms))
			}
			if alarms[0].Kind != AlarmUnexplainedFlow {
				t.Errorf("alarm kind %v, want AlarmUnexplainedFlow", alarms[0].Kind)
			}
		})
	}
}

// planRef: doc 09 §7 LOG-4 Done-when ("a deliberately mis-ruled test host trips the alarm"); §8 Stage 4 exit; doc 06 §3(c) [ADVERSARIAL]
func TestReconcile_MisRuledHost_UnexplainedFlowRaisesAlarm(t *testing.T) {
	refA := mkRef("sess-a")
	// The redirect hole: a kernel flow from A's iface straight to the
	// internet with NO corresponding proxy event and no allowance.
	hole := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "203.0.113.7:443", 9<<10, 120<<10, t0.Add(time.Second), t0.Add(4*time.Second))

	h := newReconcilerHarness(t, []ConntrackFlow{hole}, nil, nil, nil, 30*time.Second)
	mustRegister(t, h.reg, refA, 0xA001, refA.Iface)

	w := Window{From: t0, To: t0.Add(time.Minute)}
	h.settle(w, 30*time.Second)
	rep, err := h.rec.Reconcile(bg, w)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	alarms := h.alarms.all()
	if len(alarms) != 1 {
		t.Fatalf("a redirect hole is an ALARM, not a log line: want exactly 1 Raise, got %d", len(alarms))
	}
	a := alarms[0]
	if a.Kind != AlarmUnexplainedFlow {
		t.Errorf("alarm kind %v, want AlarmUnexplainedFlow", a.Kind)
	}
	if a.Session == nil || *a.Session != refA {
		t.Errorf("alarm must attribute the hole to session A, got %+v", a.Session)
	}
	if a.Flow != hole {
		t.Errorf("alarm must carry the escaping flow, got %+v", a.Flow)
	}
	if len(rep.Unexplained) != 1 || rep.Unexplained[0] != hole {
		t.Errorf("report must list the flow as Unexplained, got %+v", rep.Unexplained)
	}
	// The escaped flow must NOT be laundered into the ordinary accepted
	// story: no Explanation may exist for it, and the ordinary-event output
	// stream must not carry it as an accepted FlowRecord.
	if len(rep.Explained) != 0 {
		t.Errorf("escaped flow must not appear as an ordinary explained/accepted FlowRecord without the alarm: %+v", rep.Explained)
	}
	for _, ev := range h.events.all() {
		if fr, ok := ev.(FlowRecord); ok && fr.Dst == hole.Dst && fr.Verdict == FlowAccepted {
			t.Errorf("escaped flow shipped as an ordinary accepted FlowRecord in the story stream: %+v", fr)
		}
	}
}

// planRef: doc 09 §7 LOG-4 ("every BYTE ... must be explained" — accounting, not just flow existence) [ADVERSARIAL]
func TestReconcile_KernelProxyByteMismatch_Alarms(t *testing.T) {
	// The tolerance is a named constant this test pins.
	if DefaultByteToleranceBytes != 1<<20 {
		t.Fatalf("DefaultByteToleranceBytes drifted from the pinned 1 MiB: %d", DefaultByteToleranceBytes)
	}

	refA := mkRef("sess-a")
	idx := newFakeAdmissionIndex()
	idx.add(refA, "github.com", netip.MustParseAddr("140.82.112.3"), t0, t0.Add(10*time.Minute))

	t.Run("smuggled_bytes_beyond_tolerance_alarm", func(t *testing.T) {
		// Kernel sees 50 MiB egress; the matching proxy session accounts 1 MiB.
		kernel := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "140.82.112.3:443", 50<<20, 2048, t0.Add(time.Second), t0.Add(10*time.Second))
		proxy := validHttpEvent(refA, "github.com", t0.Add(time.Second))
		proxy.ReqBytes = 1 << 20
		proxy.RespBytes = 2048

		h := newReconcilerHarness(t, []ConntrackFlow{kernel}, []Event{proxy}, idx, nil, 30*time.Second)
		mustRegister(t, h.reg, refA, 0xA001, refA.Iface)

		w := Window{From: t0, To: t0.Add(time.Minute)}
		h.settle(w, 30*time.Second)
		if _, err := h.rec.Reconcile(bg, w); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		alarms := h.alarms.all()
		if len(alarms) != 1 {
			t.Fatalf("byte smuggling past proxy accounting must raise exactly one alarm, got %d", len(alarms))
		}
		a := alarms[0]
		if a.Kind != AlarmByteMismatch {
			t.Errorf("alarm kind %v, want AlarmByteMismatch", a.Kind)
		}
		if !strings.Contains(a.Detail, fmt.Sprintf("%d", uint64(50<<20))) || !strings.Contains(a.Detail, fmt.Sprintf("%d", uint64(1<<20))) {
			t.Errorf("alarm must carry both byte counts (kernel %d, proxy %d), got detail %q", uint64(50<<20), uint64(1<<20), a.Detail)
		}
	})

	t.Run("within_tolerance_reconciles_clean", func(t *testing.T) {
		kernel := ctFlow(0xA001, refA.Iface, "10.40.0.2:50113", "140.82.112.3:443",
			(1<<20)+(DefaultByteToleranceBytes/2), 2048, t0.Add(time.Second), t0.Add(10*time.Second))
		proxy := validHttpEvent(refA, "github.com", t0.Add(time.Second))
		proxy.ReqBytes = 1 << 20
		proxy.RespBytes = 2048

		h := newReconcilerHarness(t, []ConntrackFlow{kernel}, []Event{proxy}, idx, nil, 30*time.Second)
		mustRegister(t, h.reg, refA, 0xA001, refA.Iface)

		w := Window{From: t0, To: t0.Add(time.Minute)}
		h.settle(w, 30*time.Second)
		rep, err := h.rec.Reconcile(bg, w)
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if h.alarms.count() != 0 {
			t.Fatalf("within-tolerance accounting must not alarm, got %d raises", h.alarms.count())
		}
		if len(rep.Unexplained) != 0 || len(rep.Explained) != 1 {
			t.Errorf("control flow must reconcile clean, report: %+v", rep)
		}
	})
}

// planRef: doc 09 §7 LOG-4 ("an unexplained flow is an alarm, not a log line") [ADVERSARIAL]
func TestReconcile_AlarmPathSurvivesSpoolPressure(t *testing.T) {
	refA := mkRef("sess-a")
	grace := 30 * time.Second

	// Drive the ordinary-event spool to its bound: shedding active (LOG-3.a).
	spool := NewSpool(t.TempDir(), 64<<10)
	pad := strings.Repeat("x", 4096)
	for i := 0; i < 64; i++ {
		ev := validFlowRecord(refA, uint32(i), t0.Add(time.Duration(i)*time.Millisecond))
		ev.AdmittingDomain = pad
		mustAppend(t, spool, ev)
	}
	if u, b := spool.UsageBytes(), spool.BoundBytes(); u > b {
		t.Fatalf("spool bound violated while creating pressure: %d > %d", u, b)
	}
	if spool.UsageBytes() == 0 {
		t.Fatalf("spool pressure not established (UsageBytes() == 0)")
	}

	// An unexplained flow enters a reconciliation whose ordinary-event output
	// rides the SAME at-bound spool — the load-shedding that drops ordinary
	// events shares state with this reconciliation; the alarm path must not.
	hole := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "203.0.113.7:443", 4096, 4096, t0.Add(time.Second), t0.Add(2*time.Second))
	clock := newFakeClock(t0)
	alarms := &recordingAlarmSink{}
	reg := NewSessionRegistry()
	rec := NewReconciler(ReconcilerConfig{
		Kernel:             staticFlowSource{hole},
		Proxy:              staticEventSource(nil),
		Index:              newFakeAdmissionIndex(),
		Allowances:         staticAllowances{},
		Registry:           reg,
		Alarms:             alarms,
		Events:             spool, // the pressured, shedding spool itself
		Grace:              grace,
		ByteToleranceBytes: DefaultByteToleranceBytes,
		Now:                clock.Now,
	})
	mustRegister(t, reg, refA, 0xA001, refA.Iface)

	w := Window{From: t0, To: t0.Add(time.Minute)}
	clock.Advance(w.To.Add(grace + time.Second).Sub(clock.Now()))
	if _, err := rec.Reconcile(bg, w); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The alarm channel is distinct from the Event spool: Raise was invoked
	// and succeeded despite drop-oldest shedding of ordinary events.
	got := alarms.all()
	if len(got) != 1 {
		t.Fatalf("alarm delivery suppressed under spool pressure: want 1 Raise, got %d", len(got))
	}
	if got[0].Kind != AlarmUnexplainedFlow {
		t.Errorf("alarm kind %v, want AlarmUnexplainedFlow", got[0].Kind)
	}

	// The alarm was not demoted into (nor displaced out of) the droppable
	// spool stream: drain the spool and assert the unexplained flow never
	// appears as an ordinary record in the surviving, sheddable stream.
	for {
		batch, ack, err := spool.ReadBatch(bg, 256)
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		if len(batch) == 0 {
			break
		}
		for _, ev := range batch {
			if fr, ok := ev.(FlowRecord); ok && fr.Dst == hole.Dst {
				t.Errorf("the unexplained flow rode the droppable spool stream as an ordinary record (subject to shedding): %+v", fr)
			}
		}
		if ack == nil {
			t.Fatalf("ReadBatch returned nil ack")
		}
		if err := ack(); err != nil {
			t.Fatalf("ack: %v", err)
		}
	}
}

// planRef: doc 09 §7 LOG-4 (continuous reconciliation must be operable; alarm fatigue would un-prove the guardrail)
func TestReconcile_LateProxyEventWithinGrace_NoFalseAlarm(t *testing.T) {
	refA := mkRef("sess-a")
	grace := 30 * time.Second

	idx := newFakeAdmissionIndex()
	idx.add(refA, "github.com", netip.MustParseAddr("140.82.112.3"), t0, t0.Add(10*time.Minute))

	flow := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "140.82.112.3:443", 4096, 8192, t0.Add(time.Second), t0.Add(5*time.Second))

	t.Run("late_but_within_grace_reconciles_clean", func(t *testing.T) {
		// Matching proxy event arrives at flow-end + grace/2: in-window skew.
		proxy := mkMatchingHTTP(refA, "github.com", flow, flow.End.Add(grace/2))
		h := newReconcilerHarness(t, []ConntrackFlow{flow}, []Event{proxy}, idx, nil, grace)
		mustRegister(t, h.reg, refA, 0xA001, refA.Iface)

		w := Window{From: t0, To: t0.Add(2 * time.Minute)}
		h.settle(w, grace)
		rep, err := h.rec.Reconcile(bg, w)
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if h.alarms.count() != 0 {
			t.Fatalf("event-arrival skew inside the grace window produced a false alarm (%d raises)", h.alarms.count())
		}
		if len(rep.Unexplained) != 0 || len(rep.Explained) != 1 {
			t.Errorf("in-grace pair must reconcile clean, report: %+v", rep)
		}
	})

	t.Run("beyond_grace_alarms_window_is_bounded", func(t *testing.T) {
		// The proxy event arrives after the grace window closes: the window
		// is bounded, not infinitely forgiving.
		proxy := mkMatchingHTTP(refA, "github.com", flow, flow.End.Add(grace+30*time.Second))
		h := newReconcilerHarness(t, []ConntrackFlow{flow}, []Event{proxy}, idx, nil, grace)
		mustRegister(t, h.reg, refA, 0xA001, refA.Iface)

		w := Window{From: t0, To: t0.Add(2 * time.Minute)}
		h.settle(w, grace)
		rep, err := h.rec.Reconcile(bg, w)
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		alarms := h.alarms.all()
		if len(alarms) != 1 {
			t.Fatalf("a proxy event beyond the grace window explains nothing: want 1 alarm, got %d", len(alarms))
		}
		if alarms[0].Kind != AlarmUnexplainedFlow {
			t.Errorf("alarm kind %v, want AlarmUnexplainedFlow", alarms[0].Kind)
		}
		if len(rep.Unexplained) != 1 {
			t.Errorf("flow must be reported Unexplained, got %+v", rep)
		}
	})
}

// planRef: doc 09 §7 LOG-4 + §3 NFT-6 teardown hygiene; doc 06 §3(b) clean-teardown row [ADVERSARIAL]
func TestReconcile_FlowAfterSessionTeardown_Alarms(t *testing.T) {
	refA := mkRef("sess-a")
	t1 := t0.Add(2 * time.Minute)

	// Traffic on A's retired attribution keys, 10s after teardown.
	post := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "104.16.0.5:443", 4096, 8192, t1.Add(10*time.Second), t1.Add(30*time.Second))

	h := newReconcilerHarness(t, []ConntrackFlow{post}, nil, nil, nil, 30*time.Second)
	mustRegister(t, h.reg, refA, 0xA001, refA.Iface)
	mustRetire(t, h.reg, refA, t1)

	w := Window{From: t1, To: t1.Add(time.Minute)}
	h.settle(w, 30*time.Second)
	rep, err := h.rec.Reconcile(bg, w)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	alarms := h.alarms.all()
	if len(alarms) != 1 {
		t.Fatalf("traffic on retired attribution keys is a hole: want exactly 1 alarm, got %d", len(alarms))
	}
	a := alarms[0]
	if a.Kind != AlarmPostTeardownFlow {
		t.Errorf("alarm kind %v, want AlarmPostTeardownFlow", a.Kind)
	}
	if a.Session == nil || *a.Session != refA {
		t.Errorf("post-teardown alarm must name the retired session A, got %+v", a.Session)
	}
	// Never silently attributed to the dead session as an ordinary record.
	if len(rep.Explained) != 0 {
		t.Errorf("post-teardown flow must not be appended to A's normal shipped story: %+v", rep.Explained)
	}
	for _, ev := range h.events.all() {
		if fr, ok := ev.(FlowRecord); ok && fr.Dst == post.Dst {
			t.Errorf("post-teardown flow rode the ordinary story stream as a FlowRecord: %+v", fr)
		}
	}
	if len(rep.Unexplained) != 1 || rep.Unexplained[0] != post {
		t.Errorf("post-teardown flow must be reported, got %+v", rep.Unexplained)
	}
}
