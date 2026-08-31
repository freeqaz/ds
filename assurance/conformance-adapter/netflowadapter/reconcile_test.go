// SPDX-License-Identifier: Apache-2.0

package netflowadapter

// reconcile_test.go — conformance assertions for the LOG-4 reconciler, proving
// the adapter's real Reconciler satisfies what boundary/flowlog/
// flowlog_reconcile_test.go asserts (the boundary suite stays RED against its
// in-package stub by design, D26). Every byte that left a VM interface must be
// explained by a proxy session or an in-force escape-hatch allowance; anything
// else is a typed ALARM, not a log line.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	flowlog "github.com/dream-serpent/dream-serpent/boundary/flowlog"
)

// ───────────────────────────────────────────────────────────────────────────
// recording neighbors (mirrored from boundary/flowlog/fakes_test.go)
// ───────────────────────────────────────────────────────────────────────────

type recAlarmSink struct {
	mu     sync.Mutex
	alarms []flowlog.Alarm
}

func (r *recAlarmSink) Raise(_ context.Context, a flowlog.Alarm) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alarms = append(r.alarms, a)
	return nil
}
func (r *recAlarmSink) all() []flowlog.Alarm {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]flowlog.Alarm(nil), r.alarms...)
}
func (r *recAlarmSink) count() int { return len(r.all()) }

type recSpool struct {
	mu     sync.Mutex
	events []flowlog.Event
	bound  int64
}

func (s *recSpool) Append(_ context.Context, ev flowlog.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}
func (s *recSpool) ReadBatch(_ context.Context, max int) ([]flowlog.Event, func() error, error) {
	return nil, func() error { return nil }, nil
}
func (s *recSpool) UsageBytes() int64 { return int64(len(s.all())) }
func (s *recSpool) BoundBytes() int64 { return s.bound }
func (s *recSpool) all() []flowlog.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]flowlog.Event(nil), s.events...)
}

type staticFlowSource []flowlog.ConntrackFlow

func (s staticFlowSource) Flows(_ context.Context, _ flowlog.Window) ([]flowlog.ConntrackFlow, error) {
	return append([]flowlog.ConntrackFlow(nil), s...), nil
}

type staticEventSource []flowlog.Event

func (s staticEventSource) Events(_ context.Context, _ flowlog.Window) ([]flowlog.Event, error) {
	return append([]flowlog.Event(nil), s...), nil
}

type staticAllowances map[string][]flowlog.Allowance

func (s staticAllowances) Allowances(_ context.Context, ref flowlog.SessionRef, _ time.Time) ([]flowlog.Allowance, error) {
	return append([]flowlog.Allowance(nil), s[ref.SessionID]...), nil
}

// ───────────────────────────────────────────────────────────────────────────
// reconciler harness
// ───────────────────────────────────────────────────────────────────────────

type recHarness struct {
	rec    flowlog.Reconciler
	alarms *recAlarmSink
	reg    flowlog.SessionRegistry
	events *recSpool
	now    *time.Time
}

func newRecHarness(t *testing.T, kernel []flowlog.ConntrackFlow, proxy []flowlog.Event, idx flowlog.AdmissionIndex, allow staticAllowances, grace time.Duration) *recHarness {
	t.Helper()
	now := t0
	alarms := &recAlarmSink{}
	reg := NewSessionRegistry()
	events := &recSpool{bound: 8 << 20}
	if idx == nil {
		idx = NewAdmissionIndex()
	}
	if allow == nil {
		allow = staticAllowances{}
	}
	h := &recHarness{alarms: alarms, reg: reg, events: events, now: &now}
	h.rec = NewReconciler(flowlog.ReconcilerConfig{
		Kernel:             staticFlowSource(kernel),
		Proxy:              staticEventSource(proxy),
		Index:              idx,
		Allowances:         allow,
		Registry:           reg,
		Alarms:             alarms,
		Events:             events,
		Grace:              grace,
		ByteToleranceBytes: flowlog.DefaultByteToleranceBytes,
		Now:                func() time.Time { return *h.now },
	})
	return h
}

func (h *recHarness) settle(w flowlog.Window, grace time.Duration) {
	*h.now = w.To.Add(grace + time.Second)
}

func ctFlow(mark uint32, iif, src, dst string, bytesOut, bytesIn uint64, start, end time.Time) flowlog.ConntrackFlow {
	return flowlog.ConntrackFlow{
		CtMark: mark, Iif: iif,
		Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst),
		Protocol: flowlog.ProtoTCP, BytesOrig: bytesOut, BytesReply: bytesIn, Packets: 10,
		Start: start, End: end,
	}
}

func mustReg(t *testing.T, reg flowlog.SessionRegistry, ref flowlog.SessionRef, mark uint32) {
	t.Helper()
	if err := reg.RegisterSession(bg, ref, mark, ref.Iface); err != nil {
		t.Fatalf("RegisterSession(%s): %v", ref.SessionID, err)
	}
}

func mkMatchingHTTP(ref flowlog.SessionRef, host string, f flowlog.ConntrackFlow, at time.Time) flowlog.HttpEvent {
	ev := schemaValidHTTP(ref, host, at)
	ev.ReqBytes = f.BytesOrig
	ev.RespBytes = f.BytesReply
	return ev
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-4 tests
// ───────────────────────────────────────────────────────────────────────────

func TestReconcile_AllExplained_CleanReport(t *testing.T) {
	refA, refB := mkRef("sess-a"), mkRef("sess-b")
	idx := NewAdmissionIndex()
	mustObserveIdx(t, idx, refA, "registry.npmjs.org", "104.16.0.5", t0, t0.Add(10*time.Minute))
	mustObserveIdx(t, idx, refB, "github.com", "140.82.112.3", t0, t0.Add(10*time.Minute))

	flowA := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "104.16.0.5:443", 4096, 100<<10, t0.Add(time.Second), t0.Add(10*time.Second))
	flowB := ctFlow(0xB002, refB.Iface, "10.40.0.3:50113", "140.82.112.3:443", 8192, 200<<10, t0.Add(2*time.Second), t0.Add(12*time.Second))
	httpA := mkMatchingHTTP(refA, "registry.npmjs.org", flowA, t0.Add(time.Second))
	httpB := mkMatchingHTTP(refB, "github.com", flowB, t0.Add(2*time.Second))

	h := newRecHarness(t, []flowlog.ConntrackFlow{flowA, flowB}, []flowlog.Event{httpA, httpB}, idx, nil, 30*time.Second)
	mustReg(t, h.reg, refA, 0xA001)
	mustReg(t, h.reg, refB, 0xB002)

	w := flowlog.Window{From: t0, To: t0.Add(time.Minute)}
	h.settle(w, 30*time.Second)
	rep, err := h.rec.Reconcile(bg, w)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(rep.Unexplained) != 0 {
		t.Fatalf("fully proxied window must reconcile to zero unexplained, got %+v", rep.Unexplained)
	}
	if len(rep.Explained) != 2 {
		t.Fatalf("want both flows explained, got %d", len(rep.Explained))
	}
	wantRef := map[uint32]flowlog.SessionRef{0xA001: refA, 0xB002: refB}
	for _, ex := range rep.Explained {
		if ex.Kind != flowlog.ExplanationProxySession {
			t.Errorf("flow %#x explained by %v, want ExplanationProxySession", ex.Flow.CtMark, ex.Kind)
		}
		if want := wantRef[ex.Flow.CtMark]; ex.Ref != want {
			t.Errorf("flow %#x explained against %+v, want %+v", ex.Flow.CtMark, ex.Ref, want)
		}
	}
	if h.alarms.count() != 0 {
		t.Errorf("clean window raised %d alarms, want 0", h.alarms.count())
	}
}

func TestReconcile_EscapeHatchFlow_ExplainedByAllowance(t *testing.T) {
	refA, refB := mkRef("sess-a"), mkRef("sess-b")
	flow := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "192.0.2.10:22", 1024, 2048, t0, t0.Add(5*time.Second))

	rows := []struct {
		name          string
		allowance     flowlog.Allowance
		grantedTo     flowlog.SessionRef
		wantExplained bool
	}{
		{"live_match", flowlog.Allowance{ID: "esc-ssh-1", Session: refA, Protocol: flowlog.ProtoTCP, Port: 22, ValidFrom: t0.Add(-time.Hour), ValidUntil: t0.Add(time.Hour)}, flowlog.SessionRef{}, true},
		{"expired", flowlog.Allowance{ID: "esc-ssh-2", Session: refA, Protocol: flowlog.ProtoTCP, Port: 22, ValidFrom: t0.Add(-time.Hour), ValidUntil: t0.Add(-10 * time.Minute)}, flowlog.SessionRef{}, false},
		{"port_mismatch", flowlog.Allowance{ID: "esc-alt-1", Session: refA, Protocol: flowlog.ProtoTCP, Port: 2222, ValidFrom: t0.Add(-time.Hour), ValidUntil: t0.Add(time.Hour)}, flowlog.SessionRef{}, false},
		{"other_session_scope_enforced", flowlog.Allowance{ID: "esc-ssh-b", Session: refB, Protocol: flowlog.ProtoTCP, Port: 22, ValidFrom: t0.Add(-time.Hour), ValidUntil: t0.Add(time.Hour)}, refB, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			owner := row.grantedTo
			if owner.SessionID == "" {
				owner = refA
			}
			h := newRecHarness(t, []flowlog.ConntrackFlow{flow}, nil, nil,
				staticAllowances{owner.SessionID: {row.allowance}}, 30*time.Second)
			mustReg(t, h.reg, refA, 0xA001)
			mustReg(t, h.reg, refB, 0xB002)

			w := flowlog.Window{From: t0, To: t0.Add(time.Minute)}
			h.settle(w, 30*time.Second)
			rep, err := h.rec.Reconcile(bg, w)
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if row.wantExplained {
				if len(rep.Explained) != 1 || len(rep.Unexplained) != 0 {
					t.Fatalf("live matching allowance must explain the flow, report: %+v", rep)
				}
				ex := rep.Explained[0]
				if ex.Kind != flowlog.ExplanationEscapeHatch {
					t.Errorf("kind %v, want ExplanationEscapeHatch", ex.Kind)
				}
				if ex.Ref != refA {
					t.Errorf("cites %+v, want A", ex.Ref)
				}
				if !strings.Contains(ex.Detail, row.allowance.ID) {
					t.Errorf("must cite allowance %q, got %q", row.allowance.ID, ex.Detail)
				}
				if h.alarms.count() != 0 {
					t.Errorf("explained flow must not alarm, got %d", h.alarms.count())
				}
				return
			}
			if len(rep.Unexplained) != 1 || rep.Unexplained[0] != flow {
				t.Fatalf("expired/mismatched allowance explains nothing, report: %+v", rep)
			}
			alarms := h.alarms.all()
			if len(alarms) != 1 || alarms[0].Kind != flowlog.AlarmUnexplainedFlow {
				t.Fatalf("unexplained direct flow must raise one AlarmUnexplainedFlow, got %+v", alarms)
			}
		})
	}
}

func TestReconcile_MisRuledHost_UnexplainedFlowRaisesAlarm(t *testing.T) {
	refA := mkRef("sess-a")
	hole := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "203.0.113.7:443", 9<<10, 120<<10, t0.Add(time.Second), t0.Add(4*time.Second))

	h := newRecHarness(t, []flowlog.ConntrackFlow{hole}, nil, nil, nil, 30*time.Second)
	mustReg(t, h.reg, refA, 0xA001)

	w := flowlog.Window{From: t0, To: t0.Add(time.Minute)}
	h.settle(w, 30*time.Second)
	rep, err := h.rec.Reconcile(bg, w)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	alarms := h.alarms.all()
	if len(alarms) != 1 {
		t.Fatalf("a redirect hole is an ALARM not a log line: want 1, got %d", len(alarms))
	}
	a := alarms[0]
	if a.Kind != flowlog.AlarmUnexplainedFlow {
		t.Errorf("kind %v, want AlarmUnexplainedFlow", a.Kind)
	}
	if a.Session == nil || *a.Session != refA {
		t.Errorf("alarm must attribute the hole to A, got %+v", a.Session)
	}
	if a.Flow != hole {
		t.Errorf("alarm must carry the escaping flow")
	}
	if len(rep.Explained) != 0 {
		t.Errorf("escaped flow must not appear explained: %+v", rep.Explained)
	}
	for _, ev := range h.events.all() {
		if fr, ok := ev.(flowlog.FlowRecord); ok && fr.Dst == hole.Dst && fr.Verdict == flowlog.FlowAccepted {
			t.Errorf("escaped flow shipped as ordinary accepted record: %+v", fr)
		}
	}
}

func TestReconcile_KernelProxyByteMismatch_Alarms(t *testing.T) {
	if flowlog.DefaultByteToleranceBytes != 1<<20 {
		t.Fatalf("DefaultByteToleranceBytes drifted: %d", flowlog.DefaultByteToleranceBytes)
	}
	refA := mkRef("sess-a")
	idx := NewAdmissionIndex()
	mustObserveIdx(t, idx, refA, "github.com", "140.82.112.3", t0, t0.Add(10*time.Minute))

	t.Run("smuggled_beyond_tolerance_alarm", func(t *testing.T) {
		kernel := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "140.82.112.3:443", 50<<20, 2048, t0.Add(time.Second), t0.Add(10*time.Second))
		proxy := schemaValidHTTP(refA, "github.com", t0.Add(time.Second))
		proxy.ReqBytes = 1 << 20
		proxy.RespBytes = 2048

		h := newRecHarness(t, []flowlog.ConntrackFlow{kernel}, []flowlog.Event{proxy}, idx, nil, 30*time.Second)
		mustReg(t, h.reg, refA, 0xA001)
		w := flowlog.Window{From: t0, To: t0.Add(time.Minute)}
		h.settle(w, 30*time.Second)
		if _, err := h.rec.Reconcile(bg, w); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		alarms := h.alarms.all()
		if len(alarms) != 1 {
			t.Fatalf("byte smuggling must raise one alarm, got %d", len(alarms))
		}
		a := alarms[0]
		if a.Kind != flowlog.AlarmByteMismatch {
			t.Errorf("kind %v, want AlarmByteMismatch", a.Kind)
		}
		kernelTotal := uint64(50<<20) + 2048
		if !strings.Contains(a.Detail, fmt.Sprintf("%d", kernelTotal)) || !strings.Contains(a.Detail, fmt.Sprintf("%d", uint64(1<<20)+2048)) {
			t.Errorf("alarm must carry both byte counts, got %q", a.Detail)
		}
	})

	t.Run("within_tolerance_clean", func(t *testing.T) {
		kernel := ctFlow(0xA001, refA.Iface, "10.40.0.2:50113", "140.82.112.3:443",
			(1<<20)+(flowlog.DefaultByteToleranceBytes/2), 2048, t0.Add(time.Second), t0.Add(10*time.Second))
		proxy := schemaValidHTTP(refA, "github.com", t0.Add(time.Second))
		proxy.ReqBytes = 1 << 20
		proxy.RespBytes = 2048

		h := newRecHarness(t, []flowlog.ConntrackFlow{kernel}, []flowlog.Event{proxy}, idx, nil, 30*time.Second)
		mustReg(t, h.reg, refA, 0xA001)
		w := flowlog.Window{From: t0, To: t0.Add(time.Minute)}
		h.settle(w, 30*time.Second)
		rep, err := h.rec.Reconcile(bg, w)
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if h.alarms.count() != 0 {
			t.Fatalf("within-tolerance must not alarm, got %d", h.alarms.count())
		}
		if len(rep.Unexplained) != 0 || len(rep.Explained) != 1 {
			t.Errorf("control flow must reconcile clean: %+v", rep)
		}
	})
}

func TestReconcile_LateProxyEventWithinGrace_NoFalseAlarm(t *testing.T) {
	refA := mkRef("sess-a")
	grace := 30 * time.Second
	idx := NewAdmissionIndex()
	mustObserveIdx(t, idx, refA, "github.com", "140.82.112.3", t0, t0.Add(10*time.Minute))
	flow := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "140.82.112.3:443", 4096, 8192, t0.Add(time.Second), t0.Add(5*time.Second))

	t.Run("within_grace_clean", func(t *testing.T) {
		proxy := mkMatchingHTTP(refA, "github.com", flow, flow.End.Add(grace/2))
		h := newRecHarness(t, []flowlog.ConntrackFlow{flow}, []flowlog.Event{proxy}, idx, nil, grace)
		mustReg(t, h.reg, refA, 0xA001)
		w := flowlog.Window{From: t0, To: t0.Add(2 * time.Minute)}
		h.settle(w, grace)
		rep, err := h.rec.Reconcile(bg, w)
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if h.alarms.count() != 0 {
			t.Fatalf("in-grace skew produced a false alarm (%d)", h.alarms.count())
		}
		if len(rep.Unexplained) != 0 || len(rep.Explained) != 1 {
			t.Errorf("in-grace pair must reconcile clean: %+v", rep)
		}
	})

	t.Run("beyond_grace_alarms", func(t *testing.T) {
		proxy := mkMatchingHTTP(refA, "github.com", flow, flow.End.Add(grace+30*time.Second))
		h := newRecHarness(t, []flowlog.ConntrackFlow{flow}, []flowlog.Event{proxy}, idx, nil, grace)
		mustReg(t, h.reg, refA, 0xA001)
		w := flowlog.Window{From: t0, To: t0.Add(2 * time.Minute)}
		h.settle(w, grace)
		rep, err := h.rec.Reconcile(bg, w)
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		alarms := h.alarms.all()
		if len(alarms) != 1 || alarms[0].Kind != flowlog.AlarmUnexplainedFlow {
			t.Fatalf("beyond-grace event explains nothing: want 1 AlarmUnexplainedFlow, got %+v", alarms)
		}
		if len(rep.Unexplained) != 1 {
			t.Errorf("flow must be Unexplained: %+v", rep)
		}
	})
}

func TestReconcile_FlowAfterSessionTeardown_Alarms(t *testing.T) {
	refA := mkRef("sess-a")
	t1 := t0.Add(2 * time.Minute)
	post := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "104.16.0.5:443", 4096, 8192, t1.Add(10*time.Second), t1.Add(30*time.Second))

	h := newRecHarness(t, []flowlog.ConntrackFlow{post}, nil, nil, nil, 30*time.Second)
	mustReg(t, h.reg, refA, 0xA001)
	if err := h.reg.RetireSession(bg, refA, t1); err != nil {
		t.Fatalf("RetireSession: %v", err)
	}

	w := flowlog.Window{From: t1, To: t1.Add(time.Minute)}
	h.settle(w, 30*time.Second)
	rep, err := h.rec.Reconcile(bg, w)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	alarms := h.alarms.all()
	if len(alarms) != 1 {
		t.Fatalf("traffic on retired keys is a hole: want 1 alarm, got %d", len(alarms))
	}
	a := alarms[0]
	if a.Kind != flowlog.AlarmPostTeardownFlow {
		t.Errorf("kind %v, want AlarmPostTeardownFlow", a.Kind)
	}
	if a.Session == nil || *a.Session != refA {
		t.Errorf("post-teardown alarm must name A, got %+v", a.Session)
	}
	if len(rep.Explained) != 0 {
		t.Errorf("post-teardown flow must not be explained: %+v", rep.Explained)
	}
	for _, ev := range h.events.all() {
		if fr, ok := ev.(flowlog.FlowRecord); ok && fr.Dst == post.Dst {
			t.Errorf("post-teardown flow rode the ordinary stream: %+v", fr)
		}
	}
	if len(rep.Unexplained) != 1 || rep.Unexplained[0] != post {
		t.Errorf("post-teardown flow must be reported: %+v", rep.Unexplained)
	}
}

// TestReconcile_AlarmPathSurvivesSpoolPressure proves the alarm channel is
// DISTINCT from the droppable Events spool: an unexplained flow's alarm is
// raised through the AlarmSink even while the Events spool is at its bound and
// shedding, and the unexplained flow never rides the ordinary stream.
func TestReconcile_AlarmPathSurvivesSpoolPressure(t *testing.T) {
	refA := mkRef("sess-a")
	grace := 30 * time.Second

	// Drive the ordinary-event spool to its bound: shedding active.
	pressured := NewSpool(64 << 10)
	pad := strings.Repeat("x", 4096)
	for i := 0; i < 64; i++ {
		ev := schemaValidFlow(refA, uint32(i), t0.Add(time.Duration(i)*time.Millisecond))
		ev.AdmittingDomain = pad
		if err := pressured.Append(bg, ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if u, b := pressured.UsageBytes(), pressured.BoundBytes(); u > b {
		t.Fatalf("spool bound violated: %d > %d", u, b)
	}

	hole := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "203.0.113.7:443", 4096, 4096, t0.Add(time.Second), t0.Add(2*time.Second))
	alarms := &recAlarmSink{}
	reg := NewSessionRegistry()
	now := t0.Add(time.Minute).Add(grace + time.Second)
	rec := NewReconciler(flowlog.ReconcilerConfig{
		Kernel:             staticFlowSource{hole},
		Proxy:              staticEventSource(nil),
		Index:              NewAdmissionIndex(),
		Allowances:         staticAllowances{},
		Registry:           reg,
		Alarms:             alarms,
		Events:             pressured, // the pressured, shedding spool itself
		Grace:              grace,
		ByteToleranceBytes: flowlog.DefaultByteToleranceBytes,
		Now:                func() time.Time { return now },
	})
	mustReg(t, reg, refA, 0xA001)

	w := flowlog.Window{From: t0, To: t0.Add(time.Minute)}
	if _, err := rec.Reconcile(bg, w); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := alarms.all()
	if len(got) != 1 {
		t.Fatalf("alarm delivery suppressed under spool pressure: want 1, got %d", len(got))
	}
	if got[0].Kind != flowlog.AlarmUnexplainedFlow {
		t.Errorf("kind %v, want AlarmUnexplainedFlow", got[0].Kind)
	}
	// The unexplained flow never rode the droppable spool as an ordinary record.
	for {
		batch, ack, err := pressured.ReadBatch(bg, 256)
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		if len(batch) == 0 {
			break
		}
		for _, ev := range batch {
			if fr, ok := ev.(flowlog.FlowRecord); ok && fr.Dst == hole.Dst {
				t.Errorf("unexplained flow rode the droppable spool: %+v", fr)
			}
		}
		if err := ack(); err != nil {
			t.Fatalf("ack: %v", err)
		}
	}
}

// mustObserveIdx folds a DNS-2 admission with an explicit validity window.
func mustObserveIdx(t *testing.T, idx flowlog.AdmissionIndex, ref flowlog.SessionRef, name, ip string, from, until time.Time) {
	t.Helper()
	ev := flowlog.DnsEvent{
		Session: ref, QueryName: name,
		AdmittedIPs: []netip.Addr{netip.MustParseAddr(ip)},
		TTL:         until.Sub(from), ExpiresAt: until,
		Decision: flowlog.PolicyDecision{
			Session: ref, Verdict: flowlog.VerdictAllow, RuleID: "DNS-2.admit",
			PolicyLayer: "session", PolicyVersion: "policy-v1", Resource: name, At: from,
		},
	}
	if err := idx.ObserveDns(bg, ev); err != nil {
		t.Fatalf("ObserveDns(%s): %v", name, err)
	}
}
