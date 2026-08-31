package flowlog

// Test doubles + fixtures for the flowlog TDD harness. These ship with the
// tests, not the stubs (CONVENTIONS.md "File naming per package").

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

var bg = context.Background()

// t0 is the deterministic harness epoch — never time.Now() in assertions.
var t0 = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

// testFingerprint is a well-formed fingerprint literal for fixtures whose
// content is not under test.
var testFingerprint = CredentialFingerprint(FingerprintPrefix + strings.Repeat("a1", 32))

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

func mkRef(id string) SessionRef {
	return SessionRef{SessionID: id, HostID: "host-1", Iface: "dstap-" + id}
}

func validDecision(ref SessionRef, v Verdict, ruleID, resource string, at time.Time) PolicyDecision {
	return PolicyDecision{
		Session: ref, Verdict: v, RuleID: ruleID,
		PolicyLayer: "session", PolicyVersion: "policy-v1",
		Resource: resource, At: at,
	}
}

func validFlowRecord(ref SessionRef, seq uint32, at time.Time) FlowRecord {
	return FlowRecord{
		Session: ref, Iface: ref.Iface, AdmittingDomain: "registry.npmjs.org",
		Dst: netip.MustParseAddrPort("104.16.0.5:443"), Protocol: ProtoTCP,
		BytesIn: 2048, BytesOut: 512,
		Start: at, End: at.Add(time.Second), Duration: time.Second,
		CtMark: seq, Verdict: FlowAccepted,
	}
}

func validDnsEvent(ref SessionRef, name string, at time.Time) DnsEvent {
	return DnsEvent{
		Session: ref, QueryName: name,
		AdmittedIPs: []netip.Addr{netip.MustParseAddr("104.16.0.5")},
		TTL:         60 * time.Second, ExpiresAt: at.Add(60 * time.Second),
		Decision: validDecision(ref, VerdictAllow, "DNS-2.admit", name, at),
	}
}

func validHttpEvent(ref SessionRef, host string, at time.Time) HttpEvent {
	return HttpEvent{
		Session: ref, Method: "GET", Host: host, Path: "/", Status: 200,
		ReqBytes: 512, RespBytes: 2048,
		Start: at, Duration: 80 * time.Millisecond,
		Decision: validDecision(ref, VerdictAllow, "POL-2.allow", host, at),
	}
}

func validCredUse(ref SessionRef, fp CredentialFingerprint, at time.Time) CredentialUseEvent {
	return CredentialUseEvent{
		Session: ref, Service: "github", Fingerprint: fp,
		Request: HttpRequestMeta{Method: "POST", Host: "api.github.com", Path: "/repos/x/git-receive-pack", At: at},
	}
}

func ctFlow(mark uint32, iif, src, dst string, bytesOut, bytesIn uint64, start, end time.Time) ConntrackFlow {
	return ConntrackFlow{
		CtMark: mark, Iif: iif,
		Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst),
		Protocol:  ProtoTCP,
		BytesOrig: bytesOut, BytesReply: bytesIn, Packets: 10,
		Start: start, End: end,
	}
}

// eventTime is the canonical event timestamp used for story ordering.
func eventTime(ev Event) time.Time {
	switch e := ev.(type) {
	case FlowRecord:
		return e.Start
	case DnsEvent:
		return e.Decision.At
	case HttpEvent:
		return e.Start
	case PolicyDecision:
		return e.At
	case CredentialUseEvent:
		return e.Request.At
	case SpoolOverflow:
		return e.At
	}
	return time.Time{}
}

// ---------------------------------------------------------------------------
// must* helpers — Fatalf on error; against the stubs these fail RED as
// designed (they require the documented outcome: the operation succeeds).
// ---------------------------------------------------------------------------

func mustRegister(t *testing.T, reg SessionRegistry, ref SessionRef, mark uint32, iface string) {
	t.Helper()
	if err := reg.RegisterSession(bg, ref, mark, iface); err != nil {
		t.Fatalf("RegisterSession(%s, mark=%#x, iface=%s): %v", ref.SessionID, mark, iface, err)
	}
}

func mustRetire(t *testing.T, reg SessionRegistry, ref SessionRef, at time.Time) {
	t.Helper()
	if err := reg.RetireSession(bg, ref, at); err != nil {
		t.Fatalf("RetireSession(%s): %v", ref.SessionID, err)
	}
}

func mustObserveDns(t *testing.T, idx AdmissionIndex, ev DnsEvent) {
	t.Helper()
	if err := idx.ObserveDns(bg, ev); err != nil {
		t.Fatalf("ObserveDns(%s -> %v): %v", ev.QueryName, ev.AdmittedIPs, err)
	}
}

func mustIngest(t *testing.T, c Collector, ev Event) {
	t.Helper()
	if err := c.Ingest(bg, ev); err != nil {
		t.Fatalf("Collector.Ingest(%T): %v", ev, err)
	}
}

func mustAppend(t *testing.T, s Spool, ev Event) {
	t.Helper()
	if err := s.Append(bg, ev); err != nil {
		t.Fatalf("Spool.Append(%T): %v", ev, err)
	}
}

func mustShip(t *testing.T, sh Shipper) {
	t.Helper()
	if err := sh.Ship(bg); err != nil {
		t.Fatalf("Shipper.Ship: %v", err)
	}
}

func mustFingerprint(t *testing.T, secret []byte) CredentialFingerprint {
	t.Helper()
	fp, err := FingerprintCredential(secret)
	if err != nil {
		t.Fatalf("FingerprintCredential: %v", err)
	}
	return fp
}

func mustMarshal(t *testing.T, ev Event) []byte {
	t.Helper()
	b, err := MarshalEvent(ev)
	if err != nil {
		t.Fatalf("MarshalEvent(%T): %v", ev, err)
	}
	return b
}

// diskBytesUnder measures the REAL on-disk byte total under dir. The LOG-3
// disk bound is a property of the disk, not of the implementation's
// self-report — tests measure it directly.
func diskBytesUnder(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatalf("walking spool dir %s: %v", dir, err)
	}
	return total
}

// ---------------------------------------------------------------------------
// Fake clock (deterministic time; never time.Sleep for expiry)
// ---------------------------------------------------------------------------

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(at time.Time) *fakeClock { return &fakeClock{now: at} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ---------------------------------------------------------------------------
// Recording alarm sink (the typed escalation channel, distinct from events)
// ---------------------------------------------------------------------------

type recordingAlarmSink struct {
	mu     sync.Mutex
	alarms []Alarm
}

func (r *recordingAlarmSink) Raise(_ context.Context, a Alarm) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alarms = append(r.alarms, a)
	return nil
}

func (r *recordingAlarmSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.alarms)
}

func (r *recordingAlarmSink) all() []Alarm {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Alarm(nil), r.alarms...)
}

// ---------------------------------------------------------------------------
// Fake sink: scriptable outage, recorded batches, identity-deduped receive,
// time-ordered story Query (the doc-06 fake neighbor).
// ---------------------------------------------------------------------------

type fakeSink struct {
	mu       sync.Mutex
	failing  bool
	receives int
	batches  [][]Event
	events   []Event
	seen     map[string]bool
}

func (s *fakeSink) setFailing(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing = v
}

func (s *fakeSink) Receive(_ context.Context, batch []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receives++
	if s.failing {
		return errors.New("fakesink: scripted outage")
	}
	s.batches = append(s.batches, append([]Event(nil), batch...))
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	for _, ev := range batch {
		key := fmt.Sprintf("%T|%+v", ev, ev) // event identity: idempotent receive
		if s.seen[key] {
			continue
		}
		s.seen[key] = true
		s.events = append(s.events, ev)
	}
	return nil
}

func (s *fakeSink) Query(_ context.Context, q StoryQuery) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, ev := range s.events {
		if q.SessionID != "" && ev.Ref().SessionID != q.SessionID {
			continue
		}
		ts := eventTime(ev)
		if !q.Window.From.IsZero() && ts.Before(q.Window.From) {
			continue
		}
		if !q.Window.To.IsZero() && !ts.Before(q.Window.To) {
			continue
		}
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool { return eventTime(out[i]).Before(eventTime(out[j])) })
	return out, nil
}

func (s *fakeSink) receiveCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receives
}

func (s *fakeSink) allEvents() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

func (s *fakeSink) allBatches() [][]Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]Event, len(s.batches))
	copy(out, s.batches)
	return out
}

func (s *fakeSink) firstBatch() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.batches) == 0 {
		return nil
	}
	return append([]Event(nil), s.batches[0]...)
}

// ---------------------------------------------------------------------------
// Recording spool (for Collector-side observation in attribution tests)
// ---------------------------------------------------------------------------

type recordingSpool struct {
	mu     sync.Mutex
	events []Event
	cursor int
	bound  int64
}

func (s *recordingSpool) Append(_ context.Context, ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func (s *recordingSpool) ReadBatch(_ context.Context, max int) ([]Event, func() error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cursor >= len(s.events) {
		return nil, func() error { return nil }, nil
	}
	end := s.cursor + max
	if end > len(s.events) {
		end = len(s.events)
	}
	batch := append([]Event(nil), s.events[s.cursor:end]...)
	ack := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.cursor < end {
			s.cursor = end
		}
		return nil
	}
	return batch, ack, nil
}

func (s *recordingSpool) UsageBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.events))
}
func (s *recordingSpool) BoundBytes() int64 { return s.bound }

func (s *recordingSpool) all() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

// ---------------------------------------------------------------------------
// Ack-dropping spool wrapper (LOG-3.b: un-acked batches must be re-shipped)
// ---------------------------------------------------------------------------

// ackDroppingSpool wraps a Spool and swallows the first dropN acks (modeling
// a shipper crash between Sink.Receive succeeding and the ack landing): the
// batch is delivered but never acknowledged, so it must be re-shipped.
type ackDroppingSpool struct {
	Spool
	mu    sync.Mutex
	dropN int
}

func (s *ackDroppingSpool) ReadBatch(ctx context.Context, max int) ([]Event, func() error, error) {
	batch, ack, err := s.Spool.ReadBatch(ctx, max)
	if err != nil || ack == nil {
		return batch, ack, err
	}
	wrapped := func() error {
		s.mu.Lock()
		if s.dropN > 0 {
			s.dropN--
			s.mu.Unlock()
			return errors.New("ackDroppingSpool: scripted ack failure")
		}
		s.mu.Unlock()
		return ack()
	}
	return batch, wrapped, nil
}

// ---------------------------------------------------------------------------
// Fake admission index (programmable neighbor for reconciler tests; the real
// AdmissionIndex seam is exercised by the LOG-2 tests)
// ---------------------------------------------------------------------------

type admissionEntry struct {
	domain string
	ip     netip.Addr
	from   time.Time
	until  time.Time
}

type fakeAdmissionIndex struct {
	mu      sync.Mutex
	entries map[string][]admissionEntry // keyed by SessionID
}

func newFakeAdmissionIndex() *fakeAdmissionIndex {
	return &fakeAdmissionIndex{entries: map[string][]admissionEntry{}}
}

func (f *fakeAdmissionIndex) add(ref SessionRef, domain string, ip netip.Addr, from, until time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[ref.SessionID] = append(f.entries[ref.SessionID],
		admissionEntry{domain: domain, ip: ip, from: from, until: until})
}

func (f *fakeAdmissionIndex) ObserveDns(_ context.Context, ev DnsEvent) error {
	for _, ip := range ev.AdmittedIPs {
		f.add(ev.Session, ev.QueryName, ip, ev.ExpiresAt.Add(-ev.TTL), ev.ExpiresAt)
	}
	return nil
}

func (f *fakeAdmissionIndex) AdmittingDomain(_ context.Context, ref SessionRef, dst netip.Addr, at time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries[ref.SessionID] {
		if e.ip == dst && !at.Before(e.from) && at.Before(e.until) {
			return e.domain, nil
		}
	}
	return "", ErrNoAdmission
}

// ---------------------------------------------------------------------------
// Static reconciler input sources
// ---------------------------------------------------------------------------

type staticFlowSource []ConntrackFlow

func (s staticFlowSource) Flows(_ context.Context, _ Window) ([]ConntrackFlow, error) {
	return append([]ConntrackFlow(nil), s...), nil
}

type staticEventSource []Event

func (s staticEventSource) Events(_ context.Context, _ Window) ([]Event, error) {
	return append([]Event(nil), s...), nil
}

// staticAllowances returns everything configured for the session, including
// expired grants — judging validity is the reconciler's job.
type staticAllowances map[string][]Allowance

func (s staticAllowances) Allowances(_ context.Context, ref SessionRef, _ time.Time) ([]Allowance, error) {
	return append([]Allowance(nil), s[ref.SessionID]...), nil
}
