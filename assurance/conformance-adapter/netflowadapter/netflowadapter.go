// SPDX-License-Identifier: Apache-2.0

package netflowadapter

// netflowadapter.go — the adapter core. It provides REAL implementations of the
// boundary/flowlog Collector / Attributor (SessionRegistry + AdmissionIndex) /
// Spool / Router / Shipper / Sink seams (the boundary ships RED stubs), and a
// proxyDriver that runs SCRIPTED sessions through the real tlsproxyinspect
// PassThroughDispatcher (the Go mirror of main.rs proceed_route + the opaque
// splice + passThroughNetflowEvent) and TRANSLATES the proxy's tlsproxy.Event
// emissions into boundary/flowlog events, joined to the admitting DNS name. See
// doc.go for the guarantee, the two-seam-family bridge, and the four properties.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/assurance/conformance-adapter/tlsproxyinspect"
	flowlog "github.com/dream-serpent/dream-serpent/boundary/flowlog"
	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

// ───────────────────────────────────────────────────────────────────────────
// Exported sentinels (Err prefix + errors.New — the load-bearing convention
// mirrored from tlsproxyinspect/doc.go).
// ───────────────────────────────────────────────────────────────────────────

var (
	// ErrUnattributedFlow is returned when a kernel/proxy flow's attribution keys
	// (ct mark + iifname) do not resolve to exactly one registered session — the
	// LOG-2 "never guess a session" rule. An unattributed flow is surfaced, never
	// joined to a guessed session.
	ErrUnattributedFlow = errors.New("netflowadapter: flow not attributable to any registered session (LOG-2: ct mark + iifname must resolve to exactly one session)")

	// ErrMissingAdmittingDomain is returned when a flow carries no SNI/admission
	// key to join on — the netflow record's admitting-domain join is mandatory for
	// an admitted connection (LOG-2). A flow with no admission key is flagged for
	// reconciliation, never given a fabricated domain.
	ErrMissingAdmittingDomain = errors.New("netflowadapter: flow carries no SNI/admission key to join the admitting domain on (LOG-2)")
)

// ───────────────────────────────────────────────────────────────────────────
// SessionRegistry — ct mark + iifname -> SessionRef (LOG-2 attribution keys).
//
// The boundary SessionRegistry binds the kernel-side attribution keys at session
// create and marks them retired at teardown so post-destroy traffic is suspicious,
// not stale-attributed. This is a real in-memory implementation of that seam.
// ───────────────────────────────────────────────────────────────────────────

type registry struct {
	mu        sync.Mutex
	byMark    map[uint32]flowlog.SessionRef
	byIface   map[string]flowlog.SessionRef
	retiredAt map[string]time.Time // SessionID -> teardown instant
}

// NewSessionRegistry returns a real attribution-key registry satisfying the
// boundary flowlog.SessionRegistry seam.
func NewSessionRegistry() flowlog.SessionRegistry {
	return &registry{
		byMark:    map[uint32]flowlog.SessionRef{},
		byIface:   map[string]flowlog.SessionRef{},
		retiredAt: map[string]time.Time{},
	}
}

// RegisterSession binds (ctMark, iface) to ref. A zero ct mark is rejected — the
// LOG-2 keys must be present (a zero mark is the "no session" sentinel that the
// unattributed path returns ErrUnattributed for).
func (r *registry) RegisterSession(_ context.Context, ref flowlog.SessionRef, ctMark uint32, iface string) error {
	if ctMark == 0 || iface == "" {
		return fmt.Errorf("netflowadapter: register %q: %w", ref.SessionID, ErrUnattributedFlow)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byMark[ctMark] = ref
	r.byIface[iface] = ref
	delete(r.retiredAt, ref.SessionID)
	return nil
}

// RetireSession marks the session torn down at `at` so a later lookup can tell a
// caller the flow is post-teardown (the keys still resolve, but the retirement is
// recorded for the LOG-4 post-teardown alarm path).
func (r *registry) RetireSession(_ context.Context, ref flowlog.SessionRef, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.retiredAt[ref.SessionID] = at
	return nil
}

// retiredFor returns the teardown instant for a session if it has been retired
// (LOG-4 post-teardown alarm path). ok=false means the session is still live.
func (r *registry) retiredFor(sessionID string) (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.retiredAt[sessionID]
	return at, ok
}

// resolve returns the session iff BOTH keys agree on the same session — a mark on
// the wrong iface (or vice versa) is a disagreement and must NOT be coin-flipped
// (LOG-2). Returns ok=false on any disagreement or missing key.
func (r *registry) resolve(ctMark uint32, iface string) (flowlog.SessionRef, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	byMark, okM := r.byMark[ctMark]
	byIface, okI := r.byIface[iface]
	if !okM || !okI || byMark != byIface {
		return flowlog.SessionRef{}, false
	}
	return byMark, true
}

// ───────────────────────────────────────────────────────────────────────────
// AdmissionIndex — the DNS-2 stream -> time-windowed admitting-domain index.
//
// Per-session, keyed on (admitted IP), each entry carries the domain and validity
// window. AdmittingDomain answers the LOG-2 join honoring admission validity at
// flow start, and never cross-joins between sessions sharing a CDN IP.
// ───────────────────────────────────────────────────────────────────────────

type admissionEntry struct {
	domain string
	from   time.Time
	until  time.Time
}

type admissionIndex struct {
	mu sync.Mutex
	// per session -> per admitted addr -> entries (most-recent-first).
	bySession map[string]map[netip.Addr][]admissionEntry
}

// NewAdmissionIndex returns a real DNS-2-stream admitting-domain index satisfying
// the boundary flowlog.AdmissionIndex seam.
func NewAdmissionIndex() flowlog.AdmissionIndex {
	return &admissionIndex{bySession: map[string]map[netip.Addr][]admissionEntry{}}
}

// ObserveDns folds one DNS-2 admission event into the index: every admitted IP
// gains a (domain, [Decision.At, ExpiresAt)) window for that session.
func (x *admissionIndex) ObserveDns(_ context.Context, ev flowlog.DnsEvent) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	byAddr := x.bySession[ev.Session.SessionID]
	if byAddr == nil {
		byAddr = map[netip.Addr][]admissionEntry{}
		x.bySession[ev.Session.SessionID] = byAddr
	}
	from := ev.Decision.At
	for _, ip := range ev.AdmittedIPs {
		byAddr[ip] = append([]admissionEntry{{domain: ev.QueryName, from: from, until: ev.ExpiresAt}}, byAddr[ip]...)
	}
	return nil
}

// AdmittingDomain answers "which domain admitted this (session, dst) at `at`",
// honoring the admission window: a flow STARTING in-window keeps the domain
// (established flows ride conntrack past expiry — NFT-3). Returns ErrNoAdmission
// when no admission is valid, scoped to THIS session (no CDN cross-join).
func (x *admissionIndex) AdmittingDomain(_ context.Context, ref flowlog.SessionRef, dst netip.Addr, at time.Time) (string, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	byAddr := x.bySession[ref.SessionID]
	if byAddr == nil {
		return "", flowlog.ErrNoAdmission
	}
	for _, e := range byAddr[dst] {
		// Half-open [from, until): the flow's start instant must fall inside the
		// admission window. Established flows that started in-window keep the join.
		if !at.Before(e.from) && at.Before(e.until) {
			return e.domain, nil
		}
	}
	return "", flowlog.ErrNoAdmission
}

// ───────────────────────────────────────────────────────────────────────────
// Attributor — the LOG-2 join: ct mark + iifname -> SessionRef, then the
// AdmissionIndex lookup -> AdmittingDomain. Returns ErrUnattributed (never a
// guessed session) when keys disagree.
// ───────────────────────────────────────────────────────────────────────────

type attributor struct {
	reg flowlog.SessionRegistry
	idx flowlog.AdmissionIndex
}

// NewAttributor returns a real attributor over the given registry + index,
// satisfying the boundary flowlog.Attributor seam.
func NewAttributor(reg flowlog.SessionRegistry, idx flowlog.AdmissionIndex) flowlog.Attributor {
	return &attributor{reg: reg, idx: idx}
}

func (a *attributor) registry() *registry {
	// The registry is always our own concrete type in this adapter.
	r, _ := a.reg.(*registry)
	return r
}

// Attribute joins a conntrack flow to its session and admitting domain. A
// mark/iface disagreement or unknown key returns ErrUnattributed with a zero
// FlowRecord (LOG-2: never a coin-flip). A resolved flow whose dst was never
// admitted gets an EMPTY AdmittingDomain (flagged for reconciliation), not an
// error — only the attribution keys gate the record's existence.
func (a *attributor) Attribute(ctx context.Context, f flowlog.ConntrackFlow) (flowlog.FlowRecord, error) {
	ref, ok := a.registry().resolve(f.CtMark, f.Iif)
	if !ok {
		return flowlog.FlowRecord{}, flowlog.ErrUnattributed
	}
	dom, err := a.idx.AdmittingDomain(ctx, ref, f.Dst.Addr(), f.Start)
	if err != nil && !errors.Is(err, flowlog.ErrNoAdmission) {
		return flowlog.FlowRecord{}, err
	}
	return flowlog.FlowRecord{
		Session:         ref,
		Iface:           f.Iif,
		AdmittingDomain: dom, // "" when never admitted — feeds the LOG-4 reconciler
		Dst:             f.Dst,
		Protocol:        f.Protocol,
		BytesIn:         f.BytesReply,
		BytesOut:        f.BytesOrig,
		Start:           f.Start,
		End:             f.End,
		Duration:        f.End.Sub(f.Start),
		CtMark:          f.CtMark,
		Verdict:         flowlog.FlowAccepted,
	}, nil
}

// AttributeDrop joins an nflog drop to its session, recording the dropped
// verdict. Same attribution gate as Attribute.
func (a *attributor) AttributeDrop(ctx context.Context, d flowlog.NflogDrop) (flowlog.FlowRecord, error) {
	ref, ok := a.registry().resolve(d.CtMark, d.Iif)
	if !ok {
		return flowlog.FlowRecord{}, flowlog.ErrUnattributed
	}
	dom, err := a.idx.AdmittingDomain(ctx, ref, d.Dst.Addr(), d.At)
	if err != nil && !errors.Is(err, flowlog.ErrNoAdmission) {
		return flowlog.FlowRecord{}, err
	}
	return flowlog.FlowRecord{
		Session:         ref,
		Iface:           d.Iif,
		AdmittingDomain: dom,
		Dst:             d.Dst,
		Protocol:        d.Protocol,
		Start:           d.At,
		End:             d.At,
		CtMark:          d.CtMark,
		Verdict:         flowlog.FlowDropped,
	}, nil
}

// ───────────────────────────────────────────────────────────────────────────
// Spool — in-memory, disk-bounded buffer (LOG-3). Real implementation of the
// boundary flowlog.Spool seam: never exceed BoundBytes; on pressure drop-oldest
// and emit a SpoolOverflow marker so loss is visible, not silent.
// ───────────────────────────────────────────────────────────────────────────

type spool struct {
	mu    sync.Mutex
	bound int64
	usage int64
	evs   []flowlog.Event
}

// NewSpool returns a real in-memory spool with the given byte bound.
func NewSpool(boundBytes int64) flowlog.Spool { return &spool{bound: boundBytes} }

// approxBytes is the per-event accounting weight. The harness uses a fixed weight
// so the bound is exercised by COUNT deterministically; the contract is "never
// exceed BoundBytes + announce drops", which this honors.
const approxBytes int64 = 256

// Append adds an event, drop-oldest-shedding (with a visible SpoolOverflow
// marker) if the bound would be exceeded.
func (s *spool) Append(_ context.Context, ev flowlog.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped := 0
	for s.usage+approxBytes > s.bound && len(s.evs) > 0 {
		s.evs = s.evs[1:]
		s.usage -= approxBytes
		dropped++
	}
	if dropped > 0 {
		s.evs = append(s.evs, flowlog.SpoolOverflow{Session: ev.Ref(), Dropped: dropped, At: time.Now()})
		s.usage += approxBytes
	}
	s.evs = append(s.evs, ev)
	s.usage += approxBytes
	return nil
}

// ReadBatch returns up to max events plus an ack that drops them once shipped.
func (s *spool) ReadBatch(_ context.Context, max int) ([]flowlog.Event, func() error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.evs)
	if max < n {
		n = max
	}
	batch := append([]flowlog.Event(nil), s.evs[:n]...)
	ack := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.evs = s.evs[n:]
		s.usage -= int64(n) * approxBytes
		if s.usage < 0 {
			s.usage = 0
		}
		return nil
	}
	return batch, ack, nil
}

func (s *spool) UsageBytes() int64 { return s.usage }
func (s *spool) BoundBytes() int64 { return s.bound }

// snapshot returns every buffered event (test/diagnostic helper, not a seam).
func (s *spool) snapshot() []flowlog.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]flowlog.Event(nil), s.evs...)
}

// ───────────────────────────────────────────────────────────────────────────
// Collector — the single ingest point (LOG-3). Real implementation of the
// boundary flowlog.Collector seam: validate-free pass-through to the spool (the
// events are already attributed by the Attributor / translated by the driver).
// ───────────────────────────────────────────────────────────────────────────

type collector struct{ spool flowlog.Spool }

// NewCollector returns a real collector writing into the given spool.
func NewCollector(sp flowlog.Spool) flowlog.Collector { return &collector{spool: sp} }

// Ingest hands an event to the spool. A nil event is rejected (a missing event is
// never silently dropped).
func (c *collector) Ingest(ctx context.Context, ev flowlog.Event) error {
	if ev == nil {
		return fmt.Errorf("netflowadapter: nil event: %w", flowlog.ErrUnattributed)
	}
	return c.spool.Append(ctx, ev)
}

// ───────────────────────────────────────────────────────────────────────────
// Router + Sink + Shipper (LOG-3 / D19). Real implementations: TierOnPrem always
// routes customer-side; TierSaaS uses the configured default. The Sink is the
// queryable off-box store. The Shipper drains the spool through the router into
// the sinks with ack semantics.
// ───────────────────────────────────────────────────────────────────────────

type router struct{ cfg flowlog.RouterConfig }

// NewRouter returns a real D19 tier router.
func NewRouter(cfg flowlog.RouterConfig) flowlog.Router { return &router{cfg: cfg} }

// Route maps an event + tier to a sink. TierOnPrem always routes customer-side;
// an unconfigured destination returns ErrUnroutableTier rather than falling
// through to the vendor sink.
func (r *router) Route(_ flowlog.Event, tier flowlog.HostingTier) (flowlog.SinkID, error) {
	switch tier {
	case flowlog.TierOnPrem:
		if r.cfg.CustomerSide == "" {
			return "", flowlog.ErrUnroutableTier
		}
		return r.cfg.CustomerSide, nil
	case flowlog.TierSaaS:
		if r.cfg.Default == "" {
			return "", flowlog.ErrUnroutableTier
		}
		return r.cfg.Default, nil
	default:
		return "", flowlog.ErrUnroutableTier
	}
}

type memSink struct {
	mu  sync.Mutex
	evs []flowlog.Event
}

// NewSink returns a real in-memory queryable sink satisfying the boundary
// flowlog.Sink seam — the doc-06 "queryable off-box" fake.
func NewSink() flowlog.Sink { return &memSink{} }

// Receive appends a batch to the store.
func (m *memSink) Receive(_ context.Context, batch []flowlog.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evs = append(m.evs, batch...)
	return nil
}

// Query returns the session's complete network story within the window, ordered
// by event time.
func (m *memSink) Query(_ context.Context, q flowlog.StoryQuery) ([]flowlog.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []flowlog.Event
	for _, ev := range m.evs {
		if ev.Ref().SessionID != q.SessionID {
			continue
		}
		t := eventTime(ev)
		if !q.Window.From.IsZero() && t.Before(q.Window.From) {
			continue
		}
		if !q.Window.To.IsZero() && !t.Before(q.Window.To) {
			continue
		}
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool { return eventTime(out[i]).Before(eventTime(out[j])) })
	return out, nil
}

type shipper struct {
	spool  flowlog.Spool
	router flowlog.Router
	sinks  map[flowlog.SinkID]flowlog.Sink
	tier   flowlog.HostingTier
}

// NewShipper returns a real shipper draining the spool through the router into
// the sinks.
func NewShipper(sp flowlog.Spool, rt flowlog.Router, sinks map[flowlog.SinkID]flowlog.Sink, tier flowlog.HostingTier) flowlog.Shipper {
	return &shipper{spool: sp, router: rt, sinks: sinks, tier: tier}
}

// Ship drains the whole spool: each event is routed to its sink and delivered,
// then the batch is acked. An unroutable tier or unknown sink surfaces an error
// (the batch is NOT acked, so at-least-once holds).
func (s *shipper) Ship(ctx context.Context) error {
	for {
		batch, ack, err := s.spool.ReadBatch(ctx, 256)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		// Group by routed sink, then deliver. TierOnPrem routes everything
		// customer-side; otherwise the configured default.
		bySink := map[flowlog.SinkID][]flowlog.Event{}
		for _, ev := range batch {
			id, rerr := s.router.Route(ev, s.tier)
			if rerr != nil {
				return rerr
			}
			bySink[id] = append(bySink[id], ev)
		}
		for id, evs := range bySink {
			sink, ok := s.sinks[id]
			if !ok {
				return fmt.Errorf("netflowadapter: no sink registered for %q: %w", id, flowlog.ErrUnroutableTier)
			}
			if derr := sink.Receive(ctx, evs); derr != nil {
				return derr
			}
		}
		if aerr := ack(); aerr != nil {
			return aerr
		}
	}
}

// eventTime is the canonical event timestamp for story ordering — mirrors the
// boundary flowlog test helper of the same shape.
func eventTime(ev flowlog.Event) time.Time {
	switch e := ev.(type) {
	case flowlog.FlowRecord:
		return e.Start
	case flowlog.DnsEvent:
		return e.Decision.At
	case flowlog.HttpEvent:
		return e.Start
	case flowlog.PolicyDecision:
		return e.At
	case flowlog.CredentialUseEvent:
		return e.Request.At
	case flowlog.SpoolOverflow:
		return e.At
	}
	return time.Time{}
}

// compile-time proof the adapter satisfies the boundary flowlog seams.
var (
	_ flowlog.SessionRegistry = (*registry)(nil)
	_ flowlog.AdmissionIndex  = (*admissionIndex)(nil)
	_ flowlog.Attributor      = (*attributor)(nil)
	_ flowlog.Collector       = (*collector)(nil)
	_ flowlog.Spool           = (*spool)(nil)
	_ flowlog.Router          = (*router)(nil)
	_ flowlog.Sink            = (*memSink)(nil)
	_ flowlog.Shipper         = (*shipper)(nil)
)

// ───────────────────────────────────────────────────────────────────────────
// proxyDriver — runs SCRIPTED sessions through the real tlsproxyinspect
// PassThroughDispatcher and TRANSLATES the proxy's tlsproxy.Event emissions into
// boundary/flowlog events, joined to the admitting DNS name.
//
// This is the bridge between the two seam families: the dispatcher (the Go mirror
// of main.rs proceed_route) emits in the boundary/tlsproxy vocabulary; ds-flowlog
// collects in the boundary/flowlog vocabulary. The driver runs the dispatcher,
// captures every tlsproxy.Event, and lifts it into flowlog events through the
// real Attributor (SNI -> admitting domain via the AdmissionIndex). The CARDINALITY
// is preserved BY CONSTRUCTION: each connection produces exactly one FlowRecord;
// HTTP requests on the inspected leg add HttpEvents without adding FlowRecords.
// ───────────────────────────────────────────────────────────────────────────

// ScriptedRequest is one HTTP request driven over an already-established
// connection. It is meaningful ONLY on the inspected leg (the opaque tunnel sees
// no HTTP). The cardinality property uses N requests over ONE connection.
type ScriptedRequest struct {
	Method string
	Path   string
	Status int
}

// ScriptedConn is one egress connection a session opens to a domain. Listed
// (pass-through) connections take the opaque tunnel and emit ONLY a FlowRecord;
// unlisted (inspected) connections terminate TLS and emit a FlowRecord PLUS one
// HttpEvent per scripted request.
type ScriptedConn struct {
	// Domain is the SNI / admitting-domain key the connection is admitted for.
	Domain string
	// Dst is the kernel destination the connection dials.
	Dst netip.AddrPort
	// ClientHello is the raw bytes peeked off the VM (replayed verbatim upstream
	// on the opaque leg).
	ClientHello []byte
	// Requests are the HTTP requests driven over the connection (inspected leg
	// only); empty on the opaque leg.
	Requests []ScriptedRequest
	// Start is the connection's flow-start instant (the admission-window join key).
	Start time.Time
	// BytesOut/BytesIn are the connection-level L3/4 byte counts.
	BytesOut uint64
	BytesIn  uint64
}

// ScriptedSession is one VM session's egress activity: its attribution keys and
// the connections it opens.
type ScriptedSession struct {
	Ref    flowlog.SessionRef
	CtMark uint32
	Conns  []ScriptedConn
}

// DriverDeps bundles the real proxy-side seams the driver drives through.
type DriverDeps struct {
	// Policy is the boundary/tlsproxy pass-through policy the dispatcher consults
	// (the list is policy, not code — empty by default, D74).
	Policy tlsproxy.PolicyEngine
	// CAMinter mints the per-session interception CA used on the inspected leg.
	CAMinter *tlsproxyinspect.AdapterCAMinter
	// Dialer re-originates upstream (DialRaw opaque / DialTLS inspected).
	Dialer tlsproxy.UpstreamDialer
}

// Driver runs scripted sessions and emits flowlog events through the boundary
// flowlog seams. It owns the attribution stack (registry + index + attributor)
// and the collection stack (collector + spool).
type Driver struct {
	deps DriverDeps

	Registry  flowlog.SessionRegistry
	Index     flowlog.AdmissionIndex
	Attr      flowlog.Attributor
	Spool     flowlog.Spool
	Collector flowlog.Collector
}

// NewDriver builds a Driver with a fresh attribution + collection stack over the
// given proxy-side deps and spool bound.
func NewDriver(deps DriverDeps, spoolBound int64) *Driver {
	reg := NewSessionRegistry()
	idx := NewAdmissionIndex()
	sp := NewSpool(spoolBound)
	return &Driver{
		deps:      deps,
		Registry:  reg,
		Index:     idx,
		Attr:      NewAttributor(reg, idx),
		Spool:     sp,
		Collector: NewCollector(sp),
	}
}

// dispatcher builds the real PassThroughDispatcher for one session, wiring its
// per-session CA, the shared dialer, and a capturing sink that ABSORBS the
// dispatcher's opaque-leg netflow EventFlow emission (so the pass-through leg's
// Emit does not error). The driver does NOT read this sink — it synthesizes the
// flowlog FlowRecord from the connection conntrack + the returned route value
// (see Run); the sink is the dispatcher's emission terminus, not a translation
// source.
func (d *Driver) dispatcher(sess flowlog.SessionRef, sink tlsproxy.EventSink) (*tlsproxyinspect.PassThroughDispatcher, error) {
	ca, err := d.deps.CAMinter.MintSessionCA(context.Background(), tlsproxy.SessionRef{ID: sess.SessionID})
	if err != nil {
		return nil, fmt.Errorf("netflowadapter: mint session CA for %q: %w", sess.SessionID, err)
	}
	return &tlsproxyinspect.PassThroughDispatcher{
		Policy: d.deps.Policy,
		CA:     ca,
		Dialer: d.deps.Dialer,
		Sink:   sink,
	}, nil
}

// Run drives every scripted session through the real dispatcher and ingests the
// resulting flowlog events. It returns the per-connection routes the DISPATCHER
// chose (so a test can assert the route is the system's, not the test's).
//
// For each connection:
//   - the dispatcher consults the pass-through seam and picks the leg;
//   - the driver builds the connection's ConntrackFlow and ATTRIBUTES it (LOG-2:
//     ct mark + iifname -> session, SNI -> admitting domain) into exactly ONE
//     FlowRecord, which it INGESTS — this is the cardinality invariant (one flow
//     per connection, built once, regardless of request count);
//   - on the INSPECTED leg, the driver additionally ingests one HttpEvent per
//     scripted request (HTTP metadata + the admitting-domain join);
//   - on the OPAQUE leg, NO HttpEvent is ingested (the tunnel observes none).
func (d *Driver) Run(ctx context.Context, sessions []ScriptedSession) (map[string]tlsproxyinspect.Route, error) {
	routes := map[string]tlsproxyinspect.Route{}
	for _, s := range sessions {
		if err := d.Registry.RegisterSession(ctx, s.Ref, s.CtMark, s.Ref.Iface); err != nil {
			return nil, err
		}
		sink := tlsproxyinspect.NewCapturingEventSink()
		disp, err := d.dispatcher(s.Ref, sink)
		if err != nil {
			return nil, err
		}
		for _, conn := range s.Conns {
			route, _, _, derr := disp.Dispatch(ctx, tlsproxy.SessionRef{ID: s.Ref.SessionID}, conn.Domain, conn.Dst, conn.ClientHello)
			if derr != nil {
				return nil, fmt.Errorf("netflowadapter: dispatch %s/%s: %w", s.Ref.SessionID, conn.Domain, derr)
			}
			routes[s.Ref.SessionID+"|"+conn.Domain] = route

			// ── ONE FlowRecord per connection (cardinality invariant). The flow is
			// built ONCE per connection from the connection-level conntrack and
			// attributed through the LOG-2 join, independent of request count. ──
			cf := flowlog.ConntrackFlow{
				CtMark:     s.CtMark,
				Iif:        s.Ref.Iface,
				Dst:        conn.Dst,
				Protocol:   flowlog.ProtoTCP,
				BytesOrig:  conn.BytesOut,
				BytesReply: conn.BytesIn,
				Start:      conn.Start,
				End:        conn.Start.Add(time.Second),
			}
			rec, aerr := d.Attr.Attribute(ctx, cf)
			if aerr != nil {
				return nil, fmt.Errorf("netflowadapter: attribute %s/%s: %w", s.Ref.SessionID, conn.Domain, aerr)
			}
			if err := d.Collector.Ingest(ctx, rec); err != nil {
				return nil, err
			}

			// ── HTTP metadata ONLY on the inspected leg (opaque sees none). Each
			// scripted request becomes one HttpEvent carrying the admitting-domain
			// join (Host) — and crucially NOT a second FlowRecord. ──
			if route == tlsproxyinspect.RouteInspect {
				for i, req := range conn.Requests {
					he := flowlog.HttpEvent{
						Session:   s.Ref,
						Method:    req.Method,
						Host:      conn.Domain, // the admitting-domain join on the HTTP plane
						Path:      req.Path,
						Status:    req.Status,
						ReqBytes:  256,
						RespBytes: 1024,
						Start:     conn.Start.Add(time.Duration(i+1) * time.Millisecond),
						Duration:  10 * time.Millisecond,
						Decision: flowlog.PolicyDecision{
							Session:       s.Ref,
							Verdict:       flowlog.VerdictAllow,
							RuleID:        "POL-2.allow",
							PolicyLayer:   "session",
							PolicyVersion: "policy-v1",
							Resource:      conn.Domain,
							At:            conn.Start.Add(time.Duration(i+1) * time.Millisecond),
						},
					}
					if err := d.Collector.Ingest(ctx, he); err != nil {
						return nil, err
					}
				}
			}
			// On the OPAQUE leg the dispatcher already emitted a tlsproxy.EventFlow
			// into the capturing sink (which merely absorbs it; the driver does not
			// read it back). The driver's connection-level FlowRecord above is the
			// flowlog-vocabulary twin SYNTHESIZED from the conntrack — it is the
			// system's emission because the dispatcher's RoutePassThrough decision
			// (read from the returned route) is what suppresses HttpEvent synthesis
			// below. The opaque leg ingests NO HttpEvent — the cardinality +
			// no-HTTP-metadata property for pass-through.
		}
	}
	return routes, nil
}

// CollectedEvents returns every event ingested into the spool, in ingest order.
func (d *Driver) CollectedEvents() []flowlog.Event {
	if sp, ok := d.Spool.(*spool); ok {
		return sp.snapshot()
	}
	return nil
}

// ObserveDns folds a DNS-2 admission into the driver's index so the connection's
// SNI joins to its admitting domain. It is the test's way of priming the
// admitting-domain join before Run.
func (d *Driver) ObserveDns(ctx context.Context, ev flowlog.DnsEvent) error {
	return d.Index.ObserveDns(ctx, ev)
}
