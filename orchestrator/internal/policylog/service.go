package policylog

// This file is the in-process PolicyService (doc 15 §5.3, D36/D72): the policy_log
// APPEND + WATCH surface the orchestrator serves. It is the shape the
// PolicyService gRPC RPCs adapt to mechanically when wired (the proto is frozen
// at M0 — orchestrator.v1 policy.proto; this is the in-process seam, never a
// proto body). Three legs:
//
//   - AppendPolicy: append an authored row with the ACTOR recorded — the log IS
//     the audit trail (D36). The store assigns the bigserial seq (THE single
//     policy version namespace, D72); the service refuses an empty actor before
//     the write so every row carries attribution.
//   - WatchPolicies(from_seq): replay composed snapshots from a cursor (D36
//     catch-up). Idempotent (replaying the same from_seq yields the same
//     snapshots), deny-wins (the composed document is the deny-overrides output),
//     and EXACTLY ONE subscriber per host = the host agent (D72). A second
//     subscribe for a host already streaming is refused — the topology invariant
//     is enforced at this terminator, not trusted to callers.
//   - ApproveAsk: the §4.3 ask-grant append, already realized as the
//     gate+attribution seam in askapproval.go / askrouting.go; the service exposes
//     it here so the three RPCs sit behind one type.
//
// Snapshot identity is (seq, content_hash, composed policy) (doc 13 §5, D120):
// the service composes each emitted snapshot via ComposeSnapshot, so the watch
// stream carries the deny-overrides composed document — never raw layers (doc 13
// §1 rule 1). The composition of policy_log rows INTO layer stacks is the
// SnapshotComposer seam: the POL-1 layer-document parse lives in ds-contracts
// (opaque here), so the service depends on the composer interface and either a
// real composer or a test fake satisfies it.
//
// Push-to-enforced budget (doc 15 §1/§11): approval→enforced targets ≤5 s,
// comfortably inside the 30–60 s socket hold; this in-process serving leg is the
// control-plane half (append + fan-out), the host-side apply barrier + sweep is
// the consumer half (doc 13 §5). The pre-named substrate swap is JetStream behind
// this same WatchPolicies contract (D36), fired on the ~500-host budget miss.
//
// Governing decisions: D36, D72, D120. Primary doc: docs/15 §5.3, §4.3.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// policyStore is the narrow persistence seam the service consumes: the append
// (AppendPolicy), the replay read (ListPolicy), and the live-grant read
// (LiveGrants) for ask-grant folding. Both store impls (*store.Memory,
// *store.Postgres) satisfy it; a test fake satisfies it too. The service depends
// only on the three methods it uses, never the full Repository.
type policyStore interface {
	AppendPolicy(ctx context.Context, row store.PolicyLogRow) (store.PolicyLogRow, error)
	ListPolicy(ctx context.Context, fromSeq int64, limit int) ([]store.PolicyLogRow, error)
	LiveGrants(ctx context.Context, sessionUUID string, now time.Time) ([]store.PolicyLogRow, error)
}

// SnapshotComposer turns the policy_log state up to and including a seq into the
// composed snapshot for that seq (the deny-overrides composite host document,
// doc 13 §5). It is a SEAM because the POL-1 layer-document parse — turning each
// row's opaque payload into a Layer's allow/deny rule sets — lives in
// ds-contracts (doc 13 §3), not in this control-plane package. The service holds
// the WATCH choreography (cursor, one-subscriber-per-host, idempotent replay) and
// delegates the per-seq compose to whatever composer is wired. ComposeAt receives
// the rows up to `seq` (ascending) and the moment to evaluate grant liveness
// against, and returns the (seq, content_hash, composed policy) snapshot.
type SnapshotComposer interface {
	ComposeAt(ctx context.Context, seq int64, rows []store.PolicyLogRow, now time.Time) (Snapshot, error)
}

// ErrActorRequired is returned by AppendPolicy when the actor is empty: the log
// IS the audit trail (D36), so every row records who appended it. The service
// refuses before the store write so a row with no attribution is never persisted
// (the store's own ErrInvalid mirror is the defense in depth).
var ErrActorRequired = errors.New("policylog: AppendPolicy requires a non-empty actor (D36 audit trail)")

// ErrHostAlreadySubscribed is returned by WatchPolicies when a host already has a
// live policy subscription: EXACTLY ONE subscriber per host = the host agent
// (D72). The topology invariant is enforced at this terminator — a second
// subscribe is refused rather than silently fanning the stream to two readers (a
// split-brain apply-barrier hazard, doc 13 §5).
var ErrHostAlreadySubscribed = errors.New("policylog: host already has a policy subscription (D72 one-subscriber-per-host)")

// Service is the in-process PolicyService (doc 15 §5.3). It holds the store seam,
// the snapshot composer, and the per-host subscription registry that enforces the
// D72 one-subscriber-per-host topology. A zero Service is not usable; construct
// with NewService.
//
// askResolver / askRouter are the OPTIONAL ask-routing seams the INBOUND-ask fold
// (RouteInboundAsk) drives through ResolveAndRoute: the approver resolution
// (launching-user default + D45 allow-always org-admin escalation) and the
// gate+attribute write. Both are satisfied directly by *store.Memory /
// *store.Postgres; a test pairs synthetic fakes (D50). They are threaded onto the
// Service so that NO inbound-ask call-site can route an allow-always except through
// the org-admin-resolving fold — the D45 footgun (handing the LAUNCHING USER as the
// approver for an allow-always) is closed structurally because the seam the Service
// exposes (RouteInboundAsk) routes ONLY through ResolveAndRoute, never the bare
// ApproveAsk. They are ADDITIVE: NewService auto-detects them from the store when it
// satisfies the seams, and WithAskRouting wires them explicitly; when unset the
// inbound-ask fold is reported unavailable (ErrAskRoutingUnavailable) and every other
// leg (AppendPolicy / WatchPolicies / the thin ApproveAsk wrapper) is unchanged.
type Service struct {
	store    policyStore
	composer SnapshotComposer
	now      func() time.Time

	askResolver askApproverResolver // optional: the inbound-ask approver resolution seam (nil ⇒ fold unavailable)
	askRouter   askRouter           // optional: the inbound-ask gate+attribute write seam (nil ⇒ fold unavailable)

	mu      sync.Mutex
	subs    map[string]struct{} // host_id → live subscription (D72: at most one per host)
	maxScan int                 // replay page cap; 0 = the default
}

// NewService constructs a PolicyService over a store seam and a snapshot
// composer. now defaults to time.Now (override in tests to pin grant liveness).
//
// The inbound-ask routing seams (askResolver / askRouter) are AUTO-DETECTED from the
// store: when st ALSO satisfies askApproverResolver and askRouter (both *store.Memory
// and *store.Postgres do), the inbound-ask fold (RouteInboundAsk) is armed against the
// SAME persisted store, with NO change to the existing two-argument signature — so
// every landed NewService caller compiles unchanged. A narrowed store (e.g. the
// policy_log-only seam main.go type-asserts) that satisfies neither leaves the fold
// unavailable; WithAskRouting wires it explicitly in that case. Either way the
// AppendPolicy / WatchPolicies / ApproveAsk legs are unaffected.
func NewService(st policyStore, composer SnapshotComposer, opts ...ServiceOption) *Service {
	s := &Service{
		store:    st,
		composer: composer,
		now:      time.Now,
		subs:     make(map[string]struct{}),
		maxScan:  defaultReplayPage,
	}
	// Auto-detect the inbound-ask seams off the store (the no-config common case:
	// *store.Memory / *store.Postgres satisfy both, so the fold is armed against the
	// same persisted backend without the caller wiring anything).
	if r, ok := st.(askApproverResolver); ok {
		s.askResolver = r
	}
	if r, ok := st.(askRouter); ok {
		s.askRouter = r
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// ServiceOption configures an OPTIONAL Service seam at construction. With no option
// the Service behaves exactly as the two-argument NewService (the inbound-ask fold is
// auto-detected off the store, every other leg unchanged) — the additive extension
// point that keeps the NewService signature stable.
type ServiceOption func(*Service)

// WithAskRouting injects the inbound-ask routing seams EXPLICITLY: the approver
// resolution (launching-user default + D45 allow-always org-admin escalation) and the
// gate+attribute write. It is the wiring point when the store handed to NewService is
// NARROWED past the resolver/router seams (so auto-detection found nothing) but a full
// store is available to drive the fold — or when a test pairs synthetic fakes (D50).
// A nil resolver or router leaves that half unset (the fold then reports unavailable);
// passing both arms RouteInboundAsk against them.
func WithAskRouting(resolver askApproverResolver, router askRouter) ServiceOption {
	return func(s *Service) {
		if resolver != nil {
			s.askResolver = resolver
		}
		if router != nil {
			s.askRouter = router
		}
	}
}

// defaultReplayPage bounds one replay page. The policy_log write volume is
// trivial single-table Postgres at the ~500-host checkpoint (doc 15 §5.3), so a
// generous page keeps catch-up to one round-trip in practice while still bounding
// an unbounded scan.
const defaultReplayPage = 1024

// SetClock overrides the service clock (test seam for grant-liveness evaluation).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// AppendPolicy is the §5.3 authored-append leg (D36): it records the actor and
// appends the row, the store assigning the bigserial seq (THE single policy
// version namespace, D72). An empty actor is refused with ErrActorRequired before
// the write — the log is the audit trail, so a row with no attribution never
// lands. The row's Kind defaults to PolicyKindAppend (an ordinary composed-policy
// edit); ask-grant appends ride ApproveAsk, never this leg.
func (s *Service) AppendPolicy(ctx context.Context, row store.PolicyLogRow) (store.PolicyLogRow, error) {
	if row.Actor == "" {
		return store.PolicyLogRow{}, ErrActorRequired
	}
	if row.Kind == "" {
		row.Kind = store.PolicyKindAppend
	}
	appended, err := s.store.AppendPolicy(ctx, row)
	if err != nil {
		return store.PolicyLogRow{}, fmt.Errorf("append policy by %q: %w", row.Actor, err)
	}
	return appended, nil
}

// ApproveAsk is the §4.3 ask-grant append leg for an ALREADY-RESOLVED approver,
// surfaced on the service so the three RPCs sit behind one type. It is the THIN
// wrapper for callers that have already resolved who approves (the approver
// principal is handed in directly): the approver's MayApprove role gates the write
// (a non-approver is refused with ErrNotApprover, NO row written) and the approver
// lands in the row Actor (D36). The grant is TTL'd and session-scoped (POL-5).
//
// It is ADDITIVE and STAYS for already-resolved-approver callers. It is NOT the
// inbound-ask entry: a raw INBOUND ask (whose approver must be RESOLVED — the
// launching-user default, or the D45 org-admin acceptor for an allow-always) MUST go
// through RouteInboundAsk, which routes exclusively through ResolveAndRoute so no
// call-site can attribute an allow-always to the launching user (the D45 footgun).
// This wrapper trusts its caller to have done that resolution already.
func (s *Service) ApproveAsk(
	ctx context.Context,
	approver store.Principal,
	sessionUUID, rule string,
	expiresAt store.OptTime,
	consent store.ConsentClass,
	payload []byte,
) (store.PolicyLogRow, error) {
	return ApproveAsk(ctx, s.store, approver, sessionUUID, rule, expiresAt, consent, payload)
}

// ErrAskRoutingUnavailable is returned by RouteInboundAsk when the inbound-ask
// routing seams are not wired: the Service was constructed over a store that does
// not satisfy askApproverResolver / askRouter and no WithAskRouting option supplied
// them. The fold cannot resolve an approver without them, so it fails closed rather
// than silently degrading to the bare ApproveAsk (which would reintroduce the D45
// launching-user footgun the fold exists to close).
var ErrAskRoutingUnavailable = errors.New("policylog: inbound-ask routing seams not wired (need an askApproverResolver + askRouter — NewService over a full store, or WithAskRouting)")

// RouteInboundAsk is the INBOUND-ask entry on the Service (doc 15 §4.3 / §6.2 step 4,
// doc 16 §8.2, D45): it routes a raw, frozen, one-way boundaryv1.AskUserRequest whose
// approver is NOT yet resolved through the ATTRIBUTION-PRESERVING fold and returns the
// resolution + the policy-log write outcome. It drives ResolveAndRoute over the seams
// threaded onto the Service — never the three steps individually and never the bare
// ApproveAsk — so the approver the write attributes is ALWAYS the one ResolveAskRouting
// resolved: the launching user for allow-once / a genuine ask, the org-admin acceptor
// for an allow-always (D45). There is NO path through this seam that lets an
// allow-always be attributed to the launching user, which is exactly the footgun the
// fold closes (a hand-built AskRouting can name the wrong approver; ResolveAndRoute
// removes that opportunity — the only AskRouting it routes is the one
// AskRoutingFromResolution stamps from the resolution).
//
// The decision is passed ONCE and used for both halves (approver resolution +
// allow-vs-deny dispatch), so resolution and routing can never be computed for two
// different choices. attended is the passed-in D78 signal (the §8.2 dispatch target is
// resolved off it). body (GrantBody) carries WHAT is granted — the matched rule, TTL,
// reserved consent class, payload, and any D77/D118 deny reason — never WHO grants it.
//
// It is ADDITIVE: it adds no contract surface beyond ResolveAndRoute's and leaves the
// thin ApproveAsk wrapper untouched for already-resolved-approver callers. When the
// seams are not wired it fails closed with ErrAskRoutingUnavailable (never a silent
// fallback to the bare ApproveAsk). A fail-closed resolution error (no session / no
// default approver / no eligible org-admin) short-circuits before any write; the
// returned result then carries the routing outcome (Granted/Denied + the appended row)
// verbatim from ResolveAndRoute.
func (s *Service) RouteInboundAsk(
	ctx context.Context,
	ask *boundaryv1.AskUserRequest,
	decision AskDecision,
	attended Attendedness,
	body GrantBody,
) (AskResolution, AskRoutingResult, error) {
	if s.askResolver == nil || s.askRouter == nil {
		return AskResolution{}, AskRoutingResult{}, ErrAskRoutingUnavailable
	}
	return ResolveAndRoute(ctx, s.askResolver, s.askRouter, ask, decision, attended, body)
}

// SnapshotEmitter is the per-frame sink WatchPolicies drives: one call per
// composed snapshot, in ascending seq order. The gRPC adapter satisfies it by
// sending each frame on the server stream (wrapping the snapshot in the
// boundary.v1 WatchPoliciesResponse); a test satisfies it by collecting frames.
// Returning an error stops the replay (the stream closed / the consumer aborted).
type SnapshotEmitter interface {
	Emit(ctx context.Context, snap Snapshot) error
}

// EmitterFunc adapts a function to SnapshotEmitter.
type EmitterFunc func(ctx context.Context, snap Snapshot) error

// Emit calls the function.
func (f EmitterFunc) Emit(ctx context.Context, snap Snapshot) error { return f(ctx, snap) }

// WatchPolicies is the §5.3 / D72 replay-serving leg: it opens the ONE
// subscription for hostID (refusing a second with ErrHostAlreadySubscribed),
// then replays composed snapshots from fromSeq to the emitter in ascending seq
// order. Each frame is the deny-overrides composed document (snapshot identity
// (seq, content_hash, composed policy), doc 13 §5) — never raw layers. Replay is
// idempotent: re-subscribing at the same fromSeq emits the same snapshots, so a
// host that reconnects with its persisted applied_seq catches up exactly from
// there (D36 catch-up). fromSeq = 0 replays from the start.
//
// The subscription is released when WatchPolicies returns (the host disconnects
// or the replay completes), so a reconnect after a clean disconnect is admitted —
// only a CONCURRENT second subscriber for the same host is refused (D72). This
// leg replays the CURRENT log to the cursor; the live tail (new appends after
// catch-up) is the substrate's push fan-out, JetStream-swappable behind this same
// contract (D36) and out of scope for the replay leg.
func (s *Service) WatchPolicies(ctx context.Context, hostID string, fromSeq int64, emit SnapshotEmitter) error {
	if hostID == "" {
		return fmt.Errorf("policylog: WatchPolicies requires a host_id (D72 subscriber identity)")
	}
	if err := s.acquireSub(hostID); err != nil {
		return err
	}
	defer s.releaseSub(hostID)

	cursor := fromSeq
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, err := s.store.ListPolicy(ctx, cursor, s.maxScan)
		if err != nil {
			return fmt.Errorf("replay policy_log from seq %d for host %q: %w", cursor, hostID, err)
		}
		if len(rows) == 0 {
			return nil // caught up: the replay leg streams the log to the cursor, no more
		}
		for _, r := range rows {
			snap, err := s.composeUpTo(ctx, r.Seq)
			if err != nil {
				return fmt.Errorf("compose snapshot at seq %d for host %q: %w", r.Seq, hostID, err)
			}
			if err := emit.Emit(ctx, snap); err != nil {
				return err // the emitter aborted (stream closed / consumer NACK)
			}
			cursor = r.Seq
		}
		if len(rows) < s.maxScan {
			return nil // last (partial) page consumed: caught up
		}
	}
}

// composeUpTo builds the composed snapshot AT seq: it reads every policy_log row
// up to and including seq (ascending) and delegates the deny-overrides compose to
// the SnapshotComposer, evaluating grant liveness against the service clock. The
// snapshot a host applies at version N is the composition of the whole log
// through N (doc 13 §5 — the composed document, not the single appended row), so
// the watch stream carries cumulative composed state, never per-row deltas.
func (s *Service) composeUpTo(ctx context.Context, seq int64) (Snapshot, error) {
	rows, err := s.store.ListPolicy(ctx, 0, 0) // whole log; trivial volume (doc 15 §5.3)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read policy_log through seq %d: %w", seq, err)
	}
	upTo := make([]store.PolicyLogRow, 0, len(rows))
	for _, r := range rows {
		if r.Seq > seq {
			break // rows are ascending; stop at the watch frame's version
		}
		upTo = append(upTo, r)
	}
	return s.composer.ComposeAt(ctx, seq, upTo, s.now())
}

// acquireSub registers the one subscription for hostID, refusing a second
// (D72). It is the topology gate: at most one live WatchPolicies stream per host.
func (s *Service) acquireSub(hostID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, live := s.subs[hostID]; live {
		return ErrHostAlreadySubscribed
	}
	s.subs[hostID] = struct{}{}
	return nil
}

// releaseSub drops the subscription for hostID so a clean reconnect is admitted.
func (s *Service) releaseSub(hostID string) {
	s.mu.Lock()
	delete(s.subs, hostID)
	s.mu.Unlock()
}
