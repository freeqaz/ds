package hostagent

// This file assembles and streams the host-agent Heartbeat (doc 15 §5.2,
// dreamserpent.hostagent.v1). Two halves:
//
//   - BuildHeartbeat composes ONE frame from host-side inputs — the observed
//     sessions, the three boundary consumers' health (whose applied_seq inputs
//     fold into the D72 min-over-three top-level AppliedSeq), capacity, samples,
//     baseline version, and image-cache digest.
//   - Stream opens the long-lived client-streaming RPC and emits a frame per
//     cadence tick until the context ends (graceful host drain), then closes and
//     reads the close-path ReportHeartbeatResponse.
//
// The cadence (strawman 5 s) and the close behavior are rig-tuned values, never
// frozen here (doc 15 §10); only the SHAPE the frame carries is frozen at M0.

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// DefaultCadence is the strawman heartbeat interval (doc 15 §5.2: 5 s, free). It
// is a rig-tuned VALUE, never frozen — a deployment overrides it via
// StreamConfig.Cadence; this constant only names the documented strawman so a
// caller that wants the default need not re-derive it.
const DefaultCadence = 5 * time.Second

// BoundaryServiceName is one of the three host-side policy consumers whose
// per-consumer applied_seq feeds the D72 min-over-three. Naming them as typed
// constants keeps the Heartbeat.boundary list and the AppliedSeq min from
// drifting on a typo'd free-text name.
const (
	BoundaryDNSGate   = "ds-dnsgate"
	BoundaryTLSProxy  = "ds-tlsproxy"
	BoundaryNFTWriter = "nft-writer"
)

// SnapshotReason is the PRODUCER-side separation of a dropped/withheld committed
// version's cause (doc 13 §5.1), carried host-ward in the heartbeat so the
// SchemaFailure-vs-ContentHashMismatch separability the dataplane drop sink already
// has does not stop at the in-process dataplane drop. The host-local feed PRODUCER
// (feedwriter.go) classifies each version it is asked to fan out into one of these;
// the token is surfaced via the free-text ServiceHealth.Detail (the rig-tuned
// diagnostic field, never frozen), NOT a new wire enum — widening the proto
// SnapshotDropReason enum is additive and freeze-gated (proto/FREEZE.md), so this
// producer reserves the SEAM only and rides the existing free-text carrier.
//
// The string forms MUST match the dataplane consumer's SnapshotDropReason tokens
// (dataplane/services/ds-dnsgate/src/event.rs as_str: "content_hash_mismatch" /
// "schema_failure") so an operator reading the host-ward heartbeat sees the SAME
// reason vocabulary the dataplane drop telemetry emits — one token namespace across
// the producer (Go) and consumer (Rust) halves, the §5.1 separability end to end.
type SnapshotReason int

const (
	// ReasonNone is a version that fanned out cleanly (or a benign forward-only
	// dedup) — no drop reason to surface. It stamps no Detail token.
	ReasonNone SnapshotReason = iota

	// ReasonSchemaFailure is a verified-but-unusable version: its produce-once
	// carrier holds no transportable document (it never composed / does not parse).
	// Mirrors SnapshotDropReason::SchemaFailure ("schema_failure") — distinct from a
	// tampered-transport hash mismatch so the operator does not read a schema defect
	// as a content_hash tamper (doc 13 §5.1).
	ReasonSchemaFailure

	// ReasonContentHashMismatch is a torn carrier: the transported bytes do not match
	// the separately-transported content_hash (the §5.1 identity tuple is
	// inconsistent). Mirrors SnapshotDropReason::ContentHashMismatch
	// ("content_hash_mismatch").
	ReasonContentHashMismatch
)

// reasonToken is the cross-language string vocabulary the Go producer and the Rust
// consumer share for a dropped/withheld version's cause — the SAME tokens
// SnapshotDropReason::as_str emits in the dataplane (event.rs), so the host-ward
// heartbeat Detail and the dataplane drop telemetry read one namespace.
func (r SnapshotReason) reasonToken() string {
	switch r {
	case ReasonSchemaFailure:
		return "schema_failure"
	case ReasonContentHashMismatch:
		return "content_hash_mismatch"
	default:
		return ""
	}
}

// String returns the operator-facing token for r ("schema_failure" /
// "content_hash_mismatch"), or "none" for a clean version — the diagnostic an
// operator queries on the heartbeat.
func (r SnapshotReason) String() string {
	if t := r.reasonToken(); t != "" {
		return t
	}
	return "none"
}

// DetailFor renders the ServiceHealth.Detail diagnostic for a consumer that
// dropped/withheld a version at seq for reason r, or "" for ReasonNone (a clean
// version stamps no Detail — the field stays empty, its prior behavior). The format
// is "<reason_token> at seq <seq>" so the operator reading the heartbeat sees BOTH
// the separable cause AND the version it bit on, carried host-ward without widening
// the frozen proto enum (the token rides this free-text field, doc 13 §5.1).
func (r SnapshotReason) DetailFor(seq uint64) string {
	t := r.reasonToken()
	if t == "" {
		return ""
	}
	return fmt.Sprintf("%s at seq %d", t, seq)
}

// HostState is the host-side snapshot BuildHeartbeat folds into one frame. It is
// the agent's view of the world at one instant — the reconciler's input (§3).
// Every field maps to exactly one frozen Heartbeat field (doc 15 §5.2); nothing
// here invents a second namespace.
type HostState struct {
	// HostID identifies this host (Heartbeat.host_id). REQUIRED — a heartbeat
	// without a host identity has no reconciler key.
	HostID string

	// Observed is every session the host is running right now, as the SHARED
	// hypervisor.v1.ObservedSession element (§5.1/§5.2). The SAME list shape
	// RecoverSessions reconstructs on restart (recover.go), so the reconciler
	// reads one type across re-adoption and steady state.
	Observed []*hypervisorv1.ObservedSession

	// Boundary is the per-consumer health of the three host-side policy consumers
	// (ds-dnsgate / ds-tlsproxy / nft-writer). Each carries that consumer's OWN
	// applied policy seq — the per-consumer input to the D72 min-over-three that
	// BuildHeartbeat folds into the top-level AppliedSeq. The agent-unreachable
	// enforcement plane stays default-deny when any of these is DOWN (§5.2).
	Boundary []*hostagentv1.ServiceHealth

	// Capacity is the scheduler's floors-fit headroom (D37). Optional: a frame may
	// omit it (nil) when the agent has not yet computed it.
	Capacity *hostagentv1.HostCapacity

	// Samples is the per-session RSS/CPU/IO series (D37), wired from M0; it feeds
	// the short-retention rollup, NEVER the billing meter (§5.6).
	Samples []*hostagentv1.SessionSample

	// HostBaselineVersion is the doc 14 §11 host-baseline artifact version — only
	// the version STRING is echoed; the artifact contents never ride this seam (or
	// the policy stream).
	HostBaselineVersion string

	// ImageCacheDigest is the digest of the host's warm image cache, for the
	// cache-locality placement feed (§5.2).
	ImageCacheDigest string
}

// AppliedSeq is the FROZEN D72 host-ward policy version: the MIN over the THREE
// NAMED host-side policy consumers' applied_seq (BoundaryDNSGate /
// BoundaryTLSProxy / BoundaryNFTWriter), advancing ONLY post-sweep (doc 15 §5.2;
// doc 13 §1 rule 3). It is the single policy version namespace echoed host-ward —
// never a second namespace.
//
// Semantics this enforces so the wire value can never lie:
//
//   - The min is over EXACTLY the three named consumers, looked up by
//     ServiceHealth.name in the boundary list. A consumer that is ABSENT from
//     the list has NOT proven it applied anything — it contributes 0, EXACTLY
//     like a present-but-not-HEALTHY consumer (the missing-consumer clamp). So a
//     boundary list that does not contain all three names HEALTHY yields 0; a
//     2-of-3 list returns 0, NEVER the min over the present subset (that would
//     falsely claim a host swept on a consumer that never reported).
//   - With no consumers reporting (nil/empty), all three are absent, so the min
//     is 0 — the unschedulable floor D36 reads, never a vacuous "max uint" that
//     would falsely claim the host is fully swept.
//   - A consumer that is PRESENT but not HEALTHY has NOT proven it applied its
//     reported seq; its contribution is clamped to 0 so a DEGRADED/DOWN/
//     UNSPECIFIED consumer drags the min DOWN (fail-closed), it never lets a
//     stale-but-high number from a sick consumer inflate the host's claimed
//     applied_seq.
//   - Entries with an UNRECOGNIZED name (not one of the three) are ignored for
//     the min; they still ride Heartbeat.boundary for diagnostics, but they can
//     never raise or lower the host-ward applied_seq.
//
// This is the ONE place the min is computed; BuildHeartbeat calls it so the
// Heartbeat top-level AppliedSeq and the per-consumer Boundary list cannot
// silently diverge.
func AppliedSeq(boundary []*hostagentv1.ServiceHealth) uint64 {
	// The three NAMED consumers the D72 min is taken over. Each starts at 0 (its
	// missing-consumer clamp): a consumer only earns a non-zero contribution by
	// appearing in the list AND being HEALTHY.
	contrib := map[string]uint64{
		BoundaryDNSGate:   0,
		BoundaryTLSProxy:  0,
		BoundaryNFTWriter: 0,
	}
	for _, sh := range boundary {
		name := sh.GetName()
		if _, named := contrib[name]; !named {
			// Unrecognized name — ignored for the min (still rides boundary for
			// diagnostics).
			continue
		}
		// A present consumer that is not HEALTHY has not proven application —
		// clamp its contribution to 0 (fail-closed), never trust its reported seq.
		if sh.GetState() == hostagentv1.HealthState_HEALTH_STATE_HEALTHY {
			contrib[name] = sh.GetAppliedSeq()
		}
	}
	min := contrib[BoundaryDNSGate]
	for _, name := range []string{BoundaryTLSProxy, BoundaryNFTWriter} {
		if contrib[name] < min {
			min = contrib[name]
		}
	}
	return min
}

// BuildHeartbeat composes one Heartbeat frame from the host-side snapshot (doc
// 15 §5.2). It derives the top-level AppliedSeq from the boundary list via the
// frozen D72 min-over-three (AppliedSeq above) — the caller never sets it by
// hand, so the top-level value and the per-consumer list cannot drift.
//
// It is a pure assembly: no I/O, no clock — the caller stamps timestamps onto
// samples before handing the snapshot in. That keeps the frame deterministic and
// unit-testable, and keeps the streaming loop (Stream) the only place a clock
// lives.
func BuildHeartbeat(state HostState) *hostagentv1.Heartbeat {
	return &hostagentv1.Heartbeat{
		HostId:              state.HostID,
		AppliedSeq:          AppliedSeq(state.Boundary),
		Observed:            state.Observed,
		Capacity:            state.Capacity,
		Samples:             state.Samples,
		HostBaselineVersion: state.HostBaselineVersion,
		ImageCacheDigest:    state.ImageCacheDigest,
		Boundary:            state.Boundary,
	}
}

// StateSource is the host agent's live view of itself, queried once per cadence
// tick. It is a SEAM (an interface, like the libvirt driver's pinned-later
// binding): the real agent reads cgroup/process samples, observed domains, and
// boundary-service health from the host; a test fake returns a fixed snapshot.
// The data crosses as the in-package HostState, never an on-host type.
type StateSource interface {
	// Snapshot returns the host's current state, or an error if the agent cannot
	// observe itself this tick. An error SKIPS the tick (a missed beat — the
	// reconciler's 3-missed-beats rule, never a fabricated empty frame).
	Snapshot(ctx context.Context) (HostState, error)
}

// HeartbeatSender opens the client-streaming heartbeat RPC. It is satisfied
// natively by the generated hostagentv1.HostAgentServiceClient and identically
// by a test fake, so Stream is exercised without a live grpc dial. The data
// crosses as the generated request/response types (proto/gen/go — the one legal
// cross-tree shape).
type HeartbeatSender interface {
	Send(*hostagentv1.ReportHeartbeatRequest) error
	CloseAndRecv() (*hostagentv1.ReportHeartbeatResponse, error)
}

// HeartbeatDialer opens one heartbeat stream. The generated client's
// ReportHeartbeat satisfies it; a test fake returns an in-memory sender.
//
// The ctx handed to OpenHeartbeat is the RPC's HARD-CANCEL lifetime — the stream
// stays alive until THIS ctx is cancelled, NOT until the caller's drain signal
// fires. Stream deliberately opens the RPC on a context detached from the drain
// trigger (context.WithoutCancel) so the close-path CloseAndRecv runs while the
// underlying RPC is still alive; see Stream's doc for why.
type HeartbeatDialer interface {
	OpenHeartbeat(ctx context.Context) (HeartbeatSender, error)
}

// clientDialer wires the GENERATED grpc client (the production path) into the
// HeartbeatDialer seam: OpenHeartbeat opens the real client-streaming RPC on the
// ctx it is handed (the RPC's hard-cancel lifetime), and the returned
// grpc.ClientStreamingClient satisfies HeartbeatSender natively (Send /
// CloseAndRecv) — the compile-time assertion below proves it, so the fake the
// tests use and the production client are interchangeable.
type clientDialer struct {
	client hostagentv1.HostAgentServiceClient
}

// NewClientDialer adapts the generated HostAgentServiceClient into a
// HeartbeatDialer for Stream. The host agent constructs the client from a UDS
// gRPC dial (the §5.2 default local transport) and hands it here; the streaming
// loop then drives it through the same seam the tests exercise with a fake.
//
// Stream opens the RPC on a context detached from its DRAIN signal, so a graceful
// drain reaches CloseAndRecv with the gRPC stream still alive (a cancel of the
// open ctx would kill the stream and make CloseAndRecv fail Canceled — exactly
// the production bug the detach avoids).
func NewClientDialer(client hostagentv1.HostAgentServiceClient) HeartbeatDialer {
	return clientDialer{client: client}
}

func (d clientDialer) OpenHeartbeat(ctx context.Context) (HeartbeatSender, error) {
	stream, err := d.client.ReportHeartbeat(ctx)
	if err != nil {
		return nil, err
	}
	// The generated grpc.ClientStreamingClient is a superset of HeartbeatSender
	// (it adds the embedded ClientStream Context/Header/Trailer surface Stream
	// never touches); it satisfies the seam directly.
	return stream, nil
}

// StreamConfig tunes the streaming loop. Cadence is the rig-tuned interval
// (doc 15 §10) — zero means DefaultCadence; nothing here is frozen.
type StreamConfig struct {
	Cadence time.Duration
}

// Stream runs the host agent's heartbeat loop (doc 15 §5.2): it opens ONE
// long-lived client stream and emits a frame per cadence tick until ctx ends
// (graceful host drain), then closes and reads the close-path response.
//
// Drain vs. hard-cancel — the RPC is opened on a context DETACHED from ctx's
// cancellation (context.WithoutCancel). ctx is used ONLY as the loop's DRAIN
// SIGNAL: when it ends, the loop stops emitting, calls CloseAndRecv while the
// underlying RPC is STILL ALIVE, and returns the close-path response. If the RPC
// were opened on ctx directly, cancelling ctx for a graceful drain would tear
// the gRPC stream down first, so CloseAndRecv would always fail Canceled in
// production. The detached open ctx is cancelled (rpcCancel) only as the RPC's
// HARD-CANCEL — on the close-path's own failure, or after the drain response is
// in hand — so a leaked RPC is never left running, while a clean drain still
// reaches a live stream. (A caller that needs a hard cancel that DOES tear the
// RPC mid-flight can still get one by tearing its own dial; ctx here is the
// graceful path.)
//
// A snapshot error SKIPS the tick (a missed beat) rather than tearing the stream
// down or sending a fabricated empty frame — the reconciler's 3-missed-beats
// rule is what handles a sustained gap, and a transient self-observation failure
// must not present as "no sessions". A Send error DOES end the loop: the stream
// is broken, so the agent returns and the caller re-dials (the reconnect policy
// is the caller's, rig-tuned).
//
// It returns the close-path ReportHeartbeatResponse (beats_received) on graceful
// drain, so the caller can log the count the orchestrator acked.
func Stream(ctx context.Context, dialer HeartbeatDialer, src StateSource, cfg StreamConfig) (*hostagentv1.ReportHeartbeatResponse, error) {
	cadence := cfg.Cadence
	if cadence <= 0 {
		cadence = DefaultCadence
	}

	// Open the RPC on a context detached from ctx's cancellation so a graceful
	// drain (ctx.Done) does NOT kill the stream before CloseAndRecv runs. rpcCancel
	// is the RPC's hard-cancel, fired only to tear a leaked/failed stream down —
	// never as the drain trigger.
	rpcCtx, rpcCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer rpcCancel()

	sender, err := dialer.OpenHeartbeat(rpcCtx)
	if err != nil {
		return nil, fmt.Errorf("hostagent: open heartbeat stream: %w", err)
	}

	ticker := time.NewTicker(cadence)
	defer ticker.Stop()

	emit := func() (bool, error) {
		// Snapshot reads on ctx (the drain/cancel signal): a drain mid-snapshot is
		// a missed beat, not a torn stream.
		state, err := src.Snapshot(ctx)
		if err != nil {
			// Skip the tick — a missed beat, not a torn stream (see doc above).
			return false, nil
		}
		if err := sender.Send(&hostagentv1.ReportHeartbeatRequest{Heartbeat: BuildHeartbeat(state)}); err != nil {
			return false, fmt.Errorf("hostagent: send heartbeat: %w", err)
		}
		return true, nil
	}

	// Emit one frame immediately so the orchestrator sees the host as soon as the
	// stream opens, rather than after a full cadence interval of silence.
	if _, err := emit(); err != nil {
		return nil, err
	}

	for {
		select {
		case <-ctx.Done():
			// Graceful drain: stop emitting and close the send side while the RPC
			// (opened on the detached rpcCtx) is still alive, then read the
			// close-path response.
			resp, err := sender.CloseAndRecv()
			if err != nil {
				return nil, fmt.Errorf("hostagent: close heartbeat stream: %w", err)
			}
			return resp, nil
		case <-ticker.C:
			if _, err := emit(); err != nil {
				return nil, err
			}
		}
	}
}

// Compile-time proof that the GENERATED grpc client stream satisfies the
// HeartbeatSender seam: the production client (clientDialer.OpenHeartbeat) and
// the test fake are therefore interchangeable behind Stream. If a proto/grpc
// regen ever changed the stream shape, this assertion fails the build rather
// than letting the production wiring rot silently.
var _ HeartbeatSender = grpc.ClientStreamingClient[hostagentv1.ReportHeartbeatRequest, hostagentv1.ReportHeartbeatResponse](nil)
