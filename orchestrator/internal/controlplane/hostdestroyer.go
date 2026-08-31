package controlplane

// hostdestroyer.go is the SEAM-LEVEL wiring of the host-agent's owned §4.2
// destroy ordering (doc 15 §4.2) into the control plane, for the M0
// orchestrator-lite posture (D80: orchestrator-lite IS the OSS single-host
// all-in-one binary — create/attach/destroy in one process). It complements the
// gRPC-RPC-driving `hostDestroyer` (seams.go), which routes the frozen
// hypervisor.v1 Destroy verb to a REMOTE host's driver over the wire; THIS
// adapter drives the IN-PROCESS host-agent §4.2 orchestrator
// (internal/hostagent.Destroyer) directly when the host agent runs in the same
// binary as the control plane.
//
// THE TWO DESTROY EDGES (one §4.2 ordering, two transports):
//
//   - REMOTE (multi-host / paid fleet, M3): the control plane sends the frozen
//     hypervisor.v1 Destroy(session_uuid) verb to the placed host's driver
//     (`hostDestroyer{reg}` in seams.go); the host agent THERE runs the §4.2
//     ordering (domain destroy → unconditional flush_session(legs=all) + NFT-6 →
//     overlay disposal + durability finalize → digest flush → identity/CA revoke
//     → DESTROYED heartbeat). The wire verb is host-folded — there is no
//     distinct per-§4.2-step RPC; the host owns the ordering (the same
//     host-folded posture as the CA-inject/boot steps, doc 15 §4.1).
//   - IN-PROCESS (orchestrator-lite single host, M0): the host agent's §4.2
//     orchestrator (hostagent.Destroyer) is constructed in the SAME binary, so
//     this adapter drives it directly — no gRPC dial, no loopback. The frozen
//     ordering is identical; only the transport collapses.
//
// WHY THIS LIVES HERE (the wiring tree). internal/hostagent owns the §4.2
// orchestration (the digest flush / identity revoke / DESTROYED report seams)
// and internal/hypervisor/libvirt owns the host-local teardown (the
// NFT-6-conformant domain/flush/overlay steps); THIS package — the control-plane
// capstone — is the one place those are assembled for the single-binary posture,
// keeping the wiring a thin bootstrap. The legal cross-tree import stays
// proto/gen/go; this adapter imports only sibling orchestrator/internal packages.
//
// (b)-CONFORMANCE (doc 06 §3b / NFT-6, doc 09 §3): the host-agent §4.2 ordering
// this adapter drives leaves the ruleset byte-identical to bootstrap across a
// create→destroy loop run N times — asserted against the RecordingBackend in
// internal/hostagent's destroy conformance test (the fake/RecordingBackend, NOT
// the cgo ds-nft bridge — DS_NFTGATE_LIVE stays disabled, the live-metal binding
// is a separately-tracked follow-up). No live KVM/metal/podman.

import (
	"context"
	"errors"
	"fmt"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// Compile-time proof that the in-process §4.2 destroy adapter satisfies the
// create-coordinator's compensating-rollback seam — so a single-binary wiring can
// inject it where seams.go's remote hostDestroyer{reg} would go (both satisfy the
// same sessions.HostDestroyer; the create coordinator and reconciler are unchanged).
var _ sessions.HostDestroyer = (*inProcessHostDestroyer)(nil)

// HostAgentDestroyer is the narrow §4.2-ordering face the in-process adapter
// drives — exactly the host-agent orchestrator's Destroy verb (hostagent.Destroyer
// satisfies it). Declared as a seam so the adapter is unit-testable against a
// recording fake AND the real hostagent.Destroyer interchangeably (the
// constructible-component discipline this package follows for every host-side
// seam).
type HostAgentDestroyer interface {
	// Destroy runs the full host-agent §4.2 teardown for the session, idempotent
	// on session_uuid (doc 15 §4.2). The request carries the recorded host-side
	// state to unwind (binding / domain / overlay) and the identity/CA refs to
	// revoke.
	Destroy(ctx context.Context, req hostagent.DestroyRequest) (hostagent.DestroyResult, error)
}

// inProcessHostDestroyer drives the IN-PROCESS host-agent §4.2 orchestrator for
// the orchestrator-lite single-host posture (D80). It satisfies sessions.
// HostDestroyer (the create-coordinator's compensating-rollback seam) AND the
// reconciler's host-resolved destroy by mapping the narrow (hostID, sessionUUID)
// seam onto the full hostagent.DestroyRequest, resolving the recorded host-side
// state from the session record store.
//
// It is the single-binary counterpart of seams.go's `hostDestroyer{reg}`: the
// latter sends the wire verb to a remote host; this one drives the local host
// agent. A wiring picks ONE based on whether the host agent is in-process
// (orchestrator-lite) or remote (fleet) — both satisfy the same sessions.
// HostDestroyer seam, so the create coordinator and reconciler are unchanged.
type inProcessHostDestroyer struct {
	agent HostAgentDestroyer
	recs  destroyStateLookup
}

// destroyStateLookup is the narrow read the in-process destroyer uses to resolve
// the recorded host-side state (binding / domain / overlay / identity refs) for a
// session from the record store — the state the full §4.2 teardown unwinds. The
// control-plane store satisfies it; a miss (no record) drives a binding-less
// teardown (the unconditional flush_session still converges to a no-op, D68).
type destroyStateLookup interface {
	DestroyState(ctx context.Context, sessionUUID string) (hostagent.DestroyRequest, bool, error)
}

// newInProcessHostDestroyer assembles the single-host §4.2 destroy adapter. A nil
// agent or lookup is a programming error surfaced at construction.
func newInProcessHostDestroyer(agent HostAgentDestroyer, recs destroyStateLookup) (*inProcessHostDestroyer, error) {
	if agent == nil {
		return nil, fmt.Errorf("controlplane: in-process host destroyer requires a host-agent destroyer")
	}
	if recs == nil {
		return nil, fmt.Errorf("controlplane: in-process host destroyer requires a destroy-state lookup")
	}
	return &inProcessHostDestroyer{agent: agent, recs: recs}, nil
}

// Destroy satisfies sessions.HostDestroyer: it resolves the recorded host-side
// state for the session and drives the in-process host-agent §4.2 teardown. The
// hostID argument scopes the resolution (and the index-burn ledger for a
// rollback); an unresolvable record drives a binding-less teardown so the
// unconditional flush_session still runs (D68 — a teardown can never leak by
// being skipped). Idempotent on session_uuid.
func (d *inProcessHostDestroyer) Destroy(ctx context.Context, hostID, sessionUUID string) error {
	req, ok, err := d.recs.DestroyState(ctx, sessionUUID)
	if err != nil {
		return fmt.Errorf("controlplane: resolve destroy state for %s: %w", sessionUUID, err)
	}
	if !ok {
		// No recorded host-side state: drive the UNCONDITIONAL flush anyway (D68)
		// so a session whose record is gone still has its NFT objects torn down to
		// a no-op convergence — never a leak.
		req = hostagent.DestroyRequest{SessionUUID: sessionUUID, HostID: hostID}
	}
	req.SessionUUID = sessionUUID
	req.HostID = hostID
	if _, err := d.agent.Destroy(ctx, req); err != nil {
		return fmt.Errorf("controlplane: in-process §4.2 destroy of %s on %s: %w", sessionUUID, hostID, err)
	}
	return nil
}

// destroyRecordStore is the narrow read the store-backed destroyStateLookup needs:
// fetch the §5.6 session record (the authoritative recorded host-side state the
// §4.2 teardown unwinds). The single ControlPlaneStore satisfies it natively (it
// is a slice of GetSession), so backing the lookup with the REAL session-record
// store adds no method to any store interface (the storeseams discipline).
type destroyRecordStore interface {
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
}

// storeDestroyStateLookup backs the in-process destroyer's destroyStateLookup with
// the REAL session-record store (doc 15 §5.6): it resolves the recorded host-side
// state (the current-epoch binding, the identity/CA refs to revoke) from the
// persisted record so the in-process §4.2 teardown unwinds exactly what the create
// recorded. A missing record (store.ErrNotFound) is reported as a clean MISS (ok =
// false) so the destroyer drives the UNCONDITIONAL flush anyway (D68 — a teardown
// can never leak by being skipped), never an error.
type storeDestroyStateLookup struct{ recs destroyRecordStore }

// DestroyState resolves the recorded §4.2 teardown input for a session from the
// store record. The current-epoch binding (the live NFT/tap objects to unwind)
// rides the open IndexEpoch (EndedAt nil); the index/tap fall back to the record's
// Ref quartet when no epoch history was written yet. The identity/CA refs carry the
// minted workload identity + interception CA to revoke (empty when the session
// never reached §4.1 step 5 — then the revoke is a no-op). A record with NO host
// binding (HostSessionIndex 0, no tap) reports HasBinding false so the byte-count
// emission + index burn are skipped while the unconditional flush still runs.
func (l storeDestroyStateLookup) DestroyState(ctx context.Context, sessionUUID string) (hostagent.DestroyRequest, bool, error) {
	rec, err := l.recs.GetSession(ctx, sessionUUID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// No record: a clean miss drives the binding-less unconditional flush (D68),
			// never an error that would strand the teardown.
			return hostagent.DestroyRequest{}, false, nil
		}
		return hostagent.DestroyRequest{}, false, fmt.Errorf("controlplane: read session record for destroy %s: %w", sessionUUID, err)
	}
	return destroyRequestFromRecord(rec), true, nil
}

// destroyRequestFromRecord maps the §5.6 session record onto the host-agent §4.2
// DestroyRequest. The current-epoch binding (the host-side allocation to unwind)
// is resolved from the open IndexEpoch when present, else from the record's Ref +
// the create-time guest address; a binding is recorded only when a host index/tap
// exists (a pre-binding record drives the binding-less unconditional flush, D68).
func destroyRequestFromRecord(rec store.Session) hostagent.DestroyRequest {
	req := hostagent.DestroyRequest{
		SessionUUID: rec.Ref.SessionUUID,
		HostID:      rec.Ref.HostID,
		IdentityRef: rec.IdentityRef,
		CARef:       rec.CARef,
	}

	// Resolve the live (current-epoch) binding: the open IndexEpoch (EndedAt nil) on
	// the resident host carries the current host index / tap / guest IP / overlay; an
	// older closed epoch is a prior (migrated/parked) binding already unwound, so it
	// is skipped. Absent any epoch history (a record that never recorded an epoch
	// row) the binding falls back to the record's Ref quartet.
	idx := rec.Ref.HostSessionIndex
	tap := rec.Ref.TapName
	var guestIP []byte
	var guestFamily store.IPFamily
	var overlay string
	for i := range rec.IndexHistory {
		e := rec.IndexHistory[i]
		if e.EndedAt != nil || e.HostID != rec.Ref.HostID {
			continue
		}
		idx = e.HostSessionIndex
		tap = e.TapName
		guestIP = e.GuestIP
		guestFamily = e.GuestIPFamily
		// Read the PERSISTED per-session CoW overlay path (D29) off the open epoch so a
		// destroy after a control-plane RESTART disposes the REAL overlay — before this
		// the overlay was never persisted and the teardown always drove OverlayPath="",
		// leaking the overlay (the M0 durability gap). The open epoch on the resident
		// host carries the live overlay; a closed (migrated/parked) epoch is skipped above.
		overlay = e.OverlayPath
	}

	if idx != 0 || tap != "" {
		req.HasBinding = true
		req.Binding = libvirt.Binding{
			HostSessionIndex: idx,
			TapName:          tap,
			GuestIP: libvirt.GuestAddress{
				Family:  guestAddressFamily(guestFamily),
				Address: guestIP,
			},
			OverlayPath: overlay,
		}
		req.OverlayPath = overlay
	}
	return req
}

// guestAddressFamily maps the store's family-agnostic IPFamily tag (D75) onto the
// libvirt.AddressFamily the host-agent teardown carries. An unset family is the
// unspecified zero value (a binding with no recorded guest address — the flush is
// unconditional regardless, D68).
func guestAddressFamily(f store.IPFamily) libvirt.AddressFamily {
	switch f {
	case store.IPFamilyV4:
		return libvirt.AddressFamilyIPv4
	case store.IPFamilyV6:
		return libvirt.AddressFamilyIPv6
	default:
		return libvirt.AddressFamilyUnspecified
	}
}

// Compile-time proof the store-backed lookup satisfies the in-process destroyer's
// narrow destroyStateLookup seam.
var _ destroyStateLookup = storeDestroyStateLookup{}
