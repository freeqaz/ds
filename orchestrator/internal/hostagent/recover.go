package hostagent

// This file implements the host-agent restart re-adoption (doc 15 §5.1/§5.6):
// after a host-agent restart, the agent RE-OBSERVES rather than replaying an RPC
// chain (the D35 level-triggered contract, internal/reconciler/doc.go). It
// reconstructs the ObservedSession list — the SAME shape the steady-state
// heartbeat carries — from PERSISTED host-side handles, and restores the
// persistent monotonic per-host index counter so the next allocation never
// re-uses a burned index within the flow-log retention window (D66).
//
// The control plane is NOT the source of truth for the host's running set on
// restart: D6 keeps control-plane state in external Postgres (never on hosts),
// but the host's own adopted-handle ledger and index counter are LOCAL host
// state. The reconciler converges the re-observed set against the desired state
// in Postgres (the §3 conflict rules) — re-adoption only re-establishes what the
// host is actually running, honestly.

import (
	"context"
	"fmt"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// PersistedHandle is one host-side handle the agent wrote when it brought a
// session up (doc 15 §5.6) — the durable record that lets a restarted agent
// re-adopt the session without the control plane. It is the persisted projection
// of the CloneFromImageResponse binding (host_session_index / tap_name /
// overlay_path) plus the session/domain identity and the last observed §3 state.
//
// It is LOCAL host state, written through the HandleStore seam; it is NOT the
// control-plane session record (internal/store fronts that — D6).
type PersistedHandle struct {
	// SessionUUID is the orchestrator session this handle backs (the reconciler
	// key). REQUIRED — a handle with no session identity cannot be re-adopted.
	SessionUUID string

	// DomainUUID is the hypervisor-local domain/instance id the agent re-attaches
	// to on restart (the libvirt domain, the EC2 instance — substrate-specific,
	// opaque to the contract).
	DomainUUID string

	// HostSessionIndex is the never-recycled per-host index (D66) allocated from
	// the persistent monotonic counter. It SURVIVES restart in this handle, which
	// is also how RestoreCounter learns the high-water mark.
	HostSessionIndex uint64

	// TapName is dstap-<idx>, derived deterministically from the index (D44/D66);
	// persisted so re-adoption re-binds the existing tap, never allocates a new
	// one.
	TapName string

	// OverlayPath is the qcow2 overlay (D29) — the delta store + durability unit;
	// persisted so re-adoption re-opens the existing overlay.
	OverlayPath string

	// ObservedState is the last §3 state the agent recorded for this session
	// before the restart (incl. PARKED + D77 SUSPENDED(reason)). On re-adoption it
	// seeds the ObservedSession the heartbeat carries; the reconciler converges it
	// against the desired state. A zero (UNSPECIFIED) state is allowed — the agent
	// re-probes and the reconciler quarantines an un-pin-downable VM (§3).
	ObservedState *attachv1.SessionState
}

// HandleStore is the host-LOCAL persistence the re-adoption reads on restart and
// the allocator writes on bring-up (doc 15 §5.6). It is a SEAM (an interface,
// like the libvirt driver's pinned-later binding): a test fake satisfies it
// in-memory; the real on-host impl (a local durable store — NOT control-plane
// Postgres, D6) is owner-landed. Data crosses as PersistedHandle, never an
// on-disk type.
type HandleStore interface {
	// ListHandles returns every persisted handle for this host — the agent's
	// running set as of the last write before restart. An error fails re-adoption
	// loudly rather than presenting an empty set as "no sessions" (which would
	// orphan running VMs).
	ListHandles(ctx context.Context, hostID string) ([]PersistedHandle, error)
}

// RecoverSessions runs the host-agent restart re-adoption (doc 15 §5.1): it reads
// the persisted host-side handles and reconstructs the ObservedSession list the
// reconciler consumes (the SAME shape the steady-state heartbeat carries, §5.2).
//
// This is the HOST-side implementation of the hypervisor.v1 RecoverSessions verb
// (driver_grpc): the driver, after a restart, enumerates the sessions it is still
// running from these persisted handles. It re-observes; it never replays — the
// D35 level-triggered contract (internal/reconciler/doc.go).
//
// req.host_id scopes the read; an empty host_id is rejected (a re-adoption with
// no host key cannot distinguish this host's handles from another's).
func RecoverSessions(ctx context.Context, store HandleStore, req *hypervisorv1.RecoverSessionsRequest) (*hypervisorv1.RecoverSessionsResponse, error) {
	hostID := req.GetHostId()
	if hostID == "" {
		return nil, fmt.Errorf("hostagent: RecoverSessions: empty host_id")
	}

	handles, err := store.ListHandles(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("hostagent: RecoverSessions: list persisted handles for host %q: %w", hostID, err)
	}

	sessions := make([]*hypervisorv1.ObservedSession, 0, len(handles))
	for i := range handles {
		sessions = append(sessions, observedFromHandle(handles[i]))
	}
	return &hypervisorv1.RecoverSessionsResponse{Sessions: sessions}, nil
}

// ObservedFromHandles reconstructs the ObservedSession list a heartbeat carries
// from persisted handles — the steady-state path's bridge from re-adoption. It
// is the same projection RecoverSessions uses, exported so the heartbeat
// StateSource can seed its first post-restart Observed list from the re-adopted
// set without re-deriving the mapping.
func ObservedFromHandles(handles []PersistedHandle) []*hypervisorv1.ObservedSession {
	out := make([]*hypervisorv1.ObservedSession, 0, len(handles))
	for i := range handles {
		out = append(out, observedFromHandle(handles[i]))
	}
	return out
}

// observedFromHandle maps one persisted handle to the SHARED
// hypervisor.v1.ObservedSession element (§5.1/§5.2) — the single mapping both
// RecoverSessions and ObservedFromHandles go through, so re-adoption and the
// heartbeat can never project a handle two different ways.
func observedFromHandle(h PersistedHandle) *hypervisorv1.ObservedSession {
	return &hypervisorv1.ObservedSession{
		SessionUuid:      h.SessionUUID,
		DomainUuid:       h.DomainUUID,
		HostSessionIndex: h.HostSessionIndex,
		TapName:          h.TapName,
		OverlayPath:      h.OverlayPath,
		ObservedState:    h.ObservedState,
	}
}

// RestoreCounter recovers the persistent monotonic per-host index high-water mark
// from the re-adopted handles (doc 15 §5.6). The host_session_index is allocated
// from a persistent monotonic counter and is BURNED, NEVER RECYCLED within the
// flow-log retention window (D66); on restart the counter must resume ABOVE every
// index still in use so the next allocation cannot collide with a re-adopted
// session.
//
// It returns the next index to hand out: one past the highest re-adopted index
// (so the first post-restart allocation is strictly greater than any live one).
// With no handles it returns 1 — index 0 is reserved as "unallocated" (the proto
// zero value), so the first real index a fresh host hands out is 1.
//
// NOTE this restores the counter to AT LEAST the live high-water mark; the
// authoritative never-recycle window is wider (the full flow-log retention
// window, D66 — past indices of DESTROYED sessions are still burned). The durable
// counter the HandleStore persists is the real source of the next value across
// the retention window; RestoreCounter is the floor that guarantees no collision
// with a CURRENTLY-running session even if the durable counter read is lost.
func RestoreCounter(handles []PersistedHandle) uint64 {
	var high uint64
	for i := range handles {
		if handles[i].HostSessionIndex > high {
			high = handles[i].HostSessionIndex
		}
	}
	return high + 1
}
