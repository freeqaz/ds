package controlplane

// seams.go supplies the PRODUCTION host-side seams the §4.1 create coordinator
// (internal/sessions.SessionCreator) and the level-triggered reconciler
// (internal/reconciler) drive — the hypervisor.v1 gRPC-backed adapters that turn
// a per-host HypervisorDriverService client (the host agent's driver face, doc 15
// §5.1) into the narrow, package-owned interfaces those components consume as DATA.
//
// WHY THIS LIVES HERE (the wiring tree, not the sessions/reconciler trees). The
// sessions package owns the create-choreography seams (HostAllocator, Minter,
// DigestWriter, Injector, Booter, AttachIssuer, HostDestroyer, IdentityRevoker —
// sessioncreate.go) but deliberately does NOT build their production impls (it is
// the constructible coordinator, fenced from main.go). The reconciler owns the
// Driver seam (reconciler.go) likewise. THIS package — the control-plane capstone
// — is the one place those production impls are assembled, so the wiring is a thin
// bootstrap (main.go) over a unit-tested constructor here.
//
// THE ONLY LEGAL CROSS-TREE IMPORT IS proto/gen/go (CLAUDE.md). The host agent /
// libvirt driver lives in another tree; the orchestrator reaches it ONLY through
// the frozen hypervisor.v1 generated client interface. So every adapter here holds
// a HypervisorDriverServiceClient (the generated client face — the gRPC dial is
// constructed in main.go; the generated FAKE satisfies it natively in tests, D50)
// and carries the frozen proto request/response MESSAGES as DATA. No host-agent
// package import, no live VM/host-agent/podman — the seams COMPILE against the real
// gRPC client and are EXERCISED in tests via the generated fake + synthetic
// fixtures, exactly the session-create/reconciler/scheduler discipline.
//
// HOST-SCOPED DRIVERS (the per-host client contract). The driver client is
// PER-HOST: the create coordinator's HostAllocator/Booter/etc. and the reconciler's
// Driver both name a host and the wiring resolves it to that host's driver client.
// A DriverRegistry (below) is the resolution seam — main.go supplies one that dials
// each host's driver; tests supply one returning the generated fake.

import (
	"context"
	"errors"
	"fmt"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/scheduler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// DriverClient is the per-host hypervisor.v1 driver face the production seams call.
// It is exactly the subset of the generated HypervisorDriverServiceClient the create
// coordinator + reconciler drive (clone, attach, suspend, destroy), declared narrow
// HERE with the GENERATED-FAKE method shape (no `opts ...grpc.CallOption` tail) so the
// generated fake satisfies it NATIVELY in tests (D50) — the fake's methods are
// `CloneFromImage(ctx, req)` etc. The real generated gRPC client (whose methods carry
// the `opts ...grpc.CallOption` tail) is adapted onto this seam by the thin clientShim
// (wiring.go), which main.go wraps each dialed host client in. So a live gRPC client
// and the fake are interchangeable behind DriverClient, the gRPC dependency confined
// to main.go's dial + the shim.
type DriverClient interface {
	CloneFromImage(ctx context.Context, in *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error)
	IssueAttachHandle(ctx context.Context, in *hypervisorv1.IssueAttachHandleRequest) (*hypervisorv1.IssueAttachHandleResponse, error)
	Suspend(ctx context.Context, in *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error)
	Destroy(ctx context.Context, in *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error)
}

// GrantSuspendSink is the NARROW injected §11.2 suspend-signal seam the reconciler-facing
// Suspend routing hands the MAPPED eviction cause to (doc 16 §11.2). It exists so the
// grant-service's active eviction records the DIRECTED reason instead of the bare
// Suspend(sessionUUID) shim's implicit SUSPEND_REASON_USER (the scope this closes:
// today grant-service eviction rides the bare shim, so even a POLICY_BREACH BIC
// suspension records as USER). D80 IS THE SHAPE: the orchestrator NEVER imports
// identity/grant-service — this interface is declared in terms of proto/gen/go types
// ONLY (attachv1.SuspendReason, already imported here) and is satisfied at composition
// OUTSIDE the orchestrator binary by the grant-service's EXISTING
// SuspendWithReason(sessionUUID, reason) surface (service.go — signature already
// matches). The concrete binding is a service-boundary concern, not wired here. A NIL
// sink is a NO-OP (registryDriver.Suspend fires it only when set), so default
// construction (wiring.go's registryDriver{reg,recs}) and behavior are byte-unchanged.
// The recorded cause is a NON-SECRET classification (doc 16 §5.2), never credential
// material.
type GrantSuspendSink interface {
	SuspendWithReason(sessionUUID string, reason attachv1.SuspendReason)
}

// suspendReasonToAttach maps the frozen hypervisor.v1 SuspendReason (the wire cause the
// driver's Suspend verb carries, driver.proto) onto the frozen attach.v1 SuspendReason
// (the read-only §3 projection the grant-service records, doc 16 §5.2). The mapping is
// EXHAUSTIVE over the four D77-narrowed values and READ-ONLY over BOTH frozen enums (D80:
// proto/gen/go the only cross-tree import — no re-declare, no new enum, no proto edit):
// USER→USER, POLICY_BREACH→POLICY_BREACH, REBALANCE→REBALANCE. UNSPECIFIED (and any
// unknown) maps to USER to match the bare-shim posture (the bare Suspend(sessionUUID)
// eviction records USER today). This preserves the D35 split EXACTLY downstream:
// POLICY_BREACH is the genuine-threat class that gates resume on an approval attestation,
// while USER/REBALANCE/UNSPECIFIED keep the existing Resume path (doc 15 §3) — USER is
// NOT made to fail closed and no attestation is invented for it.
func suspendReasonToAttach(r hypervisorv1.SuspendReason) attachv1.SuspendReason {
	switch r {
	case hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH:
		return attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH
	case hypervisorv1.SuspendReason_SUSPEND_REASON_REBALANCE:
		return attachv1.SuspendReason_SUSPEND_REASON_REBALANCE
	case hypervisorv1.SuspendReason_SUSPEND_REASON_USER:
		return attachv1.SuspendReason_SUSPEND_REASON_USER
	default:
		// UNSPECIFIED and any unrecognized value collapse to USER, the bare-shim posture.
		return attachv1.SuspendReason_SUSPEND_REASON_USER
	}
}

// DriverRegistry resolves a host_id to its per-host DriverClient (doc 15 §5.1: one
// driver per virtual-metal host). The create coordinator names the PLACED host and
// the reconciler holds a per-host driver — both resolve through this seam. In
// production main.go supplies a registry that dials/caches each host's driver gRPC
// face; in tests a registry returns the generated fake for every host (D50). A miss
// (unknown host) is an error the caller surfaces — the create rolls back, the
// reconcile absorbs it into an alarm.
type DriverRegistry interface {
	// DriverFor returns the driver client for hostID, or an error if no driver is
	// registered/reachable for it.
	DriverFor(ctx context.Context, hostID string) (DriverClient, error)
	// Hosts returns the host_ids the registry currently knows a driver for. It is the
	// fleet enumeration the reconciler's host-agnostic Driver verbs (a quarantine of an
	// orphan VM whose host the interface does not carry) broadcast over: an idempotent
	// Suspend/Destroy on session_uuid is safe to issue to every host's driver, the host
	// that actually runs the session servicing it and the rest no-opping.
	Hosts(ctx context.Context) ([]string, error)
}

// ErrNoDriverForHost is the registry miss: no driver is registered/reachable for the
// host. The create coordinator's host-side step surfaces it (rollback from that step);
// the reconciler absorbs it into a degraded/alarm path rather than destroying a record
// on a transient driver-reach fault.
var ErrNoDriverForHost = errors.New("controlplane: no hypervisor driver registered for host")

// ---------------------------------------------------------------------------
// §4.1 create-coordinator host-side seams (sessions.* interfaces), all backed by
// the per-host DriverClient via the DriverRegistry. Each carries the frozen proto
// messages as DATA; none imports a host-agent package.
// ---------------------------------------------------------------------------

// hostAllocator satisfies sessions.HostAllocator (§4.1 step 4): it drives
// CloneFromImage on the placed host (the host agent allocates the never-recycled
// index, derives dstap-<idx> + the guest IP, invokes the boundary tap-create
// primitive, instantiates the per-session NFT objects, clones the overlay) and maps
// the frozen CloneFromImageResponse onto the coordinator's HostAllocation binding.
type hostAllocator struct{ reg DriverRegistry }

// AllocateAndDefine drives the placed host's CloneFromImage and returns the binding.
func (a hostAllocator) AllocateAndDefine(ctx context.Context, hostID string, spec *hypervisorv1.VmSpec) (sessions.HostAllocation, error) {
	drv, err := a.reg.DriverFor(ctx, hostID)
	if err != nil {
		return sessions.HostAllocation{}, fmt.Errorf("controlplane: host-allocate on %s: %w", hostID, err)
	}
	resp, err := drv.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{Spec: spec})
	if err != nil {
		return sessions.HostAllocation{}, fmt.Errorf("controlplane: CloneFromImage on %s: %w", hostID, err)
	}
	if resp == nil {
		return sessions.HostAllocation{}, fmt.Errorf("controlplane: CloneFromImage on %s returned nil response", hostID)
	}
	return sessions.HostAllocation{
		HostSessionIndex: resp.GetHostSessionIndex(),
		TapName:          resp.GetTapName(),
		GuestIP:          resp.GetGuestIp().GetAddress(),
		GuestIPFamily:    ipFamilyFromProto(resp.GetGuestIp().GetFamily()),
		OverlayPath:      resp.GetOverlayPath(),
	}, nil
}

// ipFamilyFromProto maps the frozen hypervisor.v1 AddressFamily onto the store's
// family tag (D75: family-agnostic bytes + family enum, never assume IPv4).
func ipFamilyFromProto(f hypervisorv1.AddressFamily) store.IPFamily {
	switch f {
	case hypervisorv1.AddressFamily_ADDRESS_FAMILY_IPV4:
		return store.IPFamilyV4
	case hypervisorv1.AddressFamily_ADDRESS_FAMILY_IPV6:
		return store.IPFamilyV6
	default:
		return store.IPFamilyUnspecified
	}
}

// attachIssuer satisfies sessions.AttachIssuer (§4.1 step 10): it issues the attach
// handle for a READY session via the placed host's IssueAttachHandle verb, mapping the
// store's seat class onto the frozen attach.v1.Role and recording the issued seat.
type attachIssuer struct{ reg DriverRegistry }

// IssueAttach drives the host's IssueAttachHandle and returns the issued seat class.
func (i attachIssuer) IssueAttach(ctx context.Context, sessionUUID, hostID string, role store.AttachRole) (sessions.AttachIssued, error) {
	drv, err := i.reg.DriverFor(ctx, hostID)
	if err != nil {
		return sessions.AttachIssued{}, fmt.Errorf("controlplane: attach-issue on %s: %w", hostID, err)
	}
	if _, err := drv.IssueAttachHandle(ctx, &hypervisorv1.IssueAttachHandleRequest{
		SessionUuid: sessionUUID,
		Role:        attachRoleToProto(role),
	}); err != nil {
		return sessions.AttachIssued{}, fmt.Errorf("controlplane: IssueAttachHandle on %s: %w", hostID, err)
	}
	return sessions.AttachIssued{Role: role}, nil
}

// attachRoleToProto maps the store seat class onto the frozen attach.v1.Role
// (D61 one-writer/N-reader). RoleNone defaults to WRITER (the launching attach takes
// the one writer seat — the coordinator already defaults this, kept robust here).
func attachRoleToProto(role store.AttachRole) attachv1.Role {
	switch role {
	case store.RoleReader:
		return attachv1.Role_ROLE_READER
	default:
		return attachv1.Role_ROLE_WRITER
	}
}

// hostDestroyer satisfies sessions.HostDestroyer (the §4.2 compensating rollback):
// it drives the placed host's Destroy verb (libvirt domain destroy →
// flush_session(legs=all) + NFT-6 → overlay disposal), idempotent on session_uuid.
type hostDestroyer struct{ reg DriverRegistry }

// Destroy drives the host's idempotent Destroy verb.
func (d hostDestroyer) Destroy(ctx context.Context, hostID, sessionUUID string) error {
	drv, err := d.reg.DriverFor(ctx, hostID)
	if err != nil {
		return fmt.Errorf("controlplane: host-destroy on %s: %w", hostID, err)
	}
	if _, err := drv.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: sessionUUID}); err != nil {
		return fmt.Errorf("controlplane: Destroy on %s: %w", hostID, err)
	}
	return nil
}

// Compile-time proof that the production adapters satisfy the §4.1 coordinator's
// host-side seams (sessioncreate.go) — so NewControlPlane can inject them.
var (
	_ sessions.HostAllocator = hostAllocator{}
	_ sessions.AttachIssuer  = attachIssuer{}
	_ sessions.HostDestroyer = hostDestroyer{}
)

// ---------------------------------------------------------------------------
// reconciler.Driver — the convergence-action seam (Suspend to quarantine an
// orphan VM; Destroy to teardown a no-VM record / DESTROYING record). The frozen
// reconciler.Driver verbs name a session, not a host, so registryDriver (below)
// resolves the host from the record store and routes through the per-host registry,
// broadcasting the idempotent verb for an orphan whose host the interface omits.
//
// OPTIONAL HOST HINT (the host-scoped targeting seam, D35/D66). For an ORPHAN VM
// (§3 rule a — no record), the host is unknown to the frozen reconciler.Driver
// interface, so the fallback below BROADCASTS the idempotent verb to every
// registered host's driver. That fan-out is fine at orchestrator-lite single-host
// density but is a fleet-wide Suspend/Destroy ping at the ~500-host virtual-metal
// density the D37 v0 density model sizes for — every host driver pinged to quarantine
// one orphan. The targeting MECHANISM that avoids it is the per-host HypervisorDriver
// contract (D35: one driver per virtual-metal host) keyed on the host/index binding (D66:
// the dstap-<host-local session index> join key recorded in the session record),
// so naming one host routes to exactly its driver instead of the fleet. Yet the
// reconciler ALREADY knows which host reported the orphan: the heartbeat carries
// the reporting host_id (doc 15 §4.2), and reconcileHost threads it as hostID.
// WithQuarantineHostHint lets that caller carry the reporting host on the request
// context WITHOUT widening the frozen reconciler.Driver signature (the verbs still
// name only a session) or the frozen hypervisor.v1 SuspendRequest / DestroyRequest
// wire messages. The hint is OPTIONAL and ADDITIVE: absent, routing is unchanged
// (record lookup, else broadcast — fully backwards-compatible); present, runVerb
// resolves that one host's driver and targets it, collapsing the O(fleet) fan-out
// to the single host that observed the orphan (D35 per-host driver contract, D66
// host/index binding). A hint to a host with no registered driver surfaces
// ErrNoDriverForHost — the reconciler absorbs it into an alarm/retry rather than
// silently falling back to a broadcast, since a hint names a definite target.
// ---------------------------------------------------------------------------

// quarantineHostHintKey is the unexported context key under which a caller carries
// the OPTIONAL reporting-host hint for a quarantine/destroy verb. Unexported +
// typed so no other package can collide with or forge the key (the value is set
// only via WithQuarantineHostHint and read only by quarantineHostHint).
type quarantineHostHintKeyType struct{}

var quarantineHostHintKey quarantineHostHintKeyType

// WithQuarantineHostHint returns a child context carrying hostID as the OPTIONAL
// target for the next quarantine (Suspend) / teardown (Destroy) verb run through a
// registryDriver. It is the seam-level host-targeting knob (D35 per-host driver
// contract, D66 host/index binding): the reconciler knows the reporting host_id
// from the heartbeat that surfaced an orphan (doc 15 §4.2) and threads it here so
// the idempotent verb targets that one host's driver instead of fanning out across
// the fleet at the ~500-host density the D37 v0 density model sizes for. An empty hostID is
// treated as "no hint" — the context is returned unchanged so callers can pass the
// reporting host unconditionally and keep the absent-hint broadcast behavior when
// they have no host to name. The frozen reconciler.Driver verbs and the frozen
// hypervisor.v1 request messages are untouched: the hint rides the context only,
// purely additive and backwards-compatible.
func WithQuarantineHostHint(ctx context.Context, hostID string) context.Context {
	if hostID == "" {
		return ctx
	}
	return context.WithValue(ctx, quarantineHostHintKey, hostID)
}

// quarantineHostHint reads the OPTIONAL host hint a caller attached via
// WithQuarantineHostHint, reporting "" + false when absent (the broadcast/record
// path then runs unchanged). The value is always the string set by the constructor,
// so the type assertion cannot pick up a foreign value (the key is unexported).
func quarantineHostHint(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	hostID, ok := ctx.Value(quarantineHostHintKey).(string)
	if !ok || hostID == "" {
		return "", false
	}
	return hostID, true
}

// effectiveQuarantineHostHint is the PRODUCTION BRIDGE that turns the orphan-quarantine
// fast path ON in prod (doc 15 §4.2). The reporting-host hint reaches runVerb from two
// stamping seams that key it under DIFFERENT unexported context keys:
//
//   - controlplane.WithQuarantineHostHint stamps THIS package's quarantineHostHintKey,
//     read directly by quarantineHostHint above; and
//   - reconciler.WithQuarantineHostHint stamps the RECONCILER's own unexported key (it
//     cannot import controlplane — that is the controlplane → reconciler → controlplane
//     cycle the reconciler seam header calls out, so it owns its OWN key and exports
//     QuarantineHostHint for the importing tree to honor).
//
// The REAL production caller is the reconciler's quarantineOrphan (conflict.go), which
// stamps reconciler.WithQuarantineHostHint with the reporting host_id the heartbeat that
// surfaced the orphan carries (doc 15 §4.2). Before this bridge, runVerb consulted ONLY
// controlplane's own key, so a reconciler-stamped hint NEVER reached prod and an orphan
// quarantine still fleet-broadcast at the ~500-host D37 v0 density the model sizes for.
// This bridge has runVerb ALSO consult the reconciler-stamped hint: reconciler STAMPS,
// controlplane HONORS. controlplane's own hint wins when both are present (a direct
// WithQuarantineHostHint caller keeps precedence); the reconciler hint is the fallback
// that lights the prod path. Absent BOTH, "" + false leaves the record-resolve / broadcast
// routing unchanged — purely additive and backwards-compatible (the frozen
// reconciler.Driver verbs and the frozen hypervisor.v1 request messages are untouched).
func effectiveQuarantineHostHint(ctx context.Context) (string, bool) {
	if hostID, ok := quarantineHostHint(ctx); ok {
		return hostID, true
	}
	return reconciler.QuarantineHostHint(ctx)
}

// registryDriver satisfies reconciler.Driver fleet-wide: the reconciler's Suspend /
// Destroy verbs name a session_uuid but NOT a host (the §3 conflict rules drive them
// with only the session). For a session that has a RECORD (rule b / a regression), the
// host is read from the record store and the verb routed to that host's driver. For an
// ORPHAN VM (rule a quarantine — no record), the host is unknown to the interface, so
// the idempotent verb is BROADCAST to every registered host's driver: the host that
// runs the session services it, the rest no-op (every verb is idempotent on
// session_uuid, doc 15 §5.1). This keeps the reconciler's host-agnostic Driver contract
// satisfiable over the per-host driver registry without widening the frozen reconciler
// seam.
type registryDriver struct {
	reg  DriverRegistry
	recs sessionHostLookup
	// grantSink is the OPTIONAL injected §11.2 suspend-signal sink (doc 16 §11.2): when
	// set, a routed Suspend hands it the MAPPED attach.v1 cause so the grant-service
	// eviction records the DIRECTED reason instead of the bare-shim USER. It is a narrow
	// proto-only interface bound at composition OUTSIDE this binary (D80). NIL is a
	// NO-OP, so default construction (wiring.go's registryDriver{reg,recs}) and behavior
	// are byte-unchanged.
	grantSink GrantSuspendSink
}

// sessionHostLookup is the narrow read the fleet driver uses to resolve a session's
// host from the record store (GetSession). The control-plane store satisfies it; a
// miss (orphan) falls to the broadcast path.
type sessionHostLookup interface {
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
}

// Suspend routes a Suspend by session (resolve the host from the record, else broadcast)
// AND — when a §11.2 grant sink is injected — hands the grant-service the MAPPED eviction
// cause so its active eviction records the DIRECTED reason (doc 16 §11.2 / §5.4) rather
// than the bare Suspend(sessionUUID) shim's implicit USER. The hypervisor verb routing
// itself is untouched: the sink is an ADDITIVE side signal fired once per routed Suspend,
// carrying suspendReasonToAttach(req.reason) (POLICY_BREACH stays POLICY_BREACH;
// USER/REBALANCE/UNSPECIFIED → USER, the bare-shim posture). A NIL sink is a NO-OP, so
// with no sink injected the routing and behavior are byte-unchanged. The sink fires
// regardless of the hypervisor verb outcome so the grant eviction stays fail-closed on
// the suspend signal (a subsequent fetch fails closed, eviction behavior UNCHANGED).
func (d registryDriver) Suspend(ctx context.Context, req *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error) {
	resp, err := runVerb(ctx, d, req.GetSessionUuid(),
		func(drv DriverClient) (*hypervisorv1.SuspendResponse, error) { return drv.Suspend(ctx, req) })
	if d.grantSink != nil {
		d.grantSink.SuspendWithReason(req.GetSessionUuid(), suspendReasonToAttach(req.GetReason()))
	}
	return resp, err
}

// Destroy routes a Destroy by session: resolve the host from the record, else broadcast.
func (d registryDriver) Destroy(ctx context.Context, req *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
	return runVerb(ctx, d, req.GetSessionUuid(),
		func(drv DriverClient) (*hypervisorv1.DestroyResponse, error) { return drv.Destroy(ctx, req) })
}

// runVerb routes a quarantine/teardown verb to a driver and runs it. Resolution
// order, all idempotent on session_uuid:
//
//  1. OPTIONAL host hint (controlplane.WithQuarantineHostHint OR the reconciler-stamped
//     reconciler.WithQuarantineHostHint, bridged via effectiveQuarantineHostHint) — when
//     the caller named the reporting host (the heartbeat that surfaced the orphan carries
//     it, doc 15 §4.2), the verb targets that ONE host's driver, NEVER a fleet broadcast.
//     This is the host-scoped targeting knob (D35 per-host driver contract, D66
//     host/index binding): the orphan-reap that would otherwise fan out across
//     every host driver collapses to the single host that observed it (the
//     fleet-broadcast cost this avoids is the ~500-host density the D37 v0 density
//     model sizes for). A hint to an unregistered host is ErrNoDriverForHost — a named
//     target that cannot be reached is surfaced, not silently broadened to a
//     broadcast.
//  2. Recorded host — a session that HAS a record (rule b / a regression) resolves
//     its host from the record store and routes there.
//  3. Broadcast fallback — an orphan with no hint and no record (the host is
//     unknown to the frozen reconciler.Driver interface) broadcasts the idempotent
//     verb to every registered host's driver, returning the first success.
//
// A total failure surfaces the last error so the reconciler retries/alarms. The
// hint is purely additive: omit it and the record/broadcast behavior is unchanged.
func runVerb[R any](ctx context.Context, d registryDriver, sessionUUID string, run func(DriverClient) (R, error)) (R, error) {
	var zero R
	// (1) OPTIONAL host hint: target the one host the reconciler named, no broadcast.
	// effectiveQuarantineHostHint bridges BOTH stamping seams — controlplane's own
	// WithQuarantineHostHint and the reconciler-stamped reconciler.WithQuarantineHostHint
	// (the real production caller, conflict.go) — so a reconciler-stamped hint reaches
	// prod and lights the fast path (reconciler STAMPS, controlplane HONORS).
	if hostID, ok := effectiveQuarantineHostHint(ctx); ok {
		drv, derr := d.reg.DriverFor(ctx, hostID)
		if derr != nil {
			return zero, fmt.Errorf("%w: %s", ErrNoDriverForHost, hostID)
		}
		return run(drv)
	}
	if d.recs != nil && sessionUUID != "" {
		if rec, err := d.recs.GetSession(ctx, sessionUUID); err == nil && rec.Ref.HostID != "" {
			drv, derr := d.reg.DriverFor(ctx, rec.Ref.HostID)
			if derr != nil {
				return zero, fmt.Errorf("%w: %s", ErrNoDriverForHost, rec.Ref.HostID)
			}
			return run(drv)
		}
	}
	// Orphan / no recorded host: broadcast the idempotent verb to the fleet.
	hosts, err := d.reg.Hosts(ctx)
	if err != nil {
		return zero, fmt.Errorf("controlplane: reconcile driver: enumerate hosts: %w", err)
	}
	if len(hosts) == 0 {
		return zero, ErrNoDriverForHost
	}
	var lastErr error
	for _, h := range hosts {
		drv, derr := d.reg.DriverFor(ctx, h)
		if derr != nil {
			lastErr = derr
			continue
		}
		if r, rerr := run(drv); rerr == nil {
			return r, nil
		} else {
			lastErr = rerr
		}
	}
	if lastErr == nil {
		lastErr = ErrNoDriverForHost
	}
	return zero, lastErr
}

// ---------------------------------------------------------------------------
// §4.1 step-9 LIVE freshness probe (D72) — the production HostFreshness seam over the
// live latest-per-host heartbeat feed.
//
// THE WINDOW THIS CLOSES (D72 step-9). The create coordinator's step-9 routable gate
// re-validates the placed host's freshness before the session goes routable. The
// recorded-only re-check (recheckFreshness) re-reads the host's RECORDED applied_seq,
// which catches a reconciler-marked-stale host but NOT a host that fell behind in the
// placement→step-9 window with no record write. The scheduler.Adapter's optional
// HostFreshness seam (placer.go) re-probes the host's CURRENT applied_seq from the live
// feed to close that residual window — but with no HostFreshness assigned the probe
// returns sessions.ErrFreshnessUnknown and the gate DEGRADES to the recorded-only
// re-check, so the window-closing path is inert. heartbeatFreshness (below) is the
// production seam that makes it live: it reads the host's current applied_seq from the
// SAME latest-per-host HeartbeatStore feed StoreCandidateSource already places against,
// so a placement and a step-9 re-check agree on what a host last reported.
//
// ONE FEED, NOW THREE READERS. The HeartbeatStore (heartbeatstore.go) is the single
// live view of a host: the SCHEDULER's StoreCandidateSource reads it at placement, the
// RECONCILER's Resync reads it for convergence, and now the §4.1 step-9 re-check reads
// it through this adapter. All three read the SAME snapshot, so the create that placed a
// session, the reconcile that converges it, and the step-9 gate that makes it routable
// share one notion of the host's current freshness.
//
// O(1) HOST-KEYED POINT READ (the store-side narrow query). The freshness probe is a
// SINGLE-host lookup, not a fleet assembly: it resolves one placed host's snapshot by
// host_id and reads its applied_seq, through the additive store.HostAppliedSeq query
// (the store's HostAppliedSeqSource narrow seam — NO Repository method, NO shared-store
// edit, the PolicyHead discipline). The live HeartbeatStore now exposes that point read
// DIRECTLY: it keys its latest-per-host set by host_id, so its SnapshotForHost accessor is
// a true O(1) map hit (heartbeatstore.go) — *HeartbeatStore satisfies HostAppliedSeqSource
// natively. CurrentAppliedSeq drives store.HostAppliedSeq over that accessor when the feed
// provides it, so the create hot-path freshness probe is a map lookup, not an O(fleet)
// index-then-filter — which at the ~500-host virtual-metal density the D37 v0 density model
// sizes for keeps the live step-9 re-check cheap. A feed that exposes ONLY the candidate-feed LatestSnapshots
// read surface still resolves through the hostSnapshotIndex bridge below (the fleet walk),
// so the point-read CONTRACT is satisfied either way; the production wiring takes the O(1)
// path because *HeartbeatStore offers the host-keyed accessor.
// ---------------------------------------------------------------------------

// hostSnapshotFeed is the narrow latest-per-host read the freshness probe needs: the
// fleet's most-recent snapshots, the EXISTING HeartbeatStore.LatestSnapshots read
// surface (heartbeatstore.go — its owner, untouched here). It is declared narrow so the
// adapter depends only on the one read it uses; *HeartbeatStore satisfies it natively.
type hostSnapshotFeed interface {
	LatestSnapshots(ctx context.Context, sessionUUID string) ([]store.HeartbeatSnapshot, error)
}

// heartbeatFreshness is the production scheduler.HostFreshness seam (placer.go's §4.1
// step-9 live probe, D72): it resolves ONE placed host's CURRENT applied_seq from the
// live latest-per-host heartbeat feed, so the step-9 routable gate re-validates against
// the host's present freshness (not the value recorded at placement), closing the
// residual D72 window. It is the host-keyed dual of StoreCandidateSource: that assembles
// a session's candidate SET from the feed; this probes ONE already-placed host. It drives
// the additive store.HostAppliedSeq O(1) point read over the feed: when the feed exposes the
// host-keyed SnapshotForHost accessor (*HeartbeatStore does — a map hit, heartbeatstore.go) it
// drives the query directly over that accessor, a true O(1) lookup; a feed with only the
// candidate-feed LatestSnapshots read surface falls back to the hostSnapshotIndex bridge (the
// fleet walk). Either way the applied_seq extraction stays in the store leaf.
type heartbeatFreshness struct {
	feed hostSnapshotFeed
}

// NewHostFreshness builds the production HostFreshness seam over the live latest-per-host
// heartbeat feed (the SAME *HeartbeatStore StoreCandidateSource places against, so a
// placement and a step-9 re-check share one view of a host). It is the seam main.go
// assigns the scheduler.Adapter's optional Freshness field under DS_ORCH_LIVE to flip the
// §4.1 step-9 live probe from inert (recorded-only re-check) to live (re-validating the
// host's current applied_seq) — closing the residual D72 window in a live run. A nil feed
// is a wiring bug surfaced fail-closed at the first probe (CurrentAppliedSeq reports the
// host absent → the coordinator degrades to the recorded re-check, never a nil panic).
func NewHostFreshness(feed hostSnapshotFeed) scheduler.HostFreshness {
	return heartbeatFreshness{feed: feed}
}

// CurrentAppliedSeq satisfies scheduler.HostFreshness: it returns the host's current
// heartbeat applied_seq and true, or (0, false) when the host has no current report in
// the live feed (the placer maps false → sessions.ErrFreshnessUnknown, the coordinator
// degrading to the recorded re-check). It resolves the host's snapshot by host_id and
// reads its applied_seq through the additive store.HostAppliedSeq point read. The lookup
// path is host-keyed O(1) when the feed exposes the SnapshotForHost accessor (the live
// *HeartbeatStore does — a map hit, heartbeatstore.go), so the §4.1 step-9 re-check on the
// create hot path is a map lookup, not an O(fleet) scan; a feed with only the candidate-feed
// LatestSnapshots read surface degrades to the hostSnapshotIndex bridge (the fleet walk). A
// nil feed reports the host absent (false) — a half-wired probe fail-closes to the recorded
// re-check rather than panicking.
func (f heartbeatFreshness) CurrentAppliedSeq(ctx context.Context, hostID string) (uint64, bool, error) {
	if f.feed == nil {
		return 0, false, nil
	}
	return store.HostAppliedSeq(ctx, f.appliedSeqSource(), hostID)
}

// appliedSeqSource picks the host-keyed point-read seam store.HostAppliedSeq drives:
// directly the feed when it offers the O(1) SnapshotForHost accessor (the live
// *HeartbeatStore — a map hit, heartbeatstore.go), else the hostSnapshotIndex bridge over the
// candidate-feed LatestSnapshots read surface (the fleet walk) for a feed that lacks it. The
// type assertion is the additive, backwards-compatible switch: the production path is O(1)
// without changing this seam's shape, and a LatestSnapshots-only feed still resolves the same
// contract.
func (f heartbeatFreshness) appliedSeqSource() store.HostAppliedSeqSource {
	if src, ok := f.feed.(store.HostAppliedSeqSource); ok {
		return src
	}
	return hostSnapshotIndex{feed: f.feed}
}

// hostSnapshotIndex bridges a feed's fleet-wide LatestSnapshots read surface onto the
// store's host-keyed HostAppliedSeqSource point-read seam — the O(fleet) FALLBACK for a feed
// that exposes ONLY the candidate-feed read (it index-then-filters the latest set by host_id
// and returns the one host's snapshot). The live *HeartbeatStore now satisfies
// HostAppliedSeqSource DIRECTLY via its O(1) SnapshotForHost map hit (heartbeatstore.go), so
// the production freshness consumer (CurrentAppliedSeq → appliedSeqSource) takes that path
// and never builds this bridge; it remains for a LatestSnapshots-only feed so the point-read
// contract is satisfiable over any candidate feed without widening the HostFreshness seam.
type hostSnapshotIndex struct {
	feed hostSnapshotFeed
}

// SnapshotForHost resolves one host's most-recent snapshot by host_id, reporting false
// when the host has no current report in the live feed (it vanished — the probe then
// degrades to the recorded re-check). The sessionUUID the feed's read surface takes is
// session-agnostic at this layer (LatestSnapshots returns the whole fleet's latest set,
// heartbeatstore.go); the empty string requests it.
func (idx hostSnapshotIndex) SnapshotForHost(ctx context.Context, hostID string) (store.HeartbeatSnapshot, bool, error) {
	snaps, err := idx.feed.LatestSnapshots(ctx, "")
	if err != nil {
		return store.HeartbeatSnapshot{}, false, fmt.Errorf("controlplane: latest snapshots for host %s: %w", hostID, err)
	}
	for _, s := range snaps {
		if s.HostID == hostID {
			return s, true, nil
		}
	}
	return store.HeartbeatSnapshot{}, false, nil
}

// Compile-time proof that the production freshness seam satisfies scheduler.HostFreshness
// (placer.go's §4.1 step-9 live probe, D72) and that the O(fleet) fallback bridge satisfies
// the store's host-keyed point-read seam — so main.go can assign NewHostFreshness(feed) to the
// scheduler.Adapter's Freshness field under DS_ORCH_LIVE and the additive store query can
// drive over it. The live *HeartbeatStore satisfies the same point-read seam DIRECTLY via its
// O(1) SnapshotForHost map hit (the proof lives in heartbeatstore.go), the path the production
// consumer takes; this bridge is the candidate-feed-only fallback.
var (
	_ scheduler.HostFreshness    = heartbeatFreshness{}
	_ store.HostAppliedSeqSource = hostSnapshotIndex{}
)
