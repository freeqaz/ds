package libvirt

import (
	"context"
	"fmt"
	"io"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// This file names the seams the host-agent create path INVOKES but does not own.
// The boundary-owned primitives (tap-create, the per-session NFT objects) and
// the identity-owned interception-CA are linked through these interfaces, the
// same deferred-binding posture internal/nftbridge uses for its ds-nft cgo edge:
// the contract is modeled now, the real wiring lands with the staticlib / proto
// freeze. Keeping them as seams keeps this module stdlib-only and offline (see
// doc.go) while the full §4.1 steps-4–9 choreography is implemented and tested
// against fakes.

// AttachPrimitive is the Boundary-owned tap-create primitive (doc 14 §1/§4; the
// `ds-nft` write path is the SINGLE writer of tap/nft objects). The host agent
// is the INVOKER (doc 15 §4.1 step 4 / the doc 14 §4 RACI row: Boundary
// Accountable for primitive semantics + `dstap-<idx>` naming; Orchestrator
// Accountable for index allocation, the never-recycle window, and the
// session-record binding). The host agent never writes nft objects itself —
// every method here crosses into ds-nft (via internal/nftbridge when the cgo
// edge lands).
type AttachPrimitive interface {
	// CreateTap programs the per-session routed tap for the binding (the
	// `dstap-<idx>` interface). Idempotent on the binding's keys: a retry for
	// the same session must converge, never double-create (every create verb is
	// idempotent on session_uuid, doc 15 §5.1).
	CreateTap(ctx context.Context, b Binding) error
	// InstantiateSessionNFT instantiates the per-session NFT objects: the
	// session chains plus the EMPTY `allow4_<session>` / `allow6_<session>` sets
	// (doc 15 §4.1 step 4). The sets start empty — DNS-admitted destinations
	// land later through the policy path; `allow6_<session>` stays empty under
	// the D75 Phase-B guest-invariant posture. Idempotent on the session.
	InstantiateSessionNFT(ctx context.Context, sessionUUID string, b Binding) error
	// FlushSession drives the unconditional `flush_session(legs=all)` teardown
	// (NFT-6, doc 14 §5) for a partial allocation. The create path invokes it on
	// rollback from step 4 onward; the sibling hostagent-destroy-teardown task
	// owns the full §4.2 ordering. Surfaced here so a create failure can unwind
	// the host-side objects it created. The recorded Binding carries the TapName +
	// never-recycled HostSessionIndex the ds-nft teardown keys on (the live edge
	// flushes conntrack-by-mark THEN removes the per-session named sets) — passed
	// explicitly, like CreateTap/InstantiateSessionNFT, so the primitive never has
	// to resolve a session→binding map (a binding-less partial converges to no-op).
	FlushSession(ctx context.Context, sessionUUID string, b Binding) error
}

// CAInjector mints and injects the per-session interception CA (D17/D82). The
// CA is minted by Identity's D22 service under the interception root hierarchy
// (a separate root from workload identity — D82) and consumed here; this seam is
// the host-agent's consume+inject side. Injection happens into the per-session
// qcow2 overlay's trust store, BEFORE boot, FAIL-CLOSED (doc 15 §4.1 step 7:
// injection failure fails the create).
type CAInjector interface {
	// InjectCA writes the per-session interception CA referenced by caBundleRef
	// (the VmSpec.material.ca_bundle_ref slot) into the overlay's trust store.
	// It MUST fail closed: any error means the CA is not provably in the trust
	// store, and the create must abort before boot rather than launch a VM whose
	// first TLS byte could bypass the egress gateway (D17). It must complete
	// before the first TLS byte the booted guest can emit (step 7 ≺ step 8).
	InjectCA(ctx context.Context, overlayPath, caBundleRef string) error
}

// OverlayStore creates the per-session qcow2 overlay (D29: raw golden image +
// per-session qcow2 overlay via libvirt external snapshots). CloneFromImage
// creates the overlay; the overlay is the delta store, the inspectable artifact,
// and the durability unit at once.
type OverlayStore interface {
	// CreateOverlay creates the per-session qcow2 overlay over the image and
	// returns its host path. Idempotent on session_uuid: a retry returns the
	// existing overlay path rather than forking a second delta.
	CreateOverlay(ctx context.Context, sessionUUID, imageID string) (overlayPath string, err error)
	// DisposeOverlay disposes the overlay on rollback (the step-7/8 failure
	// unwind, doc 15 §4.1 Rollback). Owned in full by the §4.2 destroy sibling;
	// surfaced here so a boot failure can unwind the overlay it created.
	DisposeOverlay(ctx context.Context, overlayPath string) error
}

// Booter boots the VM per the D38 frozen VM entrypoint contract (doc 15 §4.1
// step 8): the session token arrives via the D22 shim, the HTTP(S)_PROXY + CA
// environment is set (TLS-2/D17), the exec/supervise spec runs, and the
// VM-local event socket comes up — terminated HOST-SIDE at the host agent (the
// guest never reaches the orchestrator directly).
type Booter interface {
	// Boot launches the domain for the binding from its overlay, per the D38
	// entrypoint contract referenced by entrypointConfigRef. It returns the
	// libvirt domain UUID. The local event socket is terminated host-side (the
	// returned domain is the handle the heartbeat's observed-state reports).
	// Idempotent on session_uuid.
	//
	// vsockCID is the per-session deterministic AF_VSOCK guest context id
	// (Binding.VsockCID, derived in alloc.go = HostSessionIndex + reservedVsockCIDs):
	// the live domain render PINS it as `<cid auto='no' address='<vsockCID>'/>` so the
	// host agent can dial a host-predictable guestCID:port without round-tripping a
	// libvirt auto-assignment (the attach control channel rides vsock, no tap/IP/nft).
	// Zero is the not-yet-derived / auto-assign sentinel (`<cid auto='yes'/>`),
	// keeping the offline/pre-allocate render byte-identical to the historical form.
	//
	// tapName is the session's Binding.TapName (the `dstap-<idx>` join key the create
	// path threads from the recorded binding). The LIVE render wires it as
	// `<target dev='<tapName>'/>` of an `<interface type='ethernet'>` egress NIC ONLY
	// when the DS_ROUTED_TAP gate is on (LiveConfig.RoutedTap, read at construction);
	// gate-off it renders the historical usermode SLIRP NIC byte-identically (and a
	// gate-on boot with an empty tapName also falls back to SLIRP, never a malformed
	// empty target). The offline booter defines no domain and ignores it.
	Boot(ctx context.Context, sessionUUID, overlayPath, entrypointConfigRef, tapName string, vsockCID uint32) (domainUUID string, err error)
}

// RoutabilityGate is the structural step-6/step-9 gate (doc 15 §4.1): the
// session cannot become routable until BOTH the session-scoped digest ack has
// landed (step 6: mint-before-attach, D73 — the host agent acks on behalf of the
// host-side fan-out, D109) AND the placed host's policy is fresh (step 3,
// re-checked at step 9: applied_seq within the staleness budget, D72). This is
// enforced STRUCTURALLY — the create path cannot reach routable without both
// returning satisfied — not by convention.
type RoutabilityGate interface {
	// DigestAcked reports whether the session-scoped digest write has been acked
	// (step 6). Until it returns true, no first egress byte may exist for the
	// session (mint-before-attach, doc 14 §7 / D73).
	DigestAcked(ctx context.Context, sessionUUID string) (bool, error)
	// PolicyFresh reports whether the host's applied_seq is within the staleness
	// budget (step 3 re-checked at step 9, D72/D36). A stale host is
	// unschedulable and a placed session on it cannot become routable.
	PolicyFresh(ctx context.Context) (bool, error)
}

// BoundaryReadiness is the host-WIDE pre-step-4 boundary admission precondition
// (doc 09 §3, D63/D69/D70): the three host-boundary nft tables of the unit-v3
// install set are present — `inet ds_boundary` (NFT-1 default-deny floor incl. the
// QUIC reject, D70), `inet ds_resolver_closure` (NFT-4 resolver-bypass closure,
// D69/D70), `inet ds_proxy_out` (NFT-3b Stage-3 OUTPUT containment, D76) — AND the
// two boundary services answer: `ds-dnsgate` and `ds-tlsproxy` (D63). It is
// read-only and idempotent (it mutates NOTHING host-side) and is NOT a runtime
// dependency of the floor's default-deny safety (the kernel `ds_boundary` ruleset
// is self-sufficient per doc 09 §3 — the floor keeps dropping regardless of this
// probe). It gates ADDING a session, never weakens the floor: removing NFT-4/NFT-3b
// at runtime makes the probe REFUSE new sessions (correct), it never opens the floor,
// and already-running sessions are untouched.
//
// It is the FIRST host-touching action of HostAgent.CreateSession — probed after
// req.validate() and BEFORE the step-4 boundary (h.alloc.Allocate). Any probe error
// OR not-ready verdict OR uncertainty fails CLOSED at the call site (*CreateError{
// Step: StepNone}) BEFORE any host-side object exists (no index burned, no tap, no
// per-session NFT sets, no overlay, no CA inject, no boot, no record) — the doc 15
// §4.1 Rollback "failure at 1–3 ... nothing host-side exists" cell, so the create
// path owes no compensating verbs. Gating here dominates BOTH tap-attach (step 4)
// and Boot (step 8) transitively, and is DISTINCT from the per-session RoutabilityGate
// (DigestAck step 6 / PolicyFresh step 9): this is a new host-WIDE gate that dominates
// them.
//
// OFFLINE / deferred-binding posture (doc.go; the other seams here keep it stdlib-only
// and offline): the deferred impl is always-ready (no kernel/socket touch), so the
// offline/CI/fake path is byte-identical to today; the live body crosses into a
// read-only `nft list` shell-out + service dials behind the Linux+live build path.
type BoundaryReadiness interface {
	// Probe reports whether the host boundary is ready. ready==true ONLY when
	// every required check passed (all three tables present AND both services
	// answer). ready==false,err==nil is an HONEST not-ready (a named missing table
	// / non-answering service). err!=nil is an UNCERTAIN probe (an nft-exec fault,
	// a dial context timeout, a malformed config). Both not-ready AND any err are
	// FAIL-CLOSED at the call site (uncertain ⇒ no VM). detail is an operator-facing
	// reason naming the first failing check (which table / which service) so the
	// operator knows to (re)start ds-nft-bootstrap.service / ds-dnsgate / ds-tlsproxy
	// — never a raw secret.
	Probe(ctx context.Context) (ready bool, detail string, err error)
}

// RecoveredSession is one host-resident session a restart re-observed — the
// in-package value the SessionRecoverer returns (carried as DATA, the
// stdlib-only posture this module keeps; the wire ObservedSession is assembled
// from it where the seam wires up, the same lowering CloneFromImageResponse
// gets from a Binding). It pairs the global session identity + the
// hypervisor-local domain id with the recorded three-keys-agree Binding so a
// post-restart re-adoption re-seeds the clone cache with the SAME
// (index, tap_name, guest_ip, overlay_path) the session already holds — never a
// fresh never-recycled index (D66).
type RecoveredSession struct {
	// SessionUUID is the global session identity — the clone-cache idempotency
	// key a post-recover CloneFromImage re-adopts on.
	SessionUUID string
	// DomainUUID is the hypervisor-local domain/instance id the recoverer
	// observed still resident on the host (the libvirt domain handle).
	DomainUUID string
	// Binding is the recorded three-keys-agree binding (D44/D66): the
	// never-recycled host-local index, the `dstap-<idx>` tap name, the
	// per-session guest IP, and the qcow2 overlay path. Re-seeding the cache with
	// it is what makes the retried clone re-adopt instead of re-allocate.
	Binding Binding
	// SnapshotRefs is the set of opaque snapshot_refs a prior incarnation's
	// Snapshot captured for this session and that the host STILL holds as durable
	// point-in-times of the session's qcow2 overlay (D29). It is the durable
	// half of the snapshotRefs registry that a restart would otherwise lose:
	// the registry is per-process in-memory state, so without re-seeding it from
	// what the host re-observes, a captured ref would silently stop being a valid
	// since_snapshot_ref base the moment the driver restarted — a post-restart
	// ExportDiskDelta rooted at a still-live snapshot would falsely fail NotFound
	// even though the durable point-in-time is right there on disk.
	//
	// BASE AUTHORITY (the driver-vs-control-plane decision this recovery seam
	// settles): the captured-ref SET is DURABLE HOST/CONTROL-PLANE state, NOT
	// driver-resident truth. The libvirt driver's in-memory snapshotRefs map is a
	// CACHE of that durable set, authoritative ONLY for the lifetime of one
	// process; the host-side SessionRecord (the same durable record the
	// SessionRecoverer enumerates the resident domains + bindings from) is the
	// SOURCE OF TRUTH for which snapshots a session actually holds. A
	// since_snapshot_ref is valid iff the host still holds that point-in-time —
	// the driver re-adopts the host's set on recovery rather than re-deriving or
	// inventing one. This keeps the validity decision fail-closed and coherent
	// across a restart: the registry the export gate consults is re-seeded to
	// match the durable reality, so the gate never admits a ref the host dropped
	// (a §4.2 Destroy purges both the durable record and any recovered set) and
	// never rejects a ref the host still keeps. An EMPTY/absent SnapshotRefs is
	// the common case (a session that captured nothing, or a fresh host) and
	// re-seeds an empty per-session set — a clean no-op.
	SnapshotRefs []string
}

// SessionRecoverer re-observes the sessions a host was running across a
// host-agent / driver restart — the crash-matrix re-adoption leg (doc 15 §4
// "Crash matrix", §5.1 restart re-adoption; D66 never-recycled indices). The
// per-process clone-idempotency cache + the index Allocator are in-memory state
// a restart loses; without re-observation a retried CloneFromImage after a crash
// would burn a SECOND never-recycled index instead of re-adopting the live
// session. This seam re-reads the host-resident libvirt domains + their recorded
// bindings for a host_id and hands them back so RecoverSessions can re-seed
// BOTH the Allocator (past the highest observed index) and the clone cache.
//
// The real impl lands HOST-SIDE on the virtual-metal box (it enumerates the
// resident libvirt domains + the persisted session records); this seam keeps the
// wiring buildable + testable offline against a recording fake — no real
// libvirt/VM/KVM/sudo (the deferred-binding posture doc.go / the other seams
// keep). An empty result is the fresh-host case: nothing resident, a clean
// no-op.
type SessionRecoverer interface {
	// RecoverSessions enumerates the host-resident sessions for hostID — the
	// domains still running on the host plus their recorded three-keys-agree
	// bindings AND the durable snapshot_refs each session still holds (the
	// SnapshotRefs set, the durable registry the export gate consults). It is
	// read-only re-observation: it does NOT recreate taps, mint keys, boot
	// domains, or re-capture snapshots; it reports what the host already has so
	// the driver can re-adopt it. An empty slice means a fresh host with nothing
	// resident (a clean no-op). It must be idempotent — re-invocation over an
	// unchanged host returns the same observed set (same bindings, same
	// captured-ref sets), so RecoverSessions converges.
	RecoverSessions(ctx context.Context, hostID string) ([]RecoveredSession, error)
}

// CapturedRefStore durably persists — and reads back — the SET of opaque
// snapshot_refs a session's Snapshot has captured, keyed by session_uuid. It is the
// PRODUCER/host DURABLE HALF of the in-memory snapshotRefs registry (service.go): a
// captured ref registered ONLY in the per-process map is lost the moment the driver
// restarts, so a post-restart ExportDiskDelta rooted at a still-live point-in-time
// would falsely fail NotFound (seams.go RecoveredSession.SnapshotRefs documents this
// exact defect). This seam closes the loop on the WRITE side: Snapshot records each
// captured ref here, and on a restart the SessionRecoverer reads the set back out to
// populate RecoveredSession.SnapshotRefs — the same base-authority decision the
// consumer side already ratifies (the host's durable set is the source of truth; the
// driver's in-memory map is a per-process cache re-adopted from it).
//
// It belongs to the SAME durable-store family as SessionRecordStore (the bindings):
// the daemon composition root backs it host-side with the same per-session `.ds-sessions`
// durable area, so a session's captured refs live beside the binding they annotate and
// a §4.2 Destroy purges both. This module keeps it a SEAM (not the file store inline)
// for the same reason the other seams here stay interfaces: the offline/CI/fake path is
// stdlib-only + testable (service_test.go) while the real file-backed impl lands host-side
// on the virtual-metal box (the DS_HOSTAGENT_LIVE composition, offline.go), and a
// DriverService built WITHOUT one leaves Snapshot's durable-write a no-op — the default-off
// posture is byte-identical to today.
//
// FAIL-CLOSED / FAIL-LOUD, mirroring SessionRecordStore: RecordCapturedRef error means the
// ref is NOT provably durable, so Snapshot fails rather than report a capture whose base a
// restart would silently lose; CapturedRefs returns the EMPTY set (nil, nil) for a session
// that captured nothing (or a fresh host) — the common case that re-seeds an empty set — and
// a genuine read fault is a non-nil error (a corrupt record must not silently drop a
// still-held base). It must be idempotent: RecordCapturedRef is a set-insert (a retried
// Snapshot re-records the same ref harmlessly) and CapturedRefs over an unchanged store
// returns the same set.
type CapturedRefStore interface {
	// RecordCapturedRef durably records that sessionUUID captured snapshotRef (a
	// set-insert: recording the same (session, ref) again converges). An error means
	// the ref is not provably durable; the caller (Snapshot) fails closed. An empty
	// sessionUUID or snapshotRef is a programming error the impl rejects (the empty
	// ref is the full-overlay sentinel, never a captured point-in-time).
	RecordCapturedRef(ctx context.Context, sessionUUID, snapshotRef string) error
	// CapturedRefs returns the durable captured-ref set for sessionUUID. A session
	// that captured nothing (or a fresh host) is (nil, nil) — the common empty case
	// that re-seeds an empty set, fail-closed. A genuine read fault is a non-nil error
	// (fail-loud). The returned order is not significant (the consumer re-seeds a SET).
	CapturedRefs(ctx context.Context, sessionUUID string) ([]string, error)
	// RemoveCapturedRefs drops the whole captured-ref set for sessionUUID — the §4.2
	// teardown (a destroyed session's durable point-in-times are purged so a later
	// recovery never re-admits a ref whose overlay is gone). A missing set is a no-op
	// success (idempotent, the SessionRecordStore.Remove precedent).
	RemoveCapturedRefs(ctx context.Context, sessionUUID string) error
}

// capturedRefRecoverer is the production read-back leg (doc 15 §4 crash matrix): it
// DECORATES an inner SessionRecoverer (the host-resident re-observation, recoverer.go
// liveSessionRecoverer) with the durable captured-ref read-back. The inner recoverer
// re-observes the resident domains + their recorded bindings but does NOT know the
// captured refs (the domain XML / SessionRecord never carried them — that is exactly the
// gap this producer arc closes); this decorator layers each session's durable
// CapturedRefStore set onto the RecoveredSession the DriverService re-adopts, so
// RecoverSessions re-seeds the in-memory snapshotRefs registry to MATCH the durable reality.
//
// It is the composition seam the daemon root wraps around NewLiveSessionRecoverer, keeping
// this module offline + stdlib (the store is a seam; service_test.go proves the arc against a
// fake). It preserves the inner recoverer's contract verbatim: read-only re-observation, an
// empty inner result is a clean no-op (no store reads), and idempotency (a re-invocation over
// an unchanged host + store returns the same set). A CapturedRefStore read fault is surfaced
// non-nil (fail-loud — a corrupt durable set must not silently drop a still-held base), the
// same posture the inner recoverer holds for a corrupt SessionRecord.
type capturedRefRecoverer struct {
	inner SessionRecoverer
	refs  CapturedRefStore
}

// NewSessionRecovererWithCapturedRefs wraps inner with the durable captured-ref read-back
// over refs — the production SessionRecoverer that populates RecoveredSession.SnapshotRefs
// (the producer arc's read side). Both are required: a nil inner has nothing to observe and a
// nil store has no durable refs to re-adopt (use inner directly for the no-captured-refs
// posture). The returned value satisfies the SessionRecoverer seam the DriverService wires.
func NewSessionRecovererWithCapturedRefs(inner SessionRecoverer, refs CapturedRefStore) (SessionRecoverer, error) {
	if inner == nil {
		return nil, fmt.Errorf("captured-ref recoverer requires an inner session recoverer to decorate")
	}
	if refs == nil {
		return nil, fmt.Errorf("captured-ref recoverer requires a captured-ref store (use the inner recoverer directly for the no-durable-refs posture)")
	}
	return &capturedRefRecoverer{inner: inner, refs: refs}, nil
}

// RecoverSessions re-observes the host-resident sessions via the inner recoverer, then reads
// each session's durable captured-ref set out of the store and sets RecoveredSession.SnapshotRefs
// — the read-back that lets a captured ref survive re-adoption and still root an incremental
// ExportDiskDelta. An empty inner result is a clean no-op (no store reads). A store read fault is
// surfaced (fail-loud). It never re-observes taps/keys/domains — it only annotates what the inner
// recoverer already reported (read-only), so it inherits the inner's idempotency.
func (r *capturedRefRecoverer) RecoverSessions(ctx context.Context, hostID string) ([]RecoveredSession, error) {
	recovered, err := r.inner.RecoverSessions(ctx, hostID)
	if err != nil {
		return nil, err
	}
	for i := range recovered {
		refs, err := r.refs.CapturedRefs(ctx, recovered[i].SessionUUID)
		if err != nil {
			return nil, fmt.Errorf("recover sessions on host %s: read captured refs for %s: %w", hostID, recovered[i].SessionUUID, err)
		}
		// The inner recoverer never populates SnapshotRefs (the record carried none);
		// the durable store is the sole source. An empty/nil set is the common
		// no-capture case and leaves SnapshotRefs empty (fail-closed re-seed).
		recovered[i].SnapshotRefs = refs
	}
	return recovered, nil
}

// Compile-time assertion: the decorator satisfies the seam the DriverService wires.
var _ SessionRecoverer = (*capturedRefRecoverer)(nil)

// ReseedableCounter is the forward-only resume seam over the persistent
// host-local index counter (alloc.go IndexCounter: the never-recycle authority,
// D66/D44). It is the documented `newMemCounter(start)` resume point expressed
// as an interface so a restart can advance the SAME counter the Allocator draws
// from PAST the highest index a prior incarnation handed out — without ever
// recycling a live index. RecoverSessions holds the counter the Allocator wraps
// and calls SeedAtLeast after re-observing the resident sessions; the next
// Allocate() then yields an index strictly past every recovered one.
//
// It is a SUPERSET of IndexCounter (it Next()s like any counter) plus the
// forward-only SeedAtLeast advance; the same instance can back both the
// Allocator (as its IndexCounter) and the DriverService (as its reseed handle),
// so the re-seed and the allocation draw from one monotonic source.
type ReseedableCounter interface {
	// Next atomically returns the next never-recycled index and advances the
	// counter past it (the IndexCounter contract: monotonic, crash-safe, never
	// returned twice — even across a restart).
	Next() (uint64, error)
	// SeedAtLeast advances the counter so the next Next() yields an index STRICTLY
	// greater than highest — the restart resume point. It is FORWARD-ONLY: a
	// highest below the counter's current position is a no-op (the counter never
	// moves backward, preserving never-recycle, D66). Passing the highest
	// recovered index re-seeds the Allocator past every live session so
	// re-adoption never re-hands a resident index.
	SeedAtLeast(highest uint64)
}

// AttachHandleMinter mints the D79 transport-ambivalent attach handle (doc 15
// §5.4) for a known session binding — the IssueAttachHandle seam. Given the
// session identity, its recorded host-side Binding, and the requested D61
// subscriber Role (WRITER | READER), it returns a fully-populated
// attach.v1.AttachHandle: the reachable endpoint candidate(s) (the transport
// URL/socket the client dials — M0 the DIRECT host-agent endpoint, M2+ the
// RELAY joins), the short-lived session-scoped auth material (D39 — NEVER a
// long-lived cred; long-lived credentials never enter the VM and never ride this
// handle), the requested role, and the whole-handle expiry. The handle is
// transport-ambivalent by construction (doc 15 §5.4 / D79): the orchestrator
// never assumes which transport terminates the stream, only that the candidate
// set names one the client can reach.
//
// The handle is minted FROM the recorded binding (the session's host-side
// attachment artifact, binding.go) — the minter is the seam that turns "this
// session is bound on this host" into "here is how a client attaches to it",
// without the libvirt driver itself owning the transport endpoint or the auth
// hierarchy. It must be DETERMINISTIC and idempotent on (sessionUUID, role): a
// retry for the same session+role yields an EQUIVALENT handle (same endpoints,
// same role, same expiry), never a second mint of conflicting state — so a
// retried IssueAttachHandle after a control-plane blip re-issues rather than
// forks two divergent handles for one seat.
//
// OFFLINE / deferred-binding posture (doc.go; the other seams here): the real
// minter lands HOST-SIDE on the virtual-metal box — the hostbridge D79 transport
// endpoint (the per-host DIRECT address the host agent terminates) plus the
// identity-D22 per-session auth (the short-lived session-scoped credential minted
// under the session token, NOT in this package). This seam keeps the wiring
// buildable + testable offline against a recording fake (service_test.go) — no
// real hostbridge socket, no identity service, no live VM/KVM/sudo.
//
// TODO(attach, host-side): wire the real minter — the hostbridge transport
// endpoint (D79) for the DIRECT (and later RELAY) EndpointCandidate set, and the
// identity-D22 per-session auth mint for the AuthMaterial. Until it lands, a
// DriverService built without a minter answers IssueAttachHandle with an honest
// codes.Unimplemented (the same posture as the other host-side-only verbs).
type AttachHandleMinter interface {
	// MintAttachHandle mints the attach.v1 handle for sessionUUID's recorded
	// binding in the requested role. It returns a populated AttachHandle
	// (endpoints + short-lived auth + role + expiry, doc 15 §5.4); an error means
	// no handle could be minted (a real host-side auth/endpoint fault the caller
	// surfaces). It is DETERMINISTIC and idempotent on (sessionUUID, role): a
	// repeat mint for the same session+role yields an equivalent handle, never a
	// second conflicting one.
	MintAttachHandle(ctx context.Context, sessionUUID string, b Binding, role attachv1.Role) (*attachv1.AttachHandle, error)
}

// Suspender pauses and restores a host-resident session domain — the §3
// RUNNING↔SUSPENDED(reason) lifecycle transition (doc 15 §3/§4.3; D46/D77), the
// seam DriverService.Suspend / DriverService.Resume wire to. Suspend pauses the
// libvirt domain (a domain-suspend / managedsave); Resume restores it (domain
// resume / restore-from-managedsave) — the exact inverse. The pause/restore TCP
// mechanics over the boundary-owned transport are Boundary-owned (D46, doc 15 §1
// "Not owned"); this seam is the orchestrator's drive side — "pause/restore THIS
// session's domain" — without the libvirt driver itself owning the managedsave
// state file or the boundary transport.
//
// The D77 reason taxonomy is validated at the SERVICE binding, not here (doc 15
// §4.3): the binding rejects SUSPEND_REASON_UNSPECIFIED and a POLICY_BREACH
// without provenance BEFORE it ever reaches this seam, so a Suspend call here
// always carries a vetted reason (USER | POLICY_BREACH-with-provenance |
// REBALANCE). The reason + provenance are passed THROUGH to the seam so the
// host-side impl can record the genuine-threat attribution (D77) on the
// suspend — the provenance is the policy-rule lineage that justified a
// POLICY_BREACH pause, carried for audit, never re-validated host-side.
//
// IDEMPOTENT on session_uuid: re-suspending an already-suspended domain is a
// no-op success, and re-resuming an already-running domain is a no-op success
// (doc 15 §5.1: every verb idempotent on session_uuid so a retried call after a
// host or control-plane blip converges rather than faults). A deterministic
// recording fake makes that assertable over the wire (service_test.go).
//
// OFFLINE / deferred-binding posture (doc.go; the other seams here): the real
// impl lands HOST-SIDE on the virtual-metal box — libvirt domain-suspend /
// managedsave for the pause and domain resume / restore-from-managedsave for the
// restore, over the boundary-owned transport. This seam keeps the wiring
// buildable + testable offline against a recording fake — no libvirt-go/cgo, no
// managedsave, no live VM/KVM/sudo.
//
// The real Suspender lands in suspender_libvirt.go (liveSuspender /
// NewLiveSuspender): the virsh managedsave pause + virsh start
// restore-from-managedsave restore over the package runner seam, domstate-checked
// for the idempotent no-op-on-repeat contract, behind the DS_HOSTAGENT_LIVE gate
// (the host-agent wiring that SELECTS it is a separate task). A DriverService
// built without a Suspender still answers Suspend/Resume with an honest
// codes.Unimplemented (the same posture as the other host-side-only verbs).
type Suspender interface {
	// Suspend pauses the host-resident domain for sessionUUID with the
	// D77-vetted reason (the binding has already rejected UNSPECIFIED and a
	// POLICY_BREACH without provenance). provenance is the policy-rule lineage
	// that justified a POLICY_BREACH pause (nil for USER/REBALANCE), carried
	// through for the host-side audit record, never re-validated here. An error
	// means the pause did not take (a real host-side fault the caller re-drives);
	// idempotent on sessionUUID — re-suspending an already-suspended domain is a
	// no-op success.
	Suspend(ctx context.Context, sessionUUID string, reason hypervisorv1.SuspendReason, provenance *boundaryv1.Provenance) error
	// Resume restores the host-resident domain for sessionUUID — the inverse of
	// Suspend (domain resume / restore-from-managedsave). An error means the
	// restore did not take (a real host-side fault the caller re-drives);
	// idempotent on sessionUUID — re-resuming an already-running domain is a no-op
	// success.
	Resume(ctx context.Context, sessionUUID string) error
}

// SnapshotStore captures a point-in-time of the per-session qcow2 overlay — the
// D29 durability unit — and returns an OPAQUE overlay/delta reference, the seam
// DriverService.Snapshot wires to. It is the sibling of OverlayStore over the
// SAME D29 substrate (raw golden image + per-session qcow2 overlay via libvirt
// external snapshots): OverlayStore CREATES the per-session overlay at clone
// time; SnapshotStore CAPTURES a durable point-in-time of that overlay — the
// disk-delta substrate GetCapabilities already advertises
// (supports_disk_delta_export=true), surfaced here as a named snapshot.
//
// CAPABILITY HONESTY / zero-leakage (doc 15 §5.1, §10 / D29/D30): the returned
// reference is OPAQUE — an overlay/delta handle the control plane carries and
// later names back (e.g. ExportDiskDelta.since_snapshot_ref), NEVER a libvirt
// snapshot-XML, a qcow2 path, or any QEMU monitor type. The whole point of this
// seam is that the libvirt/qcow2 external-snapshot mechanics stay BEHIND it, so
// the contract surface (SnapshotResponse.snapshot_ref) leaks zero driver
// internals — the same invariant cloneResponse enforces for the binding.
//
// IDEMPOTENT on (sessionUUID, label): the capture is DETERMINISTIC on its inputs,
// so a retry with the SAME (session, label) returns an EQUIVALENT snapshot_ref
// rather than forking a second durable snapshot — a retried Snapshot after a
// control-plane blip re-names the same point-in-time, it does not duplicate it. A
// DIFFERENT label is a DIFFERENT point-in-time (a distinct snapshot_ref); an
// empty label is the unlabeled-capture case (still deterministic on the session).
// A deterministic recording fake makes that assertable over the wire
// (service_test.go).
//
// OFFLINE / deferred-binding posture (doc.go; the other seams here): the real
// impl lands HOST-SIDE on the virtual-metal box — the libvirt external-snapshot
// capture of the per-session qcow2 overlay (the D29 dirty-bitmap / delta
// substrate destroy.go's DurabilityFinalizer also rides). This seam keeps the
// wiring buildable + testable offline against a recording fake — no libvirt-go/
// cgo, no qcow2, no live VM/KVM/sudo.
//
// The real SnapshotStore lands in snapshot_libvirt.go (liveSnapshotStore /
// NewLiveSnapshotStore): the virsh snapshot-create-as --disk-only --atomic
// --no-metadata external disk snapshot of the per-session qcow2 overlay over the
// package runner seam, existence-checked via virsh snapshot-list for the
// deterministic idempotent no-op-on-repeat contract, returning the OPAQUE
// ds-snap://<session>/<label> ref, behind the DS_HOSTAGENT_LIVE gate (the
// host-agent wiring that SELECTS it via NewDriverServiceWithSnapshot is a
// separate task). A DriverService built without a SnapshotStore still answers
// Snapshot with an honest codes.Unimplemented (the same posture as the other
// host-side-only verbs).
type SnapshotStore interface {
	// CreateSnapshot captures a durable point-in-time of sessionUUID's per-session
	// qcow2 overlay (D29) under the optional label, returning an OPAQUE
	// overlay/delta reference (never a libvirt/qcow2 internal). An error means the
	// capture did not take (a real host-side fault the caller re-drives). It is
	// DETERMINISTIC and idempotent on (sessionUUID, label): a repeat capture for
	// the same session+label yields an equivalent reference, never a second durable
	// snapshot; a different label captures a distinct point-in-time.
	CreateSnapshot(ctx context.Context, sessionUUID, label string) (snapshotRef string, err error)
}

// DiskDeltaExporter opens the D29 dirty-bitmap delta of a session's per-session
// qcow2 overlay as a raw byte stream — the seam DriverService.ExportDiskDelta
// wires to. It is the sibling of OverlayStore/SnapshotStore over the SAME D29
// substrate (raw golden image + per-session qcow2 overlay via libvirt external
// snapshots): OverlayStore CREATES the per-session overlay at clone time,
// SnapshotStore CAPTURES a durable point-in-time of it (an opaque snapshot_ref),
// and DiskDeltaExporter READS BACK the bitmap delta — the inspectable artifact
// GetCapabilities already advertises (supports_disk_delta_export=true), the same
// disk-delta substrate destroy.go's DurabilityFinalizer finalizes at §4.2 step 3.
//
// SHAPE — io.ReadCloser, not an emit-callback: the seam yields the RAW delta
// bytes and the service owns the framing. Returning an io.ReadCloser keeps the
// transport concern (chunk size, the monotonic+contiguous {offset,data} frames,
// stream.Context() cancellation between chunks) entirely in the service where the
// gRPC stream lives, and keeps the seam a plain byte source — the real host-side
// impl just hands back a reader over `qemu-img`/dirty-bitmap output (a pipe, a
// file, or a process stdout) and never has to know the wire frame shape. The
// callback form would invert that, pushing offset bookkeeping and ctx-checks into
// every impl; a reader is the smaller, more host-portable contract. The CALLER
// (the service) ALWAYS Closes the returned reader — including on a mid-stream
// context cancellation — so the host-side impl can release the bitmap/qemu-img
// handle deterministically.
//
// CAPABILITY HONESTY / zero-leakage (doc 15 §5.1, §10 / D29/D30): the reader
// yields ONLY the opaque delta bytes the control plane reassembles; the service
// frames them into ExportDiskDeltaResponse{offset, data} and NOTHING libvirt/qcow2
// specific (no snapshot-XML, no qcow2 path, no QEMU monitor type) ever crosses the
// wire — the dirty-bitmap/qemu-img mechanics stay BEHIND this seam, the same
// invariant SnapshotStore enforces for the snapshot_ref.
//
// DETERMINISTIC for offline test (doc.go; the other seams here): a recording fake
// yields a fixed synthetic delta so a wire roundtrip can reassemble the streamed
// bytes and assert byte-equality with monotonic+contiguous offsets — with and
// without sinceSnapshotRef (an empty ref is the FULL-overlay export; a non-empty
// one is the incremental delta SINCE that base snapshot). No libvirt-go/cgo, no
// qcow2, no live VM/KVM/sudo.
//
// TODO(export-disk-delta, host-side): wire the real DiskDeltaExporter — the
// libvirt dirty-bitmap / qemu-img delta extraction over the per-session qcow2
// overlay on the box (full overlay when sinceSnapshotRef is empty, incremental
// since that base snapshot otherwise), handed back as a reader over the extraction
// output. Until it lands, a DriverService built without a DiskDeltaExporter
// answers ExportDiskDelta with an honest codes.Unimplemented (the same posture as
// the other host-side-only verbs).
type DiskDeltaExporter interface {
	// OpenDelta opens the dirty-bitmap delta of sessionUUID's per-session qcow2
	// overlay (D29) as a raw byte stream. An empty sinceSnapshotRef requests the
	// FULL overlay delta; a non-empty one requests the incremental delta SINCE that
	// opaque base snapshot reference (a SnapshotStore.CreateSnapshot output). The
	// returned io.ReadCloser yields ONLY the opaque delta bytes (never a
	// libvirt/qcow2 internal); the service frames them into {offset, data} chunks
	// and ALWAYS Closes the reader (including on a mid-stream context cancellation).
	// An error means the export did not open (a real host-side fault the caller
	// re-drives); on error the reader is nil and nothing needs closing.
	OpenDelta(ctx context.Context, sessionUUID, sinceSnapshotRef string) (io.ReadCloser, error)
}
