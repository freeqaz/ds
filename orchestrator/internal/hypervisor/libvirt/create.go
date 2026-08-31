package libvirt

import (
	"context"
	"fmt"
	"log"

	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// CreateStep names the §4.1 step a create failure surfaced at, so the sibling
// hostagent-destroy-teardown task can drive the right compensating rollback
// (doc 15 §4.1 Rollback: "failure at 4 still runs flush_session(legs=all) +
// NFT-6 ... failure at 7–8 destroys the domain and disposes the overlay, then
// unwinds step 4"). The step is the contract between this create path and the
// rollback path — not free-form text.
type CreateStep int

const (
	// StepNone is the zero value — no step has failed.
	StepNone CreateStep = 0
	// StepAllocate is §4.1 step 4: index allocation + tap/NFT attach + binding.
	StepAllocate CreateStep = 4
	// StepDigestAck is §4.1 step 6: the session-scoped digest write + ack gate.
	StepDigestAck CreateStep = 6
	// StepOverlay is §4.1 step 7: overlay clone + fail-closed CA injection.
	StepOverlay CreateStep = 7
	// StepBoot is §4.1 step 8: boot + entrypoint (D38).
	StepBoot CreateStep = 8
	// StepRoutable is §4.1 step 9: the structural routable gate.
	StepRoutable CreateStep = 9
)

// String renders the step for diagnostics and the rollback contract.
func (s CreateStep) String() string {
	switch s {
	case StepNone:
		return "none"
	case StepAllocate:
		return "step4-allocate-attach"
	case StepDigestAck:
		return "step6-digest-ack"
	case StepOverlay:
		return "step7-overlay-ca-inject"
	case StepBoot:
		return "step8-boot"
	case StepRoutable:
		return "step9-routable"
	default:
		return fmt.Sprintf("step%d", int(s))
	}
}

// CreateError surfaces a per-step create failure so the rollback path knows what
// host-side state exists to unwind. Step is the §4.1 step that failed; Binding is
// the (possibly partial) allocation recorded before the failure (zero if the
// failure preceded step 4); DomainUUID is the booted domain if one exists. The
// rollback driver reads these to decide which compensating verbs to run.
type CreateError struct {
	Step        CreateStep
	SessionUUID string
	Binding     Binding // partial allocation to unwind (zero before step 4)
	HasBinding  bool    // whether host-side objects (tap/nft/index) were created
	OverlayPath string  // overlay to dispose (empty before step 7)
	DomainUUID  string  // domain to destroy (empty before a successful boot)
	Err         error
}

func (e *CreateError) Error() string {
	return fmt.Sprintf("libvirt create session %s failed at %s: %v", e.SessionUUID, e.Step, e.Err)
}

func (e *CreateError) Unwrap() error { return e.Err }

// CreateRequest is the host-side input to the create path — the VmSpec fields
// (doc 15 §5.1) the host agent needs, carried as DATA (the orchestrator module
// is stdlib-only; the proto CloneFromImageRequest assembles these where the
// seam wires up). Every field is idempotent-keyed on SessionUUID.
type CreateRequest struct {
	SessionUUID         string // the global identity; every verb idempotent on it
	ImageID             string // content-addressed (repo, ref, env-spec hash) → image ID
	EntrypointConfigRef string // opaque D38 entrypoint config (step 8)
	CABundleRef         string // per-session interception CA bundle ref (step 7, D17/D82)

	// Posture is the OPTIONAL orchestrator-resolved per-session permission posture
	// (runtimev1.PermissionPosture, doc 13 §2), carried as resolved DATA: the orchestrator
	// module stays runtime-IGNORANT about HOW it was decided (the POL-1 resolution) and only
	// forwards the resolved enum to the gap-1 EntrypointConfig producer at the step-7/8
	// Produce call site (no §4.1 choreography restructure, no CreateStep signature change).
	// UNSPECIFIED (the zero value = "the orchestrator supplied none") makes the producer fall
	// back to the daemon-pinned EntrypointFacts.Posture (the M0 default-deny LOCKED pin) — it
	// is NOT a wire default for LOCKED; a CONCRETE value WINS over that daemon fallback
	// (post-M0 POL-1, doc 13 §2). The production CloneFromImage binding leaves it zero, so the
	// create path is byte-identical (UNSPECIFIED → LOCKED) until an orchestrator-resolved
	// posture is supplied. Validity is preserved downstream: the producer hands the builder a
	// CONCRETE posture after the fallback, so BuildEntrypointConfig's UNSPECIFIED-rejection
	// invariant is unchanged.
	Posture runtimev1.PermissionPosture
}

func (r CreateRequest) validate() error {
	if r.SessionUUID == "" {
		return fmt.Errorf("create request has no session uuid")
	}
	if r.ImageID == "" {
		return fmt.Errorf("create request for session %s has no image id", r.SessionUUID)
	}
	if r.CABundleRef == "" {
		// Fail-closed: no CA bundle ref means step-7 injection cannot prove the
		// interception CA is in the trust store, so the create must refuse before
		// booting a VM whose first TLS byte could bypass the egress gateway (D17).
		return fmt.Errorf("create request for session %s has no CA bundle ref (step-7 injection is fail-closed, D17)", r.SessionUUID)
	}
	return nil
}

// CreateResult is the host-side create output: the recorded binding (assembled
// into CloneFromImageResponse where the seam wires up) plus the booted domain
// and the routable verdict. Routable is true only when the structural step-9
// gate held (digest ack AND policy freshness); a created-but-not-yet-routable
// session is a valid intermediate, never an egress-capable one.
type CreateResult struct {
	Binding    Binding
	DomainUUID string
	Routable   bool
}

// HostAgent is the per-host create driver — the orchestrator-Accountable half of
// the tap-create RACI row (doc 14 §4) plus the step-7–9 choreography. It owns the
// index allocator and invokes the boundary/identity-owned seams; it never writes
// nft objects or mints keys itself.
type HostAgent struct {
	alloc   *Allocator
	attach  AttachPrimitive
	overlay OverlayStore
	ca      CAInjector
	booter  Booter
	gate    RoutabilityGate
	// records is the OPTIONAL durable session-record store (sessionrecord.go): when
	// set (the live path), CreateSession persists the booted session's binding so a
	// host-agent restart can re-adopt it (the SessionRecoverer reads it back, D66).
	// nil off the live path (no durable recovery there) — the create path skips the
	// write, the existing behavior.
	records SessionRecordStore
	// entrypoint is the OPTIONAL gap-1 EntrypointConfig producer (entrypointconfig.go):
	// when set, the step-7/8 boot site fetches the opaque role-overlay bytes by the
	// recorded EntrypointConfigRef, assembles + validates the STRUCTURED
	// runtimev1.EntrypointConfig from the recorded binding + the host-resolved facts, and
	// delivers config.pb into the guest via a per-session read-only config-drive — all
	// BEFORE Boot (so the guest can read its config). nil off the wired path: the create
	// path is then byte-identical to the historical choreography (the Booter still receives
	// the opaque EntrypointConfigRef and the producer step is skipped entirely).
	entrypoint *EntrypointProducer
	// postBoot is the OPTIONAL post-boot lifecycle hook the daemon composition root wires
	// (cmd/host-agent) to stand up the per-session gap-3 attach serving leg (the
	// ds-hostbridge child the AttachBridge manages) once a session has booted. It runs
	// AFTER a successful Boot + record-write, given the session UUID and the recorded
	// Binding (so the hook can derive the per-session guest IP the serving leg bridges to).
	// It is BEST-EFFORT and NON-FATAL: a hook error never fails or unwinds a booted session
	// (the attach serving leg is distinct from boot — a not-yet-served session is still a
	// valid booted session whose attach leg can be retried), so the create path's
	// boot/record/routable failure semantics are byte-identical to before. nil off the wired
	// path (the hook is skipped entirely — the historical create path). Defined as a plain
	// callback (not an interface importing hostagent) so the libvirt tree never imports the
	// hostagent tree (the import direction stays hostagent → libvirt; the adapter that calls
	// AttachBridge.Serve lives in the daemon root).
	postBoot PostBootHook
	// readiness is the OPTIONAL host-WIDE boundary-readiness precondition (seams.go
	// BoundaryReadiness, doc 09 §3 / D63/D69/D70): when set, CreateSession PROBES it as
	// its FIRST host-touching action — after req.validate() and BEFORE the step-4
	// boundary (h.alloc.Allocate) — and refuses the create at StepNone (fail-closed: no
	// VM started) on any not-ready verdict OR uncertain probe, so a session is never
	// admitted onto an un-fenced host (the three boundary nft tables missing, or
	// ds-dnsgate/ds-tlsproxy not answering). nil ⇒ the historical/offline default (no
	// host-boundary precondition; the create path is byte-identical to today). It is a
	// new host-WIDE gate that DOMINATES the per-session RoutabilityGate (DigestAck step
	// 6 / PolicyFresh step 9) — distinct from them — and is admission-only: it never
	// weakens the self-sufficient kernel ds_boundary floor (doc 09 §3).
	readiness BoundaryReadiness
	// hookFault is the OUT-OF-BAND observability sink for a SWALLOWED post-boot hook fault.
	// The post-boot hook (the gap-3 serving-leg stand-up) is best-effort/non-fatal: a hook
	// error must never fail or unwind a booted session, so its error is swallowed from the
	// create VERDICT. Before this seam that swallow was silent — a serving-leg fault left no
	// host-side trace, so an attach leg that failed to stand up looked identical to one that
	// succeeded. hookFault surfaces that swallowed fault STRUCTURALLY out-of-band (telemetry/
	// log), NOT as part of the verdict: the create still succeeds byte-identically, but the
	// fault is now observable. It is an injectable field (mirroring liveSuspender.audit) so a
	// test can capture the observation instead of writing to stderr; it is NEVER nil at the
	// observation site (the constructors install defaultHookFaultObserver), and it is invoked
	// ONLY when the swallowed hook actually returns a non-nil error (a clean hook emits nothing).
	hookFault HookFaultObserver
}

// HookFaultObserver is the OUT-OF-BAND sink for a swallowed best-effort hook fault. It carries
// the structured context of the fault — which hook swallowed it (HookKind), the session it was
// running for, and the error — so an operator can see a serving-leg stand-up that silently
// failed WITHOUT the fault ever entering the create verdict. It is observability, not a gate: it
// has no error return (an observer that itself faults must not regress the swallow). The default
// (defaultHookFaultObserver) writes a structured line to the standard logger (stderr); the
// composition root can swap it for a durable telemetry sink, and a test installs a capturing one.
type HookFaultObserver func(obs HookFault)

// HookFault is the structured record of a swallowed best-effort hook fault, surfaced out-of-band.
// It is the observability payload — distinct from *CreateError, which is the VERDICT type. A
// HookFault is emitted EXACTLY when a swallowed hook returned a non-nil error; the create result
// is unchanged.
type HookFault struct {
	// Hook names which best-effort hook swallowed the fault (e.g. the post-boot serving-leg
	// stand-up), so a telemetry consumer can attribute it without parsing the message.
	Hook HookKind
	// SessionUUID is the session the swallowed hook was running for.
	SessionUUID string
	// Err is the swallowed error (never nil when a HookFault is emitted).
	Err error
}

// HookKind names the best-effort hook a swallowed fault came from, so the out-of-band observation
// is attributable without string-matching.
type HookKind int

const (
	// HookPostBoot is the post-boot gap-3 serving-leg stand-up hook (PostBootHook).
	HookPostBoot HookKind = iota + 1
)

// String renders the hook kind for the default observer's structured line.
func (k HookKind) String() string {
	switch k {
	case HookPostBoot:
		return "post-boot-serving-leg"
	case HookPostDestroy:
		return "post-destroy-serving-leg-reap"
	default:
		return fmt.Sprintf("hook%d", int(k))
	}
}

// defaultHookFaultObserver is the default out-of-band sink: it writes a structured line naming
// the hook, the session, and the swallowed error to the standard logger (stderr). The fault is
// RECORDED here, never re-surfaced into the verdict — the create outcome is unchanged. The
// composition root can swap it for a durable telemetry sink; the seam stays an injectable field
// so the offline test can capture the observation instead.
func defaultHookFaultObserver(obs HookFault) {
	log.Printf("ds hook fault (swallowed, out-of-band): hook=%s session=%s err=%v", obs.Hook, obs.SessionUUID, obs.Err)
}

// PostBootHook is the OPTIONAL post-boot lifecycle callback (the gap-3 serving-leg
// stand-up). The daemon composition root supplies it; it runs after a successful boot +
// record-write with the session UUID and the recorded Binding. A returned error is
// BEST-EFFORT/NON-FATAL — the create logs/swallows it (the booted session stands; the attach
// leg can be retried), so wiring the hook never changes the create's boot failure semantics.
type PostBootHook func(ctx context.Context, sessionUUID string, binding Binding) error

// NewHostAgent assembles the create driver from its allocator and the seams it
// invokes. A nil dependency is a programming error surfaced at construction. The
// session-record store is left unset (the no-recovery default); the live host
// uses NewHostAgentWithRecords to persist records for crash re-adoption.
func NewHostAgent(alloc *Allocator, attach AttachPrimitive, overlay OverlayStore, ca CAInjector, booter Booter, gate RoutabilityGate) (*HostAgent, error) {
	return NewHostAgentWithRecords(alloc, attach, overlay, ca, booter, gate, nil)
}

// NewHostAgentWithRecords is NewHostAgent plus the OPTIONAL durable session-record
// store: when records is non-nil (the live path), a booted session's binding is
// persisted at step 8 so the SessionRecoverer can re-adopt it after a restart
// (D66). A nil records is the no-recovery default (NewHostAgent). The core seams
// are still required; only records is optional.
func NewHostAgentWithRecords(alloc *Allocator, attach AttachPrimitive, overlay OverlayStore, ca CAInjector, booter Booter, gate RoutabilityGate, records SessionRecordStore) (*HostAgent, error) {
	return NewHostAgentWithEntrypoint(alloc, attach, overlay, ca, booter, gate, records, nil, nil)
}

// NewHostAgentWithEntrypoint is NewHostAgentWithRecords plus the OPTIONAL gap-1
// EntrypointConfig producer (entrypointconfig.go) and the OPTIONAL gap-3 post-boot hook (the
// per-session attach serving-leg stand-up the daemon root wires):
//
//   - entrypoint (non-nil): the step-7/8 boot site fetches the opaque role-overlay bytes by
//     the recorded EntrypointConfigRef, assembles + validates the STRUCTURED
//     runtimev1.EntrypointConfig from the recorded binding + the host-resolved facts, and
//     delivers config.pb into the guest via a per-session read-only config-drive — BEFORE
//     Boot;
//   - postBoot (non-nil): a best-effort/non-fatal callback the create path invokes AFTER a
//     successful boot + record-write (the daemon wires it to AttachBridge.Serve).
//
// Both nil is the historical default (NewHostAgent / NewHostAgentWithRecords): the create
// path is then byte-identical to the pre-gap1/gap3 choreography (the Booter still receives
// the opaque ref; the producer + hook are skipped). The core seams are still required;
// records, entrypoint, and postBoot are optional. It delegates to the deepest
// NewHostAgentWithReadiness with a nil readiness (no host-boundary precondition), so every
// existing caller and test stays byte-identical.
func NewHostAgentWithEntrypoint(alloc *Allocator, attach AttachPrimitive, overlay OverlayStore, ca CAInjector, booter Booter, gate RoutabilityGate, records SessionRecordStore, entrypoint *EntrypointProducer, postBoot PostBootHook) (*HostAgent, error) {
	return NewHostAgentWithReadiness(alloc, attach, overlay, ca, booter, gate, records, entrypoint, postBoot, nil)
}

// NewHostAgentWithReadiness is the DEEPEST constructor: NewHostAgentWithEntrypoint plus the
// OPTIONAL host-WIDE BoundaryReadiness precondition (seams.go / doc 09 §3, D63/D69/D70).
// When readiness is non-nil (the live path), CreateSession PROBES it as its FIRST
// host-touching action — after req.validate() and BEFORE any host-side mutation (step 4) —
// and refuses the create at StepNone (fail-closed: no VM started) on any not-ready verdict
// OR uncertain probe, so a session is never admitted onto an un-fenced host. A nil readiness
// is the historical/offline default (nil ⇒ ready): the create path is byte-identical to
// today. The core seams are still required (the existing nil-dependency switch); records,
// entrypoint, postBoot, and readiness are optional.
func NewHostAgentWithReadiness(alloc *Allocator, attach AttachPrimitive, overlay OverlayStore, ca CAInjector, booter Booter, gate RoutabilityGate, records SessionRecordStore, entrypoint *EntrypointProducer, postBoot PostBootHook, readiness BoundaryReadiness) (*HostAgent, error) {
	switch {
	case alloc == nil:
		return nil, fmt.Errorf("libvirt host agent requires an allocator")
	case attach == nil:
		return nil, fmt.Errorf("libvirt host agent requires an attach primitive")
	case overlay == nil:
		return nil, fmt.Errorf("libvirt host agent requires an overlay store")
	case ca == nil:
		return nil, fmt.Errorf("libvirt host agent requires a CA injector")
	case booter == nil:
		return nil, fmt.Errorf("libvirt host agent requires a booter")
	case gate == nil:
		return nil, fmt.Errorf("libvirt host agent requires a routability gate")
	}
	return &HostAgent{alloc: alloc, attach: attach, overlay: overlay, ca: ca, booter: booter, gate: gate, records: records, entrypoint: entrypoint, postBoot: postBoot, readiness: readiness, hookFault: defaultHookFaultObserver}, nil
}

// WithHookFaultObserver installs an OUT-OF-BAND observer for swallowed best-effort hook faults,
// returning the same *HostAgent for chaining at composition. The observer surfaces a swallowed
// post-boot hook fault structurally (telemetry/log) WITHOUT changing the create verdict (the hook
// stays best-effort/non-fatal). A nil observer is ignored (the default stderr sink is kept), so a
// post-boot fault is NEVER silently un-observed. The composition root calls this to route hook
// faults to a durable telemetry sink; the offline test installs a capturing observer to assert
// the fault surfaces out-of-band.
func (h *HostAgent) WithHookFaultObserver(obs HookFaultObserver) *HostAgent {
	if obs != nil {
		h.hookFault = obs
	}
	return h
}

// CreateSession runs the host-agent create path of doc 15 §4.1 steps 4–9 over
// the libvirt v0 driver. It honors the frozen precedence constraints (§4.1:
// "the binding must be recorded before routable, and the CloneFromImageResponse
// carries it"; 5 ≺ 7's injection; 7 ≺ 8; {3,6} ≺ 9) and surfaces every per-step
// failure as a *CreateError carrying the partial host-side state, so the sibling
// hostagent-destroy-teardown task can drive the matching compensating rollback.
//
// The sequence:
//
//	pre-4   host-WIDE BoundaryReadiness probe (OPTIONAL seam, doc 09 §3 / D63/D69):
//	        the three boundary nft tables present AND ds-dnsgate/ds-tlsproxy answer.
//	        Fail-closed at StepNone — BEFORE any host-side object exists — so a
//	        session is never admitted onto an un-fenced host. Dominates steps 4–9
//	        transitively; distinct from the per-session DigestAck/PolicyFresh gates;
//	        admission-only (never weakens the self-sufficient kernel ds_boundary floor).
//	step 4  allocate index → derive (tap_name, guest_ip) → CreateTap →
//	        InstantiateSessionNFT → RECORD the three-keys-agree binding
//	step 6  DigestAck gate (mint-before-attach, D73)
//	step 7  CreateOverlay → InjectCA FAIL-CLOSED (D17)
//	step 8  Boot per the D38 entrypoint contract (event socket host-side)
//	step 9  structural routable gate (digest ack AND policy freshness)
//
// The binding is recorded (returned) BEFORE the routable verdict is computed —
// the frozen precedence — so even a session that fails the step-9 gate has its
// binding available for the session record and for rollback.
func (h *HostAgent) CreateSession(ctx context.Context, req CreateRequest) (CreateResult, error) {
	if err := req.validate(); err != nil {
		// Pre-step-4 refusal: nothing host-side exists yet (doc 15 §4.1
		// Rollback: "failure at 1–3 ... nothing host-side exists").
		return CreateResult{}, &CreateError{Step: StepNone, SessionUUID: req.SessionUUID, Err: err}
	}

	// ── pre-step-4: host-WIDE boundary-readiness gate (doc 09 §3, D63/D69) ────
	// The FIRST host-touching action, BEFORE any host-side mutation (h.alloc.Allocate
	// at step 4). It verifies the three boundary nft tables are present AND the two
	// boundary services answer, refusing the create FAIL-CLOSED on any not-ready
	// verdict OR uncertain probe — so a session is never admitted onto an un-fenced
	// host. Pre-step-4: nothing host-side exists to unwind (the doc 15 §4.1 Rollback
	// "failure at 1–3" cell — no index burned, no tap, no per-session NFT, no overlay,
	// no CA inject, no boot, no record), so the create owes no compensating verbs. The
	// StepNone refusal is the SAME pre-step-4 value req.validate() failure uses, which
	// the service binding maps to a FailedPrecondition refusal (a not-yet-ready host).
	// nil readiness ⇒ the historical/offline default (ready) — byte-identical to today.
	// This gate DOMINATES the per-session DigestAck (step 6) / PolicyFresh (step 9)
	// gates transitively and is admission-only (it never weakens the self-sufficient
	// kernel ds_boundary floor, doc 09 §3).
	if h.readiness != nil {
		ready, detail, err := h.readiness.Probe(ctx)
		if err != nil {
			return CreateResult{}, &CreateError{Step: StepNone, SessionUUID: req.SessionUUID, Err: fmt.Errorf("boundary-readiness probe uncertain (fail-closed: no VM started, D63/D69): %w", err)}
		}
		if !ready {
			return CreateResult{}, &CreateError{Step: StepNone, SessionUUID: req.SessionUUID, Err: fmt.Errorf("host boundary not ready (fail-closed: no VM started): %s (refusing to admit a session onto an un-fenced host, D63/D69)", detail)}
		}
	}

	// ── step 4: host-side allocation + tap/NFT attach + binding ──────────────
	binding, err := h.alloc.Allocate()
	if err != nil {
		// The index, if drawn, is BURNED — never recycled (D66). No host-side
		// object exists past the allocator, so no flush is owed yet.
		return CreateResult{}, &CreateError{Step: StepAllocate, SessionUUID: req.SessionUUID, Err: fmt.Errorf("allocate binding: %w", err)}
	}
	if err := h.attach.CreateTap(ctx, binding); err != nil {
		// The tap may be half-created; the binding (incl. the burned index) is
		// recorded so rollback can flush_session(legs=all) + NFT-6 (§4.1).
		return CreateResult{}, &CreateError{Step: StepAllocate, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, Err: fmt.Errorf("create tap %s: %w", binding.TapName, err)}
	}
	if err := h.attach.InstantiateSessionNFT(ctx, req.SessionUUID, binding); err != nil {
		return CreateResult{}, &CreateError{Step: StepAllocate, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, Err: fmt.Errorf("instantiate session nft objects: %w", err)}
	}
	// The three-keys-agree binding is now RECORDED (the §4.1 precedence: recorded
	// before routable; CloneFromImageResponse carries it). Re-assert the
	// invariant after attach so a seam that mutated the keys can't slip through.
	if err := binding.validate(); err != nil {
		return CreateResult{}, &CreateError{Step: StepAllocate, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, Err: fmt.Errorf("recorded binding invalid: %w", err)}
	}

	// ── step 6: session-scoped digest write + ack (mint-before-attach, D73) ──
	// Step 5 (identity + interception-CA mint) is the orchestrator spine's; the
	// host-agent path consumes its result at the step-6 ack gate and the step-7
	// injection. The session cannot become routable until this ack lands.
	acked, err := h.gate.DigestAcked(ctx, req.SessionUUID)
	if err != nil {
		return CreateResult{}, &CreateError{Step: StepDigestAck, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, Err: fmt.Errorf("digest-ack gate: %w", err)}
	}
	if !acked {
		// Not an error per se — but the create cannot proceed to a routable
		// session without it. Surfaced as a step-6 failure so rollback flushes
		// the host-side objects (the digest write is unwound identity-side).
		return CreateResult{}, &CreateError{Step: StepDigestAck, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, Err: fmt.Errorf("session-scoped digest not acked (mint-before-attach, D73)")}
	}

	// ── step 7: overlay clone + CA injection (FAIL-CLOSED, D17/D29) ──────────
	overlayPath, err := h.overlay.CreateOverlay(ctx, req.SessionUUID, req.ImageID)
	if err != nil {
		return CreateResult{}, &CreateError{Step: StepOverlay, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, Err: fmt.Errorf("create overlay: %w", err)}
	}
	binding.OverlayPath = overlayPath
	if err := h.ca.InjectCA(ctx, overlayPath, req.CABundleRef); err != nil {
		// FAIL-CLOSED: injection failure FAILS THE CREATE (doc 15 §4.1 step 7).
		// The overlay exists and must be disposed; the binding is unwound after.
		return CreateResult{}, &CreateError{Step: StepOverlay, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, OverlayPath: overlayPath, Err: fmt.Errorf("inject interception CA fail-closed: %w", err)}
	}

	// ── step-7/8 boundary: gap-1 EntrypointConfig build + deliver (D38, BEFORE Boot) ──
	// When the gap-1 producer is wired AND the create carries an entrypoint-config ref, the
	// recorded binding + the host-resolved facts + the orchestrator-dropped opaque overlay
	// bytes (fetched by the ref) are assembled into the STRUCTURED runtimev1.EntrypointConfig
	// and delivered into the guest via a per-session read-only config-drive — all BEFORE Boot,
	// so the carrier exists before the guest can mount it. The build VALIDATES the config
	// host-side (fail-closed: a malformed config aborts the create at the boot step rather than
	// booting a guest that would fail-closed on its config). Surfaced as a step-8 failure
	// (carrying the overlay + binding) so the rollback path disposes the overlay then unwinds
	// step 4 — the same posture as a Boot fault. ADDITIVE: when the producer is nil (the
	// historical default), or there is no ref, this is skipped entirely and the Booter still
	// receives the opaque ref — byte-identical to the pre-gap1 choreography.
	//
	// The per-create permission posture (req.Posture, the orchestrator-resolved POL-1 value)
	// rides the same Produce call as resolved DATA: a CONCRETE posture WINS; UNSPECIFIED ("none
	// supplied") falls back inside the producer to the daemon-pinned EntrypointFacts.Posture
	// (LOCKED). The create path is byte-identical when req.Posture is UNSPECIFIED — the zero
	// value the production CloneFromImage binding leaves it at.
	if h.entrypoint != nil && req.EntrypointConfigRef != "" {
		if _, err := h.entrypoint.ProduceConfig(ctx, ProduceInput{
			SessionUUID:         req.SessionUUID,
			Binding:             binding,
			EntrypointConfigRef: req.EntrypointConfigRef,
			Posture:             req.Posture,
		}); err != nil {
			return CreateResult{}, &CreateError{Step: StepBoot, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, OverlayPath: overlayPath, Err: fmt.Errorf("build+deliver entrypoint config: %w", err)}
		}
	}

	// ── step 8: boot + entrypoint (D38; event socket terminated host-side) ───
	// Thread the recorded binding's deterministic per-session VsockCID (alloc.go =
	// HostSessionIndex + reservedVsockCIDs) into the boot so the live domain render
	// PINS the AF_VSOCK control channel as `<cid auto='no' address='<VsockCID>'/>` —
	// the host-predictable guest CID the host agent's attach serving leg dials. Zero
	// (the offline/pre-allocate sentinel) keeps the render auto-assigned.
	//
	// Also thread the recorded binding's `dstap-<idx>` TapName so a GATE-ON boot
	// (DS_ROUTED_TAP, LiveConfig.RoutedTap read at construction) attaches the VM to
	// its per-session routed tap (`<interface type='ethernet'><target
	// dev='<TapName>'/>`) instead of usermode SLIRP. The tap carries no egress until
	// U3 (host routing) + U4 (guest IP) land, so this is inert until then; GATE-OFF
	// (the default) the render ignores TapName and keeps the historical SLIRP NIC.
	domainUUID, err := h.booter.Boot(ctx, req.SessionUUID, overlayPath, req.EntrypointConfigRef, binding.TapName, binding.VsockCID)
	if err != nil {
		return CreateResult{}, &CreateError{Step: StepBoot, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, OverlayPath: overlayPath, Err: fmt.Errorf("boot domain: %w", err)}
	}

	// Persist the durable session record (the resident session's three-keys-agree
	// binding) so a host-agent restart can re-adopt it — the libvirt domain XML
	// carries only the session UUID, not the binding (D66, doc 15 §4). Gated: nil
	// off the live path (no durable recovery there). A record-write fault FAILS the
	// create at step 8: a session that cannot be durably recorded must not be left
	// booted-but-unrecoverable (its index would be lost on a restart, risking a
	// re-handed never-recycled index). The booted domain is disposed by the
	// rollback path (the *CreateError carries the binding + DomainUUID).
	//
	// The record also carries the request's CABundleRef (non-empty by the fail-closed
	// validate above) — the ONLY durable carrier of that ref, and therefore the only way a
	// converged §4.2 Destroy can find the host-readable CA bundle (cert + proxy-bound key)
	// to dispose (D82; cabundledisposer.go).
	if h.records != nil {
		rec := SessionRecord{SessionUUID: req.SessionUUID, DomainUUID: domainUUID, Binding: binding, CABundleRef: req.CABundleRef}
		if err := h.records.Put(ctx, rec); err != nil {
			return CreateResult{}, &CreateError{Step: StepBoot, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, OverlayPath: overlayPath, DomainUUID: domainUUID, Err: fmt.Errorf("persist session record: %w", err)}
		}
	}

	// ── post-boot gap-3 serving-leg stand-up (best-effort, NON-FATAL) ─────────
	// The session has booted; stand up its per-session attach serving leg (the daemon wires
	// this to AttachBridge.Serve, which off DS_HOSTAGENT_LIVE launches nothing). It is
	// best-effort by contract: a hook fault never fails or unwinds a booted session (the
	// attach leg is distinct from boot — a not-yet-served session is still valid and the leg
	// can be retried), so the boot/record/routable failure semantics are unchanged. Skipped
	// entirely when no hook is wired (the historical path).
	//
	// The hook's error is still SWALLOWED FROM THE VERDICT (it never becomes a *CreateError),
	// but it is no longer dropped silently: a non-nil hook error is surfaced OUT-OF-BAND through
	// the hookFault observer (defaultHookFaultObserver writes a structured stderr line; the
	// composition root can route it to durable telemetry). This makes a serving-leg stand-up
	// that silently failed observable WITHOUT changing the create's success/failure outcome —
	// the create still returns its routable verdict unchanged. The observer fires ONLY on an
	// actual fault (a clean hook emits nothing), so the happy path is byte-identical.
	if h.postBoot != nil {
		if hookErr := h.postBoot(ctx, req.SessionUUID, binding); hookErr != nil {
			obs := h.hookFault
			if obs == nil {
				// Defensive: a HostAgent always installs the default observer at construction,
				// but a zero-value agent must still never silently drop a swallowed hook fault.
				obs = defaultHookFaultObserver
			}
			obs(HookFault{Hook: HookPostBoot, SessionUUID: req.SessionUUID, Err: hookErr})
		}
	}

	// ── step 9: structural routable gate ({3,6} ≺ 9) ────────────────────────
	// Routable iff the digest ack landed (re-confirmed: step 6 held above) AND
	// host policy is fresh (step 3 re-checked). Enforced structurally: the
	// result is non-routable unless both hold; the binding is already recorded.
	fresh, err := h.gate.PolicyFresh(ctx)
	if err != nil {
		return CreateResult{}, &CreateError{Step: StepRoutable, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, OverlayPath: overlayPath, DomainUUID: domainUUID, Err: fmt.Errorf("policy-freshness gate: %w", err)}
	}
	if !fresh {
		// Booted but not routable: the binding is recorded and the domain is up,
		// but no first egress byte may exist. The reconciler/destroy path decides
		// whether to wait for freshness or unwind; surfaced as a step-9 failure.
		return CreateResult{Binding: binding, DomainUUID: domainUUID, Routable: false},
			&CreateError{Step: StepRoutable, SessionUUID: req.SessionUUID, Binding: binding, HasBinding: true, OverlayPath: overlayPath, DomainUUID: domainUUID, Err: fmt.Errorf("host policy stale at routable gate (D72)")}
	}

	return CreateResult{Binding: binding, DomainUUID: domainUUID, Routable: true}, nil
}
