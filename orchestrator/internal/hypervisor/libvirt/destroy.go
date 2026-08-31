// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"fmt"
)

// destroy.go is the host-agent's libvirt-side §4.2 destroy ordering — the
// owned teardown the reconciler drives (desired = DESTROYED) and the §4.1
// create-rollback compensates from. It runs AGAINST the existing seams (the
// AttachPrimitive.FlushSession, the OverlayStore.DisposeOverlay) plus the
// destroy-specific seams below; it does NOT re-implement flush_session (that
// is DONE in ds-nft, invoked through the seam) and it does NOT touch the
// kernel (the ds-nft cgo bridge is a separately-tracked follow-up — this
// module stays stdlib-only and offline, the deferred-binding posture of
// seams.go / internal/nftbridge).
//
// THE FROZEN §4.2 ORDER (doc 15 §4.2; doc 09 §3 NFT-6):
//
//	1. Guest VM destroy (libvirt domain destroy).
//	2. flush_session(session, legs=all) — UNCONDITIONAL (D68) — driving the
//	   NFT-6 order: interface rules → named sets (allow{4,6}_<session>) + the
//	   DNS-2b admission map → conntrack by mark; destroy events carry the final
//	   byte counts into ds-flowlog (doc 14 §5).
//	3. Overlay disposal + D29 dirty-bitmap durability-stream finalization.
//
// Steps 4–6 of the §4.2 list (digest flush + ask-grant expiry; identity/CA
// revocation; DESTROYED-via-heartbeat) are the host-AGENT's to orchestrate
// (internal/hostagent/destroy.go) — this libvirt driver owns the host-local
// VM + NFT + overlay teardown (steps 1–3), the part that must leave the
// ruleset byte-identical to bootstrap (NFT-6: a create→destroy loop run N
// times leaves the ruleset byte-identical to bootstrap, asserted per-commit by
// the doc 06 (b) clean-teardown conformance).
//
// IDEMPOTENT ON session_uuid (every driver verb is, doc 15 §5.1): a Destroy of
// an already-destroyed session is a no-op that still satisfies the
// clean-teardown checklist (flush_session is unconditional — a re-flush of a
// session with no live objects converges, never errors).

// DomainDestroyer destroys the libvirt guest domain (doc 15 §4.2 step 1). It is
// the host-agent's consume side of the libvirt domain-destroy primitive; the v0
// impl drives libvirt-go, a test fake records the destroyed domains. Idempotent:
// destroying an absent domain (already gone, or never booted) is a no-op, never
// an error — a create that failed before boot has no domain to destroy and the
// rollback must still converge.
type DomainDestroyer interface {
	// DestroyDomain destroys the domain for the session. domainUUID may be empty
	// (a create that rolled back before a successful boot); the impl treats an
	// empty/absent domain as already-destroyed (no-op). Idempotent on session_uuid.
	DestroyDomain(ctx context.Context, sessionUUID, domainUUID string) error
}

// DurabilityFinalizer closes the D29 dirty-bitmap durability stream for the
// session's overlay at teardown (doc 15 §4.2 step 3). The overlay is the delta
// store, the inspectable artifact, AND the durability unit (D29); finalizing the
// stream is distinct from disposing the overlay (OverlayStore.DisposeOverlay) —
// the stream is closed BEFORE the overlay is disposed so the durability record is
// consistent at the point of disposal. Idempotent: finalizing an absent/closed
// stream is a no-op. A nil overlay path (a create that failed before step 7) has
// no stream to finalize.
type DurabilityFinalizer interface {
	// FinalizeDurabilityStream closes the dirty-bitmap durability stream for the
	// overlay (D29). An empty overlayPath (no overlay was ever created) is a no-op.
	FinalizeDurabilityStream(ctx context.Context, sessionUUID, overlayPath string) error
}

// FlowByteCounter emits the FINAL per-session byte counts into ds-flowlog at
// teardown (doc 15 §4.2 step 2 / doc 14 §5: "destroy events carry final byte
// counts into ds-flowlog"). The counts are read from conntrack-by-mark just
// before the conntrack flush (the third NFT-6 phase) so the destroy event
// reflects the session's full lifetime accounting. v0 reads them through the
// same ds-nft edge flush_session rides; a test fake records the emitted events.
// Emitting the counts is NON-FATAL to teardown: a flowlog hiccup must never
// strand a session's NFT objects (clean teardown wins over a missed accounting
// event — the missed event is recorded, never a teardown abort).
type FlowByteCounter interface {
	// EmitDestroyByteCounts emits the session's final byte counts into ds-flowlog.
	// It is called AFTER the interface rules and named sets are removed but BEFORE
	// (or in lockstep with) the conntrack-by-mark flush — the last point the
	// per-session ct-mark accounting is readable. A returned error is recorded as a
	// teardown warning, never a teardown abort (clean teardown is the contract).
	EmitDestroyByteCounts(ctx context.Context, sessionUUID string, b Binding) error
}

// DestroyStep names the §4.2 teardown phase a destroy fault surfaced at, so the
// host-agent orchestrator (internal/hostagent) can record WHERE a teardown
// stalled and the reconciler can re-drive. The numbering mirrors the §4.2 list.
type DestroyStep int

const (
	// DestroyStepNone is the zero value — no step has failed.
	DestroyStepNone DestroyStep = 0
	// DestroyStepDomain is §4.2 step 1: guest VM (libvirt domain) destroy.
	DestroyStepDomain DestroyStep = 1
	// DestroyStepFlush is §4.2 step 2: flush_session(legs=all) + the NFT-6 order.
	DestroyStepFlush DestroyStep = 2
	// DestroyStepOverlay is §4.2 step 3: overlay disposal + durability finalize.
	DestroyStepOverlay DestroyStep = 3
)

// String renders the destroy step for diagnostics.
func (s DestroyStep) String() string {
	switch s {
	case DestroyStepNone:
		return "none"
	case DestroyStepDomain:
		return "step1-domain-destroy"
	case DestroyStepFlush:
		return "step2-flush-session-nft6"
	case DestroyStepOverlay:
		return "step3-overlay-dispose-durability"
	default:
		return fmt.Sprintf("destroy-step%d", int(s))
	}
}

// DestroyError surfaces a per-step host-local teardown fault. Because the §4.2
// order is UNCONDITIONAL (D68: the session-end flush always runs), the driver
// keeps going past a step-1 fault (a domain that won't destroy must not strand
// the NFT objects), so a DestroyError may carry the FIRST fault while the rest
// of the order still ran — Step is the first step that faulted, Err wraps it.
// The host-agent orchestrator records this as a teardown warning and the
// reconciler re-drives (idempotent on session_uuid).
type DestroyError struct {
	Step        DestroyStep
	SessionUUID string
	Err         error
}

func (e *DestroyError) Error() string {
	return fmt.Sprintf("libvirt destroy session %s faulted at %s: %v", e.SessionUUID, e.Step, e.Err)
}

func (e *DestroyError) Unwrap() error { return e.Err }

// DestroyRequest is the host-local teardown input: the session identity plus the
// host-side state to unwind (the recorded Binding, the booted domain). A
// zero/partial state is valid — a create-rollback from an early step carries only
// what it created (e.g. a step-4 rollback has a Binding but no DomainUUID/overlay).
// FlushSession is invoked UNCONDITIONALLY regardless of how much state exists
// (D68): even a binding-only partial allocation must have its NFT objects flushed.
type DestroyRequest struct {
	// SessionUUID is the global identity; every teardown verb is idempotent on it.
	SessionUUID string
	// Binding is the recorded three-keys-agree allocation to tear down (the
	// allow{4,6}_<session> sets, the interface rules, the ct-mark accounting key).
	// Zero when the create failed before step 4 — but FlushSession STILL runs
	// (unconditional): a partial/absent binding flushes to a no-op convergence.
	Binding Binding
	// HasBinding records whether host-side NFT/tap objects were created (the
	// step-4+ create-rollback case). It drives the byte-count emission (only a
	// real binding has ct-mark accounting to read), never the flush — the flush is
	// unconditional.
	HasBinding bool
	// DomainUUID is the booted libvirt domain to destroy (step 1). Empty when no
	// domain was ever booted (a rollback before step 8) — domain destroy is a
	// no-op then.
	DomainUUID string
	// OverlayPath is the qcow2 overlay to dispose + finalize the durability stream
	// for (step 3). Empty when no overlay was ever created (a rollback before
	// step 7) — overlay disposal + durability finalize are no-ops then.
	OverlayPath string
}

// DestroyResult reports what the host-local teardown did, so the host-agent
// orchestrator can fold it into the DESTROYED heartbeat and the conformance
// assertion can confirm the unconditional flush ran.
type DestroyResult struct {
	// DomainDestroyed is true when step 1 ran (a domain existed and was destroyed,
	// or was already absent — both converge to destroyed).
	DomainDestroyed bool
	// SessionFlushed is true when the UNCONDITIONAL flush_session(legs=all) ran.
	// It is ALWAYS true on a non-fatal return — the flush is unconditional (D68);
	// a false here means the flush itself faulted (recorded on the DestroyError).
	SessionFlushed bool
	// OverlayDisposed is true when step 3 disposed an overlay (false when none
	// existed).
	OverlayDisposed bool
	// ByteCountsEmitted is true when the final ds-flowlog byte-count event was
	// emitted (only for a real binding; a binding-less partial has no accounting).
	ByteCountsEmitted bool
}

// Destroyer is the host-agent's libvirt-side §4.2 teardown driver. It owns the
// host-local steps 1–3 (domain destroy → unconditional flush_session + NFT-6
// order + final byte counts → overlay disposal + durability finalize) against
// the existing AttachPrimitive.FlushSession seam (flush_session is DONE in
// ds-nft — invoked, never re-implemented) and the destroy-specific seams. It is
// the (b)-conformance core: a create→destroy loop driven N times against the
// RecordingBackend leaves the ruleset byte-identical to bootstrap (NFT-6).
type Destroyer struct {
	domain    DomainDestroyer
	attach    AttachPrimitive // FlushSession (NFT-6) is invoked through here
	overlay   OverlayStore    // DisposeOverlay
	durab     DurabilityFinalizer
	flowBytes FlowByteCounter
	// postDestroy is the OPTIONAL post-destroy lifecycle hook the daemon composition
	// root wires (cmd/host-agent) to REAP the per-session gap-3 attach serving child
	// (the ds-hostbridge process the AttachBridge owns) once a session's host-local
	// objects have been torn down. It runs AFTER the §4.2 host-local teardown (domain
	// destroy → unconditional flush_session + NFT-6 → overlay dispose/durability), given
	// the session UUID, so the serving leg the create-path post-boot hook stood up is
	// reaped at session DESTROY, not only at daemon Shutdown.
	//
	// It is BEST-EFFORT and NON-FATAL: a reap is bookkeeping on a child the destroy has
	// already obviated (the guest is gone — the relay has nothing to bridge), so a hook
	// fault is SWALLOWED FROM THE VERDICT — it never touches the Destroy result (the
	// clean-teardown contract: NFT objects + overlay win over a missed child reap). The
	// AttachBridge.Destroy adapter is itself idempotent and infallible (it returns
	// nothing), so this seam swallows nothing meaningful today — but it is invoked
	// swallowed-by-contract so a FUTURE hook that errors cannot regress the §4.2 fault
	// posture into a faulted Destroy, exactly mirroring create.go's PostBootHook.
	//
	// nil off the wired path: the destroy path is then BYTE-IDENTICAL to the historical
	// §4.2 choreography (the hook site is skipped entirely). Defined as a plain callback
	// (not an interface importing hostagent) so the libvirt tree never imports the
	// hostagent tree (the import direction stays hostagent → libvirt; the adapter that
	// calls AttachBridge.Destroy lives in the daemon root) — the exact mirror of
	// create.go's PostBootHook.
	postDestroy PostDestroyHook
	// hookFault is the OUT-OF-BAND observability sink for a SWALLOWED post-destroy reap
	// fault — the §4.2-side mirror of create.go's HostAgent.hookFault. The reap is swallowed
	// FROM THE VERDICT (above), but before this seam that swallow was SILENT: a serving-child
	// reap that failed left no host-side trace at teardown, so a leaked ds-hostbridge child
	// looked identical to a cleanly-reaped one. hookFault surfaces that swallowed fault
	// STRUCTURALLY out-of-band (telemetry/log) — attributed to HookPostDestroy — WITHOUT ever
	// entering the Destroy result: the teardown verdict stays byte-identical, but the fault is
	// now observable. It is an injectable field (the constructors install
	// defaultHookFaultObserver, the SAME default create.go uses) so a test captures the
	// observation instead of writing to stderr; it is NEVER nil at the observation site and is
	// invoked ONLY when the swallowed reap actually returns a non-nil error (a clean reap emits
	// nothing).
	hookFault HookFaultObserver
}

// PostDestroyHook is the OPTIONAL post-destroy lifecycle callback (the gap-3 serving-leg
// REAP). The daemon composition root supplies it; it runs AFTER the §4.2 host-local
// teardown with the session UUID. A returned error is BEST-EFFORT/NON-FATAL and SWALLOWED
// FROM THE VERDICT — the destroy never folds it into the DestroyResult — the exact mirror of
// create.go's PostBootHook: a serving-child reap fault never affects the Destroy verdict,
// because the §4.2 host-local objects (NFT flush, overlay dispose) ARE the teardown contract
// and they are already clean before this hook runs. It is no longer SILENTLY discarded,
// though: a non-nil reap error is surfaced OUT-OF-BAND through the hookFault observer
// (attributed to HookPostDestroy), so a serving-child reap that failed is observable without
// changing the teardown outcome. The daemon's adapter calls hostagent AttachBridge.Destroy,
// which returns nothing, so the wired path never produces an error here; the observer exists
// so a FUTURE hook that errors surfaces structurally instead of vanishing.
type PostDestroyHook func(ctx context.Context, sessionUUID string) error

// HookPostDestroy is the OUT-OF-BAND attribution for a swallowed post-destroy serving-leg REAP
// fault (PostDestroyHook) — the §4.2-teardown sibling of create.go's HookPostBoot. The SAME
// HookFaultObserver seam (create.go) surfaces a swallowed reap fault structurally, attributed to
// this kind, so a telemetry consumer distinguishes a create-path post-boot fault from a
// destroy-path reap fault WITHOUT parsing the message — the fault never enters the Destroy verdict.
// Its value continues create.go's HookKind sequence (HookPostBoot = 1); HookKind.String() renders
// unlisted kinds via its default arm, so the structured Hook field is the authoritative attribution.
const HookPostDestroy HookKind = 2

// NewDestroyer assembles the teardown driver. A nil dependency is a programming
// error surfaced at construction. The seams are the SAME ones the create path
// invokes (AttachPrimitive, OverlayStore) plus the destroy-specific
// DomainDestroyer / DurabilityFinalizer / FlowByteCounter — so a host agent
// wires one set of backends for both directions and the RecordingBackend that
// records create-side instantiation is the SAME one the teardown flushes.
func NewDestroyer(domain DomainDestroyer, attach AttachPrimitive, overlay OverlayStore, durab DurabilityFinalizer, flowBytes FlowByteCounter) (*Destroyer, error) {
	switch {
	case domain == nil:
		return nil, fmt.Errorf("libvirt destroyer requires a domain destroyer")
	case attach == nil:
		return nil, fmt.Errorf("libvirt destroyer requires an attach primitive (flush_session)")
	case overlay == nil:
		return nil, fmt.Errorf("libvirt destroyer requires an overlay store")
	case durab == nil:
		return nil, fmt.Errorf("libvirt destroyer requires a durability finalizer")
	case flowBytes == nil:
		return nil, fmt.Errorf("libvirt destroyer requires a flow byte counter")
	}
	return &Destroyer{domain: domain, attach: attach, overlay: overlay, durab: durab, flowBytes: flowBytes, hookFault: defaultHookFaultObserver}, nil
}

// WithPostDestroyHook wires the OPTIONAL post-destroy serving-leg reap hook and returns the
// Destroyer for chaining. The daemon composition root (cmd/host-agent) calls it with an
// adapter that reaps the per-session ds-hostbridge serving child (AttachBridge.Destroy), so
// a session's attach serving leg is torn down at session DESTROY, not only at daemon
// Shutdown. Leaving it unset (the historical default) keeps the §4.2 destroy path
// BYTE-IDENTICAL — the hook is defined as a plain callback (not an interface importing
// hostagent) so the libvirt tree never imports the hostagent tree, the exact posture of
// create.go's PostBootHook. It is a setter (not a NewDestroyer parameter) so the constructor
// signature — and every existing caller — stays unchanged; passing a nil hook is a no-op.
func (d *Destroyer) WithPostDestroyHook(hook PostDestroyHook) *Destroyer {
	d.postDestroy = hook
	return d
}

// WithHookFaultObserver installs an OUT-OF-BAND observer for a swallowed post-destroy reap fault,
// returning the same *Destroyer for chaining at composition — the §4.2-side mirror of
// HostAgent.WithHookFaultObserver (create.go). The observer surfaces a swallowed reap fault
// structurally (telemetry/log) WITHOUT changing the Destroy verdict (the reap stays
// best-effort/non-fatal, swallowed from the DestroyResult). A nil observer is IGNORED (the default
// stderr sink is kept), so a reap fault is NEVER silently un-observed. The daemon composition root
// calls this to route reap faults to its durable structured sink; the offline test installs a
// capturing observer to assert the fault surfaces out-of-band while the teardown verdict is unchanged.
func (d *Destroyer) WithHookFaultObserver(obs HookFaultObserver) *Destroyer {
	if obs != nil {
		d.hookFault = obs
	}
	return d
}

// Destroy runs the §4.2 host-local teardown in the frozen order, UNCONDITIONALLY
// flushing the session NFT objects (D68) regardless of how much host-side state
// exists. It is idempotent on session_uuid: a re-run over an already-destroyed
// session converges (an absent domain is a no-op destroy; a flush of a session
// with no live objects is a no-op; an absent overlay is a no-op disposal).
//
// FAULT POSTURE (clean teardown wins): the order is unconditional, so a fault at
// step 1 does NOT stop the flush — the driver records the FIRST fault and keeps
// going so a domain that won't destroy can never strand the NFT objects (the
// exact "slow rot that erodes a fleet" the doc 06 (b) clean-teardown row guards).
// The final byte-count emission is NON-FATAL: a flowlog hiccup is recorded, never
// a teardown abort. The first fault is returned as a *DestroyError after the
// whole order has run; nil means a fully clean teardown.
func (d *Destroyer) Destroy(ctx context.Context, req DestroyRequest) (DestroyResult, error) {
	if req.SessionUUID == "" {
		return DestroyResult{}, &DestroyError{Step: DestroyStepNone, Err: fmt.Errorf("destroy request has no session uuid")}
	}
	var res DestroyResult
	var firstErr *DestroyError

	// record retains only the FIRST fault — the order runs unconditionally past it.
	record := func(step DestroyStep, err error) {
		if err != nil && firstErr == nil {
			firstErr = &DestroyError{Step: step, SessionUUID: req.SessionUUID, Err: err}
		}
	}

	// ── step 1: guest VM destroy (libvirt domain destroy) ────────────────────
	// Idempotent: an empty DomainUUID (no boot ever happened) is a no-op. A fault
	// here MUST NOT stop the flush (clean teardown is unconditional).
	if err := d.domain.DestroyDomain(ctx, req.SessionUUID, req.DomainUUID); err != nil {
		record(DestroyStepDomain, fmt.Errorf("destroy domain %q: %w", req.DomainUUID, err))
	} else {
		res.DomainDestroyed = true
	}

	// ── step 2: UNCONDITIONAL flush_session(legs=all) + NFT-6 order ──────────
	// The NFT-6 order (interface rules → named sets + DNS-2b map → conntrack by
	// mark) is ds-nft's, frozen by D68/D72/D76 — invoked through the seam, never
	// re-implemented here. The flush ALWAYS runs (D68), even for a binding-less
	// partial allocation (it converges to a no-op). The final byte counts are
	// read from conntrack-by-mark just before the conntrack flush, so they are
	// emitted in lockstep with this step — but only for a REAL binding (a
	// binding-less partial has no ct-mark accounting to read). The emission is
	// NON-FATAL: a flowlog fault is recorded, never an abort.
	if req.HasBinding {
		if err := d.flowBytes.EmitDestroyByteCounts(ctx, req.SessionUUID, req.Binding); err != nil {
			// Non-fatal accounting fault — recorded as a teardown warning, never
			// an abort (clean teardown of the NFT objects wins over a missed event).
			record(DestroyStepFlush, fmt.Errorf("emit destroy byte counts: %w", err))
		} else {
			res.ByteCountsEmitted = true
		}
	}
	if err := d.attach.FlushSession(ctx, req.SessionUUID, req.Binding); err != nil {
		record(DestroyStepFlush, fmt.Errorf("flush_session(legs=all) [NFT-6]: %w", err))
	} else {
		res.SessionFlushed = true
	}

	// ── step 3: overlay disposal + durability-stream finalization (D29) ──────
	// The durability stream is finalized BEFORE the overlay is disposed so the
	// dirty-bitmap record is consistent at the point of disposal. An empty
	// OverlayPath (no overlay ever created) makes both no-ops.
	if req.OverlayPath != "" {
		if err := d.durab.FinalizeDurabilityStream(ctx, req.SessionUUID, req.OverlayPath); err != nil {
			record(DestroyStepOverlay, fmt.Errorf("finalize durability stream: %w", err))
		}
		if err := d.overlay.DisposeOverlay(ctx, req.OverlayPath); err != nil {
			record(DestroyStepOverlay, fmt.Errorf("dispose overlay %q: %w", req.OverlayPath, err))
		} else {
			res.OverlayDisposed = true
		}
	}

	// ── post-destroy gap-3 serving-leg REAP (best-effort, NON-FATAL — SWALLOWED) ─
	// The session's host-local objects are now torn down (domain gone, NFT objects
	// flushed, overlay disposed); reap its per-session attach serving child (the daemon
	// wires this to AttachBridge.Destroy, which off DS_HOSTAGENT_LIVE owns nothing). It is
	// best-effort by contract: the reap is bookkeeping on a child the guest's destruction
	// has already obviated, so a hook fault NEVER affects the Destroy verdict — the error is
	// SWALLOWED FROM THE RESULT here, the exact mirror of create.go's PostBootHook.
	//
	// CHOSEN POSTURE — swallow FROM THE VERDICT, to mirror PostBootHook: a torn-down session's
	// reap fault must not turn a clean §4.2 teardown (NFT objects flushed, overlay disposed)
	// into a faulted Destroy over the wire; the §4.2 host-local objects ARE the teardown
	// contract, and they are already clean before this hook runs. Recording the fault as the
	// first *DestroyError (the discarded alternative) would propagate a serving-child
	// bookkeeping miss to the gRPC Destroy handler as a teardown fault — contradicting both the
	// PostBootHook-mirror posture the seam doc claims AND the §4.2 clean-teardown contract (the
	// host-local teardown succeeded).
	//
	// It is NO LONGER silently discarded, though (the wave-1 create-path arc, completed here):
	// a non-nil reap error is surfaced OUT-OF-BAND through the hookFault observer, attributed to
	// HookPostDestroy, so a serving-child reap that silently failed is now observable WITHOUT
	// changing the Destroy result — the exact mirror of create.go's post-boot HookFault
	// emission. The observer fires ONLY on an actual fault (a clean reap emits nothing, so the
	// happy path is byte-identical). Skipped entirely when no hook is wired (the historical
	// path) — the destroy is then byte-identical to the pre-gap3 choreography. The adapter —
	// NOT this tree — calls AttachBridge.Destroy, so the import direction stays
	// hostagent → libvirt (the PostBootHook posture, in full).
	if d.postDestroy != nil {
		if hookErr := d.postDestroy(ctx, req.SessionUUID); hookErr != nil {
			obs := d.hookFault
			if obs == nil {
				// Defensive: a Destroyer always installs the default observer at construction,
				// but a zero-value driver must still never silently drop a swallowed reap fault.
				obs = defaultHookFaultObserver
			}
			obs(HookFault{Hook: HookPostDestroy, SessionUUID: req.SessionUUID, Err: hookErr})
		}
	}

	if firstErr != nil {
		return res, firstErr
	}
	return res, nil
}
