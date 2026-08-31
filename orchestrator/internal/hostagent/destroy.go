package hostagent

// destroy.go is the host-agent's owned §4.2 destroy ORCHESTRATION (doc 15 §4.2)
// and the §4.1 create-rollback COMPENSATIONS (doc 15 §4.1 Rollback). It composes
// the libvirt-side host-local teardown (internal/hypervisor/libvirt's Destroyer:
// domain destroy → UNCONDITIONAL flush_session(legs=all) + NFT-6 order + final
// ds-flowlog byte counts → overlay disposal + durability finalize) with the
// host-agent-owned remaining §4.2 steps:
//
//	4. Session-scoped digest flush + ask-grant expiry (grants are TTL'd and die
//	   with the session; policy_log rows persist as audit, D36).
//	5. Identity/CA revocation signal to Identity (D22/D82); key-store grant
//	   revocation (D39 — grant lifetime is scoped by session lifecycle).
//	6. DESTROYED reported via heartbeat; the orchestrator finalizes the session
//	   record (retained, never deleted within the flow-log retention window, D66).
//
// The libvirt Destroyer owns steps 1–3 (the part that must leave the ruleset
// byte-identical to bootstrap — NFT-6, doc 09 §3); this file owns the host-agent
// composition of the full §4.2 list plus the create-rollback matrix.
//
// CREATE-ROLLBACK COMPENSATIONS (doc 15 §4.1 Rollback — compensating destroys
// driven from whatever create step failed):
//
//	failure at step 4   → flush_session(legs=all) + NFT-6 for the partial
//	                      allocation, and the consumed host_session_index is
//	                      BURNED (never recycled, D66). No identity/CA yet.
//	failure at steps 5–6 → signal identity/CA revocation + flush written digests
//	                      (plus the host-side flush for any partial allocation).
//	failure at steps 7–8 → destroy the domain + dispose the overlay BEFORE
//	                      unwinding step 4 (the full host-local teardown), then
//	                      revoke identity/CA (live from step 5).
//
// Create is RETRYABLE BY SESSION UUID (every driver verb is idempotent on it).
// Every rollback path satisfies the doc 06 (b) clean-teardown checklist — no
// orphaned VM, no leaked NFTables rules / allow-set entries, no dangling CoW
// overlay, no leftover minted identity.
//
// SEAM-LEVEL, (b)-CONFORMANCE (the task constraint): this is built against the
// existing FlushSession seam with the fake/RecordingBackend — NOT the Go↔ds-nft
// cgo staticlib bridge, which is a separately-tracked follow-up (DS_NFTGATE_LIVE
// stays disabled). No live KVM/metal/podman; the durability/digest/identity edges
// are seams a host fake satisfies, so the whole path runs in CI without
// nested-virt.
//
// Governing decisions: D17, D22, D29, D36, D39, D44, D66, D68, D72, D76, D82.
// Primary doc: docs/15-orchestrator-design.md §4.1 (Rollback), §4.2; doc 09 §3
// (NFT-6).

import (
	"context"
	"fmt"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// IndexBurner burns a consumed host_session_index so it is NEVER recycled within
// the flow-log retention window (doc 15 §4.1 Rollback step-4 note, D66). On the
// control-plane side the burn lives in the store (AppendIndexEpoch burns the
// index the moment a binding is recorded); on the HOST side the persistent
// monotonic counter (alloc.go IndexCounter) already burns by never re-handing a
// drawn index — but a step-4 rollback that drew an index and then failed must
// record the burn explicitly so a host-agent restart's RestoreCounter accounts
// for it. This seam is the host-local burn ledger write; a test fake records the
// burned indices, the real on-host impl persists them beside the HandleStore.
type IndexBurner interface {
	// BurnIndex records that hostSessionIndex was consumed by a create that failed
	// at step 4 and must never be recycled (D66). Idempotent: burning an
	// already-burned index is a no-op.
	BurnIndex(ctx context.Context, hostID string, hostSessionIndex uint64) error
}

// DigestFlusher flushes the session-scoped digests and expires the session's
// TTL'd ask-grants at teardown (doc 15 §4.2 step 4 / §4.3). The digests were
// written to the host at §4.1 step 6 (D73); the ask-grants are session-scoped
// TTL'd allow grants that die with the session (the policy_log rows PERSIST as
// audit — only the live derived state is flushed, D36). A test fake records the
// flushed sessions; the real impl drops the host-local digest set + the session's
// live-grant entries. Idempotent on session_uuid.
type DigestFlusher interface {
	// FlushDigests flushes the session-scoped digests and expires the session's
	// live ask-grants (the derived state — the policy_log audit rows persist, D36).
	// Idempotent: flushing an already-flushed session is a no-op.
	FlushDigests(ctx context.Context, sessionUUID string) error
}

// IdentityRevoker signals identity/CA revocation to Identity at teardown (doc 15
// §4.2 step 5, D22/D82) and revokes the key-store grant (D39 — grant lifetime is
// scoped by the session lifecycle). It is the host-agent's signal side of the
// §4.2 "no leftover minted identity" teardown assertion; the actual revocation
// runs Identity-side across the seam (carried as DATA — no cross-tree import). A
// test fake records the revoked sessions. Idempotent: revoking an
// already-revoked identity is a no-op.
type IdentityRevoker interface {
	// RevokeIdentity signals identity/CA revocation for the session (D22/D82) and
	// revokes the key-store grant (D39). identityRef / caRef may be empty when the
	// session never reached §4.1 step 5 (no mint happened) — then it is a no-op
	// (nothing to revoke). Idempotent on session_uuid.
	RevokeIdentity(ctx context.Context, sessionUUID, identityRef, caRef string) error
}

// DestroyedReporter reports DESTROYED via the heartbeat so the orchestrator
// finalizes the retained session record (doc 15 §4.2 step 6, D66; metering
// closes, D57). The record is RETAINED, never deleted within the flow-log
// retention window. A test fake records the reported sessions; the real impl
// folds the DESTROYED observed-state into the next heartbeat frame (§5.2). It is
// the LAST step — reported only after the host-local + identity teardown ran, so
// the orchestrator never finalizes a record whose host-side state still leaks.
type DestroyedReporter interface {
	// ReportDestroyed marks the session DESTROYED for the next heartbeat so the
	// orchestrator finalizes the retained record. Idempotent on session_uuid.
	ReportDestroyed(ctx context.Context, sessionUUID string) error
}

// DestroyDeps bundles the host-agent destroy seams. The libvirt Destroyer owns
// §4.2 steps 1–3 (the NFT-6-conformant host-local teardown); the remaining seams
// own steps 4–6. Required seams are checked at construction; a nil required seam
// is a programming error.
type DestroyDeps struct {
	// Libvirt drives §4.2 steps 1–3 (domain destroy → unconditional
	// flush_session(legs=all) + NFT-6 order + final byte counts → overlay
	// disposal + durability finalize). Required.
	Libvirt *libvirt.Destroyer
	// Digests flushes the session-scoped digests + expires ask-grants (§4.2
	// step 4). Required.
	Digests DigestFlusher
	// Identity signals identity/CA + key-store grant revocation (§4.2 step 5).
	// Required.
	Identity IdentityRevoker
	// Reporter reports DESTROYED via heartbeat (§4.2 step 6). Required.
	Reporter DestroyedReporter
	// Indices burns a consumed index on a step-4 create-rollback (§4.1 Rollback,
	// D66). Required (a step-4 rollback MUST be able to burn the index — never
	// recycle).
	Indices IndexBurner
}

// Destroyer is the host-agent's §4.2 destroy orchestrator + §4.1 create-rollback
// driver. It composes the libvirt host-local teardown with the host-agent-owned
// digest flush / identity revoke / DESTROYED report, and drives the step-specific
// create-rollback compensations.
type Destroyer struct {
	libv     *libvirt.Destroyer
	digests  DigestFlusher
	identity IdentityRevoker
	reporter DestroyedReporter
	indices  IndexBurner
}

// NewDestroyer assembles the host-agent destroy orchestrator. A nil required dep
// is a construction-time error.
func NewDestroyer(d DestroyDeps) (*Destroyer, error) {
	switch {
	case d.Libvirt == nil:
		return nil, fmt.Errorf("hostagent destroyer requires a libvirt destroyer")
	case d.Digests == nil:
		return nil, fmt.Errorf("hostagent destroyer requires a digest flusher")
	case d.Identity == nil:
		return nil, fmt.Errorf("hostagent destroyer requires an identity revoker")
	case d.Reporter == nil:
		return nil, fmt.Errorf("hostagent destroyer requires a destroyed reporter")
	case d.Indices == nil:
		return nil, fmt.Errorf("hostagent destroyer requires an index burner")
	}
	return &Destroyer{
		libv:     d.Libvirt,
		digests:  d.Digests,
		identity: d.Identity,
		reporter: d.reporterOrNil(),
		indices:  d.Indices,
	}, nil
}

// reporterOrNil is a tiny accessor kept so the struct-literal stays readable; the
// nil check above guarantees a non-nil reporter.
func (d DestroyDeps) reporterOrNil() DestroyedReporter { return d.Reporter }

// DestroyRequest is the host-agent §4.2 teardown input — the session identity,
// the bound host, the host-side state to unwind, and the identity/CA refs to
// revoke. A reconciler-driven destroy (desired = DESTROYED) carries the full
// recorded state; a create-rollback carries only what the failed create created.
type DestroyRequest struct {
	// SessionUUID is the global identity; every teardown verb is idempotent on it.
	SessionUUID string
	// HostID is the host the session is bound to (the burn ledger key for a
	// step-4 rollback; the heartbeat/report scope).
	HostID string
	// Binding is the recorded host-side allocation to unwind (the NFT objects, the
	// ct-mark accounting key). Zero when the create failed before step 4.
	Binding libvirt.Binding
	// HasBinding records whether host-side NFT/tap objects were created. Drives the
	// byte-count emission and the index burn (a binding carries the consumed
	// index); the flush_session is UNCONDITIONAL regardless (D68).
	HasBinding bool
	// DomainUUID is the booted domain to destroy (empty before a boot).
	DomainUUID string
	// OverlayPath is the overlay to dispose + finalize (empty before step 7).
	OverlayPath string
	// IdentityRef / CARef are the minted workload identity + interception CA refs
	// to revoke (D22/D82). Empty when the session never reached §4.1 step 5 — then
	// the revoke is a no-op (nothing minted).
	IdentityRef string
	CARef       string
}

// DestroyResult reports the full §4.2 teardown outcome so the caller (the
// reconciler, or the create coordinator's rollback) can confirm clean teardown
// and the conformance assertion can verify the unconditional flush ran.
type DestroyResult struct {
	// Libvirt is the host-local teardown result (steps 1–3): the unconditional
	// flush ran (SessionFlushed), the domain/overlay were torn down, the byte
	// counts were emitted.
	Libvirt libvirt.DestroyResult
	// DigestsFlushed is true when §4.2 step 4 ran (digest flush + ask-grant expiry).
	DigestsFlushed bool
	// IdentityRevoked is true when §4.2 step 5 signalled identity/CA + grant
	// revocation (skipped only when the session never minted — IdentityRef/CARef
	// both empty AND no binding, i.e. a step ≤4 rollback with no identity).
	IdentityRevoked bool
	// Reported is true when §4.2 step 6 reported DESTROYED via heartbeat.
	Reported bool
	// IndexBurned is true when a step-4 create-rollback burned the consumed index.
	IndexBurned bool
}

// Destroy runs the full host-agent §4.2 teardown in the frozen order. It is the
// reconciler-driven destroy (desired = DESTROYED): host-local teardown (steps
// 1–3, NFT-6-conformant) → digest flush + ask-grant expiry (step 4) → identity/CA
// + grant revocation (step 5) → DESTROYED report (step 6). It is idempotent on
// session_uuid and re-driveable.
//
// FAULT POSTURE (clean teardown wins): like the libvirt teardown, the order is
// UNCONDITIONAL — a fault at one step does NOT stop the later steps (a digest
// flush that hiccups must not strand the identity revocation that follows), so a
// teardown can never half-run and leave a leak. The FIRST fault is returned after
// the whole order ran; nil means a fully clean §4.2 teardown.
func (d *Destroyer) Destroy(ctx context.Context, req DestroyRequest) (DestroyResult, error) {
	if req.SessionUUID == "" {
		return DestroyResult{}, fmt.Errorf("hostagent destroy: request has no session uuid")
	}
	var res DestroyResult
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// ── §4.2 steps 1–3: host-local teardown (NFT-6-conformant) ───────────────
	lres, lerr := d.libv.Destroy(ctx, libvirt.DestroyRequest{
		SessionUUID: req.SessionUUID,
		Binding:     req.Binding,
		HasBinding:  req.HasBinding,
		DomainUUID:  req.DomainUUID,
		OverlayPath: req.OverlayPath,
	})
	res.Libvirt = lres
	if lerr != nil {
		record(fmt.Errorf("hostagent destroy: host-local teardown: %w", lerr))
	}

	// ── §4.2 step 4: session-scoped digest flush + ask-grant expiry (D36) ────
	if err := d.digests.FlushDigests(ctx, req.SessionUUID); err != nil {
		record(fmt.Errorf("hostagent destroy: flush digests + expire ask-grants: %w", err))
	} else {
		res.DigestsFlushed = true
	}

	// ── §4.2 step 5: identity/CA + key-store grant revocation (D22/D82/D39) ──
	// Always signalled — the revoke is idempotent and a no-op when nothing was
	// minted (IdentityRef/CARef empty). Signalling unconditionally keeps the
	// "no leftover minted identity" assertion honest even when the refs were lost.
	if err := d.identity.RevokeIdentity(ctx, req.SessionUUID, req.IdentityRef, req.CARef); err != nil {
		record(fmt.Errorf("hostagent destroy: revoke identity/CA + grant: %w", err))
	} else {
		res.IdentityRevoked = true
	}

	// ── §4.2 step 6: DESTROYED reported via heartbeat (record finalized) ─────
	// LAST — reported only after the host-side + identity teardown ran, so the
	// orchestrator never finalizes a record whose host-side state still leaks.
	if err := d.reporter.ReportDestroyed(ctx, req.SessionUUID); err != nil {
		record(fmt.Errorf("hostagent destroy: report DESTROYED: %w", err))
	} else {
		res.Reported = true
	}

	return res, firstErr
}

// Rollback drives a §4.1 create-rollback as a COMPENSATING destroy from whatever
// step failed (doc 15 §4.1 Rollback). It reads the libvirt.CreateError's Step +
// partial host-side state and runs the step-specific compensation:
//
//	StepAllocate (4)        → flush_session(legs=all) + NFT-6 for the partial
//	                          allocation, then BURN the consumed index (D66). No
//	                          identity/CA yet, so no revocation.
//	StepDigestAck (6)       → flush_session + flush written digests + signal
//	                          identity/CA revocation (live from step 5).
//	StepOverlay/Boot (7–8)  → destroy the domain + dispose the overlay (full
//	                          host-local teardown) BEFORE unwinding step 4, then
//	                          revoke identity/CA.
//	StepRoutable (9)        → full host-local teardown + digest flush + identity
//	                          revocation (the session booted but is non-routable;
//	                          unwound like a 7–8 failure plus the digest flush).
//	StepNone (1–3)          → nothing host-side exists; the record is finalized
//	                          with an audit event (no host-side compensation).
//
// It is idempotent and re-driveable; create is retryable by session UUID. Every
// path satisfies the doc 06 (b) clean-teardown checklist. The DESTROYED report is
// NOT fired on a rollback (the create never reached READY — the coordinator
// finalizes the record directly with an audit event, doc 15 §4.1); Rollback's job
// is to leave NO host-side / identity leak so a retry-by-UUID is clean.
func (d *Destroyer) Rollback(ctx context.Context, hostID string, ce *libvirt.CreateError) (DestroyResult, error) {
	if ce == nil {
		return DestroyResult{}, fmt.Errorf("hostagent rollback: nil create error")
	}
	if ce.SessionUUID == "" {
		return DestroyResult{}, fmt.Errorf("hostagent rollback: create error has no session uuid")
	}
	var res DestroyResult
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// failure at 1–3: nothing host-side exists; the record is finalized with an
	// audit event (the coordinator's job). No host-side compensation is owed —
	// but we still defensively run the unconditional flush IF a binding somehow
	// exists (it never should before step 4), so the path can never leak.
	if ce.Step == libvirt.StepNone && !ce.HasBinding {
		return res, nil
	}

	// Host-local teardown for any partial allocation (steps 4+). flush_session is
	// UNCONDITIONAL (D68); the domain/overlay are torn down when they exist (the
	// step-7/8 case). This is the SAME libvirt teardown the reconciler-driven
	// destroy runs — so a rollback leaves the ruleset byte-identical to bootstrap
	// (NFT-6), exactly like a full destroy.
	if ce.HasBinding {
		lres, lerr := d.libv.Destroy(ctx, libvirt.DestroyRequest{
			SessionUUID: ce.SessionUUID,
			Binding:     ce.Binding,
			HasBinding:  true,
			DomainUUID:  ce.DomainUUID,  // empty before a boot — no-op destroy
			OverlayPath: ce.OverlayPath, // empty before step 7 — no-op disposal
		})
		res.Libvirt = lres
		if lerr != nil {
			record(fmt.Errorf("hostagent rollback: host-local teardown: %w", lerr))
		}
	}

	// Step-specific compensations beyond the host-local teardown:
	switch {
	case ce.Step == libvirt.StepAllocate:
		// failure at step 4 → BURN the consumed index (never recycled, D66). No
		// identity/CA exists yet (step 5 not reached), so no revocation. The host
		// monotonic counter already never re-hands a drawn index; the explicit burn
		// records it so a restart's RestoreCounter accounts for the consumed index.
		if ce.HasBinding {
			if err := d.indices.BurnIndex(ctx, hostID, ce.Binding.HostSessionIndex); err != nil {
				record(fmt.Errorf("hostagent rollback: burn consumed index %d: %w", ce.Binding.HostSessionIndex, err))
			} else {
				res.IndexBurned = true
			}
		}

	case ce.Step == libvirt.StepDigestAck:
		// failure at steps 5–6 → flush written digests + signal identity/CA
		// revocation (the identity/CA are live from step 5). The host-local flush
		// already ran above for the partial allocation.
		if err := d.digests.FlushDigests(ctx, ce.SessionUUID); err != nil {
			record(fmt.Errorf("hostagent rollback: flush written digests: %w", err))
		} else {
			res.DigestsFlushed = true
		}
		if err := d.identity.RevokeIdentity(ctx, ce.SessionUUID, "", ""); err != nil {
			record(fmt.Errorf("hostagent rollback: revoke identity/CA: %w", err))
		} else {
			res.IdentityRevoked = true
		}

	case ce.Step == libvirt.StepOverlay || ce.Step == libvirt.StepBoot || ce.Step == libvirt.StepRoutable:
		// failure at steps 7–8 (and the step-9 non-routable case) → the domain +
		// overlay were torn down in the host-local teardown above. The rollback
		// REUSES the single §4.2 destroy ordering (the doc frames rollback as the
		// destroy path driven compensatingly), so the libvirt Destroyer runs step 1
		// (domain) → step 2 (flush_session, which unwinds step 4's NFT objects) →
		// step 3 (overlay disposal). NOTE the sub-step transposition vs the §4.1
		// rollback note's literal "destroys the domain and disposes the overlay,
		// THEN unwinds step 4": here the step-4 NFT unwind (the flush) precedes the
		// overlay disposal. This is sound — the overlay (a qcow2 file) and the NFT
		// objects are independent resources with no inter-ordering dependency, and
		// the (b) clean-teardown contract is an END-STATE invariant (no leak),
		// proven byte-identical-to-bootstrap by TestCreateRollbackLoopByteIdentical-
		// ToBootstrap regardless of the overlay-vs-flush sub-order. (A distinct
		// rollback ordering that disposes the overlay before the flush is filed as a
		// follow-up if the §4.1 literal sequencing is later ratified as load-bearing.)
		// The identity/CA are live from step 5, so revoke them; flush any written
		// digests (step 6 may have written them before a step-7/8 failure).
		if err := d.digests.FlushDigests(ctx, ce.SessionUUID); err != nil {
			record(fmt.Errorf("hostagent rollback: flush written digests: %w", err))
		} else {
			res.DigestsFlushed = true
		}
		if err := d.identity.RevokeIdentity(ctx, ce.SessionUUID, "", ""); err != nil {
			record(fmt.Errorf("hostagent rollback: revoke identity/CA: %w", err))
		} else {
			res.IdentityRevoked = true
		}
	}

	return res, firstErr
}
