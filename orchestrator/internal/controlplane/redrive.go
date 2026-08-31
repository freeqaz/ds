package controlplane

// redrive.go is the §3 rule-b/rule-c HOST-SIDE RE-CREATE continuation — the second half
// of the convergence-loop closer (the first half, the steps-1–2 + step-5 spine cluster,
// is re-asserted by the SpineRunnerFunc(RedriveSpine) the ConcreteRedriver runs first).
// It drives the host-side re-create of a MISSING VM (doc 15 §4.1 the host-side subset:
// re-mint of step 5 + steps 4, 6, 7, 8) through the SAME production host seams the §4.1
// ten-step coordinator uses — the host agent's idempotent verbs, keyed on session_uuid —
// onto the record's ALREADY-BOUND host.
//
// RE-DRIVE TO FULLY ROUTABLE, NOT HALF-CONVERGED (D73). A re-created VM is NOT routable
// until its session-scoped digests are re-written AND re-acked: doc 15 §4.1 step 6 is the
// digest write+ack gate (D73 — "the session cannot become routable until this ack
// lands"), and the §4.1 step-9 routable gate holds only when {step 3, step 6} do. A
// missing VM lost its host-side digest state with the domain, so re-materializing the
// domain (step 4) without re-writing+re-acking the digests (step 6) would leave a
// HALF-CONVERGED VM the create gate would have refused as not-routable. So this
// continuation re-drives step 6 in the frozen precedence (5 ≺ 6 ≺ {7,8}; {3,6} ≺ 9): the
// re-mint (step 5) supplies the CA the digest write keys on, the digest is re-written to
// the record's bound host and re-acked, and a digest that is written-but-NOT-acked is a
// structural refusal (sessions.ErrDigestNotAcked, D73) that fails the continuation — the
// reconciler does NOT declare the record converged on a half-converged VM, it takes the
// §3 rule-b fail arm instead. Re-write+re-ack is idempotent on session_uuid (the host
// re-acks a re-written digest), so a re-drive of a VM already back is a no-op.
//
// WHY HOST-SIDE-ONLY (not the full coordinator). A re-drive re-asserts an ALREADY-CREATED
// session (doc 16 §3.1): its record exists, its index is bound, its launching principal is
// linked, its role is pinned. The create RPC's coordinator OWNS record creation (steps
// 1–2) and re-running it would conflict on the burned index / existing record. So the
// re-drive must NOT re-create the record — it re-asserts the spine cluster (the
// SpineRunner) and re-drives ONLY the host-side verbs the missing VM needs (this file),
// through the SAME production seams (the driver registry's CloneFromImage, the Identity
// mint's re-mint, the CA inject, the boot). Every verb is idempotent on session_uuid
// (doc 15 §5.1), so a re-create of a VM that is already back is a no-op and a re-create of
// a missing one re-materializes it — the level-triggered convergence the reconciler needs.
//
// THIS IS NOT A SECOND CHOREOGRAPHY. It reuses the production seams the coordinator was
// built with (the same hostAllocator / minter / injector / booter), driving the host-side
// subset in the frozen precedence (4 ≺ {6,7,8}; 5 ≺ 7-injection; 7 ≺ 8). The
// create-choreography spine (steps 1–2, 5-claims) is re-asserted by the shared
// RedriveSpine, not re-implemented here — the reconciler's "never a second copy of the
// create choreography" contract holds.

import (
	"context"
	"fmt"
	"log/slog"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// launchingUserResolverSeam is the narrow read the host re-create uses to confirm the
// record's launching principal is still linked (the re-drive's premise — doc 16 §3.1).
// It is the same ResolveLaunchingUserClaim the spine reads; declared narrow here so the
// continuation depends only on the one method.
type launchingUserResolverSeam interface {
	ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error)
}

// hostReCreate drives the §4.1 host-side re-create (steps 4, 6–8) for a missing VM,
// through the SAME production seams the coordinator was built with. It holds the host
// allocator (CloneFromImage on the bound host), the re-mint (the per-session identity/CA
// the re-created VM needs), the digest writer (the §4.1 step-6 re-write+re-ack, D73), the
// CA injector, and the booter — all idempotent on session_uuid.
type hostReCreate struct {
	alloc    sessions.HostAllocator
	mint     sessions.Minter
	digest   sessions.DigestWriter
	inject   sessions.Injector
	boot     sessions.Booter
	resolver launchingUserResolverSeam
	logger   *slog.Logger
}

// hostReCreateOption tunes the host-side re-create continuation. The §4.1 step-6 digest
// re-write+re-ack (D73 — fully-routable, not half-converged) is wired through
// withDigestReAck; it is a variadic option so the seam can be installed at the wiring
// site WITHOUT widening the create-spine continuation's other dependencies (the same
// data-across-the-seam discipline the create coordinator's DigestWriter uses).
type hostReCreateOption func(*hostReCreate)

// withDigestReAck installs the §4.1 step-6 digest re-write+re-ack seam (D73) on the
// host-side re-create continuation: a re-driven missing VM is not declared CONVERGED
// until its session-scoped digests are re-written to the bound host AND re-acked. The
// DigestClient is the SAME Identity-owned (D22/D82) digest face the create coordinator's
// step 6 drives (controlplane DigestClient → sessions.DigestWriter), so the re-drive
// re-acks through the exact seam the original create acked through. A nil client leaves
// the seam unwired (the digest is not re-driven — the pre-D73 convergence-only posture).
func withDigestReAck(digestC DigestClient) hostReCreateOption {
	return func(h *hostReCreate) {
		if digestC != nil {
			h.digest = digestWriter{c: digestC}
		}
	}
}

// newHostReCreate builds the host-side re-create continuation over the production seams.
// The §4.1 step-6 digest re-write+re-ack (D73) is wired via withDigestReAck(d.Digest):
// without it the continuation re-materializes the VM but does NOT re-ack the digest, so a
// re-driven VM is only declared fully ROUTABLE when the digest seam is installed.
func newHostReCreate(reg DriverRegistry, mintC MintClient, injectC InjectClient, bootC BootClient, resolver launchingUserResolverSeam, logger *slog.Logger, opts ...hostReCreateOption) hostReCreate {
	if logger == nil {
		logger = slog.Default()
	}
	h := hostReCreate{
		alloc:    hostAllocator{reg: reg},
		mint:     minter{c: mintC},
		inject:   injector{c: injectC},
		boot:     booter{c: bootC},
		resolver: resolver,
		logger:   logger,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&h)
		}
	}
	return h
}

// reCreate drives the host-side re-create for the record's missing VM. The spine cluster
// (steps 1–2, 5-claims) was already re-asserted by the SpineRunner that produced `spine`;
// here we re-drive the host verbs (idempotent on session_uuid) on the record's ALREADY-
// BOUND host, in the frozen §4.1 precedence (5 ≺ 6 ≺ {7,8}; {3,6} ≺ 9):
//
//	(re-mint)  re-mint the per-session identity/CA the re-created VM needs (D82) — the
//	           spine re-assembled the claims; this re-mints them through the same seam.
//	(step 4)   CloneFromImage on the record's bound host — idempotent: re-creates the
//	           overlay/domain if absent, returns the existing binding if present.
//	(step 6)   re-write + re-ACK the session-scoped digests to the bound host (D73) —
//	           the missing VM lost its host-side digest state with the domain, so a
//	           re-created VM is NOT routable until the re-write is re-acked. A digest
//	           written-but-not-acked is a structural refusal (ErrDigestNotAcked) that
//	           fails the continuation, so the reconciler never declares the record
//	           converged on a half-converged VM (it takes the §3 rule-b fail arm).
//	(step 7)   re-inject the per-session CA into the (re)cloned overlay, fail-closed.
//	(step 8)   re-boot the domain per the entrypoint.
//
// The record's host binding (rec.Ref.HostID) is the re-create target — a re-drive keeps
// the same host (the index history records prior epochs; a park/migrate re-place is the
// create-RPC's job, not the convergence re-drive). A record with no bound host (never
// reached step 4) cannot be host-re-created; that is the spine-cluster-only convergence
// case (the next observed cycle picks up the create), surfaced as a no-op success.
func (h hostReCreate) reCreate(ctx context.Context, rec store.Session, spine sessions.CreateSpineResult) error {
	sessionUUID := rec.Ref.SessionUUID
	hostID := rec.Ref.HostID
	if hostID == "" {
		// The record never reached the host-side steps (no bound host) — there is no VM
		// to re-create on a host. The spine cluster re-asserted; leave the host re-create
		// to the next observed cycle (the convergence-only outcome, doc 15 §3).
		h.logger.InfoContext(ctx, "reconcile: host re-create skipped (record has no bound host; spine cluster re-asserted, host re-create deferred)",
			slog.String("session", sessionUUID))
		return nil
	}

	// Confirm the launching principal is still linked (the re-drive's premise, doc 16
	// §3.1). The SpineRunner already classified the nullable case (ErrRedriveNoLaunchingUser);
	// this re-confirms before any host mint so a dangling link never re-mints a placeholder.
	if _, ok, err := h.resolver.ResolveLaunchingUserClaim(ctx, sessionUUID); err != nil {
		return fmt.Errorf("controlplane: host re-create %s: resolve launching_user: %w", sessionUUID, err)
	} else if !ok {
		return fmt.Errorf("%w (session %s)", sessions.ErrRedriveNoLaunchingUser, sessionUUID)
	}

	// (re-mint) the per-session identity/CA (D82) — the re-created VM's trust material.
	mintRes, err := h.mint.Mint(ctx, spine.MintClaims.Claims, spine.MintClaims.RoleRef)
	if err != nil {
		return fmt.Errorf("controlplane: host re-create %s: re-mint: %w", sessionUUID, err)
	}

	// (step 4) CloneFromImage on the bound host — idempotent on session_uuid: re-creates
	// the overlay/domain if absent, returns the existing binding if present.
	alloc, err := h.alloc.AllocateAndDefine(ctx, hostID, &hypervisorv1.VmSpec{
		SessionUuid: sessionUUID,
		ImageId:     rec.ImageID,
	})
	if err != nil {
		return fmt.Errorf("controlplane: host re-create %s: clone on %s: %w", sessionUUID, hostID, err)
	}

	// (step 6) re-write + re-ACK the session-scoped digests to the bound host (D73). 5 ≺ 6:
	// the re-mint above supplied the CA ref the digest write keys on. A re-created VM is NOT
	// routable until this re-ack lands — re-materializing the domain (step 4) without
	// re-acking the digest would leave a HALF-CONVERGED VM the §4.1 step-9 routable gate
	// ({3,6} ≺ 9) would have refused. The seam is the SAME Identity-owned step-6 face the
	// create coordinator drove; it is idempotent on session_uuid (the host re-acks a
	// re-written digest). When unwired (no withDigestReAck — the pre-D73 convergence-only
	// posture), the digest is left to the next observed cycle; when wired, a write that the
	// host does NOT ack is a structural refusal that fails the re-drive (the reconciler then
	// takes the §3 rule-b fail arm rather than declaring a not-routable VM converged).
	if h.digest != nil {
		digestRes, err := h.digest.WriteAndAck(ctx, sessionUUID, hostID, mintRes.CARef)
		if err != nil {
			return fmt.Errorf("controlplane: host re-create %s: digest re-write+ack: %w", sessionUUID, err)
		}
		if !digestRes.Acked {
			// Written but NOT acked — NOT routable (D73). Do not declare converged; surface
			// the structural refusal so the reconciler takes the §3 rule-b fail arm. The
			// reconciler's next tick re-drives (idempotent on session_uuid).
			return fmt.Errorf("controlplane: host re-create %s: %w", sessionUUID, sessions.ErrDigestNotAcked)
		}
		h.logger.InfoContext(ctx, "reconcile: re-driven VM digest re-written + re-acked (D73 — routable, not half-converged)",
			slog.String("session", sessionUUID), slog.String("host", hostID), slog.String("digest_ref", digestRes.DigestRef))
	}

	// (step 7) re-inject the per-session CA into the (re)cloned overlay, fail-closed.
	if err := h.inject.InjectCA(ctx, sessionUUID, alloc.OverlayPath, mintRes.CARef); err != nil {
		return fmt.Errorf("controlplane: host re-create %s: CA inject: %w", sessionUUID, err)
	}

	// (step 8) re-boot the domain per the entrypoint (the env-config ref is the
	// entrypoint key the host-side boot resolves from, doc 15 §4.1 step 8).
	if err := h.boot.Boot(ctx, sessionUUID, rec.EnvConfigRef); err != nil {
		return fmt.Errorf("controlplane: host re-create %s: boot: %w", sessionUUID, err)
	}

	h.logger.InfoContext(ctx, "reconcile: host-side re-create driven through the shared production seams (idempotent on session_uuid)",
		slog.String("session", sessionUUID), slog.String("host", hostID))
	return nil
}
