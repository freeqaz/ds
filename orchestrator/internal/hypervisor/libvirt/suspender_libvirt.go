// SPDX-License-Identifier: Apache-2.0

// suspender_libvirt — the production Suspender seam binding (seams.go), the
// host-side body of the §3 RUNNING↔SUSPENDED(reason) lifecycle transition
// (doc 15 §3/§4.3; D46/D77). It is the real counterpart of the in-memory fake
// the service tests use (service_test.go fakeSuspender): the seam + fake prove
// the idempotent no-op-on-repeat + Unimplemented-without-Suspender contract
// offline (D50); THIS file realizes the pause/restore mechanism on the operator
// host — the host-side twin of liveOverlayStore / liveBooter (live.go) and
// liveTrustStoreWriter (trustanchor.go).
//
// Same posture as live.go: the real binding is ALWAYS compiled (no build tag)
// but only reachable behind the DS_HOSTAGENT_LIVE gate the daemon composition
// root reads (LiveEnabled) — the host-agent wiring that SELECTS this impl is a
// SEPARATE task. Off the gate / in the sandbox / in CI a DriverService is built
// WITHOUT a Suspender and Suspend/Resume answer an honest codes.Unimplemented
// (service.go), so every unit test stays green against the fake. STDLIB-ONLY
// (doc.go / seams.go): it shells out to virsh through the package's os/exec
// `runner` seam (live.go) — NO libvirt-go / cgo enters orchestrator/go.mod.
//
// THE D77 FREEZE-IN-PLACE: Suspend uses virsh suspend, which pauses the running
// domain with its RAM held resident — the threat-freeze pause (D77). It works on
// the TRANSIENT domain the liveBooter boots (`virsh create`, D29 durable-overlay
// re-create); a live e2e (01KV6PDSEF) proved `virsh managedsave` REJECTS a
// transient domain ("cannot do managed save for transient domain"), so the
// slot-releasing D46 PARKED tier (managedsave/restore) is deferred to a
// persistent/defined-domain Booter — a separate concern. Resume uses virsh
// resume, the exact inverse (paused -> running). The pause/restore TCP mechanics
// over the boundary-owned transport are Boundary-owned (D46); this binding is the
// orchestrator's drive side, "pause/restore THIS session's domain", over virsh.
//
// DOMSTATE-CHECKED IDEMPOTENCY (the seams.go contract, doc 15 §5.1): every verb
// is idempotent on session_uuid so a retried call after a host or control-plane
// blip converges rather than faults. We query `virsh domstate` FIRST and branch:
// an already-paused (or saved/shut-off) domain makes Suspend a no-op success (NO
// virsh suspend call); an already-running domain makes Resume a no-op success (NO
// virsh resume call). This is also a LIVE-GROUNDED guard (the box finding ~/ds/
// ground-suspender.sh, taskdb note 01KV6BDX51): virsh refuses the redundant
// transition (e.g. resume on an already-running domain returns rc 1), so we must
// branch on the observed state rather than call unconditionally and swallow the
// error.
//
// D77 PROVENANCE AUDIT: on a POLICY_BREACH Suspend the provenance lineage (the
// matched rule_id / policy_layer / policy_version that justified the pause) is
// recorded to a host-side audit sink. The provenance is RECORDED, never
// re-validated here (the service binding already vetted it — doc 15 §4.3): the
// audit is the genuine-threat attribution (D77), not a second gate. USER /
// REBALANCE pauses carry no provenance and record no audit line.
//
// FAIL-CLOSED: a missing domain, a domstate failure, or a virsh suspend/resume
// failure surfaces as a non-nil error the caller re-drives — a genuine host fault
// is NEVER swallowed (only the already-in-target-state branch is a deliberate
// no-op success).

package libvirt

import (
	"context"
	"fmt"
	"log"
	"strings"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// liveSuspender is the production Suspender: Suspend drives virsh suspend of the
// named session domain (the D77 freeze-in-place, transient-domain-safe) and
// Resume drives virsh resume (the inverse) — both domstate-checked for the
// idempotent no-op-on-repeat contract. Reachable only on the live path
// (DS_HOSTAGENT_LIVE); a DriverService built off the gate has no Suspender and
// answers Suspend/Resume with codes.Unimplemented (service.go).
type liveSuspender struct {
	// virshBin is the virsh binary the live suspender drives (default "virsh"
	// via PATH; reuses LiveConfig.VirshBin, the same field liveBooter drives).
	virshBin string
	// run is the single os/exec edge (live.go runner seam); the production value
	// is execRunner{} and the offline tests install a recordingRunner so the
	// command line + branch behavior is asserted WITHOUT launching virsh.
	run runner
	// audit records the D77 provenance lineage on a POLICY_BREACH pause. It is an
	// injectable sink (default a stderr log.Printf) so the test can assert it is
	// called with the provenance on POLICY_BREACH and NOT on USER/REBALANCE. The
	// line is RECORDED, never re-validated.
	audit func(line string)
}

// NewLiveSuspender builds the real Suspender over virsh on PATH, mirroring
// NewLiveBooter: it resolves the virsh binary (default "virsh" when empty) and
// installs the production execRunner + the default stderr audit sink. The
// returned value satisfies the seams.go Suspender seam, so the host-agent
// composition root can pass it to NewDriverServiceWithSuspend on the live path
// (the same place it constructs NewLiveBooter) — that wiring is a SEPARATE task.
func NewLiveSuspender(cfg LiveConfig) (Suspender, error) {
	virsh := cfg.VirshBin
	if virsh == "" {
		virsh = "virsh"
	}
	return &liveSuspender{
		virshBin: virsh,
		run:      execRunner{},
		audit:    defaultSuspendAudit,
	}, nil
}

// defaultSuspendAudit is the default host-side audit sink: it writes the D77
// provenance lineage to the standard logger (stderr). The operator host can swap
// it for a durable record at composition; the seam stays an injectable field so
// the offline test can capture the line instead.
func defaultSuspendAudit(line string) {
	log.Printf("ds suspend audit: %s", line)
}

// domStateArgs is the PURE arg-construction for the `virsh domstate` probe — the
// live.go overlayCreateArgs/domainDefineArgs convention, split out from the exec
// so the offline test asserts the exact command line without running it.
func domStateArgs(virshBin, sessionUUID string) (name string, args []string) {
	return virshBin, []string{"domstate", domainName(sessionUUID)}
}

// suspendArgs is the PURE arg-construction for the D77 freeze-in-place: virsh
// suspend pauses the running domain, holding its RAM resident (the threat-freeze
// pause). It works on a TRANSIENT domain (the liveBooter boots via `virsh create`,
// D29 durable-overlay re-create) — unlike `virsh managedsave`, which a live e2e
// (01KV6PDSEF) proved REJECTS a transient domain ("cannot do managed save for
// transient domain"). The heavier D46 PARKED tier (managedsave, slot-releasing)
// needs a persistent/defined domain and is a separate Booter-define concern.
func suspendArgs(virshBin, sessionUUID string) (name string, args []string) {
	return virshBin, []string{"suspend", domainName(sessionUUID)}
}

// resumeArgs is the PURE arg-construction for the restore: virsh resume unpauses
// a suspended domain (the inverse of virsh suspend), restoring it to RUNNING.
func resumeArgs(virshBin, sessionUUID string) (name string, args []string) {
	return virshBin, []string{"resume", domainName(sessionUUID)}
}

// domainSuspended reports whether the observed `virsh domstate` output means the
// domain is already in (or past) the SUSPENDED state — so Suspend is a no-op.
// managedsave leaves the domain "shut off" (the RAM is on disk, the domain is
// stopped) and a plain pause leaves it "paused"; both, plus a domain already
// shut off, mean there is nothing to managedsave. Matched case-insensitively on
// the libvirt state vocabulary (paused | shut off | saved | shutoff).
func domainSuspended(domstate string) bool {
	s := strings.ToLower(strings.TrimSpace(domstate))
	return strings.Contains(s, "paused") ||
		strings.Contains(s, "shut off") ||
		strings.Contains(s, "shutoff") ||
		strings.Contains(s, "saved")
}

// domainRunning reports whether the observed `virsh domstate` output means the
// domain is already running — so Resume is a no-op. libvirt reports "running"
// for an active domain.
func domainRunning(domstate string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(domstate)), "running")
}

// auditLine renders the D77 provenance lineage for the host-side audit record on
// a POLICY_BREACH pause: the matched rule / policy layer / policy version that
// justified the pause, alongside the session. It is a pure render of the
// already-vetted provenance — never a re-validation.
func auditLine(sessionUUID string, provenance *boundaryv1.Provenance) string {
	return fmt.Sprintf(
		"POLICY_BREACH suspend session=%s rule_id=%q policy_layer=%q policy_version=%d",
		sessionUUID,
		provenance.GetRuleId(),
		provenance.GetPolicyLayer(),
		provenance.GetPolicyVersion(),
	)
}

// Suspend pauses the host-resident domain for sessionUUID with the D77-vetted
// reason. It queries `virsh domstate` FIRST: an already-suspended/saved/shut-off
// domain is a NO-OP success (NO managedsave call — the idempotency contract and
// the live-grounded guard against managedsave-on-an-already-off-domain); a
// running domain is paused durably with virsh managedsave (RAM serialized to
// disk, the host slot released — D46/D77). On a POLICY_BREACH the provenance
// lineage is recorded to the audit sink (RECORDED, never re-validated); USER /
// REBALANCE record nothing. A missing domain / domstate failure / managedsave
// write failure surfaces as a non-nil error the caller re-drives (a genuine host
// fault, NEVER swallowed). The provenance taxonomy is validated at the service
// binding (service.go), so a reason reaching here is already vetted.
func (s *liveSuspender) Suspend(ctx context.Context, sessionUUID string, reason hypervisorv1.SuspendReason, provenance *boundaryv1.Provenance) error {
	if sessionUUID == "" {
		return fmt.Errorf("suspend: empty session uuid")
	}

	// Record the D77 genuine-threat attribution on a POLICY_BREACH pause BEFORE
	// the managedsave drives — the audit lineage justifies the pause that follows.
	// The provenance is carried for attribution only; it is recorded, NEVER
	// re-validated (the service binding already vetted it — doc 15 §4.3). On a
	// no-op (already-suspended) the lineage is still the genuine reason a breach
	// pause was requested, so the audit is recorded regardless of the branch.
	if reason == hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH && provenance != nil && s.audit != nil {
		s.audit(auditLine(sessionUUID, provenance))
	}

	// Query domain state first and branch (the seams.go idempotency contract + the
	// live-grounded guard: do NOT call managedsave on an already-off domain).
	stateName, stateArgs := domStateArgs(s.virshBin, sessionUUID)
	out, err := s.run.run(ctx, stateName, stateArgs...)
	if err != nil {
		// A missing domain / domstate failure is a genuine host fault — surface it
		// so the caller re-drives, never a silent no-op.
		return fmt.Errorf("suspend session %s: query domain state: %w", sessionUUID, err)
	}
	if domainSuspended(out) {
		// Already paused / saved / shut off — nothing to freeze (no-op success).
		return nil
	}

	// Running: drive the D77 freeze-in-place.
	name, args := suspendArgs(s.virshBin, sessionUUID)
	if _, err := s.run.run(ctx, name, args...); err != nil {
		return fmt.Errorf("suspend session %s: virsh suspend: %w", sessionUUID, err)
	}
	return nil
}

// Resume restores the host-resident domain for sessionUUID — the inverse of
// Suspend. It queries `virsh domstate` FIRST: an already-running domain is a
// NO-OP success (NO start call — the idempotency contract and the live-grounded
// guard against start-on-an-already-running domain); otherwise virsh start
// restores from the managedsave state file (libvirt auto-restores a
// managed-saved domain on the next start). A missing domain / domstate failure /
// start failure surfaces as a non-nil error the caller re-drives (a genuine host
// fault, NEVER swallowed).
func (s *liveSuspender) Resume(ctx context.Context, sessionUUID string) error {
	if sessionUUID == "" {
		return fmt.Errorf("resume: empty session uuid")
	}

	stateName, stateArgs := domStateArgs(s.virshBin, sessionUUID)
	out, err := s.run.run(ctx, stateName, stateArgs...)
	if err != nil {
		return fmt.Errorf("resume session %s: query domain state: %w", sessionUUID, err)
	}
	if domainRunning(out) {
		// Already running — nothing to restore (no-op success).
		return nil
	}

	name, args := resumeArgs(s.virshBin, sessionUUID)
	if _, err := s.run.run(ctx, name, args...); err != nil {
		return fmt.Errorf("resume session %s: virsh resume: %w", sessionUUID, err)
	}
	return nil
}

// Compile-time assertion: the live suspender satisfies the seam the service wires.
var _ Suspender = (*liveSuspender)(nil)
