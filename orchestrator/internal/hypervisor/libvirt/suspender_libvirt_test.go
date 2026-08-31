// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"errors"
	"strings"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// ── PURE arg-construction (always runs; touches no substrate) ────────────────

func TestSuspendResumeDomStateArgs(t *testing.T) {
	name, args := domStateArgs("virsh", "sess-1")
	if name != "virsh" || strings.Join(args, " ") != "domstate ds-sess-1" {
		t.Fatalf("domstate args = %q %q, want virsh domstate ds-sess-1", name, args)
	}
	name, args = suspendArgs("virsh", "sess-1")
	if name != "virsh" || strings.Join(args, " ") != "suspend ds-sess-1" {
		t.Fatalf("suspend args = %q %q, want virsh suspend ds-sess-1", name, args)
	}
	name, args = resumeArgs("virsh", "sess-1")
	if name != "virsh" || strings.Join(args, " ") != "resume ds-sess-1" {
		t.Fatalf("resume args = %q %q, want virsh resume ds-sess-1", name, args)
	}
}

// TestDomainStateClassifiers asserts the domstate vocabulary mapping that drives
// the idempotent branch: "running" → resume no-op; paused/shut off/saved →
// suspend no-op. These are the exact libvirt state strings `virsh domstate`
// emits (the live-grounded guard, taskdb note 01KV6BDX51).
func TestDomainStateClassifiers(t *testing.T) {
	for _, st := range []string{"running\n", "RUNNING", "  running  "} {
		if !domainRunning(st) {
			t.Fatalf("domainRunning(%q) = false, want true", st)
		}
		if domainSuspended(st) {
			t.Fatalf("domainSuspended(%q) = true, want false", st)
		}
	}
	for _, st := range []string{"paused\n", "shut off\n", "shutoff", "saved"} {
		if !domainSuspended(st) {
			t.Fatalf("domainSuspended(%q) = false, want true", st)
		}
		if domainRunning(st) {
			t.Fatalf("domainRunning(%q) = true, want false", st)
		}
	}
}

func TestAuditLineRendersProvenanceLineage(t *testing.T) {
	prov := &boundaryv1.Provenance{RuleId: "rule-7", PolicyLayer: "egress-gateway", PolicyVersion: 42}
	line := auditLine("sess-9", prov)
	for _, want := range []string{"sess-9", "rule-7", "egress-gateway", "42", "POLICY_BREACH"} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit line %q missing %q", line, want)
		}
	}
}

// ── liveSuspender behavior via the fake runner (always runs; no virsh) ───────
//
// These drive the REAL liveSuspender code path over the package recordingRunner
// (live_test.go) — NO subprocess, no virsh, no KVM. The suspender has no live
// config requirement of its own (it only needs the virsh bin), so unlike the
// gated OverlayStore/Booter live tests these run on the default offline path:
// they assert the constructed argv + every idempotent branch + the audit purely
// in-process. The actual suspend/start leg is the DEFERRED operator step on
// the DS_HOSTAGENT_LIVE box (box-grounded separately, taskdb note 01KV6BDX51).

// newTestSuspender builds a liveSuspender over a recordingRunner with a captured
// audit sink, so a test can assert the virsh argv and whether the D77 audit
// fired. The domstate output the probe sees is the runner's first canned output.
func newTestSuspender(rr *recordingRunner) (*liveSuspender, *[]string) {
	var audited []string
	s := &liveSuspender{
		virshBin: "virsh",
		run:      rr,
		audit:    func(line string) { audited = append(audited, line) },
	}
	return s, &audited
}

func TestSuspendRunningDomainDrivesSuspend(t *testing.T) {
	// call 0: domstate → running ; call 1: suspend → ok
	rr := &recordingRunner{outputs: []string{"running\n", ""}}
	s, audited := newTestSuspender(rr)

	if err := s.Suspend(context.Background(), "sess-5", hypervisorv1.SuspendReason_SUSPEND_REASON_USER, nil); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if len(rr.calls) != 2 {
		t.Fatalf("expected 2 execs (domstate, suspend), got %d: %v", len(rr.calls), rr.calls)
	}
	if strings.Join(rr.calls[0], " ") != "virsh domstate ds-sess-5" {
		t.Fatalf("domstate probe = %q", rr.calls[0])
	}
	if strings.Join(rr.calls[1], " ") != "virsh suspend ds-sess-5" {
		t.Fatalf("suspend = %q", rr.calls[1])
	}
	if len(*audited) != 0 {
		t.Fatalf("USER suspend recorded an audit line: %v", *audited)
	}
}

// TestSuspendAlreadySuspendedIsNoOp: a paused/shut-off/saved domain re-suspends
// to a no-op success with NO suspend call (the idempotency contract + the
// live-grounded guard against suspend-on-an-already-off-domain).
func TestSuspendAlreadySuspendedIsNoOp(t *testing.T) {
	for _, state := range []string{"paused\n", "shut off\n", "saved\n"} {
		rr := &recordingRunner{outputs: []string{state}}
		s, _ := newTestSuspender(rr)
		if err := s.Suspend(context.Background(), "sess-2", hypervisorv1.SuspendReason_SUSPEND_REASON_REBALANCE, nil); err != nil {
			t.Fatalf("Suspend (state %q): %v", state, err)
		}
		if len(rr.calls) != 1 {
			t.Fatalf("state %q: expected 1 exec (domstate only, no suspend), got %d: %v", state, len(rr.calls), rr.calls)
		}
		if strings.Contains(strings.Join(rr.calls[0], " "), "suspend") {
			t.Fatalf("state %q: drove suspend on an already-suspended domain: %v", state, rr.calls)
		}
	}
}

func TestResumeSuspendedDomainDrivesResume(t *testing.T) {
	// call 0: domstate → paused (virsh-suspended) ; call 1: resume → ok
	rr := &recordingRunner{outputs: []string{"paused\n", ""}}
	s, _ := newTestSuspender(rr)

	if err := s.Resume(context.Background(), "sess-7"); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if len(rr.calls) != 2 {
		t.Fatalf("expected 2 execs (domstate, resume), got %d: %v", len(rr.calls), rr.calls)
	}
	if strings.Join(rr.calls[0], " ") != "virsh domstate ds-sess-7" {
		t.Fatalf("domstate probe = %q", rr.calls[0])
	}
	if strings.Join(rr.calls[1], " ") != "virsh resume ds-sess-7" {
		t.Fatalf("resume = %q", rr.calls[1])
	}
}

// TestResumeAlreadyRunningIsNoOp: an already-running domain re-resumes to a no-op
// success with NO resume call (the idempotency contract + the live-grounded guard
// against resume-on-an-already-running domain — virsh resume returns rc 1 there).
func TestResumeAlreadyRunningIsNoOp(t *testing.T) {
	rr := &recordingRunner{outputs: []string{"running\n"}}
	s, _ := newTestSuspender(rr)
	if err := s.Resume(context.Background(), "sess-3"); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("expected 1 exec (domstate only, no resume), got %d: %v", len(rr.calls), rr.calls)
	}
	if strings.Contains(strings.Join(rr.calls[0], " "), "resume") {
		t.Fatalf("drove resume on an already-running domain: %v", rr.calls)
	}
}

// TestSuspendMissingDomainSurfacesError: a domstate failure (e.g. missing
// domain) is a genuine host fault — Suspend returns a non-nil error the caller
// re-drives, never a silent no-op, and never reaches suspend.
func TestSuspendMissingDomainSurfacesError(t *testing.T) {
	rr := &recordingRunner{errs: []error{errors.New("error: failed to get domain 'ds-sess-x'")}}
	s, _ := newTestSuspender(rr)
	if err := s.Suspend(context.Background(), "sess-x", hypervisorv1.SuspendReason_SUSPEND_REASON_USER, nil); err == nil {
		t.Fatal("expected Suspend to surface the missing-domain domstate error")
	}
	if len(rr.calls) != 1 {
		t.Fatalf("expected the probe to short-circuit before suspend, got %d: %v", len(rr.calls), rr.calls)
	}
}

// TestResumeMissingDomainSurfacesError: the symmetric Resume host fault.
func TestResumeMissingDomainSurfacesError(t *testing.T) {
	rr := &recordingRunner{errs: []error{errors.New("error: failed to get domain 'ds-sess-x'")}}
	s, _ := newTestSuspender(rr)
	if err := s.Resume(context.Background(), "sess-x"); err == nil {
		t.Fatal("expected Resume to surface the missing-domain domstate error")
	}
	if len(rr.calls) != 1 {
		t.Fatalf("expected the probe to short-circuit before start, got %d: %v", len(rr.calls), rr.calls)
	}
}

// TestSuspendManagedsaveFailureSurfacesError: a suspend write failure on a
// running domain is a genuine host fault surfaced non-nil (NEVER swallowed).
func TestSuspendFailureSurfacesError(t *testing.T) {
	rr := &recordingRunner{
		outputs: []string{"running\n", ""},
		errs:    []error{nil, errors.New("error: Failed to save domain ... suspend")},
	}
	s, _ := newTestSuspender(rr)
	if err := s.Suspend(context.Background(), "sess-9", hypervisorv1.SuspendReason_SUSPEND_REASON_USER, nil); err == nil {
		t.Fatal("expected Suspend to surface the suspend write failure")
	}
}

// TestPolicyBreachSuspendRecordsProvenance: a POLICY_BREACH pause records the
// D77 provenance lineage to the audit sink (the lineage is RECORDED, never
// re-validated); USER/REBALANCE record nothing (covered above). The audit fires
// regardless of the suspend branch — here the running-domain path.
func TestPolicyBreachSuspendRecordsProvenance(t *testing.T) {
	rr := &recordingRunner{outputs: []string{"running\n", ""}}
	s, audited := newTestSuspender(rr)

	prov := &boundaryv1.Provenance{RuleId: "rule-13", PolicyLayer: "tls-termination", PolicyVersion: 99}
	if err := s.Suspend(context.Background(), "sess-b", hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, prov); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if len(*audited) != 1 {
		t.Fatalf("expected exactly 1 audit line on POLICY_BREACH, got %d: %v", len(*audited), *audited)
	}
	line := (*audited)[0]
	for _, want := range []string{"rule-13", "tls-termination", "99", "sess-b"} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit line %q missing %q", line, want)
		}
	}
	// The suspend still drives (the audit is recorded ALONGSIDE the pause, not
	// instead of it).
	if strings.Join(rr.calls[len(rr.calls)-1], " ") != "virsh suspend ds-sess-b" {
		t.Fatalf("POLICY_BREACH suspend did not drive suspend: %v", rr.calls)
	}
}

// TestPolicyBreachAuditFiresEvenOnNoOp: the genuine-threat attribution is
// recorded even when the domain is already suspended (the no-op branch) — the
// audit captures the reason a breach pause was requested, not the disk write.
func TestPolicyBreachAuditFiresOnAlreadySuspended(t *testing.T) {
	rr := &recordingRunner{outputs: []string{"paused\n"}}
	s, audited := newTestSuspender(rr)
	prov := &boundaryv1.Provenance{RuleId: "rule-1", PolicyLayer: "egress-gateway", PolicyVersion: 1}
	if err := s.Suspend(context.Background(), "sess-c", hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, prov); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if len(*audited) != 1 {
		t.Fatalf("expected the POLICY_BREACH audit even on a no-op suspend, got %d: %v", len(*audited), *audited)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("expected the no-op (domstate only) branch, got %d: %v", len(rr.calls), rr.calls)
	}
}

// TestSuspendRejectsEmptySession / TestResumeRejectsEmptySession: a missing
// session uuid is an input fault, never a virsh call.
func TestSuspendResumeRejectEmptySession(t *testing.T) {
	rr := &recordingRunner{}
	s, _ := newTestSuspender(rr)
	if err := s.Suspend(context.Background(), "", hypervisorv1.SuspendReason_SUSPEND_REASON_USER, nil); err == nil {
		t.Fatal("expected Suspend to reject an empty session uuid")
	}
	if err := s.Resume(context.Background(), ""); err == nil {
		t.Fatal("expected Resume to reject an empty session uuid")
	}
	if len(rr.calls) != 0 {
		t.Fatalf("empty-session calls must not reach virsh: %v", rr.calls)
	}
}

// TestNewLiveSuspenderMirrorsBooterConstructor: the constructor satisfies the
// seam, defaults the virsh bin, and installs the production runner + audit sink
// (mirroring NewLiveBooter).
func TestNewLiveSuspenderMirrorsBooterConstructor(t *testing.T) {
	susp, err := NewLiveSuspender(LiveConfig{})
	if err != nil {
		t.Fatalf("NewLiveSuspender: %v", err)
	}
	ls, ok := susp.(*liveSuspender)
	if !ok {
		t.Fatalf("NewLiveSuspender returned %T, want *liveSuspender", susp)
	}
	if ls.virshBin != "virsh" {
		t.Fatalf("default virsh bin = %q, want virsh", ls.virshBin)
	}
	if _, ok := ls.run.(execRunner); !ok {
		t.Fatalf("production runner = %T, want execRunner", ls.run)
	}
	if ls.audit == nil {
		t.Fatal("production suspender must install a default audit sink")
	}
	// An explicit virsh bin is honored (the LiveConfig.VirshBin reuse).
	susp2, _ := NewLiveSuspender(LiveConfig{VirshBin: "/usr/bin/virsh"})
	if susp2.(*liveSuspender).virshBin != "/usr/bin/virsh" {
		t.Fatalf("configured virsh bin not honored: %q", susp2.(*liveSuspender).virshBin)
	}
}
