// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ── PURE arg-construction (always runs; touches no substrate) ────────────────

func TestDomainDestroyArgs(t *testing.T) {
	name, args := domainDestroyArgs("virsh", "sess-1")
	if name != "virsh" || strings.Join(args, " ") != "destroy ds-sess-1" {
		t.Fatalf("destroy args = %q %q, want virsh destroy ds-sess-1", name, args)
	}
}

// TestDomainAbsenceClassifiers asserts the virsh output vocabulary that drives the
// idempotent no-op branch: an unknown domain (both the current "failed to get
// domain" and the older "Domain not found" phrasings) and an already-stopped
// domain converge to a clean §4.2 step-1 success; a genuine host fault does NOT.
func TestDomainAbsenceClassifiers(t *testing.T) {
	for _, out := range []string{
		"error: failed to get domain 'ds-sess-1'\n",
		"error: Domain not found: no domain with matching name 'ds-sess-1'\n",
		"error: failed to get domain: no domain with matching uuid\n",
	} {
		if !domainAbsentOutput(out) {
			t.Fatalf("domainAbsentOutput(%q) = false, want true", out)
		}
	}
	if !domainNotRunningOutput("error: Requested operation is not valid: domain is not running\n") {
		t.Fatal("an already-stopped domain must classify as nothing-to-destroy")
	}
	for _, out := range []string{
		"error: failed to connect to the hypervisor\n",
		"error: internal error: End of file while reading data\n",
		"",
	} {
		if domainAbsentOutput(out) || domainNotRunningOutput(out) {
			t.Fatalf("a genuine host fault %q must NOT classify as absent/stopped", out)
		}
	}
}

// ── liveDomainDestroyer behavior via the fake runner (always runs; no virsh) ──
//
// These drive the REAL liveDomainDestroyer code path over the package
// recordingRunner (live_test.go) — NO subprocess, no virsh, no KVM. The destroyer
// has no live config requirement of its own (it only needs the virsh bin), so like
// the liveSuspender tests these run on the default offline path: the constructed
// argv and every classification branch are asserted purely in-process. The actual
// domain teardown is exercised on the DS_HOSTAGENT_LIVE box by the live smoke
// (live_smoke_test.go, which now drives THIS production body).

func newTestDomainDestroyer(rr *recordingRunner) *liveDomainDestroyer {
	return &liveDomainDestroyer{virshBin: "virsh", run: rr}
}

func TestDestroyDomainDrivesVirshDestroy(t *testing.T) {
	rr := &recordingRunner{}
	d := newTestDomainDestroyer(rr)

	// The domainUUID is threaded for seam parity and IGNORED — the domain is named
	// by the session (domainName "ds-<uuid>"), so a Destroy that resolved no
	// DomainUUID still names the right guest.
	if err := d.DestroyDomain(context.Background(), "sess-5", "dom-uuid-ignored"); err != nil {
		t.Fatalf("DestroyDomain: %v", err)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("expected 1 exec (destroy), got %d: %v", len(rr.calls), rr.calls)
	}
	if strings.Join(rr.calls[0], " ") != "virsh destroy ds-sess-5" {
		t.Fatalf("destroy = %q", rr.calls[0])
	}
}

// TestDestroyDomainAbsentIsCleanNoOp: an absent / already-gone / already-stopped
// domain converges to a no-op SUCCESS (the destroy.go DomainDestroyer contract —
// the transient domain vanishes entirely on destroy, so a §4.2 re-drive finds
// nothing and must still report a clean teardown).
func TestDestroyDomainAbsentIsCleanNoOp(t *testing.T) {
	for _, out := range []string{
		"error: failed to get domain 'ds-sess-2'\n",
		"error: Domain not found: no domain with matching name 'ds-sess-2'\n",
		"error: Failed to destroy domain 'ds-sess-2'\nerror: Requested operation is not valid: domain is not running\n",
	} {
		rr := &recordingRunner{outputs: []string{out}, errs: []error{errors.New("exit status 1")}}
		d := newTestDomainDestroyer(rr)
		if err := d.DestroyDomain(context.Background(), "sess-2", ""); err != nil {
			t.Fatalf("DestroyDomain (output %q) = %v, want a clean no-op success", out, err)
		}
		if len(rr.calls) != 1 {
			t.Fatalf("expected exactly 1 exec, got %d: %v", len(rr.calls), rr.calls)
		}
	}
}

// TestDestroyDomainRealFailurePropagates: a genuine host fault (libvirtd
// unreachable, a domain that refuses to die) is NEVER swallowed — it surfaces so
// destroy.go records the step-1 fault (DestroyStepDomain) and the reconciler
// re-drives. This is exactly where the retired smoke-local destroyer lied: it
// swallowed every error, so a domain that would not die reported a clean teardown.
func TestDestroyDomainRealFailurePropagates(t *testing.T) {
	rr := &recordingRunner{
		outputs: []string{"error: failed to connect to the hypervisor\n"},
		errs:    []error{errors.New("exit status 1")},
	}
	d := newTestDomainDestroyer(rr)

	err := d.DestroyDomain(context.Background(), "sess-3", "")
	if err == nil {
		t.Fatal("a genuine virsh failure must propagate, never a swallowed clean success")
	}
	if !strings.Contains(err.Error(), "sess-3") {
		t.Fatalf("error %q must name the session for the §4.2 destroy_error", err)
	}
}

// TestDestroyDomainEmptySessionIsRejected: destroy.go rejects an empty session uuid
// before step 1, so this is the belt-and-suspenders guard — never `virsh destroy
// ds-` (an unnamed domain), and never a silent success.
func TestDestroyDomainEmptySessionIsRejected(t *testing.T) {
	rr := &recordingRunner{}
	d := newTestDomainDestroyer(rr)
	if err := d.DestroyDomain(context.Background(), "", ""); err == nil {
		t.Fatal("an empty session uuid must be an error")
	}
	if len(rr.calls) != 0 {
		t.Fatalf("an empty session uuid must exec nothing, got %v", rr.calls)
	}
}

// TestLiveDomainDestroyerDefaultsVirshBin: an empty LiveConfig.VirshBin resolves to
// "virsh" on PATH (the NewLiveBooter / NewLiveSuspender convention).
func TestLiveDomainDestroyerDefaultsVirshBin(t *testing.T) {
	d, err := NewLiveDomainDestroyer(LiveConfig{})
	if err != nil {
		t.Fatalf("NewLiveDomainDestroyer: %v", err)
	}
	live, ok := d.(*liveDomainDestroyer)
	if !ok {
		t.Fatalf("NewLiveDomainDestroyer returned %T, want *liveDomainDestroyer", d)
	}
	if live.virshBin != "virsh" {
		t.Fatalf("virshBin = %q, want the PATH default \"virsh\"", live.virshBin)
	}
}
