// SPDX-License-Identifier: Apache-2.0

// destroyer_libvirt — the production DomainDestroyer seam binding (destroy.go),
// the host-side body of §4.2 step 1, "guest VM destroy (libvirt domain destroy)"
// (doc 15 §4.2; doc 09 §3 NFT-6). It is the real counterpart of the in-memory
// fake the service tests use (service_test.go fakeDomainDestroyer): the seam +
// fake prove the idempotent no-op-on-absent contract offline (D50); THIS file
// tears the booted transient domain down on the operator host — the host-side
// twin of liveOverlayStore / liveBooter (live.go), liveSuspender
// (suspender_libvirt.go), and liveSnapshotStore (snapshot_libvirt.go).
//
// Same posture as live.go / suspender_libvirt.go: the real binding is ALWAYS
// compiled (no build tag) but only reachable behind the DS_HOSTAGENT_LIVE gate
// the daemon composition root reads (LiveEnabled), through the gate-aware
// NewDomainDestroyer (offline.go). Off the gate / in the sandbox / in CI the
// composition root wires the no-touch offlineDomainDestroyer and the §4.2 order
// is byte-identical to today, so every unit test stays green. STDLIB-ONLY
// (doc.go / seams.go): it shells out to virsh through the package's os/exec
// `runner` seam (live.go) — NO libvirt-go / cgo enters orchestrator/go.mod.
//
// WHAT IT DESTROYS: `virsh destroy ds-<sessionUUID>` — the domainName (live.go)
// convention the whole driver keys on, so the destroy names the SAME domain the
// liveBooter defined with `virsh create` and needs NO domainUUID (the wire
// DestroyRequest carries only the session_uuid; service.go resolves a DomainUUID
// only for the seams that want it, and this binding — like the fake — ignores an
// empty one). No `-c` URI is passed, matching liveBooter / liveSuspender: the
// host-agent runs unprivileged and virsh defaults to qemu:///session, the same
// connection the domains were booted on.
//
// IDEMPOTENT ON session_uuid (the destroy.go DomainDestroyer contract, doc 15
// §5.1): an ABSENT domain — never booted, or already destroyed — is a CLEAN
// SUCCESS, never an error. The liveBooter boots a TRANSIENT domain (`virsh
// create`, D29 durable-overlay re-create), which vanishes ENTIRELY on destroy, so
// a §4.2 re-drive after a converged teardown finds nothing at all: that MUST be a
// no-op, or the reconciler could never re-drive a destroy to convergence. A
// domain that exists but is NOT RUNNING is the same clean no-op (there is nothing
// left to tear down). Absence is classified from the virsh output the runner
// returns alongside the error (domainAbsentOutput / domainNotRunningOutput), the
// trustanchor.go isNotFoundOutput convention.
//
// FAIL-CLOSED OTHERWISE: any OTHER virsh failure (libvirtd unreachable, a domain
// that refuses to die, a permission fault) surfaces as a non-nil error, which
// destroy.go records as the step-1 fault (DestroyStepDomain) WITHOUT stopping the
// unconditional flush (D68) and the service returns to the reconciler for a
// re-drive. This is the one place the smoke test's throwaway destroyer diverged:
// it swallowed EVERY error, so a domain that would not die reported a clean
// teardown. A genuine host fault is NEVER swallowed here — destroy_error must be
// truthful.

package libvirt

import (
	"context"
	"fmt"
	"strings"
)

// liveDomainDestroyer is the production DomainDestroyer: DestroyDomain drives
// virsh destroy of the named session domain (§4.2 step 1), treating an absent /
// already-gone / not-running domain as the contract's clean no-op and surfacing
// every other virsh fault. Reachable only on the live path (DS_HOSTAGENT_LIVE);
// off the gate the composition root wires offlineDomainDestroyer (offline.go).
type liveDomainDestroyer struct {
	// virshBin is the virsh binary the live destroyer drives (default "virsh" via
	// PATH; reuses LiveConfig.VirshBin, the same field liveBooter / liveSuspender
	// drive).
	virshBin string
	// run is the single os/exec edge (live.go runner seam); the production value
	// is execRunner{} and the offline tests install a recordingRunner so the
	// command line + branch behavior is asserted WITHOUT launching virsh.
	run runner
}

// NewLiveDomainDestroyer builds the real DomainDestroyer over virsh on PATH,
// mirroring NewLiveBooter / NewLiveSuspender: it resolves the virsh binary
// (default "virsh" when empty) and installs the production execRunner. The
// returned value satisfies the destroy.go DomainDestroyer seam, so the host-agent
// composition root passes it to NewDestroyer on the live path (the same place it
// constructs NewLiveBooter) — reached through the gate-aware NewDomainDestroyer.
func NewLiveDomainDestroyer(cfg LiveConfig) (DomainDestroyer, error) {
	virsh := cfg.VirshBin
	if virsh == "" {
		virsh = "virsh"
	}
	return &liveDomainDestroyer{
		virshBin: virsh,
		run:      execRunner{},
	}, nil
}

// domainDestroyArgs is the PURE arg-construction for §4.2 step 1 — the
// live.go domainDefineArgs / suspender_libvirt.go suspendArgs convention, split
// out from the exec so the offline test asserts the exact command line without
// running it. The domain is named by the session alone (domainName, live.go), so
// an empty domainUUID never reaches virsh.
func domainDestroyArgs(virshBin, sessionUUID string) (name string, args []string) {
	return virshBin, []string{"destroy", domainName(sessionUUID)}
}

// domainAbsentOutput reports whether the observed virsh output means the named
// domain DOES NOT EXIST — the idempotent no-op branch, not a host fault. libvirt
// reports an unknown domain as "failed to get domain '<name>'" (current virsh) or
// "Domain not found: no domain with matching name '<name>'" (older builds); the
// runner returns the combined output alongside the error, so the marker is in
// out. Matched case-insensitively on the libvirt not-found vocabulary — the
// trustanchor.go isNotFoundOutput convention, kept destroy-local because the
// vocabulary is virsh's, not libguestfs's.
func domainAbsentOutput(out string) bool {
	s := strings.ToLower(out)
	return strings.Contains(s, "failed to get domain") ||
		strings.Contains(s, "domain not found") ||
		strings.Contains(s, "no domain with matching name") ||
		strings.Contains(s, "no domain with matching uuid")
}

// domainNotRunningOutput reports whether the observed virsh output means the
// domain exists but is already stopped ("Requested operation is not valid: domain
// is not running") — also the idempotent no-op branch: there is no guest left to
// destroy, so §4.2 step 1 has already converged.
func domainNotRunningOutput(out string) bool {
	return strings.Contains(strings.ToLower(out), "domain is not running")
}

// DestroyDomain destroys the transient guest domain for sessionUUID (§4.2 step 1).
// domainUUID is accepted for seam parity and IGNORED: the domain is named by the
// session (domainName "ds-<uuid>"), the convention service.go already documents
// for the no-resolver path, so a Destroy that resolved no DomainUUID still tears
// down the right guest. An ABSENT / already-gone / not-running domain is a CLEAN
// no-op success (the destroy.go idempotency contract — a transient domain vanishes
// on destroy, so a §4.2 re-drive finds nothing); ANY other virsh failure surfaces
// as a non-nil error, which destroy.go records as the step-1 fault while the
// unconditional flush still runs (D68) — a genuine host fault is NEVER swallowed.
func (d *liveDomainDestroyer) DestroyDomain(ctx context.Context, sessionUUID, _ string) error {
	if sessionUUID == "" {
		// destroy.go rejects an empty session uuid before step 1, so this is
		// belt-and-suspenders: never destroy a bare "ds-" domain name.
		return fmt.Errorf("destroy domain: empty session uuid")
	}

	name, args := domainDestroyArgs(d.virshBin, sessionUUID)
	out, err := d.run.run(ctx, name, args...)
	if err != nil {
		if domainAbsentOutput(out) || domainNotRunningOutput(out) {
			// Nothing to tear down — the idempotent convergence branch.
			return nil
		}
		return fmt.Errorf("destroy session %s: virsh destroy: %w", sessionUUID, err)
	}
	return nil
}

// Compile-time assertion: the live destroyer satisfies the seam the §4.2 ordering
// wires (destroy.go NewDestroyer).
var _ DomainDestroyer = (*liveDomainDestroyer)(nil)
