// SPDX-License-Identifier: Apache-2.0

// nethelperseams.go — the LIVE Boundary-owned tap/NFT primitive, now reached
// across a PROCESS boundary rather than a cgo one (ROOT-HELPER model, ratified
// D148 2026-07-30).
//
// WHAT MOVED. The host agent used to link the ds-nft staticlib itself through
// the Go↔Rust cgo write edge (internal/nftbridge) under `-tags nftgatelive`,
// which meant the AGENT process had to carry CAP_NET_ADMIN. The doc 14 §6 linker
// set is now {ds-dnsgate, ds-nethelper}: the agent builds untagged forever, runs
// fully unprivileged, and forks the setcap'd `ds-nethelper` binary once per
// privileged action (orchestrator/cmd/ds-nethelper +
// internal/nethelper/nethelperclient). The capability lives on the HELPER file,
// never on this process. nftgatelive_refuse.go makes a tagged agent build a
// compile ERROR so the move cannot silently regress.
//
// WHAT DID NOT MOVE. The verb surface is byte-for-byte what liveAttach drove:
// the same three AttachPrimitive methods, the same recorded-Binding join keys
// (TapName + the never-recycled HostSessionIndex, ≤14-bit so the uint32
// narrowing is lossless), the same owner uid (this process's), the same EMPTY
// guest MAC (Binding carries none, so the static-neigh leg stays skipped
// helper-side — a recoverable gap, unchanged), and the same flush-THEN-teardown
// pairing on FlushSession. Idempotency is still ds-nft's; the helper surfaces
// its outcome verbatim through the nethelperclient sentinel errors.
//
// TAP DELETE IS DELIBERATELY ABSENT. AttachPrimitive has no tap-delete method
// and the agent has never deleted taps (bring-up reaps them out of band), so
// FlushSession maps to flush-session + teardown-session ONLY — NOT the client's
// TeardownAll, which would additionally delete the tap and change §4.2 behavior.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nethelper/nethelperclient"
)

// helperAttach is the REAL AttachPrimitive over the privileged helper: one fork
// per privileged op, params on stdin, one Result line back. Selected by
// newAttachPrimitive under (DS_HOSTAGENT_LIVE && a constructed helper client).
type helperAttach struct {
	c *nethelperclient.Client
}

// Compile-time assertion: the helper-backed primitive satisfies the seam the
// §4.1 create choreography and the §4.2 destroy ordering invoke.
var _ libvirt.AttachPrimitive = helperAttach{}

// CreateTap programs the per-session `dstap-<idx>` routed tap: the netdev PLUS
// its routed addressing (10.77.<idx>.0/31 gateway + /32 route, keyed on the
// never-recycled HostSessionIndex), still writing NO nft rules (the glob floor
// owns those). The tap is owned by THIS process's uid so the same-user
// `qemu:///session` process can open it (the M0 deployment posture) — and the
// helper independently RE-CHECKS that rule at its trust boundary (owner_uid must
// equal the invoking uid and be nonzero), so a confused caller cannot mint a
// root-owned or foreign-owned tap. The guest MAC is empty because Binding
// carries none: the helper maps an empty MAC to a skipped static-neigh leg
// (unchanged from the cgo edge — a recoverable gap, never a failure).
func (h helperAttach) CreateTap(ctx context.Context, b libvirt.Binding) error {
	return h.c.CreateTap(ctx, b.TapName, uint32(os.Getuid()), uint32(b.HostSessionIndex), "")
}

// InstantiateSessionNFT creates the EMPTY per-session allow4_<idx>/allow6_<idx>
// admit sets in the existing `inet ds_filter` table (Model A) keyed on the
// never-recycled HostSessionIndex — the admit SURFACE only (the glob floor owns
// default-deny/redirects; per-session policy CONTENT flows through ds-dnsgate,
// the OTHER ds-nft linker, never through this helper).
func (h helperAttach) InstantiateSessionNFT(ctx context.Context, _ string, b libvirt.Binding) error {
	return h.c.InstantiateSession(ctx, b.TapName, uint32(b.HostSessionIndex))
}

// FlushSession drives the unconditional NFT-6 teardown: flush_session(legs=all)
// (conntrack-by-mark) THEN remove the per-session named allow-sets — the two
// halves the ds-nft header pairs, in that fixed order (kill live flows BEFORE
// removing the admit surface). Byte-parity with the retired cgo liveAttach,
// including the early return on a failed flush. A binding-less partial
// allocation (empty TapName) still flows through; the helper's validation
// converges it (an empty tap name is rejected at the boundary, which is the
// honest answer for a binding that never allocated).
func (h helperAttach) FlushSession(ctx context.Context, _ string, b libvirt.Binding) error {
	if err := h.c.FlushSession(ctx, b.TapName, uint32(b.HostSessionIndex)); err != nil {
		return err
	}
	return h.c.TeardownSession(ctx, b.TapName, uint32(b.HostSessionIndex))
}

// helperProbeReadiness folds the helper's read-only self-check INTO the host-WIDE
// boundary-readiness precondition: every admission first re-forks `ds-nethelper
// probe` and refuses unless it still reports the full `+eip` posture, only then
// delegating to the real boundary probe (nft tables + gateway dials).
//
// WHY PER-ADMISSION AND NOT ONLY AT BRING-UP. Capabilities are an xattr on the
// INSTALLED file. A `make`/deploy that rewrites the binary mid-run produces a
// cap-less helper while the daemon keeps running — bring-up's verifyHelperReady
// already passed. Without this leg the next session would be admitted against a
// helper whose every privileged op is about to fail, and the failure would land
// mid-create (partial host state to unwind) instead of at the admission gate
// (StepNone, nothing to unwind — doc 15 §4.1 "failure at 1–3"). The probe is
// read-only and mutates no capability state.
//
// FAIL-CLOSED: a probe error, or any not-Ready posture, is NOT ready. The error
// is folded into the human REASON rather than returned, because a probe fault is
// itself a definitive not-ready answer (an uncertain probe must never be treated
// as ready).
type helperProbeReadiness struct {
	c     *nethelperclient.Client
	inner libvirt.BoundaryReadiness
}

// Compile-time assertion: the composite satisfies the seam it wraps.
var _ libvirt.BoundaryReadiness = helperProbeReadiness{}

func (h helperProbeReadiness) Probe(ctx context.Context) (bool, string, error) {
	status, err := h.c.Probe(ctx)
	if err != nil {
		return false, fmt.Sprintf("ds-nethelper probe failed: %v (the privileged helper is unreachable/unusable; re-run install-ds-nethelper.sh)", err), nil
	}
	if !status.Ready() {
		return false, fmt.Sprintf(
			"ds-nethelper NOT ready: built=%v cap_net_admin_effective=%v cap_net_admin_inheritable=%v ambient_raise_ok=%v "+
				"(capabilities are an xattr on the INSTALLED file — a rebuild/recopy drops them; re-run install-ds-nethelper.sh)",
			status.Built, status.CapNetAdminEffective, status.CapNetAdminInheritable, status.AmbientRaiseOK), nil
	}
	return h.inner.Probe(ctx)
}

// verifyHelperReady is the FATAL bring-up check on the live path: fork the
// installed helper's read-only `probe` ONCE at composition and REFUSE to serve
// unless it reports the full posture. This is the README "Readiness Re-Key"
// contract — fail closed (fatal), never degrade-to-fake — so "the privileged
// edge moved and nobody armed the helper" is a loud bring-up abort instead of a
// daemon that silently programs nothing.
//
// Each failure mode gets its OWN remediation-carrying error, because they demand
// different operator actions:
//
//   - probe error        → the helper is missing/not executable/not on this path.
//   - !Built             → a STUB helper (built without -tags nftgatelive): it
//     parses and validates but every privileged verb answers
//     ENOTBUILT.
//   - !CapNetAdminEffective → setcap never landed (or a rebuild dropped the xattr).
//   - !AmbientRaiseOK    → THE `+ep` TRAP: the helper is effective-green and
//     passes a naive one-field check, yet CAP_NET_ADMIN is not
//     inheritable, so every `ip`/`nft` child ds-nft execs is
//     stranded unprivileged. This is precisely why the probe
//     reports three fields instead of one.
func verifyHelperReady(ctx context.Context, c *nethelperclient.Client) error {
	const remedy = "install with: DS_NETHELPER_APPLY=1 orchestrator/cmd/ds-nethelper/scripts/install-ds-nethelper.sh <built-ds-nethelper>"

	status, err := c.Probe(ctx)
	if err != nil {
		return fmt.Errorf("ds-nethelper probe failed: %w (the live path REQUIRES a working privileged helper; %s)", err, remedy)
	}
	if !status.Built {
		return fmt.Errorf("ds-nethelper reports built=false: the installed helper is the cgo-free STUB build and every privileged verb fails closed with ENOTBUILT. "+
			"Rebuild it WITH the privileged backend (CGO_ENABLED=1 go build -tags nftgatelive ./orchestrator/cmd/ds-nethelper, after `cargo build -p ds-nft --release`), then %s", remedy)
	}
	if !status.CapNetAdminEffective {
		return fmt.Errorf("ds-nethelper reports cap_net_admin_effective=false: setcap never landed on the installed binary (capabilities are an xattr on the INSTALLED file — a rebuild/recopy drops them). %s", remedy)
	}
	if !status.AmbientRaiseOK {
		return fmt.Errorf("ds-nethelper reports ambient_raise_ok=false (cap_net_admin_inheritable=%v): this is the `+ep` half-configuration trap — "+
			"the helper is effective-green but CAP_NET_ADMIN is not inheritable, so the `ip`/`nft` children ds-nft execs would all be stranded unprivileged "+
			"(file capabilities do NOT survive execve). The install MUST be `setcap cap_net_admin+eip`, NOT `+ep`. %s",
			status.CapNetAdminInheritable, remedy)
	}
	return nil
}
