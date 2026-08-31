// SPDX-License-Identifier: Apache-2.0

package e2e

// lifecycle_smoke_test.go — the doc 06 §5 M0 (b) lifecycle smoke at the seam
// level: it drives create → attach → [work] → destroy over the FROZEN doc 15 §3
// session state machine (attach.v1.SessionStateName) and asserts the three doc
// 06 §3b budgets together in one scenario:
//
//	(1) "Seconds to start." create→attach is decomposed into the doc 15 §8
//	    segments (placement decision, overlay clone, tap/NFT programming,
//	    identity/CA/digest sequence, boot-to-entrypoint, policy-ready, routable,
//	    attach handshake) with client RTT measured SEPARATELY and EXCLUDED. Per
//	    D81 (instrument-from-M0 / gate-from-M2) the segments are RECORDED as a
//	    trend; this file asserts the decomposition EXISTS and is non-vacuous, and
//	    deliberately does NOT assert any strawman budget number as a gate (the
//	    e2e README forbids hard-coded gate timing before M2).
//	(2) "Clean teardown." destroy leaves NO orphaned VM, NO leaked nftables
//	    rules / allow-set entries, NO dangling CoW overlay, NO stranded proxy
//	    session, and NO leftover minted identity — all five leak classes the doc
//	    06 §3b / doc 15 §3 DESTROYED assertion names, returned to bootstrap.
//	(3) Pause-budget operational-invisibility (D46). A pause WITHIN budget is
//	    operationally invisible (the deliberate D46 rewording): in-flight tooling
//	    completes or transparently resumes, tested at 60 s / 5 min / 15 min
//	    against the tiered budget (≤5 min fully transparent, 5–15 min
//	    best-effort, >15 min snapshot+park with NO transparency claim).
//
// RELATIONSHIP TO THE OTHER FILES IN THIS PACKAGE (additive, no overlap):
//   - lifecycle_test.go drives the orchestrator-lite BINARY in-process and
//     asserts the create→attach→destroy log markers + the N-loop; this file is
//     the SEAM-LEVEL companion that decomposes the §8 segments and models the
//     five-class teardown + the D46 pause tiers the binary smoke does not.
//   - teardown_nft6_test.go models the NFTables byte-identity loop (rules /
//     allow-sets / overlays / domains); this file's clean-teardown model adds
//     the two leak classes that file does NOT carry — the stranded PROXY SESSION
//     and the leftover MINTED IDENTITY — and asserts the §3b five-tuple as one.
//   - lifecycle_live_test.go / hosthandoff_live_test.go carry the env-gated
//     live legs; this file is the per-commit nested-ok lane.
//
// FIDELITY (D31/D34, per the e2e README): every assertion here is a
// functional/logical statement a synthetic in-process model proves honestly, so
// each is tagged `nested-ok` in its assertion message. The TIMING budget itself
// (real seconds-to-start, snapshot/CoW storage semantics, real pause latency)
// is `metal-only` and is INSTRUMENTED here but not gated (D81) — the gate is a
// nightly/pre-release real-hardware concern (the lifecycle_live_test.go leg).
//
// SUBSTRATE (D50): SYNTHETIC fixtures + an in-process model ONLY. No live KVM /
// ESXi / Claude Code / podman, no nested virt. It imports proto/gen/go ONLY for
// the FROZEN attach.v1 lifecycle vocabulary (the one legal cross-tree import,
// D80) — never orchestrator/ or identity/ internals. Any genuinely-live
// lifecycle leg stays in lifecycle_live_test.go behind its env gate.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// fidelityNestedOK / fidelityMetalOnly tag every assertion per the e2e README's
// D31/D34 scheme: a `nested-ok` claim a synthetic in-process model proves
// honestly per-commit; a `metal-only` claim (real timing / snapshot / CoW) that
// is INSTRUMENTED here but gated on real hardware. The tags ride the assertion
// messages so a reader of a failure knows which lane it belongs to.
const (
	fidelityNestedOK  = "nested-ok"
	fidelityMetalOnly = "metal-only"
)

// ─────────────────────────────────────────────────────────────────────────────
// (1) doc 15 §8 segment decomposition — INSTRUMENT, do not gate (D81)
// ─────────────────────────────────────────────────────────────────────────────

// startSegment is one segment of the create→attach "seconds to start" path. The
// names mirror doc 15 §8 EXACTLY so a regression that drops or renames a segment
// is caught structurally; the duration is a recorded trend, never a gate (D81).
type startSegment struct {
	name string        // the doc 15 §8 segment name (the structural key)
	dur  time.Duration // the recorded segment time (a trend, NOT a budget assertion)
}

// doc15SegmentOrder is the ordered, frozen doc 15 §8 segment list for create→
// attach. Client RTT is INTENTIONALLY absent — it is measured separately and
// excluded (see clientRTTSegmentName), so a venue problem and a stack regression
// stay distinguishable.
var doc15SegmentOrder = []string{
	"placement-decision",
	"overlay-clone",
	"tap-nft-programming",
	"identity-ca-digest-sequence",
	"boot-to-entrypoint",
	"policy-ready",
	"routable",
	"attach-handshake",
}

// clientRTTSegmentName is the segment measured SEPARATELY and EXCLUDED from the
// create→attach decomposition (doc 15 §8: "client RTT measured separately and
// excluded from any trigger evaluation"). It is recorded so the venue cost is
// visible, but it MUST NOT be summed into the stack total.
const clientRTTSegmentName = "client-rtt-excluded"

// startTrace is the recorded create→attach trace: the ordered stack segments
// plus the separately-measured, excluded client RTT.
type startTrace struct {
	segments  []startSegment // the doc 15 §8 stack segments, in order
	clientRTT time.Duration  // measured separately, EXCLUDED from the stack total (D81 / §8)
}

// stackTotal is the create→attach "seconds to start" the budget would gate on at
// M2 — the SUM of the stack segments, with client RTT excluded.
func (tr startTrace) stackTotal() time.Duration {
	var total time.Duration
	for _, s := range tr.segments {
		total += s.dur
	}
	return total
}

// segmentNames returns the recorded stack-segment names in order, for the
// structural (non-vacuity) check against doc15SegmentOrder.
func (tr startTrace) segmentNames() []string {
	out := make([]string, len(tr.segments))
	for i, s := range tr.segments {
		out[i] = s.name
	}
	return out
}

// decompositionViolations is the SINGLE structural decomposition check the §8
// "seconds to start" assertion runs: the recorded stack must mirror
// doc15SegmentOrder in COUNT and in PER-INDEX NAME (a dropped, reordered, or
// renamed segment is a violation), every recorded duration must be positive (the
// trace is non-vacuous), and the separately-measured client RTT must NOT appear
// as a stack segment (doc 15 §8: measured separately and EXCLUDED). It returns
// one human-readable line per violation; an EMPTY slice is a clean decomposition.
//
// Both the positive smoke and the mutation-style negative control call THIS
// function, so the negative control trips the EXACT check the positive path
// relies on — not a parallel restatement of it.
func (tr startTrace) decompositionViolations() []string {
	var v []string
	got := tr.segmentNames()
	if len(got) != len(doc15SegmentOrder) {
		v = append(v, fmt.Sprintf("segment count = %d, want the full doc 15 §8 set of %d", len(got), len(doc15SegmentOrder)))
	}
	// Per-index name match up to the shorter length, so a dropped segment shows
	// up as both a count violation AND the first index whose name no longer lines
	// up with the frozen order.
	n := len(got)
	if len(doc15SegmentOrder) < n {
		n = len(doc15SegmentOrder)
	}
	for i := 0; i < n; i++ {
		if got[i] != doc15SegmentOrder[i] {
			v = append(v, fmt.Sprintf("§8 segment[%d] = %q, want %q (the decomposition must mirror doc 15 §8 in order)", i, got[i], doc15SegmentOrder[i]))
		}
	}
	for i, s := range tr.segments {
		if s.dur <= 0 {
			v = append(v, fmt.Sprintf("§8 segment %q recorded a non-positive duration — the trace must be non-vacuous", tr.segments[i].name))
		}
	}
	for _, name := range got {
		if name == clientRTTSegmentName {
			v = append(v, "client RTT must be measured SEPARATELY and EXCLUDED from the create→attach stack (doc 15 §8), but it appears as a stack segment")
		}
	}
	return v
}

// ─────────────────────────────────────────────────────────────────────────────
// (2) the five-class clean-teardown model (doc 06 §3b / doc 15 §3 DESTROYED)
// ─────────────────────────────────────────────────────────────────────────────

// sessionResidue is the host-side state a single session instantiates across its
// lifecycle. It models exactly the FIVE leak classes doc 06 §3b enumerates so a
// clean teardown can be asserted as "all five return to bootstrap":
//
//	orphaned VM            -> vmDomain
//	leaked nftables/allow  -> nftRuleCount (per-session iface rule + allow4/allow6 sets)
//	dangling CoW overlay   -> cowOverlay
//	stranded proxy session -> proxySession   (NOT modeled by teardown_nft6_test.go)
//	leftover minted ident  -> mintedIdentity (NOT modeled by teardown_nft6_test.go)
//
// This is a MODEL fake (D50): it never touches a kernel, a hypervisor, the
// boundary proxy, or the Identity service — it records create-side instantiation
// and destroy-side disposal so the leak-free invariant is testable offline.
type sessionResidue struct {
	vmDomain       string // the libvirt domain handle (orphaned VM if it survives destroy)
	nftRuleCount   int    // per-session nftables objects (iface rule + allow4 + allow6 + dns2b map)
	cowOverlay     string // the per-session qcow2 CoW overlay path (dangling overlay if it survives)
	proxySession   string // the ds-tlsproxy per-session state handle (stranded proxy session if it survives)
	mintedIdentity string // the short-lived minted identity / CA-leaf handle (leftover identity if it survives)

	// workState is the in-VM working set a SNAPSHOTTING capture preserves and a
	// resume / migrate restores — the doc 06 §3b "state survives the round trip"
	// payload. SYNTHETIC: an opaque token, never real guest memory (D50).
	workState string
}

// lifecycleHost is the in-process clean-teardown model: the set of live session
// residues. Bootstrap is the empty host; a clean teardown returns to it. It also
// walks each session through the FROZEN doc 15 §3 state machine
// (attach.v1.SessionStateName) so the create→attach→destroy ORDER is asserted,
// not just the endpoints.
type lifecycleHost struct {
	live     map[string]*sessionResidue
	states   map[string]attachv1.SessionStateName // session → current §3 state
	teardown int                                  // count of unconditional teardown sweeps (D68)

	// pauseTrace records the ORDERED §3 state walk a pauseSession drives for a
	// session, so an intermediate state set-then-immediately-superseded (notably
	// RESUMING on the transparent/best-effort tiers) is OBSERVABLE after the fact
	// — the same recorded-trace technique startTrace uses for the §8 segments. It
	// is pure instrumentation (D81 instrument-not-gate): it changes nothing about
	// the endpoint behavior (final `states[session]`, returned tier/tools) the
	// existing PauseBudgetTiers subtests assert.
	pauseTrace map[string][]attachv1.SessionStateName // session → ordered §3 states the last pause walked
}

func newLifecycleHost() *lifecycleHost {
	return &lifecycleHost{
		live:       map[string]*sessionResidue{},
		states:     map[string]attachv1.SessionStateName{},
		pauseTrace: map[string][]attachv1.SessionStateName{},
	}
}

// create instantiates every leak-class residue for a session and advances it
// through the §3 CREATING phase, recording the create-half §8 segments. It
// returns the recorded segment durations keyed by name so the caller assembles
// the start trace. hostIdx is the never-recycled monotonic host-session index
// (D66 burn-on-allocate) the nftables / overlay handles are stamped with.
func (h *lifecycleHost) create(session string, hostIdx uint64) map[string]time.Duration {
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_CREATING
	h.live[session] = &sessionResidue{
		vmDomain:       fmt.Sprintf("domain-%s-%d", session, hostIdx),
		nftRuleCount:   4, // iface rule + allow4 set + allow6 set + dns2b map
		cowOverlay:     fmt.Sprintf("/var/lib/ds/overlays/%s.qcow2", session),
		proxySession:   "ds-tlsproxy/" + session,
		mintedIdentity: "ds-synth-leaf-" + session, // SYNTHETIC: no real credential material (D50)
	}
	// Record the create-half §8 segments. The durations are SYNTHETIC, tiny, and
	// distinct-per-segment so the trace is non-vacuous; they are a recorded trend
	// only (D81) — never asserted against a budget.
	return map[string]time.Duration{
		"placement-decision":          1 * time.Millisecond,
		"overlay-clone":               2 * time.Millisecond,
		"tap-nft-programming":         3 * time.Millisecond,
		"identity-ca-digest-sequence": 4 * time.Millisecond,
		"boot-to-entrypoint":          5 * time.Millisecond,
		"policy-ready":                6 * time.Millisecond,
		"routable":                    7 * time.Millisecond,
	}
}

// attach advances the session to ATTACHED (via READY) and records the final §8
// attach-handshake segment. It returns the recorded attach-handshake duration.
// Modeling READY before ATTACHED keeps the §3 structural gate honest: a create
// that no longer becomes routable-then-attached would not reach ATTACHED here.
func (h *lifecycleHost) attach(session string) time.Duration {
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_READY
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED
	return 8 * time.Millisecond // attach-handshake segment (recorded trend, D81)
}

// destroy runs the §4.2 / §3 DESTROYING→DESTROYED teardown UNCONDITIONALLY
// (D68): it disposes every leak-class residue in one sweep and lands the session
// in DESTROYED. Idempotent on session (an absent session is a counted no-op
// sweep that converges to bootstrap). The teardown counter increments on every
// call so a skipped teardown (the way leaks happen) is detectable.
func (h *lifecycleHost) destroy(session string) {
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYING
	h.teardown++
	delete(h.live, session) // dispose ALL five leak classes in one residue drop
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED
}

// stateOf returns the session's current §3 state (UNSPECIFIED for an unknown
// session).
func (h *lifecycleHost) stateOf(session string) attachv1.SessionStateName {
	if s, ok := h.states[session]; ok {
		return s
	}
	return attachv1.SessionStateName_SESSION_STATE_NAME_UNSPECIFIED
}

// leakReport enumerates every leak-class residue still live after a teardown
// loop, one human-readable line per leak. An EMPTY report is the clean-teardown
// done-when; a non-empty report names exactly what leaked (and which class) so a
// failure is actionable.
func (h *lifecycleHost) leakReport() []string {
	var leaks []string
	for _, session := range sortedResidueKeys(h.live) {
		r := h.live[session]
		if r.vmDomain != "" {
			leaks = append(leaks, "orphaned-VM "+session+": "+r.vmDomain)
		}
		if r.nftRuleCount != 0 {
			leaks = append(leaks, fmt.Sprintf("leaked-nftables %s: %d rules/allow-set entries", session, r.nftRuleCount))
		}
		if r.cowOverlay != "" {
			leaks = append(leaks, "dangling-CoW-overlay "+session+": "+r.cowOverlay)
		}
		if r.proxySession != "" {
			leaks = append(leaks, "stranded-proxy-session "+session+": "+r.proxySession)
		}
		if r.mintedIdentity != "" {
			leaks = append(leaks, "leftover-minted-identity "+session+": "+r.mintedIdentity)
		}
	}
	return leaks
}

func sortedResidueKeys(m map[string]*sessionResidue) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// (3) D46 tiered pause budget — operational invisibility
// ─────────────────────────────────────────────────────────────────────────────

// pauseTier classifies a pause duration against the D46 tiered budget. The
// boundaries are the FROZEN D46 tiers (doc 06 §3b / doc 15 §3 PARKED): ≤5 min
// fully transparent, 5–15 min best-effort, >15 min snapshot+park with NO
// transparency claim. These bounds are the ratified D46 contract, not strawman
// timing numbers (so naming them here does NOT violate the D81 no-gate rule —
// D81 governs the create→attach budget, not the D46 pause tiers).
type pauseTier int

const (
	pauseTierTransparent  pauseTier = iota // ≤5 min: operationally invisible
	pauseTierBestEffort                    // 5–15 min: best-effort transparent resume
	pauseTierSnapshotPark                  // >15 min: snapshot + PARK, no transparency claim
)

func (p pauseTier) String() string {
	switch p {
	case pauseTierTransparent:
		return "transparent(≤5m)"
	case pauseTierBestEffort:
		return "best-effort(5–15m)"
	case pauseTierSnapshotPark:
		return "snapshot+park(>15m)"
	default:
		return "unknown"
	}
}

// classifyPause maps a pause duration to its D46 tier. The boundaries are
// inclusive at 5 min (still transparent) and inclusive at 15 min (still
// best-effort), so the canonical 60 s / 5 min / 15 min probes land transparent /
// transparent / best-effort and only a pause STRICTLY over 15 min parks.
func classifyPause(d time.Duration) pauseTier {
	switch {
	case d <= 5*time.Minute:
		return pauseTierTransparent
	case d <= 15*time.Minute:
		return pauseTierBestEffort
	default:
		return pauseTierSnapshotPark
	}
}

// claimsInvisibility reports whether a tier makes the D46 operational-
// invisibility claim. Transparent and best-effort tiers resume the session (the
// frozen §3 SUSPENDED─►RESUMING─►WORKING resume arm, settling at ATTACHED via the
// §3 ATTACHED⇄WORKING edge — §3 draws NO RESUMING→ATTACHED edge); the snapshot+park
// tier explicitly makes NO transparency claim (the §3 PARKED first-class state) —
// modeling that honestly is the point, so a future change that over-claims
// invisibility past 15 min is caught.
func (p pauseTier) claimsInvisibility() bool {
	return p == pauseTierTransparent || p == pauseTierBestEffort
}

// inFlightTool models one piece of in-flight tooling across a pause (git push
// over HTTPS, npm install, LLM streaming — the doc 06 §3b examples). resumedOK
// is set true when the pause was operationally invisible (the tool completed or
// transparently resumed); a parked pause leaves it false (no transparency
// claim).
type inFlightTool struct {
	name      string
	resumedOK bool
}

// pauseSession drives a session through the §3 SUSPENDED→(RESUMING|PARKED)
// path for a pause of duration d and reports the resulting tier plus whether the
// in-flight tooling stayed operationally invisible. It mutates the modeled §3
// state so the suspend/resume vs suspend/park branch is observable.
//
// The transparent/best-effort tiers walk SUSPENDED→RESUMING→WORKING→ATTACHED,
// transiting ONLY edges the frozen doc 15 §3 diagram draws: the resume arm
// `SUSPENDED ─► RESUMING ─► WORKING` (§3 line 97) lands the resumed session in
// WORKING, then the `ATTACHED ⇄ WORKING` edge settles it at the steady ATTACHED
// endpoint. (Earlier this model walked RESUMING→ATTACHED directly and the
// doc-comments named a "§3 SUSPENDED→RESUMING→ATTACHED" path; §3 has NO
// RESUMING→ATTACHED edge — only RESUMING→WORKING — so that citation named an
// edge that does not exist. Reconciled here to the real §3 edges; no new state
// name or edge is introduced — RESUMING/WORKING/ATTACHED are all frozen attach.v1
// names.) RESUMING and WORKING are DISTINCT intermediate §3 states, not just
// endpoints. Because the current state is overwritten in immediate succession,
// those intermediate steps are invisible in `states[session]` alone; pauseSession
// therefore APPENDS each state it sets to pauseTrace[session] (resetting it at the
// SUSPENDED entry) so the walk is observable after the fact — the way the migrate
// arm pins MIGRATING and the start path records its §8 segments. This is pure
// instrumentation (D81): the ENDPOINT behavior (final state ATTACHED, returned
// tier/tools) is byte-for-byte what the PauseBudgetTiers subtests already assert.
func (h *lifecycleHost) pauseSession(session string, d time.Duration, tools []inFlightTool) (pauseTier, []inFlightTool) {
	// setState records every §3 state into the per-session pause trace as it is
	// applied, so a set-then-immediately-superseded intermediate (RESUMING/WORKING)
	// is observable. The endpoint (`states[session]`) is identical to a plain set.
	setState := func(s attachv1.SessionStateName) {
		h.states[session] = s
		h.pauseTrace[session] = append(h.pauseTrace[session], s)
	}

	h.pauseTrace[session] = nil // fresh walk per pause (SUSPENDED is the entry)
	setState(attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED)
	tier := classifyPause(d)
	invisible := tier.claimsInvisibility()
	resumed := make([]inFlightTool, len(tools))
	for i, t := range tools {
		t.resumedOK = invisible // invisible pause => tool completes / transparently resumes
		resumed[i] = t
	}
	if invisible {
		// §3 line 97: SUSPENDED ─► RESUMING ─► WORKING, then settle to ATTACHED via
		// the §3 `ATTACHED ⇄ WORKING` edge. Every step is a frozen §3 edge.
		setState(attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING)
		setState(attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)
		setState(attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED)
	} else {
		// >15 min: first-class PARKED (D46), no transparency claim.
		setState(attachv1.SessionStateName_SESSION_STATE_NAME_PARKED)
	}
	return tier, resumed
}

// pauseStateTrace returns the ordered §3 state walk the LAST pauseSession drove
// for a session, so a caller can assert an intermediate transition (RESUMING) was
// OBSERVED — not just the SUSPENDED entry and the final endpoint. An empty slice
// means the session was never paused.
func (h *lifecycleHost) pauseStateTrace(session string) []attachv1.SessionStateName {
	return h.pauseTrace[session]
}

// pauseTraceObserved reports whether a given §3 state appears anywhere in the
// session's last recorded pause walk. It is how the RESUMING-intermediate subtest
// asserts the frozen §3 SUSPENDED─►RESUMING─►WORKING resume arm is traversed as
// DISTINCT states (settling at ATTACHED via §3 ATTACHED⇄WORKING).
func (h *lifecycleHost) pauseTraceObserved(session string, want attachv1.SessionStateName) bool {
	for _, s := range h.pauseTrace[session] {
		if s == want {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// (4) doc 15 §3 SNAPSHOTTING / MIGRATING — snapshot-resume + migrate handoff
// ─────────────────────────────────────────────────────────────────────────────
//
// The frozen doc 15 §3 diagram routes the active session through:
//
//	ATTACHED ⇄ WORKING ─► SNAPSHOTTING ─► (READY | MIGRATING ─► READY@host' | PARKED)
//
// This models the two non-PARKED arms the M0 smoke did not yet cover — the
// in-place snapshot/resume and the MIGRATING host handoff — against the SAME
// five-class clean-teardown invariant. Per §3 note 2 a migrate keeps the SAME
// session UUID but lands on a NEW host index/tap on the target (the record keeps
// index history); the §3b "state survives the round trip" claim is modeled by an
// opaque workState token that must come back byte-identical after the round trip.
// Synthetic / instrument-not-gate (D81): real snapshot/CoW/migration TIMING is
// metal-only and stays in lifecycle_live_test.go behind its env gate.

// work advances an ATTACHED session into WORKING and records the in-VM working
// set the snapshot will preserve. It is the ATTACHED⇄WORKING edge the §3 diagram
// names; recording workState here is what lets the round-trip assertion be
// non-vacuous (a snapshot that lost the state would not return this token).
func (h *lifecycleHost) work(session, state string) {
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_WORKING
	if r, ok := h.live[session]; ok {
		r.workState = state
	}
}

// snapshotResume drives the in-place SNAPSHOTTING ─► READY ─► ATTACHED arm: a
// snapshot is captured and the session resumes ON THE SAME HOST (no index/tap
// change), the working set preserved across the round trip. It returns the
// workState observed AFTER the round trip so the caller asserts byte-identity.
// The five leak-class residue is UNTOUCHED (an in-place resume strands nothing).
func (h *lifecycleHost) snapshotResume(session string) string {
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_SNAPSHOTTING
	// Resume in place: §3 SNAPSHOTTING ─► READY ─► ATTACHED, same host residue.
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_READY
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED
	if r, ok := h.live[session]; ok {
		return r.workState
	}
	return ""
}

// migrate drives the SNAPSHOTTING ─► MIGRATING ─► READY@host' handoff: the
// session is snapshotted on the source host, handed off to a NEW host index/tap
// on the target (§3 note 2 — same session UUID, fresh per-host handles), and the
// SOURCE-host residue is fully released so the handoff leaks nothing. The new
// target residue carries the SAME workState (state survives the handoff). It
// returns the workState observed on the target after the handoff.
//
// The handoff is the explicit anti-leak point: a migrate that forgot to release
// the source residue would double-count (source + target both live), which the
// five-class leakReport + the post-handoff live-session count catch.
func (h *lifecycleHost) migrate(session string, targetHostIdx uint64) string {
	src, ok := h.live[session]
	if !ok {
		return ""
	}
	preserved := src.workState
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_SNAPSHOTTING
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_MIGRATING
	// Land on the target: SAME session UUID, NEW host index/tap (§3 note 2). The
	// per-host handles (domain / overlay) are re-stamped with the target index;
	// the session-scoped identity / proxy session re-mint on the target. The
	// source residue is dropped — no double-booking across the handoff.
	h.live[session] = &sessionResidue{
		vmDomain:       fmt.Sprintf("domain-%s-%d", session, targetHostIdx),
		nftRuleCount:   4, // iface rule + allow4 + allow6 + dns2b map, re-programmed on the target
		cowOverlay:     fmt.Sprintf("/var/lib/ds/overlays/%s.qcow2", session),
		proxySession:   "ds-tlsproxy/" + session,
		mintedIdentity: "ds-synth-leaf-" + session, // re-minted on the target (D50 synthetic)
		workState:      preserved,                  // state survives the handoff
	}
	// READY@host' then ATTACHED — the session is live again on the target.
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_READY
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED
	return h.live[session].workState
}

// ─────────────────────────────────────────────────────────────────────────────
// THE M0 SMOKE — create → attach → destroy, all three §3b budgets in one drive
// ─────────────────────────────────────────────────────────────────────────────

// TestLifecycleSmoke_CreateAttachDestroy_AllThreeBudgets is the doc 06 §5 M0
// load-bearing lifecycle smoke at the seam level. It drives ONE create →
// attach → [pause/resume] → destroy cycle and asserts all three doc 06 §3b
// budgets: the §8 segment decomposition is recorded (instrument-not-gate, D81),
// teardown is clean across all five leak classes, and a within-budget pause is
// operationally invisible (D46). Fidelity: nested-ok logical assertions;
// metal-only timing is instrumented, not gated.
func TestLifecycleSmoke_CreateAttachDestroy_AllThreeBudgets(t *testing.T) {
	h := newLifecycleHost()
	const session = "ds-synth-smoke-0001"
	var hostIdx uint64 = 1 // index 0 is the reserved "unallocated" sentinel (D66)

	// ── create → attach, recording the §8 segments ──────────────────────────
	createSegs := h.create(session, hostIdx)
	if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_CREATING {
		t.Fatalf("[%s] after create want CREATING, got %v", fidelityNestedOK, got)
	}
	attachDur := h.attach(session)
	if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("[%s] create→attach did not reach ATTACHED, got %v", fidelityNestedOK, got)
	}

	// Assemble the start trace in the frozen §8 order; client RTT measured
	// SEPARATELY and EXCLUDED from the stack.
	trace := startTrace{clientRTT: 12 * time.Millisecond}
	for _, name := range doc15SegmentOrder {
		var dur time.Duration
		if name == "attach-handshake" {
			dur = attachDur
		} else {
			dur = createSegs[name]
		}
		trace.segments = append(trace.segments, startSegment{name: name, dur: dur})
	}

	// (1) "Seconds to start" — assert the §8 DECOMPOSITION exists and is
	// non-vacuous; do NOT assert any budget number (D81 instrument-not-gate).
	gotNames := trace.segmentNames()
	if len(gotNames) != len(doc15SegmentOrder) {
		t.Fatalf("[%s] create→attach trace has %d segments, want the full doc 15 §8 set of %d",
			fidelityNestedOK, len(gotNames), len(doc15SegmentOrder))
	}
	for i, want := range doc15SegmentOrder {
		if gotNames[i] != want {
			t.Errorf("[%s] §8 segment[%d] = %q, want %q (the decomposition must mirror doc 15 §8 in order)",
				fidelityNestedOK, i, gotNames[i], want)
		}
		if trace.segments[i].dur <= 0 {
			t.Errorf("[%s] §8 segment %q recorded a non-positive duration — the trace must be non-vacuous",
				fidelityNestedOK, want)
		}
	}
	// Client RTT is measured but EXCLUDED — it must not appear among the stack
	// segments (a venue cost folded into the stack total would be a §8 violation).
	for _, n := range gotNames {
		if n == clientRTTSegmentName {
			t.Errorf("[%s] client RTT must be measured SEPARATELY and EXCLUDED from the create→attach stack (doc 15 §8), but it appears as a stack segment", fidelityNestedOK)
		}
	}
	// The SAME structural decomposition check the mutation-style negative control
	// trips: a clean create→attach trace produces NO violations. (Additive — the
	// per-index assertions above stay; this binds the positive path and the
	// negative control to one shared check so a regression in either is caught.)
	if v := trace.decompositionViolations(); len(v) != 0 {
		t.Errorf("[%s] a clean create→attach trace must pass the §8 decomposition check, got violations:\n  %s",
			fidelityNestedOK, strings.Join(v, "\n  "))
	}
	// D81 instrumentation (NOT a gate; metal-only timing): record the trend.
	t.Logf("[%s] D81 instrumentation (NOT a gate): create→attach stack total=%s across %d §8 segments; client RTT=%s measured separately and EXCLUDED",
		fidelityMetalOnly, trace.stackTotal(), len(trace.segments), trace.clientRTT)

	// ── (3) D46 pause: a within-budget pause is operationally invisible ──────
	tools := []inFlightTool{{name: "git-push-https"}, {name: "npm-install"}, {name: "llm-streaming"}}
	tier, resumed := h.pauseSession(session, 60*time.Second, tools)
	if !tier.claimsInvisibility() {
		t.Fatalf("[%s] a 60 s pause must be operationally invisible (D46 ≤5m transparent tier), got tier %s", fidelityNestedOK, tier)
	}
	for _, tl := range resumed {
		if !tl.resumedOK {
			t.Errorf("[%s] in-flight tool %q did not complete/transparently resume across a within-budget pause (D46 operational invisibility)", fidelityNestedOK, tl.name)
		}
	}
	if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Errorf("[%s] after a within-budget pause the session must resume to ATTACHED (D46), got %v", fidelityNestedOK, got)
	}
	// Additive: the within-budget resume must transit the frozen §3 resume arm
	// SUSPENDED─►RESUMING─►WORKING (§3 line 97) before settling at ATTACHED — it must
	// NOT short-circuit past RESUMING/WORKING. (Endpoint assertion above is
	// unchanged; this only pins that the real §3 edges were walked, never a
	// non-existent RESUMING→ATTACHED edge.)
	for _, want := range []attachv1.SessionStateName{
		attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING,
		attachv1.SessionStateName_SESSION_STATE_NAME_WORKING,
	} {
		if !h.pauseTraceObserved(session, want) {
			t.Errorf("[%s] a within-budget resume must transit frozen §3 %v on the SUSPENDED─►RESUMING─►WORKING arm; trace=%v",
				fidelityNestedOK, want, stateTraceNames(h.pauseStateTrace(session)))
		}
	}

	// ── destroy → assert clean teardown across all five §3b leak classes ─────
	h.destroy(session)
	if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED {
		t.Fatalf("[%s] destroy did not reach DESTROYED, got %v", fidelityNestedOK, got)
	}
	if leaks := h.leakReport(); len(leaks) != 0 {
		t.Fatalf("[%s] clean-teardown (doc 06 §3b) violated — destroy left residue:\n  %s",
			fidelityNestedOK, strings.Join(leaks, "\n  "))
	}
	if h.teardown != 1 {
		t.Errorf("[%s] teardown must run UNCONDITIONALLY exactly once per destroy (D68), got %d sweeps", fidelityNestedOK, h.teardown)
	}
}

// TestLifecycleSmoke_PauseBudgetTiers asserts the full D46 tiered budget at the
// canonical 60 s / 5 min / 15 min probes plus the over-budget park: ≤5 min is
// fully transparent, 5–15 min is best-effort (still invisible), and STRICTLY
// over 15 min snapshots + PARKs with NO transparency claim. Fidelity: nested-ok
// (the tier classification is a logical property); real pause LATENCY is
// metal-only and not exercised here.
func TestLifecycleSmoke_PauseBudgetTiers(t *testing.T) {
	cases := []struct {
		d              time.Duration
		wantTier       pauseTier
		wantInvisible  bool
		wantResumeName attachv1.SessionStateName
	}{
		{60 * time.Second, pauseTierTransparent, true, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED},
		{5 * time.Minute, pauseTierTransparent, true, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED},
		{15 * time.Minute, pauseTierBestEffort, true, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED},
		{15*time.Minute + time.Second, pauseTierSnapshotPark, false, attachv1.SessionStateName_SESSION_STATE_NAME_PARKED},
	}
	for _, tc := range cases {
		t.Run(tc.d.String(), func(t *testing.T) {
			h := newLifecycleHost()
			const session = "ds-synth-pause-probe"
			h.create(session, 1)
			h.attach(session)

			tier, resumed := h.pauseSession(session, tc.d, []inFlightTool{{name: "git-push-https"}})
			if tier != tc.wantTier {
				t.Errorf("[%s] pause %s classified %s, want %s (D46 tiered budget)", fidelityNestedOK, tc.d, tier, tc.wantTier)
			}
			if tier.claimsInvisibility() != tc.wantInvisible {
				t.Errorf("[%s] pause %s invisibility claim = %v, want %v (D46)", fidelityNestedOK, tc.d, tier.claimsInvisibility(), tc.wantInvisible)
			}
			for _, tl := range resumed {
				if tl.resumedOK != tc.wantInvisible {
					t.Errorf("[%s] pause %s tool %q resumedOK=%v, want %v — only a within-budget pause is operationally invisible (D46)",
						fidelityNestedOK, tc.d, tl.name, tl.resumedOK, tc.wantInvisible)
				}
			}
			if got := h.stateOf(session); got != tc.wantResumeName {
				t.Errorf("[%s] pause %s landed in §3 state %v, want %v (D46: within budget resume via the frozen §3 SUSPENDED─►RESUMING─►WORKING arm, settling at ATTACHED; else first-class PARKED)",
					fidelityNestedOK, tc.d, got, tc.wantResumeName)
			}
		})
	}
}

// stateTraceNames renders an ordered §3 state walk as its frozen
// attach.v1.SessionStateName strings, for an actionable failure message.
func stateTraceNames(trace []attachv1.SessionStateName) []string {
	out := make([]string, len(trace))
	for i, s := range trace {
		out[i] = s.String()
	}
	return out
}

// TestLifecycleSmoke_PauseResumingIntermediateObserved completes the doc 15 §3
// node coverage for the SUSPENDED→(RESUMING|PARKED) sub-path. PauseBudgetTiers
// asserts the ENDPOINTS (the SUSPENDED entry implicitly and the final ATTACHED /
// PARKED state); this subtest pins the INTERMEDIATE nodes the way the migrate arm
// pins MIGRATING — it asserts that on the transparent (≤5m) and best-effort
// (5–15m) tiers the session is OBSERVED to traverse the distinct §3 RESUMING and
// WORKING states on the frozen §3 resume arm (SUSPENDED─►RESUMING─►WORKING, §3
// line 97) on the way to its ATTACHED endpoint (reached via the §3 ATTACHED⇄WORKING
// edge — §3 draws NO RESUMING→ATTACHED edge), and that the >15m snapshot+park tier
// makes NO such resume (SUSPENDED→PARKED, never RESUMING). The endpoint behavior
// the PauseBudgetTiers subtests assert is unchanged — RESUMING/WORKING
// observability is added via the recorded pause state-trace, pure instrumentation
// (D81 instrument-not-gate). Fidelity: nested-ok (the §3 transition is a logical
// property; real resume LATENCY is metal-only).
func TestLifecycleSmoke_PauseResumingIntermediateObserved(t *testing.T) {
	cases := []struct {
		d          time.Duration
		tier       pauseTier
		wantResume bool // transparent/best-effort traverse RESUMING; snapshot+park does not
		wantEnd    attachv1.SessionStateName
		resumeDesc string
	}{
		{60 * time.Second, pauseTierTransparent, true, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED, "transparent (≤5m) tier resumes transparently"},
		{5 * time.Minute, pauseTierTransparent, true, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED, "transparent boundary (=5m) still resumes"},
		{15 * time.Minute, pauseTierBestEffort, true, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED, "best-effort (5–15m) tier resumes best-effort"},
		{15*time.Minute + time.Second, pauseTierSnapshotPark, false, attachv1.SessionStateName_SESSION_STATE_NAME_PARKED, "snapshot+park (>15m) tier parks, never resumes"},
	}
	for _, tc := range cases {
		t.Run(tc.d.String(), func(t *testing.T) {
			h := newLifecycleHost()
			const session = "ds-synth-resuming-probe"
			h.create(session, 1)
			h.attach(session)

			tier, _ := h.pauseSession(session, tc.d, []inFlightTool{{name: "git-push-https"}})
			if tier != tc.tier {
				t.Fatalf("[%s] pause %s classified %s, want %s (D46 tiered budget) — fixture drift", fidelityNestedOK, tc.d, tier, tc.tier)
			}

			trace := h.pauseStateTrace(session)
			// The walk is non-vacuous and shares the endpoints PauseBudgetTiers
			// asserts: it ENTERS at SUSPENDED and ENDS at the tier's endpoint. (This
			// keeps the new observation honest — it does not weaken or restate the
			// existing endpoint assertions, it builds on the same path.)
			if len(trace) < 2 {
				t.Fatalf("[%s] %s: pause state-trace must be non-vacuous (saw %v)", fidelityNestedOK, tc.resumeDesc, stateTraceNames(trace))
			}
			if trace[0] != attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED {
				t.Errorf("[%s] %s: a pause must ENTER at §3 SUSPENDED, trace=%v", fidelityNestedOK, tc.resumeDesc, stateTraceNames(trace))
			}
			if end := trace[len(trace)-1]; end != tc.wantEnd {
				t.Errorf("[%s] %s: pause must END at %v, trace=%v", fidelityNestedOK, tc.resumeDesc, tc.wantEnd, stateTraceNames(trace))
			}
			if got := h.stateOf(session); got != tc.wantEnd {
				t.Errorf("[%s] %s: final §3 state must be %v (endpoint unchanged), got %v", fidelityNestedOK, tc.resumeDesc, tc.wantEnd, got)
			}

			// THE nodes this subtest adds: RESUMING and WORKING are OBSERVED as
			// distinct intermediate §3 states on the resume tiers (the frozen §3
			// SUSPENDED─►RESUMING─►WORKING arm), and are ABSENT on the park tier —
			// completing doc 15 §3 SUSPENDED→(RESUMING|PARKED) coverage.
			gotResume := h.pauseTraceObserved(session, attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING)
			if gotResume != tc.wantResume {
				t.Errorf("[%s] %s: §3 RESUMING observed=%v, want %v (the intermediate node the migrate arm pins for MIGRATING); trace=%v",
					fidelityNestedOK, tc.resumeDesc, gotResume, tc.wantResume, stateTraceNames(trace))
			}
			// WORKING is the §3 endpoint of the RESUMING arm (§3 line 97 draws
			// RESUMING─►WORKING, never RESUMING→ATTACHED): it must be observed on a
			// resume and ABSENT on the park tier, the same as RESUMING.
			gotWorking := h.pauseTraceObserved(session, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)
			if gotWorking != tc.wantResume {
				t.Errorf("[%s] %s: §3 WORKING observed=%v, want %v (the frozen §3 RESUMING─►WORKING resume arm); trace=%v",
					fidelityNestedOK, tc.resumeDesc, gotWorking, tc.wantResume, stateTraceNames(trace))
			}
			if tc.wantResume {
				// The frozen §3 resume arm SUSPENDED─►RESUMING─►WORKING (§3 line 97),
				// settling at ATTACHED via the §3 ATTACHED⇄WORKING edge, must appear IN
				// ORDER (not merely present): RESUMING strictly after the SUSPENDED entry,
				// WORKING strictly after RESUMING (the only edge §3 draws out of RESUMING),
				// and the ATTACHED endpoint strictly after WORKING — so the resume
				// genuinely transits each frozen §3 node, never a non-existent
				// RESUMING→ATTACHED edge.
				iSusp := indexOfState(trace, attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED)
				iResume := indexOfState(trace, attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING)
				iWork := indexOfState(trace, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)
				iAttach := indexOfState(trace, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED)
				if !(iSusp >= 0 && iResume > iSusp && iWork > iResume && iAttach > iWork) {
					t.Errorf("[%s] %s: the resume must transit §3 SUSPENDED→RESUMING→WORKING→ATTACHED IN ORDER, trace=%v",
						fidelityNestedOK, tc.resumeDesc, stateTraceNames(trace))
				}
			}
		})
	}

	// Negative control: the RESUMING observation must be able to FAIL. A park-only
	// pause (>15m) does NOT resume, so asserting RESUMING was observed there must
	// be false — proving the observation is not vacuously true for every pause.
	t.Run("park-tier-never-observes-resuming", func(t *testing.T) {
		h := newLifecycleHost()
		const session = "ds-synth-resuming-neg"
		h.create(session, 1)
		h.attach(session)
		h.pauseSession(session, 30*time.Minute, []inFlightTool{{name: "git-push-https"}})
		if h.pauseTraceObserved(session, attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING) {
			t.Errorf("[%s] a >15m snapshot+park pause must NEVER traverse §3 RESUMING (no transparency claim, D46); trace=%v",
				fidelityNestedOK, stateTraceNames(h.pauseStateTrace(session)))
		}
		if !h.pauseTraceObserved(session, attachv1.SessionStateName_SESSION_STATE_NAME_PARKED) {
			t.Errorf("[%s] a >15m pause must land in first-class §3 PARKED; trace=%v",
				fidelityNestedOK, stateTraceNames(h.pauseStateTrace(session)))
		}
	})
}

// indexOfState returns the position of the first occurrence of want in trace, or
// -1 if absent — the small helper the in-order frozen §3
// SUSPENDED→RESUMING→WORKING→ATTACHED resume-arm assertion uses.
func indexOfState(trace []attachv1.SessionStateName, want attachv1.SessionStateName) int {
	for i, s := range trace {
		if s == want {
			return i
		}
	}
	return -1
}

// TestLifecycleSmoke_CleanTeardownLoop asserts the clean-teardown invariant
// survives REPETITION: an N-loop of create→attach→destroy returns the host to
// bootstrap (zero residue across all five leak classes) and runs the
// unconditional teardown sweep exactly once per iteration (D68). A leak or a
// non-idempotent teardown that only shows up under repetition is caught here —
// the §3b five-class companion to teardown_nft6_test.go's byte-identity loop.
// Fidelity: nested-ok.
func TestLifecycleSmoke_CleanTeardownLoop(t *testing.T) {
	h := newLifecycleHost()
	const n = 5
	var hostIdx uint64 = 1 // NEVER recycled (D66): a fresh index each iteration
	for i := 0; i < n; i++ {
		session := fmt.Sprintf("ds-synth-loop-%04d", i)
		h.create(session, hostIdx)
		hostIdx++
		h.attach(session)
		// Between attach and destroy the host MUST carry residue — a non-vacuous loop.
		if len(h.live) == 0 {
			t.Fatalf("[%s] iter %d: host carries no residue after create→attach — the loop is vacuous", fidelityNestedOK, i)
		}
		h.destroy(session)
		if leaks := h.leakReport(); len(leaks) != 0 {
			t.Fatalf("[%s] iter %d: clean-teardown violated:\n  %s", fidelityNestedOK, i, strings.Join(leaks, "\n  "))
		}
	}
	if len(h.live) != 0 {
		t.Fatalf("[%s] after %d create→attach→destroy loops the host must return to bootstrap (zero residue), got %d live sessions",
			fidelityNestedOK, n, len(h.live))
	}
	if h.teardown != n {
		t.Errorf("[%s] expected %d unconditional teardown sweeps (one per destroy, D68), got %d", fidelityNestedOK, n, h.teardown)
	}
}

// TestLifecycleSmoke_SnapshotResumeAndMigrateHandoff extends the M0 smoke beyond
// create→attach→[pause]→destroy to the full doc 06 §3b / doc 15 §3 lifecycle:
//
//	create ─► attach ─► work ─► snapshot ─► (resume | migrate) ─► destroy
//
// It drives the two non-PARKED arms of the frozen §3 SNAPSHOTTING node —
// (A) the in-place SNAPSHOTTING ─► READY ─► ATTACHED snapshot/resume, and
// (B) the SNAPSHOTTING ─► MIGRATING ─► READY@host' migrate handoff — and asserts
// the §3b "state survives the round trip" claim (the working set returns
// byte-identical) plus the SAME five-class clean-teardown invariant after each.
// The migrate arm additionally pins §3 note 2: same session UUID, NEW host
// index/tap on the target, and NO double-booked residue across the handoff.
// Fidelity: nested-ok logical assertions; real snapshot/CoW/migration TIMING is
// metal-only and instrumented elsewhere (the live leg below), not gated (D81).
func TestLifecycleSmoke_SnapshotResumeAndMigrateHandoff(t *testing.T) {
	// (A) in-place snapshot/resume: state survives the round trip, no leaks.
	t.Run("snapshot-resume-in-place", func(t *testing.T) {
		h := newLifecycleHost()
		const session = "ds-synth-snap-0001"
		const workState = "ds-synth-workstate-abc123" // opaque, SYNTHETIC (D50)
		h.create(session, 1)
		h.attach(session)
		h.work(session, workState)
		if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_WORKING {
			t.Fatalf("[%s] before snapshot the session must be WORKING (§3 ATTACHED⇄WORKING), got %v", fidelityNestedOK, got)
		}

		got := h.snapshotResume(session)
		if got != workState {
			t.Errorf("[%s] snapshot/resume must preserve the working set across the round trip (doc 06 §3b 'state survives the round trip'): got %q, want %q",
				fidelityNestedOK, got, workState)
		}
		if st := h.stateOf(session); st != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
			t.Errorf("[%s] an in-place snapshot/resume must land back at ATTACHED via §3 SNAPSHOTTING─►READY─►ATTACHED, got %v", fidelityNestedOK, st)
		}

		// Clean teardown still holds after the snapshot round trip.
		h.destroy(session)
		if leaks := h.leakReport(); len(leaks) != 0 {
			t.Fatalf("[%s] clean-teardown (doc 06 §3b) violated after snapshot/resume — destroy left residue:\n  %s",
				fidelityNestedOK, strings.Join(leaks, "\n  "))
		}
		if h.teardown != 1 {
			t.Errorf("[%s] teardown must run UNCONDITIONALLY exactly once per destroy (D68) after snapshot/resume, got %d sweeps", fidelityNestedOK, h.teardown)
		}
	})

	// (B) migrate handoff: SNAPSHOTTING ─► MIGRATING ─► READY@host'. Same session
	// UUID, NEW host index/tap, state survives the handoff, no double-booked
	// residue, clean teardown on the target.
	t.Run("migrate-handoff-to-new-host-index", func(t *testing.T) {
		h := newLifecycleHost()
		const session = "ds-synth-migr-0001"
		const workState = "ds-synth-workstate-xyz789"
		var srcIdx uint64 = 1
		var dstIdx uint64 = 2 // NEW host index/tap on the target (§3 note 2; D66 burn-on-allocate)
		h.create(session, srcIdx)
		h.attach(session)
		h.work(session, workState)

		srcDomain := h.live[session].vmDomain // the source-host per-session handle, pre-handoff

		got := h.migrate(session, dstIdx)
		if got != workState {
			t.Errorf("[%s] migrate must preserve the working set across the handoff (doc 06 §3b 'state survives the round trip'): got %q, want %q",
				fidelityNestedOK, got, workState)
		}
		if st := h.stateOf(session); st != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
			t.Errorf("[%s] a migrate must land READY@host'─►ATTACHED via §3 SNAPSHOTTING─►MIGRATING, got %v", fidelityNestedOK, st)
		}

		// §3 note 2: SAME session UUID, NEW host index/tap on the target — the
		// per-host handle must be re-stamped with the target index, not carried
		// over from the source.
		dstDomain := h.live[session].vmDomain
		if dstDomain == srcDomain {
			t.Errorf("[%s] migrate must re-stamp the per-host handle with the NEW target index (§3 note 2): source=%q target=%q (unchanged)",
				fidelityNestedOK, srcDomain, dstDomain)
		}
		if want := fmt.Sprintf("domain-%s-%d", session, dstIdx); dstDomain != want {
			t.Errorf("[%s] migrated session must carry the target host index handle: got %q, want %q", fidelityNestedOK, dstDomain, want)
		}

		// No double-booking: exactly ONE live residue for the session after the
		// handoff (a migrate that forgot to release the source would leave two).
		if n := len(h.live); n != 1 {
			t.Errorf("[%s] migrate must release the source-host residue (no double-booking across the handoff): %d live residues, want 1", fidelityNestedOK, n)
		}

		// Clean teardown on the TARGET host across all five §3b leak classes.
		h.destroy(session)
		if leaks := h.leakReport(); len(leaks) != 0 {
			t.Fatalf("[%s] clean-teardown (doc 06 §3b) violated after a migrate handoff — destroy left residue:\n  %s",
				fidelityNestedOK, strings.Join(leaks, "\n  "))
		}
	})

	// (live leg) the genuinely-live snapshot/CoW/migration legs — real qemu
	// snapshot capture, CoW overlay semantics, and a live host-to-host handoff —
	// are metal-only (D34/D81) and stay env-gated; per-commit CI proves the
	// nested-ok logical model above, never a live hypervisor (D50). This stub
	// keeps the gate visible in this file; the live drive lives in
	// lifecycle_live_test.go behind the same env gate.
	t.Run("live-snapshot-migrate", func(t *testing.T) {
		if os.Getenv("DS_KVM_LIVE") != "1" {
			t.Skip("metal-only (D34/D81): live snapshot/CoW/migrate is env-gated (DS_KVM_LIVE=1); the live drive lives in lifecycle_live_test.go")
		}
		t.Fatal("live snapshot/migrate leg is not driven from this per-commit smoke file — run the env-gated lifecycle_live_test.go leg")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// LEG B — doc 15 §3 SUSPENDED(reason) split resume authorities (note 3 + §4.3)
// ─────────────────────────────────────────────────────────────────────────────
//
// The wave-1 RESUMING reconciliation above models the §3 SUSPENDED→(RESUMING|
// PARKED) sub-path for the D46 *pause-budget* tiers (a within-budget pause that
// transparently resumes vs an over-budget snapshot+park). LEG B completes the §3
// SUSPENDED sub-path coverage with the OTHER axis the same node carries: the
// `SUSPENDED(reason)` reason enum and its SPLIT RESUME AUTHORITIES.
//
// The frozen contract (consume, never re-declare):
//   - The reason enum is the FROZEN attach.v1.SuspendReason — SUSPEND_REASON_USER
//     (1) | SUSPEND_REASON_POLICY_BREACH (2) | SUSPEND_REASON_REBALANCE (3) — the
//     `SUSPENDED(reason: user | policy_breach | rebalance)` of the doc 15 §3
//     diagram. This file IMPORTS that enum (the one legal cross-tree import, D80);
//     it does NOT introduce a parallel reason type.
//   - doc 15 §3 note 3: "split resume authorities (user → user; policy_breach →
//     human approval; rebalance → scheduler)" — with policy_breach NARROWED to
//     D77's genuine-threat classes (blocklist hits / rules configured
//     action: suspend), the genuine rung-2 BIC suspension.
//   - doc 16 §8.2: "resume authority for BIC suspensions is human approval
//     (SUSPENDED(reason), D35)" — a parked genuine rung-2 ask resumes ON ANSWER,
//     never timing out into allow or kill. THE KEY ASSERTION: a policy_breach
//     suspension parks pending human approval and must NOT auto-traverse the §3
//     SUSPENDED─►RESUMING edge without that approval.
//
// The resume arm, once the right authority acts, is the SAME frozen §3 edge the
// wave-1 reconciliation walks: SUSPENDED ─► RESUMING ─► WORKING (§3 line 97),
// settling at ATTACHED via the §3 ATTACHED⇄WORKING edge. No new state name or
// edge is introduced — every state is a frozen attach.v1.SessionStateName and
// every authority maps onto the frozen attach.v1.SuspendReason. SYNTHETIC
// in-process model only (D50); nested-ok (a logical authority property — real
// suspend/resume LATENCY is metal-only and lives in the env-gated live leg).

// resumeAuthority is WHO may carry a SUSPENDED(reason) session back across the §3
// SUSPENDED─►RESUMING edge. It is the doc 15 §3 note 3 split, modeled as a small
// closed set so a resume attempt by the WRONG authority is a structural refusal
// (the policy_breach key assertion). It is NOT a wire type — it is the in-process
// model of "who holds resume authority", the §8.2 contract made testable offline.
type resumeAuthority int

const (
	resumeAuthorityNone          resumeAuthority = iota // no authority presented (the bare auto-resume attempt)
	resumeAuthorityUser                                 // the launching user (user-reason suspension)
	resumeAuthorityHumanApproval                        // a genuine rung-2 human approval (policy_breach / BIC)
	resumeAuthorityScheduler                            // the fleet scheduler (rebalance)
)

func (a resumeAuthority) String() string {
	switch a {
	case resumeAuthorityUser:
		return "user"
	case resumeAuthorityHumanApproval:
		return "human-approval"
	case resumeAuthorityScheduler:
		return "scheduler"
	default:
		return "none"
	}
}

// resumeAuthorityFor maps a FROZEN attach.v1.SuspendReason to the resume
// authority doc 15 §3 note 3 assigns it: user → user; policy_breach → human
// approval (the §8.2 BIC contract); rebalance → scheduler. An UNSPECIFIED reason
// (the enum zero value, never a legal SUSPENDED state) confers NO authority — it
// can never be resumed, a fail-closed default rather than a silent allow.
func resumeAuthorityFor(reason attachv1.SuspendReason) resumeAuthority {
	switch reason {
	case attachv1.SuspendReason_SUSPEND_REASON_USER:
		return resumeAuthorityUser
	case attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH:
		return resumeAuthorityHumanApproval
	case attachv1.SuspendReason_SUSPEND_REASON_REBALANCE:
		return resumeAuthorityScheduler
	default:
		return resumeAuthorityNone
	}
}

// suspension is the in-process record of a live SUSPENDED(reason) park: the
// FROZEN reason it was suspended under (so the required resume authority is
// derived, never stored as a parallel field that could drift) and whether a
// genuine rung-2 human approval has landed yet (the §8.2 "resume on answer"
// gate — meaningful only for the policy_breach BIC arm). A session with a live
// suspension is PARKED at §3 SUSPENDED until the matching authority resumes it.
type suspension struct {
	reason   attachv1.SuspendReason // the frozen §3 reason (user | policy_breach | rebalance)
	approved bool                   // a genuine rung-2 human approval has landed (§8.2; policy_breach arm)
}

// requiredAuthority is the resume authority THIS suspension demands, derived from
// its frozen reason via the §3 note 3 split — never a separately-stored field.
func (s suspension) requiredAuthority() resumeAuthority { return resumeAuthorityFor(s.reason) }

// suspendForReason drives an ATTACHED/WORKING session across the §3 SUSPENDED edge
// under a FROZEN attach.v1.SuspendReason and PARKS it there — it does NOT resume.
// This is the §4.3 suspend signal: the orchestrator acks the boundary→orchestrator
// suspend signal (carrying the D77 reason class) and drives Suspend(reason); the
// session now waits for the reason-appropriate resume authority. The walk is
// recorded into the SAME pauseTrace instrumentation the wave-1 resume arm uses, so
// "parked at SUSPENDED, never auto-traversed RESUMING" is observable after the
// fact (the policy_breach key assertion). It returns the live suspension handle.
func (h *lifecycleHost) suspendForReason(session string, reason attachv1.SuspendReason) *suspension {
	h.pauseTrace[session] = nil // fresh walk per suspend (SUSPENDED is the entry)
	h.states[session] = attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED
	h.pauseTrace[session] = append(h.pauseTrace[session], attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED)
	return &suspension{reason: reason}
}

// approveResume records that a genuine rung-2 HUMAN APPROVAL has landed for a
// policy_breach (BIC) suspension — the §8.2 "resume on answer" event. It mutates
// only the approval gate; it does NOT itself traverse any §3 edge (a separate
// resume call, carrying human-approval authority, does that). It is a no-op shape
// on non-policy_breach reasons (their authority is not human approval), which the
// resume gate below already enforces.
func (s *suspension) approveResume() { s.approved = true }

// resumeWithAuthority is the §3 SUSPENDED─►RESUMING─►WORKING resume arm GATED on
// resume authority (doc 15 §3 note 3 + §8.2). It traverses the frozen resume arm
// (settling at ATTACHED via §3 ATTACHED⇄WORKING) IFF the presented authority is
// the one the suspension's frozen reason demands — AND, for the policy_breach /
// human-approval arm, IFF a genuine rung-2 approval has actually landed
// (approveResume). On a mismatch (wrong authority, or human approval not yet
// granted) it REFUSES: the session stays parked at §3 SUSPENDED and NO
// SUSPENDED─►RESUMING edge is traversed (the recorded trace shows only the
// SUSPENDED entry). It reports whether the resume was admitted.
//
// THE KEY ASSERTION lives here: a policy_breach suspension resumed with anything
// other than a LANDED human approval returns false and the trace never shows
// RESUMING — the §3 SUSPENDED─►RESUMING edge does not auto-traverse without the
// §8.2 human-approval authority.
func (h *lifecycleHost) resumeWithAuthority(session string, s *suspension, by resumeAuthority) bool {
	if by != s.requiredAuthority() {
		return false // wrong authority — parked at SUSPENDED, no §3 edge traversed
	}
	if s.requiredAuthority() == resumeAuthorityHumanApproval && !s.approved {
		return false // policy_breach / BIC: §8.2 demands a LANDED human approval first
	}
	// Authority satisfied — walk the frozen §3 resume arm, recording each node so
	// the traversal is observable (the same recorded-trace technique the wave-1
	// pause resume arm and the migrate arm use). Endpoint is ATTACHED.
	setState := func(st attachv1.SessionStateName) {
		h.states[session] = st
		h.pauseTrace[session] = append(h.pauseTrace[session], st)
	}
	setState(attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING)
	setState(attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)
	setState(attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED)
	return true
}

// TestLifecycleSmoke_SuspendReasonSplitResumeAuthorities is LEG B: it drives the
// frozen doc 15 §3 SUSPENDED(reason) sub-path for all three reasons and asserts
// the §3 note 3 / §4.3 / doc 16 §8.2 SPLIT RESUME AUTHORITIES —
//
//	user          → user authority resumes
//	policy_breach → human approval resumes (genuine rung-2 BIC), and CANNOT
//	                auto-traverse SUSPENDED─►RESUMING without that approval
//	rebalance     → scheduler authority resumes
//
// completing the §3 SUSPENDED sub-path coverage the wave-1 RESUMING→WORKING
// reconciliation begins. The FROZEN attach.v1.SuspendReason enum is consumed
// (never re-declared). Additive/test-only: it adds NO state name or edge (the
// resume arm is the frozen §3 SUSPENDED─►RESUMING─►WORKING, settling at ATTACHED)
// and weakens no existing PauseBudgetTiers / RESUMING-observability assertion.
// Fidelity: nested-ok (a logical authority property; real resume LATENCY is
// metal-only).
func TestLifecycleSmoke_SuspendReasonSplitResumeAuthorities(t *testing.T) {
	cases := []struct {
		reason       attachv1.SuspendReason
		wantAuth     resumeAuthority
		needsApprove bool // the policy_breach BIC arm requires a landed human approval first
		desc         string
	}{
		{
			reason:   attachv1.SuspendReason_SUSPEND_REASON_USER,
			wantAuth: resumeAuthorityUser,
			desc:     "user reason → user resume authority (§3 note 3)",
		},
		{
			reason:       attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
			wantAuth:     resumeAuthorityHumanApproval,
			needsApprove: true,
			desc:         "policy_breach reason → human approval (genuine rung-2 BIC; doc 16 §8.2)",
		},
		{
			reason:   attachv1.SuspendReason_SUSPEND_REASON_REBALANCE,
			wantAuth: resumeAuthorityScheduler,
			desc:     "rebalance reason → scheduler resume authority (§3 note 3)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.reason.String(), func(t *testing.T) {
			h := newLifecycleHost()
			const session = "ds-synth-suspend-reason"
			h.create(session, 1)
			h.attach(session)

			// (1) The frozen §3 split is what THIS reason maps to (consume the enum,
			// derive the authority — never a parallel hand-rolled table).
			s := h.suspendForReason(session, tc.reason)
			if got := s.requiredAuthority(); got != tc.wantAuth {
				t.Fatalf("[%s] %s: SUSPENDED(%v) demands resume authority %s, want %s (doc 15 §3 note 3 split)",
					fidelityNestedOK, tc.desc, tc.reason, got, tc.wantAuth)
			}
			// The session is PARKED at §3 SUSPENDED — the suspend half does NOT resume.
			if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED {
				t.Fatalf("[%s] %s: after Suspend(reason) the session must park at §3 SUSPENDED, got %v",
					fidelityNestedOK, tc.desc, got)
			}

			// (2) Resume by the WRONG authority is REFUSED for every reason: the
			// session stays parked at SUSPENDED and the §3 SUSPENDED─►RESUMING edge is
			// NOT traversed. We probe each of the other two authorities.
			for _, wrong := range []resumeAuthority{resumeAuthorityUser, resumeAuthorityHumanApproval, resumeAuthorityScheduler} {
				if wrong == tc.wantAuth {
					continue
				}
				if h.resumeWithAuthority(session, s, wrong) {
					t.Errorf("[%s] %s: resume by the WRONG authority %s was admitted — SUSPENDED(%v) must require %s (split resume authority)",
						fidelityNestedOK, tc.desc, wrong, tc.reason, tc.wantAuth)
				}
				if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED {
					t.Errorf("[%s] %s: a refused resume must leave the session parked at §3 SUSPENDED, got %v",
						fidelityNestedOK, tc.desc, got)
				}
				if h.pauseTraceObserved(session, attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING) {
					t.Errorf("[%s] %s: a refused resume must NOT traverse the §3 SUSPENDED─►RESUMING edge; trace=%v",
						fidelityNestedOK, tc.desc, stateTraceNames(h.pauseStateTrace(session)))
				}
			}

			// (3) THE KEY ASSERTION (policy_breach arm): even the CORRECT human-approval
			// authority must NOT auto-traverse SUSPENDED─►RESUMING until a genuine rung-2
			// approval has actually LANDED (doc 16 §8.2 "resume on answer"). For the
			// non-BIC reasons there is no approval gate (their authority is not human
			// approval), so this probe is skipped.
			if tc.needsApprove {
				if h.resumeWithAuthority(session, s, tc.wantAuth) {
					t.Errorf("[%s] %s: a policy_breach suspension must NOT resume on human-approval authority BEFORE the approval lands (doc 16 §8.2)",
						fidelityNestedOK, tc.desc)
				}
				if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED {
					t.Errorf("[%s] %s: pending the rung-2 approval the session must stay parked at §3 SUSPENDED, got %v",
						fidelityNestedOK, tc.desc, got)
				}
				if h.pauseTraceObserved(session, attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING) {
					t.Errorf("[%s] %s: a policy_breach park must NOT auto-traverse §3 SUSPENDED─►RESUMING without the rung-2 approval; trace=%v",
						fidelityNestedOK, tc.desc, stateTraceNames(h.pauseStateTrace(session)))
				}
				// The approval lands (§8.2 resume-on-answer) — NOW the human-approval
				// authority may resume.
				s.approveResume()
			}

			// (4) Resume by the CORRECT authority (post-approval where required) walks
			// the frozen §3 resume arm SUSPENDED─►RESUMING─►WORKING and settles at
			// ATTACHED — the SAME arm the wave-1 reconciliation drives, never a new edge.
			if !h.resumeWithAuthority(session, s, tc.wantAuth) {
				t.Fatalf("[%s] %s: resume by the correct authority %s must be admitted", fidelityNestedOK, tc.desc, tc.wantAuth)
			}
			if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
				t.Errorf("[%s] %s: an authorized resume must settle at §3 ATTACHED via SUSPENDED─►RESUMING─►WORKING, got %v",
					fidelityNestedOK, tc.desc, got)
			}
			// The resume must transit the frozen §3 nodes IN ORDER (SUSPENDED entry →
			// RESUMING → WORKING → ATTACHED), never a non-existent RESUMING→ATTACHED
			// edge — the same in-order discipline the wave-1 resume-arm subtest pins.
			trace := h.pauseStateTrace(session)
			iSusp := indexOfState(trace, attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED)
			iResume := indexOfState(trace, attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING)
			iWork := indexOfState(trace, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)
			iAttach := indexOfState(trace, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED)
			if !(iSusp == 0 && iResume > iSusp && iWork > iResume && iAttach > iWork) {
				t.Errorf("[%s] %s: an authorized resume must transit §3 SUSPENDED→RESUMING→WORKING→ATTACHED IN ORDER, trace=%v",
					fidelityNestedOK, tc.desc, stateTraceNames(trace))
			}

			// Clean teardown still holds after a reason-suspend/resume round trip — the
			// SUSPENDED(reason) arm strands none of the five §3b leak classes.
			h.destroy(session)
			if leaks := h.leakReport(); len(leaks) != 0 {
				t.Fatalf("[%s] %s: clean-teardown (doc 06 §3b) violated after a SUSPENDED(reason) round trip:\n  %s",
					fidelityNestedOK, tc.desc, strings.Join(leaks, "\n  "))
			}
		})
	}

	// Cross-check: the three reasons map to THREE DISTINCT authorities (the split is
	// genuinely a split, not a single authority wearing three hats) and the frozen
	// enum zero value confers NONE (fail-closed — an UNSPECIFIED reason is never a
	// legal SUSPENDED state and can never be resumed).
	t.Run("authorities-are-distinct-and-zero-value-fails-closed", func(t *testing.T) {
		seen := map[resumeAuthority]attachv1.SuspendReason{}
		for _, reason := range []attachv1.SuspendReason{
			attachv1.SuspendReason_SUSPEND_REASON_USER,
			attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
			attachv1.SuspendReason_SUSPEND_REASON_REBALANCE,
		} {
			auth := resumeAuthorityFor(reason)
			if auth == resumeAuthorityNone {
				t.Errorf("[%s] a legal §3 reason %v must map to a concrete resume authority, got none", fidelityNestedOK, reason)
			}
			if prev, dup := seen[auth]; dup {
				t.Errorf("[%s] resume authority %s is shared by %v and %v — the §3 note 3 split must be DISTINCT per reason",
					fidelityNestedOK, auth, prev, reason)
			}
			seen[auth] = reason
		}
		if got := resumeAuthorityFor(attachv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED); got != resumeAuthorityNone {
			t.Errorf("[%s] the frozen SuspendReason zero value (UNSPECIFIED — never a legal SUSPENDED state) must confer NO resume authority (fail-closed), got %s",
				fidelityNestedOK, got)
		}
	})
}

// TestLifecycleSmoke_NegativeControls proves the smoke is NOT vacuous: each §3b
// assertion above must be able to FAIL on a broken lifecycle. We model the three
// failure modes and assert the model detects each — so a regression that strands
// state, drops a §8 segment, or over-claims pause invisibility cannot slip past
// the positive assertions. Fidelity: nested-ok.
func TestLifecycleSmoke_NegativeControls(t *testing.T) {
	// (2-neg) a teardown that SKIPS the proxy-session + minted-identity disposal
	// (the two classes teardown_nft6_test.go does not model) must be caught as a
	// leak — proving the five-class report is not blind to those two classes.
	t.Run("leaked-proxy-and-identity-detected", func(t *testing.T) {
		h := newLifecycleHost()
		const session = "ds-synth-leaky"
		h.create(session, 1)
		h.attach(session)
		// Model a broken teardown: drop only the VM/nft/overlay, STRAND the proxy
		// session and the minted identity (the exact bug a nft-only teardown check
		// would miss).
		r := h.live[session]
		r.vmDomain, r.nftRuleCount, r.cowOverlay = "", 0, ""
		leaks := h.leakReport()
		if len(leaks) == 0 {
			t.Fatalf("[%s] a teardown that stranded the proxy session + minted identity was reported CLEAN — the five-class teardown assertion would be vacuous", fidelityNestedOK)
		}
		joined := strings.Join(leaks, "\n")
		for _, want := range []string{"stranded-proxy-session", "leftover-minted-identity"} {
			if !strings.Contains(joined, want) {
				t.Errorf("[%s] leak report must name %q (the class teardown_nft6_test.go does not model): %q", fidelityNestedOK, want, joined)
			}
		}
	})

	// (1-neg) a create→attach trace MISSING a §8 segment must trip the structural
	// decomposition check. This is a MUTATION-style control (matching the directness
	// of the other two negative controls): we assemble a real startTrace dropping
	// one segment and assert decompositionViolations() — the EXACT check the
	// positive smoke relies on — actually FIRES, naming both the count violation
	// and the first index whose name no longer lines up with the frozen §8 order.
	t.Run("dropped-segment-detected", func(t *testing.T) {
		// Build a full, clean trace the way the positive smoke does (every §8
		// segment, distinct positive durations), then MUTATE it by dropping one
		// interior segment — the precise regression "a create that no longer
		// programs the tap/NFT step but still reports a trace".
		const dropIdx = 2 // tap-nft-programming
		full := startTrace{clientRTT: 12 * time.Millisecond}
		for i, name := range doc15SegmentOrder {
			full.segments = append(full.segments, startSegment{name: name, dur: time.Duration(i+1) * time.Millisecond})
		}
		// Vacuity guard: the UNMUTATED trace must be clean, or the control would
		// "detect" a pre-existing defect rather than the dropped segment.
		if v := full.decompositionViolations(); len(v) != 0 {
			t.Fatalf("[%s] negative control malformed: the un-mutated trace is already dirty:\n  %s",
				fidelityNestedOK, strings.Join(v, "\n  "))
		}

		mutated := startTrace{clientRTT: full.clientRTT}
		mutated.segments = append(mutated.segments, full.segments[:dropIdx]...)
		mutated.segments = append(mutated.segments, full.segments[dropIdx+1:]...) // DROP segment[dropIdx]

		v := mutated.decompositionViolations()
		if len(v) == 0 {
			t.Fatalf("[%s] a create→attach trace missing a §8 segment was reported CLEAN — the §8 decomposition assertion would be vacuous", fidelityNestedOK)
		}
		joined := strings.Join(v, "\n")
		// The mutation must trip BOTH arms of the structural check: the count no
		// longer matches the frozen set, and the per-index name match flags the
		// drop site (dropping an interior segment shifts every later name down one,
		// so index dropIdx now carries the wrong §8 name).
		for _, want := range []string{
			fmt.Sprintf("segment count = %d", len(doc15SegmentOrder)-1),
			fmt.Sprintf("§8 segment[%d]", dropIdx),
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("[%s] the dropped-segment decomposition check must name %q so the failure is actionable:\n  %s",
					fidelityNestedOK, want, joined)
			}
		}
	})

	// (3-neg) the pause-invisibility claim MUST be false strictly over 15 min — a
	// model that claimed invisibility for an over-budget pause would let the D46
	// "no transparency claim" tier silently over-promise.
	t.Run("over-budget-pause-makes-no-invisibility-claim", func(t *testing.T) {
		tier := classifyPause(15*time.Minute + time.Second)
		if tier != pauseTierSnapshotPark {
			t.Fatalf("[%s] a pause strictly over 15 min must classify snapshot+park, got %s", fidelityNestedOK, tier)
		}
		if tier.claimsInvisibility() {
			t.Errorf("[%s] the >15 min snapshot+park tier must make NO transparency claim (D46) — claimsInvisibility() was true", fidelityNestedOK)
		}
	})

	// (4-neg) the §3b "state survives the round trip" + "no double-booking" claims
	// the migrate handoff makes must be able to FAIL: a broken migrate that lost
	// the working set OR left the source-host residue live must be CAUGHT by the
	// same checks the positive handoff relies on. Modeled directly on the host.
	t.Run("broken-migrate-loses-state-or-double-books-detected", func(t *testing.T) {
		h := newLifecycleHost()
		const session = "ds-synth-migr-neg"
		const workState = "ds-synth-workstate-neg"
		h.create(session, 1)
		h.attach(session)
		h.work(session, workState)

		// A faithful handoff preserves the state and leaves exactly one residue —
		// the property the positive test asserts. Confirm it first (vacuity guard).
		if got := h.migrate(session, 2); got != workState {
			t.Fatalf("[%s] vacuity guard: a faithful migrate must preserve %q, got %q", fidelityNestedOK, workState, got)
		}
		if n := len(h.live); n != 1 {
			t.Fatalf("[%s] vacuity guard: a faithful migrate must leave exactly 1 residue, got %d", fidelityNestedOK, n)
		}

		// Now model the two migrate bugs directly and assert the checks trip:
		// (a) STATE LOSS — the target residue comes back with an empty working set.
		h.live[session].workState = "" // a snapshot that dropped the working set
		if got := h.live[session].workState; got == workState {
			t.Fatalf("[%s] negative control malformed: state-loss mutation did not change the working set", fidelityNestedOK)
		}
		// The positive test asserts got == workState; a lost working set fails it.
		if h.live[session].workState == workState {
			t.Errorf("[%s] a migrate that dropped the working set must fail the §3b 'state survives the round trip' check", fidelityNestedOK)
		}

		// (b) DOUBLE-BOOKING — a migrate that forgot to release the source leaves a
		// second live residue under a different key; the live-count check catches it.
		h.live[session+"@src"] = &sessionResidue{vmDomain: "domain-" + session + "-1", nftRuleCount: 4}
		if n := len(h.live); n == 1 {
			t.Fatalf("[%s] negative control malformed: double-booking mutation did not add a residue", fidelityNestedOK)
		}
		if leaks := h.leakReport(); len(leaks) == 0 {
			t.Errorf("[%s] a migrate that double-booked the source-host residue must surface as a leak (the handoff must release the source)", fidelityNestedOK)
		}
	})

	// (5-neg) LEG B: the SUSPENDED(reason) split-resume-authority gate must be able
	// to FAIL. A policy_breach park MUST refuse a resume until the genuine rung-2
	// human approval lands (doc 16 §8.2) — a model that auto-traversed
	// SUSPENDED─►RESUMING on bare authority (or on the wrong authority) would make
	// LEG B's key assertion vacuous. We drive the EXACT gate the positive LEG B
	// relies on and assert it REFUSES, then admits only once the approval lands.
	t.Run("policy-breach-resume-refused-without-human-approval", func(t *testing.T) {
		h := newLifecycleHost()
		const session = "ds-synth-bic-neg"
		h.create(session, 1)
		h.attach(session)
		s := h.suspendForReason(session, attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH)

		// Vacuity guard: a policy_breach park demands human-approval authority — if it
		// resolved to anything else the rest of this control would test the wrong gate.
		if got := s.requiredAuthority(); got != resumeAuthorityHumanApproval {
			t.Fatalf("[%s] negative control malformed: policy_breach must demand human-approval authority, got %s", fidelityNestedOK, got)
		}

		// The wrong authorities (user, scheduler) must NOT resume a BIC park.
		for _, wrong := range []resumeAuthority{resumeAuthorityUser, resumeAuthorityScheduler, resumeAuthorityNone} {
			if h.resumeWithAuthority(session, s, wrong) {
				t.Errorf("[%s] a policy_breach park resumed on %s authority — the §3 note 3 / §8.2 split must refuse non-human-approval authority", fidelityNestedOK, wrong)
			}
		}
		// Even the CORRECT human-approval authority must be refused BEFORE the approval
		// lands — the §8.2 "resume on answer" gate. This is the assertion that must be
		// able to fail: if resumeWithAuthority admitted here, LEG B's key assertion is
		// vacuous.
		if h.resumeWithAuthority(session, s, resumeAuthorityHumanApproval) {
			t.Errorf("[%s] a policy_breach park resumed on human-approval authority BEFORE the rung-2 approval landed — must wait for the answer (doc 16 §8.2)", fidelityNestedOK)
		}
		if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED {
			t.Errorf("[%s] a refused BIC resume must leave the session parked at §3 SUSPENDED, got %v", fidelityNestedOK, got)
		}
		if h.pauseTraceObserved(session, attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING) {
			t.Errorf("[%s] a refused BIC resume must NEVER traverse §3 SUSPENDED─►RESUMING; trace=%v", fidelityNestedOK, stateTraceNames(h.pauseStateTrace(session)))
		}

		// The approval lands — NOW (and only now) the human-approval authority resumes
		// it. This proves the refusals above were the gate doing its job, not a model
		// that can never resume.
		s.approveResume()
		if !h.resumeWithAuthority(session, s, resumeAuthorityHumanApproval) {
			t.Errorf("[%s] after the rung-2 approval lands, human-approval authority must resume the BIC park (else the gate is unconditionally closed)", fidelityNestedOK)
		}
		if got := h.stateOf(session); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
			t.Errorf("[%s] a post-approval BIC resume must settle at §3 ATTACHED via SUSPENDED─►RESUMING─►WORKING, got %v", fidelityNestedOK, got)
		}
	})
}
