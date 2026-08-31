// SPDX-License-Identifier: Apache-2.0

package identityrows

import (
	"sort"
	"strings"
	"testing"
)

// This file exercises the ten doc 16 §13 identity (c) rows not implemented by a
// sibling, as the orchctl sibling does: per row, a CONFORMING control fixture must
// pass clean, and each NAMED violation class must be tripped by at least one
// synthetic fixture (D50). All fixtures are in-code Go literals — there is no
// fixtures/ dir, no file I/O, and no working-directory dependency; "synthetic
// only" is STRUCTURAL here. A per-row coverage gate fails closed if a declared
// violation class is never exercised, so a new class cannot land un-asserted.

// ── shared helpers ──────────────────────────────────────────────────────────

// classesOf collects the sorted, deduped violation classes a check reported.
func classesOf(vs []Violation) []ViolationClass {
	set := map[ViolationClass]bool{}
	for _, v := range vs {
		set[v.Class] = true
	}
	out := make([]ViolationClass, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sameClasses reports whether got's class set equals want exactly.
func sameClasses(got []Violation, want []ViolationClass) bool {
	g := classesOf(got)
	w := append([]ViolationClass(nil), want...)
	sort.Slice(w, func(i, j int) bool { return w[i] < w[j] })
	if len(g) != len(w) {
		return false
	}
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

// render formats a violation slice for failure messages.
func render(vs []Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("  ")
		b.WriteString(v.String())
		b.WriteString("\n")
	}
	return b.String()
}

// assertClasses is the shared per-case assertion: a CONFORMING fixture (want
// empty) must report NO violations, and a violation fixture must FAIL with its
// NAMED class set exactly — a silent pass is the regression each row exists to
// catch.
func assertClasses(t *testing.T, name string, got []Violation, want []ViolationClass) {
	t.Helper()
	if len(want) == 0 {
		if len(got) != 0 {
			t.Fatalf("CONFORMING fixture %q reported %d violation(s) — the guardrail holds, so this "+
				"must pass clean:\n%s", name, len(got), render(got))
		}
		return
	}
	if len(got) == 0 {
		t.Fatalf("VIOLATION fixture %q reported NO violations — the check must fail on %v (a silent "+
			"pass is the regression this row exists to catch)", name, want)
	}
	if !sameClasses(got, want) {
		t.Fatalf("VIOLATION fixture %q reported the WRONG violation class set —\n want: %v\n got: %v"+
			"\nfull:\n%s", name, want, classesOf(got), render(got))
	}
}

// coverageGate asserts that a CONFORMING control was proven (the green case) AND
// every declared violation class was exercised at least once, failing closed on
// either a missing control or an un-exercised class.
func coverageGate(t *testing.T, row string, declared []ViolationClass, seen map[ViolationClass]bool, sawControl bool) {
	t.Helper()
	if !sawControl {
		t.Errorf("%s: no CONFORMING control fixture passed clean — the green case must be proven", row)
	}
	for _, c := range declared {
		if !seen[c] {
			t.Errorf("%s: violation class %q is never exercised by a fixture — every declared failure "+
				"mode must have a named fixture (fail-closed coverage gate)", row, c)
		}
	}
}

// ── the documented-vocabulary guard (doc 06 §3c language note) ──────────────

// allViolationClasses is the full taxonomy across the ten rows. It is the single
// list the vocabulary guard and a "no orphan class" sanity check share.
var allViolationClasses = []ViolationClass{
	// ROW 1
	ViolationRoutableBeforeDigestsMatchable, ViolationDigestWriteFailureDegradedOpen,
	// ROW 2
	ViolationCrossSessionCAValidated, ViolationCrossHierarchyValidated,
	ViolationSameSessionSameHierarchyRejected,
	// ROW 3
	ViolationInjectedCredFlagged, ViolationIntendedNotSwapped, ViolationWrongDestinationNotBlocked,
	// ROW 4
	ViolationRevocationOutsidePOL4Bar, ViolationRevocationEnforcedWithoutSweep,
	ViolationDigestChangeRequiredProxyRestart,
	// ROW 5
	ViolationDenyWithoutMachineReason, ViolationStaleCertValidated,
	ViolationKillMidFlightDigestsNotFlushed,
	// ROW 6
	ViolationApprovedInWindowNotProceeded, ViolationTimeoutNotClosed,
	ViolationDetachTornDownEarly, ViolationNewAskPostDetachNotBlocked,
	// ROW 7
	ViolationAttendedDidNotHold, ViolationUnattendedDidNotBlock, ViolationSpectateFlippedAttended,
	// ROW 8
	ViolationRemoteNotHTTPS, ViolationSSHDidNotFailClosed,
	// ROW 9
	ViolationLog5JoinUnanswerable, ViolationCredentialPlaintextInEvent, ViolationFingerprintMissing,
	// ROW 10
	ViolationParkGrantsDigestsLost, ViolationParkLivenessNotRechecked,
	ViolationParkExpiredCredNotReminted,
}

// TestNoAttackVocabulary pins the doc 06 §3c language note for this package: no
// ViolationClass string may carry attack / redteam / intrusion framing. These are
// assurance tests for advertised properties, not a security-audit exercise; a row
// named for an attacker would violate the binding vocabulary note.
func TestNoAttackVocabulary(t *testing.T) {
	banned := []string{"attack", "redteam", "red-team", "intrusion", "exploit", "adversary", "malicious"}
	for _, c := range allViolationClasses {
		low := strings.ToLower(string(c))
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("violation class %q carries banned %q framing — doc 06 §3c forbids "+
					"attack/redteam/intrusion naming; name the row for the property it proves", c, b)
			}
		}
	}
}

// ── the anchor guards (the orchctl DefaultCanaryWindowDays discipline) ──────

// TestPOL4BarMatchesDocumentedCeiling pins DefaultPOL4BarSeconds to the documented
// seconds-scale POL-4 ceiling (doc 16 §8.2 "10 s is the outer ceiling"; §6.2 the
// fleet-revocation clock inherits the POL-4 bar). A silent drift fails HERE rather
// than letting the row judge against a looser bar than the doc promises.
func TestPOL4BarMatchesDocumentedCeiling(t *testing.T) {
	const documentedOuterCeilingSeconds = 10
	if DefaultPOL4BarSeconds != documentedOuterCeilingSeconds {
		t.Fatalf("DefaultPOL4BarSeconds = %d, want %d (doc 16 §8.2 outer ceiling / §6.2 POL-4 bar); "+
			"a bar change must be reconciled with the documented number (D72)",
			DefaultPOL4BarSeconds, documentedOuterCeilingSeconds)
	}
}

// TestParkTiersMatchDocumentedLadder pins DefaultParkTierSeconds to the documented
// D46 park ladder — 60 s / 5 min / 15 min (doc 16 §13 park/resume row). A drift
// fails HERE rather than judging against tiers the doc does not promise.
func TestParkTiersMatchDocumentedLadder(t *testing.T) {
	want := []int{60, 300, 900}
	if len(DefaultParkTierSeconds) != len(want) {
		t.Fatalf("DefaultParkTierSeconds has %d tiers, want %d (doc 16 §13: 60 s / 5 min / 15 min, D46)",
			len(DefaultParkTierSeconds), len(want))
	}
	for i := range want {
		if DefaultParkTierSeconds[i] != want[i] {
			t.Errorf("DefaultParkTierSeconds[%d] = %d, want %d (doc 16 §13 D46 park ladder)",
				i, DefaultParkTierSeconds[i], want[i])
		}
	}
}

// ── the tag guard (the orchctl Tags discipline) ─────────────────────────────

// TestTagsStable pins the single-sourced guardrail tags to the doc.go REGISTRATION
// values, in order. The repo-root guardrail-map.yaml's identityrows glob row names
// these SAME tags; if a tag string drifts without re-reconciling the map row and the
// doc.go table, this fails HERE rather than letting the package and the map name
// different rows (the honest-map-row discipline: a map row names a real
// single-sourced tag value, never a placeholder).
func TestTagsStable(t *testing.T) {
	want := []string{
		"identity-mint-before-attach",
		"identity-per-session-ca-isolation",
		"identity-issued-cred-routing-asymmetry",
		"identity-fleet-revocation-clock",
		"identity-validation-failure-structured-403",
		"identity-socket-hold-paths",
		"identity-attendedness-flip",
		"identity-git-https-pin",
		"identity-log5-join",
		"identity-park-resume-tiers",
	}
	if len(Tags) != len(want) {
		t.Fatalf("Tags has %d entries, want %d (the ten doc 16 §13 identity (c) rows not in "+
			"credswap/secretegress/appinstall; doc.go REGISTRATION)", len(Tags), len(want))
	}
	for i := range want {
		if Tags[i] != want[i] {
			t.Errorf("Tags[%d] = %q, want %q (doc.go REGISTRATION / guardrail-map.yaml identityrows row)",
				i, Tags[i], want[i])
		}
	}
}

// TestExcludedRowsNotReImplemented documents that the three §13 rows owned by
// sibling packages (cred-never-in-VM/host → credswap, canary-never-egresses →
// secretegress, App-install read-level → appinstall) carry tag PREFIXES that this
// package's tags never collide with — so the same row is never asserted twice. It
// is a string-level guard: no identityrows tag may reuse a sibling's tag value.
func TestExcludedRowsNotReImplemented(t *testing.T) {
	siblingTags := []string{
		"cred-swap-never-leaks",         // credswap (cred-never-in-VM/host)
		"secret-egress-canary-blocked",  // secretegress (canary-never-egresses)
		"app-install-read-level-subset", // appinstall (App-install read-level)
	}
	for _, tag := range Tags {
		for _, sib := range siblingTags {
			if tag == sib {
				t.Errorf("identityrows tag %q collides with a sibling-owned row tag — the three "+
					"excluded §13 rows (credswap/secretegress/appinstall) must not be re-implemented here",
					tag)
			}
		}
	}
}

// ── ROW 1 — mint-before-attach + fail-closed digest-write ───────────────────

func TestRowMintBeforeAttach(t *testing.T) {
	declared := []ViolationClass{
		ViolationRoutableBeforeDigestsMatchable, ViolationDigestWriteFailureDegradedOpen,
	}
	type tc struct {
		name string
		seq  MintSequence
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-routable-after-digests-acked",
			seq:  MintSequence{Session: "s1", DigestsWritten: true, DigestAck: true, MarkedRoutable: true},
			want: nil,
		},
		{
			name: "conforming-not-yet-routable-while-digests-pending",
			seq:  MintSequence{Session: "s2", DigestsWritten: true, DigestAck: false, MarkedRoutable: false},
			want: nil,
		},
		{
			name: "violation-routable-before-ack",
			seq:  MintSequence{Session: "s3", DigestsWritten: true, DigestAck: false, MarkedRoutable: true},
			want: []ViolationClass{ViolationRoutableBeforeDigestsMatchable},
		},
		{
			name: "violation-digest-write-failure-degraded-open",
			seq:  MintSequence{Session: "s4", DigestsWritten: false, DigestAck: false, MarkedRoutable: true},
			want: []ViolationClass{ViolationDigestWriteFailureDegradedOpen},
		},
	}
	runRow(t, "mint-before-attach", declared, cases, func(c tc) []Violation {
		return CheckMintBeforeAttach(c.seq)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// ── ROW 2 — per-session CA isolation + D82 hierarchy separation ─────────────

func TestRowPerSessionCAIsolation(t *testing.T) {
	declared := []ViolationClass{
		ViolationCrossSessionCAValidated, ViolationCrossHierarchyValidated,
		ViolationSameSessionSameHierarchyRejected,
	}
	type tc struct {
		name string
		val  CAValidation
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-same-session-same-hierarchy-validates",
			val: CAValidation{
				Subject: "leaf-A", IssuedForSession: "A", IssuedUnderHierarchy: HierarchyInterception,
				ValidatedAgainstSession: "A", PresentedAsHierarchy: HierarchyInterception, Validated: true,
			},
			want: nil,
		},
		{
			name: "conforming-cross-session-rejected",
			val: CAValidation{
				Subject: "leaf-A-vs-B", IssuedForSession: "A", IssuedUnderHierarchy: HierarchyInterception,
				ValidatedAgainstSession: "B", PresentedAsHierarchy: HierarchyInterception, Validated: false,
			},
			want: nil,
		},
		{
			name: "conforming-cross-hierarchy-rejected",
			val: CAValidation{
				Subject: "interception-as-workload", IssuedForSession: "A", IssuedUnderHierarchy: HierarchyInterception,
				ValidatedAgainstSession: "A", PresentedAsHierarchy: HierarchyWorkload, Validated: false,
			},
			want: nil,
		},
		{
			name: "violation-cross-session-validated",
			val: CAValidation{
				Subject: "leaf-A-vs-B", IssuedForSession: "A", IssuedUnderHierarchy: HierarchyInterception,
				ValidatedAgainstSession: "B", PresentedAsHierarchy: HierarchyInterception, Validated: true,
			},
			want: []ViolationClass{ViolationCrossSessionCAValidated},
		},
		{
			name: "violation-cross-hierarchy-validated",
			val: CAValidation{
				Subject: "interception-as-workload", IssuedForSession: "A", IssuedUnderHierarchy: HierarchyInterception,
				ValidatedAgainstSession: "A", PresentedAsHierarchy: HierarchyWorkload, Validated: true,
			},
			want: []ViolationClass{ViolationCrossHierarchyValidated},
		},
		{
			name: "violation-legitimate-presentation-rejected",
			val: CAValidation{
				Subject: "leaf-A", IssuedForSession: "A", IssuedUnderHierarchy: HierarchyWorkload,
				ValidatedAgainstSession: "A", PresentedAsHierarchy: HierarchyWorkload, Validated: false,
			},
			want: []ViolationClass{ViolationSameSessionSameHierarchyRejected},
		},
	}
	runRow(t, "per-session-ca-isolation", declared, cases, func(c tc) []Violation {
		return CheckPerSessionCAIsolation(c.val)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// ── ROW 3 — issued-cred routing asymmetry / double-fire ─────────────────────

func TestRowIssuedCredRoutingAsymmetry(t *testing.T) {
	declared := []ViolationClass{
		ViolationInjectedCredFlagged, ViolationIntendedNotSwapped, ViolationWrongDestinationNotBlocked,
	}
	type tc struct {
		name string
		eg   IssuedEgress
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-intended-swapped-not-flagged",
			eg:   IssuedEgress{Subject: "e1", IntendedDestination: true, Disposition: DispSwappedNotFlagged},
			want: nil,
		},
		{
			name: "conforming-wrong-destination-block-logged",
			eg:   IssuedEgress{Subject: "e2", IntendedDestination: false, Disposition: DispBlockLogged},
			want: nil,
		},
		{
			name: "violation-intended-self-flagged",
			eg:   IssuedEgress{Subject: "e3", IntendedDestination: true, Disposition: DispSwappedThenFlagged},
			want: []ViolationClass{ViolationInjectedCredFlagged},
		},
		{
			name: "violation-intended-not-swapped",
			eg:   IssuedEgress{Subject: "e4", IntendedDestination: true, Disposition: DispPlaceholderUnswapped},
			want: []ViolationClass{ViolationIntendedNotSwapped},
		},
		{
			name: "violation-wrong-destination-leaked",
			eg:   IssuedEgress{Subject: "e5", IntendedDestination: false, Disposition: DispLeakedThrough},
			want: []ViolationClass{ViolationWrongDestinationNotBlocked},
		},
	}
	runRow(t, "issued-cred-routing-asymmetry", declared, cases, func(c tc) []Violation {
		return CheckIssuedCredRoutingAsymmetry(c.eg)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// ── ROW 4 — fleet revocation clock ──────────────────────────────────────────

func TestRowFleetRevocationClock(t *testing.T) {
	declared := []ViolationClass{
		ViolationRevocationOutsidePOL4Bar, ViolationRevocationEnforcedWithoutSweep,
		ViolationDigestChangeRequiredProxyRestart,
	}
	type tc struct {
		name string
		rev  DigestRevocation
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-enforced-in-bar-with-sweep-no-restart",
			rev: DigestRevocation{
				Subject: "fdig1", PropagationSeconds: 4, BarSeconds: DefaultPOL4BarSeconds,
				SweepCompleted: true, Enforced: true, RequiredProxyRestart: false,
			},
			want: nil,
		},
		{
			name: "violation-outside-pol4-bar",
			rev: DigestRevocation{
				Subject: "fdig2", PropagationSeconds: 45, BarSeconds: DefaultPOL4BarSeconds,
				SweepCompleted: true, Enforced: true, RequiredProxyRestart: false,
			},
			want: []ViolationClass{ViolationRevocationOutsidePOL4Bar},
		},
		{
			name: "violation-enforced-without-sweep",
			rev: DigestRevocation{
				Subject: "fdig3", PropagationSeconds: 3, BarSeconds: DefaultPOL4BarSeconds,
				SweepCompleted: false, Enforced: true, RequiredProxyRestart: false,
			},
			want: []ViolationClass{ViolationRevocationEnforcedWithoutSweep},
		},
		{
			name: "violation-required-proxy-restart",
			rev: DigestRevocation{
				Subject: "fdig4", PropagationSeconds: 4, BarSeconds: DefaultPOL4BarSeconds,
				SweepCompleted: true, Enforced: true, RequiredProxyRestart: true,
			},
			want: []ViolationClass{ViolationDigestChangeRequiredProxyRestart},
		},
	}
	runRow(t, "fleet-revocation-clock", declared, cases, func(c tc) []Violation {
		return CheckFleetRevocationClock(c.rev)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// ── ROW 5 — validation failure → structured 403 + stale-cert ────────────────

func TestRowValidationFailure403(t *testing.T) {
	declared := []ViolationClass{
		ViolationDenyWithoutMachineReason, ViolationStaleCertValidated,
		ViolationKillMidFlightDigestsNotFlushed,
	}
	type tc struct {
		name string
		out  ValidationOutcome
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-deny-with-machine-reason",
			out: ValidationOutcome{
				Subject: "v1", Liveness: LivenessLive, SignatureFresh: true,
				Verdict: VerdictDeny, MachineReason: "out-of-grant:github",
			},
			want: nil,
		},
		{
			name: "conforming-live-session-allowed",
			out: ValidationOutcome{
				Subject: "v2", Liveness: LivenessLive, SignatureFresh: true, Verdict: VerdictAllow,
			},
			want: nil,
		},
		{
			name: "conforming-revoked-session-denied-on-liveness",
			out: ValidationOutcome{
				Subject: "v3", Liveness: LivenessRevoked, SignatureFresh: true,
				Verdict: VerdictDeny, MachineReason: "session-not-live",
			},
			want: nil,
		},
		{
			name: "conforming-kill-mid-flight-flushes-digests",
			out: ValidationOutcome{
				Subject: "v4", Liveness: LivenessKilled, SignatureFresh: true,
				Verdict: VerdictDeny, MachineReason: "session-killed",
				KillMidFlight: true, DigestsFlushed: true,
			},
			want: nil,
		},
		{
			name: "violation-deny-without-machine-reason",
			out: ValidationOutcome{
				Subject: "v5", Liveness: LivenessLive, SignatureFresh: true,
				Verdict: VerdictDeny, MachineReason: "",
			},
			want: []ViolationClass{ViolationDenyWithoutMachineReason},
		},
		{
			name: "violation-stale-cert-validated",
			out: ValidationOutcome{
				Subject: "v6", Liveness: LivenessSuspended, SignatureFresh: true, Verdict: VerdictAllow,
			},
			want: []ViolationClass{ViolationStaleCertValidated},
		},
		{
			name: "violation-kill-mid-flight-digests-not-flushed",
			out: ValidationOutcome{
				Subject: "v7", Liveness: LivenessKilled, SignatureFresh: true,
				Verdict: VerdictDeny, MachineReason: "session-killed",
				KillMidFlight: true, DigestsFlushed: false,
			},
			want: []ViolationClass{ViolationKillMidFlightDigestsNotFlushed},
		},
	}
	runRow(t, "validation-failure-403", declared, cases, func(c tc) []Violation {
		return CheckValidationFailure403(c.out)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// ── ROW 6 — socket-hold paths + ask-grant atomicity ─────────────────────────

func TestRowSocketHoldPaths(t *testing.T) {
	declared := []ViolationClass{
		ViolationApprovedInWindowNotProceeded, ViolationTimeoutNotClosed,
		ViolationDetachTornDownEarly, ViolationNewAskPostDetachNotBlocked,
	}
	type tc struct {
		name string
		hold SocketHold
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-approved-in-window-proceeds",
			hold: SocketHold{Subject: "h1", Phase: PhaseApprovedInWindow, Outcome: HoldProceeded},
			want: nil,
		},
		{
			name: "conforming-approved-in-window-retry-succeeds",
			hold: SocketHold{Subject: "h2", Phase: PhaseApprovedInWindow, Outcome: HoldRetrySucceeded},
			want: nil,
		},
		{
			name: "conforming-timeout-closes",
			hold: SocketHold{Subject: "h3", Phase: PhaseTimeout, Outcome: HoldClosed},
			want: nil,
		},
		{
			name: "conforming-detach-in-flight-runs-to-timeout",
			hold: SocketHold{Subject: "h4", Phase: PhaseDetachInFlight, Outcome: HoldRanToTimeout},
			want: nil,
		},
		{
			name: "conforming-new-ask-post-detach-blocks",
			hold: SocketHold{Subject: "h5", Phase: PhaseNewAskPostDetach, Outcome: HoldBlockedImmediately},
			want: nil,
		},
		{
			name: "violation-approved-in-window-did-not-proceed",
			hold: SocketHold{Subject: "h6", Phase: PhaseApprovedInWindow, Outcome: HoldClosed},
			want: []ViolationClass{ViolationApprovedInWindowNotProceeded},
		},
		{
			name: "violation-timeout-into-allow",
			hold: SocketHold{Subject: "h7", Phase: PhaseTimeout, Outcome: HoldTimedOutIntoAllow},
			want: []ViolationClass{ViolationTimeoutNotClosed},
		},
		{
			name: "violation-detach-torn-down-early",
			hold: SocketHold{Subject: "h8", Phase: PhaseDetachInFlight, Outcome: HoldTornDownEarly},
			want: []ViolationClass{ViolationDetachTornDownEarly},
		},
		{
			name: "violation-new-ask-post-detach-held",
			hold: SocketHold{Subject: "h9", Phase: PhaseNewAskPostDetach, Outcome: HoldProceeded},
			want: []ViolationClass{ViolationNewAskPostDetachNotBlocked},
		},
	}
	runRow(t, "socket-hold-paths", declared, cases, func(c tc) []Violation {
		return CheckSocketHoldPaths(c.hold)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// ── ROW 7 — attendedness flip ───────────────────────────────────────────────

func TestRowAttendednessFlip(t *testing.T) {
	declared := []ViolationClass{
		ViolationAttendedDidNotHold, ViolationUnattendedDidNotBlock, ViolationSpectateFlippedAttended,
	}
	type tc struct {
		name string
		att  Attendedness
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-attended-holds",
			att: Attendedness{
				Subject: "a1", WriterAttendedFresh: true, AttendedBit: true, Disposition: AskHeld,
			},
			want: nil,
		},
		{
			name: "conforming-unattended-blocks",
			att: Attendedness{
				Subject: "a2", WriterAttendedFresh: false, AttendedBit: false, Disposition: AskBlockLog,
			},
			want: nil,
		},
		{
			name: "conforming-spectate-does-not-flip-bit",
			att: Attendedness{
				Subject: "a3", WriterAttendedFresh: false, SpectateAttached: true,
				AttendedBit: false, Disposition: AskBlockLog,
			},
			want: nil,
		},
		{
			name: "violation-attended-did-not-hold",
			att: Attendedness{
				Subject: "a4", WriterAttendedFresh: true, AttendedBit: true, Disposition: AskBlockLog,
			},
			want: []ViolationClass{ViolationAttendedDidNotHold},
		},
		{
			name: "violation-unattended-did-not-block",
			att: Attendedness{
				Subject: "a5", WriterAttendedFresh: false, AttendedBit: false, Disposition: AskHeld,
			},
			want: []ViolationClass{ViolationUnattendedDidNotBlock},
		},
		{
			name: "violation-spectate-flipped-attended",
			att: Attendedness{
				Subject: "a6", WriterAttendedFresh: false, SpectateAttached: true,
				AttendedBit: true, Disposition: AskHeld,
			},
			// A spectate-only attach wrongly flipped the bit to attended, so the ask
			// socket-held; the NAMED root cause is the flip — the hold is its
			// (bit-consistent) downstream effect, so only the flip violation fires.
			want: []ViolationClass{ViolationSpectateFlippedAttended},
		},
	}
	runRow(t, "attendedness-flip", declared, cases, func(c tc) []Violation {
		return CheckAttendednessFlip(c.att)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// ── ROW 8 — git-HTTPS pin ───────────────────────────────────────────────────

func TestRowGitHTTPSPin(t *testing.T) {
	declared := []ViolationClass{
		ViolationRemoteNotHTTPS, ViolationSSHDidNotFailClosed,
	}
	type tc struct {
		name   string
		remote GitRemote
		want   []ViolationClass
	}
	cases := []tc{
		{
			name:   "conforming-remote-resolves-https",
			remote: GitRemote{Subject: "g1", ResolvedScheme: "https"},
			want:   nil,
		},
		{
			name:   "conforming-ssh-attempt-fails-closed",
			remote: GitRemote{Subject: "g2", ResolvedScheme: "https", SSHAttempted: true, SSHFailedClosed: true},
			want:   nil,
		},
		{
			name:   "violation-remote-resolves-ssh",
			remote: GitRemote{Subject: "g3", ResolvedScheme: "ssh"},
			want:   []ViolationClass{ViolationRemoteNotHTTPS},
		},
		{
			name:   "violation-ssh-did-not-fail-closed",
			remote: GitRemote{Subject: "g4", ResolvedScheme: "https", SSHAttempted: true, SSHFailedClosed: false},
			want:   []ViolationClass{ViolationSSHDidNotFailClosed},
		},
	}
	runRow(t, "git-https-pin", declared, cases, func(c tc) []Violation {
		return CheckGitHTTPSPin(c.remote)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// ── ROW 9 — LOG-5 join + fingerprint-only ───────────────────────────────────

func TestRowLog5Join(t *testing.T) {
	declared := []ViolationClass{
		ViolationLog5JoinUnanswerable, ViolationCredentialPlaintextInEvent, ViolationFingerprintMissing,
	}
	type tc struct {
		name string
		ev   IdentityEvent
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-credential-use-event-fingerprint-only",
			ev: IdentityEvent{
				Subject: "ev1", SessionRef: "sess-1", Service: "github", Request: "git-push refs/heads/main",
				TimestampUnix: 1_700_000_000, CredentialFingerprint: "fp:sha256:abcd", AttributesCredentialUse: true,
			},
			want: nil,
		},
		{
			name: "conforming-non-credential-event-needs-no-fingerprint",
			ev: IdentityEvent{
				Subject: "ev2", SessionRef: "sess-1", Service: "github", Request: "ca-minted",
				TimestampUnix: 1_700_000_001, AttributesCredentialUse: false,
			},
			want: nil,
		},
		{
			name: "violation-join-unanswerable-missing-session",
			ev: IdentityEvent{
				Subject: "ev3", SessionRef: "", Service: "github", Request: "git-push",
				TimestampUnix: 1_700_000_002, CredentialFingerprint: "fp:sha256:abcd", AttributesCredentialUse: true,
			},
			want: []ViolationClass{ViolationLog5JoinUnanswerable},
		},
		{
			name: "violation-credential-plaintext-in-event",
			ev: IdentityEvent{
				Subject: "ev4", SessionRef: "sess-1", Service: "github", Request: "git-push",
				TimestampUnix: 1_700_000_003, CredentialFingerprint: "fp:sha256:abcd",
				CredentialPlaintext: "ghp_synthetic_placeholder", AttributesCredentialUse: true,
			},
			want: []ViolationClass{ViolationCredentialPlaintextInEvent},
		},
		{
			name: "violation-fingerprint-missing",
			ev: IdentityEvent{
				Subject: "ev5", SessionRef: "sess-1", Service: "github", Request: "git-push",
				TimestampUnix: 1_700_000_004, CredentialFingerprint: "", AttributesCredentialUse: true,
			},
			want: []ViolationClass{ViolationFingerprintMissing},
		},
	}
	runRow(t, "log5-join", declared, cases, func(c tc) []Violation {
		return CheckLog5Join(c.ev)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// ── ROW 10 — park/resume at the D46 tiers ───────────────────────────────────

func TestRowParkResumeTiers(t *testing.T) {
	declared := []ViolationClass{
		ViolationParkGrantsDigestsLost, ViolationParkLivenessNotRechecked,
		ViolationParkExpiredCredNotReminted,
	}
	type tc struct {
		name string
		park ParkResume
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-60s-survives-rechecks-live",
			park: ParkResume{
				Subject: "p1", TierSeconds: 60, GrantsDigestsSurvived: true, Resume: ResumeLive,
			},
			want: nil,
		},
		{
			name: "conforming-5min-expired-cred-reminted",
			park: ParkResume{
				Subject: "p2", TierSeconds: 300, GrantsDigestsSurvived: true, Resume: ResumeLive,
				CredExpiredDuringPark: true, ExpiredCredReminted: true,
			},
			want: nil,
		},
		{
			name: "conforming-15min-revoked-while-parked-detected",
			park: ParkResume{
				Subject: "p3", TierSeconds: 900, GrantsDigestsSurvived: true, Resume: ResumeRevoked,
			},
			want: nil,
		},
		{
			name: "violation-grants-digests-lost",
			park: ParkResume{
				Subject: "p4", TierSeconds: 60, GrantsDigestsSurvived: false, Resume: ResumeLive,
			},
			want: []ViolationClass{ViolationParkGrantsDigestsLost},
		},
		{
			name: "violation-liveness-not-rechecked",
			park: ParkResume{
				Subject: "p5", TierSeconds: 300, GrantsDigestsSurvived: true, Resume: ResumeNotChecked,
			},
			want: []ViolationClass{ViolationParkLivenessNotRechecked},
		},
		{
			name: "violation-expired-cred-not-reminted",
			park: ParkResume{
				Subject: "p6", TierSeconds: 900, GrantsDigestsSurvived: true, Resume: ResumeLive,
				CredExpiredDuringPark: true, ExpiredCredReminted: false,
			},
			want: []ViolationClass{ViolationParkExpiredCredNotReminted},
		},
	}
	runRow(t, "park-resume-tiers", declared, cases, func(c tc) []Violation {
		return CheckParkResumeTiers(c.park)
	}, func(c tc) (string, []ViolationClass) { return c.name, c.want })
}

// runRow is the shared per-row driver: it runs each case's check, asserts the
// NAMED class set, and applies the fail-closed coverage gate (a CONFORMING control
// proven + every declared class exercised). The two extractor funcs keep it generic
// over each row's case-struct type without reflection.
func runRow[C any](
	t *testing.T,
	row string,
	declared []ViolationClass,
	cases []C,
	check func(C) []Violation,
	meta func(C) (string, []ViolationClass),
) {
	t.Helper()
	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		name, want := meta(c)
		t.Run(name, func(t *testing.T) {
			assertClasses(t, name, check(c), want)
		})
		if len(want) == 0 {
			sawControl = true
		}
		for _, v := range want {
			seen[v] = true
		}
	}
	coverageGate(t, row, declared, seen, sawControl)
}
