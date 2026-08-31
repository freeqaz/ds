// SPDX-License-Identifier: Apache-2.0

package writerseat

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This file exercises the five browser-writer-seat (sessions/10 §5) rows as the
// canvas sibling does: per row, a CONFORMING control fixture must pass clean, and
// each NAMED violation class must be tripped by at least one synthetic fixture
// (D50). Four rows use in-code Go-literal fixtures; the reader-cannot-reach-
// WriterRelay row (claim 4, the D137 re-green) ALSO loads synthetic JSON from
// fixtures/ to exercise the loader + the .provenance sidecar discipline. A per-row
// coverage gate fails closed if a declared violation class is never exercised, so a
// new class cannot land un-asserted.

// ── shared helpers ───────────────────────────────────────────────────────────

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

// coverageGate asserts that the union of violation classes the row's fixtures
// produced equals the declared class set — a CONFORMING control was proven AND every
// declared class was exercised at least once, failing closed on either a missing
// control or an un-exercised class.
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

// assertRow asserts a single check result against an expected class set: a
// conforming control (want empty) must pass clean; a violation fixture must fail
// with exactly the NAMED class set.
func assertRow(t *testing.T, name string, got []Violation, want []ViolationClass) {
	t.Helper()
	if len(want) == 0 {
		if len(got) != 0 {
			t.Fatalf("CONFORMING fixture %s reported %d violation(s) — the green case must pass clean:\n%s",
				name, len(got), render(got))
		}
		return
	}
	if len(got) == 0 {
		t.Fatalf("VIOLATION fixture %s reported NO violations — the check must fail on %v (a silent pass "+
			"is the regression this row exists to catch)", name, want)
	}
	if !sameClasses(got, want) {
		t.Fatalf("VIOLATION fixture %s reported the WRONG violation class set —\n want: %v\n got: %v\n"+
			"full:\n%s", name, want, classesOf(got), render(got))
	}
}

// ── the documented-vocabulary guard (doc 06 §3c language note) ───────────────

// TestNoAttackVocabulary pins the doc 06 §3c language note for this package: no
// ViolationClass or guardrail Tag string may carry attack / redteam / intrusion
// framing. These are assurance tests for advertised properties, not a security-audit
// exercise; a row named for an attacker would violate the binding vocabulary note.
func TestNoAttackVocabulary(t *testing.T) {
	banned := []string{"attack", "redteam", "red-team", "intrusion", "exploit", "adversary", "hack"}
	all := []string{
		// claim 1
		string(ViolationTwoLiveSeats), string(ViolationLoserSilentlyDropped), string(ViolationNoSeatGranted),
		// claim 2
		string(ViolationRejectedDriveReachedStdin), string(ViolationRejectedDriveEmittedActivity),
		string(ViolationAdmittedDriveNoActivity),
		// claim 3
		string(ViolationHandoffNotObservable), string(ViolationHandoffNoGrantedSeq),
		string(ViolationHandoffNoAttribution),
		// claim 4
		string(ViolationReaderReachedWriterRelay), string(ViolationReaderInputReachedStdin),
		// claim 5
		string(ViolationDetachedSeatReadsAttended), string(ViolationSpectatorsFedAttendedness),
	}
	all = append(all, Tags...)
	for _, s := range all {
		low := strings.ToLower(s)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("string %q carries banned framing %q — doc 06 §3c forbids attack/redteam/intrusion "+
					"naming; name the row for the PROPERTY it asserts", s, b)
			}
		}
	}
}

// TestTagsStable pins the single-sourced guardrail tags to the doc.go REGISTRATION
// values, in order. The repo-root guardrail-map.yaml's writerseat glob row names
// these SAME tags; if a tag string drifts without re-reconciling the map row and the
// doc.go table, this fails HERE rather than letting the package and the map name
// different rows (the honest-map-row discipline: a map row names a real
// single-sourced tag value, never a placeholder).
func TestTagsStable(t *testing.T) {
	want := []string{
		"writerseat-exactly-one-live-seat",
		"writerseat-no-drive-without-live-grant",
		"writerseat-handoff-attributed-and-observable",
		"writerseat-reader-cannot-reach-writer-relay",
		"writerseat-attendedness-honest-when-detached",
	}
	if len(Tags) != len(want) {
		t.Fatalf("Tags has %d entries, want %d (the five sessions/10 §5 writer-seat rows; doc.go "+
			"REGISTRATION)", len(Tags), len(want))
	}
	for i := range want {
		if Tags[i] != want[i] {
			t.Errorf("Tags[%d] = %q, want %q (doc.go REGISTRATION / guardrail-map.yaml writerseat row)",
				i, Tags[i], want[i])
		}
	}
}

// ── CLAIM 1 — exactly one live writer seat (sessions/10 §5 claim 1; D61) ──────

func TestClaimExactlyOneWriterSeat(t *testing.T) {
	declared := []ViolationClass{ViolationTwoLiveSeats, ViolationLoserSilentlyDropped, ViolationNoSeatGranted}

	type tc struct {
		name string
		arb  SeatArbitration
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-one-grant-rest-refused",
			arb: SeatArbitration{Name: "conforming", Requests: []SeatRequestResult{
				{Driver: "user:alice", Outcome: OutcomeGranted},
				{Driver: "user:bob", Outcome: OutcomeRefused},
				{Driver: "user:carol", Outcome: OutcomeRefused},
			}},
			want: nil,
		},
		{
			name: "two-live-seats",
			arb: SeatArbitration{Name: "two-grants", Requests: []SeatRequestResult{
				{Driver: "user:alice", Outcome: OutcomeGranted},
				{Driver: "user:bob", Outcome: OutcomeGranted},
			}},
			want: []ViolationClass{ViolationTwoLiveSeats},
		},
		{
			name: "loser-silently-dropped",
			arb: SeatArbitration{Name: "silent-drop", Requests: []SeatRequestResult{
				{Driver: "user:alice", Outcome: OutcomeGranted},
				{Driver: "user:bob", Outcome: OutcomeDropped},
			}},
			want: []ViolationClass{ViolationLoserSilentlyDropped},
		},
		{
			name: "no-seat-granted-under-contention",
			arb: SeatArbitration{Name: "all-refused", Requests: []SeatRequestResult{
				{Driver: "user:alice", Outcome: OutcomeRefused},
				{Driver: "user:bob", Outcome: OutcomeRefused},
			}},
			want: []ViolationClass{ViolationNoSeatGranted},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { assertRow(t, c.name, CheckExactlyOneWriterSeat(c.arb), c.want) })
		got := CheckExactlyOneWriterSeat(c.arb)
		if len(c.want) == 0 {
			sawControl = sawControl || len(got) == 0
		}
		for _, v := range got {
			seen[v.Class] = true
		}
	}
	coverageGate(t, "writerseat-exactly-one-live-seat", declared, seen, sawControl)
}

// ── CLAIM 2 — no drive without a live grant (sessions/10 §5 claim 2) ──────────

func TestClaimNoDriveWithoutGrant(t *testing.T) {
	declared := []ViolationClass{
		ViolationRejectedDriveReachedStdin,
		ViolationRejectedDriveEmittedActivity,
		ViolationAdmittedDriveNoActivity,
	}

	type tc struct {
		name string
		set  DriveAttemptSet
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming",
			set: DriveAttemptSet{Name: "conforming", Attempts: []DriveAttempt{
				{Name: "live-grant-frame", Presentation: PresentationLiveGrant, ReachedStdin: true, InputActivityEmitted: true},
				{Name: "absent-seat-frame", Presentation: PresentationAbsent, ReachedStdin: false, InputActivityEmitted: false},
				{Name: "stale-seat-frame", Presentation: PresentationStale, ReachedStdin: false, InputActivityEmitted: false},
				{Name: "forged-seat-frame", Presentation: PresentationForged, ReachedStdin: false, InputActivityEmitted: false},
			}},
			want: nil,
		},
		{
			name: "rejected-reached-stdin",
			set: DriveAttemptSet{Name: "stdin-leak", Attempts: []DriveAttempt{
				{Name: "forged-seat-frame", Presentation: PresentationForged, ReachedStdin: true, InputActivityEmitted: false},
			}},
			want: []ViolationClass{ViolationRejectedDriveReachedStdin},
		},
		{
			name: "rejected-emitted-activity",
			set: DriveAttemptSet{Name: "activity-leak", Attempts: []DriveAttempt{
				{Name: "stale-seat-frame", Presentation: PresentationStale, ReachedStdin: false, InputActivityEmitted: true},
			}},
			want: []ViolationClass{ViolationRejectedDriveEmittedActivity},
		},
		{
			name: "admitted-no-activity",
			set: DriveAttemptSet{Name: "missing-activity", Attempts: []DriveAttempt{
				{Name: "live-grant-frame", Presentation: PresentationLiveGrant, ReachedStdin: true, InputActivityEmitted: false},
			}},
			want: []ViolationClass{ViolationAdmittedDriveNoActivity},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { assertRow(t, c.name, CheckNoDriveWithoutGrant(c.set), c.want) })
		got := CheckNoDriveWithoutGrant(c.set)
		if len(c.want) == 0 {
			sawControl = sawControl || len(got) == 0
		}
		for _, v := range got {
			seen[v.Class] = true
		}
	}
	coverageGate(t, "writerseat-no-drive-without-live-grant", declared, seen, sawControl)
}

// TestRejectedDriveReachingStdinAndEmittingActivityNamesBoth proves the row catches
// BOTH failure modes when one rejected drive frame both reaches stdin AND emits an
// InputActivity — the verdict must name the stdin leak AND the activity emission,
// never silently collapse to one.
func TestRejectedDriveReachingStdinAndEmittingActivityNamesBoth(t *testing.T) {
	set := DriveAttemptSet{Name: "double", Attempts: []DriveAttempt{
		{Name: "forged-seat-frame", Presentation: PresentationForged, ReachedStdin: true, InputActivityEmitted: true},
	}}
	got := CheckNoDriveWithoutGrant(set)
	if !sameClasses(got, []ViolationClass{
		ViolationRejectedDriveReachedStdin, ViolationRejectedDriveEmittedActivity,
	}) {
		t.Fatalf("a rejected drive that reaches stdin AND emits an InputActivity must report BOTH named "+
			"violations, got:\n%s", render(got))
	}
}

// ── CLAIM 3 — attributed + observable handoff (sessions/10 §5 claim 3) ────────

func TestClaimSeatChangeAttributedObservable(t *testing.T) {
	declared := []ViolationClass{
		ViolationHandoffNotObservable,
		ViolationHandoffNoGrantedSeq,
		ViolationHandoffNoAttribution,
	}

	type tc struct {
		name string
		set  SeatHandoffSet
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-grant-steal-yield",
			set: SeatHandoffSet{Name: "conforming", Handoffs: []SeatHandoff{
				{Name: "alice-grant", Kind: HandoffGrant, EventEmitted: true, ObservedSeq: 7, NewDriver: "user:alice"},
				{Name: "bob-steal", Kind: HandoffSteal, EventEmitted: true, ObservedSeq: 9, NewDriver: "user:bob", PrevDriver: "user:alice"},
				{Name: "bob-yield", Kind: HandoffYield, EventEmitted: true, ObservedSeq: 11, PrevDriver: "user:bob"},
			}},
			want: nil,
		},
		{
			name: "silent-handoff",
			set: SeatHandoffSet{Name: "silent", Handoffs: []SeatHandoff{
				{Name: "silent-steal", Kind: HandoffSteal, EventEmitted: false, NewDriver: "user:bob", PrevDriver: "user:alice"},
			}},
			want: []ViolationClass{ViolationHandoffNotObservable},
		},
		{
			name: "no-granted-seq",
			set: SeatHandoffSet{Name: "zero-seq", Handoffs: []SeatHandoff{
				{Name: "zero-seq-grant", Kind: HandoffGrant, EventEmitted: true, ObservedSeq: 0, NewDriver: "user:alice"},
			}},
			want: []ViolationClass{ViolationHandoffNoGrantedSeq},
		},
		{
			name: "missing-attribution",
			set: SeatHandoffSet{Name: "no-attrib", Handoffs: []SeatHandoff{
				{Name: "anon-grant", Kind: HandoffGrant, EventEmitted: true, ObservedSeq: 3, NewDriver: ""},
			}},
			want: []ViolationClass{ViolationHandoffNoAttribution},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { assertRow(t, c.name, CheckSeatChangeAttributedObservable(c.set), c.want) })
		got := CheckSeatChangeAttributedObservable(c.set)
		if len(c.want) == 0 {
			sawControl = sawControl || len(got) == 0
		}
		for _, v := range got {
			seen[v.Class] = true
		}
	}
	coverageGate(t, "writerseat-handoff-attributed-and-observable", declared, seen, sawControl)
}

// TestStealMissingBothAttributionsNamesAttribution proves a STEAL that names neither
// the new driver nor the prev driver still reports the attribution breach (the kind
// requires BOTH; either missing trips the named class).
func TestStealMissingBothAttributionsNamesAttribution(t *testing.T) {
	set := SeatHandoffSet{Name: "bare-steal", Handoffs: []SeatHandoff{
		{Name: "bare-steal", Kind: HandoffSteal, EventEmitted: true, ObservedSeq: 5, NewDriver: "", PrevDriver: ""},
	}}
	got := CheckSeatChangeAttributedObservable(set)
	if !sameClasses(got, []ViolationClass{ViolationHandoffNoAttribution}) {
		t.Fatalf("a STEAL missing both the new and prev driver must report the attribution breach, got:\n%s",
			render(got))
	}
}

// ── CLAIM 4 — reader cannot reach WriterRelay (sessions/10 §5 claim 4; D137) ──
//
// This is the D137 re-green of the 01KTWJ64M0 no-inject barrier, run against the v1
// read surfaces WITH the v2 write path present. It is the JSON-backed row (the
// loader + .provenance sidecar discipline), like the canvas spectator row.

func TestClaimReaderCannotReachWriterRelay(t *testing.T) {
	declared := []ViolationClass{ViolationReaderReachedWriterRelay, ViolationReaderInputReachedStdin}

	// Disposition map for the JSON fixtures backing this row. Every *.json on disk MUST
	// be registered here; the coverage gate fails closed on any unlisted one.
	corpusExpectation := map[string][]ViolationClass{
		"reader-00-conforming.json":           nil,
		"reader-01-reached-writer-relay.json": {ViolationReaderReachedWriterRelay},
		"reader-02-input-reached-stdin.json":  {ViolationReaderInputReachedStdin},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, name := range listFixtures(t) {
		want, ok := corpusExpectation[name]
		if !ok {
			t.Errorf("fixture %s has NO expectation row — every fixture must be wired into "+
				"corpusExpectation (fail-closed: a new picture cannot land un-asserted)", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			s, err := LoadJSON[ParticipantSet](filepath.Join(FixturesDir(), name))
			if err != nil {
				t.Fatalf("loading fixture %s: %v", name, err)
			}
			s.Name = name
			assertRow(t, name, CheckReaderCannotReachWriterRelay(s), want)
		})
		s, err := LoadJSON[ParticipantSet](filepath.Join(FixturesDir(), name))
		if err != nil {
			t.Fatalf("loading fixture %s: %v", name, err)
		}
		got := CheckReaderCannotReachWriterRelay(s)
		if len(want) == 0 {
			sawControl = sawControl || len(got) == 0
		}
		for _, v := range got {
			seen[v.Class] = true
		}
	}
	for name := range corpusExpectation {
		if _, err := os.Stat(filepath.Join(FixturesDir(), name)); err != nil {
			t.Errorf("corpusExpectation lists %s but no such fixture exists on disk", name)
		}
	}
	coverageGate(t, "writerseat-reader-cannot-reach-writer-relay", declared, seen, sawControl)
}

// TestGrantedWriterReachingDriveAndStdinIsConforming pins that the re-green does not
// over-claim: a ROLE_WRITER (granted seat) that reaches DriveSession and whose input
// reaches stdin is CONFORMING — only a no-grant ROLE_READER is barred from the write
// surfaces (sessions/10 §5 claim 4; the seat is exactly the legitimate write path).
func TestGrantedWriterReachingDriveAndStdinIsConforming(t *testing.T) {
	s := ParticipantSet{Name: "granted-writer", Participants: []Participant{
		{Name: "driver", Role: RoleWriter, ReachedWriterRelaySurfaces: []WriterRelaySurface{SurfaceDriveSession}, InputReachedStdin: true},
	}}
	if got := CheckReaderCannotReachWriterRelay(s); len(got) != 0 {
		t.Fatalf("a ROLE_WRITER holding a granted seat may reach DriveSession + stdin — only a no-grant "+
			"ROLE_READER is barred (sessions/10 §5 claim 4), got:\n%s", render(got))
	}
}

// ── CLAIM 5 — D78 honesty when detached (sessions/10 §5 claim 5; D78) ─────────

func TestClaimAttendednessHonest(t *testing.T) {
	declared := []ViolationClass{ViolationDetachedSeatReadsAttended, ViolationSpectatorsFedAttendedness}

	type tc struct {
		name string
		set  AttendednessSet
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming",
			set: AttendednessSet{Name: "conforming", Reports: []AttendednessReport{
				// detached seat + many spectators ⇒ unattended (the headline claim).
				{Name: "n-spectators-detached", SeatHeldWithRecentInput: false, Spectators: 9, Attended: false},
				// held seat with recent input ⇒ attended (the row does not over-claim).
				{Name: "held-with-input", SeatHeldWithRecentInput: true, Spectators: 3, Attended: true},
				// held seat, no spectators ⇒ attended.
				{Name: "held-no-spectators", SeatHeldWithRecentInput: true, Spectators: 0, Attended: true},
			}},
			want: nil,
		},
		{
			name: "detached-reads-attended-no-spectators",
			set: AttendednessSet{Name: "detached-attended", Reports: []AttendednessReport{
				{Name: "detached", SeatHeldWithRecentInput: false, Spectators: 0, Attended: true},
			}},
			want: []ViolationClass{ViolationDetachedSeatReadsAttended},
		},
		{
			name: "spectators-fed-attendedness",
			set: AttendednessSet{Name: "spectator-fed", Reports: []AttendednessReport{
				{Name: "n-spectators-no-seat", SeatHeldWithRecentInput: false, Spectators: 12, Attended: true},
			}},
			// spectator-present + detached-attended ⇒ BOTH classes name the breach.
			want: []ViolationClass{ViolationDetachedSeatReadsAttended, ViolationSpectatorsFedAttendedness},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { assertRow(t, c.name, CheckAttendednessHonest(c.set), c.want) })
		got := CheckAttendednessHonest(c.set)
		if len(c.want) == 0 {
			sawControl = sawControl || len(got) == 0
		}
		for _, v := range got {
			seen[v.Class] = true
		}
	}
	coverageGate(t, "writerseat-attendedness-honest-when-detached", declared, seen, sawControl)
}

// TestAttendedHeldSeatIsConforming pins that the row does not over-claim: a session
// whose seat is held-with-recent-input reading ATTENDED is CONFORMING regardless of
// spectator count — attendedness is honest, not suppressed (D78).
func TestAttendedHeldSeatIsConforming(t *testing.T) {
	s := AttendednessSet{Name: "held", Reports: []AttendednessReport{
		{Name: "held-many-spectators", SeatHeldWithRecentInput: true, Spectators: 50, Attended: true},
	}}
	if got := CheckAttendednessHonest(s); len(got) != 0 {
		t.Fatalf("a held seat with recent input reading attended is CONFORMING regardless of spectator "+
			"count (D78), got:\n%s", render(got))
	}
}

// ── runnability split (README.md "OSS-runnable vs paid-dependent") ───────────

// TestAllRowsOSSRunnable pins that, as modeled, every writerseat row is oss-runnable:
// each is a static synthetic data-shape diff with no live-orchestrator / web-client /
// paid-layer dependency (doc.go RUNNABILITY). CheckRunnable runs the check for an
// oss-runnable row.
func TestAllRowsOSSRunnable(t *testing.T) {
	ran := 0
	check := func() []Violation { ran++; return nil }
	for _, tag := range Tags {
		got, didRun := CheckRunnable(RunnabilityOSS, check)
		if !didRun {
			t.Errorf("row %q is oss-runnable but CheckRunnable reported it not-applicable", tag)
		}
		if len(got) != 0 {
			t.Errorf("row %q conforming control unexpectedly reported violations", tag)
		}
	}
	if ran != len(Tags) {
		t.Errorf("CheckRunnable ran the check %d time(s), want %d (one per oss-runnable row)", ran, len(Tags))
	}
}

// TestPaidDependentReportsNotApplicable exercises the doc 17 §13 split mechanism: a
// paid-dependent row on an OSS run is reported NOT-APPLICABLE (didRun=false), never
// FAILED, and its check is NOT executed. This proves a future web-client-dependent
// row can be split without a structural change.
func TestPaidDependentReportsNotApplicable(t *testing.T) {
	ran := false
	got, didRun := CheckRunnable(RunnabilityPaidDependent, func() []Violation {
		ran = true
		return []Violation{{Class: "would-have-failed", Subject: "x", Reason: "x"}}
	})
	if didRun {
		t.Error("a paid-dependent row on an OSS run must report not-applicable (didRun=false)")
	}
	if ran {
		t.Error("a paid-dependent row's check must NOT execute on an OSS run — it is not-applicable")
	}
	if len(got) != 0 {
		t.Errorf("a not-applicable row must report ZERO violations (never FAILED), got:\n%s", render(got))
	}
}

// ── D50 fixture provenance + listing ─────────────────────────────────────────

// TestEveryFixtureHasProvenance enforces the D50 sidecar contract: every *.json
// fixture on disk must carry a committed <name>.provenance sidecar beside it.
func TestEveryFixtureHasProvenance(t *testing.T) {
	for _, name := range listFixtures(t) {
		sidecar := filepath.Join(FixturesDir(), name+".provenance")
		if _, err := os.Stat(sidecar); err != nil {
			t.Errorf("fixture %s has no .provenance sidecar (%s) — every D50 synthetic fixture must carry "+
				"one", name, filepath.Base(sidecar))
		}
	}
}

// listFixtures returns the sorted *.json fixture filenames on disk (the .provenance
// sidecars are excluded). Anchored via FixturesDir (runtime.Caller).
func listFixtures(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(FixturesDir())
	if err != nil {
		t.Fatalf("reading fixtures dir %s: %v", FixturesDir(), err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".json") && !strings.HasSuffix(n, ".provenance") {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		t.Fatalf("the fixtures dir %s is empty — expected synthetic writerseat fixtures", FixturesDir())
	}
	sort.Strings(names)
	return names
}
