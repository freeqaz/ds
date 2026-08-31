// SPDX-License-Identifier: Apache-2.0

package canvas

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This file exercises the five collaborative-canvas (c)-tier rows (the four
// doc 17 §13(c) canvas claims plus the re-filed doc 06 §3c spectator no-inject
// claim) as the orchctl sibling does: per row, a CONFORMING control fixture must
// pass clean, and each NAMED violation class must be tripped by at least one
// synthetic fixture (D50). Four rows use in-code Go-literal fixtures; the
// spectator row also loads synthetic JSON from fixtures/ to exercise the loader
// + the .provenance sidecar discipline. A per-row coverage gate fails closed if
// a declared violation class is never exercised, so a new class cannot land
// un-asserted.

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
// produced equals the declared class set — a CONFORMING control was proven AND
// every declared class was exercised at least once, failing closed on either a
// missing control or an un-exercised class.
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

// ── the documented-vocabulary guard (doc 06 §3c language note) ───────────────

// TestNoAttackVocabulary pins the doc 06 §3c language note for this package: no
// ViolationClass or guardrail Tag string may carry attack / redteam / intrusion
// framing. These are assurance tests for advertised properties, not a
// security-audit exercise; a row named for an attacker would violate the binding
// vocabulary note.
func TestNoAttackVocabulary(t *testing.T) {
	banned := []string{"attack", "redteam", "red-team", "intrusion", "exploit", "adversary", "hack"}
	all := []string{
		// row 1
		string(ViolationCanvasOpReachedVM),
		// row 2
		string(ViolationProjectionEdgeIntoSession), string(ViolationCanvasMessageInputBearing),
		// row 3
		string(ViolationControlRPCNoAttribution), string(ViolationControlRPCSecondWriter),
		// row 4
		string(ViolationDirectoryRightContentLeak), string(ViolationDirectoryRightLiveRenderUnauthorized),
		string(ViolationDirectoryRightUnknownState),
		// row 5
		string(ViolationSpectatorInjected),
	}
	all = append(all, Tags...)
	for _, s := range all {
		low := strings.ToLower(s)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("string %q carries banned framing %q — doc 06 §3c forbids attack/redteam/"+
					"intrusion naming; name the row for the PROPERTY it asserts", s, b)
			}
		}
	}
}

// TestTagsStable pins the single-sourced guardrail tags to the doc.go
// REGISTRATION values, in order. The repo-root guardrail-map.yaml's canvas glob
// row names these SAME tags; if a tag string drifts without re-reconciling the
// map row and the doc.go table, this fails HERE rather than letting the package
// and the map name different rows (the honest-map-row discipline: a map row names
// a real single-sourced tag value, never a placeholder).
func TestTagsStable(t *testing.T) {
	want := []string{
		"canvas-edits-never-reach-vm",
		"canvas-not-an-input-channel",
		"canvas-control-rpc-attribution",
		"canvas-respects-directory-rights",
		"spectator-cannot-inject",
	}
	if len(Tags) != len(want) {
		t.Fatalf("Tags has %d entries, want %d (the four doc 17 §13(c) canvas rows + the re-filed "+
			"doc 06 §3c spectator row; doc.go REGISTRATION)", len(Tags), len(want))
	}
	for i := range want {
		if Tags[i] != want[i] {
			t.Errorf("Tags[%d] = %q, want %q (doc.go REGISTRATION / guardrail-map.yaml canvas row)",
				i, Tags[i], want[i])
		}
	}
}

// ── ROW 1 — canvas edits never reach a session VM (doc 17 §13(c)(1)) ─────────

func TestRowCanvasEditsNeverReachVM(t *testing.T) {
	declared := []ViolationClass{ViolationCanvasOpReachedVM}

	type tc struct {
		name string
		set  CanvasOpSet
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming",
			set: CanvasOpSet{Name: "conforming", Ops: []CanvasOp{
				{Name: "move-shape", ReachedSessionVM: false},
				{Name: "add-sticky", ReachedSessionVM: false},
				{Name: "draw-connector", ReachedSessionVM: false},
			}},
			want: nil,
		},
		{
			name: "edit-reached-vm",
			set: CanvasOpSet{Name: "edit-reached-vm", Ops: []CanvasOp{
				{Name: "move-shape", ReachedSessionVM: false},
				{Name: "rogue-op", ReachedSessionVM: true},
			}},
			want: []ViolationClass{ViolationCanvasOpReachedVM},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckCanvasEditsNeverReachVM(c.set)
			assertRow(t, c.name, got, c.want)
		})
		got := CheckCanvasEditsNeverReachVM(c.set)
		if len(c.want) == 0 {
			sawControl = sawControl || len(got) == 0
		}
		for _, v := range got {
			seen[v.Class] = true
		}
	}
	coverageGate(t, "canvas-edits-never-reach-vm", declared, seen, sawControl)
}

// ── ROW 2 — canvas is not an input channel (doc 17 §3.1/§13(c)(2)) ───────────

func TestRowCanvasNotInputChannel(t *testing.T) {
	declared := []ViolationClass{ViolationProjectionEdgeIntoSession, ViolationCanvasMessageInputBearing}

	type tc struct {
		name  string
		graph ProjectionGraph
		want  []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming",
			graph: ProjectionGraph{
				Name: "conforming",
				Edges: []ProjectionEdge{
					{Name: "session-status->tile", Direction: DirPlatformToBoard},
					{Name: "fleet-tree->node", Direction: DirPlatformToBoard},
				},
				Messages: []CanvasMessage{
					{Name: "BoardUpdate", InputBearingIntoSession: false},
					{Name: "ProjectionTile", InputBearingIntoSession: false},
				},
			},
			want: nil,
		},
		{
			name: "edge-into-session",
			graph: ProjectionGraph{
				Name: "edge-into-session",
				Edges: []ProjectionEdge{
					{Name: "session-status->tile", Direction: DirPlatformToBoard},
					{Name: "tile->guest-stdin", Direction: DirBoardToSession},
				},
			},
			want: []ViolationClass{ViolationProjectionEdgeIntoSession},
		},
		{
			name: "input-bearing-message",
			graph: ProjectionGraph{
				Name: "input-bearing-message",
				Messages: []CanvasMessage{
					{Name: "InjectBoardState", InputBearingIntoSession: true},
				},
			},
			want: []ViolationClass{ViolationCanvasMessageInputBearing},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckCanvasNotInputChannel(c.graph)
			assertRow(t, c.name, got, c.want)
		})
		got := CheckCanvasNotInputChannel(c.graph)
		if len(c.want) == 0 {
			sawControl = sawControl || len(got) == 0
		}
		for _, v := range got {
			seen[v.Class] = true
		}
	}
	coverageGate(t, "canvas-not-an-input-channel", declared, seen, sawControl)
}

// ── ROW 3 — canvas control actions carry attribution (doc 17 §7/§13(c)(3)) ───

func TestRowCanvasControlAttribution(t *testing.T) {
	declared := []ViolationClass{ViolationControlRPCNoAttribution, ViolationControlRPCSecondWriter}

	type tc struct {
		name string
		set  ControlRPCSet
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming",
			set: ControlRPCSet{Name: "conforming", RPCs: []ControlRPC{
				{Name: "Pause", Actor: "user:alice", Admitted: true, WriterSeatHeldByOther: false},
				{Name: "Resume", Actor: "user:alice", Admitted: false, WriterSeatHeldByOther: true},
			}},
			want: nil,
		},
		{
			name: "missing-attribution",
			set: ControlRPCSet{Name: "missing-attribution", RPCs: []ControlRPC{
				{Name: "Pause", Actor: "", Admitted: true, WriterSeatHeldByOther: false},
			}},
			want: []ViolationClass{ViolationControlRPCNoAttribution},
		},
		{
			name: "second-writer",
			set: ControlRPCSet{Name: "second-writer", RPCs: []ControlRPC{
				{Name: "Steer", Actor: "user:bob", Admitted: true, WriterSeatHeldByOther: true},
			}},
			want: []ViolationClass{ViolationControlRPCSecondWriter},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckCanvasControlAttribution(c.set)
			assertRow(t, c.name, got, c.want)
		})
		got := CheckCanvasControlAttribution(c.set)
		if len(c.want) == 0 {
			sawControl = sawControl || len(got) == 0
		}
		for _, v := range got {
			seen[v.Class] = true
		}
	}
	coverageGate(t, "canvas-control-rpc-attribution", declared, seen, sawControl)
}

// ── ROW 4 — boards respect directory rights (doc 17 §8/§13(c)(4)) ────────────

func TestRowCanvasDirectoryRights(t *testing.T) {
	declared := []ViolationClass{
		ViolationDirectoryRightContentLeak,
		ViolationDirectoryRightLiveRenderUnauthorized,
		ViolationDirectoryRightUnknownState,
	}

	type tc struct {
		name string
		view BoardView
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming",
			view: BoardView{Name: "conforming", Refs: []ProjectedRef{
				{Name: "own-session", ViewerHasDirectoryRight: true, RenderState: RenderLive, LeakedContentOrMetadata: true},
				{Name: "dangling-plan", ViewerHasDirectoryRight: false, RenderState: RenderTombstone, LeakedContentOrMetadata: false},
				{Name: "peer-private", ViewerHasDirectoryRight: false, RenderState: RenderAccessPlaceholder, LeakedContentOrMetadata: false},
			}},
			want: nil,
		},
		{
			name: "content-leak",
			view: BoardView{Name: "content-leak", Refs: []ProjectedRef{
				{Name: "peer-private", ViewerHasDirectoryRight: false, RenderState: RenderAccessPlaceholder, LeakedContentOrMetadata: true},
			}},
			want: []ViolationClass{ViolationDirectoryRightContentLeak},
		},
		{
			name: "live-render-unauthorized",
			view: BoardView{Name: "live-render-unauthorized", Refs: []ProjectedRef{
				{Name: "peer-private", ViewerHasDirectoryRight: false, RenderState: RenderLive, LeakedContentOrMetadata: false},
			}},
			want: []ViolationClass{ViolationDirectoryRightLiveRenderUnauthorized},
		},
		{
			name: "unknown-render-state",
			view: BoardView{Name: "unknown-render-state", Refs: []ProjectedRef{
				{Name: "peer-private", ViewerHasDirectoryRight: false, RenderState: RenderState("redacted-blob"), LeakedContentOrMetadata: false},
			}},
			want: []ViolationClass{ViolationDirectoryRightUnknownState},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckCanvasDirectoryRights(c.view)
			assertRow(t, c.name, got, c.want)
		})
		got := CheckCanvasDirectoryRights(c.view)
		if len(c.want) == 0 {
			sawControl = sawControl || len(got) == 0
		}
		for _, v := range got {
			seen[v.Class] = true
		}
	}
	coverageGate(t, "canvas-respects-directory-rights", declared, seen, sawControl)
}

// TestDirectoryRightUnauthorizedLiveRenderWithContentNamesBoth proves the row
// catches BOTH failure modes when an unauthorized reference both live-renders
// AND leaks content — the verdict must name the content leak AND the
// unauthorized live render, never silently collapse to one.
func TestDirectoryRightUnauthorizedLiveRenderWithContentNamesBoth(t *testing.T) {
	view := BoardView{Name: "double", Refs: []ProjectedRef{
		{Name: "peer-private", ViewerHasDirectoryRight: false, RenderState: RenderLive, LeakedContentOrMetadata: true},
	}}
	got := CheckCanvasDirectoryRights(view)
	if !sameClasses(got, []ViolationClass{
		ViolationDirectoryRightContentLeak, ViolationDirectoryRightLiveRenderUnauthorized,
	}) {
		t.Fatalf("an unauthorized live render that also leaks content must report BOTH named "+
			"violations, got:\n%s", render(got))
	}
}

// ── ROW 5 — read-only spectate cannot inject (doc 06 §3c re-file; D61) ───────

func TestRowSpectatorNoInject(t *testing.T) {
	declared := []ViolationClass{ViolationSpectatorInjected}

	// Disposition map for the JSON fixtures backing this row. Every *.json on disk
	// MUST be registered here; the coverage gate fails closed on any unlisted one.
	corpusExpectation := map[string][]ViolationClass{
		"spectator-00-conforming.json": nil,
		"spectator-01-injected.json":   {ViolationSpectatorInjected},
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
			s, err := LoadJSON[ViewerSet](filepath.Join(FixturesDir(), name))
			if err != nil {
				t.Fatalf("loading fixture %s: %v", name, err)
			}
			s.Name = name
			got := CheckSpectatorNoInject(s)
			assertRow(t, name, got, want)
		})
		s, err := LoadJSON[ViewerSet](filepath.Join(FixturesDir(), name))
		if err != nil {
			t.Fatalf("loading fixture %s: %v", name, err)
		}
		got := CheckSpectatorNoInject(s)
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
	coverageGate(t, "spectator-cannot-inject", declared, seen, sawControl)
}

// TestDriverInjectIsConforming pins that the row does not over-claim: a
// driver-role seat whose input is accepted is CONFORMING — only a SPECTATOR seat
// is barred from injecting (doc 06 §3c / D61).
func TestDriverInjectIsConforming(t *testing.T) {
	s := ViewerSet{Name: "driver-inject", Viewers: []Viewer{
		{Name: "driver", Role: RoleDriver, InputAccepted: true},
	}}
	if got := CheckSpectatorNoInject(s); len(got) != 0 {
		t.Fatalf("a driver-role seat whose input is accepted must be CONFORMING — only a read-only "+
			"spectator is barred from injecting (doc 06 §3c; D61), got:\n%s", render(got))
	}
}

// ── runnability split (README.md "OSS-runnable vs paid-dependent") ───────────

// TestAllRowsOSSRunnable pins that, as modeled, every canvas row is oss-runnable:
// each is a static synthetic data-shape diff with no web-client / paid-layer
// dependency (doc.go RUNNABILITY). CheckRunnable runs the check for an
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

// TestPaidDependentReportsNotApplicable exercises the doc 17 §13 split mechanism:
// a paid-dependent row on an OSS run is reported NOT-APPLICABLE (didRun=false),
// never FAILED, and its check is NOT executed. This proves a future web-client-
// dependent row can be split without a structural change.
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
			t.Errorf("fixture %s has no .provenance sidecar (%s) — every D50 synthetic fixture must "+
				"carry one", name, filepath.Base(sidecar))
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// assertRow asserts a single check result against an expected class set: a
// conforming control (want empty) must pass clean; a violation fixture must fail
// with exactly the NAMED class set.
func assertRow(t *testing.T, name string, got []Violation, want []ViolationClass) {
	t.Helper()
	if len(want) == 0 {
		if len(got) != 0 {
			t.Fatalf("CONFORMING fixture %s reported %d violation(s) — the green case must pass "+
				"clean:\n%s", name, len(got), render(got))
		}
		return
	}
	if len(got) == 0 {
		t.Fatalf("VIOLATION fixture %s reported NO violations — the check must fail on %v (a silent "+
			"pass is the regression this row exists to catch)", name, want)
	}
	if !sameClasses(got, want) {
		t.Fatalf("VIOLATION fixture %s reported the WRONG violation class set —\n want: %v\n got: %v\n"+
			"full:\n%s", name, want, classesOf(got), render(got))
	}
}

// listFixtures returns the sorted *.json fixture filenames on disk (the
// .provenance sidecars are excluded). Anchored via FixturesDir (runtime.Caller).
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
		t.Fatalf("the fixtures dir %s is empty — expected synthetic canvas fixtures", FixturesDir())
	}
	sort.Strings(names)
	return names
}
