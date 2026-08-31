// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// live_drive_test.go — the LIVE-DRIVE tier test (DRIVE-PROTOCOL.md "The e2e
// harness, in tiers"). It closes the loop: a thin client speaking only attach.v1
// drives a Claude Code process through the D79 framed-UDS transport and the
// wrapper (adapter+driver), triggers a tool ask, answers it on the grant path,
// and asserts the emitted attach.v1 events structurally / id-relative against the
// existing checklist patterns (validateEvents + the spawn-index correlation the
// goldentrace suite uses).
//
// THREE tests, one gate:
//
//   - TestLiveDriveSocketBridgeFakeCC (ALWAYS-ON): drives the EXACT same
//     host-agent + UDS transport + thin-client wiring the live path uses, but
//     with CC's "brain" replaced by a scripted fake-CC helper process — so every
//     line of the conformance path (Bridge.Pump → adapter → SocketTransport
//     fan-out → thinClient → DriveGrant → driver → CC stdin) runs in CI, proving
//     the wiring green WITHOUT a live session. Proves chat + subagent-spawn +
//     ask round-trip structurally.
//   - TestLiveDriveSocketBridgeGated: DriveLiveSocketBridge returns
//     ErrLiveDriveGateUnset with DS_E2E_LIVE unset (never launches podman).
//   - TestLiveDriveSocketBridgeReal (GATED DS_E2E_LIVE=1): the real container run.
//     Skips without the gate; when armed, drives REAL CC 2.1.173 in a rootless
//     podman container and asserts the same shapes live.

// --- structural / id-relative assertions (shared by fake + live) -------------

// assertLiveDriveConformance runs the same structural + id-relative assertions
// the goldentrace checklist suite uses, over a live-or-fake attach.v1 projection:
//
//	chat   — at least one chat.message is projected (the conversation drove);
//	spawn  — if a subagent.spawned is present, its lifecycle correlates by node_id
//	         and spawn happens-before its terminals (the spawn_test.go pattern);
//	ask    — the ask round-trip closed: an ask.requested (native control source)
//	         and a matching ask.resolved correlate by ask_id/node_id, the resolved
//	         behavior matches the grant, and request precedes resolution (P10
//	         happens-before; never literal ids or wall-clock).
//
// It NEVER asserts literal ids, wall-clock order, or timing metrics (DRIVE-
// PROTOCOL.md "assert structurally / id-relative, never literal").
func assertLiveDriveConformance(t *testing.T, evs []attach.Event, wantAllow bool) {
	t.Helper()

	// 1. Stream well-formedness — the generic checklist (golden_test.go's
	//    validateEvents): seq strictly monotonic from 1, constant session_id,
	//    exactly one payload pointer per event.
	validateEventsLive(t, evs)

	// 2. chat — the conversation produced assistant chat text.
	if !liveProjectionContains(evs, attach.TypeChatMessage) {
		t.Errorf("no chat.message in the live-drive projection (the conversation did not drive a chat turn)")
	}

	// 3. spawn — id-relative spawn-tree correlation (the spawn_test.go pattern):
	//    every spawned node's terminals correlate by node_id, and spawn precedes
	//    them. We assert the SHAPE if a spawn is present (the live model may or may
	//    not spawn on a given prompt; the fake always does, so the round-trip is
	//    proven there and the live run records whether it spawned).
	assertSpawnCorrelationLive(t, evs)

	// 4. ask — the round-trip closed: requested → resolved, correlated id-relative.
	assertAskRoundTripLive(t, evs, wantAllow)
}

// validateEventsLive mirrors replay.validateEvents (the generic checklist): seq
// strictly monotonic from 1, constant session_id, exactly one payload per event.
// Re-declared here (not imported) because the test package is e2e, not replay,
// and validateEvents is an unexported test helper there.
func validateEventsLive(t *testing.T, evs []attach.Event) {
	t.Helper()
	if len(evs) == 0 {
		t.Fatal("live-drive produced no attach.v1 events")
	}
	session := evs[0].SessionID
	if session == "" {
		t.Error("first event has empty session_id")
	}
	for i, ev := range evs {
		if want := uint64(i + 1); ev.Seq != want {
			t.Errorf("event %d (%s): seq = %d, want %d (strictly monotonic from 1, P10)", i, ev.Type, ev.Seq, want)
		}
		if ev.SessionID != session {
			t.Errorf("event %d (%s): session_id = %q, want constant %q", i, ev.Type, ev.SessionID, session)
		}
		if n := payloadCountLive(ev); n != 1 {
			t.Errorf("event %d (%s): %d payload pointers set, want exactly 1", i, ev.Type, n)
		}
	}
}

// payloadCountLive counts non-nil payload pointers (the replay.payloadCount twin).
func payloadCountLive(ev attach.Event) int {
	n := 0
	ptrs := []any{
		ev.SessionInit, ev.SessionState, ev.ChatMessage, ev.ToolInvoked, ev.ToolCompleted,
		ev.SubagentSpawned, ev.SubagentProgress, ev.SubagentCompleted, ev.SubagentAccounted,
		ev.AskRequested, ev.AskResolved, ev.PlanDelta, ev.QuotaUpdated, ev.SessionAccounted,
	}
	for _, p := range ptrs {
		switch v := p.(type) {
		case *attach.SessionInit:
			if v != nil {
				n++
			}
		case *attach.SessionState:
			if v != nil {
				n++
			}
		case *attach.ChatMessage:
			if v != nil {
				n++
			}
		case *attach.ToolInvoked:
			if v != nil {
				n++
			}
		case *attach.ToolCompleted:
			if v != nil {
				n++
			}
		case *attach.SubagentSpawned:
			if v != nil {
				n++
			}
		case *attach.SubagentProgress:
			if v != nil {
				n++
			}
		case *attach.SubagentCompleted:
			if v != nil {
				n++
			}
		case *attach.SubagentAccounted:
			if v != nil {
				n++
			}
		case *attach.AskRequested:
			if v != nil {
				n++
			}
		case *attach.AskResolved:
			if v != nil {
				n++
			}
		case *attach.PlanDelta:
			if v != nil {
				n++
			}
		case *attach.QuotaUpdated:
			if v != nil {
				n++
			}
		case *attach.SessionAccounted:
			if v != nil {
				n++
			}
		}
	}
	return n
}

// assertSpawnCorrelationLive: for every subagent.spawned, its terminal events
// (progress/completed/accounted) correlate by node_id and the spawn precedes
// them in seq (happens-before, P10). It is the spawn_test.go invariant, applied
// to a live stream where the exact node count is not known a priori.
func assertSpawnCorrelationLive(t *testing.T, evs []attach.Event) {
	t.Helper()
	spawnSeq := map[string]uint64{}
	spawned := map[string]bool{}
	for _, ev := range evs {
		if ev.SubagentSpawned != nil {
			id := ev.SubagentSpawned.NodeID
			if id == "" {
				t.Errorf("subagent.spawned at seq %d has empty node_id (id-correlation broken)", ev.Seq)
			}
			if spawned[id] {
				t.Errorf("node %s spawned twice (seq %d)", id, ev.Seq)
			}
			spawned[id] = true
			spawnSeq[id] = ev.Seq
		}
	}
	for _, ev := range evs {
		var node string
		switch {
		case ev.SubagentProgress != nil:
			node = ev.SubagentProgress.NodeID
		case ev.SubagentCompleted != nil:
			node = ev.SubagentCompleted.NodeID
		case ev.SubagentAccounted != nil:
			node = ev.SubagentAccounted.NodeID
		default:
			continue
		}
		sseq, ok := spawnSeq[node]
		if !ok {
			// Accounting-only branch (missed task lifecycle) is valid; nothing to
			// order against (subagent-spawn fixture documents this).
			continue
		}
		if ev.Seq <= sseq {
			t.Errorf("node %s: terminal %s at seq %d precedes its spawn at seq %d (happens-before violated)",
				node, ev.Type, ev.Seq, sseq)
		}
	}
}

// assertAskRoundTripLive proves the ask grant round-trip closed end to end: an
// ask.requested (the native control_request projected to attach.v1) and a
// matching ask.resolved, correlated id-relative by ask_id + node_id, the resolved
// behavior matching the grant the thin client sent, and request preceding
// resolution (P10 happens-before). This is the load-bearing assertion the
// live-drive tier exists for (DRIVE-FINDINGS §1/§6, freeze row 5).
func assertAskRoundTripLive(t *testing.T, evs []attach.Event, wantAllow bool) {
	t.Helper()
	var (
		req    *attach.AskRequested
		reqSeq uint64
		res    *attach.AskResolved
		resSeq uint64
	)
	for _, ev := range evs {
		switch {
		case ev.AskRequested != nil && req == nil:
			req = ev.AskRequested
			reqSeq = ev.Seq
		case ev.AskResolved != nil && res == nil:
			res = ev.AskResolved
			resSeq = ev.Seq
		}
	}
	if req == nil {
		t.Fatalf("no ask.requested in the projection (the tool ask did not surface — the native control round-trip did not happen)")
	}
	if res == nil {
		t.Fatalf("ask.requested present but no ask.resolved (the grant did not close the ask)")
	}
	// id-relative correlation: the resolution joins the request by ask_id and
	// node_id (NOT a literal value — only that the two events agree).
	if req.AskID == "" || req.NodeID == "" {
		t.Errorf("ask.requested has empty ask_id/node_id (ask_id=%q node_id=%q): the correlation keys are missing", req.AskID, req.NodeID)
	}
	if res.AskID != req.AskID {
		t.Errorf("ask.resolved ask_id = %q, want %q (must correlate to the request)", res.AskID, req.AskID)
	}
	if res.NodeID != req.NodeID {
		t.Errorf("ask.resolved node_id = %q, want %q (the tool_use_id correlation key, P8)", res.NodeID, req.NodeID)
	}
	// The native channel carries source "control".
	if req.Source != "control" {
		t.Errorf("ask.requested source = %q, want %q (the native control channel)", req.Source, "control")
	}
	// Behavior matches the grant the thin client drove.
	wantBehavior := "allow"
	if !wantAllow {
		wantBehavior = "deny"
	}
	if res.Behavior != wantBehavior {
		t.Errorf("ask.resolved behavior = %q, want %q (must match the driven grant)", res.Behavior, wantBehavior)
	}
	// happens-before: the request precedes its resolution (never literal order).
	if resSeq <= reqSeq {
		t.Errorf("ask.resolved at seq %d does not follow ask.requested at seq %d (happens-before violated, P10)", resSeq, reqSeq)
	}
}

// --- broad-coverage per-feature assertions (coverage.jsonl, KVM tier) --------
//
// These mirror the validateEventsLive / assertAskRoundTripLive style — id-relative,
// happens-before, never literal ids or wall-clock — and back the broad-coverage
// KVM-tier drive (script_test.go: TestScriptedDriveKVMCoverageReal). They are
// also exercised offline by the fake-CC coverage twin so a regression is caught in
// the wave gate, not only when an operator arms DS_KVM_LIVE.

// assertToolCoverageLive proves the named native tools each fired AND completed,
// correlated by node_id: for every want tool there is a ToolInvoked with that
// Name whose node_id carries a matching ToolCompleted at a strictly-later seq
// (completed.Seq > invoked.Seq, happens-before P10) with IsError=false (the allow
// branch executed cleanly). It is the breadth half of the coverage proof — the
// projection actually carried a tool.invoked/tool.completed pair for Bash, Write,
// Read, Edit, … — and it asserts the SHAPE id-relative, never a literal node_id.
//
// A tool whose only completion is a denial (IsError=true) does NOT satisfy a want
// here (that is the deny branch, asserted by assertDenyRoundTripLive); pass only
// the tools you expect to have been ALLOWED.
func assertToolCoverageLive(t *testing.T, evs []attach.Event, wantTools []string) {
	t.Helper()

	// invokedByName[name] = the node_ids a tool.invoked carried for that tool name,
	// each mapped to the invoking event's seq (the happens-before anchor).
	invokedByName := map[string]map[string]uint64{}
	for _, ev := range evs {
		if ev.ToolInvoked == nil {
			continue
		}
		name := ev.ToolInvoked.Name
		node := ev.ToolInvoked.NodeID
		if node == "" {
			t.Errorf("tool.invoked %q at seq %d has empty node_id (the correlation key is missing)", name, ev.Seq)
			continue
		}
		if invokedByName[name] == nil {
			invokedByName[name] = map[string]uint64{}
		}
		invokedByName[name][node] = ev.Seq
	}

	// completedSeq[node] = the seq of that node's ToolCompleted; isErr[node] its
	// is_error. (A node completes at most once on the wire; last write wins is fine.)
	completedSeq := map[string]uint64{}
	isErr := map[string]bool{}
	for _, ev := range evs {
		if ev.ToolCompleted == nil {
			continue
		}
		completedSeq[ev.ToolCompleted.NodeID] = ev.Seq
		isErr[ev.ToolCompleted.NodeID] = ev.ToolCompleted.IsError
	}

	for _, want := range wantTools {
		invocations, ok := invokedByName[want]
		if !ok || len(invocations) == 0 {
			t.Errorf("tool coverage: no tool.invoked for %q (the tool never fired in the projection)", want)
			continue
		}
		// At least ONE invocation of this tool must have an allow-clean completion
		// at a later seq, correlated by node_id. (A tool may be invoked more than
		// once; one allowed completion proves the feature.)
		satisfied := false
		for node, invSeq := range invocations {
			cSeq, completed := completedSeq[node]
			if !completed {
				continue
			}
			if cSeq <= invSeq {
				t.Errorf("tool %q node %s: tool.completed at seq %d does not follow tool.invoked at seq %d (happens-before violated, P10)", want, node, cSeq, invSeq)
				continue
			}
			if isErr[node] {
				continue // a denied/errored completion does not satisfy an allow want
			}
			satisfied = true
		}
		if !satisfied {
			t.Errorf("tool coverage: %q fired but no node had a clean (is_error=false) tool.completed at a later seq (the allow round-trip did not close for it)", want)
		}
	}
}

// assertToolPairsLive is the name-map breadth assertion: for EVERY name in
// wantTools the projection must carry a tool.invoked with that Name whose node_id
// has a matching clean (is_error=false) tool.completed at a strictly-later seq.
// It is assertToolCoverageLive's contract under the name the broad-coverage drive
// reads against — the coverage tier passes the full native-tool breadth
// (Bash + Read + Write + Edit + Glob + Grep), so a regression that drops any one
// of the distinct native tool names is caught, not just Bash+Read/Write.
func assertToolPairsLive(t *testing.T, evs []attach.Event, wantTools []string) {
	t.Helper()
	assertToolCoverageLive(t, evs, wantTools)
}

// logToolPairsLive is the BEST-EFFORT twin of assertToolPairsLive for tools the
// real model routes non-deterministically (Glob/Grep — it often satisfies a
// "search /work" instruction with Bash/ls or skips the search entirely). It
// reports which named tools the projection carried a clean tool.invoked/completed
// pair for and which the model routed around, but NEVER fails: the live proof for
// these turns is the in-VM side effect (the proof file), not the tool name. The
// strict named-pair requirement lives on the deterministic OFFLINE twin. Returns
// the names that DID project (so the caller can log the live breadth actually hit).
func logToolPairsLive(t *testing.T, evs []attach.Event, softTools []string) []string {
	t.Helper()
	cleanByName := map[string]bool{}
	completed := map[string]bool{}
	for _, ev := range evs {
		if ev.ToolCompleted != nil && !ev.ToolCompleted.IsError {
			completed[ev.ToolCompleted.NodeID] = true
		}
	}
	for _, ev := range evs {
		if ev.ToolInvoked != nil && completed[ev.ToolInvoked.NodeID] {
			cleanByName[ev.ToolInvoked.Name] = true
		}
	}
	var hit, missed []string
	for _, name := range softTools {
		if cleanByName[name] {
			hit = append(hit, name)
		} else {
			missed = append(missed, name)
		}
	}
	if len(hit) > 0 {
		t.Logf("soft tool breadth (best-effort, live): the model routed through the named tool for %v", hit)
	}
	if len(missed) > 0 {
		t.Logf("soft tool breadth (best-effort, live): the model routed AROUND the named tool for %v (the in-VM side effect is the proof for these turns, not the tool name; the offline twin asserts the named pair deterministically)", missed)
	}
	return hit
}

// assertPlanDeltaLive proves the TYPED plan.delta projection: the TodoWrite turn
// surfaced a first-class attach.PlanDelta (NOT an opaque tool.invoked) carrying a
// node_id, Kind == attach.PlanDeltaKindTodoWrite, and a Todos snapshot of at least
// minTodos items — the working-model plan/todo card the writer-seat renders. It is
// the load-bearing typed-plan assertion: a TodoWrite that regressed to a generic
// ToolInvoked, or a PlanDelta that lost its Todos snapshot, fails here. id-relative
// (the node_id is the tool_use id; we never assert a literal value).
func assertPlanDeltaLive(t *testing.T, evs []attach.Event, minTodos int) {
	t.Helper()
	var pd *attach.PlanDelta
	for _, ev := range evs {
		if ev.Type == attach.TypePlanDelta && ev.PlanDelta != nil {
			pd = ev.PlanDelta
			break
		}
	}
	if pd == nil {
		t.Fatal("no plan.delta in the projection (the TodoWrite turn did not project a TYPED PlanDelta — it may have regressed to a generic tool.invoked)")
	}
	if pd.NodeID == "" {
		t.Error("plan.delta has empty node_id (the tool-use correlation key is missing)")
	}
	if pd.Kind != attach.PlanDeltaKindTodoWrite {
		t.Errorf("plan.delta Kind = %q, want %q (the TodoWrite full-list snapshot kind)", pd.Kind, attach.PlanDeltaKindTodoWrite)
	}
	if len(pd.Todos) < minTodos {
		t.Errorf("plan.delta carries %d todos, want >= %d (the typed Todos snapshot did not project)", len(pd.Todos), minTodos)
	}
	for i, td := range pd.Todos {
		if strings.TrimSpace(td.Content) == "" {
			t.Errorf("plan.delta todo[%d] has empty Content (the todo snapshot is malformed)", i)
		}
		if strings.TrimSpace(td.Status) == "" {
			t.Errorf("plan.delta todo[%d] (%q) has empty Status (the todo snapshot is malformed)", i, td.Content)
		}
	}
}

// assertErrorNotDenyLive proves the IsError-not-deny branch: a tool that FAILED at
// runtime, projection-distinct from a tool the host DENIED. The distinction is
// subtle because the adapter collapses a granted-then-failed ASKED tool onto a
// deny: an asked tool's ask.resolved behavior is derived from the tool_result's
// is_error (classify.go resolveFromToolResult — is_error ⇒ behavior "deny"), and
// the is_error bare-string body lands in DenialMessage for ANY error, so a
// GRANTED-but-failed asked tool is indistinguishable from a deny at the projection.
// The only projection-distinct runtime error is an UN-ASKED (read-only auto-allow)
// failure: it has NO correlated ask.resolved at all. This asserts:
//   - a deny node exists (some ask.resolved behavior "deny"), AND
//   - an IsError tool.completed exists on a DIFFERENT node that has NO correlated
//     ask.resolved (neither allow nor deny) — the un-asked failure,
//
// so the runtime error is visibly NOT the grant-path deny. id-relative; never a
// literal id. (Finding: the adapter cannot distinguish a granted-then-failed asked
// tool from a deny — see the test comment and the run note on epic 01KVCHFEFF.)
func assertErrorNotDenyLive(t *testing.T, evs []attach.Event) {
	t.Helper()

	// resolvedNodes: node_ids that carry an ask.resolved (any behavior); denyNodes:
	// those resolved "deny". (A node resolves at most once on the wire.)
	resolvedNodes := map[string]bool{}
	denyNodes := map[string]bool{}
	for _, ev := range evs {
		r := ev.AskResolved
		if r == nil || r.NodeID == "" {
			continue
		}
		resolvedNodes[r.NodeID] = true
		if r.Behavior == "deny" {
			denyNodes[r.NodeID] = true
		}
	}
	if len(denyNodes) == 0 {
		t.Fatal("no deny resolution in the projection (the deny branch must exist to tell the IsError-not-deny branch apart from it)")
	}

	var errNode *attach.ToolCompleted
	for _, ev := range evs {
		c := ev.ToolCompleted
		if c == nil || !c.IsError {
			continue
		}
		if resolvedNodes[c.NodeID] {
			continue // this errored completion went through an ask (deny or allow) — not the un-asked failure
		}
		errNode = c
		break
	}
	if errNode == nil {
		t.Fatal("no tool.completed with IsError=true on an UN-ASKED node (the failing read-only tool branch did not surface — it must be a runtime error distinct from the grant-path deny)")
	}
	if denyNodes[errNode.NodeID] {
		t.Errorf("error node %s is ALSO a deny node (the IsError-not-deny branch is confused with the deny branch)", errNode.NodeID)
	}
	// The un-asked error node must carry the verbatim error body (the is_error
	// bare-string, P13) — the same field a deny uses, but here with NO ask resolution
	// behind it, which is what makes it provably an error and not a deny.
	if strings.TrimSpace(errNode.DenialMessage) == "" && strings.TrimSpace(errNode.OutputExcerpt) == "" {
		t.Errorf("error node %s tool.completed has no error body (the is_error bare-string did not propagate, P13)", errNode.NodeID)
	}
}

// liveProjectionHasErrorNotDeny is the non-failing predicate twin of
// assertErrorNotDenyLive: it reports whether some IsError tool.completed exists on
// a node with NO correlated ask.resolved (the un-asked read-only failure, provably
// not a deny). The LIVE drive uses it (the real model often declines to attempt a
// doomed read at all, emitting only chat — so the errored completion never fires);
// the OFFLINE twin uses the asserting form against the deterministic fake.
func liveProjectionHasErrorNotDeny(evs []attach.Event) bool {
	resolvedNodes := map[string]bool{}
	for _, ev := range evs {
		if ev.AskResolved != nil && ev.AskResolved.NodeID != "" {
			resolvedNodes[ev.AskResolved.NodeID] = true
		}
	}
	for _, ev := range evs {
		c := ev.ToolCompleted
		if c != nil && c.IsError && !resolvedNodes[c.NodeID] {
			return true
		}
	}
	return false
}

// assertNestedUnderSubagentLive proves the nested-under-subagent shape: there is a
// subagent.spawned, AND a tool.invoked whose ParentNodeID equals that spawned
// node's NodeID (a tool the dispatched subagent ran, correlated UNDER the spawn by
// node_id, P2). It is the deeper half of the Task-turn proof — the subagent did not
// merely spawn, it ran a tool whose parent threads back to the spawn. id-relative.
func assertNestedUnderSubagentLive(t *testing.T, evs []attach.Event) {
	t.Helper()
	spawned := map[string]bool{}
	for _, ev := range evs {
		if ev.SubagentSpawned != nil && ev.SubagentSpawned.NodeID != "" {
			spawned[ev.SubagentSpawned.NodeID] = true
		}
	}
	if len(spawned) == 0 {
		t.Fatal("no subagent.spawned in the projection (the nested-Task turn did not spawn a subagent)")
	}
	for _, ev := range evs {
		if ev.ToolInvoked != nil && ev.ToolInvoked.ParentNodeID != "" && spawned[ev.ToolInvoked.ParentNodeID] {
			return // found a tool the subagent ran, correlated under the spawn
		}
	}
	t.Error("no tool.invoked correlates UNDER a spawned subagent (ParentNodeID == a subagent.spawned NodeID): the nested-under-subagent shape did not project")
}

// liveProjectionHasNestedUnderSubagent is the non-failing predicate twin of
// assertNestedUnderSubagentLive: it reports whether some tool.invoked correlates
// UNDER a spawned subagent (ParentNodeID == a subagent.spawned NodeID), without
// failing. The LIVE drive uses it (the model's in-subagent tool may not thread its
// parent back to the spawn node); the OFFLINE twin uses the asserting form.
func liveProjectionHasNestedUnderSubagent(evs []attach.Event) bool {
	spawned := map[string]bool{}
	for _, ev := range evs {
		if ev.SubagentSpawned != nil && ev.SubagentSpawned.NodeID != "" {
			spawned[ev.SubagentSpawned.NodeID] = true
		}
	}
	for _, ev := range evs {
		if ev.ToolInvoked != nil && ev.ToolInvoked.ParentNodeID != "" && spawned[ev.ToolInvoked.ParentNodeID] {
			return true
		}
	}
	return false
}

// assertDenyRoundTripLive proves the DENY branch closed end to end: there is an
// ask.resolved with Behavior "deny" carrying a non-empty Message (the deny reason
// propagated verbatim, P8/P13), AND the SAME tool (correlated by node_id) carries
// a ToolCompleted with IsError=true and a non-empty DenialMessage (the bare-string
// is_error body, P13). It is the deny twin of assertAskRoundTripLive(allow=false):
// where that asserts the request→resolve behavior, this additionally asserts the
// denial surfaced on the tool's completion so a denied tool is visibly blocked,
// not silently dropped. id-relative; never a literal id or wall-clock.
func assertDenyRoundTripLive(t *testing.T, evs []attach.Event) {
	t.Helper()

	// Find a deny resolution (there may be allow resolutions on other turns; we
	// want the FIRST deny — its node_id is the denied tool's correlation key).
	var (
		deny    *attach.AskResolved
		denySeq uint64
	)
	for _, ev := range evs {
		if ev.AskResolved != nil && ev.AskResolved.Behavior == "deny" {
			deny = ev.AskResolved
			denySeq = ev.Seq
			break
		}
	}
	if deny == nil {
		t.Fatal("no ask.resolved with behavior \"deny\" in the projection (the deny branch did not close — both grant branches must be exercised)")
	}
	if deny.NodeID == "" {
		t.Errorf("deny ask.resolved at seq %d has empty node_id (the tool-use correlation key is missing)", denySeq)
	}
	if strings.TrimSpace(deny.Message) == "" {
		t.Errorf("deny ask.resolved (node %s) has empty Message: the deny reason must propagate verbatim (P8/P13)", deny.NodeID)
	}

	// The denied tool's completion: correlated by node_id, IsError=true with a
	// non-empty DenialMessage (the bare-string is_error body).
	var completed *attach.ToolCompleted
	for _, ev := range evs {
		if ev.ToolCompleted != nil && ev.ToolCompleted.NodeID == deny.NodeID {
			completed = ev.ToolCompleted
			break
		}
	}
	if completed == nil {
		t.Fatalf("deny ask.resolved for node %s has no correlated tool.completed (the denied tool's completion did not surface)", deny.NodeID)
	}
	if !completed.IsError {
		t.Errorf("denied tool (node %s) tool.completed has IsError=false, want true (a denied tool must complete as an error)", deny.NodeID)
	}
	if strings.TrimSpace(completed.DenialMessage) == "" {
		t.Errorf("denied tool (node %s) tool.completed has empty DenialMessage, want the verbatim bare-string is_error body (P13)", deny.NodeID)
	}
}

// assertTurnAccountingLive proves the multi-turn shape: at least one
// session.accounted per driven turn (a fresh result per driven input — the
// sustained-process running-count invariant, DRIVE-FINDINGS §3), and each
// session.accounted carries a closed-set outcome (never empty). wantTurns is the
// turn count the script drove. It is the count half of the coverage proof: the
// stepping advanced per-turn rather than collapsing onto a single result.
func assertTurnAccountingLive(t *testing.T, evs []attach.Event, wantTurns int) {
	t.Helper()
	results := 0
	for _, ev := range evs {
		if ev.SessionAccounted == nil {
			continue
		}
		results++
		if strings.TrimSpace(ev.SessionAccounted.Outcome) == "" {
			t.Errorf("session.accounted at seq %d has empty outcome (the closed-set terminal vocabulary, P13)", ev.Seq)
		}
	}
	if results < wantTurns {
		t.Errorf("multi-turn accounting: %d session.accounted, want >= %d (one running result per driven turn)", results, wantTurns)
	}
}

// --- TestLiveDriveSocketBridgeFakeCC (always-on) -----------------------------

// TestLiveDriveSocketBridgeFakeCC drives the FULL host-agent + framed-UDS
// transport + thin-client wiring with a scripted fake-CC helper process standing
// in for the real container. It proves the live-drive conformance path is green
// in CI — chat, subagent-spawn, AND the ask grant round-trip — exercising every
// line the live run uses except the model's choice to call the tool (scripted
// here, live there). No podman/claude/cia is touched.
func TestLiveDriveSocketBridgeFakeCC(t *testing.T) {
	cfg := LiveDriveConfig{
		Image:         "ds/cc-sandbox:2.1.173", // named, never run (fake path)
		Model:         "sonnet",
		BudgetUSD:     "1.0",
		PodmanNetwork: "none",
		// The fake-CC seam: a helper process that scripts the CC stdio (chat +
		// spawn + a can_use_tool ask it holds until the host's control_response).
		ccCommand: fakeCCCommand("allow"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := driveFakeSocketBridge(ctx, cfg, "fake-live-session", driveChatSpawnAskScenario(true))
	if err != nil {
		t.Fatalf("driveFakeSocketBridge: %v", err)
	}
	if !res.AskAnswered {
		t.Fatal("the thin client never answered an ask (the grant round-trip did not run)")
	}
	assertLiveDriveConformance(t, res.Events, true /*allow*/)

	// The spawn path must be present in the fake (it scripts an Agent tool_use +
	// task_started): assert at least one subagent.spawned, proving the spawn half
	// of the loop, not just chat+ask.
	if !liveProjectionContains(res.Events, attach.TypeSubagentSpawned) {
		t.Error("no subagent.spawned in the fake-CC projection (the spawn half of the loop did not project)")
	}
}

// TestLiveDriveSocketBridgeFakeCCDeny is the deny twin: the thin client denies
// the ask, and the resolution carries behavior "deny" with the deny message.
func TestLiveDriveSocketBridgeFakeCCDeny(t *testing.T) {
	cfg := LiveDriveConfig{
		Image:         "ds/cc-sandbox:2.1.173",
		Model:         "sonnet",
		BudgetUSD:     "1.0",
		PodmanNetwork: "none",
		ccCommand:     fakeCCCommand("deny"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := driveFakeSocketBridge(ctx, cfg, "fake-live-session-deny", driveChatSpawnAskScenario(false))
	if err != nil {
		t.Fatalf("driveFakeSocketBridge (deny): %v", err)
	}
	assertLiveDriveConformance(t, res.Events, false /*deny*/)
}

// --- TestLiveDriveSocketBridgeGated ------------------------------------------

// TestLiveDriveSocketBridgeGated asserts the real-container entry point launches
// NOTHING with the gate unset: it returns ErrLiveDriveGateUnset before any
// podman, claude, or cia is touched. The single-gate story, in Go.
func TestLiveDriveSocketBridgeGated(t *testing.T) {
	t.Setenv(LiveGateEnv, "") // ensure unset/non-"1".
	_, err := DriveLiveSocketBridge(context.Background(), LiveDriveConfigDefaults(), "gated-session",
		func(ctx context.Context, tc *thinClient) error { return nil })
	if !errors.Is(err, ErrLiveDriveGateUnset) {
		t.Fatalf("DriveLiveSocketBridge with gate unset = %v, want ErrLiveDriveGateUnset", err)
	}
	if !errors.Is(err, ErrLiveGateUnset) {
		t.Errorf("ErrLiveDriveGateUnset must wrap the shared ErrLiveGateUnset (single-gate story)")
	}
}

// --- TestLiveDriveSocketBridgeReal (gated DS_E2E_LIVE=1) ---------------------

// TestLiveDriveSocketBridgeReal is the REAL live-drive run: a thin client drives
// REAL Claude Code 2.1.173 in a rootless podman container, across the framed UDS,
// through the wrapper, triggers a tool ask, answers it, and asserts the emitted
// attach.v1 events. It SKIPS without DS_E2E_LIVE=1 (every CI / go test run), so it
// is CI-able and green by default. The operator arms it with DS_E2E_LIVE=1 for the
// deferred manual live step (e2e/README.md).
func TestLiveDriveSocketBridgeReal(t *testing.T) {
	if os.Getenv(LiveGateEnv) != "1" {
		t.Skip("DS_E2E_LIVE != 1: the real live-drive container run is the deferred manual step (see e2e/README.md). Skipping; the fake-CC twin (TestLiveDriveSocketBridgeFakeCC) proves the wiring offline.")
	}
	cfg := LiveDriveConfigDefaults()
	// DS_LIVE_SCRATCH lets the operator persist the raw capture for inspection
	// (raw-class — under ~/tmp, never committed). Empty ⇒ a MkdirTemp dir that is
	// auto-removed on return (the default, hygienic for CI).
	if sc := os.Getenv("DS_LIVE_SCRATCH"); sc != "" {
		cfg.ScratchDir = sc
	}
	// The documented longhand for routing this run through the FIRST-PARTY
	// ds-capture gateway (e.g. on :18099) instead of the :18080 monitor — the
	// counterpart to `serpent drive`, which sets these programmatically. All three
	// are additive overrides: unset, the proven LiveDriveConfigDefaults stand.
	//   DS_LIVE_PROXY_PORT — the gateway port; also re-points the pasta forward at it.
	//   DS_LIVE_CA         — the CA the gateway terminates TLS with (staged to scratch).
	//   DS_LIVE_NET        — an explicit podman --network (overrides the pasta default).
	if pp := os.Getenv("DS_LIVE_PROXY_PORT"); pp != "" {
		port, err := strconv.Atoi(pp)
		if err != nil {
			t.Fatalf("DS_LIVE_PROXY_PORT=%q is not an integer: %v", pp, err)
		}
		cfg.ProxyPort = port
		cfg.PodmanNetwork = fmt.Sprintf("pasta:-T,%d", port)
	}
	if ca := os.Getenv("DS_LIVE_CA"); ca != "" {
		cfg.CAHost = ca
	}
	if net := os.Getenv("DS_LIVE_NET"); net != "" {
		cfg.PodmanNetwork = net
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, err := DriveLiveSocketBridge(ctx, cfg, fmt.Sprintf("live-%d", time.Now().Unix()), driveChatSpawnAskScenario(true))
	if err != nil {
		t.Fatalf("DriveLiveSocketBridge (real): %v", err)
	}
	t.Logf("live-drive projected %d attach.v1 events; raw capture (raw-class, uncommitted): %s", len(res.Events), res.RawCapturePath)
	for _, ev := range res.Events {
		t.Logf("  seq=%d type=%s", ev.Seq, ev.Type)
	}
	if len(res.Warnings) > 0 {
		t.Logf("adapter warnings (drift, non-fatal): %v", res.Warnings)
	}
	assertLiveDriveConformance(t, res.Events, true /*allow*/)
	if !res.AskAnswered {
		t.Error("the thin client never answered an ask on the live run")
	}
}

// --- the drive scenario (thin client; attach.v1 only) ------------------------

// driveChatSpawnAskScenario is the multi-turn conversation the thin client drives:
// turn 1 a chat+spawn prompt (assistant text + a subagent), turn 2 a prompt that
// compels a Bash tool under default permission mode → a native ask the client
// answers via the grant path. It speaks ONLY attach.v1 (DriveText / GrantAsk);
// every CC-ism lives behind the wrapper across the UDS.
func driveChatSpawnAskScenario(allow bool) driveScenario {
	return func(ctx context.Context, tc *thinClient) error {
		// Turn 1: a prompt that yields assistant chat and (for the fake) a spawn.
		if err := tc.DriveText("Briefly introduce yourself, then dispatch a trivial subtask to a subagent."); err != nil {
			return fmt.Errorf("drive turn 1: %w", err)
		}
		// Wait for the first turn's result before driving the next input (the safe
		// idiom, DRIVE-FINDINGS §3).
		if !tc.waitForResults(ctx, 1, 90*time.Second) {
			return errors.New("turn 1 did not reach a result")
		}

		// Turn 2: compel a Bash tool that escalates to a native ask under default
		// permission mode.
		if err := tc.DriveText("Now run exactly this with the Bash tool: mkdir -p /work/scratch && echo seeded > /work/scratch/seed.txt"); err != nil {
			return fmt.Errorf("drive turn 2: %w", err)
		}

		// Render the ask and answer it on the grant path (the policy stream). The
		// wrapper turns the grant into CC's control_response inside the boundary.
		askID, nodeID, input, ok := tc.waitForAsk(ctx, 90*time.Second)
		if !ok {
			return errors.New("no ask surfaced for the Bash tool (the native control round-trip did not happen)")
		}
		var updatedInput []byte
		denyMsg := ""
		if allow {
			updatedInput = input // echo the tool input on allow (P8)
		} else {
			denyMsg = "Denied by the live-drive conformance scenario."
		}
		if err := tc.GrantAsk(askID, nodeID, allow, updatedInput, denyMsg); err != nil {
			return fmt.Errorf("grant ask: %w", err)
		}

		// Wait for the second turn's result (the tool unblocks and the turn
		// completes) before ending the conversation.
		if !tc.waitForResults(ctx, 2, 90*time.Second) {
			return errors.New("turn 2 did not reach a result after the grant")
		}
		return nil
	}
}

// --- the fake-CC helper process ----------------------------------------------

// fakeCCCommand returns a ccCommand that re-execs THIS test binary as the fake-CC
// helper process (the standard Go helper-process pattern), so the fake CC is a
// REAL separate process with REAL stdio pipes — the exact pipe shape the live
// podman process presents, only the bytes are scripted. mode is "allow"|"deny".
func fakeCCCommand(mode string) func(ctx context.Context) *exec.Cmd {
	return func(ctx context.Context) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestFakeCCHelperProcess")
		cmd.Env = append(os.Environ(), "GO_FAKE_CC_HELPER=1", "GO_FAKE_CC_MODE="+mode)
		return cmd
	}
}

// TestFakeCCHelperProcess is the fake-CC helper process: when GO_FAKE_CC_HELPER=1
// it is NOT a test but a scripted stream-json CC stand-in that reads control/user
// frames on stdin and writes a chat + spawn + a held can_use_tool ask on stdout.
// It scripts exactly the conformance path: assistant chat, an Agent tool_use +
// task_started (→ subagent.spawned), then a can_use_tool control_request it HOLDS
// until the host's control_response, then the tool_result + a final result. This
// is the model's behavior, frozen — what record-replay would pin.
func TestFakeCCHelperProcess(t *testing.T) {
	if os.Getenv("GO_FAKE_CC_HELPER") != "1" {
		return // ordinary test invocation: not the helper.
	}
	mode := os.Getenv("GO_FAKE_CC_MODE")
	runFakeCC(mode)
	os.Exit(0)
}

// runFakeCC is the scripted stdio fake. It mirrors the live CC wire shapes the
// keystone captured (DRIVE-FINDINGS §1/§3, the drive-native-allow fixture): a
// sustained stream-json host that stays alive across turns, projects a spawn, and
// holds a native ask until answered. Synthetic by construction (no real ids,
// text, or creds — D50).
func runFakeCC(mode string) {
	const session = "00000000-0000-4000-8000-0000000fake01"
	out := bufio.NewWriter(os.Stdout)
	emit := func(v map[string]any) {
		b, _ := json.Marshal(v)
		out.Write(b)
		out.WriteByte('\n')
		out.Flush()
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	turn := 0
	uuidN := 0
	nextUUID := func() string { uuidN++; return fmt.Sprintf("00000000-0000-4000-8000-00000000fa%02d", uuidN) }

	// init helper, re-emitted per driven input (DRIVE-FINDINGS §3: a fresh
	// system/init per turn). agents[] includes the subagent type so the spawn join
	// finalizes.
	emitInit := func() {
		emit(map[string]any{
			"type": "system", "subtype": "init", "session_id": session, "uuid": nextUUID(),
			"cwd": "/work", "claude_code_version": "2.1.173", "model": "claude-sonnet-4-6",
			"permissionMode": "default", "apiKeySource": "none",
			"tools":  []string{"Task", "Bash", "Agent"},
			"agents": []string{"claude", "general-purpose", "Explore"},
		})
	}

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		switch msg["type"] {
		case "control_response":
			// The host answered the held ask. Read the behavior, emit the matching
			// tool_result and the turn's final assistant + result.
			resp, _ := msg["response"].(map[string]any)
			inner, _ := resp["response"].(map[string]any)
			behavior, _ := inner["behavior"].(string)
			isErr := behavior != "allow"
			content := "(Bash completed)"
			if isErr {
				content = "Denied by the live-drive conformance scenario."
			}
			emit(map[string]any{
				"type": "user", "session_id": session, "uuid": nextUUID(),
				"message": map[string]any{"role": "user", "content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "toolu_FAKEASK000000000001",
						"is_error": isErr, "content": content},
				}},
			})
			emit(map[string]any{
				"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
				"message": map[string]any{"id": "msg_fake_ask", "type": "message", "role": "assistant",
					"model": "claude-sonnet-4-6", "stop_reason": "end_turn",
					"content": []any{map[string]any{"type": "text", "text": "Done."}}},
			})
			emit(map[string]any{
				"type": "result", "subtype": "success", "session_id": session, "uuid": nextUUID(),
				"is_error": false, "num_turns": 2, "result": "Done.", "total_cost_usd": 0,
			})
			out.Flush()
			os.Exit(0)

		case "user":
			turn++
			emitInit()
			if turn == 1 {
				// Turn 1: assistant chat + an Agent spawn (tool_use + task_started →
				// subagent.spawned), then a result. The session stays alive.
				emit(map[string]any{
					"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
					"message": map[string]any{"id": "msg_fake_1", "type": "message", "role": "assistant",
						"model": "claude-sonnet-4-6", "stop_reason": "tool_use",
						"content": []any{
							map[string]any{"type": "text", "text": "Hello — I am a scripted conformance fake."},
							map[string]any{"type": "tool_use", "id": "toolu_FAKESPAWN00000000001",
								"name": "Agent", "input": map[string]any{"description": "trivial subtask",
									"subagent_type": "general-purpose", "prompt": "do a trivial thing"}},
						}},
				})
				emit(map[string]any{
					"type": "system", "subtype": "task_started", "session_id": session, "uuid": nextUUID(),
					"task_id": "fa5ktask00000001", "tool_use_id": "toolu_FAKESPAWN00000000001",
					"task_type": "local_agent", "subagent_type": "general-purpose",
					"description": "trivial subtask", "prompt": "do a trivial thing",
				})
				emit(map[string]any{
					"type": "system", "subtype": "task_notification", "session_id": session, "uuid": nextUUID(),
					"task_id": "fa5ktask00000001", "tool_use_id": "toolu_FAKESPAWN00000000001",
					"subagent_type": "general-purpose",
					"usage":         map[string]any{"total_tokens": 42, "tool_uses": 1, "duration_ms": 100},
					"summary":       "did the trivial thing",
				})
				emit(map[string]any{
					"type": "result", "subtype": "success", "session_id": session, "uuid": nextUUID(),
					"is_error": false, "num_turns": 1, "result": "introduced + dispatched", "total_cost_usd": 0,
				})
			} else {
				// Turn 2: an assistant Bash tool_use, then a NATIVE can_use_tool
				// control_request the host must answer (HELD — no tool_result until
				// the control_response arrives, DRIVE-FINDINGS §1a socket-hold).
				emit(map[string]any{
					"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
					"message": map[string]any{"id": "msg_fake_2", "type": "message", "role": "assistant",
						"model": "claude-sonnet-4-6", "stop_reason": "tool_use",
						"content": []any{map[string]any{"type": "tool_use", "id": "toolu_FAKEASK000000000001",
							"name": "Bash", "input": map[string]any{"command": "mkdir -p /work/scratch && echo seeded > /work/scratch/seed.txt"}}}},
				})
				emit(map[string]any{
					"type": "control_request", "request_id": "creq-fake-0000000000000001",
					"request": map[string]any{"subtype": "can_use_tool", "tool_name": "Bash",
						"display_name": "Bash",
						"input":        map[string]any{"command": "mkdir -p /work/scratch && echo seeded > /work/scratch/seed.txt"},
						"tool_use_id":  "toolu_FAKEASK000000000001",
						"permission_suggestions": []any{map[string]any{"type": "addRules",
							"rules":    []any{map[string]any{"toolName": "Bash", "ruleContent": "mkdir -p /work/scratch"}},
							"behavior": "allow", "destination": "localSettings"}},
					},
				})
				// HOLD: do not emit the tool_result here — wait for the host's
				// control_response (handled in the control_response case above).
				_ = mode
			}
		}
	}
	out.Flush()
}

// ensure the helper symbols are referenced so the file compiles cleanly even if a
// future refactor drops a usage.
var _ = hostbridge.GrantRouteNativeControl
