package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadGolden(t *testing.T, base string) []byte {
	t.Helper()
	p := filepath.Join(replayGoldenDir, base+".attach.ndjson")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}

// TestBaselineChatModel: the baseline-chat cassette folds into a clean
// transcript with the session terminal and no asks (the simplest path).
func TestBaselineChatModel(t *testing.T) {
	m, _, err := BuildModel(strings.NewReader(string(loadGolden(t, "baseline-chat"))), RoleReader, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if m.Init == nil || m.Init.Model == "" {
		t.Fatalf("expected session.init with a model, got %+v", m.Init)
	}
	if len(m.PendingAsks()) != 0 || m.Parked() {
		t.Errorf("baseline-chat should have no pending asks / not be parked")
	}
	if m.Accounting == nil || m.Accounting.Outcome != "success" {
		t.Errorf("expected success accounting, got %+v", m.Accounting)
	}
	// Resume token must advance to the last event's seq.
	if m.LastSeq() == 0 {
		t.Errorf("LastSeq should be non-zero after folding")
	}
}

// TestAskControlFlow exercises the approval surface over the ask-control
// fixture: asks render as allow-once/allow-always-proposal/deny prompts, an
// unanswered ask parks the session (never times out into allow/kill), and a
// human decision is recorded WITHOUT storing a grant (D45/D53).
func TestAskControlFlow(t *testing.T) {
	src := string(loadGolden(t, "ask-control"))

	// 1. Full fold: the cassette includes wire ask.resolved events, so by the
	//    end no ask is pending (the runtime answered them on the wire).
	full, _, err := BuildModel(strings.NewReader(src), RoleWriter, 0)
	if err != nil {
		t.Fatalf("build full: %v", err)
	}
	if len(full.Asks) < 2 {
		t.Fatalf("ask-control should surface at least 2 asks, got %d", len(full.Asks))
	}
	if full.Parked() {
		t.Errorf("after full fold (wire resolved both asks) the session must not be parked")
	}
	// Both asks must have closed via a wire resolution.
	for _, a := range full.Asks {
		if a.State != AskResolved {
			t.Errorf("ask %s state = %s, want resolved (wire ask.resolved present)", a.AskID, a.State)
		}
	}

	// 2. Park semantics: fold only up to the first ask.requested (before its
	//    resolution) and confirm the session PARKS on the pending ask.
	parked := NewModel()
	stream := &ndjsonStream{dec: jsonDecoder(src)}
	for {
		ev, err := stream.Next()
		if err != nil {
			break
		}
		if err := parked.Apply(ev); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if len(parked.PendingAsks()) > 0 {
			break // stop at the first pending ask, before its resolution
		}
	}
	if !parked.Parked() {
		t.Fatalf("expected the session to be PARKED on the first pending ask")
	}
	pending := parked.PendingAsks()
	ask := pending[0]

	// 3. The prompt render names all three D45 options and flags the proposal.
	prompt := formatAsk(ask)
	for _, want := range []string{"allow-once", "allow-always(PROPOSAL)", "deny"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("ask prompt %q missing option %q", prompt, want)
		}
	}

	// 4. Answer it allow-once: the ask is recorded answered, NOT a stored grant.
	if _, err := parked.AnswerAsk(ask.AskID, DecisionAllowOnce); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if ask.State != AskAnswered || ask.Decision != DecisionAllowOnce {
		t.Errorf("after answer: state=%s decision=%s, want answered/allow-once", ask.State, ask.Decision)
	}
	if parked.Parked() {
		t.Errorf("after answering the only pending ask the session must un-park")
	}

	// 5. allow-always is a PROPOSAL, never a grant.
	if !DecisionAllowAlways.IsProposal() {
		t.Errorf("allow-always must report as a proposal (D45)")
	}
	if DecisionAllowOnce.IsProposal() || DecisionDeny.IsProposal() {
		t.Errorf("only allow-always is a proposal")
	}
}

// TestSubagentTreeDepth: the nested-spawn cassette threads parent links into
// render depth (the D18 per-call hierarchy). subagent-spawn (flat) stays depth
// 0; nested-spawn's inner node renders one level deeper than its outer parent.
func TestSubagentTreeDepth(t *testing.T) {
	// Flat spawn: no depth.
	flat, _, err := BuildModel(strings.NewReader(string(loadGolden(t, "subagent-spawn"))), RoleReader, 0)
	if err != nil {
		t.Fatalf("build subagent-spawn: %v", err)
	}
	for _, ln := range flat.Lines {
		if ln.Depth != 0 {
			t.Errorf("subagent-spawn line %q has depth %d, want 0 (flat)", ln.Text, ln.Depth)
		}
	}

	// Nested spawn: an inner node deeper than its outer parent.
	nested, _, err := BuildModel(strings.NewReader(string(loadGolden(t, "nested-spawn"))), RoleReader, 0)
	if err != nil {
		t.Fatalf("build nested-spawn: %v", err)
	}
	maxDepth := 0
	for _, ln := range nested.Lines {
		if ln.Depth > maxDepth {
			maxDepth = ln.Depth
		}
	}
	if maxDepth < 1 {
		t.Errorf("nested-spawn should render at least depth 1 (inner under outer), got max %d", maxDepth)
	}
}

// TestResumeBySeq: re-attaching with fromSeq skips the already-rendered prefix,
// so the resume token (per-event Seq, doc 15 §6.1 row 1) works end to end.
func TestResumeBySeq(t *testing.T) {
	src := string(loadGolden(t, "baseline-chat"))
	full, _, err := BuildModel(strings.NewReader(src), RoleReader, 0)
	if err != nil {
		t.Fatalf("build full: %v", err)
	}
	// Resume from the 3rd event: the tail model must start after seq 3.
	tail, _, err := BuildModel(strings.NewReader(src), RoleReader, 3)
	if err != nil {
		t.Fatalf("build tail: %v", err)
	}
	if len(tail.Lines) == 0 {
		t.Fatalf("tail should still have events after seq 3")
	}
	if got := tail.Lines[0].Seq; got <= 3 {
		t.Errorf("resume tail first line seq = %d, want > 3", got)
	}
	if full.LastSeq() != tail.LastSeq() {
		t.Errorf("full and resumed tail must reach the same LastSeq (%d vs %d)", full.LastSeq(), tail.LastSeq())
	}
}

// TestSeqMonotonicityEnforced: the model is the in-order consumer; an
// out-of-order/duplicate seq is a contract violation, surfaced not swallowed.
func TestSeqMonotonicityEnforced(t *testing.T) {
	m := NewModel()
	if err := m.Apply(ev(2, "session.state")); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := m.Apply(ev(2, "session.state")); err == nil {
		t.Errorf("duplicate seq 2 should error (ordering authority is the wrapper, P10)")
	}
	if err := m.Apply(ev(1, "session.state")); err == nil {
		t.Errorf("out-of-order seq 1 after 2 should error")
	}
}
