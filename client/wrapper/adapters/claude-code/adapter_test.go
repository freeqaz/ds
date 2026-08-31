// adapter_test.go — foundation-owned tests: envelope decode, header skip,
// dispatch warnings, seq/Source/clock stamping, init projection. Area
// behavior (classify/tree/state/ask) is covered by the area owners' tests
// and the goldentrace golden suite — nothing here asserts on stub emptiness.
package claudecode

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

const initLine = `{"type":"system","subtype":"init","session_id":"00000000-0000-4000-8000-000000000001","uuid":"00000000-0000-4000-8000-0000000000a0","cwd":"/work","claude_code_version":"2.1.173","model":"claude-sonnet-4-6","permissionMode":"default","apiKeySource":"none","output_style":"default","fast_mode_state":"off","tools":["Task","Bash"],"agents":["claude","echoer"],"slash_commands":["/verify"],"skills":["verify"],"plugins":[],"mcp_servers":[],"memory_paths":{"auto":"/work/.memory/"},"analytics_disabled":false,"product_feedback_disabled":false}`

func testClock() func() time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := 0
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

func TestFeedSkipsFixtureHeader(t *testing.T) {
	a := New()
	evs, err := a.Feed([]byte(`{"ds_fixture":{"provenance":"synthetic","seam":"attach.cc-wire","created":"2026-06-12","tool":"goldentrace"}}`))
	if err != nil {
		t.Fatalf("Feed(header) error: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("Feed(header) emitted %d events, want 0", len(evs))
	}
	if w := a.Warnings(); len(w) != 0 {
		t.Fatalf("Feed(header) warned: %v", w)
	}
}

func TestFeedSkipsBlankLines(t *testing.T) {
	a := New()
	for _, line := range []string{"", "   ", "\t"} {
		evs, err := a.Feed([]byte(line))
		if err != nil || len(evs) != 0 {
			t.Fatalf("Feed(%q) = %v, %v; want no events, no error", line, evs, err)
		}
	}
}

func TestFeedRejectsUndecodableLine(t *testing.T) {
	a := New()
	if _, err := a.Feed([]byte(`{"type":`)); err == nil {
		t.Fatal("Feed(truncated JSON) returned nil error, want error")
	}
}

func TestFeedInitProjectsSessionInit(t *testing.T) {
	a := New(WithClock(testClock()))
	evs, err := a.Feed([]byte(initLine))
	if err != nil {
		t.Fatalf("Feed(init) error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("Feed(init) emitted %d events, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Type != attach.TypeSessionInit || ev.SessionInit == nil {
		t.Fatalf("Feed(init) emitted %+v, want a session.init payload", ev)
	}
	if ev.Seq != 1 {
		t.Errorf("seq = %d, want 1", ev.Seq)
	}
	if ev.SessionID != "00000000-0000-4000-8000-000000000001" {
		t.Errorf("session_id = %q", ev.SessionID)
	}
	if want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); !ev.ObservedAt.Equal(want) {
		t.Errorf("observed_at = %v, want %v (deterministic clock)", ev.ObservedAt, want)
	}
	if len(ev.Source) != 1 || ev.Source[0] != "00000000-0000-4000-8000-0000000000a0" {
		t.Errorf("source = %v, want the init record uuid", ev.Source)
	}
	si := ev.SessionInit
	if si.RuntimeVersion != "2.1.173" || si.Model != "claude-sonnet-4-6" || si.CWD != "/work" ||
		si.PermissionMode != "default" || si.APIKeySource != "none" || si.OutputStyle != "default" {
		t.Errorf("session_init scalar fields mismapped: %+v", si)
	}
	if len(si.Tools) != 2 || len(si.AgentTypes) != 2 || len(si.Skills) != 1 || len(si.SlashCommands) != 1 {
		t.Errorf("session_init registries mismapped: %+v", si)
	}
	if !a.initSeen {
		t.Error("initSeen not latched")
	}
	if _, ok := a.agentTypes["echoer"]; !ok {
		t.Error("agentTypes allowlist not seeded from init.agents[]")
	}
	if _, ok := a.skills["verify"]; !ok {
		t.Error("skills allowlist not seeded from init.skills[]")
	}
}

func TestFeedUnknownTypesWarnNeverError(t *testing.T) {
	a := New()
	lines := []string{
		`{"type":"hologram","uuid":"00000000-0000-4000-8000-0000000000b1","session_id":"00000000-0000-4000-8000-000000000001"}`,
		`{"type":"system","subtype":"daydream","uuid":"00000000-0000-4000-8000-0000000000b2","session_id":"00000000-0000-4000-8000-000000000001"}`,
	}
	for _, line := range lines {
		evs, err := a.Feed([]byte(line))
		if err != nil {
			t.Fatalf("Feed(%s) error: %v (unknown records must skip, not crash)", line, err)
		}
		if len(evs) != 0 {
			t.Fatalf("Feed(unknown) emitted %d events, want 0", len(evs))
		}
	}
	w := a.Warnings()
	if len(w) != 2 {
		t.Fatalf("Warnings() = %v, want 2 entries", w)
	}
	if !strings.Contains(w[0], "hologram") || !strings.Contains(w[1], "daydream") {
		t.Errorf("warnings do not name the skipped types: %v", w)
	}
}

func TestProcessStreamReplaysCommittedCassette(t *testing.T) {
	f, err := os.Open("../../../fixtures/subagent-spawn.cc-wire.ndjson")
	if err != nil {
		t.Fatalf("open committed cassette: %v", err)
	}
	defer f.Close()

	a := New(WithClock(testClock()))
	evs, err := a.ProcessStream(f)
	if err != nil {
		t.Fatalf("ProcessStream error: %v", err)
	}
	if len(evs) == 0 {
		t.Fatal("ProcessStream emitted no events; the init record alone must project")
	}
	if evs[0].Type != attach.TypeSessionInit {
		t.Errorf("first event type = %q, want %q", evs[0].Type, attach.TypeSessionInit)
	}
	for i, ev := range evs {
		if ev.Seq != uint64(i+1) {
			t.Errorf("event %d: seq = %d, want %d (monotonic from 1 in emission order)", i, ev.Seq, i+1)
		}
		if ev.SessionID == "" {
			t.Errorf("event %d: empty session_id", i)
		}
	}
}

func TestExcerpt(t *testing.T) {
	if got := excerpt("short"); got != "short" {
		t.Errorf("excerpt(short) = %q", got)
	}
	long := strings.Repeat("é", 300)
	got := excerpt(long)
	if runes := []rune(got); len(runes) != 257 || runes[256] != '…' {
		t.Errorf("excerpt(300 runes) = %d runes ending %q, want 256 + …", len(runes), runes[len(runes)-1])
	}
}
