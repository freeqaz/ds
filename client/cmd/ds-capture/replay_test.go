// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/cmd/ds-capture/internal/cassette"
)

func startReplayer(t *testing.T, cas *cassette.Cassette, strict, passthrough bool) (*replayer, string, func()) {
	t.Helper()
	rp, err := newReplayer(cas, strict, passthrough, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	srv, addr, err := rp.listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("replayer listen: %v", err)
	}
	go func() { _ = srv.Serve(rp.ln) }()
	return rp, addr, func() {
		_ = srv.Close()
		rp.cleanup()
	}
}

// TestReplayHitFromTestdata loads the synthetic testdata cassette and replays
// the first turn, asserting the recorded SSE comes back and NO upstream is
// dialed (hermetic).
func TestReplayHitFromTestdata(t *testing.T) {
	cas, err := cassette.Load("testdata/synthetic-basic.json")
	if err != nil {
		t.Fatalf("load testdata: %v", err)
	}
	rp, addr, stop := startReplayer(t, cas, true, false)
	defer stop()
	client := proxyClient(t, addr, rp.caCertPath)

	body := `{"model":"claude-synthetic-test-1","system":"You are a synthetic test fixture. No real model, no real text.","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("replay request: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("replay hit status: got %d want 200", resp.StatusCode)
	}
	if !strings.Contains(string(got), "Hello from the synthetic cassette.") {
		t.Errorf("replayed body missing synthetic text:\n%s", got)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Errorf("content-type not served: %q", resp.Header.Get("Content-Type"))
	}
	if rp.dialedUpstream {
		t.Error("replay hit dialed upstream — hermetic guarantee broken")
	}
}

// TestReplayStrictMissReturns502 proves a cassette miss in strict mode returns
// the synthetic 502 cia_replay_miss-equivalent JSON OFFLINE — never dialing.
func TestReplayStrictMissReturns502(t *testing.T) {
	cas, err := cassette.Load("testdata/synthetic-basic.json")
	if err != nil {
		t.Fatalf("load testdata: %v", err)
	}
	rp, addr, stop := startReplayer(t, cas, true, false)
	defer stop()
	client := proxyClient(t, addr, rp.caCertPath)

	// A request that matches no interaction.
	body := `{"model":"claude-synthetic-test-1","system":"different system","messages":[{"role":"user","content":"unknown turn"}],"stream":true}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("replay miss request: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("strict miss status: got %d want 502", resp.StatusCode)
	}
	var payload struct {
		Type  string `json:"type"`
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("miss body not JSON: %v (%s)", err, raw)
	}
	if payload.Type != "error" || payload.Error.Type != "cia_replay_miss" {
		t.Errorf("strict miss payload mismatch: %s", raw)
	}
	if rp.dialedUpstream {
		t.Error("strict miss dialed upstream — hermetic guarantee broken")
	}
}

// TestReplayNeverDialsUpstreamStrict is the explicit hermetic test: across a
// hit AND a miss, strict-mode replay records zero upstream dial attempts.
func TestReplayNeverDialsUpstreamStrict(t *testing.T) {
	cas, err := cassette.Load("testdata/synthetic-basic.json")
	if err != nil {
		t.Fatalf("load testdata: %v", err)
	}
	rp, addr, stop := startReplayer(t, cas, true, false)
	defer stop()
	client := proxyClient(t, addr, rp.caCertPath)

	// A hit and a miss back to back.
	hit := `{"model":"claude-synthetic-test-1","system":"You are a synthetic test fixture. No real model, no real text.","messages":[{"role":"user","content":"say hi"}],"stream":true}`
	miss := `{"model":"claude-synthetic-test-1","messages":[{"role":"user","content":"nope"}],"stream":true}`
	for _, b := range []string{hit, miss} {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(b))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("replay request: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if rp.dialedUpstream {
		t.Fatal("strict replay dialed upstream across hit+miss — NOT hermetic")
	}
}

// TestReplayPassthroughOverridesStrict confirms the documented non-D50 escape
// hatch: --passthrough disables strict so a miss is forwarded. We do NOT
// exercise a real upstream (no network in tests); we assert only that
// passthrough turns off strict mode so the dispatcher would forward — verified
// via the constructed replayer's flags, not a live dial.
func TestReplayPassthroughOverridesStrict(t *testing.T) {
	cas := cassette.New()
	rp, err := newReplayer(cas, true /*strict*/, true /*passthrough*/, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	defer rp.cleanup()
	if rp.strict {
		t.Error("passthrough must override strict (strict should be false)")
	}
	if !rp.passthrough {
		t.Error("passthrough flag not set")
	}
}

// TestReplayDefaultPortRefusesProtected asserts the never-:18080 invariant on
// the replay path too.
func TestReplayDefaultPortRefusesProtected(t *testing.T) {
	rp, err := newReplayer(cassette.New(), true, false, "")
	if err != nil {
		t.Fatalf("newReplayer: %v", err)
	}
	defer rp.cleanup()
	if _, _, err := rp.listen("127.0.0.1", ProtectedMonitorPort); err == nil {
		t.Fatal("replayer.listen(:18080) must refuse")
	}
}
