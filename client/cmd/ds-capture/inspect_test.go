// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/cmd/ds-capture/internal/cassette"
)

// TestInspectSummarizesCassette proves inspect prints the version, interaction
// count, per-interaction key/model/turns/status and the SSE event types — the
// folded thin slice of cia report (no analytics).
func TestInspectSummarizesCassette(t *testing.T) {
	cas, err := cassette.Load("testdata/synthetic-basic.json")
	if err != nil {
		t.Fatalf("load testdata: %v", err)
	}
	var sb strings.Builder
	writeInspect(&sb, cas)
	out := sb.String()

	for _, want := range []string{
		"cassette version: 1",
		"interactions: 2",
		"claude-synthetic-test-1|turns=1|say hi|",
		"model:   claude-synthetic-test-1",
		"turns:   1",
		"status:  200",
		"events:",       // SSE event types listed
		"message_start", // a known synthetic event
		"content-type: text/event-stream",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect output missing %q\n--- output ---\n%s", want, out)
		}
	}
}
