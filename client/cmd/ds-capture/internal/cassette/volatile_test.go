// SPDX-License-Identifier: Apache-2.0

package cassette

import (
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------- //
// volatileRequestHeaders completeness pin (HARDENING-NOTES §2.2)          //
// ---------------------------------------------------------------------- //
//
// volatileRequestHeaders is the single source the three scrub walls key on:
// the replay --passthrough scrub, the `scrub` subcommand (via the exported
// cassette.VolatileRequestHeader), and the tolerant matcher's request-header
// drop. The residual risk those three share is SILENT SET DRIFT — a §2.2
// header-level tell quietly dropped from the set would let a real auth value
// survive a scrub with no test going red. This file pins the set to
// HARDENING-NOTES §2.2 (the governing scrub contract) so any drift fails
// closed: remove a §2.2-named header from the set and TestVolatileSetMatches
// HardeningS22 fails NAMING the missing header.
//
// NEVER-LOG-THE-SECRET (HARDENING-NOTES §2.2 / §2.4): these assertions reason
// about header NAMES and set membership only. No assertion in this file
// constructs, carries, or prints a token/credential VALUE; a failure reports
// the offending HEADER NAME and a §2.2 citation, never bytes.
//
// WHY ONLY HEADER-LEVEL TELLS LIVE HERE. HARDENING-NOTES §2.2 lists two
// classes of real-environment data. This set governs exactly the FIRST class —
// request HEADERS whose mere name/value the cassette must not retain:
//
//	Authorization, x-api-key (the credential itself),
//	anthropic-beta (the auth-method tell),
//	X-Claude-Code-Session-Id, x-client-request-id (correlatable id headers).
//
// The SECOND class §2.2 names — the agentId/task_id hex in subagent result
// trailers, real cwd/memory_paths, and total_cost_usd — are NOT header strips
// and deliberately are NOT in volatileRequestHeaders. They live inside the
// JSON request/response BODY, so removing them is a body RE-AUTHORING concern
// (raw → re-authored synthetic, §2.3's one-directional flow), not a transport-
// header drop. Folding them into a header set would be a category error: the
// matcher and the header scrub operate on header names, and a body field can
// never be neutralized by dropping a header. They are therefore excluded by
// design, not by oversight.

// hardeningS22HeaderTells is the §2.2/§2.4 header-level scrub list, derived
// straight from HARDENING-NOTES.md §2.2 ("Redaction / scrub rules for auth
// headers") and the §2.4 checklist. It is the EXPECTED membership of
// volatileRequestHeaders' §2.2-mandated core: every name here must report true
// from VolatileRequestHeader, and every name here must be present in the live
// set. Lowercased because VolatileRequestHeader matches case-insensitively.
var hardeningS22HeaderTells = []string{
	"authorization",            // §2.2: the credential itself (Bearer sk-ant-oat01-…)
	"x-api-key",                // §2.2: the credential on an API-key box
	"anthropic-beta",           // §2.2: auth-method tell (e.g. oauth-2025-04-20)
	"x-claude-code-session-id", // §2.2: == SDK session_id, correlatable identifier
	"x-client-request-id",      // §2.2: correlatable identifier
}

// TestVolatileHeaderTellsAreVolatile asserts every HARDENING-NOTES §2.2/§2.4
// header-level tell reports volatile case-insensitively, and that content-type
// — the one replay-relevant header the matcher must KEEP (it picks the
// streaming path, cassette.go replayHeaderAllow) — does not. Table-driven so a
// dropped tell fails on its own row.
func TestVolatileHeaderTellsAreVolatile(t *testing.T) {
	cases := []struct {
		name string
		want bool
		why  string
	}{
		// Every §2.2/§2.4 header-level tell, each spelled in a different case
		// to prove the case-insensitive contract of VolatileRequestHeader.
		{"Authorization", true, "§2.2: the credential itself"},
		{"X-Api-Key", true, "§2.2: the credential on an API-key box"},
		{"ANTHROPIC-BETA", true, "§2.2: auth-method tell"},
		{"X-Claude-Code-Session-Id", true, "§2.2: == SDK session_id"},
		{"x-client-request-id", true, "§2.2: correlatable identifier"},
		// content-type is the lone replay-relevant header the matcher keeps;
		// it must NOT be volatile or replay loses the streaming-path signal.
		{"content-type", false, "§ replayHeaderAllow: kept for replay fidelity"},
		{"Content-Type", false, "§ replayHeaderAllow: case-insensitive keep"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := VolatileRequestHeader(tc.name); got != tc.want {
				// Report the header NAME and the expectation only — never a value.
				t.Errorf("VolatileRequestHeader(%q) = %v, want %v (%s)",
					tc.name, got, tc.want, tc.why)
			}
		})
	}
}

// TestVolatileSetMatchesHardeningS22 is the COMPLETENESS leg: it pins the
// §2.2-derived expected header list against the live volatileRequestHeaders
// set, failing with the missing/extra HEADER NAME (names only) and a §2.2
// citation. This is the drift teeth — removing any §2.2-named header from the
// set makes this test fail naming exactly that header.
//
// Direction asymmetry is deliberate:
//   - Every §2.2 tell MUST be present (missing one = a credential/correlatable
//     header could survive a scrub → fail closed, hard error).
//   - The live set is a SUPERSET: it also carries cia's _VOLATILE_REQUEST_
//     HEADERS transport noise (request-id, user-agent, date, cookie, …) that
//     §2.2 does not enumerate. Those extras are expected and benign — the test
//     pins the §2.2 floor, not an exact equality, so cassette.go may keep
//     dropping additional volatile transport headers without this going red.
func TestVolatileSetMatchesHardeningS22(t *testing.T) {
	// 1. Completeness: every §2.2 header-level tell is in the live set.
	var missing []string
	for _, h := range hardeningS22HeaderTells {
		if !VolatileRequestHeader(h) {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		// Names only — never a token value. A missing §2.2 header means a real
		// auth/correlatable header could survive scrub; fail closed.
		t.Errorf("volatileRequestHeaders is missing HARDENING-NOTES §2.2 "+
			"header-level scrub tell(s): %s — re-add to cassette.go's "+
			"volatileRequestHeaders so the passthrough scrub / scrub subcommand "+
			"/ matcher keep dropping them (HARDENING-NOTES.md §2.2)",
			strings.Join(missing, ", "))
	}

	// 2. Sanity floor: content-type, the kept replay header, must stay OUT of
	//    the volatile set (the inverse drift — folding a kept header in would
	//    silently break replay's streaming-path selection).
	if VolatileRequestHeader("content-type") {
		t.Errorf("content-type unexpectedly volatile: it is the one replay-" +
			"relevant header the matcher keeps (cassette.go replayHeaderAllow); " +
			"it must never join volatileRequestHeaders")
	}
}
