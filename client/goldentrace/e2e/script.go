// SPDX-License-Identifier: Apache-2.0

// script.go — the SCRIPTED multi-turn headless-drive scenario. Where
// driveChatSpawnAskScenario / drivePromptScenario (live_drive.go) pin a single
// fixed conversation, this file makes a Claude Code session drivable headlessly
// from a DATA file: a newline-delimited-JSON (JSONL) script, one Turn per line,
// stepped over the SAME DriveLiveSocketBridge engine and the SAME thin-client
// surface (DriveText / GrantAsk over the framed UDS).
//
// THE LOOP (per turn N, reusing the live_drive.go thin client verbatim):
//  1. DriveText(turn.Prompt)            — drive the turn's prompt as attach.v1 input;
//  2. poll for an ask OR the turn's result together (the drivePromptScenario
//     idiom): on an ask.requested, answer it on the PROVEN attach.v1 grant path
//     (GrantAsk allow|deny per turn.Allow) — the wrapper turns the grant into
//     CC's control_response INSIDE the boundary, never --dangerously-skip-permissions;
//  3. advance when the turn reaches its result (session.accounted), then step
//     to the next line, to end-of-script.
//
// It names NO CC-ism: a Turn is {prompt, allow, assert}, and the stepping speaks
// only attach.v1. It is exercised OFFLINE against the fake-CC driveFakeSocketBridge
// (script_test.go, ungated, runs in the wave gate) and arms the same code against
// real CC behind DS_E2E_LIVE=1 (the side-effect scripted-drive test). The live
// scenario code is transport-agnostic: it retargets to the KVM tier (taskdb
// 01KV8YSY8N) once the AttachPrimitive keystone (01KV8XSNEX) lands — a
// transport-config swap only, no scenario change (LIVE-VALIDATION.md).
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Turn is one step of a scripted headless drive: a prompt to drive and the grant
// decision to answer any tool ask the prompt provokes with. It is runtime-ignorant
// (no CC vocabulary): Prompt is an attach.v1 input, Allow is the allow/deny answer
// on the policy-stream grant path, and Assert is the optional VM-side-effect the
// gated live test checks AFTER the run.
type Turn struct {
	// Prompt is the user text driven into the session this turn (attach.v1 input).
	// Empty Prompt is a parse error — a turn must drive something.
	Prompt string `json:"prompt"`
	// Allow answers the turn's tool ask: true ⇒ a behavior "allow" grant (echo the
	// tool input, P8), false ⇒ a behavior "deny" grant carrying DenyMessage. A turn
	// that provokes no ask ignores this (the turn just reaches its result).
	Allow bool `json:"allow"`
	// DenyMessage is the deny reason propagated verbatim into the is_error
	// tool_result when Allow is false (P8). Optional; a default is supplied.
	DenyMessage string `json:"deny_message,omitempty"`
	// Assert is the optional VM-side-effect expectation the gated live test checks
	// after the drive completes (e.g. a proof file under /work containing a token).
	// It is NEVER asserted by the offline fake path (no real container fs); it is
	// the load-bearing "CC actually executed the instruction" check on the live leg.
	Assert *TurnAssert `json:"assert,omitempty"`
}

// TurnAssert is a deterministic VM-side-effect expectation: after the scripted
// drive, the proof file at File (relative to the drive's workdir) must exist and
// contain Contains. It is the side-effect half of the headless-drive proof — the
// projected attach.v1 result events prove the protocol round-trip; the proof file
// proves CC ran the instruction in the container/guest, not just streamed text.
type TurnAssert struct {
	// File is the proof file path the turn's prompt instructs CC to write,
	// relative to the drive workdir (e.g. "ds-headless-proof.txt"). The live test
	// resolves it against the host side of the /work bind mount.
	File string `json:"file"`
	// Contains is the token the proof file must contain (a deterministic marker the
	// prompt embeds), proving the instruction executed end to end.
	Contains string `json:"contains"`
}

// ParseScript parses a newline-delimited-JSON (JSONL) drive script: one JSON Turn
// object per non-blank line ({"prompt":…,"allow":…,"assert":{…}}). Blank lines and
// lines whose first non-space byte is '#' (comments) are skipped, so a committed
// fixture can be self-documenting. It is STRICT on the Turn shape (DisallowUnknownFields)
// so a typo'd key is a loud parse error, never a silently-ignored field, and it
// rejects an empty Prompt (a turn must drive something) and an empty script (a
// drive with no turns is a caller error). Stdlib-only.
func ParseScript(r io.Reader) ([]Turn, error) {
	sc := bufio.NewScanner(r)
	// A turn line can carry a long prompt + assert; raise the cap above the 64KiB
	// default (matching the harness's stdout cap rationale).
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	var turns []Turn
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 || raw[0] == '#' {
			continue // blank or comment line
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var t Turn
		if err := dec.Decode(&t); err != nil {
			return nil, fmt.Errorf("e2e: drive script line %d: %w", lineNo, err)
		}
		if strings.TrimSpace(t.Prompt) == "" {
			return nil, fmt.Errorf("e2e: drive script line %d: empty prompt (a turn must drive a prompt)", lineNo)
		}
		if t.Assert != nil {
			if t.Assert.File == "" || t.Assert.Contains == "" {
				return nil, fmt.Errorf("e2e: drive script line %d: assert requires both file and contains", lineNo)
			}
		}
		turns = append(turns, t)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("e2e: read drive script: %w", err)
	}
	if len(turns) == 0 {
		return nil, errors.New("e2e: drive script has no turns (empty or all-comment)")
	}
	return turns, nil
}

// DriveScriptScenario builds a driveScenario that steps the given turns over the
// thin client, in order, to end-of-script. It is the multi-turn generalization of
// drivePromptScenario: for each turn it drives the prompt, then polls for an ask
// OR the turn's result together (so a no-tool turn returns promptly instead of
// stalling on an ask deadline), answers EVERY not-yet-granted ask the turn provokes
// on the grant path per the turn's Allow (a turn that drives two gated tools — e.g.
// Read then Edit — surfaces two asks in sequence; answering only the first would
// stall the second until the deadline), and advances on the turn's session.accounted
// before stepping to the next. It speaks ONLY attach.v1 — every CC-ism stays behind the
// wrapper across the UDS — so the SAME scenario drives the fake-CC fleet path and
// the real container, and retargets to the KVM tier unchanged.
//
// perTurnTimeout bounds each turn's wait for its result; zero ⇒ a sensible default.
func DriveScriptScenario(turns []Turn, perTurnTimeout time.Duration) driveScenario {
	if perTurnTimeout <= 0 {
		perTurnTimeout = 120 * time.Second
	}
	return func(ctx context.Context, tc *thinClient) error {
		// session.accounted accumulates across turns (one live CC process, sustained;
		// a fresh result per driven input, DRIVE-FINDINGS §3). We track how many we
		// have seen so each turn waits for ITS result (the running count crossing the
		// turn index), not merely "at least one".
		//
		// The thin client's snapshot() returns the WHOLE event history, so prior
		// turns' ask.requested events stay visible. We must therefore join on the
		// ask id, never on position: an ask is answerable iff we have not already
		// granted THAT ask id. A running counter (answered<=i) is not enough — on a
		// later turn it would re-grab the first (already-resolved) ask in the
		// history and re-grant a stale request id while the live turn's own ask goes
		// unanswered and stalls. Real CC joins the grant on the control request id,
		// so the stale-id re-grant is a live-leg hazard the fake-CC (which ignores
		// the id) would not surface.
		grantedAsks := make(map[string]bool) // ask ids already answered, by AskID
		for i, turn := range turns {
			if err := tc.DriveText(turn.Prompt); err != nil {
				return fmt.Errorf("drive turn %d: %w", i+1, err)
			}
			wantResults := i + 1 // this turn's result is the (i+1)-th session.accounted
			deadline := time.Now().Add(perTurnTimeout)
			for {
				// A single turn can provoke MORE THAN ONE ask: a prompt that drives a
				// Read AND an Edit (or any two gated tools) surfaces two ask.requested
				// in the same turn, in sequence — the second only after the first is
				// answered and its tool runs. Answering at most one ask per turn would
				// leave the second tool blocked, stalling the turn until the deadline
				// (proven live: a Read→Edit/Bash turn hangs at the per-turn timeout).
				// So we answer EVERY not-yet-granted ask we see this poll — the turn's
				// single Allow/Deny decision applies to each tool it gates — and join on
				// the ask id so a later turn never re-answers an earlier turn's already-
				// resolved ask (the whole history is visible in the snapshot; real CC
				// joins the grant on the control request id, a stale-id re-grant the
				// fake-CC, which ignores the id, would not surface).
				type openAsk struct {
					askID, nodeID string
					input         []byte
				}
				var pending []openAsk
				results := 0
				for _, ev := range tc.snapshot() {
					switch {
					case ev.Type == attach.TypeAskRequested && ev.AskRequested != nil:
						if !grantedAsks[ev.AskRequested.AskID] {
							pending = append(pending, openAsk{
								askID:  ev.AskRequested.AskID,
								nodeID: ev.AskRequested.NodeID,
								input:  ev.AskRequested.Input,
							})
						}
					case ev.Type == attach.TypeSessionAccounted:
						results++
					}
				}
				for _, a := range pending {
					var updatedInput []byte
					denyMsg := ""
					if turn.Allow {
						updatedInput = a.input // echo the tool input on allow (P8)
					} else {
						denyMsg = turn.DenyMessage
						if denyMsg == "" {
							denyMsg = "Denied by the scripted headless drive (turn.allow=false)."
						}
					}
					if err := tc.GrantAsk(a.askID, a.nodeID, turn.Allow, updatedInput, denyMsg); err != nil {
						return fmt.Errorf("grant ask on turn %d: %w", i+1, err)
					}
					grantedAsks[a.askID] = true
				}
				if results >= wantResults {
					break // this turn reached its result; advance to the next turn
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				if time.Now().After(deadline) {
					return fmt.Errorf("turn %d did not reach a result within %s", i+1, perTurnTimeout)
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		return nil
	}
}
