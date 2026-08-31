#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ds-serpent-claude-run.sh — headless scripted smoke for `serpent claude --vm`.
#
# Drives ONE deterministic prompt through the FULL live path
#   serpent claude --vm -> serpent-tui up -> orchestrator CreateSession ->
#   host-agent boots a per-session KVM VM -> Attach(WRITER) -> the real in-VM
#   Claude Code answers -> the answer renders back over attach.v1
# and asserts the answer + a successful session. Run ds-serve-stack.sh up first.
#
# It uses DS_SERPENT_SCRIPTED_PROMPT (serpent-tui's non-interactive verification
# leg): the prompt is injected via the real keystroke->SubmitInput->DriveInput
# path with NO TTY input reader, so it is robust in a script/CI context (a
# piped-stdin EOF races the bubbletea teardown and the non-TTY cancelreader
# aborts the attach before the prompt is driven). Scripted mode does NOT quit the
# loop on its own, so we wrap it in `timeout` and stop once the turn has rendered.
#
# Usage:
#   scripts/live-mvp/ds-serpent-claude-run.sh [OUT_FILE]
# Env overrides:
#   DS_BIN_DIR   (default <repo>/.bin)          the ds-serve-stack.sh build dir
#   DS_ORCHESTRATOR (default 127.0.0.1:18090)   the running orchestrator
#   PROMPT       (default 'Reply with exactly: PONG')
#   EXPECT       (default 'PONG')               substring asserted in the answer
#   TIMEOUT      (default 300)                  hard cap (cold VM boot + the turn)
set -uo pipefail

# Same default as ds-serve-stack.sh: the repo's gitignored .bin, so this smoke
# asserts against the binaries the stack it accompanies actually built. (~/tmp/ds-bin
# was the old shared default; a stale copy there silently smoked the WRONG build.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${DS_BIN_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/.bin}"
ORCH="${DS_ORCHESTRATOR:-127.0.0.1:18090}"
OUT="${1:-$HOME/tmp/ds-serpent-claude.out}"
PROMPT="${PROMPT:-Reply with exactly: PONG}"
EXPECT="${EXPECT:-PONG}"
TIMEOUT="${TIMEOUT:-300}"

[ -x "$BIN/serpent" ] || { echo "ERROR: $BIN/serpent missing — run scripts/live-mvp/ds-serve-stack.sh up" >&2; exit 1; }

echo ">> driving '$PROMPT' through serpent claude --vm (orchestrator $ORCH); output -> $OUT"
timeout "$TIMEOUT" env \
  DS_ORCHESTRATOR="$ORCH" \
  DS_SERPENT_SCRIPTED_PROMPT="$PROMPT" \
  PATH="$BIN:$PATH" \
  "$BIN/serpent" claude --vm \
    --orchestrator "$ORCH" \
    --repo demo --env-config-ref demo-env --launching-user mvp-user \
  > "$OUT" 2>&1
rc=$?
echo "EXIT=$rc (124 = timeout reached after the turn rendered — expected, scripted mode does not self-quit)" | tee -a "$OUT"

# Strip ANSI/CR so the assertion reads the rendered text, not the escape stream.
plain="$(sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r/\n/g' "$OUT")"
if grep -q "assistant: $EXPECT" <<<"$plain" && grep -q 'session success' <<<"$plain"; then
  echo "PASS: in-VM Claude Code answered '$EXPECT' and the session reported success"
  grep -E 'assistant: |session success' <<<"$plain" | tail -3
  exit 0
fi
echo "FAIL: did not observe 'assistant: $EXPECT' + 'session success' in $OUT" >&2
echo "----- last rendered lines -----" >&2
grep -vE '^\s*$' <<<"$plain" | tail -15 >&2
exit 1
