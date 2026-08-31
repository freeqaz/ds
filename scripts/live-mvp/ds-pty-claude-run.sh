#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ds-pty-claude-run.sh — headless TERMINAL-mode smoke for `serpent claude --vm`.
#
# The PTY twin of ds-serpent-claude-run.sh. Where that script drives the STRUCTURED
# path (attach.v1 events, stream-json CC), THIS one drives the RAW-TERMINAL path:
#   serpent claude --vm -> serpent-tui -> (handle advertises a RAW_TERMINAL endpoint)
#   -> SocketTransport.DialTerminal -> *hostbridge.TerminalConn -> ds-hostbridge
#      --mode terminal vsockTerminalCarriage -> vsock -> in-guest ds-entrypoint pty
#      bridge (bridgePTY) -> pty master -> the REAL interactive Claude Code TUI.
# The dev's terminal IS the in-VM Claude Code (ssh/mosh-style). It drives one
# deterministic prompt, asserts the rendered marker + an in-VM /work side-effect,
# then detaches (Ctrl-], the VM session keeps running).
#
# ============================================================================
# PREREQUISITE — terminal mode is NOT what ds-serve-stack.sh launches today.
# ============================================================================
# ds-serve-stack.sh brings the stack up in STRUCTURED mode: the host-agent launches
# with the stream-json drivable CC argv and NO -session-mode, so the session serves
# the attach.v1 event stream over a DIRECT endpoint — there is NO RAW_TERMINAL
# endpoint to dial and serpent-tui stays in the structured bubbletea loop.
#
# TERMINAL mode needs TWO deltas vs the structured bring-up:
#
#   (A) THE M0 IMAGE must carry the NEW PTY-launch ds-entrypoint. The terminal
#       carriage drives a guest pty: ds-entrypoint must allocate a pty (stdioPTY /
#       bridgePTY, vm/entrypoint/pty_linux.go + ptywire.go) and exec the runtime as
#       its controlling tty when the lowered EntrypointConfig selects PTY stdio. A
#       baked image whose ds-entrypoint predates that branch will boot but launch CC
#       over PIPES (structured) and serve no pty — the terminal dial then internal-
#       rejects ("no terminal carriage for session").
#
#       >> Does the currently-baked image have it? The shipped baked base
#          (m0-base-v3.raw on the live boxes) was baked BEFORE the PTY launch-mode
#          and DOES NOT carry the PTY-launch ds-entrypoint. You MUST rebake from
#          current origin/main before this runbook can pass. REBAKE (rootless, from
#          a clean origin/main checkout):
#
#            DS_IMAGES_DIR=~/tmp/ds-images vm/m0-image/build-m0-image.sh --build
#
#          which re-stages vm/entrypoint/cmd/ds-entrypoint at
#          /usr/local/bin/ds-entrypoint (build-m0-image.sh bake_install_guest_bin,
#          M0_ENTRYPOINT_PATH) into the rootfs. Point DS_BASE_IMAGE at the rebaked
#          .raw for the host-agent below. (On a box without debootstrap/root, the
#          rootless podman->mke2fs -d->direct-kernel recipe in the M0 image notes
#          bakes the same artifact; the load-bearing fact is the NEW ds-entrypoint
#          binary being at M0_ENTRYPOINT_PATH in the rootfs.)
#
#   (B) THE HOST-AGENT must default sessions to terminal mode (or the per-session
#       overlay must carry a DS_SESSION_MODE=terminal hint). Add to the
#       ds-serve-stack.sh host-agent launch (start_hostagent):
#
#            -session-mode terminal
#
#       and REMOVE the structured stream-json launch args — in terminal mode the
#       host strips the stream-json argv itself (libvirt.SessionModeTerminal's
#       allow-list lowers LaunchSpec.stdio=PTY + a seeded window and drops the
#       --input-format/--output-format/--permission-prompt-tool=stdio flags, which
#       only make sense for the headless structured driver). With -session-mode
#       terminal the host-agent (U-HOST-SERVE) mints a RAW_TERMINAL writer-seat
#       endpoint instead of a DIRECT one, and the serving leg runs
#       ds-hostbridge --mode terminal (vsockTerminalCarriage) over the guest pty.
#
#       i.e. the host-agent block becomes (delta only):
#            -session-mode terminal \
#            -launch-command /usr/bin/claude \
#            -launch-arg --model -launch-arg sonnet \
#            -launch-arg --permission-mode -launch-arg default \
#            -launch-arg --max-budget-usd -launch-arg 1 \
#            # (no --input-format/--output-format/--verbose/--permission-prompt-tool)
#            -launch-env CLAUDE_CODE_OAUTH_TOKEN="$DS_CC_TOKEN" ...
#
# This script does NOT modify ds-serve-stack.sh or rebake — it ASSERTS the prereqs
# are in place (a RAW_TERMINAL endpoint is reachable) and drives the terminal smoke;
# it fails loud with the rebake/mode guidance above if terminal mode is not served.
#
# ============================================================================
# Usage:
#   scripts/live-mvp/ds-pty-claude-run.sh [OUT_FILE]
# Env overrides:
#   DS_BIN_DIR    (default <repo>/.bin)          the ds-serve-stack.sh build dir
#   DS_ORCHESTRATOR (default 127.0.0.1:18090)   the running orchestrator
#   PROMPT        (default writes a token to /work + replies it)
#   TOKEN         (default DS-PTY-PROOF-7Q4T)    deterministic marker asserted in the grid
#   PROOF_FILE    (default ds-pty-proof.txt)     proof file under the guest /work
#   DS_WORK_HOST  (optional)                     host side of the guest /work share for readback
#   TIMEOUT       (default 360)                  hard cap (cold VM boot + the turn)
set -uo pipefail

# Same default as ds-serve-stack.sh: the repo's gitignored .bin (see the note in
# ds-serpent-claude-run.sh — ~/tmp/ds-bin was the old shared default).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${DS_BIN_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/.bin}"
ORCH="${DS_ORCHESTRATOR:-127.0.0.1:18090}"
OUT="${1:-$HOME/tmp/ds-pty-claude.out}"
TOKEN="${TOKEN:-DS-PTY-PROOF-7Q4T}"
PROOF_FILE="${PROOF_FILE:-ds-pty-proof.txt}"
PROMPT="${PROMPT:-Run exactly: printf '$TOKEN' > /work/$PROOF_FILE ; then reply with exactly: $TOKEN}"
TIMEOUT="${TIMEOUT:-360}"

[ -x "$BIN/serpent" ] || { echo "ERROR: $BIN/serpent missing — run scripts/live-mvp/ds-serve-stack.sh up (then apply the -session-mode terminal delta above)" >&2; exit 1; }

echo ">> driving '$PROMPT' through serpent claude --vm in TERMINAL mode (orchestrator $ORCH); output -> $OUT"

# Terminal/raw mode requires a real TTY (serpent-tui drops to the raw passthrough
# only when stdin/stdout are a tty AND the handle advertises a RAW_TERMINAL endpoint).
# A plain pipe has no tty, so we allocate one with script(1) — the standard headless
# pty wrapper — and drive the prompt via serpent-tui's scripted-prompt leg (the same
# non-interactive verification path ds-serpent-claude-run.sh uses, robust to a
# piped-stdin EOF racing teardown). The scripted leg does not self-quit, so we wrap
# in `timeout` and detach once the turn rendered.
run_in_pty() {
  # script(1): -q quiet, -c command, -e return the command's exit code (util-linux),
  # writing the typescript to $OUT. The inner command is the serpent invocation.
  script -q -e -c "$1" "$OUT" </dev/null
}

SERPENT_CMD="env \
  DS_ORCHESTRATOR='$ORCH' \
  DS_SERPENT_SCRIPTED_PROMPT='$PROMPT' \
  PATH='$BIN:\$PATH' \
  timeout '$TIMEOUT' '$BIN/serpent' claude --vm \
    --orchestrator '$ORCH' \
    --repo demo --env-config-ref demo-env --launching-user mvp-user \
    --raw on"

run_in_pty "$SERPENT_CMD"
rc=$?
echo "EXIT=$rc (124 = timeout reached after the turn rendered — expected; scripted mode does not self-quit)" | tee -a "$OUT"

# Detect the not-served-in-terminal-mode failure precisely and point at the prereq.
if grep -qiE 'no terminal carriage|raw mode selected but the handle carries no raw-terminal endpoint|carries no raw-terminal' "$OUT"; then
  echo "FAIL: the session is NOT served in terminal mode — no RAW_TERMINAL endpoint / no guest pty carriage." >&2
  echo "      Apply BOTH prereqs (see this script's header):" >&2
  echo "        (A) rebake the M0 image so ds-entrypoint carries the PTY launch-mode:" >&2
  echo "            DS_IMAGES_DIR=~/tmp/ds-images vm/m0-image/build-m0-image.sh --build" >&2
  echo "        (B) start the host-agent with -session-mode terminal (drop the stream-json launch args)." >&2
  exit 2
fi

# Strip ANSI/CR so the assertion reads the rendered text, not the escape stream.
plain="$(sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\x1b\][^\x07]*\x07//g; s/\r/\n/g' "$OUT")"

ok=0
if grep -qF "$TOKEN" <<<"$plain"; then
  echo "PASS(grid): the in-VM Claude Code rendered the marker '$TOKEN' over the raw terminal carriage"
  ok=1
else
  echo "FAIL(grid): did not observe the marker '$TOKEN' in the rendered terminal output" >&2
  echo "----- last rendered lines -----" >&2
  grep -vE '^\s*$' <<<"$plain" | tail -20 >&2
fi

# The in-VM side-effect proof (CC actually ran the command, not just streamed text).
# Resolved from DS_WORK_HOST (the host side of the guest /work share); unset ⇒ a
# manual operator readback (inspect the guest /work for the proof file).
if [ -n "${DS_WORK_HOST:-}" ]; then
  proof="$DS_WORK_HOST/$PROOF_FILE"
  if [ -f "$proof" ] && grep -qF "$TOKEN" "$proof"; then
    echo "PASS(side-effect): $proof contains '$TOKEN' — CC executed the write in the VM over the raw terminal"
  else
    echo "FAIL(side-effect): $proof missing or lacks '$TOKEN' (CC did not execute the in-VM write)" >&2
    ok=0
  fi
else
  echo "NOTE: DS_WORK_HOST unset — the /work side-effect proof readback is a manual operator check (inspect the guest /work/$PROOF_FILE for '$TOKEN')."
fi

[ "$ok" -eq 1 ] && exit 0
exit 1
