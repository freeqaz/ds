#!/usr/bin/env bash
# capture.sh — D49 capture harness for the Claude Code stream-json (Layer 1) protocol.
#
# Produces RAW NDJSON captures of `claude -p --output-format stream-json`. Raw output
# contains real local paths, session UUIDs, costs and agent ids, so it is written to a
# scratch dir and MUST be scrubbed/re-authored before becoming a synthetic fixture
# (D50 — see ../fixtures/PROVENANCE.md). See PROTOCOL-NOTES.md for the message model.
#
# Usage:
#   ./capture.sh <scenario> [outdir]
#   ./capture.sh --scrub <raw.ndjson> <candidate.ndjson>   # D50 re-author pass (see below)
#   ./capture.sh --scenarios                                # list the scripted scenario set
# Scenarios:
#   baseline        trivial prompt, no tools         — the bare envelope
#   tool            one Bash echo                    — tool_use / tool_result framing
#   subagent        one Task/Agent spawn (Sonnet)    — the subagent sub-protocol
#   subagent-tools  subagent that runs Bash inside   — proves ordinary internals are opaque
#   denial          default-mode permission denial   — verified P5 recipe (--disallowedTools)
#   sendmsg         spawn + attempted SendMessage    — shows continuation is gated headless
#
# THE NIGHTLY-CANARY SCRIPTED SET (D49 — the scenarios the canary captures against
# CC-LATEST and diffs vs the committed canon goldens in goldentrace/canary/testdata/;
# the operator runs these gated, the fleet never does):
#   canary-baseline   == baseline   — golden: baseline-chat
#   canary-ask        native ask/approval control flow — golden: ask-control
#   canary-subagent   nested subagent spawn (lifecycle) — golden: nested-spawn
# (the canary runner DS_CANARY_RAW_<SCENARIO> env points at the scrubbed-then-
# re-authored capture; see client/goldentrace/canary/live.go's runbook.)
#
# Env overrides: MODEL (default sonnet), BUDGET (default 0.60).
#
# CIA RECORD MODE (the fidelity loop's ground-truth capture — taskdb 01KTXBGTK6):
#   Set CIA_RECORD=1 to run the claude invocation UNDER `cia record`, so the
#   Anthropic /v1/messages API plane is captured to a cassette IN PARALLEL with the
#   stdout NDJSON. The recorder runs on a PRIVATE control socket (the step-0 cia
#   override `--runtime-dir`) and a FREE proxy port, so it COEXISTS with the
#   protected :18080 monitor — it NEVER binds, stops, or touches :18080 or
#   ~/.cia/cia.sock. The API cassette is the ground truth that distinguishes a STALE
#   synthetic cassette from genuine CC DRIFT when a projection-equality check fails
#   (the stdout harness alone cannot see the transport plane — DRIVE-PROTOCOL.md).
#
#   CIA_RECORD env (all optional; sensible private defaults):
#     CIA_RECORD       1 to arm record mode (default off — plain capture).
#     CIA_BIN          the cia binary (default: cia on PATH).
#     CIA_PROXY_PORT   the FREE proxy port (default 18099; MUST NOT be 18080/8080).
#     CIA_RUNTIME_DIR  the private control-socket/pid/log dir (default <outdir>/cia-rt).
#     CIA_CASSETTE     the API cassette path (default <outdir>/<scenario>.api.json).
#
#   The API cassette and the cia runtime dir are RAW-CLASS: real model output, kept
#   under the job/outdir and ~/.cia only, NEVER committed (D50; HARDENING-NOTES §2).
set -euo pipefail

# --- The scripted nightly-canary scenario set (D49) -------------------------
# The canary captures CC-LATEST for each of these and diffs the projection vs
# the committed canon golden (goldentrace/canary/testdata/<golden>.canon.ndjson).
# Format: "<scenario>:<golden-base>:<DS_CANARY_RAW_env-suffix>".
CANARY_SCENARIOS="canary-baseline:baseline-chat:BASELINE
canary-ask:ask-control:ASK_CONTROL
canary-subagent:nested-spawn:SUBAGENT"

# --- D50 SCRUB PASS (raw -> re-authored-synthetic candidate) ----------------
# `./capture.sh --scrub <raw.ndjson> <candidate.ndjson>`. The scrub list comes
# straight from HARDENING-NOTES §2.2/§2.4: strip the auth-bearing + correlatable
# fields to fixed synthetic placeholders so NO real credential, session UUID,
# cost, or path can ride a capture toward fixtures/. The output is a CANDIDATE
# under the job tmp dir — it is NOT yet committable; it must still clear the
# canary provenance gate (`go run ./goldentrace/canary/cmd/canary provenance-gate`)
# AND be re-authored synthetic (raw -> synthetic -> fixtures is one-directional;
# scrub is a SAFETY net, not the path into git — D50, clean-by-construction).
#
# never-log-the-secret: the scrub rewrites VALUES; it never echoes a matched
# secret. It writes the candidate to the job tmp dir, never under a git tree.
scrub_pass() {
  _raw=$1
  _candidate=$2
  if [ ! -f "$_raw" ]; then
    echo "scrub: raw capture not found: $_raw" >&2; exit 2
  fi
  # Refuse to write the candidate under a git working tree (raw stays in job tmp;
  # the candidate is a job-tmp artifact too — only a re-authored synthetic file
  # ever enters fixtures/, by hand, after review).
  case "$_candidate" in
    */fixtures/*) echo "scrub: refusing to write a candidate under fixtures/ — re-author by hand (D50)" >&2; exit 3 ;;
  esac
  if command -v jq >/dev/null 2>&1; then
    # jq path: rewrite the known auth/correlatable fields wherever they appear.
    # walk() rewrites by KEY so the scrub is position-independent. Bearer/x-api-key
    # header values, session/request ids, agent/task ids, costs, and real cwd/paths
    # all collapse to fixed synthetic constants (HARDENING-NOTES §2.2).
    jq -c '
      def scrub:
        walk(
          if type == "object" then
            with_entries(
              if   (.key|ascii_downcase) == "authorization"       then .value = "Bearer ds_fixture"
              elif (.key|ascii_downcase) == "x-api-key"           then .value = "ds_fixture"
              elif (.key|ascii_downcase) == "anthropic-beta"      then .value = "ds_fixture"
              elif (.key|ascii_downcase) == "x-claude-code-session-id" then .value = "ds_fixture_session"
              elif (.key|ascii_downcase) == "x-client-request-id" then .value = "ds_fixture_request"
              elif .key == "session_id"      then .value = "f24b8a07-0000-0000-0000-000000000001"
              elif .key == "uuid"            then .value = "00000000-0000-4000-8000-000000000000"
              elif .key == "request_id"      then .value = "ds_fixture_request"
              elif .key == "agentId"         then .value = "0000000000000000"
              elif .key == "task_id"         then .value = "ds_fixture_task"
              elif .key == "total_cost_usd"  then .value = 0
              elif .key == "cwd"             then .value = "/work"
              else . end
            )
          else . end
        );
      scrub
    ' "$_raw" > "$_candidate"
  else
    # No jq: fall back to a conservative line-level redaction of the auth-bearing
    # token VALUES (never a usable prefix). Correlatable-id re-authoring then MUST
    # be done by hand — this fallback only guarantees no secret survives.
    echo "scrub: jq not found — token-value redaction only; re-author ids by hand" >&2
    sed -E \
      -e 's/(Bearer )[A-Za-z0-9._-]{20,}/\1ds_fixture/g' \
      -e 's/(sk-ant-[a-z0-9]+-)[A-Za-z0-9_-]{12,}/\1ds_fixture/g' \
      "$_raw" > "$_candidate"
  fi
  # Provenance header: prepend the synthetic ds_fixture record so the candidate
  # at least declares its intended class (the gate re-checks it).
  _hdr='{"ds_fixture":{"provenance":"synthetic","seam":"attach.cc-wire","created":"'"$(date +%Y-%m-%d)"'","tool":"goldentrace-canary"}}'
  printf '%s\n' "$_hdr" | cat - "$_candidate" > "$_candidate.tmp" && mv "$_candidate.tmp" "$_candidate"
  echo "scrubbed $_raw -> $_candidate (candidate; gate it + re-author before fixtures/, D50)" >&2
}

# Early dispatch for the non-capture verbs (scrub / scenario list).
case "${1:-}" in
  --scrub)
    [ $# -eq 3 ] || { echo "usage: $0 --scrub <raw.ndjson> <candidate.ndjson>" >&2; exit 2; }
    scrub_pass "$2" "$3"; exit 0 ;;
  --scenarios)
    echo "scripted nightly-canary scenarios (scenario:golden:raw-env-suffix):"
    printf '%s\n' "$CANARY_SCENARIOS" | sed 's/^/  /'
    exit 0 ;;
esac

scenario="${1:-baseline}"
outdir="${2:-${CLAUDE_JOB_DIR:-/tmp}/tmp/cap}"
mkdir -p "$outdir"
MODEL="${MODEL:-sonnet}"
BUDGET="${BUDGET:-0.60}"
out="$outdir/${scenario}.ndjson"
err="$outdir/${scenario}.err"

# --- CIA record-mode wiring (opt-in; coexists with the protected :18080 monitor) ---
# When CIA_RECORD=1, run_claude wraps `claude …` in `cia run --proxy-port <free>`
# and a backgrounded `cia record --runtime-dir <private> --proxy-port <free>` on a
# PRIVATE socket. Off ⇒ run_claude is a transparent passthrough to claude.
CIA_RECORD="${CIA_RECORD:-0}"
CIA_BIN="${CIA_BIN:-cia}"
CIA_PROXY_PORT="${CIA_PROXY_PORT:-18099}"
CIA_RUNTIME_DIR="${CIA_RUNTIME_DIR:-$outdir/cia-rt}"
CIA_CASSETTE="${CIA_CASSETTE:-$outdir/${scenario}.api.json}"
_cia_pid=""

_cia_assert_free_port() {
  # HARD refusal: never run the recorder on the protected monitor's port.
  case "$CIA_PROXY_PORT" in
    18080|8080)
      echo "REFUSING: CIA_PROXY_PORT=$CIA_PROXY_PORT is a protected/known proxy port." >&2
      echo "  Pick a FREE high port (e.g. 18099) — the recorder coexists via a private socket." >&2
      exit 3 ;;
  esac
}

_cia_record_start() {
  _cia_assert_free_port
  mkdir -p "$CIA_RUNTIME_DIR" "$(dirname "$CIA_CASSETTE")"
  echo ">> cia record (private socket=$CIA_RUNTIME_DIR/cia.sock, proxy :$CIA_PROXY_PORT) -> $CIA_CASSETTE" >&2
  # --runtime-dir relocates the control socket/pid/log so this recorder coexists
  # with the protected ~/.cia/cia.sock monitor (the step-0 cia override). Backgrounded;
  # writes the cassette on SIGINT (we send it in _cia_record_stop).
  "$CIA_BIN" record \
    --cassette "$CIA_CASSETTE" \
    --proxy-port "$CIA_PROXY_PORT" \
    --runtime-dir "$CIA_RUNTIME_DIR" \
    > "$outdir/${scenario}.cia.log" 2>&1 &
  _cia_pid=$!
  # Wait for the private control socket to appear (recorder is up).
  for _ in $(seq 1 40); do
    [ -S "$CIA_RUNTIME_DIR/cia.sock" ] && break
    sleep 0.25
  done
}

_cia_record_stop() {
  [ -n "$_cia_pid" ] || return 0
  # SIGINT makes `cia record` write the cassette and exit (its Ctrl-C path).
  kill -INT "$_cia_pid" 2>/dev/null || true
  wait "$_cia_pid" 2>/dev/null || true
  _cia_pid=""
  echo ">> cia record stopped; API cassette -> $CIA_CASSETTE (raw-class, NEVER commit)" >&2
}
trap '_cia_record_stop' EXIT

# run_claude — the single claude entry point. Off-mode: exec claude directly.
# Record-mode: route through `cia run --proxy-port <free>` so the API plane is
# captured by the coexisting recorder.
run_claude() {
  if [ "$CIA_RECORD" = "1" ]; then
    "$CIA_BIN" run --proxy-port "$CIA_PROXY_PORT" -- claude "$@"
  else
    claude "$@"
  fi
}

[ "$CIA_RECORD" = "1" ] && _cia_record_start

# --no-session-persistence is MANDATORY: without it, captures leak transcripts into the
# shared ~/.claude/projects/* index (same store other same-uid sessions use). Do not remove.
common=( -p --output-format stream-json --verbose --include-partial-messages
         --no-session-persistence --model "$MODEL" --max-budget-usd "$BUDGET" )

case "$scenario" in
  baseline)
    run_claude "${common[@]}" --tools "" \
      "Reply with exactly the word PONG and nothing else. Do not use any tools." ;;
  tool)
    run_claude "${common[@]}" --tools "Bash" --permission-mode bypassPermissions \
      "Run the bash command: echo HELLO. Then reply with the single word done." ;;
  subagent)
    run_claude "${common[@]}" --tools "Task" --permission-mode bypassPermissions \
      --agents '{"echoer":{"description":"one word","prompt":"Reply with exactly the word ACORN and nothing else. Do not use any tools.","tools":[]}}' \
      "Launch the 'echoer' subagent exactly once to do its task. After it returns, reply with the single word: done." ;;
  subagent-tools)
    run_claude "${common[@]}" --tools "Task" --permission-mode bypassPermissions \
      --agents '{"worker":{"description":"runs a shell command","prompt":"Run the bash command: echo HELLO_FROM_SUBAGENT. Then reply with exactly the word DONE.","tools":["Bash"]}}' \
      "Launch the 'worker' subagent exactly once. After it returns, reply with: ok." ;;
  denial)
    # Captures the default-mode DENIAL path. Key: do NOT pre-allow the tool — an explicit
    # --tools allowlist auto-approves under default mode (Phase 2 / P5). --disallowedTools is
    # the verified recipe that yields result.permission_denials[] + an is_error:true tool_result.
    run_claude "${common[@]}" --tools "Bash" --disallowedTools 'Bash(echo*)' --permission-mode default \
      "Run the bash command: echo NOPE. Do that and nothing else." ;;
  sendmsg)
    run_claude "${common[@]}" --tools "Task,SendMessage" --permission-mode bypassPermissions \
      --agents '{"echoer":{"description":"one word","prompt":"Reply with exactly the word ACORN and nothing else.","tools":[]}}' \
      "Step 1: launch the 'echoer' subagent once. Step 2: use SendMessage to send 'again' to that agent's id. Step 3: reply done." ;;
  # --- nightly-canary scripted scenarios (golden = baseline-chat/ask-control/nested-spawn) ---
  canary-baseline)
    # The bare envelope, captured against CC-latest; golden: baseline-chat.
    run_claude "${common[@]}" --tools "" \
      "Reply with exactly the word PONG and nothing else. Do not use any tools." ;;
  canary-ask)
    # The native ask/approval control flow: default mode + a tool that is NOT
    # pre-allowed elicits a permission ask (the control channel). golden: ask-control.
    run_claude "${common[@]}" --tools "Bash" --permission-mode default \
      "Run the bash command: echo HELLO. Do that and nothing else." ;;
  canary-subagent)
    # A nested subagent spawn (full lifecycle), captured against CC-latest;
    # golden: nested-spawn.
    run_claude "${common[@]}" --tools "Task" --permission-mode bypassPermissions \
      --agents '{"echoer":{"description":"one word","prompt":"Reply with exactly the word ACORN and nothing else. Do not use any tools.","tools":[]}}' \
      "Launch the 'echoer' subagent exactly once to do its task. After it returns, reply with the single word: done." ;;
  *)
    echo "unknown scenario: $scenario" >&2; exit 2 ;;
# `< /dev/null` skips the 3s stdin-wait stall. NOTE: a stream-json INPUT scenario (feeding a
# user message on stdin) must NOT use this redirect — pipe the input instead. None here do.
esac < /dev/null > "$out" 2> "$err" || true

# Stop the recorder (writes the API cassette) before the summary, so the cassette
# is on disk when we report it.
_cia_record_stop

# Version/model stamp sidecar so a future canary diff attributes a schema change to a CC
# version bump rather than model nondeterminism (Phase 2 methodology fix).
printf '{"scenario":"%s","cli_version":"%s","model":"%s","cia_record":"%s"}\n' \
  "$scenario" "$(claude --version 2>/dev/null | awk '{print $1}')" "$MODEL" "$CIA_RECORD" > "$out.meta.json"

lines=$(wc -l < "$out")
echo "wrote $out ($lines lines); meta -> $out.meta.json; stderr -> $err"
if [ "$CIA_RECORD" = "1" ]; then
  echo "API cassette -> $CIA_CASSETTE (raw-class — re-author to synthetic before committing, D50)"
fi
echo "--- type/subtype timeline (non-partial) ---"
jq -rc 'select(.type!="stream_event") | [.type, (.subtype // "-")] | @tsv' "$out" | nl -ba
