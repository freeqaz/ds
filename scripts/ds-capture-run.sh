#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# ds-capture-run.sh — run a real Claude Code against the FIRST-PARTY ds-capture
# egress gateway.
#
# It is the one-liner replacement for the retired external capture-proxy recipe
# (see client/goldentrace/CAPTURE-TOOL-DESIGN.md): stand up
# `ds-capture record` on the free :18099 (NEVER the protected :18080 monitor),
# point a real `claude` at it (HTTPS_PROXY + NODE_USE_ENV_PROXY=1 + the
# gateway-minted CA), run the command, then tear the gateway down and report the
# cassette it captured. Egress is TLS-terminated and re-originated by OUR
# gateway: the API turn lands in the cassette; everything else passes through.
#
#   scripts/ds-capture-run.sh                       # default PONG smoke (Sonnet, $0.10 cap)
#   scripts/ds-capture-run.sh -- claude -p "hi" --model sonnet --max-budget-usd 0.20
#   scripts/ds-capture-run.sh --cassette ~/tmp/cap.json -- claude   # interactive
#
# FLAGS (all optional; everything after `--` is the claude argv to run):
#   --port N         gateway listen port (default 18099; refuses 18080).
#   --cassette PATH  where to write the captured cassette
#                    (default <scratch>/ds-capture-<pid>.json).
#   --ca-dir DIR     where the gateway writes its CA (default <scratch>/ca);
#                    the CA file is <DIR>/ds-capture-ca.pem.
#   --bin PATH       a prebuilt ds-capture binary (default: `go run` the source).
#   --claude PATH    the claude binary for the DEFAULT smoke only (default:
#                    `claude` on PATH); a command after `--` always runs verbatim.
#   -h | --help      this help.
#
# D50 WALL: the written cassette is a RAW-class capture (real paths, costs, and
# the request's `Authorization: Bearer …`). It stays under ~/tmp and is NEVER
# committed; run `ds-capture scrub` before any promotion, and only re-authored
# SYNTHETIC cassettes ever enter git (client/goldentrace/HARDENING-NOTES.md).
#
# POSIX sh, no bashisms. Exits with the claude command's status.

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
PROTECTED_PORT=18080
PORT=18099
CASSETTE=""
CA_DIR=""
DS_CAPTURE_BIN=""
CLAUDE_BIN="${CLAUDE_BIN:-claude}"

# Scratch root: ~/tmp (btrfs/reflink, not tmpfs).
SCRATCH_ROOT="${DS_WT_ROOT:-${HOME}/tmp}"

die() { echo "ds-capture-run: $*" >&2; exit 2; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# --- parse args (everything after `--` is the claude argv) -------------------
while [ $# -gt 0 ]; do
	case "$1" in
		--port)     PORT="${2:?--port needs a value}"; shift 2 ;;
		--cassette) CASSETTE="${2:?--cassette needs a value}"; shift 2 ;;
		--ca-dir)   CA_DIR="${2:?--ca-dir needs a value}"; shift 2 ;;
		--bin)      DS_CAPTURE_BIN="${2:?--bin needs a value}"; shift 2 ;;
		--claude)   CLAUDE_BIN="${2:?--claude needs a value}"; shift 2 ;;
		-h|--help)  usage 0 ;;
		--)         shift; break ;;
		-*)         die "unknown flag: $1 (see --help)" ;;
		*)          break ;;
	esac
done

[ "$PORT" != "$PROTECTED_PORT" ] || \
	die "refusing :$PROTECTED_PORT — the protected shared monitor; pick a free port (default 18099)"

mkdir -p "$SCRATCH_ROOT"
JOB_DIR=$(mktemp -d "$SCRATCH_ROOT/ds-capture-run.XXXXXX")
[ -n "$CASSETTE" ] || CASSETTE="$JOB_DIR/cassette.json"
[ -n "$CA_DIR" ]   || CA_DIR="$JOB_DIR/ca"
CA_FILE="$CA_DIR/ds-capture-ca.pem"

# The command to run through the gateway: everything after `--` runs VERBATIM
# (e.g. `-- claude -p "…"`). With nothing after `--`, a cheap throwaway smoke
# against CLAUDE_BIN.
if [ $# -eq 0 ]; then
	set -- "$CLAUDE_BIN" -p "Reply with exactly the word PONG and nothing else." \
		--model sonnet --no-session-persistence --max-budget-usd 0.10
fi

# --- resolve the ds-capture binary (build once; a daemon, not `go run`) ------
# Backgrounding `go run` leaves the compiled child as a grandchild that signal
# forwarding doesn't reliably reap (it lingers holding the stdout fd); build a
# real binary so SIGINT teardown is clean.
if [ -n "$DS_CAPTURE_BIN" ]; then
	[ -x "$DS_CAPTURE_BIN" ] || die "--bin '$DS_CAPTURE_BIN' is not executable"
	CAPTURE_BIN="$DS_CAPTURE_BIN"
else
	command -v go >/dev/null 2>&1 || die "no ds-capture --bin and no 'go' to build the source"
	CAPTURE_BIN="$JOB_DIR/ds-capture"
	echo "ds-capture-run: building ds-capture -> $CAPTURE_BIN" >&2
	( cd "$REPO_ROOT" && go build -o "$CAPTURE_BIN" ./client/cmd/ds-capture ) \
		|| die "go build ./client/cmd/ds-capture failed"
fi

GW_PID=""
cleanup() {
	# Tear the gateway down (SIGINT → it writes the cassette on the way out).
	if [ -n "$GW_PID" ] && kill -0 "$GW_PID" 2>/dev/null; then
		kill -INT "$GW_PID" 2>/dev/null || true
		wait "$GW_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT INT TERM

# --- start the gateway ------------------------------------------------------
echo "ds-capture-run: starting first-party egress gateway on :$PORT (job dir: $JOB_DIR)" >&2
"$CAPTURE_BIN" record --port "$PORT" --cassette "$CASSETTE" --ca-dir "$CA_DIR" \
	>"$JOB_DIR/gateway.log" 2>&1 &
GW_PID=$!

# Wait for the gateway to be listening (and for the CA to be written).
i=0
while :; do
	if [ -f "$CA_FILE" ] && { command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":$PORT[[:space:]]"; }; then
		break
	fi
	# Fall back to just the CA file when `ss` is unavailable.
	if [ -f "$CA_FILE" ] && ! command -v ss >/dev/null 2>&1; then
		break
	fi
	i=$((i + 1))
	[ "$i" -lt 150 ] || die "gateway did not come up on :$PORT within ~15s (see $JOB_DIR/gateway.log)"
	kill -0 "$GW_PID" 2>/dev/null || die "gateway exited before it was ready (see $JOB_DIR/gateway.log)"
	sleep 0.1
done
echo "ds-capture-run: gateway up; CA=$CA_FILE" >&2

# --- run the real claude through the gateway --------------------------------
# undici (this CC build, Node 26) honours the proxy env only with
# NODE_USE_ENV_PROXY=1 (DRIVE-FINDINGS P6).
export HTTPS_PROXY="http://127.0.0.1:$PORT"
export HTTP_PROXY="http://127.0.0.1:$PORT"
export NODE_USE_ENV_PROXY=1
export NODE_EXTRA_CA_CERTS="$CA_FILE"

echo "ds-capture-run: running: $*" >&2
set +e
"$@"
STATUS=$?
set -e

# cleanup (trap) writes the cassette as the gateway exits.
cleanup
trap - EXIT INT TERM

if [ -f "$CASSETTE" ]; then
	echo "ds-capture-run: cassette written to $CASSETTE" >&2
	echo "ds-capture-run: RAW-class (D50) — scrub before any promotion:" >&2
	echo "    go run ./client/cmd/ds-capture scrub '$CASSETTE' --out <synthetic> --provenance synthetic" >&2
else
	echo "ds-capture-run: no /v1/messages turn was captured (cassette not written; see $JOB_DIR/gateway.log)" >&2
fi
exit "$STATUS"
