#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# ds-headless-drive-smoke.sh — drive a REAL Claude Code session HEADLESSLY (no
# human), multi-turn, from a committed JSONL script, and prove a deterministic
# VM-side effect.
#
# It is the operator wrapper for the DS_E2E_LIVE-gated scripted-drive test
# (client/goldentrace/e2e TestScriptedDriveVMSideEffectReal): it arms the single
# live gate (DS_E2E_LIVE=1) and runs that test, which drives the committed
# proof.jsonl fixture against real CC in a rootless podman container, fronted by
# the host-agent bridge, answering the tool-use ask on the PROVEN attach.v1 grant
# path (NEVER --dangerously-skip-permissions). The test asserts BOTH the projected
# attach.v1 ask round-trip AND that the proof file CC was told to write actually
# exists on the host /work mount carrying the deterministic token — proving CC
# executed the instruction, not merely streamed text.
#
#   scripts/ds-headless-drive-smoke.sh                  # arm DS_E2E_LIVE=1 + run the gated test
#   scripts/ds-headless-drive-smoke.sh --offline        # ungated: run only the offline fake-CC twins
#
# FLAGS (all optional):
#   --offline        do NOT arm the gate; run the offline fake-CC stepping/parser
#                    tests only (no podman/claude/cia/network). Safe anywhere.
#   --proxy-port N   route live egress through a ds-capture gateway on port N
#                    (sets DS_LIVE_PROXY_PORT; the gateway is operator-managed,
#                    see client/hostbridge/LIVE-VALIDATION.md §B).
#   --ca PATH        the CA the gateway terminates TLS with (sets DS_LIVE_CA).
#   --scratch DIR    persist the raw CC-stdout capture under DIR (sets DS_LIVE_SCRATCH;
#                    under ~/tmp, raw-class, never committed — D50).
#   -h | --help      this help.
#
# PREREQUISITES for the live run (see client/hostbridge/LIVE-VALIDATION.md §B):
#   - rootless podman + the pinned image localhost/ds/cc-sandbox:2.1.173 (D49);
#   - the host claude binary at /opt/claude-code/bin/claude (mounted ro, drift 1);
#   - an OAuth token source (~/.claude/.credentials.json) and, for routed egress,
#     a ds-capture gateway on the free :18099 (NEVER the protected :18080 monitor).
#
# D50 WALL: anything the live run records (raw CC stdout, real paths, costs,
# Authorization headers) is RAW-class — it stays under ~/tmp / the job dir and is
# NEVER committed. Only re-authored synthetic fixtures enter git.
#
# POSIX sh, no bashisms. Exits with the test's status; records GREEN on success.

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
E2E_PKG="./client/goldentrace/e2e"
GATED_TEST="TestScriptedDriveVMSideEffectReal"
# The offline twins proven in the wave gate (parser + multi-turn stepping + the
# gated test's clean skip): a single -run alternation runs them all.
OFFLINE_TESTS="TestParseScript|TestDriveScriptScenario|TestScriptedDriveVMSideEffectReal"

OFFLINE=0
PROXY_PORT=""
CA_PATH=""
SCRATCH_DIR=""

die() { echo "ds-headless-drive-smoke: $*" >&2; exit 2; }
usage() { sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
	case "$1" in
		--offline)    OFFLINE=1; shift ;;
		--proxy-port) PROXY_PORT="${2:?--proxy-port needs a value}"; shift 2 ;;
		--ca)         CA_PATH="${2:?--ca needs a value}"; shift 2 ;;
		--scratch)    SCRATCH_DIR="${2:?--scratch needs a value}"; shift 2 ;;
		-h|--help)    usage 0 ;;
		*)            die "unknown argument: $1 (try --help)" ;;
	esac
done

cd "$REPO_ROOT"

if [ "$OFFLINE" -eq 1 ]; then
	echo "ds-headless-drive-smoke: OFFLINE — running the fake-CC stepping + parser tests (no gate, no live process)" >&2
	# Gate explicitly unset so the gated test takes its clean skip path.
	DS_E2E_LIVE="" go test "$E2E_PKG" -run "$OFFLINE_TESTS" -count=1 -v
	echo "ds-headless-drive-smoke: OFFLINE GREEN" >&2
	exit 0
fi

# --- the armed live run ------------------------------------------------------
echo "ds-headless-drive-smoke: arming DS_E2E_LIVE=1 — driving real CC headlessly from client/goldentrace/e2e/testdata/proof.jsonl" >&2

# Optional egress-gateway routing (the documented DS_LIVE_* knobs the test reads).
[ -n "$PROXY_PORT" ]  && export DS_LIVE_PROXY_PORT="$PROXY_PORT"
[ -n "$CA_PATH" ]     && export DS_LIVE_CA="$CA_PATH"
[ -n "$SCRATCH_DIR" ] && export DS_LIVE_SCRATCH="$SCRATCH_DIR"

# Disarm `set -e` around the run so we can record the verdict on either outcome.
status=0
DS_E2E_LIVE=1 go test "$E2E_PKG" -run "$GATED_TEST" -count=1 -v || status=$?

if [ "$status" -eq 0 ]; then
	echo "ds-headless-drive-smoke: LIVE GREEN — scripted headless drive closed the attach.v1 round-trip AND proved the VM-side effect" >&2
else
	echo "ds-headless-drive-smoke: LIVE FAILED (status $status) — see the test output above" >&2
fi
exit "$status"
