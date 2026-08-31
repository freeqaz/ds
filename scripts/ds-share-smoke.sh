#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# ds-share-smoke.sh — smoke the serpent-share DEMO: a tmux-style 2-person shared
# Claude Code session (D141). Two clients drive ONE shared CC stdin; CC output is
# broadcast to both. Imperfect interleaving is ACCEPTED by charter.
#
# It is the operator wrapper for client/cmd/serpent-share's two-tier smoke
# (mirrors ds-headless-drive-smoke.sh):
#
#   scripts/ds-share-smoke.sh --offline   # TIER 1: fake/echo CC, no network, no
#                                         #   API spend — the always-green gate.
#                                         #   Proves byte-atomic shared fan-in +
#                                         #   shared fan-out (2 sims + 2 WS clients).
#   scripts/ds-share-smoke.sh             # ARMED: TIER 2 (DS_E2E_LIVE=1) drives a
#                                         #   REAL local claude through a ds-capture
#                                         #   gateway with two WS clients sending
#                                         #   distinct prompts; asserts both reach
#                                         #   CC and both clients see both replies.
#
# FLAGS (all optional):
#   --offline        run ONLY the offline fake-CC tier (no claude/ds-capture/network).
#   --claude PATH    claude binary for the live tier (sets CLAUDE_BIN).
#   --capture-bin P  ds-capture binary for the live tier (sets DS_CAPTURE_BIN).
#   -h | --help      this help.
#
# PREREQUISITES for the live (armed) run:
#   - the host claude binary on PATH (or --claude), the box's OAuth token at
#     ~/.claude/.credentials.json, and a buildable ds-capture (the script builds
#     .bin/ds-capture if it is not on PATH). Egress flows through a ds-capture
#     gateway the demo starts on a FREE local port (never the protected :18080
#     monitor). ~cents/turn of API budget.
#
# D50 WALL: the live run's gateway cassette + any raw CC stdout are RAW-class —
# they stay under the demo's ~/tmp job dir and are reaped on exit. Nothing the
# live run records is ever committed.
#
# POSIX sh, no bashisms. Exits with the test status; prints GREEN on success.

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
PKG="./client/cmd/serpent-share"
OFFLINE_TESTS="TestSharedFanInFanOut|TestServerTwoClientsSharedSession"
LIVE_TEST="TestSharedSessionRealCC"

OFFLINE=0

die() { echo "ds-share-smoke: $*" >&2; exit 2; }
usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
	case "$1" in
		--offline) OFFLINE=1 ;;
		--claude) shift; [ $# -gt 0 ] || die "--claude needs a value"; CLAUDE_BIN=$1; export CLAUDE_BIN ;;
		--capture-bin) shift; [ $# -gt 0 ] || die "--capture-bin needs a value"; DS_CAPTURE_BIN=$1; export DS_CAPTURE_BIN ;;
		-h|--help) usage 0 ;;
		*) die "unknown flag: $1 (try --help)" ;;
	esac
	shift
done

cd "$REPO_ROOT"

if [ "$OFFLINE" -eq 1 ]; then
	echo "ds-share-smoke: TIER 1 (offline, fake/echo CC — no network, no API spend)"
	go test "$PKG" -run "$OFFLINE_TESTS" -count=1 -race
	echo "ds-share-smoke: GREEN — shared fan-in (byte-atomic) + shared fan-out proven with the echo CC."
	exit 0
fi

# Armed: run the offline tier first (must stay green), then the live tier.
echo "ds-share-smoke: TIER 1 (offline) — must be green before arming the live tier"
go test "$PKG" -run "$OFFLINE_TESTS" -count=1 -race

# Make ds-capture resolvable for the live tier: build it into .bin if not on PATH.
if [ -z "${DS_CAPTURE_BIN:-}" ] && ! command -v ds-capture >/dev/null 2>&1; then
	echo "ds-share-smoke: building .bin/ds-capture for the live tier"
	mkdir -p .bin
	go build -o .bin/ds-capture ./client/cmd/ds-capture
	PATH="$REPO_ROOT/.bin:$PATH"; export PATH
fi

echo "ds-share-smoke: TIER 2 (DS_E2E_LIVE=1) — real claude through ds-capture, ~cents/turn"
DS_E2E_LIVE=1 go test "$PKG" -run "$LIVE_TEST" -count=1 -v -timeout 300s
echo "ds-share-smoke: GREEN — real shared Claude Code session: 2 clients, 1 shared stdin, both replies broadcast to both."
