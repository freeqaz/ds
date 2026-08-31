#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# check-no-loopback-bind.sh — fail-closed lint asserting the identity/ test tree
# stands up its in-process gRPC harnesses over an in-memory bufconn pipe, never
# a real loopback-TCP `net.Listen("tcp", "127.0.0.1:…")` socket bind.
#
# WHY: the identity in-process seam tests (identity/mint/grpc_seam_test.go,
# identity/fakes/digest-publisher/publisher_test.go, identity/digest/…, the
# grant-service Server round-trips) exercise a real generated gRPC client over
# an in-process server. Binding a loopback TCP socket for that pipe makes the
# test flaky under a hardened CI sandbox that runs with NO network namespace
# (the bind fails), and needlessly touches the transport stack. bufconn is an
# in-memory pipe — no socket, no off-box surface — so it is the mandated
# transport for these harnesses. This lint catches a regression back to
# loopback TCP at static-analysis time (D47 fail-closed spirit).
#
# ALLOWLIST: cmd/**/main_test.go is exempt. A package `main()` end-to-end test
# legitimately drives the real serve path, which binds an ephemeral loopback
# socket exactly as the shipped binary does (identity/grant-service/cmd/
# grant-service/main_test.go, identity/fleetreg/cmd/fleetreg/main_test.go); that
# is the behaviour under test, not an in-process seam shortcut.
#
# Fail-closed on a finding; clean pass (exit 0) when the identity test surface
# has no loopback-TCP bind outside the allowlist, or when there is no identity
# test tree at all (LOUD SKIP, stderr, exit 0 — a tree without identity tests is
# not a failure). No optional host tool: grep(1) + git(1) are always present, so
# there is no missing-tool SKIP path.
#
# --self-test: run a hermetic regression (inject a violating test file and an
# allowlisted one into a throwaway tree, assert the scan flags exactly the
# violation) and exit 0/1 on the self-test result. Wired ahead of the real
# sweep in the Makefile target (the check-actionlint self-test-in-the-gate
# precedent) so a refactor that neuters the matcher fails loudly.
#
# NO_LOOPBACK_SCAN_DIR: repo-root-relative directory to sweep. Defaults to
# "identity". Overridable so the self-test can retarget a throwaway tree without
# editing this script.
#
# Network-free. Read-only: greps only; mutates nothing (the self-test writes
# solely under a mktemp dir it removes).
#
# Exit codes: 0 = no loopback-TCP bind outside the allowlist (or no identity
#               test surface; or --self-test passed).
#             1 = a `net.Listen("tcp", …)` bind found in a non-allowlisted
#               identity/**/*_test.go (or --self-test failed).

set -euo pipefail

# The loopback-TCP bind signature: a net.Listen call whose network argument is a
# tcp family ("tcp", "tcp4", "tcp6"). Any such bind in an identity in-process
# seam test is the regression this lint fails closed on.
readonly BIND_RE='net\.Listen\(\s*"tcp[46]?"'
# Path suffix exempted from the lint: a package-main end-to-end test that drives
# the real serve path (binds a socket exactly as the shipped binary does).
readonly ALLOW_GLOB='*/cmd/*/main_test.go'

# scan_dir DIR — emit the offending "file:line:match" lines under DIR (an
# absolute directory), honouring the cmd/**/main_test.go allowlist. Prints
# nothing and returns 0 when the surface is clean; prints findings and returns 1
# when at least one non-allowlisted bind is present. A DIR with no *_test.go
# files is clean (returns 0).
scan_dir() {
    local dir="$1"
    local hits found=0
    # -r recurse, -E extended regex, -n line numbers, --include restricts to Go
    # test files. grep exits 1 when nothing matches — that is the clean path, so
    # tolerate it via `|| true` and decide on the captured output instead.
    hits="$(grep -rEn --include='*_test.go' "$BIND_RE" "$dir" 2>/dev/null || true)"
    [ -n "$hits" ] || return 0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        # Strip the "file:line:..." prefix down to the path for the allowlist test.
        local path="${line%%:*}"
        # shellcheck disable=SC2254  # ALLOW_GLOB is a deliberate glob pattern.
        case "$path" in
            $ALLOW_GLOB) continue ;;
        esac
        echo "$line"
        found=1
    done <<EOF
$hits
EOF
    [ "$found" -eq 0 ]
}

# --- hermetic self-test -----------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    # A violating in-process seam test (must be flagged).
    mkdir -p "$tmp/identity/mint"
    cat >"$tmp/identity/mint/grpc_seam_test.go" <<'GO'
package mint
// lis, err := net.Listen("tcp", "127.0.0.1:0")
var _ = 0
GO
    # An allowlisted package-main e2e test with the SAME bind (must NOT be flagged).
    mkdir -p "$tmp/identity/grant-service/cmd/grant-service"
    cat >"$tmp/identity/grant-service/cmd/grant-service/main_test.go" <<'GO'
package main
// lis, err := net.Listen("tcp", "127.0.0.1:0")
var _ = 0
GO
    out="$(scan_dir "$tmp/identity" || true)"
    fail=0
    if ! printf '%s\n' "$out" | grep -q 'identity/mint/grpc_seam_test.go'; then
        echo "check-no-loopback-bind: SELF-TEST FAIL — a loopback-TCP bind in a non-allowlisted identity seam test was NOT flagged" >&2
        fail=1
    fi
    if printf '%s\n' "$out" | grep -q 'cmd/grant-service/main_test.go'; then
        echo "check-no-loopback-bind: SELF-TEST FAIL — an allowlisted cmd/**/main_test.go bind was flagged" >&2
        fail=1
    fi
    if [ "$fail" -ne 0 ]; then
        exit 1
    fi
    echo "check-no-loopback-bind: self-test OK (violation flagged, allowlist honoured)"
    exit 0
fi

# --- locate repo root (git-anchored; fall back to script-relative) ----------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    :
else
    ROOT=$(cd "$(dirname "$0")/.." && pwd)
fi

SCAN_DIR="${NO_LOOPBACK_SCAN_DIR:-identity}"
target="${ROOT}/${SCAN_DIR}"

if [ ! -d "$target" ]; then
    echo "check-no-loopback-bind: SKIP — no ${SCAN_DIR}/ tree at ${target}; nothing to lint on this tree" >&2
    exit 0
fi

if findings="$(scan_dir "$target")"; then
    echo "check-no-loopback-bind: OK — no loopback-TCP bind in ${SCAN_DIR}/**/*_test.go outside the cmd/**/main_test.go allowlist (in-process seam tests use bufconn)"
    exit 0
else
    {
        echo "check-no-loopback-bind: ERROR: loopback-TCP net.Listen(\"tcp\", …) found in an in-process ${SCAN_DIR} seam test — use an in-memory bufconn.Listener instead (allowlist: cmd/**/main_test.go):"
        printf '%s\n' "$findings" | sed 's#^#  #'
    } >&2
    exit 1
fi
