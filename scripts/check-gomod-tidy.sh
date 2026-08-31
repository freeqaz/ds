#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# check-gomod-tidy.sh — assert the standalone identity Go modules' go.mod/go.sum
# are `go mod tidy`-clean, failing closed on tidy drift (a stale `// indirect`
# annotation, a missing/extra require, an unpruned go.sum entry).
#
# WHY: nothing in the standard build gate runs `go mod tidy`. `go build`/`go vet`
# /`go test` (and `go work` for the workspace members) resolve the module graph
# but never PRUNE it, so a dep promoted from indirect to direct (e.g. grpc/
# protobuf once main.go imports the generated types) leaves a stale `// indirect`
# comment — or a now-unused require lingers — with no gate catching the drift.
# identity/mint is additionally standalone (deliberately OUTSIDE go.work — the
# substrate-swap pattern must not perturb the workspace), so even the workspace
# tidy never reaches it. This lint evaluates each module's own go.mod under
# `GOWORK=off go mod tidy -diff` (the module-local graph, independent of go.work
# membership) so that tidy drift fails closed at lint time for both.
#
# NO VERSION BUMPS: `-diff` is READ-ONLY — it never edits go.mod/go.sum, it only
# reports whether tidy WOULD change them. This lint therefore cannot bump a
# dependency; it only asserts the committed files already match `go mod tidy`.
#
# Network-free: run with GOPROXY=off so tidy resolves solely from the local
# module cache (the standalone modules resolve their intra-repo deps via
# `replace` to local paths, and third-party deps come from the warm cache the
# build populated). When the cache is cold and a module cannot be resolved
# offline, that is an ENVIRONMENTAL limit, not drift — this lint LOUD-SKIPs that
# module (stderr, exit 0) rather than failing, so a cold-cache runner stays
# green. A real tidy DIFF (printed by `-diff` to stdout) is always a FAIL.
#
# Fail-open on a MISSING toolchain: when `go` is not on PATH this is a LOUD clean
# SKIP (reason on stderr, exit 0) — the same fail-open-on-missing-tool discipline
# check-shellcheck.sh / check-vendor-tracked.sh use. DS_REQUIRE_GOMOD_TIDY=1
# converts the go-absent SKIP and the cold-cache offline SKIP into a hard FAIL
# (exit 1), so a gate leg that provisions the Go toolchain + a warm cache can
# assert the lint is actually exercised, never vacuously skipped — mirroring
# check-runbook-nft.sh's DS_REQUIRE_NFT=1 contract.
#
# GOMOD_TIDY_MODULES: space-separated list of repo-root-relative module dirs to
# check. Defaults to "identity/grant-service identity/mint". Overridable so the
# standalone-module surface can grow without editing this script.
#
# Requires: bash, git; go (optional — drives the SKIP path when absent).
# Read-only: `-diff` mutates nothing.
#
# Exit codes: 0 = every checked module is tidy (or go absent / cold-cache and
#               DS_REQUIRE_GOMOD_TIDY≠1 → loud skip).
#             1 = at least one module has tidy drift; or go absent / a module is
#               unresolvable offline and DS_REQUIRE_GOMOD_TIDY=1.

set -euo pipefail

REQUIRE="${DS_REQUIRE_GOMOD_TIDY:-}"

# --- locate repo root (git-anchored; fall back to script-relative) ----------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    :
else
    ROOT=$(cd "$(dirname "$0")/.." && pwd)
fi

MODULES="${GOMOD_TIDY_MODULES:-identity/grant-service identity/mint}"

# --- LOUD SKIP (or FAIL when DS_REQUIRE_GOMOD_TIDY=1) when go absent ----------
if ! command -v go >/dev/null 2>&1; then
    if [ "$REQUIRE" = "1" ]; then
        echo "check-gomod-tidy: ERROR: go(1) not found on PATH and DS_REQUIRE_GOMOD_TIDY=1 — failing closed (install the Go toolchain on this gate host)" >&2
        exit 1
    fi
    echo "check-gomod-tidy: SKIP — go(1) not found on PATH; go.mod tidy lint is SKIPPED on this host (install Go to enforce the lint, or set DS_REQUIRE_GOMOD_TIDY=1 to turn this skip into a failure)" >&2
    exit 0
fi

rc=0
for mod in $MODULES; do
    dir="${ROOT}/${mod}"
    if [ ! -f "${dir}/go.mod" ]; then
        echo "check-gomod-tidy: SKIP — no go.mod at ${mod}/; not a module on this tree" >&2
        continue
    fi

    # Capture stdout (the tidy diff) and stderr (toolchain/resolution errors)
    # separately so a real DIFF (stdout) is distinguished from a cold-cache
    # offline failure (stderr). GOWORK=off forces the standalone module graph;
    # GOPROXY=off keeps the lint network-free.
    err_file="$(mktemp)"
    if diff_out="$( cd "$dir" && GOWORK=off GOPROXY=off GOFLAGS=-mod=mod go mod tidy -diff 2>"$err_file" )"; then
        rm -f "$err_file"
        echo "check-gomod-tidy: OK — ${mod} is go mod tidy-clean"
        continue
    fi

    # Non-zero exit. A non-empty stdout diff is real tidy drift → fail closed.
    if [ -n "$diff_out" ]; then
        rm -f "$err_file"
        {
            echo "check-gomod-tidy: ERROR: ${mod} is NOT go mod tidy-clean — run \`(cd ${mod} && GOWORK=off go mod tidy)\` and commit the result (no version bumps expected):"
            printf '%s\n' "$diff_out" | sed 's#^#  #'
        } >&2
        rc=1
        continue
    fi

    # Empty stdout + non-zero exit == the toolchain could not resolve the module
    # offline (cold cache), not drift. Environmental SKIP unless DS_REQUIRE=1.
    err_msg="$(cat "$err_file" 2>/dev/null || true)"
    rm -f "$err_file"
    if [ "$REQUIRE" = "1" ]; then
        {
            echo "check-gomod-tidy: ERROR: ${mod} could not be resolved offline (GOPROXY=off) and DS_REQUIRE_GOMOD_TIDY=1 — warm the module cache on this gate host (\`go mod download\` in the module) before enforcing:"
            printf '%s\n' "$err_msg" | sed 's#^#  #'
        } >&2
        rc=1
        continue
    fi
    {
        echo "check-gomod-tidy: SKIP — ${mod} could not be resolved offline (cold module cache; GOPROXY=off). tidy drift is UNVERIFIED for this module on this host; warm the cache or set DS_REQUIRE_GOMOD_TIDY=1 to turn this skip into a failure. go stderr was:"
        printf '%s\n' "$err_msg" | sed 's#^#  #'
    } >&2
done

exit "$rc"
