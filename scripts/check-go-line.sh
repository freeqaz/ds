#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# check-go-line.sh — single source for the off-workspace go-line toolchain-
# coupling guard consumed by .github/workflows/go.yml (off-workspace-modules
# lane) and .github/workflows/grant-sigterm-drain.yml (grant-process-smoke lane).
#
# PURPOSE
#   Both CI lanes pin setup-go from a SINGLE off-workspace go.mod
#   (go.yml: identity/fakes/digest-publisher/go.mod; grant-sigterm-drain.yml:
#   identity/grant-service/go.mod). If any off-workspace module bumped its `go`
#   line ahead of go.work's, it would silently build on a DIFFERENT toolchain
#   than it declares. Each lane carried its OWN inlined awk-extract + compare of
#   the same invariant, and the two copies drift. This script is the single home
#   for that extract/compare: it reads go.work's first top-level `go` directive
#   as the canonical truth and reconciles every module go.mod passed as an
#   argument against it.
#
#   The lane-specific rationale (which module setup-go pins from, why a mismatch
#   builds on the wrong toolchain) stays in each workflow step's comments; this
#   script emits a neutral `GO-LINE MISMATCH:` prefix naming the offending path
#   and both versions, matching the scope's "same failure wording where
#   reasonable".
#
# Usage:
#   sh scripts/check-go-line.sh <module-go.mod> [<module-go.mod> ...]
#   sh scripts/check-go-line.sh --self-test
#
#   Each positional argument is a path to a module's go.mod (e.g.
#   identity/mint/go.mod). A missing input FILE is a per-arg SKIP (mirroring
#   go.yml's `[ -f "$mod/go.mod" ] || continue` — identity/mint is documented as
#   legitimately possibly go.mod-less / "language-unbound"). A go.mod that IS
#   present but has no `go` directive, or one whose `go` line diverges from
#   go.work's, fails CLOSED.
#
# GO_WORK override (deliberately NOT GOWORK):
#   The canonical go.work path defaults to <repo-root>/go.work and is overridable
#   via the GO_WORK environment variable (underscore) — used by --self-test to
#   point at a synthetic sandbox go.work. It is intentionally NOT named GOWORK:
#   both consuming CI jobs export `GOWORK: "off"` at the job level, so reading
#   GOWORK here would try to open a file literally named `off` and break the lane.
#
# Exit codes:
#   0 — every checked module agrees with go.work's `go` directive (missing input
#       files were skipped); or --self-test passed.
#   1 — a checked module's `go` line is missing or diverges (fail-closed); or
#       zero module arguments were given (an emptied list must not pass); or
#       go.work is missing / has no `go` directive; or --self-test failed.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# GO_WORK (underscore), NOT the Go toolchain's GOWORK: both consuming CI jobs pin
# `GOWORK: "off"` at job level, so consulting GOWORK would try to read a file
# named `off`. The override is a distinct env var only this guard reads.
GO_WORK="${GO_WORK:-$REPO_ROOT/go.work}"

# ---------------------------------------------------------------------------
# --self-test: hermetic regression harness, dispatched BEFORE any real-tree read.
#   Builds a self-contained temp sandbox with a synthetic go.work pinned to a
#   canary version (1.99.1) that can never match the real tree, plus synthetic
#   module go.mods, and re-invokes THIS script (GO_WORK pointed at the sandbox)
#   across four arms:
#     (A) matched go line          -> rc 0
#     (B) divergent go line        -> rc 1, and the failure names the module
#     (C) present but no go line   -> rc 1 (fail-closed)
#     (D) matched + missing file   -> rc 0 (per-arg skip)
#   The sandbox is removed via an EXIT trap; the real tree is never consulted.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    _SELF="$SCRIPT_DIR/$(basename "$0")"
    _ST_ROOT="$(mktemp -d)"
    trap 'rm -rf "$_ST_ROOT"' EXIT

    # Synthetic go.work: a leading `//` comment block (so the awk extractor is
    # proven to skip comments) then a canary `go` directive that differs from the
    # real tree's — a bug that fell through to the default go.work would then
    # fail the matched arm, catching an unpassed-GO_WORK regression.
    {
        printf '// synthetic go.work self-test fixture\n'
        printf '// canary version, never matches the real tree\n'
        printf 'go 1.99.1\n'
        printf '\nuse (\n\t./modmatch\n)\n'
    } > "$_ST_ROOT/go.work"

    mkdir -p "$_ST_ROOT/modmatch" "$_ST_ROOT/moddiverge" "$_ST_ROOT/modnogoline"
    {
        printf 'module example.test/match\n\n'
        printf 'go 1.99.1\n'
    } > "$_ST_ROOT/modmatch/go.mod"
    {
        printf 'module example.test/diverge\n\n'
        printf 'go 1.88.7\n'
    } > "$_ST_ROOT/moddiverge/go.mod"
    # A go.mod with NO `go` directive at all (module line only).
    printf 'module example.test/nogoline\n' > "$_ST_ROOT/modnogoline/go.mod"

    _st_fail=0

    # _st_arm NAME WANT_RC [grep-substr] -- ARGS...
    #   Re-invoke $_SELF with GO_WORK pointed at the sandbox over ARGS, capture rc
    #   under set -eu (bare `cmd; rc=$?` would abort on nonzero), and assert the
    #   rc. If grep-substr is non-empty, also assert the captured output names it.
    _st_arm() {
        _arm_name="$1"
        _arm_want="$2"
        _arm_grep="$3"
        shift 3   # remaining "$@" are the module go.mod path arguments
        _arm_rc=0
        GO_WORK="$_ST_ROOT/go.work" sh "$_SELF" "$@" > "$_ST_ROOT/out" 2>&1 || _arm_rc=$?
        if [ "$_arm_rc" -ne "$_arm_want" ]; then
            printf 'self-test FAILED: %s (want rc=%s got rc=%s)\n' \
                "$_arm_name" "$_arm_want" "$_arm_rc" >&2
            cat "$_ST_ROOT/out" >&2
            _st_fail=1
            return
        fi
        if [ -n "$_arm_grep" ] && ! grep -q "$_arm_grep" "$_ST_ROOT/out"; then
            printf 'self-test FAILED: %s (rc ok but output did not name %s)\n' \
                "$_arm_name" "$_arm_grep" >&2
            cat "$_ST_ROOT/out" >&2
            _st_fail=1
            return
        fi
        printf 'self-test: %s OK (rc=%s)\n' "$_arm_name" "$_arm_rc"
    }

    # (A) matched -> rc 0
    _st_arm "matched-go-line" 0 "" "$_ST_ROOT/modmatch/go.mod"
    # (B) divergent -> rc 1, failure names the module path
    _st_arm "divergent-go-line" 1 "moddiverge" "$_ST_ROOT/moddiverge/go.mod"
    # (C) present but no go directive -> rc 1 (fail-closed)
    _st_arm "missing-go-directive" 1 "modnogoline" "$_ST_ROOT/modnogoline/go.mod"
    # (D) matched + missing input file -> rc 0 (per-arg skip)
    _st_arm "missing-file-skip" 0 "" \
        "$_ST_ROOT/modmatch/go.mod" "$_ST_ROOT/modabsent/go.mod"

    if [ "$_st_fail" -ne 0 ]; then
        printf 'check-go-line: self-test FAILED\n' >&2
        exit 1
    fi
    printf 'check-go-line: self-test PASSED\n'
    exit 0
fi

# ---------------------------------------------------------------------------
# Production path.
# ---------------------------------------------------------------------------

# Zero args must fail CLOSED: a botched future YAML edit that empties the module
# list must not turn the guard into a silent no-op.
if [ "$#" -eq 0 ]; then
    echo "check-go-line: usage: sh scripts/check-go-line.sh <module-go.mod> [<module-go.mod> ...]" >&2
    echo "check-go-line: no module go.mod arguments given — refusing to pass (fail-closed)" >&2
    exit 1
fi

if [ ! -f "$GO_WORK" ]; then
    echo "check-go-line: could not read 'go' directive from $GO_WORK (file missing)"
    exit 1
fi

# The canonical `go` line: the first top-level `go` directive in go.work. The
# `exit` after the first match skips any later occurrence and the awk correctly
# steps over the leading `//` comment block (comment lines have no `go` first
# field). Byte-identical to the extractor the two inlined workflow copies used.
want="$(awk '$1=="go"{print $2; exit}' "$GO_WORK")"
if [ -z "$want" ]; then
    echo "check-go-line: could not read 'go' directive from $GO_WORK"
    exit 1
fi
echo "canonical go line ($GO_WORK): $want"

fail=0
for f in "$@"; do
    mod="${f%/go.mod}"
    # Per-arg missing-file SKIP: mirrors go.yml's `[ -f "$mod/go.mod" ] || continue`
    # (identity/mint is legitimately language-unbound until it binds a build).
    if [ ! -f "$f" ]; then
        echo "==> $mod: no go.mod yet (language-unbound) — skipping"
        continue
    fi
    got="$(awk '$1=="go"{print $2; exit}' "$f")"
    if [ -z "$got" ]; then
        echo "GO-LINE MISMATCH: $f has no 'go' directive (want $want from $GO_WORK)"
        fail=1
    elif [ "$got" != "$want" ]; then
        echo "GO-LINE MISMATCH: $f declares 'go $got' but go.work declares 'go $want' — a lane pinning setup-go from one module's go.mod would build on the wrong toolchain"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "go-line consistency check FAILED (see modules above)"
    exit 1
fi
echo "all checked modules agree on go $want"
