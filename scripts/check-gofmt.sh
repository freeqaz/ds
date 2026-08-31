#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# check-gofmt.sh — toolchain-pinned gofmt formatting gate (repo-lints class).
#
# WHAT THIS GUARDS. Every tracked Go file in the repo's built trees must be
# formatted by the gofmt of the repo's PINNED Go toolchain (the `go` directive
# in go.work — the same version setup-go installs in CI). A file that is not
# gofmt-clean fails the gate CLOSED, naming the file and printing the exact
# `gofmt -w` command that fixes it.
#
# WHY IT EXISTS. The repo had NO gofmt gate: gofmt-dirty files land silently
# because per-package `go build` / `go vet` / `go test` NEVER inspect
# formatting, so a file authored under a different toolchain (a doc-comment
# list-item reflow, a struct/var alignment column shift, etc.) surfaces
# NOWHERE until a downstream reader trips over it — this already cost a
# fix-up commit (ba28d377). This turns "is the tree gofmt-clean?" into a
# STANDING, CI-visible invariant folded into `make repo-lints`.
#
# TOOLCHAIN PIN (the load-bearing property). gofmt's output is version-
# sensitive: newer toolchains reflow doc comments and re-align columns
# differently, so a gate that ran the caller's ambient gofmt would render a
# DIFFERENT verdict on a dev box (go1.26) than in CI (the go.work pin). This
# gate is deterministic: it reads the canonical `go` line from go.work and
# invokes the gofmt of EXACTLY that toolchain via GOTOOLCHAIN=go<version>
# (the Go command materializes the pinned toolchain — a no-op when the local
# toolchain already IS that version, e.g. in CI after setup-go). If the pinned
# toolchain cannot be materialized (offline box whose local go differs from the
# pin), the gate FAILS LOUDLY rather than silently formatting against the wrong
# version — you never get a green verdict from an unpinned gofmt.
#
# SCOPE. The Go trees CI already builds (GOFMT_TREES below): orchestrator,
# client, vm, proto/gen/go, assurance, scripts/taskdb, identity. boundary/ is
# DELIBERATELY EXCLUDED — it is the executable specification (D26), RED by
# design and outside go.work; formatting it is not this gate's business. gofmt
# itself skips testdata/ and dot/underscore dirs.
#
# ALLOWLIST RATCHET (the doc-links-allowlist.txt precedent). Pre-existing
# gofmt-dirty files that predate this gate — and live in trees this gate's
# introducing change does not own — are suppressed by an audited allowlist
# (scripts/check-gofmt-allowlist.txt, one repo-relative path per line). The
# gate fails closed on any dirty file NOT in the allowlist, so it ratchets:
# new drift is caught, the known debt is tracked for a follow-up sweep, and a
# file that gets fixed simply drops out of the dirty set (a stale allowlist
# entry is reported, never fatal). NEVER silently widen the allowlist.
#
# Usage:
#   sh scripts/check-gofmt.sh              # sweep the real tree, fail closed on drift
#   sh scripts/check-gofmt.sh --self-test  # hermetic clean-PASS / dirty-FAIL / allowlist harness
#
# Overrides (used only by --self-test to stay hermetic; never set in CI):
#   GO_WORK             canonical go.work whose `go` directive is the pin (default: <repo>/go.work)
#   GOFMT_BASE          directory the trees are resolved against and gofmt runs in (default: <repo>)
#   GOFMT_TREES         space-separated tree list to sweep (default: the CI-built set)
#   DS_GOFMT_ALLOWLIST  allowlist path (default: <script-dir>/check-gofmt-allowlist.txt)
#
# Exit codes:
#   0 — every non-allowlisted file in scope is gofmt-clean (or --self-test passed).
#   1 — a non-allowlisted file is gofmt-dirty; or the pinned toolchain could not
#       be materialized; or go.work has no `go` directive; or --self-test failed.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GO_WORK="${GO_WORK:-$REPO_ROOT/go.work}"
GOFMT_BASE="${GOFMT_BASE:-$REPO_ROOT}"
# The Go trees CI already builds. boundary/ is excluded by design (D26). gofmt
# recurses each and skips testdata/ + dot/underscore dirs on its own.
GOFMT_TREES="${GOFMT_TREES:-orchestrator client vm proto/gen/go assurance scripts/taskdb identity}"
DS_GOFMT_ALLOWLIST="${DS_GOFMT_ALLOWLIST:-$SCRIPT_DIR/check-gofmt-allowlist.txt}"

# ---------------------------------------------------------------------------
# resolve_pinned_gofmt — echo the absolute path to the gofmt of the toolchain
#   pinned by GO_WORK's first top-level `go` directive, materializing it via
#   GOTOOLCHAIN if the local toolchain differs. Fails closed (rc 1, reason on
#   stderr) if the pin cannot be read or the pinned toolchain cannot be
#   materialized — the gate never falls back to an unpinned gofmt.
# ---------------------------------------------------------------------------
resolve_pinned_gofmt() {
    if [ ! -f "$GO_WORK" ]; then
        echo "check-gofmt: cannot read pin: $GO_WORK missing" >&2
        return 1
    fi
    # First top-level `go` directive; awk steps over the leading `//` comment
    # block (comment lines have no `go` first field). Byte-identical to the
    # extractor check-go-line.sh uses.
    _want="$(awk '$1=="go"{print $2; exit}' "$GO_WORK")"
    if [ -z "$_want" ]; then
        echo "check-gofmt: could not read 'go' directive from $GO_WORK" >&2
        return 1
    fi
    _tc="go$_want"
    if ! command -v go >/dev/null 2>&1; then
        echo "check-gofmt: the 'go' command is not on PATH — cannot materialize pinned toolchain $_tc" >&2
        return 1
    fi
    # GOTOOLCHAIN=go<version> forces EXACTLY that toolchain (download/cache when
    # the local one differs; a no-op when it already matches, e.g. CI after
    # setup-go). GOROOT of that toolchain contains its bundled gofmt.
    _goroot="$(GOTOOLCHAIN="$_tc" go env GOROOT 2>/dev/null || true)"
    _gofmt="$_goroot/bin/gofmt"
    if [ -z "$_goroot" ] || [ ! -x "$_gofmt" ]; then
        echo "check-gofmt: could not materialize the pinned toolchain $_tc" >&2
        echo "check-gofmt: (offline box whose local go differs from the go.work pin? install $_tc or make it fetchable — the gate refuses to run an unpinned gofmt)" >&2
        return 1
    fi
    # Belt-and-suspenders: prove the resolved toolchain really IS the pin, so a
    # future GOTOOLCHAIN semantics change can never silently hand us go1.26's
    # gofmt for a 1.25 pin.
    _gv="$(GOTOOLCHAIN="$_tc" go env GOVERSION 2>/dev/null || true)"
    case "$_gv" in
        "$_tc"|"$_tc"-*) : ;;
        *)
            echo "check-gofmt: pinned toolchain resolved to '$_gv' but the go.work pin is '$_tc' — refusing to run a mismatched gofmt" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$_gofmt"
}

# ---------------------------------------------------------------------------
# run_check — the production sweep. Resolves the pinned gofmt, lists dirty files
#   over GOFMT_TREES (run from GOFMT_BASE so paths are repo-relative), subtracts
#   the allowlist, and fails closed on any survivor.
# ---------------------------------------------------------------------------
run_check() {
    _gofmt="$(resolve_pinned_gofmt)" || return 1
    echo "check-gofmt: pinned gofmt = $_gofmt"
    echo "check-gofmt: trees = $GOFMT_TREES"

    # Collect dirty files (repo-relative, since we cd into GOFMT_BASE). gofmt -l
    # prints one path per non-clean file and nothing when the tree is clean.
    _dirty="$(cd "$GOFMT_BASE" && "$_gofmt" -l $GOFMT_TREES)"

    # Load the allowlist (skip blank lines and #-comments). Missing file = empty.
    _allow=""
    if [ -f "$DS_GOFMT_ALLOWLIST" ]; then
        _allow="$(sed -e 's/#.*$//' -e 's/[[:space:]]*$//' "$DS_GOFMT_ALLOWLIST" | grep -v '^[[:space:]]*$' || true)"
    fi

    # Survivors = dirty minus allowlisted (exact-line match).
    _survivors=""
    if [ -n "$_dirty" ]; then
        _survivors="$(printf '%s\n' "$_dirty" | while IFS= read -r f; do
            [ -n "$f" ] || continue
            if printf '%s\n' "$_allow" | grep -qxF "$f"; then
                continue
            fi
            printf '%s\n' "$f"
        done)"
    fi

    # Report stale allowlist entries (listed but now clean) — informational,
    # never fatal, so a fix that cleans a file cannot turn the gate red.
    if [ -n "$_allow" ]; then
        printf '%s\n' "$_allow" | while IFS= read -r a; do
            [ -n "$a" ] || continue
            if ! printf '%s\n' "$_dirty" | grep -qxF "$a"; then
                echo "check-gofmt: NOTE: allowlisted path is now gofmt-clean (prune it): $a" >&2
            fi
        done
    fi

    if [ -n "$_survivors" ]; then
        echo "" >&2
        echo "check-gofmt: FAIL — the following tracked Go files are not gofmt-clean under the pinned toolchain:" >&2
        printf '%s\n' "$_survivors" | sed 's/^/  /' >&2
        echo "" >&2
        echo "check-gofmt: fix with the PINNED gofmt (do not use an ambient 'gofmt'):" >&2
        echo "  $_gofmt -w $(printf '%s ' $_survivors)" >&2
        return 1
    fi

    echo "check-gofmt: OK — all files in scope are gofmt-clean under the pinned toolchain"
    return 0
}

# ---------------------------------------------------------------------------
# --self-test: hermetic regression harness dispatched BEFORE any real-tree read.
#   Stands up a temp sandbox (a clean .go + a deliberately dirty .go under a
#   package dir, plus a synthetic go.work pinned to the REAL repo version so the
#   same cached toolchain is reused) and re-invokes THIS script across three arms:
#     (A) clean-only              -> rc 0
#     (B) clean + dirty, no allow -> rc 1, output names the dirty file
#     (C) clean + dirty, allowed  -> rc 0
#   The sandbox is removed via an EXIT trap; the real tree is never consulted.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    _SELF="$SCRIPT_DIR/$(basename "$0")"

    # Reuse the REAL repo pin so the self-test resolves the same toolchain the
    # production sweep will (no second version downloaded).
    _real_want="$(awk '$1=="go"{print $2; exit}' "$REPO_ROOT/go.work" 2>/dev/null || true)"
    if [ -z "$_real_want" ]; then
        echo "check-gofmt: self-test could not read the repo go.work pin" >&2
        exit 1
    fi

    _ST_ROOT="$(mktemp -d)"
    trap 'rm -rf "$_ST_ROOT"' EXIT

    # Synthetic go.work: a leading `//` comment block (proving the awk extractor
    # skips comments) then the real pin.
    {
        printf '// synthetic go.work self-test fixture\n'
        printf 'go %s\n' "$_real_want"
        printf '\nuse (\n\t./pkg\n)\n'
    } > "$_ST_ROOT/go.work"

    # Clean and dirty files live in SEPARATE package dirs so the clean-only arm
    # has no dirty file in scope.
    mkdir -p "$_ST_ROOT/pkgclean" "$_ST_ROOT/pkgdirty"
    # Clean file: already gofmt-canonical.
    printf 'package pkgclean\n\nfunc Clean() {}\n' > "$_ST_ROOT/pkgclean/clean.go"
    # Dirty file: double space after ()  and an unindented body gofmt rewrites,
    # reliably dirty across toolchain versions.
    printf 'package pkgdirty\n\nfunc Dirty()  {\nx:=1\n_ = x\n}\n' > "$_ST_ROOT/pkgdirty/dirty.go"

    # Empty allowlist (arm A/B) and a dirty-suppressing allowlist (arm C).
    : > "$_ST_ROOT/allow-empty.txt"
    printf '# self-test allowlist\npkgdirty/dirty.go\n' > "$_ST_ROOT/allow-dirty.txt"

    _st_fail=0
    # _st_arm NAME WANT_RC GREP TREES ALLOWLIST -- runs the check over TREES.
    _st_arm() {
        _arm_name="$1"; _arm_want="$2"; _arm_grep="$3"; _arm_trees="$4"; _arm_allow="$5"
        _arm_rc=0
        GO_WORK="$_ST_ROOT/go.work" \
        GOFMT_BASE="$_ST_ROOT" \
        GOFMT_TREES="$_arm_trees" \
        DS_GOFMT_ALLOWLIST="$_arm_allow" \
            sh "$_SELF" > "$_ST_ROOT/out" 2>&1 || _arm_rc=$?
        if [ "$_arm_rc" -ne "$_arm_want" ]; then
            printf 'self-test FAILED: %s (want rc=%s got rc=%s)\n' "$_arm_name" "$_arm_want" "$_arm_rc" >&2
            cat "$_ST_ROOT/out" >&2
            _st_fail=1
            return
        fi
        if [ -n "$_arm_grep" ] && ! grep -q "$_arm_grep" "$_ST_ROOT/out"; then
            printf 'self-test FAILED: %s (rc ok but output did not name %s)\n' "$_arm_name" "$_arm_grep" >&2
            cat "$_ST_ROOT/out" >&2
            _st_fail=1
            return
        fi
        printf 'self-test: %s OK (rc=%s)\n' "$_arm_name" "$_arm_rc"
    }

    _st_arm "clean-passes"        0 ""          "pkgclean"          "$_ST_ROOT/allow-empty.txt"
    _st_arm "dirty-fails"         1 "dirty.go"  "pkgclean pkgdirty" "$_ST_ROOT/allow-empty.txt"
    _st_arm "allowlisted-passes"  0 ""          "pkgclean pkgdirty" "$_ST_ROOT/allow-dirty.txt"

    if [ "$_st_fail" -ne 0 ]; then
        echo "check-gofmt: self-test FAILED" >&2
        exit 1
    fi
    echo "check-gofmt: self-test PASSED"
    exit 0
fi

# ---------------------------------------------------------------------------
# Production path.
# ---------------------------------------------------------------------------
if [ "$#" -ne 0 ]; then
    echo "check-gofmt: unknown argument: $1 (usage: sh scripts/check-gofmt.sh [--self-test])" >&2
    exit 1
fi

run_check
