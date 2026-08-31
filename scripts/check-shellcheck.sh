#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# check-shellcheck.sh — run shellcheck(1) over the tracked shell-script surface,
# failing closed on a real lint finding.
#
# WHY: repo-lints already mechanizes doc links, SPDX headers, golden byte-
# identity, NFTables grammar, and vendor tracking — but it lints NO shell
# scripts.  The scripts/taskdb/ shell surface keeps growing (lockserver-
# tunnel.sh, ready-work_shim_test.sh, and the shim under test), and a quoting
# or POSIX bug there ships unlinted.  This adds the missing class: a
# static-analysis pass with shellcheck(1) that fails closed on a real finding.
#
# TWO SEVERITY TIERS — the sweep lints two disjoint surfaces at two thresholds:
#
#   1. FULL tier (SHELLCHECK_GLOBS, default "scripts/taskdb/*.sh"): linted at
#      the DEFAULT severity of shellcheck (style and above), failing closed on
#      ANY finding.  This is the original, curated surface — kept clean, so
#      the full lint bites on every class of finding.
#
#   2. ERROR tier (SHELLCHECK_ERROR_GLOBS, default "scripts/check-*.sh"): the
#      repo-lint check scripts themselves — previously UNLINTED — linted at
#      `--severity=error` only.  These scripts carry pre-existing lower-severity
#      findings (word-splitting, useless-cat, unreachable-cleanup style/info/
#      warning notes) that are out of scope to churn here; the error tier is
#      strictly ADDITIVE coverage over a surface that was linted at zero
#      severity before, and it catches the parse-breaking class — exactly the
#      SC1073/SC1072 directive-parse error that was lurking in this very script
#      before the sweep was widened to cover it.  Widen the tier (fix findings +
#      lower its severity) in a dedicated pass; do not weaken the full tier to
#      accommodate it.
#
# Fail-open on a MISSING tool: shellcheck is not guaranteed to be installed on
# every developer machine or CI gate host.  When the tool is absent this is a
# LOUD clean SKIP — the skip reason is printed to stderr (so it appears in CI
# logs) and the script exits 0.  This is the exact fail-open-on-missing-tool
# discipline scripts/check-vendor-tracked.sh and scripts/check-runbook-nft.sh
# already use ("LOUD SKIP (stderr, exit 0) when no ..."): never block work
# because an optional static-analysis tool is unavailable, but fail closed on
# a real finding when the tool IS present.
#
# DS_REQUIRE_SHELLCHECK=1: when this environment variable is set to "1", the
# tool-absent SKIP path becomes a FAIL instead (exit 1, loud reason on
# stderr).  This lets a CI gate leg that provisions shellcheck(1) assert the
# lint is actually exercised — converting the soft skip into a hard CI-enforced
# requirement, mirroring check-runbook-nft.sh's DS_REQUIRE_NFT=1 contract.
# Default behaviour (unset or any value other than "1") is unchanged: LOUD
# clean SKIP with exit 0 when shellcheck is absent.
#
# SHELLCHECK_GLOBS / SHELLCHECK_ERROR_GLOBS: space-separated lists of repo-root-
# relative globs to lint at the full and error tiers respectively.  Defaults are
# "scripts/taskdb/*.sh" and "scripts/check-*.sh".  Overridable so each surface
# can be extended without editing this script, and so a hermetic test can point
# a tier at a throwaway directory.  Globs that match nothing contribute no
# files; if NEITHER tier matches any file at all the check is a LOUD clean SKIP
# (exit 0) — an empty shell surface is not a failure.
#
# Requires: bash, git; shellcheck (optional — drives the SKIP path when absent).
# Network-free.  Idempotent: reads only; mutates nothing.
#
# Exit codes: 0 = shellcheck reported no in-tier findings over the discovered
#               scripts; or shellcheck is absent and DS_REQUIRE_SHELLCHECK≠1
#               (loud skip); or no script matched either tier (loud skip).
#             1 = shellcheck reported at least one in-tier finding over a
#               discovered script; or shellcheck is absent and
#               DS_REQUIRE_SHELLCHECK=1.

set -euo pipefail

# --- locate repo root (git-anchored; fall back to script-relative) ----------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    :
else
    ROOT=$(cd "$(dirname "$0")/.." && pwd)
fi

# Tier surfaces.  Overridable via env so each can grow (or a hermetic test can
# retarget it) without an edit here.
SHELLCHECK_GLOBS="${SHELLCHECK_GLOBS:-scripts/taskdb/*.sh}"
SHELLCHECK_ERROR_GLOBS="${SHELLCHECK_ERROR_GLOBS:-scripts/check-*.sh}"

# --- LOUD SKIP (or FAIL when DS_REQUIRE_SHELLCHECK=1) when shellcheck absent --
# NOTE: if no CI gate host has shellcheck installed, this check is skipped
# fleet-wide and the shell surface goes unlinted.  Install the shellcheck
# package in at least one gate runner image to enforce the lint; set
# DS_REQUIRE_SHELLCHECK=1 on that gate leg to turn the skip into a hard failure
# so a provisioning regression is caught loudly.
if ! command -v shellcheck >/dev/null 2>&1; then
    if [ "${DS_REQUIRE_SHELLCHECK:-}" = "1" ]; then
        echo "check-shellcheck: ERROR: shellcheck(1) not found on PATH and DS_REQUIRE_SHELLCHECK=1 — failing closed (install the shellcheck package on this gate host)" >&2
        exit 1
    fi
    echo "check-shellcheck: SKIP — shellcheck(1) not found on PATH; shell-script lint is SKIPPED on this host (install shellcheck to enforce the lint, or set DS_REQUIRE_SHELLCHECK=1 to turn this skip into a failure)" >&2
    exit 0
fi

# --- discover the scripts for a glob list -----------------------------------
# Populates the global DISCOVERED array with the existing files matched by the
# space-separated glob list in $1.  Each glob is word-split deliberately (the
# arg holds a list of globs); the inner expansion is guarded so a glob that
# matches nothing contributes no phantom path.
discover_scripts() {
    local glob f
    DISCOVERED=()
    for glob in $1; do
        for f in "${ROOT}"/${glob}; do
            # When a glob matches nothing the literal pattern survives expansion;
            # skip any path that does not resolve to an existing file.
            [ -f "$f" ] || continue
            DISCOVERED+=("$f")
        done
    done
}

SC_VERSION="$(shellcheck --version | awk '/^version:/ {print $2}' | head -n1)"
any_linted=0
rc=0

# --- FULL tier: lint at shellcheck's default severity, fail closed on any -----
discover_scripts "$SHELLCHECK_GLOBS"
if [ "${#DISCOVERED[@]}" -gt 0 ]; then
    any_linted=1
    full_scripts=("${DISCOVERED[@]}")
    echo "check-shellcheck: [full] linting ${#full_scripts[@]} shell script(s) at default severity with ${SC_VERSION}"
    for s in "${full_scripts[@]}"; do
        echo "check-shellcheck:   ${s#"${ROOT}"/}"
    done
    if shellcheck "${full_scripts[@]}"; then
        echo "check-shellcheck: [full] OK — shellcheck reported no findings"
    else
        echo "check-shellcheck: [full] ERROR: shellcheck reported findings over [${SHELLCHECK_GLOBS}] (see output above) — failing closed" >&2
        rc=1
    fi
fi

# --- ERROR tier: lint at --severity=error over the wider check-*.sh surface ---
# This surface (the repo-lint check scripts) was previously unlinted; error-tier
# coverage is strictly additive and catches the parse-breaking class without
# churning the pre-existing lower-severity findings those scripts carry.
discover_scripts "$SHELLCHECK_ERROR_GLOBS"
if [ "${#DISCOVERED[@]}" -gt 0 ]; then
    any_linted=1
    err_scripts=("${DISCOVERED[@]}")
    echo "check-shellcheck: [error] linting ${#err_scripts[@]} shell script(s) at --severity=error with ${SC_VERSION}"
    for s in "${err_scripts[@]}"; do
        echo "check-shellcheck:   ${s#"${ROOT}"/}"
    done
    if shellcheck --severity=error "${err_scripts[@]}"; then
        echo "check-shellcheck: [error] OK — shellcheck reported no error-severity findings"
    else
        echo "check-shellcheck: [error] ERROR: shellcheck reported error-severity findings over [${SHELLCHECK_ERROR_GLOBS}] (see output above) — failing closed" >&2
        rc=1
    fi
fi

if [ "$any_linted" -eq 0 ]; then
    echo "check-shellcheck: SKIP — no shell scripts matched [${SHELLCHECK_GLOBS}] or [${SHELLCHECK_ERROR_GLOBS}]; nothing to lint on this tree" >&2
    exit 0
fi

exit "$rc"
