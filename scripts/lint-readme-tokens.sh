#!/bin/sh
# lint-readme-tokens.sh — shared helper: declarative README-token anti-drift guard.
#
# PURPOSE
#   Verify that load-bearing literal tokens in a README.md stay in sync with
#   their canonical source of truth.  This is the generalised form of the
#   README token guard that was hand-rolled inside
#   images/mirror/lint-env-drift.sh --self-test (wave16b); centralising it
#   here retires the first-match residual risk and enables every image-tree
#   lint script to guard its own README tokens with zero hand-rolled
#   reconciliation code.
#
# ANCHOR CONTRACT — UNIQUE-MATCH REQUIRED
#   Every token is keyed on a README anchor pattern (a grep -E regex).  The
#   helper requires the anchor to match EXACTLY ONE line in README.md.  Zero
#   or multiple matches is itself a failure (not a pass-through): this retires
#   the wave-1 first-match residual risk where two matching lines could have
#   returned the wrong one silently.
#
# USAGE — sourcing mode (the normal caller path)
#   Source this script from another lint script, then register tokens with
#   lrt_register, then call lrt_check_all.
#
#   Example:
#     . scripts/lint-readme-tokens.sh
#     lrt_set_readme /path/to/README.md
#
#     lrt_register  "TOKEN_NAME" \
#       "sh -c '...extraction cmd...'" \
#       "regex that matches EXACTLY ONE line in README.md" \
#       "sed expr to extract the token value from that matched line"
#
#     lrt_check_all || exit 1
#
# USAGE — --self-test mode
#   sh scripts/lint-readme-tokens.sh --self-test
#   Runs positive + drift fixtures against an in-process synthetic README and
#   token spec.  Exit 0 on success, non-zero on any failure.
#
# USAGE — --check mode (standalone single-file check)
#   Sourcing is the preferred path; --check is a convenience for ad-hoc runs.
#   Not used by the image-tree lint scripts; they source and register directly.
#
#   sh scripts/lint-readme-tokens.sh --check README ANCHOR TRUTH_CMD EXTRACT [NAME]
#
#   Registers a single token and calls lrt_check_all.  Arguments match the
#   lrt_register parameters: ANCHOR is a grep -E pattern (unique-match
#   required), TRUTH_CMD is eval'd for the source-of-truth value, EXTRACT is a
#   sed expression applied to the matched README line.  Returns the same exit
#   codes as the sourcing path (0 match / 1 drift / 2 structural).
#
# ENVIRONMENT
#   LRT_README   — override the README path (useful in tests).
#
# EXIT CODES
#   0  — all tokens matched (or self-test passed)
#   1  — one or more tokens drifted (or self-test failed)
#   2  — structural failure: README not found, anchor matched 0 or >1 lines,
#         or extraction returned empty output
#
# SPDX-License-Identifier: Apache-2.0

set -eu

# ---------------------------------------------------------------------------
# Internal state — arrays emulated via shell variables with a count index.
# Names use _LRT_ prefix to avoid collisions when sourced.
# ---------------------------------------------------------------------------
_LRT_COUNT=0
_LRT_README=""

# lrt_set_readme PATH — set the README path for lrt_check_all.
lrt_set_readme() {
    _LRT_README="$1"
}

# lrt_register NAME TRUTH_CMD ANCHOR_PATTERN EXTRACT_EXPR
#   NAME          — a short label for error messages (e.g. "loopback-set")
#   TRUTH_CMD     — shell command string; stdout is the source-of-truth value
#   ANCHOR_PATTERN — grep -E pattern that must match EXACTLY ONE line in README
#   EXTRACT_EXPR  — sed expression applied to the single matched line to produce
#                   the README-side value for comparison
lrt_register() {
    _n="$_LRT_COUNT"
    eval "_LRT_NAME_${_n}=\"\$1\""
    eval "_LRT_TRUTH_${_n}=\"\$2\""
    eval "_LRT_ANCHOR_${_n}=\"\$3\""
    eval "_LRT_EXTRACT_${_n}=\"\$4\""
    _LRT_COUNT=$((_LRT_COUNT + 1))
}

# ---------------------------------------------------------------------------
# lrt_check TOKEN_INDEX README_PATH
#   Returns 0 if token matches, 1 if drift, 2 if structural failure.
#   Prints a diagnostic to stderr on any non-zero exit.
# ---------------------------------------------------------------------------
_lrt_check_one() {
    _idx="$1"
    _readme="$2"

    eval "_name=\"\$_LRT_NAME_${_idx}\""
    eval "_truth_cmd=\"\$_LRT_TRUTH_${_idx}\""
    eval "_anchor=\"\$_LRT_ANCHOR_${_idx}\""
    eval "_extract=\"\$_LRT_EXTRACT_${_idx}\""

    # --- source-of-truth value ---
    _truth_val="$(eval "$_truth_cmd" 2>&1)" || {
        printf 'lint-readme-tokens: STRUCTURAL [%s] truth command failed: %s\n' \
            "$_name" "$_truth_val" >&2
        return 2
    }
    if [ -z "$_truth_val" ]; then
        printf 'lint-readme-tokens: STRUCTURAL [%s] truth command returned empty output\n' \
            "$_name" >&2
        return 2
    fi

    # --- unique-match anchoring ---
    _match_count="$(grep -cE "$_anchor" "$_readme" 2>/dev/null || true)"
    if [ "$_match_count" -eq 0 ]; then
        printf 'lint-readme-tokens: STRUCTURAL [%s] anchor matched 0 lines in %s (pattern: %s)\n' \
            "$_name" "$_readme" "$_anchor" >&2
        return 2
    fi
    if [ "$_match_count" -gt 1 ]; then
        printf 'lint-readme-tokens: STRUCTURAL [%s] anchor matched %d lines in %s (must be unique; pattern: %s)\n' \
            "$_name" "$_match_count" "$_readme" "$_anchor" >&2
        return 2
    fi

    # --- extract README-side value ---
    _readme_val="$(grep -E "$_anchor" "$_readme" | sed "$_extract")"
    if [ -z "$_readme_val" ]; then
        printf 'lint-readme-tokens: STRUCTURAL [%s] extract expression produced empty output from matched line (anchor: %s)\n' \
            "$_name" "$_anchor" >&2
        return 2
    fi

    # --- reconcile ---
    if [ "$_truth_val" != "$_readme_val" ]; then
        printf 'lint-readme-tokens: DRIFT [%s] truth=(%s)  readme=(%s)  [anchor: %s]\n' \
            "$_name" "$_truth_val" "$_readme_val" "$_anchor" >&2
        return 1
    fi

    printf 'lint-readme-tokens: OK [%s] (%s)\n' "$_name" "$_truth_val"
    return 0
}

# ---------------------------------------------------------------------------
# lrt_check_all [README_PATH]
#   Check all registered tokens.  README_PATH overrides lrt_set_readme().
#   Returns 0 if all pass, 2 on structural failure, 1 on any drift.
# ---------------------------------------------------------------------------
lrt_check_all() {
    _readme="${1:-${LRT_README:-${_LRT_README:-}}}"
    if [ -z "$_readme" ]; then
        printf 'lint-readme-tokens: STRUCTURAL no README path set (call lrt_set_readme or pass as arg)\n' >&2
        return 2
    fi
    if [ ! -f "$_readme" ]; then
        printf 'lint-readme-tokens: STRUCTURAL README not found: %s\n' "$_readme" >&2
        return 2
    fi

    _overall=0
    _i=0
    while [ "$_i" -lt "$_LRT_COUNT" ]; do
        _lrt_check_one "$_i" "$_readme" || {
            _rc=$?
            # structural failure (2) overrides drift (1)
            if [ "$_rc" -gt "$_overall" ]; then
                _overall="$_rc"
            fi
        }
        _i=$((_i + 1))
    done
    return "$_overall"
}

# ---------------------------------------------------------------------------
# --self-test: positive and drift fixtures (in-process, no external README).
#
# Guard: only run when this script is the MAIN script (not when sourced by
# another script that happens to pass --self-test).  Checking $0 avoids the
# POSIX behaviour where positional params leak through to sourced files.
# ---------------------------------------------------------------------------
_lrt_is_main=0
case "$0" in
    *lint-readme-tokens.sh) _lrt_is_main=1 ;;
esac
if [ "$_lrt_is_main" -eq 1 ] && [ "${1:-}" = "--check" ]; then
    # --check README ANCHOR TRUTH_CMD EXTRACT [NAME]
    if [ $# -lt 5 ]; then
        printf 'usage: %s --check README ANCHOR TRUTH_CMD EXTRACT [NAME]\n' "$0" >&2
        exit 2
    fi
    _chk_readme="$2"
    _chk_anchor="$3"
    _chk_truth="$4"
    _chk_extract="$5"
    _chk_name="${6:-token}"
    lrt_set_readme "$_chk_readme"
    lrt_register "$_chk_name" "$_chk_truth" "$_chk_anchor" "$_chk_extract"
    lrt_check_all
    exit $?
fi

if [ "$_lrt_is_main" -eq 1 ] && [ "${1:-}" = "--self-test" ]; then

    _ST_TMPDIR="$(mktemp -d)"
    _st_cleanup() { rm -rf "$_ST_TMPDIR"; }
    trap _st_cleanup EXIT

    _ST_README="$_ST_TMPDIR/README.md"
    _FAIL=0

    # Helpers
    _st_pass() { printf 'self-test: PASS — %s\n' "$1"; }
    _st_fail() { printf 'self-test: FAIL — %s\n' "$1" >&2; _FAIL=1; }

    # -----------------------------------------------------------------
    # Fixture: synthetic README with two tokens
    #   - "accepted-set" token:  "{127.0.0.1, [::1]}" (loopback set)
    #   - "drift-count" token:   "10 recognized drifts"
    # -----------------------------------------------------------------
    _write_readme() {
        printf '%s\n' \
            '# Test README' \
            '' \
            'The accepted loopback set is {127.0.0.1, [::1]} per the lint.' \
            'There are 10 recognized drifts total.' \
            'Nothing else interesting here.' \
            > "$_ST_README"
    }

    # Source-of-truth commands used in positive fixture
    _TRUTH_SET="printf '127.0.0.1 [::1]'"
    _ANCHOR_SET='accepted loopback set is \{'
    _EXTRACT_SET='s/.*{\([^}]*\)}.*/\1/; s/, / /g; s/`//g'

    _TRUTH_COUNT="printf '10'"
    _ANCHOR_COUNT='[0-9][0-9]* recognized drifts'
    # NOTE: use [^0-9]\(...\) to avoid greedy .* stealing digits from the count.
    _EXTRACT_COUNT='s/.*[^0-9]\([0-9][0-9]*\) recognized drifts.*/\1/'

    # Reset internal state between sub-tests
    _st_reset() {
        _LRT_COUNT=0
        _LRT_README=""
    }

    # -----------------------------------------------------------------
    # Test 1: positive fixture — both tokens match
    # -----------------------------------------------------------------
    _write_readme
    _st_reset
    lrt_set_readme "$_ST_README"
    lrt_register "accepted-set"  "$_TRUTH_SET"   "$_ANCHOR_SET"   "$_EXTRACT_SET"
    lrt_register "drift-count"   "$_TRUTH_COUNT" "$_ANCHOR_COUNT" "$_EXTRACT_COUNT"
    if lrt_check_all >/dev/null 2>&1; then
        _st_pass "positive fixture: both tokens match"
    else
        _st_fail "positive fixture: expected rc=0, got non-zero"
    fi

    # -----------------------------------------------------------------
    # Test 2: drift fixture — wrong drift-count in README
    # -----------------------------------------------------------------
    printf '%s\n' \
        '# Test README' \
        '' \
        'The accepted loopback set is {127.0.0.1, [::1]} per the lint.' \
        'There are 99 recognized drifts total.' \
        > "$_ST_README"
    _st_reset
    lrt_set_readme "$_ST_README"
    lrt_register "accepted-set"  "$_TRUTH_SET"   "$_ANCHOR_SET"   "$_EXTRACT_SET"
    lrt_register "drift-count"   "$_TRUTH_COUNT" "$_ANCHOR_COUNT" "$_EXTRACT_COUNT"
    _rc2=0
    lrt_check_all >/dev/null 2>&1 || _rc2=$?
    if [ "$_rc2" -ne 0 ]; then
        _st_pass "drift fixture (wrong count): drift caught (rc=$_rc2)"
    else
        _st_fail "drift fixture (wrong count): drift NOT caught (rc=0)"
    fi

    # -----------------------------------------------------------------
    # Test 3: drift fixture — wrong set in README
    # -----------------------------------------------------------------
    printf '%s\n' \
        '# Test README' \
        '' \
        'The accepted loopback set is {0.0.0.0, [::1]} per the lint.' \
        'There are 10 recognized drifts total.' \
        > "$_ST_README"
    _st_reset
    lrt_set_readme "$_ST_README"
    lrt_register "accepted-set"  "$_TRUTH_SET"   "$_ANCHOR_SET"   "$_EXTRACT_SET"
    lrt_register "drift-count"   "$_TRUTH_COUNT" "$_ANCHOR_COUNT" "$_EXTRACT_COUNT"
    _rc3=0
    lrt_check_all >/dev/null 2>&1 || _rc3=$?
    if [ "$_rc3" -ne 0 ]; then
        _st_pass "drift fixture (wrong set): drift caught (rc=$_rc3)"
    else
        _st_fail "drift fixture (wrong set): drift NOT caught (rc=0)"
    fi

    # -----------------------------------------------------------------
    # Test 4: structural failure — anchor matches 0 lines (anchor gone)
    # -----------------------------------------------------------------
    _write_readme
    _st_reset
    lrt_set_readme "$_ST_README"
    lrt_register "missing-anchor"  "printf 'x'" "THIS_ANCHOR_DOES_NOT_EXIST_XYZ_123" "s/.*/x/"
    _rc4=0
    lrt_check_all >/dev/null 2>&1 || _rc4=$?
    if [ "$_rc4" -eq 2 ]; then
        _st_pass "structural failure (anchor=0): rc=2 as expected"
    else
        _st_fail "structural failure (anchor=0): expected rc=2, got rc=$_rc4"
    fi

    # -----------------------------------------------------------------
    # Test 5: structural failure — anchor matches multiple lines (non-unique)
    # -----------------------------------------------------------------
    printf '%s\n' \
        '# Test README' \
        '' \
        'The accepted loopback set is {127.0.0.1, [::1]} per the lint.' \
        'Another accepted loopback set line appears here too.' \
        'There are 10 recognized drifts total.' \
        > "$_ST_README"
    _st_reset
    lrt_set_readme "$_ST_README"
    lrt_register "multi-match"  "printf '127.0.0.1 [::1]'" "accepted loopback set" "s/.*/x/"
    _rc5=0
    lrt_check_all >/dev/null 2>&1 || _rc5=$?
    if [ "$_rc5" -eq 2 ]; then
        _st_pass "structural failure (anchor>1): rc=2 as expected"
    else
        _st_fail "structural failure (anchor>1): expected rc=2, got rc=$_rc5"
    fi

    # -----------------------------------------------------------------
    # Test 6: structural failure — README not found
    # -----------------------------------------------------------------
    _st_reset
    lrt_set_readme "$_ST_TMPDIR/NO_SUCH_README.md"
    lrt_register "noop"  "printf 'x'" "anything" "s/.*/x/"
    _rc6=0
    lrt_check_all >/dev/null 2>&1 || _rc6=$?
    if [ "$_rc6" -eq 2 ]; then
        _st_pass "structural failure (README missing): rc=2 as expected"
    else
        _st_fail "structural failure (README missing): expected rc=2, got rc=$_rc6"
    fi

    # -----------------------------------------------------------------
    # Test 7: structural failure — truth command returns empty
    # -----------------------------------------------------------------
    _write_readme
    _st_reset
    lrt_set_readme "$_ST_README"
    lrt_register "empty-truth"  "printf ''" "$_ANCHOR_SET" "$_EXTRACT_SET"
    _rc7=0
    lrt_check_all >/dev/null 2>&1 || _rc7=$?
    if [ "$_rc7" -eq 2 ]; then
        _st_pass "structural failure (empty truth): rc=2 as expected"
    else
        _st_fail "structural failure (empty truth): expected rc=2, got rc=$_rc7"
    fi

    # -----------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------
    if [ "$_FAIL" -ne 0 ]; then
        printf 'self-test: FAIL — one or more sub-tests failed\n' >&2
        exit 1
    fi
    printf 'self-test: ALL TESTS PASSED — lint-readme-tokens.sh OK\n'
    exit 0
fi

# ---------------------------------------------------------------------------
# When sourced (the normal path), this file defines the lrt_* functions above
# and returns without executing anything further.  The caller then registers
# tokens and calls lrt_check_all.
# ---------------------------------------------------------------------------
