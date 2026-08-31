#!/bin/sh
# lint-config-drift.sh — assert that prebake.config.example.yaml stays parseable
# by the schema anchors prebake.sh's stdlib awk parser relies on, and FAIL CLOSED
# if the schema and the parser diverge.
#
# WHY THIS LINT EXISTS (fail-closed coupling, doc 03 §6 / D12)
# -----------------------------------------------------------
# prebake.sh has NO yq dependency: it reads the opt-in config with a focused awk
# pass that understands exactly the documented schema
# (prebake.config.example.yaml) and nothing else.  That parser is deliberately
# FAIL-CLOSED — an unrecognized shape simply yields no match and the repo is
# treated as UNCONFIGURED, i.e. NOT baked.  That is the safe direction for an
# unknown file, but it is the DANGEROUS direction for schema drift: if the
# example config (the documented schema) is reshaped in a way the awk anchors no
# longer recognize, an OPTED-IN repo is silently dropped — `enabled: true` reads
# as disabled, a `- repo:` entry vanishes, a `prebake: true` flag stops counting,
# or a configured branch is never enumerated.  The bake just quietly does
# nothing; nothing errors.  This lint is the guard against that silent drop: it
# re-derives, from the COMMITTED example config, each schema anchor the parser
# depends on, and asserts the parser still extracts what the schema declares.
#
# THE FOUR SCHEMA ANCHORS prebake.sh's awk parser binds (kept in lockstep here):
#
#   (a) COLUMN-0 `enabled:` — cfg_global_enabled matches /^enabled:.../ with NO
#       leading whitespace.  Only a top-level (column-0) `enabled:` satisfies the
#       global kill-switch; a nested/indented one is invisible to it.  If the
#       example's `enabled:` ever became indented, the global switch would read
#       as OFF and every opted-in repo would be silently skipped.
#
#   (b) `- repo:` LIST ITEMS — cfg_repo_state / cfg_repo_branches / bake_all
#       match /^[[:space:]]*-[[:space:]]+repo:.../, i.e. each repo is a YAML list
#       item `- repo: <name>`.  If repos[] were reshaped (e.g. a map keyed by
#       name) the parser would enumerate ZERO repos and treat them all as
#       unconfigured — nothing baked.
#
#   (c) INDENTED `prebake:` FLAG — cfg_repo_state matches
#       /^[[:space:]]+prebake:.../, i.e. the per-repo opt-in flag MUST be indented
#       (leading whitespace REQUIRED).  A column-0 `prebake:` would not be read as
#       a per-repo flag, so an opted-in repo would read as opted-out.
#
#   (d) TWO-SPACE `branches[]` ITEMS — cfg_repo_branches reads a `branches:` key
#       inside a repo block, then enumerates the `- <name>` items beneath it.  If
#       the branch list shape drifts, configured branches stop being enumerated
#       and only the default (main) is ever baked — an opted-in `release` is
#       silently dropped.
#
# HOW IT CHECKS (recompute both sides, never literal-freeze)
# ----------------------------------------------------------
# Modeled on images/mirror/lint-env-drift.sh: every expectation is recomputed
# from the live files, never frozen as a literal, so a future edit that updates
# BOTH the schema example AND the parser stays green while a one-sided edit fails
# immediately.  The check sources prebake.sh's OWN parser functions (cfg_*) and
# drives them against the committed example config — if the parser cannot extract
# the anchors the schema declares, parser and schema have diverged and the lint
# FAILS CLOSED (exit 1).  It runs entirely offline: no live tooling, no network,
# no DS_GOLDEN_BAKE_LIVE leg (it only calls the pure cfg_* parser functions).
#
# Usage:
#   sh images/golden/lint-config-drift.sh [GOLDEN_DIR]
#   LINT_GOLDEN_DIR=/path/to/images/golden sh images/golden/lint-config-drift.sh
# (or run from repo root; paths are resolved relative to this script's directory
# when no GOLDEN_DIR argument or LINT_GOLDEN_DIR env var is given)
#
# --self-test: internal regression harness.  Verifies the committed example
# passes, then synthesizes each drift class (one at a time, in a temp copy) and
# asserts the lint catches it — proving the lint actually fails closed on schema
# drift, not just that the clean config passes.  Temp dir cleaned via an EXIT
# trap.  Dispatched BEFORE any file-existence checks.
#
# Invoked by `make repo-lints` (check-image-drift glob-discovers every
# images/*/lint-*.sh automatically — no Makefile edit needed for this script).
#
# SPDX-License-Identifier: Apache-2.0

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Source prebake.sh's parser functions WITHOUT running its main().
#
# prebake.sh is a bash script whose tail is `main "$@"`.  We re-use its cfg_*
# parser functions (the single source of truth for the schema anchors) rather
# than re-implementing them — re-implementing would let the lint's copy drift
# from the real parser, defeating the purpose.  prebake.sh DEFINES its own
# main() and then tail-calls `main "$@"`, so pre-shimming main() does not help
# (the file redefines it during sourcing).  Instead we source a copy with the
# final `main "$@"` invocation stripped, so the cfg_* functions are defined but
# no CLI/bake logic runs.  We source under `bash` because prebake.sh uses
# bashisms (`local`, BASH_SOURCE).
# ---------------------------------------------------------------------------

_PREBAKE_DEFAULT="$SCRIPT_DIR/prebake.sh"

# _run_parser FUNC CFG [ARG...] — invoke prebake.sh's cfg_* FUNC against CFG and
# print its stdout.  Sources a main-stripped copy of prebake.sh so no bake/CLI
# logic runs.  PREBAKE override (env) lets the self-test point at a mutated copy.
_run_parser() {
    _rp_func="$1"
    shift
    _rp_prebake="${PREBAKE:-$_PREBAKE_DEFAULT}"
    # Strip the top-level `main` invocation so sourcing defines the cfg_*
    # functions without executing the CLI.  We match a COLUMN-0 line that begins
    # with an optional `exec ` then `main` as a bare word, optionally followed by
    # `"$@"` and/or a `|| exit`-style suffix — covering the forms a prebake.sh
    # tail-call is likely to take.  The match is column-0-anchored and requires
    # `main` to end at a word boundary, so the main() DEFINITION line
    # (`main() {`, where `main` is immediately followed by `(`) and any indented
    # internal use are preserved.
    _rp_stripped="$(mktemp)"
    awk '
        /^(exec[[:space:]]+)?main([[:space:]]|$)/ { next }
        { print }
    ' "$_rp_prebake" > "$_rp_stripped"
    # Source the stripped copy under bash, then call the requested cfg_* FUNC.
    # Guard: if FUNC is not a defined function after sourcing, the parser was
    # renamed/removed — fail loudly rather than silently mis-reading the schema.
    bash -c '
        # shellcheck disable=SC1090
        . "$1"        # source the main-stripped parser
        _f="$2"; shift 2
        if ! command -v "$_f" >/dev/null 2>&1 || [ "$(type -t "$_f" 2>/dev/null)" != function ]; then
            printf "lint-config-drift: ERROR: prebake.sh parser function %s is not defined after sourcing — parser was renamed/removed; schema coupling cannot be verified\n" "$_f" >&2
            exit 2
        fi
        "$_f" "$@"    # run cfg_* FUNC with its args
    ' _ "$_rp_stripped" "$_rp_func" "$@"
    _rp_rc=$?
    rm -f "$_rp_stripped"
    return $_rp_rc
}

# ---------------------------------------------------------------------------
# Static schema-anchor assertions on the example config text.
#
# These check the SHAPE the parser anchors bind, independent of the parser, so
# the lint names the specific drift even when (rarely) both a parser anchor and
# the example move together in a way the parser-driven checks would tolerate.
# ---------------------------------------------------------------------------

# _assert_col0_enabled CFG — the example MUST carry a column-0 (top-level)
# `enabled:` line.  An indented `enabled:` is invisible to cfg_global_enabled.
_assert_col0_enabled() {
    _ace_cfg="$1"
    # A top-level enabled: line has NO leading whitespace.
    if ! grep -Eq '^enabled:[[:space:]]' "$_ace_cfg"; then
        printf 'lint-config-drift: FAIL anchor(a): no column-0 `enabled:` in %s — cfg_global_enabled only matches a top-level enabled:, so an indented one reads as OFF and silently skips every opted-in repo (D12 fail-closed)\n' \
            "$_ace_cfg" >&2
        return 1
    fi
    # And NO indented `enabled:` masquerading as the global switch (a nested
    # enabled: would never satisfy the global gate but signals schema confusion).
    if grep -Eq '^[[:space:]]+enabled:' "$_ace_cfg"; then
        printf 'lint-config-drift: FAIL anchor(a): indented `enabled:` present in %s — only a column-0 enabled: is the global switch; an indented one is silently inert\n' \
            "$_ace_cfg" >&2
        return 1
    fi
    return 0
}

# _assert_repo_list_items CFG — the example MUST present repos as `- repo: <name>`
# list items (the shape /^[[:space:]]*-[[:space:]]+repo:/ binds).
_assert_repo_list_items() {
    _arl_cfg="$1"
    if ! grep -Eq '^[[:space:]]*-[[:space:]]+repo:[[:space:]]*' "$_arl_cfg"; then
        printf 'lint-config-drift: FAIL anchor(b): no `- repo:` list items in %s — cfg_repo_state/cfg_repo_branches enumerate repos as YAML list items; another shape enumerates ZERO repos and every repo reads as unconfigured (silently not baked)\n' \
            "$_arl_cfg" >&2
        return 1
    fi
    return 0
}

# _assert_prebake_indented CFG — every `prebake:` flag in the example MUST be
# indented (the shape /^[[:space:]]+prebake:/ binds); a column-0 prebake: is not
# read as a per-repo flag.
_assert_prebake_indented() {
    _api_cfg="$1"
    if grep -Eq '^prebake:' "$_api_cfg"; then
        printf 'lint-config-drift: FAIL anchor(c): column-0 `prebake:` in %s — cfg_repo_state only reads an INDENTED per-repo prebake: flag; a top-level one is invisible, so the repo reads as opted-out (silently not baked)\n' \
            "$_api_cfg" >&2
        return 1
    fi
    if ! grep -Eq '^[[:space:]]+prebake:[[:space:]]*' "$_api_cfg"; then
        printf 'lint-config-drift: FAIL anchor(c): no indented `prebake:` flag in %s — the per-repo opt-in flag the parser reads is gone; no repo can opt in\n' \
            "$_api_cfg" >&2
        return 1
    fi
    return 0
}

# _assert_branches_block CFG — the example MUST carry a `branches:` key whose
# items are list entries the parser enumerates (the shape cfg_repo_branches
# binds).
_assert_branches_block() {
    _abb_cfg="$1"
    if ! grep -Eq '^[[:space:]]+branches:[[:space:]]*$' "$_abb_cfg"; then
        printf 'lint-config-drift: FAIL anchor(d): no `branches:` block in %s — cfg_repo_branches reads the per-repo branches[] list; without it only the default branch (main) is ever baked and a configured branch is silently dropped\n' \
            "$_abb_cfg" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Parser-driven assertions: drive prebake.sh's OWN cfg_* functions against the
# config and assert they extract what the schema declares.  This is the
# fail-closed heart of the lint — if the parser cannot see the anchors the
# example presents, parser and schema have diverged.
# ---------------------------------------------------------------------------

# _check_parser CFG — run all parser-driven anchor checks against CFG (the
# committed example or a synthetic enabled twin).  Returns non-zero on the first
# divergence, naming the anchor.  Two variants of `enabled` are needed: the
# committed example ships enabled:false (the safe default), so to exercise the
# enabled-true parse we flip it in a temp twin (done by the caller for the clean
# path; the static anchor (a) covers the column-0 shape regardless).
_check_parser() {
    _cp_cfg="$1"
    _cp_rc=0

    # (b) cfg_repo_state must classify the example's repos correctly: the
    # opted-in monorepo as "on", the opted-out scratch repo as "off", an absent
    # repo as "" (empty).  A reshaped repos[] would yield "" for ALL of them.
    _cp_on="$(_run_parser cfg_repo_state "$_cp_cfg" github.com/acme/monorepo)"
    if [ "$_cp_on" != "on" ]; then
        printf 'lint-config-drift: FAIL anchor(b/c): cfg_repo_state could not read the opted-in repo as "on" (got: %s) — `- repo:` list-item or `prebake:` anchor drifted; an opted-in repo would be silently not baked\n' \
            "${_cp_on:-<empty>}" >&2
        _cp_rc=1
    fi
    _cp_off="$(_run_parser cfg_repo_state "$_cp_cfg" github.com/acme/scratch)"
    if [ "$_cp_off" != "off" ]; then
        printf 'lint-config-drift: FAIL anchor(b/c): cfg_repo_state could not read the opted-out repo as "off" (got: %s) — `- repo:`/`prebake:` anchor drifted\n' \
            "${_cp_off:-<empty>}" >&2
        _cp_rc=1
    fi
    _cp_absent="$(_run_parser cfg_repo_state "$_cp_cfg" github.com/acme/not-listed)"
    if [ -n "$_cp_absent" ]; then
        printf 'lint-config-drift: FAIL anchor(b): cfg_repo_state read an ABSENT repo as %s (expected empty) — repo enumeration anchor drifted\n' \
            "$_cp_absent" >&2
        _cp_rc=1
    fi

    # (d) cfg_repo_branches must enumerate the configured branches[] list for the
    # opted-in repo: exactly main + release per the example schema.
    _cp_branches="$(_run_parser cfg_repo_branches "$_cp_cfg" github.com/acme/monorepo)"
    if ! printf '%s\n' "$_cp_branches" | grep -qx 'main'; then
        printf 'lint-config-drift: FAIL anchor(d): cfg_repo_branches did not enumerate branch "main" — branches[] anchor drifted; configured branches silently fall back to the default\n' >&2
        _cp_rc=1
    fi
    if ! printf '%s\n' "$_cp_branches" | grep -qx 'release'; then
        printf 'lint-config-drift: FAIL anchor(d): cfg_repo_branches did not enumerate branch "release" — branches[] anchor drifted; an opted-in non-default branch is silently dropped\n' >&2
        _cp_rc=1
    fi

    return $_cp_rc
}

# _check_global_enabled_parse CFG — assert cfg_global_enabled reads "true" from a
# config whose top-level enabled: is true.  The committed example ships
# enabled:false, so this is driven against the enabled twin the caller builds.
_check_global_enabled_parse() {
    _cgp_cfg="$1"
    _cgp_val="$(_run_parser cfg_global_enabled "$_cgp_cfg")"
    if [ "$_cgp_val" != "true" ]; then
        printf 'lint-config-drift: FAIL anchor(a): cfg_global_enabled did not read a column-0 `enabled: true` as "true" (got: %s) — the global switch anchor drifted; with it reading OFF, every opted-in repo is silently skipped\n' \
            "${_cgp_val:-<empty>}" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# run_lint GOLDEN_DIR — the full check against a golden image dir.
# ---------------------------------------------------------------------------
run_lint() {
    _rl_dir="$1"
    _rl_cfg="$_rl_dir/prebake.config.example.yaml"
    _rl_prebake="$_rl_dir/prebake.sh"

    if [ ! -f "$_rl_cfg" ]; then
        printf 'lint-config-drift: ERROR: not found: %s\n' "$_rl_cfg" >&2
        exit 2
    fi
    if [ ! -f "$_rl_prebake" ]; then
        printf 'lint-config-drift: ERROR: not found: %s\n' "$_rl_prebake" >&2
        exit 2
    fi

    # Point the parser at THIS dir's prebake.sh (so the lint checks the example
    # against the parser that ships beside it).
    PREBAKE="$_rl_prebake"
    export PREBAKE

    _rl_fail=0

    # Static anchor-shape assertions (name the specific drift).
    _assert_col0_enabled       "$_rl_cfg" || _rl_fail=1
    _assert_repo_list_items    "$_rl_cfg" || _rl_fail=1
    _assert_prebake_indented   "$_rl_cfg" || _rl_fail=1
    _assert_branches_block     "$_rl_cfg" || _rl_fail=1

    # Parser-driven assertions against the committed example (enabled:false twin
    # is irrelevant for repo/branch parsing — those are independent of the global
    # switch).
    _check_parser "$_rl_cfg" || _rl_fail=1

    # enabled-true parse: build a temp twin with the global switch flipped on and
    # confirm cfg_global_enabled reads it.  This exercises anchor (a) through the
    # real parser, not just the static grep.
    _rl_twin="$(mktemp)"
    awk '/^enabled:[[:space:]]/ { print "enabled: true"; next } { print }' \
        "$_rl_cfg" > "$_rl_twin"
    _check_global_enabled_parse "$_rl_twin" || _rl_fail=1
    rm -f "$_rl_twin"

    if [ "$_rl_fail" -ne 0 ]; then
        printf 'lint-config-drift: FAIL — prebake.config.example.yaml drifted from the schema anchors prebake.sh awk parser relies on (a parser/schema divergence silently drops an opted-in repo)\n' >&2
        exit 1
    fi

    printf 'lint-config-drift: OK — prebake.config.example.yaml matches the schema anchors prebake.sh parser relies on\n'
}

# ---------------------------------------------------------------------------
# --self-test: prove the lint FAILS CLOSED on each drift class.
#
# Must be dispatched before any file-existence checks.  Copies the golden dir's
# prebake.sh + example config into a temp sandbox, confirms the clean copy
# passes, then injects each schema-drift class one at a time and asserts the lint
# catches it (exit non-zero).  The real images/golden/ tree is never mutated —
# only the temp copy.  Cleaned via an EXIT trap.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    ST_DIR="$(mktemp -d)"
    _st_cleanup() { rm -rf "$ST_DIR"; }
    trap _st_cleanup EXIT

    # Copy only what the lint reads: the example config + prebake.sh (the parser).
    cp "$SCRIPT_DIR/prebake.config.example.yaml" "$ST_DIR/prebake.config.example.yaml"
    cp "$SCRIPT_DIR/prebake.sh"                   "$ST_DIR/prebake.sh"
    _ST_CFG="$ST_DIR/prebake.config.example.yaml"

    # Helper: restore the clean copy of the example config.
    _restore() {
        cp "$SCRIPT_DIR/prebake.config.example.yaml" "$_ST_CFG"
    }

    # Helper: replace the FIRST line matching ANCHOR_PAT in the config with
    # NEW_LINE.  Fails loudly if no line matched (anchor gone — no silent no-op,
    # mirroring lint-env-drift.sh's injection-anchor discipline).
    # Usage: _replace_line ANCHOR_PAT NEW_LINE LABEL
    _replace_line() {
        _rpl_pat="$1"
        _rpl_new="$2"
        _rpl_label="$3"
        _rpl_matched="$(awk -v pat="$_rpl_pat" '$0 ~ pat { print NR; exit }' "$_ST_CFG")"
        if [ -z "$_rpl_matched" ]; then
            printf 'self-test: ABORT — injection anchor gone: %s (pattern: %s)\n' \
                "$_rpl_label" "$_rpl_pat" >&2
            exit 1
        fi
        awk -v pat="$_rpl_pat" -v new="$_rpl_new" '
            !done && $0 ~ pat { print new; done=1; next }
            { print }
        ' "$_ST_CFG" > "$_ST_CFG.tmp" && mv "$_ST_CFG.tmp" "$_ST_CFG"
    }

    # Helper: run the lint against the temp sandbox and assert PASS (rc 0).
    _expect_pass() {
        _ep_label="$1"
        _ep_rc=0
        sh "$SCRIPT_DIR/lint-config-drift.sh" "$ST_DIR" >/dev/null 2>&1 || _ep_rc=$?
        if [ "$_ep_rc" -ne 0 ]; then
            printf 'self-test: FAIL — %s should PASS but lint exited %d\n' \
                "$_ep_label" "$_ep_rc" >&2
            exit 1
        fi
        printf 'self-test: %s passed (rc=0)\n' "$_ep_label"
    }

    # Helper: run the lint against the temp sandbox and assert it FAILS CLOSED
    # (rc non-zero) — the drift was caught.
    _expect_fail() {
        _ef_label="$1"
        _ef_rc=0
        sh "$SCRIPT_DIR/lint-config-drift.sh" "$ST_DIR" >/dev/null 2>&1 || _ef_rc=$?
        if [ "$_ef_rc" -eq 0 ]; then
            printf 'self-test: FAIL — drift [%s] was NOT caught (lint exited 0)\n' \
                "$_ef_label" >&2
            exit 1
        fi
        printf 'self-test: drift [%s] caught (rc=%d)\n' "$_ef_label" "$_ef_rc"
    }

    # --- clean copy passes ---
    _restore
    _expect_pass "clean example config"

    # --- drift (a): top-level enabled: indented (nested) ---
    # cfg_global_enabled only matches a COLUMN-0 enabled:; indenting it makes the
    # global switch invisible -> reads OFF -> every opted-in repo silently skipped.
    _restore
    _replace_line '^enabled:' '  enabled: false' 'enabled: indented (anchor a)'
    _expect_fail 'enabled: indented (anchor a)'

    # --- drift (b): repos reshaped from `- repo:` list items to a map ---
    # If repos[] stops being a YAML list of `- repo:` items, cfg_repo_state /
    # cfg_repo_branches enumerate ZERO repos -> every repo reads as unconfigured.
    # We mutate BOTH `- repo:` lines to a non-list `repo_name:` map key.
    _restore
    _replace_line '^[[:space:]]*-[[:space:]]+repo:[[:space:]]*github.com/acme/monorepo' \
        '  github.com/acme/monorepo:' 'repos map-not-list (anchor b)'
    _replace_line '^[[:space:]]*-[[:space:]]+repo:[[:space:]]*github.com/acme/scratch' \
        '  github.com/acme/scratch:' 'repos map-not-list scratch (anchor b)'
    _expect_fail 'repos map-not-list (anchor b)'

    # --- drift (c): per-repo prebake: flag dedented to column 0 ---
    # cfg_repo_state only reads an INDENTED prebake:; a column-0 prebake: is not a
    # per-repo flag -> the opted-in repo reads as opted-out (silently not baked).
    _restore
    _replace_line '^[[:space:]]+prebake:[[:space:]]*true' 'prebake: true' \
        'prebake: dedented (anchor c)'
    _expect_fail 'prebake: dedented (anchor c)'

    # --- drift (d): branches: block key renamed ---
    # cfg_repo_branches keys off a `branches:` line; rename it and the configured
    # branch list stops being enumerated -> only the default (main) is baked, a
    # configured `release` is silently dropped.
    _restore
    _replace_line '^[[:space:]]+branches:[[:space:]]*$' '    refs:' \
        'branches: renamed (anchor d)'
    _expect_fail 'branches: renamed (anchor d)'

    # --- drift (b'): opted-in repo entry removed entirely ---
    # The strongest silent-drop: the monorepo `- repo:` block disappears, so
    # cfg_repo_state reads it as absent ("") instead of "on".  The parser-driven
    # check catches this even though the surviving scratch entry keeps the
    # `- repo:` shape valid.
    _restore
    # Delete the monorepo repo line and its immediate opt-in/branches lines.
    awk '
        /^[[:space:]]*-[[:space:]]+repo:[[:space:]]*github.com\/acme\/monorepo/ { skip=1; next }
        skip && /^[[:space:]]*-[[:space:]]+repo:/ { skip=0 }
        skip { next }
        { print }
    ' "$_ST_CFG" > "$_ST_CFG.tmp" && mv "$_ST_CFG.tmp" "$_ST_CFG"
    _expect_fail 'opted-in repo block removed (anchor b)'

    # --- drift (a'): enabled: line removed entirely (parser reads OFF) ---
    # If the column-0 enabled: line is gone, cfg_global_enabled never reads
    # "true" even from the enabled-twin the lint builds -> the enabled-true parse
    # assertion fails.  Verifies absence of the global switch is caught, not just
    # a wrong indent.
    _restore
    awk '/^enabled:[[:space:]]/ { next } { print }' "$_ST_CFG" > "$_ST_CFG.tmp" \
        && mv "$_ST_CFG.tmp" "$_ST_CFG"
    _expect_fail 'enabled: line removed (anchor a)'

    # --- guard: prebake.sh parser function renamed ---
    # The lint sources prebake.sh's OWN cfg_* functions; if a future prebake.sh
    # refactor renames one (here cfg_repo_state), the lint must fail LOUDLY (the
    # function-defined guard in _run_parser) rather than silently mis-read the
    # schema.  We mutate the COPY of prebake.sh in the temp sandbox only; the
    # config stays clean, isolating this to the parser-rename class.
    _restore
    awk '{ gsub(/cfg_repo_state/, "cfg_repo_state_RENAMED"); print }' \
        "$SCRIPT_DIR/prebake.sh" > "$ST_DIR/prebake.sh.tmp" \
        && mv "$ST_DIR/prebake.sh.tmp" "$ST_DIR/prebake.sh"
    _expect_fail 'prebake.sh parser function renamed (cfg_repo_state)'
    # Restore the clean prebake.sh copy for any later cases / hygiene.
    cp "$SCRIPT_DIR/prebake.sh" "$ST_DIR/prebake.sh"

    printf 'self-test: ALL DRIFTS CAUGHT — lint-config-drift.sh OK\n'
    exit 0
fi

# ---------------------------------------------------------------------------
# Resolve the golden dir: $1 > $LINT_GOLDEN_DIR > script-relative default.
# ---------------------------------------------------------------------------
if [ $# -ge 1 ]; then
    GOLDEN_DIR="$1"
elif [ -n "${LINT_GOLDEN_DIR:-}" ]; then
    GOLDEN_DIR="$LINT_GOLDEN_DIR"
else
    GOLDEN_DIR="$SCRIPT_DIR"
fi

run_lint "$GOLDEN_DIR"
