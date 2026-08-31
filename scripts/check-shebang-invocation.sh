#!/bin/sh
# check-shebang-invocation.sh — per-invocation shebang-discipline guard.
#
# PURPOSE
#   A shell script's shebang (`#!/bin/sh` vs `#!/usr/bin/env bash`) is a CONTRACT:
#   `#!/bin/sh` asserts the body is POSIX-clean and must be TESTED under a strict
#   POSIX shell, while `#!/usr/bin/env bash` asserts the body may use bash
#   extensions.  When a caller invokes a script with an interpreter that does NOT
#   match its shebang, that contract silently breaks:
#
#     * `bash scripts/foo.sh` on a `#!/bin/sh` script MASKS accidental bashisms —
#       bash accepts the POSIX script's superset, so a bashism creeping into a
#       "POSIX" script is never caught (the class the ci.yml direct-invocation
#       lines fell into: `bash scripts/check-corpus-suffix.sh` /
#       `bash scripts/check-grantref-goldens.sh`, both `#!/bin/sh`).
#     * `sh scripts/foo.sh` on a `#!/usr/bin/env bash` script RUNS a bash-featured
#       body under whatever /bin/sh is (dash on Debian), breaking at runtime on the
#       first bash-only construct — a fail that only shows on POSIX-sh hosts.
#
#   This lint cross-references EVERY literal `sh|bash <path>.sh` invocation in the
#   two places that invoke the repo's check scripts by an explicit interpreter —
#   the Makefile recipe lines (repo-lints and its constituent targets) and the
#   GitHub-workflow `run:` steps of EVERY .github/workflows/*.yml (not ci.yml
#   alone) — against the target script's shebang, and fails CLOSED on any
#   mismatch.  It locks, as a standing gate, the class of bug that was previously
#   fixed only by hand.
#
#   READ-ONLY: it greps the Makefile, every .github/workflows/*.yml, and the
#   target scripts' first lines and edits NONE of them.  grep/awk/sed only,
#   network-free.
#
#   SCOPE / limitations (deliberate, documented):
#     * Only LITERAL invocations are scanned: `sh scripts/x.sh`.  A variable target
#       (`sh "$s"` in check-image-drift's discovery loop) has no statically-known
#       shebang and is skipped by construction (the path token is not a literal
#       `*.sh`).
#     * A recipe/step line that `cd`s before the invocation changes the base the
#       relative path resolves against (`cd dataplane && bash scripts/...`), so
#       such lines are SKIPPED — this guard only reasons about repo-root-relative
#       targets it can resolve unambiguously.
#     * Makefile scanning is restricted to RECIPE lines (leading TAB), never the
#       comment/prose that names scripts in passing.
#     * `.claude/workflows/*.js` is DELIBERATELY EXCLUDED from the production sweep.
#       The workflow-engine .js files embed shell invocations two ways: as REAL
#       call sites the engine execs (e.g. task-wave.js's LAND-phase gate prompt),
#       and as INSTRUCTIONAL PROSE inside `scope:`/JSDoc strings that merely NAME a
#       script (`_dispatch-*.wf.js`, task-wave-dispatch.template.js) without ever
#       running it.  A static grep cannot separate the two, so live-scanning the
#       tree would false-positive on the prose mentions.  The `jsworkflow` scan KIND
#       below IS implemented and self-tested (it correctly catches a js-side
#       `sh <bash-shebang-script>.sh` mismatch), so the capability is real and
#       non-vacuous — it is simply not wired to the live tree until the .js prose
#       call sites are disambiguated.  A future maintainer can pass a JSDIR to
#       `_run_checks` to opt a cleaned subtree in.  This is a DECISION, not a gap.
#
# USAGE
#   sh scripts/check-shebang-invocation.sh              # production sweep
#   sh scripts/check-shebang-invocation.sh --self-test  # internal regression harness
#   sh scripts/check-shebang-invocation.sh --emit-posix # list the sh-invoked
#                                                       #   Makefile invocations
#                                                       #   (path + args), one per
#                                                       #   line, for the dash CI leg
#
# EXIT CODES
#   0  — every scanned invocation's interpreter matches its target's shebang family
#   1  — MISMATCH: a script is invoked with the wrong interpreter family
#   2  — STRUCTURAL: a target is missing, or has an absent/unrecognised shebang
#
# --emit-posix
#   Prints, one per line, the argument tail of each Makefile recipe line that
#   invokes a script with `sh` (e.g. `scripts/check-gofmt.sh --self-test`), in
#   Makefile order, deduplicated by exact line.  The dash CI leg replays each of
#   these under dash(1) so POSIX-mode compliance of every sh-invoked target is
#   proven BEHAVIOURALLY, not merely asserted by this static shebang cross-check.
#
# --self-test
#   Builds a self-contained sandbox (a synthetic Makefile + workflow files under
#   .github/workflows/ + engine files under .claude/workflows/ + scripts with
#   assorted shebangs), verifies the matched-interpreter clean copy passes (rc=0),
#   then plants each failure class — a `#!/bin/sh` script invoked with bash, a
#   `#!/usr/bin/env bash` script invoked with sh, a missing target, and an
#   unrecognised shebang — and confirms each is caught (rc=1 mismatch / rc=2
#   structural).  A dedicated case plants a mismatch in a SECOND workflow file
#   (release.yml, both Makefile and ci.yml clean) to prove the *.yml glob is
#   non-vacuous: it REDs if the scan ever regresses to ci.yml alone.  A further
#   block exercises the `jsworkflow` KIND against a synthetic .claude/workflows/
#   .js file: it REDs on a planted js-side `sh <bash-shebang-script>.sh` mismatch
#   (proving the .js-scan capability is non-vacuous), passes a matched js
#   invocation, and confirms both a variable target and a `//`-comment mention are
#   skipped.  It NEVER reads the real tree for its own pass/fail; the sandbox is
#   cleaned up via an EXIT trap.  This proves the guard is non-vacuous.
#
# SPDX-License-Identifier: Apache-2.0

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# _shebang_family FILE — print the interpreter FAMILY the script's shebang
# declares: "sh" (#!/bin/sh, #!/bin/dash, #!/usr/bin/env sh, ...), "bash"
# (#!/bin/bash, #!/usr/bin/env bash, ...), or "" when there is no shebang or the
# interpreter is unrecognised (upstreams to STRUCTURAL). `env <interp>` unwraps to
# <interp>; a bare interpreter path uses its basename.
# ---------------------------------------------------------------------------
_shebang_family() {
    [ -f "$1" ] || { printf ''; return 0; }
    _sf_line="$(head -1 "$1" 2>/dev/null || true)"
    case "$_sf_line" in
        '#!'*) : ;;
        *) printf ''; return 0 ;;
    esac
    _sf_rest="${_sf_line#\#!}"
    _sf_rest="$(printf '%s' "$_sf_rest" | sed 's/^[[:space:]]*//')"
    _sf_prog="${_sf_rest%%[[:space:]]*}"
    _sf_arg="${_sf_rest#"$_sf_prog"}"
    _sf_arg="$(printf '%s' "$_sf_arg" | sed 's/^[[:space:]]*//;s/[[:space:]].*//')"
    _sf_base="${_sf_prog##*/}"
    if [ "$_sf_base" = "env" ] && [ -n "$_sf_arg" ]; then
        _sf_base="${_sf_arg##*/}"
    fi
    case "$_sf_base" in
        sh|dash|ash) printf 'sh' ;;
        bash) printf 'bash' ;;
        *) printf '' ;;
    esac
}

# ---------------------------------------------------------------------------
# _extract KIND FILE — emit one record per literal `sh|bash <path>.sh` invocation
# found in FILE, as `LINENO<TAB>INTERP<TAB>PATH`.  KIND selects the source
# discipline:
#   makefile   — only RECIPE lines (leading TAB); recipe-comment lines (TAB then #)
#                and any line containing a `cd ` are skipped.
#   ciyml      — any non-comment line; `#`-comment lines and any line containing a
#                `cd ` are skipped.
#   jsworkflow — any non-comment line of a workflow-engine .js file; JS line
#                comments (`//`) and block-comment continuation lines (leading `*`
#                or `/*`) and any line containing a `cd ` are skipped.  (Used only
#                against an explicitly opted-in JSDIR — see the SCOPE note on why
#                the live .claude/workflows tree is not swept.)
# The path token is a LITERAL (no `$`), so variable targets are excluded by
# construction.  The interpreter must sit at a non-word boundary so `refresh` /
# `bash` never masquerade as an `sh` token.
# ---------------------------------------------------------------------------
_extract() {
    awk -v kind="$1" '
        function trim(x) { sub(/^[[:space:]]+/, "", x); return x }
        {
            line = $0
            if (kind == "makefile") {
                if (substr(line, 1, 1) != "\t") next
                probe = trim(line)
                if (substr(probe, 1, 1) == "#") next
            } else if (kind == "jsworkflow") {
                probe = trim(line)
                if (substr(probe, 1, 2) == "//") next
                if (substr(probe, 1, 1) == "*") next
                if (substr(probe, 1, 2) == "/*") next
            } else {
                probe = trim(line)
                if (substr(probe, 1, 1) == "#") next
            }
            # A directory change re-bases the relative path — do not reason about it.
            if (line ~ /(^|[^A-Za-z])cd[ \t]/) next
            while (match(line, /(^|[^-A-Za-z0-9_./])(sh|bash)[ \t]+[-A-Za-z0-9_./]+\.sh/)) {
                m = substr(line, RSTART, RLENGTH)
                sub(/^[^A-Za-z]*/, "", m)            # strip leading separator
                interp = m; sub(/[ \t].*/, "", interp)
                path = m; sub(/^(sh|bash)[ \t]+/, "", path)
                print NR "\t" interp "\t" path
                line = substr(line, RSTART + RLENGTH)
            }
        }
    ' "$2"
}

# ---------------------------------------------------------------------------
# _check_source ROOT KIND FILE — scan one source file's invocations and compare
# each interpreter against its target's shebang family.  Targets resolve under
# ROOT.  Prints per-invocation results; returns the worst rc (2 > 1 > 0).  A
# missing FILE is itself STRUCTURAL.
# ---------------------------------------------------------------------------
_check_source() {
    _cs_root="$1"; _cs_kind="$2"; _cs_file="$3"
    _cs_worst=0

    if [ ! -f "$_cs_file" ]; then
        printf 'check-shebang-invocation: STRUCTURAL — source file absent: %s\n' "$_cs_file" >&2
        return 2
    fi

    _cs_recs="$(_extract "$_cs_kind" "$_cs_file")"
    [ -n "$_cs_recs" ] || { printf 'check-shebang-invocation: %s (%s): no literal script invocations\n' "$_cs_file" "$_cs_kind"; return 0; }

    # Read records via a here-doc so the while loop runs in THIS shell (no
    # subshell), letting _cs_worst mutations survive the loop.
    while IFS="$(printf '\t')" read -r _cs_ln _cs_interp _cs_path; do
        [ -n "$_cs_path" ] || continue
        _cs_target="$_cs_root/$_cs_path"
        if [ ! -f "$_cs_target" ]; then
            printf 'check-shebang-invocation: STRUCTURAL — %s:%s invokes missing target %s\n' \
                "$_cs_file" "$_cs_ln" "$_cs_path" >&2
            _cs_worst=2
            continue
        fi
        _cs_fam="$(_shebang_family "$_cs_target")"
        if [ -z "$_cs_fam" ]; then
            printf 'check-shebang-invocation: STRUCTURAL — %s:%s target %s has no recognised shebang\n' \
                "$_cs_file" "$_cs_ln" "$_cs_path" >&2
            _cs_worst=2
            continue
        fi
        if [ "$_cs_interp" != "$_cs_fam" ]; then
            printf 'check-shebang-invocation: MISMATCH — %s:%s invokes `%s %s` but its shebang is #!.../%s\n' \
                "$_cs_file" "$_cs_ln" "$_cs_interp" "$_cs_path" "$_cs_fam" >&2
            [ "$_cs_worst" -lt 1 ] && _cs_worst=1
            continue
        fi
        printf 'check-shebang-invocation: OK — %s:%s `%s %s` matches shebang (%s)\n' \
            "$_cs_file" "$_cs_ln" "$_cs_interp" "$_cs_path" "$_cs_fam"
    done <<EOF
$_cs_recs
EOF

    return "$_cs_worst"
}

# ---------------------------------------------------------------------------
# _run_checks ROOT MAKEFILE WFDIR [JSDIR] — the shared check body over the
# sources.  WFDIR is the GitHub-workflows DIRECTORY: EVERY `$WFDIR/*.yml` file is
# scanned as a ciyml source (not ci.yml alone), so a mismatched invocation in any
# workflow — not just ci.yml — is caught. WFDIR may be empty ("") to scan the
# Makefile alone (self-test Makefile-only cases); a WFDIR that exists but holds
# no *.yml contributes nothing. JSDIR (optional 4th arg) is a workflow-engine .js
# DIRECTORY: when non-empty, EVERY `$JSDIR/*.js` file is scanned as a jsworkflow
# source. It defaults to "" — the PRODUCTION sweep passes no JSDIR (the live
# .claude/workflows tree is deliberately not swept; see the SCOPE note) and it is
# exercised only by the self-test. Returns the worst rc across every scanned file.
# ---------------------------------------------------------------------------
_run_checks() {
    _rc_root="$1"; _rc_mk="$2"; _rc_wfdir="$3"; _rc_jsdir="${4:-}"
    _rc_worst=0

    _rc_mrc=0
    _check_source "$_rc_root" "makefile" "$_rc_mk" || _rc_mrc=$?
    [ "$_rc_mrc" -gt "$_rc_worst" ] && _rc_worst=$_rc_mrc

    if [ -n "$_rc_wfdir" ]; then
        for _rc_wf in "$_rc_wfdir"/*.yml; do
            # An unmatched glob expands to the literal pattern under POSIX sh; the
            # -f guard drops it (and any non-file), so an empty/absent dir is a
            # clean no-op rather than a STRUCTURAL miss on a bogus path.
            [ -f "$_rc_wf" ] || continue
            _rc_crc=0
            _check_source "$_rc_root" "ciyml" "$_rc_wf" || _rc_crc=$?
            if [ "$_rc_crc" -gt "$_rc_worst" ]; then _rc_worst=$_rc_crc; fi
        done
    fi

    if [ -n "$_rc_jsdir" ]; then
        for _rc_js in "$_rc_jsdir"/*.js; do
            [ -f "$_rc_js" ] || continue
            _rc_jrc=0
            _check_source "$_rc_root" "jsworkflow" "$_rc_js" || _rc_jrc=$?
            if [ "$_rc_jrc" -gt "$_rc_worst" ]; then _rc_worst=$_rc_jrc; fi
        done
    fi

    return "$_rc_worst"
}

# ---------------------------------------------------------------------------
# --emit-posix: list the sh-invoked Makefile invocations (path + args), one per
# line, deduplicated, in Makefile order.  Consumed by the dash CI leg.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--emit-posix" ]; then
    awk '
        substr($0, 1, 1) != "\t" { next }
        {
            probe = $0; sub(/^[[:space:]]+/, "", probe)
            if (substr(probe, 1, 1) == "#") next
            if ($0 ~ /(^|[^A-Za-z])cd[ \t]/) next
            line = $0
            while (match(line, /(^|[^-A-Za-z0-9_./])sh[ \t]+[-A-Za-z0-9_./]+\.sh([ \t][^\n]*)?$/)) {
                m = substr(line, RSTART, RLENGTH)
                sub(/^[^s]*/, "", m)          # strip leading separator up to `sh`
                sub(/^sh[ \t]+/, "", m)       # drop the `sh ` interpreter token
                sub(/[[:space:]]+$/, "", m)   # rstrip
                if (!(m in seen)) { seen[m] = 1; print m }
                line = substr(line, RSTART + RLENGTH)
            }
        }
    ' "$REPO_ROOT/Makefile"
    exit 0
fi

# ---------------------------------------------------------------------------
# --self-test: dispatched BEFORE any real-tree access.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    _ST_ROOT="$(mktemp -d)"
    _st_cleanup() { rm -rf "$_ST_ROOT"; }
    trap _st_cleanup EXIT

    mkdir -p "$_ST_ROOT/scripts" "$_ST_ROOT/.github/workflows" "$_ST_ROOT/.claude/workflows"
    _ST_MK="$_ST_ROOT/Makefile"
    _ST_CI="$_ST_ROOT/.github/workflows/ci.yml"
    # JSDIR is passed to _run_checks only for the jsworkflow cases; "" everywhere
    # else keeps the .js scan out of the yml/Makefile cases.
    _ST_JSDIR=""

    # Two synthetic target scripts with KNOWN shebangs.
    printf '#!/bin/sh\necho posix\n'            > "$_ST_ROOT/scripts/posix.sh"
    printf '#!/usr/bin/env bash\necho bashy\n'  > "$_ST_ROOT/scripts/bashy.sh"
    # A script with an unrecognised interpreter (structural class).
    printf '#!/usr/bin/perl\nprint "x";\n'      > "$_ST_ROOT/scripts/weird.sh"

    _fail=0

    _st_case() {  # $1=label $2=expected_rc  (Makefile+workflows already written)
        _c_label="$1"; _c_want="$2"
        _c_rc=0
        _run_checks "$_ST_ROOT" "$_ST_MK" "$_ST_ROOT/.github/workflows" "$_ST_JSDIR" >/dev/null 2>&1 || _c_rc=$?
        if [ "$_c_rc" -ne "$_c_want" ]; then
            printf 'self-test: FAIL — %s expected rc=%s, got rc=%s\n' "$_c_label" "$_c_want" "$_c_rc" >&2
            _fail=1
        else
            printf 'self-test: %s (rc=%s)\n' "$_c_label" "$_c_rc"
        fi
    }

    _st_write_mk() {  # writes a recipe with the given TAB-indented body lines
        {
            printf 'repo-lints:\n'
            for _l in "$@"; do
                printf '\t%s\n' "$_l"
            done
        } > "$_ST_MK"
    }

    _st_write_ci() {  # writes a run: step invoking the given command into ci.yml
        _st_write_wf "$_ST_CI" "$1"
    }

    _st_write_wf() {  # $1=workflow-file-path $2=run-command — writes ONE synthetic
                      # workflow file; used to plant a SECOND *.yml so the glob
                      # (not a ci.yml-only scan) is proven to cover it.
        {
            printf 'jobs:\n  x:\n    steps:\n'
            printf '      - name: lint\n        run: %s\n' "$2"
        } > "$1"
    }

    _st_write_js() {  # $1=js-file-path $2=raw-body-line — writes ONE synthetic
                      # workflow-engine .js file whose body line is scanned by the
                      # jsworkflow KIND.  Wrapped in a trivial module skeleton so the
                      # file reads like real engine source.
        {
            printf 'module.exports = function () {\n'
            printf '%s\n' "$2"
            printf '};\n'
        } > "$1"
    }

    # --- clean: interpreters match shebangs on both sources -> rc 0 ---
    _st_write_mk 'sh scripts/posix.sh --self-test' 'bash scripts/bashy.sh'
    _st_write_ci 'sh scripts/posix.sh'
    _st_case "clean matched invocations pass" 0

    # --- mismatch (the ci.yml bug class): bash invoking a #!/bin/sh script -> rc 1 ---
    _st_write_mk 'sh scripts/posix.sh' 'bash scripts/bashy.sh'
    _st_write_ci 'bash scripts/posix.sh'
    _st_case "bash-invokes-POSIX-script mismatch caught (ci.yml)" 1

    # --- mismatch (Makefile side): sh invoking a #!/usr/bin/env bash script -> rc 1 ---
    _st_write_mk 'sh scripts/posix.sh' 'sh scripts/bashy.sh'
    _st_write_ci 'sh scripts/posix.sh'
    _st_case "sh-invokes-bash-script mismatch caught (Makefile)" 1

    # --- structural: invocation of a target that does not exist -> rc 2 ---
    _st_write_mk 'sh scripts/posix.sh' 'sh scripts/ghost.sh'
    _st_write_ci 'sh scripts/posix.sh'
    _st_case "missing-target structural miss caught" 2

    # --- structural: target with an unrecognised shebang interpreter -> rc 2 ---
    _st_write_mk 'sh scripts/posix.sh' 'sh scripts/weird.sh'
    _st_write_ci 'sh scripts/posix.sh'
    _st_case "unrecognised-shebang structural miss caught" 2

    # --- scope: a `cd`-prefixed invocation re-bases the path and is SKIPPED, so a
    # deliberately-mismatched cd line does NOT trip (proves the documented skip). ---
    _st_write_mk 'sh scripts/posix.sh' 'cd sub && bash scripts/posix.sh'
    _st_write_ci 'sh scripts/posix.sh'
    _st_case "cd-prefixed invocation skipped (re-based path)" 0

    # --- scope: a variable target (sh "$s") has no static shebang and is SKIPPED. ---
    _st_write_mk 'sh scripts/posix.sh' 'sh "$$s"'
    _st_write_ci 'sh scripts/posix.sh'
    _st_case "variable target skipped (no literal .sh)" 0

    # --- multi-file workflow scan (NON-VACUITY of the *.yml glob): the Makefile and
    # ci.yml are both CLEAN, but a SECOND workflow file (release.yml) plants a
    # bash-invokes-#!/bin/sh mismatch. The production scan globs .github/workflows/
    # *.yml, so this MUST be caught (rc 1). If the glob ever regresses to scanning
    # ci.yml alone, the mismatch goes unseen, the case yields rc 0, and — because we
    # expect 1 — THIS self-test REDs. The extra file is removed afterwards so it
    # cannot leak into any later case. ---
    _st_write_mk 'sh scripts/posix.sh'
    _st_write_ci 'sh scripts/posix.sh'
    _ST_WF2="$_ST_ROOT/.github/workflows/release.yml"
    _st_write_wf "$_ST_WF2" 'bash scripts/posix.sh'   # mismatch: bash on a #!/bin/sh target
    _st_case "mismatch in a NON-ci.yml workflow file is caught (glob scans *.yml, not ci.yml alone)" 1
    rm -f "$_ST_WF2"

    # --- jsworkflow scan (NON-VACUITY of the .js capability): with the Makefile and
    # every *.yml CLEAN, point a JSDIR at a synthetic .claude/workflows/ .js file
    # and plant a js-side `sh scripts/bashy.sh` — sh invoking a #!/usr/bin/env bash
    # target. The jsworkflow KIND MUST catch it (rc 1). This is the case the wave
    # scope calls for: it REDs on a planted js-side sh-invocation of a bash-shebang
    # script, proving the .js-scan machinery is real, not decorative. The clean
    # Makefile+ci ensure ONLY the js file drives the verdict. ---
    _ST_JSDIR="$_ST_ROOT/.claude/workflows"
    _ST_JS1="$_ST_ROOT/.claude/workflows/engine.js"
    _st_write_mk 'sh scripts/posix.sh'
    _st_write_ci 'sh scripts/posix.sh'

    _st_write_js "$_ST_JS1" "  run('sh scripts/bashy.sh');"
    _st_case "js-side sh-invokes-bash-script mismatch caught (jsworkflow scan)" 1

    # --- jsworkflow: a matched js invocation (sh on a #!/bin/sh target) passes. ---
    _st_write_js "$_ST_JS1" "  run('sh scripts/posix.sh');"
    _st_case "js-side matched invocation passes (jsworkflow)" 0

    # --- jsworkflow scope: a variable target (bash \"\$gate\") has no literal .sh
    # and is SKIPPED — mirrors task-wave.js's real `bash \"\$gate\"` gate call. ---
    _st_write_js "$_ST_JS1" '  run(`bash "$gate"`);'
    _st_case "js-side variable target skipped (no literal .sh)" 0

    # --- jsworkflow scope: a `//`-comment mention names a script in prose but does
    # not invoke it, so it is SKIPPED (proves comment lines never trip). ---
    _st_write_js "$_ST_JS1" '  // legacy note: sh scripts/bashy.sh (documented, not run)'
    _st_case "js-side // comment mention skipped (not a live invocation)" 0

    rm -f "$_ST_JS1"
    _ST_JSDIR=""

    if [ "$_fail" -ne 0 ]; then
        printf 'self-test: FAIL — one or more sub-tests failed\n' >&2
        exit 1
    fi
    printf 'self-test: ALL CHECKS PASSED — check-shebang-invocation.sh OK\n'
    exit 0
fi

# Reject unknown flags (the taskdb footgun-guard discipline: an unknown flag must
# never be silently treated as a no-op production run).
if [ "$#" -gt 0 ]; then
    printf 'check-shebang-invocation: unknown argument: %s (use --self-test | --emit-posix | no args)\n' "$1" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Production path: guard the real Makefile + EVERY .github/workflows/*.yml
# invocation (not ci.yml alone — a mismatched `sh|bash <script>.sh` in any
# workflow is now caught).
# ---------------------------------------------------------------------------
MAKEFILE="$REPO_ROOT/Makefile"
WFDIR="$REPO_ROOT/.github/workflows"

_rc=0
_run_checks "$REPO_ROOT" "$MAKEFILE" "$WFDIR" || _rc=$?

if [ "$_rc" -ne 0 ]; then
    printf 'check-shebang-invocation: FAIL — an interpreter invocation disagrees with its target shebang (rc=%d)\n' "$_rc" >&2
    exit "$_rc"
fi

printf 'check-shebang-invocation: OK — every sh|bash script invocation matches its target shebang\n'
