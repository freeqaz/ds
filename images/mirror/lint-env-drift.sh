#!/bin/sh
# lint-env-drift.sh — assert that the quadlet ds-mirror-serve.container
# generator-key literals match the canonical values in ds-mirror.env, and
# that the container-side Volume= mount path matches GIT_PROJECT_ROOT in
# git-http-backend.conf, and that the mirror mount is read-only, and that
# the push verb is disabled at the CGI layer.
#
# The quadlet's Image=, PublishPort=, and Volume= are processed by the podman
# GENERATOR at install time, NOT by the container runtime, so they cannot
# expand EnvironmentFile= variables.  Those literals are therefore kept in
# lockstep with ds-mirror.env by hand; this lint catches divergence before it
# reaches production.
#
# The third assertion checks that the container-side path in Volume=
# (e.g. Volume=/var/lib/ds-mirror:/srv/git:ro,Z -> /srv/git) matches
# GIT_PROJECT_ROOT in deploy/git-http-backend.conf; divergence here silently
# breaks serving.
#
# The fourth assertion checks that the options field of the Volume= line
# (third colon-separated field, e.g. ro,Z) contains the token 'ro' as an
# EXACT comma-split token — not a substring ('rom'/'roo' are rejected).
# This guards the belt-and-suspenders read-only mount atop the push-disabled
# CGI (D83 boundary/egress posture; mirror is structurally pull-only per
# git-http-backend.conf GIT_HTTP_RECEIVE_PACK=0).  The check splits the
# options field on commas and matches 'ro' exactly as a token.
# Canonical Volume= line is:
#   Volume=/var/lib/ds-mirror:/srv/git:ro,Z
#
# The fifth assertion checks that deploy/git-http-backend.conf sets
# GIT_HTTP_RECEIVE_PACK=0 (exact key, exact value, not commented out, not
# absent).  The push-disabled CGI is the primary pull-only enforcement; the
# :ro mount is belt-and-suspenders on top.  Both guards must be present.
#
# The sixth assertion is a standalone loopback check: the serve container's
# PublishPort MUST bind to a loopback address ({127.0.0.1, [::1]}) regardless of
# DS_MIRROR_ADDR.  This closes a gap where matching both files to 0.0.0.0 would
# satisfy the env-file equality check but expose the serve face beyond
# host-loopback.
#
# Usage:
#   sh images/mirror/lint-env-drift.sh [DEPLOY_DIR]
#   LINT_DEPLOY_DIR=/path/to/deploy sh images/mirror/lint-env-drift.sh
# (or run from repo root; paths are resolved relative to this script's
# directory when no DEPLOY_DIR argument or LINT_DEPLOY_DIR env var is given)
#
# --self-test: internal regression harness; copies deploy/ to a temp dir,
# verifies the clean copy passes, then injects each recognised drift one at a
# time and verifies the lint catches it.  Exits 0 on success, non-zero if any
# injection is not caught.  Dispatched BEFORE any file-existence checks.
# Temp dir is cleaned up via a trap on EXIT.
# Injections are anchored to generator key PATTERNS (not byte-exact whole
# lines) — the harness fails immediately if an anchor is gone (no silent
# no-op when upstream lines are reformatted).
#
# Wired into smoke.sh: runs automatically under DS_MIRROR_SMOKE=1.  Also folded
# into the standing gate: `make check-image-drift` runs the clean-mode lint and
# `make check-image-drift-selftest` re-runs it under --self-test (both repo-lints
# prerequisites), so the injection arms and README-token guards fire in CI, not
# only under the DS_MIRROR_SMOKE smoke path.
#
# SPDX-License-Identifier: Apache-2.0

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# --self-test mode: must be dispatched before any file-existence checks.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    SELF_TEST_DEPLOY="$(mktemp -d)"
    _st_cleanup() { rm -rf "$SELF_TEST_DEPLOY"; }
    trap _st_cleanup EXIT

    cp -r "$SCRIPT_DIR/deploy/." "$SELF_TEST_DEPLOY/"

    # Resolve the container and conf file paths for injection helpers.
    _ST_CTR="$SELF_TEST_DEPLOY/ds-mirror-serve.container"
    _ST_CONF="$SELF_TEST_DEPLOY/git-http-backend.conf"

    # Helper: replace the first line matching ANCHOR_PAT in FILE with NEW_LINE.
    # Fails if no line matched (anchor gone — no silent no-op).
    # Usage: _replace_line FILE ANCHOR_PAT NEW_LINE LABEL
    _replace_line() {
        _rl_file="$1"
        _rl_pat="$2"
        _rl_new="$3"
        _rl_label="$4"
        _rl_matched="$(awk -v pat="$_rl_pat" '$0 ~ pat { print NR; exit }' "$_rl_file")"
        if [ -z "$_rl_matched" ]; then
            printf 'self-test: ABORT — injection anchor gone: %s (pattern: %s)\n' \
                "$_rl_label" "$_rl_pat" >&2
            exit 1
        fi
        awk -v pat="$_rl_pat" -v new="$_rl_new" -v done=0 '
            !done && $0 ~ pat { print new; done=1; next }
            { print }
        ' "$_rl_file" > "$_rl_file.tmp" && mv "$_rl_file.tmp" "$_rl_file"
    }

    # Helper: restore the clean copy.
    _restore() {
        cp -r "$SCRIPT_DIR/deploy/." "$SELF_TEST_DEPLOY/"
    }

    # Helper: delete lines matching ANCHOR_PAT from FILE.
    # Fails if no line matched (anchor gone — no silent no-op).
    # Usage: _delete_line FILE ANCHOR_PAT LABEL
    _delete_line() {
        _dl_file="$1"
        _dl_pat="$2"
        _dl_label="$3"
        _dl_matched="$(awk -v pat="$_dl_pat" '$0 ~ pat { print NR; exit }' "$_dl_file")"
        if [ -z "$_dl_matched" ]; then
            printf 'self-test: ABORT — injection anchor gone: %s (pattern: %s)\n' \
                "$_dl_label" "$_dl_pat" >&2
            exit 1
        fi
        awk -v pat="$_dl_pat" '$0 ~ pat { next } { print }' \
            "$_dl_file" > "$_dl_file.tmp" && mv "$_dl_file.tmp" "$_dl_file"
    }

    # Confirm the canonical (clean) copy passes.
    _clean_rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _clean_rc=$?
    if [ "$_clean_rc" -ne 0 ]; then
        printf 'self-test: FAIL — clean copy did not exit 0 (rc=%d)\n' "$_clean_rc" >&2
        exit 1
    fi
    printf 'self-test: clean copy passed (rc=0)\n'

    # --- loopback-set coverage: [::1] is an accepted loopback address ---
    # Verify that the loopback assertion also accepts the IPv6 loopback [::1]
    # (the set is {127.0.0.1, [::1]}; quadlet PublishPort= brackets IPv6 addrs).
    # We mutate DS_MIRROR_ADDR AND the PublishPort= addr to [::1] together so the
    # env-equality check still passes, then confirm the lint exits 0 ([::1] is
    # valid — NOT an injection to catch).
    _restore
    _replace_line "$_ST_CTR" \
        '^PublishPort=' \
        'PublishPort=[::1]:8418:8418' \
        'PublishPort= ::1 loopback'
    _replace_line "$SELF_TEST_DEPLOY/ds-mirror.env" \
        '^DS_MIRROR_ADDR=' \
        'DS_MIRROR_ADDR=[::1]' \
        'DS_MIRROR_ADDR ::1 loopback'
    _ipv6_rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _ipv6_rc=$?
    if [ "$_ipv6_rc" -ne 0 ]; then
        printf 'self-test: FAIL — ::1 loopback should be accepted but lint exited %d\n' \
            "$_ipv6_rc" >&2
        exit 1
    fi
    printf 'self-test: ::1 loopback accepted (rc=0)\n'

    # --- injection 1: wrong Image= digest ---
    _restore
    _replace_line "$_ST_CTR" \
        '^Image=docker[.]io/alpine/git:' \
        'Image=docker.io/alpine/git:latest@sha256:0000000000000000000000000000000000000000000000000000000000000bad' \
        'Image= digest'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [Image= digest] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [Image= digest] caught (rc=%d)\n' "$_rc"

    # --- injection 2: wrong PublishPort= addr ---
    _restore
    _replace_line "$_ST_CTR" \
        '^PublishPort=' \
        'PublishPort=0.0.0.0:8418:8418' \
        'PublishPort= addr'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [PublishPort= addr] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [PublishPort= addr] caught (rc=%d)\n' "$_rc"

    # --- injection 3: wrong PublishPort= host port ---
    _restore
    _replace_line "$_ST_CTR" \
        '^PublishPort=' \
        'PublishPort=127.0.0.1:9999:8418' \
        'PublishPort= host port'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [PublishPort= host port] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [PublishPort= host port] caught (rc=%d)\n' "$_rc"

    # --- injection 4: wrong Volume= host path ---
    _restore
    _replace_line "$_ST_CTR" \
        '^Volume=' \
        'Volume=/var/lib/ds-WRONG:/srv/git:ro,Z' \
        'Volume= host path'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [Volume= host path] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [Volume= host path] caught (rc=%d)\n' "$_rc"

    # --- injection 5: wrong Volume= container path ---
    _restore
    _replace_line "$_ST_CTR" \
        '^Volume=' \
        'Volume=/var/lib/ds-mirror:/srv/WRONG:ro,Z' \
        'Volume= container path'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [Volume= container path] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [Volume= container path] caught (rc=%d)\n' "$_rc"

    # --- injection 6: :ro removed from Volume= options ---
    _restore
    _replace_line "$_ST_CTR" \
        '^Volume=' \
        'Volume=/var/lib/ds-mirror:/srv/git:Z' \
        'Volume= :ro removed'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [Volume= :ro suffix] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [Volume= :ro suffix] caught (rc=%d)\n' "$_rc"

    # --- injection 6b: :ro replaced by :rom (token-level mutation, not :ro) ---
    # This verifies the exact comma-split token check: 'rom' is NOT 'ro'.
    _restore
    _replace_line "$_ST_CTR" \
        '^Volume=' \
        'Volume=/var/lib/ds-mirror:/srv/git:rom,Z' \
        'Volume= :ro->:rom token mutation'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [Volume= :rom token mutation] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [Volume= :rom token mutation] caught (rc=%d)\n' "$_rc"

    # --- injection 7: GIT_HTTP_RECEIVE_PACK disabled or changed ---
    # Verifies the fifth assertion: receive-pack must be exactly 0.
    _restore
    _replace_line "$_ST_CONF" \
        '^GIT_HTTP_RECEIVE_PACK=' \
        'GIT_HTTP_RECEIVE_PACK=1' \
        'GIT_HTTP_RECEIVE_PACK value'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [GIT_HTTP_RECEIVE_PACK=1] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [GIT_HTTP_RECEIVE_PACK=1] caught (rc=%d)\n' "$_rc"

    # --- injection 8: GIT_HTTP_RECEIVE_PACK commented out ---
    # Verifies the fifth assertion also catches a disabled-via-comment guard:
    # a commented-out line is invisible to the parser (returns absent), which
    # must be rejected just as firmly as a missing or wrong-value line.
    _restore
    _replace_line "$_ST_CONF" \
        '^GIT_HTTP_RECEIVE_PACK=' \
        '# GIT_HTTP_RECEIVE_PACK=0' \
        'GIT_HTTP_RECEIVE_PACK commented out'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [GIT_HTTP_RECEIVE_PACK commented out] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [GIT_HTTP_RECEIVE_PACK commented out] caught (rc=%d)\n' "$_rc"

    # --- injection 9: GIT_HTTP_RECEIVE_PACK line removed entirely ---
    # Verifies the fifth assertion catches a removed receive-pack guard: absence
    # of the key is as dangerous as a wrong value (the push-disabled CGI is the
    # primary pull-only enforcement; its absence cannot go undetected).
    _restore
    _delete_line "$_ST_CONF" \
        '^GIT_HTTP_RECEIVE_PACK=' \
        'GIT_HTTP_RECEIVE_PACK absent line'
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [GIT_HTTP_RECEIVE_PACK absent] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [GIT_HTTP_RECEIVE_PACK absent] caught (rc=%d)\n' "$_rc"

    # --- injection 10: ds-mirror.env renamed aside (env-absent) ---
    # Renames deploy/ds-mirror.env in the temp sandbox to verify the lint
    # fails closed (ABORT, non-zero exit) when the env file is missing.
    # The real images/mirror/deploy/ tree is never touched — only the temp copy.
    # Restore (mv back) precedes the assertion so the temp sandbox is clean
    # regardless of whether the assertion causes an early exit.
    _restore
    mv "$SELF_TEST_DEPLOY/ds-mirror.env" "$SELF_TEST_DEPLOY/ds-mirror.env.absent"
    _rc=0
    sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
    mv "$SELF_TEST_DEPLOY/ds-mirror.env.absent" "$SELF_TEST_DEPLOY/ds-mirror.env"
    if [ "$_rc" -eq 0 ]; then
        printf 'self-test: FAIL — injection [env-absent] was not caught\n' >&2
        exit 1
    fi
    printf 'self-test: injection [env-absent] caught (rc=%d)\n' "$_rc"

    # -----------------------------------------------------------------------
    # Egress-enrollment guard — .service Environment= literals vs README table.
    #
    # The seventh assertion compares each DS_MIRROR_EGRESS_* Environment= value
    # in ds-mirror-refresh.service against the value cell in the README
    # "Boundary enrollment" table.  These arms exercise BOTH sides of that
    # comparison against the REAL clean-mode code path:
    #   (a) per-key .service value mutation — temp deploy's .service diverges
    #       from the (canonical) README → mismatch must be caught;
    #   (b) per-key .service Environment= line removal — the fail-closed absent
    #       branch must be caught;
    #   (c) per-key README value-cell mutation — via $LINT_README_FILE pointed at
    #       a mutated README copy (the real .service stays canonical) → mismatch
    #       must be caught.
    # The .service injections are anchored to the Environment=KEY= pattern (not
    # byte-exact whole lines); _replace_line / _delete_line abort non-zero if the
    # anchor is gone, so an upstream reformat cannot silently no-op an arm.
    # -----------------------------------------------------------------------
    _ST_SVC="$SELF_TEST_DEPLOY/ds-mirror-refresh.service"

    # (a) per-key .service value mutation.
    for _eg_key in \
        DS_MIRROR_EGRESS_GATEWAY \
        DS_MIRROR_EGRESS_SWAP \
        DS_MIRROR_EGRESS_CRED_REF \
        DS_MIRROR_EGRESS_UPSTREAMS
    do
        _restore
        _replace_line "$_ST_SVC" \
            "^Environment=${_eg_key}=" \
            "Environment=${_eg_key}=DRIFTED-WRONG-VALUE" \
            "Environment=${_eg_key} value"
        _rc=0
        sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ]; then
            printf 'self-test: FAIL — injection [Environment=%s drift] was not caught\n' \
                "$_eg_key" >&2
            exit 1
        fi
        printf 'self-test: injection [Environment=%s drift] caught (rc=%d)\n' \
            "$_eg_key" "$_rc"
    done

    # (b) per-key .service Environment= line removed (fail-closed absent branch).
    for _eg_key in \
        DS_MIRROR_EGRESS_GATEWAY \
        DS_MIRROR_EGRESS_SWAP \
        DS_MIRROR_EGRESS_CRED_REF \
        DS_MIRROR_EGRESS_UPSTREAMS
    do
        _restore
        _delete_line "$_ST_SVC" \
            "^Environment=${_eg_key}=" \
            "Environment=${_eg_key} absent line"
        _rc=0
        sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ]; then
            printf 'self-test: FAIL — injection [Environment=%s absent] was not caught\n' \
                "$_eg_key" >&2
            exit 1
        fi
        printf 'self-test: injection [Environment=%s absent] caught (rc=%d)\n' \
            "$_eg_key" "$_rc"
    done

    # (c) per-key README value-cell mutation, via $LINT_README_FILE pointed at a
    #     mutated copy of the real README.  The temp deploy is restored clean
    #     first so ONLY the README side drifts.  The README copy mutates the
    #     value cell of one egress table row at a time; the lint must catch the
    #     resulting .service↔README mismatch.  The copy is cleaned up via the
    #     extended EXIT trap below ($_README_MUT).
    #
    # $_README (the canonical tree README) is the perturbation source for both
    # this block AND the README-token guard further down; it is defined+guarded
    # here, the first point of use, so set -eu never sees it unbound.
    _README="$SCRIPT_DIR/README.md"
    if [ ! -f "$_README" ]; then
        printf 'self-test: ABORT — README.md not found at %s\n' "$_README" >&2
        exit 1
    fi
    _restore
    _EG_README_MUT="$(mktemp)"
    _st_cleanup_eg() { rm -rf "$SELF_TEST_DEPLOY"; rm -f "$_EG_README_MUT"; }
    trap _st_cleanup_eg EXIT
    for _eg_pair in \
        'DS_MIRROR_EGRESS_GATEWAY|ds-tlsproxy' \
        'DS_MIRROR_EGRESS_SWAP|authorization-header-swap' \
        'DS_MIRROR_EGRESS_CRED_REF|workload:ds-mirror-refresh' \
        'DS_MIRROR_EGRESS_UPSTREAMS|github.com,api.github.com,codeload.github.com'
    do
        _eg_k="${_eg_pair%%|*}"
        _eg_v="${_eg_pair#*|}"
        # Anchored to the table row "^| `KEY` |"; abort non-zero if the row is
        # gone (no silent no-op on an upstream reformat).  Then rewrite the
        # backtick-wrapped value cell to a wrong value in the README copy via an
        # awk index-based substitution (robust to the '|' table delimiters that
        # would break a sed s|…| expression).
        _eg_matched="$(awk -v k="$_eg_k" '$0 ~ ("^\\| `" k "` \\|") { print NR; exit }' "$_README")"
        if [ -z "$_eg_matched" ]; then
            printf 'self-test: ABORT — egress README anchor gone for %s\n' "$_eg_k" >&2
            exit 1
        fi
        awk -v k="$_eg_k" -v oldv="$_eg_v" '
            $0 ~ ("^\\| `" k "` \\|") {
                idx = index($0, "`" oldv "`")
                if (idx > 0) {
                    $0 = substr($0, 1, idx - 1) "`DRIFTED-README-VALUE`" \
                         substr($0, idx + length("`" oldv "`"))
                }
            }
            { print }
        ' "$_README" > "$_EG_README_MUT"
        _rc=0
        LINT_README_FILE="$_EG_README_MUT" \
            sh "$SCRIPT_DIR/lint-env-drift.sh" "$SELF_TEST_DEPLOY" >/dev/null 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ]; then
            printf 'self-test: FAIL — README perturbation [%s value] was not caught\n' \
                "$_eg_k" >&2
            exit 1
        fi
        printf 'self-test: README perturbation [%s value] caught (rc=%d)\n' \
            "$_eg_k" "$_rc"
    done
    rm -f "$_EG_README_MUT"

    # -----------------------------------------------------------------------
    # README token guard — via scripts/lint-readme-tokens.sh (shared helper).
    #
    # Unique-match anchoring: zero or multiple anchor hits is itself a failure,
    # retiring the wave-1 first-match residual risk.
    #
    # Five load-bearing tokens in README.md must stay in sync with the script's
    # ground truth.  All sides are recomputed here (never literal-frozen), so
    # a future unit that updates both sides stays green while a one-sided edit
    # fails immediately.
    #
    # (i)   Accepted loopback set — anchored to the unique line containing
    #       "accepted loopback set"; value extracted from `{…}` on that line.
    # (ii)  Injected-drift count — anchored to the unique bold-backtick phrase
    #       **`N recognized drifts`**; value is the leading number.
    # (iii) DS_MIRROR_ROOT default — anchored to the unique line containing
    #       DS_MIRROR_ROOT= in the README; truth sourced from deploy/ds-mirror.env.
    # (iv)  DS_MIRROR_ADDR default — anchored to the unique line containing
    #       DS_MIRROR_ADDR= in the README; truth sourced from deploy/ds-mirror.env.
    # (v)   DS_MIRROR_PORT default — anchored to the unique line containing
    #       DS_MIRROR_PORT= in the README; truth sourced from deploy/ds-mirror.env.
    # -----------------------------------------------------------------------

    # $_README is already defined+guarded above (section (c), first use).
    _SELF="$SCRIPT_DIR/lint-env-drift.sh"
    _HELPER="$(cd "$SCRIPT_DIR/../.." && pwd)/scripts/lint-readme-tokens.sh"
    _ENV_FILE="$SCRIPT_DIR/deploy/ds-mirror.env"

    if [ ! -f "$_HELPER" ]; then
        printf 'self-test: ABORT — lint-readme-tokens.sh helper not found at %s\n' "$_HELPER" >&2
        exit 1
    fi
    if [ ! -f "$_ENV_FILE" ]; then
        printf 'self-test: ABORT — ds-mirror.env not found at %s\n' "$_ENV_FILE" >&2
        exit 1
    fi
    . "$_HELPER"

    lrt_set_readme "$_README"

    # (i) Accepted loopback set — source: case statement in the lint body.
    # The canonical case line is:  "    127.0.0.1|'[::1]') ;;"
    # After tr -d " \t'\"" it becomes "127.0.0.1|[::1]);;"; strip from ) onward,
    # then split on | (preserve order — README must list addresses in the same
    # order as the case pattern) to produce "127.0.0.1 [::1]".
    _script_loopback_set="$(awk '/^case.*CTR_ADDR/,/^esac/' "$_SELF" | \
        grep -v '^case\|^\*)\|^esac' | awk '/\)/' | head -1 | \
        tr -d " \t'\"" | sed 's/).*$//' | tr '|' '\n' | tr '\n' ' ' | \
        sed 's/ $//')"
    # README anchor: line containing "accepted loopback set" (unique in README).
    # Extract: strip leading context, pull content of `{…}`, normalise commas.
    lrt_register "loopback-set" \
        "printf '%s' \"$_script_loopback_set\"" \
        'accepted loopback set' \
        's/.*`{\([^}]*\)}`.*/\1/; s/, / /g'

    # (ii) Injected-drift count — source: count of injection blocks in this script.
    _script_injection_count="$(grep -c '^    # --- injection' "$_SELF")"
    # README anchor: the unique bold-backtick phrase **`N recognized drifts`**.
    # Extract: strip everything except the leading number before " recognized drifts".
    lrt_register "drift-count" \
        "printf '%s' \"$_script_injection_count\"" \
        '\*\*`[0-9][0-9]* recognized drifts`\*\*' \
        's/[^0-9]*\([0-9][0-9]*\) recognized drifts.*/\1/'

    # (iii) DS_MIRROR_ROOT default — source: deploy/ds-mirror.env.
    # README anchor: the list-item line "- mirror root: `DS_MIRROR_ROOT=…`" (line ~159).
    # Combined anchor "mirror root.*DS_MIRROR_ROOT=" is unique in README (the
    # self-test description uses a different phrasing that lacks "mirror root:").
    # Extract: pull value after DS_MIRROR_ROOT= and before the closing backtick.
    _env_mirror_root="$(awk '/^DS_MIRROR_ROOT=/{val=substr($0,index($0,"=")+1); print val; exit}' "$_ENV_FILE")"
    lrt_register "mirror-root" \
        "printf '%s' \"$_env_mirror_root\"" \
        'mirror root.*DS_MIRROR_ROOT=' \
        's/.*`DS_MIRROR_ROOT=\([^`]*\)`.*/\1/'

    # (iv) DS_MIRROR_ADDR default — source: deploy/ds-mirror.env.
    # README anchor: the list-item line "- serve address: `DS_MIRROR_ADDR=…`, …" (line ~160).
    # Combined anchor "serve address.*DS_MIRROR_ADDR=" is unique in README.
    # Extract: pull value after DS_MIRROR_ADDR= and before the closing backtick.
    _env_mirror_addr="$(awk '/^DS_MIRROR_ADDR=/{val=substr($0,index($0,"=")+1); print val; exit}' "$_ENV_FILE")"
    lrt_register "serve-addr" \
        "printf '%s' \"$_env_mirror_addr\"" \
        'serve address.*DS_MIRROR_ADDR=' \
        's/.*`DS_MIRROR_ADDR=\([^`]*\)`.*/\1/'

    # (v) DS_MIRROR_PORT default — source: deploy/ds-mirror.env.
    # README anchor: same list-item line as serve-addr "- serve address: …, `DS_MIRROR_PORT=…`."
    # Combined anchor "serve address.*DS_MIRROR_PORT=" is unique in README.
    # Extract: pull value after DS_MIRROR_PORT= and before the closing backtick.
    _env_mirror_port="$(awk '/^DS_MIRROR_PORT=/{val=substr($0,index($0,"=")+1); print val; exit}' "$_ENV_FILE")"
    lrt_register "serve-port" \
        "printf '%s' \"$_env_mirror_port\"" \
        'serve address.*DS_MIRROR_PORT=' \
        's/.*`DS_MIRROR_PORT=\([^`]*\)`.*/\1/'

    # Capture lrt_check_all exit code before piping its output through sed.
    # POSIX sh gives us the last cmd's exit code from a pipeline, not lrt_check_all's;
    # use a temp file to decouple output from exit code.
    _readme_out="$(mktemp)"
    _readme_rc=0
    lrt_check_all > "$_readme_out" 2>&1 || _readme_rc=$?
    sed 's/^/self-test: /' < "$_readme_out"
    rm -f "$_readme_out"
    if [ "$_readme_rc" -ne 0 ]; then
        printf 'self-test: FAIL — README token guard failed (rc=%d)\n' "$_readme_rc" >&2
        exit 1
    fi

    # -----------------------------------------------------------------------
    # README mirror-defaults perturbation tests (iii–v).
    #
    # Verify that a one-sided README mutation (each default literal changed
    # independently while ds-mirror.env stays untouched) makes lrt_check_all
    # exit non-zero.  We work on a temp copy of README so the live file is
    # never modified.  Each block is PIPESTATUS-safe: lrt_check_all's exit
    # code is captured via || _prc=$? without any piped consumer that could
    # shadow it.
    # -----------------------------------------------------------------------

    _README_ORIG="$_README"
    _README_MUT="$(mktemp)"
    # Extend the existing EXIT trap to also clean up the mutation temp file.
    _st_cleanup_ext() { rm -rf "$SELF_TEST_DEPLOY"; rm -f "$_README_MUT"; }
    trap _st_cleanup_ext EXIT

    # Helper: run lrt_check_all against a mutated README copy and verify it
    # catches the perturbation (exit non-zero).  PIPESTATUS-safe: lrt_check_all's
    # exit code is captured via || _rpc_rc=$? with no piped consumer to shadow it;
    # output goes to a temp file to decouple it from the exit code.
    # Usage: _readme_perturb_check LABEL MUTATED_README
    _readme_perturb_check() {
        _rpc_label="$1"
        _rpc_readme="$2"
        _rpc_out="$(mktemp)"
        _rpc_rc=0
        lrt_check_all "$_rpc_readme" > "$_rpc_out" 2>&1 || _rpc_rc=$?
        rm -f "$_rpc_out"
        if [ "$_rpc_rc" -eq 0 ]; then
            printf 'self-test: FAIL — README perturbation [%s] was NOT caught\n' \
                "$_rpc_label" >&2
            exit 1
        fi
        printf 'self-test: README perturbation [%s] caught (rc=%d)\n' \
            "$_rpc_label" "$_rpc_rc"
    }

    # Perturbation (iii): mutate DS_MIRROR_ROOT default in README copy.
    awk '{gsub(/`DS_MIRROR_ROOT=\/var\/lib\/ds-mirror`/, "`DS_MIRROR_ROOT=/var/lib/ds-WRONG`"); print}' \
        "$_README_ORIG" > "$_README_MUT"
    _readme_perturb_check "mirror-root" "$_README_MUT"

    # Perturbation (iv): mutate DS_MIRROR_ADDR default in README copy.
    awk '{gsub(/`DS_MIRROR_ADDR=127\.0\.0\.1`/, "`DS_MIRROR_ADDR=10.0.0.1`"); print}' \
        "$_README_ORIG" > "$_README_MUT"
    _readme_perturb_check "serve-addr" "$_README_MUT"

    # Perturbation (v): mutate DS_MIRROR_PORT default in README copy.
    awk '{gsub(/`DS_MIRROR_PORT=8418`/, "`DS_MIRROR_PORT=9999`"); print}' \
        "$_README_ORIG" > "$_README_MUT"
    _readme_perturb_check "serve-port" "$_README_MUT"

    printf 'self-test: ALL INJECTIONS CAUGHT — lint-env-drift.sh OK\n'
    exit 0
fi

# ---------------------------------------------------------------------------
# Resolve the deploy directory: $1 > $LINT_DEPLOY_DIR > script-relative default
# ---------------------------------------------------------------------------
if [ $# -ge 1 ]; then
    DEPLOY_DIR="$1"
elif [ -n "${LINT_DEPLOY_DIR:-}" ]; then
    DEPLOY_DIR="$LINT_DEPLOY_DIR"
else
    DEPLOY_DIR="$SCRIPT_DIR/deploy"
fi

ENV_FILE="$DEPLOY_DIR/ds-mirror.env"
CONTAINER_FILE="$DEPLOY_DIR/ds-mirror-serve.container"
CONF_FILE="$DEPLOY_DIR/git-http-backend.conf"
SERVICE_FILE="$DEPLOY_DIR/ds-mirror-refresh.service"
# The egress-enrollment table lives in the tree README, NOT in the deploy dir,
# so it is resolved script-relative by default (the --self-test harness copies
# only deploy/ to a temp dir; the README guard then reads the canonical tree
# README).  $LINT_README_FILE overrides it so the --self-test README-side
# perturbation arms can point the real clean-mode assertion at a mutated copy.
README_FILE="${LINT_README_FILE:-$SCRIPT_DIR/README.md}"

if [ ! -f "$ENV_FILE" ]; then
    printf 'lint-env-drift: ERROR: not found: %s\n' "$ENV_FILE" >&2
    exit 2
fi
if [ ! -f "$CONTAINER_FILE" ]; then
    printf 'lint-env-drift: ERROR: not found: %s\n' "$CONTAINER_FILE" >&2
    exit 2
fi
if [ ! -f "$CONF_FILE" ]; then
    printf 'lint-env-drift: ERROR: not found: %s\n' "$CONF_FILE" >&2
    exit 2
fi
if [ ! -f "$SERVICE_FILE" ]; then
    printf 'lint-env-drift: ERROR: not found: %s\n' "$SERVICE_FILE" >&2
    exit 2
fi
if [ ! -f "$README_FILE" ]; then
    printf 'lint-env-drift: ERROR: not found: %s\n' "$README_FILE" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Parse ds-mirror.env — extract KEY=VALUE pairs (skip comments and blanks)
# ---------------------------------------------------------------------------
_env_val() {
    # _env_val KEY  → prints the value or empty string
    awk -v key="$1" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        {
            sub(/^[[:space:]]*/, "")
            if (index($0, key "=") == 1) {
                val = substr($0, length(key) + 2)
                # strip inline comments (first unquoted #)
                gsub(/#.*/, "", val)
                # strip trailing whitespace
                gsub(/[[:space:]]*$/, "", val)
                print val
                exit
            }
        }
    ' "$ENV_FILE"
}

# ---------------------------------------------------------------------------
# Parse ds-mirror-serve.container — extract generator key values
# ---------------------------------------------------------------------------

# Image= line: "Image=<ref>"
_container_image() {
    awk '
        /^\[/ { in_container = 0 }
        /^\[Container\]/ { in_container = 1; next }
        in_container && /^Image=/ {
            val = substr($0, 7)
            gsub(/[[:space:]]*$/, "", val)
            print val
            exit
        }
    ' "$CONTAINER_FILE"
}

# PublishPort= line: "PublishPort=<addr>:<host_port>:<container_port>"
# addr may be an IPv4 dotted address (127.0.0.1) or a bracketed IPv6 address
# ([::1]).  We split on the LAST two colons to extract addr, host_port, and
# container_port, so that the bracket group is preserved intact as the addr.
# e.g. "127.0.0.1:8418:8418"  -> addr=127.0.0.1  hp=8418  cp=8418
#      "[::1]:8418:8418"       -> addr=[::1]       hp=8418  cp=8418
_container_publish_addr() {
    awk '
        /^\[/ { in_container = 0 }
        /^\[Container\]/ { in_container = 1; next }
        in_container && /^PublishPort=/ {
            val = substr($0, 13)
            gsub(/[[:space:]]*$/, "", val)
            # Split from the right on the last two colons to handle IPv6 brackets.
            # Find last colon -> container port; strip it; find new last colon ->
            # host port; everything before is the addr.
            cp_sep = match(val, /:[^:]+$/)
            if (cp_sep == 0) { exit }
            rest = substr(val, 1, cp_sep - 1)
            hp_sep = match(rest, /:[^:]+$/)
            if (hp_sep == 0) { exit }
            print substr(rest, 1, hp_sep - 1)
            exit
        }
    ' "$CONTAINER_FILE"
}

_container_publish_host_port() {
    awk '
        /^\[/ { in_container = 0 }
        /^\[Container\]/ { in_container = 1; next }
        in_container && /^PublishPort=/ {
            val = substr($0, 13)
            gsub(/[[:space:]]*$/, "", val)
            cp_sep = match(val, /:[^:]+$/)
            if (cp_sep == 0) { exit }
            rest = substr(val, 1, cp_sep - 1)
            hp_sep = match(rest, /:[^:]+$/)
            if (hp_sep == 0) { exit }
            print substr(rest, hp_sep + 1)
            exit
        }
    ' "$CONTAINER_FILE"
}

_container_publish_container_port() {
    awk '
        /^\[/ { in_container = 0 }
        /^\[Container\]/ { in_container = 1; next }
        in_container && /^PublishPort=/ {
            val = substr($0, 13)
            gsub(/[[:space:]]*$/, "", val)
            cp_sep = match(val, /:[^:]+$/)
            if (cp_sep == 0) { exit }
            print substr(val, cp_sep + 1)
            exit
        }
    ' "$CONTAINER_FILE"
}

# Volume= line: "Volume=<host_path>:<container_path>[:<opts>]"
# We extract only the host path (the canonical mirror root).
_container_volume_host_path() {
    awk '
        /^\[/ { in_container = 0 }
        /^\[Container\]/ { in_container = 1; next }
        in_container && /^Volume=/ {
            val = substr($0, 8)
            gsub(/[[:space:]]*$/, "", val)
            n = split(val, parts, ":")
            if (n >= 1) { print parts[1] }
            exit
        }
    ' "$CONTAINER_FILE"
}

# Volume= line: extract the CONTAINER-SIDE path (second colon-separated field).
# e.g. Volume=/var/lib/ds-mirror:/srv/git:ro,Z  ->  /srv/git
_container_volume_container_path() {
    awk '
        /^\[/ { in_container = 0 }
        /^\[Container\]/ { in_container = 1; next }
        in_container && /^Volume=/ {
            val = substr($0, 8)
            gsub(/[[:space:]]*$/, "", val)
            n = split(val, parts, ":")
            if (n >= 2) { print parts[2] }
            exit
        }
    ' "$CONTAINER_FILE"
}

# Volume= line: extract the OPTIONS field (third colon-separated field).
# e.g. Volume=/var/lib/ds-mirror:/srv/git:ro,Z  ->  ro,Z
_container_volume_opts() {
    awk '
        /^\[/ { in_container = 0 }
        /^\[Container\]/ { in_container = 1; next }
        in_container && /^Volume=/ {
            val = substr($0, 8)
            gsub(/[[:space:]]*$/, "", val)
            n = split(val, parts, ":")
            if (n >= 3) { print parts[3] }
            exit
        }
    ' "$CONTAINER_FILE"
}

# git-http-backend.conf: extract GIT_PROJECT_ROOT value.
_conf_git_project_root() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        {
            sub(/^[[:space:]]*/, "")
            if (index($0, "GIT_PROJECT_ROOT=") == 1) {
                val = substr($0, length("GIT_PROJECT_ROOT=") + 1)
                gsub(/#.*/, "", val)
                gsub(/[[:space:]]*$/, "", val)
                print val
                exit
            }
        }
    ' "$CONF_FILE"
}

# git-http-backend.conf: extract GIT_HTTP_RECEIVE_PACK value.
# Returns empty string if the key is absent or commented out.
_conf_git_receive_pack() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        {
            sub(/^[[:space:]]*/, "")
            if (index($0, "GIT_HTTP_RECEIVE_PACK=") == 1) {
                val = substr($0, length("GIT_HTTP_RECEIVE_PACK=") + 1)
                gsub(/#.*/, "", val)
                gsub(/[[:space:]]*$/, "", val)
                print val
                exit
            }
        }
    ' "$CONF_FILE"
}

# ds-mirror-refresh.service: extract the value of an Environment=KEY=VALUE line,
# scoped to the [Service] section (a stray KEY= line in another section is NOT
# matched).  These are systemd Environment= literals — the egress-enrollment
# seam (DS_MIRROR_EGRESS_*) the boundary owes this unit (D63 boundary path + D83
# credential swap; doc 16 §5).  Returns empty string if the key is absent.
# Usage: _service_env_val KEY  (with $1 = the .service file path)
_service_env_val() {
    awk -v key="$1" '
        BEGIN { in_service = 0 }
        /^\[/ { in_service = ($0 == "[Service]") ; next }
        in_service && index($0, "Environment=" key "=") == 1 {
            val = substr($0, length("Environment=" key "=") + 1)
            gsub(/[[:space:]]*$/, "", val)
            print val
            exit
        }
    ' "$2"
}

# README.md "Boundary enrollment" table: extract the VALUE cell for an egress
# key.  Table rows have the shape:
#   | `DS_MIRROR_EGRESS_X` | `value` | description… |
# The anchor "^\| `KEY` \|" matches exactly that table row (the leading cell),
# never the prose mentions of the same key elsewhere in the README, and the
# value is the content of the SECOND backtick pair.  Returns empty string if
# the row is absent.  Usage: _readme_egress_val KEY  (with $2 = README path)
_readme_egress_val() {
    _ree_key="$1"
    _ree_readme="$2"
    grep -E "^\| \`${_ree_key}\` \|" "$_ree_readme" \
        | sed 's/^| `[^`]*` | `\([^`]*\)`.*/\1/'
}

# ---------------------------------------------------------------------------
# Compare and report
# ---------------------------------------------------------------------------
FAIL=0

_check() {
    key="$1"
    expected="$2"
    actual="$3"
    if [ "$expected" != "$actual" ]; then
        printf 'lint-env-drift: MISMATCH %s: ds-mirror.env=%s  ds-mirror-serve.container=%s\n' \
            "$key" "$expected" "$actual" >&2
        FAIL=1
    fi
}

# _check_pair: compare a value from one named file against a value from another.
# Usage: _check_pair LABEL file_a label_a val_a file_b label_b val_b
_check_pair() {
    label="$1"
    file_a="$2" ; label_a="$3" ; val_a="$4"
    file_b="$5" ; label_b="$6" ; val_b="$7"
    if [ "$val_a" != "$val_b" ]; then
        printf 'lint-env-drift: MISMATCH %s: %s(%s)=%s  %s(%s)=%s\n' \
            "$label" "$file_a" "$label_a" "$val_a" "$file_b" "$label_b" "$val_b" >&2
        FAIL=1
    fi
}

# DS_MIRROR_IMAGE vs Image=
ENV_IMAGE="$(_env_val DS_MIRROR_IMAGE)"
CTR_IMAGE="$(_container_image)"
_check DS_MIRROR_IMAGE "$ENV_IMAGE" "$CTR_IMAGE"

# DS_MIRROR_ADDR vs PublishPort addr component
ENV_ADDR="$(_env_val DS_MIRROR_ADDR)"
CTR_ADDR="$(_container_publish_addr)"
_check DS_MIRROR_ADDR "$ENV_ADDR" "$CTR_ADDR"

# Standalone loopback assertion: the serve container's PublishPort MUST bind to
# a loopback address ({127.0.0.1, [::1]}) regardless of what DS_MIRROR_ADDR says.
# This guards against a configuration drift where both ds-mirror.env and the
# container file are changed to a non-loopback address (e.g. 0.0.0.0), which
# would satisfy the env-file match above but expose the serve face beyond
# host-loopback — violating the D83 boundary/egress posture (mirror is
# structurally pull-only on loopback; VMs reach it on their host-local gateway
# address only).
case "${CTR_ADDR:-}" in
    127.0.0.1|'[::1]') ;;
    *)
        printf 'lint-env-drift: MISMATCH PublishPort-loopback: ds-mirror-serve.container PublishPort= addr (%s) is not a loopback address ({127.0.0.1, [::1]}) — serve face must bind loopback only (D83)\n' \
            "${CTR_ADDR:-<absent>}" >&2
        FAIL=1
        ;;
esac

# DS_MIRROR_PORT vs PublishPort host port component
ENV_PORT="$(_env_val DS_MIRROR_PORT)"
CTR_HOST_PORT="$(_container_publish_host_port)"
_check DS_MIRROR_PORT "$ENV_PORT" "$CTR_HOST_PORT"

# DS_MIRROR_PORT vs PublishPort container port component
# (host port and container port must both match the canonical port)
CTR_CONTAINER_PORT="$(_container_publish_container_port)"
_check DS_MIRROR_PORT "$ENV_PORT" "$CTR_CONTAINER_PORT"

# DS_MIRROR_ROOT vs Volume= host path
ENV_ROOT="$(_env_val DS_MIRROR_ROOT)"
CTR_VOL_HOST="$(_container_volume_host_path)"
_check DS_MIRROR_ROOT "$ENV_ROOT" "$CTR_VOL_HOST"

# Volume= container-side path vs GIT_PROJECT_ROOT in git-http-backend.conf
# (these are hand-kept literals in two separate files; divergence silently breaks serving)
CTR_VOL_CONTAINER="$(_container_volume_container_path)"
CONF_PROJECT_ROOT="$(_conf_git_project_root)"
_check_pair "Volume-container-path/GIT_PROJECT_ROOT" \
    "ds-mirror-serve.container" "Volume container path" "$CTR_VOL_CONTAINER" \
    "git-http-backend.conf"     "GIT_PROJECT_ROOT"      "$CONF_PROJECT_ROOT"

# Volume= options field must have 'ro' as an EXACT comma-split token
# (belt-and-suspenders read-only mount on top of the push-disabled CGI;
# D83 boundary/egress posture).  Substring-only checks (e.g. 'rom','roo')
# are rejected.  Canonical: Volume=/var/lib/ds-mirror:/srv/git:ro,Z
CTR_VOL_OPTS="$(_container_volume_opts)"
_ro_found="$(printf '%s' "$CTR_VOL_OPTS" | awk '
    BEGIN { found = 0 }
    {
        n = split($0, tok, ",")
        for (i = 1; i <= n; i++) {
            if (tok[i] == "ro") { found = 1; break }
        }
    }
    END { print found }
')"
if [ "$_ro_found" != "1" ]; then
    printf 'lint-env-drift: MISMATCH Volume-ro: ds-mirror-serve.container Volume= options field (%s) does not have ro as an exact comma-split token (read-only mount required, D83)\n' \
        "$CTR_VOL_OPTS" >&2
    FAIL=1
fi

# GIT_HTTP_RECEIVE_PACK must be exactly 0 in git-http-backend.conf (not
# commented out, not absent, not 1).  Push verb is the primary pull-only
# enforcement; the :ro mount is belt-and-suspenders on top.
CONF_RECEIVE_PACK="$(_conf_git_receive_pack)"
if [ "$CONF_RECEIVE_PACK" != "0" ]; then
    printf 'lint-env-drift: MISMATCH GIT_HTTP_RECEIVE_PACK: git-http-backend.conf must set GIT_HTTP_RECEIVE_PACK=0 (got: %s) — push disabled at CGI layer required (D83)\n' \
        "${CONF_RECEIVE_PACK:-<absent>}" >&2
    FAIL=1
fi

# ---------------------------------------------------------------------------
# Seventh assertion (token guard) — egress-enrollment env literals.
#
# The DS_MIRROR_EGRESS_* Environment= literals in ds-mirror-refresh.service are
# the boundary egress-enrollment seam (D63 boundary path + D83 credential swap;
# doc 16 §5).  They are kept in lockstep with the "Boundary enrollment" table in
# README.md BY HAND — the same hand-kept-literal discipline the quadlet
# generator keys follow.  Until this guard, that lockstep was "by convention";
# this assertion makes it mechanical: for each egress key, the .service value
# must be present (fail-closed if the Environment= line is absent) AND must
# equal the value cell in the README table row.  A one-sided edit to either file
# fails the lint.
#
# This runs in clean mode (so `make check-image-drift` fires it), and the
# --self-test harness adds injection arms for each side (a mutated .service
# value, a removed .service key, and a mutated README value cell).
# ---------------------------------------------------------------------------
for _egress_key in \
    DS_MIRROR_EGRESS_GATEWAY \
    DS_MIRROR_EGRESS_SWAP \
    DS_MIRROR_EGRESS_CRED_REF \
    DS_MIRROR_EGRESS_UPSTREAMS
do
    _svc_val="$(_service_env_val "$_egress_key" "$SERVICE_FILE")"
    _rdm_val="$(_readme_egress_val "$_egress_key" "$README_FILE")"

    if [ -z "$_svc_val" ]; then
        printf 'lint-env-drift: MISMATCH %s: ds-mirror-refresh.service has no [Service] Environment=%s= line — the egress-enrollment seam must be present (D63/D83)\n' \
            "$_egress_key" "$_egress_key" >&2
        FAIL=1
        continue
    fi
    if [ -z "$_rdm_val" ]; then
        printf 'lint-env-drift: MISMATCH %s: README.md Boundary-enrollment table has no row for %s — the table must mirror the .service egress literals (D63/D83)\n' \
            "$_egress_key" "$_egress_key" >&2
        FAIL=1
        continue
    fi
    _check_pair "egress-enrollment/$_egress_key" \
        "ds-mirror-refresh.service" "Environment=$_egress_key" "$_svc_val" \
        "README.md"                 "Boundary-enrollment value" "$_rdm_val"
done

if [ "$FAIL" -ne 0 ]; then
    printf 'lint-env-drift: FAIL — generator-key literals in ds-mirror-serve.container diverged from ds-mirror.env\n' >&2
    exit 1
fi

printf 'lint-env-drift: OK — all generator-key literals match ds-mirror.env\n'
