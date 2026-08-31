#!/usr/bin/env bash
# check-readme-rawname.sh — anti-drift guard for the vm/cow/README RAW example.
#
# The README walkthrough of the consolidated DS_KVM_LIVE boot-validate runbook
# hand-types a raw-base filename:
#
#     RAW=~/tmp/ds-images/m0-base-bookworm-cc2.1.173.raw
#
# That stem — m0-base-<suite>-cc<ver> — is the SAME stem boot-validate.sh derives
# from vm/m0-image/m0-image.env (M0_BASE_SUITE + M0_CC_VERSION):
#
#     OUT_QCOW=...${M0_BASE_SUITE}-cc${M0_CC_VERSION}.qcow2   # the .raw twin of this
#
# A CC-pin or suite bump in m0-image.env therefore silently drifts the README
# example out from under boot-validate.sh. This guard recomputes the expected
# raw name FROM the env and asserts the README example matches it token-for-token,
# failing loudly on drift. It is the vm/cow twin of vm/m0-image/verify-image-pins.sh
# (same README<->env token-agreement posture), scoped to the one RAW example line.
#
# Usage:
#   vm/cow/check-readme-rawname.sh             # run the check
#   vm/cow/check-readme-rawname.sh --self-test # regression harness (inject drift)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE_DEFAULT="$(cd "$HERE/../m0-image" && pwd)/m0-image.env"
ST_TMP=""  # self-test temp dir; referenced by the EXIT trap (see self_test)

# run_checks [readme] [env]
# Recompute the expected raw name from the env and assert the README's RAW=
# example line carries exactly that filename (token-for-token).
run_checks() {
  local readme="${1:-$HERE/README.md}"
  local env="${2:-$ENV_FILE_DEFAULT}"
  local fail=0
  err() { printf 'check-readme-rawname: FAIL: %s\n' "$*" >&2; fail=1; }

  for f in "$readme" "$env"; do
    [ -f "$f" ] || err "missing $f"
  done
  [ "$fail" = 0 ] || return 1

  # --- recompute the expected raw name from the env (the boot-validate stem) ---
  local suite ver
  suite="$(grep -E '^M0_BASE_SUITE=' "$env" | cut -d= -f2-)"
  ver="$(grep -E '^M0_CC_VERSION=' "$env" | cut -d= -f2-)"
  [ -n "$suite" ] || err "M0_BASE_SUITE absent from $env"
  [ -n "$ver" ]   || err "M0_CC_VERSION absent from $env"
  [ "$fail" = 0 ] || return 1

  # The stem boot-validate.sh derives is m0-base-<suite>-cc<ver>; the raw base is
  # that stem with the .raw extension (the qcow2 hand-build's at-rest twin, D29).
  local expected="m0-base-${suite}-cc${ver}.raw"

  # --- extract the RAW= example basename(s) from the README ---
  # Match the documented example line shape: RAW=<path>/m0-base-...raw . We pull
  # the basename so the guard is anchored on the drift-prone token (the filename),
  # not the ~/tmp/ds-images/ prefix the operator may relocate.
  local raw_lines
  raw_lines="$(grep -nE '^RAW=.*/m0-base-[^/]*\.raw[[:space:]]*$' "$readme" || true)"
  if [ -z "$raw_lines" ]; then
    err "no 'RAW=.../m0-base-*.raw' example line found in $readme"
    return 1
  fi

  # Every such example line must carry the expected basename token-for-token.
  local line lineno path base
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    lineno="${line%%:*}"
    path="${line#*:RAW=}"
    path="${path%%[[:space:]]*}"   # strip any trailing whitespace
    base="${path##*/}"
    if [ "$base" != "$expected" ]; then
      err "README:$lineno RAW example basename '$base' != derived '$expected' (m0-image.env drift: suite=$suite ver=$ver)"
    fi
  done <<EOF
$raw_lines
EOF

  [ "$fail" = 0 ] || return 1
  echo "check-readme-rawname: OK (RAW example = $expected; matches m0-image.env suite=$suite ver=$ver)"
}

self_test() {
  # Copy the two inputs to a temp dir, confirm the clean copy passes, then inject
  # each recognised drift one at a time and confirm the check catches it.
  # ST_TMP is script-scoped (not `local`) so the EXIT trap can still see it after
  # this function returns (with set -u a stale local would be unbound at trap time).
  ST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/cowraw.XXXXXX")"
  trap 'rm -rf "${ST_TMP:-}"' EXIT

  # Stage a minimal fixture pair: the real README + the real env.
  local stage="$ST_TMP/clean"
  mkdir -p "$stage"
  cp "$HERE/README.md" "$stage/README.md"
  cp "$ENV_FILE_DEFAULT" "$stage/m0-image.env"

  echo "self-test: clean copy must PASS"
  run_checks "$stage/README.md" "$stage/m0-image.env" >/dev/null \
    || { echo "self-test FAIL: clean copy did not pass" >&2; exit 1; }

  inject_and_expect_fail() {
    local label="$1"; shift
    local work; work="$(mktemp -d "${TMPDIR:-/tmp}/cowraw.XXXXXX")"
    cp "$HERE/README.md" "$work/README.md"
    cp "$ENV_FILE_DEFAULT" "$work/m0-image.env"
    "$@" "$work"
    if run_checks "$work/README.md" "$work/m0-image.env" >/dev/null 2>&1; then
      echo "self-test FAIL: drift '$label' was NOT caught" >&2; rm -rf "$work"; exit 1
    fi
    echo "self-test: drift '$label' caught (good)"
    rm -rf "$work"
  }

  # Drift A: env CC pin bumped — README now quotes a stale CC version.
  inject_and_expect_fail "env CC pin bump (stale README)" bash -c '
    sed -i "s/^M0_CC_VERSION=.*/M0_CC_VERSION=9.9.999/" "$1/m0-image.env"' _
  # Drift B: env suite bumped — README now quotes a stale suite.
  inject_and_expect_fail "env suite bump (stale README)" bash -c '
    sed -i "s/^M0_BASE_SUITE=.*/M0_BASE_SUITE=trixie/" "$1/m0-image.env"' _
  # Drift C: README RAW example hand-edited to a stale filename.
  inject_and_expect_fail "README RAW basename drift" bash -c '
    sed -i "s#m0-base-[^/]*\.raw#m0-base-bookworm-cc0.0.0.raw#" "$1/README.md"' _

  echo "check-readme-rawname: --self-test OK"
}

case "${1:-}" in
  --self-test) self_test ;;
  "" ) run_checks ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
