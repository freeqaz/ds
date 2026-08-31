#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check.sh — validate the shape of subscriptions.yaml and the advisory seed specs.
#
# Stdlib-only (POSIX shell + grep), env-independent: runs offline, needs no DS_* gating,
# no network, no YAML library. It is a STRUCTURAL lint — it asserts the four subscriptions
# are present, that the doc 14 §9 verbatim watch points are carried, and that both RUSTSEC
# seeds exist with a suite destination. It does NOT validate against a live advisory feed
# (that is the named owner's running process, not a hermetic check).
#
# Usage:
#   ./check.sh            # validate, print PASS/FAIL per assertion
#
# Exit codes: 0 = all assertions hold, 1 = one or more failed.

set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
SUBS="$DIR/subscriptions.yaml"
ADV="$DIR/advisories"

fail=0
pass() { printf 'PASS  %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; fail=1; }

# require <label> <file> <fixed-string> — assert the file contains the literal string.
require() {
  if grep -qF -- "$3" "$2" 2>/dev/null; then
    pass "$1"
  else
    bad "$1 (missing: $3)"
  fi
}

# --- subscriptions.yaml exists -------------------------------------------------
if [ ! -f "$SUBS" ]; then
  bad "subscriptions.yaml present"
  exit 1
fi
pass "subscriptions.yaml present"

# --- the four subscription ids -------------------------------------------------
for id in pingora hickory-dns gitleaks-compatible-ruleset-format yjs-ecosystem; do
  require "subscription present: $id" "$SUBS" "id: $id"
done

# --- exactly four subscription entries ----------------------------------------
n="$(grep -cE '^[[:space:]]*-[[:space:]]+id:' "$SUBS" 2>/dev/null || true)"
if [ "$n" = "4" ]; then
  pass "exactly four subscriptions (found $n)"
else
  bad "exactly four subscriptions (found $n)"
fi

# --- Pingora verbatim API watch points (doc 14 §9) ----------------------------
require "pingora watch: get_original_dest"                  "$SUBS" "get_original_dest"
require "pingora watch: tweak_new_upstream_tcp_connection"  "$SUBS" "tweak_new_upstream_tcp_connection"
require "pingora watch: SO_MARK insertion point"            "$SUBS" "SO_MARK"
require "pingora watch: CONNECT-method server option"       "$SUBS" "CONNECT-method server option"
require "pingora watch: HTTP/3 PRs #514/#524"               "$SUBS" "#514/#524"
require "pingora watch: HTTP/3 issue #95"                   "$SUBS" "#95"
require "pingora watch: D70 trigger recheck"                "$SUBS" "D70"

# --- hickory verbatim watch + mandatory mirroring -----------------------------
require "hickory pin 0.26.x"                                "$SUBS" "0.26.x"
require "hickory churn: Authority->ZoneHandler"             "$SUBS" "Authority->ZoneHandler"
require "hickory RUSTSEC mirroring mandatory"               "$SUBS" "mandatory: true"
require "hickory seed: RUSTSEC-2026-0118"                   "$SUBS" "RUSTSEC-2026-0118"
require "hickory seed: RUSTSEC-2026-0119"                   "$SUBS" "RUSTSEC-2026-0119"

# --- gitleaks-compatible ruleset format fields (doc 14 §9) --------------------
require "gitleaks field: secretGroup"                       "$SUBS" "secretGroup"
require "gitleaks field: [[rules.required]]"                "$SUBS" "[[rules.required]]"
require "gitleaks field: [extend]"                          "$SUBS" "[extend]"
require "gitleaks remediation via POL-4"                    "$SUBS" "POL-4"

# --- Yjs verbatim watch points (doc 14 §9) ------------------------------------
require "yjs watch: update-encoding changes"                "$SUBS" "update-encoding changes"
require "yjs watch: provider-package maintenance"           "$SUBS" "provider-package maintenance"
require "yjs executed by Canvas"                            "$SUBS" "Canvas"

# --- owner is proposed/unassigned (pending ratification) ----------------------
require "owner status proposed"                             "$SUBS" "status: proposed"
require "named individual unassigned (null)"               "$SUBS" "named_individual: null"

# --- advisory seed specs: both RUSTSEC seeds, with a suite destination --------
for adv in RUSTSEC-2026-0118 RUSTSEC-2026-0119; do
  spec="$ADV/$adv.yaml"
  if [ -f "$spec" ]; then
    pass "advisory spec present: $adv"
    require "  $adv has advisory id"        "$spec" "advisory: $adv"
    require "  $adv has suite_destination"  "$spec" "suite_destination:"
    require "  $adv has expected_verdict"   "$spec" "expected_verdict:"
    require "  $adv has citation"           "$spec" "citation:"
  else
    bad "advisory spec present: $adv"
  fi
done

# --- summary -------------------------------------------------------------------
if [ "$fail" -eq 0 ]; then
  printf '\nOK — all advisory-mirror shape assertions hold.\n'
  exit 0
fi
printf '\nFAILED — one or more advisory-mirror shape assertions did not hold.\n'
exit 1
