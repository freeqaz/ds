#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-drain-workflow-shape.sh — OFFLINE shape test for the grant-service
# SIGTERM graceful-drain lane .github/workflows/grant-sigterm-drain.yml.
#
# WHAT THIS PROVES (and why it is shape-only)
# -------------------------------------------
# The drain lane encodes ONE fail-closed ordering invariant in its YAML *shape*.
# A silent reorder would regress it while every other lane stays green, so this
# test parses the workflow AS DATA (grep/awk over the committed YAML — NO live
# GitHub, NO `act`, NO network, NO secrets) and FAILS CLOSED if the shape is
# broken. It is the sibling of images/golden/nightly-workflow-shape-test.sh,
# which pins the nightly golden-image rotation lane; that script is charter-
# pinned to golden-image-nightly.yml and is NOT extended here.
#
# THE INVARIANT (why the ordering is load-bearing)
# ------------------------------------------------
#   The toolchain-coupling guard step
#
#       - name: grant-service go-line consistency (toolchain coupling guard)
#         run: ... sh scripts/check-go-line.sh identity/grant-service/go.mod
#
#   MUST appear BEFORE the `actions/setup-go@v5` step that carries
#   `go-version-file: identity/grant-service/go.mod`.
#
#   scripts/check-go-line.sh treats a MISSING go.mod as a per-arg SKIP (rc 0) —
#   it mirrors go.yml's `[ -f "$mod/go.mod" ] || continue`, because identity/mint
#   is documented as legitimately go.mod-less. So a DELETED
#   identity/grant-service/go.mod would PASS the guard. What keeps the lane
#   fail-closed is the very next step: setup-go hard-fails when the file named by
#   `go-version-file:` is absent. Hoist setup-go above the guard (or change its
#   go-version-file) and the missing-go.mod case becomes a REAL fail-open — the
#   lane would provision an unpinned toolchain and keep going.
#
#   .github/workflows/grant-sigterm-drain.yml already states this in prose
#   ("Preserve that ordering: do NOT move setup-go above this guard ... or this
#   becomes a real fail-open"). This script converts that comment into an
#   enforced gate: a comment cannot fail a build, this can.
#
#   Three assertions, each a non-zero exit on violation:
#     (1) the go-line guard step EXISTS, and its `run:` body invokes
#         scripts/check-go-line.sh against the pinned module go.mod;
#     (2) a setup-go step EXISTS carrying `go-version-file:` for the SAME module
#         go.mod (so the two steps are actually coupled, not merely co-resident);
#     (3) the guard's line number is STRICTLY LESS than that setup-go step's.
#
# OFFLINE / NO LIVE TOOLING: reads one committed file and runs only grep/awk/sed
# over it. Never invokes gh/act/curl/qemu/podman/claude, never touches the
# network, asserts no secrets. Exit 0 iff the invariant holds.
#
# DRAIN_WORKFLOW: override the workflow path (used by --self-test to point at
# synthetic fixtures; never overridden on the production path).
#
# Usage:
#   sh scripts/check-drain-workflow-shape.sh              # run the shape test
#   sh scripts/check-drain-workflow-shape.sh --self-test  # hermetic regression harness
#   sh scripts/check-drain-workflow-shape.sh --help       # this usage
#
# Exit codes: 0 = the ordering invariant holds (or --self-test passed)
#             1 = the invariant is broken (or --self-test failed)
#             2 = bad usage

set -euo pipefail

# ---------------------------------------------------------------------------
# Single-sourced literals. Every assertion references one of these constants;
# the workflow file, the step names, and the module path are never re-typed
# inside a check, so a rename is changed in exactly one place.
# (Structure and comment style modelled on the sibling
# images/golden/nightly-workflow-shape-test.sh.)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKFLOW="${DRAIN_WORKFLOW:-${REPO_ROOT}/.github/workflows/grant-sigterm-drain.yml}"

GUARD_SCRIPT="scripts/check-go-line.sh"                 # the single-sourced guard
PINNED_GOMOD="identity/grant-service/go.mod"            # the module both steps pin
SETUP_GO_USES="actions/setup-go@"                       # the toolchain provisioner
GO_VERSION_FILE_KEY="go-version-file"                   # setup-go's pinning input

usage() {
  sed -n '4,58p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

SELF_TEST=0
case "${1:-}" in
  -h|--help)   usage; exit 0 ;;
  --self-test) SELF_TEST=1 ;;
  "") : ;;
  *) echo "check-drain-workflow-shape: unknown argument: $1" >&2; usage >&2; exit 2 ;;
esac

fail() {
  echo "check-drain-workflow-shape: FAIL — $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# YAML-as-data helpers (no yq/python dependency — pure grep/awk over the text).
# ---------------------------------------------------------------------------

# guard_step_line — 1-indexed line number of the `- name: ...` step whose body
# invokes GUARD_SCRIPT against PINNED_GOMOD. Emits nothing when absent.
#
# Walks the file tracking the most recent `- name:` step header; when a
# `sh scripts/check-go-line.sh <module go.mod>` invocation is seen, the header's
# line number is the step's position. Keying on the INVOCATION (not on the step's
# prose name) means renaming the step does not defeat the gate.
guard_step_line() {
  awk -v guard="${GUARD_SCRIPT}" -v mod="${PINNED_GOMOD}" '
    /^[[:space:]]*-[[:space:]]+name:/ { hdr = NR }
    index($0, guard) && index($0, mod) && $0 !~ /^[[:space:]]*#/ {
      if (hdr) { print hdr; exit }
    }
  ' "${WORKFLOW}"
}

# setup_go_step_line — 1-indexed line number of the `- uses: actions/setup-go@*`
# step whose `with:` block pins `go-version-file: <PINNED_GOMOD>`. Emits nothing
# when absent.
#
# The `with:` key is matched only while inside that step: a step boundary is any
# `- uses:`/`- name:` list item at the same or shallower indent, which resets the
# tracked header. That keeps a setup-go elsewhere in the file from being paired
# with an unrelated go-version-file line.
setup_go_step_line() {
  awk -v uses="${SETUP_GO_USES}" -v key="${GO_VERSION_FILE_KEY}" -v mod="${PINNED_GOMOD}" '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*-[[:space:]]+(uses|name):/ {
      hdr = (index($0, uses) > 0) ? NR : 0
      next
    }
    hdr && index($0, key ":") && index($0, mod) { print hdr; exit }
  ' "${WORKFLOW}"
}

# ---------------------------------------------------------------------------
# The shape check itself, factored so --self-test can drive it over fixtures via
# a recursive invocation with DRAIN_WORKFLOW retargeted.
# ---------------------------------------------------------------------------
run_shape_check() {
  [ -f "${WORKFLOW}" ] || fail "workflow not found: ${WORKFLOW}"

  echo "check-drain-workflow-shape: parsing ${WORKFLOW#"${REPO_ROOT}/"} as data (offline)"

  # --- INVARIANT (1): the go-line guard step exists and pins the module ------
  guard_line="$(guard_step_line)"
  [ -n "${guard_line}" ] || \
    fail "(inv1) no step invoking '${GUARD_SCRIPT} ${PINNED_GOMOD}' — the toolchain coupling guard must exist in this lane; without it a stale \`go\` line builds on the wrong toolchain"

  # --- INVARIANT (2): a setup-go step pins the SAME module go.mod ------------
  setup_line="$(setup_go_step_line)"
  [ -n "${setup_line}" ] || \
    fail "(inv2) no '${SETUP_GO_USES}*' step carrying '${GO_VERSION_FILE_KEY}: ${PINNED_GOMOD}' — the guard and the toolchain pin must reference the SAME module go.mod, or the guard checks a file the lane never uses"

  # --- INVARIANT (3): guard PRECEDES setup-go (the fail-closed ordering) -----
  if [ "${guard_line}" -ge "${setup_line}" ]; then
    fail "(inv3) '${GUARD_SCRIPT}' guard is at line ${guard_line} but ${SETUP_GO_USES}(${GO_VERSION_FILE_KEY}: ${PINNED_GOMOD}) is at line ${setup_line} — the guard MUST come FIRST. ${GUARD_SCRIPT} treats a MISSING go.mod as a per-arg SKIP (rc 0), so a deleted ${PINNED_GOMOD} passes the guard; only setup-go hard-failing on the absent ${GO_VERSION_FILE_KEY} keeps this lane fail-closed. Hoisting setup-go above the guard turns that into a real fail-open"
  fi

  echo "  [ok] inv1: '${GUARD_SCRIPT} ${PINNED_GOMOD}' guard step present (line ${guard_line})"
  echo "  [ok] inv2: ${SETUP_GO_USES}* pins ${GO_VERSION_FILE_KEY}: ${PINNED_GOMOD} (line ${setup_line})"
  echo "  [ok] inv3: guard (line ${guard_line}) PRECEDES setup-go (line ${setup_line}) — missing-go.mod stays fail-closed"
  echo "check-drain-workflow-shape: PASS — the drain lane's ordering invariant holds (offline)"
}

# ---------------------------------------------------------------------------
# --self-test: hermetic regression harness. Builds synthetic workflow fixtures
# in a mktemp sandbox and re-invokes THIS script with DRAIN_WORKFLOW pointed at
# each, asserting BOTH directions:
#   (A) correct order (guard, then setup-go)   -> rc 0
#   (B) setup-go HOISTED above the guard       -> rc 1   <- the planted drift
#   (C) guard step deleted entirely            -> rc 1
#   (D) setup-go pinned from a DIFFERENT go.mod-> rc 1
#   (E) workflow file absent                   -> rc 1
# Plus the real tree, which must pass. Offline; mutates only the sandbox.
# ---------------------------------------------------------------------------
self_test() {
  local TMP
  TMP="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand TMP now: it must survive into the trap
  trap "rm -rf \"$TMP\"" EXIT

  # Fixture A — the shape the real lane has: guard FIRST, then setup-go.
  cat > "${TMP}/ok.yml" <<OKYML
name: drain-ok
on: push
jobs:
  grant-process-smoke:
    runs-on: [self-hosted, debian]
    steps:
      - uses: actions/checkout@v4
      - name: grant-service go-line consistency (toolchain coupling guard)
        run: |
          set -euo pipefail
          sh ${GUARD_SCRIPT} ${PINNED_GOMOD}
      - uses: actions/setup-go@v5
        with:
          ${GO_VERSION_FILE_KEY}: ${PINNED_GOMOD}
          cache: false
OKYML

  # Fixture B — the PLANTED DRIFT: setup-go hoisted ABOVE the guard.
  cat > "${TMP}/hoisted.yml" <<HOISTYML
name: drain-hoisted
on: push
jobs:
  grant-process-smoke:
    runs-on: [self-hosted, debian]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          ${GO_VERSION_FILE_KEY}: ${PINNED_GOMOD}
          cache: false
      - name: grant-service go-line consistency (toolchain coupling guard)
        run: |
          set -euo pipefail
          sh ${GUARD_SCRIPT} ${PINNED_GOMOD}
HOISTYML

  # Fixture C — the guard step deleted outright.
  cat > "${TMP}/noguard.yml" <<NOGUARDYML
name: drain-noguard
on: push
jobs:
  grant-process-smoke:
    runs-on: [self-hosted, debian]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          ${GO_VERSION_FILE_KEY}: ${PINNED_GOMOD}
          cache: false
NOGUARDYML

  # Fixture D — guard and setup-go pinned from DIFFERENT modules (decoupled).
  cat > "${TMP}/decoupled.yml" <<DECOUPYML
name: drain-decoupled
on: push
jobs:
  grant-process-smoke:
    runs-on: [self-hosted, debian]
    steps:
      - name: grant-service go-line consistency (toolchain coupling guard)
        run: |
          sh ${GUARD_SCRIPT} ${PINNED_GOMOD}
      - uses: actions/setup-go@v5
        with:
          ${GO_VERSION_FILE_KEY}: identity/fakes/digest-publisher/go.mod
DECOUPYML

  local self rc
  self="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"

  # Run the PLANTED-DRIFT arm FIRST: it proves the DRAIN_WORKFLOW plumbing and
  # the ordering comparison are live, so a dead check cannot let the clean arm
  # pass falsely.
  rc=0; DRAIN_WORKFLOW="${TMP}/hoisted.yml" bash "${self}" >/dev/null 2>&1 || rc=$?
  [ "${rc}" -eq 1 ] || { echo "check-drain-workflow-shape: self-test FAIL: hoisted setup-go expected rc=1, got rc=${rc}" >&2; exit 1; }
  echo "check-drain-workflow-shape: self-test — hoisted setup-go caught (rc=1)"

  rc=0; DRAIN_WORKFLOW="${TMP}/noguard.yml" bash "${self}" >/dev/null 2>&1 || rc=$?
  [ "${rc}" -eq 1 ] || { echo "check-drain-workflow-shape: self-test FAIL: missing guard step expected rc=1, got rc=${rc}" >&2; exit 1; }
  echo "check-drain-workflow-shape: self-test — deleted guard step caught (rc=1)"

  rc=0; DRAIN_WORKFLOW="${TMP}/decoupled.yml" bash "${self}" >/dev/null 2>&1 || rc=$?
  [ "${rc}" -eq 1 ] || { echo "check-drain-workflow-shape: self-test FAIL: decoupled go-version-file expected rc=1, got rc=${rc}" >&2; exit 1; }
  echo "check-drain-workflow-shape: self-test — decoupled go-version-file caught (rc=1)"

  rc=0; DRAIN_WORKFLOW="${TMP}/absent.yml" bash "${self}" >/dev/null 2>&1 || rc=$?
  [ "${rc}" -eq 1 ] || { echo "check-drain-workflow-shape: self-test FAIL: absent workflow expected rc=1, got rc=${rc}" >&2; exit 1; }
  echo "check-drain-workflow-shape: self-test — absent workflow caught (rc=1)"

  rc=0; DRAIN_WORKFLOW="${TMP}/ok.yml" bash "${self}" >/dev/null 2>&1 || rc=$?
  [ "${rc}" -eq 0 ] || { echo "check-drain-workflow-shape: self-test FAIL: correctly-ordered fixture expected rc=0, got rc=${rc}" >&2; exit 1; }
  echo "check-drain-workflow-shape: self-test — correctly-ordered fixture passed (rc=0)"

  echo "check-drain-workflow-shape: self-test OK"
}

if [ "${SELF_TEST}" -eq 1 ]; then
  self_test
  exit 0
fi

run_shape_check
exit 0
