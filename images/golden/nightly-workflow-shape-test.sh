#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# nightly-workflow-shape-test.sh — OFFLINE shape test for the nightly
# golden-image rotation lane .github/workflows/golden-image-nightly.yml
# (doc 03 §6, the wave-3 nightly rebuild + rotation policy).
#
# WHAT THIS PROVES (and why it is shape-only)
# -------------------------------------------
# The nightly workflow encodes three security/operational invariants in its YAML
# *shape*. A silent edit could regress any of them while every other lane stays
# green, so this test parses the workflow AS DATA (grep/awk over the committed
# YAML — NO live GitHub, NO `act`, NO network, NO secrets) and FAILS CLOSED if a
# shape invariant is broken. It is the structural counterpart to the behavioural
# `nightly-rebuild.sh --self-test`: that proves the rotation *logic*; this proves
# the *workflow wiring* around it cannot silently escalate or stop gating.
#
# THE THREE INVARIANTS (each one a non-zero exit on violation)
# ------------------------------------------------------------
#   (1) goldens_dir FALLBACK. The workflow_dispatch input `goldens_dir` exists
#       with an EMPTY default, and the plan job maps it to DS_GOLDEN_OUTPUT_DIR
#       through a `goldens_dir || ''` fallback — so an empty/absent override (the
#       cron-schedule case, always) yields an empty dir and nightly-rebuild.sh
#       falls back to the config's defaults.output_dir / its built-in default.
#       A regression that drops the input, gives it a non-empty default, or
#       hardcodes a dir would silently point the rotation stat at the wrong tree.
#
#   (2) exit==3 NOTIFY GATE. The notify-rotation-breach job is GATED on the
#       captured --check-rotation exit code (`rotation_exit == '3'`), NOT
#       always-run. A breach (>=1 stale/missing golden) returns exit 3; the plan
#       job records it as a step output; the notify job's `if:` references that
#       recorded exit. A regression to a bare `if: always()` (or dropping the
#       gate) would annotate/notify on EVERY run, destroying the signal.
#
#   (3) JOB-SCOPED issues:write. The top-level/default workflow permission stays
#       `contents: read` and never carries `issues: write`; `issues: write` is
#       granted ONLY inside the notify-rotation-breach job's own permissions
#       block. A regression that hoists `issues: write` to the top level would let
#       a breach annotation escalate write authority across the WHOLE workflow.
#
# OFFLINE / NO LIVE TOOLING: this script reads one committed file and runs only
# grep/awk/sed over it. It never invokes gh/act/curl/qemu/podman/claude, never
# touches the network, and asserts no secrets. Exit 0 iff all three invariants
# hold; non-zero (with a diagnostic) on the first violation found.
#
# Usage:
#   images/golden/nightly-workflow-shape-test.sh            # run the shape test
#   images/golden/nightly-workflow-shape-test.sh --help     # this usage

set -euo pipefail

# ---------------------------------------------------------------------------
# Single-sourced literals. Every assertion references one of these constants;
# the workflow file and the job names are never re-typed inside a check, so a
# rename is changed in exactly one place.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKFLOW="${REPO_ROOT}/.github/workflows/golden-image-nightly.yml"

# The jobs and the wiring tokens the invariants pin (single-source).
NOTIFY_JOB="notify-rotation-breach"          # the breach-notify job (inv 2 & 3)
PLAN_JOB="nightly-rebuild-plan"              # captures the rotation exit (inv 2)
DISPATCH_INPUT="goldens_dir"                 # the override input (inv 1)
OUTPUT_DIR_ENV="DS_GOLDEN_OUTPUT_DIR"        # the env the input maps to (inv 1)
ROTATION_OUTPUT="rotation_exit"              # the captured exit output (inv 2)
BREACH_CODE="3"                              # --check-rotation breach exit (inv 2)
TOPLEVEL_PERM="contents: read"               # the default workflow permission (inv 3)
WRITE_PERM="issues: write"                   # the job-scoped write grant (inv 3)

usage() {
  sed -n '4,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") : ;;
  *) echo "nightly-workflow-shape-test: unknown argument: $1" >&2; usage >&2; exit 2 ;;
esac

fail() {
  echo "nightly-workflow-shape-test: FAIL — $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# YAML-as-data helpers (no yq/python dependency — pure grep/awk over the text).
# ---------------------------------------------------------------------------

# Emit the indented body of a top-level YAML block ("$1:" at column 0) up to the
# next column-0 key. Used to scope assertions to e.g. `permissions:` or `jobs:`.
toplevel_block() {
  local key="$1"
  awk -v k="${key}:" '
    $0 ~ "^"k"([[:space:]]|$)" { inblk=1; next }
    inblk && /^[^[:space:]#]/ { inblk=0 }
    inblk { print }
  ' "${WORKFLOW}"
}

# Emit the body of a single job block: from `  <job>:` (2-space indent under
# jobs:) up to the next 2-space-indented job key. Job keys live at 2 spaces.
job_block() {
  local job="$1"
  awk -v j="  ${job}:" '
    $0 ~ "^"j"([[:space:]]|$)" { inblk=1; next }
    inblk && /^  [^[:space:]#]/ { inblk=0 }
    inblk { print }
  ' "${WORKFLOW}"
}

# Emit the body of the workflow_dispatch input block for a named input:
# from `      <name>:` (6-space indent under inputs:) to the next 6-space key.
dispatch_input_block() {
  local name="$1"
  awk -v n="      ${name}:" '
    $0 ~ "^"n"([[:space:]]|$)" { inblk=1; next }
    inblk && /^      [^[:space:]#]/ { inblk=0 }
    inblk { print }
  ' "${WORKFLOW}"
}

# ---------------------------------------------------------------------------
# Preconditions.
# ---------------------------------------------------------------------------
[ -f "${WORKFLOW}" ] || fail "workflow not found: ${WORKFLOW}"

echo "nightly-workflow-shape-test: parsing ${WORKFLOW#"${REPO_ROOT}/"} as data (offline)"

# ===========================================================================
# INVARIANT 1 — goldens_dir input exists, EMPTY default, mapped via `|| ''`.
# ===========================================================================
inv1_input="$(dispatch_input_block "${DISPATCH_INPUT}")"
[ -n "${inv1_input}" ] || \
  fail "(inv1) workflow_dispatch input '${DISPATCH_INPUT}' is missing — the rotation-dir override input must exist"

# Default must be EMPTY: `default: ""` (the cron-schedule + unset-override case).
# Accept either double- or single-quoted empty string; reject any non-empty
# default (which would stop the fallback to the config/built-in default dir).
if ! printf '%s\n' "${inv1_input}" | grep -Eq '^[[:space:]]*default:[[:space:]]*(""|'\'''\'')[[:space:]]*$'; then
  default_line="$(printf '%s\n' "${inv1_input}" | grep -E '^[[:space:]]*default:' || echo '<none>')"
  fail "(inv1) input '${DISPATCH_INPUT}' must have an EMPTY default (default: \"\") so an unset override falls back to the config/built-in dir; found: ${default_line}"
fi

# The plan job must map the input to ${OUTPUT_DIR_ENV} through a `|| ''` fallback
# (empty input => empty env => script's own default-dir fallback). We assert the
# env line carries both the input name and the empty-string fallback operator.
inv1_plan="$(job_block "${PLAN_JOB}")"
[ -n "${inv1_plan}" ] || fail "(inv1) plan job '${PLAN_JOB}' not found"
if ! printf '%s\n' "${inv1_plan}" \
     | grep -E "^[[:space:]]*${OUTPUT_DIR_ENV}:" \
     | grep -Fq "github.event.inputs.${DISPATCH_INPUT}"; then
  fail "(inv1) job '${PLAN_JOB}' must map ${OUTPUT_DIR_ENV} from github.event.inputs.${DISPATCH_INPUT}"
fi
if ! printf '%s\n' "${inv1_plan}" \
     | grep -E "^[[:space:]]*${OUTPUT_DIR_ENV}:" \
     | grep -Eq "${DISPATCH_INPUT}[[:space:]]*\|\|[[:space:]]*(''|\"\")"; then
  fail "(inv1) ${OUTPUT_DIR_ENV} must use a 'goldens_dir || \"\"' fallback so an empty override yields an empty dir (script falls back to config/built-in default)"
fi
echo "  [ok] inv1: '${DISPATCH_INPUT}' input present, empty default, mapped to ${OUTPUT_DIR_ENV} via empty-string fallback"

# ===========================================================================
# INVARIANT 2 — notify job GATED on the captured rotation exit == 3.
# ===========================================================================
inv2_plan="$(job_block "${PLAN_JOB}")"
# The plan job must EXPORT the captured exit as a job output the notify job reads.
if ! printf '%s\n' "${inv2_plan}" \
     | grep -Eq "^[[:space:]]*${ROTATION_OUTPUT}:[[:space:]]*\\\$\{\{.*outputs\.exit_code"; then
  fail "(inv2) plan job '${PLAN_JOB}' must expose the captured rotation exit as the '${ROTATION_OUTPUT}' job output (from the rotation step's exit_code)"
fi

inv2_notify="$(job_block "${NOTIFY_JOB}")"
[ -n "${inv2_notify}" ] || fail "(inv2) notify job '${NOTIFY_JOB}' not found"

# The notify job's `if:` must reference the recorded rotation exit == '3'.
inv2_if="$(printf '%s\n' "${inv2_notify}" | grep -E '^[[:space:]]*if:' || true)"
[ -n "${inv2_if}" ] || fail "(inv2) notify job '${NOTIFY_JOB}' has no 'if:' gate — a breach notify must be conditional, never always-run"
if ! printf '%s\n' "${inv2_if}" | grep -Fq "needs.${PLAN_JOB}.outputs.${ROTATION_OUTPUT}"; then
  fail "(inv2) notify job '${NOTIFY_JOB}' if: must reference needs.${PLAN_JOB}.outputs.${ROTATION_OUTPUT} (gate on the recorded rotation exit, not an unconditional run)"
fi
# It must compare that recorded exit against the breach code 3 (quoted, GHA
# string-compares job outputs). This is the load-bearing gate.
if ! printf '%s\n' "${inv2_if}" | grep -Eq "${ROTATION_OUTPUT}[[:space:]]*==[[:space:]]*'${BREACH_CODE}'"; then
  fail "(inv2) notify job '${NOTIFY_JOB}' if: must gate on ${ROTATION_OUTPUT} == '${BREACH_CODE}' (the --check-rotation breach exit); an always-run or unguarded notify destroys the breach signal"
fi
echo "  [ok] inv2: '${NOTIFY_JOB}' gated on needs.${PLAN_JOB}.outputs.${ROTATION_OUTPUT} == '${BREACH_CODE}'"

# ===========================================================================
# INVARIANT 3 — issues:write is JOB-SCOPED; top-level stays contents:read.
# ===========================================================================
# Top-level permissions block must be contents:read and must NOT grant write.
inv3_top="$(toplevel_block "permissions")"
[ -n "${inv3_top}" ] || fail "(inv3) no top-level 'permissions:' block — the default workflow permission must be pinned to '${TOPLEVEL_PERM}'"
if ! printf '%s\n' "${inv3_top}" | grep -Eq "^[[:space:]]*${TOPLEVEL_PERM}[[:space:]]*$"; then
  fail "(inv3) top-level permissions must pin '${TOPLEVEL_PERM}'"
fi
if printf '%s\n' "${inv3_top}" | grep -Eq "^[[:space:]]*${WRITE_PERM}[[:space:]]*$"; then
  fail "(inv3) top-level permissions must NOT grant '${WRITE_PERM}' — a breach annotation must not escalate write authority across the whole workflow; scope it to '${NOTIFY_JOB}' only"
fi

# The notify job's OWN permissions block must grant issues:write (job-scoped).
inv3_notify="$(job_block "${NOTIFY_JOB}")"
if ! printf '%s\n' "${inv3_notify}" | grep -Eq "^[[:space:]]*${WRITE_PERM}[[:space:]]*$"; then
  fail "(inv3) notify job '${NOTIFY_JOB}' must carry its own '${WRITE_PERM}' (job-scoped write for the optional tracking issue)"
fi

# No OTHER job may carry issues:write — the only write grant in the file lives in
# the notify job. Count file-wide write grants and the notify-job write grants;
# they must be equal (every write line is inside the notify job).
total_write="$(grep -Ec "^[[:space:]]*${WRITE_PERM}[[:space:]]*$" "${WORKFLOW}" || true)"
notify_write="$(printf '%s\n' "${inv3_notify}" | grep -Ec "^[[:space:]]*${WRITE_PERM}[[:space:]]*$" || true)"
if [ "${total_write}" != "${notify_write}" ]; then
  fail "(inv3) '${WRITE_PERM}' appears ${total_write}x in the workflow but only ${notify_write}x inside '${NOTIFY_JOB}' — write must be granted ONLY in the notify job"
fi
echo "  [ok] inv3: top-level stays '${TOPLEVEL_PERM}'; '${WRITE_PERM}' is scoped to '${NOTIFY_JOB}' only"

echo "nightly-workflow-shape-test: PASS — all 3 shape invariants hold (offline)"
exit 0
