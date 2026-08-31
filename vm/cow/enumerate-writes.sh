#!/usr/bin/env bash
# enumerate-writes.sh — after a session VM is DESTROYED, enumerate the writes
# isolated in its per-session qcow2 overlay.
#
# This is the capture half of the D29 disk stack. The overlay produced by
# overlay-create.sh is, after destroy, the single artifact holding "everything
# the agent wrote" (doc 02 §5). Two host-side answers, both from the doc 01
# sessions/01 spike, both DRIVEN here and PARSED by the Go package in this dir
# (vm/cow/enumerate.go — the testable introspection logic):
#
#   - virt-diff (libguestfs): file-level delta of base-vs-overlay, host-side,
#     no in-guest agent (controls-outside-the-boundary, doc 04 §5).
#   - qemu-img info --backing-chain: block-level confirmation of the D29
#     backing-file invariant (overlay -> raw base).
#
# SCOPE / D29: the block-inspection MECHANISM is out of scope — we shell out to
# virt-diff / qemu-img and parse their TEXT. v0 introspection may be crude
# (doc 05 §8): the file list + per-kind counts are the deliverable, not a rich
# UX (that matures at M1-M2).
#
# DS_KVM_LIVE GATE: the virt-diff/qemu-img legs touch real on-disk images and
# (for virt-diff) spin a libguestfs appliance. They run ONLY when DS_KVM_LIVE=1.
# Without it (CI, the sandbox) the script does NOT invoke those tools; it instead
# exercises the PARSER against the committed synthetic fixtures via --self-test,
# and the live path is a documented deferred manual step. There is NO live
# claude/qemu/podman run anywhere in this script.
#
# CONSOLIDATED RUNBOOK: this live leg is step (A) — CoW write-capture — of the
# single DS_KVM_LIVE operator pass driven by vm/m0-image/boot-validate.sh
# --runbook (clone -> attach -> destroy -> ENUMERATE here + the in-guest git-pin
# assertion, one virtual-metal-host pass; D31, infra/terraform/esxi/BRINGUP.md).
# That runbook shells THIS script's --base/--overlay live leg unchanged, so the
# enumerate behavior is identical whether run standalone or from the runbook.
# Standalone usage below stays the canonical entry; see vm/cow/README.md for the
# consolidated-runbook entry and the (out-of-git, D50) fixture-refresh procedure.
#
# Usage:
#   # Live (operator host, after destroy):
#   DS_KVM_LIVE=1 vm/cow/enumerate-writes.sh \
#       --base <raw-base> --overlay <session-overlay.qcow2>
#   # Parse a captured tool dump (no live tools needed):
#   vm/cow/enumerate-writes.sh --from-virtdiff <file>
#   vm/cow/enumerate-writes.sh --from-qemuimg  <file>
#   # Force the virt-diff shape rather than auto-detect (operator override of a
#   # mixed-shape / header-only mis-detect); applies to the virt-diff leg only:
#   vm/cow/enumerate-writes.sh --mode-csv   --from-virtdiff <file>
#   vm/cow/enumerate-writes.sh --mode-plain --base <raw> --overlay <qcow2>
#   # CI/sandbox regression of the parser against committed fixtures:
#   vm/cow/enumerate-writes.sh --self-test
#
# Env:
#   DS_KVM_LIVE=1  enable the live virt-diff/qemu-img legs (default: gated off).
#   QEMU_IMG       override qemu-img (default: $(command -v qemu-img)).
#   VIRT_DIFF      override virt-diff (default: $(command -v virt-diff)).
#   GO            override the go binary used to drive the parser (default: go).
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU_IMG="${QEMU_IMG:-$(command -v qemu-img || true)}"
VIRT_DIFF="${VIRT_DIFF:-$(command -v virt-diff || true)}"
GO="${GO:-go}"
# VIRTDIFF_MODE carries the operator's --mode-csv | --mode-plain shape override
# (empty = auto-detect). It is forwarded to cmd/parse so a mixed-shape /
# header-only capture the heuristic mis-detects can be parsed in the FORCED
# shape rather than guessed. It applies to the virt-diff leg only.
VIRTDIFF_MODE=""

log() { printf 'enumerate-writes: %s\n' "$*"; }
die() { printf 'enumerate-writes: ERROR: %s\n' "$*" >&2; exit 1; }

# parse_virtdiff <file> — feed captured virt-diff text to the Go parser, which
# classifies + sorts + tallies. We run the parser through a tiny `go run` shim
# generated on the fly so the shell never re-implements the parsing the Go
# package owns (single source of truth, D29: parse, never hand-roll).
parse_virtdiff() {
  local f="$1"
  [ -f "$f" ] || die "virt-diff capture not found: $f"
  run_parser virtdiff "$f"
}

parse_qemuimg() {
  local f="$1"
  [ -f "$f" ] || die "qemu-img capture not found: $f"
  run_parser qemuimg "$f"
}

# parse_virtdiff_forced <csv|plain> <file> — feed a captured virt-diff text to
# the Go parser with the shape FORCED (the operator --mode-* override), without
# disturbing the caller's VIRTDIFF_MODE. Used by --self-test to exercise the
# degrade-then-override flow: a forced single shape on a genuinely interleaved
# (mixed-shape) capture degrades (errors or under-reports), while auto-detect
# RECOVERS it via the per-row classifier.
parse_virtdiff_forced() {
  local forced="$1" f="$2"
  [ -f "$f" ] || die "virt-diff capture not found: $f"
  local saved="${VIRTDIFF_MODE}"
  VIRTDIFF_MODE="${forced}"
  # Run the parser; restore VIRTDIFF_MODE whether it succeeds or fails so a
  # forced-mode assertion never leaks the override into the next leg.
  local rc=0
  run_parser virtdiff "$f" || rc=$?
  VIRTDIFF_MODE="${saved}"
  return "${rc}"
}

# run_parser <mode> <file> — invoke the in-package Go driver (cmd/parse) on the
# captured text. The driver prints the crude v0 summary (counts + paths, or the
# backing-chain invariant result) and exits non-zero on a parse/invariant
# failure, so a malformed capture fails the enumerate loudly.
run_parser() {
  local mode="$1" file="$2"
  command -v "${GO%% *}" >/dev/null 2>&1 \
    || die "go toolchain not found (set GO); the parser is the Go package in this dir"
  # Absolutize the input path: run_parser cds into the package dir to `go run`
  # the driver, so a relative --in (e.g. a captured dump passed on the CLI) must
  # be resolved against the ORIGINAL cwd first.
  local abs; abs="$(readlink -f -- "${file}" 2>/dev/null || printf '%s' "${file}")"
  # Forward the operator's virt-diff shape override (if any) to cmd/parse. The
  # override is meaningful only for the virtdiff leg; qemu-img info has no shape.
  local mode_flag=()
  if [ "${mode}" = virtdiff ] && [ -n "${VIRTDIFF_MODE}" ]; then
    mode_flag=("--mode-${VIRTDIFF_MODE}")
  fi
  ( cd "${HERE}" && ${GO} run ./cmd/parse --mode "${mode}" "${mode_flag[@]}" --in "${abs}" )
}

live_enumerate() {
  local base="$1" overlay="$2"
  [ "${DS_KVM_LIVE:-0}" = 1 ] \
    || die "live enumerate requires DS_KVM_LIVE=1 (the virt-diff/qemu-img legs are gated off in CI/sandbox; this is a deferred manual step on the operator host)"
  [ -f "${base}" ]    || die "base image not found: ${base}"
  [ -f "${overlay}" ] || die "overlay image not found: ${overlay}"
  [ -n "${QEMU_IMG}" ]  || die "qemu-img not found (set QEMU_IMG)"
  [ -n "${VIRT_DIFF}" ] || die "virt-diff not found (set VIRT_DIFF; it ships with libguestfs-tools)"

  local td; td="$(mktemp -d "${TMPDIR:-/tmp}/ds-cow-enum.XXXXXX")"
  trap 'rm -rf "${td}"' RETURN

  log "[live] qemu-img info --backing-chain (D29 backing-file invariant)"
  "${QEMU_IMG}" info --backing-chain "${overlay}" > "${td}/qemuimg.txt"
  parse_qemuimg "${td}/qemuimg.txt"

  # virt-diff compares the read-only base (A) against the overlay (B); -A/-a
  # take the disk images directly. The base is opened read-only by libguestfs.
  # --csv emits the RFC-4180 machine-readable shape (status field, then a
  # QUOTED path field), which bounds the path UNAMBIGUOUSLY so a path with an
  # embedded space is never truncated; --extra-stats adds the stat columns the
  # parser folds into Detail. The Go parser auto-detects this shape vs plain.
  log "[live] virt-diff base-vs-overlay (file-level delta; libguestfs, host-side; --csv machine-readable)"
  "${VIRT_DIFF}" --csv --extra-stats -a "${base}" -A "${overlay}" > "${td}/virtdiff.txt"
  parse_virtdiff "${td}/virtdiff.txt"

  log "[live] enumerate complete for overlay ${overlay}"
}

self_test() {
  # Drive the Go parser against the committed synthetic fixtures: the positive
  # fixtures parse clean, the negative fixtures fail. This is the CI/sandbox
  # regression that keeps the enumerate path honest with NO live tools.
  command -v "${GO%% *}" >/dev/null 2>&1 \
    || { log "SKIP --self-test: go toolchain not found"; return 0; }

  log "self-test: conforming virt-diff fixture must PARSE"
  parse_virtdiff "${HERE}/fixtures/virtdiff-conforming.txt" >/dev/null \
    || die "self-test FAIL: conforming virt-diff fixture did not parse"

  log "self-test: malformed virt-diff fixture must FAIL"
  if parse_virtdiff "${HERE}/fixtures/virtdiff-malformed.txt" >/dev/null 2>&1; then
    die "self-test FAIL: malformed virt-diff fixture was NOT rejected"
  fi
  log "self-test: malformed virt-diff rejected (good)"

  log "self-test: CSV space/quote-path virt-diff fixture must PARSE (no path truncation)"
  parse_virtdiff "${HERE}/fixtures/virtdiff-csv-spacepaths.txt" >/dev/null \
    || die "self-test FAIL: CSV space-paths virt-diff fixture did not parse"

  log "self-test: malformed CSV virt-diff fixture must FAIL"
  if parse_virtdiff "${HERE}/fixtures/virtdiff-csv-malformed.txt" >/dev/null 2>&1; then
    die "self-test FAIL: malformed CSV virt-diff fixture was NOT rejected"
  fi
  log "self-test: malformed CSV virt-diff rejected (good)"

  # Degrade-then-override: the mixed-shape fixture is a GENUINELY INTERLEAVED
  # capture (plain rows AND CSV rows in one dump). The whole-capture auto-detect
  # commits to ONE shape from the first (plain) data row, so FORCING the wrong
  # single shape degrades — but ModeAuto RECOVERS it via the per-row classifier.
  local mixed="${HERE}/fixtures/virtdiff-mixed-shape.txt"
  log "self-test: mixed-shape fixture — forced --mode-plain must DEGRADE (errors on the CSV rows)"
  if parse_virtdiff_forced plain "${mixed}" >/dev/null 2>&1; then
    die "self-test FAIL: forced --mode-plain on the mixed-shape capture was NOT rejected (it must error on the CSV-shaped rows)"
  fi
  log "self-test: forced --mode-plain rejected the mixed-shape capture (good — single-shape degrade)"

  log "self-test: mixed-shape fixture — auto-detect (per-row classifier) must RECOVER it"
  if ! parse_virtdiff "${mixed}" >/dev/null; then
    die "self-test FAIL: auto-detect did NOT recover the mixed-shape capture (the per-row classifier should parse it as DetectedMode=mixed)"
  fi
  # Belt-and-suspenders: the recovered summary must report the per-row classifier
  # ran (mode 'mixed'), proving recovery was honest, not a silent single-shape
  # mis-parse. (The Go test asserts the full typed delta + per-kind counts.)
  if ! parse_virtdiff "${mixed}" 2>/dev/null | grep -q 'virt-diff parse mode: mixed'; then
    die "self-test FAIL: recovered mixed-shape summary did not report the per-row classifier (mode 'mixed')"
  fi
  log "self-test: auto-detect recovered the mixed-shape capture via the per-row classifier (good)"

  # The forced-CSV override also parses (the operator escape hatch is exact), but
  # on THIS interleaved capture it under-reports by silently dropping the plain
  # rows — so we only assert it does not crash; the per-row recovery above is the
  # honest path. (The Go test pins the exact under-report so this stays meaningful.)
  log "self-test: mixed-shape fixture — forced --mode-csv override is accepted (escape hatch parses; per-row recovery is the honest path)"
  if ! parse_virtdiff_forced csv "${mixed}" >/dev/null 2>&1; then
    die "self-test FAIL: forced --mode-csv override did not parse the mixed-shape capture at all"
  fi
  log "self-test: forced --mode-csv override accepted (good)"

  log "self-test: conforming qemu-img fixture must PARSE (backing invariant holds)"
  parse_qemuimg "${HERE}/fixtures/qemuimg-conforming.txt" >/dev/null \
    || die "self-test FAIL: conforming qemu-img fixture did not parse"

  log "self-test: backing-less qemu-img fixture must FAIL (D29)"
  if parse_qemuimg "${HERE}/fixtures/qemuimg-nobacking.txt" >/dev/null 2>&1; then
    die "self-test FAIL: backing-less qemu-img fixture was NOT rejected"
  fi
  log "self-test: backing-less qemu-img rejected (good)"

  echo "enumerate-writes: --self-test OK"
}

# set_virtdiff_mode <csv|plain> — record the operator's shape override, rejecting
# a second, conflicting --mode-* flag (the override is single-valued).
set_virtdiff_mode() {
  local want="$1"
  if [ -n "${VIRTDIFF_MODE}" ] && [ "${VIRTDIFF_MODE}" != "${want}" ]; then
    die "--mode-csv and --mode-plain are mutually exclusive"
  fi
  VIRTDIFF_MODE="${want}"
}

main() {
  # Pre-scan for the virt-diff shape override (--mode-csv | --mode-plain), which
  # may appear in ANY position; strip them out so the remaining args dispatch as
  # before. The override is forwarded to cmd/parse by run_parser.
  local args=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --mode-csv)   set_virtdiff_mode csv;   shift ;;
      --mode-plain) set_virtdiff_mode plain; shift ;;
      *) args+=("$1"); shift ;;
    esac
  done
  set -- "${args[@]+"${args[@]}"}"

  case "${1:-}" in
    --self-test) self_test; return ;;
    --from-virtdiff) [ -n "${2:-}" ] || die "--from-virtdiff needs a file"; parse_virtdiff "$2"; return ;;
    --from-qemuimg)  [ -n "${2:-}" ] || die "--from-qemuimg needs a file"; parse_qemuimg "$2"; return ;;
  esac
  local base="" overlay=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --base) base="$2"; shift 2 ;;
      --overlay) overlay="$2"; shift 2 ;;
      *) die "unknown argument: $1 (usage: $0 [--mode-csv|--mode-plain] --base <raw> --overlay <qcow2> | --from-virtdiff <f> | --from-qemuimg <f> | --self-test)" ;;
    esac
  done
  [ -n "${base}" ]    || die "missing --base (the raw M0 golden image)"
  [ -n "${overlay}" ] || die "missing --overlay (the destroyed session's overlay)"
  live_enumerate "${base}" "${overlay}"
}

main "$@"
