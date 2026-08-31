#!/usr/bin/env bash
# overlay-create.sh — clone a per-session qcow2 copy-on-write overlay over the
# RAW M0 base image, with the base wired in as a READ-ONLY backing file.
#
# This is the create half of the D29 disk stack (raw golden image + per-session
# qcow2 overlay; D5/D31 place it on the nested virtual-metal KVM host). The
# overlay is the session's READ/WRITE delta and the single inspectable artifact
# behind the doc 02 §5 "show the user everything the agent wrote" promise; the
# raw base is NEVER written through the overlay — that is the invariant this
# script establishes and asserts.
#
# SCOPE / D29: the block-inspection MECHANISM is out of scope — we drive
# `qemu-img` only (create + info), never hand-rolled qcow2 surgery. The
# hypervisor calls that ATTACH this overlay to a running VM (libvirt external
# snapshots at clone time) belong to the host agent's libvirt driver
# (orchestrator/internal/hypervisor/libvirt, doc 15 §5.1), NOT here; this script
# produces the artifact those calls consume.
#
# IDEMPOTENT: re-running with the same --overlay path is a no-op IFF the overlay
# already exists AND already backs onto the requested base (the create path is
# replay-safe under the level-triggered reconciler, doc 15). A pre-existing
# overlay that backs onto a DIFFERENT base is an error (never silently
# re-pointed). Pass --force to recreate.
#
# READ-ONLY BACKING: qcow2's contract is that an overlay never writes through to
# its backing file (writes are redirected into the overlay's own clusters); the
# host agent additionally opens the base read-only at attach. This script
# asserts the static half of that invariant: the base file is present and the
# overlay's recorded `backing file` resolves to it. It also chmods the base to
# 0444 (read-only on the host filesystem) so an accidental host-side write is
# refused — belt-and-suspenders over the qcow2 contract.
#
# Usage:
#   vm/cow/overlay-create.sh --base <raw-base> --overlay <session-overlay.qcow2>
#   vm/cow/overlay-create.sh --base ... --overlay ... --force
#   vm/cow/overlay-create.sh --self-test     # synthetic base+overlay, no KVM
#
# Env:
#   QEMU_IMG   override the qemu-img binary (default: $(command -v qemu-img)).
#
# This script touches NO running VM and needs NO KVM/root: `qemu-img create -b`
# and `qemu-img info` are pure file operations. The live ATTACH leg is the host
# agent's; see enumerate-writes.sh for the DS_KVM_LIVE-gated inspection leg.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

QEMU_IMG="${QEMU_IMG:-$(command -v qemu-img || true)}"
ST_TMP=""  # self-test temp dir; referenced by the EXIT trap (script-scoped so
           # `set -u` does not unbind it when the trap fires after return).

log() { printf 'overlay-create: %s\n' "$*"; }
die() { printf 'overlay-create: ERROR: %s\n' "$*" >&2; exit 1; }

require_qemu_img() {
  [ -n "${QEMU_IMG}" ] && [ -x "${QEMU_IMG}" ] \
    || die "qemu-img not found (set QEMU_IMG); the D29 overlay create path needs it"
}

# resolve_backing <overlay> -> prints the overlay's recorded backing-file path.
# Parses `qemu-img info` (the same text vm/cow/enumerate.go ParseQemuImgInfo
# parses); empty output means no backing file recorded.
resolve_backing() {
  local overlay="$1"
  "${QEMU_IMG}" info "${overlay}" 2>/dev/null \
    | sed -n 's/^backing file: //p' \
    | sed 's/ (actual path:.*$//' \
    | head -n1
}

# same_file <a> <b> -> 0 iff both paths resolve to the same canonical file.
same_file() {
  local a b
  a="$(readlink -f -- "$1" 2>/dev/null || printf '%s' "$1")"
  b="$(readlink -f -- "$2" 2>/dev/null || printf '%s' "$2")"
  [ "$a" = "$b" ]
}

create_overlay() {
  local base="$1" overlay="$2" force="$3"
  require_qemu_img
  [ -f "${base}" ] || die "base image not found: ${base} (D29: the raw golden image must exist before a session overlay clones onto it)"

  # Enforce the host-side read-only posture on the base BEFORE creating the
  # overlay: the base is shared by every concurrent session and must never be
  # mutated. 0444 is advisory over the qcow2 contract; the host agent opens it
  # read-only at attach (doc 15 §5.1).
  chmod 0444 "${base}" 2>/dev/null || log "WARN: could not chmod base 0444 (continuing; qcow2 still never writes through)"

  if [ -f "${overlay}" ]; then
    local existing; existing="$(resolve_backing "${overlay}")"
    if [ -z "${existing}" ]; then
      [ "${force}" = 1 ] || die "overlay ${overlay} exists with NO backing file (D29 violation) — refuse to reuse; pass --force to recreate"
    elif same_file "${existing}" "${base}"; then
      log "overlay ${overlay} already backs onto ${base} — idempotent no-op"
      assert_readonly_backing "${overlay}" "${base}"
      return 0
    elif [ "${force}" != 1 ]; then
      die "overlay ${overlay} already backs onto a DIFFERENT base (${existing}); refuse to silently re-point — pass --force to recreate"
    fi
    log "recreating overlay ${overlay} (--force)"
    rm -f -- "${overlay}"
  fi

  mkdir -p "$(dirname -- "${overlay}")"
  # -F raw: the base is the RAW golden image (D29: raw base under qcow2 overlay).
  # qemu-img >= 5 requires the explicit backing format.
  "${QEMU_IMG}" create -f qcow2 -F raw -b "${base}" "${overlay}" >/dev/null
  log "created per-session overlay ${overlay} backing onto ${base} (raw, read-only)"
  assert_readonly_backing "${overlay}" "${base}"
}

# assert_readonly_backing — the load-bearing acceptance check: the overlay's
# recorded backing file resolves to the base, AND the base is read-only on the
# host filesystem. Fails closed if either does not hold.
assert_readonly_backing() {
  local overlay="$1" base="$2"
  local recorded; recorded="$(resolve_backing "${overlay}")"
  [ -n "${recorded}" ] || die "overlay ${overlay} has NO backing file after create (D29 invariant broken)"
  same_file "${recorded}" "${base}" \
    || die "overlay backing file ${recorded} != requested base ${base}"
  if [ -w "${base}" ]; then
    # Writable base is a posture defect, not a qcow2-correctness defect (qcow2
    # still never writes through); surface it loudly but do not fail in
    # environments where chmod was refused (e.g. read-only-fs CI mounts).
    log "WARN: base ${base} is still host-writable — the host agent MUST open it read-only at attach (doc 15 §5.1)"
  else
    log "OK: base ${base} is read-only on the host (0444) and is the overlay's backing file"
  fi
  log "OK: overlay ${overlay} -> backing ${recorded} (D29 raw-base + per-session-qcow2 invariant holds)"
}

self_test() {
  # Prove the create path end-to-end against a SYNTHETIC base — no KVM, no root,
  # no VM boot: qemu-img create/info are pure file operations. Skips cleanly
  # (exit 0) where qemu-img is unavailable (some CI images), so this can run in
  # the repo-lints/test lane honestly.
  if [ -z "${QEMU_IMG}" ] || [ ! -x "${QEMU_IMG}" ]; then
    log "SKIP --self-test: qemu-img not available in this environment"
    return 0
  fi
  ST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/ds-cow-create.XXXXXX")"
  trap 'rm -rf "${ST_TMP:-}"' EXIT
  local td="${ST_TMP}"
  local base="${td}/base.raw" overlay="${td}/sess/overlay.qcow2"

  log "self-test: create a 16M synthetic raw base"
  "${QEMU_IMG}" create -f raw "${base}" 16M >/dev/null

  log "self-test: first create must establish a read-only-backed overlay"
  create_overlay "${base}" "${overlay}" 0

  log "self-test: second create with the SAME base must be an idempotent no-op"
  create_overlay "${base}" "${overlay}" 0

  log "self-test: a create against a DIFFERENT base (no --force) must FAIL"
  local base2="${td}/base2.raw"
  "${QEMU_IMG}" create -f raw "${base2}" 16M >/dev/null
  # Subshell: create_overlay's die() calls exit; isolate it so the refusal does
  # not terminate the self-test (set -e would otherwise propagate the exit).
  if ( create_overlay "${base2}" "${overlay}" 0 ) >/dev/null 2>&1; then
    die "self-test FAIL: re-pointing the overlay to a different base was NOT refused"
  fi
  log "self-test: re-point refusal caught (good)"

  log "self-test: --force must allow recreate onto the new base"
  create_overlay "${base2}" "${overlay}" 1

  # Positive read-only assertion: the base must have been chmod'd 0444.
  if [ -w "${base2}" ]; then
    die "self-test FAIL: base ${base2} should be read-only (0444) after create"
  fi
  log "self-test: base is read-only (0444) as asserted"

  echo "overlay-create: --self-test OK"
}

main() {
  local base="" overlay="" force=0
  if [ "${1:-}" = "--self-test" ]; then self_test; return; fi
  while [ $# -gt 0 ]; do
    case "$1" in
      --base) base="$2"; shift 2 ;;
      --overlay) overlay="$2"; shift 2 ;;
      --force) force=1; shift ;;
      *) die "unknown argument: $1 (usage: $0 --base <raw> --overlay <qcow2> [--force] | --self-test)" ;;
    esac
  done
  [ -n "${base}" ] || die "missing --base (the raw M0 golden image)"
  [ -n "${overlay}" ] || die "missing --overlay (the per-session qcow2 path)"
  create_overlay "${base}" "${overlay}" "${force}"
}

main "$@"
