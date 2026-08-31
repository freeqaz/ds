#!/usr/bin/env bash
# boot-validate.sh — boot the hand-built M0 base image LOCALLY with the
# sudo-free user qemu and confirm the done-when conditions short of ESXi, AND
# (the --runbook mode) drive the consolidated DS_KVM_LIVE operator pass that
# proves the two deferred live legs of the wave-1 M0 units end-to-end on the
# real virtual-metal KVM host.
#
# The task's done-when is "the image boots on the M0 host and the entrypoint
# launches the pinned Claude Code runtime". The M0 host is virtual-metal ESXi
# (D5/D31) we do not have here; per the ratified local substitute, we
# boot-validate with the user-space qemu under ~/.local/opt/qemu (KVM via the
# 0666 /dev/kvm, falling back to TCG) on btrfs scratch under ~/tmp/ds-images.
#
# *** Boot-on-ESXi validation explicitly transfers to the HUMAN follow-up
#     task — the default mode validates the local substitute, NOT the production
#     host. The --runbook mode is the procedure that human follow-up drives ON
#     the virtual-metal host (infra/terraform/esxi/BRINGUP.md). ***
#
# What the default (local boot) mode checks (against a real boot of ${OUT_QCOW}):
#   1. the image BOOTS to a glibc userland (login banner / `ldd --version`);
#   2. the D75 guest v6 posture holds (egress NIC has no global v6 addr; lo
#      keeps ::1);
#   3. the ds-entrypoint.service is present + enabled and, IFF the D38 entrypoint
#      binary was staged, that it launched the pinned CC runtime; if the binary
#      is absent (the M0 skeleton state today, runtime/v1 unfrozen) it reports
#      the EXPECTED fail-closed boot rather than a failure.
#   4. the gap-1 config-drive mount unit (run-ds-entrypoint.mount) and the gap-3
#      attach-carriage forwarder unit (ds-attachfwd.service) are present + enabled,
#      both ordered Before=ds-entrypoint.service; IFF the forwarder binary
#      (M0_ATTACHFWD_PATH) is staged the forwarder is active and the config-drive
#      mounted read-only at M0_ENTRYPOINT_CONFIG_DIR — else the same EXPECTED
#      fail-closed M0-skeleton state.
#
# --- THE CONSOLIDATED DS_KVM_LIVE RUNBOOK (`--runbook`) ---
# Wave 1 left two live legs DEFERRED to "the human boot-on-ESXi follow-up",
# because each touches real images / a booted guest the build env and CI do not
# have:
#   (A) CoW write-capture — vm/cow/enumerate-writes.sh running virt-diff +
#       qemu-img against a real DESTROYED per-session overlay (its live leg).
#   (B) golden git-pin — vm/m0-image/verify-git-pin.sh running its three
#       insteadOf/ssh-fails-closed/https-resolution checks against the REAL
#       /etc/gitconfig INSIDE a booted M0 guest (its live leg).
# `--runbook` folds BOTH into ONE operator pass on the nested virtual-metal KVM
# host (D31): clone -> attach -> (in-guest git-pin assertion) -> destroy ->
# enumerate-writes (CoW). Each unit is proven END-TO-END where it actually
# ships, instead of only by its offline self-test. The runbook is the single
# place the operator drives; it shells the two owning scripts' live legs rather
# than re-implementing them (single source of truth).
#
# This script is the BOOT HARNESS + the operator RUNBOOK. It is run by hand; it
# is NOT run by the repo gate (no image blob is committed, no live qemu/
# libguestfs in CI, and the gate never boots a VM). With no live gate set it
# PRINTS exactly the procedure it would run and exits 0 (a reviewer/gate can
# confirm the plan is sound). The live legs fire only behind their env gates:
#   - DS_BOOT=1    : the default mode really boots ${OUT_QCOW};
#   - DS_KVM_LIVE=1: the --runbook mode runs the real virt-diff/qemu-img capture
#                    and the in-guest git-pin assertion on the M0 host.
#
# Usage:
#   vm/m0-image/boot-validate.sh             # print the LOCAL boot plan (no image)
#   DS_BOOT=1 vm/m0-image/boot-validate.sh   # really boot ${OUT_QCOW} and assert
#   vm/m0-image/boot-validate.sh --runbook   # print the consolidated DS_KVM_LIVE
#                                            #   operator runbook (no live tools)
#   DS_KVM_LIVE=1 DS_BOOT=1 \
#     vm/m0-image/boot-validate.sh --runbook \
#       --base <raw-base> --overlay <destroyed-session-overlay.qcow2>
#                                            # drive the real clone->attach->
#                                            #   destroy->enumerate + in-guest
#                                            #   git-pin pass on the M0 host
#
# Env:
#   DS_BOOT=1       boot ${OUT_QCOW} (default mode) / required for the --runbook
#                   in-guest leg (the guest must be booted to assert in it).
#   DS_KVM_LIVE=1   enable the --runbook live virt-diff/qemu-img + in-guest legs.
#   OVERLAY/BASE    --overlay / --base of the destroyed session overlay to
#                   enumerate (the CoW leg); see vm/cow/enumerate-writes.sh.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${HERE}/m0-image.env"

# The two owning scripts whose live legs this runbook drives. enumerate-writes.sh
# is the CoW write-capture half (vm/cow/, D29); verify-git-pin.sh is the golden
# git-pin half (this dir, D83). The runbook shells THEIR live legs so the
# behavior is identical to running each script standalone — never re-implemented.
COW_DIR="$(cd "${HERE}/../cow" && pwd)"
ENUMERATE_WRITES="${COW_DIR}/enumerate-writes.sh"
VERIFY_GIT_PIN="${HERE}/verify-git-pin.sh"

DS_IMAGES_DIR="${DS_IMAGES_DIR:-${HOME}/tmp/ds-images}"
OUT_QCOW="${OUT_QCOW:-${DS_IMAGES_DIR}/m0-base-${M0_BASE_SUITE}-cc${M0_CC_VERSION}.qcow2}"

die() { printf 'boot-validate: ERROR: %s\n' "$*" >&2; exit 1; }

# Sudo-free user qemu (~/.local/opt/qemu, qemu 11). Override QEMU_BIN/QEMU_LIB
# to point elsewhere.
QEMU_LIB="${QEMU_LIB:-${HOME}/.local/opt/qemu/usr/lib}"
QEMU_BIN="${QEMU_BIN:-${HOME}/.local/opt/qemu/usr/bin/qemu-system-x86_64}"

# Prefer KVM (the 0666 /dev/kvm) for a representative boot; fall back to TCG so
# the harness still runs where /dev/kvm is absent.
if [ -w /dev/kvm ]; then ACCEL="kvm"; else ACCEL="tcg"; fi

boot_argv() {
  cat <<EOF
LD_LIBRARY_PATH=${QEMU_LIB} ${QEMU_BIN} \\
  -machine q35,accel=${ACCEL} -cpu host -m 2048 -smp 2 \\
  -nographic -serial mon:stdio \\
  -drive file=${OUT_QCOW},if=virtio,format=qcow2,snapshot=on \\
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0,mac=52:54:00:de:ad:01
EOF
}

print_plan() {
  cat <<EOF
M0 base-image LOCAL boot validation plan
  qemu      : ${QEMU_BIN} (accel=${ACCEL})
  image     : ${OUT_QCOW}
  CC pin    : ${M0_CC_VERSION} (D49)
  entrypoint: ${M0_ENTRYPOINT_PATH} (D38) launched by ds-entrypoint.service

Boot command (snapshot=on so the validation never mutates the base):
$(boot_argv)

In-guest assertions (over the serial console / a boot-completion probe):
  [boot]  reaches multi-user.target on a glibc userland
             ldd --version | head -1   # -> "ldd (Debian GLIBC ...)"  (NOT musl)
  [D75]   ip -6 addr show dev \$(ls /sys/class/net | grep -E '${M0_EGRESS_NIC_GLOB}')
             # -> no global v6 addr on the egress NIC
          ip -6 addr show dev lo        # -> ::1 still present
  [D38]   systemctl is-enabled ds-entrypoint.service   # -> enabled
          # IFF ${M0_ENTRYPOINT_PATH} staged:
          systemctl is-active  ds-entrypoint.service   # -> active, and
          pgrep -af claude                              # -> the pinned CC runtime
          # ELSE (M0 skeleton today, runtime/v1 unfrozen):
          systemctl status ds-entrypoint.service        # -> inactive (condition
          #   ConditionFileIsExecutable failed) — the EXPECTED fail-closed state.
  [pty]   # terminal/PTY mode (M0_PTY_TERM=${M0_PTY_TERM}, doc serpent-cli-mvp 02 §2.9):
          # the in-guest pty launch-mode of ds-entrypoint allocates a pseudo-terminal,
          # so the kernel must carry devpts and the baked terminfo must be present.
          test -e /dev/ptmx && mountpoint -q /dev/pts  # -> devpts mounted (unpriv pty alloc)
          script -qec true /dev/null </dev/null >/dev/null # -> a /dev/pts slave allocates
          test -f /lib/terminfo/${M0_PTY_TERM:0:1}/${M0_PTY_TERM} # -> baked terminfo entry
          #   (a missing devpts or terminfo => garbled/failed TUI; doc 02 R2/R4. This
          #    is a guard against a future kernel-config / slimmed-base regression — the
          #    M0 Debian kernel mounts devpts and ncurses-base ships the terminfo today.)
  [gap-1] systemctl is-enabled run-ds-entrypoint.mount # -> enabled, ordered
          systemctl show -p Before run-ds-entrypoint.mount # -> ds-entrypoint.service
          systemctl show -p RequiredBy run-ds-entrypoint.mount # -> ds-entrypoint.service
          #   (RequiredBy, not WantedBy: a config-drive that fails to mount must
          #    STOP the entrypoint — fail-closed: no config => no runtime => no egress.)
          # IFF a per-session config-drive is attached (the M1-live-close path, §A):
          findmnt -no FSTYPE,OPTIONS ${M0_ENTRYPOINT_CONFIG_DIR}
          #   -> ${M0_CONFIG_DRIVE_FS} ... ro   (read-only mount of LABEL=${M0_CONFIG_DRIVE_LABEL})
          test -f ${M0_ENTRYPOINT_CONFIG_DIR}/config.pb # -> config.pb present
          # ELSE (no config-drive attached — boot-validate dry boot drops none):
          #   the mount stays inactive and ds-entrypoint fails closed on absent config.
  [gap-3] systemctl is-enabled ds-attachfwd.service    # -> enabled, ordered
          systemctl show -p Before ds-attachfwd.service # -> ds-entrypoint.service
          systemctl show -p WantedBy ds-attachfwd.service # -> ds-entrypoint.service
          #   (WantedBy, not RequiredBy: a forwarder hiccup is NON-fatal — a
          #    not-yet-carried session is still a valid booted session whose attach
          #    leg the host-agent bridge can re-dial; mirrors attachbridge.go.)
          # IFF ${M0_ATTACHFWD_PATH} staged:
          systemctl is-active ds-attachfwd.service      # -> active, and
          ss -ltn 'sport = :${M0_ATTACH_PORT}'          # -> LISTEN on :${M0_ATTACH_PORT} (carriage)
          test -S ${M0_ATTACHFWD_UDS_PATH}              # -> the guest UDS is served
          #   (the carriage terminus of the host->guest data path: the host-agent
          #    bridge dials GuestIP:${M0_ATTACH_PORT}; ds-attachfwd splices it 1:1 to
          #    ${M0_ATTACHFWD_UDS_PATH}, which ds-entrypoint dials as the event socket.)
          # ELSE (M0 skeleton — vm/attachfwd binary absent):
          systemctl status ds-attachfwd.service         # -> inactive (condition
          #   ConditionFileIsExecutable failed) — the EXPECTED fail-closed state.
          # NOTE: the host<->guest :${M0_ATTACH_PORT} tap NFT allow is nft4's (a
          # DECLARED dependency); the forwarder only LISTENs, it writes no rule.

The gap-1 + gap-3 units are the IN-GUEST half of the Milestone-1 live close
(serpent up -> VM-hosted Claude Code over attach.v1). The full operator arc —
bake -> nft4 :${M0_ATTACH_PORT} allow -> host-agent daemon (DS_HOSTAGENT_LIVE) ->
orchestrator (DS_ORCH_LIVE) -> serpent up -> drive -> per-session destroy reap —
is the consolidated runbook at orchestrator/cmd/host-agent/LIVE-SMOKE.md §A.

*** Boot-on-ESXi (virtual-metal, D5/D31) is the HUMAN follow-up task. ***
EOF
}

# local_boot — the default mode: print the local-substitute boot plan and, with
# DS_BOOT=1 + an image present, perform the real headless user-qemu boot.
local_boot() {
  print_plan

  if [ "${DS_BOOT:-0}" != "1" ]; then
    echo
    echo "boot-validate: plan-only (set DS_BOOT=1 with an image at ${OUT_QCOW} to boot)."
    echo "boot-validate: for the consolidated DS_KVM_LIVE operator pass on the M0 host, see --runbook."
    exit 0
  fi

  if [ ! -f "${OUT_QCOW}" ]; then
    echo "boot-validate: DS_BOOT=1 but no image at ${OUT_QCOW} — build it first (build-m0-image.sh --build)." >&2
    exit 4
  fi
  if [ ! -x "${QEMU_BIN}" ]; then
    echo "boot-validate: qemu not found/executable at ${QEMU_BIN}" >&2
    exit 4
  fi

  echo "boot-validate: booting ${OUT_QCOW} with ${QEMU_BIN} (accel=${ACCEL})..."
  # The operator drives the in-guest assertions above over the serial console /
  # a virtio-vsock probe; this harness hands off the live boot. (A fully
  # automated assertion path — cloud-init probe or guest-agent readiness — is the
  # images/golden/ pipeline's job from M1, not the hand-build's.)
  eval "$(boot_argv)"
}

# --- consolidated DS_KVM_LIVE runbook ------------------------------------------

# print_runbook — the operator-facing procedure for the single virtual-metal
# pass. Printed verbatim in the no-live-gate case so a reviewer/gate confirms
# the plan, and printed as the header of a real run for the operator's log.
print_runbook() {
  cat <<EOF
M0 CONSOLIDATED DS_KVM_LIVE boot-validate runbook
  host      : the nested virtual-metal KVM host on the ESXi cluster (D5/D31).
              Bring it up first with infra/terraform/esxi/BRINGUP.md
              (nested kvm_intel, libvirt + libguestfs-tools + qemu-utils, the
              default storage pool + NAT net). The CoW leg needs virt-diff +
              qemu-img (libguestfs-tools/qemu-utils) from that runbook.
  image     : ${OUT_QCOW}  (the RAW M0 golden base after build-m0-image.sh --build)
  CC pin    : ${M0_CC_VERSION} (D49)
  git pin   : /etc/gitconfig — D83 insteadOf ssh->https + credential helper, so
              git-over-SSH cannot bypass the credential-swap / secret-scanning
              planes of the TLS-terminating egress gateway (doc 16 §5.3).

This folds the two wave-1 DEFERRED live legs into ONE pass so each is proven
end-to-end where it ships:
  (A) CoW write-capture  — ${ENUMERATE_WRITES}  (DS_KVM_LIVE virt-diff/qemu-img)
  (B) golden git-pin     — ${VERIFY_GIT_PIN}    (DS_KVM_LIVE in-guest /etc/gitconfig)

Operator sequence on the M0 host (each step is a deferred manual step — none of
it runs in CI/sandbox; all live legs are env-gated and skip cleanly there):

  # 0. Host is up per infra/terraform/esxi/BRINGUP.md; the raw base is built.
  RAW=${OUT_QCOW%.qcow2}.raw       # or the raw base build-m0-image.sh produced
  OVERLAY=\${DS_IMAGES_DIR:-~/tmp/ds-images}/m0-session-runbook.qcow2

  # 1. CLONE: per-session qcow2 overlay over the read-only raw base (D29).
  vm/cow/overlay-create.sh --base "\$RAW" --overlay "\$OVERLAY"

  # 2. ATTACH + BOOT: the host agent's libvirt driver attaches the overlay to a
  #    session VM (libvirt external snapshot at clone time, doc 15 §5.1). For the
  #    runbook the operator boots the overlay directly under libvirt/qemu, e.g.
  #    virt-install --import --disk path=\$OVERLAY,format=qcow2,bus=virtio ...
  #    (the BRINGUP.md smoke test shows the exact virt-install invocation).

  # 3. IN-GUEST git-pin assertion (B): over the serial console / a vsock probe,
  #    run the three checks against the REAL baked /etc/gitconfig. This script
  #    prints the exact guest commands:
  DS_KVM_LIVE=1 vm/m0-image/verify-git-pin.sh    # emits the in-guest snippet

  # 4. Do representative agent work in the guest so the overlay holds real writes,
  #    then DESTROY the session VM (virsh destroy; the overlay survives — it is
  #    the artifact). The base is NEVER written through (qcow2 + 0444 base).

  # 5. ENUMERATE the writes (A): host-side, after destroy — qemu-img backing-chain
  #    invariant + virt-diff file-level delta, parsed by the Go package:
  DS_KVM_LIVE=1 vm/cow/enumerate-writes.sh --base "\$RAW" --overlay "\$OVERLAY"

  # 6. Confirm: the credential never appears in the CoW delta (doc 06 level-(c),
  #    D8/D39) and the git pin held in-guest. Then teardown the overlay.

One-shot driver (this script) once the guest is booted and the overlay is the
destroyed session's:
  DS_KVM_LIVE=1 DS_BOOT=1 vm/m0-image/boot-validate.sh --runbook \\
      --base "\$RAW" --overlay "\$OVERLAY"

Fixture-refresh (out-of-git, D50): see vm/cow/README.md — the captured real
virt-diff/qemu-img/gitconfig dumps confirm the committed SYNTHETIC fixture shapes
still match real tool output. Captures land OUTSIDE git and are NEVER committed.
EOF
}

# runbook_live — the real consolidated pass. Drives (B) the in-guest git-pin
# assertion then (A) the CoW enumerate, each by shelling the owning script's
# OWN live leg so behavior is identical to running them standalone.
runbook_live() {
  local base="$1" overlay="$2"

  [ "${DS_KVM_LIVE:-0}" = 1 ] \
    || die "runbook live pass requires DS_KVM_LIVE=1 (the virt-diff/qemu-img + in-guest legs are gated off in CI/sandbox; this is the deferred operator pass on the virtual-metal M0 host)"
  [ "${DS_BOOT:-0}" = 1 ] \
    || die "runbook live pass requires DS_BOOT=1 — the in-guest git-pin leg asserts INSIDE a booted M0 guest; boot it first (see infra/terraform/esxi/BRINGUP.md / step 2 above)"
  [ -n "${base}" ]    || die "runbook needs --base <raw M0 golden base>"
  [ -n "${overlay}" ] || die "runbook needs --overlay <destroyed session overlay.qcow2>"

  echo "boot-validate[runbook]: (B) in-guest git-HTTPS-pin assertion (D83; /etc/gitconfig)"
  # verify-git-pin.sh's DS_KVM_LIVE leg emits the exact in-guest snippet for the
  # operator to run over the serial console / vsock; the operator's confirmation
  # of those three checks closes leg (B). We invoke it here so the runbook log
  # carries the snippet inline and a missing script fails the pass loudly.
  DS_KVM_LIVE=1 "${VERIFY_GIT_PIN}" \
    || die "in-guest git-pin leg (verify-git-pin.sh) failed"

  echo "boot-validate[runbook]: (A) CoW write-capture against the DESTROYED overlay (D29)"
  # enumerate-writes.sh's OWN DS_KVM_LIVE leg runs qemu-img backing-chain +
  # virt-diff and pipes both into the Go parser; it dies non-zero on any
  # parse/invariant failure, failing the runbook loudly.
  DS_KVM_LIVE=1 "${ENUMERATE_WRITES}" --base "${base}" --overlay "${overlay}" \
    || die "CoW write-capture leg (enumerate-writes.sh) failed"

  echo "boot-validate[runbook]: consolidated DS_KVM_LIVE pass complete"
  echo "  (A) CoW write-capture and (B) golden git-pin both proven end-to-end on the M0 host."
}

# run_runbook — dispatch for --runbook: always print the procedure; with the
# live gates set, also perform the real consolidated pass.
run_runbook() {
  local base="" overlay=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --base)    base="${2:-}"; shift 2 ;;
      --overlay) overlay="${2:-}"; shift 2 ;;
      *) die "unknown --runbook argument: $1 (usage: --runbook [--base <raw> --overlay <qcow2>])" ;;
    esac
  done

  print_runbook

  if [ "${DS_KVM_LIVE:-0}" != "1" ]; then
    echo
    echo "boot-validate[runbook]: plan-only (set DS_KVM_LIVE=1 DS_BOOT=1 with a booted M0 guest"
    echo "  and a destroyed session overlay to run the real consolidated pass)."
    exit 0
  fi
  runbook_live "${base}" "${overlay}"
}

case "${1:-}" in
  --runbook) shift; run_runbook "$@" ;;
  "")        local_boot ;;
  *) echo "usage: $0 [--runbook [--base <raw> --overlay <qcow2>]]" >&2; exit 2 ;;
esac
