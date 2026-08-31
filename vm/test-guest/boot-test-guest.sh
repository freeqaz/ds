#!/usr/bin/env bash
# boot-test-guest.sh — boot the local test-guest fixture under the SUDO-FREE qemu
# (~/.local/opt/qemu, qemu 11) in one of two network modes:
#
#   --smoke (default): qemu USER-mode networking (-netdev user / slirp). No sudo,
#                      no tap. The smoke seed (build-test-guest.sh --smoke) makes
#                      cloud-init DHCP on the NIC, ensure curl, run a self-
#                      asserting curl-out (sentinels to the serial console), then
#                      poweroff — so this harness verifies "reaches a shell, has
#                      curl, curls an upstream out" and EXITS on its own. This is
#                      the self-contained, no-sudo validation the unit owns.
#
#   --tap            : attach the host tap dstap-0 (-netdev tap,ifname=dstap-0,
#                      script=no,downscript=no) and apply the static
#                      10.77.0.2/24 gw/DNS 10.77.0.1 from the tap seed. Creating
#                      dstap-0 on the host is the SEPARATE §E2 task (it needs sudo
#                      / a pre-created tap); this wrapper only knows how to ATTACH
#                      to an already-present tap. It refuses if dstap-0 is absent.
#
# The wrapper exports LD_LIBRARY_PATH=$TG_QEMU_LIB and runs $TG_QEMU_BIN
# -enable-kvm (KVM via the 0666 /dev/kvm; TCG fallback where /dev/kvm is absent),
# with -L $TG_QEMU_SHARE so SeaBIOS/virtio firmware resolve from the same prefix.
#
# The qemu invocation is built as a BASH ARRAY (QEMU_ARGV) and exec'd as
# "${QEMU_ARGV[@]}" — there is NO eval and no string-splitting of the command,
# so a path with a space or a shell metacharacter can never be word-split or
# re-interpreted by the shell. The printed plan re-quotes the same array (via
# `printf %q`) for display only.
#
# It NEVER mutates the base image (snapshot=on). It prints the exact argv before
# booting; with DS_TG_BOOT unset it is PLAN-ONLY (prints the plan, exits 0) so a
# reviewer/gate can confirm the command without a live boot. DS_TG_BOOT=1 boots.
#
# Usage:
#   vm/test-guest/boot-test-guest.sh                 # == --smoke, plan-only
#   DS_TG_BOOT=1 vm/test-guest/boot-test-guest.sh --smoke   # really boot + assert
#   DS_TG_BOOT=1 vm/test-guest/boot-test-guest.sh --tap     # attach dstap-0 (§E2)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${HERE}/test-guest.env"

ARTIFACT_DIR="${TG_ARTIFACT_DIR}"
IMG_PATH="${ARTIFACT_DIR}/${TG_IMAGE_NAME}"
SEED_PATH="${ARTIFACT_DIR}/seed-test-guest.iso"

QEMU_LIB="${TG_QEMU_LIB}"
QEMU_BIN="${TG_QEMU_BIN}"
QEMU_SHARE="${TG_QEMU_SHARE}"

die() { printf 'boot-test-guest: ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf 'boot-test-guest: %s\n' "$*"; }

NETMODE="smoke"
case "${1:-}" in
  ""|--smoke) NETMODE="smoke" ;;
  --tap)      NETMODE="tap" ;;
  *) die "usage: $0 [--smoke|--tap]" ;;
esac

# Prefer KVM (the 0666 /dev/kvm) for a representative boot; fall back to TCG.
if [ -w /dev/kvm ]; then ACCEL="kvm"; KVM_FLAG="-enable-kvm"; else ACCEL="tcg"; KVM_FLAG=""; fi

# Build the qemu invocation as a BASH ARRAY (no eval, no word-splitting). Every
# element is a single argv token, so paths with spaces/metacharacters are safe.
# QEMU_BIN is exec'd directly with LD_LIBRARY_PATH set in the child env (via the
# `env` prefix array), so nothing is re-parsed by the shell.
build_qemu_argv() {
  QEMU_ARGV=( env "LD_LIBRARY_PATH=${QEMU_LIB}" "${QEMU_BIN}" )
  # -enable-kvm only when KVM is available; an empty KVM_FLAG must NOT become an
  # empty "" argv token (which qemu would reject), so append it conditionally.
  [ -n "${KVM_FLAG}" ] && QEMU_ARGV+=( "${KVM_FLAG}" )
  QEMU_ARGV+=(
    -L "${QEMU_SHARE}"
    -machine "q35,accel=${ACCEL}" -cpu host -m "${TG_GUEST_MEM_MB}" -smp "${TG_GUEST_SMP}"
    -nographic -serial mon:stdio -no-reboot
    -drive "file=${IMG_PATH},if=virtio,format=qcow2,snapshot=on"
    -drive "file=${SEED_PATH},if=virtio,format=raw,readonly=on"
  )
  if [ "$NETMODE" = "tap" ]; then
    QEMU_ARGV+=(
      -netdev "tap,id=n0,ifname=${TG_TAP_IFNAME},script=no,downscript=no"
      -device "virtio-net-pci,netdev=n0,mac=52:54:00:de:ad:77"
    )
  else
    QEMU_ARGV+=(
      -netdev "user,id=n0"
      -device "virtio-net-pci,netdev=n0,mac=52:54:00:de:ad:02"
    )
  fi
}

# Render QEMU_ARGV for human display ONLY, shell-quoting each token with %q so
# the printed line is copy-paste-safe and unambiguous (never re-parsed to run).
print_qemu_argv() {
  local first=1 tok
  for tok in "${QEMU_ARGV[@]}"; do
    if [ "$first" = 1 ]; then first=0; else printf ' '; fi
    printf '%q' "$tok"
  done
  printf '\n'
}

print_plan() {
  cat <<EOF
test-guest LOCAL boot plan
  mode    : ${NETMODE}   $([ "$NETMODE" = tap ] && echo "(attach ${TG_TAP_IFNAME}; create-tap is the §E2 task)" || echo "(qemu user-net / slirp — no sudo, no tap)")
  qemu    : ${QEMU_BIN} (accel=${ACCEL})
  firmware: ${QEMU_SHARE} (SeaBIOS + virtio ROMs from the sudo-free prefix)
  image   : ${IMG_PATH}   (snapshot=on — base never mutated)
  seed    : ${SEED_PATH}  (NoCloud cidata; build with build-test-guest.sh --${NETMODE})

Boot command (array argv, exec'd directly — shown %q-quoted for copy-paste):
$(print_qemu_argv)

In-guest assertions:
  smoke mode is SELF-ASSERTING — cloud-init runcmd prints to the serial console:
      ===DS-SMOKE-BEGIN===
      DS-SMOKE-CURL-PRESENT          # curl present (seed runcmd apk-installs it at boot)
      DS-SMOKE-HTTP-200              # the guest curled an upstream OUT over user-net
      ===DS-SMOKE-END===
    then powers off, so this harness exits on its own. A PASS is all three
    sentinels present with HTTP-200 (or any 2xx/3xx) and no *-FAIL/*-MISSING.
  tap mode boots the static ${TG_GUEST_IP}/${TG_GUEST_CIDR} (gw/DNS ${TG_GUEST_GATEWAY}) seed and drops to
    a serial login (root / 'ds'); egress depends on what dstap-0 is wired to
    (the boundary per-session tap — exercised by the §E2 task, not here).
EOF
}

build_qemu_argv
print_plan

if [ "${DS_TG_BOOT:-0}" != "1" ]; then
  echo
  log "plan-only (set DS_TG_BOOT=1 to boot; build first with build-test-guest.sh --${NETMODE})."
  exit 0
fi

# --- live boot path -----------------------------------------------------------
[ -x "$QEMU_BIN" ] || die "sudo-free qemu not found/executable at $QEMU_BIN"
[ -f "$IMG_PATH" ] || die "no image at $IMG_PATH — run build-test-guest.sh --${NETMODE} first"
[ -f "$SEED_PATH" ] || die "no seed at $SEED_PATH — run build-test-guest.sh --${NETMODE} first"

if [ "$NETMODE" = "tap" ]; then
  # §E2 tap-attach: we ATTACH to an already-present dstap-0; we do NOT create it
  # (creating the tap needs sudo and is the SEPARATE §E2 operator step). If the
  # tap is absent we REFUSE cleanly — never fabricate a green tap-attach result.
  if [ ! -e "/sys/class/net/${TG_TAP_IFNAME}" ]; then
    die "tap ${TG_TAP_IFNAME} is absent — create it first (the §E2 dstap-0 operator step; needs sudo). This wrapper only attaches, never creates; refusing rather than fabricating a tap-attach boot."
  fi
  log "attaching to existing ${TG_TAP_IFNAME} (static ${TG_GUEST_IP}/${TG_GUEST_CIDR})"
fi

log "booting (mode=${NETMODE}, accel=${ACCEL})..."
# Direct array exec — no eval, no word-splitting. QEMU_ARGV[0] is `env`, which
# sets LD_LIBRARY_PATH in qemu's child environment.
exec "${QEMU_ARGV[@]}"
