#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# boot-l1.sh — boot the L1 outer VM on the HOST (rootless qemu) for the nested NFT testbed.
#
# L1 gets FULL network access via SLIRP (NAT'd out through the host — the host nft
# floor and routing are NEVER touched). Nested KVM is exposed via `-cpu host` on this
# AMD host (kvm_amd nested=1), so L1 can boot the inner L2 agent VM. A 9p share mounts
# the host artifacts (dataplane binaries + L2 image + inside-L1 scripts) at /opt/ds in
# L1 so iterating on them never needs an L1 rebake. Drive L1 over ssh (hostfwd 2222->22)
# or the serial console.
#
# Usage:
#   boot-l1.sh stage     # (re)populate the 9p share at ~/tmp/ds-nested/share
#   boot-l1.sh up         # stage + boot L1 in the background; wait for ssh; print how to enter
#   boot-l1.sh ssh [...]  # ssh into L1 (root), passing through any args/command
#   boot-l1.sh console    # attach to the serial console (Ctrl-a x to detach via socat; else tail log)
#   boot-l1.sh status     # pid + ssh reachability
#   boot-l1.sh down       # shut L1 down (graceful via monitor, then kill)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGES="${DS_IMAGES_DIR:-$HOME/tmp/ds-images}"
NESTED="${DS_NESTED_DIR:-$HOME/tmp/ds-nested}"
SHARE="$NESTED/share"          # 9p-mounted at /opt/ds inside L1
RUN="$NESTED/run"              # pid/log/monitor for the L1 qemu
BIN_SRC="${DS_NESTED_BIN:-$NESTED/bin}"   # Debian-compatible dataplane binaries land here

L1_RAW="$IMAGES/l1-base.raw"
L1_KERNEL="$IMAGES/l1-vmlinuz"
L1_INITRD="$IMAGES/l1-initrd.img"
L1_OVERLAY="$RUN/l1.qcow2"
L1_MEM="${DS_L1_MEM_MIB:-16384}"
L1_SMP="${DS_L1_SMP:-4}"
L1_CID="${DS_L1_VSOCK_CID:-10}"
SSH_PORT="${DS_L1_SSH_PORT:-2222}"

# L2 (inner agent VM) artifacts staged into the share for in-L1 boot. Default to the
# routed-cc generation emitted by vm/m0-image/build-m0-image-rootless.sh — that is the
# reproducibly-buildable m0 (ds-netcfg routed-tap self-config + the DS_M0_INTERCEPT_CA_CERT
# hook that bakes the posture-(b) interception CA to guest /etc/ds/intercept-ca.crt). Rebuild
# with `DS_M0_INTERCEPT_CA_CERT=<share>/ca/intercept-ca.crt build-m0-image-rootless.sh` to get
# a swap-mode-ready base without any manual image patching. Override via DS_L2_* for older bases.
L2_KERNEL="${DS_L2_KERNEL:-$IMAGES/m0-vmlinuz-routed-cc}"
L2_INITRD="${DS_L2_INITRD:-$IMAGES/m0-initrd-routed-cc.img}"
L2_BASE="${DS_L2_BASE:-$IMAGES/m0-base-routed-cc.raw}"

SERIAL="$RUN/l1-serial.log"; PIDF="$RUN/l1.pid"; MON="$RUN/l1-monitor.sock"; QOUT="$RUN/l1-qemu.out"
CONSOCK="$RUN/l1-console.sock"   # bidirectional serial console (socat lifeline if ssh is down)
SSH_OPTS=(-p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

say() { printf '\033[1;36m[boot-l1] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[boot-l1][FATAL] %s\033[0m\n' "$*" >&2; exit 1; }

stage() {
  say "staging 9p share at $SHARE"
  mkdir -p "$SHARE/bin" "$SHARE/l2" "$SHARE/nft" "$SHARE/inside-l1" "$RUN"
  # dataplane gateways + the real host-agent live stack (Debian-glibc build dropped by
  # build-dataplane-debian.sh). ds-nethelper carries the nftgatelive cgo edge (libds_nft.a
  # is statically archived into it at build time, so only the binary needs staging) and
  # ds-host-agent is untagged/unprivileged (D148); the
  # orchestrator/hostbridge/driver-e2e are the up-orch real-stack bring-up (orchestrator-boot-l2.sh).
  # ds-seat-drive is the headless writer-seat drive harness orchestrator-boot-l2.sh execs to
  # drive one scripted CC turn over the per-session writer seat the host-agent advertises (the
  # structured analogue of the DS_KVM_LIVE goldentrace KVM-tier test; L1 has no Go toolchain).
  # ds-identity-validate-fake is the always-ALLOW D22 Validate UDS responder gate-up.sh's
  # DS_GATE_TLS_MODE=swap (posture-b cred-swap) starts so DS_SWAP_VALIDATE_LIVE has a responder.
  # ds-nethelper is the setcap'd privileged helper the (unprivileged) host-agent forks
  # per tap/nft op (D148). It lands at /opt/ds/bin/ds-nethelper in L1; orchestrator-boot-l2.sh
  # install_nethelper() installs it root:ds-agent 0750 + setcap cap_net_admin+eip inside L1.
  for b in ds-dnsgate ds-tlsproxy ds-host-agent ds-nethelper ds-orchestrator ds-hostbridge ds-driver-e2e ds-seat-drive ds-identity-validate-fake; do
    if [ -x "$BIN_SRC/$b" ]; then cp -f "$BIN_SRC/$b" "$SHARE/bin/$b"; else
      printf '\033[1;33m[boot-l1] WARN: %s not at %s yet — drop it in and re-run `stage` (9p is live, no reboot)\033[0m\n' "$b" "$BIN_SRC/$b" >&2
    fi
  done
  # The ds-nethelper installer (armed install + setcap + verify). orchestrator-boot-l2.sh
  # install_nethelper() shells it inside L1 (DS_NETHELPER_APPLY=1 DS_NETHELPER_GROUP=ds-agent)
  # to install + setcap the staged helper. Stage it at /opt/ds/install-ds-nethelper.sh.
  cp -f "$REPO/orchestrator/cmd/ds-nethelper/scripts/install-ds-nethelper.sh" "$SHARE/install-ds-nethelper.sh" 2>/dev/null \
    || printf '\033[1;33m[boot-l1] WARN: install-ds-nethelper.sh missing at %s\033[0m\n' "$REPO/orchestrator/cmd/ds-nethelper/scripts/install-ds-nethelper.sh" >&2
  chmod +x "$SHARE/install-ds-nethelper.sh" 2>/dev/null || true
  # nft floor artifacts (the real input-policy-drop appliance floor)
  cp -f "$REPO"/dataplane/artifacts/nft/*.nft "$SHARE/nft/" 2>/dev/null || true
  # full dataplane/artifacts (gate-up.sh symlinks /work/dataplane/artifacts here so
  # ds-dnsgate finds its compile-time-baked policy-packs/pol2-system-baseline.pol1.yaml)
  rm -rf "$SHARE/artifacts"; cp -r "$REPO/dataplane/artifacts" "$SHARE/artifacts" 2>/dev/null || true
  # inside-L1 orchestration scripts
  cp -f "$SCRIPT_DIR"/inside-l1/*.sh "$SHARE/inside-l1/" 2>/dev/null || true
  chmod +x "$SHARE"/inside-l1/*.sh 2>/dev/null || true
  # The deterministic single-turn headless-drive proof script (JSONL): the committed
  # fixture ds-seat-drive's -proof turn mirrors (a Bash printf of a token to a /work
  # proof file). Stage it so the in-L1 driver (orchestrator-boot-l2.sh) can reference
  # the canonical turn shape + token alongside the harness binary.
  mkdir -p "$SHARE/drive"
  cp -f "$REPO/client/goldentrace/e2e/testdata/proof.jsonl" "$SHARE/drive/proof.jsonl" 2>/dev/null \
    || printf '\033[1;33m[boot-l1] WARN: proof.jsonl fixture missing at %s\033[0m\n' "$REPO/client/goldentrace/e2e/testdata/proof.jsonl" >&2
  # L2 boot artifacts — two flavors. FAT (= the L1 image, reused): rich tooling
  # (curl/dig/nc/ssh + autologin) for egress probes. M0 (= the real agent image):
  # the gated-CC demo. Bases reflink-copied (instant CoW on btrfs); read over 9p as
  # the per-session overlay backing.
  cp -f "$L1_KERNEL" "$SHARE/l2/fat-vmlinuz"
  cp -f "$L1_INITRD" "$SHARE/l2/fat-initrd.img"
  cp -f --reflink=auto "$L1_RAW" "$SHARE/l2/fat-base.raw"
  cp -f "$L2_KERNEL" "$SHARE/l2/m0-vmlinuz"  2>/dev/null || say "WARN: M0 kernel $L2_KERNEL missing (m0 flavor unavailable)"
  cp -f "$L2_INITRD" "$SHARE/l2/m0-initrd.img" 2>/dev/null || say "WARN: M0 initrd missing"
  [ -r "$L2_BASE" ] && cp -f --reflink=auto "$L2_BASE" "$SHARE/l2/m0-base.raw" || say "WARN: M0 base missing"
  say "share staged: $(du -sh "$SHARE" 2>/dev/null | cut -f1)"
}

is_up() { [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; }

up() {
  is_up && { say "L1 already running (pid $(cat "$PIDF"))"; return 0; }
  [ -r "$L1_RAW" ] && [ -r "$L1_KERNEL" ] && [ -r "$L1_INITRD" ] || die "L1 artifacts missing — run build-l1-image.sh"
  [ -c /dev/kvm ] || die "/dev/kvm absent"
  stage
  mkdir -p "$RUN"
  say "create fresh L1 overlay over $(basename "$L1_RAW") (base never mutated)"
  rm -f "$L1_OVERLAY"
  qemu-img create -f qcow2 -F raw -b "$L1_RAW" "$L1_OVERLAY" >/dev/null
  : > "$SERIAL"
  say "boot L1 (rootless KVM, -cpu host nested, ${L1_MEM}MiB/${L1_SMP}vcpu, SLIRP+ssh:$SSH_PORT, 9p /opt/ds; L1 is a pure vsock HOST for L2)"
  # NO -device vhost-vsock-pci for L1 itself: the host<->L1 channel is SSH+9p (the L1 vsock
  # was vestigial). Giving L1 a guest-cid makes it occupy that CID *inside* L1, which
  # collides with the per-session L2 CID the host-agent derives (index+reservedVsockCIDs;
  # the fat-flavor index 7 -> CID 10 == the old L1_CID 10 -> "failed to set guest cid:
  # Address already in use"). Without it, L1 is a pure vsock host (local CID 2) and L2 takes
  # CID 3+. vhost_vsock (the L1->L2 host side) is still loaded via modules-load.d.
  nohup qemu-system-x86_64 \
    -enable-kvm -cpu host -m "$L1_MEM" -smp "$L1_SMP" \
    -kernel "$L1_KERNEL" -initrd "$L1_INITRD" \
    -append "root=LABEL=DS_L1ROOT console=ttyS0,115200 rw" \
    -drive file="$L1_OVERLAY",format=qcow2,if=virtio \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=n0 \
    -fsdev local,id=ds9p,path="$SHARE",security_model=mapped-xattr \
    -device virtio-9p-pci,fsdev=ds9p,mount_tag=ds9p \
    -chardev "socket,id=con0,path=$CONSOCK,server=on,wait=off,logfile=$SERIAL" \
    -serial chardev:con0 \
    -monitor "unix:$MON,server,nowait" \
    -display none -no-reboot \
    >"$QOUT" 2>&1 &
  echo $! > "$PIDF"
  disown 2>/dev/null || true   # fully detach: qemu must survive this script exiting / its caller being timed out
  sleep 1
  is_up || { say "qemu died immediately:"; cat "$QOUT"; die "L1 launch failed"; }
  say "L1 qemu pid $(cat "$PIDF") (serial: $SERIAL)"
  say "waiting for ssh on 127.0.0.1:$SSH_PORT ..."
  local deadline=$(( $(date +%s) + 180 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    is_up || { say "qemu exited during boot; serial tail:"; tail -30 "$SERIAL"; die "L1 died before ssh"; }
    if ssh "${SSH_OPTS[@]}" root@127.0.0.1 true 2>/dev/null; then
      say "L1 SSH UP. Enter with:  scripts/nested-testbed/boot-l1.sh ssh"
      return 0
    fi
    sleep 3
  done
  say "ssh did not come up in time; serial tail:"; tail -40 "$SERIAL"
  die "L1 ssh timeout"
}

case "${1:-up}" in
  stage) stage ;;
  up) up ;;
  ssh) shift; exec ssh "${SSH_OPTS[@]}" root@127.0.0.1 "$@" ;;
  console)
    # interactive serial console; detach with Ctrl-] (0x1d). Falls back to tailing the log.
    command -v socat >/dev/null && exec socat -,raw,echo=0,escape=0x1d "unix-connect:$CONSOCK" || { say "no socat; tailing serial"; exec tail -f "$SERIAL"; } ;;
  consend)
    # non-interactive console driver: pipe a command line into the serial console
    # (lifeline when ssh is down). Usage: boot-l1.sh consend 'systemctl status ssh'
    shift; command -v socat >/dev/null || die "socat needed for consend"
    printf '%s\n' "$*" | socat -t2 - "unix-connect:$CONSOCK" >/dev/null 2>&1 || true
    sleep 2; tail -25 "$SERIAL" | sed 's/\x1b\[[0-9;]*m//g' ;;
  status)
    if is_up; then echo "L1: RUNNING (pid $(cat "$PIDF"))"; else echo "L1: stopped"; fi
    ssh "${SSH_OPTS[@]}" -o ConnectTimeout=3 root@127.0.0.1 'echo "  ssh: OK  ($(uname -n), kvm=$(test -c /dev/kvm && echo yes || echo NO))"' 2>/dev/null || echo "  ssh: unreachable" ;;
  down)
    if is_up; then
      say "shutting L1 down"
      if command -v socat >/dev/null && [ -S "$MON" ]; then echo system_powerdown | socat - "unix-connect:$MON" >/dev/null 2>&1 || true; sleep 4; fi
      kill "$(cat "$PIDF")" 2>/dev/null || true; sleep 1; kill -9 "$(cat "$PIDF")" 2>/dev/null || true
    fi
    rm -f "$PIDF"; say "L1 down" ;;
  *) die "usage: $0 {stage|up|ssh [cmd]|console|status|down}" ;;
esac
