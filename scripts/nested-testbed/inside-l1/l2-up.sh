#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# l2-up.sh — runs INSIDE L1. Boot the nested L2 agent VM on the routed tap, so its
# only egress path is L1's nft floor + gateways. Nested KVM: L1 exposes /dev/kvm
# (the host `-cpu host` passed AMD-V through), so L2 boots with -enable-kvm too.
#
# L2 flavor (DS_L2_FLAVOR):
#   fat (default) — reuse the L1 fat image: has curl/dig/nc/ssh + serial autologin,
#                   so it is trivial to drive egress probes. Gets its routed-tap IP
#                   from kernel `ip=` autoconfig (net.ifnames=0 => eth0).
#   m0            — the real M0 agent image (runs CC). Uses the config-drive ds-net.env
#                   path instead (staged separately); for the full gated-CC demo.
set -uo pipefail
IDX="${DS_SESSION_IDX:-7}"
TAP="dstap-${IDX}"
NET="10.77.${IDX}"
L2DIR="${DS_L2_DIR:-/opt/ds/l2}"
RUN="${DS_L2_RUN:-/run/ds-l2}"
FLAVOR="${DS_L2_FLAVOR:-fat}"
MEM="${DS_L2_MEM:-4096}"; SMP="${DS_L2_SMP:-2}"
mkdir -p "$RUN"
say(){ printf '\033[1;35m[l2] %s\033[0m\n' "$*"; }
die(){ printf '\033[1;31m[l2][FATAL] %s\033[0m\n' "$*" >&2; exit 1; }

# Same /31 third-octet ceiling the Go side fail-closes on (netconfig.go
# netConfigMaxIndexThirdOct / live.go macIndexMaxOctet): past 255 the 10.77.<IDX>.x
# /31 would alias and the 2-hex-digit MAC octet below would overflow — refuse
# rather than hand qemu a malformed mac=. Leading zeros are rejected too: bash
# printf reads a 0-prefixed IDX as OCTAL ("010" -> octet 08, silently the WRONG
# index; "099" errors and renders 00, aliasing session 0's MAC), and the sanctioned
# Go tapName never emits them.
case "$IDX" in *[!0-9]*|'') die "DS_SESSION_IDX=$IDX is not a decimal index" ;; 0?*) die "DS_SESSION_IDX=$IDX has a leading zero — bash printf would read it as octal (use $((10#$IDX)))" ;; esac
[ "$IDX" -le 255 ] || die "DS_SESSION_IDX=$IDX exceeds the /31 third-octet ceiling (255) — same ceiling as the Go netConfigForIndex/macForIndex"

[ -c /dev/kvm ] || die "/dev/kvm absent inside L1 — nested KVM not exposed (need host -cpu host + modprobe kvm_amd)"
ip link show "$TAP" >/dev/null 2>&1 || die "$TAP missing — run gate-up.sh first"

case "$FLAVOR" in
  fat) BASE="$L2DIR/fat-base.raw"; KERN="$L2DIR/fat-vmlinuz"; INITRD="$L2DIR/fat-initrd.img"; ROOTLBL=DS_L1ROOT ;;
  m0)  BASE="$L2DIR/m0-base.raw";  KERN="$L2DIR/m0-vmlinuz";  INITRD="$L2DIR/m0-initrd.img";  ROOTLBL=DS_M0ROOT ;;
  *) die "unknown DS_L2_FLAVOR=$FLAVOR (fat|m0)" ;;
esac
for f in "$BASE" "$KERN" "$INITRD"; do [ -r "$f" ] || die "missing L2 artifact: $f"; done

if [ -f "$RUN/l2.pid" ] && kill -0 "$(cat "$RUN/l2.pid")" 2>/dev/null; then
  say "L2 already running (pid $(cat "$RUN/l2.pid")) — destroy with l2-down or kill it first"; exit 0
fi

say "create L2 overlay over $(basename "$BASE") (backing read over 9p; overlay on L1 disk)"
rm -f "$RUN/l2.qcow2"
qemu-img create -f qcow2 -F raw -b "$BASE" "$RUN/l2.qcow2" >/dev/null || die "overlay create failed"

# net.ifnames=0 => the NIC is eth0 (dodges the en* DHCP match), so the fat image's
# MAC-matched 20-l2-routedtap.network brings it up static on the /31. (Kernel ip=
# autoconfig is NOT used: Debian's initramfs only honors it for a network root.)
#
# MAC 5th octet is TWO HEX DIGITS (printf '%02x'): byte-identical to the Go host
# render (orchestrator/internal/hypervisor/libvirt/live.go macForIndex) so the
# orchestrator-driven and manual boot paths pin the SAME MAC for a given IDX. Hex
# covers the full 0..255 index range (the same ceiling netconfig.go's /31 admits);
# the pinned demo IDX=7 renders "07" identically in hex and decimal, so the baked
# fat-L2 image's 05-l2-routedtap.network (MAC 52:54:00:77:07:01) is unaffected.
APPEND="root=LABEL=$ROOTLBL console=ttyS0,115200 rw net.ifnames=0"
say "boot L2 ($FLAVOR, ${MEM}MiB/${SMP}vcpu) on $TAP — eth0=$NET.1 default via $NET.0"
nohup qemu-system-x86_64 \
  -enable-kvm -cpu host -m "$MEM" -smp "$SMP" \
  -kernel "$KERN" -initrd "$INITRD" -append "$APPEND" \
  -drive file="$RUN/l2.qcow2",format=qcow2,if=virtio \
  -netdev "tap,id=n0,ifname=$TAP,script=no,downscript=no" \
  -device "virtio-net-pci,netdev=n0,mac=52:54:00:77:$(printf '%02x' "$IDX"):01" \
  -chardev "socket,id=c0,path=$RUN/l2-console.sock,server=on,wait=off,logfile=$RUN/l2-serial.log" \
  -serial chardev:c0 \
  -monitor "unix:$RUN/l2-monitor.sock,server,nowait" \
  -display none -no-reboot \
  >"$RUN/l2-qemu.out" 2>&1 &
echo $! >"$RUN/l2.pid"; disown
sleep 1
kill -0 "$(cat "$RUN/l2.pid")" 2>/dev/null || { say "qemu died:"; cat "$RUN/l2-qemu.out"; die "L2 launch failed"; }
say "L2 qemu pid $(cat "$RUN/l2.pid") (serial: $RUN/l2-serial.log, console: $RUN/l2-console.sock)"
say "waiting for L2 ssh on $NET.1 (fat image) ..."
SSH=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=6 -o BatchMode=yes)
deadline=$(( $(date +%s) + 150 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  kill -0 "$(cat "$RUN/l2.pid")" 2>/dev/null || { say "L2 died; serial tail:"; tail -25 "$RUN/l2-serial.log"; die "L2 exited"; }
  if "${SSH[@]}" root@"$NET.1" true 2>/dev/null; then say "L2 SSH UP at $NET.1"; exit 0; fi
  sleep 4
done
say "L2 ssh not up in time; serial tail (it may still be usable via console $RUN/l2-console.sock):"
tail -30 "$RUN/l2-serial.log" | sed 's/\x1b\[[0-9;]*m//g'
exit 1
