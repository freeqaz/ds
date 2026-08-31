#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# setup-local-kvm.sh — provision an Arch bare-metal box as a local KVM rig for
# the dream-serpent live sandbox validation.
#
# Assumes the machine is already capable: bare metal, /dev/kvm accessible,
# hardware virt + nested=1, and the live binaries (libds_nft.a, the nftgatelive
# ds-nethelper helper plus the untagged unprivileged host-agent (D148),
# ds-driver-e2e, ds-hostbridge) all build there. The gaps this closes are
# software + perms:
#   - no libvirt/virsh (the host-agent boots the VM via `virsh`, qemu:///session)
#   - sudo needs a password (the sandbox's `nft` floor + `ip tuntap` need root)
#
# RUN:  sudo DS_KVM_USER=<login> bash scripts/live-mvp/setup-local-kvm.sh
#   (or just add the sudoers snippet in [3] and grant that login passwordless
#    sudo for pacman too, then run the rest unprivileged.)
#
# NOTE: this is package-manager + sudoers surgery on a HOST. Read it end to end
# before running it anywhere you care about.
set -euo pipefail
U="${DS_KVM_USER:-${SUDO_USER:-$USER}}"

echo "[1/3] libvirt + qemu + dnsmasq (qemu:///session; ~/.local/opt/qemu exists but virsh/libvirt are missing)"
pacman -S --needed --noconfirm libvirt qemu-full dnsmasq

echo "[2/3] groups: kvm + libvirt for $U"
usermod -aG kvm,libvirt "$U"

echo "[3/3] sudoers: let $U run the sandbox privileged tools without a password"
echo "      (nft = the per-session floor + allow-sets; ip = routed-tap addressing, PINNED per subcommand)"
# ---------------------------------------------------------------------------
# WHY THIS GRANT IS SHAPED THIS WAY (audit 2026-08-03) — read before widening.
#
# The original grant was:
#     $U ALL=(ALL) NOPASSWD: /usr/bin/nft, /usr/sbin/nft, /usr/bin/ip, /usr/bin/setpriv
# Two of those four entries were passwordless root for ANY command, which made
# the careful per-script grants elsewhere (stack-up-host.sh, safe-apply.sh)
# decorative:
#
#   setpriv  — its entire job is to exec a program with chosen credentials, so
#              `sudo setpriv --reuid=0 --regid=0 --init-groups /bin/bash` is a
#              root shell. It is a standard GTFOBins entry. REMOVED: nothing
#              calls it under sudo. The one real caller (nested-testbed's
#              orchestrator-boot-l2.sh) runs INSIDE L1 where it is already root,
#              and the host-agent launcher it was added for in June 2026 is
#              superseded by the D148 ds-nethelper model.
#
#   ip       — `sudo ip netns add x && sudo ip netns exec x /bin/bash` is equally
#              a root shell. PINNED to the subcommands the sandbox actually uses
#              (routed-tap addressing), which excludes `netns` entirely. Note the
#              rules pin argv[1] and argv[2], so `ip -n <ns> ...` and `ip -batch
#              <file>` do not match either. scripts/ci-runner-install.sh already
#              used this pinning style for its own CI netns grant.
#
#   nft      — KEPT unrestricted by owner decision 2026-08-03. It is not a
#              command-exec primitive, but be clear-eyed about the residual: it
#              can `flush ruleset` or drop `table inet ds_boundary`, i.e. tear
#              down the very egress floor the gated VMs depend on, and `nft -f
#              <path>` echoes offending lines so it is a partial file-read. The
#              hardened, dead-man-guarded path for floor writes is
#              `sudo safe-apply.sh apply --arm`; prefer it.
#
# NOT COVERED HERE: the per-script grants (stack-up-host.sh, deadman/safe-apply.sh)
# live in their own drop-in. Generate it with
#     scripts/host-bringup/ds-deploy.sh print-sudoers
# and read that script's header first — those grants are only meaningful if they
# point at the ROOT-OWNED /opt/ds-host-gated tree. Pointed at a checkout or a
# ~/tmp staging dir (the shape here until 2026-08-09) they are unconditional
# passwordless root, because the granted user can rewrite the granted file.
#
# Also tightened (ALL)->(root): the runas spec never needed to cover every user.
# Validate any edit with `visudo -cf <file>` BEFORE installing — a malformed
# drop-in can lock this box out of sudo entirely.
# ---------------------------------------------------------------------------
install -m0440 /dev/stdin /etc/sudoers.d/ds-kvm-validation <<EOF
$U ALL=(root) NOPASSWD: /usr/bin/nft, /usr/sbin/nft
$U ALL=(root) NOPASSWD: /usr/bin/ip tuntap add *, /usr/bin/ip tuntap del *
$U ALL=(root) NOPASSWD: /usr/bin/ip link set *, /usr/bin/ip link del *
$U ALL=(root) NOPASSWD: /usr/bin/ip addr add *, /usr/bin/ip addr del *
$U ALL=(root) NOPASSWD: /usr/bin/ip route add *, /usr/bin/ip route del *
$U ALL=(root) NOPASSWD: /usr/sbin/ip tuntap add *, /usr/sbin/ip tuntap del *
$U ALL=(root) NOPASSWD: /usr/sbin/ip link set *, /usr/sbin/ip link del *
$U ALL=(root) NOPASSWD: /usr/sbin/ip addr add *, /usr/sbin/ip addr del *
$U ALL=(root) NOPASSWD: /usr/sbin/ip route add *, /usr/sbin/ip route del *
EOF

cat <<'NEXT'

✅ provisioning done. Remaining steps (run these as the unprivileged login, NO further sudo):
   1. systemctl --user enable --now libvirtd.socket           # the user-session libvirt
   2. build the M0 image (the ONE slow step, ~10–20 min, ~12 GB; needs sudo/debootstrap —
      either run it yourself or it's covered by the sudoers entry above if you widen it):
        cd <repo>/vm/m0-image && sudo ./build-m0-image.sh --build
   3. then drive the live RoutedTap validation — installing the nft floor SCOPED to
      dstap-*/forward only (NEVER the host-INPUT chain, which on a box reached over
      a VPN/SSH silently drops management traffic), so the host's own SSH/management
      is never touched.
NEXT
