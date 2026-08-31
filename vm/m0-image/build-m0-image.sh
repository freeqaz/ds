#!/usr/bin/env bash
# build-m0-image.sh — the reproducible hand-build procedure for the M0 base
# image (the single image the one M0 VM is cloned from, doc 05 §3 / §8).
#
# This is a HAND-BUILT artifact, not a CI product (D12: v0 environments stay
# dynamic; the images/golden/ pipeline industrializes the same image from M1).
# The COMMITTED artifact is THIS PROCEDURE — the script, the guest-config files,
# and the README. The image BLOB it produces is never committed (it lives under
# ~/tmp/ds-images/, btrfs/CoW; see README "What never gets committed").
#
# Content spec (all from doc 04 §6 / the cited docs):
#   - D49  : the pinned Claude Code runtime (M0_CC_VERSION), installed at bake.
#   - doc 11 §3.2/§8.6 : a glibc (Debian) userland, NOT musl — fail-fast resolver.
#   - D38  : the VM entrypoint binary staged at M0_ENTRYPOINT_PATH and launched
#            at boot by ds-entrypoint.service (the entrypoint then launches the
#            pinned CC runtime). The binary is a SEPARATE task; this build stages
#            it iff present and otherwise leaves the fail-closed boot unit.
#   - D75  : guest-interior v6 disabled per-egress-NIC (lo keeps ::1), via the
#            99-ds-disable-ipv6.conf sysctl drop-in; kernel ipv6.disable=1 is
#            FORBIDDEN.
#   - D29  : the result is the RAW base under the per-session qcow2 overlay; we
#            build into a qcow2 for hand-build/boot-test convenience.
#
# ENVIRONMENT NOTE (ratified local substitute): the production base is a
# virtual-metal ESXi host running KVM/libvirt/qcow2 nested (D5/D31). We DO NOT
# have that here; the boot-on-ESXi validation is explicitly the human follow-up
# task. Locally we build and boot-test with the sudo-free user qemu under
# ~/.local/opt/qemu (see boot-validate.sh).
#
# This script is written to be runnable two ways:
#   (a) on a host WITH debootstrap + a loop/chroot-capable environment (the real
#       hand-build, run once by an operator) — produces the full glibc rootfs;
#   (b) as a DRY-RUN plan (--plan) that prints every step and validates the pins
#       and guest-config WITHOUT requiring root/debootstrap — this is what the
#       gate and a reviewer run, and what the sandbox can execute honestly.
# The default is --plan precisely because the real bake needs privileges this
# environment (and CI) deliberately lack; a real bake is `--build`.
#
# Usage:
#   vm/m0-image/build-m0-image.sh            # same as --plan
#   vm/m0-image/build-m0-image.sh --plan     # print the procedure, validate inputs
#   vm/m0-image/build-m0-image.sh --build    # actually bake (needs root+debootstrap)
#   DS_IMAGES_DIR=~/tmp/ds-images vm/m0-image/build-m0-image.sh --build
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${HERE}/m0-image.env"

MODE="${1:---plan}"
case "$MODE" in
  --plan | --build) ;;
  *) echo "usage: $0 [--plan|--build]" >&2; exit 2 ;;
esac

# Scratch/output root: btrfs (CoW), NEVER /tmp (tmpfs/RAM) and NEVER the repo.
DS_IMAGES_DIR="${DS_IMAGES_DIR:-${HOME}/tmp/ds-images}"
OUT_QCOW="${DS_IMAGES_DIR}/m0-base-${M0_BASE_SUITE}-cc${M0_CC_VERSION}.qcow2"
ROOTFS_DIR="${DS_IMAGES_DIR}/m0-rootfs"

QEMU_IMG="${QEMU_IMG:-$(command -v qemu-img || echo /usr/bin/qemu-img)}"

# The guest 'ds' user's home, which is also the CC working dir the live MVP launches
# in (scripts/live-mvp/ds-serve-stack.sh: -working-dir /home/ds, HOME=/home/ds). The
# workspace pre-trust seed (do_build step 4b) keys CC's per-path trust registry on it.
WORKDIR="/home/ds"

log() { printf 'build-m0-image: %s\n' "$*"; }
step() { printf '\n=== STEP: %s ===\n' "$*"; }

# Expand the per-egress-NIC sysctl template (the sysctl.d file cannot glob
# interface names). For the --plan path we expand against the canonical M0
# virtio-net name `enp1s0`; the real --build path enumerates the booted NICs.
expand_ipv6_dropin() {
  local iface="${1:-enp1s0}"
  sed "s/__IFACE__/${iface}/g" "${HERE}/guest-config/99-ds-disable-ipv6.conf"
}

# Expand the entrypoint unit's bake-time tokens.
expand_entrypoint_unit() {
  sed -e "s|__ENTRYPOINT_PATH__|${M0_ENTRYPOINT_PATH}|g" \
      -e "s|__ENTRYPOINT_CONFIG_DIR__|${M0_ENTRYPOINT_CONFIG_DIR}|g" \
      -e "s|__TOOLCHAIN_PATH__|${M0_GO_PREFIX}/bin:${M0_RUST_PREFIX}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|g" \
      "${HERE}/guest-config/ds-entrypoint.service"
}

# Expand the config-drive mount unit's bake-time tokens (gap-1). The mount point /
# label / fs are single-sourced from m0-image.env and MUST match the host-side
# producer (configdrive.go): LABEL the host stamps + iso9660 it packs.
expand_configdrive_mount() {
  sed -e "s|__ENTRYPOINT_CONFIG_DIR__|${M0_ENTRYPOINT_CONFIG_DIR}|g" \
      -e "s|__CONFIG_DRIVE_LABEL__|${M0_CONFIG_DRIVE_LABEL}|g" \
      -e "s|__CONFIG_DRIVE_FS__|${M0_CONFIG_DRIVE_FS}|g" \
      "${HERE}/guest-config/run-ds-entrypoint.mount"
}

# Expand the attach-carriage forwarder unit's bake-time tokens (gap-3). The binary
# path / UDS path / AF_VSOCK port are single-sourced from m0-image.env; M0_ATTACH_PORT
# MUST match the host-side libvirt.DefaultAttachPort the host-agent bridge dials
# guestCID:port over virtio-vsock.
expand_attachfwd_unit() {
  sed -e "s|__ATTACHFWD_PATH__|${M0_ATTACHFWD_PATH}|g" \
      -e "s|__ATTACHFWD_UDS_PATH__|${M0_ATTACHFWD_UDS_PATH}|g" \
      -e "s|__ATTACH_PORT__|${M0_ATTACH_PORT}|g" \
      "${HERE}/guest-config/ds-attachfwd.service"
}

# Expand the U4 per-session net-config apply script's bake-time tokens. The config
# dir / NIC glob / net-config file name are single-sourced from m0-image.env; the
# file name MUST match the host-side producer (netconfig.go netConfigFileName).
expand_netcfg_script() {
  sed -e "s|__ENTRYPOINT_CONFIG_DIR__|${M0_ENTRYPOINT_CONFIG_DIR}|g" \
      -e "s|__EGRESS_NIC_GLOB__|${M0_EGRESS_NIC_GLOB}|g" \
      -e "s|__NETCFG_FILE__|${M0_NETCFG_FILE}|g" \
      "${HERE}/guest-config/ds-apply-netcfg.sh"
}

# Expand the U4 net-config service unit's bake-time tokens. The apply-script path is
# single-sourced from m0-image.env; the unit runs the script Before=ds-entrypoint.
expand_netcfg_unit() {
  sed -e "s|__NETCFG_SCRIPT_PATH__|${M0_NETCFG_SCRIPT_PATH}|g" \
      "${HERE}/guest-config/ds-netcfg.service"
}

# Expand the SLIRP DHCP .network's bake-time tokens. The NIC glob is single-sourced
# from m0-image.env (M0_EGRESS_NIC_GLOB); the literal `eth0` is the net.ifnames=0 name.
# This file is STAGED at M0_SLIRP_NETWORK_STAGE (a NON-networkd-search path), never in
# /etc|/run|/usr/lib /systemd/network — ds-slirp-net.service installs it into
# /run/systemd/network only on the SLIRP path (ds-net.env absent).
expand_slirp_network() {
  sed -e "s|__EGRESS_NIC_GLOB__|${M0_EGRESS_NIC_GLOB}|g" \
      "${HERE}/guest-config/ds-slirp-dhcp.network"
}

# Expand the SLIRP DHCP service unit's bake-time tokens. The staged .network path /
# config-dir / net-config file name are single-sourced from m0-image.env; the unit
# installs the .network + reloads networkd Before=ds-entrypoint, ONLY when the
# routed-tap signal ds-net.env is absent (ConditionPathExists=!<dir>/<file>).
expand_slirp_net_unit() {
  sed -e "s|__SLIRP_NETWORK_STAGE__|${M0_SLIRP_NETWORK_STAGE}|g" \
      -e "s|__ENTRYPOINT_CONFIG_DIR__|${M0_ENTRYPOINT_CONFIG_DIR}|g" \
      -e "s|__NETCFG_FILE__|${M0_NETCFG_FILE}|g" \
      "${HERE}/guest-config/ds-slirp-net.service"
}

# The terminfo entry path for a TERM name, in the ncurses-on-Debian layout: the
# first character of the name is the directory (e.g. xterm-256color -> x/xterm-256color).
# Debian's ncurses-base installs the common entries under /lib/terminfo and the
# fuller ncurses-term set under /usr/share/terminfo; xterm-256color is in
# ncurses-base at /lib/terminfo/x/xterm-256color (confirmed present in the baked
# image, doc serpent-cli-mvp 10 §B). The two candidate roots the bake checks.
terminfo_subpath() {
  local term="${1:-$M0_PTY_TERM}"
  printf '%s/%s' "${term:0:1}" "${term}"
}
M0_TERMINFO_ROOTS=(/lib/terminfo /usr/share/terminfo /etc/terminfo)

# Emit the D83/§5.3 git-over-HTTPS pin gitconfig. It carries no bake-time tokens
# (it pins github.com, the one source-control host POL-2 admits), so this is a
# straight pass-through — but routed through a helper so the build step and the
# procedure print/install the SAME bytes.
emit_git_pin() { cat "${HERE}/guest-config/git-https-pin.gitconfig"; }

print_procedure() {
  cat <<EOF
M0 base-image build procedure (pins from m0-image.env):

  base userland   : ${M0_BASE_DISTRO} ${M0_BASE_SUITE} (glibc — doc 11 §3.2/§8.6)
  node major      : ${M0_NODE_MAJOR}
  CC runtime pin  : @anthropic-ai/claude-code@${M0_CC_VERSION} (D49)
  entrypoint path : ${M0_ENTRYPOINT_PATH} (D38; launched by ds-entrypoint.service)
  config-ref dir  : ${M0_ENTRYPOINT_CONFIG_DIR} (D38; config-drive mount point)
  config-drive    : LABEL=${M0_CONFIG_DRIVE_LABEL} fs=${M0_CONFIG_DRIVE_FS} (gap-1; host attaches read-only, run-ds-entrypoint.mount mounts it)
  net config      : ${M0_NETCFG_SCRIPT_PATH} (U4; ds-netcfg.service applies ${M0_NETCFG_FILE} 10.77.<idx>.1/31 via 10.77.<idx>.0 Before=ds-entrypoint; no-op when absent = SLIRP)
  slirp dhcp      : ${M0_SLIRP_NETWORK_STAGE} (systemd-networkd DHCP for the SLIRP NIC; ds-slirp-net.service installs it Before=ds-entrypoint ONLY when ${M0_NETCFG_FILE} is absent — provably off the routed tap)
  attach forwarder: ${M0_ATTACHFWD_PATH} (gap-3; ds-attachfwd.service, UDS ${M0_ATTACHFWD_UDS_PATH} <-> AF_VSOCK :${M0_ATTACH_PORT})
  pty TERM        : ${M0_PTY_TERM} (terminal/PTY mode; terminfo asserted present at /lib/terminfo/$(terminfo_subpath) — doc serpent-cli-mvp 02 §2.9)
  guest v6        : disabled per-egress-NIC (${M0_EGRESS_NIC_GLOB}), lo keeps ::1 (D75)
  git remotes     : pinned to HTTPS (insteadOf ssh->https + credential helper, D83/§5.3)
  disk            : raw base + per-session qcow2 overlay (D29); virtual ${M0_DISK_VIRTUAL_SIZE}
  output          : ${OUT_QCOW}

Steps (the --build path runs these; --plan prints + validates inputs only):

 1. debootstrap a minimal ${M0_BASE_SUITE} glibc rootfs into ${ROOTFS_DIR}.
      debootstrap --variant=minbase --include=systemd-sysv,ca-certificates,curl,dbus \\
        ${M0_BASE_SUITE} ${ROOTFS_DIR} \\
        http://\${M0_DEB_MIRROR:-deb.debian.org/debian}
    Rationale: minbase + systemd-sysv gives a glibc init the entrypoint unit
    needs; ca-certificates so the per-session interception CA (D17) injects into
    a real trust store at create; curl/node only as bake-time tooling; dbus is
    the system bus 'networkctl reload' (ds-slirp-net.service) calls over —
    systemd only RECOMMENDS it, and minbase pulls no Recommends, so an implicit
    dbus is NOT a thing (live-found 2026-07-29: absent dbus failed the unit and
    the SLIRP NIC never DHCP'd).

 2. In the rootfs, create the unprivileged guest user 'ds' the entrypoint runs
    as, and the config-ref drop dir ${M0_ENTRYPOINT_CONFIG_DIR}.
      chroot ${ROOTFS_DIR} useradd --create-home --shell /usr/sbin/nologin ds
      install -d -m 0750 -o ds -g ds ${ROOTFS_DIR}${M0_ENTRYPOINT_CONFIG_DIR}

 3. Install node ${M0_NODE_MAJOR} and the D49-pinned Claude Code runtime.
      # node ${M0_NODE_MAJOR} from NodeSource (or the operator's D41 cache).
      chroot ${ROOTFS_DIR} npm install -g "@anthropic-ai/claude-code@${M0_CC_VERSION}"
    The npm registry traffic here is the OPERATOR's bake-time pull-through cache
    (D41), not the runtime egress path the boundary gates. NOTE the live drift
    recorded in client/wrapper/DRIVE-FINDINGS.md §1: an in-image npm install can
    fail UNABLE_TO_VERIFY_LEAF_SIGNATURE under a TLS-intercepting egress — bake
    behind a CA-aware cache, or stage a known-good pinned ${M0_CC_VERSION}
    binary at /opt/claude-code/bin/claude (the same fallback cc_sandbox.sh uses).

 4. Bake the D75 guest IPv6 drop-in (per egress NIC; lo untouched).
      expand 99-ds-disable-ipv6.conf for each egress NIC matching
      '${M0_EGRESS_NIC_GLOB}' into ${ROOTFS_DIR}/etc/sysctl.d/99-ds-disable-ipv6.conf
    (rendered template below.)

 4a. Assert the terminal/PTY-mode terminfo entry is present (HARD; fail the bake
     if absent). The interactive CC TUI runs under a pty with TERM=${M0_PTY_TERM};
     it needs /lib/terminfo/$(terminfo_subpath) (ncurses-base, shipped by the
     minbase debootstrap) or it renders garbled (doc serpent-cli-mvp 02 R4). No
     new install — the base already carries it; the assertion is the guard.

 4b. Seed CC workspace pre-trust so the first-run "trust this folder?" prompt does
     NOT gate the dev. Writes ${ROOTFS_DIR}${WORKDIR}/.claude.json keying the global
     trust registry on ${WORKDIR} (hasTrustDialogAccepted + onboarding-seen). The
     env complement CLAUDE_TRUST_WORKSPACE=1 is a host-resolved LaunchSpec.env fact
     the guest-launch unit SHOULD also set (out of this tree — cross-tree note).

 5. Stage the D38 entrypoint binary + boot unit.
      install -m 0755 <ds-entrypoint artifact> ${ROOTFS_DIR}${M0_ENTRYPOINT_PATH}
      install -m 0644 (expanded) ds-entrypoint.service \\
        ${ROOTFS_DIR}/etc/systemd/system/ds-entrypoint.service
      chroot ${ROOTFS_DIR} systemctl enable ds-entrypoint.service
    The binary is a SEPARATE task (proto runtime/v1 unfrozen); if absent the
    unit is staged anyway and fails closed at boot (ConditionFileIsExecutable),
    which is the expected M0-skeleton state.

 5a. Stage the gap-1 config-drive mount unit + the gap-3 attach forwarder.
      # The host attaches a per-session READ-ONLY config-drive (a 2nd disk holding
      # config.pb, built host-side by configdrive.go). This unit mounts it at
      # ${M0_ENTRYPOINT_CONFIG_DIR} by LABEL=${M0_CONFIG_DRIVE_LABEL} (${M0_CONFIG_DRIVE_FS}),
      # ordered Before=ds-entrypoint.service so loadConfig finds config.pb.
      install -m 0644 (expanded) run-ds-entrypoint.mount \\
        ${ROOTFS_DIR}/etc/systemd/system/run-ds-entrypoint.mount
      chroot ${ROOTFS_DIR} systemctl enable run-ds-entrypoint.mount
      # The attach carriage forwarder (vm/attachfwd): LISTENs on the guest UDS
      # ${M0_ATTACHFWD_UDS_PATH} (ds-entrypoint dials it) and AF_VSOCK :${M0_ATTACH_PORT}
      # (the host-agent bridge dials guestCID:${M0_ATTACH_PORT} over virtio-vsock). Staged
      # at ${M0_ATTACHFWD_PATH}, started Before=ds-entrypoint.service. The binary is
      # a SEPARATE task (vm/attachfwd); if absent the unit fails closed at boot
      # (ConditionFileIsExecutable), the expected M0-skeleton state.
      install -m 0755 <ds-attachfwd artifact> ${M0_ATTACHFWD_PATH}
      install -m 0644 (expanded) ds-attachfwd.service \\
        ${ROOTFS_DIR}/etc/systemd/system/ds-attachfwd.service
      chroot ${ROOTFS_DIR} systemctl enable ds-attachfwd.service
      # /run is tmpfs (wiped each boot); a tmpfiles.d drop-in materializes /run/ds
      # (owned by ds) early so ds-attachfwd's UDS bind does not race the config-drive
      # mount and crash-loop on the absent directory (live-found 2026-06-16).
      install -m 0644 guest-config/ds-runtime-dir.conf \\
        ${ROOTFS_DIR}/etc/tmpfiles.d/ds-runtime-dir.conf
    The host<->guest :${M0_ATTACH_PORT} tap NFT allow is nft4's (a DECLARED
    dependency, NOT written by this image): the forwarder only LISTENs; the
    host-side per-session allow rule scopes who may dial it.

 5b. Stage the U4 per-session guest static net config apply (script + unit).
      # For the VM to egress over the ROUTED TAP, the guest must address its tap NIC
      # with the static per-session address + default route. The host renders those
      # L3 facts (10.77.<idx>.1/31 via 10.77.<idx>.0) into a SECOND config-drive file
      # ${M0_NETCFG_FILE} (only when the routed tap is active; configdrive.go/netconfig.go).
      # This script reads it and applies ip addr/route; it NO-OPS when ${M0_NETCFG_FILE}
      # is absent (the SLIRP/offline path is byte-identical). The unit runs it
      # Before=ds-entrypoint.service so the guest network is configured before the
      # entrypoint launches the egressing runtime.
      install -m 0755 (expanded) ds-apply-netcfg.sh ${ROOTFS_DIR}${M0_NETCFG_SCRIPT_PATH}
      install -m 0644 (expanded) ds-netcfg.service \\
        ${ROOTFS_DIR}/etc/systemd/system/ds-netcfg.service
      chroot ${ROOTFS_DIR} systemctl enable ds-netcfg.service
    The tap + the per-session gateway themselves are U3 / the dataplane nft4 lane
    (a DECLARED dependency, NOT written by this image): this script only addresses
    the NIC the host wired.

 5c. Stage the SLIRP DHCP .network + ds-slirp-net.service; enable systemd-networkd.
      # WITHOUT this the M0-minimal SLIRP NIC gets no IP/DNS (no DHCP client) and CC
      # loops on api_retry forever (live-found 2026-06-18). The DHCP .network is STAGED
      # at ${M0_SLIRP_NETWORK_STAGE} — a NON-networkd-search path — so networkd does NOT
      # auto-load it at boot. ds-slirp-net.service installs it into /run/systemd/network
      # + reloads networkd ONLY when the routed-tap signal ${M0_NETCFG_FILE} is ABSENT
      # (ConditionPathExists=!). On a routed-tap boot the .network is never loaded, so
      # its [Match] provably cannot catch the tap (ds-netcfg.service owns that NIC).
      install -m 0644 (expanded) ds-slirp-dhcp.network ${ROOTFS_DIR}${M0_SLIRP_NETWORK_STAGE}
      install -m 0644 (expanded) ds-slirp-net.service \\
        ${ROOTFS_DIR}/etc/systemd/system/ds-slirp-net.service
      chroot ${ROOTFS_DIR} systemctl enable systemd-networkd.service
      chroot ${ROOTFS_DIR} systemctl enable ds-slirp-net.service
    systemd-networkd ships in the Debian ${M0_BASE_SUITE} \`systemd\` package (pulled
    by systemd-sysv in step 1); the bake asserts /lib/systemd/systemd-networkd is
    present and fails closed if a future base splits it into a separate package.

 6. Pin git remotes to HTTPS (D83/§5.3; aligned with doc 09 POL-2 baseline).
      install -D -m 0644 guest-config/git-https-pin.gitconfig \\
        ${ROOTFS_DIR}/etc/gitconfig
    Bakes the system git config so an accidental git-over-SSH path cannot
    silently bypass the credential-swap + scanning planes: an insteadOf rewrite
    folds the SSH remote forms onto https://github.com/, and a credential helper
    carries the host-injected PAT over HTTPS (the real long-lived credential
    never enters the VM — the TLS-terminating egress gateway swaps it in
    outside the guest, doc 16 §5). The install is idempotent (install(1) to a
    fixed path overwrites). SSH-git is a TESTED non-goal: vm/m0-image/verify-git-pin.sh.
    (rendered gitconfig below.)

 7. Leave the D17 trust-store injection point. The image ships a real glibc
    trust store (ca-certificates, step 1); the host agent injects the
    per-session CA bundle at create (doc 15 §4.1 step 7) — the image only
    provides the store, it NEVER generates CA material (identity/mint owns that).

 8. Convert the rootfs to a raw disk, then wrap as qcow2 for hand-build/boot
    convenience (D29: raw base at rest on the M0 host).
      ${QEMU_IMG} create -f qcow2 ${OUT_QCOW} ${M0_DISK_VIRTUAL_SIZE}
      # (partition, mkfs ext4, copy rootfs, install a bootloader/kernel —
      #  the operator's preferred path; on ESXi the same raw base is the qcow2
      #  backing file under each session overlay.)

Rendered D75 sysctl drop-in (egress NIC enp1s0 shown):
$(expand_ipv6_dropin enp1s0 | sed 's/^/    /')

Rendered ds-entrypoint.service (tokens expanded):
$(expand_entrypoint_unit | sed 's/^/    /')

Rendered run-ds-entrypoint.mount (gap-1 config-drive; tokens expanded):
$(expand_configdrive_mount | sed 's/^/    /')

Rendered ds-attachfwd.service (gap-3 attach carriage; tokens expanded):
$(expand_attachfwd_unit | sed 's/^/    /')

Rendered ds-apply-netcfg.sh (U4 per-session net config; tokens expanded):
$(expand_netcfg_script | sed 's/^/    /')

Rendered ds-netcfg.service (U4; tokens expanded):
$(expand_netcfg_unit | sed 's/^/    /')

Rendered ds-slirp-dhcp.network (SLIRP DHCP; staged off networkd's search path; tokens expanded):
$(expand_slirp_network | sed 's/^/    /')

Rendered ds-slirp-net.service (SLIRP DHCP installer, gated off the routed tap; tokens expanded):
$(expand_slirp_net_unit | sed 's/^/    /')

Baked git-over-HTTPS pin (/etc/gitconfig; D83/§5.3):
$(emit_git_pin | sed 's/^/    /')

Boot validation: vm/m0-image/boot-validate.sh (sudo-free user qemu under
~/.local/opt/qemu). Boot-on-ESXi validation is the HUMAN follow-up task.
EOF
}

validate_inputs() {
  step "validate pins + guest-config (no privileges needed)"
  local ok=1
  [ -n "${M0_CC_VERSION:-}" ] || { echo "  MISSING M0_CC_VERSION" >&2; ok=0; }
  [ -n "${M0_ENTRYPOINT_PATH:-}" ] || { echo "  MISSING M0_ENTRYPOINT_PATH" >&2; ok=0; }
  [ -n "${M0_CONFIG_DRIVE_LABEL:-}" ] || { echo "  MISSING M0_CONFIG_DRIVE_LABEL" >&2; ok=0; }
  [ -n "${M0_CONFIG_DRIVE_FS:-}" ] || { echo "  MISSING M0_CONFIG_DRIVE_FS" >&2; ok=0; }
  [ -n "${M0_ATTACHFWD_PATH:-}" ] || { echo "  MISSING M0_ATTACHFWD_PATH" >&2; ok=0; }
  [ -n "${M0_ATTACHFWD_UDS_PATH:-}" ] || { echo "  MISSING M0_ATTACHFWD_UDS_PATH" >&2; ok=0; }
  [ -n "${M0_ATTACH_PORT:-}" ] || { echo "  MISSING M0_ATTACH_PORT" >&2; ok=0; }
  [ -n "${M0_NETCFG_SCRIPT_PATH:-}" ] || { echo "  MISSING M0_NETCFG_SCRIPT_PATH" >&2; ok=0; }
  [ -n "${M0_NETCFG_FILE:-}" ] || { echo "  MISSING M0_NETCFG_FILE" >&2; ok=0; }
  [ -n "${M0_SLIRP_NETWORK_STAGE:-}" ] || { echo "  MISSING M0_SLIRP_NETWORK_STAGE" >&2; ok=0; }
  [ -n "${M0_PTY_TERM:-}" ] || { echo "  MISSING M0_PTY_TERM" >&2; ok=0; }
  [ -f "${HERE}/guest-config/99-ds-disable-ipv6.conf" ] || { echo "  MISSING ipv6 drop-in" >&2; ok=0; }
  [ -f "${HERE}/guest-config/ds-entrypoint.service" ] || { echo "  MISSING entrypoint unit" >&2; ok=0; }
  [ -f "${HERE}/guest-config/run-ds-entrypoint.mount" ] || { echo "  MISSING config-drive mount unit" >&2; ok=0; }
  [ -f "${HERE}/guest-config/ds-attachfwd.service" ] || { echo "  MISSING attach forwarder unit" >&2; ok=0; }
  [ -f "${HERE}/guest-config/ds-apply-netcfg.sh" ] || { echo "  MISSING net-config apply script" >&2; ok=0; }
  [ -f "${HERE}/guest-config/ds-netcfg.service" ] || { echo "  MISSING net-config unit" >&2; ok=0; }
  [ -f "${HERE}/guest-config/ds-slirp-dhcp.network" ] || { echo "  MISSING SLIRP DHCP .network" >&2; ok=0; }
  [ -f "${HERE}/guest-config/ds-slirp-net.service" ] || { echo "  MISSING SLIRP DHCP installer unit" >&2; ok=0; }
  [ -f "${HERE}/guest-config/ds-runtime-dir.conf" ] || { echo "  MISSING /run/ds tmpfiles drop-in" >&2; ok=0; }
  [ -f "${HERE}/guest-config/git-https-pin.gitconfig" ] || { echo "  MISSING git-https pin config" >&2; ok=0; }
  # The expanded drop-in must still carry disable_ipv6=1 and must NOT touch lo
  # or kernel ipv6.disable (D75 invariants). Inspect only ACTIVE sysctl lines —
  # strip comments (which legitimately quote the forbidden forms in prose) so
  # the guard reasons about settings, not the file's own documentation.
  local rendered; rendered="$(expand_ipv6_dropin enp1s0 | grep -vE '^[[:space:]]*#' | grep -vE '^[[:space:]]*$')"
  printf '%s\n' "$rendered" | grep -q 'net\.ipv6\.conf\.enp1s0\.disable_ipv6 = 1' \
    || { echo "  D75 VIOLATION: drop-in does not disable v6 on the egress NIC" >&2; ok=0; }
  printf '%s\n' "$rendered" | grep -Eq 'net\.ipv6\.conf\.(lo|all|default)\.' \
    && { echo "  D75 VIOLATION: drop-in touches lo/all/default (must be per-egress-NIC only)" >&2; ok=0; }
  printf '%s\n' "$rendered" | grep -q 'ipv6\.disable=1' \
    && { echo "  D75 VIOLATION: drop-in sets kernel ipv6.disable=1 (forbidden)" >&2; ok=0; }
  # The expanded unit must launch the pinned entrypoint path and be fail-closed.
  local unit; unit="$(expand_entrypoint_unit)"
  printf '%s\n' "$unit" | grep -q "ExecStart=${M0_ENTRYPOINT_PATH}" \
    || { echo "  D38 VIOLATION: unit ExecStart != M0_ENTRYPOINT_PATH" >&2; ok=0; }
  printf '%s\n' "$unit" | grep -q "ConditionFileIsExecutable=${M0_ENTRYPOINT_PATH}" \
    || { echo "  unit not fail-closed on missing entrypoint" >&2; ok=0; }

  # The expanded config-drive mount unit (gap-1) must: mount the drive by the
  # host-stamped LABEL, mount it at the config-ref dir, use the host's fs, be
  # read-only, and be ordered BEFORE ds-entrypoint.service (so loadConfig finds
  # config.pb). The unit FILE NAME must be the systemd-escaped mount path, else
  # systemd rejects it — assert run-ds-entrypoint == /run/ds/entrypoint.
  local mount_unit; mount_unit="$(expand_configdrive_mount)"
  printf '%s\n' "$mount_unit" | grep -q "What=/dev/disk/by-label/${M0_CONFIG_DRIVE_LABEL}" \
    || { echo "  gap-1 VIOLATION: mount unit What != config-drive LABEL" >&2; ok=0; }
  printf '%s\n' "$mount_unit" | grep -q "Where=${M0_ENTRYPOINT_CONFIG_DIR}" \
    || { echo "  gap-1 VIOLATION: mount unit Where != M0_ENTRYPOINT_CONFIG_DIR" >&2; ok=0; }
  printf '%s\n' "$mount_unit" | grep -q "Type=${M0_CONFIG_DRIVE_FS}" \
    || { echo "  gap-1 VIOLATION: mount unit Type != M0_CONFIG_DRIVE_FS (configdrive.go fs)" >&2; ok=0; }
  printf '%s\n' "$mount_unit" | grep -Eq '^Options=.*\bro\b' \
    || { echo "  gap-1 VIOLATION: mount unit is not read-only (Options=ro)" >&2; ok=0; }
  printf '%s\n' "$mount_unit" | grep -q 'Before=ds-entrypoint.service' \
    || { echo "  gap-1 VIOLATION: mount unit not ordered Before=ds-entrypoint.service" >&2; ok=0; }
  # systemd mount-unit name == escaped mount path: /run/ds/entrypoint -> run-ds-entrypoint
  local escaped="${M0_ENTRYPOINT_CONFIG_DIR#/}"; escaped="${escaped//\//-}"
  [ "${escaped}.mount" = "run-ds-entrypoint.mount" ] \
    || { echo "  gap-1 VIOLATION: mount unit file name != systemd-escaped ${M0_ENTRYPOINT_CONFIG_DIR} (${escaped}.mount)" >&2; ok=0; }

  # The expanded attach-forwarder unit (gap-3) must: launch the pinned forwarder
  # path bound to the UDS + the AF_VSOCK :PORT carriage, be fail-closed on a missing
  # binary, and be ordered BEFORE ds-entrypoint.service (it serves the UDS the
  # entrypoint dials). The vsock port must match M0_ATTACH_PORT (== host-side
  # DefaultAttachPort the host-agent dials guestCID:port over virtio-vsock).
  local fwd_unit; fwd_unit="$(expand_attachfwd_unit)"
  printf '%s\n' "$fwd_unit" | grep -q "ExecStart=${M0_ATTACHFWD_PATH} " \
    || { echo "  gap-3 VIOLATION: forwarder unit ExecStart != M0_ATTACHFWD_PATH" >&2; ok=0; }
  printf '%s\n' "$fwd_unit" | grep -q -- "--uds-path ${M0_ATTACHFWD_UDS_PATH}" \
    || { echo "  gap-3 VIOLATION: forwarder unit --uds-path != M0_ATTACHFWD_UDS_PATH" >&2; ok=0; }
  printf '%s\n' "$fwd_unit" | grep -q -- "--vsock-port ${M0_ATTACH_PORT}" \
    || { echo "  gap-3 VIOLATION: forwarder unit --vsock-port != M0_ATTACH_PORT" >&2; ok=0; }
  printf '%s\n' "$fwd_unit" | grep -q "ConditionFileIsExecutable=${M0_ATTACHFWD_PATH}" \
    || { echo "  gap-3 VIOLATION: forwarder unit not fail-closed on missing binary" >&2; ok=0; }
  printf '%s\n' "$fwd_unit" | grep -q 'Before=ds-entrypoint.service' \
    || { echo "  gap-3 VIOLATION: forwarder unit not ordered Before=ds-entrypoint.service" >&2; ok=0; }

  # The expanded U4 net-config script must: read the host-stamped net-config file
  # name (M0_NETCFG_FILE == netconfig.go netConfigFileName) from the config dir,
  # consume the three renderer keys, and NO-OP when the file is absent (the SLIRP
  # path). The expanded service unit must run the script path Before=ds-entrypoint,
  # NOT gate on network-online (it brings the NIC up), and be fail-closed on a
  # missing script (ConditionPathExists).
  # The script builds the net-config path from the expanded config dir + file-name
  # tokens (held in a shell variable); assert BOTH expanded tokens appear and that
  # the absent-file no-op + the three renderer keys are present.
  local netcfg_script; netcfg_script="$(expand_netcfg_script)"
  printf '%s\n' "$netcfg_script" | grep -qF "${M0_ENTRYPOINT_CONFIG_DIR}" \
    || { echo "  U4 VIOLATION: net-config script does not reference M0_ENTRYPOINT_CONFIG_DIR" >&2; ok=0; }
  printf '%s\n' "$netcfg_script" | grep -qF "${M0_NETCFG_FILE}" \
    || { echo "  U4 VIOLATION: net-config script does not reference the host-stamped net-config file name M0_NETCFG_FILE" >&2; ok=0; }
  for k in DS_NET_GUEST_IP DS_NET_PREFIX DS_NET_GATEWAY; do
    printf '%s\n' "$netcfg_script" | grep -q "$k" \
      || { echo "  U4 VIOLATION: net-config script does not consume the renderer key $k" >&2; ok=0; }
  done
  # The expanded service unit (reason about ACTIVE lines only — the header comments
  # legitimately quote network-online.target in prose explaining why it is forbidden).
  local netcfg_unit; netcfg_unit="$(expand_netcfg_unit | grep -vE '^[[:space:]]*#' | grep -vE '^[[:space:]]*$')"
  printf '%s\n' "$netcfg_unit" | grep -q "ExecStart=${M0_NETCFG_SCRIPT_PATH}" \
    || { echo "  U4 VIOLATION: net-config unit ExecStart != M0_NETCFG_SCRIPT_PATH" >&2; ok=0; }
  printf '%s\n' "$netcfg_unit" | grep -q "ConditionPathExists=${M0_NETCFG_SCRIPT_PATH}" \
    || { echo "  U4 VIOLATION: net-config unit not fail-closed on a missing script" >&2; ok=0; }
  printf '%s\n' "$netcfg_unit" | grep -q 'Before=ds-entrypoint.service' \
    || { echo "  U4 VIOLATION: net-config unit not ordered Before=ds-entrypoint.service" >&2; ok=0; }
  printf '%s\n' "$netcfg_unit" | grep -qE 'network-online\.target' \
    && { echo "  U4 VIOLATION: net-config unit gates on network-online.target (it BRINGS the NIC up — would deadlock)" >&2; ok=0; }

  # The D83/§5.3 git pin must rewrite the SSH github remote forms onto HTTPS and
  # carry a credential helper (the HTTPS auth path). Reason about ACTIVE config
  # only — the file's header comments legitimately quote the ssh forms in prose.
  local pin; pin="$(emit_git_pin | grep -vE '^[[:space:]]*#' | grep -vE '^[[:space:]]*$')"
  printf '%s\n' "$pin" | grep -q 'insteadOf = ssh://git@github.com/' \
    || { echo "  §5.3 VIOLATION: git pin has no ssh:// insteadOf rewrite for github" >&2; ok=0; }
  printf '%s\n' "$pin" | grep -q 'insteadOf = git@github.com:' \
    || { echo "  §5.3 VIOLATION: git pin has no scp-style insteadOf rewrite for github" >&2; ok=0; }
  printf '%s\n' "$pin" | grep -q 'helper = ' \
    || { echo "  §5.3 VIOLATION: git pin configures no credential helper (HTTPS auth carrier)" >&2; ok=0; }
  # An inverted rewrite (https->ssh) would silently escape the egress gateway.
  printf '%s\n' "$pin" | grep -q 'insteadOf = https://github.com/' \
    && { echo "  §5.3 VIOLATION: git pin inverts the rewrite (https->ssh) — escapes the egress gateway" >&2; ok=0; }

  # The terminal/PTY-mode TERM pin (doc serpent-cli-mvp 02 §2.9 / 10 §A2). --plan
  # cannot open the real image, so it validates the pin is well-formed and that the
  # bake-time terminfo-exists assertion (do_build step 4a) is consistent with it: the
  # name maps to a non-empty terminfo subpath the bake will look up under the ncurses
  # roots. The HARD image-level "the entry actually exists in the rootfs" assertion
  # lives in the real --build path (it is the one that can stat the rootfs).
  case "$M0_PTY_TERM" in
    */* | "" ) echo "  PTY VIOLATION: M0_PTY_TERM='${M0_PTY_TERM}' is not a bare TERM name" >&2; ok=0 ;;
  esac
  local tisub; tisub="$(terminfo_subpath "$M0_PTY_TERM")"
  [ "${tisub}" = "${M0_PTY_TERM:0:1}/${M0_PTY_TERM}" ] \
    || { echo "  PTY VIOLATION: terminfo subpath for '${M0_PTY_TERM}' did not derive (${tisub})" >&2; ok=0; }

  [ "$ok" = 1 ] && log "inputs OK" || { echo "build-m0-image: input validation FAILED" >&2; exit 1; }
}

# ── --build state + cleanup (robust teardown on ANY exit) ────────────────────
# Bake-time mutable state the trap unwinds. Recorded as we go so a failure at any
# step leaves NO dangling bind-mounts or loop devices behind (the #1 footgun of a
# debootstrap/losetup bake). The trap is installed by do_build (not at file scope)
# so the --plan path is untouched.
DS_BAKE_MNT=""          # the assembled-disk mount point (mounted last, unmount first)
DS_BAKE_LOOP=""         # the losetup device backing the raw disk
declare -a DS_BAKE_BINDS=()  # chroot bind mounts (/dev,/dev/pts,/proc,/sys,/run), unmount in reverse

bake_cleanup() {
  local rc=$?
  set +e
  # Unmount the chroot bind mounts in REVERSE order (children before parents).
  local i
  for (( i=${#DS_BAKE_BINDS[@]}-1 ; i>=0 ; i-- )); do
    mountpoint -q "${DS_BAKE_BINDS[$i]}" && umount -l "${DS_BAKE_BINDS[$i]}" 2>/dev/null
  done
  # Unmount the assembled-disk root, then detach the loop device.
  if [ -n "${DS_BAKE_MNT}" ] && mountpoint -q "${DS_BAKE_MNT}" 2>/dev/null; then
    umount -R "${DS_BAKE_MNT}" 2>/dev/null || umount -l "${DS_BAKE_MNT}" 2>/dev/null
  fi
  if [ -n "${DS_BAKE_LOOP}" ] && [ -e "${DS_BAKE_LOOP}" ]; then
    losetup -d "${DS_BAKE_LOOP}" 2>/dev/null
  fi
  if [ "$rc" -ne 0 ]; then
    echo "build-m0-image: --build FAILED (rc=$rc) — cleaned up mounts/loop; rootfs at ${ROOTFS_DIR} is reusable on re-run." >&2
  fi
}

# Bind-mount a chroot kernel filesystem and record it for teardown.
bake_bind() {
  local what="$1" where="$2" type="${3:-}"
  mkdir -p "${where}"
  if [ -n "${type}" ]; then
    mount -t "${type}" "${what}" "${where}"
  else
    mount --bind "${what}" "${where}"
  fi
  DS_BAKE_BINDS+=("${where}")
}

# Bind the standard chroot kernel filesystems into ${ROOTFS_DIR}, run a command in
# the chroot, then unmount them (reverse order). Keeps apt/dpkg/grub/systemctl in
# the chroot from racing on a /proc or /sys that is not present.
bake_chroot_with_kfs() {
  local rootfs="$1"; shift
  local before=${#DS_BAKE_BINDS[@]}
  bake_bind /dev      "${rootfs}/dev"
  bake_bind /dev/pts  "${rootfs}/dev/pts"
  bake_bind proc      "${rootfs}/proc" proc
  bake_bind sysfs     "${rootfs}/sys"  sysfs
  bake_bind tmpfs     "${rootfs}/run"  tmpfs
  # Capture the chroot's status WITHOUT letting `set -e` abort here, so the inline
  # kfs-unmount below always runs (the EXIT trap is the backstop, but unmount the
  # transient kfs eagerly so a later step's bind does not stack on a stale mount).
  local rc=0
  chroot "${rootfs}" "$@" || rc=$?
  # Unmount just the kfs we added here, in reverse, and drop them from the list.
  local i
  for (( i=${#DS_BAKE_BINDS[@]}-1 ; i>=before ; i-- )); do
    mountpoint -q "${DS_BAKE_BINDS[$i]}" && umount -l "${DS_BAKE_BINDS[$i]}" 2>/dev/null
    unset 'DS_BAKE_BINDS[i]'
  done
  DS_BAKE_BINDS=("${DS_BAKE_BINDS[@]}")  # re-pack the array
  return $rc
}

# Build a guest Go binary static/portable (CGO_ENABLED=0) so it runs on the Debian
# guest regardless of this build host's libc, and install it into the rootfs. The
# binary is built from its tree subdir with the relative package path (the vm/ tree
# is one Go module rooted at vm/go.mod).
bake_install_guest_bin() {
  local tree="$1" pkg="$2" dest_in_rootfs="$3" tmp
  tmp="$(mktemp "${DS_IMAGES_DIR}/.bake-bin.XXXXXX")"
  log "building ${pkg} (CGO_ENABLED=0, static) from ${tree}"
  ( cd "${HERE}/../../${tree}" \
      && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "${tmp}" "${pkg}" )
  install -D -m 0755 "${tmp}" "${ROOTFS_DIR}${dest_in_rootfs}"
  rm -f "${tmp}"
  log "staged ${dest_in_rootfs} (0755)"
}

do_build() {
  # ── preconditions ──────────────────────────────────────────────────────────
  if [ "$(id -u)" -ne 0 ]; then
    echo "build-m0-image: --build must run as root (debootstrap/chroot/losetup/mkfs/mount/grub need it)." >&2
    echo "  sudo env DS_IMAGES_DIR=${DS_IMAGES_DIR} $0 --build" >&2
    exit 3
  fi
  # Host tools the bake calls OUTSIDE the chroot. grub-pc/update-grub are NOT here:
  # they are installed INTO and run FROM the chroot (step 8a), so the build host
  # itself need not be Debian/grub-pc — only debootstrap + loop/partition tooling.
  local missing=()
  for t in debootstrap chroot losetup mkfs.ext4 mount umount mountpoint rsync parted blkid "${QEMU_IMG}"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  command -v go >/dev/null 2>&1 || missing+=(go)
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "build-m0-image: --build is missing host tools: ${missing[*]}" >&2
    echo "  Install them (Debian: debootstrap parted rsync qemu-utils golang-go util-linux; grub-pc is pulled INTO the chroot) and re-run." >&2
    exit 3
  fi

  # Robust teardown of every mount/loop on ANY exit from here on.
  trap bake_cleanup EXIT

  local CLEAN="${DS_BAKE_CLEAN:-0}"

  # ── step 1: debootstrap the glibc rootfs (idempotent) ──────────────────────
  step "1. debootstrap ${M0_BASE_SUITE} glibc rootfs -> ${ROOTFS_DIR}"
  local mirror="${M0_DEB_MIRROR:-deb.debian.org/debian}"
  if [ "${CLEAN}" = 1 ] && [ -d "${ROOTFS_DIR}" ]; then
    log "DS_BAKE_CLEAN=1: removing existing ${ROOTFS_DIR} for a fresh debootstrap"
    rm -rf "${ROOTFS_DIR}"
  fi
  if [ -x "${ROOTFS_DIR}/bin/bash" ] || [ -x "${ROOTFS_DIR}/usr/bin/bash" ]; then
    log "rootfs already populated at ${ROOTFS_DIR} — skipping debootstrap (DS_BAKE_CLEAN=1 to force)"
  else
    mkdir -p "${ROOTFS_DIR}"
    # dbus is EXPLICIT: systemd only Recommends it and minbase pulls no Recommends,
    # so without it `networkctl reload` (ds-slirp-net.service step 3) has no system
    # bus to call over and the SLIRP DHCP install fails (live-found 2026-07-29).
    # Keep token-identical with the --plan quote of this line above.
    debootstrap --variant=minbase \
      --include=systemd-sysv,ca-certificates,curl,dbus \
      "${M0_BASE_SUITE}" "${ROOTFS_DIR}" "http://${mirror}"
    log "debootstrap complete"
  fi
  # ca-certificates from step 1 IS the D17 trust-store injection point (step 7).
  [ -d "${ROOTFS_DIR}/etc/ssl/certs" ] \
    || { echo "build-m0-image: rootfs has no /etc/ssl/certs trust store (step 1 ca-certificates failed?)" >&2; exit 1; }

  # ── step 2: unprivileged 'ds' user + config-ref dir ────────────────────────
  step "2. create the unprivileged 'ds' guest user + ${M0_ENTRYPOINT_CONFIG_DIR}"
  if chroot "${ROOTFS_DIR}" id ds >/dev/null 2>&1; then
    log "user 'ds' already exists — skipping useradd"
  else
    chroot "${ROOTFS_DIR}" useradd --create-home --shell /usr/sbin/nologin ds
  fi
  # The config-ref dir is the config-drive mount point; /run is tmpfs at runtime
  # (the ds-runtime-dir.conf tmpfiles drop-in recreates it each boot), but stage
  # the dir + parent in the image so the mount unit's Where= resolves.
  install -d -m 0750 -o ds -g ds "${ROOTFS_DIR}${M0_ENTRYPOINT_CONFIG_DIR}"

  # ── step 3: node + the D49-pinned Claude Code runtime ──────────────────────
  step "3. install node ${M0_NODE_MAJOR} + @anthropic-ai/claude-code@${M0_CC_VERSION} (D49)"
  # Under sudo the TLS-intercepting egress proxy env is stripped, so the in-chroot
  # apt/npm pulls go DIRECT (the UNABLE_TO_VERIFY_LEAF_SIGNATURE drift in
  # client/wrapper/DRIVE-FINDINGS.md §1 does not bite). Install node from NodeSource
  # if the suite's nodejs is older than M0_NODE_MAJOR; bookworm ships node 18, so
  # NodeSource is the default path for node 22.
  # shellcheck disable=SC2016  # the '...' body runs in the chroot's /bin/sh and must
  # stay LITERAL; only the explicitly-spliced "${M0_NODE_MAJOR}" expands on the host.
  bake_chroot_with_kfs "${ROOTFS_DIR}" /bin/sh -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl gnupg
    # Try the distro nodejs first; fall back to NodeSource if it is too old.
    NEED_NODESOURCE=1
    if apt-cache policy nodejs 2>/dev/null | grep -qE "Candidate: '"${M0_NODE_MAJOR}"'\."; then
      NEED_NODESOURCE=0
    fi
    if [ "${NEED_NODESOURCE}" = 1 ]; then
      mkdir -p /etc/apt/keyrings
      curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
      echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_'"${M0_NODE_MAJOR}"'.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list
      apt-get update
    fi
    apt-get install -y --no-install-recommends nodejs
    node --version
    npm --version
  '
  # The global CC install. A failure here is NOT silently swallowed (step-3 prose):
  # point at the documented fallback (stage a pinned binary at /opt/claude-code/bin)
  # unless DS_BAKE_ALLOW_NO_CC=1 explicitly tolerates an M0-skeleton image without CC.
  # shellcheck disable=SC2016  # chroot /bin/sh body stays literal; only the spliced
  # "${M0_CC_VERSION}" expands on the host (the npm version pin).
  if bake_chroot_with_kfs "${ROOTFS_DIR}" /bin/sh -euc '
        npm install -g "@anthropic-ai/claude-code@'"${M0_CC_VERSION}"'"
        command -v claude || ls -l "$(npm root -g)/@anthropic-ai/claude-code" >/dev/null
      '; then
    log "Claude Code ${M0_CC_VERSION} installed in the image"
  else
    echo "build-m0-image: npm install of @anthropic-ai/claude-code@${M0_CC_VERSION} FAILED." >&2
    echo "  This is the documented egress drift (client/wrapper/DRIVE-FINDINGS.md §1):" >&2
    echo "  an in-image npm install can fail UNABLE_TO_VERIFY_LEAF_SIGNATURE under a" >&2
    echo "  TLS-intercepting egress. Fallbacks:" >&2
    echo "    - bake behind a CA-aware pull-through cache (D41), OR" >&2
    echo "    - stage a known-good pinned ${M0_CC_VERSION} binary at" >&2
    echo "      ${ROOTFS_DIR}/opt/claude-code/bin/claude (the cc_sandbox.sh fallback)," >&2
    echo "      then re-run with DS_BAKE_ALLOW_NO_CC=1." >&2
    if [ "${DS_BAKE_ALLOW_NO_CC:-0}" = 1 ]; then
      log "DS_BAKE_ALLOW_NO_CC=1: continuing WITHOUT the pinned CC runtime (M0-skeleton image)"
    else
      exit 1
    fi
  fi

  # ── step 4: D75 IPv6 drop-in per egress NIC ────────────────────────────────
  step "4. bake the D75 per-egress-NIC IPv6 drop-in (${M0_EGRESS_NIC_GLOB})"
  # sysctl.d cannot glob interface names. At runtime the routed-tap NIC name is not
  # known until boot, so we render the canonical virtio-net name (enp1s0) — the same
  # name --plan renders and boot-validate asserts. (A booted-NIC enumeration is the
  # ESXi follow-up; enp1s0 is the M0 virtio-net name under qemu/libvirt q35.)
  install -d -m 0755 "${ROOTFS_DIR}/etc/sysctl.d"
  expand_ipv6_dropin enp1s0 > "${ROOTFS_DIR}/etc/sysctl.d/99-ds-disable-ipv6.conf"
  log "staged /etc/sysctl.d/99-ds-disable-ipv6.conf (egress NIC enp1s0)"

  # ── step 4a: HARD terminfo-exists assertion for the PTY-mode TERM ──────────
  step "4a. assert the ${M0_PTY_TERM} terminfo entry is present (terminal/PTY mode)"
  # The interactive CC TUI runs under a pty in terminal mode with TERM=${M0_PTY_TERM}
  # (a host-resolved LaunchSpec.env fact; doc serpent-cli-mvp 02 §2.9). A usable TUI
  # requires the matching terminfo entry IN THE IMAGE — a missing entry yields a
  # garbled terminal (doc 02 R4). ncurses-base (pulled by the minbase + systemd
  # debootstrap) ships /lib/terminfo/x/xterm-256color; assert it is really in the
  # rootfs so a slimmed base or a future TERM bump can't silently break the TUI.
  # FAIL the bake if absent (no new install: the base already carries it; if a
  # future base drops it, the operator adds ncurses-base/ncurses-term explicitly).
  local tisub; tisub="$(terminfo_subpath "${M0_PTY_TERM}")"
  local found_terminfo=""
  for root in "${M0_TERMINFO_ROOTS[@]}"; do
    if [ -f "${ROOTFS_DIR}${root}/${tisub}" ]; then found_terminfo="${root}/${tisub}"; break; fi
  done
  if [ -z "${found_terminfo}" ]; then
    echo "build-m0-image: terminfo entry for TERM=${M0_PTY_TERM} is ABSENT in the rootfs." >&2
    echo "  Looked under: ${M0_TERMINFO_ROOTS[*]/%//${tisub}}" >&2
    echo "  The interactive CC TUI (terminal/PTY mode) needs this terminfo entry or it" >&2
    echo "  renders garbled (doc serpent-cli-mvp 02 R4). On Debian it ships in" >&2
    echo "  ncurses-base (/lib/terminfo/${tisub}); install ncurses-base/ncurses-term" >&2
    echo "  into the rootfs and re-run, or correct M0_PTY_TERM to an entry the base carries." >&2
    exit 1
  fi
  log "terminfo present: ${found_terminfo} (TERM=${M0_PTY_TERM})"

  # ── step 4b: workspace pre-trust seed so CC's first-run trust prompt is silent ─
  step "4b. seed CC workspace pre-trust for ${WORKDIR} (no first-run trust gate)"
  # CC's interactive TUI shows a first-run "Do you trust the files in this folder?"
  # prompt the first time it runs in a workspace; unanswered it BLOCKS the dev in a
  # fresh VM (doc serpent-cli-mvp 10 §B). CC records trust acceptance in the global
  # ~/.claude.json under a per-absolute-path key (NOT under CLAUDE_CONFIG_DIR — that
  # registry stays at $HOME/.claude.json even when CLAUDE_CONFIG_DIR is set). Seed it
  # so the working dir is already trusted + onboarding already seen. The launch HOME
  # is /home/ds and the working dir is /home/ds (scripts/live-mvp/ds-serve-stack.sh:
  # -working-dir /home/ds, HOME=/home/ds), so the registry file is /home/ds/.claude.json
  # keyed on /home/ds. The bytes carry NO credential (creds never enter the image,
  # D8/D39); this is a UX latch only.
  cat > "${ROOTFS_DIR}/home/ds/.claude.json" <<EOF
{
  "${WORKDIR}": {
    "hasTrustDialogAccepted": true,
    "hasCompletedProjectOnboarding": true,
    "projectOnboardingSeenCount": 1
  }
}
EOF
  chroot "${ROOTFS_DIR}" chown ds:ds /home/ds/.claude.json
  chmod 0600 "${ROOTFS_DIR}/home/ds/.claude.json"
  log "seeded /home/ds/.claude.json (workspace ${WORKDIR} pre-trusted; onboarding marked seen)"
  # NOTE (cross-tree, guest-launch / host-producer unit): the env-var path
  # CLAUDE_TRUST_WORKSPACE=1 (a LaunchSpec.env launch fact, not an image fact) is the
  # belt-and-suspenders complement — the guest-launch unit SHOULD also set it via
  # -launch-env CLAUDE_TRUST_WORKSPACE=1 (alongside HOME=/home/ds and
  # CLAUDE_CONFIG_DIR=/home/ds/.claude in ds-serve-stack.sh) so a different working dir
  # than /home/ds is still un-gated. TERM is NOT set by ds-serve-stack: in terminal mode
  # it is host-resolved by the orchestrator's applyLaunchMode (TERM=${M0_PTY_TERM}, see
  # DefaultTerminalTERM in orchestrator/internal/hypervisor/libvirt/sessionmode.go),
  # injected into LaunchSpec.env so the in-VM CC renders color — no rebake. This image
  # owns only the baked /home/ds seed; the env knobs are host-resolved (out of vm/m0-image).

  # ── step 5: D38 entrypoint binary + boot unit ──────────────────────────────
  step "5. stage the D38 entrypoint binary + ds-entrypoint.service"
  bake_install_guest_bin vm/entrypoint ./cmd/ds-entrypoint "${M0_ENTRYPOINT_PATH}"
  install -D -m 0644 /dev/stdin "${ROOTFS_DIR}/etc/systemd/system/ds-entrypoint.service" \
    <<<"$(expand_entrypoint_unit)"
  chroot "${ROOTFS_DIR}" systemctl enable ds-entrypoint.service

  # ── step 5a: gap-1 config-drive mount + gap-3 attach forwarder + /run/ds ────
  step "5a. stage the gap-1 config-drive mount unit + gap-3 attach forwarder"
  install -D -m 0644 /dev/stdin "${ROOTFS_DIR}/etc/systemd/system/run-ds-entrypoint.mount" \
    <<<"$(expand_configdrive_mount)"
  chroot "${ROOTFS_DIR}" systemctl enable run-ds-entrypoint.mount
  bake_install_guest_bin vm/attachfwd ./cmd/ds-attachfwd "${M0_ATTACHFWD_PATH}"
  install -D -m 0644 /dev/stdin "${ROOTFS_DIR}/etc/systemd/system/ds-attachfwd.service" \
    <<<"$(expand_attachfwd_unit)"
  chroot "${ROOTFS_DIR}" systemctl enable ds-attachfwd.service
  install -D -m 0644 "${HERE}/guest-config/ds-runtime-dir.conf" \
    "${ROOTFS_DIR}/etc/tmpfiles.d/ds-runtime-dir.conf"
  log "staged the /run/ds tmpfiles drop-in"

  # ── step 5b: U4 per-session net-config script + unit ───────────────────────
  step "5b. stage the U4 per-session net-config script + ds-netcfg.service"
  install -D -m 0755 /dev/stdin "${ROOTFS_DIR}${M0_NETCFG_SCRIPT_PATH}" \
    <<<"$(expand_netcfg_script)"
  install -D -m 0644 /dev/stdin "${ROOTFS_DIR}/etc/systemd/system/ds-netcfg.service" \
    <<<"$(expand_netcfg_unit)"
  chroot "${ROOTFS_DIR}" systemctl enable ds-netcfg.service

  # ── step 5c: SLIRP DHCP .network + installer unit + enable networkd ─────────
  step "5c. stage the SLIRP DHCP .network + ds-slirp-net.service; enable systemd-networkd"
  # Without a DHCP client the M0-minimal SLIRP NIC gets no IP/DNS and CC loops on
  # api_retry forever (live-found 2026-06-18). The DHCP .network is STAGED at
  # ${M0_SLIRP_NETWORK_STAGE} — a NON-networkd-search path — so networkd does NOT
  # auto-load it at boot. ds-slirp-net.service installs it into /run/systemd/network +
  # reloads networkd ONLY when the routed-tap signal ${M0_NETCFG_FILE} is ABSENT: on a
  # routed-tap boot the .network is never loaded, so its [Match] provably cannot catch
  # the tap (ds-netcfg.service owns that NIC there).
  # systemd-networkd ships in the Debian ${M0_BASE_SUITE} `systemd` package (pulled by
  # systemd-sysv, step 1). Assert it is really present and fail closed if a future base
  # splits it into a separate package (the operator would then add it explicitly).
  if [ ! -x "${ROOTFS_DIR}/lib/systemd/systemd-networkd" ] \
     && [ ! -x "${ROOTFS_DIR}/usr/lib/systemd/systemd-networkd" ]; then
    echo "build-m0-image: systemd-networkd is ABSENT in the rootfs (/lib/systemd/systemd-networkd)." >&2
    echo "  The SLIRP DHCP egress needs it; on Debian ${M0_BASE_SUITE} it ships in the systemd" >&2
    echo "  package (pulled by systemd-sysv). If a future base splits it out, add the" >&2
    echo "  networkd package to the step-1 debootstrap --include and re-run." >&2
    exit 1
  fi
  install -D -m 0644 /dev/stdin "${ROOTFS_DIR}${M0_SLIRP_NETWORK_STAGE}" \
    <<<"$(expand_slirp_network)"
  install -D -m 0644 /dev/stdin "${ROOTFS_DIR}/etc/systemd/system/ds-slirp-net.service" \
    <<<"$(expand_slirp_net_unit)"
  chroot "${ROOTFS_DIR}" systemctl enable systemd-networkd.service
  chroot "${ROOTFS_DIR}" systemctl enable ds-slirp-net.service
  log "staged SLIRP DHCP .network (${M0_SLIRP_NETWORK_STAGE}) + ds-slirp-net.service; enabled systemd-networkd"

  # ── step 6: git-over-HTTPS pin ─────────────────────────────────────────────
  step "6. install the D83/§5.3 git-over-HTTPS pin -> /etc/gitconfig"
  install -D -m 0644 "${HERE}/guest-config/git-https-pin.gitconfig" \
    "${ROOTFS_DIR}/etc/gitconfig"

  # ── step 7: D17 trust-store injection point (already present from step 1) ──
  step "7. confirm the D17 trust store is present (ca-certificates, step 1)"
  [ -d "${ROOTFS_DIR}/etc/ssl/certs" ] \
    || { echo "build-m0-image: /etc/ssl/certs missing — the D17 injection point is absent" >&2; exit 1; }
  log "trust store present at /etc/ssl/certs (host injects the per-session CA at create)"

  # ── step 8: make it bootable + emit raw + qcow2 ────────────────────────────
  step "8. install kernel + bootloader, build the raw disk, convert to qcow2"

  # 8a. Kernel + BIOS bootloader INTO the chroot. grub-pc (SeaBIOS/i386-pc) is the
  #     simplest path for qemu/libvirt; linux-image-amd64 pulls the guest kernel.
  #     A serial console (ttyS0) is wired so libvirt/qemu -serial works for debug.
  # shellcheck disable=SC2016  # chroot /bin/sh body + the heredoc are LITERAL by
  # design (\$GRUB_CMDLINE_LINUX must reach the generated grub config unexpanded).
  bake_chroot_with_kfs "${ROOTFS_DIR}" /bin/sh -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y --no-install-recommends linux-image-amd64 grub-pc
    # Serial console on the kernel cmdline (console=tty0 keeps the VGA console too).
    mkdir -p /etc/default/grub.d
    cat > /etc/default/grub.d/99-ds-serial.cfg <<EOF
GRUB_CMDLINE_LINUX="\$GRUB_CMDLINE_LINUX console=tty0 console=ttyS0,115200"
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"
GRUB_TIMEOUT=2
GRUB_DISABLE_OS_PROBER=true
EOF
    # A serial getty so the boot drops to a console over ttyS0 for the operator.
    systemctl enable serial-getty@ttyS0.service
  '

  # 8b. Create a RAW disk, MBR-partition a single bootable ext4 root, loop-mount it,
  #     copy the rootfs in, install grub to the loop MBR, set fstab by UUID.
  local raw="${OUT_QCOW%.qcow2}.raw"
  log "creating raw disk ${raw} (${M0_DISK_VIRTUAL_SIZE})"
  rm -f "${raw}"
  "${QEMU_IMG}" create -f raw "${raw}" "${M0_DISK_VIRTUAL_SIZE}"

  # Single bootable ext4 partition (type 83, *), 1MiB-aligned start for grub-pc.
  log "partitioning ${raw} (MBR, single bootable ext4 root)"
  parted -s "${raw}" mklabel msdos
  parted -s "${raw}" mkpart primary ext4 1MiB 100%
  parted -s "${raw}" set 1 boot on

  # Loop-mount with partition scanning so ${loop}p1 appears.
  DS_BAKE_LOOP="$(losetup --find --show --partscan "${raw}")"
  log "loop device: ${DS_BAKE_LOOP}"
  local part="${DS_BAKE_LOOP}p1"
  # Settle so the partition node exists before mkfs.
  for _ in 1 2 3 4 5; do [ -b "${part}" ] && break; udevadm settle 2>/dev/null || sleep 0.5; done
  [ -b "${part}" ] || { echo "build-m0-image: partition ${part} did not appear after partscan" >&2; exit 1; }

  local LABEL="DS_M0ROOT"
  log "mkfs.ext4 on ${part} (LABEL=${LABEL})"
  mkfs.ext4 -q -F -L "${LABEL}" "${part}"
  local uuid; uuid="$(blkid -s UUID -o value "${part}")"
  [ -n "${uuid}" ] || { echo "build-m0-image: could not read UUID of ${part}" >&2; exit 1; }

  DS_BAKE_MNT="${DS_IMAGES_DIR}/m0-mnt"
  mkdir -p "${DS_BAKE_MNT}"
  mount "${part}" "${DS_BAKE_MNT}"

  log "copying rootfs -> ${DS_BAKE_MNT}"
  rsync -aHAX --numeric-ids \
    --exclude='/dev/*' --exclude='/proc/*' --exclude='/sys/*' --exclude='/run/*' \
    "${ROOTFS_DIR}/" "${DS_BAKE_MNT}/"

  # Generate /etc/fstab: root by UUID (matches the kernel-found root partition).
  log "writing /etc/fstab (root by UUID=${uuid})"
  cat > "${DS_BAKE_MNT}/etc/fstab" <<EOF
# /etc/fstab — generated by build-m0-image.sh
UUID=${uuid}  /  ext4  errors=remount-ro  0  1
EOF

  # Install grub to the loop device MBR and generate grub.cfg against the assembled
  # disk. grub-install/update-grub run INSIDE the chroot (that is where grub-pc was
  # installed, step 8a — the build host need not be Debian/grub). The chroot's /dev
  # bind carries the loop device + its partition node; a device.map maps (hd0) ->
  # the loop device so grub installs i386-pc boot code to its MBR.
  log "installing grub (i386-pc) to ${DS_BAKE_LOOP} MBR + generating grub.cfg (in chroot)"
  mkdir -p "${DS_BAKE_MNT}/boot/grub"
  cat > "${DS_BAKE_MNT}/boot/grub/device.map" <<EOF
(hd0) ${DS_BAKE_LOOP}
EOF
  bake_chroot_with_kfs "${DS_BAKE_MNT}" /bin/sh -euc '
    grub-install --target=i386-pc --recheck \
      --boot-directory=/boot \
      --modules="part_msdos ext2 biosdisk" \
      "'"${DS_BAKE_LOOP}"'"
    # Generate grub.cfg referencing the in-image kernel/initrd by the fstab UUID
    # (root=UUID=…) + carrying the serial cmdline (from 99-ds-serial.cfg).
    update-grub
  '

  # Unmount the assembled disk + detach the loop (the trap would also do this, but
  # do it now so the raw is consistent before convert/chmod).
  sync
  umount -R "${DS_BAKE_MNT}"; DS_BAKE_MNT=""
  losetup -d "${DS_BAKE_LOOP}"; DS_BAKE_LOOP=""

  # 8c. The host-agent wants a READ-ONLY raw golden base (D29 invariant: mode 0444,
  #     asserted by live_smoke_test.go); keep the raw at ${raw} and also wrap a qcow2
  #     for hand-build/boot-test convenience (boot-validate.sh boots OUT_QCOW).
  log "converting raw -> qcow2 ${OUT_QCOW}"
  rm -f "${OUT_QCOW}"
  "${QEMU_IMG}" convert -O qcow2 "${raw}" "${OUT_QCOW}"
  # D29: the raw golden base is read-only at rest (per-session writes go to the qcow2
  # overlay the host backs onto it; the base is NEVER written through).
  chmod 0444 "${raw}"

  step "DONE"
  log "raw golden base (D29, 0444, host-agent --base-image): ${raw}"
  log "qcow2 (hand-build/boot convenience, boot-validate.sh OUT_QCOW): ${OUT_QCOW}"
  log "boot-test it: DS_BOOT=1 vm/m0-image/boot-validate.sh"
}

mkdir -p "${DS_IMAGES_DIR}"
validate_inputs
print_procedure
if [ "$MODE" = "--build" ]; then do_build; fi
log "done (${MODE})"
