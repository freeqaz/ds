#!/usr/bin/env bash
# ds-apply-netcfg.sh — apply the per-session GUEST static net config (U4).
#
# For the VM to egress over the ROUTED TAP (the nft4 keystone), the guest must
# address its tap NIC with the static per-session address + default route. The
# host renders those L3 facts into a SECOND file (ds-net.env) on the per-session
# read-only config-drive (orchestrator/internal/hypervisor/libvirt/netconfig.go),
# alongside config.pb. This script — run by ds-netcfg.service early at boot,
# BEFORE ds-entrypoint — reads that file and applies it.
#
# NO-OP WHEN ABSENT (the SLIRP/offline path, byte-identical to before U4): when
# the host runs the M0-minimal usermode SLIRP NIC (no routed tap) the host emits
# NO ds-net.env, so this script finds nothing and exits 0 cleanly. On that SLIRP
# path the NIC is instead addressed by DHCP — systemd-networkd applies the DHCP
# .network that ds-slirp-net.service installs, and that installer is itself gated to
# run ONLY when ds-net.env is ABSENT (ConditionPathExists=!<config-dir>/ds-net.env,
# this very same routed-tap signal). So networkd never touches the routed tap and
# never races this static apply; this script must never touch the SLIRP NIC. The
# file's PRESENCE is the routed-tap signal in-guest — exactly mirroring the
# host-side gate (LiveConfig.RoutedTap only emits the file when the tap is active).
#
# FAIL-CLOSED WHEN PRESENT-BUT-UNAPPLIABLE: when ds-net.env IS present (routed
# tap active) but the config is malformed or no egress NIC can be brought up, the
# script EXITS NON-ZERO so ds-netcfg.service fails — under an active routed tap a
# guest with no address has no egress, and booting it would silently strand the
# session. The service is ordered Before=ds-entrypoint so this fail-closes the
# boot exactly where the config-drive mount unit already does (no config => no
# entrypoint). The contrast is deliberate: ABSENT => SLIRP, fine; PRESENT but
# unappliable => fail.
#
# CONTRACT MATCH (netconfig.go — replicated here, NEVER imported; D80 keeps the
# guest tree from crossing into orchestrator/):
#   - file name : ds-net.env (M0_NETCFG_FILE == netConfigFileName), mounted under
#                 the config-drive at DS_ENTRYPOINT_CONFIG_DIR (run-ds-entrypoint.mount).
#   - keys      : DS_NET_GUEST_IP / DS_NET_PREFIX / DS_NET_GATEWAY (the renderer's
#                 three keys, renderNetConfigEnv).
#
# NIC SELECTION: the host-side tap appears in-guest as the FIRST egress NIC
# (M0_EGRESS_NIC_GLOB, the en* virtio-net name); `lo` is never touched. We pick
# the first matching, link-up-able interface; if none can be brought up under a
# present config we fail closed.
#
# build-m0-image.sh substitutes the concrete config dir / NIC glob for the
# __ENTRYPOINT_CONFIG_DIR__ / __EGRESS_NIC_GLOB__ tokens at bake time
# (single-sourced from m0-image.env).
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

CONFIG_DIR="__ENTRYPOINT_CONFIG_DIR__"
NIC_GLOB="__EGRESS_NIC_GLOB__"
NETCFG_FILE="${CONFIG_DIR}/__NETCFG_FILE__"

log() { printf 'ds-apply-netcfg: %s\n' "$*"; }
die() { printf 'ds-apply-netcfg: FAIL: %s\n' "$*" >&2; exit 1; }

# ── absent => SLIRP/offline: no-op, exit clean ───────────────────────────────
# The host only writes ds-net.env when the routed tap is active. No file means
# the M0-minimal usermode SLIRP NIC is in play — ds-slirp-net.service + systemd-
# networkd DHCP that NIC (gated to this same absent-ds-net.env path); leave it
# alone and succeed so the boot proceeds to ds-entrypoint unchanged.
if [ ! -f "${NETCFG_FILE}" ]; then
  log "no ${NETCFG_FILE} (SLIRP/offline path): nothing to apply"
  exit 0
fi

# ── present => routed tap active: apply, fail-closed ─────────────────────────
log "found ${NETCFG_FILE}: applying per-session static net config (routed tap)"

# Source the POSIX key=value file (the renderer's shape: no spaces around '=',
# one per line). Only the three known keys are consumed.
DS_NET_GUEST_IP=""
DS_NET_PREFIX=""
DS_NET_GATEWAY=""
# shellcheck source=/dev/null
. "${NETCFG_FILE}"

[ -n "${DS_NET_GUEST_IP}" ] || die "ds-net.env present but DS_NET_GUEST_IP is empty (malformed config under an active routed tap)"
[ -n "${DS_NET_PREFIX}" ]   || die "ds-net.env present but DS_NET_PREFIX is empty"
[ -n "${DS_NET_GATEWAY}" ]  || die "ds-net.env present but DS_NET_GATEWAY is empty"

# Resolve the egress NIC: the first link matching the glob that we can bring up.
# `lo` is never matched (the glob is en*). Fail closed if none exists.
pick_egress_nic() {
  local d
  for d in /sys/class/net/${NIC_GLOB}; do
    [ -e "$d" ] || continue
    basename "$d"
    return 0
  done
  return 1
}

NIC="$(pick_egress_nic)" || die "no egress NIC matching '${NIC_GLOB}' (cannot apply net config under an active routed tap)"
log "egress NIC: ${NIC} -> ${DS_NET_GUEST_IP}/${DS_NET_PREFIX} default via ${DS_NET_GATEWAY}"

# Bring the link up, assign the static per-session address, install the default
# route via the per-session gateway. Each step fail-closes (set -e). The address
# add is idempotent-tolerant (a retry of an already-set address is not fatal).
ip link set dev "${NIC}" up || die "failed to bring up ${NIC}"
ip addr add "${DS_NET_GUEST_IP}/${DS_NET_PREFIX}" dev "${NIC}" 2>/dev/null \
  || ip addr show dev "${NIC}" | grep -qF "${DS_NET_GUEST_IP}/${DS_NET_PREFIX}" \
  || die "failed to assign ${DS_NET_GUEST_IP}/${DS_NET_PREFIX} to ${NIC}"
# Replace (not merely add) the default route so a re-apply converges; the /31
# gateway is reachable on-link, so no separate on-link route is needed.
ip route replace default via "${DS_NET_GATEWAY}" dev "${NIC}" \
  || die "failed to install default route via ${DS_NET_GATEWAY} on ${NIC}"

log "applied per-session static net config on ${NIC}"
