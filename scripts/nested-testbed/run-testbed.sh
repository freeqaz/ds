#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# run-testbed.sh — one-command driver for the 2-level nested-VM NFTables testbed.
#
#   HOST (untouched: SLIRP only, no sudo nft)
#     └─ L1 VM  (full network; runs the REAL nft input-policy-drop floor + ds-dnsgate
#        │       + ds-tlsproxy + nested KVM)   ← the device under test
#        └─ L2 VM (nested; the agent VM — egress FORCED through L1's floor + gateways)
#
# Breaking L1's networking is harmless (reboot the VM); the host and its VPN/SSH
# management path are never at risk. This is the safe way to test nft /
# egress-gateway changes.
#
# Two L2 bring-up paths:
#   MANUAL (the historical fallback, default `up`): gate-up.sh hand-applies the nft
#     floor + routed tap + gateways, then l2-up.sh hand-boots L2 with qemu.
#   ORCHESTRATOR-DRIVEN (`up-orch`, or `DS_ORCH_BOOT=1 up`): the REAL stack —
#     ds-orchestrator + ds-host-agent (DS_HOSTAGENT_LIVE=1, -routed-tap, the
#     privileged edge in the setcap'd ds-nethelper helper, D148) — and a driven
#     CreateSession, so the host-agent's REAL AttachPrimitive (helperAttach)
#     programs the per-session tap + session NFT and
#     boots L2 via libvirt (the ATTACH-PRIMITIVE.md acceptance, run safely in L1).
#
# Usage:
#   run-testbed.sh up            build (if needed) + boot L1 + gate-up + boot L2 + validate
#                                (DS_ORCH_BOOT=1 substitutes the orchestrator-driven path
#                                 for gate-up+l2-up — see up-orch)
#   run-testbed.sh up-orch       build (if needed) + boot L1 + orchestrator-driven L2
#                                (ds-orchestrator + ds-host-agent boot L2; the REAL
#                                 host-agent AttachPrimitive programs the tap+NFT)
#   run-testbed.sh orch-status   show the orchestrator-stack + booted-L2 state inside L1
#   run-testbed.sh orch-down     tear down the orchestrator stack + its booted L2 (keeps L1)
#   run-testbed.sh validate      re-run the gating validation from L2
#   run-testbed.sh enforce       restart gateways in TLS-1 SNI-enforce mode + validate
#   run-testbed.sh shell         drop into an L1 root shell (ssh)
#   run-testbed.sh l2shell       drop into the nested L2 root shell (ssh via L1)
#   run-testbed.sh status        show L1/L2 + gateway state
#   run-testbed.sh down          tear down L2 + gateways + L1
#   run-testbed.sh rebuild       force-rebake the L1 image, then up
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGES="${DS_IMAGES_DIR:-$HOME/tmp/ds-images}"
NESTED="${DS_NESTED_DIR:-$HOME/tmp/ds-nested}"
SHARE="$NESTED/share"          # the 9p share boot-l1.sh stages, mounted at /opt/ds in L1
L1SSH="$SCRIPT_DIR/boot-l1.sh ssh"
say(){ printf '\033[1;32m[testbed] %s\033[0m\n' "$*"; }

ensure_image() {
  [ -r "$IMAGES/l1-base.raw" ] && [ "${1:-}" != "force" ] || { say "baking L1 image"; "$SCRIPT_DIR/build-l1-image.sh"; }
}
preflight() {
  say "preflight: nested-virt + tooling readiness"
  local nested ok=1
  nested=$(cat /sys/module/kvm_amd/parameters/nested 2>/dev/null || cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || echo '')
  case "$nested" in
    Y|1) say "  nested virt: ENABLED ($nested)" ;;
    *)   echo "  FAIL nested virt NOT enabled (kvm_*/parameters/nested='$nested'); enable: 'options kvm_amd nested=1' (or kvm_intel) + reload"; ok=0 ;;
  esac
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then say "  /dev/kvm: rw OK for $(id -un)"; else echo "  FAIL /dev/kvm not rw for $(id -un) — add the runner user to the 'kvm' group"; ok=0; fi
  for t in podman qemu-system-x86_64 nft mke2fs ssh ssh-keygen; do
    if command -v "$t" >/dev/null; then say "  $t: ok"; else echo "  FAIL missing tool: $t"; ok=0; fi
  done
  [ "$ok" = 1 ] || { echo "preflight FAILED — this host is not nested-KVM-ready" >&2; exit 3; }
}
boot_l1() { say "booting L1"; "$SCRIPT_DIR/boot-l1.sh" up; }
build_bins() { [ -x "${DS_NESTED_BIN:-$HOME/tmp/ds-nested/bin}/ds-dnsgate" ] && [ -x "${DS_NESTED_BIN:-$HOME/tmp/ds-nested/bin}/ds-tlsproxy" ] || { say "building Debian-glibc dataplane binaries"; "$SCRIPT_DIR/build-dataplane-debian.sh"; }; }
gate_up() { say "gate-up inside L1"; $L1SSH "DS_GATE_TLS_MODE=${DS_GATE_TLS_MODE:-opaque} bash /opt/ds/inside-l1/gate-up.sh"; }
l2_up()   { say "booting nested L2"; $L1SSH 'bash /opt/ds/inside-l1/l2-up.sh'; }
validate(){ say "validating gating from L2"; $L1SSH 'bash /opt/ds/inside-l1/validate.sh'; }

# stage_overlay_create copies vm/cow/overlay-create.sh into the 9p share so the
# in-L1 host-agent's live OverlayStore (which shells out to it for the D29 clone)
# can find it at /opt/ds/vm/cow/overlay-create.sh. boot-l1.sh stage does not copy
# the vm/ tree, so the orchestrator-driven path seeds it here (9p is live — no L1
# reboot needed). Idempotent.
stage_overlay_create() {
  local src="$REPO/vm/cow/overlay-create.sh"
  [ -r "$src" ] || { say "WARN: $src missing — the host-agent live OverlayStore needs it (clone will fail)"; return 0; }
  mkdir -p "$SHARE/vm/cow"
  cp -f "$src" "$SHARE/vm/cow/overlay-create.sh"
  chmod +x "$SHARE/vm/cow/overlay-create.sh" 2>/dev/null || true
  say "staged overlay-create.sh into the share (/opt/ds/vm/cow/overlay-create.sh)"
}

# orch_up runs the orchestrator-driven L2 bring-up INSIDE L1 (the real stack:
# ds-orchestrator + ds-host-agent drive a CreateSession; the host-agent's
# AttachPrimitive programs the per-session tap + NFT and boots L2 via libvirt).
# Pass the flavor/drive selectors through to the in-L1 runner.
orch_up() {
  stage_overlay_create
  say "orchestrator-driven L2 inside L1 (DS_HOSTAGENT_LIVE host-agent boots L2; real AttachPrimitive tap+NFT)"
  $L1SSH "DS_L2_FLAVOR=${DS_L2_FLAVOR:-fat} DS_ORCH_DRIVE=${DS_ORCH_DRIVE:-orchestrator} DS_DRIVE_SEAT=${DS_DRIVE_SEAT:-0} DS_GATE_TLS_MODE=${DS_GATE_TLS_MODE:-opaque} bash /opt/ds/inside-l1/orchestrator-boot-l2.sh up"
}
orch_status(){ say "orchestrator-stack status inside L1"; $L1SSH 'bash /opt/ds/inside-l1/orchestrator-boot-l2.sh status'; }
orch_down()  { say "tearing down the orchestrator stack + its booted L2 inside L1"; $L1SSH 'bash /opt/ds/inside-l1/orchestrator-boot-l2.sh down' 2>/dev/null || true; }

case "${1:-up}" in
  preflight) preflight ;;
  up)        build_bins; ensure_image; boot_l1
             # DS_ORCH_BOOT=1 substitutes the orchestrator-driven L2 path (the real
             # host-agent AttachPrimitive boots L2) for the manual gate-up+l2-up flow;
             # default keeps the historical manual path + validate.
             if [ "${DS_ORCH_BOOT:-0}" = 1 ]; then orch_up; else gate_up; l2_up; validate; fi ;;
  up-orch)   build_bins; ensure_image; boot_l1; orch_up ;;
  orch-status) orch_status ;;
  orch-down)   orch_down ;;
  rebuild)   build_bins; ensure_image force; boot_l1; gate_up; l2_up; validate ;;
  ci)        # CI entrypoint: readiness-gated; rebuilds from CURRENT source (cargo is
             # incremental via the cached target dir; image rebaked fresh); returns the
             # assert-gating exit code as the job result.
             #
             # KEYSTONE path (D148): drive the REAL stack via orch_up (ds-orchestrator +
             # the non-root ds-host-agent + the setcap'd ds-nethelper program the per-session
             # tap+NFT and boot L2), NOT the manual gate_up+l2_up flow — that path makes
             # assert-gating.sh auto-detect mode=manual and SKIP the K* keystone checks. Keep
             # DS_L2_FLAVOR=fat (assert-gating.sh A2-A4 SSH into L2 and run dig/nc/curl, which
             # only the fat image carries). orch_up + fat pins index 7 (seed_index_counter) ->
             # dstap-7/allow4_7 align with assert-gating.sh's default IDX=7.
             preflight; "$SCRIPT_DIR/build-dataplane-debian.sh"; ensure_image force; boot_l1
             DS_L2_FLAVOR=fat DS_ORCH_DRIVE=orchestrator orch_up
             # Source the runner-persisted session facts (the orchestrator MINTS the UUID
             # server-side; only the in-L1 runner knows it) so assert-gating.sh's K3/K5
             # UUID-dependent checks look at the right domain/socket names. session.env lives
             # at /run/ds-orch/session.env inside L1; `set -a` exports the sourced vars into
             # assert-gating.sh. K2 (allow4_7/dstap-7) + A1-A4 are index-keyed and pass on
             # IDX=7 even without this; K3/K5 are the UUID-dependent extras.
             say "asserting gating (CI keystone gate)"
             $L1SSH 'set -a; . /run/ds-orch/session.env 2>/dev/null || true; set +a; bash /opt/ds/inside-l1/assert-gating.sh' ;;
  logs)      d="${DS_LOG_DIR:-./testbed-logs}"; mkdir -p "$d"
             cp -f "$HOME/tmp/ds-nested/run/l1-serial.log" "$d/l1-serial.log" 2>/dev/null || true
             $L1SSH 'cat /run/ds-gate/dnsgate.log'  > "$d/dnsgate.log"  2>/dev/null || true
             $L1SSH 'cat /run/ds-gate/tlsproxy.log' > "$d/tlsproxy.log" 2>/dev/null || true
             $L1SSH 'cat /run/ds-l2/l2-serial.log'  > "$d/l2-serial.log" 2>/dev/null || true
             $L1SSH 'nft list ruleset'              > "$d/l1-nft-ruleset.txt" 2>/dev/null || true
             say "logs in $d:"; ls -la "$d" ;;
  gate-up)   gate_up ;;
  l2-up)     l2_up ;;
  validate)  validate ;;
  enforce)   DS_GATE_TLS_MODE=enforce gate_up; validate ;;
  shell)     exec "$SCRIPT_DIR/boot-l1.sh" ssh ;;
  l2shell)   exec "$SCRIPT_DIR/boot-l1.sh" ssh -t 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.77.7.1' ;;
  status)    "$SCRIPT_DIR/boot-l1.sh" status; $L1SSH 'echo "--- L1 inside ---"; ss -ltnup 2>/dev/null | grep -E ":15353|:18080|:18443" || echo "gateways down"; ip -br link show dstap-7 2>/dev/null || echo "no tap"; echo "L2:"; (kill -0 $(cat /run/ds-l2/l2.pid 2>/dev/null) 2>/dev/null && echo running || echo stopped)' ;;
  down)      # reap BOTH paths' state inside L1 (manual gate+L2 and the orchestrator
             # stack+its booted L2), then power L1 down. Either reap no-ops cleanly if
             # that path was never brought up.
             $L1SSH 'bash /opt/ds/inside-l1/gate-down.sh' 2>/dev/null || true
             $L1SSH 'bash /opt/ds/inside-l1/orchestrator-boot-l2.sh down' 2>/dev/null || true
             "$SCRIPT_DIR/boot-l1.sh" down ;;
  *) echo "usage: $0 {up|up-orch|ci|rebuild|preflight|gate-up|l2-up|orch-status|orch-down|validate|enforce|logs|shell|l2shell|status|down}" >&2; exit 2 ;;
esac
