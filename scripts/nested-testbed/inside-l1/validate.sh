#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# validate.sh — runs INSIDE L1. Prove L2's egress is gated by L1's nft floor.
# Probes are run FROM L2 (over ssh on the routed tap); enforcement is observed on L1.
#
# Two L2 bring-up paths (run-testbed.sh): the MANUAL appliance-floor path (gate-up.sh +
# l2-up.sh) and the KEYSTONE real-stack path (orchestrator-boot-l2.sh: the live ds-host-agent
# AttachPrimitive programs the per-session tap + NFT and boots L2 via libvirt). The [A]-[E]
# sections below are the canonical egress-gating evidence for BOTH paths (unchanged). When
# the keystone path ran, the [F] section additionally surfaces the host-agent-programmed
# substrate evidence (provenance + per-session NFT + libvirt domain + the :4242 writer seat).
#
# Mode: DS_ASSERT_MODE=auto|manual|keystone (default auto — keystone iff the orchestrator
# stack left a footprint: a live host-agent pid, a running ds-<uuid> domain, or the attach dir).
set -uo pipefail
IDX="${DS_SESSION_IDX:-7}"
NET="10.77.${IDX}"; L2="$NET.1"
RUN="${DS_GATE_RUN:-/run/ds-gate}"
SSH=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=8 -o BatchMode=yes root@"$L2")
hr(){ printf '\033[1;36m── %s\033[0m\n' "$*"; }

# --- keystone-path footprint (set by orchestrator-boot-l2.sh) -----------------
ORCH_RUN="${DS_ORCH_RUN:-/run/ds-orch}"
ATTACH_DIR="${DS_ATTACH_DIR:-/run/ds/attach}"
EVENT_SOCK="${DS_EVENT_SOCK:-/run/ds/attach.sock}"
SESSION_UUID="${DS_SESSION_UUID:-l1-orchboot-1}"
HA_PID_FILE="$ORCH_RUN/host-agent.pid"
ORCH_PID_FILE="$ORCH_RUN/orchestrator.pid"
DOM="ds-${SESSION_UUID}"
sanitize_socket(){ printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]/_/g'; }
ATTACH_SOCK="$ATTACH_DIR/$(sanitize_socket "$SESSION_UUID").sock"
pid_alive(){ [ -f "$1" ] && kill -0 "$(cat "$1" 2>/dev/null)" 2>/dev/null; }
dom_running(){ command -v virsh >/dev/null 2>&1 && virsh -c qemu:///session domstate "$1" 2>/dev/null | grep -q running; }
detect_mode(){
  case "${DS_ASSERT_MODE:-auto}" in
    manual)   echo manual ;;
    keystone) echo keystone ;;
    *)        if pid_alive "$HA_PID_FILE" || dom_running "$DOM" || [ -d "$ATTACH_DIR" ]; then echo keystone; else echo manual; fi ;;
  esac
}
MODE="$(detect_mode)"

"${SSH[@]}" true 2>/dev/null || { echo "L2 not reachable at $L2 — boot it (l2-up.sh, or orchestrator-boot-l2.sh up) first"; exit 1; }

hr "mode: $MODE  (L2=$L2, session=$SESSION_UUID)"

hr "L2 network (proves it has ONLY the routed tap, no SLIRP)"
"${SSH[@]}" 'ip -4 -br addr; echo default:; ip route show default'

hr "[A] DIRECT non-gated egress  nc -vz 1.1.1.1 22  → EXPECT DENIED (forward policy drop)"
"${SSH[@]}" 'timeout 6 nc -vz 1.1.1.1 22 2>&1; echo "→ exit=$?"' || true

hr "[B] DIRECT DNS to 8.8.8.8  dig @8.8.8.8  → EXPECT intercepted by ds-dnsgate (cannot reach 8.8.8.8)"
"${SSH[@]}" 'timeout 8 dig +tries=1 +time=4 @8.8.8.8 example.com 2>&1 | grep -E "SERVER:|status:|ANSWER:|connection timed out|;; ->>" | head' || true

hr "[C] HTTPS to api.anthropic.com  → routed through ds-tlsproxy (:18443)"
"${SSH[@]}" 'timeout 20 curl -sS -o /dev/null -w "http_code=%{http_code} remote=%{remote_ip}:%{remote_port}\n" https://api.anthropic.com/ 2>&1 || echo "curl failed: $?"' || true

hr "[D] L1 nft forward-chain counters (the deny/reject path firing)"
nft list chain inet ds_boundary forward 2>/dev/null | grep -E 'counter|policy' || true

hr "[E] L1 gateway evidence (dnsgate saw queries / tlsproxy saw connections)"
echo "dnsgate recent:"; tail -4 "$RUN/dnsgate.log" 2>/dev/null | sed 's/^/   /'
echo "tlsproxy recent:"; tail -4 "$RUN/tlsproxy.log" 2>/dev/null | sed 's/^/   /'
echo "allow4_${IDX} set members (fill as names are admitted):"
nft list set inet ds_filter "allow4_${IDX}" 2>/dev/null | grep -E 'elements|}' | head

# ----------------------------------------------------------------------------
# [F] KEYSTONE substrate evidence — only when the orchestrator-driven real stack ran.
# Surfaces that the host-agent AttachPrimitive (not gate-up.sh) programmed the per-session
# tap + NFT and booted L2 via libvirt, plus the :4242 writer-seat carriage state.
# ----------------------------------------------------------------------------
if [ "$MODE" = keystone ]; then
  hr "[F1] host-agent provenance (the REAL stack ran — distinguishes the host-agent-programmed NFT from the manual floor)"
  if pid_alive "$HA_PID_FILE"; then echo "   ds-host-agent: LIVE (pid $(cat "$HA_PID_FILE"))"; else echo "   ds-host-agent: not live (pid file $HA_PID_FILE: $( [ -f "$HA_PID_FILE" ] && echo present || echo absent ))"; fi
  if pid_alive "$ORCH_PID_FILE"; then echo "   ds-orchestrator: LIVE (pid $(cat "$ORCH_PID_FILE"))"; else echo "   ds-orchestrator: not live (pid file $ORCH_PID_FILE: $( [ -f "$ORCH_PID_FILE" ] && echo present || echo absent ))"; fi
  echo "   host-agent log tail:"; tail -4 "$ORCH_RUN/host-agent.log" 2>/dev/null | sed 's/^/      /' || true

  hr "[F2] host-agent-programmed per-session NFT (CreateTap + InstantiateSessionNFT)"
  echo "   tap dstap-${IDX} (CreateTap netdev):"
  ip -br link show "dstap-${IDX}" 2>/dev/null | sed 's/^/      /' || echo "      (absent)"
  echo "   per-session allow-sets in inet ds_filter (InstantiateSessionNFT; empty until DNS-admitted, allow6 empty under D75 Phase-B):"
  nft list set inet ds_filter "allow4_${IDX}" 2>/dev/null | sed 's/^/      /' || echo "      allow4_${IDX}: absent"
  nft list set inet ds_filter "allow6_${IDX}" 2>/dev/null | sed 's/^/      /' || echo "      allow6_${IDX}: absent"

  hr "[F3] libvirt session domain (host-agent virsh boot, not bare qemu)"
  if command -v virsh >/dev/null 2>&1; then
    virsh -c qemu:///session domstate "$DOM" 2>/dev/null | sed "s/^/   $DOM: /" || echo "   $DOM: (no domain)"
    virsh -c qemu:///session list 2>/dev/null | sed 's/^/   /' || true
  else
    echo "   (virsh unavailable inside L1)"
  fi

  hr "[F4] :4242 writer-seat carriage (served host-local UDS; host→guest leg rides vsock guestCID:4242, not TCP)"
  echo "   attach socket dir ($ATTACH_DIR):"
  ls -la "$ATTACH_DIR" 2>/dev/null | sed 's/^/      /' || echo "      (absent)"
  if [ -S "$ATTACH_SOCK" ]; then echo "   per-session writer-seat UDS: SERVED ($ATTACH_SOCK)"; else echo "   per-session writer-seat UDS: $ATTACH_SOCK not yet bound (binds on first client attach — serpent up)"; fi
  [ -S "$EVENT_SOCK" ] && echo "   host-agent event socket: SERVED ($EVENT_SOCK)" || echo "   host-agent event socket: $EVENT_SOCK absent"
  if [ "${DS_ASSERT_LEGACY_4242:-0}" = 1 ]; then
    echo "   legacy TCP GuestIP:4242 probe (informational — the live carriage is vsock):"
    if timeout 6 bash -c "exec 3<>/dev/tcp/${L2}/4242" 2>/dev/null; then exec 3>&- 3<&- 2>/dev/null || true; echo "      ${L2}:4242 reachable"; else echo "      ${L2}:4242 not reachable (EXPECTED — carriage is vsock)"; fi
  fi
fi
