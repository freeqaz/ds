#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# assert-gating.sh — runs INSIDE L1. Hard pass/fail gate for CI: exit 0 iff every
# egress-gating invariant holds. Prints PASS/FAIL per check. Probes run from L2.
#
# TWO PATHS, ONE GATE. L2 can be brought up two ways (run-testbed.sh):
#   MANUAL (gate-up.sh + l2-up.sh) — the historical appliance-floor path: gate-up.sh
#     hand-applies the nft floor (ds_boundary default-deny + 53/80/443 redirects) + the
#     routed tap + the gateways, and l2-up.sh hand-boots L2 with bare qemu. The A*
#     checks below are the canonical proof for THIS path and are UNCHANGED.
#   KEYSTONE (orchestrator-boot-l2.sh) — the REAL stack: ds-orchestrator + the live
#     ds-host-agent (DS_HOSTAGENT_LIVE=1, -routed-tap, privileged edge in the setcap'd
#     ds-nethelper helper, D148) drive a
#     CreateSession so the host-agent's REAL AttachPrimitive (helperAttach) programs the
#     per-session tap (CreateTap → dstap-<idx>) + the per-session allow-sets
#     (InstantiateSessionNFT → allow4_<idx>/allow6_<idx> in inet ds_filter) and boots L2
#     via libvirt. The K* checks below add the KEYSTONE-LEVEL proof (host-agent-programmed
#     per-session NFT + gated egress + the :4242 writer-seat) on TOP of A* — gated on the
#     detected path so the manual A* asserts keep passing untouched.
#
# Mode detection: DS_ASSERT_MODE=auto|manual|keystone (default auto). auto =>
# keystone iff the orchestrator-stack left its footprint inside L1 (a live
# host-agent pid, a running ds-<uuid> libvirt domain, or the served attach UDS dir).
set -uo pipefail
IDX="${DS_SESSION_IDX:-7}"; NET="10.77.${IDX}"; L2="$NET.1"
SSH=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=8 root@"$L2")
fail=0
ck(){ if [ "$1" = 0 ]; then printf '  \033[1;32mPASS\033[0m  %s\n' "$2"; else printf '  \033[1;31mFAIL\033[0m  %s\n' "$2"; fail=1; fi; }
warn(){ printf '  \033[1;33mWARN\033[0m  %s\n' "$1"; }
dropcount(){ nft list chain inet ds_boundary forward 2>/dev/null | sed -n 's/.*ct state new counter packets \([0-9]*\) .*drop/\1/p' | tail -1; }

# --- keystone-path footprint (set by orchestrator-boot-l2.sh) -----------------
ORCH_RUN="${DS_ORCH_RUN:-/run/ds-orch}"
ATTACH_DIR="${DS_ATTACH_DIR:-/run/ds/attach}"
EVENT_SOCK="${DS_EVENT_SOCK:-/run/ds/attach.sock}"
SESSION_UUID="${DS_SESSION_UUID:-l1-orchboot-1}"
HA_PID_FILE="$ORCH_RUN/host-agent.pid"
ORCH_PID_FILE="$ORCH_RUN/orchestrator.pid"
DOM="ds-${SESSION_UUID}"
# The per-session served attach UDS path: <attach-dir>/<sanitized-uuid>.sock. The
# orchestrator/host-agent sanitizer keeps [A-Za-z0-9._-] and maps every other byte to '_'
# (controlplane attachendpoint.go sanitizeSocketComponent / hostagent sanitizeAttachComponent).
sanitize_socket(){ printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]/_/g'; }
ATTACH_SOCK="$ATTACH_DIR/$(sanitize_socket "$SESSION_UUID").sock"

pid_alive(){ [ -f "$1" ] && kill -0 "$(cat "$1" 2>/dev/null)" 2>/dev/null; }
# The L1 host-agent boots the L2 domain at qemu:///system (orchestrator-boot-l2.sh pins
# LIBVIRT_DEFAULT_URI=qemu:///system; L1 runs as root, direct-kernel), so probe the SAME
# instance — a qemu:///session dial hides the running domain (the wait_for_l2 URI-mismatch
# bug). Honor LIBVIRT_DEFAULT_URI if the operator overrode it, else default to qemu:///system.
LIBVIRT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"
dom_running(){ command -v virsh >/dev/null 2>&1 && virsh -c "$LIBVIRT_URI" domstate "$1" 2>/dev/null | grep -q running; }

detect_mode(){
  case "${DS_ASSERT_MODE:-auto}" in
    manual)   echo manual ;;
    keystone) echo keystone ;;
    auto)
      if pid_alive "$HA_PID_FILE" || dom_running "$DOM" || [ -d "$ATTACH_DIR" ]; then
        echo keystone
      else
        echo manual
      fi ;;
    *) echo "unknown DS_ASSERT_MODE=${DS_ASSERT_MODE} (auto|manual|keystone)" >&2; echo manual ;;
  esac
}
MODE="$(detect_mode)"

echo "── gating assertions (idx=$IDX, L2=$L2, mode=$MODE)"

# A1 — gateways listening
n=$(ss -ltnu 2>/dev/null | grep -cE ':15353|:18080|:18443'); [ "${n:-0}" -ge 3 ]; ck $? "gateways listening (15353/18080/18443): $n/4 sockets"

# A2 — L2 reachable + isolated (only the routed tap, default route via the gateway)
"${SSH[@]}" true 2>/dev/null; ck $? "L2 reachable over the routed tap ($L2)"
iso=$("${SSH[@]}" 'ip -4 addr show 2>/dev/null | grep -q "inet 10.0.2" && echo HASSLIRP; ip route show default 2>/dev/null' 2>/dev/null)
{ ! echo "$iso" | grep -q HASSLIRP; } && echo "$iso" | grep -q "default via ${NET}.0"; ck $? "L2 isolated: no SLIRP, default via ${NET}.0 only"

# A3 — direct non-gated egress DENIED + the nft forward DROP counter increments
before=$(dropcount)
"${SSH[@]}" 'timeout 5 nc -w3 1.1.1.1 22 </dev/null >/dev/null 2>&1'; nc_rc=$?
sleep 1; after=$(dropcount)
[ "$nc_rc" -ne 0 ]; ck $? "direct egress nc 1.1.1.1:22 DENIED (rc=$nc_rc, expect non-zero)"
[ "${after:-0}" -gt "${before:-0}" ]; ck $? "nft forward DROP counter incremented (${before:-?} -> ${after:-?})"

# A4 — DNS forced through ds-dnsgate: a direct query to 8.8.8.8 is intercepted (the gate
# answers REFUSED for an unadmitted name; a real 8.8.8.8 would ANSWER example.com).
dns=$("${SSH[@]}" 'timeout 8 dig +tries=1 +time=4 @8.8.8.8 example.com 2>&1' 2>/dev/null)
echo "$dns" | grep -qE 'status: REFUSED' && ! echo "$dns" | grep -qE 'status: NOERROR'; ck $? "direct DNS @8.8.8.8 intercepted by ds-dnsgate (REFUSED, not a real answer)"

# A5 — gated HTTPS path is functional: reaches the real API only via ds-tlsproxy.
# SOFT by default (needs external internet to api.anthropic.com, which can be blocked
# in a CI sandbox): a miss WARNs, it doesn't fail the gate. The hard gating proof is
# A1-A4 (isolation + direct-egress-drop + DNS-intercept), which need no external reach.
# Set DS_ASSERT_EXTERNAL=1 to make this a hard check.
code=$("${SSH[@]}" 'timeout 20 curl -sS -o /dev/null -w "%{http_code}" https://api.anthropic.com/ 2>/dev/null' 2>/dev/null)
if [ -n "$code" ] && [ "$code" != "000" ]; then ck 0 "HTTPS to api.anthropic.com reaches the API via ds-tlsproxy (http_code=$code)"
elif [ "${DS_ASSERT_EXTERNAL:-0}" = 1 ]; then ck 1 "HTTPS to api.anthropic.com reaches the API via ds-tlsproxy (http_code=${code:-none})"
else warn "HTTPS to api.anthropic.com unreachable (http_code=${code:-none}) — external connectivity, not a gating failure"; fi

# ============================================================================
# KEYSTONE-MODE checks (only when L2 was brought up via the orchestrator-driven
# real-stack path). These prove the host-agent AttachPrimitive — not gate-up.sh —
# programmed the per-session NFT + tap + booted L2, that egress is STILL gated
# through the gateways, and that the :4242 writer-seat carriage is in place. They
# are SKIPPED in manual mode so the A* appliance-floor proof is untouched.
# ============================================================================
if [ "$MODE" = keystone ]; then
  echo "── keystone assertions (real host-agent AttachPrimitive: idx=$IDX, session=$SESSION_UUID, dom=$DOM)"

  # K1 — provenance: the REAL stack ran (host-agent live). This is what distinguishes
  # the host-agent-programmed per-session NFT from the manual gate-up.sh appliance floor.
  if pid_alive "$HA_PID_FILE"; then ck 0 "host-agent process LIVE (pid $(cat "$HA_PID_FILE")) — real-stack provenance"
  elif [ -f "$HA_PID_FILE" ]; then warn "host-agent pid file present ($HA_PID_FILE) but process not alive — it ran then exited (CreateSession leaves the session resident; check $ORCH_RUN/host-agent.log)"
  else ck 1 "host-agent provenance: no pid file at $HA_PID_FILE (orchestrator-boot-l2.sh did not run?)"; fi
  # The orchestrator is started alongside (full stack up); a missing/dead orchestrator
  # is a soft signal — the host-agent CloneFromImage is what programs the substrate.
  if pid_alive "$ORCH_PID_FILE"; then printf '  \033[1;32mPASS\033[0m  ds-orchestrator process LIVE (pid %s) — control plane up\n' "$(cat "$ORCH_PID_FILE")"
  else warn "ds-orchestrator not live (pid file $ORCH_PID_FILE) — host-agent-driven create still valid; control-plane dial not asserted"; fi

  # K2 — host-agent-programmed per-session NFT (InstantiateSessionNFT Model A): the EMPTY
  # allow4_<idx> set in inet ds_filter is the admit SURFACE liveAttach creates. (allow6_<idx>
  # stays empty under D75 Phase-B.) The dstap-<idx> tap is the CreateTap netdev. The
  # per-session NFT object name (allow4_<idx>) + the host-agent provenance (K1) +
  # the libvirt domain (K3) together distinguish this from the manual floor.
  nft list set inet ds_filter "allow4_${IDX}" >/dev/null 2>&1; ck $? "per-session allow-set inet ds_filter allow4_${IDX} programmed (InstantiateSessionNFT)"
  nft list set inet ds_filter "allow6_${IDX}" >/dev/null 2>&1; ck $? "per-session allow-set inet ds_filter allow6_${IDX} programmed (InstantiateSessionNFT, empty under D75 Phase-B)"
  ip -br link show "dstap-${IDX}" >/dev/null 2>&1; ck $? "per-session tap dstap-${IDX} programmed (CreateTap netdev)"

  # K3 — the host-agent booted L2 via libvirt (NOT l2-up.sh's bare qemu): the ds-<uuid>
  # domain is RUNNING. This is the distinguishing boot-provenance marker for the keystone
  # path. SOFT if virsh is unavailable (the substrate proof is K1+K2).
  if command -v virsh >/dev/null 2>&1; then
    dom_running "$DOM"; ck $? "libvirt session domain $DOM RUNNING (host-agent virsh boot, not bare qemu)"
  else
    warn "virsh unavailable inside L1 — cannot assert the libvirt domain $DOM (K1+K2 carry the substrate proof)"
  fi

  # K4 — gated egress STILL holds on the keystone path. The host-agent's liveAttach writes
  # the per-session allow-SETS + tap (K2); the default-deny floor + the 53/80/443 redirects
  # + the gateways are owned by the host-wide dstap-* glob floor (ds-nft session.rs: the
  # floor owns deny/redirect/closure). A1-A4 ABOVE already proved gated egress when that
  # floor + the gateways are present; here we re-state that the keystone path REQUIRES them.
  # If the gateways are NOT up (orchestrator-boot-l2.sh by itself stands up only the tap +
  # per-session sets, leaving the glob floor + gateways to the operator/CI harness), warn
  # rather than fail unless DS_ASSERT_GATEWAYS=1 makes it hard — the A* block is the gating
  # judge, K4 only flags that the keystone path did not bypass it.
  ng=$(ss -ltnu 2>/dev/null | grep -cE ':15353|:18080|:18443')
  if [ "${ng:-0}" -ge 3 ]; then ck 0 "keystone egress STILL gated: gateways up (A1-A4 hold over the host-agent-programmed tap)"
  elif [ "${DS_ASSERT_GATEWAYS:-0}" = 1 ]; then ck 1 "keystone egress gating: gateways NOT up ($ng/4) — the glob floor + gateways must be present for the keystone path"
  else warn "keystone egress gating: gateways not up ($ng/4) — stand up the glob floor + gateways (gate-up.sh) for the full A1-A4 egress proof over the host-agent tap; set DS_ASSERT_GATEWAYS=1 to make this hard"; fi

  # K5 — the host<->guest :4242 writer-seat carriage. In the current architecture the seat
  # is the SERVED host-local UDS the host-agent AttachBridge binds per session
  # (/run/ds/attach/<session>.sock — the DIRECT endpoint serpent-tui dials); the host->guest
  # leg rides virtio-vsock (guestCID:4242 == DefaultAttachPort), NOT TCP GuestIP:4242 and not
  # an nft-controlled path (attachminter.go). So the writer-seat proof is the served UDS dir +
  # (when a client has attached) the per-session socket / the host-agent event socket.
  if [ -S "$ATTACH_SOCK" ]; then ck 0 "writer-seat per-session attach UDS served: $ATTACH_SOCK (host-agent AttachBridge)"
  elif [ -d "$ATTACH_DIR" ]; then
    # The per-session UDS is bound lazily on the first client attach (servingChildArgs
    # --serve-uds); the served dir being present is the carriage being ready. Soft unless
    # DS_ASSERT_WRITERSEAT=1 demands the bound per-session socket.
    if [ "${DS_ASSERT_WRITERSEAT:-0}" = 1 ]; then ck 1 "writer-seat: attach dir $ATTACH_DIR present but per-session socket $ATTACH_SOCK not bound — attach a client (serpent up) to bind it"
    else warn "writer-seat: attach dir $ATTACH_DIR ready; per-session socket $ATTACH_SOCK binds on first client attach (set DS_ASSERT_WRITERSEAT=1 to require it)"; ck 0 "writer-seat attach socket dir present ($ATTACH_DIR)"; fi
  else ck 1 "writer-seat: no attach socket dir at $ATTACH_DIR (host-agent -attach-socket-dir not served?)"; fi
  [ -S "$EVENT_SOCK" ] && printf '  \033[1;32mPASS\033[0m  host-agent event socket served: %s\n' "$EVENT_SOCK" || warn "host-agent event socket $EVENT_SOCK not present (set -event-socket-path; non-fatal to the writer seat)"

  # K5-legacy — OPTIONAL raw TCP dial of GuestIP:4242. The live carriage moved to vsock
  # (above), so this is the CONCEPTUAL/legacy leg named in ATTACH-PRIMITIVE.md §3.6; a miss
  # is expected and informational. Only attempted under DS_ASSERT_LEGACY_4242=1.
  if [ "${DS_ASSERT_LEGACY_4242:-0}" = 1 ]; then
    "${SSH[@]}" true 2>/dev/null \
      && { if timeout 6 bash -c "exec 3<>/dev/tcp/${L2}/4242" 2>/dev/null; then exec 3>&- 3<&- 2>/dev/null || true; printf '  \033[1;32mPASS\033[0m  legacy TCP GuestIP:4242 reachable from L1 (%s:4242)\n' "$L2"; else warn "legacy TCP ${L2}:4242 not reachable — EXPECTED (the live carriage is vsock guestCID:4242, not TCP); informational only"; fi; } \
      || warn "legacy TCP 4242 probe skipped — L2 not ssh-reachable at $L2"
  fi
fi

echo "──"
if [ "$fail" = 0 ]; then echo "GATING: ALL CHECKS PASS"; exit 0; else echo "GATING: FAILURES PRESENT"; exit 1; fi
