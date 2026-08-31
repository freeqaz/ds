#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
###############################################################################
# ds-gated-egress.sh — HOST bring-up for the "fully sandboxed" gated-egress
# posture of the dream-serpent serpent-claude -> per-session KVM VM stack.
#
#   *** DO NOT RUN WITHOUT THE HOST OWNER'S EXPLICIT GO-AHEAD ***
#   This script WRITES the host nftables ruleset and host routing. Never touch a
#   shared host's nft floor without go-ahead. It was PREPARED and
#   NETNS-VALIDATED only (see ds-gated-egress-validate.sh +
#   ds-gated-egress-proof.txt). The validation never touched the host.
#
# ─────────────────────────────────────────────────────────────────────────────
# WHAT "FULLY SANDBOXED" MEANS HERE (the design this implements)
#
#   The MVP boots the per-session KVM VM with usermode SLIRP egress + an injected
#   OAuth token (direct egress, no boundary). "Fully sandboxed" replaces SLIRP
#   with a per-session ROUTED TAP whose egress is forced through the boundary:
#
#     VM (10.77.<idx>.1) --dstap-<idx>--> host
#        |  default-deny nft floor (forward policy DROP)  => direct egress DENIED
#        |  nat prerouting REDIRECT:
#        |     udp/tcp 53 -> ds-dnsgate  (:15353)         => DNS only via the gate
#        |     tcp     80 -> ds-tlsproxy (:18080)
#        |     tcp    443 -> ds-tlsproxy (:18443)         => HTTPS only via the gate
#        v
#     ds-dnsgate (resolves+admits, writes allow4_<idx>) + ds-tlsproxy
#        (terminates/forwards to the model API). Everything else: DROP.
#
#   So Claude Code in the VM reaches ONLY the model API, and only through the two
#   Rust gateways. A REDIRECT rewrites the dst to the host's own (inbound-iface)
#   address, so the redirected flow lands in the *input* chain (policy ACCEPT)
#   and the gateways serve it; only DIRECT (non-redirected) egress hits the
#   forward DROP. That is why the box-safety `input=accept` is sound (below).
#
# CRED POSTURE (parameterized; this script validates / runs POSTURE=a):
#   (a) DEFAULT — keep the injected OAuth token IN the VM; only gate the egress
#       path. ds-tlsproxy terminates+forwards (opaque tunnel at this stage); NO
#       credential swap. This is the MVP "fully sandboxed".
#   (b) FUTURE — credential swap at ds-tlsproxy (long-lived creds never enter the
#       VM; the gateway swaps a short-lived token outbound). The POSTURE knob
#       below reserves the seam; (b) is NOT wired here (needs TLS-5 swap + the
#       identity mint path) — running with POSTURE=b currently ABORTS.
#
# ─────────────────────────────────────────────────────────────────────────────
# BOX-SAFETY RATIONALE — WHY `chain input { policy accept }` (NON-NEGOTIABLE)
#
#   The target is typically a SHARED, remote-managed box reached over a VPN/SSH.
#   The canonical appliance floor (nft-1-bootstrap.nft) sets `chain input policy
#   drop`, which on such a box silently drops NEW inbound WireGuard/SSH and falls
#   the host off the network (100% loss; recovery needs console) — an outage this
#   project has hit for real. The sandbox's egress enforcement does NOT live in
#   `input` — it lives in `forward` (default DROP, reproduced verbatim) which
#   never touches host-local inbound. So `input=accept` keeps the FULL egress
#   posture while never cutting host management. This is the management-safe
#   floor netns-proved in ds-boundary-scoped.nft.
#   ===> NEVER flip `input` to `policy drop` on a remote-managed box. <===
#
# ─────────────────────────────────────────────────────────────────────────────
# EXACT HOST COMMANDS THIS SCRIPT RUNS (the operator's review surface)
#   sudo nft -f <the floor + 53/80/443 redirect + allow-set table>   # writes ds_boundary, ds_filter
#   sudo ds-nft create_tap / instantiate_session  (via the orchestrator host-agent -routed-tap path)
#   (boundary services, NOT sudo if CAP-granted; here started under sudo for CAP_NET_ADMIN):
#     ds-dnsgate    (env DS_NFTGATE_LIVE=1 to write allow4_<idx> live)   [SEE GAP 1]
#     ds-tlsproxy   (binds 0.0.0.0:18080 / 0.0.0.0:18443)
#   host-agent -routed-tap  (boots the VM on dstap-<idx>, DS_ROUTED_TAP=1, not SLIRP)
#   Teardown: sudo nft delete table inet ds_boundary; ... ds_filter; ip link del dstap-<idx>
#
#   SUDO USED: nft (ruleset), ip (tap+route), and starting the gateways with
#   CAP_NET_ADMIN (for the live nft writer). All granted to the operator on this
#   box. No long-lived credential is handled by this script.
#
# ─────────────────────────────────────────────────────────────────────────────
# KNOWN GAPS / RISKS — READ BEFORE RUNNING (surfaced by the netns prep)
#
#   GAP 1 (BLOCKER, ds-dnsgate listen address): the AS-BUILT ds-dnsgate binds
#     127.0.0.1:<ephemeral> (GateConfig::default()=LOCALHOST:0; main.rs never
#     sets udp_addr/tcp_addr and exposes NO env/CLI override). The floor's
#     `redirect to :15353` needs ds-dnsgate on 0.0.0.0:15353. A REDIRECT lands on
#     the inbound-iface address (not loopback), so even 127.0.0.1:15353 would not
#     catch it. ==> ds-dnsgate must be changed to bind 0.0.0.0:15353 (a small
#     code/env-knob change the dataplane owner lands) BEFORE the DNS leg is live.
#     ds-tlsproxy already binds 0.0.0.0:18080/:18443 correctly (netns-verified).
#     This script DETECTS the gap at preflight and refuses the DNS leg if unfixed.
#
#   GAP 2 (NFT-2b not in the floor artifact): the canonical nft-1-bootstrap.nft
#     carries only the 53->dnsgate redirect; the 80/443->tlsproxy cutover (NFT-2b)
#     is still a separate spike artifact (nft-2b-spike.nft). This script FOLDS the
#     80/443 redirect into ds_boundary's prerouting itself (the netns-validated
#     shape) so HTTPS is gated. When NFT-2b lands in the floor, drop the fold.
#
#   GAP 3 (per-session admit fill = DS_NFTGATE_LIVE + root): ds-dnsgate fills
#     allow4_<idx> only behind DS_NFTGATE_LIVE=1, running as root/CAP_NET_ADMIN,
#     AND the set must pre-exist (ds-nft instantiate_session). Without it, the
#     admit set stays empty. NOTE the cross-table subtlety (GAP 4).
#
#   GAP 4 (NFT-3b cross-table — does it bite? NO, for posture (a)): allow4_<idx>
#     lives in `inet ds_filter`; the floor's forward DROP lives in `inet
#     ds_boundary`. NOTHING in ds_boundary's forward chain reads @allow4_<idx>.
#     Under the REDIRECT model the VM->gateway flow is DNAT'd to a LOCAL addr and
#     handled in `input` (accept) — it never traverses `forward`, so the forward
#     DROP correctly denies only DIRECT egress and the missing forward-admit is
#     CORRECT, not a bug. @allow4_<idx> is consumed ONLY by NFT-3b's out_<session>
#     OUTPUT chain (ds_proxy_out), which bounds the PROXY's re-originated UPSTREAM
#     egress by UID — a Stage-3, defense-in-depth layer that is DOCUMENTED-SHAPE-
#     ONLY / deferred (ds_nft.h:89, off the M1 gate). So for POSTURE=a the gated
#     egress is fully functional WITHOUT NFT-3b; installing NFT-3b later only adds
#     proxy-upstream containment. The admit set thus gates the proxy's upstream,
#     not the VM's forward path. (If you WANT the VM forward path itself gated per
#     admitted-IP rather than "all-redirected-to-gateway", that is a different
#     design — not this MVP.)
#
#   GAP 5 (orchestrator boot wiring): the routed-tap boot is gated by BOTH the
#     host-agent `-routed-tap` flag AND DS_ROUTED_TAP=1 (NewLiveBooter ORs them).
#     The VM also needs the in-guest ds-apply-netcfg.sh to apply ds-net.env
#     (10.77.<idx>.1/31 via .0) from the config-drive — that is the M0 guest image
#     half. A guest that does not apply it has no route and reaches nothing.
#
#   GAP 6 (host ip_forward): the routed tap forwards across interfaces, so
#     net.ipv4.ip_forward=1 must be set host-wide. This script sets it ONLY if
#     unset and records the prior value for teardown (it does not assume it).
#
#   RISK: this script writes the host floor. The `delete table inet ds_boundary`
#   preamble is idempotent and touches ONLY our tables (never WireGuard /
#   systemd-networkd). Teardown is clean. But verify `ss -ltn` shows your SSH/
#   Tailscale still bound AFTER the floor applies (the script asserts input=accept
#   rendered) before trusting it.
###############################################################################
set -uo pipefail

# ── Parameters (env-overridable) ─────────────────────────────────────────────
POSTURE="${POSTURE:-a}"                 # a = gate-only (MVP); b = cred-swap (future, not wired)
IDX="${DS_SESSION_IDX:-7}"              # per-session host index -> dstap-<idx>, allow4_<idx>, 10.77.<idx>.x
TAP="dstap-${IDX}"
DNSGATE_REDIR_PORT="${DNSGATE_REDIR_PORT:-15353}"
TLS_HTTP_PORT="${TLS_HTTP_PORT:-18080}"
TLS_HTTPS_PORT="${TLS_HTTPS_PORT:-18443}"
REPO="${DS_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DP="${REPO}/dataplane/target/release"
DNSGATE_BIN="${DNSGATE_BIN:-$DP/ds-dnsgate}"
TLSPROXY_BIN="${TLSPROXY_BIN:-$DP/ds-tlsproxy}"
RUN_DIR="${RUN_DIR:-$HOME/tmp/ds-gated-run}"   # logs + pidfiles (NOT /tmp — tmpfs/RAM)
DRY_RUN="${DRY_RUN:-1}"                  # 1 = print only; flip to 0 ONLY on go-ahead

mkdir -p "$RUN_DIR"
say()  { printf '[ds-gated] %s\n' "$*"; }
die()  { printf '[ds-gated][FATAL] %s\n' "$*" >&2; exit 1; }
run()  { # gated runner: prints always; executes only when DRY_RUN=0
  printf '[ds-gated][cmd] %s\n' "$*"
  if [ "$DRY_RUN" = "0" ]; then eval "$@"; else printf '[ds-gated][dry-run] (not executed)\n'; fi
}

[ "$POSTURE" = "a" ] || die "POSTURE=$POSTURE not supported here. Only (a) gate-only is wired; (b) cred-swap needs TLS-5 swap + identity mint (reserved seam, not implemented)."
[ -x "$DNSGATE_BIN" ]  || die "ds-dnsgate not found/executable at $DNSGATE_BIN (build: cargo build -p ds-dnsgate --release)"
[ -x "$TLSPROXY_BIN" ] || die "ds-tlsproxy not found/executable at $TLSPROXY_BIN"

# ── The gated-egress ruleset (NETNS-VALIDATED shape) ─────────────────────────
# Management-safe floor (input=accept, forward=drop) + 53->dnsgate + 80/443->
# tlsproxy (NFT-2b fold, GAP 2) + the per-session allow-set table (ds_filter).
read -r -d '' RULESET <<NFT
table inet ds_boundary
delete table inet ds_boundary
table inet ds_boundary {
	chain input {
		# BOX-SAFETY: policy ACCEPT — host Tailscale/SSH inbound is NEVER cut.
		type filter hook input priority filter; policy accept;
		ct state established,related accept
		iifname "lo" accept
	}
	chain forward {
		# Egress default-deny gate. DIRECT VM egress is dropped here; the
		# REDIRECT'd 53/80/443 flows are DNAT'd to local and handled in input.
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
		iifname "dstap-*" ct state new udp dport 443 counter reject with icmpx type port-unreachable
		iifname "dstap-*" ct state new drop
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		# NFT-2: DNS -> ds-dnsgate (both transports; tcp/53 can't bypass).
		iifname "dstap-*" udp dport 53 redirect to :${DNSGATE_REDIR_PORT}
		iifname "dstap-*" tcp dport 53 redirect to :${DNSGATE_REDIR_PORT}
		# NFT-2b fold (GAP 2): HTTP/HTTPS -> ds-tlsproxy.
		iifname "dstap-*" tcp dport 80  redirect to :${TLS_HTTP_PORT}
		iifname "dstap-*" tcp dport 443 redirect to :${TLS_HTTPS_PORT}
	}
}
# Per-session admit surface (ds-nft instantiate_session / Model A shape). In the
# live path ds-nft (invoked by the host-agent through the setcap'd ds-nethelper
# helper, built -tags nftgatelive; D148) creates these; rendered
# here so the floor is self-contained if you apply it standalone.
table inet ds_filter
table inet ds_filter {
	set allow4_${IDX} { type ipv4_addr; flags timeout; }
	set allow6_${IDX} { type ipv6_addr; flags timeout; }
}
NFT

# ── Preflight (NON-DESTRUCTIVE checks) ───────────────────────────────────────
preflight() {
  say "PREFLIGHT (posture=$POSTURE idx=$IDX dry_run=$DRY_RUN)"

  # GAP 1 detector: does ds-dnsgate bind 0.0.0.0:<redir-port>? Probe its banner
  # in a throwaway rootless netns (zero host touch) and read the printed addr.
  say "checking ds-dnsgate listen address (GAP 1: must be 0.0.0.0:${DNSGATE_REDIR_PORT}) ..."
  local probe; probe="$(unshare -rn bash -c '
    ip link set lo up 2>/dev/null
    timeout 5 '"$DNSGATE_BIN"' 2>&1 | grep -m1 "listeners up" ' 2>/dev/null)"
  printf '   ds-dnsgate banner: %s\n' "${probe:-<none>}"
  if printf '%s' "$probe" | grep -q "0.0.0.0:${DNSGATE_REDIR_PORT}"; then
    say "   GAP 1: RESOLVED — ds-dnsgate binds 0.0.0.0:${DNSGATE_REDIR_PORT}."
    DNSGATE_OK=1
  else
    say "   GAP 1: UNRESOLVED — ds-dnsgate binds loopback/ephemeral, NOT 0.0.0.0:${DNSGATE_REDIR_PORT}."
    say "          The DNS leg will NOT work until ds-dnsgate binds 0.0.0.0:${DNSGATE_REDIR_PORT}."
    say "          (Fix: set GateConfig.udp_addr/tcp_addr to (0.0.0.0, ${DNSGATE_REDIR_PORT}) in main.rs,"
    say "           or add a DS_DNSGATE_LISTEN env knob, then rebuild. Code change, dataplane owner.)"
    DNSGATE_OK=0
  fi

  # GAP 6: host ip_forward.
  local ipf; ipf="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '?')"
  say "host net.ipv4.ip_forward=${ipf} (need 1 for routed-tap forwarding; GAP 6)"
}

# ── Bring-up legs (each gated by run()) ──────────────────────────────────────
apply_floor() {
  say "STEP 1 — apply the management-safe floor + redirects + allow-sets"
  if [ "$DRY_RUN" = "0" ]; then
    printf '%s\n' "$RULESET" | sudo nft -f -  || die "nft -f failed"
    # Assert the box-safety invariant rendered before trusting the floor.
    sudo nft list chain inet ds_boundary input | grep -q 'policy accept' \
      || die "SAFETY ABORT: input chain is NOT policy accept after apply"
    say "   input=accept asserted; ss -ltn should still show your SSH/Tailscale:"
    ss -ltn | grep -E ':22|:41641|tailscale' || true
  else
    printf '%s\n' "$RULESET" | sed 's/^/   /'
  fi
}

enable_forwarding() {
  say "STEP 2 — enable host ip_forward (GAP 6), recording prior value for teardown"
  if [ "$DRY_RUN" = "0" ]; then
    cat /proc/sys/net/ipv4/ip_forward > "$RUN_DIR/.ip_forward.prev"
    run "sudo sysctl -w net.ipv4.ip_forward=1"
  else
    run "sudo sysctl -w net.ipv4.ip_forward=1"
  fi
}

start_tlsproxy() {
  say "STEP 3 — start ds-tlsproxy (binds 0.0.0.0:${TLS_HTTP_PORT}/${TLS_HTTPS_PORT})"
  # POSTURE=a: opaque terminate+forward, no cred-swap. (DS_TLS1_LIVE/DS_TLS3_LIVE
  # left UNSET => default opaque tunnel path; set them later to arm SNI/admission.)
  run "sudo -E env DS_TLS1_LIVE= DS_TLS3_LIVE= '$TLSPROXY_BIN' > '$RUN_DIR/tlsproxy.log' 2>&1 & echo \$! > '$RUN_DIR/tlsproxy.pid'"
}

start_dnsgate() {
  say "STEP 4 — start ds-dnsgate (DS_NFTGATE_LIVE=1 to fill allow4_${IDX} live; GAP 3)"
  if [ "${DNSGATE_OK:-0}" != "1" ]; then
    say "   SKIPPING ds-dnsgate start — GAP 1 unresolved (it would bind loopback, not :${DNSGATE_REDIR_PORT})."
    say "   Resolve GAP 1 (0.0.0.0:${DNSGATE_REDIR_PORT} bind) then re-run; HTTPS still works via tlsproxy."
    return 0
  fi
  # Live nft writer needs CAP_NET_ADMIN (root here) + the allow4_<idx> set present.
  run "sudo -E env DS_NFTGATE_LIVE=1 '$DNSGATE_BIN' > '$RUN_DIR/dnsgate.log' 2>&1 & echo \$! > '$RUN_DIR/dnsgate.pid'"
}

instantiate_session() {
  say "STEP 5 — create the routed tap + per-session admit sets (via the orchestrator host-agent)"
  # The real path: the orchestrator host-agent -routed-tap boots the session,
  # which forks the setcap'd ds-nethelper (D148) which calls ds-nft CreateTap (programs
  # 10.77.<idx>.0/31 + the /32 route to the guest) and InstantiateSession
  # (creates allow4_<idx>/allow6_<idx>). The floor above already rendered the
  # sets; CreateTap brings up the tap netdev + routing.
  run "sudo ip tuntap add '$TAP' mode tap"   # ds-nft create_tap does this + addressing:
  run "sudo ip link set '$TAP' up"
  run "sudo ip addr add '10.77.${IDX}.0/31' dev '$TAP'"
  run "sudo ip route add '10.77.${IDX}.1/32' dev '$TAP'"
  say "   (in production these four are ds-nft create_tap via the host-agent cgo edge, not hand-run)"
}

boot_vm() {
  say "STEP 6 — boot the per-session VM on the gated tap (NOT SLIRP)"
  say "   host-agent must run with -routed-tap AND DS_ROUTED_TAP=1 so NewLiveBooter renders"
  say "   the dstap-<idx> NIC + ds-net.env (10.77.${IDX}.1/31) onto the config-drive (GAP 5)."
  run "DS_ROUTED_TAP=1 '$REPO/orchestrator/...host-agent...' -routed-tap   # (operator wires the real invocation)"
  say "   The guest applies ds-net.env via ds-apply-netcfg.sh BEFORE ds-entrypoint (M0 image half)."
}

verify() {
  say "STEP 7 — VERIFY: CC reaches the API ONLY via the gateways; direct egress DENIED"
  cat <<'V'
   Run these once the VM is up (from the HOST, observing the boundary):
   (1) gateway listeners bound:
         ss -ltn | grep -E ':18080|:18443'           # tlsproxy
         ss -lun | grep ':15353' ; ss -ltn | grep ':15353'   # dnsgate (after GAP 1 fix)
   (2) the floor's box-safety invariant still holds:
         sudo nft list chain inet ds_boundary input | grep 'policy accept'
   (3) redirects + admit set present:
         sudo nft list chain inet ds_boundary prerouting
         sudo nft list set inet ds_filter allow4_<idx>     # fills as CC resolves names
   (4) FROM INSIDE THE VM (proves gated):
         curl https://api.anthropic.com/      # SUCCEEDS (via tlsproxy :18443)
         curl https://example.org/            # policy-denied by the gate, NOT direct
         curl --resolve evil:443:1.2.3.4 ...  # DNS forced through dnsgate; direct DNS blocked
         dig @8.8.8.8 anthropic.com           # REDIRECTED to dnsgate (cannot reach 8.8.8.8 directly)
         nc -w2 1.1.1.1 22                     # DROPPED by forward default-deny (direct egress)
   (5) counters prove the deny path fired:
         sudo nft list chain inet ds_boundary forward   # the ct-new-drop / quic-reject counters
V
}

teardown() {
  say "TEARDOWN — clean, idempotent, touches ONLY our tables"
  run "sudo nft delete table inet ds_filter   2>/dev/null || true"
  run "sudo nft delete table inet ds_boundary 2>/dev/null || true"
  run "sudo ip link del '$TAP' 2>/dev/null || true"
  if [ -f "$RUN_DIR/.ip_forward.prev" ]; then
    run "sudo sysctl -w net.ipv4.ip_forward=\$(cat '$RUN_DIR/.ip_forward.prev')"
  fi
  for p in dnsgate tlsproxy; do
    [ -f "$RUN_DIR/$p.pid" ] && run "sudo kill \$(cat '$RUN_DIR/$p.pid') 2>/dev/null || true"
  done
  say "teardown done; verify: sudo nft list ruleset | grep -E 'ds_boundary|ds_filter' (should be empty)"
}

# ── Entry ────────────────────────────────────────────────────────────────────
case "${1:-up}" in
  up)
    preflight
    apply_floor
    enable_forwarding
    start_tlsproxy
    start_dnsgate
    instantiate_session
    boot_vm
    verify
    say "DONE (dry_run=$DRY_RUN). If this was dry-run, review the [cmd] lines, get go-ahead, then DRY_RUN=0 ./ds-gated-egress.sh up"
    ;;
  preflight) preflight ;;
  down|teardown) teardown ;;
  verify) verify ;;
  *) die "usage: $0 {up|preflight|verify|down}  (env: POSTURE=a DS_SESSION_IDX=7 DRY_RUN=1)";;
esac
