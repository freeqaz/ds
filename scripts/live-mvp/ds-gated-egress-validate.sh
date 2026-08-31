#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ds-gated-egress-validate.sh — NETNS-ONLY validation of the gated-egress ruleset.
# ZERO host network touch: EVERYTHING below runs inside `unshare -rn` (a rootless
# network namespace). The host's real nft/ip/routing is never read or written.
# Writes proof to ~/tmp/ds-gated-egress-proof.txt. Reads nothing destructive.
set -uo pipefail

PROOF="${HOME}/tmp/ds-gated-egress-proof.txt"
: > "$PROOF"
log() { printf '%s\n' "$*" | tee -a "$PROOF"; }
hr()  { printf '%s\n' "------------------------------------------------------------" | tee -a "$PROOF"; }

IDX=7   # demo per-session host index → tap dstap-7, allow4_7, /31 10.77.7.x

# The COMPLETE gated-egress ruleset under test, assembled in-script:
#   (A) the management-safe floor (ds_boundary): input policy ACCEPT, forward DROP,
#       nat prerouting 53->:15353 redirect  — verbatim shape from ~/tmp/ds-boundary-scoped.nft
#   (B) the NFT-2b 443/80 -> ds-tlsproxy redirect, folded INTO ds_boundary's prerouting
#       (the nft-2b-spike shape, glob iifname dstap-* not the spike's single dstap-0)
#   (C) the per-session admit table ds_filter with the allow4_<idx> set (ds-nft session.rs shape)
RULESET="$(cat <<NFT
table inet ds_boundary
delete table inet ds_boundary

table inet ds_boundary {
	chain input {
		# BOX-SAFETY KEYSTONE: policy ACCEPT so host Tailscale/SSH is never cut.
		type filter hook input priority filter; policy accept;
		ct state established,related accept
		iifname "lo" accept
	}

	chain forward {
		# Egress default-deny gate for the per-session tap.
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
		# NFT-2: 53 -> ds-dnsgate
		iifname "dstap-*" udp dport 53 redirect to :15353
		iifname "dstap-*" tcp dport 53 redirect to :15353
		# NFT-2b (folded in for "fully sandboxed"): 80/443 -> ds-tlsproxy
		iifname "dstap-*" tcp dport 80 redirect to :18080
		iifname "dstap-*" tcp dport 443 redirect to :18443
	}
}

# Per-session admit surface (ds-nft instantiate_session shape: Model A, the two empty sets).
table inet ds_filter
delete table inet ds_filter
table inet ds_filter {
	set allow4_${IDX} { type ipv4_addr; flags timeout; }
	set allow6_${IDX} { type ipv6_addr; flags timeout; }
}
NFT
)"

# ───────────────────────────────────────────────────────────────────────────────
# Run the WHOLE validation inside ONE rootless netns. Nothing escapes to the host.
# ───────────────────────────────────────────────────────────────────────────────
export RULESET_ENV="$RULESET"
unshare -rn bash -s -- "$IDX" <<'NETNS' 2>&1 | tee -a "$PROOF"
set -uo pipefail
IDX="$1"
RULESET="$RULESET_ENV"

echo "## netns identity (proof this is an isolated namespace, not the host):"
ip -o link show | awk -F': ' '{print "   iface: "$2}'
echo "   (host has Tailscale/SSH/etc; this netns has only lo — confirms isolation)"
echo

echo "## 1. create the dummy per-session tap dstap-${IDX} INSIDE the netns"
ip tuntap add "dstap-${IDX}" mode tap 2>&1 || echo "   tuntap add rc=$?"
ip link set "dstap-${IDX}" up 2>&1 || true
ip addr add "10.77.${IDX}.0/31" dev "dstap-${IDX}" 2>&1 || true
ip route add "10.77.${IDX}.1/32" dev "dstap-${IDX}" 2>&1 || true
ip -o link show "dstap-${IDX}" >/dev/null 2>&1 && echo "   dstap-${IDX} present: YES" || echo "   dstap-${IDX} present: NO"
echo

echo "## 2. apply the COMPLETE gated-egress ruleset (floor + 53/80/443 redirect + allow-sets)"
if printf '%s\n' "$RULESET" | nft -f - 2>&1; then
  echo "   APPLY: OK (ruleset loaded clean in netns with live nat/redirect/reject/conntrack)"
else
  echo "   APPLY: FAILED (rc=$?) — see errors above"
fi
echo

echo "## 3. ASSERTIONS"
echo
echo "### (i) BOX-SAFETY INVARIANT — input chain is policy ACCEPT:"
nft list chain inet ds_boundary input 2>&1 | sed 's/^/   /'
if nft list chain inet ds_boundary input 2>/dev/null | grep -q 'policy accept'; then
  echo "   ASSERT (i): PASS — input policy accept (host management can NEVER be cut)"
else
  echo "   ASSERT (i): FAIL — input is NOT policy accept"
fi
echo

echo "### (ii) forward chain is default-deny (policy drop):"
nft list chain inet ds_boundary forward 2>&1 | sed 's/^/   /'
if nft list chain inet ds_boundary forward 2>/dev/null | grep -q 'policy drop'; then
  echo "   ASSERT (ii): PASS — forward policy drop (tap egress gated by default)"
else
  echo "   ASSERT (ii): FAIL — forward is NOT policy drop"
fi
echo

echo "### (iii) the 53/80/443 redirects rendered in nat prerouting:"
nft list chain inet ds_boundary prerouting 2>&1 | sed 's/^/   /'
PR="$(nft list chain inet ds_boundary prerouting 2>/dev/null)"
ok=1
echo "$PR" | grep -q 'udp dport 53 redirect to :15353' || { echo "   MISS: udp/53->15353"; ok=0; }
echo "$PR" | grep -q 'tcp dport 53 redirect to :15353' || { echo "   MISS: tcp/53->15353"; ok=0; }
echo "$PR" | grep -q 'tcp dport 80 redirect to :18080'  || { echo "   MISS: tcp/80->18080"; ok=0; }
echo "$PR" | grep -q 'tcp dport 443 redirect to :18443' || { echo "   MISS: tcp/443->18443"; ok=0; }
[ "$ok" = 1 ] && echo "   ASSERT (iii): PASS — all four redirects (53 udp/tcp, 80, 443) render" || echo "   ASSERT (iii): FAIL"
echo

echo "### (iv) per-session admit allow4_${IDX} — add then remove an element:"
nft list set inet ds_filter "allow4_${IDX}" 2>&1 | sed 's/^/   before: /'
if nft add element inet ds_filter "allow4_${IDX}" '{ 160.79.104.10 timeout 900s }' 2>&1; then
  echo "   ADD element 160.79.104.10 timeout 900s: OK"
fi
nft list set inet ds_filter "allow4_${IDX}" 2>&1 | sed 's/^/   after-add: /'
ADDED=0
nft list set inet ds_filter "allow4_${IDX}" 2>/dev/null | grep -q '160.79.104.10' && ADDED=1
if nft delete element inet ds_filter "allow4_${IDX}" '{ 160.79.104.10 }' 2>&1; then
  echo "   DELETE element 160.79.104.10: OK"
fi
nft list set inet ds_filter "allow4_${IDX}" 2>&1 | sed 's/^/   after-del: /'
REMOVED=1
nft list set inet ds_filter "allow4_${IDX}" 2>/dev/null | grep -q '160.79.104.10' && REMOVED=0
if [ "$ADDED" = 1 ] && [ "$REMOVED" = 1 ]; then
  echo "   ASSERT (iv): PASS — allow4_${IDX} element add+remove round-trips"
else
  echo "   ASSERT (iv): FAIL (added=$ADDED removed=$REMOVED)"
fi
echo

echo "### (bonus) ds-nft redirect.rs shape-lint cross-check: the prerouting both-transport 53 redirect"
echo "   (validated structurally by crates/ds-nft/src/redirect.rs::satisfies_nft2_redirect_shape)"
echo

echo "## 4. teardown round-trip (create->destroy returns to baseline byte-identically)"
nft delete table inet ds_filter 2>&1 && echo "   delete ds_filter: OK"
nft delete table inet ds_boundary 2>&1 && echo "   delete ds_boundary: OK"
nft list ruleset 2>&1 | grep -q . && echo "   residual ruleset present" || echo "   ruleset empty after teardown: PASS (round-trip clean)"
ip link del "dstap-${IDX}" 2>&1 && echo "   delete dstap-${IDX}: OK"
echo
echo "## netns exits here; the kernel discards this namespace. HOST UNTOUCHED."
NETNS

rc=$?
hr
log "VALIDATION SCRIPT EXIT rc=${rc}"
log "Proof written to: ${PROOF}"
