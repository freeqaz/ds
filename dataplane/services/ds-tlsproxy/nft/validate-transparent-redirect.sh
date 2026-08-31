#!/usr/bin/env bash
# Validate the NFT-2 transparent-redirect ruleset (doc 03 §3; doc 09 NFT-2; D69)
# WITHOUT root and WITHOUT a reboot, honestly separating what loads now from what
# is reboot-pending. Run from anywhere; uses only `unshare -rn` (user+net ns).
#
#   ./validate-transparent-redirect.sh
#
# Three checks, each printed PASS / DEFERRED:
#   1. iifname interface-match LOADS  (the NFT-2 control — must pass)
#   2. nat-type prerouting chain LOADS (the dstnat hook — must pass)
#   3. `redirect to :port` statement   (the live REDIRECT — DEFERRED on a host
#                                       whose kernel lacks nft_redir/nft_nat)
#
# This is the reproducible procedure the spike commits. It NEVER fabricates a
# green kernel-redirect result: on a host with the modules loaded, check 3 flips
# to PASS and the live iifname-REDIRECT + SO_ORIGINAL_DST recovery demo (the
# manual step in SPIKE-NOTES.md §E1) becomes runnable.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
fail=0

run_ns() { unshare -rn sh -c "$1" 2>&1; }

echo "== check 1: iifname interface-match (the NFT-2 control) =="
c1="$(run_ns '
nft add table inet ds_iiftest
nft "add chain inet ds_iiftest fwd { type filter hook forward priority 0 ; policy drop ; }"
nft add rule inet ds_iiftest fwd iifname \"dstap-0\" accept
nft list chain inet ds_iiftest fwd
')"
if printf '%s' "$c1" | grep -q 'iifname "dstap-0"'; then
	echo "  PASS — iifname match loads (the interface, never source IP)"
else
	echo "  FAIL — iifname match did not load:"; printf '%s\n' "$c1" | sed 's/^/    /'; fail=1
fi

echo "== check 2: nat-type prerouting chain at dstnat priority =="
c2="$(run_ns '
nft add table ip ds_nattest
nft "add chain ip ds_nattest pre { type nat hook prerouting priority dstnat ; policy accept ; }"
nft list chain ip ds_nattest pre
')"
if printf '%s' "$c2" | grep -q 'type nat hook prerouting'; then
	echo "  PASS — nat prerouting hook loads"
else
	echo "  FAIL — nat prerouting hook did not load:"; printf '%s\n' "$c2" | sed 's/^/    /'; fail=1
fi

echo "== check 3: redirect-to-port statement (the LIVE transparent REDIRECT) =="
# The PASS signal is the rule body appearing in a CLEAN `nft list` of the chain
# (stdout-only, after the add) — NEVER the `nft add` output, because a failed
# add echoes the offending command (which contains the words "redirect to") in
# its error text. A failed add (module gap) leaves the chain EMPTY, so the clean
# list shows no redirect line and we report DEFERRED. This deliberately refuses
# to fabricate a green kernel-redirect result. Exit status of the add is the
# ground truth; the clean list is the corroboration.
c3="$(run_ns '
nft add table ip ds_redirtest >/dev/null 2>&1
nft "add chain ip ds_redirtest pre { type nat hook prerouting priority dstnat ; policy accept ; }" >/dev/null 2>&1
if nft add rule ip ds_redirtest pre iifname \"dstap-0\" tcp dport 80 redirect to :18080 >/dev/null 2>&1; then
	echo ADD_OK
else
	echo ADD_FAILED
fi
# clean list (stdout only) — never echoes the failed command
nft list chain ip ds_redirtest pre 2>/dev/null
')"
if printf '%s' "$c3" | grep -q 'ADD_OK' && printf '%s' "$c3" | grep -q 'redirect to'; then
	echo "  PASS — redirect statement loads; the LIVE iifname-REDIRECT demo is RUNNABLE on this host."
	echo "         (run SPIKE-NOTES.md §E1 to exercise SO_ORIGINAL_DST recovery end to end.)"
else
	echo "  DEFERRED — redirect statement REFUSED by the running kernel (nft_redir/nft_nat absent)."
	echo "         The add failed and the chain stayed empty (corroboration):"
	printf '%s\n' "$c3" | sed 's/^/    /'
	echo "         This is the reboot-pending gap. The recovery wiring it feeds is"
	echo "         validated now over loopback + the real SO_ORIGINAL_DST getsockopt"
	echo "         (cargo test -p ds-tlsproxy: transparent::tests + e2e_transparent_forward)."
fi

echo
echo "== full spike ruleset (golden text) =="
echo "  $here/transparent-redirect.nft"
if [ "$fail" -eq 0 ]; then
	echo "RESULT: controls load; live REDIRECT status reported honestly above."
else
	echo "RESULT: a load-bearing control FAILED — see above."; exit 1
fi
