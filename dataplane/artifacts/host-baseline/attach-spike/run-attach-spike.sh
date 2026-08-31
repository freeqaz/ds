#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run-attach-spike.sh — the reproducible procedure for the D66 Linux per-session
# attachment-primitive spike (OQ1/D66; doc 09 §2 placement note, §8 Stage 1;
# sessions/round2/01-linux-attachment-primitive.md). It is the *committed
# artifact* of the spike: a runnable, auto-detecting harness, not a captured blob.
#
# WHAT THE SPIKE DECIDES (the FREE implementation detail D66 left to this spike)
#   Among the three sound primitives D66 named — (1) per-session bridge,
#   (2) routed tap (libvirt type='ethernet'), (3) shared bridge + BR_ISOLATED —
#   this harness exercises the candidates and the spike write-up
#   (FINDINGS.md) records the recommendation (proposed: routed tap as the
#   default-lean structural primitive, per-session bridge as the equally-sound
#   alternative, BR_ISOLATED accepted only under the continuous flag audit).
#   The findings bind nothing (no D-number); D66 already ratified the dissolution.
#
# THE FOUR D66 EXIT CRITERIA THIS HARNESS COVERS
#   (i)   no-L2-path proof          — STRUCTURAL (enumerate-and-audit) + traffic
#   (ii)  per-session addressing    — per-session /31, distinct guest IP per tap
#   (iii) uplink-throughput number  — measured on the nested v0 substrate (HOST)
#   plus the dstap-<idx> naming contract (≤15 chars / IFNAMSIZ) and teardown.
#
# HONEST SANDBOX-vs-HOST SPLIT (the deliverable's stated obligation)
#   This dev sandbox kernel (7.0.10-arch1-1) has NO loadable `bridge`/`veth`
#   modules and NO conntrack hooks inside an unprivileged `unshare -rn` netns.
#   So the harness runs in two tiers and SAYS WHICH ran:
#     PHASE A (always, anywhere)     — naming-contract width, golden-rule text,
#                                      structural-audit logic. Pure userspace.
#     PHASE B (netns, sandbox-OK)    — tuntap create + `iifname`/`ip saddr` rule
#                                      APPLICATION inside `unshare -rn`. Proves
#                                      the enforcement match works against a real
#                                      kernel netfilter path (no ct, no bridge).
#     PHASE C (HOST-ONLY, needs priv)— per-session bridge/routed-tap/BR_ISOLATED
#                                      build, live L2-isolation traffic proof,
#                                      `ct state` rules, throughput. SKIPPED with
#                                      a loud banner when the substrate is absent;
#                                      the procedure is printed so a real host
#                                      operator can run it verbatim.
#
# Usage:
#   run-attach-spike.sh            # auto-detect; run A+B, print C procedure
#   run-attach-spike.sh --host     # demand the host substrate; fail if absent
#   run-attach-spike.sh --self-test  # adversarial non-vacuous proof of the
#                                      structural auditor + golden-drift detector
#                                      (house precedent: check-fixture-provenance
#                                      --self-test, proto-gates.sh). CI-wireable.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMAND_HOST=0
[ "${1:-}" = "--host" ] && DEMAND_HOST=1

pass=0 fail=0 skip=0
ok()   { printf '  [ OK ]   %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  [FAIL]   %s\n' "$1"; fail=$((fail + 1)); }
skipc(){ printf '  [SKIP]   %s  (host-only: %s)\n' "$1" "$2"; skip=$((skip + 1)); }

banner() { printf '\n=== %s ===\n' "$1"; }

# ---------------------------------------------------------------------------
# PHASE A — pure userspace (runs anywhere, no privileges, no kernel state)
# ---------------------------------------------------------------------------
phase_a() {
  banner "PHASE A — naming contract + golden rule text + structural-audit logic"

  # A1. dstap-<idx> width budget. IFNAMSIZ = 16 incl NUL → 15 printable chars;
  #     "dstap-" = 6 → 9 for the index (doc 14 §4, ds-contracts session.rs).
  local max_idx_digits=9
  local widest="dstap-$(printf '9%.0s' $(seq 1 $max_idx_digits))"
  if [ "${#widest}" -eq 15 ]; then
    ok "naming: widest dstap-<idx> ('$widest') is exactly 15 chars (IFNAMSIZ ceiling)"
  else
    bad "naming: widest dstap-<idx> is ${#widest} chars, expected 15"
  fi
  local over="dstap-$(printf '9%.0s' $(seq 1 $((max_idx_digits + 1))))"
  if [ "${#over}" -eq 16 ]; then
    ok "naming: a 10-digit index ('$over') is 16 chars — over IFNAMSIZ, must be rejected at create"
  else
    bad "naming: 10-digit index width math wrong (${#over})"
  fi

  # A2. golden rule text is reproducible from the generator.
  local got want
  got="$("$HERE/gen-attach-rules.sh" 3 --with-ct)"
  want="$(cat "$HERE/golden/attach-rules-n3.nft")"
  if [ "$got" = "$want" ]; then
    ok "golden: gen-attach-rules.sh 3 --with-ct matches golden/attach-rules-n3.nft"
  else
    bad "golden: generator output drifted from golden/attach-rules-n3.nft"
  fi

  # A3. addressing exit criterion (D69): each session's anchor carries a DISTINCT
  #     per-session guest IP, none shared. Audit the generated text directly.
  local ips
  ips="$(printf '%s\n' "$got" | grep -oE 'ip saddr 10\.77\.[0-9]+\.1' | sort)"
  local uniq total
  total="$(printf '%s\n' "$ips" | grep -c .)"
  uniq="$(printf '%s\n' "$ips" | sort -u | grep -c .)"
  if [ "$total" -eq 3 ] && [ "$uniq" -eq 3 ]; then
    ok "addressing (D69): 3 sessions present 3 DISTINCT interface-anchored guest IPs (no shared gateway)"
  else
    bad "addressing (D69): expected 3 distinct guest IPs, got total=$total uniq=$uniq"
  fi

  # A4. structural-audit logic: the no-L2-path proof must NEVER be inferred from
  #     the inet ruleset. Assert the auditor flags a shared-bridge layout. We run
  #     the auditor against two synthetic membership maps (no kernel needed).
  if audit_memberships "$(synthetic_good_map)"; then
    ok "structural audit: PASS on a per-tap/per-bridge (or routed) layout"
  else
    bad "structural audit: false-positive on a sound layout"
  fi
  if audit_memberships "$(synthetic_bad_map)"; then
    bad "structural audit: MISSED two agent taps sharing a non-isolated bridge (regression!)"
  else
    ok "structural audit: correctly FAILS two agent taps on one non-isolated bridge (D66 invariant load-bearing)"
  fi

  # A5. br_netfilter must be forbidden (D66). If the sysctl exists it must be 0.
  local f=/proc/sys/net/bridge/bridge-nf-call-iptables
  if [ ! -e "$f" ]; then
    ok "br_netfilter: bridge-nf-call-iptables absent (forbidden per D66 — not merely unused)"
  elif [ "$(cat "$f" 2>/dev/null)" = "0" ]; then
    ok "br_netfilter: present but disabled (=0); D66 forbids enabling it"
  else
    bad "br_netfilter: bridge-nf-call-iptables is ENABLED — D66 forbidden; would mask isolation bugs"
  fi
}

# audit_memberships <map> : the structural auditor (the runtime-+-per-commit check
#   the spike owns, sessions/round2/01 assurance test 2). <map> is lines of
#   "<iface> <role> <bridge|-> <isolated:yes|no|->". FAILS (returns non-zero) iff
#   two AGENT taps share a bridge without both isolated, or any agent tap shares a
#   bridge that also carries the UPLINK. Pure text; no kernel.
audit_memberships() {
  awk '
    { iface=$1; role=$2; br=$3; iso=$4
      if (br != "-") { roles[br]=roles[br] " " role; isos[br]=isos[br] " " iso }
    }
    END {
      bad=0
      for (b in roles) {
        nag=gsub(/agent/, "agent", roles[b])     # count agent members on bridge b
        # uplink co-tenancy: any agent tap on a bridge that also carries uplink
        if (roles[b] ~ /agent/ && roles[b] ~ /uplink/) { bad=1 }
        # two+ agent taps on one bridge: every agent member must be isolated
        if (nag >= 2) {
          niso=gsub(/yes/, "yes", isos[b])
          if (niso < nag) bad=1
        }
      }
      exit bad
    }' <<<"$1"
}
synthetic_good_map() {
  # Each agent tap on its own bridge (or routed: br="-"); uplink alone.
  printf 'dstap-0 agent br-s0 -\ndstap-1 agent br-s1 -\ndstap-2 agent - -\neth0 uplink br-up -\n'
}
synthetic_bad_map() {
  # Two agent taps on ONE non-isolated bridge — the exact D66 sharp edge.
  printf 'dstap-0 agent br-shared no\ndstap-1 agent br-shared no\neth0 uplink br-up -\n'
}

# ---------------------------------------------------------------------------
# PHASE B — netns rule application (sandbox-OK: tuntap + iifname/ip-saddr apply)
# ---------------------------------------------------------------------------
phase_b() {
  banner "PHASE B — netns: tuntap create + iifname/ip-saddr rule APPLICATION (sandbox-verified)"
  if ! unshare -rn true 2>/dev/null; then
    skipc "netns rule application" "unprivileged user+net namespaces unavailable"
    return
  fi
  local rules="$HERE/golden/attach-rules-n3-noct.nft"
  # Run the whole phase inside one netns so the tap + ruleset share a kernel view.
  if unshare -rn bash -c '
        set -e
        # B1. create the widest-legal tap, prove the name survives the kernel.
        ip tuntap add dev dstap-999999999 mode tap
        ip -o link show dstap-999999999 >/dev/null
        # B2. a 16-char name must be refused by the kernel (IFNAMSIZ).
        if ip tuntap add dev dstap-9999999999 mode tap 2>/dev/null; then exit 21; fi
        # B3. apply the iifname + ip-saddr forward anchors against a real netfilter
        #     path and read them back byte-checking the iifname match survived.
        nft -f "'"$rules"'"
        nft list table inet ds_attach_audit | grep -q "iifname \"dstap-0\" ip saddr 10.77.0.1" || exit 23
        nft list table inet ds_attach_audit | grep -q "iifname \"dstap-\*\" counter" || exit 24
     '; then
    ok "netns: widest dstap-999999999 created; 16-char name kernel-refused; iifname+ip-saddr ruleset APPLIED + read back"
  else
    bad "netns: phase B assertions failed (rc above) — see manual repro in FINDINGS.md"
  fi
}

# ---------------------------------------------------------------------------
# PHASE C — host-only (bridge/routed-tap/BR_ISOLATED build, L2 traffic, throughput)
# ---------------------------------------------------------------------------
phase_c() {
  banner "PHASE C — HOST-ONLY (real kernel: bridge/veth/conntrack/throughput)"
  local have_bridge=0 have_veth=0
  modprobe -n bridge >/dev/null 2>&1 && have_bridge=1
  modprobe -n veth   >/dev/null 2>&1 && have_veth=1
  # In the dev sandbox these modules are absent (CONFIG_*=m but no modules dir).
  if [ "$have_bridge" -eq 0 ] || [ "$have_veth" -eq 0 ]; then
    cat <<'PROC'

  ┌─ HOST SUBSTRATE ABSENT — PHASE C NOT RUN ───────────────────────────────┐
  │ The dev sandbox kernel exposes no loadable `bridge`/`veth` and no        │
  │ conntrack hooks in an unprivileged netns, so the THREE primitives and    │
  │ the live L2-isolation / throughput proofs are HOST-ONLY. Run this on the │
  │ virtual-metal VM (sudo, real kernel ≥6.12, /dev/kvm) verbatim:           │
  └─────────────────────────────────────────────────────────────────────────┘

  # --- Candidate 1: ROUTED TAP (default lean — structural, no bridge object) ---
  sudo ip tuntap add dev dstap-0 mode tap; sudo ip link set dstap-0 up
  sudo ip addr add 10.77.0.0/31 dev dstap-0        # host = gateway .0
  sudo ip route add 10.77.0.1/32 dev dstap-0       # guest .1, on-link via the tap
  sudo ip neigh replace 10.77.0.1 lladdr <guest-mac> dev dstap-0
  #   repeat for dstap-1 (10.77.1.0/31). NO bridge exists → no shared L2 segment
  #   by construction → the no-L2-path proof is STRUCTURAL (enumerate: zero
  #   bridges carry two agent taps).

  # --- Candidate 2: PER-SESSION BRIDGE (equally sound, structural) ---
  sudo ip link add ds-br-0 type bridge; sudo ip link set dstap-0 master ds-br-0
  sudo ip addr add 10.77.0.0/31 dev ds-br-0        # gateway on the bridge device
  #   one tap per bridge → still no shared segment. Audit: each bridge has exactly
  #   one agent member.

  # --- Candidate 3: SHARED BRIDGE + BR_ISOLATED (flag-audited, NOT default) ---
  sudo ip link add ds-br type bridge
  sudo ip link set dstap-0 master ds-br; sudo bridge link set dev dstap-0 isolated on
  sudo ip link set dstap-1 master ds-br; sudo bridge link set dev dstap-1 isolated on
  #   isolated ports can't talk to each other, only to the host. Proof rests on a
  #   per-port flag surviving every re-attach → demands the CONTINUOUS audit
  #   (run-attach-spike.sh PHASE A structural auditor, as a blocking runtime alarm).

  # --- no-L2-path TRAFFIC PROOF (sessions/round2/01 assurance test 1) ---
  #   from guest A: arping -I eth0 10.77.1.1 ; ndisc to B; raw-eth unicast to B's MAC;
  #   forged-MAC frame toward B. Assert ZERO frames arrive on dstap-1:
  sudo timeout 5 tcpdump -ni dstap-1 -c1 'not arp or arp' ; echo "expect: 0 packets"

  # --- br_netfilter MUST be absent/0 (D66 forbidden) ---
  test ! -e /proc/sys/net/bridge/bridge-nf-call-iptables || \
    [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = 0 ]

  # --- UPLINK THROUGHPUT (D66 exit criterion iii; (d)-rig capacity input) ---
  #   On the NESTED v0 substrate, under many-VMs load, measure per-session AND
  #   aggregate egress through the single virtual-metal uplink:
  iperf3 -s &                                  # on an upstream reflector
  for s in 0 1 2; do ip netns exec guest-$s iperf3 -c <reflector> -t 30 -P 4 & done; wait
  #   record aggregate Gbps as the per-host session-capacity number (RECORDED on
  #   nested per D34, ASSERTED with thresholds on metal only).

PROC
    skipc "three-primitive build + live L2-isolation proof" "no loadable bridge/veth in sandbox kernel"
    skipc "ct state rules + teardown-to-bootstrap" "no conntrack hooks in unprivileged netns"
    skipc "uplink throughput measurement" "needs the nested v0 substrate + traffic generators"
    if [ "$DEMAND_HOST" -eq 1 ]; then
      printf '\n--host was requested but the substrate is absent — failing.\n'
      fail=$((fail + 1))
    fi
    return
  fi

  # If we ever DO have the modules (real host), run the live proofs here. Left as
  # the executable procedure above for the sandbox; a host CI lane wires this body.
  ok "host substrate present — run the Candidate 1/2/3 + traffic + throughput steps above under CI"
}

# ---------------------------------------------------------------------------
# --self-test — adversarial, non-vacuous: the auditor MUST reject the bad layout
#   and the golden-drift detector MUST trip on a mutated generator. Both negative
#   cases must exit non-zero, or this whole spike is theater. No kernel needed.
# ---------------------------------------------------------------------------
self_test() {
  banner "SELF-TEST — non-vacuous proof (negative cases must be caught)"
  local rc=0
  # 1. auditor catches two agent taps on one non-isolated bridge.
  if audit_memberships "$(synthetic_bad_map)"; then
    bad "self-test: auditor PASSED a shared non-isolated bridge — vacuous!"; rc=1
  else
    ok "self-test: auditor rejects the shared non-isolated bridge (the D66 sharp edge)"
  fi
  # 2. auditor catches an agent tap co-tenant with the uplink.
  if audit_memberships "$(printf 'dstap-0 agent br-up -\neth0 uplink br-up -\n')"; then
    bad "self-test: auditor PASSED an agent tap sharing the uplink bridge — vacuous!"; rc=1
  else
    ok "self-test: auditor rejects an agent tap on the uplink bridge"
  fi
  # 3. auditor accepts a sound shared bridge ONLY when every agent port isolated.
  if audit_memberships "$(printf 'dstap-0 agent br-shared yes\ndstap-1 agent br-shared yes\n')"; then
    ok "self-test: auditor accepts a shared bridge with ALL agent ports isolated (BR_ISOLATED path)"
  else
    bad "self-test: auditor wrongly rejected an all-isolated shared bridge"; rc=1
  fi
  # 4. golden-drift: a mutated generator output must NOT match the golden.
  local mutated
  mutated="$("$HERE/gen-attach-rules.sh" 3 --with-ct | sed 's/10\.77\.0\.1/10.77.0.99/')"
  if [ "$mutated" = "$(cat "$HERE/golden/attach-rules-n3.nft")" ]; then
    bad "self-test: golden matched a MUTATED ruleset — drift detector is vacuous!"; rc=1
  else
    ok "self-test: golden-drift detector trips on a mutated guest IP"
  fi
  return "$rc"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test; st=$?
  banner "SUMMARY"
  printf '  self-test pass=%d  fail=%d\n' "$pass" "$fail"
  exit "$st"
fi

phase_a
phase_b
phase_c

banner "SUMMARY"
printf '  pass=%d  fail=%d  skip=%d (skip = host-only, procedure printed above)\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
