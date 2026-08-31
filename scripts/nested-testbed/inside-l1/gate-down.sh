#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# gate-down.sh — runs INSIDE L1. Tear down the gated-egress boundary + L2 VM. Clean,
# idempotent, touches ONLY our tables/tap.
set -uo pipefail
IDX="${DS_SESSION_IDX:-7}"; TAP="dstap-${IDX}"
RUN="${DS_GATE_RUN:-/run/ds-gate}"; L2RUN="${DS_L2_RUN:-/run/ds-l2}"
say(){ printf '\033[1;36m[gate-down] %s\033[0m\n' "$*"; }

[ -f "$L2RUN/l2.pid" ] && kill "$(cat "$L2RUN/l2.pid")" 2>/dev/null && say "stopped L2 vm" || true
for p in dnsgate tlsproxy; do [ -f "$RUN/$p.pid" ] && kill "$(cat "$RUN/$p.pid")" 2>/dev/null && say "stopped $p" || true; done
nft delete table inet ds_filter   2>/dev/null && say "removed ds_filter"   || true
nft delete table inet ds_boundary 2>/dev/null && say "removed ds_boundary" || true
ip link del "$TAP" 2>/dev/null && say "removed $TAP" || true
say "down. (ip_forward left as-is)"
