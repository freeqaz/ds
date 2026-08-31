#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# stack-up.sh — the Arch-1 bare-metal dogfood-host bring-up narrative, as an
# EXECUTABLE. It is the ordered, reviewable-as-code account of how the
# ds-nethelper ROOT-HELPER privilege model (maintainer ruling 2026-07-09, chosen over
# setcap-on-host-agent / run-as-root) is built, installed, capability-armed,
# self-checked, and exercised for one session — WITHOUT ever running a
# privileged step in this run.
#
# ── MODES ──────────────────────────────────────────────────────────────────
#   --dry-run   (DEFAULT, and the ONLY mode this script implements): print EVERY
#               action in order, prefixed with a stable STEP marker, running
#               NONE of them. No host mutation, no build, no setcap, no nft/ip.
#   live        REFUSED, always, and exits nonzero — NOT because the wiring is
#               unratified (D148 ratified it 2026-07-30) but because this file
#               is the NARRATIVE, not the apply tool. Applying is deliberately
#               owned by two other, testable, single-purpose scripts:
#                 · ../install-ds-nethelper.sh   (armed install + setcap + verify)
#                 · scripts/host-bringup/stack-up-host.sh (the real host bring-up)
#               Duplicating the privileged steps here would give the dogfood host
#               two divergent copies of its own install posture.
#
# WHY THIS SCRIPT EXISTS. The privileged install posture — capability flavor,
# ordering, the per-session op sequence and its exact stdin JSON — is the load-
# bearing security surface of the dogfood host. Emitting it as an ordered dry
# run keeps it diffable and reviewable as ONE artifact, independently of the
# scripts that execute it. The verbs, params shapes, and exit codes printed
# below mirror nethelperproto/proto.go one-for-one (both sides compile that one
# package).
#
# HARD SAFETY: this file NEVER runs nft/ip/systemctl/setcap against the host.
# The per-session sequence is PRINTED, not executed. Namespace rehearsal of the
# kernel ops (unshare -rn) lives in scripts/netns-validate.sh, not here.

set -uo pipefail

# ── knobs (all overridable; defaults are the intended dogfood layout) ────────
REPO_ROOT="${DS_REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}" # canonical repo (build cwd)
HELPER_PKG="${DS_HELPER_PKG:-./orchestrator/cmd/ds-nethelper}"  # in-repo home (OSS orchestrator tree, D80)
AGENT_PKG="${DS_AGENT_PKG:-./orchestrator/cmd/host-agent}"      # host-agent, built cgo-free forever
DEST="${DS_NETHELPER_DEST:-/usr/local/libexec/ds-nethelper}"    # installed helper path
AGENT_GROUP="${DS_NETHELPER_GROUP:-ds-agent}"                   # exec-authn group (0750 root:<grp>)
# The example session identity the per-session sequence is rendered for.
SESS_IDX="${DS_DEMO_INDEX:-7}"                                  # host session index (never recycled, D66)
SESS_TAP="dstap-${SESS_IDX}"                                    # dstap-<idx> join key (doc 14 §4)
SESS_OWNER_UID="${DS_DEMO_OWNER_UID:-$(id -u)}"                 # tap owner == invoking uid (helper rule)
SESS_MAC="${DS_DEMO_MAC:-52:54:00:ab:cd:ef}"                    # guest lladdr (optional static-neigh leg)

# ── output helpers ───────────────────────────────────────────────────────────
STEP_N=0
step() { # step <title>
  STEP_N=$((STEP_N + 1))
  printf 'STEP %d: %s\n' "$STEP_N" "$1"
}
cmd() {  printf '  $ %s\n' "$1"; }          # a command that WOULD run
note() { printf '  # %s\n' "$1"; }          # an inline rationale comment
# op <verb> <json> — render one helper invocation exactly as the agent forks it:
# argv is [verb] only (op visible in exec auditing), params are ONE JSON object
# on stdin. Mirrors nethelperclient.Client.invoke.
op() { printf "  $ printf '%s' | %s %s\n" "$2" "$DEST" "$1"; }

# ── live-mode gate: refuse, and say why ──────────────────────────────────────
MODE="dry-run"
case "${1:-}" in
  ""|--dry-run) MODE="dry-run" ;;
  live|--live|--apply)
    MODE="live"
    echo "REFUSING live bring-up: this script is the NARRATIVE, not the apply tool." >&2
    echo "  The live wiring is RATIFIED (D148, 2026-07-30) — the doc 14 §6 linker set is now" >&2
    echo "  {ds-dnsgate, ds-nethelper} and the host agent runs unprivileged — but applying it" >&2
    echo "  belongs to the two single-purpose scripts that are tested as apply tools:" >&2
    echo "    install:  DS_NETHELPER_APPLY=1 <repo>/orchestrator/cmd/ds-nethelper/scripts/install-ds-nethelper.sh <built-helper>" >&2
    echo "    bring-up: <repo>/scripts/host-bringup/stack-up-host.sh up" >&2
    echo "  Keeping the privileged steps in ONE place is the point: a second copy here would" >&2
    echo "  let the dogfood host's install posture drift from the posture printed below." >&2
    if [[ "${DS_NETHELPER_APPLY:-0}" == "1" ]]; then
      echo "  (DS_NETHELPER_APPLY=1 is set; it arms install-ds-nethelper.sh, never this script.)" >&2
    fi
    exit 3
    ;;
  *)
    echo "usage: $0 [--dry-run]        (default; the only mode this script implements)" >&2
    echo "       $0 live               (always refused — use install-ds-nethelper.sh / stack-up-host.sh; D148)" >&2
    exit 2
    ;;
esac

echo "=== ds-nethelper dogfood-host bring-up (DRY RUN — nothing below is executed) ==="
echo "repo=$REPO_ROOT helper=$DEST group=$AGENT_GROUP session=($SESS_TAP idx=$SESS_IDX)"
echo

# ── (1) build the privileged ds-nft staticlib (Rust) ─────────────────────────
step "build the ds-nft privileged staticlib (libds_nft.a)"
cmd "cd $REPO_ROOT/dataplane && cargo build -p ds-nft --release"
note "produces dataplane/target/release/libds_nft.a (crate-type staticlib) + the"
note "checked-in include/ds_nft.h — the C-ABI the helper's cgo edge links."

# ── (2) build the helper WITH the cgo write edge ─────────────────────────────
step "build ds-nethelper WITH the privileged backend (-tags nftgatelive)"
cmd "cd $REPO_ROOT && CGO_ENABLED=1 go build -tags nftgatelive -o ./bin/ds-nethelper $HELPER_PKG"
note "the ONLY cgo-linked binary in the stack: it links libds_nft.a via the same"
note "write edge as nftbridge/writeedge.go. DEFAULT builds stay cgo-free (stub"
note "backend, fail-closed ENOTBUILT) — the tag is what arms the privileged path."

# ── (3) build the host-agent WITHOUT the tag (unprivileged forever) ──────────
step "build host-agent WITHOUT the tag (agent stays cgo-free / unprivileged)"
cmd "cd $REPO_ROOT && go build -o ./bin/host-agent $AGENT_PKG"
note "the host-agent NEVER links the write edge and NEVER carries a capability:"
note "it forks the setcap'd helper per privileged op (nethelperclient). This is"
note "the whole point of the ROOT-HELPER model — the agent process is untrusted."
note "ENFORCED, not just documented: cmd/host-agent/nftgatelive_refuse.go makes a"
note "-tags nftgatelive host-agent build a COMPILE ERROR (D148 linker set)."

# ── (4) install the helper with the exec-authn perms ─────────────────────────
step "install the helper 0750 root:${AGENT_GROUP}"
cmd "sudo install -o root -g $AGENT_GROUP -m 0750 $REPO_ROOT/bin/ds-nethelper $DEST"
note "filesystem perms ARE the authn boundary: only members of the agent group"
note "may exec the helper; owned root so the caller cannot rewrite the binary."

# ── (5) arm the capability on the HELPER (not the agent) ──────────────────────
step "setcap the helper — cap_net_admin+eip (NOT +ep)"
cmd "sudo setcap cap_net_admin+eip $DEST"
note "+eip, NOT +ep: the ds-nft backend EXECS ip/nft, and FILE capabilities do"
note "NOT survive execve — a +ep helper would lose CAP_NET_ADMIN the moment it"
note "shells out. +eip puts the cap in the INHERITABLE set too, and the helper"
note "does PR_CAP_AMBIENT_RAISE(CAP_NET_ADMIN) scoped to the backend call so the"
note "ambient set carries it across execve into ip/nft. The cap lives on the"
note "HELPER binary, never on the host-agent."
note "FOOTGUN: capabilities are an xattr on the INSTALLED file — a rebuild/recopy"
note "produces a cap-less binary. setcap MUST be re-run after EVERY rebuild;"
note "the probe (step 6) is what catches a half-armed host at bring-up."

# ── (6) probe: fail-closed readiness BEFORE any session ──────────────────────
step "probe the installed helper — verify ProbeReady (Built && effective && ambient-raisable) before anything else"
op "probe" ""
note "read-only self-check: reports v/ok/code plus built and the THREE-field"
note "CAP_NET_ADMIN posture (effective / inheritable / ambient_raise_ok). The"
note "agent's boundary-readiness gate keys on ProbeReady() = Built &&"
note "cap_net_admin_effective && ambient_raise_ok and refuses to admit any"
note "session otherwise — the rebuilt-binary footgun AND a wrong-flavor"
note "+ep-only setcap (effective-green, ip/nft children stranded) both surface"
note "HERE, loud, not mid-create. This gate REPLACED the old nftbridge.Built"
note "check (permanently false in the untag'd host-agent): the host-agent now"
note "keys newAttachPrimitive/newBoundaryReadiness on the helper client and"
note "REFUSES bring-up unless Probe().Ready() (verifyHelperReady, D148)."
cmd 'expect: {"v":1,"op":"probe","ok":true,"code":"OK","built":true,"cap_net_admin_effective":true,"cap_net_admin_inheritable":true,"ambient_raise_ok":true,"cap_net_admin":true}'
note '(cap_net_admin is the retained legacy effective-set alias; readiness must'
note 'NOT key on it alone — that is the +ep half-configuration trap.)'

# ── (7) the per-session privileged op sequence (create, then rollback trio) ──
step "per-session CREATE ops (what the agent forks for session idx=$SESS_IDX)"
note "each line: one exec = one argv-verb = one JSON params object on stdin ="
note "one Result line + one audit line = exit. Exact stdin JSON below."

op "create-tap" "$(printf '{"tap_name":"%s","owner_uid":%s,"host_session_index":%s,"guest_mac":"%s"}' "$SESS_TAP" "$SESS_OWNER_UID" "$SESS_IDX" "$SESS_MAC")"
note "programs the routed tap: netdev + 10.77.$SESS_IDX.0/31 gateway + /32 route"
note "+ static neigh (guest_mac optional; empty ⇒ neigh leg skipped). owner_uid"
note "MUST equal the invoking uid — the helper re-checks os.Getuid()."

op "instantiate-session" "$(printf '{"tap_name":"%s","host_session_index":%s}' "$SESS_TAP" "$SESS_IDX")"
note "creates the EMPTY allow4_$SESS_IDX/allow6_$SESS_IDX admit sets in inet"
note "ds_filter — the admit SURFACE only. Per-session policy CONTENT flows via"
note "ds-dnsgate (the other ds-nft linker), NEVER through this helper."

echo
step "per-session ROLLBACK/TEARDOWN trio (fixed NFT-6 order: flush -> teardown -> delete)"
note "best-effort + idempotent; the agent runs this on mid-create fault and on"
note "session end (nethelperclient.TeardownAll). Order is load-bearing: kill live"
note "flows (flush) BEFORE removing the admit sets, then remove the tap last."

op "flush-session" "$(printf '{"tap_name":"%s","host_session_index":%s}' "$SESS_TAP" "$SESS_IDX")"
note "unconditional NFT-6 conntrack-by-mark flush (ds_nft_flush_session)."

op "teardown-session" "$(printf '{"tap_name":"%s","host_session_index":%s}' "$SESS_TAP" "$SESS_IDX")"
note "removes the per-session allow-sets (the named-set half of NFT-6)."

op "delete-tap" "$(printf '{"tap_name":"%s","host_session_index":%s}' "$SESS_TAP" "$SESS_IDX")"
note "removes the tap netdev (idempotent; absent tap = success)."

echo
echo "=== end of dry run: $STEP_N steps printed, 0 executed ==="
echo "to APPLY this (D148-ratified) posture, use the single-purpose tools, not this script:"
echo "  install:  DS_NETHELPER_APPLY=1 ../install-ds-nethelper.sh <built-ds-nethelper>"
echo "  bring-up: scripts/host-bringup/stack-up-host.sh up"
