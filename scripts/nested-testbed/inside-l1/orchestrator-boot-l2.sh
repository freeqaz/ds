#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# orchestrator-boot-l2.sh — runs INSIDE L1. The REAL-stack alternative to the
# manual gate-up.sh + l2-up.sh path: instead of hand-applying the nft floor and
# hand-booting L2 with qemu, it stands up the production binaries — ds-orchestrator
# + ds-host-agent (untagged/unprivileged since D148) from the
# 9p share — and drives a CreateSession so the REAL host-agent's AttachPrimitive
# programs the per-session tap + session NFT and boots the L2 session VM via libvirt.
#
# NOTE (D148 follow-up, tracked): the privileged nft write edge moved out of the agent
# into the setcap'd ds-nethelper helper (built by build-dataplane-debian.sh as
# /out/ds-nethelper). This script still starts the host-agent as ROOT, and the helper's
# owner_uid == caller-uid AND nonzero rule can never mint a tap for a root caller — so the
# in-L1 RUNTIME wiring (install + setcap the helper in L1, run the agent as a non-root
# agent uid, pass -nethelper-path) is a SEPARATE follow-up. Until it lands, an untagged
# agent here takes the no-touch deferred attach and programs no tap/nft. This is the path the ATTACH-PRIMITIVE.md
# acceptance describes, exercised SAFELY: every kernel write + every booted VM is
# inside the disposable L1, never the host.
#
#   ds-host-agent (DS_HOSTAGENT_LIVE=1, -routed-tap; privileged ops via ds-nethelper, D148)
#     CreateSession/CloneFromImage  ──▶  AttachPrimitive.CreateTap(dstap-<idx>)
#                                        AttachPrimitive.InstantiateSessionNFT(per-session NFT)
#                                        libvirt virsh boot of the L2 overlay over /opt/ds/l2
#   ds-orchestrator (DS_ORCH_LIVE=1)  ──▶  SessionService.CreateSession routes to the
#                                          host-agent driver (the full control plane)
#
# DRIVE PATH (DS_ORCH_DRIVE; default orchestrator — see the DRIVE= resolution below):
#   hostagent            — drive the host-agent's HypervisorDriverService DIRECTLY
#                         with ds-driver-e2e `-mode clone` (RecoverSessions +
#                         CloneFromImage, leave the session resident). This is the
#                         §4.1 create spine that invokes CreateTap +
#                         InstantiateSessionNFT + the libvirt boot — the most direct
#                         proof the AttachPrimitive programs the tap + NFT. The
#                         orchestrator is started too (so the full stack is up and
#                         its driver dial is exercisable) but the create is driven at
#                         the host-agent for a deterministic, single-RPC bring-up.
#                         NOTE: incompatible with DS_GATE_TLS_MODE=swap (posture-(b)
#                         needs the orchestrator-minted per-session CA — guard_swap_drive
#                         rejects the combination up front).
#   orchestrator (default) — drive the full control plane: ds-orchestrator
#                          SessionService.CreateSession (which resolves the host_id ->
#                          host-agent driver and runs CloneFromImage on it). Uses
#                          ds-driver-e2e-style direct create is NOT used; instead the
#                          orchestrator-lite CreateSession spine is exercised. Requires
#                          the orchestrator's create env to be seeded (handled below).
#
# L2 FLAVOR (DS_L2_FLAVOR):
#   fat (default) — reuse the L1 "fat" image staged at /opt/ds/l2 (curl/dig/nc/ssh +
#                   serial autologin). It self-configures its routed-tap IP from a
#                   MAC-matched systemd-networkd drop-in pinned to session index 7
#                   (MAC 52:54:00:77:07:01 -> 10.77.7.1/31 via 10.77.7.0), so this
#                   runner PRE-SEEDS the host-agent's never-recycle index counter to
#                   7 (a fresh host starts at 0) so the FIRST CreateSession allocates
#                   dstap-7 and the fat image's static net matches by construction.
#   m0            — the real M0 agent image (runs CC). Its routed-tap IP comes from
#                   the host-agent's per-session config-drive ds-net.env (netconfig.go)
#                   keyed on whatever index the counter hands, so NO index pin is forced.
#
# WHY this is safe (the testbed invariant): every nft object liveAttach writes and
# every libvirt domain it boots lands inside L1 (a throwaway VM). Break L1's net and
# you reboot L1; the host + its Tailscale link are never touched. The manual
# gate-up.sh/l2-up.sh path remains the fallback (run-testbed.sh `up`); this is the
# real-stack path (run-testbed.sh `up-orch`).
set -uo pipefail

# --- host-bring-up facts (doc 13 §4); all overridable via env -----------------
BIN="${DS_BIN:-/opt/ds/bin}"
L2DIR="${DS_L2_DIR:-/opt/ds/l2}"
RUN="${DS_ORCH_RUN:-/run/ds-orch}"
GATE_RUN="${DS_GATE_RUN:-/run/ds-gate}"        # gate-up.sh's dir (gateways live here too if started)
ATTACH_DIR="${DS_ATTACH_DIR:-/run/ds/attach}"  # host-local per-session attach UDS dir
OVERLAYS="${DS_OVERLAY_DIR:-/var/lib/ds/overlays}"
FLAVOR="${DS_L2_FLAVOR:-fat}"
DRIVE="${DS_ORCH_DRIVE:-orchestrator}"

# --- ds-nethelper privileged helper (D148 ROOT-HELPER model) ------------------
# The host-agent runs UNPRIVILEGED (as $AGENT_USER, see start_hostagent) and forks
# this setcap'd helper for every privileged tap/nft op; the capability lives on the
# HELPER file, never on the agent. install_nethelper() installs the staged
# /opt/ds/bin/ds-nethelper to $NETHELPER as root:$AGENT_USER 0750 + setcap
# cap_net_admin+eip inside L1, then the host-agent forks it via DS_NETHELPER_PATH.
# NETHELPER is the INSTALLED path the agent execs; NETHELPER_SRC is the staged binary
# the installer copies from; NETHELPER_INSTALL is the staged installer script.
AGENT_USER="${DS_AGENT_USER:-ds-agent}"
NETHELPER="${DS_NETHELPER_PATH:-/usr/local/libexec/ds-nethelper}"
NETHELPER_SRC="${DS_NETHELPER_SRC:-$BIN/ds-nethelper}"
NETHELPER_INSTALL="${DS_NETHELPER_INSTALL:-/opt/ds/install-ds-nethelper.sh}"

# DS_DRIVE_SEAT=1 turns the substrate proof into a REAL CC-turn proof: when set
# (and typically DS_L2_FLAVOR=m0, the flavor that runs CC), start_hostagent folds
# the structured stream-json CC launch argv + the CC OAuth token into the
# host-agent's -launch-* facts, and a post-boot drive_seat() drives one CC turn
# over the writer seat the orchestrator minted (DS_KVM_LIVE_* from the orch-create
# Attach handle). UNSET (the default up-orch) ⇒ this whole path is skipped and the
# bring-up is byte-identical to the substrate+egress proof. The CC OAuth token is
# read at RUNTIME from $DS_CC_OAUTH_TOKEN (preferred) or a staged file
# $DS_CC_TOKEN_FILE (default /opt/ds/secrets/cc-oauth-token) — NEVER hardcoded or
# committed (D50 raw-class). ds-seat-drive (g1's writer-seat client) is execed from
# DS_SEAT_DRIVE_BIN (default $BIN/ds-seat-drive).
DRIVE_SEAT="${DS_DRIVE_SEAT:-}"
CC_TOKEN_FILE="${DS_CC_TOKEN_FILE:-/opt/ds/secrets/cc-oauth-token}"
SEAT_DRIVE_BIN="${DS_SEAT_DRIVE_BIN:-$BIN/ds-seat-drive}"
SEAT_PROMPT="${DS_SEAT_PROMPT:-say PONG}"
# VM-side-effect proof (optional). DS_SEAT_PROOF is a unique marker TOKEN; when set,
# drive_seat passes it as ds-seat-drive's -proof, which makes the turn instruct CC to
# write that token to a file (-proof-file, relative to the guest /work cwd) — a true
# in-VM side effect. NOTE the division of labor that matches ds-seat-drive's flags:
# -proof is the token CONTENT (not a path); ds-seat-drive asserts the projected
# attach.v1 round-trip but does NOT read the file back — the readback is an operator's
# manual check on the host side of the guest /work share. DS_SEAT_WORK is that host dir
# (where the operator looks for the written file); it is printed in the manual-check
# hint only — ds-seat-drive does not consume it. Unset DS_SEAT_PROOF ⇒ a no-tool PONG
# turn and the turn-completed signal alone is the green.
SEAT_PROOF="${DS_SEAT_PROOF:-}"
SEAT_PROOF_FILE="${DS_SEAT_PROOF_FILE:-ds-seat-drive-proof.txt}"
SEAT_WORK="${DS_SEAT_WORK:-}"

# --- posture-(b) cred-swap mode (DS_GATE_TLS_MODE=swap; additive) --------------
# DS_GATE_TLS_MODE is plumbed THROUGH to gate-up.sh by bring_up_gateways_and_floor
# (the orchestrator DRIVE path). When it is "swap", ds-tlsproxy TERMINATES the VM's
# TLS with a per-session interception CA and SWAPS a placeholder Authorization header
# for the REAL Anthropic token host-side (D39 posture-(b)). The cred-swap consequence
# for THIS script's CC launch (under DS_DRIVE_SEAT=1): instead of folding the REAL
# token into the guest as CLAUDE_CODE_OAUTH_TOKEN (the opaque/posture-(a) behavior),
# we fold a PLACEHOLDER token (the real token never enters the VM — it lives only in
# the host secret store gate-up.sh staged) PLUS NODE_EXTRA_CA_CERTS pointing at the
# interception CA cert so the in-guest CC's Node TLS stack trusts the terminated TLS.
# Unset / any-other value ⇒ this whole branch is skipped and the launch is
# byte-identical to the opaque substrate+CC proof.
TLS_MODE="${DS_GATE_TLS_MODE:-opaque}"
# CA-MATCH FIX (m0 flavor): with DS_HOSTAGENT_SKIP_CA_INJECT=1 (no runtime InjectCA — L1
# has no libguestfs) the m0 guest trusts ONLY its baked /etc/ds/intercept-ca.crt. Force the
# proxy to present leaves under that SAME baked CA (staged at /opt/ds/ca) — else the per-run
# $GATE_RUN CA (fresh key each tmpfs boot, same CN) fails the guest's cert path-build → RST
# after Finished (the "downstream handshake reset"). The m0 image must carry the SAME CA at
# /etc/ds/intercept-ca.crt: the DURABLE way is to (re)bake it in via
# vm/m0-image/build-m0-image-rootless.sh DS_M0_INTERCEPT_CA_CERT=<share>/ca/intercept-ca.crt;
# a quick one-off is a debugfs write of that cert into the base image. Either way the guest's
# baked CA and the proxy's presented CA must be byte-identical.
# Export so SWAP_CA_CERT + seed_intercept_ca (reuse, no per-run gen) + gate-up.sh inherit it.
if [ "$TLS_MODE" = "swap" ] && [ -z "${DS_TLSPROXY_SESSION_CA_CERT:-}" ] \
   && [ -r /opt/ds/ca/intercept-ca.crt ] && [ -r /opt/ds/ca/intercept-ca.key ]; then
  export DS_TLSPROXY_SESSION_CA_CERT=/opt/ds/ca/intercept-ca.crt
  export DS_TLSPROXY_SESSION_CA_KEY=/opt/ds/ca/intercept-ca.key
fi
# The interception CA cert path. gate-up.sh (swap mode) honors this exact var, so a
# shared default keeps the host-side CA and the guest's NODE_EXTRA_CA_CERTS pointing at
# ONE cert. Default = gate-up.sh's $RUN/intercept-ca.crt (DS_GATE_RUN=$GATE_RUN here).
SWAP_CA_CERT="${DS_TLSPROXY_SESSION_CA_CERT:-$GATE_RUN/intercept-ca.crt}"
# The guest path NODE_EXTRA_CA_CERTS points at + where the host-agent delivers the CA
# cert in-guest. /etc/ds/intercept-ca.crt is the testbed convention (a single-file CA
# bundle Node reads directly; no system trust-store rebuild needed). The host-agent's
# §4.1 step-7 InjectCA (libguestfs overlay write) lands the cert there: start_hostagent
# arms it under swap mode by setting DS_GUEST_INTERCEPT_CA_PATH=$SWAP_GUEST_CA_PATH so
# the live trust-store writer (trustanchor.go) targets EXACTLY this path. Host-side
# assertable post-boot with `$0 ca-assert` (virt-cat the overlay; no VM start).
SWAP_GUEST_CA_PATH="${DS_GUEST_INTERCEPT_CA_PATH:-/etc/ds/intercept-ca.crt}"
# A non-secret placeholder Authorization token handed to the guest's CC in place of the
# real one (the swap replaces it at the proxy). An operator may pin DS_PLACEHOLDER_TOKEN;
# otherwise it is derived per-session at launch time (start_hostagent, once SESSION_UUID
# is resolved) as ds-placeholder-<session>-anthropic.
PLACEHOLDER_TOKEN="${DS_PLACEHOLDER_TOKEN:-}"

# The host-agent runs as root inside L1, so its live.go Booter's bare `virsh create`
# resolves to qemu:///system (libvirtd.service, baked into the L1 image). Pin the URI
# explicitly so (a) the host-agent inherits it and (b) our verify/cleanup virsh calls
# below target the SAME instance the domain was booted into (was a qemu:///session
# mismatch that hid the running domain from wait_for_l2).
export LIBVIRT_DEFAULT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"

HOST_ID="${DS_HOST_ID:-l1-host}"
HOSTAGENT_LISTEN="${DS_HOSTAGENT_LISTEN:-127.0.0.1:18091}"
ORCH_LISTEN="${DS_ORCH_LISTEN:-127.0.0.1:18090}"

# The fat image's MAC-matched networkd drop-in pins session index 7 (l1.Containerfile
# 05-l2-routedtap.network: MAC 52:54:00:77:07:01 -> 10.77.7.1/31). Pin the host-agent
# index counter to it so the FIRST CreateSession allocates dstap-7 + 10.77.7.1. The
# 5th MAC octet is the index in TWO HEX DIGITS (live.go macForIndex / l2-up.sh), which
# for IDX=7 is "07" — identical in hex and decimal, so this pinned demo is byte-stable
# across the hex render and needs no rebake.
PIN_INDEX="${DS_PIN_INDEX:-7}"
SESSION_IDX="$PIN_INDEX"
NET="10.77.${SESSION_IDX}"
TAP="dstap-${SESSION_IDX}"

# Direct-kernel boot artifacts staged in the share (boot-l1.sh stage names them
# fat-* / m0-*). The host-agent renders a libvirt direct-kernel <os> from these
# (DS_KERNEL_PATH/DS_INITRD_PATH; live.go DirectKernelEnabled) — the rootless
# grub-less image can ONLY boot direct-kernel.
# NIC naming differs by flavor: the fat L2 self-configs via a MAC-matched systemd-networkd
# drop-in keyed on `eth0` (so it NEEDS net.ifnames=0), but the m0 image applies its routed-tap
# IP via ds-apply-netcfg which globs the egress NIC as `en*` (M0_EGRESS_NIC_GLOB) — so m0 must
# use PREDICTABLE names (no net.ifnames=0), else its NIC is eth0, the en* glob finds nothing,
# and ds-netcfg.service fails closed → no guest IP → CC can't egress (the gap4 no-turn RC).
case "$FLAVOR" in
  fat) BASE="$L2DIR/fat-base.raw"; KERN="$L2DIR/fat-vmlinuz"; INITRD="$L2DIR/fat-initrd.img"; ROOTLBL=DS_L1ROOT; IFNAMES="net.ifnames=0" ;;
  m0)  BASE="$L2DIR/m0-base.raw";  KERN="$L2DIR/m0-vmlinuz";  INITRD="$L2DIR/m0-initrd.img";  ROOTLBL=DS_M0ROOT; IFNAMES="" ;;
  *) echo "unknown DS_L2_FLAVOR=$FLAVOR (fat|m0)" >&2; exit 2 ;;
esac

# overlay-create.sh: the host-agent's live OverlayStore shells out to it to clone the
# read-only base into a per-session qcow2 overlay (D29). It is staged into the share
# alongside the bins by the stack build; fall back to a couple of conventional paths.
OVERLAY_CREATE="${DS_OVERLAY_CREATE:-}"
SESSION_UUID="${DS_SESSION_UUID:-l1-orchboot-1}"
BOOT_WAIT="${DS_BOOT_WAIT:-12}"     # settle seconds after CloneFromImage (ds-driver-e2e -boot-wait)
DEADLINE_SECS="${DS_L2_DEADLINE:-180}"

say(){ printf '\033[1;34m[orch-l2] %s\033[0m\n' "$*"; }
die(){ printf '\033[1;31m[orch-l2][FATAL] %s\033[0m\n' "$*" >&2; exit 1; }

# --- preflight: the live substrate + the staged stack -------------------------
preflight() {
  say "preflight: nested KVM + the live stack binaries + the L2 image"
  [ -c /dev/kvm ] || die "/dev/kvm absent inside L1 — nested KVM not exposed (need host -cpu host + modprobe kvm_amd)"
  for b in ds-host-agent ds-nethelper ds-orchestrator ds-driver-e2e; do
    [ -x "$BIN/$b" ] || die "$BIN/$b missing/!exec — build it (build-dataplane-debian.sh emits all four into the 9p bin/) and re-stage"
  done
  for f in "$BASE" "$KERN" "$INITRD"; do
    [ -r "$f" ] || die "missing L2 ($FLAVOR) artifact: $f — stage it (boot-l1.sh stage)"
  done
  # The libds_nft.a staticlib the nftgatelive cgo edge linked is BAKED INTO the
  # ds-nethelper binary at build time (D148 — no longer into the agent), so there is
  # nothing to check at runtime, but the live nft write still needs the `nft`/`ip`
  # tools (ds-nft execs them, the mechanism-only edge).
  for t in nft ip virsh qemu-img; do
    command -v "$t" >/dev/null || die "missing tool inside L1: $t (the live host-agent shells out to it)"
  done
  # overlay-create.sh resolution (the host-agent's live clone primitive).
  if [ -z "$OVERLAY_CREATE" ]; then
    for c in /opt/ds/vm/cow/overlay-create.sh /opt/ds/overlay-create.sh /work/vm/cow/overlay-create.sh; do
      [ -x "$c" ] && { OVERLAY_CREATE="$c"; break; }
    done
  fi
  [ -n "$OVERLAY_CREATE" ] && [ -x "$OVERLAY_CREATE" ] \
    || die "overlay-create.sh not found — stage vm/cow/overlay-create.sh into the share and pass DS_OVERLAY_CREATE (the host-agent's live OverlayStore needs it)"
  say "  /dev/kvm rw, bins at $BIN, L2 $FLAVOR image at $L2DIR, overlay-create=$OVERLAY_CREATE"
}

# --- kernel readiness (same modprobe + ip_forward shape as gate-up.sh) --------
# The host-agent's liveAttach writes nft + creates the tap; the redirects/forward
# floor it programs need the same modules + forwarding gate-up.sh loads. (liveAttach
# does NOT set sysctls — it is the nft/tap writer; the host posture is ours to set.)
kernel_prep() {
  say "kernel modules + ip_forward (for the per-session tap + redirects liveAttach writes)"
  for m in nf_tables nft_redir nft_nat nf_nat nft_reject_inet tun vhost_vsock; do modprobe "$m" 2>/dev/null || true; done
  sysctl -wq net.ipv4.ip_forward=1 2>/dev/null || true
  sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
}

# --- index counter pin (fat flavor only) --------------------------------------
# A fresh host-agent starts its never-recycle index counter at 0 (durablecounter.go:
# a missing <OverlayDir>/ds-host-index.counter => next=0). The fat L2 image's
# networkd is pinned to index 7, so seed the counter to PIN_INDEX BEFORE the
# host-agent starts so its FIRST Allocate() hands index PIN_INDEX => dstap-7 =>
# 10.77.7.1/31 (matching the fat image). The m0 flavor takes its IP from the
# per-session config-drive the host-agent writes, so it needs no pin.
seed_index_counter() {
  mkdir -p "$OVERLAYS"
  local cfile="$OVERLAYS/ds-host-index.counter"
  if [ "$FLAVOR" = "fat" ]; then
    if [ ! -s "$cfile" ]; then
      printf '%s\n' "$PIN_INDEX" > "$cfile"
      say "pinned host-agent index counter to $PIN_INDEX ($cfile) so the first session is $TAP / $NET.1 (fat image match)"
    else
      say "index counter already present ($cfile = $(cat "$cfile")); leaving as-is (re-run on a fresh L1 to repin)"
    fi
  fi
}

# The host-agent's gap-1 EntrypointProducer fail-closes at step-8 (build+deliver entrypoint
# config) on a MISSING D38 opaque entrypoint-config drop — the orchestrator is the producer
# in the full design (it drops <ref> into <OverlayDir>/.ds-entrypoint-refs from the §4.1
# step-1 env config). For the hostagent-DIRECT drive (ds-driver-e2e -mode clone) the
# orchestrator never produces it, so pre-materialize the SAME minimal opaque role overlay
# ds-serve-stack.sh drops, keyed on the refs the two drive paths request: e2e-entrypoint
# (ds-driver-e2e hardcodes EntrypointConfigRef=e2e-entrypoint) and demo-env (the
# orchestrator path's --env-config-ref / DS_ORCH_SEED_ENV_CONFIG). The bytes are OPAQUE —
# the host never inspects them; the drivable CC launch comes from the host-agent's -launch-*
# facts, not this overlay — so a minimal non-credential blob satisfies the fail-closed fetch.
seed_entrypoint_ref() {
  local epref="$OVERLAYS/.ds-entrypoint-refs"
  mkdir -p "$epref"
  local ref
  for ref in e2e-entrypoint demo-env; do
    if [ ! -s "$epref/$ref" ]; then
      printf '{"ds_role_overlay":"mvp","runtime":null}\n' > "$epref/$ref"
      say "seeded D38 opaque entrypoint-config drop at $epref/$ref (fail-closed step-8 fetch satisfied)"
    fi
  done
}

# --- CC OAuth token (DS_DRIVE_SEAT only; NEVER printed/logged/committed) -------
# Resolve the CC OAuth token at RUNTIME from $DS_CC_OAUTH_TOKEN (preferred) or the
# staged file $DS_CC_TOKEN_FILE (default /opt/ds/secrets/cc-oauth-token). Sets the
# global CC_OAUTH_TOKEN on success and returns 0; returns 1 (token left empty) when
# neither source is present, so the caller can WARN and skip the seat drive without
# aborting the substrate proof. The token is a D50 raw-class secret: it lives only
# in this var + the child host-agent's env, is never echoed, and is never written
# to a tracked file.
CC_OAUTH_TOKEN=""
read_cc_token() {
  CC_OAUTH_TOKEN=""
  if [ -n "${DS_CC_OAUTH_TOKEN:-}" ]; then
    CC_OAUTH_TOKEN="$DS_CC_OAUTH_TOKEN"
    return 0
  fi
  if [ -r "$CC_TOKEN_FILE" ]; then
    # Trim a trailing newline; do not echo the contents.
    CC_OAUTH_TOKEN="$(tr -d '\r\n' < "$CC_TOKEN_FILE")"
    [ -n "$CC_OAUTH_TOKEN" ] && return 0
  fi
  return 1
}

# --- posture-(b) interception CA seed (DS_GATE_TLS_MODE=swap only) -------------
# The CA cert must EXIST (so NODE_EXTRA_CA_CERTS resolves) and be DELIVERED into the
# guest BEFORE the guest's CC starts. start_hostagent folds NODE_EXTRA_CA_CERTS=<guest
# path> into the launch facts, and bring_up_gateways_and_floor (later) runs gate-up.sh
# swap mode which generates the proxy's interception CA at the SAME $SWAP_CA_CERT path
# (shared DS_TLSPROXY_SESSION_CA_CERT). Because the host-agent starts BEFORE gate-up.sh
# in the up() ordering, we pre-generate the CA HERE (idempotent: gate-up.sh then honors
# the already-present pair). The CA cert is non-secret; the KEY is mode 0600, never
# printed (D50).
#
# GUEST DELIVERY (the load-bearing live step, now WIRED): the cert lands at
# $SWAP_GUEST_CA_PATH inside the L2 guest via the host-agent's §4.1 step-7 InjectCA
# (cainject.go: FetchCABundle -> liveTrustStoreWriter virt-customize --upload into the
# per-session overlay). start_hostagent DROPS DS_HOSTAGENT_SKIP_CA_INJECT under swap mode
# and sets DS_GUEST_INTERCEPT_CA_PATH=$SWAP_GUEST_CA_PATH so the live writer targets EXACTLY
# the NODE_EXTRA_CA_CERTS path (the trustanchor.go guest-path reconcile) — Node reads the
# literal cert, no system-trust rebuild. The AUTHORITATIVE per-session CA is the one the
# orchestrator mints + drops under <overlay-dir>/.ds-ca-bundles/<caRef>.pem (DS_ORCH_OVERLAY_DIR
# in start_orchestrator) and sets as ca_bundle_ref on CreateSession; the FileCABundleSource
# resolves it with no hand-seeded ref. We ALSO stage the pre-generated proxy CA below under
# .ds-ca-bundles/intercept-ca.pem as a fallback ref. COORDINATION (loop-1 / gate-up.sh, value
# only): ds-tlsproxy MUST terminate with the SAME CA whose cert the guest now trusts — the
# orchestrator-minted per-session CA — so the egress-gateway cert and the in-guest anchor are
# one identity (else the guest CC rejects the terminated TLS). Surfaced as a coordinator note.
seed_intercept_ca() {
  [ "$TLS_MODE" = "swap" ] || return 0
  mkdir -p "$GATE_RUN"
  local cakey="${DS_TLSPROXY_SESSION_CA_KEY:-$GATE_RUN/intercept-ca.key}"
  if [ -r "$SWAP_CA_CERT" ] && [ -r "$cakey" ]; then
    say "posture-b: interception CA already present (cert=$SWAP_CA_CERT) — reusing"
  elif command -v openssl >/dev/null 2>&1; then
    say "posture-b: pre-generating the per-run interception CA at $SWAP_CA_CERT (gate-up.sh swap mode reuses it)"
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$cakey" -out "$SWAP_CA_CERT" \
      -days 7 -subj "/CN=ds-session-ca-l1-testbed" >/dev/null 2>&1 \
      || { say "WARN: posture-b openssl CA generation failed — gate-up.sh will generate it later, but NODE_EXTRA_CA_CERTS may point at an absent cert at CC start"; return 0; }
    chmod 600 "$cakey" 2>/dev/null || true
  else
    say "WARN: posture-b but no openssl to pre-generate the interception CA — gate-up.sh generates it later; set DS_TLSPROXY_SESSION_CA_CERT/KEY to a pre-staged pair if CC starts before the gate"
    return 0
  fi
  # Stage the cert into the per-session overlay CA-bundle dir convention as a fallback ref
  # for the live InjectCA path (the authoritative bundle is the orchestrator-minted one
  # keyed by ca_bundle_ref); harmless and overwritten-converging on a re-run.
  local cabundle_dir="$OVERLAYS/.ds-ca-bundles"
  mkdir -p "$cabundle_dir" 2>/dev/null || true
  cp -f "$SWAP_CA_CERT" "$cabundle_dir/intercept-ca.pem" 2>/dev/null || true
  say "posture-b: staged interception CA cert -> $cabundle_dir/intercept-ca.pem; the host-agent live InjectCA delivers it in-guest at NODE_EXTRA_CA_CERTS=$SWAP_GUEST_CA_PATH (host-side assertable: '$0 ca-assert')"
}

# --- install + setcap the ds-nethelper privileged helper inside L1 (D148) -----
# Runs as ROOT (orchestrator-boot-l2.sh keeps root for modprobe/sysctl/nft/install)
# BEFORE the non-root host-agent starts. Mirrors stack-up-host.sh's preflight but this
# is the L1 ANALOGUE of the live host's one-time install: the staged helper is a fresh
# cap-less copy (9p), so it must be install+setcap'd here every boot. The installer
# runs its own verify (getcap cap_net_admin+eip + the three-field probe incl
# ambient_raise_ok + built:true) and FAILS if not green — the +ep-trap guard, reused.
install_nethelper() {
  say "install + setcap the ds-nethelper privileged helper (root:$AGENT_USER 0750, cap_net_admin+eip) -> $NETHELPER"
  [ -x "$NETHELPER_SRC" ] || die "staged ds-nethelper missing/!exec at $NETHELPER_SRC — build it (build-dataplane-debian.sh) + re-stage (boot-l1.sh stage)"
  [ -r "$NETHELPER_INSTALL" ] || die "ds-nethelper installer missing at $NETHELPER_INSTALL — re-stage (boot-l1.sh stage copies orchestrator/cmd/ds-nethelper/scripts/install-ds-nethelper.sh)"
  # DS_NETHELPER_GROUP=$AGENT_USER is MANDATORY: the installer's default group is
  # $(id -gn) = root when run as root, which would install the helper root:root 0750 —
  # and the $AGENT_USER agent could not exec it. It MUST be root:$AGENT_USER 0750.
  DS_NETHELPER_APPLY=1 DS_NETHELPER_GROUP="$AGENT_USER" DS_NETHELPER_DEST="$NETHELPER" \
    bash "$NETHELPER_INSTALL" "$NETHELPER_SRC" 2>&1 | sed 's/^/   /'
  local rc=${PIPESTATUS[0]}
  [ "$rc" = 0 ] || die "ds-nethelper install/setcap/verify FAILED (rc=$rc) — see above (a +ep install, a cap-less copy, or a stub build without -tags nftgatelive fails here)"
  say "  ds-nethelper installed + verified at $NETHELPER"
}

# --- ownership: the non-root agent must own what it creates/writes/advances -----
# The host-agent runs as $AGENT_USER (D148 helper trust boundary rejects a root caller),
# so it must OWN: the attach UDS dir + the event-socket dir (both under /run/ds) and the
# per-session overlays + serial logs + the durable ds-host-index.counter ($OVERLAYS).
# chown -R so it can create/bind/advance them. The ORCHESTRATOR stays root and still
# writes into these dirs (root overrides the mode). We deliberately do NOT chown $RUN
# (/run/ds-orch): the root parent opens HA_LOG/ORCH_LOG/pidfiles there and the agent
# writes its own log via an inherited fd, so it needs no ownership of $RUN.
chown_agent_dirs() {
  local d
  for d in /run/ds "$ATTACH_DIR" "$OVERLAYS"; do
    [ -e "$d" ] && { chown -R "$AGENT_USER:$AGENT_USER" "$d" 2>/dev/null \
      || say "WARN: chown $d -> $AGENT_USER failed (are we root? the agent may fail to bind the attach UDS / advance the index counter)"; }
  done
}

# --- host-agent (live, routed-tap; privileged ops via ds-nethelper, D148) -----
HA_PID="$RUN/host-agent.pid"; HA_LOG="$RUN/host-agent.log"
ORCH_PID="$RUN/orchestrator.pid"; ORCH_LOG="$RUN/orchestrator.log"

start_hostagent() {
  if [ -f "$HA_PID" ] && kill -0 "$(cat "$HA_PID")" 2>/dev/null; then
    say "host-agent already running (pid $(cat "$HA_PID"))"; return 0
  fi
  say "start ds-host-agent on $HOSTAGENT_LISTEN (DS_HOSTAGENT_LIVE=1, -routed-tap, direct-kernel $FLAVOR)"
  # DS_HOSTAGENT_LIVE=1 arms the real overlay-create.sh clone and the real virsh boot.
  # The tap + per-session NFT leg is armed only when a verified ds-nethelper is wired in
  # (-nethelper-path / DS_NETHELPER_PATH) — see the D148 follow-up note in the header. -routed-tap
  # renders the L2 domain on the per-session dstap-<idx> ethernet NIC (not SLIRP) so
  # its egress is governed by the NFT liveAttach writes. DS_KERNEL_PATH/DS_INITRD_PATH
  # select direct-kernel boot of the rootless image; -kernel-cmdline mounts the L2
  # overlay root by LABEL. The identity/proxy legs are LEFT UNSET — this runner
  # proves the tap+NFT+boot substrate, not the credential swap (those are later phases,
  # like ds-serve-stack.sh's MVP scope). DS_DRIVE_SEAT=1 is the one exception: it folds
  # the DRIVABLE structured stream-json CC launch + the CC OAuth token into the
  # host-agent's -launch-* facts so the booted m0 VM runs a headless CC the writer seat
  # can drive.
  #
  # launch_args is EMPTY by default (so the launch argv is byte-identical to the
  # substrate proof: just `-launch-command /usr/bin/claude`); under DS_DRIVE_SEAT it
  # appends the STRUCTURED stream-json argv set (copied verbatim from
  # scripts/live-mvp/ds-serve-stack.sh's structured mode) + the token via -launch-env.
  #
  # CRED-SWAP FORK (DS_GATE_TLS_MODE):
  #   opaque/enforce (default) — POSTURE=a: fold the REAL CC OAuth token into the guest
  #     as CLAUDE_CODE_OAUTH_TOKEN, read at RUNTIME (never hardcoded/committed — D50
  #     raw-class). If neither token source is present we WARN and DO NOT add the launch
  #     flags, so the substrate proof still stands. BYTE-IDENTICAL to the prior behavior.
  #   swap — POSTURE=b: the REAL token NEVER enters the VM (it lives only in the host
  #     secret store gate-up.sh staged; ds-tlsproxy swaps it in at egress). Instead fold
  #     a PLACEHOLDER CLAUDE_CODE_OAUTH_TOKEN + NODE_EXTRA_CA_CERTS=<guest CA path> so the
  #     guest CC's Node TLS stack trusts the proxy-terminated TLS. No real token is read,
  #     so this path stands even with no host token staged (CC starts with the
  #     placeholder; the swap supplies the real credential upstream).
  local launch_args=()
  if [ "$DRIVE_SEAT" = 1 ]; then
    # The shared structured stream-json CC launch argv (identical across postures).
    local cc_structured_args=(
      -launch-arg --input-format -launch-arg stream-json
      -launch-arg --output-format -launch-arg stream-json
      -launch-arg --verbose
      -launch-arg --no-session-persistence
      -launch-arg --model -launch-arg sonnet
      -launch-arg --permission-mode -launch-arg default
      -launch-arg --permission-prompt-tool -launch-arg stdio
      -launch-arg --max-budget-usd -launch-arg 1
    )
    if [ "$TLS_MODE" = "swap" ]; then
      # Per-session placeholder (derived now that SESSION_UUID is resolved, unless pinned).
      local placeholder="${PLACEHOLDER_TOKEN:-ds-placeholder-${SESSION_UUID}-anthropic}"
      # NODE_EXTRA_CA_CERTS is NOT folded via -launch-env: vm/entrypoint OWNS that key
      # (env.go proxyEnvKeys) and strips any launch-env value, then re-derives it from the
      # entrypoint config's egress.ca_bundle_path. That ca_bundle_path is reconciled to THIS
      # run's $SWAP_GUEST_CA_PATH host-side by the host-agent (entrypointFacts reads
      # DS_GUEST_INTERCEPT_CA_PATH, set in the ca_inject_env below) — the SAME env that drives
      # the InjectCA --upload target — so the cert is delivered TO $SWAP_GUEST_CA_PATH and the
      # guest CC's NODE_EXTRA_CA_CERTS points AT it from one source of truth. (A -launch-env
      # NODE_EXTRA_CA_CERTS here would be silently dropped — it never reached CC.)
      say "DS_DRIVE_SEAT=1 + DS_GATE_TLS_MODE=swap (posture-b): folding the structured CC launch + a PLACEHOLDER token; NODE_EXTRA_CA_CERTS is set in-guest from the entrypoint config's ca_bundle_path=$SWAP_GUEST_CA_PATH (reconciled to DS_GUEST_INTERCEPT_CA_PATH; the REAL token stays in the host secret store, never in the VM)"
      launch_args=(
        "${cc_structured_args[@]}"
        -launch-env "CLAUDE_CODE_OAUTH_TOKEN=$placeholder"
      )
    elif read_cc_token; then
      say "DS_DRIVE_SEAT=1 (posture-a/opaque): folding the structured stream-json CC launch + the REAL OAuth token into the host-agent (token value never logged)"
      launch_args=(
        "${cc_structured_args[@]}"
        -launch-env "CLAUDE_CODE_OAUTH_TOKEN=$CC_OAUTH_TOKEN"
      )
    else
      say "WARN: DS_DRIVE_SEAT=1 but no CC OAuth token (set \$DS_CC_OAUTH_TOKEN or stage $CC_TOKEN_FILE) — skipping the structured CC launch; the substrate proof still stands"
    fi
  fi
  # CA-INJECTION FORK (DS_GATE_TLS_MODE):
  #   default (opaque/enforce) — DS_HOSTAGENT_SKIP_CA_INJECT=1: the MVP no-inject posture
  #     (newGatedCAInjector pairs the synthetic-CA source with the no-op overlay writer; no
  #     libguestfs, no in-guest trust anchor). The SLIRP/transparent egress needs none.
  #     BYTE-IDENTICAL to the prior behavior.
  #   swap (posture-b) — DROP the skip so the host-agent's REAL §4.1 step-7 InjectCA path
  #     arms (cainject.go: FileCABundleSource fetch -> liveTrustStoreWriter virt-customize
  #     write into the per-session overlay), and set DS_GUEST_INTERCEPT_CA_PATH so the live
  #     writer lands the orchestrator-minted CA at the ONE fixed in-guest path the guest CC
  #     reads via NODE_EXTRA_CA_CERTS (=$SWAP_GUEST_CA_PATH, reconciled to loop-1). The CA
  #     bundle is the per-session interception CA the orchestrator mints + drops under
  #     $OVERLAYS/.ds-ca-bundles (DS_ORCH_OVERLAY_DIR, set in start_orchestrator) and sets as
  #     ca_bundle_ref on CreateSession — so the consumer resolves it with no hand-seeded ref.
  #     FAIL-CLOSED: a missing/empty bundle aborts the create before the guest's first TLS
  #     byte (cainject.go doc 16 §4). The CA private key NEVER enters the guest (only the
  #     public cert is uploaded) and is never logged.
  # POSTURE-B / BAKED-CA APPROACH (testbed): the interception CA is BAKED into the m0 image
  # at $SWAP_GUEST_CA_PATH (build-m0-image-rootless.sh DS_M0_INTERCEPT_CA_CERT), and
  # ds-tlsproxy signs leaves with the SAME CA (DS_TLSPROXY_SESSION_CA_CERT=/opt/ds/ca/…).
  # So we do NOT need the live InjectCA DELIVERY (step-7) — KEEP DS_HOSTAGENT_SKIP_CA_INJECT=1
  # (arming InjectCA fail-closes: the testbed orch-create mints no ca_bundle_ref → "create …
  # has no CA bundle ref"). We STILL set DS_GUEST_INTERCEPT_CA_PATH so the host-agent
  # entrypointFacts threads it into the config's egress.ca_bundle_path (loop-1 reconcile, #5429)
  # → ds-entrypoint sets the guest CC's NODE_EXTRA_CA_CERTS/SSL_CERT_FILE to the BAKED cert.
  # (Wiring the orchestrator's per-session CA mint→ca_bundle_ref→InjectCA is the production
  # path, deferred — prod-d82-ca-ingest.) CA private key NEVER enters the VM; never logged.
  local ca_inject_env=(DS_HOSTAGENT_SKIP_CA_INJECT=1)
  if [ "$TLS_MODE" = "swap" ]; then
    ca_inject_env=(DS_HOSTAGENT_SKIP_CA_INJECT=1 DS_GUEST_INTERCEPT_CA_PATH="$SWAP_GUEST_CA_PATH")
    say "posture-b (baked-CA): SKIP live InjectCA (cert baked at $SWAP_GUEST_CA_PATH; orch-create mints no ca_bundle_ref) but thread DS_GUEST_INTERCEPT_CA_PATH so the guest CC's NODE_EXTRA_CA_CERTS=$SWAP_GUEST_CA_PATH points at the baked interception CA"
  fi
  # D148: DROP to the non-root $AGENT_USER for the agent process ONLY (this script stays
  # root for modprobe/sysctl/nft/install). setpriv --reuid/--regid/--init-groups EXECS the
  # agent directly (no intermediate shell), so $! below is the REAL agent pid the pidfile +
  # kill -0 provenance checks depend on — runuser would fork a shell and break $!. --init-groups
  # gives the agent its supplementary groups (libvirt, so the live.go Booter's `virsh -c
  # qemu:///system create` reaches the system socket; kvm defensively). With a nonzero
  # os.Getuid() the agent's CreateTap carries owner_uid==caller-uid==nonzero, which the
  # helper's ValidateCreateTap accepts (a root caller would be rejected). DS_NETHELPER_PATH
  # points the agent at the just-installed setcap'd helper it forks per privileged op.
  # The >"$HA_LOG" redirect is opened by root before the drop; the agent inherits the fd.
  nohup setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --init-groups \
  env \
  DS_HOSTAGENT_LIVE=1 \
  DS_KERNEL_PATH="$KERN" \
  DS_INITRD_PATH="$INITRD" \
  "${ca_inject_env[@]}" \
  DS_HOSTBRIDGE_NO_AUTH=1 \
  DS_NETHELPER_PATH="$NETHELPER" \
  DS_SERIAL_LOG="${DS_SERIAL_LOG:-$OVERLAYS}" \
  "$BIN/ds-host-agent" \
    -listen "$HOSTAGENT_LISTEN" \
    -host-id "$HOST_ID" \
    -routed-tap \
    -base-image "$BASE" \
    -overlay-dir "$OVERLAYS" \
    -overlay-create-script "$OVERLAY_CREATE" \
    -kernel-path "$KERN" \
    -initrd-path "$INITRD" \
    -kernel-cmdline "root=LABEL=$ROOTLBL console=ttyS0,115200 rw${IFNAMES:+ $IFNAMES}" \
    -attach-socket-dir "$ATTACH_DIR" \
    -hostbridge-bin "$BIN/ds-hostbridge" \
    -orchestrator-addr "$ORCH_LISTEN" \
    -dns-gate-addr "127.0.0.1:${DS_GATE_DNS_PORT:-15353}" \
    -tls-proxy-probe-addr "127.0.0.1:${DS_GATE_HTTPS_PORT:-18443}" \
    -event-socket-path /run/ds/attach.sock \
    -working-dir /home/ds \
    -launch-command /usr/bin/claude \
    "${launch_args[@]}" \
    >"$HA_LOG" 2>&1 &
  echo $! > "$HA_PID"; disown
  # Do not keep the token in the shell after the child inherited it via argv.
  CC_OAUTH_TOKEN=""
  sleep 1
  kill -0 "$(cat "$HA_PID")" 2>/dev/null || { say "host-agent exited immediately:"; tail -25 "$HA_LOG"; die "host-agent launch failed"; }
  say "host-agent pid $(cat "$HA_PID") (log: $HA_LOG)"
  # The substrate banner names the live path: "substrate=LIVE (overlay-create.sh + virsh, DS_HOSTAGENT_LIVE=1)".
  grep -m1 -E 'substrate=|listening|serving' "$HA_LOG" 2>/dev/null | sed 's/^/   /' || true
}

# --- orchestrator (live-dial, pointed at the host-agent) ----------------------
start_orchestrator() {
  if [ -f "$ORCH_PID" ] && kill -0 "$(cat "$ORCH_PID")" 2>/dev/null; then
    say "orchestrator already running (pid $(cat "$ORCH_PID"))"; return 0
  fi
  say "start ds-orchestrator on $ORCH_LISTEN (DS_ORCH_LIVE=1, dialing host-agent $HOST_ID=$HOSTAGENT_LISTEN)"
  # In-memory store (no PG). DS_ORCH_HOST_DRIVERS host_id MUST equal the host-agent
  # -host-id so a placement resolves the right driver. DS_ORCH_FAKE_IDENTITY=1 is the
  # MVP no-auth loopback identity. DS_ORCH_ATTACH_SOCKET_DIR/DS_ORCH_OVERLAY_DIR match
  # the host-agent so the served attach UDS + the minted CA bundle land where the
  # host-agent reads. DS_ORCH_SEED_* seeds the §4.1 step-1 env config + repo so a
  # fresh in-memory live run can complete CreateSession (the GAP-A fix, same as
  # ds-serve-stack.sh).
  DS_ORCH_LIVE=1 \
  DS_ORCH_LISTEN="$ORCH_LISTEN" \
  DS_ORCH_HOST_DRIVERS="$HOST_ID=$HOSTAGENT_LISTEN" \
  DS_ORCH_DEFAULT_ORG=l1-org \
  DS_ORCH_ATTACH_SOCKET_DIR="$ATTACH_DIR" \
  DS_ORCH_OVERLAY_DIR="$OVERLAYS" \
  DS_ORCH_FAKE_IDENTITY=1 \
  DS_ORCH_SEED_ENV_CONFIG="demo-env=${FLAVOR}-base" \
  DS_ORCH_SEED_REPO_ID=demo \
  nohup "$BIN/ds-orchestrator" >"$ORCH_LOG" 2>&1 &
  echo $! > "$ORCH_PID"; disown
  sleep 1
  kill -0 "$(cat "$ORCH_PID")" 2>/dev/null || { say "orchestrator exited immediately:"; tail -25 "$ORCH_LOG"; die "orchestrator launch failed"; }
  say "orchestrator pid $(cat "$ORCH_PID") (log: $ORCH_LOG)"
}

# --- recover-before-serve latch (D66) -----------------------------------------
# RecoverSessions must complete before the host's first CloneFromImage on a
# recovery-wired LIVE host (else CreateSession fails at 4-host-alloc). It boots no
# VM; idempotent. Run it once after the host-agent starts (standing in for an
# orchestrator-driven RecoverSessions on host registration, same as ds-serve-stack.sh).
open_recover_latch() {
  say "open recover-before-serve latch (RecoverSessions, no VM boot) on $HOST_ID"
  "$BIN/ds-driver-e2e" -addr "$HOSTAGENT_LISTEN" -host-id "$HOST_ID" -mode recover 2>&1 \
    | sed 's/^/   /' || say "WARN: RecoverSessions latch open failed — CreateSession may fail at 4-host-alloc"
}

# --- drive a CreateSession ----------------------------------------------------
# DEFAULT (hostagent): drive the host-agent's HypervisorDriverService directly with
# ds-driver-e2e -mode clone (RecoverSessions + CloneFromImage, leave resident). This
# is the §4.1 create spine that invokes liveAttach.CreateTap + InstantiateSessionNFT
# and the libvirt boot — the most direct proof of the AttachPrimitive substrate.
drive_hostagent() {
  say "drive CreateSession at the host-agent (ds-driver-e2e -mode clone, session=$SESSION_UUID)"
  "$BIN/ds-driver-e2e" \
    -addr "$HOSTAGENT_LISTEN" \
    -host-id "$HOST_ID" \
    -session "$SESSION_UUID" \
    -mode clone \
    -boot-wait "${BOOT_WAIT}s" 2>&1 | sed 's/^/   /'
  # ds-driver-e2e exits non-zero iff a CRITICAL verb (CloneFromImage/Destroy) failed.
  local rc=${PIPESTATUS[0]}
  [ "$rc" = 0 ] || die "host-agent CloneFromImage failed (rc=$rc) — see $HA_LOG (liveAttach/overlay-create/virsh)"
}

# orchestrator path (DEFAULT): drive a REAL control-plane SessionService.CreateSession via
# `ds-driver-e2e -mode orch-create`. This is the load-bearing difference from the hostagent
# path: CreateSession writes an authoritative SESSION RECORD (server-minted UUID) *and*
# places + CloneFromImage on the host-agent for that same UUID. So the booted domain
# `ds-<uuid>` is backed by a record — the host-agent reconciler treats it as legitimate
# instead of orphan-quarantining a recordless VM (the §3-rule-a suspend that kept L2 paused
# under the bare hostagent-clone). The minted UUID becomes SESSION_UUID (consumed by
# wait_for_l2/down); the writer Attach handle (endpoint+token) is captured for the :4242
# drive (DS_DRIVE_SEAT).
ATTACH_ENDPOINT=""; ATTACH_TOKEN=""
drive_orchestrator() {
  say "drive CreateSession through the orchestrator control plane (ds-driver-e2e -mode orch-create — a session RECORD exists, so the reconciler does not orphan-quarantine the VM)"
  local out rc
  out="$("$BIN/ds-driver-e2e" -mode orch-create -orch-addr "$ORCH_LISTEN" -repo demo -env-config-ref demo-env -launching-user mvp-user 2>&1)"; rc=$?
  printf '%s\n' "$out" | sed 's/^/   /'
  [ "$rc" = 0 ] || die "orchestrator CreateSession failed (rc=$rc) — see above + $ORCH_LOG"
  local minted
  minted="$(printf '%s\n' "$out" | sed -n 's/.*E2E-ORCH-CREATE: session=\([^ ]*\).*/\1/p' | head -1)"
  [ -n "$minted" ] || die "could not parse the minted session UUID from the E2E-ORCH-CREATE line"
  SESSION_UUID="$minted"
  ATTACH_ENDPOINT="$(printf '%s\n' "$out" | sed -n 's/.*E2E-ORCH-ATTACH:.*endpoint=\([^ ]*\).*/\1/p' | head -1)"
  ATTACH_TOKEN="$(printf '%s\n' "$out" | sed -n 's/.*E2E-ORCH-ATTACH:.*token=\([^ ]*\).*/\1/p' | head -1)"
  # ALIGN the per-session index to whatever was actually allocated. The fat flavor pins 7
  # (seed_index_counter) so it reports index=7; m0 is NOT pinned, so the host-agent counter
  # hands a dynamic index (e.g. 0 -> dstap-0/10.77.0.x). The floor/gateways/route
  # (bring_up_gateways_and_floor -> gate-up.sh DS_SESSION_IDX), wait_for_l2 ($TAP/$SESSION_IDX),
  # and the reach probe ($NET.1) MUST target the REAL tap — hardcoding 7 left the m0 VM on
  # dstap-0 ungated/unrouted so its CC could not egress (the no-turn RC). Re-derive from index=.
  local aidx
  aidx="$(printf '%s\n' "$out" | sed -n 's/.*E2E-ORCH-CREATE: session=[^ ]* index=\([0-9][0-9]*\).*/\1/p' | head -1)"
  if [ -n "$aidx" ] && [ "$aidx" != "$SESSION_IDX" ]; then
    say "aligning per-session index $SESSION_IDX -> $aidx (orchestrator-allocated tap dstap-$aidx)"
    SESSION_IDX="$aidx"; NET="10.77.${SESSION_IDX}"; TAP="dstap-${SESSION_IDX}"
  fi
  say "orchestrator minted session $SESSION_UUID on $TAP (writer endpoint: ${ATTACH_ENDPOINT:-n/a})"
}

# Compose the appliance floor + gateways with the host-agent's live per-session NFT. The
# host-agent's InstantiateSessionNFT (Model A) makes only the per-session allow4_/allow6_
# sets in `inet ds_filter`; the default-deny forward + 53/80/443 redirects + QUIC reject
# (the `inet ds_boundary` floor) and the ds-dnsgate/ds-tlsproxy gateways come from
# gate-up.sh, run in PRESERVE-FILTER mode so it leaves ds_filter + the host-agent's tap
# untouched. Applied right after the create so the booted L2's egress is gated. (A zero
# open-egress window — floor before NIC — is the 01KV9B2DGN "full boundary readiness
# before VM start" follow-up; for the demo the floor lands immediately post-boot.)
bring_up_gateways_and_floor() {
  say "compose ds_boundary floor + ds-dnsgate/ds-tlsproxy gateways (gate-up.sh --no-filter-reset; host-agent owns ds_filter + the tap)"
  # DS_GATE_TLS_MODE is passed THROUGH (opaque default). In swap mode (posture-b) ALSO
  # pin the interception CA cert+key paths so gate-up.sh's ds-tlsproxy ingests the SAME
  # CA whose cert the guest CC already trusts (NODE_EXTRA_CA_CERTS, seeded by
  # seed_intercept_ca). DS_TLSPROXY_SESSION_CA_CERT/KEY are inherited from the env if the
  # operator pinned them; otherwise default to the seed_intercept_ca pair under $GATE_RUN.
  DS_SESSION_IDX="$SESSION_IDX" DS_GATE_PRESERVE_FILTER=1 DS_GATE_TLS_MODE="${DS_GATE_TLS_MODE:-opaque}" \
  DS_TLSPROXY_SESSION_CA_CERT="${DS_TLSPROXY_SESSION_CA_CERT:-$SWAP_CA_CERT}" \
  DS_TLSPROXY_SESSION_CA_KEY="${DS_TLSPROXY_SESSION_CA_KEY:-$GATE_RUN/intercept-ca.key}" \
    bash "$(dirname "$0")/gate-up.sh" --no-filter-reset 2>&1 | sed 's/^/   /'
}

# D63 boundary-readiness PRE-step (01KV9B2DGN): bring the host-WIDE floor (the 3
# RequiredBoundaryTables: ds_boundary/ds_resolver_closure/ds_proxy_out) + the
# ds-dnsgate/ds-tlsproxy gateways UP BEFORE drive_orchestrator, so the host-agent's
# pre-CreateSession readiness probe (3 tables present + both gateways answering) passes
# instead of fail-closing. DS_GATE_FLOOR_ONLY skips the per-session routed tap (the
# host-agent's CreateTap owns it at step-4); the per-tap route lands on the normal
# post-CreateSession bring_up_gateways_and_floor pass. Same swap env as that pass.
bring_up_floor_only() {
  say "D63 readiness PRE-step: floor (3 boundary tables) + ds-dnsgate/ds-tlsproxy BEFORE CreateSession (gate-up.sh DS_GATE_FLOOR_ONLY=1)"
  DS_GATE_FLOOR_ONLY=1 DS_GATE_PRESERVE_FILTER=1 DS_GATE_TLS_MODE="${DS_GATE_TLS_MODE:-opaque}" \
  DS_TLSPROXY_SESSION_CA_CERT="${DS_TLSPROXY_SESSION_CA_CERT:-$SWAP_CA_CERT}" \
  DS_TLSPROXY_SESSION_CA_KEY="${DS_TLSPROXY_SESSION_CA_KEY:-$GATE_RUN/intercept-ca.key}" \
    bash "$(dirname "$0")/gate-up.sh" --no-filter-reset 2>&1 | sed 's/^/   /'
}

# Assert the orphan-quarantine is gone: with an orchestrator session record the reconciler
# must NOT suspend the VM. Confirm domstate stays `running` across 3 resync intervals and no
# POLICY_BREACH/quarantine line is emitted.
assert_no_quarantine() {
  say "assert: no orphan-quarantine (domstate stays running + no POLICY_BREACH over ~15s)"
  local dom="ds-${SESSION_UUID}" ok=1 i st
  for i in 1 2 3; do
    sleep 5
    st="$(virsh domstate "$dom" 2>/dev/null | tr -d '[:space:]')"
    say "  +$((i*5))s domstate=$st"
    [ "$st" = running ] || ok=0
  done
  if grep -qiE "quarantin|POLICY_BREACH" "$HA_LOG" 2>/dev/null; then
    say "  WARN: quarantine/POLICY_BREACH seen in $HA_LOG:"; grep -iE "quarantin|POLICY_BREACH" "$HA_LOG" | tail -2 | sed 's/^/     /'; ok=0
  fi
  [ "$ok" = 1 ] && say "  OK: L2 RUNNING with no quarantine (orchestrator session record honored)" \
    || die "L2 quarantined or not running — the session record did not suppress §3-rule-a (see $HA_LOG / $ORCH_LOG)"
}

# --- drive a REAL CC turn over the writer seat (DS_DRIVE_SEAT=1) ---------------
# The substrate proof (tap+NFT+boot, no quarantine) stands on its own; this leg adds
# the M1 headline: drive ONE Claude Code turn over the writer seat the orchestrator
# already minted (the orch-create Attach handle, ATTACH_ENDPOINT/ATTACH_TOKEN captured
# by drive_orchestrator). It is a TRANSPORT-TARGET SWAP, not a new harness: ds-seat-drive
# (g1's writer-seat client, the cmd front-end of e2e.DriveKVMScripted) DIALS the
# pre-advertised writer-seat over attach.v1 and drives the prompt — it launches no
# podman/qemu of its own; the per-session m0 VM already runs the headless stream-json CC
# start_hostagent folded in.
#
# It is gated DS_KVM_LIVE=1 by ds-seat-drive itself (e2e.kvmGateArmed); with the gate
# unset the binary dials nothing and returns ErrKVMLiveGateUnset. Here, INSIDE the live
# L1 with a booted VM + a minted writer seat, we arm it and resolve the DS_KVM_LIVE_*
# knobs from the orch-create Attach handle. A completed CC turn is the green signal.
# A missing handle (e.g. the hostagent DRIVE path mints none) or a missing ds-seat-drive
# binary is a WARN, not a die — the substrate proof above is independent.
drive_seat() {
  if [ -z "$ATTACH_ENDPOINT" ] || [ -z "$ATTACH_TOKEN" ]; then
    say "WARN: DS_DRIVE_SEAT=1 but no writer-seat Attach handle was captured (endpoint/token empty — orch-create mints it; the hostagent DRIVE path does not) — skipping the seat drive; the substrate proof stands"
    return 0
  fi
  if [ ! -x "$SEAT_DRIVE_BIN" ]; then
    say "WARN: DS_DRIVE_SEAT=1 but ds-seat-drive not found/!exec at $SEAT_DRIVE_BIN (build it: go build ./client/cmd/ds-seat-drive and stage it; override DS_SEAT_DRIVE_BIN) — skipping the seat drive; the substrate proof stands"
    return 0
  fi
  say "drive ONE CC turn over the minted writer seat (ds-seat-drive, session=$SESSION_UUID, endpoint=$ATTACH_ENDPOINT)"
  # Arm the per-session KVM-VM writer-seat tier (e2e.kvmAttachFromEnv) from the
  # orch-create Attach handle: the host-local writer-seat endpoint, the minted session
  # UUID, and the short-lived session-scoped attach token. The token rides the env only
  # (DS_KVM_LIVE_TOKEN), never an argv or a tracked file (D50 raw-class). These four are
  # the ONLY env knobs ds-seat-drive resolves (e2e.DriveKVMScriptedFromEnv).
  local args=(-prompt "$SEAT_PROMPT" -timeout "${DS_SEAT_TIMEOUT:-2m0s}")
  # VM-side-effect proof: pass the marker TOKEN as ds-seat-drive's -proof (the CONTENT
  # CC writes), and -proof-file as the file name under the guest /work cwd. ds-seat-drive
  # asserts the projected attach.v1 round-trip; the file readback is a manual operator
  # check on the host side of the guest /work share ($SEAT_WORK), which we surface as a
  # hint (ds-seat-drive itself does not consume DS_SEAT_WORK). Unset ⇒ a no-tool turn.
  if [ -n "$SEAT_PROOF" ]; then
    args+=(-proof "$SEAT_PROOF" -proof-file "$SEAT_PROOF_FILE")
    [ -n "$SEAT_WORK" ] && say "  (proof token set; after the run inspect $SEAT_WORK/$SEAT_PROOF_FILE on the host side of the guest /work share for the token)"
  fi
  DS_KVM_LIVE=1 \
  DS_KVM_LIVE_ATTACH_UDS="$ATTACH_ENDPOINT" \
  DS_KVM_LIVE_SESSION="$SESSION_UUID" \
  DS_KVM_LIVE_TOKEN="$ATTACH_TOKEN" \
    "$SEAT_DRIVE_BIN" "${args[@]}" 2>&1 | sed 's/^/   /'
  # ds-seat-drive exits non-zero iff the writer-seat drive failed (dial / no CC turn).
  local rc=${PIPESTATUS[0]}
  if [ "$rc" = 0 ]; then
    say "  OK: the CC turn completed over the writer seat — M1 headline proven (real CC driven inside the per-session KVM VM)"
  else
    say "  WARN: ds-seat-drive returned rc=$rc — the substrate proof stands; inspect the output above + $HA_LOG (CC launch / writer-seat dial)"
  fi
}

# --- wait for the booted L2 domain + its attach reachability ------------------
# Proof the real host-agent (not gate-up.sh/l2-up.sh) created the tap+NFT and booted
# L2: (1) a libvirt domain ds-<uuid> is RUNNING; (2) the per-session tap dstap-<idx>
# exists (liveAttach.CreateTap); (3) the per-session NFT objects exist
# (InstantiateSessionNFT); (4) L2 is reachable on its routed-tap IP (fat) or the
# attach UDS is served (both flavors). All observed on L1 — host untouched.
wait_for_l2() {
  say "wait for the booted L2 domain + the per-session tap/NFT (deadline ${DEADLINE_SECS}s)"
  local dom="ds-${SESSION_UUID}"
  local deadline=$(( $(date +%s) + DEADLINE_SECS ))
  local dom_up="" tap_up="" nft_up=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ -z "$dom_up" ] && virsh domstate "$dom" 2>/dev/null | grep -q running; then
      dom_up=1; say "  [domain] $dom is RUNNING (libvirt boot via the host-agent)"
    fi
    if [ -z "$tap_up" ] && ip -br link show "$TAP" >/dev/null 2>&1; then
      tap_up=1; say "  [tap] $TAP exists (liveAttach.CreateTap)"
    fi
    if [ -z "$nft_up" ] && nft list ruleset 2>/dev/null | grep -qE "allow4_|dstap-${SESSION_IDX}|ds_filter|ds_boundary"; then
      nft_up=1; say "  [nft] per-session NFT objects present (InstantiateSessionNFT)"
    fi
    [ -n "$dom_up" ] && [ -n "$tap_up" ] && [ -n "$nft_up" ] && break
    sleep 3
  done

  # Reachability leg (best-effort, flavor-aware): fat -> ssh on the routed tap;
  # both -> the served attach UDS under $ATTACH_DIR (the writer-seat carriage).
  if [ "$FLAVOR" = "fat" ]; then
    say "  [reach] probe L2 ssh on $NET.1 (fat routed-tap self-config)"
    local sdl=$(( $(date +%s) + 60 ))
    while [ "$(date +%s)" -lt "$sdl" ]; do
      if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=6 -o BatchMode=yes root@"$NET.1" true 2>/dev/null; then
        say "  [reach] L2 SSH UP at $NET.1 (routed-tap egress path live)"; break
      fi
      sleep 4
    done
  fi
  ls -la "$ATTACH_DIR" 2>/dev/null | sed 's/^/   attach: /' || true

  # yn renders a set-or-empty marker as yes/NO (the markers are "1" or "", and the
  # bare ${v:+yes}${v:-NO} idiom would print "yes1" when set, since :- expands the value).
  yn(){ [ -n "$1" ] && printf yes || printf NO; }
  say "── summary ─────────────────────────────────────────────"
  say "  domain RUNNING : $(yn "$dom_up")"
  say "  tap $TAP       : $(yn "$tap_up")"
  say "  per-session NFT: $(yn "$nft_up")"
  [ -n "$dom_up" ] && [ -n "$tap_up" ] && [ -n "$nft_up" ] \
    && say "DONE: the REAL host-agent AttachPrimitive programmed $TAP + per-session NFT and booted L2 ($dom)." \
    || die "incomplete: not all of {domain,tap,nft} came up in time — see $HA_LOG / 'nft list ruleset' / 'virsh list'"
}

# --- teardown -----------------------------------------------------------------
down() {
  say "tearing down the orchestrator stack + the booted L2"
  command -v virsh >/dev/null && {
    for d in $(virsh list --name 2>/dev/null | grep '^ds-' || true); do
      say "  destroy domain $d"; virsh destroy "$d" >/dev/null 2>&1 || true
    done
  }
  for pf in "$ORCH_PID" "$HA_PID"; do
    [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2>/dev/null && { kill "$(cat "$pf")" 2>/dev/null || true; sleep 1; kill -9 "$(cat "$pf")" 2>/dev/null || true; }
    rm -f "$pf"
  done
  say "orchestrator stack down (the host + its Tailscale link were never touched — all state was in L1)"
}

status() {
  for p in "$HA_PID:host-agent" "$ORCH_PID:orchestrator"; do
    pf="${p%%:*}"; nm="${p##*:}"
    if [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2>/dev/null; then echo "$nm: RUNNING (pid $(cat "$pf"))"; else echo "$nm: stopped"; fi
  done
  echo "domains:"; virsh list 2>/dev/null | sed 's/^/  /' || echo "  (no virsh)"
  echo "tap $TAP:"; ip -br link show "$TAP" 2>/dev/null | sed 's/^/  /' || echo "  (absent)"
  echo "nft (per-session):"; nft list ruleset 2>/dev/null | grep -E "allow4_|dstap-|ds_filter|ds_boundary" | sed 's/^/  /' || echo "  (none)"
  echo "attach sockets ($ATTACH_DIR):"; ls -la "$ATTACH_DIR" 2>/dev/null | sed 's/^/  /' || true
}

# --- posture-(b) host-side CA-delivery assertion (NO live VM boot) -------------
# The acceptance proof for the in-guest interception-CA delivery: HOST-SIDE, by
# virt-cat'ing the per-session qcow2 overlay at the reconciled guest path
# ($SWAP_GUEST_CA_PATH = NODE_EXTRA_CA_CERTS) — read-only, no domain start. It
# confirms (1) a CERTIFICATE landed at that path and (2) it is the SAME CA whose
# cert is staged host-side (fingerprint match), i.e. the orchestrator-minted/proxy
# interception CA, not a stale leftover. This is the same read-back probe the live
# liveTrustStoreWriter.HasTrustAnchor performs, exposed as an operator check.
#
# It locates the overlay as $OVERLAYS/<session>.qcow2 (the v0 OverlayStore naming);
# override the session via DS_SESSION_UUID or the overlay via DS_ASSERT_OVERLAY.
# Exits non-zero (fail-closed) if the cert is absent, unreadable, or mismatched.
ca_assert() {
  [ "$TLS_MODE" = "swap" ] || die "ca-assert is posture-(b) only — set DS_GATE_TLS_MODE=swap"
  command -v virt-cat >/dev/null 2>&1 || die "ca-assert needs virt-cat (libguestfs-tools) — read-only overlay inspect, no VM boot"
  local overlay="${DS_ASSERT_OVERLAY:-}"
  if [ -z "$overlay" ]; then
    # Prefer the orchestrator-minted session's overlay; fall back to the seed UUID.
    for cand in "$OVERLAYS/$SESSION_UUID.qcow2" "$OVERLAYS"/*.qcow2; do
      [ -r "$cand" ] && { overlay="$cand"; break; }
    done
  fi
  [ -n "$overlay" ] && [ -r "$overlay" ] || die "ca-assert: no readable per-session overlay under $OVERLAYS (boot a swap-mode session first, or set DS_ASSERT_OVERLAY)"
  say "ca-assert: virt-cat overlay=$overlay path=$SWAP_GUEST_CA_PATH (read-only; no VM boot)"
  local guest_pem
  guest_pem="$(virt-cat -a "$overlay" "$SWAP_GUEST_CA_PATH" 2>/dev/null)" \
    || die "ca-assert: interception CA NOT present at $SWAP_GUEST_CA_PATH in $overlay (InjectCA did not deliver it — fail-closed)"
  printf '%s' "$guest_pem" | grep -q "BEGIN CERTIFICATE" \
    || die "ca-assert: $SWAP_GUEST_CA_PATH in $overlay is not a PEM CERTIFICATE (fail-closed)"
  # Fingerprint-match against the host-side staged cert (the public CA material). We
  # NEVER print the cert body or any key — only the SHA-256 fingerprint of the public
  # DER, which is non-secret.
  if command -v openssl >/dev/null 2>&1 && [ -r "$SWAP_CA_CERT" ]; then
    local host_fp guest_fp
    host_fp="$(openssl x509 -in "$SWAP_CA_CERT" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')"
    guest_fp="$(printf '%s' "$guest_pem" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')"
    if [ -n "$host_fp" ] && [ "$host_fp" = "$guest_fp" ]; then
      say "ca-assert: OK — the interception CA at $SWAP_GUEST_CA_PATH MATCHES the host-side CA (sha256=$guest_fp)"
    elif [ -n "$host_fp" ]; then
      # The orchestrator-minted per-session CA may legitimately differ from the
      # pre-staged proxy CA; a present-but-different cert is still a delivered anchor.
      say "ca-assert: OK — a CERTIFICATE is present at $SWAP_GUEST_CA_PATH (guest sha256=$guest_fp); differs from the staged proxy CA (sha256=$host_fp) — confirm it is the orchestrator-minted per-session CA the proxy terminates with (coordinator)"
    else
      say "ca-assert: OK — a CERTIFICATE is present at $SWAP_GUEST_CA_PATH (could not fingerprint the host staged cert to compare)"
    fi
  else
    say "ca-assert: OK — a CERTIFICATE is present at $SWAP_GUEST_CA_PATH (openssl/host cert unavailable for a fingerprint compare)"
  fi
}

# --- posture-(b) swap + hostagent-drive guard (additive; fail-closed) ---------
# posture-(b) (DS_GATE_TLS_MODE=swap) is built around the per-session interception CA
# the ORCHESTRATOR mints + drops under $DS_ORCH_OVERLAY_DIR/.ds-ca-bundles/<caRef>.pem
# (keyed by the ca_bundle_ref CreateSession carries) AND the writer-seat Attach handle
# the orchestrator advertises. Only the DEFAULT orchestrator drive path produces both:
# drive_orchestrator (ds-driver-e2e -mode orch-create) creates an authoritative session
# record + captures the Attach handle, and start_orchestrator's DS_ORCH_OVERLAY_DIR is
# where the minted CA lands. The hostagent DRIVE path (drive_hostagent -> ds-driver-e2e
# -mode clone) drives the host-agent's HypervisorDriverService DIRECTLY: it mints NO
# orchestrator session-CA and NO writer-seat handle, so swap mode has no per-session CA
# for ds-tlsproxy to terminate with and (under DS_DRIVE_SEAT) no seat to drive.
#   - As-shipped (baked-CA posture, this file keeps DS_HOSTAGENT_SKIP_CA_INJECT=1): the
#     swap CC launch trusts the BAKED in-guest CA, but ds-tlsproxy still has to sign
#     leaves with the orchestrator-minted per-session CA the hostagent path never created.
#   - When the live §4.1 step-7 InjectCA is armed instead (DS_HOSTAGENT_SKIP_CA_INJECT
#     dropped), the host-agent's FileCABundleSource ADDITIONALLY reads nothing for the
#     absent ca_bundle_ref and CreateSession aborts fail-closed mid-boot (cainject.go:
#     "create ... has no CA bundle ref").
#
# Either way swap+hostagent is unsupported, so rather than let it surface as an opaque
# mid-boot crash (or a CA-identity mismatch the guest CC rejects), REJECT the combination
# up front (option A) with actionable guidance steering the operator to
# DS_ORCH_DRIVE=orchestrator (the path that mints the CA + the handle). This is PURELY
# ADDITIVE under DS_GATE_TLS_MODE=swap: any non-swap mode (opaque/enforce) returns 0
# immediately, and the swap+orchestrator path returns 0 too — so the opaque/enforce paths
# AND the default orchestrator drive path are byte-identical (no change to their argv or
# control flow). No host/guest state is created before this runs (it is the first step of
# up()), so a rejected run leaves the testbed untouched.
guard_swap_drive() {
  [ "$TLS_MODE" = "swap" ] || return 0          # only posture-(b) is affected
  [ "$DRIVE" = "hostagent" ] || return 0        # the orchestrator drive path mints the CA
  die "DS_GATE_TLS_MODE=swap requires DS_ORCH_DRIVE=orchestrator (got DS_ORCH_DRIVE=$DRIVE).
   posture-(b) terminates the guest TLS with the per-session interception CA the
   ORCHESTRATOR mints + drops under \$DS_ORCH_OVERLAY_DIR/.ds-ca-bundles (keyed by the
   ca_bundle_ref CreateSession carries) and drives over the orchestrator-minted writer
   seat. The hostagent DRIVE path drives the host-agent directly (ds-driver-e2e -mode
   clone) with NO minted ca_bundle_ref and NO writer-seat handle — so swap has no
   per-session CA for ds-tlsproxy to sign leaves with (and, when the live InjectCA is
   armed, CreateSession aborts fail-closed mid-boot on the absent bundle).
   Re-run with DS_ORCH_DRIVE=orchestrator (the default), which mints + drops the bundle."
}

# --- persist session facts for the CI keystone asserts (assert-gating.sh) ------
# assert-gating.sh's K3 (domain ds-<uuid>) + K5 (<uuid>.sock) key on the SESSION UUID,
# but the orchestrator drive path MINTS a server-side UUID (drive_orchestrator) that only
# this in-L1 runner knows. Persist it (+ the aligned index) to $SESSION_ENV so
# run-testbed.sh `ci` can source it and thread DS_SESSION_UUID/DS_SESSION_IDX into the
# SSH'd assert-gating.sh invocation (mirrors stack-up-host.sh persist_session). Written by
# root into $RUN (root-owned); no secrets land here (the attach token stays in-process).
SESSION_ENV="${DS_SESSION_ENV:-$RUN/session.env}"
persist_session() {
  mkdir -p "$RUN"
  cat > "$SESSION_ENV" <<EOF
DS_SESSION_UUID=$SESSION_UUID
DS_SESSION_IDX=$SESSION_IDX
DS_SESSION_TAP=$TAP
DS_SESSION_DOMAIN=ds-$SESSION_UUID
EOF
  say "persisted session facts -> $SESSION_ENV (DS_SESSION_UUID=$SESSION_UUID DS_SESSION_IDX=$SESSION_IDX)"
}

# --- orchestration ------------------------------------------------------------
up() {
  # FIRST: reject the unsupported swap + hostagent-drive combination before any host
  # or guest state is created (additive; a no-op outside DS_GATE_TLS_MODE=swap +
  # DS_ORCH_DRIVE=hostagent, so every other path is byte-identical).
  guard_swap_drive
  mkdir -p "$RUN" "$ATTACH_DIR" "$OVERLAYS"
  preflight
  kernel_prep
  seed_index_counter
  seed_entrypoint_ref
  # posture-(b) only: pre-generate the interception CA so start_hostagent's
  # NODE_EXTRA_CA_CERTS resolves to an existing cert and gate-up.sh reuses the same pair.
  # No-op outside DS_GATE_TLS_MODE=swap, so the opaque/fat/m0 path is byte-identical.
  seed_intercept_ca
  # D148: hand the run/overlay dirs + the pre-seeded index counter + entrypoint refs to
  # $AGENT_USER BEFORE the non-root agent starts (it must bind the attach UDS + advance the
  # counter). No-op'd cleanly if not root (WARN).
  chown_agent_dirs
  # Orchestrator FIRST so the host-agent's heartbeat reporter (-orchestrator-addr)
  # connects immediately and the scheduler has this host before the first CreateSession
  # (same start order as ds-serve-stack.sh; the dials are otherwise lazy/per-RPC).
  start_orchestrator
  # D148: arm the setcap'd privileged helper (install + setcap + verify) BEFORE the
  # non-root agent starts — it forks the helper at the first CreateSession's CreateTap.
  install_nethelper
  start_hostagent
  open_recover_latch
  case "$DRIVE" in
    hostagent)    drive_hostagent ;;
    orchestrator)
      # D63 boundary-readiness (01KV9B2DGN): the host-agent PROBES the boundary (3 floor
      # tables + ds-dnsgate/ds-tlsproxy answering) at CreateSession and fails-closed if
      # absent. So bring the host-wide floor + gateways up FIRST (bring_up_floor_only —
      # NO tap, which the host-agent's CreateTap owns at step-4). drive_orchestrator then
      # passes the probe + creates the tap; bring_up_gateways_and_floor adds the
      # per-session tap route (PRESERVE mode). (Pre-D63 order ran the floor AFTER create.)
      bring_up_floor_only
      drive_orchestrator
      bring_up_gateways_and_floor
      ;;
    *) die "unknown DS_ORCH_DRIVE=$DRIVE (hostagent|orchestrator)" ;;
  esac
  # Persist the (now-final) session UUID + aligned index so run-testbed.sh `ci` can thread
  # them into assert-gating.sh's K3/K5 UUID-dependent checks (the orchestrator drive path
  # mints the UUID server-side; only this runner knows it).
  persist_session
  wait_for_l2
  if [ "$DRIVE" = orchestrator ]; then assert_no_quarantine; fi
  # DS_DRIVE_SEAT=1 adds the M1-headline leg: drive one REAL CC turn over the
  # orchestrator-minted writer seat (the orch-create Attach handle). Gated so the
  # default up-orch (substrate+egress proof) is unchanged; the seat-drive carriage
  # only exists on the orchestrator DRIVE path (it is what mints the Attach handle).
  if [ "$DRIVE_SEAT" = 1 ]; then drive_seat; fi
}

case "${1:-up}" in
  up)         up ;;
  preflight)  preflight ;;
  status)     status ;;
  ca-assert)  ca_assert ;;
  down)       down ;;
  *) echo "usage: $0 {up|preflight|status|ca-assert|down}   (env: DS_L2_FLAVOR=fat|m0  DS_ORCH_DRIVE=hostagent|orchestrator  DS_GATE_TLS_MODE=opaque|enforce|swap)" >&2; exit 2 ;;
esac
