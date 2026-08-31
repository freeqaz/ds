#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ds-test-cc-drive.sh — reproduce the proven MVP end to end, idempotently:
#
#   boot a rootless KVM VM (the baked M0 image v3) → inject a FRESH Claude Code
#   OAuth credential → DRIVE real Claude Code over attach.v1 (the committed
#   DS_KVM_LIVE goldentrace KVM-tier test) → print CC's real response + the
#   in-VM tool-execution proof (a file CC was driven to write, read back from
#   the guest's /work 9p share) → clean up.
#
# 100% ROOTLESS: no sudo anywhere. /dev/kvm + /dev/vhost-vsock are 0666; the VM
# image is prepared offline with debugfs (writes an ext4 image the user owns),
# the config-drive ISO is built inside a throwaway podman container (no host iso
# tool), and the host↔guest /work share is plain virtio-9p.
#
# This is the MVP egress posture (SLIRP-direct NAT to api.anthropic.com + the
# OAuth token injected into the guest, contained to a single trusted box) — NOT
# the gated egress-gateway path (ds-dnsgate/ds-tlsproxy), which is a separate
# future test. The attach DRIVE channel is already sandboxed (AF_VSOCK, no IP).
#
# Run:  bash scripts/live-mvp/ds-test-cc-drive.sh
#
# Prereqs: a valid ~/.claude OAuth token (~/.claude/.credentials.json with
# .claudeAiOauth.accessToken) and the baked image present under ~/tmp/ds-images
# (m0-base-v3.raw + m0-vmlinuz-v2 + m0-initrd-v2.img). qemu, qemu-img, podman,
# jq, go, debugfs on PATH.

set -u -o pipefail

# ───────────────────────────── config ──────────────────────────────────────
# REPO defaults to the checkout this script lives in (<repo>/scripts/live-mvp/).
REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
IMG_DIR="$HOME/tmp/ds-images"
BASE_RAW="$IMG_DIR/m0-base-v3.raw"
VMLINUZ="$IMG_DIR/m0-vmlinuz-v2"
INITRD="$IMG_DIR/m0-initrd-v2.img"
GENCC_DIR="$HOME/tmp/ds-m0-build/gencc"

SESSION_UUID="m0-cc-drive"
GUEST_CID=63            # unique high guest-cid (vhost-vsock context id)
GUEST_VSOCK_PORT=4242   # ds-attachfwd listens here in the guest
PROOF_FILE="ds-headless-proof.txt"               # written by proof.jsonl, under /work
PROOF_TOKEN="DS-HEADLESS-PROOF-7Q2K"             # token proof.jsonl embeds

# Per-run scratch (all under ~/tmp; nothing in /tmp). Stable names ⇒ idempotent.
RUN_DIR="$HOME/tmp/ds-cc-drive-run"
PREP_RAW="$RUN_DIR/m0-base-v3-work.raw"   # reflink copy of BASE_RAW + /work fstab
OVERLAY="$RUN_DIR/overlay.qcow2"          # per-session qcow2 over PREP_RAW
CONFIG_PB="$RUN_DIR/config.pb"
ISO_STAGE="$RUN_DIR/iso-stage"
CONFIG_ISO="$RUN_DIR/config-drive.iso"
TOKEN_FILE="$RUN_DIR/attach-token.json"
WORKDIR="$RUN_DIR/work"                   # host side of the guest /work 9p share
UDS="$RUN_DIR/attach.sock"                # the writer-seat UDS the test dials
SERIAL_LOG="$RUN_DIR/serial.log"
QEMU_MON="$RUN_DIR/qemu-monitor.log"
HOSTBRIDGE_BIN="$HOME/tmp/ds-hostbridge"
HOSTBRIDGE_LOG="$RUN_DIR/hostbridge.log"
TEST_LOG="$RUN_DIR/gotest.log"

QEMU_PID=""
HB_PID=""

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
grn()   { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()   { printf '\033[33m%s\033[0m\n' "$*"; }
step()  { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
die()   { red "FATAL: $*"; exit 1; }

# ───────────────────────────── cleanup trap ────────────────────────────────
cleanup() {
  local rc=$?
  step "cleanup"
  if [ -n "${HB_PID:-}" ] && kill -0 "$HB_PID" 2>/dev/null; then
    kill "$HB_PID" 2>/dev/null || true
    wait "$HB_PID" 2>/dev/null || true
  fi
  if [ -n "${QEMU_PID:-}" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
    # graceful then hard
    kill "$QEMU_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do kill -0 "$QEMU_PID" 2>/dev/null || break; sleep 0.4; done
    kill -9 "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  # remove the per-run mutable artifacts (the overlay never mutated the base);
  # keep logs for forensics.
  rm -f "$OVERLAY" "$CONFIG_ISO" "$CONFIG_PB" "$TOKEN_FILE" 2>/dev/null || true
  rm -rf "$ISO_STAGE" 2>/dev/null || true
  # PREP_RAW is a reflink CoW copy (near-zero real bytes); drop it too.
  rm -f "$PREP_RAW" 2>/dev/null || true
  echo "cleanup done (logs kept under $RUN_DIR)"
  exit $rc
}
trap cleanup EXIT INT TERM

# ───────────────────────────── preflight ───────────────────────────────────
step "preflight"
for t in qemu-system-x86_64 qemu-img podman jq go debugfs; do
  command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"
done
[ -e /dev/kvm ]          || die "/dev/kvm not present"
[ -w /dev/kvm ]          || die "/dev/kvm not writable (need 0666, rootless KVM)"
[ -e /dev/vhost-vsock ]  || die "/dev/vhost-vsock not present"
[ -w /dev/vhost-vsock ]  || die "/dev/vhost-vsock not writable (need 0666, rootless vsock)"
[ -f "$BASE_RAW" ]       || die "base image missing: $BASE_RAW"
[ -f "$VMLINUZ" ]        || die "kernel missing: $VMLINUZ"
[ -f "$INITRD" ]         || die "initrd missing: $INITRD"
[ -d "$GENCC_DIR" ]      || die "gencc generator dir missing: $GENCC_DIR"
[ -f "$REPO/client/goldentrace/e2e/testdata/proof.jsonl" ] || die "committed proof.jsonl fixture missing"

# A FRESH token, every run. Never printed.
[ -f "$HOME/.claude/.credentials.json" ] || die "no ~/.claude/.credentials.json (a valid OAuth token is required)"
DS_CC_TOKEN="$(jq -r '.claudeAiOauth.accessToken // empty' "$HOME/.claude/.credentials.json")"
[ -n "$DS_CC_TOKEN" ] || die "no .claudeAiOauth.accessToken in ~/.claude/.credentials.json"
export DS_CC_TOKEN
grn "fresh OAuth token extracted (value redacted, len=${#DS_CC_TOKEN})"

# Fresh per-session scratch dir (idempotent: clear any prior run's mutables).
rm -rf "$RUN_DIR" 2>/dev/null || true
mkdir -p "$RUN_DIR" "$WORKDIR" "$ISO_STAGE"
# the guest ds user (uid 1000 == host user under mapped-xattr) must write here.
chmod 0777 "$WORKDIR"
rm -f "$WORKDIR/$PROOF_FILE" 2>/dev/null || true

# ───────────── prepare a per-run raw base with a /work 9p mount ─────────────
# The committed proof.jsonl drives CC to write /work/<PROOF_FILE>. The M0 image
# has no /work and no host↔guest share, so we (rootlessly, offline) reflink-copy
# the base raw and use debugfs to (a) mkdir /work and (b) add an fstab line that
# auto-mounts a virtio-9p share (tag "work") at /work. systemd-fstab-generator
# (present in the image, systemd 252) pulls it in at boot.
step "prepare per-run image (/work 9p auto-mount, rootless via debugfs)"
cp --reflink=auto "$BASE_RAW" "$PREP_RAW" || die "reflink copy of base raw failed"
NEW_FSTAB="$RUN_DIR/fstab"
{
  echo 'LABEL=DS_M0ROOT / ext4 defaults 0 1'
  echo 'work /work 9p trans=virtio,version=9p2000.L,msize=104857600,access=client,_netdev,nofail 0 0'
} > "$NEW_FSTAB"
debugfs -w -R "mkdir /work" "$PREP_RAW" >/dev/null 2>&1 || true   # idempotent (ok if exists)
debugfs -w -R "rm /etc/fstab" "$PREP_RAW" >/dev/null 2>&1 || true
debugfs -w -R "write $NEW_FSTAB /etc/fstab" "$PREP_RAW" >/dev/null 2>&1 \
  || die "debugfs: could not write /etc/fstab into the prepared raw"
# verify
debugfs -R "cat /etc/fstab" "$PREP_RAW" 2>/dev/null | grep -q '/work 9p' \
  || die "prepared raw is missing the /work 9p fstab line"
grn "prepared raw has /work + the 9p auto-mount fstab line"

# ───────────────── build the config.pb (fresh token injected) ───────────────
step "build config.pb (gencc, fresh token injected into launch.env)"
( cd "$GENCC_DIR" && go build -o gencc . ) || die "gencc build failed"
# DS_CC_TOKEN is read from env by gencc; never appears on argv.
( cd "$GENCC_DIR" && ./gencc "$CONFIG_PB" "$SESSION_UUID" ) >/dev/null \
  || die "gencc failed to write $CONFIG_PB"
[ -s "$CONFIG_PB" ] || die "config.pb empty"
grn "config.pb built ($(wc -c < "$CONFIG_PB") bytes)"

# ───────────────── build the config-drive ISO (in podman) ───────────────────
# No host iso tool (genisoimage absent); run it inside a throwaway debian:bookworm
# container with genisoimage installed, mounting the stage dir. EXACT producer
# args: -volid DS_ENTRYPOINT -input-charset utf-8 -rational-rock -joliet.
step "build config-drive ISO (genisoimage inside a throwaway podman container)"
cp "$CONFIG_PB" "$ISO_STAGE/config.pb"   # ds-entrypoint reads config.pb (lowercase)
podman run --rm --network=host \
  -v "$ISO_STAGE":/stage:ro -v "$RUN_DIR":/out \
  docker.io/library/debian:bookworm \
  bash -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq genisoimage >/dev/null 2>&1 && \
           genisoimage -volid DS_ENTRYPOINT -input-charset utf-8 -rational-rock -joliet \
             -o /out/config-drive.iso /stage' \
  || die "config-drive ISO build (podman/genisoimage) failed"
[ -s "$CONFIG_ISO" ] || die "config-drive ISO not produced"
grn "config-drive ISO built ($(wc -c < "$CONFIG_ISO") bytes, volid DS_ENTRYPOINT)"

# ───────────────── per-session qcow2 overlay over the prepared raw ──────────
step "create per-session qcow2 overlay (base never mutated)"
qemu-img create -f qcow2 -F raw -b "$PREP_RAW" "$OVERLAY" >/dev/null \
  || die "qemu-img overlay create failed"
grn "overlay created over $(basename "$PREP_RAW")"

# ───────────────── mint the per-session attach token ────────────────────────
# The ds-hostbridge serve leg validates the presented attach token against this
# file (hex token + expiry). The drive test presents the SAME hex via
# DS_KVM_LIVE_TOKEN.
step "mint per-session attach token"
ATTACH_TOKEN_HEX="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
EXPIRES_AT=$(( $(date +%s) + 3600 ))
printf '{"token": "%s", "expires_at": %d}\n' "$ATTACH_TOKEN_HEX" "$EXPIRES_AT" > "$TOKEN_FILE"
grn "attach token minted (expires in 1h)"

# ───────────────── boot the VM in the background (rootless KVM) ─────────────
# -cpu host is MANDATORY (without AVX2 CC's V8 SEA SIGILLs). SLIRP user NIC is
# required for egress (v3 networkd DHCPs en* → 10.0.2.15). The 9p device exposes
# the host WORKDIR at guest /work (tag "work" matches the fstab source field).
step "boot VM (background, rootless KVM, -cpu host, SLIRP egress, vsock cid=$GUEST_CID)"
: > "$SERIAL_LOG"
qemu-system-x86_64 \
  -enable-kvm -cpu host -m 8192 -smp 2 -nographic \
  -kernel "$VMLINUZ" -initrd "$INITRD" \
  -append "root=LABEL=DS_M0ROOT console=ttyS0,115200 rw" \
  -drive file="$OVERLAY",format=qcow2,if=virtio \
  -drive file="$CONFIG_ISO",format=raw,if=virtio,readonly=on \
  -device vhost-vsock-pci,guest-cid="$GUEST_CID" \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -fsdev local,id=work9p,path="$WORKDIR",security_model=mapped-xattr \
  -device virtio-9p-pci,fsdev=work9p,mount_tag=work \
  -serial file:"$SERIAL_LOG" \
  -monitor "unix:$QEMU_MON,server,nowait" \
  -display none -no-reboot \
  >"$RUN_DIR/qemu.out" 2>&1 &
QEMU_PID=$!
sleep 1
kill -0 "$QEMU_PID" 2>/dev/null || { red "qemu died immediately:"; cat "$RUN_DIR/qemu.out"; die "qemu launch failed"; }
grn "qemu started (pid $QEMU_PID)"

# ───────────────── wait for the VM attach carriage to be up ─────────────────
# Poll the serial log for the boot milestones that mean the attach path is live:
# ds-attachfwd (the vsock carriage), ds-entrypoint (launches CC), multi-user.
step "wait for boot + attach carriage (multi-user + ds-attachfwd + ds-entrypoint)"
BOOT_DEADLINE=$(( $(date +%s) + 180 ))
booted=0
while [ "$(date +%s)" -lt "$BOOT_DEADLINE" ]; do
  kill -0 "$QEMU_PID" 2>/dev/null || { red "qemu exited during boot"; tail -40 "$SERIAL_LOG"; die "VM died before ready"; }
  # strip ANSI, then look for all three milestones.
  plain="$(sed 's/\x1b\[[0-9;]*m//g' "$SERIAL_LOG" 2>/dev/null)"
  if printf '%s' "$plain" | grep -q 'Reached target multi-user.target' \
     && printf '%s' "$plain" | grep -q 'Started ds-attachfwd' \
     && printf '%s' "$plain" | grep -q 'Started ds-entrypoint'; then
    booted=1
    break
  fi
  sleep 2
done
[ "$booted" = 1 ] || { red "VM did not reach the attach-ready milestones within timeout"; tail -50 "$SERIAL_LOG" | sed 's/\x1b\[[0-9;]*m//g'; die "boot timeout"; }
grn "VM booted: multi-user + ds-attachfwd + ds-entrypoint up (CC launching)"
# brief settle so CC has emitted its init record onto the carriage.
sleep 4

# ───────────────── host serving child: ds-hostbridge --serve-uds ────────────
step "build + start ds-hostbridge serving child (UDS ↔ AF_VSOCK $GUEST_CID:$GUEST_VSOCK_PORT)"
( cd "$REPO/client" && go build -o "$HOSTBRIDGE_BIN" ./cmd/ds-hostbridge ) || die "ds-hostbridge build failed"
rm -f "$UDS" 2>/dev/null || true
"$HOSTBRIDGE_BIN" \
  --serve-uds "$UDS" \
  --guest-vsock-cid "$GUEST_CID" \
  --guest-vsock-port "$GUEST_VSOCK_PORT" \
  --session-uuid "$SESSION_UUID" \
  --session-token-file "$TOKEN_FILE" \
  >"$HOSTBRIDGE_LOG" 2>&1 &
HB_PID=$!

# wait for the serving child to bind the UDS (it dials the guest carriage first,
# with up to 30s retry, then serves the UDS).
step "wait for the writer-seat UDS to be served"
UDS_DEADLINE=$(( $(date +%s) + 45 ))
uds_up=0
while [ "$(date +%s)" -lt "$UDS_DEADLINE" ]; do
  if ! kill -0 "$HB_PID" 2>/dev/null; then
    red "ds-hostbridge exited before serving the UDS:"; cat "$HOSTBRIDGE_LOG"; die "serving child failed"
  fi
  [ -S "$UDS" ] && { uds_up=1; break; }
  sleep 1
done
[ "$uds_up" = 1 ] || { red "UDS never appeared:"; cat "$HOSTBRIDGE_LOG"; die "serving child did not bind the UDS"; }
grn "writer-seat UDS served at $UDS"

# ───────────────── drive real CC over attach.v1 (committed KVM-tier test) ───
# TestScriptedDriveKVMVMSideEffectReal: drives the committed proof.jsonl over the
# SAME DriveScriptScenario the podman tier uses, against the REAL CC in the VM,
# answering the tool ask on the attach.v1 grant path. DS_KVM_LIVE_WORK points at
# the host side of the guest /work share so the test also asserts the VM-side
# proof file directly.
step "DRIVE real Claude Code over attach.v1 (DS_KVM_LIVE goldentrace KVM-tier test)"
set +e
( cd "$REPO/client" && \
  DS_KVM_LIVE=1 \
  DS_KVM_LIVE_ATTACH_UDS="$UDS" \
  DS_KVM_LIVE_SESSION="$SESSION_UUID" \
  DS_KVM_LIVE_TOKEN="$ATTACH_TOKEN_HEX" \
  DS_KVM_LIVE_WORK="$WORKDIR" \
  go test ./goldentrace/e2e -run '^TestScriptedDriveKVMVMSideEffectReal$' -v -count=1 -timeout 6m \
) >"$TEST_LOG" 2>&1
TEST_RC=$?
set +e   # keep going through the RESULTS section regardless of grep exit codes

echo "----- go test output (tail) -----"
sed 's/\x1b\[[0-9;]*m//g' "$TEST_LOG" | tail -40
echo "---------------------------------"

# ───────────────── read back the VM-side proof from the share ──────────────
step "VM-side tool-execution proof (read back from the guest /work share)"
PROOF_PATH="$WORKDIR/$PROOF_FILE"
PROOF_OK=0
if [ -f "$PROOF_PATH" ]; then
  PROOF_CONTENT="$(cat "$PROOF_PATH" 2>/dev/null)"
  if printf '%s' "$PROOF_CONTENT" | grep -q "$PROOF_TOKEN"; then
    PROOF_OK=1
  fi
fi

# ───────────────── print results + verdict ──────────────────────────────────
step "RESULTS"
echo "• Committed test: TestScriptedDriveKVMVMSideEffectReal"
# What the test asserted, straight from its own log: the projected attach.v1
# event count (CC's real turn, projected over the per-session writer-seat) and
# the VM-side-effect proof line.
grep -aE 'projected [0-9]+ attach.v1 events|VM-side effect proven' "$TEST_LOG" 2>/dev/null \
  | sed 's/\x1b\[[0-9;]*m//g' | sed -E 's/^[[:space:]]*script_test\.go:[0-9]+:[[:space:]]*/    /' || true
# CC's REAL response text: the assistant chat content CC streamed this turn, read
# back from the host-bridged raw stream-json (best-effort; the result event proves
# the turn completed). CC's stdout rides the vsock carriage → ds-hostbridge.
CC_TEXT="$(grep -aoE '"text":"[^"]*"' "$HOSTBRIDGE_LOG" 2>/dev/null | head -3 | sed 's/^/    CC said: /')" || true
[ -n "$CC_TEXT" ] && printf '%s\n' "$CC_TEXT"

echo "• VM-side proof file: $PROOF_PATH"
if [ "$PROOF_OK" = 1 ]; then
  echo "    content: $PROOF_CONTENT"
  echo "    contains expected token '$PROOF_TOKEN': YES"
else
  echo "    content: ${PROOF_CONTENT:-<absent>}"
  echo "    contains expected token '$PROOF_TOKEN': NO"
fi

echo
if [ "$TEST_RC" -eq 0 ] && [ "$PROOF_OK" = 1 ]; then
  grn "GREEN: real Claude Code completed a turn driven over attach.v1 inside a rootless KVM VM,"
  grn "       the committed KVM-tier test PASSED, and the VM-side tool-execution proof verified."
  FINAL_RC=0
else
  red "NOT GREEN: test_rc=$TEST_RC proof_ok=$PROOF_OK"
  red "  see logs: $TEST_LOG | $HOSTBRIDGE_LOG | $SERIAL_LOG"
  FINAL_RC=1
fi
# cleanup runs on the EXIT trap; exit with the verdict code.
exit "$FINAL_RC"
