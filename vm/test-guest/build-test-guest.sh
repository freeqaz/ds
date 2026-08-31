#!/usr/bin/env bash
# build-test-guest.sh — reproducibly produce the LOCAL test-guest fixture for the
# sudo-free qemu rig (vm/test-guest/). This is a LIGHTWEIGHT TEST FIXTURE, NOT the
# heavyweight images/golden/ M0 session image — see test-guest.env header and
# IMAGE-IDENTITY.md.
#
# What "build" means here:
#   1. FETCH the pinned Alpine "nocloud" cloud qcow2 (version from test-guest.env)
#      with `curl --noproxy '*'` (a global HTTPS_PROXY=:18080 breaks non-API
#      egress, so the image fetch always bypasses the proxy).
#   2. VERIFY it: sha256 against the TG_IMAGE_SHA256 pin (THE contract), and —
#      when the vendor `.sha512` sidecar is reachable — against TG_IMAGE_SHA512
#      too. A mismatch is a fail-closed build error; the blob is never trusted on
#      size alone.
#   3. GENERATE a NoCloud cloud-init seed ISO (meta-data / user-data /
#      network-config) for the requested mode:
#        --smoke  (default): DHCP on the NIC (qemu user-net / slirp), autologin,
#                            self-asserting curl-out — what boot-test-guest.sh
#                            --smoke boots.
#        --tap             : static 10.77.0.2/24 gw/DNS 10.77.0.1 (doc 13) for the
#                            dstap-0 attach — the SEPARATE §E2 task.
#      Real tools are preferred when present (genisoimage / xorriso / mkisofs /
#      cloud-localds); otherwise the bundled stdlib writer mkseed.py is used (the
#      sudo-free sandbox has no ISO tooling). Either way the ISO carries the
#      `cidata` volume label cloud-init's NoCloud datasource keys on.
#
# The COMMITTED artifact is THIS BUILDER + the seed inputs it generates + the
# scripts/tests/docs — NEVER the qcow2 or the seed ISO (both live under
# $TG_ARTIFACT_DIR = ~/tmp/ds-test-guest, btrfs/CoW; see .gitignore).
#
# Modes:
#   vm/test-guest/build-test-guest.sh                 # == --smoke (fetch+verify+seed)
#   vm/test-guest/build-test-guest.sh --smoke         # user-net DHCP smoke seed
#   vm/test-guest/build-test-guest.sh --tap           # static dstap-0 seed
#   vm/test-guest/build-test-guest.sh --plan          # print the plan, verify PINS only (no download)
#   vm/test-guest/build-test-guest.sh --self-test     # offline: seed-gen + pin sanity, no network
#   vm/test-guest/build-test-guest.sh --seed-only ... # (re)generate just the seed ISO
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${HERE}/test-guest.env"

ARTIFACT_DIR="${TG_ARTIFACT_DIR}"
IMG_PATH="${ARTIFACT_DIR}/${TG_IMAGE_NAME}"
SEED_PATH="${ARTIFACT_DIR}/seed-test-guest.iso"

log()  { printf 'build-test-guest: %s\n' "$*"; }
step() { printf '\n=== STEP: %s ===\n' "$*"; }
die()  { printf 'build-test-guest: ERROR: %s\n' "$*" >&2; exit 1; }

MODE="--smoke"
SEED_MODE="smoke"
case "${1:-}" in
  ""|--smoke)   MODE="--smoke";   SEED_MODE="smoke" ;;
  --tap)        MODE="--tap";     SEED_MODE="tap" ;;
  --plan)       MODE="--plan" ;;
  --self-test)  MODE="--self-test" ;;
  --seed-only)  MODE="--seed-only"; SEED_MODE="${2:-smoke}" ;;
  *) die "usage: $0 [--smoke|--tap|--plan|--self-test|--seed-only <smoke|tap>]" ;;
esac

# --- seed input authoring -----------------------------------------------------
# Render the three NoCloud files into $1 (a dir) for SEED_MODE ($2). The static
# (tap) network-config applies the doc 13 addressing; the smoke one uses DHCP so
# qemu user-net (slirp) provides a working gateway/DNS for the curl-out assert.
render_seed_inputs() {
  local dir="$1" mode="$2"
  mkdir -p "$dir"

  cat > "${dir}/meta-data" <<EOF
instance-id: ds-test-guest-${mode}
local-hostname: ds-test-guest
EOF

  if [ "$mode" = "tap" ]; then
    cat > "${dir}/network-config" <<EOF
version: 2
ethernets:
  eth0:
    match:
      name: "e*"
    dhcp4: false
    addresses:
      - ${TG_GUEST_IP}/${TG_GUEST_CIDR}
    routes:
      - to: default
        via: ${TG_GUEST_GATEWAY}
    nameservers:
      addresses: [${TG_GUEST_DNS}]
EOF
  else
    cat > "${dir}/network-config" <<EOF
version: 2
ethernets:
  eth0:
    match:
      name: "e*"
    dhcp4: true
EOF
  fi

  # user-data: set a known root password + autologin posture, ensure curl, and
  # (smoke mode) run a self-asserting curl-out that prints sentinels to the
  # serial console then powers off so the boot harness exits on its own.
  {
    echo "#cloud-config"
    echo "ssh_pwauth: true"
    echo "disable_root: false"
    echo "chpasswd:"
    echo "  expire: false"
    echo "  list:"
    echo "    - root:ds"
    echo "runcmd:"
    echo "  - [ sh, -c, \"command -v curl >/dev/null 2>&1 || apk add --no-cache curl\" ]"
    if [ "$mode" = "smoke" ]; then
      echo "  - [ sh, -c, \"echo '===DS-SMOKE-BEGIN===' >/dev/console\" ]"
      echo "  - [ sh, -c, \"if command -v curl >/dev/null 2>&1; then echo 'DS-SMOKE-CURL-PRESENT' >/dev/console; else echo 'DS-SMOKE-CURL-MISSING' >/dev/console; fi\" ]"
      echo "  - [ sh, -c, \"curl -fsS --max-time 25 -o /dev/null -w 'DS-SMOKE-HTTP-%{http_code}\\\\n' ${TG_SMOKE_URL} >/dev/console 2>/dev/console || echo 'DS-SMOKE-CURL-EGRESS-FAIL' >/dev/console\" ]"
      echo "  - [ sh, -c, \"echo '===DS-SMOKE-END===' >/dev/console\" ]"
      echo "  - [ sh, -c, \"poweroff\" ]"
    fi
  } > "${dir}/user-data"
}

# Build the seed ISO from a rendered input dir into $2. Prefer a real ISO tool;
# fall back to the bundled stdlib writer. The label MUST be `cidata` (NoCloud).
make_seed_iso() {
  local in_dir="$1" out_iso="$2"
  rm -f "$out_iso"
  if command -v cloud-localds >/dev/null 2>&1; then
    log "seed: cloud-localds"
    cloud-localds -N "${in_dir}/network-config" "$out_iso" \
      "${in_dir}/user-data" "${in_dir}/meta-data"
  elif command -v genisoimage >/dev/null 2>&1; then
    log "seed: genisoimage"
    genisoimage -quiet -output "$out_iso" -volid cidata -joliet -rock \
      "${in_dir}/meta-data" "${in_dir}/user-data" "${in_dir}/network-config"
  elif command -v xorrisofs >/dev/null 2>&1; then
    log "seed: xorrisofs"
    xorrisofs -quiet -output "$out_iso" -volid cidata -joliet -rock \
      "${in_dir}/meta-data" "${in_dir}/user-data" "${in_dir}/network-config"
  elif command -v mkisofs >/dev/null 2>&1; then
    log "seed: mkisofs"
    mkisofs -quiet -output "$out_iso" -volid cidata -joliet -rock \
      "${in_dir}/meta-data" "${in_dir}/user-data" "${in_dir}/network-config"
  else
    log "seed: mkseed.py (no ISO tool on PATH — stdlib fallback)"
    python3 "${HERE}/mkseed.py" "$out_iso" \
      "meta-data=${in_dir}/meta-data" \
      "user-data=${in_dir}/user-data" \
      "network-config=${in_dir}/network-config"
  fi
  [ -s "$out_iso" ] || die "seed ISO was not produced at $out_iso"
}

# --- integrity ----------------------------------------------------------------
verify_sha256() {
  local f="$1" want="$2" got
  got="$(sha256sum "$f" | awk '{print $1}')"
  [ "$got" = "$want" ] || die "sha256 mismatch for $f
  want: $want
  got:  $got"
  log "sha256 OK ($want)"
}

verify_published_sha512() {
  # Best-effort: fetch the vendor `.sha512` sidecar and verify against it. A
  # network failure here is non-fatal (the sha256 pin is the contract); a
  # CONTENT mismatch is fatal.
  local f="$1" url="${TG_IMAGE_BASE_URL}/${TG_IMAGE_NAME}.sha512" side got want
  side="$(mktemp)"
  if curl --noproxy '*' -fsSL --max-time 30 -o "$side" "$url" 2>/dev/null; then
    want="$(awk '{print $1}' "$side" | head -1)"
    got="$(sha512sum "$f" | awk '{print $1}')"
    rm -f "$side"
    [ -n "$want" ] || { log "sha512 sidecar empty — skipping vendor check"; return 0; }
    [ "$got" = "$want" ] || die "vendor sha512 mismatch for $f (want $want got $got)"
    log "vendor sha512 OK (chains to Alpine published sidecar)"
  else
    rm -f "$side"
    log "sha512 sidecar unreachable — relying on the pinned sha256 (offline-OK)"
  fi
}

# --- validate pins (no privileges, no network) --------------------------------
validate_pins() {
  step "validate pins (no privileges, no network)"
  local ok=1
  [ -n "${TG_ALPINE_VERSION:-}" ] || { echo "  MISSING TG_ALPINE_VERSION" >&2; ok=0; }
  [ -n "${TG_IMAGE_NAME:-}" ]     || { echo "  MISSING TG_IMAGE_NAME" >&2; ok=0; }
  [ -n "${TG_IMAGE_BASE_URL:-}" ] || { echo "  MISSING TG_IMAGE_BASE_URL" >&2; ok=0; }
  case "${TG_IMAGE_SHA256:-}" in
    [0-9a-f]*) [ "${#TG_IMAGE_SHA256}" = 64 ] || { echo "  TG_IMAGE_SHA256 not 64 hex chars" >&2; ok=0; } ;;
    *) echo "  MISSING/!hex TG_IMAGE_SHA256" >&2; ok=0 ;;
  esac
  # The pinned image name must agree with the pinned version+arch+flavor — a
  # cheap guard against a half-edited pin bump.
  local expect="nocloud_alpine-${TG_ALPINE_VERSION}-${TG_ALPINE_ARCH}-${TG_ALPINE_FLAVOR}.qcow2"
  [ "${TG_IMAGE_NAME}" = "$expect" ] \
    || { echo "  PIN DRIFT: TG_IMAGE_NAME ($TG_IMAGE_NAME) != derived ($expect)" >&2; ok=0; }
  # The image fetch must use the proxy bypass.
  [ -n "${TG_SMOKE_URL:-}" ] || { echo "  MISSING TG_SMOKE_URL" >&2; ok=0; }
  [ "$ok" = 1 ] && log "pins OK" || die "pin validation FAILED"
}

# Validate a rendered seed is well-formed (used by --self-test): smoke carries
# the self-assert + poweroff; tap carries the static doc-13 addressing.
validate_seed_inputs() {
  local dir="$1" mode="$2" ok=1
  grep -q '^instance-id:' "${dir}/meta-data" || { echo "  seed meta-data missing instance-id" >&2; ok=0; }
  head -1 "${dir}/user-data" | grep -q '^#cloud-config' || { echo "  seed user-data not #cloud-config" >&2; ok=0; }
  grep -q 'command -v curl' "${dir}/user-data" || { echo "  seed does not ensure curl" >&2; ok=0; }
  if [ "$mode" = "tap" ]; then
    grep -q "${TG_GUEST_IP}/${TG_GUEST_CIDR}" "${dir}/network-config" || { echo "  tap seed missing static ${TG_GUEST_IP}/${TG_GUEST_CIDR}" >&2; ok=0; }
    grep -q "via: ${TG_GUEST_GATEWAY}" "${dir}/network-config" || { echo "  tap seed missing gateway ${TG_GUEST_GATEWAY}" >&2; ok=0; }
    grep -q "${TG_GUEST_DNS}" "${dir}/network-config" || { echo "  tap seed missing DNS ${TG_GUEST_DNS}" >&2; ok=0; }
    grep -q 'DS-SMOKE-BEGIN' "${dir}/user-data" && { echo "  tap seed must NOT auto-poweroff (it is for the live dstap attach)" >&2; ok=0; }
  else
    grep -q 'dhcp4: true' "${dir}/network-config" || { echo "  smoke seed should DHCP on user-net" >&2; ok=0; }
    grep -q 'DS-SMOKE-HTTP' "${dir}/user-data" || { echo "  smoke seed missing curl-out self-assert" >&2; ok=0; }
    grep -q 'poweroff' "${dir}/user-data" || { echo "  smoke seed missing poweroff (harness would hang)" >&2; ok=0; }
  fi
  [ "$ok" = 1 ]
}

print_plan() {
  cat <<EOF
test-guest build plan (pins from test-guest.env):

  base image     : ${TG_IMAGE_NAME}
  version / arch : Alpine ${TG_ALPINE_VERSION} / ${TG_ALPINE_ARCH} (${TG_ALPINE_FLAVOR})
  fetch url      : ${TG_IMAGE_BASE_URL}/${TG_IMAGE_NAME}
  fetch          : curl --noproxy '*'  (HTTPS_PROXY=:18080 breaks non-API egress)
  sha256 pin     : ${TG_IMAGE_SHA256}   (THE verified contract)
  sha512 (vendor): ${TG_IMAGE_SHA512}   (checked vs Alpine .sha512 sidecar when reachable)
  seed (smoke)   : DHCP (qemu user-net), autologin, curl-out self-assert + poweroff
  seed (tap)     : static ${TG_GUEST_IP}/${TG_GUEST_CIDR} gw/DNS ${TG_GUEST_GATEWAY} (doc 13) for dstap-0 (§E2)
  artifact dir   : ${ARTIFACT_DIR}   (btrfs/CoW; NEVER committed — see .gitignore)
  image path     : ${IMG_PATH}
  seed path      : ${SEED_PATH}

Seed tool: $(for t in cloud-localds genisoimage xorrisofs mkisofs; do command -v "$t" >/dev/null 2>&1 && { echo "$t"; break; }; done || echo "mkseed.py (stdlib fallback — no ISO tool on PATH)")

Boot it: vm/test-guest/boot-test-guest.sh --smoke   (sudo-free qemu, user-net)
         vm/test-guest/boot-test-guest.sh --tap     (dstap-0 attach — §E2, needs the tap)
EOF
}

# --- self-test: offline seed-gen + pin sanity (no network, no qemu) -----------
do_self_test() {
  step "self-test (offline: pins + seed generation, no network)"
  validate_pins
  local tmp; tmp="$(mktemp -d)"
  # Clean up on return without a script-EXIT trap (which, under `set -u`, would
  # reference an out-of-scope local at the final exit).
  _cleanup_selftest() { rm -rf "$tmp"; }
  local fail=0
  for m in smoke tap; do
    render_seed_inputs "${tmp}/${m}" "$m"
    if validate_seed_inputs "${tmp}/${m}" "$m"; then
      log "seed inputs ($m) OK"
    else
      echo "  seed inputs ($m) FAILED" >&2; fail=1
    fi
    make_seed_iso "${tmp}/${m}" "${tmp}/seed-${m}.iso"
    # The produced image MUST carry the cidata volume label (NoCloud key).
    if grep -qa 'cidata' "${tmp}/seed-${m}.iso"; then
      log "seed ISO ($m) carries the cidata volume label"
    else
      echo "  seed ISO ($m) is MISSING the cidata volume label" >&2; fail=1
    fi
  done
  # Negative case: a half-edited pin (name not matching version) MUST be caught.
  # validate_pins hard-exits (die) on a bad pin, so the subshell exits non-zero
  # exactly when drift is caught; a ZERO exit would be the leak.
  if ( TG_IMAGE_NAME="nocloud_alpine-9.9.9-x86_64-bios-cloudinit-r0.qcow2"
       validate_pins >/dev/null 2>&1 ); then
    echo "  NEGATIVE-CASE LEAK: drifted image name passed validate_pins" >&2
    fail=1
  else
    log "negative case OK (drifted pin rejected)"
  fi
  _cleanup_selftest
  [ "$fail" = 0 ] || die "self-test FAILED"
  log "self-test OK"
}

# --- fetch + verify + seed ----------------------------------------------------
do_build() {
  mkdir -p "$ARTIFACT_DIR"
  validate_pins

  step "fetch pinned base image (curl --noproxy)"
  if [ -f "$IMG_PATH" ] && sha256sum "$IMG_PATH" | awk '{print $1}' | grep -qx "${TG_IMAGE_SHA256}"; then
    log "image already present and sha256-verified — skipping download"
  else
    log "downloading ${TG_IMAGE_NAME} ..."
    curl --noproxy '*' -fSL --max-time 600 --retry 3 --retry-delay 2 \
      -o "$IMG_PATH" "${TG_IMAGE_BASE_URL}/${TG_IMAGE_NAME}" \
      || die "image download failed (try again; the CDN can be flaky)"
  fi

  step "verify integrity"
  verify_sha256 "$IMG_PATH" "${TG_IMAGE_SHA256}"
  verify_published_sha512 "$IMG_PATH"

  step "generate NoCloud seed (${SEED_MODE})"
  local seed_in="${ARTIFACT_DIR}/seed-inputs-${SEED_MODE}"
  render_seed_inputs "$seed_in" "$SEED_MODE"
  make_seed_iso "$seed_in" "$SEED_PATH"
  log "seed ISO: $SEED_PATH"

  step "done"
  log "image : $IMG_PATH"
  log "seed  : $SEED_PATH (mode=${SEED_MODE})"
  log "boot  : vm/test-guest/boot-test-guest.sh --${SEED_MODE}"
}

case "$MODE" in
  --plan)       validate_pins; print_plan ;;
  --self-test)  do_self_test ;;
  --seed-only)
    mkdir -p "$ARTIFACT_DIR"
    validate_pins
    seed_in="${ARTIFACT_DIR}/seed-inputs-${SEED_MODE}"
    render_seed_inputs "$seed_in" "$SEED_MODE"
    make_seed_iso "$seed_in" "$SEED_PATH"
    log "seed-only: $SEED_PATH (mode=${SEED_MODE})" ;;
  --smoke|--tap) do_build ;;
esac
