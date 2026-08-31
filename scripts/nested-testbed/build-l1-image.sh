#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# build-l1-image.sh — rootlessly bake the L1 outer-VM image for the nested NFT testbed.
#
# Reuses the proven M0 pipeline (podman -> mke2fs -d -> extract kernel/initrd for
# direct-kernel qemu boot). Output under ~/tmp/ds-images/:
#   l1-base.raw      ext4 rootfs, LABEL=DS_L1ROOT (sparse, ~30G virtual)
#   l1-vmlinuz       the Debian generic kernel (carries kvm_amd + vhost_vsock)
#   l1-initrd.img    the matching initrd
# Boot it with scripts/nested-testbed/boot-l1.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES="${DS_IMAGES_DIR:-$HOME/tmp/ds-images}"
BUILD="${DS_L1_BUILD_DIR:-$HOME/tmp/ds-l1-build}"
CTX="$BUILD/context"
ROOTFS="$BUILD/rootfs"
TAG="${DS_L1_IMAGE_TAG:-localhost/ds-l1:latest}"
RAW="$IMAGES/l1-base.raw"
DISK_SIZE="${DS_L1_DISK_SIZE:-30G}"
CA="${DS_MITM_CA:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"
PUBKEY="${DS_SSH_PUBKEY:-$HOME/.ssh/id_ed25519.pub}"

say() { printf '\033[1;36m[build-l1] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[build-l1][FATAL] %s\033[0m\n' "$*" >&2; exit 1; }

[ -r "$PUBKEY" ] || die "ssh pubkey not readable: $PUBKEY (gen one or set DS_SSH_PUBKEY)"
command -v podman >/dev/null || die "podman not found"
command -v mke2fs >/dev/null || die "mke2fs (e2fsprogs) not found"

mkdir -p "$IMAGES" "$CTX" "$ROOTFS"

say "stage build context at $CTX"
cp "$SCRIPT_DIR/l1.Containerfile" "$CTX/Containerfile"
# egress: a host with a local TLS-intercepting gateway (CA present) → trust it + route
# apt through the proxy. A CI runner with direct internet has no CA → empty placeholder,
# no proxy.
if [ -r "$CA" ]; then
  cp "$CA" "$CTX/egress-ca.crt"; PROXY="${DS_BUILD_PROXY:-http://127.0.0.1:18080}"
  say "egress gateway detected (CA at $CA) — proxied build"
else
  : > "$CTX/egress-ca.crt"; PROXY="${DS_BUILD_PROXY:-}"
  say "no egress CA — direct-internet build (CI runner)"
fi
# Bake a shared testbed keypair so any instance can ssh any other (L1 -> nested L2 over
# the routed tap; both run THIS image). The private key never leaves the local disposable
# testbed. authorized_keys = the operator's host key (host -> L1) + the testbed key (L1 -> L2).
TBKEY="$BUILD/testbed_key"
[ -f "$TBKEY" ] || ssh-keygen -q -t ed25519 -N '' -C ds-nested-testbed -f "$TBKEY"
cat "$PUBKEY" "$TBKEY.pub" > "$CTX/authorized_keys"
cp "$TBKEY" "$CTX/id_ed25519"

say "podman build $TAG (rootless${PROXY:+, via proxy $PROXY})"
PROXY_ARGS=()
[ -n "$PROXY" ] && PROXY_ARGS=(--build-arg "http_proxy=$PROXY" --build-arg "https_proxy=$PROXY" \
                               --build-arg "HTTP_PROXY=$PROXY" --build-arg "HTTPS_PROXY=$PROXY")
podman build --network=host "${PROXY_ARGS[@]}" -t "$TAG" "$CTX"

say "export rootfs to tarball"
cid="$(podman create "$TAG")"
podman export "$cid" > "$BUILD/rootfs.tar"
podman rm "$cid" >/dev/null

# CRITICAL: extract + mke2fs INSIDE `podman unshare` (the rootless user namespace).
# Otherwise `tar -x` runs as the host user (uid 1000) and CANNOT chown to 0, so every
# root-owned file (e.g. /root/.ssh/authorized_keys) lands as uid 1000 — and sshd's
# StrictModes then silently ignores the key (publickey auth fails). In the userns,
# container uid 0 maps correctly, so mke2fs records real root ownership in the image.
say "extract (uid-preserving) + kernel/initrd + mke2fs -d, inside podman userns"
podman unshare bash -euc '
  ROOTFS="$1"; TAR="$2"; IMAGES="$3"; RAW="$4"; SIZE="$5"
  rm -rf "$ROOTFS"; mkdir -p "$ROOTFS"
  tar -C "$ROOTFS" --numeric-owner -xpf "$TAR"
  k="$(ls "$ROOTFS"/boot/vmlinuz-* 2>/dev/null | head -1)"
  i="$(ls "$ROOTFS"/boot/initrd.img-* 2>/dev/null | head -1)"
  [ -n "$k" ] && [ -n "$i" ] || { echo "no vmlinuz/initrd in rootfs /boot"; exit 1; }
  cp "$k" "$IMAGES/l1-vmlinuz"; cp "$i" "$IMAGES/l1-initrd.img"
  echo "  kernel: $(basename "$k")  initrd: $(basename "$i")"
  rm -f "$RAW"
  mke2fs -q -t ext4 -L DS_L1ROOT -d "$ROOTFS" "$RAW" "$SIZE"
  rm -rf "$ROOTFS"
' _ "$ROOTFS" "$BUILD/rootfs.tar" "$IMAGES" "$RAW" "$DISK_SIZE"
rm -f "$BUILD/rootfs.tar"

say "DONE. Artifacts:"
ls -lh "$IMAGES/l1-base.raw" "$IMAGES/l1-vmlinuz" "$IMAGES/l1-initrd.img"
say "boot with: scripts/nested-testbed/boot-l1.sh up"
