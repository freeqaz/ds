#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ds-genisoimage-podman.sh — a drop-in `genisoimage` that runs the REAL genisoimage
# inside a throwaway rootless podman container (debian:bookworm), for a host that has
# no genisoimage/mkisofs/xorriso on PATH and no sudo to install one. It is the proven
# manual config-drive workaround (ds-test-cc-drive.sh) packaged as the host-agent's
# DS_HOSTAGENT_GENISOIMAGE_BIN, so the host-agent's create choreography builds the
# per-session config-drive ISO unchanged.
#
# The host-agent calls:  genisoimage -output <ISO> -volid <L> -input-charset utf-8 \
#                          -rational-rock -joliet <STAGING_DIR>
# Both <ISO> and <STAGING_DIR> are absolute host paths under the overlay dir. We mount
# the overlay-dir tree so those exact absolute paths resolve inside the container, and
# pass every arg through verbatim. The image is cached after the first pull.
set -euo pipefail

IMAGE="${DS_GENISO_PODMAN_IMAGE:-localhost/ds-geniso:bookworm}"
BASE="${DS_GENISO_PODMAN_BASE:-docker.io/library/debian:bookworm}"

# Build a tiny image WITH genisoimage once (cached); fall back to apt-in-container if the
# build image is absent. Quiet — only the genisoimage stdout/exit matters to the caller.
ensure_image() {
  if podman image exists "$IMAGE" 2>/dev/null; then return 0; fi
  local cdir; cdir="$(mktemp -d "${HOME}/tmp/ds-geniso-build.XXXXXX")"
  cat > "$cdir/Containerfile" <<EOF
FROM $BASE
RUN apt-get update -qq && apt-get install -y -qq genisoimage && rm -rf /var/lib/apt/lists/*
EOF
  podman build -q -t "$IMAGE" "$cdir" >/dev/null 2>&1 || return 1
  rm -rf "$cdir"
}

# Mount roots: the overlay dir holds both the output ISO and the staging dir. Mount the
# user's ~/tmp tree (the scratch root) read-write so every absolute path the host-agent
# hands us resolves identically inside the container.
MOUNT_ROOT="${DS_GENISO_MOUNT_ROOT:-$HOME/tmp}"

if ! ensure_image; then
  # Fallback: run on the base image, installing genisoimage inline (slower, no cache).
  exec podman run --rm --network=none \
    -v "$MOUNT_ROOT:$MOUNT_ROOT" \
    "$BASE" \
    bash -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq genisoimage >/dev/null 2>&1 && exec genisoimage "$@"' _ "$@"
fi

exec podman run --rm --network=none \
  -v "$MOUNT_ROOT:$MOUNT_ROOT" \
  "$IMAGE" \
  genisoimage "$@"
