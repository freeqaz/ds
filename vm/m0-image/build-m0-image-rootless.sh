# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# build-m0-image-rootless.sh — bake the M0 base image 100% ROOTLESSLY (no sudo,
# no debootstrap, no losetup, no chroot), modeled on scripts/nested-testbed/
# build-l1-image.sh's proven rootless flow (podman build a rootfs -> `podman
# unshare` + mke2fs -d to emit the raw -> extract kernel/initrd for direct-kernel
# qemu boot).
#
# WHY a second builder: the canonical recipe vm/m0-image/build-m0-image.sh --build
# is the authoritative content spec, but its bake path needs root (debootstrap +
# losetup + chroot + grub-install). This box has none of that. This script
# reproduces the SAME image CONTENT — the pins, the guest-config units, CC, the
# two guest Go binaries — through the rootless podman pipeline instead, and emits
# a direct-kernel-bootable raw + kernel + initrd (no in-image grub/bootloader; the
# boot harness passes root=LABEL=DS_M0ROOT + the kernel/initrd, exactly like the
# L1/M0 nested-testbed boot).
#
# CONTENT (single-sourced from m0-image.env, expanded EXACTLY as build-m0-image.sh
# does — same expand_* token substitutions):
#   - bookworm glibc base (D11 §3.2/§8.6), systemd-sysv init, ca-certificates (D17
#     trust-store injection point), curl, node ${M0_NODE_MAJOR}, git, ncurses
#     (terminfo for the PTY-mode TERM), iproute2 (ds-apply-netcfg's ip(8) calls).
#   - @anthropic-ai/claude-code@${M0_CC_VERSION} (D49) installed -g, with the
#     /opt/claude-code/bin fallback build-m0-image.sh documents if the global bin
#     symlink is not created.
#   - /usr/local/bin/ds-entrypoint (D38) + /usr/local/bin/ds-attachfwd (gap-3),
#     built here CGO_ENABLED=0 static (run on any glibc/musl guest libc).
#   - /usr/local/bin/ds-apply-netcfg (U4 routed-tap applier — THE thing the on-disk
#     m0-base-*.raw images lack) + its ds-netcfg.service.
#   - guest-config units installed + `systemctl enable`d: ds-entrypoint.service,
#     run-ds-entrypoint.mount, ds-netcfg.service, ds-attachfwd.service,
#     systemd-networkd.service + ds-slirp-net.service (SLIRP DHCP egress — the
#     ds-slirp-dhcp.network staged off networkd's search path, gated off the routed
#     tap); the ds-runtime-dir.conf tmpfiles drop-in; the D75 per-egress-NIC v6
#     sysctl; the D83/§5.3 git-over-HTTPS pin; the CC workspace pre-trust seed + TERM.
#   - net.ifnames=0 + serial console=ttyS0 on the kernel cmdline (passed by the
#     direct-kernel boot, and a serial getty enabled); LABEL=DS_M0ROOT rootfs.
#
# OUTPUT (under ~/tmp/ds-images/, btrfs/CoW; NEVER overwrites the existing
# m0-base-*.raw / m0-vmlinuz / m0-initrd*):
#   m0-base-routed-cc.raw       ext4 rootfs, LABEL=DS_M0ROOT (sparse, 12G virtual)
#   m0-vmlinuz-routed-cc        the Debian generic kernel
#   m0-initrd-routed-cc.img     the matching initrd
#
# 100% ROOTLESS: podman (rootless), `podman unshare` (the rootless user namespace,
# so container uid 0 maps correctly and mke2fs records real root ownership),
# mke2fs -d, qemu-img. No sudo / debootstrap / losetup / chroot anywhere.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${HERE}/m0-image.env"
GUEST_CONFIG="${HERE}/guest-config"
VM_TREE="$(cd "${HERE}/../" && pwd)"   # the vm/ Go module root

# Scratch/output roots: btrfs (CoW), NEVER /tmp (tmpfs/RAM) and NEVER the repo.
IMAGES="${DS_IMAGES_DIR:-${HOME}/tmp/ds-images}"
BUILD="${DS_M0_BUILD_DIR:-${HOME}/tmp/ds-m0-routed-build}"
CTX="${BUILD}/context"
ROOTFS="${BUILD}/rootfs"
TAG="${DS_M0_IMAGE_TAG:-localhost/ds-m0-routed:latest}"

RAW="${IMAGES}/m0-base-routed-cc.raw"
KERNEL_OUT="${IMAGES}/m0-vmlinuz-routed-cc"
INITRD_OUT="${IMAGES}/m0-initrd-routed-cc.img"
DISK_SIZE="${DS_M0_DISK_SIZE:-${M0_DISK_VIRTUAL_SIZE:-12G}}"

# Egress: free-ai-rig fronts outbound HTTPS with a TLS-intercepting mitmproxy
# gateway (CA at ~/.mitmproxy). To let the in-container apt/npm pulls succeed we
# trust that CA inside the build and route through the proxy — exactly what
# build-l1-image.sh does. Direct-internet hosts (no CA) build direct.
CA="${DS_MITM_CA:-${HOME}/.mitmproxy/mitmproxy-ca-cert.pem}"

# The guest 'ds' user's home == the CC working dir the live MVP launches in
# (scripts/live-mvp/ds-serve-stack.sh: -working-dir /home/ds, HOME=/home/ds); the
# pre-trust seed keys CC's per-path trust registry on it (build-m0-image.sh 4b).
WORKDIR="/home/ds"

say() { printf '\033[1;36m[build-m0-rootless] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[build-m0-rootless][FATAL] %s\033[0m\n' "$*" >&2; exit 1; }

command -v podman >/dev/null || die "podman not found (rootless bake needs it)"
command -v mke2fs >/dev/null || die "mke2fs (e2fsprogs) not found"
command -v go     >/dev/null || die "go not found (needed to build the guest binaries)"
[ "$(id -u)" -ne 0 ] || die "run me ROOTLESS (NOT as root / sudo) — the whole point is the unprivileged podman flow"

# ── token expanders: byte-identical to build-m0-image.sh's expand_* helpers ───
expand_ipv6_dropin() {            # per-egress-NIC v6 sysctl (D75)
  local iface="${1:-enp1s0}"
  sed "s/__IFACE__/${iface}/g" "${GUEST_CONFIG}/99-ds-disable-ipv6.conf"
}
expand_entrypoint_unit() {        # D38 ds-entrypoint.service
  sed -e "s|__ENTRYPOINT_PATH__|${M0_ENTRYPOINT_PATH}|g" \
      -e "s|__ENTRYPOINT_CONFIG_DIR__|${M0_ENTRYPOINT_CONFIG_DIR}|g" \
      -e "s|__TOOLCHAIN_PATH__|${M0_GO_PREFIX}/bin:${M0_RUST_PREFIX}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|g" \
      "${GUEST_CONFIG}/ds-entrypoint.service"
}
expand_configdrive_mount() {      # gap-1 run-ds-entrypoint.mount
  sed -e "s|__ENTRYPOINT_CONFIG_DIR__|${M0_ENTRYPOINT_CONFIG_DIR}|g" \
      -e "s|__CONFIG_DRIVE_LABEL__|${M0_CONFIG_DRIVE_LABEL}|g" \
      -e "s|__CONFIG_DRIVE_FS__|${M0_CONFIG_DRIVE_FS}|g" \
      "${GUEST_CONFIG}/run-ds-entrypoint.mount"
}
expand_workspace_mount() {        # dogfood work.mount (per-session workspace disk)
  sed -e "s|__WORKSPACE_LABEL__|${M0_WORKSPACE_LABEL}|g" \
      -e "s|__WORKSPACE_DIR__|${M0_WORKSPACE_DIR}|g" \
      -e "s|__WORKSPACE_FS__|${M0_WORKSPACE_FS}|g" \
      "${GUEST_CONFIG}/work.mount"
}
expand_attachfwd_unit() {         # gap-3 ds-attachfwd.service
  sed -e "s|__ATTACHFWD_PATH__|${M0_ATTACHFWD_PATH}|g" \
      -e "s|__ATTACHFWD_UDS_PATH__|${M0_ATTACHFWD_UDS_PATH}|g" \
      -e "s|__ATTACH_PORT__|${M0_ATTACH_PORT}|g" \
      "${GUEST_CONFIG}/ds-attachfwd.service"
}
expand_netcfg_script() {          # U4 ds-apply-netcfg.sh
  sed -e "s|__ENTRYPOINT_CONFIG_DIR__|${M0_ENTRYPOINT_CONFIG_DIR}|g" \
      -e "s|__EGRESS_NIC_GLOB__|${M0_EGRESS_NIC_GLOB}|g" \
      -e "s|__NETCFG_FILE__|${M0_NETCFG_FILE}|g" \
      "${GUEST_CONFIG}/ds-apply-netcfg.sh"
}
expand_netcfg_unit() {            # U4 ds-netcfg.service
  sed -e "s|__NETCFG_SCRIPT_PATH__|${M0_NETCFG_SCRIPT_PATH}|g" \
      "${GUEST_CONFIG}/ds-netcfg.service"
}
expand_slirp_network() {          # SLIRP DHCP .network (staged off networkd's search path)
  sed -e "s|__EGRESS_NIC_GLOB__|${M0_EGRESS_NIC_GLOB}|g" \
      "${GUEST_CONFIG}/ds-slirp-dhcp.network"
}
expand_slirp_net_unit() {         # SLIRP DHCP installer, gated off the routed tap
  sed -e "s|__SLIRP_NETWORK_STAGE__|${M0_SLIRP_NETWORK_STAGE}|g" \
      -e "s|__ENTRYPOINT_CONFIG_DIR__|${M0_ENTRYPOINT_CONFIG_DIR}|g" \
      -e "s|__NETCFG_FILE__|${M0_NETCFG_FILE}|g" \
      "${GUEST_CONFIG}/ds-slirp-net.service"
}

# terminfo subpath (ncurses-on-Debian layout): xterm-256color -> x/xterm-256color
terminfo_subpath() { local t="${1:-$M0_PTY_TERM}"; printf '%s/%s' "${t:0:1}" "${t}"; }

# ── stage the build context ───────────────────────────────────────────────────
rm -rf "${BUILD}"
mkdir -p "${IMAGES}" "${CTX}" "${ROOTFS}"

say "stage build context at ${CTX}"

# Expanded guest-config artifacts (same bytes build-m0-image.sh installs).
expand_ipv6_dropin enp1s0          > "${CTX}/99-ds-disable-ipv6.conf"
expand_entrypoint_unit             > "${CTX}/ds-entrypoint.service"
expand_configdrive_mount           > "${CTX}/run-ds-entrypoint.mount"
# The workspace mount unit's FILE NAME must be the systemd-escaped mount point, or
# systemd rejects it at boot. Derive it rather than hard-coding `work.mount`, and
# assert the checked-in source file matches, so moving M0_WORKSPACE_DIR can never
# ship an image whose workspace silently never mounts.
WORKSPACE_UNIT="$(systemd-escape -p --suffix=mount "${M0_WORKSPACE_DIR}")"
if [ "${WORKSPACE_UNIT}" != "work.mount" ]; then
  die "M0_WORKSPACE_DIR=${M0_WORKSPACE_DIR} escapes to '${WORKSPACE_UNIT}', but the checked-in unit is guest-config/work.mount — rename the source file to match (systemd rejects a mount unit whose name is not its escaped path)."
fi
expand_workspace_mount             > "${CTX}/${WORKSPACE_UNIT}"
expand_attachfwd_unit              > "${CTX}/ds-attachfwd.service"
expand_netcfg_script               > "${CTX}/ds-apply-netcfg"        # -> M0_NETCFG_SCRIPT_PATH
expand_netcfg_unit                 > "${CTX}/ds-netcfg.service"
expand_slirp_network               > "${CTX}/ds-slirp-dhcp.network"  # -> M0_SLIRP_NETWORK_STAGE (staged, non-search)
expand_slirp_net_unit              > "${CTX}/ds-slirp-net.service"
cp "${GUEST_CONFIG}/ds-runtime-dir.conf"      "${CTX}/ds-runtime-dir.conf"
cp "${GUEST_CONFIG}/git-https-pin.gitconfig"  "${CTX}/gitconfig"

# CC workspace pre-trust seed (build-m0-image.sh step 4b): a UX latch, no credential.
# BOTH roots are seeded: ${WORKDIR} (the historical home-dir cwd) and
# ${M0_WORKSPACE_DIR} (the dogfood workspace disk mount point). CC keys its trust
# registry on the cwd it is launched in, so a session launched with
# WorkingDir=${M0_WORKSPACE_DIR} would otherwise stall on a first-run trust dialog
# that a HEADLESS seat drive has no way to answer — the turn just hangs. Seeding is
# a UX latch only: it grants no capability and carries no credential, and the real
# containment is the boundary, not a dialog the agent is asked to click through.
cat > "${CTX}/ds-dot-claude.json" <<EOF
{
  "${WORKDIR}": {
    "hasTrustDialogAccepted": true,
    "hasCompletedProjectOnboarding": true,
    "projectOnboardingSeenCount": 1
  },
  "${M0_WORKSPACE_DIR}": {
    "hasTrustDialogAccepted": true,
    "hasCompletedProjectOnboarding": true,
    "projectOnboardingSeenCount": 1
  }
}
EOF

# Build the two guest Go binaries STATIC (CGO_ENABLED=0) — same as
# build-m0-image.sh's bake_install_guest_bin — and drop them in the context.
say "build guest binaries (CGO_ENABLED=0 static, linux/amd64)"
( cd "${VM_TREE}" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -o "${CTX}/ds-entrypoint" ./entrypoint/cmd/ds-entrypoint )
( cd "${VM_TREE}" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -o "${CTX}/ds-attachfwd"  ./attachfwd/cmd/ds-attachfwd )
say "  staged ds-entrypoint + ds-attachfwd"

# Egress CA / proxy (mirror build-l1-image.sh).
if [ -r "${CA}" ]; then
  cp "${CA}" "${CTX}/egress-ca.crt"; PROXY="${DS_BUILD_PROXY:-http://127.0.0.1:18080}"
  say "egress gateway detected (CA at ${CA}) — proxied, CA-trusted build"
else
  : > "${CTX}/egress-ca.crt"; PROXY="${DS_BUILD_PROXY:-}"
  say "no egress CA — direct-internet build"
fi

# Posture-(b) interception CA (additive, testbed). Bake a TLS-3 interception CA cert into the
# guest at /etc/ds/intercept-ca.crt so an in-VM CC launched with
# NODE_EXTRA_CA_CERTS=/etc/ds/intercept-ca.crt trusts ds-tlsproxy's terminated TLS (the
# cred-swap posture-b proof). This is the GUEST-trust half; ds-tlsproxy signs leaves with the
# SAME CA via DS_TLSPROXY_SESSION_CA_CERT/KEY. Default (DS_M0_INTERCEPT_CA_CERT unset) → an
# empty file → the Containerfile's `[ -s ]` guard skips it → byte-identical image. The cert is
# a public CA cert (never the key); D50 — never bake/commit a private key.
if [ -n "${DS_M0_INTERCEPT_CA_CERT:-}" ] && [ -r "${DS_M0_INTERCEPT_CA_CERT}" ]; then
  cp "${DS_M0_INTERCEPT_CA_CERT}" "${CTX}/intercept-ca.crt"
  say "posture-b: baking interception CA ${DS_M0_INTERCEPT_CA_CERT} -> guest /etc/ds/intercept-ca.crt"
else
  : > "${CTX}/intercept-ca.crt"
fi

# Terminfo subpath the bake asserts (build-m0-image.sh step 4a) — emitted into the
# Containerfile so the in-container assertion fails the build if absent.
TISUB="$(terminfo_subpath "${M0_PTY_TERM}")"

# ── the Containerfile (kept INLINE so this script is the only new repo file) ───
# Mirrors build-m0-image.sh's content steps 1-7 + the systemctl enables; the raw
# + kernel/initrd emission (its step 8) is replaced by the rootless mke2fs path.
cat > "${CTX}/Containerfile" <<CFEOF
# SPDX-License-Identifier: Apache-2.0
# Generated by build-m0-image-rootless.sh — the rootless M0 base rootfs.
FROM ${M0_BASE_DISTRO}:${M0_BASE_SUITE}

COPY egress-ca.crt /tmp/egress-ca.crt
COPY intercept-ca.crt /tmp/intercept-ca.crt
# Posture-(b) interception CA (additive, testbed): place the staged TLS-3 interception CA at
# the guest path NODE_EXTRA_CA_CERTS points at (/etc/ds/intercept-ca.crt). Empty file
# (DS_M0_INTERCEPT_CA_CERT unset at bake) -> skipped -> byte-identical image.
RUN set -eux; \\
    if [ -s /tmp/intercept-ca.crt ]; then \\
      mkdir -p /etc/ds; \\
      cp /tmp/intercept-ca.crt /etc/ds/intercept-ca.crt; \\
      chmod 0644 /etc/ds/intercept-ca.crt; \\
      echo "posture-b interception CA baked at /etc/ds/intercept-ca.crt"; fi
ARG http_proxy=
ARG https_proxy=
ARG HTTP_PROXY=
ARG HTTPS_PROXY=
ENV DEBIAN_FRONTEND=noninteractive

# --- step 1 + 7: glibc base userland + D17 trust store + runtime deps ----------
#   systemd-sysv     -> /sbin/init = systemd (PID 1), the entrypoint unit's init
#   ca-certificates  -> /etc/ssl/certs = the D17 per-session-CA injection point
#   curl/gnupg       -> bake-time tooling (NodeSource key, npm)
#   linux-image-amd64-> the guest kernel (extracted for direct-kernel boot)
#   ncurses-base/term-> the PTY-mode TERM terminfo (asserted below; CC TUI)
#   iproute2         -> ds-apply-netcfg's ip link/addr/route calls (U4)
#   git              -> the git-over-HTTPS pin target (D83/§5.3)
#   udev/kmod        -> /dev/disk/by-label (config-drive mount) + module load
#   dbus             -> the D-Bus system bus `networkctl reload` (ds-slirp-net.service
#                       ExecStart step 3) calls over; systemd only RECOMMENDS dbus, so
#                       --no-install-recommends drops it and the unit FAILS at execution
#                       — SLIRP NIC never DHCPs (live-found 2026-07-29, CC:
#                       FailedToOpenSocket). Must be listed EXPLICITLY.
RUN set -eux; \\
    if [ -s /tmp/egress-ca.crt ]; then \\
      mkdir -p /usr/local/share/ca-certificates; \\
      cp /tmp/egress-ca.crt /usr/local/share/ca-certificates/ds-egress-gateway.crt; fi; \\
    apt-get update; \\
    apt-get install -y --no-install-recommends \\
      systemd-sysv ca-certificates curl gnupg \\
      linux-image-amd64 \\
      ncurses-base ncurses-term \\
      iproute2 iptables kmod udev \\
      dbus \\
      git \\
      build-essential pkg-config \\
      ; \\
    update-ca-certificates
# Keep the egress CA in the image trust store path for the npm step below: node/npm
# do NOT read the system OpenSSL store, so the @anthropic-ai/claude-code pull would
# hit UNABLE_TO_VERIFY_LEAF_SIGNATURE under the TLS-intercepting gateway unless node
# is pointed at the CA via NODE_EXTRA_CA_CERTS (set on the npm RUN below).

# --- step 3: node ${M0_NODE_MAJOR} + the D49-pinned Claude Code runtime ---------
# bookworm ships node 18; pull node ${M0_NODE_MAJOR} from NodeSource when the
# distro candidate is older. The egress CA is trusted above, so the npm pull does
# NOT hit UNABLE_TO_VERIFY_LEAF_SIGNATURE under the TLS-intercepting gateway
# (the drift in client/wrapper/DRIVE-FINDINGS.md §1).
RUN set -eux; \\
    NEED_NODESOURCE=1; \\
    if apt-cache policy nodejs 2>/dev/null | grep -qE "Candidate: ${M0_NODE_MAJOR}\\."; then NEED_NODESOURCE=0; fi; \\
    if [ "\$NEED_NODESOURCE" = 1 ]; then \\
      mkdir -p /etc/apt/keyrings; \\
      curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \\
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \\
      echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${M0_NODE_MAJOR}.x nodistro main" \\
        > /etc/apt/sources.list.d/nodesource.list; \\
      apt-get update; \\
    fi; \\
    apt-get install -y --no-install-recommends nodejs; \\
    node --version; npm --version

# The D49-pinned CC. If the global \`claude\` bin symlink is not created, fall back
# to a /opt/claude-code/bin/claude shim onto the installed package (the same
# fallback path cc_sandbox.sh / build-m0-image.sh document).
# NODE_EXTRA_CA_CERTS: node/npm ignore the system OpenSSL store, so under the
# TLS-intercepting egress gateway point node at the egress CA (copied to the image
# trust path in step 1) — this is what avoids UNABLE_TO_VERIFY_LEAF_SIGNATURE
# (client/wrapper/DRIVE-FINDINGS.md §1). Harmless on a direct-internet build (the
# file is empty there and node ignores an empty extra-CA file).
RUN set -eux; \\
    if [ -s /usr/local/share/ca-certificates/ds-egress-gateway.crt ]; then \\
      export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/ds-egress-gateway.crt; fi; \\
    npm install -g "@anthropic-ai/claude-code@${M0_CC_VERSION}"; \\
    if command -v claude >/dev/null 2>&1; then \\
      echo "claude on PATH: \$(command -v claude)"; \\
    else \\
      pkg="\$(npm root -g)/@anthropic-ai/claude-code"; \\
      test -d "\$pkg"; \\
      mkdir -p /opt/claude-code/bin; \\
      bin="\$pkg/cli.js"; [ -f "\$bin" ] || bin="\$(ls "\$pkg"/*.js 2>/dev/null | head -1)"; \\
      test -n "\$bin"; \\
      printf '#!/bin/sh\\nexec node %s "\$@"\\n' "\$bin" > /opt/claude-code/bin/claude; \\
      chmod 0755 /opt/claude-code/bin/claude; \\
      echo "claude fallback shim at /opt/claude-code/bin/claude -> \$bin"; \\
    fi

# --- step 3a: the pinned dev toolchains (dogfood, 01KWHCG6EV scope 2) ----------
# Fetched HERE, at bake time on the unrestricted host, because a GATED session
# provably cannot fetch them: the POL-2 baseline allowlists the module/crate
# endpoints but deliberately not the toolchain installers (go.dev/dl,
# static.rust-lang.org). The image is where a compiler can legitimately come from.
#
# Both are unpacked from the official release tarballs rather than installed via
# apt (bookworm's Go is far behind the repo's `go` directive) or via rustup's
# network-resolving shim (a shim that reaches for static.rust-lang.org on first
# use is precisely the failure mode this bake exists to avoid). Each tarball is
# verified against a pinned SHA-256 before it is unpacked — a bake that silently
# accepts a substituted toolchain would be the single highest-leverage supply-chain
# hole in the whole image, since this compiler builds the code the agent runs.
RUN set -eux; \\
    cd /tmp; \\
    curl -fsSLO "https://go.dev/dl/go${M0_GO_VERSION}.linux-amd64.tar.gz"; \\
    echo "${M0_GO_SHA256}  go${M0_GO_VERSION}.linux-amd64.tar.gz" | sha256sum -c -; \\
    rm -rf ${M0_GO_PREFIX}; \\
    tar -C "\$(dirname ${M0_GO_PREFIX})" -xzf "go${M0_GO_VERSION}.linux-amd64.tar.gz"; \\
    rm -f "go${M0_GO_VERSION}.linux-amd64.tar.gz"; \\
    ${M0_GO_PREFIX}/bin/go version

# Rust ships as a self-contained installer tarball; install.sh lays down rustc,
# cargo, clippy and rustfmt with NO network access of its own.
RUN set -eux; \\
    cd /tmp; \\
    rt="rust-${M0_RUST_VERSION}-x86_64-unknown-linux-gnu"; \\
    curl -fsSLO "https://static.rust-lang.org/dist/\${rt}.tar.gz"; \\
    echo "${M0_RUST_SHA256}  \${rt}.tar.gz" | sha256sum -c -; \\
    tar -xzf "\${rt}.tar.gz"; \\
    "./\${rt}/install.sh" --prefix=${M0_RUST_PREFIX} \\
        --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,clippy-preview,rustfmt-preview \\
        --disable-ldconfig; \\
    rm -rf "\${rt}" "\${rt}.tar.gz"; \\
    ${M0_RUST_PREFIX}/bin/rustc --version; ${M0_RUST_PREFIX}/bin/cargo --version

# PATH for every login/non-login shell the agent spawns. /etc/profile.d covers
# interactive shells; /etc/environment covers the systemd-launched runtime, which
# is the one that actually matters here (the agent's Bash tool inherits it).
RUN set -eux; \\
    printf 'export PATH=%s/bin:%s/bin:\$PATH\\n' "${M0_GO_PREFIX}" "${M0_RUST_PREFIX}" \\
      > /etc/profile.d/ds-toolchains.sh; \\
    chmod 0644 /etc/profile.d/ds-toolchains.sh; \\
    printf 'PATH=%s/bin:%s/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\\n' \\
      "${M0_GO_PREFIX}" "${M0_RUST_PREFIX}" >> /etc/environment; \\
    for t in ${M0_GO_PREFIX}/bin/* ${M0_RUST_PREFIX}/bin/*; do \\
      [ -x "\$t" ] && ln -sf "\$t" "/usr/local/bin/\$(basename "\$t")"; \\
    done; \\
    /usr/local/bin/go version; /usr/local/bin/cargo --version

# --- step 2: the unprivileged 'ds' guest user + the config-ref / mount dir ------
RUN set -eux; \\
    useradd --create-home --shell /usr/sbin/nologin ds; \\
    install -d -m 0750 -o ds -g ds "${M0_ENTRYPOINT_CONFIG_DIR}"

# --- step 4: D75 per-egress-NIC IPv6 drop-in -----------------------------------
COPY 99-ds-disable-ipv6.conf /etc/sysctl.d/99-ds-disable-ipv6.conf

# --- step 4a: HARD terminfo assertion for the PTY-mode TERM (fail if absent) ----
RUN set -eux; \\
    if [ -f /lib/terminfo/${TISUB} ] || [ -f /usr/share/terminfo/${TISUB} ] || [ -f /etc/terminfo/${TISUB} ]; then \\
      echo "terminfo present for TERM=${M0_PTY_TERM}"; \\
    else \\
      echo "terminfo entry for TERM=${M0_PTY_TERM} ABSENT (need ncurses-base/ncurses-term)"; exit 1; \\
    fi

# --- step 4b: CC workspace pre-trust seed + the PTY-mode TERM default ----------
COPY ds-dot-claude.json /home/ds/.claude.json
RUN set -eux; \\
    chown ds:ds /home/ds/.claude.json; chmod 0600 /home/ds/.claude.json; \\
    printf 'TERM=${M0_PTY_TERM}\\n' >> /etc/environment

# --- step 5/5a/5b: guest binaries + units, installed + enabled ------------------
COPY ds-entrypoint   ${M0_ENTRYPOINT_PATH}
COPY ds-attachfwd    ${M0_ATTACHFWD_PATH}
COPY ds-apply-netcfg ${M0_NETCFG_SCRIPT_PATH}
COPY ds-entrypoint.service     /etc/systemd/system/ds-entrypoint.service
COPY run-ds-entrypoint.mount   /etc/systemd/system/run-ds-entrypoint.mount
COPY ds-attachfwd.service      /etc/systemd/system/ds-attachfwd.service
COPY ds-netcfg.service         /etc/systemd/system/ds-netcfg.service
COPY ds-runtime-dir.conf       /etc/tmpfiles.d/ds-runtime-dir.conf
# SLIRP DHCP: the .network is STAGED at ${M0_SLIRP_NETWORK_STAGE} (a NON-networkd-search
# path) — ds-slirp-net.service installs it into /run/systemd/network + reloads networkd
# ONLY when the routed-tap signal ${M0_NETCFG_FILE} is ABSENT, so on a routed-tap boot
# the .network is never loaded and its [Match] provably cannot catch the tap. Fixes the
# no-IP/no-DNS SLIRP hang (CC loops on api_retry; live-found 2026-06-18).
COPY ds-slirp-dhcp.network     ${M0_SLIRP_NETWORK_STAGE}
COPY ds-slirp-net.service      /etc/systemd/system/ds-slirp-net.service
# The per-session workspace disk mount (dogfood). Fail-OPEN: it is pulled in by the
# DS_WORKSPACE device unit, so a session with no workspace attached never runs it.
COPY ${WORKSPACE_UNIT}         /etc/systemd/system/${WORKSPACE_UNIT}
RUN set -eux; \\
    chmod 0755 ${M0_ENTRYPOINT_PATH} ${M0_ATTACHFWD_PATH} ${M0_NETCFG_SCRIPT_PATH}; \\
    chmod 0644 /etc/systemd/system/ds-entrypoint.service \\
               /etc/systemd/system/run-ds-entrypoint.mount \\
               /etc/systemd/system/ds-attachfwd.service \\
               /etc/systemd/system/ds-netcfg.service \\
               /etc/systemd/system/ds-slirp-net.service \\
               ${M0_SLIRP_NETWORK_STAGE} \\
               /etc/systemd/system/${WORKSPACE_UNIT} \\
               /etc/tmpfiles.d/ds-runtime-dir.conf; \\
    install -d -m 0755 -o ds -g ds ${M0_WORKSPACE_DIR}; \\
    systemctl enable ds-entrypoint.service; \\
    systemctl enable run-ds-entrypoint.mount; \\
    systemctl enable ds-attachfwd.service; \\
    systemctl enable ds-netcfg.service; \\
    systemctl enable systemd-networkd.service; \\
    systemctl enable ds-slirp-net.service; \\
    systemctl enable ${WORKSPACE_UNIT}
# Assert the workspace mount really installed onto the DEVICE unit, not somewhere
# else. `systemctl enable` on a mount whose [Install] names a .device target is the
# load-bearing half of the fail-open design (work.mount's header): if this symlink
# is missing, a session WITH a workspace disk boots with /work silently empty and
# the agent quietly works in the wrong directory — a failure that looks like a bad
# prompt, not a bad image. Assert it exists rather than trusting enable's exit code.
RUN test -L "/etc/systemd/system/dev-disk-by\\x2dlabel-${M0_WORKSPACE_LABEL}.device.wants/${WORKSPACE_UNIT}" \\
    || { echo "workspace mount ${WORKSPACE_UNIT} did not install onto the ${M0_WORKSPACE_LABEL} device unit"; ls -R /etc/systemd/system | grep -i device || true; exit 1; }
# The workspace disk is built host-side with files owned by uid/gid 1000 and ext4
# carries no uid-mapping mount option, so the guest runtime user MUST be 1000 or the
# agent gets a workspace it cannot write. Assert it here: adding another user to the
# image ahead of `ds` would shift the uid and break this silently at runtime.
RUN set -eux; \\
    uid="\$(id -u ds)"; gid="\$(id -g ds)"; \\
    [ "\$uid" = 1000 ] && [ "\$gid" = 1000 ] \\
      || { echo "guest 'ds' is uid:gid \$uid:\$gid, expected 1000:1000 — the host-built workspace disk would be unwritable (see m0-image.env M0_WORKSPACE_LABEL)"; exit 1; }
# Assert systemd-networkd is really present (Debian ${M0_BASE_SUITE} ships it in the
# systemd package pulled by systemd-sysv). Fail the build closed if a future base
# splits it out — mirrors build-m0-image.sh's bake-time networkd-present assert.
RUN test -x /lib/systemd/systemd-networkd || test -x /usr/lib/systemd/systemd-networkd \\
    || { echo "systemd-networkd ABSENT (needed for SLIRP DHCP); add the networkd package"; exit 1; }

# --- step 6: D83/§5.3 git-over-HTTPS pin ---------------------------------------
COPY gitconfig /etc/gitconfig
RUN chmod 0644 /etc/gitconfig

# --- vsock module autoload (ds-attachfwd LISTENs on AF_VSOCK) -------------------
RUN printf 'vmw_vsock_virtio_transport\nvhost_vsock\n' > /etc/modules-load.d/ds-vsock.conf

# --- net.ifnames=0 + serial console + DS_M0ROOT root in fstab -------------------
# The direct-kernel boot passes net.ifnames=0 console=ttyS0 root=LABEL=DS_M0ROOT on
# the cmdline; mirror the root in fstab and enable a serial getty + autologin as the
# operator lifeline (the canonical recipe enables serial-getty@ttyS0 in step 8a).
RUN set -eux; \\
    printf 'LABEL=DS_M0ROOT / ext4 errors=remount-ro 0 1\\n' > /etc/fstab; \\
    mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d; \\
    printf '[Service]\\nExecStart=\\nExecStart=-/sbin/agetty --autologin root --keep-baud 115200,57600,38400,9600 %%I \$TERM\\n' \\
      > /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf; \\
    systemctl enable serial-getty@ttyS0.service; \\
    [ -e /sbin/init ] || ln -s /lib/systemd/systemd /sbin/init; \\
    apt-get clean; rm -rf /var/lib/apt/lists/*
CFEOF

# ── podman build (rootless, network=host, CA-trusted proxied apt/npm) ──────────
say "podman build ${TAG} (rootless${PROXY:+, via proxy ${PROXY}})"
PROXY_ARGS=()
[ -n "${PROXY}" ] && PROXY_ARGS=( \
  --build-arg "http_proxy=${PROXY}"  --build-arg "https_proxy=${PROXY}" \
  --build-arg "HTTP_PROXY=${PROXY}"  --build-arg "HTTPS_PROXY=${PROXY}" )
podman build --network=host "${PROXY_ARGS[@]}" -t "${TAG}" "${CTX}"

# ── export -> rootfs -> kernel/initrd + mke2fs -d, INSIDE podman unshare ───────
# CRITICAL (same rationale as build-l1-image.sh): the tar extract + mke2fs MUST run
# inside the rootless user namespace so container uid 0 maps correctly and the
# image records real root ownership (ds-entrypoint runs as 'ds', but /usr/local/bin
# binaries, units, /etc must be root-owned).
say "export rootfs to tarball"
cid="$(podman create "${TAG}")"
podman export "${cid}" > "${BUILD}/rootfs.tar"
podman rm "${cid}" >/dev/null

say "extract (uid-preserving) + kernel/initrd + mke2fs -d, inside podman userns"
podman unshare bash -euc '
  ROOTFS="$1"; TAR="$2"; RAW="$3"; SIZE="$4"; KOUT="$5"; IOUT="$6"
  rm -rf "$ROOTFS"; mkdir -p "$ROOTFS"
  tar -C "$ROOTFS" --numeric-owner -xpf "$TAR"
  k="$(ls "$ROOTFS"/boot/vmlinuz-* 2>/dev/null | head -1)"
  i="$(ls "$ROOTFS"/boot/initrd.img-* 2>/dev/null | head -1)"
  [ -n "$k" ] && [ -n "$i" ] || { echo "no vmlinuz/initrd in rootfs /boot"; exit 1; }
  cp "$k" "$KOUT"; cp "$i" "$IOUT"
  echo "  kernel: $(basename "$k")  initrd: $(basename "$i")"
  rm -f "$RAW"
  mke2fs -q -t ext4 -L DS_M0ROOT -d "$ROOTFS" "$RAW" "$SIZE"
  rm -rf "$ROOTFS"
' _ "${ROOTFS}" "${BUILD}/rootfs.tar" "${RAW}" "${DISK_SIZE}" "${KERNEL_OUT}" "${INITRD_OUT}"
rm -f "${BUILD}/rootfs.tar"

say "DONE. Artifacts:"
ls -lh "${RAW}" "${KERNEL_OUT}" "${INITRD_OUT}"
cat <<EOF

M0 routed-tap+CC base baked rootlessly. Boot direct-kernel, e.g.:
  qemu-system-x86_64 -kernel ${KERNEL_OUT} -initrd ${INITRD_OUT} \\
    -append 'root=LABEL=DS_M0ROOT rw net.ifnames=0 console=ttyS0,115200' \\
    -drive file=${RAW},format=raw,if=virtio ...
EOF
