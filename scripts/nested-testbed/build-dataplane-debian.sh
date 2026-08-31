#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# build-dataplane-debian.sh — build the FULL L1 enforcement stack INSIDE a
# debian:bookworm container so every binary links Debian's glibc (2.36) and runs
# in the L1 VM. An Arch-host build links a newer glibc and fails in L1 with
# `GLIBC_2.39 not found`. Output → the dir the 9p share pulls from
# (default ~/tmp/ds-nested/bin; boot-l1.sh stage copies bin/ + lib/ into /opt/ds).
#
# What it emits (all glibc-2.36 / L1-runnable), in ONE container pass:
#   bin/ds-dnsgate, bin/ds-tlsproxy      — the Rust boundary gateways (unchanged)
#   lib/libds_nft.a                       — the ds-nft C-ABI staticlib (the Go↔Rust
#                                           nft write edge, doc 14 §6)
#   bin/ds-nethelper                      — built WITH `-tags nftgatelive` (the LIVE
#                                           cgo edge that links libds_nft.a, NOT the
#                                           no-link stub — this is the whole point:
#                                           live nft programming runs inside L1). Since
#                                           D148 the write path lives in this setcap'd
#                                           helper, not in the agent.
#   bin/ds-host-agent                     — UNTAGGED (D148): cgo-free, capability-free;
#                                           it forks ds-nethelper per privileged op
#   bin/ds-orchestrator                   — the control plane (SessionService)
#   bin/ds-hostbridge                     — the attach UDS<->TCP bridge
#   bin/ds-driver-e2e                     — the host-agent driver smoke/recover tool
#   bin/ds-seat-drive                     — the headless KVM writer-seat drive harness
#                                           (the structured analogue of the DS_KVM_LIVE
#                                           goldentrace KVM-tier test; runs INSIDE L1
#                                           where there is no Go toolchain to `go test`)
#
# Toolchains in the container: Rust (rustup, pinned by dataplane/rust-toolchain.toml)
# AND a pinned Go (downloaded once, cached under the build work dir). debian:bookworm's
# apt cargo/golang are too old, so both are installed fresh and cached for re-runs.
#
# Egress: auto-detects a local TLS-intercepting gateway (CA at ~/.mitmproxy) vs a
# direct-internet host (CI runner). With a CA it routes cargo/crates.io + the Go
# toolchain download + GOPROXY through the proxy + trusts the CA; without, it builds
# against crates.io / proxy.golang.org directly.
set -euo pipefail
REPO="${DS_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
OUT="${DS_NESTED_BIN:-$HOME/tmp/ds-nested/bin}"
WORK="${DS_DP_BUILD_DIR:-$HOME/tmp/ds-nested/dpbuild}"
CA="${DS_MITM_CA:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"
IMG="${DS_DEBIAN_IMAGE:-docker.io/library/debian:bookworm}"
# Pin Go to the repo's go.work toolchain (glibc 2.36-compatible static-ish linux/amd64
# tarball). Bump in lockstep with go.work's `go <ver>` line.
GO_VERSION="${DS_GO_VERSION:-1.25.11}"
say(){ printf '\033[1;36m[dp-build] %s\033[0m\n' "$*"; }
# bin/ holds the executables (existing layout the 9p stage already pulls); lib/ is the
# new sibling for libds_nft.a (the Go host-agent's link-time dep, also staged into L1).
mkdir -p "$OUT" "$OUT/lib" "$WORK/cargo" "$WORK/target" "$WORK/ca" "$WORK/go"

PROXY_ENV=()
if [ -r "$CA" ]; then
  say "egress gateway detected (CA at $CA) — routing the build through the proxy"
  cp "$CA" "$WORK/ca/egress-ca.crt"
  PROXY="${DS_BUILD_PROXY:-http://127.0.0.1:18080}"
  PROXY_ENV=(-e "HTTPS_PROXY=$PROXY" -e "HTTP_PROXY=$PROXY"
             -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
             -e CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt)
else
  say "no egress CA — assuming direct internet (CI runner)"
  : > "$WORK/ca/egress-ca.crt"
fi

cat > "$WORK/in-container.sh" <<INNER
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
GO_VERSION="$GO_VERSION"
INNER
cat >> "$WORK/in-container.sh" <<'INNER'
apt-get update -qq
# build-essential (cc/ar/ld for both the Rust staticlib and the cgo link), curl/ca-certs
# for the toolchain fetches, pkg-config/cmake for the gateways' native deps.
apt-get install -y -qq build-essential curl ca-certificates pkg-config cmake >/dev/null
if [ -s /ca/egress-ca.crt ]; then
  cp /ca/egress-ca.crt /usr/local/share/ca-certificates/egress-ca.crt
  update-ca-certificates >/dev/null 2>&1 || true
fi

# --- Rust toolchain (pinned by dataplane/rust-toolchain.toml; apt's cargo is too old) ---
export RUSTUP_HOME=/cargo/rustup CARGO_HOME=/cargo/home PATH=/cargo/home/bin:$PATH
if ! command -v cargo >/dev/null; then
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain none >/dev/null
fi

# --- Go toolchain (pinned to go.work's version; cached under /gocache for re-runs) ---
# debian:bookworm's apt golang is too old for the repo (go 1.25.x). Download the official
# linux/amd64 tarball once into the cache mount and install it to /usr/local/go.
export GOROOT=/usr/local/go
export GOPATH=/gocache/gopath
export GOCACHE=/gocache/build
export GOMODCACHE=/gocache/mod
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
mkdir -p "$GOPATH" "$GOCACHE" "$GOMODCACHE" /gocache/dl
GO_TARBALL="/gocache/dl/go${GO_VERSION}.linux-amd64.tar.gz"
if [ ! -x "$GOROOT/bin/go" ] || [ "$($GOROOT/bin/go version 2>/dev/null | awk '{print $3}')" != "go${GO_VERSION}" ]; then
  if [ ! -s "$GO_TARBALL" ]; then
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "$GO_TARBALL"
  fi
  rm -rf "$GOROOT"
  tar -C /usr/local -xzf "$GO_TARBALL"
fi
go version

# === (a) Rust: gateways + the ds-nft C-ABI staticlib =========================
cd /work/dataplane
export CARGO_TARGET_DIR=/target
# Gateways (unchanged behavior) + the ds-nft staticlib in one cargo invocation so the
# crates.io graph is fetched once. ds-nft's [lib] declares crate-type rlib+staticlib,
# so `--release` emits /target/release/libds_nft.a (the cgo link target below).
cargo build --release --locked -p ds-dnsgate -p ds-tlsproxy -p ds-nft
cp /target/release/ds-dnsgate /target/release/ds-tlsproxy /out/
# The cgo edge (orchestrator/internal/nftbridge/writeedge.go) hard-codes its LDFLAGS to
# -L${SRCDIR}/../../../dataplane/target/release (i.e. /work/dataplane/target/release at
# this mount). We build with CARGO_TARGET_DIR=/target, so the archive lands at
# /target/release/libds_nft.a — mirror it into the in-tree path the linker searches AND
# export it to the 9p lib/ output dir.
mkdir -p /work/dataplane/target/release
cp /target/release/libds_nft.a /work/dataplane/target/release/libds_nft.a
cp /target/release/libds_nft.a /out/lib/libds_nft.a

# === (b) Go: the live-stack binaries ========================================
# All four cross-import proto/gen/go (a separate module), so the build is driven through
# the repo's go.work (auto-discovered by walking up from each module dir to /work/go.work).
# In workspace mode -mod may ONLY be readonly|vendor (NOT mod) — go rejects -mod=mod with a
# go.work present. readonly is the workspace default + keeps the build hermetic w.r.t. the
# committed go.sum/go.work.sum (downloads to the mounted module cache are still allowed).
export GOFLAGS=-mod=readonly
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

# ds-nethelper — the LIVE nft edge, since D148 (2026-07-30). The doc 14 §6 linker set is
# {ds-dnsgate, ds-nethelper}: -tags nftgatelive selects backend_live.go → writeedge.go (cgo)
# over the stub, so CGO_ENABLED=1 and it links libds_nft.a (+ its libc transitive set)
# staged above. This is the binary that programs nft INSIDE L1 (host-safe by construction).
# It must be INSTALLED with `setcap cap_net_admin+eip` in-L1 to be usable (capabilities are
# an xattr on the installed file) — see orchestrator/cmd/ds-nethelper/scripts/
# install-ds-nethelper.sh. NOTE: the L1 runtime wires the host-agent as ROOT today, and the
# helper's owner_uid==caller-uid && nonzero rule can never mint a tap for a root agent, so
# the in-L1 RUNTIME wiring is a tracked follow-up; this step only builds the binary.
( cd /work/orchestrator && CGO_ENABLED=1 go build -tags nftgatelive -o /out/ds-nethelper ./cmd/ds-nethelper )

# ds-host-agent — UNTAGGED forever (D148): it no longer links the ds-nft cgo edge and
# carries no capability; it forks the setcap'd ds-nethelper once per privileged op.
# Building it with -tags nftgatelive is a deliberate COMPILE ERROR
# (cmd/host-agent/nftgatelive_refuse.go). CGO stays on only to match the previous build's
# libc linkage for this binary's glibc target.
( cd /work/orchestrator && CGO_ENABLED=1 go build -o /out/ds-host-agent ./cmd/host-agent )

# The remaining four are plain Go (no cgo edge). Keep CGO off so they stay portable.
( cd /work/orchestrator && CGO_ENABLED=0 go build -o /out/ds-orchestrator ./cmd/orchestrator )
( cd /work/orchestrator && CGO_ENABLED=0 go build -o /out/ds-driver-e2e   ./cmd/ds-driver-e2e )
( cd /work/client       && CGO_ENABLED=0 go build -o /out/ds-hostbridge   ./cmd/ds-hostbridge )
# ds-seat-drive — the headless writer-seat drive harness. It runs INSIDE L1 (no Go
# toolchain there to `go test` the DS_KVM_LIVE goldentrace KVM-tier test), driving one
# scripted CC turn over the live per-session writer seat the host-agent advertises.
# Pure attach.v1 client (stdlib + the client module's e2e/hostbridge); CGO off so the
# glibc-2.36 binary stays portable into L1.
( cd /work/client       && CGO_ENABLED=0 go build -o /out/ds-seat-drive  ./cmd/ds-seat-drive )

# ds-identity-validate-fake — the FAKE D22 identity.v1 Validate UDS responder
# (always-ALLOW + grant_ref) ds-tlsproxy's live Validate client dials when
# DS_SWAP_VALIDATE_LIVE is armed in the testbed (doc 16 §4 / §9). It is a SELF-
# CONTAINED stdlib-only module with its OWN go.mod and NO dependencies, so it must
# build OUTSIDE the repo go.work — GOWORK=off (and CGO off for a portable glibc-2.36
# binary into L1). TEST FAKE only; never on a production cred-egress path.
( cd /work/scripts/nested-testbed/ds-identity-validate-fake && GOWORK=off CGO_ENABLED=0 go build -o /out/ds-identity-validate-fake . )

echo "DP-BUILD-OK"
INNER

say "building (slow the first time: rustup + Go ${GO_VERSION} fetch + crates.io + pingora/hickory + cgo link)"
podman run --rm --network=host \
  -v "$REPO":/work -v "$WORK/cargo":/cargo -v "$WORK/target":/target \
  -v "$WORK/go":/gocache \
  -v "$OUT":/out -v "$WORK/ca":/ca:ro -v "$WORK/in-container.sh":/in.sh:ro \
  "${PROXY_ENV[@]}" "$IMG" bash /in.sh

say "done — Debian-glibc artifacts at $OUT:"
ls -lh "$OUT"/ds-dnsgate "$OUT"/ds-tlsproxy \
       "$OUT"/ds-nethelper "$OUT"/ds-host-agent \
       "$OUT"/ds-orchestrator "$OUT"/ds-hostbridge "$OUT"/ds-driver-e2e \
       "$OUT"/ds-seat-drive "$OUT"/ds-identity-validate-fake \
       "$OUT"/lib/libds_nft.a
