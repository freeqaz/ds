#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# install-vanilla-metal.sh — build + install the OSS data-plane release artifact
# (the D80 single-host all-in-one) onto a clean vanilla Linux host with ZERO
# cloud dependencies. This is the "install on vanilla Linux metal" leg of the
# D33 release gate (.github/workflows/release-vanilla-metal.yml): it must run
# with nothing but a Go toolchain + this repo — no cloud SDK, no cloud
# metadata endpoint, no network at all.
#
# D80 (doc 04 §6 / orchestrator/README.md "two services + one all-in-one"): the
# OSS single-host all-in-one is `cmd/orchestrator-lite` (create/attach/destroy,
# single-host placement, env-config recording, local policy_log + snapshot
# serving) plus the host-side `cmd/host-agent` (the per-host agent / libvirt
# driver). Both are Apache-2.0 (D25), listed in oss-manifest.yaml. We install
# BOTH binaries plus the checked-in roles/ catalog the all-in-one serves.
#
# D33: nothing cloud-specific. The build is `go build` over the standard
# library + the one legal cross-tree import (proto/gen/go, resolved by the
# module's `replace`); the cloud EC2 demo driver
# (orchestrator/internal/hypervisor/ec2demo/) is a SEPARATE capability-flagged
# control-plane tool that the all-in-one does NOT pull — proven by
# scripts/release/cloud-coupling-scan.sh, which this gate runs alongside.
#
# OFFLINE-CLEAN: this script sets GOFLAGS=-mod=mod GOWORK=off and never fetches.
# A vanilla metal host with the module cache already present (or the vendored
# repo) installs with no network. We additionally export GOPROXY=off when
# DS_RELEASE_OFFLINE=1 so an accidental fetch fails loudly rather than reaching
# out — the gate proves the artifact needs no download.
#
# Exit codes: 0 = installed, non-zero = build/install error.
#
# Usage:
#   scripts/release/install-vanilla-metal.sh [--prefix DIR]
#
#   --prefix DIR   install root (default: a fresh mktemp dir, printed on stdout
#                  as the LAST line so a caller / the smoke script can capture it:
#                      PREFIX="$(scripts/release/install-vanilla-metal.sh)"
#   DS_RELEASE_OFFLINE=1   set GOPROXY=off so any fetch attempt fails closed
#                          (the gate uses this to prove no-network install)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

note() { printf 'install-vanilla-metal: %s\n' "$*" >&2; }
die()  { printf 'install-vanilla-metal: ERROR: %s\n' "$*" >&2; exit 1; }

# ---- args -------------------------------------------------------------------
PREFIX=""
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:-}"; [ -n "$PREFIX" ] || die "--prefix requires a DIR"; shift 2 ;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

command -v go >/dev/null 2>&1 || die "go toolchain not found on PATH (the only build dependency)"

if [ -z "$PREFIX" ]; then
  PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/ds-vanilla-metal.XXXXXX")"
fi
mkdir -p "$PREFIX/bin" "$PREFIX/share/ds"
note "install prefix: $PREFIX"

# ---- offline posture (D33 no-cloud / no-network proof) ----------------------
# GOWORK=off resolves the orchestrator module STANDALONE on a fresh clone (the
# repo ships a `replace` for the one legal cross-tree import, proto/gen/go). We
# keep the default -mod=readonly so the build NEVER mutates go.mod/go.sum — an
# install gate must not perturb the tree it builds from.
export GOWORK="off"
if [ "${DS_RELEASE_OFFLINE:-}" = "1" ]; then
  # Prove the artifact installs with NO network: any module fetch must fail
  # closed rather than reach a proxy. The build is stdlib + proto/gen/go (a
  # path `replace`), so a populated module cache (or a fresh `go build` whose
  # deps are already resolved) needs no proxy.
  export GOPROXY="off"
  note "DS_RELEASE_OFFLINE=1 — GOPROXY=off (no-network install; a fetch attempt fails closed)"
fi

# ---- build the OSS all-in-one (D80: orchestrator-lite + host-agent) ---------
ORCH_DIR="$REPO_ROOT/orchestrator"
[ -d "$ORCH_DIR" ] || die "orchestrator/ tree not found at $ORCH_DIR"

build_one() {
  local target="$1" out="$2"
  note "building $target -> $out"
  ( cd "$ORCH_DIR" && go build -o "$out" "$target" ) \
    || die "go build $target failed"
  [ -x "$out" ] || die "build produced no executable at $out"
}

build_one ./cmd/orchestrator-lite "$PREFIX/bin/ds-orchestrator-lite"
build_one ./cmd/host-agent        "$PREFIX/bin/ds-host-agent"

# ---- install the checked-in roles/ catalog the all-in-one serves (D80/D90) --
# orchestrator-lite serves the built-in role catalog (roles/, D80/D90/D93); it
# reads it from DS_ORCH_ROLES_DIR. Install it beside the binaries so the
# installed all-in-one serves the catalog (the smoke points the binary at it).
if [ -d "$REPO_ROOT/roles" ]; then
  cp -R "$REPO_ROOT/roles" "$PREFIX/share/ds/roles"
  note "installed roles/ catalog -> $PREFIX/share/ds/roles"
else
  note "WARN: roles/ catalog not found at $REPO_ROOT/roles — the all-in-one will degrade to the v0 default-only resolver (D50)"
fi

# ---- record what was installed (a tiny manifest for the smoke + operators) --
{
  printf '# OSS data-plane vanilla-metal install manifest (D33/D80)\n'
  printf 'prefix=%s\n' "$PREFIX"
  printf 'bin/ds-orchestrator-lite\n'
  printf 'bin/ds-host-agent\n'
  printf 'share/ds/roles\n'
} > "$PREFIX/share/ds/INSTALL_MANIFEST.txt"

note "install complete: 2 binaries + roles catalog under $PREFIX"
# The LAST stdout line is the prefix, so a caller can capture it.
printf '%s\n' "$PREFIX"
