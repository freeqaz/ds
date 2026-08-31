#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# install-ds-nethelper.sh — OPERATOR-APPLY installer for the setcap'd
# ds-nethelper privileged helper (ROOT-HELPER model, Arch-1 dogfood host,
# ratified D148 2026-07-30).
#
# ── TWO SUBCOMMANDS ────────────────────────────────────────────────────────
#   <built-binary>   ARMED INSTALL. Mutates host state (install + setcap), so
#                    it refuses to run unless DS_NETHELPER_APPLY=1 is set
#                    explicitly by the operator.
#   verify <path>    READ-ONLY verification of an already-installed helper.
#                    No sudo, no host mutation, no DS_NETHELPER_APPLY needed —
#                    safe to run from a bring-up preflight (and stack-up-host.sh
#                    does exactly that before starting the host-agent).
#
# What the armed install does:
#   1. install the helper binary to $DEST (default /usr/local/libexec/ds-nethelper)
#      owned root:$AGENT_GROUP, mode 0750 — filesystem perms are the authn
#      boundary: ONLY members of the agent group may exec the helper.
#   2. setcap cap_net_admin+eip on the installed copy — the capability lives on
#      the HELPER, never on the host-agent. NOTE the +eip (effective +
#      INHERITABLE), NOT +ep: the helper's backend execs ip/nft, and file caps
#      do not survive execve unless the capability is inheritable AND the helper
#      raises it into the ambient set (PR_CAP_AMBIENT_RAISE) around the backend
#      call. A +ep-only install passes the helper's own effective probe yet
#      strands every ip/nft child unprivileged — the half-configured-host trap.
#   3. run `verify` on the installed copy (step 3 below) and FAIL the install if
#      it does not come back green.
#
# FOOTGUN (why verify exists): capabilities are xattrs on the INSTALLED file.
# Rebuilding/copying the binary produces a cap-less file — every `make`/deploy
# must re-run this script; the agent's bring-up probe (verifyHelperReady,
# orchestrator/cmd/host-agent/nethelperseams.go) fails closed otherwise.

set -euo pipefail

DEST="${DS_NETHELPER_DEST:-/usr/local/libexec/ds-nethelper}"
# The helper is installed 0750 root:AGENT_GROUP, so AGENT_GROUP is the authn
# boundary — it must be the group the HOST-AGENT runs as, not whoever typed the
# command. This script sudo's internally and is meant to be run unprivileged, but
# running it under sudo anyway is the obvious mistake, and then a bare `id -gn`
# resolves to `root` and installs a helper the unprivileged agent cannot exec:
# the half-configured-host trap from the header, reached through a different
# door. Prefer the invoking (pre-sudo) user's group.
if [ -n "${DS_NETHELPER_GROUP:-}" ]; then
  AGENT_GROUP="$DS_NETHELPER_GROUP"
elif [ -n "${SUDO_USER:-}" ]; then
  AGENT_GROUP="$(id -gn "$SUDO_USER")"
  echo "note: running under sudo — installing group '$AGENT_GROUP' (from SUDO_USER=$SUDO_USER), not root." >&2
  echo "      override with DS_NETHELPER_GROUP=<group> if the host-agent runs as someone else." >&2
else
  AGENT_GROUP="$(id -gn)"
fi

usage() {
  echo "usage: DS_NETHELPER_APPLY=1 $0 <built-ds-nethelper-binary>   # armed install + verify" >&2
  echo "       $0 verify [--allow-stub] <installed-ds-nethelper>     # read-only verification" >&2
}

# ── verify: the ONE definition of 'this helper is usable' ────────────────────
# Checks, in order, collecting EVERY failure rather than stopping at the first
# (a half-armed host should learn all of what is wrong in one run):
#
#   1. the capability xattr, accepted in BOTH libcap spellings — older libcap
#      prints "<path> = cap_net_admin+eip", newer prints "<path> cap_net_admin=eip".
#      Matching only one spelling would fail a correctly-installed helper.
#   2. the helper's own read-only probe: exit 0 AND the full three-field
#      CAP_NET_ADMIN posture. ambient_raise_ok is the field that distinguishes a
#      correct +eip install from the +ep trap; cap_net_admin_effective alone is
#      NOT sufficient.
#   3. built:true — the helper links the privileged ds-nft backend. Suppressed by
#      --allow-stub, so a cgo-free stub build can be verified for the OTHER
#      fields (and so the installer's own tests can exercise the failure leg).
verify_helper() {
  local allow_stub=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --allow-stub) allow_stub=1; shift ;;
      -*) usage; return 2 ;;
      *) break ;;
    esac
  done
  local path="${1:-}"
  if [[ -z "$path" ]]; then
    usage
    return 2
  fi

  local fails=()

  if [[ ! -x "$path" ]]; then
    echo "VERIFY FAILED for $path" >&2
    echo "  - not an executable file" >&2
    return 1
  fi

  # (1) the capability xattr — both libcap spellings.
  local caps=""
  if command -v getcap >/dev/null 2>&1; then
    caps="$(getcap "$path" 2>/dev/null || true)"
    if [[ "$caps" != *"cap_net_admin=eip"* && "$caps" != *"cap_net_admin+eip"* ]]; then
      fails+=("getcap: expected 'cap_net_admin=eip' (or the older '= cap_net_admin+eip'), got: ${caps:-<no capabilities on the file>}")
    fi
  else
    fails+=("getcap: not found (install libcap; the capability xattr cannot be confirmed)")
  fi

  # (2)+(3) the helper's read-only self-probe.
  local out="" rc=0
  out="$("$path" probe 2>/dev/null)" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    fails+=("probe: exited $rc (want 0)")
  fi
  local field
  for field in '"ok":true' '"cap_net_admin_effective":true' '"cap_net_admin_inheritable":true' '"ambient_raise_ok":true'; do
    case "$out" in
      *"$field"*) ;;
      *) fails+=("probe: missing ${field} in the Result line") ;;
    esac
  done
  if [[ "$allow_stub" -eq 0 ]]; then
    case "$out" in
      *'"built":true'*) ;;
      *) fails+=('probe: missing "built":true — this helper was built WITHOUT -tags nftgatelive, so every privileged verb fails closed with ENOTBUILT') ;;
    esac
  fi

  if [[ "${#fails[@]}" -gt 0 ]]; then
    echo "VERIFY FAILED for $path" >&2
    local f
    for f in "${fails[@]}"; do echo "  - $f" >&2; done
    echo "  probe output: ${out:-<none>}" >&2
    echo "  remedy: sudo setcap cap_net_admin+eip $path   (+eip, NOT +ep — file caps do not survive the ip/nft execve)" >&2
    echo "          and re-run the armed install after ANY rebuild: DS_NETHELPER_APPLY=1 $0 <built-ds-nethelper>" >&2
    return 1
  fi

  echo "verify OK: $path (${caps:-caps confirmed}); probe reports built + cap_net_admin effective/inheritable + ambient_raise_ok"
  return 0
}

# ── dispatch ─────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "verify" ]]; then
  shift
  verify_helper "$@" || exit $?
  exit 0
fi

SRC="${1:-}"

if [[ "${DS_NETHELPER_APPLY:-0}" != "1" ]]; then
  echo "REFUSING: this is the operator-apply installer (privileged: install + setcap)." >&2
  echo "Review it, then arm with: DS_NETHELPER_APPLY=1 $0 <built-ds-nethelper-binary>" >&2
  echo "(The read-only '$0 verify <path>' subcommand needs no arming.)" >&2
  exit 3
fi

if [[ -z "$SRC" || ! -f "$SRC" ]]; then
  usage
  exit 2
fi

# The destination directory may not exist yet (/usr/local/libexec is absent on a
# stock Arch box). `install` does not create parents, so without this the very
# first install on a new host dies with a bare ENOENT that reads like a bad DEST
# rather than a missing directory. Root-owned 0755: it holds a setcap'd binary,
# so a non-root-writable parent is part of the guarantee.
sudo install -d -o root -g root -m 0755 "$(dirname "$DEST")"

echo "installing $SRC -> $DEST (root:$AGENT_GROUP 0750)"
sudo install -o root -g "$AGENT_GROUP" -m 0750 "$SRC" "$DEST"

# +eip (effective + INHERITABLE), NOT +ep — the backend execs ip/nft and file
# caps only reach those children via the inheritable/ambient path. See header.
echo "setcap cap_net_admin+eip $DEST"
sudo setcap cap_net_admin+eip "$DEST"

# Final step: the SAME read-only verification the host-agent's bring-up probe
# and stack-up-host.sh's preflight key on. An install that cannot be verified is
# a FAILED install — never report success on a half-armed helper.
echo "verify: getcap + helper self-probe (built + effective + inheritable + ambient-raisable)"
verify_helper "$DEST"
