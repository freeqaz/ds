#!/usr/bin/env bash
# verify-git-pin.sh — executable assertion for the D83/§5.3 git-over-HTTPS pin
# baked into the M0 base image (guest-config/git-https-pin.gitconfig).
#
# git-over-SSH cannot ride the TLS-terminating egress gateway, so an accidental
# git-over-SSH path from the guest would silently bypass BOTH the credential-swap
# plane and the secret-scanning plane (doc 16 §5.3 / §13 HTTPS-pin assertion;
# doc 09 POL-2; adopted under D83's "may pin" allowance). SSH-git is an explicit,
# TESTED non-goal — this script is that test. It proves three things against the
# baked gitconfig, fully OFFLINE (no network, no live VM):
#
#   (a) insteadOf rewrites SSH -> HTTPS: an `ssh://git@github.com/...` and a
#       scp-style `git@github.com:...` remote both resolve to `https://...`.
#   (b) git-over-SSH fails closed: with the pin active, fetching an SSH-form
#       github remote NEVER invokes the ssh transport (the URL is rewritten to
#       https before transport selection) — proven with a poison GIT_SSH_COMMAND
#       that loudly marks any ssh invocation.
#   (c) remotes resolve to HTTPS: the effective (post-rewrite) remote URL is an
#       https:// URL.
#
# NON-VACUITY: the --self-test also runs the SAME assertions against a gitconfig
# with NO insteadOf rewrite and confirms they FAIL there (ssh stays ssh, the
# poison ssh fires) — so a future edit that drops the rewrite cannot pass.
#
# This script is a SELF-CHECKING GATE artifact, run by hand / the wave gate; it
# is NOT named images/*/lint-*.sh and lives under vm/, so it is outside the
# repo-wide check-image-drift glob (Image & cache builder owns that). It is
# invoked directly (see README "Gate") and self-tested with --self-test.
#
# Usage:
#   vm/m0-image/verify-git-pin.sh             # assert against the baked gitconfig
#   vm/m0-image/verify-git-pin.sh --self-test # regression harness (+ negative case)
#
# LIVE leg (DS_KVM_LIVE=1, DEFERRED MANUAL STEP): against a booted M0 image, run
# the same three assertions INSIDE the guest, against the REAL baked
# /etc/gitconfig. The build environment (and CI) have no live KVM/qemu and no
# booted M0 image, so this leg is env-gated and skips cleanly everywhere else.
#
# CONSOLIDATED RUNBOOK: this live in-guest leg is step (B) — golden git-pin — of
# the single DS_KVM_LIVE operator pass driven by vm/m0-image/boot-validate.sh
# --runbook (clone -> attach -> destroy -> CoW enumerate + this in-guest git-pin
# assertion, one virtual-metal-host pass; D31, infra/terraform/esxi/BRINGUP.md).
# That runbook shells THIS script's DS_KVM_LIVE leg, which emits the exact three
# in-guest checks the operator runs over the serial console / a vsock probe; the
# operator's confirmation of those three checks closes leg (B). Run standalone or
# from the runbook the emitted assertions are identical.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PINNED_GITCONFIG="${HERE}/guest-config/git-https-pin.gitconfig"

# A throwaway HOME so the developer's real ~/.gitconfig can never leak into (or
# be mutated by) these assertions; cleaned on EXIT. Script-scoped (not local) so
# the trap can still see it after a function returns under set -u.
WORK=""
cleanup() { [ -n "${WORK:-}" ] && rm -rf "${WORK}" || true; }
trap cleanup EXIT

# poison_ssh PATH: write an executable that marks ANY ssh-transport invocation
# (so an SSH path that should have been rewritten is caught loudly) and fails.
poison_ssh() {
  local p="$1"
  printf '#!/bin/sh\necho "SSH-INVOKED: $*" >&2\nexit 97\n' > "$p"
  chmod +x "$p"
}

# assert_pin GITCONFIG : run the three assertions against GITCONFIG. Returns 0
# only if (a) ssh forms rewrite to https, (b) ssh transport is never invoked for
# a github ssh remote, (c) the effective url is https. Used BOTH for the real
# baked config (must pass) and the no-rewrite config (must fail -> non-vacuity).
assert_pin() {
  local gitconfig="$1"
  local sb; sb="$(mktemp -d "${WORK}/sb.XXXXXX")"
  local poison="${sb}/poison-ssh"; poison_ssh "$poison"

  # Run every git here in a hermetic config env: only the candidate gitconfig is
  # global; no system config; no terminal prompts; no credential helper firing.
  gx() {
    GIT_CONFIG_GLOBAL="$gitconfig" GIT_CONFIG_SYSTEM=/dev/null \
    GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$poison" \
    HOME="$sb" git -c credential.helper= "$@"
  }

  local repo="${sb}/repo"; git init -q "$repo"

  # (a) insteadOf rewrites SSH -> HTTPS, for BOTH ssh:// and scp-style forms.
  local form url
  for form in 'ssh://git@github.com/owner/repo.git' 'git@github.com:owner/repo.git'; do
    git -C "$repo" remote remove origin >/dev/null 2>&1 || true
    git -C "$repo" remote add origin "$form"
    # `ls-remote --get-url` prints the EFFECTIVE url AFTER insteadOf, no network.
    url="$(gx -C "$repo" ls-remote --get-url origin)"
    case "$url" in
      https://github.com/owner/repo.git) : ;;  # (a)+(c): rewritten to HTTPS
      *) return 1 ;;                            # not rewritten -> assertion fails
    esac
  done

  # (b) git-over-SSH fails closed: with the pin, an SSH-form github remote must
  # NOT reach the ssh transport. We attempt a real ls-remote (it will fail to
  # reach github from a sandbox — that's fine) and assert the poison ssh marker
  # NEVER appears, i.e. ssh was never the chosen transport.
  git -C "$repo" remote remove origin >/dev/null 2>&1 || true
  git -C "$repo" remote add origin 'ssh://git@github.com/owner/repo.git'
  local err="${sb}/err.txt"
  # The ls-remote is EXPECTED to exit non-zero (no network / no creds); we only
  # care whether ssh was invoked, so swallow its status.
  gx -C "$repo" ls-remote origin >/dev/null 2>"$err" || true
  if grep -q 'SSH-INVOKED' "$err"; then
    return 1   # ssh transport WAS reached -> the pin did not fail SSH closed
  fi

  return 0
}

run_checks() {
  local gitconfig="${1:-$PINNED_GITCONFIG}"
  WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/gitpin.XXXXXX")}"
  [ -f "$gitconfig" ] || { echo "verify-git-pin: FAIL: missing gitconfig $gitconfig" >&2; return 1; }

  # Structural pre-checks on the baked artifact (cheap, and they pin intent even
  # if a future git changes the resolution UX): the rewrite base + at least the
  # two canonical github ssh forms, and a credential helper, must be present.
  local insteadof
  insteadof="$(git config -f "$gitconfig" --get-all 'url.https://github.com/.insteadOf' 2>/dev/null || true)"
  printf '%s\n' "$insteadof" | grep -q '^ssh://git@github.com/$'  || { echo "verify-git-pin: FAIL: no ssh:// insteadOf for github" >&2; return 1; }
  printf '%s\n' "$insteadof" | grep -q '^git@github.com:$'        || { echo "verify-git-pin: FAIL: no scp-style insteadOf for github" >&2; return 1; }
  git config -f "$gitconfig" --get-all 'credential.helper' >/dev/null 2>&1 \
    || { echo "verify-git-pin: FAIL: no credential.helper (HTTPS auth carrier) configured" >&2; return 1; }

  # The three behavioral assertions against real git resolution.
  if assert_pin "$gitconfig"; then
    echo "verify-git-pin: OK (insteadOf ssh->https; git-over-SSH fails closed; remotes resolve to HTTPS)"
    return 0
  fi
  echo "verify-git-pin: FAIL: the HTTPS pin did not hold (ssh not rewritten / ssh transport reachable)" >&2
  return 1
}

self_test() {
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/gitpin.XXXXXX")"

  echo "self-test: baked gitconfig must PASS the three assertions"
  run_checks "$PINNED_GITCONFIG" >/dev/null \
    || { echo "self-test FAIL: baked gitconfig did not pass" >&2; exit 1; }
  echo "self-test: baked pin PASSES (good)"

  # NON-VACUITY: a gitconfig with NO insteadOf rewrite (only a credential helper)
  # must FAIL — ssh stays ssh and the ssh transport IS reached. If this passed,
  # the assertions would be vacuous.
  local negcfg="${WORK}/no-rewrite.gitconfig"
  cat > "$negcfg" <<'EOF'
[credential]
	helper = store --file=/run/ds/git/credentials
EOF
  echo "self-test: NEGATIVE case — a config without the ssh->https rewrite must FAIL"
  if assert_pin "$negcfg"; then
    echo "self-test FAIL: a config WITHOUT the rewrite passed the pin assertions (VACUOUS)" >&2
    exit 1
  fi
  echo "self-test: negative case correctly FAILS (assertions are non-vacuous, good)"

  # Second negative: a config whose insteadOf points the WRONG way (https->ssh)
  # must also fail — guards against an inverted rewrite silently shipping.
  local badcfg="${WORK}/inverted.gitconfig"
  cat > "$badcfg" <<'EOF'
[url "ssh://git@github.com/"]
	insteadOf = https://github.com/
[credential]
	helper = store
EOF
  echo "self-test: NEGATIVE case — an INVERTED rewrite (https->ssh) must FAIL"
  if assert_pin "$badcfg"; then
    echo "self-test FAIL: an inverted https->ssh rewrite passed the pin assertions" >&2
    exit 1
  fi
  echo "self-test: inverted rewrite correctly FAILS (good)"

  echo "verify-git-pin: --self-test OK"
}

# Live leg: assert the pin INSIDE a booted M0 guest, step (B) of the consolidated
# DS_KVM_LIVE runbook (vm/m0-image/boot-validate.sh --runbook). DEFERRED MANUAL
# STEP — the build env / CI have no live KVM/qemu and no booted image, so this is
# env-gated and skips cleanly. It emits the exact in-guest assertions; the
# operator runs them over the serial console / a vsock probe against the REAL
# baked /etc/gitconfig, and their confirmation closes leg (B).
live_check() {
  if [ "${DS_KVM_LIVE:-0}" != "1" ]; then
    echo "verify-git-pin: live in-guest leg skipped (set DS_KVM_LIVE=1 against a booted M0 guest)."
    echo "  DEFERRED MANUAL STEP — exercised by the consolidated boot-validate.sh --runbook pass"
    echo "  on the virtual-metal M0 host (D31), not CI/sandbox."
    return 0
  fi
  echo "verify-git-pin: DS_KVM_LIVE=1 — in-guest HTTPS-pin assertion, step (B) of the" >&2
  echo "  boot-validate.sh --runbook consolidated pass. Run these INSIDE the booted M0" >&2
  echo "  guest (over the serial console / vsock probe), against the baked /etc/gitconfig:" >&2
  cat <<'GUEST' >&2
    # (a) insteadOf rewrites SSH -> HTTPS, for BOTH ssh:// and scp-style forms:
    for FORM in 'ssh://git@github.com/o/r.git' 'git@github.com:o/r.git'; do
      D="$(mktemp -d)"; git -C "$D" init -q
      git -C "$D" remote add o "$FORM"
      # (c) remotes resolve to HTTPS: the effective post-rewrite url is https://
      test "$(git -C "$D" ls-remote --get-url o)" = 'https://github.com/o/r.git' \
        || { echo "FAIL(a/c): $FORM did not rewrite to https" >&2; exit 1; }
    done
    # (b) git-over-SSH fails closed: the ssh transport must NEVER be chosen — a
    # poison GIT_SSH_COMMAND that fires marks an un-rewritten ssh path loudly.
    GIT_SSH_COMMAND='sh -c "echo SSH-INVOKED >&2; exit 97"' GIT_TERMINAL_PROMPT=0 \
      git ls-remote 'ssh://git@github.com/o/r.git' 2>&1 | grep -q SSH-INVOKED \
      && { echo 'FAIL(b): ssh transport was reached — pin did not fail SSH closed' >&2; exit 1; } \
      || echo 'OK: insteadOf ssh->https; git-over-SSH fails closed; remotes resolve to HTTPS'
GUEST
  echo "  (This script does not boot a VM; boot-validate.sh --runbook + the human" >&2
  echo "  boot-on-ESXi follow-up own the clone->attach->destroy lifecycle.)" >&2
  return 0
}

case "${1:-}" in
  --self-test) self_test; live_check ;;
  "" )         run_checks; live_check ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
