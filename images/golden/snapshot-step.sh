#!/usr/bin/env bash
# snapshot-step.sh — the GitHub Actions golden-image SNAPSHOT entry (D55, doc 07
# §1/§3, doc 03 §6).
#
# WHAT THIS IS
# ------------
# The entry script the `golden-snapshot` composite GitHub Action calls AFTER a
# team's existing build job completes. It is the CI-side end of the doc 03 §6
# CI-to-golden-image loop and the doc 07 §2a-spec snapshot step: the build the
# team already trusts (deps installed, caches warm, artifacts built in the
# workspace) becomes the workspace a Dream Serpent session boots from. Teams
# never re-describe their build (doc 07 §1) — they hang this step off the end of
# the CI job that already builds.
#
# It does NOT re-implement the bake. It is a thin (repo, branch) → config →
# prebake.sh adapter:
#   1. resolve the snapshot config (--config, default the example config);
#   2. resolve (repo, branch) from flags or the GitHub Actions environment
#      (GITHUB_REPOSITORY_URL/GITHUB_REPOSITORY, GITHUB_REF_NAME);
#   3. delegate the per-(repo, branch) gating + plan/live decision to
#      prebake.sh — the vmw2-landed config-gating + DS_GOLDEN_BAKE_LIVE gate are
#      REUSED verbatim, never duplicated here.
#
# OPT-IN, DEFAULT OFF (D12) — INHERITED FROM prebake.sh
# -----------------------------------------------------
# This script adds NO new gating. prebake.sh bakes a (repo, branch) ONLY when
# the config has BOTH the global `enabled: true` AND a repos[] entry carrying
# `prebake: true`. An unconfigured repo — absent from repos[], opted out, or
# with the global switch off — is left UNTOUCHED: prebake.sh prints a skip and
# exits 0 without invoking any bake step. The team opts a repo in by adding it
# to the committed prebake config (doc 07 §2b onboarding PR); until then the
# snapshot step is a no-op even though the Action is wired into the pipeline.
#
# DS_GOLDEN_BAKE_LIVE GATE — INHERITED FROM prebake.sh
# ----------------------------------------------------
# The actual qemu/libguestfs clone/warm/commit legs are DS_GOLDEN_BAKE_LIVE-gated
# inside prebake.sh and are a deferred manual operator-host step. Without
# DS_GOLDEN_BAKE_LIVE=1 (CI, the sandbox) NO live tool runs: with --dry-run this
# script delegates to prebake.sh which prints the PLAN it WOULD execute. There is
# NO live claude/qemu(VM-run)/podman invocation anywhere in this script, and the
# composite Action never sets DS_GOLDEN_BAKE_LIVE — the CI default is dry-run.
#
# Usage:
#   # Print the snapshot plan for the GHA-provided (repo, branch) — no live tools:
#   images/golden/snapshot-step.sh --config <cfg.yaml> --dry-run
#   # Override the auto-detected repo/branch (e.g. for a local invocation):
#   images/golden/snapshot-step.sh --config <cfg.yaml> --repo <repo> --branch <branch> --dry-run
#   # LIVE bake (operator host, deferred manual step — NOT CI):
#   DS_GOLDEN_BAKE_LIVE=1 images/golden/snapshot-step.sh --config <cfg.yaml> --repo <repo> --branch <branch>
#   # CI/sandbox regression of this adapter against committed synthetic fixtures:
#   images/golden/snapshot-step.sh --self-test
#
# Env:
#   DS_GOLDEN_BAKE_LIVE=1  enable the live bake (passed through to prebake.sh).
#   PREBAKE                override the prebake.sh delegated to (default: sibling).
#   GITHUB_REPOSITORY_URL  GHA-provided repo URL; used when --repo is omitted.
#   GITHUB_REPOSITORY      GHA-provided owner/name; used to derive the repo when
#                          GITHUB_REPOSITORY_URL is absent (→ github.com/<repo>).
#   GITHUB_REF_NAME        GHA-provided branch; used when --branch is omitted.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREBAKE="${PREBAKE:-${HERE}/prebake.sh}"
EXAMPLE_CONFIG="${HERE}/prebake.config.example.yaml"

log() { printf 'snapshot-step: %s\n' "$*"; }
die() { printf 'snapshot-step: ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Repo/branch resolution. An explicit --repo/--branch wins; otherwise we read
# the GitHub Actions runner environment, which is how the composite Action feeds
# the post-build (repo, branch) without the team re-describing anything.
#
#   repo:   GITHUB_REPOSITORY_URL (e.g. https://github.com/acme/api) is preferred;
#           it is normalized to the canonical github.com/<owner>/<name> ID the
#           prebake config keys on (doc 07 §2a-spec inputs table). If only
#           GITHUB_REPOSITORY (owner/name) is set, prefix github.com/.
#   branch: GITHUB_REF_NAME (the short branch name on a branch build).
# ---------------------------------------------------------------------------

# normalize_repo <raw> -> canonical github.com/<owner>/<name>
# Strips a scheme (https://, git://, ssh://, git@host:), a trailing .git, and a
# trailing slash, leaving the host/owner/name form prebake configs key on.
normalize_repo() {
  local raw="$1"
  raw="${raw%/}"
  raw="${raw%.git}"
  # Strip a leading URL scheme (https://, ssh://, git://) FIRST, before any ':'
  # rewrite, so the scheme colon is never confused with the scp-style separator.
  case "$raw" in
    *://*) raw="${raw#*://}" ;;
  esac
  # scp-style remote: git@github.com:acme/api -> github.com:acme/api -> .../api
  raw="${raw#git@}"
  raw="${raw/:/\/}"
  printf '%s' "$raw"
}

resolve_repo() {
  if [ -n "${1:-}" ]; then normalize_repo "$1"; return; fi
  if [ -n "${GITHUB_REPOSITORY_URL:-}" ]; then normalize_repo "$GITHUB_REPOSITORY_URL"; return; fi
  if [ -n "${GITHUB_REPOSITORY:-}" ]; then normalize_repo "github.com/${GITHUB_REPOSITORY}"; return; fi
  printf ''
}

resolve_branch() {
  if [ -n "${1:-}" ]; then printf '%s' "$1"; return; fi
  if [ -n "${GITHUB_REF_NAME:-}" ]; then printf '%s' "$GITHUB_REF_NAME"; return; fi
  printf ''
}

# ---------------------------------------------------------------------------
# snapshot — resolve (repo, branch) and delegate the per-(repo, branch) gating
# decision (and the plan/live legs) to prebake.sh. All gating + the
# DS_GOLDEN_BAKE_LIVE behavior live in prebake.sh; this layer only adapts GHA
# inputs into a prebake.sh call. DS_GOLDEN_BAKE_LIVE is passed THROUGH unchanged
# — this script never sets it.
# ---------------------------------------------------------------------------
snapshot() {
  local cfg="$1" repo_flag="$2" branch_flag="$3" dry_run="$4"
  [ -n "$cfg" ] || die "missing --config (the per-repo snapshot opt-in config)"
  [ -f "$cfg" ] || die "config not found: $cfg"
  [ -x "$PREBAKE" ] || die "prebake.sh not found/executable at $PREBAKE (set PREBAKE)"

  local repo branch
  repo="$(resolve_repo "$repo_flag")"
  branch="$(resolve_branch "$branch_flag")"
  [ -n "$repo" ] || die "could not resolve repo: pass --repo or run inside GitHub Actions (GITHUB_REPOSITORY_URL/GITHUB_REPOSITORY)"
  [ -n "$branch" ] || die "could not resolve branch: pass --branch or run inside GitHub Actions (GITHUB_REF_NAME)"

  log "post-build snapshot for repo=${repo} branch=${branch} (config=${cfg})"
  log "delegating gating + plan/live to $(basename "$PREBAKE") (config-gating, opt-in, DS_GOLDEN_BAKE_LIVE inherited)"

  # Pass --dry-run through verbatim. prebake.sh applies the global+per-repo
  # gates: an unconfigured/opted-out repo or a globally-disabled config is
  # skipped untouched (exit 0); a configured (repo, branch) emits the plan
  # (dry-run) or runs the DS_GOLDEN_BAKE_LIVE-gated live bake.
  local args=( --config "$cfg" --repo "$repo" --branch "$branch" )
  [ "$dry_run" = 1 ] && args+=( --dry-run )
  "$PREBAKE" "${args[@]}"
}

# ---------------------------------------------------------------------------
# Self-test: prove this adapter offline against the committed synthetic fixtures
# (D50). It asserts that (a) a configured sample repo, fed via the GHA env, emits
# the expected snapshot plan through prebake.sh, (b) an unconfigured repo is
# skipped untouched (no plan), (c) repo/branch normalization handles the
# GHA-provided forms, and (d) the live leg refuses without DS_GOLDEN_BAKE_LIVE=1.
# No live tooling, no network.
# ---------------------------------------------------------------------------
self_test() {
  local fx="${HERE}/prebake_selftest"
  local on_cfg="${fx}/configured.config.yaml"
  local off_cfg="${fx}/disabled.config.yaml"
  [ -f "$on_cfg" ]  || die "self-test fixture missing: $on_cfg"
  [ -f "$off_cfg" ] || die "self-test fixture missing: $off_cfg"

  log "self-test: repo normalization maps GHA forms to the canonical ID"
  [ "$(normalize_repo 'https://github.com/acme/monorepo')" = 'github.com/acme/monorepo' ] \
    || die "self-test FAIL: https URL not normalized"
  [ "$(normalize_repo 'https://github.com/acme/monorepo.git')" = 'github.com/acme/monorepo' ] \
    || die "self-test FAIL: trailing .git not stripped"
  [ "$(normalize_repo 'git@github.com:acme/monorepo.git')" = 'github.com/acme/monorepo' ] \
    || die "self-test FAIL: scp-style remote not normalized"
  [ "$(normalize_repo 'github.com/acme/monorepo')" = 'github.com/acme/monorepo' ] \
    || die "self-test FAIL: bare canonical ID not preserved"
  log "self-test: repo normalization OK"

  log "self-test: repo/branch resolved from the GitHub Actions environment"
  local got
  got="$( GITHUB_REPOSITORY_URL='https://github.com/acme/monorepo' resolve_repo '' )"
  [ "$got" = 'github.com/acme/monorepo' ] || die "self-test FAIL: GITHUB_REPOSITORY_URL not resolved (got '$got')"
  got="$( GITHUB_REPOSITORY_URL='' GITHUB_REPOSITORY='acme/monorepo' resolve_repo '' )"
  [ "$got" = 'github.com/acme/monorepo' ] || die "self-test FAIL: GITHUB_REPOSITORY not resolved (got '$got')"
  got="$( GITHUB_REF_NAME='main' resolve_branch '' )"
  [ "$got" = 'main' ] || die "self-test FAIL: GITHUB_REF_NAME not resolved (got '$got')"
  log "self-test: GHA-environment resolution OK"

  log "self-test: a CONFIGURED sample repo (via GHA env) emits the expected snapshot plan"
  local out
  out="$( GITHUB_REPOSITORY_URL='https://github.com/acme/monorepo' GITHUB_REF_NAME='main' \
          snapshot "$on_cfg" '' '' 1 )"
  printf '%s\n' "$out" | grep -q '^PLAN prebake repo=github.com/acme/monorepo branch=main$' \
    || die "self-test FAIL: configured sample repo did not emit the expected prebake PLAN"
  printf '%s\n' "$out" | grep -q 'DS_GOLDEN_BAKE_LIVE=0' \
    || die "self-test FAIL: plan did not record the DS_GOLDEN_BAKE_LIVE gate as off"
  log "self-test: configured sample repo emitted the snapshot plan (good)"

  log "self-test: an UNCONFIGURED repo (absent from repos[]) is SKIPPED, untouched — no plan"
  out="$( GITHUB_REPOSITORY_URL='https://github.com/acme/not-listed' GITHUB_REF_NAME='main' \
          snapshot "$on_cfg" '' '' 1 )"
  printf '%s\n' "$out" | grep -q 'not configured (absent from repos\[\]; left untouched)' \
    || die "self-test FAIL: unconfigured repo was not skipped/untouched by prebake.sh"
  printf '%s\n' "$out" | grep -q '^PLAN ' \
    && die "self-test FAIL: unconfigured repo emitted a snapshot PLAN (must not)"
  log "self-test: unconfigured repo skipped, no plan (good — opt-in, default OFF, D12)"

  log "self-test: the global kill-switch (enabled: false) skips an otherwise-opted-in sample repo"
  out="$( GITHUB_REPOSITORY_URL='https://github.com/acme/monorepo' GITHUB_REF_NAME='main' \
          snapshot "$off_cfg" '' '' 1 )"
  printf '%s\n' "$out" | grep -q 'pre-bake globally disabled' \
    || die "self-test FAIL: global kill-switch did not skip an opted-in repo"
  printf '%s\n' "$out" | grep -q '^PLAN ' \
    && die "self-test FAIL: globally-disabled config emitted a snapshot PLAN (must not)"
  log "self-test: global kill-switch skips opted-in repo (good)"

  log "self-test: the live bake leg REFUSES without DS_GOLDEN_BAKE_LIVE=1"
  # Subshell isolates prebake.sh's die() exit so set -e does not propagate here.
  if ( GITHUB_REPOSITORY_URL='https://github.com/acme/monorepo' GITHUB_REF_NAME='main' \
       DS_GOLDEN_BAKE_LIVE=0 snapshot "$on_cfg" '' '' 0 ) >/dev/null 2>&1; then
    die "self-test FAIL: live bake ran without DS_GOLDEN_BAKE_LIVE=1"
  fi
  log "self-test: live bake refused without the gate (good — no live qemu/libguestfs in CI/sandbox)"

  echo "snapshot-step: --self-test OK"
}

usage() {
  cat >&2 <<EOF
usage:
  $0 --config <cfg.yaml> [--repo <repo>] [--branch <branch>] [--dry-run]
  $0 --self-test
Inside GitHub Actions, --repo/--branch default to GITHUB_REPOSITORY_URL/
GITHUB_REPOSITORY and GITHUB_REF_NAME. With no --config the example config is
used (global enabled: false ⇒ a no-op snapshot that fires no bake). The live
bake is DS_GOLDEN_BAKE_LIVE-gated in prebake.sh (deferred manual operator step).
EOF
  exit 1
}

main() {
  if [ "${1:-}" = "--self-test" ]; then self_test; return; fi
  local cfg="" repo="" branch="" dry_run=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --config)  cfg="$2"; shift 2 ;;
      --repo)    repo="$2"; shift 2 ;;
      --branch)  branch="$2"; shift 2 ;;
      --dry-run) dry_run=1; shift ;;
      *) die "unknown argument: $1 (run with no args for usage)" ;;
    esac
  done
  # Default to the example config so a wired-but-unconfigured pipeline is a clean
  # no-op (the example ships enabled: false) rather than an error.
  [ -n "$cfg" ] || cfg="$EXAMPLE_CONFIG"
  snapshot "$cfg" "$repo" "$branch" "$dry_run"
}

main "$@"
