#!/usr/bin/env bash
# nightly-rebuild.sh — NIGHTLY golden-image rebuild + rotation policy (doc 03 §6).
#
# THE NIGHTLY REBUILD (doc 03 §6)
# -------------------------------
# "A nightly job rebuilds the image all devs work from. Combined with short-lived
# environments, this DISSOLVES the patching problem for dev boxes: when a CVE
# drops you roll the image, and no instance lives long enough to drift. (The
# five-year-old unpatched dev box stops existing.)" (doc 03 §6, the Image & cache
# builder's M1 "nightly rebuild cadence", doc 05 §3.) This is the scheduled
# counterpart to the per-build snapshot-step.sh / prebake.sh CI-to-golden loop:
# instead of waiting for a push, the nightly cadence re-bakes the opted-in
# goldens on a clock so the base every session clones (D29) carries the latest
# patched master + warmed deps, and the rotation window below guarantees a stale
# image can never back a live session for longer than the window.
#
# IT DOES NOT RE-IMPLEMENT THE BAKE (reuse, never duplicate — D12 gating)
# -----------------------------------------------------------------------
# The re-bake of each opted-in (repo, branch) is delegated VERBATIM to
# prebake.sh --all: the global `enabled:`/per-repo `prebake:` config-gating AND
# the DS_GOLDEN_BAKE_LIVE gate live there and are REUSED, never copied here. This
# script adds exactly two things on top of prebake.sh:
#   1. the NIGHTLY cadence framing (it is the thing a cron fires), and
#   2. the ROTATION POLICY (below) — a checkable max-age/freshness gate that
#      prebake.sh does not own.
#
# THE ROTATION POLICY (the "no instance lives long enough to drift" invariant)
# ----------------------------------------------------------------------------
# doc 03 §6 turns CVE response into image rotation: the SLA is that a golden a
# session clones from is never older than the rotation window. This script
# enforces a checkable freshness/max-age check:
#   - rotation window, per (repo, branch), resolved MOST SPECIFIC FIRST:
#       config per-branch override > config per-repo max_age_hours >
#       config defaults.max_age_hours > DS_GOLDEN_MAX_AGE_HOURS env >
#       built-in default (24h — nightly cadence).
#     The config scopes live in prebake.config.example.yaml; a branch that lives
#     sessions clone most (e.g. release) can carry a tighter SLA than the repo.
#   - For each opted-in (repo, branch) the bake writes one per-repo golden under
#     the config's output_dir (see prebake.config.example.yaml). The rotation
#     check stats that golden's mtime; an image older than the window is STALE
#     and MUST be rolled (re-baked) before any new session clones from it.
#   - A MISSING golden (opted in but never baked) is also reported — it cannot
#     back a session until the first bake produces it.
#   - An UNROTATABLE golden — present on disk but with a mtime in the FUTURE
#     (now − mtime is NEGATIVE), so the freshness arithmetic yields no usable
#     age — is a breach, never a silent pass: a future-dated golden would slip
#     past the `age > window` test (a negative age is never "> window") and read
#     as FRESH forever. This is the SAME verdict the public conformance claim
#     models (assurance/guardrail-conformance/goldenfreshness ViolationUnrotatable
#     = "golden-rotation-verdict-undecidable"): the runtime classification and
#     the published claim are single-sourced on the UNROTATABLE verdict token
#     below, so a future-mtime golden cannot be FRESH at runtime while the claim
#     calls it a breach (runtime == claim).
# The check is offline and deterministic (a filesystem stat + arithmetic); it
# never opens an image. With --dry-run the script reports the rotation verdict
# and the bake PLAN; the actual re-bake is the DS_GOLDEN_BAKE_LIVE-gated step.
#
# DS_GOLDEN_BAKE_LIVE GATE — INHERITED FROM prebake.sh
# ----------------------------------------------------
# The qemu/libguestfs clone/warm/commit legs are DS_GOLDEN_BAKE_LIVE-gated inside
# prebake.sh and are a deferred manual operator-host step. Without
# DS_GOLDEN_BAKE_LIVE=1 (CI, the sandbox, the scheduled workflow) NO live tool
# runs: the rotation check + the dry-run PLAN are computed offline. There is NO
# live claude/qemu(VM-run)/podman invocation anywhere in this script, and the
# scheduled workflow (.github/workflows/golden-image-nightly.yml) never sets
# DS_GOLDEN_BAKE_LIVE — the nightly CI default is rotation-report + plan only.
#
# Usage:
#   # Nightly rotation report + dry-run bake plan for every opted-in golden:
#   images/golden/nightly-rebuild.sh --config <cfg.yaml> --dry-run
#   # Just the rotation/freshness verdict (no bake plan), e.g. for a monitor:
#   images/golden/nightly-rebuild.sh --config <cfg.yaml> --check-rotation
#   # LIVE nightly re-bake (operator host / scheduled runner with the base image):
#   DS_GOLDEN_BAKE_LIVE=1 images/golden/nightly-rebuild.sh --config <cfg.yaml>
#   # CI/sandbox regression against synthesized images (no committed fixtures):
#   images/golden/nightly-rebuild.sh --self-test
#
# Env:
#   DS_GOLDEN_BAKE_LIVE=1     enable the live re-bake (passed THROUGH to prebake.sh;
#                             this script never sets it).
#   DS_GOLDEN_MAX_AGE_HOURS   BASE rotation window in hours (default 24) — used
#                             for a (repo, branch) the config sets no
#                             max_age_hours for. An image older than the resolved
#                             window is flagged STALE. The config's per-branch /
#                             per-repo / defaults max_age_hours are MORE specific
#                             and override this env per (repo, branch).
#   DS_GOLDEN_OUTPUT_DIR      override the golden output dir the rotation check
#                             stats (default: parsed from the config's
#                             defaults.output_dir; falls back to a documented
#                             constant if absent).
#   PREBAKE                   override the prebake.sh delegated to (default: sibling).
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREBAKE="${PREBAKE:-${HERE}/prebake.sh}"
SNAPSHOT_STEP="${SNAPSHOT_STEP:-${HERE}/snapshot-step.sh}"
EXAMPLE_CONFIG="${HERE}/prebake.config.example.yaml"

# Rotation window default: 24h. The cadence is nightly, so a golden older than a
# day means a nightly run was missed (or never baked) — it must be rolled.
DEFAULT_MAX_AGE_HOURS=24
# Documented default output dir, mirrored from prebake.config.example.yaml. Used
# only when the config carries no defaults.output_dir and DS_GOLDEN_OUTPUT_DIR is
# unset (so the rotation check always has a directory to stat).
DEFAULT_OUTPUT_DIR=/var/lib/ds/golden/prebaked

# UNROTATABLE verdict token — SINGLE-SOURCED with the public conformance claim's
# ViolationUnrotatable class (assurance/guardrail-conformance/goldenfreshness/
# goldenfreshness.go: "golden-rotation-verdict-undecidable"). A present golden
# whose mtime is in the FUTURE yields a negative (now − mtime) age; the freshness
# arithmetic is undecidable, so the runtime classifies it UNROTATABLE rather than
# letting it read FRESH. The check_rotation ROTATION line and the ROTATION
# SUMMARY use this token, and the self-test pins it to the Go class string so the
# runtime verdict and the claim verdict cannot drift apart (runtime == claim).
UNROTATABLE_VERDICT_CLASS=golden-rotation-verdict-undecidable

# Temp dir the --self-test synthesizes goldens in; cleaned by an EXIT trap.
# Declared here so it is always a defined global under set -u.
SELFTEST_TMP=""

log()  { printf 'nightly-rebuild: %s\n' "$*"; }
warn() { printf 'nightly-rebuild: %s\n' "$*" >&2; }
die()  { printf 'nightly-rebuild: ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Config reads. stdlib-only (no yq), same posture as prebake.sh: a focused awk
# pass over the documented fixed-shape schema (prebake.config.example.yaml). We
# only read the keys the rotation/enumeration logic needs; an unrecognized shape
# yields no match and we fall back to the documented defaults (fail-safe: the
# rotation check still runs and reports MISSING rather than crashing).
# ---------------------------------------------------------------------------

# cfg_global_enabled <cfg> -> "true" iff the top-level `enabled:` is true.
cfg_global_enabled() {
  awk '/^enabled:[[:space:]]*true[[:space:]]*$/ { print "true"; exit }' "$1"
}

# cfg_output_dir <cfg> -> the defaults.output_dir value (column-2 under a
# top-level `defaults:` block), or empty if absent. We track whether we are
# inside the top-level defaults: block and read the first output_dir under it.
cfg_output_dir() {
  awk '
    /^defaults:[[:space:]]*$/ { ind = 1; next }
    /^[A-Za-z_]/ { ind = 0 }          # any new top-level key leaves defaults:
    ind && /^[[:space:]]+output_dir:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]+output_dir:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      print line; exit
    }
  ' "$1"
}

# cfg_opted_in_repos <cfg> -> every repos[] entry carrying prebake: true, one
# per line. Mirrors prebake.sh's repo enumeration but filtered to the opted-in
# set (the rotation check only cares about images that WILL be baked).
cfg_opted_in_repos() {
  awk '
    function flush() {
      if (cur != "" && pb) print cur
      cur = ""; pb = 0
    }
    /^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/ {
      flush()
      line = $0
      sub(/^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      cur = line; pb = 0; next
    }
    /^[[:space:]]+prebake:[[:space:]]*true[[:space:]]*$/  { if (cur != "") pb = 1; next }
    /^[[:space:]]+prebake:[[:space:]]*false[[:space:]]*$/ { if (cur != "") pb = 0; next }
    END { flush() }
  ' "$1"
}

# cfg_repo_branches <cfg> <repo> -> the branch list for <repo> (same parse as
# prebake.sh's branches[] reader); empty if none (caller defaults to "main").
cfg_repo_branches() {
  awk -v want="$2" '
    /^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      inblk = (line == want); inbr = 0; next
    }
    inblk && /^[[:space:]]+branches:[[:space:]]*$/ { inbr = 1; next }
    inblk && inbr && /^[[:space:]]*-[[:space:]]+/ {
      b = $0
      sub(/^[[:space:]]*-[[:space:]]+/, "", b)
      sub(/[[:space:]]*$/, "", b); gsub(/"/, "", b)
      print b; next
    }
    inblk && inbr && /^[[:space:]]*[A-Za-z_]+:/ { inbr = 0 }
  ' "$1"
}

# ---------------------------------------------------------------------------
# Rotation-window (max_age_hours) reads — the per-(repo, branch) freshness SLA.
# Same stdlib awk posture as the cfg_* readers above: a focused pass over the
# documented fixed-shape schema (prebake.config.example.yaml). Three scopes, most
# specific wins (resolved by cfg_max_age_hours below):
#   per-branch override  > per-repo max_age_hours > defaults.max_age_hours
# An unrecognized shape yields no match and the caller falls back to the next
# scope (and ultimately DS_GOLDEN_MAX_AGE_HOURS / the built-in default) — the
# rotation check always has a window and never crashes on an unknown file.
# ---------------------------------------------------------------------------

# cfg_default_max_age <cfg> -> defaults.max_age_hours (column-2 under the
# top-level `defaults:` block), or empty if absent. Mirrors cfg_output_dir's
# scoping: only an indented key UNDER `defaults:` counts.
cfg_default_max_age() {
  awk '
    /^defaults:[[:space:]]*$/ { ind = 1; next }
    /^[A-Za-z_]/ { ind = 0 }          # any new top-level key leaves defaults:
    ind && /^[[:space:]]+max_age_hours:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]+max_age_hours:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      print line; exit
    }
  ' "$1"
}

# cfg_repo_max_age <cfg> <repo> -> the per-repo max_age_hours for <repo>, or
# empty. Tracks the current `- repo:` block and reads a max_age_hours key at the
# repo level (NOT inside a nested branch_overrides: block — its keys are
# per-branch). The repo-level max_age_hours and branch_overrides are SIBLINGS, so
# their YAML order is not fixed: we open `inov` on `branch_overrides:` AND close
# it again the moment a repo-level (two-space-under-dash) key follows, so a
# repo-level max_age_hours is read whether it precedes OR follows branch_overrides.
cfg_repo_max_age() {
  awk -v want="$2" '
    # number of leading spaces of a "<key>:" line (the indent of the key text).
    function key_indent(s,   m) { m = s; sub(/[^[:space:]].*$/, "", m); return length(m) }
    # indent of the branch_overrides: key itself (same helper, named for clarity).
    function ov_indent(s) { return key_indent(s) }
    /^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      inblk = (line == want); inov = 0; ovind = ""; next
    }
    # entering the nested branch_overrides: map (its max_age_hours are per-branch).
    inblk && /^[[:space:]]+branch_overrides:[[:space:]]*$/ { inov = 1; ovind = ov_indent($0); next }
    # leaving branch_overrides: on a key at branch_overrides own indent or shallower
    # (a repo-level sibling), so a repo-level max_age_hours AFTER the overrides map
    # is still read below. Keys DEEPER than branch_overrides are its interior.
    inblk && inov && /^[[:space:]]*[A-Za-z_]+:/ && ovind != "" && key_indent($0) <= ovind { inov = 0 }
    inblk && inov && /^[[:space:]]+max_age_hours:[[:space:]]*/ { next }
    inblk && !inov && /^[[:space:]]+max_age_hours:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]+max_age_hours:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      print line; exit
    }
  ' "$1"
}

# cfg_branch_max_age <cfg> <repo> <branch> -> the per-branch max_age_hours under
# the repo's `branch_overrides:` map (keyed by branch name), or empty. The map
# shape is:  branch_overrides:\n  <branch>:\n    max_age_hours: <n>
cfg_branch_max_age() {
  awk -v want="$2" -v br="$3" '
    /^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      inblk = (line == want); inov = 0; inbr = 0; next
    }
    inblk && /^[[:space:]]+branch_overrides:[[:space:]]*$/ { inov = 1; inbr = 0; next }
    # leaving branch_overrides: on a less-indented repo-level key (a key at the
    # same column as branch_overrides itself, i.e. two spaces under the dash).
    inblk && inov && /^[[:space:]][[:space:]][A-Za-z_]+:/ && !/^[[:space:]][[:space:]][[:space:]]/ { inov = 0; inbr = 0 }
    inblk && inov && /^[[:space:]]+[^[:space:]].*:[[:space:]]*$/ {
      key = $0
      sub(/^[[:space:]]+/, "", key); sub(/:[[:space:]]*$/, "", key); gsub(/"/, "", key)
      inbr = (key == br); next
    }
    inblk && inov && inbr && /^[[:space:]]+max_age_hours:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]+max_age_hours:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      print line; exit
    }
  ' "$1"
}

# cfg_max_age_hours <cfg> <repo> <branch> -> the resolved rotation window in
# hours for one (repo, branch), applying precedence MOST SPECIFIC FIRST:
#   per-branch override > per-repo max_age_hours > defaults.max_age_hours
# Prints empty if the config sets none at any scope (the caller then falls back
# to DS_GOLDEN_MAX_AGE_HOURS / the built-in default). A value is accepted only
# if it is a positive integer; a malformed value is skipped to the next scope.
cfg_max_age_hours() {
  local cfg="$1" repo="$2" branch="$3" v
  v="$(cfg_branch_max_age "$cfg" "$repo" "$branch")"
  case "$v" in ''|*[!0-9]*) v="" ;; esac
  if [ -z "$v" ]; then
    v="$(cfg_repo_max_age "$cfg" "$repo")"
    case "$v" in ''|*[!0-9]*) v="" ;; esac
  fi
  if [ -z "$v" ]; then
    v="$(cfg_default_max_age "$cfg")"
    case "$v" in ''|*[!0-9]*) v="" ;; esac
  fi
  printf '%s' "$v"
}

# ---------------------------------------------------------------------------
# Golden-image identity for the rotation check. The content-addressed image ID
# is computed by the image pipeline (IMAGE-IDENTITY.md); for the freshness stat
# the rotation check needs only a STABLE per-(repo, branch) path under the output
# dir — the SAME path the bake's step-3 commit writes/refreshes. So this is the
# path whose mtime answers "how old is the golden this (repo, branch) clones
# from?", and it MUST be the identical derivation prebake.sh's bake uses.
#
# SINGLE SOURCE OF TRUTH (D-reconcile): the canonical (repo, branch) → filename
# derivation lives in prebake.sh (golden_slug/golden_path — the bake's step-3
# commit path). To make the rotation-check path and the commit path impossible
# to diverge, this script MIRRORS that derivation here and the self-test asserts
# the two agree byte-for-byte (prebake_golden_path below extracts prebake.sh's
# OWN helper and the self-test compares it against this mirror for the same
# inputs — a one-sided edit to either fails the self-test loudly). The local
# copy is what runs (sourcing all of prebake.sh would clobber this script's
# HERE/log/die), so we keep the mirror as the executable derivation and pin it
# to prebake.sh with a cross-check rather than a runtime source.
# ---------------------------------------------------------------------------
golden_slug() {
  # repo + branch -> "<repo-with-slashes-as-__>--<branch>.qcow2"
  local repo="$1" branch="$2" slug
  slug="${repo}--${branch}"
  slug="${slug//\//__}"
  slug="${slug// /_}"
  printf '%s.qcow2' "$slug"
}

golden_path() {
  printf '%s/%s' "$1" "$(golden_slug "$2" "$3")"
}

# prebake_golden_path <output_dir> <repo> <branch> — resolve the SAME path via
# prebake.sh's OWN canonical golden_path, by sourcing a main-stripped copy of
# prebake.sh in an ISOLATED subshell (so its HERE/log/die/main never leak into
# this script) and calling its helper. Prints prebake.sh's resolved path, or
# empty if prebake.sh cannot be sourced. The self-test uses this to assert the
# local mirror above agrees with prebake.sh's single source.
prebake_golden_path() {
  [ -r "$PREBAKE" ] || { printf ''; return; }
  local stripped
  stripped="$(mktemp)" || { printf ''; return; }
  awk '/^(exec[[:space:]]+)?main([[:space:]]|$)/ { next } { print }' "$PREBAKE" > "$stripped" 2>/dev/null \
    || { rm -f "$stripped"; printf ''; return; }
  # Subshell isolates the sourced prebake.sh: its globals/functions die with the
  # subshell and never overwrite this script's HERE/log/die.
  (
    # shellcheck disable=SC1090
    . "$stripped" 2>/dev/null || exit 0
    [ "$(type -t golden_path)" = function ] || exit 0
    golden_path "$1" "$2" "$3"
  )
  rm -f "$stripped"
}

# file_age_seconds <path> -> seconds since the file's mtime, or empty if missing.
# Uses `stat -c %Y` (GNU) with a BSD `stat -f %m` fallback so the check is
# portable across the operator host and CI runners.
file_age_seconds() {
  local f="$1" mtime now
  [ -e "$f" ] || { printf ''; return; }
  if mtime="$(stat -c %Y "$f" 2>/dev/null)" && [ -n "$mtime" ]; then
    :
  elif mtime="$(stat -f %m "$f" 2>/dev/null)" && [ -n "$mtime" ]; then
    :
  else
    printf ''; return
  fi
  now="$(date +%s)"
  printf '%s' "$(( now - mtime ))"
}

# ---------------------------------------------------------------------------
# Rotation check. For each opted-in (repo, branch), stat its golden under the
# output dir and classify against the window. Prints one ROTATION line per
# image and a summary. Per-row verdict (the SAME taxonomy the public claim uses,
# assurance/guardrail-conformance/goldenfreshness):
#   MISSING      — no golden on disk (opted in, never baked).
#   UNROTATABLE  — present but mtime in the FUTURE (now − mtime < 0): the
#                  freshness arithmetic is undecidable, so it is a breach, never
#                  a silent FRESH. Verdict token == UNROTATABLE_VERDICT_CLASS,
#                  single-sourced with the claim's ViolationUnrotatable.
#   STALE        — present, age > window: must be rolled.
#   FRESH        — present, 0 <= age <= window.
# Returns:
#   0  every opted-in golden is FRESH (within the window)
#   3  at least one is STALE, MISSING, or UNROTATABLE (the rotation SLA is
#      breached — roll it / re-bake to correct the mtime)
# A non-zero return is the signal a monitor/operator acts on; the nightly
# workflow surfaces it as a job annotation (never a hard CI failure on the
# default plan-only path — see the workflow header).
# ---------------------------------------------------------------------------
check_rotation() {
  local cfg="$1"
  [ -f "$cfg" ] || die "config not found: $cfg"

  # The BASE window — the value used when the config sets no max_age_hours at any
  # scope for a given (repo, branch). Precedence below the config scopes:
  #   DS_GOLDEN_MAX_AGE_HOURS env > built-in DEFAULT_MAX_AGE_HOURS.
  # The config's per-branch > per-repo > defaults windows (cfg_max_age_hours) are
  # MORE specific and override this base per (repo, branch).
  local base_max_age_hours="${DS_GOLDEN_MAX_AGE_HOURS:-$DEFAULT_MAX_AGE_HOURS}"
  case "$base_max_age_hours" in
    ''|*[!0-9]*) die "DS_GOLDEN_MAX_AGE_HOURS must be a positive integer (hours); got '$base_max_age_hours'" ;;
  esac
  [ "$base_max_age_hours" -gt 0 ] || die "DS_GOLDEN_MAX_AGE_HOURS must be > 0"

  local out_dir="${DS_GOLDEN_OUTPUT_DIR:-}"
  if [ -z "$out_dir" ]; then
    out_dir="$(cfg_output_dir "$cfg")"
    [ -n "$out_dir" ] || out_dir="$DEFAULT_OUTPUT_DIR"
  fi

  local base_src="DS_GOLDEN_MAX_AGE_HOURS"
  [ -n "${DS_GOLDEN_MAX_AGE_HOURS:-}" ] || base_src="built-in default"
  log "rotation base window: ${base_max_age_hours}h (${base_src}); golden output dir: ${out_dir} (per-(repo,branch) config max_age_hours overrides: per-branch > per-repo > defaults)"

  if [ "$(cfg_global_enabled "$cfg")" != "true" ]; then
    log "ROTATION: pre-bake globally disabled (enabled: false; D12 dynamic default) — no goldens to rotate; environments stay dynamic"
    log "ROTATION SUMMARY ok=0 stale=0 missing=0 (pre-bake off)"
    return 0
  fi

  local repos; repos="$(cfg_opted_in_repos "$cfg")"
  if [ -z "$repos" ]; then
    log "ROTATION: no opted-in repos (prebake: true) — nothing to rotate"
    log "ROTATION SUMMARY ok=0 stale=0 missing=0"
    return 0
  fi

  local ok=0 stale=0 missing=0 unrotatable=0
  local repo branch branches path age
  local max_age_hours max_age_secs win_src cfg_win
  while IFS= read -r repo; do
    [ -n "$repo" ] || continue
    branches="$(cfg_repo_branches "$cfg" "$repo")"
    [ -n "$branches" ] || branches="main"
    while IFS= read -r branch; do
      [ -n "$branch" ] || continue
      # Resolve THIS (repo, branch)'s window: config (per-branch > per-repo >
      # defaults) wins; else the base window above.
      cfg_win="$(cfg_max_age_hours "$cfg" "$repo" "$branch")"
      if [ -n "$cfg_win" ]; then
        max_age_hours="$cfg_win"; win_src="config"
      else
        max_age_hours="$base_max_age_hours"; win_src="$base_src"
      fi
      max_age_secs=$(( max_age_hours * 3600 ))
      path="$(golden_path "$out_dir" "$repo" "$branch")"
      age="$(file_age_seconds "$path")"
      if [ -z "$age" ]; then
        printf 'nightly-rebuild: ROTATION repo=%s branch=%s MISSING (no golden at %s — never baked; cannot back a session until first bake)\n' \
          "$repo" "$branch" "$path"
        missing=$(( missing + 1 ))
      elif [ "$age" -lt 0 ]; then
        # Present, but mtime is in the FUTURE: now − mtime is negative, so the
        # freshness arithmetic is undecidable. Without this branch a future-dated
        # golden would never satisfy `age > window` and read as FRESH forever —
        # the exact silent pass the public claim's ViolationUnrotatable catches.
        # The verdict token is single-sourced with the claim (UNROTATABLE_VERDICT_CLASS).
        printf 'nightly-rebuild: ROTATION repo=%s branch=%s UNROTATABLE [%s] age=%dh (mtime in the future — freshness verdict undecidable; an undecidable golden is a breach, never a silent pass) (%s)\n' \
          "$repo" "$branch" "$UNROTATABLE_VERDICT_CLASS" "$(( age / 3600 ))" "$path"
        unrotatable=$(( unrotatable + 1 ))
      elif [ "$age" -gt "$max_age_secs" ]; then
        printf 'nightly-rebuild: ROTATION repo=%s branch=%s STALE age=%dh > window=%dh [%s] (%s — MUST be rolled before a new session clones it)\n' \
          "$repo" "$branch" "$(( age / 3600 ))" "$max_age_hours" "$win_src" "$path"
        stale=$(( stale + 1 ))
      else
        printf 'nightly-rebuild: ROTATION repo=%s branch=%s FRESH age=%dh <= window=%dh [%s] (%s)\n' \
          "$repo" "$branch" "$(( age / 3600 ))" "$max_age_hours" "$win_src" "$path"
        ok=$(( ok + 1 ))
      fi
    done <<EOF
$branches
EOF
  done <<EOF
$repos
EOF

  log "ROTATION SUMMARY ok=${ok} stale=${stale} missing=${missing} unrotatable=${unrotatable} base_window=${base_max_age_hours}h (per-(repo,branch) windows on each ROTATION line above)"
  if [ "$stale" -gt 0 ] || [ "$missing" -gt 0 ] || [ "$unrotatable" -gt 0 ]; then
    warn "ROTATION BREACH: ${stale} stale + ${missing} missing + ${unrotatable} unrotatable golden(s) — the nightly re-bake must roll these (DS_GOLDEN_BAKE_LIVE=1, operator/scheduled-runner step)"
    return 3
  fi
  log "ROTATION OK: every opted-in golden is within its rotation window"
  return 0
}

# ---------------------------------------------------------------------------
# rebuild — the nightly entry. Run the rotation check (report-only, never fatal
# to the run), then delegate the actual re-bake of every opted-in (repo, branch)
# to prebake.sh --all. With --dry-run prebake.sh prints the PLAN; the live legs
# are DS_GOLDEN_BAKE_LIVE-gated INSIDE prebake.sh (this script passes the env
# through, never sets it).
# ---------------------------------------------------------------------------
rebuild() {
  local cfg="$1" dry_run="$2"
  [ -n "$cfg" ] || die "missing --config (the per-repo pre-bake opt-in config)"
  [ -f "$cfg" ] || die "config not found: $cfg"
  [ -x "$PREBAKE" ] || die "prebake.sh not found/executable at $PREBAKE (set PREBAKE)"

  log "nightly golden rebuild for config=${cfg} (dry-run=${dry_run}, DS_GOLDEN_BAKE_LIVE=${DS_GOLDEN_BAKE_LIVE:-0})"

  # 1) Rotation policy first: report freshness so a breach is visible whether or
  #    not the re-bake leg runs. Report-only here — a breach does not abort the
  #    run (the re-bake is precisely how a breach is remediated). The standalone
  #    --check-rotation entry returns the non-zero rotation code for monitors.
  check_rotation "$cfg" || warn "rotation breach noted above; the re-bake below is what rolls the stale/missing goldens"

  # 2) Delegate the re-bake to prebake.sh --all. Gating (global + per-repo) and
  #    the DS_GOLDEN_BAKE_LIVE gate are REUSED there, never duplicated. Pass
  #    --dry-run through verbatim; DS_GOLDEN_BAKE_LIVE is inherited from the env.
  log "delegating re-bake to $(basename "$PREBAKE") --all (config-gating, opt-in, DS_GOLDEN_BAKE_LIVE inherited)"
  local args=( --config "$cfg" --all )
  [ "$dry_run" = 1 ] && args+=( --dry-run )
  "$PREBAKE" "${args[@]}"
}

# ---------------------------------------------------------------------------
# snapshot_leg — drive the per-(repo, branch) SNAPSHOT step for every opted-in
# golden. This is the CI-to-golden snapshot leg (snapshot-step.sh) fanned out
# across the nightly enumeration: for each opted-in (repo, branch) it invokes
# snapshot-step.sh --repo <repo> --branch <branch>, which is the thin adapter
# that delegates the gating + plan/live decision to prebake.sh. The
# DS_GOLDEN_BAKE_LIVE gate is INHERITED (passed through, never set here), so with
# --dry-run / no gate this is a plan-only leg — no live qemu/libguestfs. It is
# kept distinct from the prebake.sh --all re-bake so the snapshot adapter (the
# GHA-facing path) is exercised against the same opted-in set the rotation check
# and re-bake use, closing the previously-untested snapshot branch in --self-test.
# Prints one "SNAPSHOT-LEG ..." line per opted-in golden it drives.
# ---------------------------------------------------------------------------
snapshot_leg() {
  local cfg="$1" dry_run="$2"
  [ -f "$cfg" ] || die "config not found: $cfg"
  [ -x "$SNAPSHOT_STEP" ] || die "snapshot-step.sh not found/executable at $SNAPSHOT_STEP (set SNAPSHOT_STEP)"

  if [ "$(cfg_global_enabled "$cfg")" != "true" ]; then
    log "SNAPSHOT-LEG: pre-bake globally disabled (enabled: false; D12) — no goldens to snapshot"
    return 0
  fi
  local repos; repos="$(cfg_opted_in_repos "$cfg")"
  [ -n "$repos" ] || { log "SNAPSHOT-LEG: no opted-in repos (prebake: true) — nothing to snapshot"; return 0; }

  local repo branch branches args
  while IFS= read -r repo; do
    [ -n "$repo" ] || continue
    branches="$(cfg_repo_branches "$cfg" "$repo")"
    [ -n "$branches" ] || branches="main"
    while IFS= read -r branch; do
      [ -n "$branch" ] || continue
      log "SNAPSHOT-LEG repo=${repo} branch=${branch} -> $(basename "$SNAPSHOT_STEP") (gating + plan/live delegated to prebake.sh; DS_GOLDEN_BAKE_LIVE inherited)"
      args=( --config "$cfg" --repo "$repo" --branch "$branch" )
      [ "$dry_run" = 1 ] && args+=( --dry-run )
      "$SNAPSHOT_STEP" "${args[@]}"
    done <<EOF
$branches
EOF
  done <<EOF
$repos
EOF
}

# ---------------------------------------------------------------------------
# Self-test: prove the nightly + rotation logic offline, with NO committed
# fixtures and NO live tooling. We synthesize a golden output dir in a temp
# directory (the way overlay-create.sh --self-test synthesizes a base+overlay)
# and assert:
#   (a) a configured repo drives the re-bake (prebake.sh emits a dry-run PLAN);
#   (b) a synthetic STALE golden (mtime backdated past the window) is flagged
#       and check_rotation returns non-zero;
#   (c) a synthetic FRESH golden is within the window and check_rotation returns 0;
#   (d) a MISSING golden (opted in, never baked) is flagged;
#   (e) the live re-bake REFUSES without DS_GOLDEN_BAKE_LIVE=1.
#   (f) the SNAPSHOT leg (snapshot-step.sh) is invoked PER opted-in golden during
#       a gated (no live tool) re-bake — one snapshot adapter call per (repo,
#       branch), each emitting a dry-run PLAN, and it refuses live without the gate;
#   (g) the rotation window honors the config's per-branch > per-repo > defaults
#       max_age_hours precedence;
#   (h) the local golden_path mirror agrees with prebake.sh's canonical helper
#       (single source of truth — rotation path == bake commit path);
#   (i) a future-dated golden (mtime in the future ⇒ negative age) is flagged
#       UNROTATABLE and returns non-zero, and the runtime verdict TOKEN is the
#       SAME string as the public claim's ViolationUnrotatable (runtime == claim);
#   (j) the awk config readers extract IDENTICAL values across a fuzz matrix of
#       key-ORDER / INDENTation / benign-whitespace variants (parsing hardened
#       against format drift — a tighter freshness window can't be silently lost).
# ---------------------------------------------------------------------------
self_test() {
  local fx="${HERE}/prebake_selftest"
  local on_cfg="${fx}/configured.config.yaml"
  local off_cfg="${fx}/disabled.config.yaml"
  [ -f "$on_cfg" ]  || die "self-test fixture missing: $on_cfg"
  [ -f "$off_cfg" ] || die "self-test fixture missing: $off_cfg"

  # Use a script-global for the temp dir so the EXIT trap (which fires AFTER
  # this function returns, when the local would be out of scope under set -u)
  # can still clean it up.
  SELFTEST_TMP="$(mktemp -d)"
  trap 'rm -rf "${SELFTEST_TMP:-}"' EXIT
  local T="$SELFTEST_TMP"
  local out_dir="$T/prebaked"
  local out
  mkdir -p "$out_dir"

  # --- (a) configured repo drives the re-bake via prebake.sh (dry-run PLAN) ---
  log "self-test: a CONFIGURED config must drive a re-bake PLAN through prebake.sh --all"
  out="$( DS_GOLDEN_OUTPUT_DIR="$out_dir" rebuild "$on_cfg" 1 )"
  printf '%s\n' "$out" | grep -q '^PLAN prebake repo=github.com/acme/monorepo branch=main$' \
    || die "self-test FAIL: configured repo did not drive a prebake PLAN for main"
  printf '%s\n' "$out" | grep -q '^PLAN prebake repo=github.com/acme/monorepo branch=release$' \
    || die "self-test FAIL: configured repo did not drive a prebake PLAN for release"
  printf '%s\n' "$out" | grep -q 'DS_GOLDEN_BAKE_LIVE=0' \
    || die "self-test FAIL: re-bake plan did not record the DS_GOLDEN_BAKE_LIVE gate as off"
  log "self-test: configured config drove the re-bake plan via prebake.sh (good)"

  # --- (d) MISSING golden (opted in, never baked) is flagged ---
  log "self-test: an opted-in (repo, branch) with NO golden on disk must be MISSING"
  if ( DS_GOLDEN_OUTPUT_DIR="$out_dir" check_rotation "$on_cfg" ) >/dev/null 2>&1; then
    die "self-test FAIL: rotation check passed with no goldens baked (must flag MISSING)"
  fi
  out="$( DS_GOLDEN_OUTPUT_DIR="$out_dir" check_rotation "$on_cfg" 2>&1 || true )"
  printf '%s\n' "$out" | grep -q 'repo=github.com/acme/monorepo branch=main MISSING' \
    || die "self-test FAIL: missing golden for main was not flagged MISSING"
  log "self-test: missing golden flagged (good — cannot back a session until first bake)"

  # --- (c) a FRESH golden is within the window ---
  # Synthesize the goldens this config's opted-in (repo, branch) pairs map to.
  local fresh_main fresh_rel
  fresh_main="$(golden_path "$out_dir" "github.com/acme/monorepo" "main")"
  fresh_rel="$(golden_path "$out_dir" "github.com/acme/monorepo" "release")"
  : > "$fresh_main"   # mtime = now ⇒ FRESH
  : > "$fresh_rel"
  log "self-test: freshly-baked goldens (mtime now) must be FRESH within a 24h window"
  out="$( DS_GOLDEN_OUTPUT_DIR="$out_dir" DS_GOLDEN_MAX_AGE_HOURS=24 check_rotation "$on_cfg" )" \
    || die "self-test FAIL: fresh goldens reported a rotation breach"
  printf '%s\n' "$out" | grep -q 'branch=main FRESH' \
    || die "self-test FAIL: fresh main golden not reported FRESH"
  printf '%s\n' "$out" | grep -q 'ROTATION SUMMARY ok=2 stale=0 missing=0' \
    || die "self-test FAIL: rotation summary did not show 2 fresh goldens"
  log "self-test: fresh goldens within the window (good)"

  # --- (b) a STALE golden (backdated past the window) is flagged + non-zero ---
  log "self-test: a STALE golden (mtime backdated 48h, window 24h) MUST be flagged and return non-zero"
  # Backdate the main golden's mtime 48h into the past.
  if ! touch -d '48 hours ago' "$fresh_main" 2>/dev/null; then
    touch -t "$(date -d '48 hours ago' +%Y%m%d%H%M.%S 2>/dev/null || date -v-48H +%Y%m%d%H%M.%S)" "$fresh_main"
  fi
  if ( DS_GOLDEN_OUTPUT_DIR="$out_dir" DS_GOLDEN_MAX_AGE_HOURS=24 check_rotation "$on_cfg" ) >/dev/null 2>&1; then
    die "self-test FAIL: stale golden (48h old, 24h window) did not return non-zero"
  fi
  out="$( DS_GOLDEN_OUTPUT_DIR="$out_dir" DS_GOLDEN_MAX_AGE_HOURS=24 check_rotation "$on_cfg" 2>&1 || true )"
  printf '%s\n' "$out" | grep -q 'branch=main STALE' \
    || die "self-test FAIL: stale golden was not flagged STALE"
  printf '%s\n' "$out" | grep -q 'ROTATION BREACH' \
    || die "self-test FAIL: stale golden did not surface a ROTATION BREACH"
  log "self-test: stale golden flagged + rotation breach reported (good — no instance outlives the window)"

  # --- (i) an UNROTATABLE golden (mtime in the FUTURE) is flagged + non-zero ---
  # RUNTIME == CLAIM: a present golden whose mtime is in the future yields a
  # NEGATIVE (now − mtime) age; without the UNROTATABLE branch it would never
  # satisfy `age > window` and would read FRESH forever — the exact silent pass
  # the public claim's ViolationUnrotatable models. Re-freshen main (so only the
  # future-dated golden is anomalous) and future-date release, then assert the
  # runtime flags UNROTATABLE, breaches, and — crucially — that the runtime
  # verdict TOKEN is byte-for-byte the claim's class string (single source).
  log "self-test: an UNROTATABLE golden (mtime in the FUTURE) MUST be flagged UNROTATABLE and return non-zero"
  : > "$fresh_main"   # mtime = now ⇒ FRESH again, so the breach isolates release
  if ! touch -d '48 hours' "$fresh_rel" 2>/dev/null; then
    touch -t "$(date -d '48 hours' +%Y%m%d%H%M.%S 2>/dev/null || date -v+48H +%Y%m%d%H%M.%S)" "$fresh_rel"
  fi
  if ( DS_GOLDEN_OUTPUT_DIR="$out_dir" DS_GOLDEN_MAX_AGE_HOURS=24 check_rotation "$on_cfg" ) >/dev/null 2>&1; then
    die "self-test FAIL: future-dated golden (UNROTATABLE) did not return non-zero"
  fi
  out="$( DS_GOLDEN_OUTPUT_DIR="$out_dir" DS_GOLDEN_MAX_AGE_HOURS=24 check_rotation "$on_cfg" 2>&1 || true )"
  printf '%s\n' "$out" | grep -q "branch=release UNROTATABLE \[$UNROTATABLE_VERDICT_CLASS\]" \
    || die "self-test FAIL: future-dated golden was not flagged UNROTATABLE with the verdict class token"
  printf '%s\n' "$out" | grep -q 'ROTATION SUMMARY ok=1 stale=0 missing=0 unrotatable=1' \
    || die "self-test FAIL: rotation summary did not count exactly 1 unrotatable + 1 ok"
  printf '%s\n' "$out" | grep -q 'ROTATION BREACH' \
    || die "self-test FAIL: unrotatable golden did not surface a ROTATION BREACH"
  # RUNTIME == CLAIM single-source cross-check: the runtime UNROTATABLE_VERDICT_CLASS
  # token MUST equal the public claim's ViolationUnrotatable class string in
  # goldenfreshness.go. Extract the Go const value and compare (the way
  # prebake_golden_path cross-checks the path derivation — one source, cannot drift).
  local claim_go="${HERE}/../../assurance/guardrail-conformance/goldenfreshness/goldenfreshness.go"
  if [ -r "$claim_go" ]; then
    local go_class
    go_class="$(awk -F'"' '/ViolationUnrotatable[[:space:]]+ViolationClass[[:space:]]*=/ { print $2; exit }' "$claim_go")"
    [ -n "$go_class" ] \
      || die "self-test FAIL: could not extract ViolationUnrotatable class from $claim_go (single-source check inconclusive)"
    [ "$go_class" = "$UNROTATABLE_VERDICT_CLASS" ] \
      || die "self-test FAIL: runtime UNROTATABLE token ($UNROTATABLE_VERDICT_CLASS) diverges from the public claim's ViolationUnrotatable ($go_class) — runtime != claim"
    log "self-test: runtime UNROTATABLE token == public claim's ViolationUnrotatable (good — runtime == claim, single source)"
  else
    warn "self-test: goldenfreshness.go not found beside images/golden ($claim_go) — skipped the runtime==claim token cross-check (verdict branch still asserted above)"
  fi
  # Restore release to a fresh mtime so later legs are not perturbed by the future date.
  : > "$fresh_rel"
  log "self-test: future-dated golden flagged UNROTATABLE + rotation breach (good — runtime == claim, no silent FRESH)"

  # --- global kill-switch: a disabled config has no goldens to rotate ---
  log "self-test: a globally-disabled config (enabled: false) reports no goldens to rotate"
  out="$( DS_GOLDEN_OUTPUT_DIR="$out_dir" check_rotation "$off_cfg" )" \
    || die "self-test FAIL: disabled config returned a rotation breach (should be a clean no-op)"
  printf '%s\n' "$out" | grep -q 'pre-bake globally disabled' \
    || die "self-test FAIL: disabled config did not report pre-bake off"
  log "self-test: disabled config is a clean rotation no-op (good — D12 dynamic default)"

  # --- (e) live re-bake refuses without the gate ---
  log "self-test: the live re-bake MUST refuse without DS_GOLDEN_BAKE_LIVE=1"
  if ( DS_GOLDEN_OUTPUT_DIR="$out_dir" DS_GOLDEN_BAKE_LIVE=0 rebuild "$on_cfg" 0 ) >/dev/null 2>&1; then
    die "self-test FAIL: live re-bake ran without DS_GOLDEN_BAKE_LIVE=1"
  fi
  log "self-test: live re-bake refused without the gate (good — no live qemu/libguestfs in CI/sandbox)"

  # --- (f) the SNAPSHOT leg drives snapshot-step.sh PER opted-in golden ---
  # Closes the previously-untested branch: the snapshot adapter (snapshot-step.sh)
  # is invoked once per opted-in (repo, branch) during a gated (no-live-tool)
  # re-bake, each emitting a dry-run PLAN, and it refuses live without the gate.
  log "self-test: the SNAPSHOT leg must invoke snapshot-step.sh once per opted-in golden (gated, no live tool)"
  out="$( DS_GOLDEN_OUTPUT_DIR="$out_dir" snapshot_leg "$on_cfg" 1 )"
  # one SNAPSHOT-LEG dispatch line per opted-in (repo, branch): main + release.
  printf '%s\n' "$out" | grep -q 'SNAPSHOT-LEG repo=github.com/acme/monorepo branch=main ->' \
    || die "self-test FAIL: snapshot leg did not drive snapshot-step.sh for main"
  printf '%s\n' "$out" | grep -q 'SNAPSHOT-LEG repo=github.com/acme/monorepo branch=release ->' \
    || die "self-test FAIL: snapshot leg did not drive snapshot-step.sh for release"
  # each opted-in golden's snapshot adapter emitted a dry-run PLAN through prebake.sh.
  printf '%s\n' "$out" | grep -q '^PLAN prebake repo=github.com/acme/monorepo branch=main$' \
    || die "self-test FAIL: snapshot leg's adapter did not emit a PLAN for main"
  printf '%s\n' "$out" | grep -q '^PLAN prebake repo=github.com/acme/monorepo branch=release$' \
    || die "self-test FAIL: snapshot leg's adapter did not emit a PLAN for release"
  # exactly the two opted-in pairs were snapshotted (the opted-out scratch repo is skipped).
  local snap_count
  snap_count="$(printf '%s\n' "$out" | grep -c 'SNAPSHOT-LEG repo=' || true)"
  [ "$snap_count" = 2 ] \
    || die "self-test FAIL: snapshot leg drove $snap_count adapters, expected 2 (one per opted-in golden)"
  printf '%s\n' "$out" | grep -q 'branch=scratch' \
    && die "self-test FAIL: snapshot leg drove the opted-out scratch repo (must not)"
  # the snapshot leg refuses a LIVE bake without the gate.
  if ( DS_GOLDEN_OUTPUT_DIR="$out_dir" DS_GOLDEN_BAKE_LIVE=0 snapshot_leg "$on_cfg" 0 ) >/dev/null 2>&1; then
    die "self-test FAIL: snapshot leg ran a live bake without DS_GOLDEN_BAKE_LIVE=1"
  fi
  # a globally-disabled config snapshots nothing.
  out="$( DS_GOLDEN_OUTPUT_DIR="$out_dir" snapshot_leg "$off_cfg" 1 )"
  printf '%s\n' "$out" | grep -q 'SNAPSHOT-LEG: pre-bake globally disabled' \
    || die "self-test FAIL: disabled config still drove a snapshot adapter"
  printf '%s\n' "$out" | grep -q '^PLAN ' \
    && die "self-test FAIL: disabled config emitted a snapshot PLAN (must not)"
  log "self-test: snapshot leg invoked snapshot-step.sh per opted-in golden, gated, none for opted-out/disabled (good)"

  # --- (g) per-branch > per-repo > defaults max_age_hours precedence ---
  # Synthesize (in the temp dir, never committed) a config whose three scopes set
  # DIFFERENT windows, then assert the resolved window picks the most specific.
  log "self-test: the rotation window honors per-branch > per-repo > defaults max_age_hours"
  local age_cfg="$T/maxage.config.yaml"
  cat > "$age_cfg" <<'YAML'
enabled: true
defaults:
  base_image: /var/lib/ds/golden/m0-base.raw
  output_dir: /var/lib/ds/golden/prebaked
  max_age_hours: 100
repos:
  - repo: github.com/acme/monorepo
    prebake: true
    max_age_hours: 50
    branch_overrides:
      release:
        max_age_hours: 10
    branches:
      - main
      - release
YAML
  # release: per-branch override (10) wins over per-repo (50) and defaults (100).
  [ "$(cfg_max_age_hours "$age_cfg" "github.com/acme/monorepo" "release")" = 10 ] \
    || die "self-test FAIL: per-branch max_age_hours override (10) did not win for release"
  # main: no per-branch override -> per-repo (50) wins over defaults (100).
  [ "$(cfg_max_age_hours "$age_cfg" "github.com/acme/monorepo" "main")" = 50 ] \
    || die "self-test FAIL: per-repo max_age_hours (50) did not win for main"
  # a repo with no per-repo value would fall to defaults (100): drive cfg_default_max_age.
  [ "$(cfg_default_max_age "$age_cfg")" = 100 ] \
    || die "self-test FAIL: defaults.max_age_hours (100) not read"

  # KEY-ORDER INVARIANCE: repo-level max_age_hours and branch_overrides are YAML
  # SIBLINGS, so their order is not fixed. A repo-level max_age_hours that appears
  # AFTER branch_overrides must still be read (regression guard: an inov flag that
  # never reset would skip it and the window would wrongly fall to defaults, a
  # freshness-SLA breach — a tighter per-repo window silently widened).
  local ord_cfg="$T/maxage-order.config.yaml"
  cat > "$ord_cfg" <<'YAML'
enabled: true
defaults:
  output_dir: /var/lib/ds/golden/prebaked
  max_age_hours: 100
repos:
  - repo: github.com/acme/monorepo
    prebake: true
    branch_overrides:
      release:
        max_age_hours: 10
    max_age_hours: 50
    branches:
      - main
      - release
YAML
  [ "$(cfg_max_age_hours "$ord_cfg" "github.com/acme/monorepo" "main")" = 50 ] \
    || die "self-test FAIL: per-repo max_age_hours (50) AFTER branch_overrides did not win for main (key-order regression)"
  [ "$(cfg_max_age_hours "$ord_cfg" "github.com/acme/monorepo" "release")" = 10 ] \
    || die "self-test FAIL: per-branch override (10) did not win for release with overrides-before-repo-key ordering"
  log "self-test: repo-level max_age_hours read regardless of order vs branch_overrides (good — key-order invariant)"

  # END-TO-END: a golden 30h old is FRESH under the repo's 50h main window but
  # STALE under release's 10h window — proving the per-pair window is applied.
  local age_out="$T/maxage_out"; mkdir -p "$age_out"
  local g_main g_rel
  g_main="$(golden_path "$age_out" "github.com/acme/monorepo" "main")"
  g_rel="$(golden_path "$age_out" "github.com/acme/monorepo" "release")"
  : > "$g_main"; : > "$g_rel"
  for g in "$g_main" "$g_rel"; do
    if ! touch -d '30 hours ago' "$g" 2>/dev/null; then
      touch -t "$(date -d '30 hours ago' +%Y%m%d%H%M.%S 2>/dev/null || date -v-30H +%Y%m%d%H%M.%S)" "$g"
    fi
  done
  out="$( DS_GOLDEN_OUTPUT_DIR="$age_out" check_rotation "$age_cfg" 2>&1 || true )"
  printf '%s\n' "$out" | grep -q 'branch=main FRESH age=30h <= window=50h' \
    || die "self-test FAIL: main golden (30h) not FRESH under its 50h per-repo window"
  printf '%s\n' "$out" | grep -q 'branch=release STALE age=30h > window=10h' \
    || die "self-test FAIL: release golden (30h) not STALE under its 10h per-branch window"
  log "self-test: per-(repo,branch) max_age_hours precedence applied end-to-end (good)"

  # --- (j) AWK-READER FUZZ MATRIX: key ORDER / INDENTation / whitespace drift ---
  # The stdlib awk readers (cfg_global_enabled, cfg_output_dir, cfg_opted_in_repos,
  # cfg_repo_branches, cfg_default_max_age, cfg_repo_max_age, cfg_branch_max_age)
  # parse the documented fixed-shape schema, but a real operator's config will
  # drift in benign ways: keys reordered (YAML maps are unordered), indentation
  # widened (2 vs 4 spaces), trailing whitespace, and blank lines. Hardening:
  # synthesize SEVERAL configs that all encode the SAME logical config but vary
  # ORDER + INDENT + whitespace, and assert EVERY reader extracts the IDENTICAL
  # canonical value from every variant. A reader that is order/indent-sensitive
  # would return a different value (or empty) for some variant and fail HERE,
  # before a freshness-SLA window is silently widened/dropped in production.
  #
  # Canonical expected values (single source — every assertion below references
  # these, never a re-typed literal):
  local FZ_REPO="github.com/acme/monorepo"
  local FZ_OUTPUT_DIR="/var/lib/ds/golden/prebaked"
  local FZ_ENABLED="true"
  local FZ_DEFAULT_MAX="100"
  local FZ_REPO_MAX="50"
  local FZ_RELEASE_MAX="10"
  local FZ_BRANCHES="main release"   # space-joined; the reader emits one per line
  local fuzz_dir="$T/awkfuzz"; mkdir -p "$fuzz_dir"

  # Variant 1 — the canonical example shape (2-space indent, schema key order).
  cat > "$fuzz_dir/v1-canonical.yaml" <<YAML
enabled: ${FZ_ENABLED}
defaults:
  output_dir: ${FZ_OUTPUT_DIR}
  max_age_hours: ${FZ_DEFAULT_MAX}
repos:
  - repo: ${FZ_REPO}
    prebake: true
    max_age_hours: ${FZ_REPO_MAX}
    branch_overrides:
      release:
        max_age_hours: ${FZ_RELEASE_MAX}
    branches:
      - main
      - release
YAML

  # Variant 2 — DEFAULTS block moved AFTER repos; defaults keys reordered;
  # enabled at the bottom. Top-level key ORDER must not matter.
  cat > "$fuzz_dir/v2-toplevel-reorder.yaml" <<YAML
repos:
  - repo: ${FZ_REPO}
    prebake: true
    branch_overrides:
      release:
        max_age_hours: ${FZ_RELEASE_MAX}
    branches:
      - main
      - release
    max_age_hours: ${FZ_REPO_MAX}
defaults:
  max_age_hours: ${FZ_DEFAULT_MAX}
  output_dir: ${FZ_OUTPUT_DIR}
enabled: ${FZ_ENABLED}
YAML

  # Variant 3 — WIDER indentation (4-space defaults keys, 8/12-space overrides
  # interior) and a deeper branches list. Indent DEPTH must not matter.
  cat > "$fuzz_dir/v3-wide-indent.yaml" <<YAML
enabled: ${FZ_ENABLED}
defaults:
    output_dir: ${FZ_OUTPUT_DIR}
    max_age_hours: ${FZ_DEFAULT_MAX}
repos:
  - repo: ${FZ_REPO}
    prebake: true
    max_age_hours: ${FZ_REPO_MAX}
    branch_overrides:
        release:
            max_age_hours: ${FZ_RELEASE_MAX}
    branches:
      - main
      - release
YAML

  # Variant 4 — BENIGN whitespace: extra inline spaces after colons + on list
  # dashes, trailing whitespace on several lines, and blank lines between blocks.
  # printf injects the trailing spaces a heredoc would otherwise strip in review.
  {
    printf 'enabled:   %s   \n\n' "$FZ_ENABLED"
    printf 'defaults:\n'
    printf '  output_dir:    %s\t\n' "$FZ_OUTPUT_DIR"
    printf '\n'
    printf '  max_age_hours:  %s \n' "$FZ_DEFAULT_MAX"
    printf '\n'
    printf 'repos:\n'
    printf '  - repo:   %s\n' "$FZ_REPO"
    printf '    prebake:  true \n'
    printf '    branch_overrides:\n'
    printf '      release:\n'
    printf '        max_age_hours:   %s \n' "$FZ_RELEASE_MAX"
    printf '    max_age_hours:  %s\n' "$FZ_REPO_MAX"
    printf '    branches:\n'
    printf '      -  main \n'
    printf '      -  release \n'
  } > "$fuzz_dir/v4-whitespace.yaml"

  local fz nfz=0
  for fz in "$fuzz_dir"/v*.yaml; do
    nfz=$(( nfz + 1 ))
    local v; v="$(basename "$fz")"
    [ "$(cfg_global_enabled "$fz")"  = "$FZ_ENABLED" ] \
      || die "self-test FAIL: awk-fuzz $v — cfg_global_enabled != $FZ_ENABLED (key-order/indent drift broke the reader)"
    [ "$(cfg_output_dir "$fz")"      = "$FZ_OUTPUT_DIR" ] \
      || die "self-test FAIL: awk-fuzz $v — cfg_output_dir != $FZ_OUTPUT_DIR"
    [ "$(cfg_opted_in_repos "$fz")"  = "$FZ_REPO" ] \
      || die "self-test FAIL: awk-fuzz $v — cfg_opted_in_repos != $FZ_REPO"
    # branches are emitted one-per-line; normalize to a space-joined list to compare.
    local got_branches; got_branches="$(cfg_repo_branches "$fz" "$FZ_REPO" | tr '\n' ' ')"
    got_branches="${got_branches% }"
    [ "$got_branches" = "$FZ_BRANCHES" ] \
      || die "self-test FAIL: awk-fuzz $v — cfg_repo_branches '[$got_branches]' != '[$FZ_BRANCHES]'"
    [ "$(cfg_default_max_age "$fz")" = "$FZ_DEFAULT_MAX" ] \
      || die "self-test FAIL: awk-fuzz $v — cfg_default_max_age != $FZ_DEFAULT_MAX"
    [ "$(cfg_repo_max_age "$fz" "$FZ_REPO")" = "$FZ_REPO_MAX" ] \
      || die "self-test FAIL: awk-fuzz $v — cfg_repo_max_age != $FZ_REPO_MAX (repo-level window silently widened/dropped)"
    [ "$(cfg_branch_max_age "$fz" "$FZ_REPO" release)" = "$FZ_RELEASE_MAX" ] \
      || die "self-test FAIL: awk-fuzz $v — cfg_branch_max_age(release) != $FZ_RELEASE_MAX (per-branch SLA silently lost)"
    # The resolved precedence must also hold per variant: release picks the tighter
    # per-branch window, main falls to the per-repo window.
    [ "$(cfg_max_age_hours "$fz" "$FZ_REPO" release)" = "$FZ_RELEASE_MAX" ] \
      || die "self-test FAIL: awk-fuzz $v — resolved release window != $FZ_RELEASE_MAX"
    [ "$(cfg_max_age_hours "$fz" "$FZ_REPO" main)" = "$FZ_REPO_MAX" ] \
      || die "self-test FAIL: awk-fuzz $v — resolved main window != $FZ_REPO_MAX"
  done
  [ "$nfz" -ge 4 ] \
    || die "self-test FAIL: awk-fuzz matrix exercised only $nfz variant(s), expected >= 4 (order/indent/whitespace)"
  log "self-test: awk readers extract identical values across $nfz key-order/indent/whitespace variants (good — parsing hardened against format drift)"

  # --- (h) the local golden_path mirror agrees with prebake.sh's canonical helper ---
  # Single source of truth: the rotation-check path MUST equal the bake's commit
  # path. Compare this script's golden_path against prebake.sh's own (sourced in
  # isolation by prebake_golden_path) for the opted-in pairs.
  log "self-test: the rotation golden_path must agree with prebake.sh's canonical helper (single source)"
  local pb_path local_path bp
  for bp in main release; do
    pb_path="$(prebake_golden_path "$out_dir" "github.com/acme/monorepo" "$bp")"
    local_path="$(golden_path "$out_dir" "github.com/acme/monorepo" "$bp")"
    [ -n "$pb_path" ] \
      || die "self-test FAIL: prebake.sh's golden_path could not be sourced for $bp (single-source check inconclusive)"
    [ "$pb_path" = "$local_path" ] \
      || die "self-test FAIL: rotation path ($local_path) diverges from prebake.sh's commit path ($pb_path) for $bp"
  done
  log "self-test: rotation path == prebake.sh commit path (good — single source, cannot diverge)"

  echo "nightly-rebuild: --self-test OK"
}

usage() {
  cat >&2 <<EOF
usage:
  $0 --config <cfg.yaml> [--dry-run]      # rotation report + re-bake (plan w/ --dry-run)
  $0 --config <cfg.yaml> --check-rotation # rotation/freshness verdict only (exit 3 on breach)
  $0 --self-test
With no --config the example config is used (global enabled: false ⇒ a no-op:
no goldens to rotate, nothing baked). DS_GOLDEN_MAX_AGE_HOURS sets the rotation
window (default 24h). The live re-bake is DS_GOLDEN_BAKE_LIVE-gated in prebake.sh
(a deferred manual operator/scheduled-runner step); this script never sets it.
EOF
  exit 1
}

main() {
  if [ "${1:-}" = "--self-test" ]; then self_test; return; fi
  local cfg="" dry_run=0 check_only=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --config)         cfg="$2"; shift 2 ;;
      --dry-run)        dry_run=1; shift ;;
      --check-rotation) check_only=1; shift ;;
      *) die "unknown argument: $1 (run with no args for usage)" ;;
    esac
  done
  # Default to the example config so a wired-but-unconfigured run is a clean
  # no-op (the example ships enabled: false) rather than an error.
  [ -n "$cfg" ] || cfg="$EXAMPLE_CONFIG"
  if [ "$check_only" = 1 ]; then
    check_rotation "$cfg"   # exits 3 on a rotation breach (monitor signal)
    return
  fi
  rebuild "$cfg" "$dry_run"
}

main "$@"
