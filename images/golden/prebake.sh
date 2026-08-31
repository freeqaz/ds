#!/usr/bin/env bash
# prebake.sh — CI-to-golden-image PRE-BAKE orchestration (doc 03 §6, D12).
#
# THE PRE-BAKE PATH (doc 03 §6)
# -----------------------------
# CI snapshots node_modules + build artifacts into the golden VM image PER
# REPO/BRANCH so a session created from that branch boots with dependencies
# already on disk — no network stampede, no cold build (doc 05 §5 "instant
# start", M2). The bake is shell over the D29 disk stack:
#
#   1. clone a throwaway golden overlay from the raw base (overlay-create.sh —
#      the same raw-base + per-session-qcow2 stack the session create path uses);
#   2. run the repo's install/build steps INSIDE that overlay to warm it
#      (node_modules on disk, build cache warm);
#   3. commit the warmed overlay as the per-repo golden image, written to the
#      configured output dir (one per repo+branch).
#
# OPT-IN, DEFAULT OFF (D12)
# -------------------------
# Pre-seeding is OPTIONAL and per-repo configurable. v0 environments stay
# DYNAMIC (no golden-image requirement, D12); pre-bake is the M2 optimization.
# This script bakes a (repo, branch) ONLY when the config (prebake.config.yaml,
# schema in prebake.config.example.yaml) has BOTH the global `enabled: true`
# AND a repos[] entry for that repo carrying `prebake: true`. An unconfigured
# repo — absent, opted out, or with the global switch off — is left UNTOUCHED:
# the script prints "skip" and exits 0 without invoking any bake step. This
# config-gating logic is what the --self-test proves offline.
#
# DS_GOLDEN_BAKE_LIVE GATE
# ------------------------
# Steps 1-3 above touch real on-disk images and (for the warm step) spin a
# libguestfs/qemu appliance. They run ONLY when DS_GOLDEN_BAKE_LIVE=1. Without
# it (CI, the sandbox) the script invokes NO live tools: it resolves the config,
# decides configured-vs-unconfigured, and (with --dry-run) prints the PLAN it
# WOULD execute. There is NO live claude/qemu(VM-run)/podman invocation anywhere
# in this script; the live leg is a deferred manual step on the operator host.
#
# Usage:
#   # Print the plan a configured (repo, branch) would drive — no live tools:
#   images/golden/prebake.sh --config <cfg.yaml> --repo <repo> --branch <branch> --dry-run
#   # LIVE bake (operator host, deferred manual step):
#   DS_GOLDEN_BAKE_LIVE=1 images/golden/prebake.sh --config <cfg.yaml> --repo <repo> --branch <branch>
#   # CI/sandbox config-gating regression against committed fixtures:
#   images/golden/prebake.sh --self-test
#
# Env:
#   DS_GOLDEN_BAKE_LIVE=1  enable the live clone/warm/commit legs (default: off).
#   QEMU_IMG               override qemu-img (default: $(command -v qemu-img)).
#   OVERLAY_CREATE         override the overlay-create.sh used for the clone leg
#                          (default: ../../vm/cow/overlay-create.sh).
#   VIRT_CUSTOMIZE         override virt-customize used for the in-overlay warm
#                          leg (default: $(command -v virt-customize)). libguestfs
#                          runs warm_steps INSIDE the overlay — it never boots a VM.
#   DS_GOLDEN_BASE_IMAGE   override the raw base the clone leg clones from
#                          (default: the config's defaults.base_image).
#   DS_GOLDEN_OUTPUT_DIR   override the committed-golden output dir
#                          (default: the config's defaults.output_dir).
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU_IMG="${QEMU_IMG:-$(command -v qemu-img || true)}"
OVERLAY_CREATE="${OVERLAY_CREATE:-${HERE}/../../vm/cow/overlay-create.sh}"

log() { printf 'prebake: %s\n' "$*"; }
die() { printf 'prebake: ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# APPEND-SAFE EXIT CLEANUP REGISTRY
#
# `trap ... EXIT` is LAST-WRITER-WINS: the second `trap` in a process silently
# REPLACES the first. This script had two independent arms each registering its
# own EXIT trap (the live-smoke synthetic config and the --self-test fake-tool
# sandbox); they never overlapped in practice, but any future arm registering a
# third would have dropped a prior one and leaked its temp state.
#
# ONE trap is installed here, once, at script scope. Every arm APPENDS its
# cleanup command to DS_PREBAKE_CLEANUPS via register_cleanup instead of calling
# `trap` itself, so registrations compose instead of clobbering.
#
# Semantics:
#   * cleanups run in REVERSE registration order (LIFO — inner arms unwind
#     before outer ones, the order nested temp state must be torn down in);
#   * each is best-effort (`|| true`): one failing cleanup can never strand the
#     rest, and cleanup failure never rewrites the script's exit status;
#   * the original exit status is captured first and re-returned, so `set -e`
#     failures still propagate their code to the caller.
# Callers pass a fully-expanded command string (expand NOW, at registration —
# a `local` variable referenced lazily is already gone when the trap fires).
# ---------------------------------------------------------------------------
DS_PREBAKE_CLEANUPS=()

register_cleanup() { DS_PREBAKE_CLEANUPS+=("$1"); }

_prebake_run_cleanups() {
  local _rc=$? _i
  for (( _i=${#DS_PREBAKE_CLEANUPS[@]} - 1; _i >= 0; _i-- )); do
    eval "${DS_PREBAKE_CLEANUPS[$_i]}" || true
  done
  return "$_rc"
}
trap _prebake_run_cleanups EXIT

# ---------------------------------------------------------------------------
# Config parsing.
#
# stdlib-only (no yq): the config is a small, fixed-shape YAML. A focused awk
# pass reads exactly the keys the gating logic needs. This is NOT a general YAML
# parser — it understands the documented schema (prebake.config.example.yaml)
# and nothing else; an unrecognized shape simply yields no match and the repo is
# treated as unconfigured (fail-closed: an unparsed repo is never baked).
# ---------------------------------------------------------------------------

# cfg_global_enabled <cfg> -> prints "true" iff the top-level `enabled:` is true.
# Only a top-level (column-0) `enabled:` counts — a nested per-repo `prebake:`
# key never satisfies the global switch.
cfg_global_enabled() {
  local cfg="$1"
  awk '
    /^enabled:[[:space:]]*true[[:space:]]*$/ { print "true"; exit }
  ' "$cfg"
}

# cfg_repo_state <cfg> <repo> -> prints the repo block state, one of:
#   "on"   — repos[] entry for <repo> with prebake: true
#   "off"  — repos[] entry for <repo> with prebake: false / omitted
#   ""     — <repo> not present in repos[] at all
#
# The repos[] list is a sequence of `- repo: <name>` blocks. We track the
# CURRENT block's repo name and its prebake flag; when the next `- repo:` (or
# EOF) is reached we emit the matched block's state. Indentation is the
# list-item dash plus two spaces, matching the example schema.
cfg_repo_state() {
  local cfg="$1" want="$2"
  awk -v want="$want" '
    # emit() prints the matched block state exactly once and marks us done so a
    # later flush (the next "- repo:" boundary, or END) cannot print again.
    function flush() {
      if (done) return
      if (cur != "" && cur == want) {
        print (pb ? "on" : "off")
        done = 1
        cur = ""
        return
      }
      cur = ""; pb = 0
    }
    # Start of a new list item: "  - repo: <name>"
    /^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/ {
      flush()
      if (done) next
      line = $0
      sub(/^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line)
      gsub(/"/, "", line)
      cur = line
      pb = 0
      next
    }
    # prebake flag inside the current block.
    /^[[:space:]]+prebake:[[:space:]]*true[[:space:]]*$/  { if (!done && cur != "") pb = 1; next }
    /^[[:space:]]+prebake:[[:space:]]*false[[:space:]]*$/ { if (!done && cur != "") pb = 0; next }
    END { flush() }
  ' "$cfg"
}

# cfg_repo_branches <cfg> <repo> -> prints the branch list for <repo>, one per
# line; empty if the repo has no `branches:` block (caller defaults to "main").
cfg_repo_branches() {
  local cfg="$1" want="$2"
  awk -v want="$want" '
    # Enter/leave the target repo block on each "- repo:" boundary.
    /^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line)
      gsub(/"/, "", line)
      inblk = (line == want)
      inbr = 0
      next
    }
    inblk && /^[[:space:]]+branches:[[:space:]]*$/ { inbr = 1; next }
    # A branch item: "    - <name>" (deeper than the repo dash). Leave the
    # branches list on any non-list, less-indented key.
    inblk && inbr && /^[[:space:]]*-[[:space:]]+/ {
      b = $0
      sub(/^[[:space:]]*-[[:space:]]+/, "", b)
      sub(/[[:space:]]*$/, "", b)
      gsub(/"/, "", b)
      print b
      next
    }
    inblk && inbr && /^[[:space:]]*[A-Za-z_]+:/ { inbr = 0 }
  ' "$cfg"
}

# ---------------------------------------------------------------------------
# Canonical golden-image slug — THE single source of truth (D-reconcile).
#
# A bake's per-(repo, branch) golden is written to / refreshed at ONE stable
# path under the output dir, and the rotation check (nightly-rebuild.sh) stats
# that SAME path to answer "how old is the golden this (repo, branch) clones
# from?". If the commit-output path and the rotation-check path ever diverged,
# a bake would refresh one file while rotation stat'd another — a freshly-baked
# golden could read STALE forever, or a stale one read FRESH. To make that
# divergence impossible, the canonical (repo, branch) → filename derivation lives
# HERE, in the bake orchestrator. nightly-rebuild.sh runs a byte-identical mirror
# of golden_slug/golden_path (it cannot source this file wholesale without
# clobbering its own HERE/log/die), and its --self-test pins that mirror to this
# canonical helper: it sources a main-stripped copy of prebake.sh in an isolated
# subshell and asserts the mirror's output equals this helper's for the same
# inputs, so a one-sided edit to either fails the self-test loudly — the two
# cannot drift silently.
#
# golden_slug <repo> <branch> -> "<repo-slashes-as-__>--<branch>.qcow2"
# A filesystem-safe slug of the (repo, branch): '/' → '__', ' ' → '_', so the
# same pair always maps to the same filename. The content-addressed image ID
# (IMAGE-IDENTITY.md) is a separate concern computed by the image pipeline; this
# is just the stable on-disk destination the bake writes and rotation stats.
golden_slug() {
  local repo="$1" branch="$2" slug
  slug="${repo}--${branch}"
  slug="${slug//\//__}"
  slug="${slug// /_}"
  printf '%s.qcow2' "$slug"
}

# golden_path <output_dir> <repo> <branch> -> the full committed-golden path.
# The bake writes/refreshes this exact path (step 3 commit) and the rotation
# check stats it — one derivation, no drift.
golden_path() {
  printf '%s/%s' "$1" "$(golden_slug "$2" "$3")"
}

# ---------------------------------------------------------------------------
# D133 / Option A content-addressed image_id — stamped alongside the committed
# golden at step-3 (IMAGE-IDENTITY.md, RATIFIED 2026-06-16; taskdb 01KTZS6F7V).
#
#   image_id = content_hash(repo, ref, env-spec hash, role-layer-set hash)
#
# over the SHARED RFC-8785 (JCS) / SHA-256 canonicalizer (doc 13 §5.1) — the SAME
# byte-format the policy-snapshot `content_hash` and the role document's
# `role_content_hash` (dataplane/crates/policy-core/src/role.rs) produce. There is
# ONE canonicalization spec across all three hashes, not three (the explicit
# non-goal of every prior identity row). CROSS-LANGUAGE AGREEMENT is load-bearing:
# the orchestrator independently records this same ID (D7, doc 15 §9), so the
# bake's stamp MUST equal what the shared canonicalizer produces for the same
# input. We reproduce the JCS canonical form for this FIXED-SHAPE tuple in
# self-contained shell + sha256sum (no build dependency) and PIN it with a
# committed test vector asserted in --self-test (image_id_test_vector below), so
# any drift from the canonical spec fails the self-test offline.
#
# Agreement argument (the bytes, not the tool): the canonical payload for the
# tuple is a JCS object with keys sorted lexicographically (env_spec_hash, ref,
# repo, role_layer_set_hash — already sorted), no insignificant whitespace,
# strings JCS-escaped, integers bare — identical to role.rs's JcsValue::to_jcs
# for an all-string object. SHA-256 over those exact bytes is FIPS 180-4, which
# `sha256sum` and the hand-rolled ds_contracts::snapshot_verify::sha256 compute
# bit-for-bit identically. So a Go/Rust producer forming the same JCS bytes and
# hashing them lands on the same hex digest as this stamp by construction.
#
# jcs_string <s> -> the RFC-8785 (JCS) JSON string token for <s> (with quotes).
# §3.2.2.2 escaping: the two-char escapes for the C0 controls that have them,
# \uXXXX (lowercase hex) for the rest, \" and \\, everything else literal. The
# image-id inputs are content-address slugs/hex (ASCII, no specials in practice),
# but the full escape rule is implemented so the form matches role.rs byte-for-byte
# for any input — a drift here would silently disagree with the shared canonicalizer.
jcs_string() {
  local s="$1" out='"' c i n=${#1} code
  for (( i = 0; i < n; i++ )); do
    c="${s:i:1}"
    case "$c" in
      '"')  out+='\"' ;;
      '\')  out+='\\' ;;
      $'\b') out+='\b' ;;
      $'\t') out+='\t' ;;
      $'\n') out+='\n' ;;
      $'\f') out+='\f' ;;
      $'\r') out+='\r' ;;
      *)
        printf -v code '%d' "'$c"
        if [ "$code" -lt 32 ] && [ "$code" -ge 0 ]; then
          out+="$(printf '\\u%04x' "$code")"
        else
          out+="$c"
        fi
        ;;
    esac
  done
  printf '%s"' "$out"
}

# role_layer_set_hash [<digest>...] -> the SHA-256 hex of the canonicalized,
# ORDER-INDEPENDENT resolved layer-digest set (IMAGE-IDENTITY.md §"Recommendation"
# step 1). The set is canonicalized by sorting digests lexicographically (a SET,
# not a list: two roles naming the same layers in any order MUST hash equal),
# rendered as a JCS array of JCS strings, and SHA-256'd. An EMPTY layer set (the
# roleless / layerless M0 case — `default` role, no image.layers[]) is the empty
# JCS array `[]`, a FIXED empty-set digest, so the role axis is INERT and the M0
# golden stamps the same image_id as today's (repo, ref, env-spec hash) —
# backward-identity-compatible. dedup (sort -u) so a repeated digest cannot change
# the set's identity.
role_layer_set_hash() {
  local sorted parts='' first=1 d
  if [ "$#" -gt 0 ]; then
    sorted="$(printf '%s\n' "$@" | LC_ALL=C sort -u)"
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      if [ "$first" = 1 ]; then first=0; else parts+=','; fi
      parts+="$(jcs_string "$d")"
    done <<EOF
$sorted
EOF
  fi
  printf '[%s]' "$parts" | sha256sum | cut -d' ' -f1
}

# The fixed empty-set role-layer-set digest — SHA-256 of the empty JCS array `[]`
# (the M0 roleless/layerless tail). Pinned as a constant so the inert-role-axis
# invariant is visible and the self-test can assert it directly; equals
# role_layer_set_hash with no arguments.
EMPTY_ROLE_LAYER_SET_HASH=4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945

# image_id_canonical_payload <repo> <ref> <env_spec_hash> <role_layer_set_hash>
# -> the produce-once RFC-8785 (JCS) canonical-JSON payload for the image-id tuple
# (IMAGE-IDENTITY.md §"Recommendation" step 2): a JCS object over the ordered
# tuple under the pinned mapping (keys lexicographically sorted — env_spec_hash,
# ref, repo, role_layer_set_hash are already in sorted order; absent ≡ default ≡
# omitted, and the empty-set tail is the explicit-presence worked example). These
# are the EXACT bytes the shared canonicalizer forms for this fixed-shape tuple.
image_id_canonical_payload() {
  local repo="$1" ref="$2" esh="$3" rls="$4"
  printf '{%s:%s,%s:%s,%s:%s,%s:%s}' \
    "$(jcs_string env_spec_hash)"       "$(jcs_string "$esh")" \
    "$(jcs_string ref)"                 "$(jcs_string "$ref")" \
    "$(jcs_string repo)"                "$(jcs_string "$repo")" \
    "$(jcs_string role_layer_set_hash)" "$(jcs_string "$rls")"
}

# compute_image_id <repo> <ref> <env_spec_hash> [<role-layer-digest>...]
# -> the content-addressed image_id: SHA-256 hex of the canonical tuple payload.
# The role-layer-set hash is derived from the (possibly empty) resolved layer
# digests, then folded into the tuple. With no layer digests this is the M0
# roleless ID (empty-set tail).
compute_image_id() {
  local repo="$1" ref="$2" esh="$3"; shift 3
  local rls; rls="$(role_layer_set_hash "$@")"
  image_id_canonical_payload "$repo" "$ref" "$esh" "$rls" | sha256sum | cut -d' ' -f1
}

# cfg_env_spec_hash <cfg> -> the defaults.env_spec_hash value (the third
# content-address input, the env-spec digest the orchestrator surface resolves;
# doc 15 §5.1 "(repo, ref, env_spec_hash) → image ID"). DS_GOLDEN_ENV_SPEC_HASH
# overrides it. Same column-2-under-top-level-`defaults:` extraction the other
# defaults helpers use. Empty if absent; the bake falls back to the documented
# zero sentinel below so the stamp is always well-defined offline.
cfg_env_spec_hash() {
  awk '
    /^defaults:[[:space:]]*$/ { ind = 1; next }
    /^[A-Za-z_]/ { ind = 0 }          # any new top-level key leaves defaults:
    ind && /^[[:space:]]+env_spec_hash:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]+env_spec_hash:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      print line; exit
    }
  ' "$1"
}

# Documented default env-spec hash for the roleless M0 stamp when neither
# DS_GOLDEN_ENV_SPEC_HASH nor defaults.env_spec_hash is set: the 64-zero sentinel
# (an unresolved/absent env-spec digest). A real bake supplies the resolved
# env-spec hash; the sentinel keeps the stamp deterministic and the plan
# inspectable offline without inventing a value that could collide with a real one.
PREBAKE_DEFAULT_ENV_SPEC_HASH=0000000000000000000000000000000000000000000000000000000000000000

# resolve_env_spec_hash [<cfg>] -> the env-spec hash for the stamp, honoring the
# DS_GOLDEN_ENV_SPEC_HASH override, then the config's defaults.env_spec_hash, then
# the zero sentinel. One resolution shared by emit_plan and live_bake (lockstep).
resolve_env_spec_hash() {
  local cfg="${1:-}" esh="${DS_GOLDEN_ENV_SPEC_HASH:-}"
  if [ -z "$esh" ] && [ -n "$cfg" ] && [ -f "$cfg" ]; then
    esh="$(cfg_env_spec_hash "$cfg")"
  fi
  [ -n "$esh" ] || esh="$PREBAKE_DEFAULT_ENV_SPEC_HASH"
  printf '%s' "$esh"
}

# image_id_sidecar_path <golden_path> -> the sidecar the step-3 commit writes the
# stamped image_id to, alongside the committed golden. The rotation/identity path
# reads this back (one stable derivation, like golden_path). `<golden>.image-id`.
image_id_sidecar_path() {
  printf '%s.image-id' "$1"
}

# cfg_output_dir <cfg> -> the defaults.output_dir value (column-2 under the
# top-level `defaults:` block), or empty if absent. Used so emit_plan can print
# the resolved commit path; DS_GOLDEN_OUTPUT_DIR overrides it for the plan, and
# a documented default backstops an absent key (same posture nightly-rebuild.sh
# uses — both read the same schema key).
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

# Documented default output dir, mirrored from prebake.config.example.yaml. Used
# only when the config carries no defaults.output_dir and DS_GOLDEN_OUTPUT_DIR is
# unset, so emit_plan always has a directory to resolve the commit path under.
PREBAKE_DEFAULT_OUTPUT_DIR=/var/lib/ds/golden/prebaked

# cfg_base_image <cfg> -> the defaults.base_image value (the raw M0 golden the
# bake clones a throwaway overlay from), or empty if absent. Same column-2-under-
# top-level-`defaults:` extraction as cfg_output_dir; the live clone leg resolves
# the base on the operator host at bake time (D29 raw-base + per-session-qcow2).
cfg_base_image() {
  awk '
    /^defaults:[[:space:]]*$/ { ind = 1; next }
    /^[A-Za-z_]/ { ind = 0 }          # any new top-level key leaves defaults:
    ind && /^[[:space:]]+base_image:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]+base_image:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      print line; exit
    }
  ' "$1"
}

# cfg_warm_steps <cfg> <repo> -> prints the install/build commands run INSIDE the
# cloned overlay to warm it, one per line. Resolution mirrors the schema's
# precedence (prebake.config.example.yaml): a per-repo `warm_steps:` block
# OVERRIDES the top-level `defaults.warm_steps:` for that repo; only when the
# repo declares no warm_steps of its own do the defaults apply. This is purely
# offline-computable (a focused awk pass over the documented schema), so the
# self-test pins it without any live tooling.
#
# Two passes keep the precedence explicit and the awk readable: first try the
# repo's own block; if that yields nothing, fall back to defaults.warm_steps.
cfg_warm_steps() {
  local cfg="$1" want="$2" steps
  steps="$(cfg_repo_warm_steps "$cfg" "$want")"
  if [ -n "$steps" ]; then
    printf '%s\n' "$steps"
    return 0
  fi
  cfg_defaults_warm_steps "$cfg"
}

# cfg_repo_warm_steps <cfg> <repo> -> the per-repo warm_steps[] list (empty if
# the repo block carries none). Scoped to the target repo's `- repo:` block the
# same way cfg_repo_branches scopes branches[]: enter the block on its `- repo:`
# boundary, capture `- <cmd>` list items under the block's `warm_steps:` key, and
# leave the list on any non-list, less-indented key.
cfg_repo_warm_steps() {
  local cfg="$1" want="$2"
  awk -v want="$want" '
    /^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      inblk = (line == want)
      inws = 0
      next
    }
    inblk && /^[[:space:]]+warm_steps:[[:space:]]*$/ { inws = 1; next }
    # A warm-step item: "    - <command>" (deeper than the repo dash). A quoted
    # command keeps its inner spaces; we strip only surrounding quotes/whitespace.
    inblk && inws && /^[[:space:]]*-[[:space:]]+/ {
      s = $0
      sub(/^[[:space:]]*-[[:space:]]+/, "", s)
      sub(/[[:space:]]*$/, "", s)
      sub(/^"/, "", s); sub(/"$/, "", s)
      print s
      next
    }
    # Leave the warm_steps list on any non-list key inside the block.
    inblk && inws && /^[[:space:]]*[A-Za-z_]+:/ { inws = 0 }
  ' "$cfg"
}

# cfg_defaults_warm_steps <cfg> -> the top-level defaults.warm_steps[] list. The
# fallback for a repo that declares no warm_steps of its own. Scoped to the
# top-level `defaults:` block (column-2 list under it), leaving the block on any
# new top-level key — the same defaults-scoping cfg_output_dir/cfg_base_image use.
cfg_defaults_warm_steps() {
  awk '
    /^defaults:[[:space:]]*$/ { ind = 1; inws = 0; next }
    /^[A-Za-z_]/ { ind = 0; inws = 0 }   # any new top-level key leaves defaults:
    ind && /^[[:space:]]+warm_steps:[[:space:]]*$/ { inws = 1; next }
    ind && inws && /^[[:space:]]*-[[:space:]]+/ {
      s = $0
      sub(/^[[:space:]]*-[[:space:]]+/, "", s)
      sub(/[[:space:]]*$/, "", s)
      sub(/^"/, "", s); sub(/"$/, "", s)
      print s
      next
    }
    ind && inws && /^[[:space:]]+[A-Za-z_]+:/ { inws = 0 }
  ' "$1"
}

# ---------------------------------------------------------------------------
# Plan: the offline-computable description of what a bake WOULD do. --dry-run
# prints it; the live leg executes the same steps in order.
# ---------------------------------------------------------------------------

# emit_plan <repo> <branch> [<cfg>] — print the dry-run plan for one
# (repo, branch). The plan is deterministic given (repo, branch) and the env
# defaults, so the self-test can assert on it without any live tooling. When a
# config is supplied (or DS_GOLDEN_OUTPUT_DIR is set) the plan PRINTS the
# resolved commit path so the bake's output path and the rotation-check path are
# visibly the same single derivation (golden_path).
emit_plan() {
  local repo="$1" branch="$2" cfg="${3:-}"
  local out_dir="${DS_GOLDEN_OUTPUT_DIR:-}"
  if [ -z "$out_dir" ] && [ -n "$cfg" ] && [ -f "$cfg" ]; then
    out_dir="$(cfg_output_dir "$cfg")"
  fi
  [ -n "$out_dir" ] || out_dir="$PREBAKE_DEFAULT_OUTPUT_DIR"
  local golden esh image_id sidecar
  golden="$(golden_path "$out_dir" "$repo" "$branch")"
  # The image_id stamp is offline-computable from (repo, ref, env-spec hash) +
  # the EMPTY role-layer-set tail (roleless M0 — no resolved tool layers in the
  # bake path; a roled bake folds the resolved digests in via compute_image_id).
  # Mirrors EXACTLY the live_bake step-3 stamp so plan and bake stay in lockstep.
  esh="$(resolve_env_spec_hash "$cfg")"
  image_id="$(compute_image_id "$repo" "$branch" "$esh")"
  sidecar="$(image_id_sidecar_path "$golden")"
  printf 'PLAN prebake repo=%s branch=%s\n' "$repo" "$branch"
  printf '  step 1 clone golden overlay from base via %s (D29 raw-base + per-session-qcow2)\n' "$(basename "${OVERLAY_CREATE}")"
  printf '  step 2 warm overlay: run repo install/build steps in the cloned overlay (node_modules + build cache)\n'
  printf '  step 3 commit warmed overlay as per-repo golden image at %s (one per repo+branch)\n' "$golden"
  printf '  step 3 stamp image_id=%s (content_hash(repo, ref, env-spec hash=%s, empty role-layer-set)) -> %s (D133/Option A, IMAGE-IDENTITY.md)\n' "$image_id" "$esh" "$sidecar"
  printf '  gate   DS_GOLDEN_BAKE_LIVE=%s (live qemu/libguestfs runs ONLY when =1; deferred manual step otherwise)\n' "${DS_GOLDEN_BAKE_LIVE:-0}"
}

# ---------------------------------------------------------------------------
# bake_one — the per-(repo, branch) entry point. Gating decision first, THEN
# either emit the plan (--dry-run) or execute the live legs (DS_GOLDEN_BAKE_LIVE).
# ---------------------------------------------------------------------------
bake_one() {
  local cfg="$1" repo="$2" branch="$3" dry_run="$4"
  [ -f "$cfg" ] || die "config not found: $cfg"

  # GATE 1: global kill-switch. Default OFF (D12).
  if [ "$(cfg_global_enabled "$cfg")" != "true" ]; then
    log "skip repo=${repo} branch=${branch} — pre-bake globally disabled (enabled: false; D12 dynamic default)"
    return 0
  fi

  # GATE 2: per-repo opt-in.
  local state; state="$(cfg_repo_state "$cfg" "$repo")"
  case "$state" in
    on)  : ;; # configured + opted in -> proceed to the bake path
    off) log "skip repo=${repo} branch=${branch} — repo present but prebake: false (opted out)"; return 0 ;;
    *)   log "skip repo=${repo} branch=${branch} — repo not configured (absent from repos[]; left untouched)"; return 0 ;;
  esac

  log "repo=${repo} branch=${branch} is configured for pre-bake (prebake: true)"

  if [ "$dry_run" = 1 ]; then
    emit_plan "$repo" "$branch" "$cfg"
    return 0
  fi

  live_bake "$repo" "$branch" "$cfg"
}

# VIRT_CUSTOMIZE — the libguestfs warm driver (default: $(command -v
# virt-customize)). virt-customize runs commands INSIDE a disk image via the
# libguestfs appliance — it mounts the image's filesystems in a tiny helper
# kernel and execs the commands against them, then unmounts. It NEVER boots the
# guest as a VM (no KVM domain, no qemu-system, no network namespace for the
# guest), so the warm leg lands node_modules + a warm build cache on the
# overlay's own clusters without the session-boot machinery — and without any
# claude/podman ever running. Overridable for the operator host / self-test.
VIRT_CUSTOMIZE="${VIRT_CUSTOMIZE:-$(command -v virt-customize || true)}"

# live_bake — the DS_GOLDEN_BAKE_LIVE-gated clone/warm/commit. NEVER runs in CI
# or the sandbox; this is the deferred manual step on the operator host. It
# executes the SAME three steps emit_plan prints, in the SAME order:
#   step 1 CLONE  — drive OVERLAY_CREATE to clone a throwaway golden overlay from
#                   the raw base (D29 raw-base + per-session-qcow2);
#   step 2 WARM   — run the repo's warm_steps INSIDE that overlay via libguestfs
#                   (virt-customize --run-command), so node_modules land on disk
#                   and the build cache warms — WITHOUT booting a VM;
#   step 3 COMMIT — qemu-img commit the warmed overlay down onto a fresh copy of
#                   the base and publish it as the per-repo golden at
#                   golden_path(out_dir, repo, branch) (one per repo+branch).
# The throwaway overlay is cleaned up on ANY failure (EXIT trap in the subshell
# the work runs in) so a half-baked overlay never lingers.
live_bake() {
  local repo="$1" branch="$2" cfg="${3:-}"

  # --- gate guards (the --self-test pins the refuses-without-gate behavior) ----
  [ "${DS_GOLDEN_BAKE_LIVE:-0}" = 1 ] \
    || die "live bake requires DS_GOLDEN_BAKE_LIVE=1 (the qemu/libguestfs clone/warm/commit legs are gated off in CI/sandbox; this is a deferred manual step on the operator host — use --dry-run to see the plan)"
  [ -n "${QEMU_IMG}" ] || die "qemu-img not found (set QEMU_IMG); the D29 clone leg needs it"
  [ -x "${OVERLAY_CREATE}" ] || die "overlay-create.sh not found/executable at ${OVERLAY_CREATE} (set OVERLAY_CREATE)"
  [ -n "${VIRT_CUSTOMIZE}" ] || die "virt-customize not found (set VIRT_CUSTOMIZE); the libguestfs warm leg needs it (it runs warm_steps IN-overlay without booting a VM)"

  # --- resolve the bake inputs from the config (offline-computed helpers) ------
  [ -n "$cfg" ] && [ -f "$cfg" ] || die "live bake needs a config to resolve base_image/warm_steps/output_dir"
  local base_image out_dir golden warm_steps env_spec_hash image_id sidecar
  base_image="${DS_GOLDEN_BASE_IMAGE:-$(cfg_base_image "$cfg")}"
  [ -n "$base_image" ] || die "no base_image resolved (set defaults.base_image in the config or DS_GOLDEN_BASE_IMAGE); the D29 clone leg needs the raw golden base"
  [ -f "$base_image" ] || die "base_image not found on disk: ${base_image} (the raw M0 golden must exist before the overlay clones onto it)"

  out_dir="${DS_GOLDEN_OUTPUT_DIR:-}"
  [ -n "$out_dir" ] || out_dir="$(cfg_output_dir "$cfg")"
  [ -n "$out_dir" ] || out_dir="$PREBAKE_DEFAULT_OUTPUT_DIR"
  golden="$(golden_path "$out_dir" "$repo" "$branch")"

  # --- resolve the D133 image_id stamp inputs (offline-computed; lockstep with
  # emit_plan's step-3 stamp line). The roleless M0 bake folds the EMPTY
  # role-layer-set tail (no resolved tool layers on this bake path), so the stamp
  # is content_hash(repo, ref, env-spec hash, empty-set) — backward-identity-
  # compatible with today's (repo, ref, env-spec hash) ID. A future roled bake
  # passes the resolved layer digests to compute_image_id.
  env_spec_hash="$(resolve_env_spec_hash "$cfg")"
  image_id="$(compute_image_id "$repo" "$branch" "$env_spec_hash")"
  sidecar="$(image_id_sidecar_path "$golden")"

  warm_steps="$(cfg_warm_steps "$cfg" "$repo")"
  [ -n "$warm_steps" ] || die "no warm_steps resolved for repo=${repo} (set warm_steps in the repo block or defaults); nothing would warm the overlay"

  # The throwaway overlay clones into the output dir alongside the golden; a PID-
  # tagged name keeps concurrent bakes from colliding. It is committed away and
  # removed at the end, and the EXIT trap removes it on any failure.
  #
  # Track whether WE freshly created out_dir so the failure path can clean it up
  # without ever touching a pre-existing (or now-populated) directory. If out_dir
  # already exists, created_out_root stays empty and the failure path leaves it
  # alone. If out_dir is absent, `mkdir -p` mints it AND any missing PARENT dirs
  # too; a leaf-only record would leave those freshly-minted empty parents behind
  # on failure. So we walk up from out_dir to the deepest EXISTING ancestor: the
  # last MISSING dir on that walk is created_out_root, the TOPMOST dir this bake is
  # about to create. The failure path rmdir's the fresh chain BOTTOM-UP from
  # out_dir to created_out_root. rmdir (not rm -rf) is deliberate: it refuses a
  # non-empty dir, so a concurrent bake that dropped its own artifact anywhere in
  # the chain halts the walk there and is never clobbered, and the happy path
  # (which removes nothing) is untouched.
  local created_out_root=""
  if [ ! -d "$out_dir" ]; then
    created_out_root="$out_dir"
    local _parent
    while :; do
      _parent="$(dirname -- "$created_out_root")"
      [ -d "$_parent" ] && break
      [ "$_parent" = "$created_out_root" ] && break   # hit filesystem root
      created_out_root="$_parent"
    done
    mkdir -p "$out_dir" || die "could not create output dir ${out_dir}"
  fi
  local overlay="${out_dir}/.bake-$(golden_slug "$repo" "$branch").$$.qcow2"

  log "live bake repo=${repo} branch=${branch}: base=${base_image} -> golden=${golden}"

  # Run the three legs in a subshell with a cleanup trap, so a failure at any
  # step removes the throwaway overlay (and any partial golden) rather than
  # leaving a half-baked artifact behind. die() inside the subshell exits the
  # subshell non-zero. If the subshell SUCCEEDS we return 0 to the caller; if it
  # FAILS we fall through to the failure path, which also rmdir's the just-created
  # EMPTY out_dir CHAIN (see created_out_root above) so a bake that freshly minted
  # the dir (and any missing parents) then failed leaves no empty persistent
  # directory behind, then re-raises the failure via die(). A pre-existing or
  # non-empty out_dir is left untouched.
  if (
    set -euo pipefail
    cleanup() { rm -f -- "$overlay"; }
    trap cleanup EXIT

    # --- step 1 CLONE: throwaway golden overlay from the raw base (D29) --------
    # Drive overlay-create.sh exactly like the session-create path: it qemu-img
    # creates a qcow2 whose read-only backing file is the raw base, asserts the
    # backing invariant, and chmods the base 0444. --force so a stale leftover
    # from a crashed prior bake is recreated rather than refused.
    log "step 1 clone golden overlay from base via $(basename "${OVERLAY_CREATE}") (D29 raw-base + per-session-qcow2)"
    QEMU_IMG="${QEMU_IMG}" "${OVERLAY_CREATE}" --base "${base_image}" --overlay "${overlay}" --force \
      || die "step 1 clone failed: overlay-create.sh could not clone ${overlay} from ${base_image}"

    # --- step 2 WARM: run warm_steps IN-overlay via libguestfs, no VM boot -----
    # virt-customize mounts the overlay's filesystems in the libguestfs appliance
    # and runs each warm step against them, then unmounts — writes land on the
    # overlay's own clusters (the base is never touched: qcow2 redirects writes,
    # and overlay-create chmod'd the base 0444). Each warm_steps[] entry becomes
    # one `--run-command`, executed IN ORDER (virt-customize preserves operation
    # order), so `npm ci` then `npm run build` warm node_modules + the build
    # cache. No VM is booted, no claude/podman runs.
    #
    # EGRESS CONTEXT (correction): these warm steps run in the libguestfs
    # APPLIANCE on the OPERATOR HOST — they are NOT a boundary-gated session VM
    # behind ds-dnsgate / ds-tlsproxy. The appliance inherits the operator host's
    # network context, so the warm leg BYPASSES the per-session egress gateway
    # entirely. Any network the warm steps need must therefore be fronted by the
    # operator host's own egress policy and pointed at the same D41 Nexus
    # pull-through cache URLs the golden bakes in — see docs/03 §6's operational
    # note on the pre-bake warm leg. (Deterministic warm_steps that hit only the
    # cache keep the bake reproducible and off the open internet.)
    log "step 2 warm overlay: run repo install/build steps in the cloned overlay (node_modules + build cache)"
    local -a vc_args=( -a "${overlay}" )
    local step
    while IFS= read -r step; do
      [ -n "$step" ] || continue
      log "  warm step: ${step}"
      vc_args+=( --run-command "$step" )
    done <<EOF
$warm_steps
EOF
    "${VIRT_CUSTOMIZE}" "${vc_args[@]}" \
      || die "step 2 warm failed: virt-customize could not run warm_steps in ${overlay} (no VM was booted; this is the libguestfs in-overlay leg)"

    # --- step 3 COMMIT: publish the warmed overlay as the per-repo golden ------
    # The warmed overlay is a delta ON TOP of the read-only raw base; the golden
    # a session clones from must be a SELF-CONTAINED raw image (overlay-create
    # backs every per-session overlay onto a raw base, -F raw). So we materialize
    # the golden as base ⊕ warmed-delta: start from a fresh copy of the base,
    # then `qemu-img commit` the overlay's clusters down onto it. Committing into
    # a private copy (not the shared base) keeps the shared base pristine for
    # every other (repo, branch). The publish is atomic-on-rename: build at a
    # temp path, then mv into place, so a reader/rotation-stat never sees a
    # half-written golden.
    log "step 3 commit warmed overlay as per-repo golden image at ${golden} (one per repo+branch)"
    local golden_tmp="${golden}.$$.tmp"
    cleanup() { rm -f -- "$overlay" "$golden_tmp"; }
    # Re-point the overlay's backing file at the private copy, then commit into
    # it. cp preserves the raw base bytes; qemu-img rebase -u re-labels the
    # backing pointer without rewriting data (the bytes are identical), and
    # commit folds the overlay delta down into the copy.
    cp -- "${base_image}" "${golden_tmp}" \
      || die "step 3 commit failed: could not copy base ${base_image} -> ${golden_tmp}"
    "${QEMU_IMG}" rebase -u -f qcow2 -F raw -b "${golden_tmp}" "${overlay}" \
      || die "step 3 commit failed: could not rebase ${overlay} onto the private base copy"
    "${QEMU_IMG}" commit "${overlay}" \
      || die "step 3 commit failed: qemu-img commit of ${overlay} onto ${golden_tmp} failed"
    mv -f -- "${golden_tmp}" "${golden}" \
      || die "step 3 commit failed: could not publish golden to ${golden}"

    # --- step 3 STAMP: write the D133/Option A content-addressed image_id -------
    # alongside the just-published golden (IMAGE-IDENTITY.md). image_id +
    # sidecar were resolved offline above and inherited into this subshell, so the
    # bytes stamped here are IDENTICAL to the emit_plan dry-run line (lockstep) and
    # equal what the shared RFC-8785(JCS)/SHA-256 canonicalizer (doc 13 §5.1)
    # produces for the same (repo, ref, env-spec hash, empty role-layer-set). The
    # orchestrator records this same ID independently (D7) and reads this sidecar
    # back on the rotation/identity path. Atomic-on-rename (temp then mv) so a
    # reader never sees a half-written stamp; cleanup widens to remove it on a
    # late failure between write and golden being final.
    local sidecar_tmp="${sidecar}.$$.tmp"
    cleanup() { rm -f -- "$overlay" "$golden_tmp" "$sidecar_tmp"; }
    printf '%s\n' "$image_id" >"$sidecar_tmp" \
      || die "step 3 stamp failed: could not write image_id to ${sidecar_tmp}"
    mv -f -- "${sidecar_tmp}" "${sidecar}" \
      || die "step 3 stamp failed: could not publish image-id sidecar to ${sidecar}"

    log "step 3 stamp image_id=${image_id} -> ${sidecar} (content_hash(repo, ref, env-spec hash=${env_spec_hash}, empty role-layer-set); D133/Option A)"
    log "live bake OK: published golden ${golden} (repo=${repo} branch=${branch})"
  ); then
    return 0
  fi
  # Failure path: the subshell's EXIT trap already removed the throwaway overlay
  # and any partial golden. If THIS bake freshly created out_dir (and possibly
  # missing parents), rmdir the fresh chain BOTTOM-UP from the leaf up to
  # created_out_root so a failed bake never leaves empty persistent directories.
  # rmdir refuses a non-empty dir: a concurrent bake's artifact makes that dir
  # (and every ancestor above it) non-empty, so the walk HALTS at the first
  # non-empty dir and clobbers nothing. A pre-existing out_dir (created_out_root
  # empty) is left entirely untouched.
  if [ -n "$created_out_root" ]; then
    local _d="$out_dir"
    while :; do
      rmdir -- "$_d" 2>/dev/null || break   # refuses non-empty: stop, never clobber
      [ "$_d" = "$created_out_root" ] && break
      [ "$_d" = "/" ] && break
      _d="$(dirname -- "$_d")"
    done
  fi
  die "live bake failed for repo=${repo} branch=${branch} (throwaway overlay cleaned up)"
}

# ---------------------------------------------------------------------------
# live_smoke — the OPTIONAL, DS_GOLDEN_BAKE_LIVE-gated operator-host bake SMOKE.
#
# This is the offline-un-runnable end-to-end check that the proven bake
# procedure (images/golden/README.md "DS_GOLDEN_BAKE_LIVE bake smoke" runbook)
# actually produces a session-cloneable golden on a real operator host. It
# drives the SAME live_bake() the CI/snapshot paths defer to, against a real
# raw base, with a TRIVIAL warm_steps of ["true"] (a no-op warm — we are proving
# the clone -> warm -> commit -> publish plumbing + the self-contained-raw
# invariant, NOT a real dependency warm). It then asserts the published golden
# is a SELF-CONTAINED raw-backed image a session overlay can clone from, i.e. the
# overlay-create `-F raw` invariant: a fresh per-session overlay must be able to
# back onto the published golden with `-F raw` and no missing backing chain.
#
# It NEVER auto-runs: like live_bake it REFUSES without DS_GOLDEN_BAKE_LIVE=1, so
# --self-test (CI/sandbox) can assert the refusal without spinning any live tool.
# On the operator host an operator runs it explicitly with the gate set; it is a
# deferred manual step, identical in spirit to the live_bake leg.
#
# Inputs (all operator-host paths; no committed fixtures — there is no raw base
# in the repo, by design):
#   --base   <m0-base.raw>   the real raw M0 golden base (defaults to
#                            DS_GOLDEN_BASE_IMAGE).
#   --out    <dir>           a scratch output dir for the smoke golden (defaults
#                            to DS_GOLDEN_OUTPUT_DIR).
# A synthetic (repo, branch) of ds-smoke/smoke @ smoke keeps the smoke golden
# from colliding with any real opted-in golden.
live_smoke() {
  local base="${DS_GOLDEN_BASE_IMAGE:-}" out="${DS_GOLDEN_OUTPUT_DIR:-}"
  while [ $# -gt 0 ]; do
    case "$1" in
      --base) base="$2"; shift 2 ;;
      --out)  out="$2";  shift 2 ;;
      *) die "live-smoke: unknown argument: $1" ;;
    esac
  done

  # Gate FIRST, before any path/tool resolution, so --self-test's refuses-without
  # -gate assertion fires deterministically with no live dependency present.
  [ "${DS_GOLDEN_BAKE_LIVE:-0}" = 1 ] \
    || die "live-smoke requires DS_GOLDEN_BAKE_LIVE=1 (the clone/warm/commit/publish legs are gated off in CI/sandbox; this is a deferred manual operator-host step — see images/golden/README.md)"
  [ -n "$base" ] || die "live-smoke: no base image (pass --base or set DS_GOLDEN_BASE_IMAGE) — the real raw M0 golden base"
  [ -f "$base" ] || die "live-smoke: base image not found on disk: ${base}"
  [ -n "$out" ]  || die "live-smoke: no output dir (pass --out or set DS_GOLDEN_OUTPUT_DIR)"
  [ -n "${QEMU_IMG}" ] || die "live-smoke: qemu-img not found (set QEMU_IMG)"
  [ -x "${OVERLAY_CREATE}" ] || die "live-smoke: overlay-create.sh not found/executable at ${OVERLAY_CREATE} (set OVERLAY_CREATE)"

  local repo="ds-smoke/smoke" branch="smoke"
  local golden; golden="$(golden_path "$out" "$repo" "$branch")"

  log "live-smoke: bake ds-smoke/smoke @ smoke from base=${base} -> ${golden} (warm_steps=[true])"

  # Drive the SAME live_bake() the production paths use, via a tiny synthetic
  # config carrying the trivial ["true"] warm step. mktemp keeps it off the repo;
  # an EXIT trap removes it. DS_GOLDEN_BASE_IMAGE / DS_GOLDEN_OUTPUT_DIR pin the
  # base + output dir so live_bake resolves exactly the smoke paths.
  local smoke_cfg; smoke_cfg="$(mktemp "${TMPDIR:-/tmp}/prebake-smoke.XXXXXX.yaml")" \
    || die "live-smoke: could not mktemp a smoke config"
  # APPEND (never `trap ... EXIT` directly): the single script-scope EXIT trap
  # runs every registered cleanup, so this one cannot clobber (or be clobbered
  # by) another arm's. The path is expanded NOW — `smoke_cfg` is `local` and is
  # already out of scope by the time the trap fires.
  register_cleanup "rm -f -- '$smoke_cfg'"
  cat >"$smoke_cfg" <<YAML
# SYNTHETIC live-smoke config — generated by prebake.sh live_smoke (not committed).
enabled: true
defaults:
  base_image: ${base}
  output_dir: ${out}
  warm_steps:
    - "true"
repos:
  - repo: ${repo}
    prebake: true
    branches:
      - ${branch}
    warm_steps:
      - "true"
YAML

  DS_GOLDEN_BASE_IMAGE="$base" DS_GOLDEN_OUTPUT_DIR="$out" \
    live_bake "$repo" "$branch" "$smoke_cfg" \
    || die "live-smoke: live_bake failed — see the step that died above"

  [ -f "$golden" ] || die "live-smoke: published golden missing at ${golden} after a reportedly-OK bake"

  # --- the self-contained-raw assertion: a session overlay can clone from it ---
  # The published golden must be a SELF-CONTAINED raw-backed image: commit folded
  # the warmed delta down onto a private copy of the raw base, so the golden has
  # NO qcow2 backing chain of its own and a per-session overlay can back onto it
  # with `-F raw`. Prove it the way the session-create path does — drive
  # overlay-create.sh with `-F raw` (its own backing-format invariant) against
  # the golden; a successful clone IS the proof the golden is session-cloneable.
  local probe="${out}/.smoke-probe.$$.qcow2"
  log "live-smoke: assert a session overlay can clone from the golden (overlay-create -F raw invariant)"
  if QEMU_IMG="${QEMU_IMG}" "${OVERLAY_CREATE}" --base "${golden}" --overlay "${probe}" --force; then
    rm -f -- "$probe"
    log "live-smoke OK: published golden ${golden} is a self-contained raw-backed image a session overlay can clone from"
  else
    rm -f -- "$probe"
    die "live-smoke: session overlay could NOT clone from the published golden ${golden} (self-contained-raw invariant violated)"
  fi
}

# ---------------------------------------------------------------------------
# Self-test: prove the config-gating logic offline against committed fixtures.
# Asserts: a configured repo drives the bake (dry-run plan emitted), and an
# unconfigured repo is skipped/untouched. Then, under a fully OFFLINE fake-tool
# harness (PATH-stub overlay-create/qemu-img/virt-customize via the existing
# OVERLAY_CREATE/QEMU_IMG/VIRT_CUSTOMIZE overrides), drives live_bake to
# forced-SUCCESS and forced-FAILURE and asserts exit 0 vs non-zero PLUS
# rmdir-on-failure of the freshly-created dir chain (incl. the parent-chain case
# and the concurrent-artifact-never-clobbered case) / preserved-on-success. No
# live qemu/libguestfs, no VM boot, no network — every arm sets DS_GOLDEN_BAKE_LIVE
# ONLY inside its own sandboxed subshell.
# ---------------------------------------------------------------------------
self_test() {
  local fx="${HERE}/prebake_selftest"
  local on_cfg="${fx}/configured.config.yaml"
  local off_cfg="${fx}/disabled.config.yaml"
  [ -f "$on_cfg" ]  || die "self-test fixture missing: $on_cfg"
  [ -f "$off_cfg" ] || die "self-test fixture missing: $off_cfg"

  log "self-test: a CONFIGURED repo (enabled + prebake:true) must emit a dry-run PLAN"
  local out
  out="$(bake_one "$on_cfg" "github.com/acme/monorepo" "main" 1)"
  printf '%s\n' "$out" | grep -q '^PLAN prebake repo=github.com/acme/monorepo branch=main$' \
    || die "self-test FAIL: configured repo did not emit the expected PLAN header"
  printf '%s\n' "$out" | grep -q 'step 1 clone golden overlay from base' \
    || die "self-test FAIL: plan missing the clone step"
  printf '%s\n' "$out" | grep -q 'step 2 warm overlay' \
    || die "self-test FAIL: plan missing the warm step"
  printf '%s\n' "$out" | grep -q 'step 3 commit warmed overlay as per-repo golden image' \
    || die "self-test FAIL: plan missing the commit step"
  printf '%s\n' "$out" | grep -q 'DS_GOLDEN_BAKE_LIVE=0' \
    || die "self-test FAIL: plan did not record the DS_GOLDEN_BAKE_LIVE gate as off"
  log "self-test: configured repo drove the bake plan (good)"

  # --- the plan PRINTS the resolved commit path from the canonical slug helper ---
  # The single-source-of-truth derivation: the commit step prints the exact path
  # golden_path() resolves, so the bake's output path and the rotation-check path
  # (nightly-rebuild.sh, which delegates to this same helper) cannot diverge.
  log "self-test: the dry-run PLAN must print the resolved commit path from golden_path()"
  local exp_path
  exp_path="$(golden_path "$(cfg_output_dir "$on_cfg")" "github.com/acme/monorepo" "main")"
  [ -n "$exp_path" ] || die "self-test FAIL: golden_path() resolved an empty path"
  printf '%s\n' "$out" | grep -qF "commit warmed overlay as per-repo golden image at ${exp_path}" \
    || die "self-test FAIL: plan did not print the resolved commit path ${exp_path}"
  [ "$(golden_slug 'github.com/acme/monorepo' 'main')" = 'github.com__acme__monorepo--main.qcow2' ] \
    || die "self-test FAIL: golden_slug did not produce the canonical filesystem-safe slug"
  log "self-test: plan prints the resolved commit path from the canonical slug helper (good)"

  # DS_GOLDEN_OUTPUT_DIR overrides the config's output_dir in the printed path.
  log "self-test: DS_GOLDEN_OUTPUT_DIR overrides the resolved commit path in the plan"
  out="$( DS_GOLDEN_OUTPUT_DIR=/tmp/ds-plan-override bake_one "$on_cfg" "github.com/acme/monorepo" "main" 1 )"
  printf '%s\n' "$out" | grep -qF "golden image at /tmp/ds-plan-override/github.com__acme__monorepo--main.qcow2" \
    || die "self-test FAIL: DS_GOLDEN_OUTPUT_DIR did not override the resolved commit path"
  log "self-test: output-dir override reflected in the plan path (good)"

  log "self-test: an UNCONFIGURED repo (absent from repos[]) must be SKIPPED, untouched"
  out="$(bake_one "$on_cfg" "github.com/acme/not-listed" "main" 1)"
  printf '%s\n' "$out" | grep -q 'not configured (absent from repos\[\]; left untouched)' \
    || die "self-test FAIL: unconfigured repo was not skipped/untouched"
  printf '%s\n' "$out" | grep -q '^PLAN ' \
    && die "self-test FAIL: unconfigured repo emitted a bake PLAN (must not)"
  log "self-test: unconfigured repo skipped, no plan emitted (good)"

  log "self-test: an OPTED-OUT repo (prebake: false) must be SKIPPED"
  out="$(bake_one "$on_cfg" "github.com/acme/scratch" "main" 1)"
  printf '%s\n' "$out" | grep -q "prebake: false (opted out)" \
    || die "self-test FAIL: opted-out repo was not skipped"
  printf '%s\n' "$out" | grep -q '^PLAN ' \
    && die "self-test FAIL: opted-out repo emitted a bake PLAN (must not)"
  log "self-test: opted-out repo skipped (good)"

  log "self-test: the GLOBAL kill-switch (enabled: false) must skip even an opted-in repo"
  out="$(bake_one "$off_cfg" "github.com/acme/monorepo" "main" 1)"
  printf '%s\n' "$out" | grep -q "pre-bake globally disabled" \
    || die "self-test FAIL: global kill-switch did not skip an otherwise-opted-in repo"
  printf '%s\n' "$out" | grep -q '^PLAN ' \
    && die "self-test FAIL: globally-disabled config emitted a bake PLAN (must not)"
  log "self-test: global kill-switch skips opted-in repo (good — default OFF, D12)"

  log "self-test: branch enumeration reads the configured branches[] list"
  local branches; branches="$(cfg_repo_branches "$on_cfg" "github.com/acme/monorepo")"
  printf '%s\n' "$branches" | grep -qx 'main'    || die "self-test FAIL: branch 'main' not enumerated"
  printf '%s\n' "$branches" | grep -qx 'release' || die "self-test FAIL: branch 'release' not enumerated"
  log "self-test: branches enumerated (main, release)"

  # --- warm_steps / base_image extraction (offline inputs the live legs use) ---
  # The live bake resolves base_image + warm_steps from the config before it
  # touches any image; that resolution is pure config parsing, so we pin it here
  # without any live qemu/libguestfs. A per-repo warm_steps block OVERRIDES the
  # top-level defaults.warm_steps; absent a repo block, defaults apply.
  log "self-test: the live bake resolves defaults.base_image from the config (the D29 clone source)"
  [ "$(cfg_base_image "$on_cfg")" = '/var/lib/ds/golden/m0-base.raw' ] \
    || die "self-test FAIL: cfg_base_image did not resolve defaults.base_image"

  log "self-test: a repo's OWN warm_steps block overrides defaults.warm_steps"
  local ws; ws="$(cfg_warm_steps "$on_cfg" "github.com/acme/monorepo")"
  printf '%s\n' "$ws" | grep -qx 'pnpm install --frozen-lockfile' \
    || die "self-test FAIL: per-repo warm_steps missing 'pnpm install --frozen-lockfile'"
  printf '%s\n' "$ws" | grep -qx 'pnpm -r build' \
    || die "self-test FAIL: per-repo warm_steps missing 'pnpm -r build'"
  printf '%s\n' "$ws" | grep -qx 'npm ci' \
    && die "self-test FAIL: per-repo warm_steps leaked the defaults (override must win)"
  # Order is load-bearing (install before build): assert the first line is install.
  [ "$(printf '%s\n' "$ws" | sed -n 1p)" = 'pnpm install --frozen-lockfile' ] \
    || die "self-test FAIL: per-repo warm_steps did not preserve install-before-build order"
  log "self-test: per-repo warm_steps override resolved in order (good)"

  log "self-test: a repo with NO warm_steps block falls back to defaults.warm_steps"
  # github.com/acme/scratch is opted-out and declares no warm_steps -> defaults.
  local dws; dws="$(cfg_warm_steps "$on_cfg" "github.com/acme/scratch")"
  printf '%s\n' "$dws" | grep -qx 'npm ci'        || die "self-test FAIL: defaults fallback missing 'npm ci'"
  printf '%s\n' "$dws" | grep -qx 'npm run build' || die "self-test FAIL: defaults fallback missing 'npm run build'"
  printf '%s\n' "$dws" | grep -qx 'pnpm -r build' \
    && die "self-test FAIL: defaults fallback leaked the monorepo's per-repo warm_steps"
  log "self-test: defaults.warm_steps fallback resolved (good)"

  # --- D133 image_id stamp: PIN the canonical test vector (cross-language drift) -
  # CROSS-LANGUAGE AGREEMENT GUARD. The orchestrator records this same image_id
  # independently (D7, doc 15 §9) via the shared RFC-8785(JCS)/SHA-256
  # canonicalizer (doc 13 §5.1; the policy-core role_content_hash / policy-snapshot
  # content_hash machinery). This stamp MUST equal that. We pin a KNOWN
  # (repo, ref, env-spec hash, empty role-layer-set) -> expected image_id vector;
  # any drift of our reproduced JCS canonical form from the shared spec — a changed
  # key order, an escaping bug, a tuple-shape edit — flips this digest and fails the
  # self-test OFFLINE, before a divergent stamp can ship.
  #
  # The vector: repo=github.com/acme/monorepo, ref=main, env-spec hash=<64 zeros>,
  # EMPTY role-layer-set. Canonical payload (keys lexicographically sorted, no
  # whitespace, strings JCS-escaped):
  #   {"env_spec_hash":"0…0","ref":"main","repo":"github.com/acme/monorepo",
  #    "role_layer_set_hash":"4f53cda1…b945"}
  # role_layer_set_hash for the empty set = SHA-256("[]") = 4f53cda1…b945, and the
  # image_id = SHA-256(payload).
  log "self-test: the EMPTY role-layer-set hashes to the fixed empty-set digest (role axis inert)"
  [ "$(role_layer_set_hash)" = "$EMPTY_ROLE_LAYER_SET_HASH" ] \
    || die "self-test FAIL: empty role-layer-set hash drifted from the fixed empty-set digest"
  [ "$EMPTY_ROLE_LAYER_SET_HASH" = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945' ] \
    || die "self-test FAIL: the pinned empty-set digest (SHA-256 of the JCS empty array) drifted"

  log "self-test: image_id matches the committed canonical test vector (cross-language drift guard)"
  local exp_image_id='7111af2208b612a6783c8861d3482d41ef7b1d5e01cfd5291e3a792f0c4636c6'
  local exp_payload='{"env_spec_hash":"0000000000000000000000000000000000000000000000000000000000000000","ref":"main","repo":"github.com/acme/monorepo","role_layer_set_hash":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"}'
  local zero64='0000000000000000000000000000000000000000000000000000000000000000'
  # (i) the canonical payload bytes match the spec byte-for-byte (keys sorted, no
  # whitespace, JCS strings) — this is what a Go/Rust producer must also form.
  [ "$(image_id_canonical_payload 'github.com/acme/monorepo' 'main' "$zero64" "$EMPTY_ROLE_LAYER_SET_HASH")" = "$exp_payload" ] \
    || die "self-test FAIL: image_id canonical payload drifted from the pinned JCS bytes (cross-language canonicalizer disagreement)"
  # (ii) the full stamp (payload -> SHA-256) matches the pinned vector.
  [ "$(compute_image_id 'github.com/acme/monorepo' 'main' "$zero64")" = "$exp_image_id" ] \
    || die "self-test FAIL: stamped image_id drifted from the committed canonical test vector ${exp_image_id}"
  # (iii) the role-layer-set is ORDER-INDEPENDENT (a set, not a list): the same
  # layers in any order hash equal (IMAGE-IDENTITY.md §step 1).
  [ "$(role_layer_set_hash 'images:layer/b@sha256:bbb' 'images:layer/a@sha256:aaa')" \
    = "$(role_layer_set_hash 'images:layer/a@sha256:aaa' 'images:layer/b@sha256:bbb')" ] \
    || die "self-test FAIL: role-layer-set hash is order-dependent (must be a set, not a list)"
  # (iv) backward-identity-compat: a roleless bake (no layer digests) folds the
  # EMPTY-set tail, so the M0 image_id is exactly the empty-set-tail ID — the role
  # axis never changes a roleless create's identity.
  [ "$(compute_image_id 'github.com/acme/monorepo' 'main' "$zero64")" \
    = "$(image_id_canonical_payload 'github.com/acme/monorepo' 'main' "$zero64" "$EMPTY_ROLE_LAYER_SET_HASH" | sha256sum | cut -d' ' -f1)" ] \
    || die "self-test FAIL: roleless compute_image_id is not the empty-set-tail ID (backward-identity-compat broken)"
  log "self-test: image_id matches the committed vector; empty-set tail + order-independence + M0 compat hold (good)"

  log "self-test: the dry-run PLAN must carry the step-3 image_id stamp line"
  # The plan's step-3 stamp must print the SAME image_id the live bake stamps
  # (lockstep). Pin the env-spec hash via the override so the plan's stamp equals
  # the committed vector; the line names the sidecar path the bake writes.
  local plan_out
  plan_out="$( DS_GOLDEN_ENV_SPEC_HASH="$zero64" bake_one "$on_cfg" 'github.com/acme/monorepo' 'main' 1 )"
  printf '%s\n' "$plan_out" | grep -qF "step 3 stamp image_id=${exp_image_id}" \
    || die "self-test FAIL: plan did not carry the step-3 image_id stamp matching the committed vector"
  printf '%s\n' "$plan_out" | grep -qF "$(image_id_sidecar_path "$(golden_path "$(cfg_output_dir "$on_cfg")" 'github.com/acme/monorepo' 'main')")" \
    || die "self-test FAIL: plan's step-3 stamp did not name the image-id sidecar path"
  log "self-test: plan step-3 stamp carries the committed image_id + sidecar path (good — lockstep with live_bake)"

  log "self-test: the live bake leg must REFUSE without DS_GOLDEN_BAKE_LIVE=1"
  # Subshell isolates the die() exit so set -e does not propagate it here.
  if ( DS_GOLDEN_BAKE_LIVE=0 bake_one "$on_cfg" "github.com/acme/monorepo" "main" 0 ) >/dev/null 2>&1; then
    die "self-test FAIL: live bake ran without DS_GOLDEN_BAKE_LIVE=1"
  fi
  log "self-test: live bake refused without the gate (good — no live qemu/libguestfs in CI/sandbox)"

  log "self-test: the optional live-smoke leg must ALSO REFUSE without DS_GOLDEN_BAKE_LIVE=1"
  # The smoke gates BEFORE resolving any base/tool, so the refusal is deterministic
  # in CI/sandbox even with no raw base present. Subshell isolates the die() exit.
  if ( DS_GOLDEN_BAKE_LIVE=0 live_smoke --base /nonexistent/m0-base.raw --out /tmp/ds-smoke ) >/dev/null 2>&1; then
    die "self-test FAIL: live-smoke ran without DS_GOLDEN_BAKE_LIVE=1"
  fi
  log "self-test: live-smoke refused without the gate (good — never auto-runs in CI/sandbox)"

  # --- OFFLINE fake-tool live_bake arms: exit code + created-dir cleanup ---------
  # Everything below drives the REAL live_bake() clone/warm/commit path with the
  # qemu/libguestfs tools swapped for PATH-stub fakes (the OVERLAY_CREATE /
  # QEMU_IMG / VIRT_CUSTOMIZE overrides), so no VM boots, no libguestfs appliance
  # runs, and no network is touched. This pins BOTH the exit-code contract (0 on
  # success, non-zero on failure — the exact gap the inverted-return regression
  # fixed in 907f2244 slipped through) AND the failure-path cleanup: a freshly
  # created out_dir CHAIN is rmdir'd bottom-up, a pre-existing dir is preserved, a
  # concurrent bake's artifact is never clobbered, and a successful bake leaves the
  # published golden + sidecar in place.
  #
  # SELFTEST_SANDBOX is a SCRIPT-GLOBAL (not local): the EXIT trap fires after
  # self_test returns, when a `local` would already be gone (rm -rf -- "").
  SELFTEST_SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/prebake-selftest.XXXXXX")" \
    || die "self-test: could not mktemp the fake-tool sandbox"
  # APPEND, do not `trap`: see register_cleanup's contract at the top of the file.
  register_cleanup "rm -rf -- '$SELFTEST_SANDBOX'"

  # --- EXIT-registry append-safety arm ------------------------------------------
  # Non-vacuity for the append-safe trap: a CHILD process registers TWO cleanups
  # (a pre-existing arm, then a newly-added one) and exits; BOTH files must be
  # gone. Under the old last-writer-wins `trap ... EXIT` the second registration
  # replaced the first and `first` would survive — so this arm fails loudly if the
  # registry ever regresses to a bare `trap`. Offline: no tools, no network, just
  # two temp files in the sandbox.
  local probe_dir="${SELFTEST_SANDBOX}/cleanup-registry"
  bash "$0" --cleanup-registry-probe "$probe_dir" >/dev/null \
    || die "self-test FAIL: cleanup-registry probe exited non-zero"
  [ ! -e "${probe_dir}/first" ] \
    || die "self-test FAIL: the FIRST-registered EXIT cleanup did not run — EXIT trap registration is last-writer-wins again (use register_cleanup, never a bare 'trap ... EXIT')"
  [ ! -e "${probe_dir}/second" ] \
    || die "self-test FAIL: the SECOND-registered EXIT cleanup did not run"
  log "self-test: EXIT cleanup registry ran BOTH the pre-existing and the newly-registered cleanup (append-safe)"
  local stubs="${SELFTEST_SANDBOX}/stubs"; mkdir -p "$stubs"
  printf 'fake-raw-base\n' >"${SELFTEST_SANDBOX}/base.raw"

  # overlay-create fake: parse --overlay, materialize that path, exit 0. MUST end
  # `exit 0` — a trailing `[ -n "$ov" ] && : >"$ov"` list returns 1 when ov is
  # empty and would silently flip the success arm to a failure.
  cat >"${stubs}/overlay-create" <<'STUB'
#!/usr/bin/env bash
set -eu
ov=""
while [ $# -gt 0 ]; do
  case "$1" in
    --overlay) ov="$2"; shift 2 ;;
    --base)    shift 2 ;;
    *)         shift ;;
  esac
done
if [ -n "$ov" ]; then : >"$ov"; fi
exit 0
STUB

  # qemu-img fake: rebase/commit are no-ops on a fake overlay.
  cat >"${stubs}/qemu-img" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

  # virt-customize fake (success): ignore -a/--run-command args, warm nothing.
  cat >"${stubs}/virt-customize" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

  # virt-customize fake (failure at step 2): optionally drop a "concurrent bake's
  # artifact" into a dir under the fresh chain, then fail — so the failure path's
  # rmdir walk must refuse the now-non-empty ancestor.
  cat >"${stubs}/virt-customize-fail" <<'STUB'
#!/usr/bin/env bash
if [ -n "${DS_FAKE_CONCURRENT_ARTIFACT:-}" ]; then
  mkdir -p -- "$(dirname -- "$DS_FAKE_CONCURRENT_ARTIFACT")"
  : >"$DS_FAKE_CONCURRENT_ARTIFACT"
fi
exit 1
STUB
  chmod +x "$stubs"/*

  # No new committed fixtures (D50 provenance untouched): every arm reuses the
  # already-provenance'd $on_cfg (repo github.com/acme/monorepo, non-empty
  # warm_steps) with DS_GOLDEN_BASE_IMAGE / DS_GOLDEN_OUTPUT_DIR overrides. The
  # tool overrides are PLAIN shell assignments inside each subshell (they shadow
  # the load-time globals; live_bake reads them as shell vars); only
  # DS_FAKE_CONCURRENT_ARTIFACT needs export (the stub is an external process).
  # The published golden slug for this repo+branch:
  local golden_leaf='github.com__acme__monorepo--main.qcow2'

  # Arm S — forced SUCCESS: exit 0, freshly-created chain + artifacts PRESERVED.
  log "self-test: fake-tool live_bake FORCED-SUCCESS must exit 0 and PRESERVE the freshly-created dir"
  if ! (
    DS_GOLDEN_BAKE_LIVE=1
    QEMU_IMG="${stubs}/qemu-img"
    OVERLAY_CREATE="${stubs}/overlay-create"
    VIRT_CUSTOMIZE="${stubs}/virt-customize"
    DS_GOLDEN_BASE_IMAGE="${SELFTEST_SANDBOX}/base.raw"
    DS_GOLDEN_OUTPUT_DIR="${SELFTEST_SANDBOX}/ok/nested/out"
    bake_one "$on_cfg" "github.com/acme/monorepo" "main" 0
  ) >/dev/null 2>&1; then
    die "self-test FAIL: forced-success live_bake exited non-zero under fake tools"
  fi
  [ -f "${SELFTEST_SANDBOX}/ok/nested/out/${golden_leaf}" ] \
    || die "self-test FAIL: forced-success bake did not publish the golden image"
  [ -f "${SELFTEST_SANDBOX}/ok/nested/out/${golden_leaf}.image-id" ] \
    || die "self-test FAIL: forced-success bake did not stamp the image-id sidecar"
  log "self-test: forced-success bake exited 0 and preserved the published golden + sidecar (good)"

  # Arm F1 — forced FAILURE, leaf-only rmdir: fresh leaf gone, pre-existing parent kept.
  log "self-test: fake-tool live_bake FORCED-FAILURE must exit non-zero and rmdir the fresh LEAF"
  mkdir -p "${SELFTEST_SANDBOX}/f1"
  if (
    DS_GOLDEN_BAKE_LIVE=1
    QEMU_IMG="${stubs}/qemu-img"
    OVERLAY_CREATE="${stubs}/overlay-create"
    VIRT_CUSTOMIZE="${stubs}/virt-customize-fail"
    DS_GOLDEN_BASE_IMAGE="${SELFTEST_SANDBOX}/base.raw"
    DS_GOLDEN_OUTPUT_DIR="${SELFTEST_SANDBOX}/f1/out"
    bake_one "$on_cfg" "github.com/acme/monorepo" "main" 0
  ) >/dev/null 2>&1; then
    die "self-test FAIL: forced-failure live_bake exited 0 (must be non-zero)"
  fi
  [ ! -e "${SELFTEST_SANDBOX}/f1/out" ] \
    || die "self-test FAIL: failed bake left the freshly-created leaf out_dir behind"
  [ -d "${SELFTEST_SANDBOX}/f1" ] \
    || die "self-test FAIL: failed bake rmdir'd the PRE-EXISTING parent (must leave it untouched)"
  log "self-test: forced-failure bake exited non-zero, rmdir'd the fresh leaf, kept the pre-existing parent (good)"

  # Arm F2 — forced FAILURE, PARENT-CHAIN rmdir (the new behavior under test): the
  # whole freshly-minted chain f2/a/b/c is removed up to the pre-existing sandbox.
  log "self-test: fake-tool live_bake FORCED-FAILURE must rmdir the whole freshly-created PARENT CHAIN"
  if (
    DS_GOLDEN_BAKE_LIVE=1
    QEMU_IMG="${stubs}/qemu-img"
    OVERLAY_CREATE="${stubs}/overlay-create"
    VIRT_CUSTOMIZE="${stubs}/virt-customize-fail"
    DS_GOLDEN_BASE_IMAGE="${SELFTEST_SANDBOX}/base.raw"
    DS_GOLDEN_OUTPUT_DIR="${SELFTEST_SANDBOX}/f2/a/b/c"
    bake_one "$on_cfg" "github.com/acme/monorepo" "main" 0
  ) >/dev/null 2>&1; then
    die "self-test FAIL: forced-failure (parent-chain) live_bake exited 0 (must be non-zero)"
  fi
  [ ! -e "${SELFTEST_SANDBOX}/f2" ] \
    || die "self-test FAIL: failed bake left freshly-created EMPTY parent dirs behind"
  [ -d "$SELFTEST_SANDBOX" ] \
    || die "self-test FAIL: rmdir walk overshot the pre-existing sandbox root"
  log "self-test: forced-failure bake rmdir'd the full fresh chain, stopped at the pre-existing root (good)"

  # Arm F3 — forced FAILURE, PRE-EXISTING out_dir preserved (created_out_root empty).
  log "self-test: fake-tool live_bake FORCED-FAILURE must PRESERVE a pre-existing (non-fresh) out_dir"
  mkdir -p "${SELFTEST_SANDBOX}/f3-out"
  : >"${SELFTEST_SANDBOX}/f3-out/keep.txt"
  if (
    DS_GOLDEN_BAKE_LIVE=1
    QEMU_IMG="${stubs}/qemu-img"
    OVERLAY_CREATE="${stubs}/overlay-create"
    VIRT_CUSTOMIZE="${stubs}/virt-customize-fail"
    DS_GOLDEN_BASE_IMAGE="${SELFTEST_SANDBOX}/base.raw"
    DS_GOLDEN_OUTPUT_DIR="${SELFTEST_SANDBOX}/f3-out"
    bake_one "$on_cfg" "github.com/acme/monorepo" "main" 0
  ) >/dev/null 2>&1; then
    die "self-test FAIL: forced-failure (pre-existing dir) live_bake exited 0 (must be non-zero)"
  fi
  [ -d "${SELFTEST_SANDBOX}/f3-out" ] \
    || die "self-test FAIL: failed bake rmdir'd a PRE-EXISTING out_dir (must never touch it)"
  [ -f "${SELFTEST_SANDBOX}/f3-out/keep.txt" ] \
    || die "self-test FAIL: failed bake clobbered content in a pre-existing out_dir"
  log "self-test: forced-failure bake left the pre-existing out_dir + its content intact (good)"

  # Arm F4 — forced FAILURE, concurrent artifact NEVER clobbered: the fail stub
  # drops concurrent.keep into the intermediate parent f4/a before exiting 1, so
  # the empty leaf f4/a/b is rmdir'd but the non-empty parent halts the walk and
  # the artifact survives. DS_FAKE_CONCURRENT_ARTIFACT MUST be exported (external
  # process reads it).
  log "self-test: fake-tool live_bake FORCED-FAILURE must NEVER clobber a concurrent bake's artifact"
  if (
    DS_GOLDEN_BAKE_LIVE=1
    QEMU_IMG="${stubs}/qemu-img"
    OVERLAY_CREATE="${stubs}/overlay-create"
    VIRT_CUSTOMIZE="${stubs}/virt-customize-fail"
    DS_GOLDEN_BASE_IMAGE="${SELFTEST_SANDBOX}/base.raw"
    DS_GOLDEN_OUTPUT_DIR="${SELFTEST_SANDBOX}/f4/a/b"
    export DS_FAKE_CONCURRENT_ARTIFACT="${SELFTEST_SANDBOX}/f4/a/concurrent.keep"
    bake_one "$on_cfg" "github.com/acme/monorepo" "main" 0
  ) >/dev/null 2>&1; then
    die "self-test FAIL: forced-failure (concurrent-artifact) live_bake exited 0 (must be non-zero)"
  fi
  [ ! -e "${SELFTEST_SANDBOX}/f4/a/b" ] \
    || die "self-test FAIL: failed bake left the empty fresh leaf behind"
  [ -f "${SELFTEST_SANDBOX}/f4/a/concurrent.keep" ] \
    || die "self-test FAIL: failed bake clobbered a concurrent bake's artifact (rmdir must refuse the non-empty parent)"
  log "self-test: forced-failure bake removed the empty leaf but left the concurrent artifact intact (good)"

  echo "prebake: --self-test OK"
}

# bake_all — drive every configured (repo, branch) in the config. Used by the CI
# lane: iterate the opted-in repos and their branches. Unconfigured/opted-out
# repos are skipped by bake_one's gates; the global switch short-circuits all.
bake_all() {
  local cfg="$1" dry_run="$2"
  [ -f "$cfg" ] || die "config not found: $cfg"
  if [ "$(cfg_global_enabled "$cfg")" != "true" ]; then
    log "pre-bake globally disabled (enabled: false) — no repos baked (D12 dynamic default)"
    return 0
  fi
  # Enumerate repos[] entries and bake each opted-in one across its branches.
  local repos; repos="$(awk '
    /^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]+repo:[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line); gsub(/"/, "", line)
      print line
    }' "$cfg")"
  [ -n "$repos" ] || { log "no repos[] entries — nothing to bake"; return 0; }
  local repo branch branches
  while IFS= read -r repo; do
    [ -n "$repo" ] || continue
    branches="$(cfg_repo_branches "$cfg" "$repo")"
    [ -n "$branches" ] || branches="main"  # default to main per the schema
    while IFS= read -r branch; do
      [ -n "$branch" ] || continue
      bake_one "$cfg" "$repo" "$branch" "$dry_run"
    done <<EOF
$branches
EOF
  done <<EOF
$repos
EOF
}

usage() {
  cat >&2 <<EOF
usage:
  $0 --config <cfg.yaml> --repo <repo> --branch <branch> [--dry-run]
  $0 --config <cfg.yaml> --all [--dry-run]
  $0 --smoke [--base <m0-base.raw>] [--out <dir>]   # operator-host bake smoke (gated)
  $0 --self-test
DS_GOLDEN_BAKE_LIVE=1 enables the live qemu/libguestfs bake (deferred manual step).
The --smoke leg is an OPTIONAL operator-host end-to-end check; it REFUSES without
DS_GOLDEN_BAKE_LIVE=1 and never auto-runs in CI/sandbox (see images/golden/README.md).
EOF
  exit 1
}

# cleanup_registry_probe DIR — HIDDEN mode, driven only by --self-test. Registers
# TWO EXIT cleanups (standing in for a pre-existing arm and a later-added one) on
# two files it creates, then exits. The parent asserts BOTH files are gone, which
# is only true if EXIT-trap registration is APPEND-safe. Offline; touches nothing
# outside DIR. Not in usage(): it is a test hook, not an operator verb.
cleanup_registry_probe() {
  local dir="${1:-}"
  [ -n "$dir" ] || die "cleanup-registry-probe: missing DIR argument"
  mkdir -p "$dir" || die "cleanup-registry-probe: could not create ${dir}"
  : >"${dir}/first"
  : >"${dir}/second"
  register_cleanup "rm -f -- '${dir}/first'"    # the "pre-existing" arm
  register_cleanup "rm -f -- '${dir}/second'"   # a NEW arm registered afterwards
  log "cleanup-registry-probe: ${#DS_PREBAKE_CLEANUPS[@]} cleanups registered; exiting"
}

main() {
  if [ "${1:-}" = "--self-test" ]; then self_test; return; fi
  if [ "${1:-}" = "--cleanup-registry-probe" ]; then cleanup_registry_probe "${2:-}"; return; fi
  if [ "${1:-}" = "--smoke" ]; then shift; live_smoke "$@"; return; fi
  local cfg="" repo="" branch="" dry_run=0 all=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --config)  cfg="$2"; shift 2 ;;
      --repo)    repo="$2"; shift 2 ;;
      --branch)  branch="$2"; shift 2 ;;
      --dry-run) dry_run=1; shift ;;
      --all)     all=1; shift ;;
      *) die "unknown argument: $1 (run with no args for usage)" ;;
    esac
  done
  [ -n "$cfg" ] || usage
  if [ "$all" = 1 ]; then
    bake_all "$cfg" "$dry_run"
    return
  fi
  [ -n "$repo" ]   || usage
  [ -n "$branch" ] || usage
  bake_one "$cfg" "$repo" "$branch" "$dry_run"
}

main "$@"
