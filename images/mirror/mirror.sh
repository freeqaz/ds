#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# mirror.sh — host-local git mirror operator helper (images/mirror/).
#
# Config-as-code, NO daemon: this is a thin wrapper over stock git.
#   add <upstream-url> [<name>]   git clone --mirror into the mirror root
#   refresh <repo>                git remote update --prune for one mirror
#   refresh-all                   refresh every bare mirror under the root
#   list                          list enrolled mirrors
#   path <repo>                   print the on-disk path of a mirror
#
# HTTPS remotes ONLY: the mirror holds no long-lived upstream credentials of
# its own; mirror-to-upstream fetch rides the boundary credential-swap path
# (egress gateway / ds-tlsproxy, D83; doc 16 §5). git-over-SSH cannot ride the
# egress gateway and would bypass the swap + scanning planes, so ssh:// / git@
# remotes are refused (doc 16 §5.3, D83 "may pin to HTTPS").
#
# Reads images/mirror/deploy/ds-mirror.env for DS_MIRROR_ROOT (single source of
# truth shared with the systemd units and the quadlet).

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${DS_MIRROR_ENV:-$SCRIPT_DIR/deploy/ds-mirror.env}"

if [ -r "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

DS_MIRROR_ROOT="${DS_MIRROR_ROOT:-/var/lib/ds-mirror}"

die() { printf 'mirror.sh: %s\n' "$1" >&2; exit "${2:-1}"; }

usage() {
  cat >&2 <<'EOF'
usage: mirror.sh <command> [args]
  add <upstream-url> [<name>]   enrol a repo (git clone --mirror); HTTPS only
  refresh <repo>                refresh one mirror (remote update --prune)
  refresh-all                   refresh every mirror under the root
  list                          list enrolled mirrors
  path <repo>                   print on-disk path of a mirror
EOF
  exit 2
}

# Refuse anything that is not an HTTPS remote (see header rationale).
require_https() {
  case "$1" in
    https://*) : ;;
    ssh://*|git@*|git://*|*://*)
      die "refusing non-HTTPS remote '$1': mirror fetch must ride the egress gateway (HTTPS only, D83/doc 16 §5.3)" ;;
    *)
      die "unrecognized remote '$1': expected an https:// URL" ;;
  esac
}

# Derive a mirror directory name from an upstream URL: host/path -> host/path.git
# e.g. https://github.com/acme/api -> github.com/acme/api.git
name_from_url() {
  local url="$1" rest
  rest="${url#https://}"
  rest="${rest%/}"
  rest="${rest%.git}"
  printf '%s.git' "$rest"
}

mirror_dir() {
  local name="$1"
  case "$name" in
    /*) printf '%s' "$name" ;;
    *)  printf '%s/%s' "$DS_MIRROR_ROOT" "$name" ;;
  esac
}

cmd_add() {
  [ "$#" -ge 1 ] || usage
  local url="$1" name dir
  require_https "$url"
  name="${2:-$(name_from_url "$url")}"
  case "$name" in *.git) : ;; *) name="$name.git" ;; esac
  dir="$(mirror_dir "$name")"

  if [ -d "$dir" ]; then
    die "mirror already exists at $dir (use 'refresh $name')"
  fi
  mkdir -p "$(dirname -- "$dir")"
  printf 'mirror.sh: cloning --mirror %s -> %s\n' "$url" "$dir" >&2
  git clone --mirror "$url" "$dir"
  printf 'mirror.sh: enrolled %s\n' "$name" >&2
}

cmd_refresh() {
  [ "$#" -ge 1 ] || usage
  local name="$1" dir
  case "$name" in *.git) : ;; *) name="$name.git" ;; esac
  dir="$(mirror_dir "$name")"
  [ -d "$dir" ] || die "no mirror at $dir"
  printf 'mirror.sh: refreshing %s\n' "$dir" >&2
  git -C "$dir" remote update --prune
}

# Find every bare mirror under the root (a dir whose name ends in .git holding
# a git repo) and refresh it. Continues past individual failures, exits non-zero
# if any refresh failed, so the systemd unit surfaces partial failure.
cmd_refresh_all() {
  [ -d "$DS_MIRROR_ROOT" ] || die "mirror root $DS_MIRROR_ROOT does not exist"
  local rc=0 dir
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    printf 'mirror.sh: refreshing %s\n' "$dir" >&2
    if ! git -C "$dir" remote update --prune; then
      printf 'mirror.sh: WARN refresh failed for %s\n' "$dir" >&2
      rc=1
    fi
  done <<EOF
$(find "$DS_MIRROR_ROOT" -type d -name '*.git' -prune 2>/dev/null)
EOF
  return "$rc"
}

cmd_list() {
  [ -d "$DS_MIRROR_ROOT" ] || { printf '(no mirror root at %s)\n' "$DS_MIRROR_ROOT"; return 0; }
  find "$DS_MIRROR_ROOT" -type d -name '*.git' -prune 2>/dev/null \
    | sed "s#^$DS_MIRROR_ROOT/##" | sort
}

cmd_path() {
  [ "$#" -ge 1 ] || usage
  local name="$1"
  case "$name" in *.git) : ;; *) name="$name.git" ;; esac
  mirror_dir "$name"
  printf '\n'
}

main() {
  [ "$#" -ge 1 ] || usage
  local sub="$1"; shift
  case "$sub" in
    add)         cmd_add "$@" ;;
    refresh)     cmd_refresh "$@" ;;
    refresh-all) cmd_refresh_all ;;
    list)        cmd_list ;;
    path)        cmd_path "$@" ;;
    -h|--help|help) usage ;;
    *) die "unknown command '$sub'" 2 ;;
  esac
}

main "$@"
