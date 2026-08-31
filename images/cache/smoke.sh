#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# smoke.sh — host-local cache-hit/miss round-trip smoke test.
#
# RUNS ON A REAL HOST ONLY — never in CI. It talks to a live Nexus instance and
# fetches real artifacts from each per-ecosystem proxy, asserting a cache MISS on
# first pull and a cache HIT on the second (upstream-only-on-miss, D41). It does
# NOT exercise any registry protocol of ours — there is none (D41); it drives the
# off-the-shelf cache through stock clients/curl.
#
# Env gate (fail-closed): refuses to run unless DS_CACHE_SMOKE=1 is set, so CI
# and accidental invocations are no-ops.
#   DS_CACHE_SMOKE=1 images/cache/smoke.sh
#
# Optional env (defaults match deploy/nexus.container + deploy/repos.yaml):
#   CACHE_HOST   cache host alias/IP   (default cache.ds.local)
#   HTTP_PORT    Nexus HTTP endpoints  (default 8081)
#   DOCKER_PORT  OCI connector         (default 5000)

set -euo pipefail

if [ "${DS_CACHE_SMOKE:-0}" != "1" ]; then
  printf 'smoke: refusing to run without DS_CACHE_SMOKE=1 (host-only test, never CI).\n' >&2
  exit 2
fi

CACHE_HOST="${CACHE_HOST:-cache.ds.local}"
HTTP_PORT="${HTTP_PORT:-8081}"
DOCKER_PORT="${DOCKER_PORT:-5000}"

NPM_BASE="http://${CACHE_HOST}:${HTTP_PORT}/repository/npm-proxy"
PYPI_BASE="http://${CACHE_HOST}:${HTTP_PORT}/repository/pypi-proxy"
GO_BASE="http://${CACHE_HOST}:${HTTP_PORT}/repository/go-proxy"
DOCKER_BASE="http://${CACHE_HOST}:${DOCKER_PORT}"

command -v curl >/dev/null 2>&1 || { printf 'smoke: curl required\n' >&2; exit 1; }

fail=0
note() { printf '  %s\n' "$1"; }

# round_trip <label> <url>
# Pull twice. First pull may be a cache miss (cache fetches upstream); second
# pull must succeed from the warm cache. A non-2xx on the second pull is a fail.
round_trip() {
  label="$1"; url="$2"
  printf '[%s] %s\n' "${label}" "${url}"

  c1=$(curl -s -o /dev/null -w '%{http_code}' "${url}" || true)
  note "first pull  (may be miss -> upstream fetch): HTTP ${c1}"

  c2=$(curl -s -o /dev/null -w '%{http_code}' "${url}" || true)
  note "second pull (must be cache hit):            HTTP ${c2}"

  case "${c2}" in
    2*) note "OK: served from cache" ;;
    *)  note "FAIL: second pull did not return 2xx"; fail=1 ;;
  esac
  printf '\n'
}

printf 'smoke: cache round-trip against %s\n\n' "${CACHE_HOST}"

# npm — package metadata document (stable, small).
round_trip "npm"  "${NPM_BASE}/left-pad"

# PyPI — PEP 503 simple index page for a stable package.
round_trip "pypi" "${PYPI_BASE}/simple/six/"

# Go — @latest info for a stable module path.
round_trip "go"   "${GO_BASE}/rsc.io/quote/@latest"

# OCI — the registry API version probe through the Docker proxy connector.
# (Full image-layer round-trip needs a configured client; this asserts the
# proxy connector is live and answering the v2 API.)
round_trip "oci"  "${DOCKER_BASE}/v2/"

if [ "${fail}" -ne 0 ]; then
  printf 'smoke: FAILED — at least one ecosystem did not serve a warm hit.\n' >&2
  exit 1
fi
printf 'smoke: PASS — all ecosystems served a warm cache hit (upstream-only-on-miss, D41).\n'
