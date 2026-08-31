#!/usr/bin/env bash
# D131 shm-rollout T1 — operator-gated two-binary boot smoke (doc 13 §Rollout).
#
# Boots the REAL ds-dnsgate (writer) then ds-tlsproxy (reader) over a UNIQUE
# DS_ADMISSION_SHM_NAME under the production profile, confirms the named segment lands
# in /dev/shm, and asserts the forget-the-gate startup guard: with DS_PRODUCTION set but
# the mandatory gate MISSING, each binary must EXIT NON-ZERO (refuse to boot) rather than
# silently run the in-process map / empty fake.
#
# Operator-gated: it actually binds listeners + /dev/shm, so it does NOT run under the
# portable `cargo test` path (use tests/shm_live_path_smoke.rs for the in-sandbox proof).
# Gate it on with DS_SHM_SMOKE=1. Run from the dataplane/ workspace root.
#
#   DS_SHM_SMOKE=1 dataplane/scripts/shm-rollout-smoke.sh
#
set -euo pipefail

if [[ "${DS_SHM_SMOKE:-}" != "1" ]]; then
  echo "shm-rollout-smoke: set DS_SHM_SMOKE=1 to run the live two-binary boot smoke (skipped)."
  exit 0
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" # dataplane/
cd "${here}"

# A unique segment name per run (PID), so co-located runs / stale leftovers never collide.
seg="/ds-admission-smoke-$$"
seg_file="/dev/shm/${seg#/}"

dnsgate_pid=""
tlsproxy_pid=""
cleanup() {
  [[ -n "${tlsproxy_pid}" ]] && kill "${tlsproxy_pid}" 2>/dev/null || true
  [[ -n "${dnsgate_pid}" ]] && kill "${dnsgate_pid}" 2>/dev/null || true
  rm -f "${seg_file}" 2>/dev/null || true
}
trap cleanup EXIT

echo "shm-rollout-smoke: building ds-dnsgate + ds-tlsproxy (--locked)…"
cargo build --quiet --locked -p ds-dnsgate -p ds-tlsproxy

dnsgate_bin="$(cargo metadata --quiet --format-version 1 \
  | grep -o '"target_directory":"[^"]*"' | head -1 | cut -d'"' -f4)/debug/ds-dnsgate"
tlsproxy_bin="$(dirname "${dnsgate_bin}")/ds-tlsproxy"

fail() {
  echo "shm-rollout-smoke: FAIL — $1" >&2
  exit 1
}

# ── 1. forget-the-gate guard: DS_PRODUCTION set, the mandatory gate MISSING → exit≠0 ──
echo "shm-rollout-smoke: asserting the forget-the-gate guard (must refuse to boot)…"

# ds-dnsgate: DS_PRODUCTION on, DS_ADMISSION_SHM_LIVE missing → fatal exit.
if env -u DS_ADMISSION_SHM_LIVE DS_PRODUCTION=1 "${dnsgate_bin}" >/dev/null 2>&1; then
  fail "ds-dnsgate booted with DS_PRODUCTION set but DS_ADMISSION_SHM_LIVE missing (should refuse)"
fi
echo "  ds-dnsgate refused (DS_ADMISSION_SHM_LIVE missing under DS_PRODUCTION) — OK"

# ds-tlsproxy: DS_PRODUCTION on, DS_TLS1_LIVE missing → fatal exit.
if env -u DS_TLS1_LIVE DS_PRODUCTION=1 "${tlsproxy_bin}" >/dev/null 2>&1; then
  fail "ds-tlsproxy booted with DS_PRODUCTION set but DS_TLS1_LIVE missing (should refuse)"
fi
echo "  ds-tlsproxy refused (DS_TLS1_LIVE missing under DS_PRODUCTION) — OK"

# ── 2. writer-before-reader: start the writer, confirm the segment, start the reader ──
echo "shm-rollout-smoke: bringing the writer up over ${seg}…"
DS_PRODUCTION=1 DS_ADMISSION_SHM_LIVE=1 DS_DNSGATE_RERESOLVE_LISTEN=1 \
  DS_ADMISSION_SHM_NAME="${seg}" "${dnsgate_bin}" >/tmp/ds-dnsgate-smoke.$$.log 2>&1 &
dnsgate_pid=$!

# Wait (bounded) for the named segment to appear (writer create-or-reattach).
for _ in $(seq 1 50); do
  [[ -e "${seg_file}" ]] && break
  kill -0 "${dnsgate_pid}" 2>/dev/null || fail "ds-dnsgate exited early (see /tmp/ds-dnsgate-smoke.$$.log)"
  sleep 0.1
done
[[ -e "${seg_file}" ]] || fail "the named shm segment ${seg_file} did not appear"
echo "  segment present: $(ls -l "${seg_file}")"

echo "shm-rollout-smoke: bringing the reader up over the SAME name…"
DS_PRODUCTION=1 DS_TLS1_LIVE=1 DS_ADMISSION_SHM_NAME="${seg}" \
  "${tlsproxy_bin}" >/tmp/ds-tlsproxy-smoke.$$.log 2>&1 &
tlsproxy_pid=$!

# Give the reader a moment to attach; it must stay up (it attached the live segment).
sleep 1
kill -0 "${tlsproxy_pid}" 2>/dev/null || fail "ds-tlsproxy exited after attaching (see /tmp/ds-tlsproxy-smoke.$$.log)"
echo "  reader attached the live segment and is serving — OK"

echo "shm-rollout-smoke: PASS — writer-before-reader boot + forget-the-gate guard."
