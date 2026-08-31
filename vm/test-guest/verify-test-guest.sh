#!/usr/bin/env bash
# verify-test-guest.sh — anti-drift guard for the local test-guest fixture.
#
# Asserts the cheap, offline invariants that keep the rig honest, with NO
# network and NO qemu:
#   1. test-guest.env pins are internally consistent (image name == derived from
#      version/arch/flavor; sha256 is 64 hex; static net fields present).
#   2. IMAGE-IDENTITY.md quotes the SAME pin values as test-guest.env, token-for-
#      token (a pin bump is one reviewed diff that can't drift the doc).
#   3. The committed scripts carry the SPDX Apache-2.0 header (D25) and the
#      builder fetches the base image with the proxy bypass (curl --noproxy).
#   4. No blob/oversize file leaked into the tree (no *.qcow2/*.iso/etc.; nothing
#      over 1 MB), belt-and-suspenders to .gitignore.
#   5. Every committed *.sh parses under the parser its shebang names, and a
#      bash-array script can never carry a POSIX (/bin/sh) shebang — the
#      sh-n-vs-bash-n / POSIX-vs-array drift the local gate's sh==bash assumption
#      would otherwise hide (BUILD-NOTES §4a). If shellcheck is on PATH it also
#      lints the bash scripts with --shell=bash; absent, that leg soft-skips.
#
# --self-test injects drift and confirms each guard catches it (non-vacuous).
#
# Usage:
#   vm/test-guest/verify-test-guest.sh             # run the guards
#   vm/test-guest/verify-test-guest.sh --self-test # inject drift, confirm each is caught
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${HERE}/test-guest.env"
IDENTITY="${HERE}/IMAGE-IDENTITY.md"

log()  { printf 'verify-test-guest: %s\n' "$*"; }
fail() { printf 'verify-test-guest: FAIL: %s\n' "$*" >&2; FAILED=1; }

# shebang_parser_agreement DIR
#
# For every *.sh under DIR, read the shebang and parse-check the script with the
# parser that shebang NAMES — bash -n for a bash shebang, sh -n for a POSIX one.
# This is the anti-drift insurance the rest of this tree lacks: the local gate
# parse-checks with `sh -n`, which only passes because the dev host's /bin/sh is
# symlinked to bash; on a real dash runner a bash-array script (boot-test-guest.sh's
# QEMU_ARGV) under a /bin/sh shebang would be REJECTED at parse time. So we also
# fail-closed if a script that uses bash-only syntax (arrays / [[ ]] / etc.) is NOT
# parseable by a strict POSIX sh while declaring a /bin/sh shebang — i.e. the
# parser the shebang implies must actually accept the script. When shellcheck is
# present we additionally lint the bash scripts with --shell=bash (pinning the
# dialect); when it is absent that leg soft-skips (no network, no install).
#
# Returns non-zero (via fail()) on any disagreement; FAILED must be pre-set by the
# caller (run_checks does this).
shebang_parser_agreement() {
  local dir="${1:-$HERE}"
  local f shebang parser
  for f in "${dir}"/*.sh; do
    [ -f "$f" ] || continue
    shebang="$(head -n1 "$f")"
    case "$shebang" in
      '#!'*[/\ ]bash|'#!'*'/env bash'|'#!'*'/env -S bash'*)
        parser=bash ;;
      '#!'*[/\ ]sh|'#!'*'/env sh'|'#!'*'/env -S sh'*)
        parser=sh ;;
      '#!'*)
        fail "$(basename "$f"): unrecognized shebang for parser mapping: $shebang"
        continue ;;
      *)
        fail "$(basename "$f"): missing shebang (#!...) on line 1"
        continue ;;
    esac

    # 1. The script must parse under the parser its shebang NAMES.
    if [ "$parser" = bash ]; then
      bash -n "$f" 2>/dev/null \
        || fail "$(basename "$f"): declares a bash shebang but fails bash -n"
    else
      sh -n "$f" 2>/dev/null \
        || fail "$(basename "$f"): declares a /bin/sh (POSIX) shebang but fails sh -n"
    fi

    # 2. A POSIX (/bin/sh) shebang must MEAN it: if the script carries bash-only
    #    syntax it would be rejected on a real dash runner, so reject it here even
    #    when the dev host's /bin/sh == bash silently accepts it. Probe with a
    #    strict POSIX parser when one is reachable (dash/posh); else flag the
    #    bashism textually so the drift can never ride the sh==bash assumption.
    if [ "$parser" = sh ]; then
      local posix_sh=""
      for cand in dash posh; do
        command -v "$cand" >/dev/null 2>&1 && { posix_sh="$cand"; break; }
      done
      if [ -n "$posix_sh" ]; then
        "$posix_sh" -n "$f" 2>/dev/null \
          || fail "$(basename "$f"): /bin/sh shebang but $posix_sh -n rejects it (bashism under a POSIX shebang)"
      else
        # No strict POSIX parser on PATH (the sh==bash host). Textually flag the
        # load-bearing bashisms (array assignment / "${arr[@]}" / double-bracket
        # tests) that a real dash would reject — exactly the QEMU_ARGV-style drift
        # this guards. Strip whole-line comments first so prose can't false-trip.
        if grep -v '^[[:space:]]*#' "$f" \
             | grep -Eq '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=\(|\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\]\}|\[\[[[:space:]]'; then
          fail "$(basename "$f"): /bin/sh (POSIX) shebang but the script uses bash-only syntax (array/double-bracket test); a dash runner would reject it"
        fi
      fi
    fi

    # 3. Optional: lint the bash scripts with shellcheck --shell=bash when present
    #    (pins the dialect + flags portability drift). Soft-skip when absent — the
    #    CI/sandbox lane stays offline and never installs it.
    if [ "$parser" = bash ] && command -v shellcheck >/dev/null 2>&1; then
      shellcheck --shell=bash --severity=error "$f" >/dev/null 2>&1 \
        || fail "$(basename "$f"): shellcheck --shell=bash reported error-level findings"
    fi
  done
}

run_checks() {
  local env_file="${1:-$ENV_FILE}" identity="${2:-$IDENTITY}" scripts_dir="${3:-$HERE}"
  FAILED=0

  # shellcheck source=/dev/null
  . "$env_file"

  # 1. internal pin consistency
  local expect="nocloud_alpine-${TG_ALPINE_VERSION}-${TG_ALPINE_ARCH}-${TG_ALPINE_FLAVOR}.qcow2"
  [ "${TG_IMAGE_NAME}" = "$expect" ] || fail "TG_IMAGE_NAME ($TG_IMAGE_NAME) != derived ($expect)"
  case "${TG_IMAGE_SHA256:-}" in
    [0-9a-f]*) [ "${#TG_IMAGE_SHA256}" = 64 ] || fail "TG_IMAGE_SHA256 not 64 hex chars" ;;
    *) fail "TG_IMAGE_SHA256 missing/not hex" ;;
  esac
  [ -n "${TG_GUEST_IP:-}" ] && [ -n "${TG_GUEST_GATEWAY:-}" ] || fail "static net fields missing"

  # 2. doc <-> env agreement (token-for-token on the load-bearing pins)
  for tok in "${TG_IMAGE_NAME}" "${TG_IMAGE_SHA256}" "${TG_ALPINE_VERSION}" \
             "${TG_GUEST_IP}/${TG_GUEST_CIDR}" "${TG_GUEST_GATEWAY}" "${TG_TAP_IFNAME}"; do
    grep -qF "$tok" "$identity" || fail "IMAGE-IDENTITY.md does not quote pin token: $tok"
  done

  # 3. SPDX header + proxy-bypass fetch
  for s in "${HERE}/build-test-guest.sh" "${HERE}/boot-test-guest.sh" \
           "${HERE}/verify-test-guest.sh" "${HERE}/mkseed.py" "${HERE}/test-guest.env"; do
    grep -qF 'SPDX-License-Identifier: Apache-2.0' "$s" || fail "missing SPDX header: $(basename "$s")"
  done
  grep -qF "curl --noproxy '*'" "${HERE}/build-test-guest.sh" \
    || fail "builder does not fetch the image with curl --noproxy '*'"

  # 4. no committed blob / oversize file (the artifact dir lives under ~/tmp)
  local big
  big="$(find "${HERE}" -maxdepth 1 -type f -size +1M 2>/dev/null || true)"
  [ -z "$big" ] || fail "oversize (>1MB) file(s) in tree: $big"
  local blob
  blob="$(find "${HERE}" -maxdepth 1 -type f \( -name '*.qcow2' -o -name '*.iso' -o -name '*.img' -o -name 'vmlinuz*' -o -name 'initramfs*' \) 2>/dev/null || true)"
  [ -z "$blob" ] || fail "blob artifact committed in tree: $blob"

  # 5. shebang <-> parser agreement (sh-n-vs-bash-n / POSIX-vs-array drift)
  shebang_parser_agreement "$scripts_dir"

  return "$FAILED"
}

if [ "${1:-}" = "--self-test" ]; then
  log "self-test: confirming each guard catches injected drift"
  tmp="$(mktemp -d)"
  cp "$ENV_FILE" "${tmp}/env"
  cp "$IDENTITY" "${tmp}/id.md"

  # Inject a drifted image name (name no longer matches version) into the env.
  sed 's/^TG_IMAGE_NAME=.*/TG_IMAGE_NAME=nocloud_alpine-9.9.9-x86_64-bios-cloudinit-r0.qcow2/' \
    "$ENV_FILE" > "${tmp}/env-drift"
  if run_checks "${tmp}/env-drift" "${tmp}/id.md" >/dev/null 2>&1; then
    log "self-test FAIL: drifted image name slipped past the guards"; rm -rf "$tmp"; exit 1
  fi

  # Inject a doc that omits the sha256 pin (env unchanged) → doc/env mismatch.
  grep -v "$(grep '^TG_IMAGE_SHA256=' "$ENV_FILE" | cut -d= -f2)" "$IDENTITY" > "${tmp}/id-drift.md" || true
  if run_checks "$ENV_FILE" "${tmp}/id-drift.md" >/dev/null 2>&1; then
    log "self-test FAIL: doc missing the sha256 pin slipped past the guards"; rm -rf "$tmp"; exit 1
  fi

  # --- shebang <-> parser agreement (guard 5) -------------------------------
  # POSITIVE: a clean scripts dir (a bash-array script under a bash shebang +
  # a POSIX script under a /bin/sh shebang) must PASS the agreement leg — proof
  # the check is not vacuously red.
  ok_dir="${tmp}/sh-ok"; mkdir -p "$ok_dir"
  cat > "${ok_dir}/array-bash.sh" <<'EOF'
#!/usr/bin/env bash
# bash-array body — matches its bash shebang (boot-test-guest.sh's QEMU_ARGV shape).
ARGV=(env FOO=bar qemu -enable-kvm); exec "${ARGV[@]}"
EOF
  cat > "${ok_dir}/posix-ok.sh" <<'EOF'
#!/bin/sh
# pure POSIX body under a /bin/sh shebang — no arrays, no [[ ]].
x=1; [ "$x" = 1 ] && echo ok
EOF
  if ! run_checks "$ENV_FILE" "$IDENTITY" "$ok_dir" >/dev/null 2>&1; then
    log "self-test FAIL: an agreeing scripts dir was wrongly rejected (guard 5 is vacuously red)"; rm -rf "$tmp"; exit 1
  fi

  # DRIFT: the exact footgun — a bash-array body smuggled under a /bin/sh
  # (POSIX) shebang. A real dash runner rejects the array syntax at parse time;
  # guard 5 must catch it even where the dev host's /bin/sh == bash.
  bad_dir="${tmp}/sh-drift"; mkdir -p "$bad_dir"
  cp "${ok_dir}/posix-ok.sh" "${bad_dir}/posix-ok.sh"
  cat > "${bad_dir}/array-under-sh.sh" <<'EOF'
#!/bin/sh
# DRIFT: bash arrays under a POSIX shebang — dash would reject this at parse time.
ARGV=(env FOO=bar qemu -enable-kvm); exec "${ARGV[@]}"
EOF
  if run_checks "$ENV_FILE" "$IDENTITY" "$bad_dir" >/dev/null 2>&1; then
    log "self-test FAIL: a bash-array body under a /bin/sh shebang slipped past guard 5"; rm -rf "$tmp"; exit 1
  fi

  # DRIFT 2: a missing shebang (line 1 is not #!...) must also be caught.
  nohash_dir="${tmp}/sh-noshebang"; mkdir -p "$nohash_dir"
  cat > "${nohash_dir}/no-shebang.sh" <<'EOF'
# no shebang on line 1 — the parser is undefined; guard 5 must reject it.
echo hello
EOF
  if run_checks "$ENV_FILE" "$IDENTITY" "$nohash_dir" >/dev/null 2>&1; then
    log "self-test FAIL: a script missing its shebang slipped past guard 5"; rm -rf "$tmp"; exit 1
  fi

  rm -rf "$tmp"
  log "self-test OK (every injected drift was caught)"
  exit 0
fi

if run_checks; then
  log "all anti-drift guards OK"
  exit 0
else
  log "anti-drift guards FAILED" >&2
  exit 1
fi
