#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# netns-validate.sh — HOST-SAFE end-to-end validation of the ds-nethelper
# skeleton. Touches NOTHING on the host: all network-namespace work runs
# inside `unshare -rn` (a private user+net ns where we hold CAP_NET_ADMIN
# over throwaway objects only).
#
# What it proves:
#   A. protocol conformance of the real built binary: exit codes + Result
#      lines for probe / validation rejection / stub not-built signaling.
#   B. the trust boundary rejects BEFORE any privileged path (unknown op,
#      uid rule, tap<->index cross-check, unknown JSON field, trailing data).
#   C. the netns rehearsal vehicle for the live backend: inside unshare -rn we
#      can create/destroy a dstap-<idx> tap with `ip` — i.e. the exact kernel
#      ops the ds-nft backend performs are testable here without ever touching
#      the host (skipped if `ip`/unshare absent).
#   D. the +ep-TRAP DETECTOR (D148). A fresh user namespace has a FULL permitted
#      set but an EMPTY INHERITABLE set — which is byte-for-byte the capability
#      signature of a helper mis-installed with `setcap cap_net_admin+ep`
#      instead of `+eip`: effective-green, ambient-raise impossible, every
#      ip/nft child stranded. So `unshare -rn <helper> probe` is a FREE,
#      host-safe reproduction of the half-configured host, and part D asserts
#      the probe reports exactly that signature — proving the three-field probe
#      can actually distinguish the trap, on any box, with no setcap and no
#      privilege. (This is why the rehearsal asserts a probe SIGNATURE and not a
#      successful create: uid 0 in-ns can never green-path create-tap, because
#      ValidateCreateTap rejects owner_uid==0 by design.)

set -uo pipefail

# In-repo home: this script sits at orchestrator/cmd/ds-nethelper/scripts/, so
# ".." is the helper package dir itself (orchestrator/cmd/ds-nethelper). Build
# it as the current package (".") from inside the orchestrator module so
# go.work / module resolution picks up the re-homed import paths.
here="$(cd "$(dirname "$0")/.." && pwd)"
bin="$(mktemp -d)/ds-nethelper"
trap 'rm -rf "$(dirname "$bin")"' EXIT

pass=0; fail=0
check() { # check <name> <want_exit> <got_exit>
  local name="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    echo "PASS  $name (exit $got)"; pass=$((pass+1))
  else
    echo "FAIL  $name (exit $got, want $want)"; fail=$((fail+1))
  fi
}

echo "== build =="
(cd "$here" && go build -o "$bin" .) || { echo "build failed"; exit 1; }

echo "== A/B: protocol + trust boundary (default stub build) =="
uid="$(id -u)"

"$bin" probe >/dev/null 2>/dev/null; check "probe ok" 0 $?
out="$("$bin" probe 2>/dev/null)"
echo "$out" | grep -q '"code":"OK"' || { echo "FAIL probe result line: $out"; fail=$((fail+1)); }
echo "$out" | grep -q '"built":true' && { echo "FAIL stub probe claims built"; fail=$((fail+1)); }

"$bin" apply-nft </dev/null >/dev/null 2>/dev/null; check "unknown op rejected (no generic verb)" 2 $?
"$bin" >/dev/null 2>/dev/null; check "no op rejected" 2 $?
"$bin" create-tap probe >/dev/null 2>/dev/null; check "extra argv rejected" 2 $?

printf '{"tap_name":"dstap-7","owner_uid":%s,"host_session_index":8}' "$uid" \
  | "$bin" create-tap >/dev/null 2>/dev/null
check "tap<->index cross-check rejects" 2 $?

printf '{"tap_name":"dstap-7","owner_uid":0,"host_session_index":7}' \
  | "$bin" create-tap >/dev/null 2>/dev/null
check "root owner_uid rejected" 2 $?

printf '{"tap_name":"dstap-7","owner_uid":%s,"host_session_index":7,"ruleset":"flush ruleset"}' "$uid" \
  | "$bin" create-tap >/dev/null 2>/dev/null
check "unknown field (ruleset smuggling) rejected" 5 $?

printf '{"tap_name":"dstap-7","owner_uid":%s,"host_session_index":7}' "$uid" \
  | "$bin" create-tap >/dev/null 2>/dev/null
check "valid create-tap reaches backend -> ENOTBUILT on stub" 4 $?

printf '{"tap_name":"dstap-7","host_session_index":7}' \
  | "$bin" flush-session >/dev/null 2>/dev/null
check "valid flush-session -> ENOTBUILT on stub" 4 $?

echo "== C: netns rehearsal vehicle (unshare -rn) =="
if command -v unshare >/dev/null && command -v ip >/dev/null; then
  # Same protocol behavior inside the namespace…
  unshare -rn "$bin" probe >/dev/null 2>/dev/null; check "probe inside netns" 0 $?
  # …and the kernel ops the FUTURE live backend performs are rehearsable
  # here: create + address + delete a throwaway dstap tap, all inside the
  # private ns (nothing on the host).
  unshare -rn sh -c '
    set -e
    ip tuntap add mode tap dstap-7
    ip addr add 10.77.7.0/31 dev dstap-7
    ip link set dstap-7 up
    ip link show dstap-7 >/dev/null
    ip link del dstap-7
  ' >/dev/null 2>&1
  check "netns tap create/address/delete rehearsal" 0 $?
else
  echo "SKIP  netns rehearsal (unshare/ip not available)"
fi

echo "== D: +ep-trap detector (fresh userns == the +ep capability signature) =="
# want_signature <label> <probe-output> [extra-required-substring...]
# The +ep-only signature: CAP_NET_ADMIN effective, but NOT inheritable and NOT
# ambient-raisable. Result fields are omitempty, so a false field is ABSENT —
# assert the true one is present and the two false ones are absent.
want_signature() {
  local label="$1" out="$2"; shift 2
  local ok=1 extra
  case "$out" in *'"cap_net_admin_effective":true'*) ;; *) ok=0 ;; esac
  case "$out" in *'"cap_net_admin_inheritable"'*) ok=0 ;; esac
  case "$out" in *'"ambient_raise_ok"'*) ok=0 ;; esac
  for extra in "$@"; do
    case "$out" in *"$extra"*) ;; *) ok=0 ;; esac
  done
  if [[ "$ok" -eq 1 ]]; then
    echo "PASS  $label (+ep signature: effective yes, inheritable no, ambient-raise no)"; pass=$((pass+1))
  else
    echo "FAIL  $label (want the +ep-only signature, got: $out)"; fail=$((fail+1))
  fi
}

if command -v unshare >/dev/null; then
  # The STUB build: proves the probe distinguishes the trap with no privilege.
  want_signature "stub helper probe in userns reports the +ep trap" \
    "$(unshare -rn "$bin" probe 2>/dev/null)"

  # OPTIONAL live leg — only when the ds-nft staticlib has been built, since the
  # tagged helper links it. Same signature (the capability posture is the
  # namespace's, not the build's) plus built:true, and the trust boundary still
  # rejects a create: uid 0 in-ns means owner_uid would be 0, which
  # ValidateCreateTap refuses outright (EARG / exit 2) — the uid rule holding
  # even where the kernel would happily let root create the tap.
  staticlib="$(cd "$here/../../.." && pwd)/dataplane/target/release/libds_nft.a"
  if [[ -f "$staticlib" ]]; then
    livebin="$(dirname "$bin")/ds-nethelper-live"
    if (cd "$here" && CGO_ENABLED=1 go build -tags nftgatelive -o "$livebin" .) 2>/dev/null; then
      want_signature "LIVE helper probe in userns reports the +ep trap" \
        "$(unshare -rn "$livebin" probe 2>/dev/null)" '"built":true'
      printf '{"tap_name":"dstap-7","owner_uid":0,"host_session_index":7}' \
        | unshare -rn "$livebin" create-tap >/dev/null 2>/dev/null
      check "LIVE create-tap in userns REJECTED at the trust boundary (owner_uid 0)" 2 $?
    else
      echo "SKIP  live-leg (tagged build failed; libds_nft.a present but not linkable here)"
    fi
  else
    echo "SKIP  live-leg (dataplane/target/release/libds_nft.a absent — run: cd dataplane && cargo build -p ds-nft --release)"
  fi
else
  echo "SKIP  +ep-trap detector (unshare not available)"
fi

echo
echo "== summary: $pass passed, $fail failed =="
[[ "$fail" -eq 0 ]]
