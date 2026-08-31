#!/bin/sh
# check-macceil-drift.sh — nested-testbed routed-tap MAC/ceiling anti-drift guard.
#
# PURPOSE
#   The nested-testbed manual-qemu boot path (scripts/nested-testbed/inside-l1/
#   l2-up.sh) hand-maintains the routed-tap NIC MAC literal that the orchestrator-
#   driven path derives in Go from a SINGLE source of truth (macForIndex in
#   orchestrator/internal/hypervisor/libvirt/live.go). Both paths MUST render the
#   SAME MAC for a given session index or the fat-L2 image's MAC-matched
#   *.network unit never fires and the guest comes up with no IP. This lint pins,
#   in lockstep with the Go source, the two literals l2-up.sh reproduces by hand:
#
#     (1) the render FORMAT of the 5th octet — the `printf` conversion the MAC's
#         per-index byte is rendered with. Go's macForIndex uses
#         `fmt.Sprintf("52:54:00:77:%02x:01", index)` (TWO HEX DIGITS, %02x);
#         l2-up.sh must render `mac=52:54:00:77:$(printf '%02x' "$IDX"):01`. If
#         either side flips the conversion (e.g. back to %02d decimal, which goes
#         to three digits at idx 100 and emits a MALFORMED octet libvirt rejects),
#         the two boot paths silently pin different MACs — this lint fails closed.
#
#     (2) the OUI/prefix `52:54:00:77` (the locally-administered QEMU OUI the
#         routed-tap MAC is built on) — asserted to appear VERBATIM in BOTH
#         live.go and l2-up.sh, so a prefix edit on one side cannot drift.
#
#   It also pins the companion /31 third-octet CEILING that bounds the index
#   space the MAC render must stay well-formed across:
#
#     (3) netConfigMaxIndexThirdOct in
#         orchestrator/internal/hypervisor/libvirt/netconfig.go (=255). The index
#         is the third octet of the per-session 10.77.<idx>.x /31; past the
#         ceiling the /31 would alias another session (fail-closed). The %02x MAC
#         render is well-formed across the SAME 0..255 range, so the two ceilings
#         agree by construction. l2-up.sh does not itself carry the 255 literal
#         today; this arm pins the Go constant's VALUE so a future l2-up.sh
#         ceiling literal cannot silently diverge from the source of truth, and
#         so a one-sided edit of the Go ceiling is caught here.
#
#   READ-ONLY: this lint greps live.go, netconfig.go, and l2-up.sh and edits
#   NONE of them. l2-up.sh is owned elsewhere; it is READ, never written.
#
# Usage:
#   sh scripts/check-macceil-drift.sh
#   sh scripts/check-macceil-drift.sh --self-test
#
# Exit codes:
#   0  — every pinned literal agrees across the Go source and l2-up.sh
#   1  — a literal drifted (Go source != l2-up.sh render, or the pinned ceiling
#         value changed)
#   2  — structural failure (a required input file is absent, or an extractor
#         found none of the anchor it keys on — the anchor was reworded/removed)
#
# --self-test: internal regression harness. Builds a self-contained sandbox
#   (synthetic live.go + netconfig.go + l2-up.sh), verifies the clean copy passes
#   (rc=0), then mutates each pinned literal on one side at a time (the MAC render
#   conversion, the OUI prefix, and the ceiling value) and confirms each drift is
#   caught (rc=1), plus a reworded-anchor structural case (rc=2). It NEVER reads
#   the real tree for its own pass/fail; the sandbox is cleaned up via an EXIT
#   trap. This proves the guard is non-vacuous.
#
# SPDX-License-Identifier: Apache-2.0

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# The OUI/prefix both boot paths build the routed-tap MAC on. Pinned as a literal
# here deliberately: it is the shared constant BOTH sources must reproduce, so
# the guard asserts it appears verbatim on BOTH sides (a prefix edit on either
# side that this literal no longer matches surfaces as a structural miss).
MAC_OUI_PREFIX='52:54:00:77'

# ---------------------------------------------------------------------------
# Extractors (READ-ONLY greps). Each prints the pinned token, or empty when the
# anchor it keys on is absent (an empty extraction upstreams to STRUCTURAL rc=2).
# ---------------------------------------------------------------------------

# _go_mac_conv LIVE_GO — print the printf conversion (e.g. %02x) the Go MAC render
# uses for the 5th octet, from the macForIndex `fmt.Sprintf("52:54:00:77:%XX:01",`
# literal. Anchored on the OUI prefix so it never matches an unrelated Sprintf.
_go_mac_conv() {
    awk -v pfx="$MAC_OUI_PREFIX" '
        index($0, "Sprintf(\"" pfx ":") > 0 {
            s = $0
            sub(/.*Sprintf\("/, "", s)
            sub(/".*/, "", s)                 # s = 52:54:00:77:%02x:01
            n = split(s, parts, ":")
            print parts[5]                    # the 5th-octet render token (%02x)
            exit
        }
    ' "$1"
}

# _sh_mac_conv L2_UP — print the printf conversion l2-up.sh renders the MAC's
# 5th octet with, from the `mac=52:54:00:77:$(printf '%XX' "$IDX"):01` literal.
# Anchored on the OUI prefix + `printf '` so it keys only on the MAC render line.
_sh_mac_conv() {
    awk -v pfx="$MAC_OUI_PREFIX" '
        index($0, "mac=" pfx ":$(printf ") > 0 {
            s = $0
            sub(/.*\$\(printf '"'"'/, "", s)  # strip up to the opening quote of the fmt
            sub(/'"'"'.*/, "", s)             # strip from the closing quote onward
            print s                           # the conversion (%02x)
            exit
        }
    ' "$1"
}

# _go_ceiling NETCONFIG_GO — print the integer RHS of the
# `netConfigMaxIndexThirdOct = <n>` const in netconfig.go. Trailing `// comment`
# and whitespace are stripped. Empty if the const is absent (STRUCTURAL upstream).
_go_ceiling() {
    awk '
        $0 ~ /netConfigMaxIndexThirdOct[[:space:]]*=/ {
            s = $0
            sub(/.*netConfigMaxIndexThirdOct[[:space:]]*=[[:space:]]*/, "", s)
            sub(/[^0-9].*/, "", s)            # keep the leading integer only
            print s
            exit
        }
    ' "$1"
}

# _file_has_prefix FILE — rc 0 iff the OUI prefix appears verbatim at least once
# in FILE. Used to assert both sources carry the shared prefix.
_file_has_prefix() {
    grep -q "$MAC_OUI_PREFIX" "$1"
}

# ---------------------------------------------------------------------------
# _run_checks LIVE_GO NETCONFIG_GO L2_UP — the shared check body, run against
# either the real tree or a synthetic self-test sandbox. Prints per-arm results
# and returns the worst rc (2 structural > 1 drift > 0 clean).
# ---------------------------------------------------------------------------
_run_checks() {
    _rc_live="$1"
    _rc_net="$2"
    _rc_l2="$3"
    _worst=0

    for _f in "$_rc_live" "$_rc_net" "$_rc_l2"; do
        if [ ! -f "$_f" ]; then
            printf 'check-macceil-drift: STRUCTURAL — required input absent: %s\n' "$_f" >&2
            return 2
        fi
    done

    # Arm (1): MAC render conversion — Go source vs l2-up.sh, both extracted.
    _go_conv="$(_go_mac_conv "$_rc_live")"
    _sh_conv="$(_sh_mac_conv "$_rc_l2")"
    if [ -z "$_go_conv" ]; then
        printf 'check-macceil-drift: STRUCTURAL — macForIndex Sprintf anchor not found in %s\n' "$_rc_live" >&2
        _worst=2
    elif [ -z "$_sh_conv" ]; then
        printf 'check-macceil-drift: STRUCTURAL — mac= printf anchor not found in %s\n' "$_rc_l2" >&2
        _worst=2
    elif [ "$_go_conv" != "$_sh_conv" ]; then
        printf 'check-macceil-drift: DRIFT — MAC render conversion differs: live.go %s vs l2-up.sh %s\n' "$_go_conv" "$_sh_conv" >&2
        [ "$_worst" -lt 1 ] && _worst=1
    else
        printf 'check-macceil-drift: OK — MAC render conversion lockstep (%s)\n' "$_go_conv"
    fi

    # Arm (2): OUI prefix present verbatim in BOTH sources.
    _pfx_go=0; _file_has_prefix "$_rc_live" || _pfx_go=$?
    _pfx_sh=0; _file_has_prefix "$_rc_l2"   || _pfx_sh=$?
    if [ "$_pfx_go" -ne 0 ]; then
        printf 'check-macceil-drift: STRUCTURAL — OUI prefix %s not found verbatim in %s\n' "$MAC_OUI_PREFIX" "$_rc_live" >&2
        _worst=2
    elif [ "$_pfx_sh" -ne 0 ]; then
        printf 'check-macceil-drift: STRUCTURAL — OUI prefix %s not found verbatim in %s\n' "$MAC_OUI_PREFIX" "$_rc_l2" >&2
        _worst=2
    else
        printf 'check-macceil-drift: OK — OUI prefix %s present verbatim in both live.go and l2-up.sh\n' "$MAC_OUI_PREFIX"
    fi

    # Arm (3): /31 third-octet ceiling value pinned from netconfig.go.
    _ceil="$(_go_ceiling "$_rc_net")"
    if [ -z "$_ceil" ]; then
        printf 'check-macceil-drift: STRUCTURAL — netConfigMaxIndexThirdOct const not found in %s\n' "$_rc_net" >&2
        _worst=2
    elif [ "$_ceil" != "255" ]; then
        printf 'check-macceil-drift: DRIFT — /31 third-octet ceiling changed: netConfigMaxIndexThirdOct=%s (pinned 255)\n' "$_ceil" >&2
        [ "$_worst" -lt 1 ] && _worst=1
    else
        printf 'check-macceil-drift: OK — /31 third-octet ceiling pinned (netConfigMaxIndexThirdOct=%s)\n' "$_ceil"
    fi

    return "$_worst"
}

# ---------------------------------------------------------------------------
# --self-test: dispatched BEFORE any real-tree access.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    _ST_ROOT="$(mktemp -d)"
    _st_cleanup() { rm -rf "$_ST_ROOT"; }
    trap _st_cleanup EXIT

    _ST_LIVE="$_ST_ROOT/live.go"
    _ST_NET="$_ST_ROOT/netconfig.go"
    _ST_L2="$_ST_ROOT/l2-up.sh"

    # Synthetic live.go carrying the SAME macForIndex Sprintf shape the real
    # source uses. $1 = 5th-octet render conversion (default %02x).
    _st_write_live() {
        _wl_conv="${1:-%02x}"
        {
            printf '// synthetic live.go self-test fixture\n'
            printf 'func macForIndex(index uint64) string {\n'
            printf '\treturn fmt.Sprintf("52:54:00:77:%s:01", index)\n' "$_wl_conv"
            printf '}\n'
        } > "$_ST_LIVE"
    }

    # Synthetic live.go whose OUI prefix is mutated (drops the shared prefix).
    _st_write_live_badprefix() {
        {
            printf '// synthetic live.go self-test fixture (bad OUI prefix)\n'
            printf 'func macForIndex(index uint64) string {\n'
            printf '\treturn fmt.Sprintf("52:54:00:99:%%02x:01", index)\n'
            printf '}\n'
        } > "$_ST_LIVE"
    }

    # Synthetic netconfig.go carrying the ceiling const shape _go_ceiling keys on.
    # $1 = ceiling value (default 255).
    _st_write_net() {
        _wn_ceil="${1:-255}"
        {
            printf '// synthetic netconfig.go self-test fixture\n'
            printf 'const (\n'
            printf '\tnetConfigFirstOctet       = 10\n'
            printf '\tnetConfigBaseSecondOctet  = 77\n'
            printf '\tnetConfigMaxIndexThirdOct = %s // idx is the third octet\n' "$_wn_ceil"
            printf ')\n'
        } > "$_ST_NET"
    }

    # Synthetic l2-up.sh carrying the SAME mac= printf render shape the real
    # script uses. $1 = 5th-octet render conversion (default %02x).
    _st_write_l2() {
        _w2_conv="${1:-%02x}"
        {
            printf '#!/usr/bin/env bash\n'
            printf '# synthetic l2-up.sh self-test fixture\n'
            printf '  -device "virtio-net-pci,netdev=n0,mac=52:54:00:77:$(printf '"'"'%s'"'"' "$IDX"):01" \\\n' "$_w2_conv"
        } > "$_ST_L2"
    }

    _fail=0

    _st_case() {  # $1=label $2=expected_rc  (files already written by caller)
        _c_label="$1"; _c_want="$2"
        _c_rc=0
        _run_checks "$_ST_LIVE" "$_ST_NET" "$_ST_L2" >/dev/null 2>&1 || _c_rc=$?
        if [ "$_c_rc" -ne "$_c_want" ]; then
            printf 'self-test: FAIL — %s expected rc=%s, got rc=%s\n' "$_c_label" "$_c_want" "$_c_rc" >&2
            _fail=1
        else
            printf 'self-test: %s caught (rc=%s)\n' "$_c_label" "$_c_rc"
        fi
    }

    # --- baseline: matched sources -> rc 0 ---
    _st_write_live "%02x"; _st_write_net "255"; _st_write_l2 "%02x"
    _st_case "clean fixture" 0

    # --- drift 1: l2-up.sh render flipped to %02d, Go still %02x -> rc 1 ---
    _st_write_live "%02x"; _st_write_net "255"; _st_write_l2 "%02d"
    _st_case "MAC render conversion drift (l2-up.sh %02d vs live.go %02x)" 1

    # --- drift 1b: Go render flipped to %02d, l2-up.sh still %02x -> rc 1 ---
    _st_write_live "%02d"; _st_write_net "255"; _st_write_l2 "%02x"
    _st_case "MAC render conversion drift (live.go %02d vs l2-up.sh %02x)" 1

    # --- drift 2: netconfig ceiling bumped to 254 -> rc 1 ---
    _st_write_live "%02x"; _st_write_net "254"; _st_write_l2 "%02x"
    _st_case "ceiling drift (netConfigMaxIndexThirdOct=254)" 1

    # --- structural: Go OUI prefix mutated (shared prefix gone from live.go) -> rc 2 ---
    _st_write_live_badprefix; _st_write_net "255"; _st_write_l2 "%02x"
    _st_case "OUI-prefix structural miss (live.go)" 2

    # --- structural: reworded live.go anchor (macForIndex Sprintf gone) -> rc 2 ---
    {
        printf '// synthetic live.go self-test fixture (reworded)\n'
        printf 'func macForIndex(index uint64) string { return renderMac(index) }\n'
    } > "$_ST_LIVE"
    _st_write_net "255"; _st_write_l2 "%02x"
    _st_case "reworded live.go anchor structural miss" 2

    # --- structural: missing input file -> rc 2 ---
    _st_write_live "%02x"; _st_write_net "255"; rm -f "$_ST_L2"
    _st_case "missing l2-up.sh structural miss" 2

    if [ "$_fail" -ne 0 ]; then
        printf 'self-test: FAIL — one or more sub-tests failed\n' >&2
        exit 1
    fi
    printf 'self-test: ALL CHECKS PASSED — check-macceil-drift.sh OK\n'
    exit 0
fi

# ---------------------------------------------------------------------------
# Production path: guard the real nested-testbed MAC render + ceiling.
# ---------------------------------------------------------------------------
LIVE_GO="$REPO_ROOT/orchestrator/internal/hypervisor/libvirt/live.go"
NETCONFIG_GO="$REPO_ROOT/orchestrator/internal/hypervisor/libvirt/netconfig.go"
L2_UP="$REPO_ROOT/scripts/nested-testbed/inside-l1/l2-up.sh"

_rc=0
_run_checks "$LIVE_GO" "$NETCONFIG_GO" "$L2_UP" || _rc=$?

if [ "$_rc" -ne 0 ]; then
    printf 'check-macceil-drift: FAIL — nested-testbed MAC/ceiling literal drifted from the Go source of truth (rc=%d)\n' "$_rc" >&2
    exit "$_rc"
fi

printf 'check-macceil-drift: OK — nested-testbed MAC render + /31 ceiling lockstep with the Go source\n'
