#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# check-controlplane-mtls-single-builder.sh — assert a SINGLE TLS-dial-credentials
# builder symbol in orchestrator/internal/controlplane.
#
# The mTLS DialOption builder is the one source of truth for the orchestrator's
# live-dial transport-credentials posture (doc 15 §2, D35): the lone exported
# MTLSDialOptionFromEnv reads the DS_ORCH_TLS_* triplet, loads the client
# keypair, pins the peer cert, and is composed into BOTH live legs (the
# hypervisor.v1 driver dial AND the Identity D22/D82 dial). Re-introducing a
# second *TLSDialOptionFromEnv builder — or an unexported in-package
# mTLSDialOptionFromEnv forwarder — splits that single source of truth and lets
# the two legs drift in their TLS floor / CA-pinning / half-config posture. This
# lint fails closed the next time either appears.
#
# It asserts, over orchestrator/internal/controlplane/*.go (PRODUCTION files
# only — *_test.go are excluded; tests legitimately name the builder many times):
#
#   (a) NO `func mTLSDialOptionFromEnv` — no unexported in-package forwarder is
#       reintroduced.
#   (b) at most ONE exported `func *TLSDialOptionFromEnv` builder — the lone
#       MTLSDialOptionFromEnv.
#
# FAIL-CLOSED contract: any offending declaration fails the lint, naming the
# offending file:line. Stdlib/coreutils only (grep/sed/sort); network-free.
# POSIX sh.
#
# Self-test:  check-controlplane-mtls-single-builder.sh --self-test
#   Drives the assertion over synthetic scratch trees: a clean single-builder
#   tree PASSES; a planted second exported builder FAILS; a planted unexported
#   forwarder FAILS.
#
# Exit codes: 0 = single exported builder, no unexported forwarder
#             1 = a forbidden/duplicate builder declaration was found
#             2 = structural error (target directory missing / no matching file)

set -eu

# --- locate repo root (git-anchored; fall back to cwd) ---------------------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    :
else
    ROOT=$(pwd)
fi

# scan_dir DIR
# Runs the single-builder assertion over the PRODUCTION *.go files (no _test.go)
# directly under DIR. Prints OK/FAIL diagnostics. Returns:
#   0 = clean, 1 = forbidden/duplicate builder, 2 = structural error.
scan_dir() {
    _dir="$1"

    if [ ! -d "$_dir" ]; then
        echo "check-controlplane-mtls-single-builder: ERROR — target directory missing: $_dir" >&2
        return 2
    fi

    # Production Go files only: exclude *_test.go. Use a portable glob loop so a
    # tree with spaces in a path is handled, and skip the literal-glob case when
    # nothing matches.
    _files=""
    for _f in "$_dir"/*.go; do
        [ -e "$_f" ] || continue
        case "$_f" in
            *_test.go) continue ;;
        esac
        _files="${_files}${_f}
"
    done

    if [ -z "$_files" ]; then
        echo "check-controlplane-mtls-single-builder: ERROR — no production *.go files under $_dir — fail-closed" >&2
        return 2
    fi

    _fail=0

    # (a) NO unexported in-package forwarder: func mTLSDialOptionFromEnv(...
    # Match the declaration with a leading lowercase 'm' immediately at func.
    _forwarders=$(printf '%s' "$_files" | while IFS= read -r _f; do
        [ -n "$_f" ] || continue
        grep -nE '^[[:space:]]*func[[:space:]]+mTLSDialOptionFromEnv[[:space:]]*\(' "$_f" 2>/dev/null \
            | sed "s|^|${_f}:|" || true
    done)
    if [ -n "$_forwarders" ]; then
        echo "check-controlplane-mtls-single-builder: FAIL — unexported in-package forwarder func mTLSDialOptionFromEnv reintroduced:" >&2
        printf '%s\n' "$_forwarders" | sed 's/^/    /' >&2
        _fail=1
    fi

    # (b) at most ONE exported *TLSDialOptionFromEnv builder.
    # Match: func <Exported>TLSDialOptionFromEnv( where the leading run of name
    # characters before "TLSDialOptionFromEnv" starts with an uppercase letter
    # (an exported identifier). The regex anchors func ... <Upper>...TLSDialOptionFromEnv(.
    _builders=$(printf '%s' "$_files" | while IFS= read -r _f; do
        [ -n "$_f" ] || continue
        grep -nE '^[[:space:]]*func[[:space:]]+[A-Z][A-Za-z0-9_]*TLSDialOptionFromEnv[[:space:]]*\(' "$_f" 2>/dev/null \
            | sed "s|^|${_f}:|" || true
    done)

    _count=0
    if [ -n "$_builders" ]; then
        _count=$(printf '%s\n' "$_builders" | grep -c . || true)
    fi

    if [ "$_count" -gt 1 ]; then
        echo "check-controlplane-mtls-single-builder: FAIL — more than one exported *TLSDialOptionFromEnv builder (expected exactly the lone MTLSDialOptionFromEnv):" >&2
        printf '%s\n' "$_builders" | sed 's/^/    /' >&2
        _fail=1
    fi

    if [ "$_fail" -ne 0 ]; then
        return 1
    fi

    echo "check-controlplane-mtls-single-builder: OK — exactly $_count exported builder, no unexported forwarder ($_dir)"
    return 0
}

# ----------------------------------------------------------------- self-test
run_self_test() {
    _tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf \"$_tmp\"" EXIT INT TERM

    _rc=0

    # Case 1: clean single-builder tree -> PASS (rc 0).
    mkdir -p "$_tmp/clean"
    cat > "$_tmp/clean/dialregistry.go" <<'EOF'
package controlplane

func MTLSDialOptionFromEnv() (DialOption, bool, error) { return nil, false, nil }
EOF
    # A *_test.go that names the builder must be IGNORED by the production scan.
    cat > "$_tmp/clean/dialregistry_test.go" <<'EOF'
package controlplane

func TestMTLSDialOptionFromEnv_x(t *testing.T) { _, _, _ = MTLSDialOptionFromEnv() }
EOF
    if scan_dir "$_tmp/clean" >/dev/null 2>&1; then
        echo "self-test: clean single-builder tree PASSED (as expected)"
    else
        echo "self-test: FAIL — clean single-builder tree should PASS but did not" >&2
        _rc=1
    fi

    # Case 2: a planted SECOND exported builder -> FAIL (rc 1).
    mkdir -p "$_tmp/dup"
    cat > "$_tmp/dup/dialregistry.go" <<'EOF'
package controlplane

func MTLSDialOptionFromEnv() (DialOption, bool, error) { return nil, false, nil }
EOF
    cat > "$_tmp/dup/extra.go" <<'EOF'
package controlplane

func LegacyTLSDialOptionFromEnv() (DialOption, bool, error) { return nil, false, nil }
EOF
    if scan_dir "$_tmp/dup" >/dev/null 2>&1; then
        echo "self-test: FAIL — planted second exported builder should FAIL but PASSED" >&2
        _rc=1
    else
        echo "self-test: planted second exported builder FAILED the lint (as expected)"
    fi

    # Case 3: a planted unexported forwarder -> FAIL (rc 1).
    mkdir -p "$_tmp/fwd"
    cat > "$_tmp/fwd/dialregistry.go" <<'EOF'
package controlplane

func MTLSDialOptionFromEnv() (DialOption, bool, error) { return mTLSDialOptionFromEnv() }

func mTLSDialOptionFromEnv() (DialOption, bool, error) { return nil, false, nil }
EOF
    if scan_dir "$_tmp/fwd" >/dev/null 2>&1; then
        echo "self-test: FAIL — planted unexported forwarder should FAIL but PASSED" >&2
        _rc=1
    else
        echo "self-test: planted unexported forwarder FAILED the lint (as expected)"
    fi

    if [ "$_rc" -eq 0 ]; then
        echo "check-controlplane-mtls-single-builder: self-test OK"
    else
        echo "check-controlplane-mtls-single-builder: self-test FAILED" >&2
    fi
    return "$_rc"
}

# ----------------------------------------------------------------- main
if [ "${1:-}" = "--self-test" ]; then
    run_self_test
    exit $?
fi

TARGET_DIR="${ROOT}/orchestrator/internal/controlplane"
# Allow override for negative tests (unused by the standing gate).
TARGET_DIR="${CHECK_MTLS_TARGET_DIR:-$TARGET_DIR}"

scan_dir "$TARGET_DIR"
exit $?
