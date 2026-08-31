#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# check-corpus-suffix.sh — assert that the two corpus-canonical-suffix constants
# are byte-identical across the Go and Rust readers (D-coupling assertion).
#
# The drift corpus location is encoded in two source files:
#
#   Go  assurance/conformance-adapter/resolverlock/resolverlock.go
#       const CorpusFixturesCanonicalSuffix = "..."
#
#   Rust dataplane/crates/policy-core/tests/pack_drift_corpus.rs
#       const CORPUS_CANONICAL_SUFFIX: &str = "..."
#
# This script extracts the string literal assigned to each named constant,
# strips surrounding double-quotes, and asserts byte-equality.
#
# FAIL-CLOSED contract: if EITHER constant is missing or unparseable, the
# script exits non-zero and names BOTH constants and BOTH files.  An
# extraction miss is always a failure, never a skip.
#
# Stdlib/coreutils only; network-free.  POSIX sh.
#
# It ALSO enforces the D127 token-scope taxonomy is byte-identical across three
# sites (Go auth-sdk config, Rust ds-contracts, Go mint grant table); see below.
#
# `--self-test` runs a scratch-copy negative test proving the D127 scope-parity
# gate fails closed on a divergent mint literal.
#
# Exit codes: 0 = constants present and byte-identical (or --self-test passed)
#             1 = mismatch or extraction failure

set -eu

# --- locate repo root (git-anchored; fall back to cwd) ---------------------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    :
else
    ROOT=$(pwd)
fi

# --- optional negative self-test -------------------------------------------
# `check-corpus-suffix.sh --self-test` proves the D127 three-site scope-parity
# gate below actually fails closed.  It copies the three scope-declaring files
# into a scratch dir and re-invokes THIS script over the copies (via the
# CHECK_SCOPE_*_FILE overrides), asserting: (1) the gate PASSES over untouched
# copies, and (2) a single typo'd mint scope literal makes the gate FAIL.
# mktemp/cp/sed/coreutils only; network-free.
if [ "${1:-}" = "--self-test" ]; then
    _st_tmp=$(mktemp -d "${TMPDIR:-/tmp}/corpus-suffix-selftest.XXXXXX")
    trap 'rm -rf "$_st_tmp"' EXIT INT TERM
    cp "${ROOT}/identity/auth-sdk/token/config.go"        "$_st_tmp/config.go"
    cp "${ROOT}/dataplane/crates/ds-contracts/src/scopes.rs" "$_st_tmp/scopes.rs"
    cp "${ROOT}/identity/mint/server.go"                  "$_st_tmp/server.go"

    # (1) byte-identical scratch copies → the gate MUST pass.
    if ! CHECK_SCOPE_GO_FILE="$_st_tmp/config.go" \
         CHECK_SCOPE_RS_FILE="$_st_tmp/scopes.rs" \
         CHECK_SCOPE_MINT_FILE="$_st_tmp/server.go" \
         sh "$0" >/dev/null 2>&1; then
        echo "check-corpus-suffix --self-test: FAIL — gate rejected byte-identical scratch copies" >&2
        exit 1
    fi

    # (2) diverge ONE mint scope literal → the gate MUST fail closed.
    # The corruption target is DERIVED from the first extracted mint scope
    # literal (sorted), never a hardcoded string: renaming or retiring any
    # single scope can no longer turn this negative case into a silent no-op
    # (which would leave the "fails closed" claim untested).  We append "-x" to
    # the last segment — still a valid scope shape (so the widened extractor
    # picks it up), but divergent from the Go+Rust sites, so the parity gate
    # must reject it.
    _st_target=$(grep -oE '"v1:[a-z][a-z:-]*"' "$_st_tmp/server.go" 2>/dev/null \
        | tr -d '"' | sort -u | head -n1)
    if [ -z "$_st_target" ]; then
        echo "check-corpus-suffix --self-test: FAIL — no mint scope literal found to diverge" >&2
        exit 1
    fi
    # scopes are [a-z:-] only → no sed BRE metacharacters, / delimiter is safe.
    sed "s/\"${_st_target}\"/\"${_st_target}-x\"/" "$_st_tmp/server.go" > "$_st_tmp/server.go.new"
    # Non-vacuity guard: the corruption MUST actually change the file, else the
    # negative case proves nothing.
    if cmp -s "$_st_tmp/server.go" "$_st_tmp/server.go.new"; then
        echo "check-corpus-suffix --self-test: FAIL — corruption was a no-op (target \"$_st_target\" not present in mint file)" >&2
        exit 1
    fi
    mv "$_st_tmp/server.go.new" "$_st_tmp/server.go"
    if CHECK_SCOPE_GO_FILE="$_st_tmp/config.go" \
       CHECK_SCOPE_RS_FILE="$_st_tmp/scopes.rs" \
       CHECK_SCOPE_MINT_FILE="$_st_tmp/server.go" \
       sh "$0" >/dev/null 2>&1; then
        echo "check-corpus-suffix --self-test: FAIL — gate PASSED despite a typo'd mint scope literal" >&2
        exit 1
    fi

    echo "check-corpus-suffix --self-test: OK — D127 scope-parity gate fails closed on a divergent mint literal"
    exit 0
fi

GO_FILE="${ROOT}/assurance/conformance-adapter/resolverlock/resolverlock.go"
RS_FILE="${ROOT}/dataplane/crates/policy-core/tests/pack_drift_corpus.rs"
GO_CONST="CorpusFixturesCanonicalSuffix"
RS_CONST="CORPUS_CANONICAL_SUFFIX"

# Allow overrides for negative self-tests (scratch copies).
GO_FILE="${CHECK_CORPUS_GO_FILE:-$GO_FILE}"
RS_FILE="${CHECK_CORPUS_RS_FILE:-$RS_FILE}"

FAIL=0

# extract_go_const FILE CONST_NAME
# Finds:  const <CONST_NAME> = "..."
# where the value may live on the same line or the next line (handles both).
# Prints the bare string value (no quotes) on stdout; returns 1 on failure.
extract_go_const() {
    _file="$1"
    _name="$2"
    if [ ! -f "$_file" ]; then
        echo "check-corpus-suffix: MISSING file: $_file" >&2
        return 1
    fi
    # Try single-line form: const NAME = "value"
    _val=$(grep -oP "(?<=const ${_name} = \")[^\"]*" "$_file" 2>/dev/null || true)
    if [ -n "$_val" ]; then
        printf '%s' "$_val"
        return 0
    fi
    # Try two-line form (e.g. const NAME =\n    "value")
    _val=$(awk -v name="$_name" '
        found && match($0, /"[^"]*"/) { print substr($0, RSTART+1, RLENGTH-2); exit }
        $0 ~ ("const " name " =") { found=1 }
    ' "$_file" 2>/dev/null || true)
    if [ -n "$_val" ]; then
        printf '%s' "$_val"
        return 0
    fi
    return 1
}

# extract_rs_const FILE CONST_NAME
# Finds:  const <CONST_NAME>: &str = "..."   (value may be on next line)
# Prints the bare string value (no quotes) on stdout; returns 1 on failure.
extract_rs_const() {
    _file="$1"
    _name="$2"
    if [ ! -f "$_file" ]; then
        echo "check-corpus-suffix: MISSING file: $_file" >&2
        return 1
    fi
    # Try single-line form: const NAME: &str = "value";
    _val=$(grep -oP "(?<=const ${_name}: &str = \")[^\"]*" "$_file" 2>/dev/null || true)
    if [ -n "$_val" ]; then
        printf '%s' "$_val"
        return 0
    fi
    # Try two-line form: const NAME: &str =\n    "value";
    _val=$(awk -v name="$_name" '
        found && match($0, /"[^"]*"/) { print substr($0, RSTART+1, RLENGTH-2); exit }
        $0 ~ ("const " name ":") { found=1 }
    ' "$_file" 2>/dev/null || true)
    if [ -n "$_val" ]; then
        printf '%s' "$_val"
        return 0
    fi
    return 1
}

# Extract Go constant.
if ! GO_VAL=$(extract_go_const "$GO_FILE" "$GO_CONST"); then
    echo "check-corpus-suffix: FAIL — could not extract const $GO_CONST from $GO_FILE" >&2
    FAIL=1
fi

# Extract Rust constant.
if ! RS_VAL=$(extract_rs_const "$RS_FILE" "$RS_CONST"); then
    echo "check-corpus-suffix: FAIL — could not extract const $RS_CONST from $RS_FILE" >&2
    FAIL=1
fi

# If either extraction failed, bail now (both names + both files already printed).
if [ "$FAIL" -ne 0 ]; then
    echo "check-corpus-suffix: FAIL — at least one constant is missing or unparseable" >&2
    echo "  Go  const: $GO_CONST  in $GO_FILE" >&2
    echo "  Rust const: $RS_CONST  in $RS_FILE" >&2
    exit 1
fi

# Assert byte-equality.
if [ "$GO_VAL" = "$RS_VAL" ]; then
    echo "check-corpus-suffix: OK — $GO_CONST == $RS_CONST (\"$GO_VAL\")"
else
    echo "check-corpus-suffix: FAIL — corpus-suffix constants differ" >&2
    echo "  Go  const $GO_CONST  in $GO_FILE" >&2
    echo "    value: \"$GO_VAL\"" >&2
    echo "  Rust const $RS_CONST  in $RS_FILE" >&2
    echo "    value: \"$RS_VAL\"" >&2
    FAIL=1
fi

# ─────────────────────────────────────────────────────────────────────────────
# D127 token-scope taxonomy coupling (doc 23 §6).
#
# The eight D127 scope strings are declared at THREE sites, and the multi-point
# enforcement only agrees if the STRING SETS are byte-identical:
#
#   Go   identity/auth-sdk/token/config.go   const ScopeCodeRead = "v1:code:read" ...
#   Rust dataplane/crates/ds-contracts/src/scopes.rs  pub const SCOPE_CODE_READ: &str = "v1:code:read"; ...
#   Go   identity/mint/server.go   OpWorkspaceRead: {"v1:code:read"} ...  (mint per-op grant table)
#
# This extracts every `v1:...` scope string literal from each file, sorts them,
# and asserts all THREE SORTED SETS are equal. A scope added/removed/typo'd on
# one site but not the others fails CLOSED here (naming all three files), the
# same fail-closed contract as the corpus-suffix assertion above.
# Stdlib/coreutils only; network-free.
# ─────────────────────────────────────────────────────────────────────────────
SCOPE_GO_FILE="${ROOT}/identity/auth-sdk/token/config.go"
SCOPE_RS_FILE="${ROOT}/dataplane/crates/ds-contracts/src/scopes.rs"
SCOPE_MINT_FILE="${ROOT}/identity/mint/server.go"
# Allow overrides for negative self-tests (scratch copies).
SCOPE_GO_FILE="${CHECK_SCOPE_GO_FILE:-$SCOPE_GO_FILE}"
SCOPE_RS_FILE="${CHECK_SCOPE_RS_FILE:-$SCOPE_RS_FILE}"
SCOPE_MINT_FILE="${CHECK_SCOPE_MINT_FILE:-$SCOPE_MINT_FILE}"

# extract_scope_strings FILE — print every "v1:..." scope string literal (bare,
# one per line, sorted+unique). Both languages quote scopes with double quotes,
# so one grep serves both. Fail (return 1) if the file is missing.
#
# The pattern is "v1:" followed by one lowercase letter and then any run of
# lowercase letters, colons, or HYPHENS.  This intentionally admits hyphenated
# and multi-segment scopes (e.g. "v1:code:read-write", "v1:a:b:c"): a scope of
# that shape added to all three sites now extracts+couples correctly instead of
# being silently dropped by a rigid two-segment pattern (which would let a
# hyphenated scope diverge across sites unnoticed).  The trailing double-quote
# anchors the match, so this never bleeds past the literal.
extract_scope_strings() {
    _file="$1"
    if [ ! -f "$_file" ]; then
        echo "check-corpus-suffix: MISSING scope file: $_file" >&2
        return 1
    fi
    grep -oE '"v1:[a-z][a-z:-]*"' "$_file" 2>/dev/null | tr -d '"' | sort -u
}

if ! SCOPE_GO_VALS=$(extract_scope_strings "$SCOPE_GO_FILE"); then
    echo "check-corpus-suffix: FAIL — could not read Go scope file $SCOPE_GO_FILE" >&2
    FAIL=1
    SCOPE_GO_VALS=""
fi
if ! SCOPE_RS_VALS=$(extract_scope_strings "$SCOPE_RS_FILE"); then
    echo "check-corpus-suffix: FAIL — could not read Rust scope file $SCOPE_RS_FILE" >&2
    FAIL=1
    SCOPE_RS_VALS=""
fi
if ! SCOPE_MINT_VALS=$(extract_scope_strings "$SCOPE_MINT_FILE"); then
    echo "check-corpus-suffix: FAIL — could not read mint scope file $SCOPE_MINT_FILE" >&2
    FAIL=1
    SCOPE_MINT_VALS=""
fi

# A taxonomy of ZERO scopes at ANY site is always a failure (an extraction
# miss must never masquerade as agreement).
SCOPE_GO_COUNT=$(printf '%s\n' "$SCOPE_GO_VALS" | grep -c . || true)
SCOPE_RS_COUNT=$(printf '%s\n' "$SCOPE_RS_VALS" | grep -c . || true)
SCOPE_MINT_COUNT=$(printf '%s\n' "$SCOPE_MINT_VALS" | grep -c . || true)
if [ "$SCOPE_GO_COUNT" -eq 0 ] || [ "$SCOPE_RS_COUNT" -eq 0 ] || [ "$SCOPE_MINT_COUNT" -eq 0 ]; then
    echo "check-corpus-suffix: FAIL — no D127 scope strings extracted (Go=$SCOPE_GO_COUNT Rust=$SCOPE_RS_COUNT Mint=$SCOPE_MINT_COUNT)" >&2
    echo "  Go   scopes: $SCOPE_GO_FILE" >&2
    echo "  Rust scopes: $SCOPE_RS_FILE" >&2
    echo "  Mint scopes: $SCOPE_MINT_FILE" >&2
    FAIL=1
elif [ "$SCOPE_GO_VALS" = "$SCOPE_RS_VALS" ] && [ "$SCOPE_GO_VALS" = "$SCOPE_MINT_VALS" ]; then
    echo "check-corpus-suffix: OK — D127 scope strings byte-identical across Go+Rust+mint ($SCOPE_GO_COUNT scopes)"
else
    echo "check-corpus-suffix: FAIL — D127 scope strings differ across the three sites" >&2
    echo "  Go   ($SCOPE_GO_FILE):" >&2
    printf '    %s\n' $SCOPE_GO_VALS >&2
    echo "  Rust ($SCOPE_RS_FILE):" >&2
    printf '    %s\n' $SCOPE_RS_VALS >&2
    echo "  Mint ($SCOPE_MINT_FILE):" >&2
    printf '    %s\n' $SCOPE_MINT_VALS >&2
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
exit 0
