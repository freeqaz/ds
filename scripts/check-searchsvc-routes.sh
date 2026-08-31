#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# check-searchsvc-routes.sh — doc-vs-code route-parity lint for searchsvc.
#
# The searchsvc README (scripts/taskdb/searchsvc/README.md) carries a "Wire
# contract" route table; the dispatcher (scripts/taskdb/searchsvc/serve.py)
# declares its routes twice — once as FastAPI `@app.post("/route")` decorators
# and once as the stdlib fallback `self.path == "/route"` dispatch. The table
# drifted from the code once already. This lint fails CLOSED the next time a
# route lands in serve.py without a README row (or a README row names a route
# serve.py no longer serves), instead of relying on a manual reconcile.
#
# It asserts a THREE-WAY set equality:
#   1. FastAPI @app.post("...") routes,
#   2. stdlib self.path == "..." routes, and
#   3. README route-table rows (the leading `| `/route` |` cells),
# are all the SAME set. A route missing from any of the three fails named.
#
# Network-free; runs in seconds. POSIX sh + grep/sed/sort only. READ-ONLY: it
# only greps README.md and serve.py — it never edits either.
#
# Exit codes: 0 = all three route sets agree (prints "PARITY: OK")
#             1 = a route set differs, or a source file is missing

set -eu

# --- locate repo root (git-anchored; fall back to cwd) ---------------------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    :
else
    ROOT=$(pwd)
fi

SVC_DIR="${ROOT}/scripts/taskdb/searchsvc"
README="${SVC_DIR}/README.md"
SERVE="${SVC_DIR}/serve.py"

# Allow overrides for negative self-tests (scratch copies).
README="${CHECK_SEARCHSVC_README:-$README}"
SERVE="${CHECK_SEARCHSVC_SERVE:-$SERVE}"

fail=0
for f in "$README" "$SERVE"; do
    if [ ! -f "$f" ]; then
        echo "check-searchsvc-routes: MISSING file: $f" >&2
        fail=1
    fi
done
[ "$fail" -eq 0 ] || exit 1

# FastAPI decorator routes: @app.post("/route") — extract just the /route token.
fastapi_routes=$(grep -oE '@app\.post\("/[a-z_]+"' "$SERVE" \
    | grep -oE '/[a-z_]+' | sort -u)

# stdlib fallback routes: self.path == "/route".
stdlib_routes=$(grep -oE 'self\.path *== *"/[a-z_]+"' "$SERVE" \
    | grep -oE '/[a-z_]+' | sort -u)

# README route-table rows: a markdown table cell `| `/route` |` — the first cell
# of each route row wraps the path in backticks.
readme_routes=$(grep -oE '^\| `/[a-z_]+`' "$README" \
    | grep -oE '/[a-z_]+' | sort -u)

if [ -z "$fastapi_routes" ]; then
    echo "check-searchsvc-routes: FAIL — no @app.post routes found in $SERVE" >&2
    exit 1
fi
if [ -z "$stdlib_routes" ]; then
    echo "check-searchsvc-routes: FAIL — no self.path== routes found in $SERVE" >&2
    exit 1
fi
if [ -z "$readme_routes" ]; then
    echo "check-searchsvc-routes: FAIL — no route-table rows found in $README" >&2
    exit 1
fi

# diff_sets LABEL_A SET_A LABEL_B SET_B — print any element in exactly one set.
diff_sets() {
    _la="$1"; _sa="$2"; _lb="$3"; _sb="$4"
    _only_a=$(comm -23 <(printf '%s\n' "$_sa") <(printf '%s\n' "$_sb"))
    _only_b=$(comm -13 <(printf '%s\n' "$_sa") <(printf '%s\n' "$_sb"))
    _d=0
    if [ -n "$_only_a" ]; then
        echo "check-searchsvc-routes: FAIL — route(s) in $_la but not $_lb:" >&2
        printf '    %s\n' $_only_a >&2
        _d=1
    fi
    if [ -n "$_only_b" ]; then
        echo "check-searchsvc-routes: FAIL — route(s) in $_lb but not $_la:" >&2
        printf '    %s\n' $_only_b >&2
        _d=1
    fi
    return $_d
}

rc=0
diff_sets "serve.py @app.post" "$fastapi_routes" "serve.py self.path" "$stdlib_routes" || rc=1
diff_sets "serve.py @app.post" "$fastapi_routes" "README table" "$readme_routes" || rc=1

if [ "$rc" -ne 0 ]; then
    echo "check-searchsvc-routes: FAIL — README route table and serve.py routes disagree." >&2
    echo "  Update the README 'Wire contract' table (scripts/taskdb/searchsvc/README.md)" >&2
    echo "  or the serve.py routes so all three route sets match." >&2
    exit 1
fi

count=$(printf '%s\n' "$fastapi_routes" | grep -c '^/')
echo "check-searchsvc-routes: PARITY: OK — $count routes agree across @app.post, self.path, and the README table"
exit 0
