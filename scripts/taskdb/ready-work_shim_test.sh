#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# ready-work_shim_test.sh — regression test for the ready-work.py back-compat shim.
#
# ready-work.py is a THIN SHIM that locates the taskdb binary and execs
# `taskdb work`, forwarding ALL of its arguments VERBATIM (see ready-work.py and
# .claude/workflows/FINDING-WORK.md §1.1). External callers still invoke the shim
# by path, so its EXEC CONTRACT — binary resolution + verbatim argv forwarding —
# is load-bearing back-compat surface. This test locks that contract so a future
# edit to the shim cannot silently break those callers.
#
# It asserts three things, against a FAKE taskdb that merely echoes its argv:
#   1. TASKDB_BIN, when set to an existing executable, is the resolved binary and
#      args are forwarded as `work <argv...>` unchanged.
#   2. With TASKDB_BIN unset, a cwd-anchored .bin/taskdb is resolved.
#   3. With neither TASKDB_BIN nor any .bin/taskdb reachable, `taskdb` on PATH is
#      resolved.
#   4. Representative flags (value flags, `--flag=value`, repeated/positional,
#      and `--` style tokens) are forwarded BYTE-FOR-BYTE after the `work` verb.
#
# Hermetic: no network, no real taskdb, no live claude/cia — only a tiny shell
# stub on a scratch PATH/dir. POSIX sh; runs under any /bin/sh.
#
# Usage:
#   sh scripts/taskdb/ready-work_shim_test.sh

set -eu

# --- locate the shim under test (anchored to THIS test file, cwd-independent) --
TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
SHIM="${TEST_DIR}/ready-work.py"

if [ ! -f "${SHIM}" ]; then
  echo "FAIL: shim under test not found at ${SHIM}" >&2
  exit 1
fi

# A python3 interpreter is required to run the shim.
if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: python3 not found on PATH — required to run the ready-work.py shim" >&2
  exit 1
fi

# --- scratch sandbox, cleaned on any exit ------------------------------------
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ready-work-shim-test.XXXXXX")
trap 'rm -rf "${WORK}"' EXIT INT TERM

# The fake taskdb: echoes argv0 then one line per arg, NUL-free and verbatim.
# `set -eu` in the test must not leak into the stub, so the stub is fully
# self-contained. Each arg is printed on its own line prefixed with ARG= so the
# assertions can compare byte-for-byte (a trailing/embedded space in an arg
# survives because we read whole lines).
make_fake_taskdb() {
  # $1 = destination path for the executable stub
  cat > "$1" <<'STUB'
#!/bin/sh
printf 'ARGV0=%s\n' "$0"
for a in "$@"; do
  printf 'ARG=%s\n' "$a"
done
STUB
  chmod +x "$1"
}

# Assert that $1 (haystack) contains the exact line $2 (needle).
assert_line() {
  # $1 = output, $2 = expected exact line, $3 = case label
  printf '%s\n' "$1" | grep -qxF -- "$2" || {
    echo "FAIL [$3]: expected line not found: <$2>" >&2
    echo "----- actual output -----" >&2
    printf '%s\n' "$1" >&2
    echo "-------------------------" >&2
    exit 1
  }
}

# Assert that $1 (haystack) does NOT contain a line equal to $2.
refute_line() {
  if printf '%s\n' "$1" | grep -qxF -- "$2"; then
    echo "FAIL [$3]: unexpected line present: <$2>" >&2
    echo "----- actual output -----" >&2
    printf '%s\n' "$1" >&2
    echo "-------------------------" >&2
    exit 1
  fi
}

PASS=0

# ---------------------------------------------------------------------------
# Case 1: TASKDB_BIN wins and args forward verbatim as `work <argv...>`.
#         Also exercises the trickiest argv: a value flag, an `--flag=value`
#         token, a bare positional, and a literal `--` token. None of these are
#         options the shim itself understands, so each one proves the shim does
#         NO parsing of its own and hands argv through untouched.
# ---------------------------------------------------------------------------
BIN1="${WORK}/explicit-taskdb"
make_fake_taskdb "${BIN1}"

OUT=$(
  TASKDB_BIN="${BIN1}" python3 "${SHIM}" \
    --tag gated --epic=01KTWJ1VX0 --substantive -- 01ABC
)

assert_line "${OUT}" "ARGV0=${BIN1}"   "TASKDB_BIN resolves binary"
assert_line "${OUT}" "ARG=work"        "verb prepended"
assert_line "${OUT}" "ARG=--tag"       "value flag name forwarded"
assert_line "${OUT}" "ARG=gated"       "value flag value forwarded"
assert_line "${OUT}" "ARG=--epic=01KTWJ1VX0" "--flag=value token forwarded intact"
assert_line "${OUT}" "ARG=--substantive"     "boolean flag forwarded"
assert_line "${OUT}" "ARG=--"          "double-dash token forwarded"
assert_line "${OUT}" "ARG=01ABC"       "positional forwarded"
# The verb must be 'work' and nothing else should be injected ahead of argv.
refute_line "${OUT}" "ARG=audit"       "no extra verb injected"
PASS=$((PASS + 1))

# A second invocation with an arg containing a space proves whitespace inside a
# single argv element is preserved (no word-splitting in the exec path).
OUT=$(
  TASKDB_BIN="${BIN1}" python3 "${SHIM}" --tag "a b"
)
assert_line "${OUT}" "ARG=a b"         "embedded-space arg preserved verbatim"
PASS=$((PASS + 1))

# Zero-arg invocation forwards exactly `work` and nothing else.
OUT=$(
  TASKDB_BIN="${BIN1}" python3 "${SHIM}"
)
assert_line "${OUT}" "ARG=work"        "bare invocation forwards just 'work'"
NARGS=$(printf '%s\n' "${OUT}" | grep -c '^ARG=' || true)
[ "${NARGS}" -eq 1 ] || {
  echo "FAIL [bare invocation]: expected exactly 1 forwarded arg, got ${NARGS}" >&2
  printf '%s\n' "${OUT}" >&2
  exit 1
}
PASS=$((PASS + 1))

# ---------------------------------------------------------------------------
# Case 2: with TASKDB_BIN unset, a cwd-anchored .bin/taskdb is resolved.
#         The shim ALSO anchors resolution to its own location (3 dirs up), and
#         the real repo .bin/taskdb sits there — so to test the cwd branch
#         hermetically we run an ISOLATED COPY of the shim whose own anchor has
#         no .bin/taskdb, leaving the cwd copy as the only candidate.
# ---------------------------------------------------------------------------
ISO="${WORK}/iso"            # isolated shim copy; its 3-up has no .bin/taskdb
mkdir -p "${ISO}/lvl1/lvl2"
cp "${SHIM}" "${ISO}/lvl1/lvl2/ready-work.py"
[ ! -e "${ISO}/.bin/taskdb" ] || { echo "FAIL: isolated anchor unexpectedly has .bin/taskdb" >&2; exit 1; }

CWDROOT="${WORK}/cwdroot"
mkdir -p "${CWDROOT}/.bin"
make_fake_taskdb "${CWDROOT}/.bin/taskdb"

OUT=$(
  cd "${CWDROOT}" \
    && env -u TASKDB_BIN python3 "${ISO}/lvl1/lvl2/ready-work.py" --all
)
assert_line "${OUT}" "ARGV0=${CWDROOT}/.bin/taskdb" "cwd-anchored .bin/taskdb resolved"
assert_line "${OUT}" "ARG=work" "verb prepended (cwd branch)"
assert_line "${OUT}" "ARG=--all" "arg forwarded (cwd branch)"
PASS=$((PASS + 1))

# ---------------------------------------------------------------------------
# Case 3: with no TASKDB_BIN and no reachable .bin/taskdb, fall back to `taskdb`
#         on PATH. Uses the isolated shim copy (anchor has no .bin/taskdb) and a
#         cwd that also has no .bin/taskdb, so PATH is the only resolution left.
# ---------------------------------------------------------------------------
PATHDIR="${WORK}/pathbin"
mkdir -p "${PATHDIR}"
make_fake_taskdb "${PATHDIR}/taskdb"

EMPTYCWD="${WORK}/emptycwd"
mkdir -p "${EMPTYCWD}"
[ ! -e "${EMPTYCWD}/.bin/taskdb" ] || { echo "FAIL: empty cwd unexpectedly has .bin/taskdb" >&2; exit 1; }

OUT=$(
  cd "${EMPTYCWD}" \
    && env -u TASKDB_BIN PATH="${PATHDIR}:/usr/bin:/bin" \
       python3 "${ISO}/lvl1/lvl2/ready-work.py" --json
)
assert_line "${OUT}" "ARGV0=${PATHDIR}/taskdb" "PATH-resolved taskdb used"
assert_line "${OUT}" "ARG=work" "verb prepended (PATH branch)"
assert_line "${OUT}" "ARG=--json" "arg forwarded (PATH branch)"
PASS=$((PASS + 1))

echo "ready-work_shim_test: OK (${PASS} cases) — shim resolves the binary and forwards argv verbatim"
