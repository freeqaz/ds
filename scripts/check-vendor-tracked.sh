#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# check-vendor-tracked.sh — assert that every path listed in a vendored crate's
# .cargo-checksum.json "files" map is tracked by git, and that no untracked
# files lurk under dataplane/vendor/.
#
# WHY: root .gitignore patterns (bin/, .idea/, __pycache__/, *.sw?) can match
# inside vendored crate directories.  A `cargo vendor` run on a machine that
# produced those patterns results in branches that build locally (the files are
# present) but fail on every fresh clone (`cargo build --locked` checksum
# verification fails because git-checkout never restores the untracked files).
# This lint catches that class of breakage at static-analysis time, matching
# the repo fail-closed posture (D47 spirit).
#
# Two assertions:
#   1. For each dataplane/vendor/*/.cargo-checksum.json, parse the "files" map
#      keys and assert each path (relative to the crate dir) appears in
#      `git ls-files` for that crate directory.
#   2. Assert `git ls-files --others --exclude-standard dataplane/vendor/` is
#      empty — catches present-but-untracked vendor files before they vanish in
#      clones.
#
# LOUD SKIP (exit 0, reason on stderr) when dataplane/vendor/ contains no crate
# directories (detected by the absence of any .cargo-checksum.json files).
# The base tree has only vendor/README.md — this keeps pre-vendor branches
# green, mirroring the scripts/check-runbook-nft.sh skip pattern.
#
# Requires: bash, python3 (stdlib only), git.
# Network-free.
#
# Exit codes: 0 = all checksummed paths are git-tracked AND no untracked files
#               under dataplane/vendor/ (or: no crate dirs present — loud skip)
#             1 = at least one checksummed path is not git-tracked; or at least
#               one untracked file exists under dataplane/vendor/; or python3 or
#               git are not available; or a .cargo-checksum.json cannot be parsed.

set -euo pipefail

# --- locate repo root (git-anchored; fall back to script-relative) ----------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    :
else
    ROOT=$(cd "$(dirname "$0")/.." && pwd)
fi

VENDOR_DIR="${ROOT}/dataplane/vendor"

# --- LOUD SKIP when no crate directories are present -----------------------
# A crate directory is one that contains a .cargo-checksum.json file.
# `find` returns nothing if the glob matches nothing; -maxdepth 2 keeps it
# to immediate crate children (vendor/<name>/.cargo-checksum.json).
CHECKSUM_FILES=()
while IFS= read -r -d '' f; do
    CHECKSUM_FILES+=("$f")
done < <(find "${VENDOR_DIR}" -maxdepth 2 -name '.cargo-checksum.json' -print0 2>/dev/null || true)

if [ "${#CHECKSUM_FILES[@]}" -eq 0 ]; then
    echo "check-vendor-tracked: SKIP — dataplane/vendor/ contains no crate directories (no .cargo-checksum.json found); vendor tracking lint is SKIPPED on this tree (add vendored crates to enforce the lint)" >&2
    exit 0
fi

echo "check-vendor-tracked: found ${#CHECKSUM_FILES[@]} vendored crate(s) to verify"

FAIL=0

# Shared temp file cleanup: we use temp files to hold large tracked-path lists
# reliably (a large shell variable piped through grep can be truncated by the
# shell's pipe buffer limits).
_tmpfiles=()
cleanup() {
    for f in "${_tmpfiles[@]:-}"; do
        rm -f "$f" 2>/dev/null || true
    done
}
trap cleanup EXIT

# --- assertion 1: every checksummed path must be git-tracked ----------------
for checksum_file in "${CHECKSUM_FILES[@]}"; do
    crate_dir=$(dirname "$checksum_file")
    crate_name=$(basename "$crate_dir")

    # Parse the "files" map keys from the JSON using python3 stdlib.
    # .cargo-checksum.json schema: {"files": {"<relative-path>": "<sha256>", ...}, "package": "..."}
    # We only need the keys of the "files" object.
    CHECKSUMMED_FILE=$(mktemp)
    _tmpfiles+=("$CHECKSUMMED_FILE")

    python3 - "$checksum_file" > "$CHECKSUMMED_FILE" <<'PYEOF' || {
import json
import sys

path = sys.argv[1]
try:
    with open(path) as f:
        data = json.load(f)
except Exception as e:
    print(f"ERROR: cannot parse {path}: {e}", file=sys.stderr)
    sys.exit(1)

files = data.get("files", {})
if not isinstance(files, dict):
    print(f"ERROR: 'files' key in {path} is not a dict", file=sys.stderr)
    sys.exit(1)

for rel_path in files.keys():
    print(rel_path)
PYEOF
        echo "check-vendor-tracked: ERROR: failed to parse ${checksum_file}" >&2
        FAIL=1
        continue
    }

    checksummed_count=$(wc -l < "$CHECKSUMMED_FILE" || echo 0)
    if [ "${checksummed_count}" -eq 0 ]; then
        # An empty files map is unusual but not an error — nothing to check.
        echo "check-vendor-tracked: ${crate_name}: files map is empty — nothing to verify"
        continue
    fi

    # Build a temp file of git-tracked paths under the crate directory.
    # Using a file (not a shell variable) avoids pipe-buffer truncation on
    # large crates (e.g. wit-component with 775 checksummed paths).
    TRACKED_FILE=$(mktemp)
    _tmpfiles+=("$TRACKED_FILE")
    git -C "$ROOT" ls-files -- "$crate_dir" \
        | sed "s|^dataplane/vendor/${crate_name}/||" \
        > "$TRACKED_FILE"

    crate_fail=0
    while IFS= read -r rel_path; do
        [ -z "$rel_path" ] && continue
        # Check if this relative path appears in the tracked set.
        if ! grep -qxF "$rel_path" "$TRACKED_FILE"; then
            echo "check-vendor-tracked: ERROR: ${crate_name}/${rel_path} is listed in .cargo-checksum.json but is NOT git-tracked (gitignore pattern match? run: git add dataplane/vendor/${crate_name}/${rel_path})" >&2
            crate_fail=1
        fi
    done < "$CHECKSUMMED_FILE"

    if [ "$crate_fail" -eq 0 ]; then
        echo "check-vendor-tracked: ${crate_name}: all checksummed paths are git-tracked (OK)"
    else
        FAIL=1
    fi
done

# --- assertion 2: no untracked files under dataplane/vendor/ -----------------
UNTRACKED=$(git -C "$ROOT" ls-files --others --exclude-standard "${VENDOR_DIR}" 2>/dev/null || true)

if [ -n "$UNTRACKED" ]; then
    echo "check-vendor-tracked: ERROR: untracked files found under dataplane/vendor/ — these will be absent in fresh clones and may break cargo build --locked:" >&2
    printf '%s\n' "$UNTRACKED" | while IFS= read -r f; do
        echo "  untracked: $f" >&2
    done
    echo "  (run: git add <paths> to track them, or add to .gitignore if they should not be vendored)" >&2
    FAIL=1
else
    echo "check-vendor-tracked: no untracked files under dataplane/vendor/ (OK)"
fi

if [ "$FAIL" -eq 0 ]; then
    echo "check-vendor-tracked: OK — all vendored crate paths are git-tracked"
    exit 0
else
    exit 1
fi
