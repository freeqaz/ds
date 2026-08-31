#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-spdx.sh — verify that every source file in the allowlisted trees
# carries an SPDX-License-Identifier: Apache-2.0 header (D25, docs/08 §1).
#
# RATCHET PLAN: this list is deliberately PARTIAL (wave-5 scope).  Later waves
# extend coverage by adding entries to TREES below:
#
#   Wave 5: vm/, identity/, assurance/ (minus load-rig)
#   Current: + scripts/, images/ (golden + cache + mirror OSS shell)
#   Wave N+1: client/
#   Wave N+2: orchestrator/, infra/
#   Wave N+3: dataplane/  (frozen-module discipline applies)
#   Wave N+4: boundary/   (the executable-specification tree, D26)
#
# Exclusions that apply to every wave:
#   - assurance/load-rig/**        (INTERNAL per D51 — excluded from OSS publication)
#   - **/testdata/**               (test fixtures, not source)
#   - **/fixtures/**               (same)
#   - generated files (*.pb.go, *.gen.go, etc.)
#   - markdown, text, yaml, toml, mod/sum files
#
# Exit codes: 0 = all clear, 1 = one or more files missing the identifier.
#
# Usage:
#   scripts/check-spdx.sh                    # check the allowlisted trees
#   scripts/check-spdx.sh --fix              # print offending files (no auto-fix)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Allowlisted trees — EXTEND THIS LIST in later waves (see RATCHET PLAN above).
TREES=(
  vm
  identity
  assurance
  scripts
  images
)

# Patterns to skip within allowlisted trees.
EXCLUDE_PATTERNS=(
  "*/load-rig/*"
  "*/testdata/*"
  "*/fixtures/*"
  "*.pb.go"
  "*.gen.go"
  "*_gen.go"
)

# Source file extensions to check.
EXTENSIONS=( "*.go" "*.rs" "*.sh" "*.py" "*.ts" )

MISSING=()

# Build git ls-files path specs: one per (tree, extension) pair.
# We enumerate only git-tracked files so a parallel session's untracked
# in-flight content (node_modules, draft fixtures, etc.) never fails this gate.
ls_files_args=()
for tree in "${TREES[@]}"; do
  tree_path="${REPO_ROOT}/${tree}"
  if [[ ! -d "${tree_path}" ]]; then
    echo "WARNING: tree '${tree}' not found at ${tree_path} — skipping" >&2
    continue
  fi
  for ext in "${EXTENSIONS[@]}"; do
    ls_files_args+=( "${tree}/${ext}" )
  done
done

if [[ ${#ls_files_args[@]} -eq 0 ]]; then
  echo "check-spdx: no trees found — nothing to check" >&2
  exit 0
fi

# git ls-files emits repo-root-relative paths for the given pathspecs.
# Run from REPO_ROOT so relative paths resolve correctly.
while IFS= read -r rel; do
  # Apply exclusion patterns (matched against the repo-root-relative path).
  skip=false
  for excl in "${EXCLUDE_PATTERNS[@]}"; do
    # shellcheck disable=SC2254  # glob in case is intentional
    case "${rel}" in
      ${excl}) skip=true; break ;;
    esac
  done
  [[ "${skip}" == true ]] && continue

  file="${REPO_ROOT}/${rel}"
  if ! grep -qF 'SPDX-License-Identifier: Apache-2.0' "${file}"; then
    MISSING+=( "${rel}" )
  fi
done < <(git -C "${REPO_ROOT}" ls-files -- "${ls_files_args[@]}" 2>/dev/null)

if [[ ${#MISSING[@]} -eq 0 ]]; then
  echo "check-spdx: all source files in allowlisted trees carry SPDX-License-Identifier: Apache-2.0"
  exit 0
else
  echo "check-spdx: MISSING SPDX header in ${#MISSING[@]} file(s):" >&2
  for f in "${MISSING[@]}"; do
    echo "  ${f}" >&2
  done
  exit 1
fi
