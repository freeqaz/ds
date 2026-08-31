#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# cloud-coupling-scan.sh — the load-bearing D33 guard: a mechanical, FAIL-CLOSED
# scan of the OSS data-plane import/dependency closure for cloud-SDK packages
# and cloud metadata-endpoint coupling. Exits NON-ZERO the moment a cloud
# dependency is introduced, so a deliberately cloud-coupled change is rejected
# at the release gate (the .github/workflows/release-vanilla-metal.yml lane).
#
# D33 (doc 04 §6): "nothing cloud-specific" is a HARD, CI-ENFORCED constraint
# for the data plane — every release installs on vanilla Linux metal with no
# cloud deps. D80: the OSS single-host all-in-one is orchestrator-lite plus the
# host-side host-agent; the cloud EC2 demo driver
# (orchestrator/internal/hypervisor/ec2demo/) is a SEPARATE capability-flagged
# control-plane tool that the OSS all-in-one must NOT pull. This scan proves it.
#
# WHAT IT SCANS (two complementary lenses):
#   (1) The Go import closure of the OSS data-plane all-in-one targets
#       (`go list -deps` of cmd/orchestrator-lite + cmd/host-agent), matched
#       against the cloud-SDK package deny-list. This is the AUTHORITATIVE check:
#       if a cloud SDK enters the actual build closure, the scan sees it.
#   (2) A textual scan of the OSS data-plane Go sources for cloud metadata
#       endpoints / cloud-SDK import paths that a closure walk could miss (e.g.
#       a string literal hitting 169.254.169.254, or a cloud import behind an
#       unbuilt build tag). Defense in depth — the closure walk is primary.
#
# This script takes NO live cloud calls (D50): it reads the local repo + the Go
# toolchain only. Offline-clean.
#
# Exit codes:
#   0  — no cloud coupling found in the OSS data-plane closure (release-clean)
#   1  — a cloud SDK / metadata-endpoint coupling was found (BLOCK the release)
#   2  — usage / environment error (e.g. go toolchain missing)
#
# Usage:
#   scripts/release/cloud-coupling-scan.sh                # scan the real closure
#   scripts/release/cloud-coupling-scan.sh --self-test    # also assert the scan
#                                                         # REJECTS the synthetic
#                                                         # cloud-coupled fixture
#   scripts/release/cloud-coupling-scan.sh --scan-file F  # scan a single file F
#                                                         # against the deny-list
#                                                         # (used by the negative
#                                                         # control + --self-test)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURES_DIR="$REPO_ROOT/scripts/release/fixtures"

# ---------------------------------------------------------------------------
# THE CLOUD DENY-LIST (D33). Extended regexes, matched case-insensitively. Each
# entry is a cloud-provider SDK import path or a cloud metadata-endpoint string
# that has NO place in the vanilla-Linux-metal OSS data plane. Keep this list in
# sync with scripts/release/README.md (the human-readable deny-list doc).
# ---------------------------------------------------------------------------
DENY_PATTERNS=(
  # --- AWS ---
  'github\.com/aws/aws-sdk-go'          # AWS SDK for Go v1
  'github\.com/aws/aws-sdk-go-v2'       # AWS SDK for Go v2
  'github\.com/aws/smithy-go'           # AWS SDK v2 transport runtime
  # --- Google Cloud ---
  'cloud\.google\.com/go'               # Google Cloud client libraries
  'google\.golang\.org/api/compute'     # GCE compute API client
  # --- Azure ---
  'github\.com/Azure/azure-sdk-for-go'  # Azure SDK for Go
  'github\.com/Azure/go-autorest'       # Azure autorest runtime
  # --- Cloud instance-metadata endpoints (provider-agnostic coupling) ---
  '169\.254\.169\.254'                  # EC2 / GCE / Azure IMDS link-local IP
  'metadata\.google\.internal'          # GCE metadata hostname
  'instance-data\.ec2\.internal'        # EC2 metadata hostname
)

# A single ERE alternation built from the deny-list (used by grep -E -i).
deny_regex() {
  local IFS='|'
  printf '%s' "${DENY_PATTERNS[*]}"
}

# ---------------------------------------------------------------------------
# THE OSS DATA-PLANE BUILD TARGETS (D80). The single-host all-in-one
# (orchestrator-lite) plus the host-side agent (host-agent). These are the
# binaries the release artifact ships and installs on vanilla metal; their
# combined import closure IS the "OSS data-plane closure" D33 constrains.
# ---------------------------------------------------------------------------
OSS_TARGETS=(
  ./cmd/orchestrator-lite
  ./cmd/host-agent
)

note() { printf 'cloud-coupling-scan: %s\n' "$*" >&2; }
die()  { printf 'cloud-coupling-scan: ERROR: %s\n' "$*" >&2; exit 2; }

# scan_file_against_denylist FILE — exits 0 if FILE is clean, 1 if it matches a
# deny-list pattern (printing the offending lines). Pure-text; no toolchain.
scan_file_against_denylist() {
  local file="$1"
  [ -r "$file" ] || die "cannot read file: $file"
  local re hits
  re="$(deny_regex)"
  # grep -E -i: case-insensitive ERE. -n for line numbers in the report.
  if hits="$(grep -E -i -n -- "$re" "$file" 2>/dev/null)"; then
    note "CLOUD COUPLING FOUND in $file:"
    printf '%s\n' "$hits" | sed 's/^/    /' >&2
    return 1
  fi
  return 0
}

# scan_go_closure — the AUTHORITATIVE lens: walk the Go import closure of the
# OSS data-plane targets and match every package path against the deny-list.
# Returns 0 clean, 1 if a cloud package is in the closure.
scan_go_closure() {
  command -v go >/dev/null 2>&1 || die "go toolchain not found on PATH (required for the closure scan)"
  local orch_dir="$REPO_ROOT/orchestrator"
  [ -d "$orch_dir" ] || die "orchestrator/ tree not found at $orch_dir"

  note "walking the OSS data-plane import closure (${OSS_TARGETS[*]}) ..."
  local closure re
  # GOWORK=off: resolve the orchestrator module STANDALONE (the repo ships a
  # `replace` for the one legal cross-tree import, proto/gen/go), so the closure
  # is reproducible on a fresh clone with no workspace file present. We keep the
  # default -mod=readonly so the scan NEVER mutates go.mod/go.sum (read-only by
  # construction — a release gate must not perturb the tree it inspects).
  if ! closure="$(cd "$orch_dir" && GOWORK=off go list -deps "${OSS_TARGETS[@]}" 2>/dev/null)"; then
    die "go list -deps failed for the OSS data-plane targets (cannot compute the closure)"
  fi
  [ -n "$closure" ] || die "go list -deps returned an empty closure (unexpected)"

  re="$(deny_regex)"
  local matches
  if matches="$(printf '%s\n' "$closure" | grep -E -i -- "$re" || true)"; then
    if [ -n "$matches" ]; then
      note "CLOUD SDK / metadata coupling in the OSS data-plane IMPORT CLOSURE:"
      printf '%s\n' "$matches" | sed 's/^/    /' >&2
      note "the OSS all-in-one (D80) must install on vanilla Linux metal with no cloud deps (D33)."
      return 1
    fi
  fi
  note "import closure clean: no cloud-SDK package among $(printf '%s\n' "$closure" | wc -l | tr -d ' ') packages."
  return 0
}

# scan_oss_sources_textually — the DEFENSE-IN-DEPTH lens: text-scan the OSS
# data-plane Go sources for metadata endpoints / cloud import paths a closure
# walk could miss (string literals, imports behind an unbuilt build tag). The
# scan is scoped to the OSS data-plane trees and EXCLUDES test files, the
# fixtures dir, and the deliberately-cloud ec2demo driver (a separate
# control-plane tool, not part of the OSS all-in-one closure — see D33 note in
# its doc.go). git-tracked files only, so a parallel session's untracked
# in-flight content never trips the gate.
scan_oss_sources_textually() {
  local re; re="$(deny_regex)"
  note "text-scanning OSS data-plane Go sources for metadata/cloud coupling ..."
  # OSS data-plane trees that ship in the all-in-one artifact (D80). The Rust
  # data plane (dataplane/) is scanned for the endpoint strings too.
  local trees=(orchestrator dataplane)
  local -a files=()
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      # EXCLUSIONS: the deliberately-cloud ec2demo driver (separate
      # capability-flagged control-plane tool, NOT in the OSS all-in-one
      # closure — proven by scan_go_closure), test files, and any fixtures.
      orchestrator/internal/hypervisor/ec2demo/*) continue ;;
      *_test.go) continue ;;
      */fixtures/*|*/testdata/*) continue ;;
    esac
    files+=("$REPO_ROOT/$f")
  done < <(cd "$REPO_ROOT" && git ls-files -- "${trees[@]/%//}" 2>/dev/null | grep -E '\.(go|rs)$' || true)

  [ "${#files[@]}" -gt 0 ] || { note "no OSS data-plane source files found to text-scan (skipping textual lens)"; return 0; }

  local matches
  if matches="$(grep -E -i -n -- "$re" "${files[@]}" 2>/dev/null || true)"; then
    if [ -n "$matches" ]; then
      note "CLOUD coupling in OSS data-plane SOURCES (textual lens):"
      printf '%s\n' "$matches" | sed 's/^/    /' >&2
      return 1
    fi
  fi
  note "textual lens clean: no metadata-endpoint / cloud import in ${#files[@]} OSS data-plane sources."
  return 0
}

# self_test — prove the gate has TEETH: assert the scan REJECTS the synthetic
# cloud-coupled negative-control fixture (D50: synthetic only, no live cloud).
# This is the negative control that proves a deliberately cloud-coupled change
# is blocked. A scan that cannot fail is not a gate.
self_test() {
  local fixture="$FIXTURES_DIR/cloud-coupled-negative-control.txt"
  [ -r "$fixture" ] || die "negative-control fixture not found: $fixture"
  note "self-test: asserting the scan REJECTS the negative-control fixture ..."
  if scan_file_against_denylist "$fixture" >/dev/null 2>&1; then
    note "SELF-TEST FAILED: the negative-control fixture was NOT flagged — the gate has no teeth."
    return 1
  fi
  note "self-test PASS: the negative-control fixture is correctly REJECTED (gate has teeth)."
  return 0
}

main() {
  case "${1:-}" in
    --scan-file)
      [ -n "${2:-}" ] || die "--scan-file requires a FILE argument"
      if scan_file_against_denylist "$2"; then
        note "clean: $2"
        exit 0
      fi
      exit 1
      ;;
    --self-test)
      # Full run: real closure must be clean AND the negative control rejected.
      local rc=0
      scan_go_closure || rc=1
      scan_oss_sources_textually || rc=1
      self_test || rc=1
      if [ "$rc" -eq 0 ]; then
        note "ALL CHECKS PASS — OSS data-plane closure clean, negative control rejected."
      fi
      exit "$rc"
      ;;
    -h|--help)
      sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    "")
      # Default: scan the real OSS data-plane closure + sources. FAIL CLOSED.
      local rc=0
      scan_go_closure || rc=1
      scan_oss_sources_textually || rc=1
      if [ "$rc" -eq 0 ]; then
        note "PASS — no cloud coupling in the OSS data-plane (D33 satisfied)."
      else
        note "FAIL — cloud coupling detected; BLOCKING the release (D33)."
      fi
      exit "$rc"
      ;;
    *)
      die "unknown argument: $1 (try --help)"
      ;;
  esac
}

main "$@"
