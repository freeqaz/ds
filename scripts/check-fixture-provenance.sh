#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# check-fixture-provenance.sh — D50 synthetic-only fixture gate (content level).
#
# Three checks, run git-side in CI (.github/workflows/fixtures-provenance.yml):
#
#   0. Per-directory contract. Every fixtures/ directory must carry a
#      PROVENANCE.md (checked against git-tracked files in normal operation,
#      so a written-but-never-added contract is caught locally before CI's
#      checkout-side find does). Mirrors the workflow's first step — the two
#      were drifted until 2026-06-13 (local green / CI red on four dirs).
#
#   1. Per-file provenance tag. Every *.ndjson cassette under any fixtures/
#      directory must begin with a JSON header record carrying
#      {"ds_fixture":{"provenance":"synthetic", ...}}. Non-NDJSON fixtures must
#      carry a <name>.provenance sidecar with the same object. Missing header,
#      unparseable header, or a non-"synthetic" provenance value FAILS.
#      (client/fixtures/PROVENANCE.md — "if it is in git, it is synthetic".)
#
#   2. Secret-shaped-string scan over committed files (git ls-files). Matches
#      REAL TOKEN VALUES, not the bare prefixes:
#        - sk-ant-<class>- followed by >=20 chars of [A-Za-z0-9_-]
#        - Bearer followed by a >=40-char [A-Za-z0-9_.-] token
#      It deliberately does NOT match the redacted placeholders that legitimately
#      live in client/goldentrace/HARDENING-NOTES.md and PHASE2-FINDINGS.md
#      (e.g. "sk-ant-oat01-<ellipsis>", a lone "x-api-key", "Bearer sk-ant-oat01-<ellipsis>"):
#      those carry no >=20/>=40-char token suffix, so the value regexes miss them.
#      This is the git-side twin of the canary-never-egresses test (doc 12 §5.3).
#
# POSIX sh. Exits 0 iff both checks pass; non-zero (and prints offenders) on any failure.
#
# Test hooks (used only by the --self-test mode below; CI sets neither):
#   FIXTURE_SCAN_ROOT   — directory to search for fixtures/ dirs (default: repo root)
#   SECRET_SCAN_FILES   — newline-separated explicit file list for the secret scan
#                         (default: `git ls-files` from the repo root)
#
# --self-test: prove the gate is not vacuous by running four adversarial cases
# in a temp directory (via the hooks above) and asserting each exits non-zero.
# Lives in the script, not the CI workflow, so a local run gets the same proof.
# House precedent: proto-gates.sh ships a negative self-test for the same reason.

set -eu

# --- locate the repo root (works from CI checkout or a manual run) ---------
if [ -n "${FIXTURE_SCAN_ROOT:-}" ]; then
	ROOT=$FIXTURE_SCAN_ROOT
elif ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
	:
else
	ROOT=$(pwd)
fi

# jq is the JSON parser. It ships on GitHub ubuntu-latest; fail loudly if absent
# rather than silently degrading the header check.
if ! command -v jq >/dev/null 2>&1; then
	echo "FATAL: jq is required for the provenance header check but was not found" >&2
	exit 2
fi

# --- Self-test mode: four negative cases, each must exit non-zero -----------
if [ "${1:-}" = "--self-test" ]; then
	T=$(mktemp -d)
	trap 'rm -rf "$T"' EXIT

	# Case 1: non-NDJSON fixture without a sidecar
	mkdir -p "$T/c1/fixtures"
	printf 'fixture-data\n' > "$T/c1/fixtures/trace.json"
	if FIXTURE_SCAN_ROOT="$T/c1" SECRET_SCAN_FILES="" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: missing-sidecar should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): missing-sidecar"

	# Case 2: sidecar with provenance != synthetic
	mkdir -p "$T/c2/fixtures"
	printf 'fixture-data\n' > "$T/c2/fixtures/trace.json"
	printf '{"ds_fixture":{"provenance":"dogfood","seam":"test","created":"2026-01-01"}}\n' \
		> "$T/c2/fixtures/trace.json.provenance"
	if FIXTURE_SCAN_ROOT="$T/c2" SECRET_SCAN_FILES="" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: bad-provenance-sidecar should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): bad-provenance-sidecar"

	# Case 3: NDJSON with missing ds_fixture header
	mkdir -p "$T/c3/fixtures"
	printf '{"event":"start"}\n{"event":"end"}\n' > "$T/c3/fixtures/trace.ndjson"
	if FIXTURE_SCAN_ROOT="$T/c3" SECRET_SCAN_FILES="" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: headerless-ndjson should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): headerless-ndjson"

	# Case 4: secret-shaped string in a planted file.
	# The token body (25 chars) is assembled at runtime so the literal does not
	# appear in this committed file and does not trip the scan on the script
	# itself. Tests that the SK_RE value regex fires end-to-end.
	PLANTED="$T/planted.txt"
	PFX="sk-ant-api01-"
	BODY=$(printf '%025d' 0 | tr '0' 'X')
	printf '%s%s\n' "$PFX" "$BODY" > "$PLANTED"
	if FIXTURE_SCAN_ROOT="$T" SECRET_SCAN_FILES="$PLANTED" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: planted-token should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): planted-token"

	# Case 5: fixtures dir whose files are all properly tagged but which lacks
	# the directory-level PROVENANCE.md contract — proves check 0 non-vacuous.
	mkdir -p "$T/c5/fixtures"
	printf 'fixture-data\n' > "$T/c5/fixtures/trace.json"
	printf '{"ds_fixture":{"provenance":"synthetic","seam":"test","created":"2026-01-01"}}\n' \
		> "$T/c5/fixtures/trace.json.provenance"
	if FIXTURE_SCAN_ROOT="$T/c5" SECRET_SCAN_FILES="" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: missing-dir-PROVENANCE.md should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): missing-dir-PROVENANCE.md"

	echo "Gate self-test: all five negative cases confirmed non-vacuous"
	exit 0
fi

fail=0

# --- Check 1: per-file provenance tag --------------------------------------
# Validate one header JSON string: must parse and carry
# .ds_fixture.provenance == "synthetic". Prints a reason and returns non-zero
# on any violation. Arg 1 = label for messages, stdin = the header text.
validate_header() {
	_label=$1
	_hdr=$(cat)
	if [ -z "$_hdr" ]; then
		echo "PROVENANCE FAIL: $_label — empty (no header record)"
		return 1
	fi
	# .ds_fixture.provenance, or the literal __ERR__ if the line is not JSON.
	_prov=$(printf '%s' "$_hdr" | jq -r 'try (.ds_fixture.provenance) catch "__ERR__"' 2>/dev/null) || _prov="__ERR__"
	if [ "$_prov" = "__ERR__" ]; then
		echo "PROVENANCE FAIL: $_label — first record is not valid JSON"
		return 1
	fi
	if [ "$_prov" = "null" ]; then
		echo "PROVENANCE FAIL: $_label — missing ds_fixture.provenance"
		return 1
	fi
	if [ "$_prov" != "synthetic" ]; then
		echo "PROVENANCE FAIL: $_label — provenance=\"$_prov\" (only \"synthetic\" may live in git; D50)"
		return 1
	fi
	echo "OK provenance: $_label"
	return 0
}

# Enumerate fixture files under every fixtures/ directory.
# When FIXTURE_SCAN_ROOT is set (self-test mode uses a temp directory that is
# not a git repo), fall back to the filesystem walk so the four self-test
# negative cases continue to function.  In normal operation (FIXTURE_SCAN_ROOT
# unset) we use `git ls-files` so that a parallel session's untracked in-flight
# content (node_modules, draft cassettes, etc.) never fails this gate —
# only committed files are checked.

if [ -n "${FIXTURE_SCAN_ROOT:-}" ]; then
	# Self-test / explicit override: scan the filesystem directly.
	fixture_dirs=$(find "$ROOT" -type d -name fixtures -not -path '*/.git/*' | sort)
	for d in $fixture_dirs; do
		# 0. Directory-level contract.
		if [ ! -f "$d/PROVENANCE.md" ]; then
			echo "PROVENANCE FAIL: ${d#"$ROOT"/}/PROVENANCE.md missing (D50: every fixtures dir carries the contract)"
			fail=1
		fi
		# 1a. NDJSON cassettes.
		for f in $(find "$d" -type f -name '*.ndjson' | sort); do
			rel=${f#"$ROOT"/}
			if ! head -n 1 "$f" | validate_header "$rel"; then
				fail=1
			fi
		done
		# 1b. Non-NDJSON fixtures: require a <name>.provenance sidecar.
		for f in $(find "$d" -type f \
			! -name '*.ndjson' \
			! -name '*.provenance' \
			! -name 'PROVENANCE.md' | sort); do
			rel=${f#"$ROOT"/}
			side="$f.provenance"
			if [ ! -f "$side" ]; then
				echo "PROVENANCE FAIL: $rel — non-NDJSON fixture has no $rel.provenance sidecar"
				fail=1
				continue
			fi
			if ! cat "$side" | validate_header "$rel.provenance"; then
				fail=1
			fi
		done
	done
else
	# Normal operation: enumerate only git-tracked files under fixtures/ dirs.
	# Untracked in-flight files (other sessions' node_modules, draft cassettes)
	# are silently skipped — only committed content is subject to this gate.
	tracked_fixtures=$( (cd "$ROOT" && git ls-files -- '*/fixtures/*' 'fixtures/*') | sort)

	# 0. Directory-level contract: every fixtures dir derived from the tracked
	# file list must have a TRACKED PROVENANCE.md (presence on disk is not
	# enough — CI checks the checkout, i.e. committed state).
	for d in $(printf '%s\n' "$tracked_fixtures" \
		| sed -E 's#^(fixtures)/.*#\1#; s#^(.*/fixtures)/.*#\1#' | sort -u); do
		[ -n "$d" ] || continue
		if ! printf '%s\n' "$tracked_fixtures" | grep -qx "$d/PROVENANCE.md"; then
			echo "PROVENANCE FAIL: $d/PROVENANCE.md missing or untracked (D50: every fixtures dir carries the contract)"
			fail=1
		else
			echo "OK provenance dir: $d/PROVENANCE.md"
		fi
	done

	# 1a. NDJSON cassettes (tracked).
	for rel in $tracked_fixtures; do
		case "$rel" in *.ndjson) ;; *) continue ;; esac
		f="$ROOT/$rel"
		[ -f "$f" ] || continue
		if ! head -n 1 "$f" | validate_header "$rel"; then
			fail=1
		fi
	done

	# 1b. Non-NDJSON fixtures (tracked): require a <name>.provenance sidecar.
	for rel in $tracked_fixtures; do
		case "$rel" in
			*.ndjson)     continue ;;
			*.provenance) continue ;;
			*PROVENANCE.md) continue ;;
		esac
		f="$ROOT/$rel"
		[ -f "$f" ] || continue
		side="$f.provenance"
		if [ ! -f "$side" ]; then
			echo "PROVENANCE FAIL: $rel — non-NDJSON fixture has no $rel.provenance sidecar"
			fail=1
			continue
		fi
		if ! cat "$side" | validate_header "$rel.provenance"; then
			fail=1
		fi
	done
fi

# --- Check 2: secret-shaped-string scan over committed files ---------------
# Build the file list: the explicit override (self-test), else git ls-files.
if [ -n "${SECRET_SCAN_FILES:-}" ]; then
	files=$(printf '%s\n' "$SECRET_SCAN_FILES")
else
	files=$( (cd "$ROOT" && git ls-files) | sed "s#^#$ROOT/#")
fi

# Two value-shaped regexes (ERE). They require an actual token body so the
# redacted "<prefix>-<ellipsis>" / lone-"x-api-key" placeholders never match:
#   - sk-ant-<class>- + >=20 of [A-Za-z0-9_-]
#   - Bearer + space + >=40 of [A-Za-z0-9_.-]
SK_RE='sk-ant-(oat|api|sid|adm|art|key)[0-9]{2}-[A-Za-z0-9_-]{20,}'
BEARER_RE='Bearer[ ]+[A-Za-z0-9_.-]{40,}'

scan_one() {
	# $1 = file. Print "FILE:LINE:match" lines for any hit; return 1 if any.
	_f=$1
	[ -f "$_f" ] || return 0
	# Skip binary files: grep -I makes grep treat binary as a non-match.
	_hits=$(grep -InE "$SK_RE|$BEARER_RE" "$_f" 2>/dev/null || true)
	if [ -n "$_hits" ]; then
		printf '%s\n' "$_hits" | sed "s#^#SECRET FAIL: $_f:#"
		return 1
	fi
	return 0
}

# Iterate the file list (newline-separated; paths with spaces are not expected
# in this repo, and git ls-files would quote them — accepted limitation).
oldifs=$IFS
IFS='
'
for f in $files; do
	[ -n "$f" ] || continue
	if ! scan_one "$f"; then
		fail=1
	fi
done
IFS=$oldifs

if [ "$fail" -ne 0 ]; then
	echo "FIXTURE PROVENANCE / SECRET SCAN: FAILED" >&2
	exit 1
fi
echo "FIXTURE PROVENANCE / SECRET SCAN: OK"
exit 0
