#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# check-guardrail-map-tags.sh — structural guardrail-map<->owning-package tag lint
# (D47 fail-closed scoping; D51 public-claims single-sourcing; doc 20
# guardrail-assurance model).
#
# WHY THIS GATE EXISTS
#   The repo-root guardrail-map.yaml maps a diff glob to the conformance row(s)
#   that must gate it (D47). For every row whose glob points INTO an owning
#   guardrail-conformance package —
#       assurance/guardrail-conformance/<pkg>/**
#   — the map row's `tags:` list MUST name the SAME guardrail tag the owning
#   package single-sources (its `const Tag` / `var Tags` value, or — for the
#   goldenfreshness precedent — its doc.go REGISTRATION `guardrail tag:` line).
#   That single-sourcing is what lets the §3c claims table, the package, and the
#   map name the SAME row (README.md "The row split"; each package's TestTagStable
#   / TestTagsStable guard pins its own half). But NOTHING gates the SEAM BETWEEN
#   the map and the package: a tag renamed in the package only (the test still
#   passes — it pins the package against itself), or renamed in the map only, or a
#   stale map row whose package no longer carries the tag, all slip through every
#   per-module test. This repo-level lint closes that gap: it parses the map's
#   conformance-package rows and asserts every named tag still appears verbatim in
#   its owning package's *.go, failing LOUDLY (naming the glob, the tag, and the
#   package dir) on a package-only rename, a map-only rename, or an orphaned row.
#   It is the git-side twin of the per-package Tag-stability guards.
#
#   The match is a verbatim substring of the package's *.go on purpose: it accepts
#   BOTH the `const Tag = "<tag>"` single-sourcing (orchctl, suspendbreach,
#   passthrough, secretegress) AND the doc.go-comment single-sourcing the
#   goldenfreshness precedent uses (`guardrail tag: golden-rotation-freshness`),
#   while still breaking the instant either side renames the tag.
#
# House precedent: scripts/check-snapshot-goldens.sh,
# scripts/check-corpus-suffix.sh (committed-source structural-coupling lints).
#
# POSIX sh, network-free, go-tooling-free (pure shell + grep/sed). Reads
# guardrail-map.yaml and the owning packages READ-ONLY; edits nothing. Exits 0 iff
# every conformance-package map row names only tags its owning package carries;
# non-zero (naming each offender) on any package-only rename, map-only rename, or
# orphaned map row, or if the map / an owning package is missing.
#
# Test hook (used only by --self-test; CI/normal runs set neither):
#   GMAP_TAGS_ROOT — repo root to resolve guardrail-map.yaml + the owning
#                    packages against (default: `git rev-parse --show-toplevel`,
#                    else cwd).
#
# --self-test: prove the gate is not vacuous by running adversarial cases in a
# temp directory and asserting each exits non-zero (a package-only rename; a
# map-only rename; an orphaned map row whose package dropped the tag; a missing
# owning package) plus one positive case (the map and package agree -> exit 0).
# House precedent: check-snapshot-goldens.sh ships the same proof.

set -eu

MAP_REL="guardrail-map.yaml"
PKG_PREFIX="assurance/guardrail-conformance/"

# --- locate the repo root (works from CI checkout or a manual run) ---------
if [ -n "${GMAP_TAGS_ROOT:-}" ]; then
	ROOT=$GMAP_TAGS_ROOT
elif ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
	:
else
	ROOT=$(pwd)
fi

# ---------------------------------------------------------------------------
# core: scan the map, emit a non-zero status (and named diagnostics on stderr)
# on any seam mismatch. Factored into a function so --self-test can re-enter it
# against a synthetic ROOT.
# ---------------------------------------------------------------------------
run_check() {
	_root=$1
	_map="$_root/$MAP_REL"

	if [ ! -f "$_map" ]; then
		echo "GUARDRAIL-MAP TAGS: FAILED — missing map file: $_map" >&2
		return 1
	fi

	_fail=0
	_rows=0

	# Parse the conformance-package rows. The map is hand-maintained YAML with a
	# fixed two-line shape per row:
	#     - glob: "assurance/guardrail-conformance/<pkg>/**"
	#       tags: [tag-a, tag-b, ...]
	# We walk lines, latch the most recent glob, and when its following `tags:`
	# line arrives — IF the glob is a conformance-package glob — assert each tag.
	# No PyYAML / no external YAML parser (kin to check-corpus-suffix.sh's grep
	# extraction); the shape is stable and owner-fenced.
	_cur_glob=""
	while IFS= read -r _line || [ -n "$_line" ]; do
		# A glob line: capture the quoted path after `glob:`.
		case $_line in
		*glob:*\"*\"*)
			_cur_glob=$(printf '%s\n' "$_line" | sed -n 's/.*glob:[[:space:]]*"\([^"]*\)".*/\1/p')
			continue
			;;
		esac

		# A tags line: only act when the latched glob is a conformance-package
		# glob of the form  assurance/guardrail-conformance/<pkg>/**.
		case $_line in
		*tags:*\[*\]*)
			[ -n "$_cur_glob" ] || continue
			case $_cur_glob in
			"$PKG_PREFIX"*/\*\*) ;;
			*)
				_cur_glob=""
				continue
				;;
			esac

			# Derive the owning package dir:  <prefix><pkg>/**  ->  <prefix><pkg>
			_pkg_rel=${_cur_glob%/\*\*}
			_pkg_dir="$_root/$_pkg_rel"
			_pkg_name=${_pkg_rel#"$PKG_PREFIX"}

			# The owning package must exist with at least one *.go source.
			if [ ! -d "$_pkg_dir" ]; then
				echo "GUARDRAIL-MAP TAGS: FAILED — map row glob '$_cur_glob' names owning package '$_pkg_rel', but that directory does not exist." >&2
				_fail=1
				_cur_glob=""
				continue
			fi
			# The single-source is the package's NON-TEST source: its const Tag /
			# var Tags value, or — the goldenfreshness precedent — its doc.go
			# REGISTRATION 'guardrail tag:' comment. We deliberately EXCLUDE
			# *_test.go so a package-side rename of the real single-source is caught
			# even when a stale literal still lingers in the package's own
			# TestTagStable / TestTagsStable guard (that guard pins the package
			# against itself and would mask the rename from this seam lint; a const
			# renamed without its test is already caught by `go test`, never here).
			# Collect the non-test *.go files into the positional params.
			set --
			for _f in "$_pkg_dir"/*.go; do
				[ -f "$_f" ] || continue
				case $_f in
				*_test.go) continue ;;
				esac
				set -- "$@" "$_f"
			done
			if [ "$#" -eq 0 ]; then
				echo "GUARDRAIL-MAP TAGS: FAILED — owning package '$_pkg_rel' has no non-test *.go source to single-source its tag(s)." >&2
				_fail=1
				_cur_glob=""
				continue
			fi

			# Extract the comma/space-separated tag tokens between [ and ].
			_taglist=$(printf '%s\n' "$_line" | sed -n 's/.*tags:[[:space:]]*\[\([^]]*\)\].*/\1/p')
			# Normalize separators to whitespace, then iterate.
			_taglist=$(printf '%s\n' "$_taglist" | tr ',' ' ')

			for _tag in $_taglist; do
				# Strip any stray surrounding quotes/whitespace from the token.
				_tag=$(printf '%s\n' "$_tag" | sed 's/^[[:space:]]*"\{0,1\}//; s/"\{0,1\}[[:space:]]*$//')
				[ -n "$_tag" ] || continue
				_rows=$((_rows + 1))

				# The owning package must carry this exact tag string as a WHOLE
				# token in one of its NON-TEST *.go files (const value OR doc.go
				# REGISTRATION line; the positional params set above). We match it
				# bounded by a non-tag character (or line start/end) on each side so a
				# renamed tag that merely PREFIXES the old one — e.g.
				# `orch-suspend-on-breach-RENAMED` vs the stale map tag
				# `orch-suspend-on-breach` — does NOT spuriously match (a plain
				# substring grep would, masking a package-only rename). Tag tokens
				# are kebab-case [A-Za-z0-9-]; the boundary class forbids those plus
				# `_`. The tag is regex-escaped first (only `.` and `-` can appear
				# from the kebab grammar, but we escape defensively for any token).
				_tag_re=$(printf '%s\n' "$_tag" | sed 's/[][\\.^$*+?(){}|/-]/\\&/g')
				if grep -Eq -- "(^|[^A-Za-z0-9_-])${_tag_re}([^A-Za-z0-9_-]|\$)" "$@" 2>/dev/null; then
					echo "check-guardrail-map-tags: OK — $_pkg_rel single-sources '$_tag'"
				else
					echo "GUARDRAIL-MAP TAGS: FAILED — map row '$_cur_glob' names tag '$_tag', but its owning package '$_pkg_rel' does not single-source it (no *.go carries the literal)." >&2
					echo "  This is a guardrail-map<->package SEAM break: a tag renamed package-only, renamed map-only, or an orphaned map row whose package dropped the tag." >&2
					echo "  Reconcile so the map row and the package's const Tag / var Tags (or doc.go REGISTRATION 'guardrail tag:' line) name the SAME row (D51 single-sourcing; D47 fail-closed scoping)." >&2
					_fail=1
				fi
			done
			_cur_glob=""
			;;
		esac
	done <"$_map"

	if [ "$_rows" -eq 0 ]; then
		# Fail closed: a map with NO conformance-package rows means our parser
		# matched nothing (a shape drift or an empty map) — never silently pass.
		echo "GUARDRAIL-MAP TAGS: FAILED — found no '${PKG_PREFIX}<pkg>/**' rows to verify in $_map (parser found nothing — shape drift?)." >&2
		return 1
	fi

	if [ "$_fail" -ne 0 ]; then
		echo "GUARDRAIL-MAP TAGS: FAILED — see the named seam break(s) above." >&2
		return 1
	fi

	echo "check-guardrail-map-tags: OK — all $_rows conformance-package map tag(s) are single-sourced by their owning packages"
	return 0
}

# --- Self-test mode: four negative cases + one positive --------------------
if [ "${1:-}" = "--self-test" ]; then
	T=$(mktemp -d)
	trap 'rm -rf "$T"' EXIT

	PKG="$T/${PKG_PREFIX}sample"
	mkdir -p "$PKG"
	MAP="$T/$MAP_REL"

	# Positive case: the map row and the package agree -> exit 0.
	cat >"$PKG/sample.go" <<'EOF'
package sample

// Tag is the single-sourced guardrail tag for this row.
const Tag = "sample-claim-holds"
EOF
	cat >"$MAP" <<'EOF'
version: 1
rules:
  - glob: "docs/**"
    tags: []
  - glob: "assurance/guardrail-conformance/sample/**"
    tags: [sample-claim-holds]
EOF
	if ! GMAP_TAGS_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: agreeing map+package should exit 0" >&2
		exit 1
	fi
	echo "SELF-TEST OK (zero): map-and-package-agree"

	# Case 1: package-only rename — the package const changed; the map is stale.
	cat >"$PKG/sample.go" <<'EOF'
package sample

// Tag is the single-sourced guardrail tag for this row.
const Tag = "sample-claim-renamed"
EOF
	if GMAP_TAGS_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: package-only rename should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): package-only-rename"

	# Case 2: map-only rename — the map row changed; the package is unchanged.
	cat >"$PKG/sample.go" <<'EOF'
package sample

// Tag is the single-sourced guardrail tag for this row.
const Tag = "sample-claim-holds"
EOF
	cat >"$MAP" <<'EOF'
version: 1
rules:
  - glob: "assurance/guardrail-conformance/sample/**"
    tags: [sample-claim-holds-renamed]
EOF
	if GMAP_TAGS_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: map-only rename should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): map-only-rename"

	# Case 3: orphaned map row — the package dropped the tag entirely.
	cat >"$PKG/sample.go" <<'EOF'
package sample

// The tag this package once single-sourced is gone; the map row is now orphaned.
const Other = "unrelated"
EOF
	cat >"$MAP" <<'EOF'
version: 1
rules:
  - glob: "assurance/guardrail-conformance/sample/**"
    tags: [sample-claim-holds]
EOF
	if GMAP_TAGS_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: orphaned map row should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): orphaned-map-row"

	# Case 4: the owning package directory is missing entirely.
	rm -rf "$PKG"
	if GMAP_TAGS_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: missing owning package should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): missing-owning-package"

	# Multi-row + doc.go-comment single-sourcing: prove the lint accepts a
	# var Tags package AND a comment-only single-source (the goldenfreshness
	# precedent), so the positive path is not limited to a single const Tag.
	PKG2="$T/${PKG_PREFIX}multi"
	PKG3="$T/${PKG_PREFIX}commentonly"
	mkdir -p "$PKG2" "$PKG3"
	cat >"$PKG2/multi.go" <<'EOF'
package multi

const (
	TagA = "multi-row-a"
	TagB = "multi-row-b"
)

var Tags = []string{TagA, TagB}
EOF
	cat >"$PKG3/doc.go" <<'EOF'
// Package commentonly single-sources its tag in a doc.go REGISTRATION line.
//
//	guardrail tag: comment-only-claim
package commentonly
EOF
	cat >"$MAP" <<'EOF'
version: 1
rules:
  - glob: "assurance/guardrail-conformance/multi/**"
    tags: [multi-row-a, multi-row-b]
  - glob: "assurance/guardrail-conformance/commentonly/**"
    tags: [comment-only-claim]
EOF
	if ! GMAP_TAGS_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: multi-row var Tags + comment-only single-source should exit 0" >&2
		exit 1
	fi
	echo "SELF-TEST OK (zero): multi-row-and-comment-only-single-source"

	# Case 5: package-side rename with a STALE TEST LITERAL — the real single-
	# source (const + doc) was renamed but the package's own TestTagStable guard
	# still carries the OLD literal, and the map row is stale (still names the old
	# tag). The lint must ignore *_test.go and FAIL, because the test file pins the
	# package against itself and would otherwise mask a package-side rename.
	PKG5="$T/${PKG_PREFIX}staletest"
	mkdir -p "$PKG5"
	cat >"$PKG5/staletest.go" <<'EOF'
package staletest

// Tag is the single-sourced guardrail tag for this row (renamed).
const Tag = "stale-test-claim-renamed"
EOF
	cat >"$PKG5/staletest_test.go" <<'EOF'
package staletest

import "testing"

// A stale guard literal lingering after a package-side rename — must NOT count
// as single-sourcing for the map<->package seam lint.
func TestTagStable(t *testing.T) {
	if Tag != "stale-test-claim" {
		t.Fatalf("tag drift")
	}
}
EOF
	cat >"$MAP" <<'EOF'
version: 1
rules:
  - glob: "assurance/guardrail-conformance/staletest/**"
    tags: [stale-test-claim]
EOF
	if GMAP_TAGS_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: package-side rename with a stale *_test.go literal should exit non-zero (test files are not the single-source)" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): package-rename-with-stale-test-literal"

	echo "Gate self-test: all cases confirmed non-vacuous"
	exit 0
fi

run_check "$ROOT"
