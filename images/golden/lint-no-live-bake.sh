#!/bin/sh
# lint-no-live-bake.sh — assert that NO committed CI workflow yaml or committed
# composite GitHub Action SETS the operator-only DS_GOLDEN_BAKE_LIVE gate, and
# FAIL CLOSED if one does.
#
# WHY THIS LINT EXISTS (the operator-only bake gate, doc 03 §6 / D12)
# ------------------------------------------------------------------
# The golden-image clone/warm/commit legs touch real on-disk images and spin a
# libguestfs/qemu appliance, so they run ONLY when DS_GOLDEN_BAKE_LIVE=1
# (images/golden/README.md "The DS_GOLDEN_BAKE_LIVE gate — deferred manual
# step").  That gate is deliberately OPERATOR-ONLY: a real bake is an explicit
# decision made off the CI default, on an operator host that has the raw base
# image present.  The CI lanes that drive the pre-bake / snapshot / nightly
# paths (golden-image.yml, golden-image-nightly.yml, the golden-snapshot
# composite Action) are plan-only and MUST NEVER set DS_GOLDEN_BAKE_LIVE
# themselves — that is the invariant every one of those files documents in prose
# ("NEVER sets DS_GOLDEN_BAKE_LIVE", "No DS_GOLDEN_BAKE_LIVE is set here").
#
# Prose promises drift.  This lint mechanizes the invariant: it scans every
# committed CI workflow yaml AND every committed composite Action yaml and FAILS
# CLOSED (exit 1) the instant one of them actually ASSIGNS / EXPORTS / declares
# an env: key for DS_GOLDEN_BAKE_LIVE.  A bad copy-paste, a hand-edited
# workflow, or a future lane that sets the gate "just to test" can no longer
# slip a live bake into a hosted CI run unreviewed.
#
# PRECISION: assignment, not mention (the whole point)
# ----------------------------------------------------
# The token DS_GOLDEN_BAKE_LIVE appears DOZENS of times across the committed
# yaml today — every one a DOCUMENTARY reference (a `#` comment or a
# `description:` / prose line explaining that the lane never sets the gate).
# Those are the GOOD state and MUST pass.  This lint flags ONLY an actual
# SETTER:
#
#   (a) a YAML mapping key   DS_GOLDEN_BAKE_LIVE:        (env:/with: entry)
#   (b) a shell export       export DS_GOLDEN_BAKE_LIVE= (inside a run: block)
#   (c) a shell assignment   DS_GOLDEN_BAKE_LIVE=        (plain/inline env)
#
# To stay precise it strips a trailing `#` comment from each line first, so a
# token that lives only inside a comment is invisible; then it requires the
# assignment token to be the FIRST non-whitespace code on the line (optionally
# after `export`).  A `description:`/prose mention, a `${{ ... }}` reference, or
# a comment therefore passes; a real `env:` key, `export`, or shell assignment
# fails.
#
# WHAT IT SCANS
# -------------
#   .github/workflows/*.yml  .github/workflows/*.yaml   (CI workflows)
#   .github/actions/**/action.yml  .github/actions/**/action.yaml  (composite
#                                                                   Actions)
# Resolved relative to the repo root (this script's dir is images/golden/, two
# levels under the root), so the lint runs from any cwd — like its sibling
# images/golden/lint-config-drift.sh.
#
# SCOPE BOUNDARY — per-file, not call-graph (deliberate)
# -----------------------------------------------------
# The scan is PER-FILE: it fails closed on a setter in any one committed
# workflow / composite Action, but it does NOT trace a `workflow_call`
# (reusable-workflow) call graph — a caller that passed DS_GOLDEN_BAKE_LIVE into
# a reusable workflow via `with:` / `secrets:` would only be caught if the SETTER
# (the `env:` key / export / assignment) is itself committed in some file, which
# this scan would then flag. It is sound today because the committed tree threads
# the gate through NO reusable workflow: a callee cannot receive a value it does
# not declare as an input, and none declare a DS_GOLDEN_BAKE_LIVE input. If a
# reusable-workflow that forwards the gate is ever added, every file is still
# individually scanned, but the reviewer must confirm the cross-file composition
# (the onboarding PR review, doc 07 §2a-spec) — the per-file invariant is the
# floor, not the whole call-graph proof.
#
# Usage:
#   sh images/golden/lint-no-live-bake.sh [REPO_ROOT]
#   LINT_REPO_ROOT=/path/to/repo sh images/golden/lint-no-live-bake.sh
#   sh images/golden/lint-no-live-bake.sh --self-test
#
# --self-test: internal regression harness.  Synthesizes a POSITIVE fixture (a
# yaml whose only DS_GOLDEN_BAKE_LIVE occurrences are a documentary comment and
# a prose `description:` — must PASS) and a NEGATIVE fixture (a yaml with a real
# `env:` assignment — must FAIL), plus export/inline-shell setter variants, and
# asserts the detector classifies each correctly.  It then runs the real scan
# over the committed tree and asserts it is GREEN (the current tree sets the
# gate nowhere).  Temp dir cleaned via an EXIT trap.  Dispatched BEFORE any
# repo scan.
#
# Invoked by `make repo-lints` — check-image-drift glob-discovers every
# images/*/lint-*.sh automatically, so NO Makefile edit is needed for this
# script.
#
# SPDX-License-Identifier: Apache-2.0

set -eu

GATE="DS_GOLDEN_BAKE_LIVE"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# scan_file FILE
#   Print one diagnostic line per OFFENDING line (a real setter of $GATE) in
#   FILE, in the form  <file>:<lineno>: <trimmed offending line>.  Prints
#   nothing for a clean file.  Returns 0 always (the caller aggregates the
#   verdict from whether any output was produced) so `set -e` never aborts the
#   walk on a grep/awk non-match.
#
# The classifier is a single awk pass (POSIX awk — no gawk extensions) that, for
# each line:
#   1. drops a trailing `#` comment (a `#` at start-of-line or preceded by
#      whitespace — YAML and shell comment syntax), so a token that lives only
#      inside a comment disappears;
#   2. left-trims the surviving code, then peels a leading YAML block-sequence
#      dash (`- `) and a single-line `run:` step prefix, so an inline-env setter
#      written as  - run: GATE=1 prebake.sh  is seen as the shell it is, not as
#      a `run:` value;
#   3. flags the line ONLY when the remaining code BEGINS with the gate as an
#      assignment:
#        ^GATE[:=]              YAML mapping key (env:/with:) OR shell assignment
#        ^export[ \t]+GATE=     shell export
#      i.e. the gate must be the leading code token being assigned — a mention
#      buried in prose, a `${{ }}` reference, an argument/value, or a comment
#      never matches.
# ---------------------------------------------------------------------------
scan_file() {
	awk -v gate="$GATE" -v fname="$1" '
	{
		raw = $0
		code = $0

		# (1) strip a trailing comment: a "#" that is at the start of the
		# (left-trimmed) line or is preceded by a space/tab.  This removes
		# documentary comments without touching a "#" embedded in a token.
		if (code ~ /^[[:space:]]*#/) {
			code = ""
		} else {
			# find the first " #" or "\t#" and cut from there.
			if (match(code, /[[:space:]]#/)) {
				code = substr(code, 1, RSTART - 1)
			}
		}

		# (2) left-trim the surviving code.
		sub(/^[[:space:]]+/, "", code)

		# (2a) strip a leading YAML block-sequence indicator ("- "), which fronts
		# an inline step key like  - run: ...  or  - env: ... , then re-trim, so
		# the key/setter tests below see the step content rather than the dash.
		while (code ~ /^-[[:space:]]+/) {
			sub(/^-[[:space:]]+/, "", code)
		}

		# (2b) a SINGLE-LINE GitHub `run:` step carries inline shell on the same
		# line, e.g.  run: DS_GOLDEN_BAKE_LIVE=1 prebake.sh  — a real inline-env
		# setter.  Strip a leading `run:` (and a `|`/`>` block-scalar indicator)
		# and re-trim, so the assignment test below sees the shell, not the YAML
		# key.  A `run:` with no inline payload (a block scalar) leaves an empty
		# code string — harmless; the block body lines are scanned on their own.
		if (code ~ /^run:[[:space:]]*/) {
			sub(/^run:[[:space:]]*[|>]?[+-]?[[:space:]]*/, "", code)
		}

		# (3) does the leading code assign the gate?
		#   a YAML mapping key:   GATE:
		#   a shell assignment:   GATE=
		#   a shell export:       export <ws> GATE=
		assigns = 0
		if (code ~ ("^" gate "[:=]")) {
			assigns = 1
		} else if (code ~ ("^export[[:space:]]+" gate "=")) {
			assigns = 1
		}

		if (assigns) {
			# trim the raw line for a tidy diagnostic.
			trimmed = raw
			sub(/^[[:space:]]+/, "", trimmed)
			sub(/[[:space:]]+$/, "", trimmed)
			printf "%s:%d: %s\n", fname, NR, trimmed
		}
	}
	' "$1"
}

# ---------------------------------------------------------------------------
# run_scan REPO_ROOT
#   Scan every committed CI workflow + composite Action yaml under REPO_ROOT.
#   Returns 0 if clean, 1 if any offender found (printing a fail-closed banner).
# ---------------------------------------------------------------------------
run_scan() {
	root="$1"

	# Enumerate the target yaml.  We DO NOT require .github/ to exist (a stripped
	# checkout is a clean pass), but if it exists we walk it.
	offenders=""
	scanned=0

	# Build the candidate list with find (portable; no bashism, no glob-nullglob
	# dependence).  Two roots: workflows and composite actions.  CI workflow /
	# Action paths under .github/ never contain newlines, so newline-delimited
	# iteration is safe and stays strict-POSIX (no `read -d ''` bashism); the
	# `#!/bin/sh` contract is honored.
	wf_dir="$root/.github/workflows"
	act_dir="$root/.github/actions"

	# Collect candidate paths into a temp file so the while loop runs in the
	# current shell (no subshell — offenders/scanned persist).
	cand="$(mktemp)"
	: > "$cand"

	if [ -d "$wf_dir" ]; then
		find "$wf_dir" -type f \( -name '*.yml' -o -name '*.yaml' \) -print >> "$cand" 2>/dev/null || true
	fi
	if [ -d "$act_dir" ]; then
		find "$act_dir" -type f \( -name 'action.yml' -o -name 'action.yaml' \) -print >> "$cand" 2>/dev/null || true
	fi

	while IFS= read -r f; do
		[ -n "$f" ] || continue
		scanned=$((scanned + 1))
		out="$(scan_file "$f")"
		if [ -n "$out" ]; then
			offenders="${offenders}${out}
"
		fi
	done < "$cand"

	rm -f "$cand"

	if [ -n "$offenders" ]; then
		printf '%s\n' "lint-no-live-bake: ERROR: committed CI yaml SETS the operator-only ${GATE} gate — fail-closed (D12, doc 03 §6)." >&2
		printf '%s\n' "lint-no-live-bake: the ${GATE} bake gate is an OPERATOR-HOST deferred manual step; no committed workflow or composite Action may set it." >&2
		printf '%s' "$offenders" | while IFS= read -r line; do
			[ -n "$line" ] && printf '  %s\n' "$line" >&2
		done
		return 1
	fi

	printf '%s\n' "lint-no-live-bake: OK — scanned ${scanned} CI/Action yaml file(s); none set ${GATE}."
	return 0
}

# ---------------------------------------------------------------------------
# resolve_root [ARG]
#   Resolve the repo root: explicit ARG > $LINT_REPO_ROOT > two levels up from
#   this script (images/golden/ -> repo root).
# ---------------------------------------------------------------------------
resolve_root() {
	if [ -n "${1:-}" ]; then
		printf '%s\n' "$1"
	elif [ -n "${LINT_REPO_ROOT:-}" ]; then
		printf '%s\n' "$LINT_REPO_ROOT"
	else
		( cd "$SCRIPT_DIR/../.." && pwd )
	fi
}

# ===========================================================================
# --self-test
# ===========================================================================
self_test() {
	tmp="$(mktemp -d)"
	# shellcheck disable=SC2064
	trap "rm -rf '$tmp'" EXIT

	fails=0
	t_pass=0
	t_total=0

	assert_clean() {
		# $1 file, $2 label — scan_file must produce NO output.
		t_total=$((t_total + 1))
		out="$(scan_file "$1")"
		if [ -z "$out" ]; then
			t_pass=$((t_pass + 1))
			printf '  PASS  %s (clean)\n' "$2"
		else
			fails=$((fails + 1))
			printf '  FAIL  %s — expected clean but flagged:\n' "$2" >&2
			printf '%s\n' "$out" | sed 's/^/        /' >&2
		fi
	}

	assert_flagged() {
		# $1 file, $2 label, $3 expected-substring — scan_file MUST flag it.
		t_total=$((t_total + 1))
		out="$(scan_file "$1")"
		if [ -n "$out" ] && printf '%s' "$out" | grep -q "$3"; then
			t_pass=$((t_pass + 1))
			printf '  PASS  %s (flagged as expected)\n' "$2"
		else
			fails=$((fails + 1))
			printf '  FAIL  %s — expected a flag matching %s but got:\n' "$2" "$3" >&2
			printf '%s\n' "${out:-<no output>}" | sed 's/^/        /' >&2
		fi
	}

	printf 'lint-no-live-bake --self-test:\n'

	# ----- POSITIVE fixture: documentary-only — MUST PASS (be clean) ---------
	pos="$tmp/positive.yml"
	cat > "$pos" <<'YAML'
# SPDX-License-Identifier: Apache-2.0
# golden-image.yml — plan-only CI lane. This workflow NEVER sets
# DS_GOLDEN_BAKE_LIVE; the live bake is an operator-host deferred manual step.
name: golden-image
on:
  workflow_dispatch:
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - name: Dry-run plan
        # No DS_GOLDEN_BAKE_LIVE is set here — plan only.
        env:
          DS_SNAPSHOT_DRY_RUN: "true"
        run: |
          # The live bake needs DS_GOLDEN_BAKE_LIVE=1, which this lane never sets.
          images/golden/prebake.sh --all --dry-run
YAML
	assert_clean "$pos" "positive fixture (comment + prose mention only)"

	# A standalone description: prose line that names the gate — also clean.
	prose="$tmp/prose.yml"
	cat > "$prose" <<'YAML'
inputs:
  dry-run:
    description: >
      Set "false" only on an operator host that ALSO sets DS_GOLDEN_BAKE_LIVE=1;
      this Action never sets DS_GOLDEN_BAKE_LIVE itself.
YAML
	assert_clean "$prose" "prose description: naming the gate"

	# A trailing-comment mention after real code — clean.
	trailing="$tmp/trailing.yml"
	cat > "$trailing" <<'YAML'
env:
  DS_SNAPSHOT_DRY_RUN: "true"   # NOT DS_GOLDEN_BAKE_LIVE=1 (operator-only)
YAML
	assert_clean "$trailing" "trailing comment mention after unrelated env key"

	# ----- NEGATIVE fixture: real env: assignment — MUST FAIL ----------------
	neg="$tmp/negative-env.yml"
	cat > "$neg" <<'YAML'
# A workflow that wrongly sets the operator-only gate in an env: block.
jobs:
  bake:
    runs-on: ubuntu-latest
    steps:
      - name: Live bake (WRONG — sets the gate)
        env:
          DS_GOLDEN_BAKE_LIVE: "1"
        run: images/golden/prebake.sh --all
YAML
	assert_flagged "$neg" "negative fixture (env: DS_GOLDEN_BAKE_LIVE assignment)" "negative-env.yml"

	# ----- NEGATIVE variant: shell export inside a run: block ----------------
	neg_exp="$tmp/negative-export.yml"
	cat > "$neg_exp" <<'YAML'
jobs:
  bake:
    steps:
      - run: |
          export DS_GOLDEN_BAKE_LIVE=1
          images/golden/prebake.sh --all
YAML
	assert_flagged "$neg_exp" "negative variant (export DS_GOLDEN_BAKE_LIVE=1)" "negative-export.yml"

	# ----- NEGATIVE variant: plain shell assignment line ---------------------
	neg_sh="$tmp/negative-shell.yml"
	cat > "$neg_sh" <<'YAML'
jobs:
  bake:
    steps:
      - run: |
          DS_GOLDEN_BAKE_LIVE=1
          images/golden/prebake.sh --all
YAML
	assert_flagged "$neg_sh" "negative variant (plain DS_GOLDEN_BAKE_LIVE= assignment)" "negative-shell.yml"

	# ----- NEGATIVE variant: single-line run: inline-env setter --------------
	neg_inline="$tmp/negative-inline.yml"
	cat > "$neg_inline" <<'YAML'
jobs:
  bake:
    steps:
      - run: DS_GOLDEN_BAKE_LIVE=1 images/golden/prebake.sh --all
YAML
	assert_flagged "$neg_inline" "negative variant (single-line run: DS_GOLDEN_BAKE_LIVE=1 ...)" "negative-inline.yml"

	# ----- NEGATIVE variant: single-line run: export setter ------------------
	neg_inline_exp="$tmp/negative-inline-export.yml"
	cat > "$neg_inline_exp" <<'YAML'
jobs:
  bake:
    steps:
      - run: export DS_GOLDEN_BAKE_LIVE=1
YAML
	assert_flagged "$neg_inline_exp" "negative variant (single-line run: export DS_GOLDEN_BAKE_LIVE=1)" "negative-inline-export.yml"

	# A run: line whose payload merely MENTIONS the gate as an argument value
	# (not an assignment) stays clean — e.g. echoing a doc string.
	run_mention="$tmp/run-mention.yml"
	cat > "$run_mention" <<'YAML'
jobs:
  note:
    steps:
      - run: echo "the live bake needs DS_GOLDEN_BAKE_LIVE=1 (operator-only)"
YAML
	assert_clean "$run_mention" "run: line that only echoes the gate name (mention, not setter)"

	# ----- NEGATIVE variant: with: input key named like the gate -------------
	neg_with="$tmp/negative-with.yml"
	cat > "$neg_with" <<'YAML'
jobs:
  bake:
    steps:
      - uses: ./.github/actions/golden-snapshot
        with:
          DS_GOLDEN_BAKE_LIVE: "1"
YAML
	assert_flagged "$neg_with" "negative variant (with: DS_GOLDEN_BAKE_LIVE key)" "negative-with.yml"

	# ----- the REAL committed tree must be GREEN today -----------------------
	root="$(resolve_root "")"
	printf '\n  scanning the committed tree at %s ...\n' "$root"
	if run_scan "$root" >/dev/null 2>&1; then
		t_total=$((t_total + 1)); t_pass=$((t_pass + 1))
		printf '  PASS  committed CI/Action yaml is clean (gate set nowhere)\n'
	else
		t_total=$((t_total + 1)); fails=$((fails + 1))
		printf '  FAIL  committed tree unexpectedly flags a %s setter:\n' "$GATE" >&2
		run_scan "$root" >&2 || true
	fi

	printf '\nlint-no-live-bake --self-test: %d/%d checks passed.\n' "$t_pass" "$t_total"
	if [ "$fails" -ne 0 ]; then
		printf 'lint-no-live-bake --self-test: FAILED (%d).\n' "$fails" >&2
		return 1
	fi
	printf 'lint-no-live-bake --self-test: OK.\n'
	return 0
}

# ===========================================================================
# main
# ===========================================================================
case "${1:-}" in
	--self-test)
		self_test
		;;
	-h|--help)
		sed -n '2,72p' "$0"
		;;
	*)
		root="$(resolve_root "${1:-}")"
		run_scan "$root"
		;;
esac
