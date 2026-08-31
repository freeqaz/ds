#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# check-grantref-goldens.sh — repo-level byte-identity gate for the GrantRef
# cross-module golden fixture (doc 16 §5.1, §9 grant-fetch row; D50 synthetic).
#
# WHY THIS GATE EXISTS
#   The grant_ref string is the ONLY thing identity/mint (the WRITER) and
#   identity/grant-service (the READER) agree on across two standalone
#   GOWORK=off modules. The contract is carried as testdata/grantref-golden.json
#   IDENTICALLY in both modules:
#     - mint/grants_test.go        asserts FormatGrantRef(session,service) == ref
#                                  against its OWN copy (writer side)
#     - grant-service/grantref_test.go asserts ParseGrantRef(ref) == {…}
#                                  against its OWN copy (reader side)
#   Each module's suite pins ITS HALF, but because the two copies are separate
#   committed files in separate modules, NOTHING in either test tree gates that
#   the two fixtures are byte-identical. If they silently diverge, the writer
#   and reader can both pass their own golden while encoding different cases —
#   exactly the cross-module drift the shared golden is meant to forbid. This
#   repo-level lint closes that gap: it cmp's the two committed copies and fails
#   loudly (naming both paths and the rationale) on any divergence or a missing
#   file. It is the git-side twin of the two per-module round-trip tests.
#
# POSIX sh, network-free. Exits 0 iff both files exist, are byte-identical, and
# (when a JSON parser is available) the canonical copy is well-formed JSON of the
# expected SHAPE; non-zero (and prints both paths) on divergence, a missing/
# unreadable file, malformed JSON, or a shape violation.
#
# SHAPE ASSERTION (doc 16 section 5.1, section 9 grant-fetch row). Byte-identity
# + well-formedness still let a structurally-valid-but-WRONG golden through — a
# renamed key, an empty case list, or a ref that no longer derives from its
# session/service. So beyond parsing, we assert the golden's shape:
#     - .format is a string,
#     - .cases is a NON-EMPTY array,
#     - every case has string .session, .service, .ref, and
#     - .ref == "grant:" + .session + ":" + .service   (the section 5.1 rule).
# HONEST TOOL DEGRADATION: the shape (and well-formedness) leg needs a JSON
# parser. We prefer jq, fall back to python3, and if NEITHER is present we SKIP
# the parse+shape leg with a loud note (the byte-identity leg above has already
# run) rather than hard-failing a gate host that ships no JSON tool. Per-module
# tests still gate JSON validity downstream. (Skip-with-note, not hard-require.)
#
# Test hook (used only by --self-test; CI/normal runs set neither):
#   GRANTREF_GOLDEN_ROOT — repo root to resolve the two fixture paths against
#                          (default: `git rev-parse --show-toplevel`, else cwd).
#
# --self-test: prove the gate is not vacuous by running adversarial cases in a
# temp directory and asserting each exits non-zero (divergent copies; missing
# writer copy; missing reader copy; identical-but-malformed JSON; and — when a
# parser is present — the shape arms: .format not a string, empty .cases, a non-
# string entry field, and a ref that does not derive as grant:session:service)
# plus one positive case (identical, well-formed, correctly-shaped). House
# precedent: check-fixture-provenance.sh ships the same proof.

set -eu

# --- the two fixture paths, relative to the repo root ----------------------
MINT_REL="identity/mint/testdata/grantref-golden.json"
GRANT_REL="identity/grant-service/testdata/grantref-golden.json"

# --- locate the repo root (works from CI checkout or a manual run) ---------
if [ -n "${GRANTREF_GOLDEN_ROOT:-}" ]; then
	ROOT=$GRANTREF_GOLDEN_ROOT
elif ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
	:
else
	ROOT=$(pwd)
fi

# --- Self-test mode: three negative cases + one positive --------------------
if [ "${1:-}" = "--self-test" ]; then
	T=$(mktemp -d)
	trap 'rm -rf "$T"' EXIT

	mkdir -p "$T/identity/mint/testdata" "$T/identity/grant-service/testdata"
	MINT="$T/$MINT_REL"
	GRANT="$T/$GRANT_REL"

	# A well-formed, correctly-SHAPED golden (the positive baseline). Kept compact;
	# the live goldens carry a _comment + multiple cases, but the shape rules are
	# the same: .format string, .cases non-empty, each {session,service,ref} of
	# strings with ref == grant:<session>:<service>.
	valid_golden() {
		printf '%s\n' '{"format":"grant:<session_uuid>:<service_id>","cases":[{"session":"00000000-0000-4000-8000-000000000001","service":"github","ref":"grant:00000000-0000-4000-8000-000000000001:github"}]}'
	}

	# Positive case: identical, well-formed, correctly-shaped copies must pass.
	valid_golden > "$MINT"
	valid_golden > "$GRANT"
	if ! GRANTREF_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: identical well-formed correctly-shaped copies should exit 0" >&2
		exit 1
	fi
	echo "SELF-TEST OK (zero): identical-copies"

	# Case 1: the two copies diverge by a single byte.
	printf '{"format":"grant:<session>:<SERVICE>"}\n' > "$GRANT"
	if GRANTREF_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: divergent copies should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): divergent-copies"

	# Case 2: the writer (mint) copy is missing.
	printf '{"format":"grant:<session>:<service>"}\n' > "$GRANT"
	rm -f "$MINT"
	if GRANTREF_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: missing-mint-copy should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): missing-mint-copy"

	# Case 3: the reader (grant-service) copy is missing.
	printf '{"format":"grant:<session>:<service>"}\n' > "$MINT"
	rm -f "$GRANT"
	if GRANTREF_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: missing-grant-copy should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): missing-grant-copy"

	# Case 4: both copies byte-identical but malformed JSON (symmetric corruption).
	# Only assertable when a parser is present; with neither tool the script skips
	# the parse leg by design, so we skip this self-test case to match.
	if command -v jq >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
		printf '{"format": MALFORMED,,,}\n' > "$MINT"
		printf '{"format": MALFORMED,,,}\n' > "$GRANT"
		if GRANTREF_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
			echo "SELF-TEST FAIL: identical-but-malformed JSON should exit non-zero" >&2
			exit 1
		fi
		echo "SELF-TEST OK (non-zero): identical-malformed-json"

		# Shape arms (Cases 5–8): both copies byte-identical AND well-formed JSON,
		# so cmp and the well-formedness leg BOTH pass — only the shape assertion can
		# fail these. Each must exit non-zero. Guarded by the same parser-present gate
		# as Case 4 (with no parser the shape leg is skipped by design).
		shape_case() {
			# $1 = label; $2 = the identical (well-formed, wrong-shape) JSON body.
			printf '%s\n' "$2" > "$MINT"
			printf '%s\n' "$2" > "$GRANT"
			if GRANTREF_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
				echo "SELF-TEST FAIL: ${1} should exit non-zero (shape assertion)" >&2
				exit 1
			fi
			echo "SELF-TEST OK (non-zero): ${1}"
		}

		# Case 5: .format is not a string (a renamed/retyped format field).
		shape_case "format-not-a-string" \
			'{"format":123,"cases":[{"session":"s","service":"github","ref":"grant:s:github"}]}'
		# Case 6: .cases is an empty array (the golden proves nothing).
		shape_case "empty-cases" \
			'{"format":"grant:<session>:<service>","cases":[]}'
		# Case 7: a case entry field is not a string (session is a number).
		shape_case "entry-field-not-a-string" \
			'{"format":"grant:<session>:<service>","cases":[{"session":123,"service":"github","ref":"grant:123:github"}]}'
		# Case 8: ref does NOT derive as grant:<session>:<service> (the §5.1 rule).
		shape_case "ref-does-not-derive" \
			'{"format":"grant:<session>:<service>","cases":[{"session":"s1","service":"github","ref":"grant:WRONG:github"}]}'
	else
		echo "SELF-TEST SKIP: identical-malformed-json + shape arms (no jq/python3 for parse leg)"
	fi

	echo "Gate self-test: all cases confirmed non-vacuous"
	exit 0
fi

MINT_PATH="$ROOT/$MINT_REL"
GRANT_PATH="$ROOT/$GRANT_REL"

fail=0

# Both committed copies must be present and readable.
for p in "$MINT_PATH" "$GRANT_PATH"; do
	if [ ! -f "$p" ]; then
		echo "GRANTREF GOLDEN FAIL: missing fixture — $p" >&2
		fail=1
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "GRANTREF GOLDEN: FAILED" >&2
	echo "  the GrantRef cross-module golden must exist in BOTH modules:" >&2
	echo "    $MINT_REL  (writer: identity/mint)" >&2
	echo "    $GRANT_REL  (reader: identity/grant-service)" >&2
	echo "  doc 16 §9 grant-fetch row — the shared golden is the single source of truth." >&2
	exit 1
fi

# Both present: assert byte-identity. cmp -s is silent; we print the diagnostic.
if ! cmp -s "$MINT_PATH" "$GRANT_PATH"; then
	echo "GRANTREF GOLDEN: FAILED — the two committed copies DIVERGE:" >&2
	echo "    $MINT_REL  (writer: identity/mint)" >&2
	echo "    $GRANT_REL  (reader: identity/grant-service)" >&2
	echo "  These MUST be byte-identical: the grant_ref string is the only thing" >&2
	echo "  the WRITER (mint) and READER (grant-service) agree on across two" >&2
	echo "  standalone GOWORK=off modules (doc 16 §9). Each module's own suite" >&2
	echo "  pins only its half, so nothing else gates that the two fixture copies" >&2
	echo "  stay identical — this lint is that gate. Reconcile them (the byte-diff" >&2
	echo "  follows):" >&2
	# Show the actual divergence to make the fix obvious; non-fatal if diff absent.
	cmp "$MINT_PATH" "$GRANT_PATH" >&2 || true
	if command -v diff >/dev/null 2>&1; then
		diff -u "$MINT_PATH" "$GRANT_PATH" >&2 || true
	fi
	exit 1
fi

# Byte-identity holds — but a bad merge can corrupt BOTH copies symmetrically,
# leaving them identical yet malformed JSON, OR structurally-valid-but-WRONG
# (a renamed key, an emptied case list, a ref that no longer derives from its
# session/service). cmp catches NEITHER; both slip past and only blow up later
# at per-module test time. So we parse the canonical (writer/mint) copy — byte-
# identity already guarantees the reader copy is the same bytes — and assert its
# SHAPE (doc 16 §5.1, §9). Tool-optional: prefer jq, fall back to python3, and
# if NEITHER is present skip the parse+shape leg with a clear notice (the byte-
# identity leg above has already run and passed). See the shape rules in the
# header comment.
#
# shape_fail — print a uniform shape-violation diagnostic and exit 1.
#   $1 = the specific violation the parser reported.
shape_fail() {
	echo "GRANTREF GOLDEN: FAILED — canonical copy has the wrong SHAPE:" >&2
	echo "    $MINT_REL  (writer: identity/mint)" >&2
	echo "  Violation: $1" >&2
	echo "  The two copies are byte-identical but the golden does not match the" >&2
	echo "  contract shape: .format a string, .cases a NON-EMPTY array, and each" >&2
	echo "  case a {session,service,ref} of strings with" >&2
	echo "  ref == \"grant:\" + session + \":\" + service (doc 16 §5.1, §9 grant-" >&2
	echo "  fetch row). A structurally-valid-but-wrong golden that cmp cannot see." >&2
	echo "  Reconcile the golden against doc 16 §5.1." >&2
	exit 1
}

if command -v jq >/dev/null 2>&1; then
	if ! jq -e . "$MINT_PATH" >/dev/null 2>&1; then
		echo "GRANTREF GOLDEN: FAILED — canonical copy is not well-formed JSON:" >&2
		echo "    $MINT_REL  (writer: identity/mint)" >&2
		echo "  The two copies are byte-identical but do not parse as JSON (jq)." >&2
		echo "  This is the symmetric-corruption case a bad merge can produce — both" >&2
		echo "  copies broken identically, so cmp passes. Reconcile against doc 16 §9." >&2
		# Surface the parser's own diagnostic to pinpoint the malformation.
		jq . "$MINT_PATH" >&2 || true
		exit 1
	fi
	# Shape assertion: emit the FIRST failing invariant (empty output == all OK).
	shape_err=$(jq -r '
		if (.format | type) != "string" then ".format is not a string"
		elif (.cases | type) != "array" then ".cases is not an array"
		elif (.cases | length) == 0 then ".cases is empty (need at least one case)"
		else
			( .cases
			  | to_entries[]
			  | .key as $i
			  | .value as $c
			  | if ($c.session | type) != "string" then "cases[\($i)].session is not a string"
			    elif ($c.service | type) != "string" then "cases[\($i)].service is not a string"
			    elif ($c.ref | type) != "string" then "cases[\($i)].ref is not a string"
			    elif $c.ref != ("grant:" + $c.session + ":" + $c.service)
			      then "cases[\($i)].ref=\($c.ref) does not derive as grant:<session>:<service> (expected grant:\($c.session):\($c.service))"
			    else empty
			    end )
		end
	' "$MINT_PATH" 2>&1 | head -1)
	[ -z "$shape_err" ] || shape_fail "$shape_err"
elif command -v python3 >/dev/null 2>&1; then
	if ! python3 -m json.tool "$MINT_PATH" >/dev/null 2>&1; then
		echo "GRANTREF GOLDEN: FAILED — canonical copy is not well-formed JSON:" >&2
		echo "    $MINT_REL  (writer: identity/mint)" >&2
		echo "  The two copies are byte-identical but do not parse as JSON (python3)." >&2
		echo "  This is the symmetric-corruption case a bad merge can produce — both" >&2
		echo "  copies broken identically, so cmp passes. Reconcile against doc 16 §9." >&2
		# Surface the parser's own diagnostic to pinpoint the malformation.
		python3 -m json.tool "$MINT_PATH" >/dev/null 2>&1 || python3 -m json.tool "$MINT_PATH" >&2 || true
		exit 1
	fi
	# Shape assertion (python3 fallback): print the FIRST violation, else nothing.
	shape_err=$(python3 - "$MINT_PATH" <<'PY' 2>&1
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("not well-formed JSON: %s" % e); sys.exit(0)
def bad(m):
    print(m); sys.exit(0)
if not isinstance(d.get("format"), str): bad(".format is not a string")
cases = d.get("cases")
if not isinstance(cases, list): bad(".cases is not an array")
if len(cases) == 0: bad(".cases is empty (need at least one case)")
for i, c in enumerate(cases):
    if not isinstance(c, dict): bad("cases[%d] is not an object" % i)
    if not isinstance(c.get("session"), str): bad("cases[%d].session is not a string" % i)
    if not isinstance(c.get("service"), str): bad("cases[%d].service is not a string" % i)
    if not isinstance(c.get("ref"), str): bad("cases[%d].ref is not a string" % i)
    exp = "grant:%s:%s" % (c["session"], c["service"])
    if c["ref"] != exp:
        bad("cases[%d].ref=%s does not derive as grant:<session>:<service> (expected %s)" % (i, c["ref"], exp))
PY
)
	[ -z "$shape_err" ] || shape_fail "$shape_err"
else
	echo "check-grantref-goldens: NOTE — neither jq nor python3 found; skipping JSON" >&2
	echo "  well-formedness AND shape validation. The byte-identity leg ran and passed;" >&2
	echo "  a symmetric malformed-JSON or wrong-shape corruption would not be caught" >&2
	echo "  here (install jq or python3 for the parse+shape leg). Per-module tests" >&2
	echo "  still gate JSON validity downstream." >&2
fi

echo "check-grantref-goldens: OK — $MINT_REL and $GRANT_REL are byte-identical$([ -n "${shape_err+x}" ] && printf ' and shape-valid')"
exit 0
