#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-freeze-riders.sh — mechanically enforce the doc 15 §6.1 freeze riders.
#
# WHAT THIS GUARDS
#   docs/15-orchestrator-design.md §6.1 hosts the consolidated M0 attach-event-
#   schema freeze checklist plus the "Four riders" that make the freeze wave
#   unambiguous. Two of those riders are author-discipline prose that this lint
#   turns into a toolchain-enforced repo check, plus two cross-file drift checks
#   so the prose can never silently part ways with the code it cites:
#
#   CHECK 1 — riders block present and complete (guard-the-guard).
#     The §6.1 riders block (between the BEGIN/END HTML-comment anchors) must
#     exist and carry ALL FOUR riders by name:
#         (a) ds-canvas contract stub freezes alongside
#         (b) Freeze ordering
#         (c) Frame-tag-vs-proto-field-number disambiguation (row 9)
#         (d) Row-1 <-> row-9 coherent freeze
#     A PARSE MISS IS A HARD FAILURE, NEVER A SKIP: if the anchors or any rider
#     are gone, the lint fails loudly rather than passing vacuously.
#
#   CHECK 2 — row-1 <-> row-9 coherent freeze, made mechanical.
#     The §6.1 checklist table's row 1 (per-event sequence numbers, D79) and
#     row 9 (projection-resume wire frames, D61) freeze TOGETHER-OR-NOT-AT-ALL.
#     Their "Checked / waived" status cells must AGREE: both OPEN, or both
#     checked/waived — never one without the other. Divergence FAILS, naming the
#     row-1<->row-9 rider.
#
#   CHECK 3 — frame-tag literals vs. the real constants (drift check).
#     The rider's frame-tag literals
#         frameResume=8 / frameResumeReply=9 / frameResumeReject=10
#         resumeRejectWindowExceeded=1 / resumeRejectInternal=2
#     must match the actual constants in client/hostbridge/socket.go (the
#     framed-UDS frameType enum + the resumeRejectCode byte enum). Any drift in
#     either direction — a renumbered constant, or a doctored doc literal — FAILS.
#
#   CHECK 4 — no proto cross-reference of the socket frame tags (fail closed).
#     The frame tags live in the hostbridge socket wire's OWN number space, NOT
#     in attach.v1. No proto/dreamserpent/attach/v1/*.proto file may name
#     frameResume*/resumeRejectCode (4a) or STRUCTURALLY reserve/allocate field
#     numbers while CITING the socket frame tags (4b). (4b) parses the actual
#     'reserved N, M, X to Y;' statements and '= N;' field allocations out of the
#     .proto and flags a number 8/9/10 (or reject-code 1/2) ONLY when a
#     frame/socket/resume citation rides the same statement's symbol or comment —
#     the rider forbids the cross-REFERENCE, not the numbers themselves, so a
#     .proto that legitimately allocates fields 8/9/10 with no socket citation
#     PASSES (the false-positive negative control). attach.v1 has no .proto on
#     disk at M0 (the early-OK no-.proto paths stay), so the structural parser is
#     exercised NOW solely via --self-test synthetic fixtures.
#     ENUMERATION IS TRACKED-ONLY: the .proto set comes from `git ls-files` (the
#     committed/staged tree), NOT a `find` walk. A parallel session's UNTRACKED
#     draft .proto under proto/dreamserpent/attach/v1/ therefore can no longer
#     trip this gate for every concurrent session — only a tracked .proto is the
#     freeze contract this rider guards.
#
#   CHECK 5 — freeze-ledger substance: co-freeze + ordering, made mechanical.
#     CHECK 1 guards the rider PROSE; a freeze PR can still flip proto/FREEZE.md
#     Status cells INCOHERENTLY and pass. CHECK 5 parses the FREEZE.md ledger
#     table — keyed STRICTLY on the Package + Status columns so a sibling unit's
#     edit to the gating-checklist (notes) cell never perturbs it — classifies
#     each Status OPEN vs FROZEN (reusing the classify_status idiom), and enforces
#     the substance of two §6.1 riders the M0 one-shot freeze rides on:
#         (a) CO-FREEZE (ds-canvas-stub rider): canvas.v1's M0-window stub row may
#             not stay OPEN once attach.v1 is FROZEN — neighbors must be able to
#             fake the canvas from the same wave.
#         (b) ORDERING (attach.v1-first-or-same-wave rider): orchestrator.v1 and
#             hypervisor.v1 import attach.v1's AttachHandle, so neither may be
#             FROZEN while attach.v1 is still OPEN.
#     A missing package row or an unparseable table is a HARD failure naming the
#     check (guard-the-guard), never a skip.
#
# NETWORK-FREE. Pure bash + grep/sed/awk; reads only the tracked tree. Exits 0
# iff all five checks pass; non-zero (and prints the offending check) otherwise.
#
# TEST HOOKS (used only by --self-test; CI sets none of these):
#   DS_FREEZE_DOC      — override the §6.1 doc path (default: docs/15-orchestrator-design.md)
#   DS_SOCKET_GO       — override the socket.go path (default: client/hostbridge/socket.go)
#   DS_ATTACH_PROTO_DIR— override the attach.v1 proto dir
#                        (default: proto/dreamserpent/attach/v1)
#   DS_FREEZE_LEDGER   — override the proto/FREEZE.md ledger path
#                        (default: proto/FREEZE.md)
#
# --self-test proves the gate is NOT vacuous: it runs adversarial mutations in a
# temp tree (via the hooks above) and asserts each exits non-zero. House
# precedent: check-fixture-provenance.sh and proto-gates.sh ship the same.
#
# USAGE
#   bash scripts/check-freeze-riders.sh
#   bash scripts/check-freeze-riders.sh --self-test

set -euo pipefail

# --- locate the repo root (works from CI checkout or a manual run) -----------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
	:
else
	ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fi

FREEZE_DOC="${DS_FREEZE_DOC:-${ROOT}/docs/15-orchestrator-design.md}"
SOCKET_GO="${DS_SOCKET_GO:-${ROOT}/client/hostbridge/socket.go}"
ATTACH_PROTO_DIR="${DS_ATTACH_PROTO_DIR:-${ROOT}/proto/dreamserpent/attach/v1}"
FREEZE_LEDGER="${DS_FREEZE_LEDGER:-${ROOT}/proto/FREEZE.md}"

# The frame-tag literals the rider names, as the single source of truth this
# lint pins. CHECK 3 asserts the doc rider AND socket.go both still carry them.
RIDER_FRAME_TAGS=(
	"frameResume=8"
	"frameResumeReply=9"
	"frameResumeReject=10"
	"resumeRejectWindowExceeded=1"
	"resumeRejectInternal=2"
)

fail() {
	echo "check-freeze-riders: FAIL — $*" >&2
	exit 1
}

# ---------------------------------------------------------------------------
# Extract the §6.1 riders block (between the content-neutral HTML anchors).
# A parse miss here is a HARD FAILURE (guard-the-guard), never a silent skip.
# ---------------------------------------------------------------------------
extract_riders_block() {
	local doc="$1"
	[ -f "$doc" ] || fail "CHECK 1 (riders present): freeze doc not found: $doc"
	# Pull the lines strictly between the BEGIN and END anchor comments.
	local block
	block=$(sed -n '/<!-- BEGIN §6.1 FREEZE RIDERS/,/<!-- END §6.1 FREEZE RIDERS/p' "$doc")
	if [ -z "$block" ]; then
		fail "CHECK 1 (riders present): the §6.1 FREEZE RIDERS anchor block is MISSING from ${doc#"$ROOT"/} — a parse miss is a hard failure, not a skip (guard-the-guard). Restore the '<!-- BEGIN/END §6.1 FREEZE RIDERS -->' anchors around the four-riders bullet list."
	fi
	printf '%s\n' "$block"
}

# ---------------------------------------------------------------------------
# CHECK 1 — all four riders present by name.
# ---------------------------------------------------------------------------
check_riders_present() {
	local block="$1"
	# (name-for-error, fixed-string the bullet must contain)
	local -a riders=(
		"ds-canvas contract stub|ds-canvas\` contract stub freezes alongside this checklist"
		"Freeze ordering|Freeze ordering (previously implied, now stated)"
		"Frame-tag-vs-proto-field-number disambiguation (row 9)|Frame-tag-vs-proto-field-number disambiguation (row 9)"
		"Row-1 <-> row-9 coherent freeze|Row-1 ⟷ row-9 coherent freeze"
	)
	local missing=()
	local entry name needle
	for entry in "${riders[@]}"; do
		name="${entry%%|*}"
		needle="${entry#*|}"
		if ! printf '%s\n' "$block" | grep -qF -- "$needle"; then
			missing+=("$name")
		fi
	done
	if [ "${#missing[@]}" -gt 0 ]; then
		fail "CHECK 1 (riders present): the §6.1 riders block no longer carries all four riders — missing: ${missing[*]}. A missing rider is a hard failure (guard-the-guard)."
	fi
	echo "check-freeze-riders: CHECK 1 OK — all four §6.1 riders present" >&2
}

# ---------------------------------------------------------------------------
# CHECK 2 — row-1 <-> row-9 coherent freeze: their status cells must AGREE.
#   Each checklist row is a markdown table row beginning "| N |". The LAST
#   pipe-delimited cell is the "Checked / waived" status. We classify it as
#   OPEN vs. checked/waived and fail if row 1 and row 9 diverge.
# ---------------------------------------------------------------------------
row_status_cell() {
	# $1 = doc path, $2 = row number. Prints the final cell of "| N | … | <cell> |".
	local doc="$1" n="$2" line
	line=$(grep -nE "^\| ${n} \|" "$doc" | head -1 | cut -d: -f2-)
	[ -n "$line" ] || fail "CHECK 2 (row-1<->row-9 coherent freeze rider): §6.1 checklist row ${n} not found in ${doc#"$ROOT"/} — cannot verify together-or-not-at-all coherence."
	# Strip the trailing "|" then take everything after the last remaining "|".
	line="${line%|}"
	line="${line%"${line##*[![:space:]]}"}"   # rtrim
	printf '%s' "${line##*|}"
}

classify_status() {
	# Map a status cell to "OPEN" or "SET" (checked/waived). OPEN is named
	# explicitly in the cell (case-insensitively, ignoring markdown emphasis);
	# anything else is treated as a set (checked/waived) status.
	local cell="$1" stripped
	stripped=$(printf '%s' "$cell" | tr '[:upper:]' '[:lower:]' | tr -d '*` ')
	case "$stripped" in
		*open*) echo "OPEN" ;;
		*)      echo "SET" ;;
	esac
}

check_row1_row9_coherent() {
	local doc="$1" c1 c9 s1 s9
	c1=$(row_status_cell "$doc" 1)
	c9=$(row_status_cell "$doc" 9)
	s1=$(classify_status "$c1")
	s9=$(classify_status "$c9")
	if [ "$s1" != "$s9" ]; then
		fail "CHECK 2 (Row-1 ⟷ row-9 coherent freeze rider, D79/D61): §6.1 row 1 (per-event sequence numbers) and row 9 (projection-resume wire frames) must freeze TOGETHER-OR-NOT-AT-ALL, but their status cells DIVERGE — row 1 is '${c1## }' (${s1}), row 9 is '${c9## }' (${s9}). The resume frames are meaningless without the seqs they key on: either both OPEN or both checked/waived, never one without the other."
	fi
	echo "check-freeze-riders: CHECK 2 OK — §6.1 row 1 and row 9 status agree (${s1})" >&2
}

# ---------------------------------------------------------------------------
# CHECK 3 — frame-tag literals in the rider match socket.go.
#   For each "name=value" literal: the rider prose (the disambiguation bullet)
#   must carry it, AND socket.go must declare the constant with that value.
# ---------------------------------------------------------------------------
check_frame_tag_drift() {
	local block="$1"
	[ -f "$SOCKET_GO" ] || fail "CHECK 3 (frame-tag drift): socket.go not found: ${SOCKET_GO#"$ROOT"/}"

	# Isolate the disambiguation rider bullet (the one that owns the literals).
	local rider
	rider=$(printf '%s\n' "$block" | grep -F "Frame-tag-vs-proto-field-number disambiguation" || true)
	[ -n "$rider" ] || fail "CHECK 3 (frame-tag drift): the frame-tag disambiguation rider bullet is missing from the §6.1 riders block."

	local pair name val esc_name doc_re
	for pair in "${RIDER_FRAME_TAGS[@]}"; do
		name="${pair%%=*}"
		val="${pair#*=}"

		# (3a) The rider prose carries the literal, in either markdown form:
		#   `frameResume=8`                      (name=value)
		#   `resumeRejectWindowExceeded` (=1)    (name`, then " (=value")
		# ERE: name, then an optional run of backtick/space/open-paren, then '=',
		# optional space, then the value at a word boundary.
		esc_name=$(printf '%s' "$name" | sed 's/[][\.*^$(){}+?|/]/\\&/g')
		doc_re="${esc_name}[\` (]*=[ ]*${val}([^0-9]|$)"
		if ! printf '%s\n' "$rider" | grep -qE "$doc_re"; then
			fail "CHECK 3 (frame-tag drift): the §6.1 disambiguation rider no longer names the frame-tag literal '${name}=${val}'. The rider's literals are teeth — verify-and-extend, never drop or renumber; if socket.go genuinely renumbered, that is a wire-contract change (D79/D61), not a doc edit."
		fi

		# (3b) socket.go declares the constant with the same value. The enum
		# lines read e.g. "frameResume frameType = 8" / "resumeRejectWindowExceeded resumeRejectCode = 1".
		if ! grep -qE "^[[:space:]]*${esc_name}[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*${val}\b" "$SOCKET_GO"; then
			fail "CHECK 3 (frame-tag drift): client/hostbridge/socket.go does not declare '${name} = ${val}' — the §6.1 rider's literal and the socket-wire constant have DRIFTED. Reconcile the rider with socket.go (or vice versa); the rider exists to keep them locked."
		fi
	done
	echo "check-freeze-riders: CHECK 3 OK — all 5 frame-tag literals match socket.go" >&2
}

# ---------------------------------------------------------------------------
# CHECK 4 (4b) STRUCTURAL — parse reserved-statements and field-number
#   allocations out of a .proto, and flag a socket frame tag (8/9/10) or a
#   reject-code (1/2) ONLY when the SAME statement carries a frame/socket/resume
#   citation in its symbol or trailing comment. The rider forbids the
#   cross-REFERENCE, not the numbers — fields legitimately numbered 8/9/10 with
#   no socket citation must PASS (the false-positive negative control, case K).
#
#   Statement forms parsed (proto3):
#     reserved 8, 9, 10;                  // <comment>
#     reserved 7 to 10;                   // <comment>   (range expands to 7..10)
#     <type> <name> = 8;                  // <comment>
#     <NAME> = 1;                         // (enum value)  // <comment>
#   A "citation" = the case-insensitive token frame | socket | resume appearing
#   in the field/enum symbol name OR the statement's trailing `// …` comment.
#   We emit a flag line per offending statement so the failure is legible.
#
#   Pure awk per file (no per-line shell fork). $0 is the raw .proto line.
# ---------------------------------------------------------------------------
proto_structural_cross_refs() {
	# $1 = .proto path. Prints one "Ln: <line>" per offending statement; empty
	# output means clean. A "socket frame tag" here is 8/9/10; a reject code is
	# 1/2 — and ONLY when a frame/socket/resume citation rides the statement.
	local proto="$1"
	awk '
		# Split a statement into its code part and its trailing // comment.
		function code_of(s,   i){ i=index(s,"//"); return (i?substr(s,1,i-1):s) }
		function comment_of(s, i){ i=index(s,"//"); return (i?substr(s,i+2):"")  }
		# Does the symbol/comment cite the socket frame wire? A citation token
		# (frame|socket|resume) must START a word — a leading non-letter boundary
		# — but may be a PREFIX of a compound (frameResume, resumeRejectWindow…,
		# socket_wire all cite; "consumer"/"presume" do NOT, the token not being
		# word-initial). This is what flags an enum reject-code comment like
		# "// mirrors resumeRejectWindowExceeded" while leaving ordinary prose be.
		function cites(sym,cmt,   blob){
			blob=tolower(sym " " cmt)
			return (blob ~ /(^|[^a-z])(frame|socket|resume)/)
		}
		# Emit the offending statement once.
		function flag(){ printf "L%d: %s\n", NR, $0 }
		{
			line=$0
			code=code_of(line)
			cmt=comment_of(line)

			# --- reserved statements: "reserved <nums/ranges> ;" -------------
			if (code ~ /^[[:space:]]*reserved[[:space:]]/) {
				# Extract the numeric body between "reserved" and ";".
				body=code
				sub(/^[[:space:]]*reserved[[:space:]]*/, "", body)
				sub(/;.*$/, "", body)
				gsub(/,/, " ", body)
				# Walk tokens, expanding "N to M" ranges.
				n=split(body, tok, /[[:space:]]+/)
				hit=0
				for (i=1; i<=n; i++) {
					if (tok[i]=="") continue
					if (tok[i]=="to" && i>1 && (i+1)<=n) {
						lo=tok[i-1]+0; hi=tok[i+1]+0
						for (v=lo; v<=hi; v++) if (v>=8 && v<=10) hit=1
						continue
					}
					if (tok[i] ~ /^[0-9]+$/) { v=tok[i]+0; if (v>=8 && v<=10) hit=1 }
				}
				# A reserved range that covers 8/9/10 only matters if the
				# statement CITES the socket wire (symbol n/a here → comment).
				if (hit && cites("", cmt)) flag()
				next
			}

			# --- field / enum-value allocations: "<sym> = N;" ----------------
			# Capture the symbol left of "=" and the integer right of it.
			if (code ~ /=[[:space:]]*[0-9]+[[:space:]]*;/) {
				# number = last "= N" on the code part.
				num=code
				sub(/^.*=[[:space:]]*/, "", num)
				sub(/[[:space:]]*;.*$/, "", num)
				if (num ~ /^[0-9]+$/) {
					v=num+0
					# symbol = the identifier just left of "=".
					sym=code
					sub(/[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]*;.*$/, "", sym)
					sub(/^.*[[:space:]]/, "", sym)   # last whitespace-delimited token
					if ((v>=8 && v<=10) || v==1 || v==2) {
						if (cites(sym, cmt)) flag()
					}
				}
				next
			}
		}
	' "$proto"
}

# ---------------------------------------------------------------------------
# enumerate_tracked_protos — the TRACKED *.proto immediately under a dir.
#   $1 = dir (absolute). Prints one absolute path per line, only files git
#   tracks (committed or staged), only directly under the dir (mirrors the old
#   `find -maxdepth 1`: a nested-subdir .proto is NOT this dir's concern). An
#   UNTRACKED draft .proto is deliberately INVISIBLE here — that is the whole
#   point: a parallel session's work-in-progress .proto must not trip the gate.
#   `git ls-files -- '*.proto'` is scoped to the dir via -C and emits paths
#   RELATIVE to it; we drop any path with a slash (a subdir) and re-prefix the
#   dir so callers (grep/awk, ${p#$ROOT/}) get an openable absolute path.
#   Empty output (no tracked .proto, or the dir is outside any git work tree)
#   means there is nothing to cross-reference.
# ---------------------------------------------------------------------------
enumerate_tracked_protos() {
	local dir="$1" rel listing
	# If the dir is outside any git work tree (e.g. a README-only attach.v1 with
	# no repo, or a hermetic temp fixture), there is nothing tracked — emit
	# nothing. Probing first keeps `git ls-files`'s not-a-repo exit (128) from
	# tripping `set -e`/pipefail and aborting the whole lint.
	git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0
	# -C "$dir" runs git as if from the dir; ls-files then lists TRACKED paths
	# (the index — committed or staged) under it, relative to it. Capture first
	# so a failure cannot ride a pipeline into pipefail. Newline-delimited: the
	# attach.v1 dir holds plain `*.proto` names (no embedded newlines), matching
	# the prior find-based contract.
	listing=$(git -C "$dir" ls-files --cached -- '*.proto' 2>/dev/null || true)
	[ -n "$listing" ] || return 0
	while IFS= read -r rel; do
		[ -n "$rel" ] || continue
		# -maxdepth 1: only files DIRECTLY in the dir (no slash in the rel path).
		case "$rel" in
			*/*) continue ;;
		esac
		printf '%s/%s\n' "$dir" "$rel"
	done <<< "$listing"
}

# ---------------------------------------------------------------------------
# CHECK 4 — no attach.v1 .proto cross-references the socket frame tags.
#   Fail closed if any TRACKED *.proto under the attach.v1 dir names a socket
#   frame-tag symbol (4a) or STRUCTURALLY reserves/allocates a field number
#   while citing the socket frame tags (4b). The tags live in the hostbridge
#   socket wire's OWN number space. Enumeration is git-ls-files (tracked-only),
#   never a find walk — an untracked draft .proto from a parallel session is
#   NOT the freeze contract and must not trip this gate.
# ---------------------------------------------------------------------------
check_no_proto_cross_reference() {
	# The dir may legitimately hold no .proto yet (README-only at M0). That is
	# fine — there is simply nothing to cross-reference. We only fail on an
	# actual offending TRACKED .proto.
	[ -d "$ATTACH_PROTO_DIR" ] || { echo "check-freeze-riders: CHECK 4 OK — no attach.v1 proto dir (nothing to cross-reference)" >&2; return 0; }

	local protos
	protos=$(enumerate_tracked_protos "$ATTACH_PROTO_DIR")
	if [ -z "$protos" ]; then
		echo "check-freeze-riders: CHECK 4 OK — no tracked attach.v1 *.proto files yet (nothing to cross-reference)" >&2
		return 0
	fi

	local offenders="" p hits
	while IFS= read -r p; do
		[ -n "$p" ] || continue
		# (4a) Naming a socket frame-tag symbol inside a .proto is forbidden:
		#      the tags are not attach.v1 symbols.
		hits=$(grep -nE 'frameResume(Reply|Reject)?|resumeRejectCode|resumeRejectWindowExceeded|resumeRejectInternal' "$p" || true)
		if [ -n "$hits" ]; then
			offenders+="${p#"$ROOT"/}: names a socket frame-tag symbol (frameResume*/resumeRejectCode) — the tags live in the hostbridge socket wire's OWN number space, never attach.v1:"$'\n'"$hits"$'\n'
		fi
		# (4b) STRUCTURAL: parse reserved-statements + field-number allocations
		#      and flag a socket frame tag (8/9/10) or reject code (1/2) ONLY
		#      when the same statement CITES the socket wire (frame/socket/
		#      resume in the symbol or trailing comment). A legitimate field
		#      numbered 8/9/10 with NO such citation does NOT trip this — the
		#      rider forbids the cross-reference, not the numbers (case K).
		hits=$(proto_structural_cross_refs "$p" || true)
		if [ -n "$hits" ]; then
			offenders+="${p#"$ROOT"/}: a reserved-statement or field-number allocation cites the socket frame tags (8/9/10) or reject codes (1/2) — distinct numbering spaces; no attach.v1 field number is constrained by a socket frame tag:"$'\n'"$hits"$'\n'
		fi
	done <<< "$protos"

	if [ -n "$offenders" ]; then
		fail "CHECK 4 (frame-tag-vs-proto-field-number disambiguation rider): attach.v1 .proto cross-references the hostbridge socket frame tags — fail closed. The socket frame tags (8/9/10, reject codes 1/2) and attach.v1 field numbers are DISTINCT numbering spaces."$'\n'"$offenders"
	fi
	echo "check-freeze-riders: CHECK 4 OK — no attach.v1 .proto cross-references the socket frame tags" >&2
}

# ---------------------------------------------------------------------------
# CHECK 5 — freeze-ledger substance (co-freeze + ordering).
#   Parse the proto/FREEZE.md table, keyed STRICTLY on the Package (col 1) and
#   Status (col 4) columns, and enforce the SUBSTANCE of two §6.1 riders:
#     (a) CO-FREEZE: canvas.v1's stub may not stay OPEN once attach.v1 is FROZEN.
#     (b) ORDERING: orchestrator.v1 / hypervisor.v1 never FROZEN while attach.v1
#         is OPEN.
#   A missing package row or unparseable Status is a HARD failure (guard-the-
#   guard). Keying on the Package + Status columns ONLY means a sibling unit's
#   edit to the gating-checklist (col 5) cell never perturbs this parse.
# ---------------------------------------------------------------------------

# ledger_status_cell — print the Status (col 4) cell for an EXACT package name.
#   $1 = ledger path, $2 = package (e.g. dreamserpent.attach.v1, no backticks).
#   FREEZE.md rows read: | `<pkg>` | <owner> | <stage> | <status> | <checklist> |
#   We match col 1 on the backtick-fenced package EXACTLY (so attach.v1 never
#   matches a hypothetical attach.v1beta row), then take col 4 by field index —
#   robust to commas/pipes-as-text only if the col-5 checklist holds no literal
#   '|'; FREEZE.md's checklist cells use '\|' or none, so a raw '|' is a column
#   boundary and field 5 (Status) is unambiguous. Prints nothing if no row.
ledger_status_cell() {
	local ledger="$1" pkg="$2"
	# awk: a table row is a line whose first non-space char is '|'. Field 2 (after
	# the leading empty field 1) is the Package cell; field 5 is the Status cell.
	# We trim each cell and compare the Package cell to "`<pkg>`" exactly.
	awk -v want="\`${pkg}\`" '
		function trim(s){ gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
		/^[[:space:]]*\|/ {
			# Split on "|"; leading "|" yields an empty $1, so cells are $2..$NF.
			n=split($0, c, "|")
			if (n < 5) next
			pkgcell=trim(c[2])
			if (pkgcell == want) { print trim(c[5]); exit }
		}
	' "$ledger"
}

# classify_freeze — map a FREEZE.md Status cell to OPEN | FROZEN.
#   Statuses read '**OPEN**' / '**OPEN** (reserved)' / '**FROZEN 2026-06-12** (…)'.
#   Reuses the classify_status lowercase/strip idiom, then disambiguates OPEN vs
#   FROZEN. An EMPTY cell (no such row) returns "" so the caller hard-fails with
#   a precise message. A cell that is neither open nor frozen returns "?" — also
#   a hard failure (guard-the-guard: an unparseable Status never passes vacuously).
classify_freeze() {
	local cell="$1" stripped
	[ -n "$cell" ] || { echo ""; return 0; }
	stripped=$(printf '%s' "$cell" | tr '[:upper:]' '[:lower:]' | tr -d '*` ')
	case "$stripped" in
		frozen*) echo "FROZEN" ;;
		open*)   echo "OPEN" ;;
		*)       echo "?" ;;
	esac
}

# ledger_state — resolve a package to OPEN | FROZEN, hard-failing on miss/garble.
ledger_state() {
	local pkg="$1" cell state
	cell=$(ledger_status_cell "$FREEZE_LEDGER" "$pkg")
	if [ -z "$cell" ]; then
		fail "CHECK 5 (freeze-ledger substance): package row '${pkg}' is MISSING from ${FREEZE_LEDGER#"$ROOT"/} (keyed on the Package column). A missing ledger row is a hard failure (guard-the-guard) — the co-freeze/ordering riders cannot be verified against a ledger that does not name the package."
	fi
	state=$(classify_freeze "$cell")
	if [ "$state" = "?" ]; then
		fail "CHECK 5 (freeze-ledger substance): the Status cell for '${pkg}' in ${FREEZE_LEDGER#"$ROOT"/} is neither OPEN nor FROZEN — got '${cell}'. An unparseable Status is a hard failure (guard-the-guard); the ledger rows read '**OPEN**' / '**OPEN** (reserved)' / '**FROZEN <date>** (…)'."
	fi
	echo "$state"
}

check_freeze_ledger_substance() {
	[ -f "$FREEZE_LEDGER" ] || fail "CHECK 5 (freeze-ledger substance): the freeze ledger is MISSING: ${FREEZE_LEDGER#"$ROOT"/} — a parse miss is a hard failure, not a skip (guard-the-guard)."

	local attach canvas orch hyper
	attach=$(ledger_state "dreamserpent.attach.v1")
	canvas=$(ledger_state "dreamserpent.canvas.v1")
	orch=$(ledger_state "dreamserpent.orchestrator.v1")
	hyper=$(ledger_state "dreamserpent.hypervisor.v1")

	# (5a) CO-FREEZE (ds-canvas-stub rider): canvas.v1 may not stay OPEN once
	#      attach.v1 is FROZEN — neighbors must fake the canvas from the same wave.
	if [ "$attach" = "FROZEN" ] && [ "$canvas" = "OPEN" ]; then
		fail "CHECK 5 (ds-canvas-stub co-freeze rider, §6.1): attach.v1 is FROZEN in ${FREEZE_LEDGER#"$ROOT"/} but the canvas.v1 stub row is still OPEN. The 'ds-canvas contract stub freezes alongside this checklist' rider requires canvas.v1's M0-window stub to freeze in the SAME wave (D87) so neighbors can name and fake the canvas — an attach.v1 freeze that leaves canvas.v1 OPEN is incoherent and a freeze-blocker."
	fi

	# (5b) ORDERING (attach.v1-first-or-same-wave rider): orchestrator.v1 and
	#      hypervisor.v1 import attach.v1's AttachHandle, so neither may freeze
	#      AHEAD of attach.v1 (FROZEN while attach.v1 is still OPEN).
	local downstream pkg dstate
	downstream="dreamserpent.orchestrator.v1:${orch} dreamserpent.hypervisor.v1:${hyper}"
	if [ "$attach" = "OPEN" ]; then
		for pair in $downstream; do
			pkg="${pair%%:*}"; dstate="${pair#*:}"
			if [ "$dstate" = "FROZEN" ]; then
				fail "CHECK 5 (freeze-ordering rider — attach.v1-first-or-same-wave, §6.1): ${pkg} is FROZEN in ${FREEZE_LEDGER#"$ROOT"/} while attach.v1 is still OPEN. ${pkg} imports attach.v1's AttachHandle (orchestrator.v1 §5.3 Attach / hypervisor.v1 §5.1 IssueAttachHandle) and WatchSession's event vocabulary is gated by the §6.1 checklist — the M0 packages freeze as ONE WAVE or attach.v1-FIRST, never orchestrator.v1/hypervisor.v1 ahead of it."
			fi
		done
	fi

	echo "check-freeze-riders: CHECK 5 OK — freeze ledger coherent (attach.v1=${attach}, canvas.v1=${canvas}, orchestrator.v1=${orch}, hypervisor.v1=${hyper}); co-freeze + ordering riders satisfied" >&2
}

# ---------------------------------------------------------------------------
# Self-test: adversarial mutations, each must exit non-zero. CI never sets this.
# ---------------------------------------------------------------------------
self_test() {
	local T script rc
	script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
	T=$(mktemp -d)
	trap 'rm -rf "$T"' EXIT

	# Build a minimal, self-contained scratch tree the cases mutate.
	mkdir -p "$T/docs" "$T/client/hostbridge" "$T/proto/dreamserpent/attach/v1"

	# CHECK 4 now enumerates the attach.v1 .proto set via `git ls-files`
	# (tracked-only), never a find walk. So the .proto cases below must STAGE
	# their fixture into a real git work tree for the gate to see it — an
	# untracked file is deliberately invisible (the parallel-session footgun
	# this unit fixes). git_init_repo makes a dir a git repo; stage_proto writes
	# a .proto AND `git add`s it so the tracked-only enumeration picks it up.
	# All hermetic: a throwaway repo under $T, no network, no shared config.
	git_init_repo() {
		# $1 = repo root. Idempotent; quiet; identity pinned so commits/adds need
		# no global git config (CI runners may have none).
		local root="$1"
		mkdir -p "$root"
		git -C "$root" rev-parse --git-dir >/dev/null 2>&1 && return 0
		git -C "$root" init -q
		git -C "$root" config user.email "self-test@dream-serpent.invalid"
		git -C "$root" config user.name  "freeze-riders self-test"
	}
	stage_proto() {
		# $1 = repo root; $2 = path-relative-to-root of the .proto; $3 = body.
		# Writes the file and `git add`s it so it is TRACKED (staged is enough —
		# git ls-files --cached lists the index). No commit needed.
		local root="$1" rel="$2" body="$3" dir
		dir=$(dirname "$root/$rel")
		mkdir -p "$dir"
		printf '%s' "$body" > "$root/$rel"
		git -C "$root" add -- "$rel"
	}

	# A faithful (passing) doc §6.1 fixture: rows 1 & 9 both OPEN, all four
	# riders present with the live frame-tag literals.
	cat > "$T/docs/15.md" <<'DOC'
### 6.1 Consolidated M0 attach-event-schema freeze checklist

| # | Field class | Source | Checked / waived |
|---|---|---|---|
| 1 | Per-event sequence numbers | D79 | OPEN |
| 9 | Projection-resume wire frames | socket.go; D79; D61 | **OPEN** (reserve frame tags 8/9/10 + the `resumeRejectCode` enum) |

Four riders, stated here so the freeze wave is unambiguous:

<!-- BEGIN §6.1 FREEZE RIDERS (lint anchor — content-neutral) -->
- **The `ds-canvas` contract stub freezes alongside this checklist** — neighbors can fake the canvas.
- **Freeze ordering (previously implied, now stated):** the M0 packages freeze attach.v1-first.
- **Frame-tag-vs-proto-field-number disambiguation (row 9):** the reserved 8/9/10 are LOCAL hostbridge wire frame-type tags (`frameResume=8` / `frameResumeReply=9` / `frameResumeReject=10`, plus the `resumeRejectCode` byte enum `resumeRejectWindowExceeded=1` / `resumeRejectInternal=2`) — NOT attach.v1 field numbers.
- **Row-1 ⟷ row-9 coherent freeze (D79 / D61):** row 1 and the row-9 family freeze together-or-not-at-all.
<!-- END §6.1 FREEZE RIDERS -->
DOC

	# A faithful socket.go fixture with the live constants.
	cat > "$T/client/hostbridge/socket.go" <<'GO'
package hostbridge

const (
	frameResume       frameType = 8
	frameResumeReply  frameType = 9
	frameResumeReject frameType = 10
)

const (
	resumeRejectWindowExceeded resumeRejectCode = 1
	resumeRejectInternal       resumeRejectCode = 2
)
GO

	# A faithful (coherent) FREEZE.md ledger fixture: everything OPEN — the M0
	# pre-freeze state. CHECK 5 must pass against it. The Status column (col 4)
	# carries the markdown-emphasis form the live ledger uses; the checklist cell
	# (col 5) is deliberately noisy (pipes-as-text are escaped) to prove CHECK 5
	# keys ONLY on the Package + Status columns. Cases A-G that mutate the DOC or
	# the .proto point DS_FREEZE_LEDGER at THIS coherent ledger so they fail on
	# their OWN mutation, never incidentally on CHECK 5.
	write_ledger() {
		# $1 = dest path; $2..$5 = status cells for attach/canvas/orch/hyper.
		local dest="$1" a="$2" c="$3" o="$4" h="$5"
		cat > "$dest" <<LEDGER
# Contract freeze ledger

| Package | Owner workstream | Freeze stage | Status | Gating checklist |
|---|---|---|---|---|
| \`dreamserpent.boundary.v1\` | Boundary | Stage 0 | **FROZEN 2026-06-12** (freeze PR) | doc 14 §2 |
| \`dreamserpent.attach.v1\` | Attach & client | M0 | ${a} | consolidated checklist hosted at doc 15 §6 — per-event seqs, D79 handle |
| \`dreamserpent.canvas.v1\` | Collaborative canvas | stub in M0 window; v1 at M2 (D87) | ${c} | doc 17 §10 board-API stub; structural check: NO session-input message |
| \`dreamserpent.orchestrator.v1\` | Orchestrator | M0 | ${o} | doc 15 §5.3 (D35 names; CreateChildSession RESERVED) |
| \`dreamserpent.hypervisor.v1\` | Orchestrator | M0 | ${h} | doc 15 §5.1: full verb set + D35 flags + RecoverSessions |
LEDGER
	}
	write_ledger "$T/proto/FREEZE.md" "**OPEN**" "**OPEN**" "**OPEN**" "**OPEN**"

	# Common env for the coherent fixture — every case overrides only what it
	# mutates, so a missing override silently falling back to the real tree can
	# never let a case pass for the wrong reason.
	base_env() {
		printf '%s\n' \
			"DS_FREEZE_DOC=$T/docs/15.md" \
			"DS_SOCKET_GO=$T/client/hostbridge/socket.go" \
			"DS_ATTACH_PROTO_DIR=$T/proto/dreamserpent/attach/v1" \
			"DS_FREEZE_LEDGER=$T/proto/FREEZE.md"
	}

	run_case() {
		# $1 = human label; remaining = env overrides for one invocation. The
		# coherent base_env is applied FIRST, then the case's overrides win.
		local label="$1"; shift
		if env $(base_env) "$@" bash "$script" >/dev/null 2>&1; then
			echo "SELF-TEST FAIL: '${label}' should have exited non-zero" >&2
			rm -rf "$T"; exit 1
		fi
		echo "SELF-TEST OK (non-zero): ${label}"
	}

	pass_case() {
		# $1 = human label; remaining = env overrides. Asserts EXIT ZERO — used by
		# the coherent-ledger and false-positive-negative-control cases.
		local label="$1"; shift
		if ! env $(base_env) "$@" bash "$script" >/dev/null 2>&1; then
			echo "SELF-TEST FAIL: '${label}' should have exited ZERO" >&2
			rm -rf "$T"; exit 1
		fi
		echo "SELF-TEST OK (zero): ${label}"
	}

	# Sanity: the unmutated fixture must PASS (else the cases prove nothing).
	if ! env $(base_env) bash "$script" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: the unmutated fixture should PASS" >&2
		rm -rf "$T"; exit 1
	fi
	echo "SELF-TEST OK (zero): unmutated fixture passes"

	# Case A — row 1 flipped to checked while row 9 stays OPEN (incoherent).
	sed 's/^| 1 | Per-event sequence numbers | D79 | OPEN |/| 1 | Per-event sequence numbers | D79 | checked |/' \
		"$T/docs/15.md" > "$T/docs/15-caseA.md"
	run_case "row-1 checked while row-9 OPEN (Row-1<->row-9 coherent freeze rider)" \
		DS_FREEZE_DOC="$T/docs/15-caseA.md" DS_SOCKET_GO="$T/client/hostbridge/socket.go" \
		DS_ATTACH_PROTO_DIR="$T/proto/dreamserpent/attach/v1"

	# Case B — a frame-tag literal doctored in the doc (8 -> 7).
	sed 's/frameResume=8/frameResume=7/' "$T/docs/15.md" > "$T/docs/15-caseB.md"
	run_case "doctored frame-tag literal in the doc (drift check)" \
		DS_FREEZE_DOC="$T/docs/15-caseB.md" DS_SOCKET_GO="$T/client/hostbridge/socket.go" \
		DS_ATTACH_PROTO_DIR="$T/proto/dreamserpent/attach/v1"

	# Case C — a socket.go constant renumbered out from under the rider.
	sed 's/frameResumeReject frameType = 10/frameResumeReject frameType = 11/' \
		"$T/client/hostbridge/socket.go" > "$T/client/hostbridge/socket-caseC.go"
	run_case "renumbered socket.go constant (drift check)" \
		DS_FREEZE_DOC="$T/docs/15.md" DS_SOCKET_GO="$T/client/hostbridge/socket-caseC.go" \
		DS_ATTACH_PROTO_DIR="$T/proto/dreamserpent/attach/v1"

	# Case D — a rider removed (guard-the-guard: parse miss is a hard failure).
	grep -v 'Frame-tag-vs-proto-field-number disambiguation' "$T/docs/15.md" > "$T/docs/15-caseD.md"
	run_case "rider removed (guard-the-guard, hard failure)" \
		DS_FREEZE_DOC="$T/docs/15-caseD.md" DS_SOCKET_GO="$T/client/hostbridge/socket.go" \
		DS_ATTACH_PROTO_DIR="$T/proto/dreamserpent/attach/v1"

	# Case E — the whole anchor block gone (parse miss is a hard failure).
	grep -v 'FREEZE RIDERS' "$T/docs/15.md" > "$T/docs/15-caseE.md"
	run_case "riders anchor block removed (guard-the-guard, hard failure)" \
		DS_FREEZE_DOC="$T/docs/15-caseE.md" DS_SOCKET_GO="$T/client/hostbridge/socket.go" \
		DS_ATTACH_PROTO_DIR="$T/proto/dreamserpent/attach/v1"

	# Case F — a TRACKED attach.v1 .proto naming a socket frame-tag symbol (fail
	#   closed). The fixture is STAGED into a throwaway git repo so the tracked-
	#   only enumeration sees it; an untracked copy would (correctly) be ignored.
	git_init_repo "$T/proto-caseF"
	stage_proto "$T/proto-caseF" "dreamserpent/attach/v1/bad.proto" \
'syntax = "proto3";
package dreamserpent.attach.v1;
message Bad {
  // wrong: the socket frameResume tag has no business in attach.v1
  string frameResume = 8;
}
'
	run_case "tracked attach.v1 .proto names a socket frame-tag symbol (fail closed)" \
		DS_FREEZE_DOC="$T/docs/15.md" DS_SOCKET_GO="$T/client/hostbridge/socket.go" \
		DS_ATTACH_PROTO_DIR="$T/proto-caseF/dreamserpent/attach/v1"

	# Case G — a TRACKED attach.v1 .proto reserving a field number citing the
	#   socket tags. Staged into git so the tracked-only enumeration sees it.
	git_init_repo "$T/proto-caseG"
	stage_proto "$T/proto-caseG" "dreamserpent/attach/v1/bad.proto" \
'syntax = "proto3";
package dreamserpent.attach.v1;
message Bad {
  // wrong: reserves 8/9/10 to "match the socket resume frame tags"
  reserved 8, 9, 10; // socket resume frame tags
}
'
	run_case "tracked attach.v1 .proto reserves field numbers citing the socket frame tags (fail closed)" \
		DS_FREEZE_DOC="$T/docs/15.md" DS_SOCKET_GO="$T/client/hostbridge/socket.go" \
		DS_ATTACH_PROTO_DIR="$T/proto-caseG/dreamserpent/attach/v1"

	# Case F2 — THE PARALLEL-SESSION FOOTGUN THIS UNIT FIXES. The SAME offending
	#   .proto as case F, but UNTRACKED (written to disk, never `git add`ed) in a
	#   real git repo. The tracked-only enumeration must NOT see it, so the full
	#   script exits ZERO — a parallel session's work-in-progress draft .proto
	#   can no longer fail the freeze-rider gate for every concurrent session.
	git_init_repo "$T/proto-caseF2"
	mkdir -p "$T/proto-caseF2/dreamserpent/attach/v1"
	cat > "$T/proto-caseF2/dreamserpent/attach/v1/draft.proto" <<'PROTO'
syntax = "proto3";
package dreamserpent.attach.v1;
message Draft {
  // an UNTRACKED draft naming the socket frameResume tag — git does not track
  // it, so CHECK 4 (tracked-only) must ignore it entirely.
  string frameResume = 8;
}
PROTO
	pass_case "untracked offending attach.v1 draft .proto does NOT trip CHECK 4 (tracked-only enumeration — parallel-session footgun)" \
		DS_ATTACH_PROTO_DIR="$T/proto-caseF2/dreamserpent/attach/v1"

	# === CHECK 5 — freeze-ledger substance (co-freeze + ordering) ============

	# Case H — CO-FREEZE rider: canvas.v1 stub OPEN while attach.v1 is FROZEN.
	#   The ds-canvas-stub rider's substance — must FAIL, naming the co-freeze rider.
	write_ledger "$T/proto/FREEZE-caseH.md" "**FROZEN 2026-06-12** (freeze PR)" "**OPEN**" "**OPEN**" "**OPEN**"
	run_case "ledger: canvas.v1 OPEN while attach.v1 FROZEN (ds-canvas-stub co-freeze rider)" \
		DS_FREEZE_LEDGER="$T/proto/FREEZE-caseH.md"

	# Case I — ORDERING rider: orchestrator.v1 (and, in I2, hypervisor.v1) FROZEN
	#   while attach.v1 is OPEN — the attach.v1-first-or-same-wave rider. Must FAIL.
	write_ledger "$T/proto/FREEZE-caseI.md" "**OPEN**" "**OPEN**" "**FROZEN 2026-06-12** (freeze PR)" "**OPEN**"
	run_case "ledger: orchestrator.v1 FROZEN while attach.v1 OPEN (freeze-ordering rider)" \
		DS_FREEZE_LEDGER="$T/proto/FREEZE-caseI.md"
	write_ledger "$T/proto/FREEZE-caseI2.md" "**OPEN**" "**OPEN**" "**OPEN**" "**FROZEN 2026-06-12** (freeze PR)"
	run_case "ledger: hypervisor.v1 FROZEN while attach.v1 OPEN (freeze-ordering rider)" \
		DS_FREEZE_LEDGER="$T/proto/FREEZE-caseI2.md"

	# Case I3 — guard-the-guard: a missing package row is a HARD failure, never a
	#   vacuous skip. Drop the attach.v1 row entirely.
	grep -v 'dreamserpent.attach.v1' "$T/proto/FREEZE.md" > "$T/proto/FREEZE-caseI3.md"
	run_case "ledger: attach.v1 row MISSING (guard-the-guard, hard failure)" \
		DS_FREEZE_LEDGER="$T/proto/FREEZE-caseI3.md"

	# Case I4 — guard-the-guard: an unparseable Status cell is a HARD failure.
	#   (e.g. the freeze PR typo'd the canvas.v1 status to something non-canonical.)
	sed 's/| \*\*OPEN\*\* | doc 17/| TODO | doc 17/' "$T/proto/FREEZE.md" > "$T/proto/FREEZE-caseI4.md"
	run_case "ledger: canvas.v1 Status neither OPEN nor FROZEN (guard-the-guard, hard failure)" \
		DS_FREEZE_LEDGER="$T/proto/FREEZE-caseI4.md"

	# Case J — COHERENT ledgers PASS. (J1) all-OPEN is the base_env fixture itself;
	#   (J2) a coherent all-FROZEN-same-wave ledger (attach + canvas + orch + hyper
	#   all FROZEN) must also exit ZERO — the riders forbid INCOHERENT flips, not
	#   freezing per se.
	write_ledger "$T/proto/FREEZE-caseJ.md" \
		"**FROZEN 2026-06-12** (freeze PR)" "**FROZEN 2026-06-12** (freeze PR)" \
		"**FROZEN 2026-06-12** (freeze PR)" "**FROZEN 2026-06-12** (freeze PR)"
	pass_case "ledger: coherent all-FROZEN-same-wave passes (no incoherent flip)" \
		DS_FREEZE_LEDGER="$T/proto/FREEZE-caseJ.md"

	# Case K — THE FALSE-POSITIVE NEGATIVE CONTROL. A legit, TRACKED attach.v1
	#   .proto that allocates field numbers 8, 9 AND 10 (and an enum value 1 and
	#   2) with NO socket/frame/resume citation must let the FULL SCRIPT exit
	#   ZERO. The rider forbids the cross-REFERENCE, not the numbers — fields
	#   8/9/10 are perfectly legal attach.v1 field numbers in their own right.
	#   NOTE: the comments here are deliberately CLEAN — they carry no frame/
	#   socket/resume token. The .proto IS git-tracked (staged), so this proves
	#   the tracked-only enumeration still admits a legitimate tracked .proto.
	legit_proto='syntax = "proto3";
package dreamserpent.attach.v1;

// A legitimate attach.v1 message whose own field numbering happens to reach
// 8/9/10. None of this names the hostbridge wire tags — these are ordinary
// attach.v1 proto field numbers, which the rider explicitly permits.
message SessionEvent {
  string session_id = 1;
  string state      = 2;
  uint64 seq        = 3;
  string actor      = 4;
  string tile_id    = 5;
  string detail     = 6;
  string reason     = 7;
  string parked_by  = 8;   // who parked the session (D46)
  string spawn_id   = 9;   // subagent-spawn correlation id
  string ask_id     = 10;  // ask-prompt correlation id
  reserved 11, 12;         // future per-event fields
}

enum AskDecision {
  ASK_DECISION_UNSPECIFIED = 0;
  ASK_DECISION_ALLOW       = 1;   // allow-once / allow-always
  ASK_DECISION_DENY        = 2;   // deny
}
'
	git_init_repo "$T/proto-caseK"
	stage_proto "$T/proto-caseK" "dreamserpent/attach/v1/legit.proto" "$legit_proto"
	pass_case "tracked attach.v1 .proto allocates fields 8/9/10 + enum 1/2 with NO socket citation (false-positive negative control — must PASS)" \
		DS_ATTACH_PROTO_DIR="$T/proto-caseK/dreamserpent/attach/v1"

	# Case K2 — tighten the negative control's teeth: the SAME legit .proto, but
	#   now ONE field's comment carries a genuine socket citation — proves the
	#   parser DOES flag the cross-reference it must, so case K's PASS is the
	#   parser discriminating, not the parser being blind to 8/9/10 outright.
	#   Staged into git so the tracked-only enumeration sees it.
	git_init_repo "$T/proto-caseK2"
	stage_proto "$T/proto-caseK2" "dreamserpent/attach/v1/legit.proto" \
		"${legit_proto/string spawn_id   = 9;   \/\/ subagent-spawn correlation id/string spawn_id   = 9;   // pinned to mirror the socket resume frame tag}"
	run_case "tracked attach.v1 .proto field 9 comment cites the socket frame (genuine cross-reference, fail closed)" \
		DS_ATTACH_PROTO_DIR="$T/proto-caseK2/dreamserpent/attach/v1"

	echo "check-freeze-riders: --self-test PASSED (all adversarial cases failed closed; the unmutated fixture passed)"
	rm -rf "$T"
	trap - EXIT
	exit 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
	self_test
fi

BLOCK=$(extract_riders_block "$FREEZE_DOC")
check_riders_present "$BLOCK"
check_row1_row9_coherent "$FREEZE_DOC"
check_frame_tag_drift "$BLOCK"
check_no_proto_cross_reference
check_freeze_ledger_substance

echo "check-freeze-riders: OK — §6.1 freeze riders enforced (riders present, row1<->row9 coherent, frame-tag literals match socket.go, no proto cross-reference, freeze-ledger co-freeze + ordering coherent)" >&2
exit 0
