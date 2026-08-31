#!/bin/sh
# apply.sh — the reference migration-apply runner for the control-plane Postgres
# (doc 15 §2 D6/D33, §10 "migration tooling is free, bounded by the D19 tier
# swap"). It is deliberately NON-Go so it stays OUTSIDE orchestrator/go.mod's
# stdlib-only import graph: nothing in the module compiles or imports it.
#
# Contract it implements (see README.md "Apply contract"):
#   - ORDERING:   apply every NNNN_*.sql in this directory in LEXICAL order by
#                 filename (the zero-padded NNNN prefix == apply order).
#   - FAILURE:    STOP ON FIRST ERROR. psql runs each file with -v ON_ERROR_STOP=1
#                 inside a single transaction (-1); a failing file aborts the run
#                 with a non-zero exit and applies nothing from that file.
#   - IDEMPOTENCY (re-run posture): the raw DDL is NOT individually idempotent
#                 (plain CREATE TABLE, no IF NOT EXISTS — a re-applied file errors
#                 on the existing object). This runner therefore records applied
#                 versions in a schema_migrations ledger and SKIPS files already
#                 present, so re-running the runner over a populated database is a
#                 safe no-op. Applying the WHOLE set to a FRESH database, in order,
#                 is the supported path.
#
# This script never runs in CI or the build sandbox; live application is the
# env-gated DEFERRED MANUAL STEP. It is exercised offline two ways:
#   * `sh -n apply.sh`  — syntax check (wired into the no-database smoke test).
#   * DRY_RUN=1 apply.sh — print the lexical apply plan and exit, no psql, no DB.
#
# Usage:
#   DS_PG_DSN='postgres://user:pw@host:5432/db' ./apply.sh
#   DRY_RUN=1 ./apply.sh            # print the ordered plan only, touch no DB
#
# Environment:
#   DS_PG_DSN   required unless DRY_RUN=1 — libpq connection string / URI.
#   PSQL        psql binary to use (default: psql).
#   DRY_RUN     when set to 1, print the plan and exit 0 without connecting.

set -eu

# Resolve this script's own directory so the runner is invariant to cwd.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PSQL=${PSQL:-psql}

# Lexical apply order: the shell glob expands sorted in the C locale, and the
# zero-padded NNNN prefix makes lexical order == numeric order. Guard the
# no-match case so an empty directory fails loudly instead of applying a literal.
plan=""
for f in "$script_dir"/[0-9][0-9][0-9][0-9]_*.sql; do
	[ -e "$f" ] || { echo "apply.sh: no NNNN_*.sql migrations found in $script_dir" >&2; exit 1; }
	plan="$plan$f
"
done

if [ "${DRY_RUN:-}" = "1" ]; then
	echo "apply plan (lexical order):"
	printf '%s' "$plan" | while IFS= read -r f; do
		[ -n "$f" ] || continue
		echo "  $(basename -- "$f")"
	done
	exit 0
fi

: "${DS_PG_DSN:?apply.sh: DS_PG_DSN must be set (or DRY_RUN=1)}"

# A version ledger so the runner is re-runnable: already-applied files are
# skipped. The raw .sql files stay free of any tracking table (the schema is
# owner-landed and the ledger is a runner concern, not a schema shape).
"$PSQL" "$DS_PG_DSN" -v ON_ERROR_STOP=1 -q -c \
	'CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());'

printf '%s' "$plan" | while IFS= read -r f; do
	[ -n "$f" ] || continue
	version=$(basename -- "$f" .sql)
	already=$("$PSQL" "$DS_PG_DSN" -v ON_ERROR_STOP=1 -tAq -c \
		"SELECT 1 FROM schema_migrations WHERE version = '$version';")
	if [ "$already" = "1" ]; then
		echo "skip   $version (already applied)" >&2
		continue
	fi
	echo "apply  $version" >&2
	# -1 wraps the file in a single transaction; ON_ERROR_STOP aborts the whole
	# run on the first error (stop-on-first-error). The ledger insert rides the
	# same transaction so a half-applied file never records as done.
	"$PSQL" "$DS_PG_DSN" -v ON_ERROR_STOP=1 -1 -q \
		-f "$f" \
		-c "INSERT INTO schema_migrations (version) VALUES ('$version');"
done

echo "apply.sh: all migrations applied" >&2
