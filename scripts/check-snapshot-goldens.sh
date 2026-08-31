#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# check-snapshot-goldens.sh — repo-level byte-identity gate for the snapshot
# content_hash cross-module golden fixture (doc 13 §5.1, D120; D50 synthetic).
#
# WHY THIS GATE EXISTS
#   The canonical-serialization content_hash is the ONLY thing the Go host agent
#   (the PRODUCER, orchestrator/internal/nftbridge) and the Rust consumers (the
#   VERIFIERS, dataplane/crates/ds-contracts) agree on across two languages. The
#   contract is carried as testdata/snapshot-goldens.json IDENTICALLY in both:
#     - orchestrator/internal/nftbridge/content_hash_test.go
#                                  re-produces (payload, content_hash) and pins
#                                  them against its OWN copy (producer side)
#     - dataplane/crates/ds-contracts/tests/snapshot_goldens.rs
#                                  hashes the stored bytes and verifies them
#                                  against its OWN copy (verify-only consumer)
#   Each side's suite pins ITS HALF, but because the two copies are separate
#   committed files in separate modules (one Go, one Rust), NOTHING in either
#   test tree gates that the two fixtures are byte-identical. If they silently
#   diverge, the producer and the verifier can both pass their own golden while
#   encoding different bytes — exactly the Go<->Rust drift the produce-once /
#   verify-only design (doc 13 §5.1) is meant to forbid BY CONSTRUCTION. This
#   repo-level lint closes that gap: it cmp's the two committed copies and fails
#   loudly (naming both paths and the rationale) on any divergence or a missing
#   file. It is the git-side twin of the two per-module cross-checks.
#
# House precedent: scripts/check-grantref-goldens.sh, scripts/check-corpus-suffix.sh
# (committed-copies + byte-identity-lint pattern).
#
# POSIX sh, network-free. Exits 0 iff both files exist and are byte-identical;
# non-zero (and prints both paths) on divergence or a missing/unreadable file.
#
# NOTE (wave): the Makefile repo-lints aggregate is owner-FENCED this wave; the
# `repo-lints` hookup for this gate is a proposed follow-up task (see the exec
# report). Run it directly: sh scripts/check-snapshot-goldens.sh
#
# Test hook (used only by --self-test; CI/normal runs set neither):
#   SNAPSHOT_GOLDEN_ROOT — repo root to resolve the two fixture paths against
#                          (default: `git rev-parse --show-toplevel`, else cwd).
#
# --self-test: prove the gate is not vacuous by running adversarial cases in a
# temp directory and asserting each exits non-zero (divergent copies; missing
# producer copy; missing verifier copy) plus one positive case (identical copies
# -> exit 0). House precedent: check-grantref-goldens.sh ships the same proof.

set -eu

# --- the two fixture paths, relative to the repo root ----------------------
GO_REL="orchestrator/internal/nftbridge/testdata/snapshot-goldens.json"
RUST_REL="dataplane/crates/ds-contracts/testdata/snapshot-goldens.json"

# --- locate the repo root (works from CI checkout or a manual run) ---------
if [ -n "${SNAPSHOT_GOLDEN_ROOT:-}" ]; then
	ROOT=$SNAPSHOT_GOLDEN_ROOT
elif ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
	:
else
	ROOT=$(pwd)
fi

# --- Self-test mode: three negative cases + one positive --------------------
if [ "${1:-}" = "--self-test" ]; then
	T=$(mktemp -d)
	trap 'rm -rf "$T"' EXIT

	mkdir -p "$T/orchestrator/internal/nftbridge/testdata" \
		"$T/dataplane/crates/ds-contracts/testdata"
	GO="$T/$GO_REL"
	RUST="$T/$RUST_REL"

	# Positive case: identical copies must pass (exit 0).
	printf '{"content_hash":"abc","payload":"x"}\n' > "$GO"
	printf '{"content_hash":"abc","payload":"x"}\n' > "$RUST"
	if ! SNAPSHOT_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: identical copies should exit 0" >&2
		exit 1
	fi
	echo "SELF-TEST OK (zero): identical-copies"

	# Case 1: the two copies diverge by a single byte.
	printf '{"content_hash":"ABC","payload":"x"}\n' > "$RUST"
	if SNAPSHOT_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: divergent copies should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): divergent-copies"

	# Case 2: the producer (Go) copy is missing.
	printf '{"content_hash":"abc","payload":"x"}\n' > "$RUST"
	rm -f "$GO"
	if SNAPSHOT_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: missing-go-copy should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): missing-go-copy"

	# Case 3: the verifier (Rust) copy is missing.
	printf '{"content_hash":"abc","payload":"x"}\n' > "$GO"
	rm -f "$RUST"
	if SNAPSHOT_GOLDEN_ROOT="$T" sh "$0" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: missing-rust-copy should exit non-zero" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): missing-rust-copy"

	echo "Gate self-test: all cases confirmed non-vacuous"
	exit 0
fi

GO_PATH="$ROOT/$GO_REL"
RUST_PATH="$ROOT/$RUST_REL"

fail=0

# Both committed copies must be present and readable.
for p in "$GO_PATH" "$RUST_PATH"; do
	if [ ! -f "$p" ]; then
		echo "SNAPSHOT GOLDEN FAIL: missing fixture — $p" >&2
		fail=1
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "SNAPSHOT GOLDEN: FAILED" >&2
	echo "  the content_hash cross-module golden must exist in BOTH modules:" >&2
	echo "    $GO_REL    (producer: orchestrator/internal/nftbridge)" >&2
	echo "    $RUST_REL  (verifier: dataplane/crates/ds-contracts)" >&2
	echo "  doc 13 §5.1 — the shared golden is the single source of truth for the" >&2
	echo "  produce-once / verify-only content_hash contract." >&2
	exit 1
fi

# Both present: assert byte-identity. cmp -s is silent; we print the diagnostic.
if ! cmp -s "$GO_PATH" "$RUST_PATH"; then
	echo "SNAPSHOT GOLDEN: FAILED — the two committed copies DIVERGE:" >&2
	echo "    $GO_REL    (producer: orchestrator/internal/nftbridge)" >&2
	echo "    $RUST_REL  (verifier: dataplane/crates/ds-contracts)" >&2
	echo "  These MUST be byte-identical: the (payload, content_hash) golden is the" >&2
	echo "  only thing the Go PRODUCER and the Rust VERIFIER agree on across two" >&2
	echo "  languages (doc 13 §5.1). Each module's own suite pins only its half, so" >&2
	echo "  nothing else gates that the two fixture copies stay identical — this" >&2
	echo "  lint is that gate. Reconcile them (the byte-diff follows):" >&2
	# Show the actual divergence to make the fix obvious; non-fatal if diff absent.
	cmp "$GO_PATH" "$RUST_PATH" >&2 || true
	if command -v diff >/dev/null 2>&1; then
		diff -u "$GO_PATH" "$RUST_PATH" >&2 || true
	fi
	exit 1
fi

echo "check-snapshot-goldens: OK — $GO_REL and $RUST_REL are byte-identical"
exit 0
