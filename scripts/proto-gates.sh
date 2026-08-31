#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# proto-gates.sh — the four proto/ contract merge gates (D24; doc 06 §2.1).
#
# proto/ is THE single contract home (D24/D58/D80; doc 06 §2.1, doc 14 §7,
# doc 15 §5). This script is the executable form of the four ordered checks that
# .github/workflows/contracts.yml wires as the merge gate for any change under
# proto/**. Run it whole (no subcommand) to run all four in order; pass a
# subcommand to run just one. It expects a pinned `buf` (1.x) on PATH.
#
#   lint      (1) buf lint           — house style (proto/buf.yaml STANDARD).
#   breaking  (2) buf breaking       — against the committed descriptor sets in
#                                       proto/baselines/; baselines are written
#                                       ONLY by freeze PRs (proto/FREEZE.md).
#   drift     (3) codegen-drift      — regenerate (buf generate) and fail if
#                                       proto/gen/go or
#                                       dataplane/crates/ds-contracts/src/gen
#                                       differs from the committed output.
#   stray     (4) no-stray-proto     — no .proto file exists outside proto/.
#   selftest  negative breaking-gate proof — build a scratch baseline in a temp
#                                       dir, make an incompatible edit, assert
#                                       `buf breaking` exits non-zero.
#
# Design resolution 16 (proto/README.md, FREEZE.md): the skeleton ships ZERO
# .proto bodies and ZERO baselines on purpose — Stage-0 freezes are one-shot and
# checklist-gated, so a stub message would imply a freeze that has not happened.
# While that holds, checks (1) and (2) cannot run (buf errors on an empty
# module) and (3) has nothing to regenerate: each NO-OPs with a clear log line
# and PASSES. They go live with the first freeze PR, which lands the first
# .proto bodies and the first baseline together. Checks (4) and the negative
# self-test are valid with zero bodies and run for real now.
#
# POSIX sh. Exits 0 iff the selected check(s) pass; non-zero (offenders printed)
# on any failure.
#
# Test hooks (used only by the negative self-test wiring; CI sets none):
#   PROTO_STRAY_ROOT  — directory the stray scan walks (default: repo root).

set -eu

# --- locate the repo root (works from a CI checkout or a manual run) --------
if [ -n "${PROTO_GATES_ROOT:-}" ]; then
	ROOT=$PROTO_GATES_ROOT
elif ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
	:
else
	ROOT=$(pwd)
fi

PROTO_DIR="$ROOT/proto"

# Count committed .proto bodies under the contract home. Zero means the
# skeleton-time state (design resolution 16): lint/breaking/drift NO-OP+PASS.
proto_body_count() {
	if [ -d "$PROTO_DIR/dreamserpent" ]; then
		find "$PROTO_DIR/dreamserpent" -type f -name '*.proto' | wc -l | tr -d ' '
	else
		echo 0
	fi
}

# Count committed baselines (descriptor sets) under proto/baselines/.
baseline_count() {
	if [ -d "$PROTO_DIR/baselines" ]; then
		find "$PROTO_DIR/baselines" -type f \( -name '*.binpb' -o -name '*.bin' \) | wc -l | tr -d ' '
	else
		echo 0
	fi
}

require_buf() {
	if ! command -v buf >/dev/null 2>&1; then
		echo "FATAL: buf is required for the proto gates but was not found on PATH" >&2
		exit 2
	fi
}

# --- (1) buf lint -----------------------------------------------------------
check_lint() {
	bodies=$(proto_body_count)
	if [ "$bodies" -eq 0 ]; then
		echo "buf lint: NO-OP — zero .proto bodies under proto/dreamserpent/ (design resolution 16; goes live on the first freeze PR). PASS."
		return 0
	fi
	require_buf
	echo "buf lint: $bodies .proto body file(s) — running buf lint."
	( cd "$PROTO_DIR" && buf lint )
}

# --- (2) buf breaking against proto/baselines/ ------------------------------
# Each freeze PR commits one descriptor set per frozen package into
# proto/baselines/ and gates that package with
# `buf breaking --against ./baselines/<set>`. While there are no bodies and no
# baselines, there is nothing to break against — NO-OP+PASS.
check_breaking() {
	bodies=$(proto_body_count)
	baselines=$(baseline_count)
	if [ "$bodies" -eq 0 ] || [ "$baselines" -eq 0 ]; then
		echo "buf breaking: NO-OP — bodies=$bodies baselines=$baselines (design resolution 16; baselines land with the first freeze PR). PASS."
		return 0
	fi
	require_buf
	echo "buf breaking: gating $bodies body file(s) against $baselines baseline(s)."
	fail=0
	for set in "$PROTO_DIR"/baselines/*.binpb "$PROTO_DIR"/baselines/*.bin; do
		[ -f "$set" ] || continue
		echo "  buf breaking --against $(basename "$set")"
		if ! ( cd "$PROTO_DIR" && buf breaking --against "$set" ); then
			fail=1
		fi
	done
	return "$fail"
}

# --- (3) codegen-drift ------------------------------------------------------
# Regenerate from the protos and fail if the committed generated trees differ.
# The two targets (proto/buf.gen.yaml): Go -> proto/gen/go, Rust ->
# dataplane/crates/ds-contracts/src/gen. With zero bodies `buf generate`
# produces nothing, so there is no drift to find — NO-OP+PASS.
check_drift() {
	bodies=$(proto_body_count)
	if [ "$bodies" -eq 0 ]; then
		echo "codegen-drift: NO-OP — zero .proto bodies, nothing to regenerate (design resolution 16). PASS."
		return 0
	fi
	require_buf
	echo "codegen-drift: regenerating from $bodies .proto body file(s) and diffing the committed trees."
	# buf.gen.yaml's Go plugins (protoc-gen-go / protoc-gen-go-grpc) must be on
	# PATH; the workflow installs the pinned versions before this runs.
	( cd "$PROTO_DIR" && buf generate )
	# The Rust target is produced by the ds-contracts build script (prost/tonic),
	# not a buf plugin, so it is regenerated as part of the dataplane build; this
	# check diffs the trees buf+cargo wrote against what is committed.
	fail=0
	for gen in "proto/gen/go" "dataplane/crates/ds-contracts/src/gen"; do
		[ -e "$ROOT/$gen" ] || continue
		if ! ( cd "$ROOT" && git diff --quiet -- "$gen" ); then
			echo "CODEGEN DRIFT: $gen differs from regenerated output — run buf generate and commit."
			( cd "$ROOT" && git --no-pager diff --stat -- "$gen" )
			fail=1
		fi
	done
	if [ "$fail" -eq 0 ]; then
		echo "codegen-drift: committed generated trees match regenerated output. PASS."
	fi
	return "$fail"
}

# --- (4) no-stray-proto -----------------------------------------------------
# THE single contract home invariant (doc 06 §2.1, doc 14 §7, doc 15 §5): no
# .proto file may live anywhere but under proto/. Valid (and enforced) now,
# with zero bodies. Excludes .git and the negative self-test's temp fixtures,
# which never touch the working tree.
check_stray() {
	scan_root=${PROTO_STRAY_ROOT:-$ROOT}
	echo "no-stray-proto: scanning $scan_root for .proto files outside proto/."
	stray=$(find "$scan_root" -type f -name '*.proto' \
		-not -path "$scan_root/proto/*" \
		-not -path '*/.git/*' \
		-not -path '*/vendor/*' | sort)
	if [ -n "$stray" ]; then
		echo "STRAY PROTO: .proto files exist outside proto/ (the single contract home — D24/D58/D80):"
		printf '  %s\n' $stray
		return 1
	fi
	echo "no-stray-proto: no .proto files outside proto/. PASS."
	return 0
}

# --- negative self-test: prove the breaking gate actually fails -------------
# Construct a self-contained scratch module + descriptor-set baseline in a temp
# dir, make a wire-incompatible edit, and assert `buf breaking` exits non-zero.
# Also assert the unchanged module passes — so the gate is proven to fire only
# on a real break, not unconditionally. Nothing here touches proto/ or the
# working tree, so no-stray-proto and the one-shot freeze rule are unaffected.
check_selftest() {
	require_buf
	work=$(mktemp -d)
	# shellcheck disable=SC2064
	trap "rm -rf \"$work\"" EXIT
	mkdir -p "$work/proto/scratch/v1"
	cat > "$work/proto/buf.yaml" <<'EOF'
version: v2
modules:
  - path: .
breaking:
  use:
    - FILE
EOF
	cat > "$work/proto/scratch/v1/scratch.proto" <<'EOF'
syntax = "proto3";
package scratch.v1;

message Probe {
  string id = 1;
  int32 count = 2;
}
EOF
	# Baseline descriptor set from the original module.
	( cd "$work/proto" && buf build -o "$work/baseline.binpb" )

	# Sanity: the UNCHANGED module must pass `buf breaking` (gate not stuck on).
	if ! ( cd "$work/proto" && buf breaking --against "$work/baseline.binpb" ); then
		echo "SELFTEST FAIL: buf breaking flagged an unchanged module (false positive)."
		return 1
	fi

	# Wire-incompatible edit: delete field 1 and retype field 2 (int32 -> string).
	cat > "$work/proto/scratch/v1/scratch.proto" <<'EOF'
syntax = "proto3";
package scratch.v1;

message Probe {
  string count = 2;
}
EOF
	if ( cd "$work/proto" && buf breaking --against "$work/baseline.binpb" ) >/dev/null 2>&1; then
		echo "SELFTEST FAIL: buf breaking PASSED on a wire-incompatible edit — the gate is not working."
		return 1
	fi
	echo "breaking-gate self-test: buf breaking correctly exits non-zero on an incompatible edit, zero on an unchanged module. PASS."
	return 0
}

run_all() {
	rc=0
	# Order matters: lint -> breaking -> drift -> stray (header of contracts.yml).
	check_lint || rc=1
	check_breaking || rc=1
	check_drift || rc=1
	check_stray || rc=1
	check_selftest || rc=1
	if [ "$rc" -ne 0 ]; then
		echo "PROTO GATES: FAILED" >&2
	else
		echo "PROTO GATES: OK"
	fi
	return "$rc"
}

case "${1:-all}" in
	lint) check_lint ;;
	breaking) check_breaking ;;
	drift) check_drift ;;
	stray) check_stray ;;
	selftest) check_selftest ;;
	all) run_all ;;
	*)
		echo "usage: $0 [lint|breaking|drift|stray|selftest|all]" >&2
		exit 2
		;;
esac
