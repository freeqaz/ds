#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# check-nft-mark-constants.sh — the doc 14 §11 mark-constant lint of the NFT-1
# bootstrap ruleset, wired into `make repo-lints` (the standing land gate).
#
# WHAT IT ASSERTS (doc 14 §11 / §5, D76). The NFT-1 bootstrap ruleset
# (dataplane/artifacts/nft/nft-1-bootstrap.nft) is MARK-FREE BY DESIGN: "NFT-1
# needs NO marks at all. No packet-mark or conntrack-mark expression and no mark
# literal appears anywhere in this file by design" (the file's own MARKS header).
# The composite ct-mark machinery arrives later with NFT-5 at Stage 1, sourced
# ONLY from ds-contracts constants — never authored in the floor. This lint
# mechanizes that invariant: any mark WRITE or MATCH expression in an effective
# (non-comment) line of the bootstrap ruleset is a FAILURE, so a mark literal
# that violates the D76 bit-field discipline can never be introduced here without
# going through NFT-5 + ds-contracts.
#
# RELATIONSHIP TO THE RUST LINT. dataplane/scripts/lint-nft-artifacts.sh runs the
# ds-contracts `ds-nft-mark-lint` binary over the WHOLE artifacts/nft dir for the
# full D76 bit-discipline + D70 composition-order model (cargo-dependent, runs in
# the rust-dataplane / ci workflows). This shell lint is its cargo-free twin for
# repo-lints: a precise, static assertion that the FLOOR stays mark-free, so the
# land gate catches a mark introduced into nft-1-bootstrap.nft even on a checkout
# with no Rust toolchain. Additive — it neither replaces nor weakens the Rust lint.
#
# SKIP path: if the bootstrap ruleset is absent this is a LOUD clean SKIP (exit 0,
# reason on stderr) so a pre-artifact branch stays green. DS_REQUIRE_NFT_MARK_LINT=1
# flips the skip into a FAIL (exit 1) so a gate leg that expects the artifact
# present asserts the lint actually ran — the DS_REQUIRE_* precedent.
#
# --self-test: prove the gate is non-vacuous (a clean ruleset PASSES, a ruleset
# with a planted mark expression FAILS) in a temp dir. House precedent:
# check-fixture-provenance.sh / check-runbook-nft.sh ship the same in-script proof.

set -eu

# --- locate the repo root (works from CI checkout or a manual run) ----------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
	:
else
	ROOT=$(cd "$(dirname "$0")/.." && pwd)
fi

RULESET_REL="dataplane/artifacts/nft/nft-1-bootstrap.nft"

# scan_ruleset FILE — exit 0 if the effective (comment-stripped) ruleset contains
# no mark write/match expression, non-zero (printing offenders) otherwise.
scan_ruleset() {
	_file=$1
	# Strip full-line and inline comments, then look for nftables mark expressions:
	#   *mark set*     — a packet-mark / ct-mark / meta-mark WRITE
	#   ct mark        — a conntrack-mark match or write
	#   meta mark      — a packet-mark match
	#   secmark / connsecmark — SELinux mark expressions (also forbidden in the floor)
	# The pattern is intentionally broad: the floor authors NO mark of any kind.
	_hits=$(sed 's/#.*$//' "$_file" \
		| grep -nE '(^|[[:space:]])(ct[[:space:]]+mark|meta[[:space:]]+mark|mark[[:space:]]+set|secmark|connsecmark)([[:space:]]|$)' \
		|| true)
	if [ -n "$_hits" ]; then
		echo "NFT-MARK-LINT FAIL: ${_file} authors a mark expression (the NFT-1 floor is mark-free by design; D76 — marks arrive with NFT-5 from ds-contracts):" >&2
		printf '%s\n' "$_hits" >&2
		return 1
	fi
	return 0
}

# --- Self-test mode: one positive + one negative case, in a temp dir --------
if [ "${1:-}" = "--self-test" ]; then
	T=$(mktemp -d)
	trap 'rm -rf "$T"' EXIT

	# Case 1: a clean, mark-free ruleset PASSES.
	cat > "$T/clean.nft" <<-'EOF'
		table inet ds_boundary {
			chain forward {
				type filter hook forward priority filter; policy drop;
				# a comment mentioning mark discipline must not trip the scan
				iifname "dstap-*" ct state new drop
			}
		}
	EOF
	if ! scan_ruleset "$T/clean.nft" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: a mark-free ruleset should PASS" >&2
		exit 1
	fi
	echo "SELF-TEST OK (pass): mark-free ruleset"

	# Case 2: a ruleset with a planted mark write FAILS.
	cat > "$T/marked.nft" <<-'EOF'
		table inet ds_boundary {
			chain forward {
				type filter hook forward priority filter; policy drop;
				iifname "dstap-*" ct mark set 0x000d0001
			}
		}
	EOF
	if scan_ruleset "$T/marked.nft" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: a ruleset authoring a ct-mark write should FAIL" >&2
		exit 1
	fi
	echo "SELF-TEST OK (non-zero): planted ct-mark write"

	echo "Gate self-test: both cases confirmed non-vacuous"
	exit 0
fi

# --- Normal operation -------------------------------------------------------
ruleset="$ROOT/$RULESET_REL"
if [ ! -f "$ruleset" ]; then
	if [ "${DS_REQUIRE_NFT_MARK_LINT:-}" = "1" ]; then
		echo "check-nft-mark-constants: FAIL — $RULESET_REL absent but DS_REQUIRE_NFT_MARK_LINT=1" >&2
		exit 1
	fi
	echo "check-nft-mark-constants: SKIP — $RULESET_REL not present (pre-artifact branch)" >&2
	exit 0
fi

echo "check-nft-mark-constants: scanning $RULESET_REL for mark expressions (must be mark-free; D76)"
if scan_ruleset "$ruleset"; then
	echo "check-nft-mark-constants: OK — NFT-1 bootstrap ruleset is mark-free"
	exit 0
fi
exit 1
