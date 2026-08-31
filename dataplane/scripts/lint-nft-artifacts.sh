#!/usr/bin/env bash
# NFT artifact contract lints (doc 14 §5; doc 04 §6 D70/D76).
#
# Runs TWO lints over dataplane/artifacts/nft/ via the ds-contracts CLI:
#   1. Mark-discipline (D76 — the Tailscale PR-5606 lesson): fails on a mark
#      literal touching the permanently-unclaimed bits 14–23, an unmasked /
#      full-register mark write, or a raw mark literal not sourced from the
#      ds-contracts constants.
#   2. Composition-order (D70; taskdb 01KTZV3XN / 01KV8YYA7N): over the EFFECTIVE
#      ruleset that emerges when the closure artifacts are priority-merged per
#      hook, fails if a declared terminal verdict (the udp/443 QUIC reject today)
#      is pre-empted by an earlier-priority terminal `drop` on an overlapping
#      selector — the cross-base-chain shadowing defect class.
#
# The lint logic lives in ds-contracts (the constants + the merge model are the
# single source of truth); this script is the CI entry point.
#
# Passes on an empty artifacts dir by design — the rulesets are authored in
# separate tasks and the lint must be green before and after they land.
#
# Run from the dataplane/ workspace root (CI sets working-directory: dataplane).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"  # dataplane/
artifacts_dir="${here}/artifacts/nft"

echo "NFT artifact lints (mark-discipline + composition-order): scanning ${artifacts_dir}"

# Build + run the std-only lint binary from ds-contracts. --locked keeps the
# offline-build invariant; the binary takes the same toolchain as the workspace.
cargo run --quiet --locked --bin ds-nft-mark-lint -- "${artifacts_dir}"
