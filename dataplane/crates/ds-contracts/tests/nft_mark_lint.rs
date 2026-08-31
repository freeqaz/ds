//! Integration test: the NFT-1 mark-discipline lint over the real
//! `dataplane/artifacts/nft/` directory (doc 14 §5, D76).
//!
//! The lint must pass on whatever ruleset artifacts exist right now — an empty
//! directory at skeleton time, or the NFT-1 ruleset once the parallel task
//! (01KTWJ3GMGG79QK4H364FPJQAQ) lands it. It scans every `*.nft` file present.
//!
//! The negative case (a line using mark bits 14–23 makes the lint FAIL) is
//! asserted here too, so the gate's teeth are proven in the same suite, against
//! a fixture rather than the tracked artifacts dir.

use ds_contracts::mark::DS_MARK_MASK;
use ds_contracts::nft_lint::{lint_dir, lint_text, ViolationKind};
use std::path::PathBuf;

/// The repo-relative path from this crate to the NFT-1 artifacts directory.
fn artifacts_nft_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../dataplane/crates/ds-contracts
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // dataplane
    p.push("artifacts");
    p.push("nft");
    p
}

#[test]
fn real_nft_artifacts_dir_passes_the_lint() {
    let dir = artifacts_nft_dir();
    let violations = lint_dir(&dir).expect("walking the artifacts dir must not error");
    assert!(
        violations.is_empty(),
        "NFT-1 mark-discipline lint found violations in {}:\n{:#?}",
        dir.display(),
        violations
    );
}

#[test]
fn the_lint_has_teeth_bits_14_to_23_fail() {
    // The brief's required negative fixture: a deliberate line using mark bits
    // 14–23 must make the lint fail. Bit 18 is squarely in the unclaimed gap.
    let mask = format!("0x{DS_MARK_MASK:X}");
    let bad = 0xD000_0000u32 | (1u32 << 18);
    let fixture = format!("ct mark set (ct mark & ~{mask}) | 0x{bad:X}\n");
    let violations = lint_text("negative-fixture.nft", &fixture);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v.kind, ViolationKind::UnclaimedBits { .. })),
        "the lint must fail on a bits-14–23 mark literal; got {violations:?}"
    );
}
