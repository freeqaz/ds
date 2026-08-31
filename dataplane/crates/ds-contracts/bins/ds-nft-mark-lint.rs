//! `ds-nft-mark-lint` — CLI wrapper around [`ds_contracts::nft_lint`]. CI invokes
//! it via `scripts/lint-nft-artifacts.sh`. It runs TWO lints over the artifacts:
//!
//!  1. The D76 mark-discipline lint (doc 14 §5): per-file, per-rule. Fails on any
//!     mark literal in the unclaimed gap, an unmasked write, or a raw inline mark
//!     value.
//!  2. The composition-order lint (taskdb 01KTZV3XN / 01KV8YYA7N; doc 04 §6 D70):
//!     over the EFFECTIVE ruleset that emerges when all `*.nft` artifacts in the
//!     dir(s) are priority-merged per hook, it asserts each declared terminal
//!     verdict is REACHABLE — i.e. not pre-empted by an earlier-priority terminal
//!     `drop` on an overlapping selector. The shipped instance is the udp/443
//!     QUIC reject (D70: REJECTED, not silently dropped); the predicate is the
//!     general [`ds_contracts::nft_lint::check_terminal_verdict_reachable`] one,
//!     so the same gate catches the NFT-2b / NFT-3 / NFT-5 closure classes once
//!     they layer onto a hook.
//!
//! Usage: `ds-nft-mark-lint <dir> [<dir> ...]` — scans each directory for `*.nft`
//! rulesets. A missing or empty directory is clean (exit 0): the NFT-1 ruleset is
//! authored in a parallel task and the lint must pass on the empty artifacts dir.
//! Exits 1 on any violation, 2 on a usage / IO error.

use ds_contracts::nft_lint::{
    check_terminal_verdict_reachable, Hook, Reachability, TerminalVerdictClaim,
};
use std::path::Path;
use std::process::ExitCode;

/// Read and concatenate every `*.nft` file under each dir (recursively) into one
/// text, so the composition lint sees the EFFECTIVE merged ruleset (the closures
/// ship as separate tables/files). Returns the merged text and the file count.
fn merged_artifacts(dirs: &[String]) -> std::io::Result<(String, usize)> {
    let mut merged = String::new();
    let mut count = 0usize;
    for dir in dirs {
        let root = Path::new(dir);
        if !root.exists() {
            continue;
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d)? {
                let path = entry?.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("nft") {
                    merged.push_str(&std::fs::read_to_string(&path)?);
                    merged.push('\n');
                    count += 1;
                }
            }
        }
    }
    Ok((merged, count))
}

/// Run the composition-order lint over the merged artifacts: the udp/443 QUIC
/// reject (D70) must stay reachable in the priority-merged `forward` hook. Returns
/// the number of composition violations (0 = clean; `ClaimAbsent` is clean too —
/// the QUIC reject is authored in a parallel task and may not be present yet).
fn composition_violations(merged: &str) -> usize {
    let quic_claim = TerminalVerdictClaim {
        hook: Hook::Forward,
        label: "udp/443 QUIC reject (D70; taskdb 01KTZV3XN)",
        claim_selector: &|c: &str| c.contains("dport 443") && c.contains("reject"),
        shadowing_selector: &|c: &str| c.contains("ct state new") && !c.contains("dport"),
    };
    match check_terminal_verdict_reachable(merged, &quic_claim) {
        Reachability::Shadowed(v) => {
            eprintln!(
                "composition-order violation [{}]: a terminal `drop` at priority {} pre-empts the \
                 declared verdict at priority {} (shadowing rule: `{}`) — the verdict never fires \
                 in the effective merged ruleset",
                v.label, v.shadowing_priority, v.claim_priority, v.shadowing_rule
            );
            1
        }
        Reachability::Reachable | Reachability::ClaimAbsent => 0,
    }
}

fn main() -> ExitCode {
    let dirs: Vec<String> = std::env::args().skip(1).collect();
    if dirs.is_empty() {
        eprintln!("usage: ds-nft-mark-lint <dir> [<dir> ...]");
        return ExitCode::from(2);
    }

    // (1) mark-discipline lint, per file.
    let mut total = 0usize;
    for dir in &dirs {
        match ds_contracts::nft_lint::lint_dir(Path::new(dir)) {
            Ok(violations) => {
                for v in &violations {
                    eprintln!(
                        "{}:{}: mark-discipline violation [{:?}]: {}",
                        v.file, v.line, v.kind, v.text
                    );
                }
                total += violations.len();
            }
            Err(e) => {
                eprintln!("ds-nft-mark-lint: error scanning {dir}: {e}");
                return ExitCode::from(2);
            }
        }
    }

    // (2) composition-order lint, over the merged effective ruleset.
    let (merged, file_count) = match merged_artifacts(&dirs) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ds-nft-mark-lint: error reading artifacts for composition lint: {e}");
            return ExitCode::from(2);
        }
    };
    total += composition_violations(&merged);

    if total == 0 {
        println!(
            "ds-nft-mark-lint: OK ({} dir(s), {file_count} ruleset(s); mark-discipline + \
             composition-order clean)",
            dirs.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("ds-nft-mark-lint: FAILED ({total} violation(s))");
        ExitCode::FAILURE
    }
}
