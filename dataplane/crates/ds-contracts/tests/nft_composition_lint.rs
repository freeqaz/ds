//! Integration test: the composition-order lint over the EFFECTIVE (priority-
//! merged) boundary ruleset — the cross-base-chain terminal-verdict-reachability
//! check (taskdb 01KTZV3XNB / 01KV8YYA7N; doc 04 §6 D70, doc 14 §5).
//!
//! The boundary closures each ship their OWN `inet` table with a base chain on a
//! hook at a DISTINCT priority; nftables runs them in ascending priority and a
//! `drop` is TERMINAL across chains. So a closure's declared terminal verdict,
//! authored in a later-priority chain, is SILENTLY pre-empted if an earlier-
//! priority chain already terminally `drop`s an overlapping selector. The per-
//! rule shape lints cannot see this (each rule is individually compliant); the
//! gap is the cross-base-chain ORDER.
//!
//! This suite proves the general
//! [`ds_contracts::nft_lint::check_terminal_verdict_reachable`] predicate:
//!  * POSITIVE — the already-fixed QUIC case over the REAL merged NFT-1 + NFT-4
//!    artifacts must stay `Reachable` (the D70 / 01KTZV3XN regression guard);
//!  * NEGATIVE — a synthetic fixture for EACH closure class named in the task
//!    body (NFT-2b 80/443 redirect, NFT-3 allow-sets, NFT-5 ct-mark) where the
//!    declared verdict is authored behind an earlier-priority terminal drop must
//!    be caught as `Shadowed`.

use ds_contracts::nft_lint::{
    check_terminal_verdict_reachable, Hook, Reachability, TerminalVerdictClaim,
};
use std::path::PathBuf;

/// The repo-relative path from this crate to a shipped nft artifact.
/// CARGO_MANIFEST_DIR = .../dataplane/crates/ds-contracts.
fn artifact(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // dataplane
    p.push("artifacts");
    p.push("nft");
    p.push(name);
    p
}

fn read_artifact(name: &str) -> String {
    let p = artifact(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The QUIC claim the `ds-nft` quic_reject module also constructs (the udp/443
/// reject must survive the forward-hook merge): a `dport 443` `reject` that must
/// not be pre-empted by the floor's catch-all `ct state new drop`.
fn udp443_quic_claim<'a>() -> TerminalVerdictClaim<'a> {
    TerminalVerdictClaim {
        hook: Hook::Forward,
        label: "udp/443 QUIC reject (D70)",
        claim_selector: &|c: &str| c.contains("dport 443") && c.contains("reject"),
        // The floor's terminal `ct state new drop` catch-all (no `dport`) overlaps
        // any new udp/443 — the shadowing terminal.
        shadowing_selector: &|c: &str| c.contains("ct state new") && !c.contains("dport"),
    }
}

/// POSITIVE: the EFFECTIVE merged NFT-1 + NFT-4 ruleset keeps the udp/443 QUIC
/// reject reachable. The floor (NFT-1, forward priority 0) carries the live
/// reject BEFORE its terminal `ct state new drop`, so the merge never shadows it
/// — the 01KTZV3XN / D70 regression guard against the SHIPPED artifacts.
#[test]
fn merged_nft1_nft4_keeps_quic_reject_reachable() {
    let merged = format!(
        "{}\n{}",
        read_artifact("nft-1-bootstrap.nft"),
        read_artifact("nft-4-resolver-closure.nft")
    );
    let verdict = check_terminal_verdict_reachable(&merged, &udp443_quic_claim());
    assert_eq!(
        verdict,
        Reachability::Reachable,
        "the effective merged NFT-1+NFT-4 forward hook must keep udp/443 reject reachable; got {verdict:?}"
    );
}

/// POSITIVE: NFT-1 alone (the floor that owns the live reject) is reachable —
/// the reject precedes the floor's own terminal drop in the priority-0 chain.
#[test]
fn shipped_nft1_floor_forward_merge_is_reachable() {
    let text = read_artifact("nft-1-bootstrap.nft");
    assert_eq!(
        check_terminal_verdict_reachable(&text, &udp443_quic_claim()),
        Reachability::Reachable
    );
}

/// NEGATIVE (the 01KTZV3XN defect, reconstructed): if the floor did NOT carry the
/// reject and the closure authored it ONLY in its later-priority (1) forward
/// chain, the floor's priority-0 `ct state new drop` shadows it — caught.
#[test]
fn quic_reject_only_in_later_priority_chain_is_shadowed() {
    let shadowed = "\
table inet ds_boundary {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    iifname \"dstap-*\" ct state new drop
  }
}
table inet ds_resolver_closure {
  chain resolver_closure_forward {
    type filter hook forward priority 1; policy accept;
    iifname \"dstap-*\" ct state new udp dport 443 counter reject with icmpx type port-unreachable
  }
}
";
    match check_terminal_verdict_reachable(shadowed, &udp443_quic_claim()) {
        Reachability::Shadowed(v) => {
            assert_eq!(v.shadowing_priority, 0, "the floor drop is priority 0");
            assert_eq!(
                v.claim_priority, 1,
                "the reject is in the priority-1 closure"
            );
        }
        other => panic!("the 01KTZV3XN shadowing must be caught; got {other:?}"),
    }
}

/// NEGATIVE — NFT-2b 80/443 redirect class. The transparent-redirect cutover
/// (tcp/80 → ds-tlsproxy) authored at a LATER prerouting priority, behind an
/// earlier catch-all `iifname dstap-* drop` on the same prerouting hook, is
/// shadowed: the redirect never fires and the flow is silently dropped.
#[test]
fn nft2b_redirect_behind_an_earlier_drop_is_shadowed() {
    let claim = TerminalVerdictClaim {
        hook: Hook::Prerouting,
        label: "NFT-2b tcp/80 transparent redirect",
        claim_selector: &|c: &str| c.contains("dport 80") && c.contains("redirect"),
        shadowing_selector: &|c: &str| c.contains("iifname") && !c.contains("dport"),
    };
    let shadowed = "\
table inet ds_floor {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname \"dstap-*\" drop
  }
}
table inet ds_tlsproxy_redirect {
  chain prerouting {
    type nat hook prerouting priority dstnat + 1; policy accept;
    iifname \"dstap-0\" tcp dport 80 redirect to :18080
  }
}
";
    assert!(
        matches!(
            check_terminal_verdict_reachable(shadowed, &claim),
            Reachability::Shadowed(_)
        ),
        "an NFT-2b redirect behind an earlier-priority terminal drop must be Shadowed"
    );
    // The shipped NFT-2b spike (its own dsspike table, no preceding drop on the
    // hook) keeps the redirect reachable — never Shadowed.
    let spike = read_artifact("nft-2b-spike.nft");
    assert!(
        !matches!(
            check_terminal_verdict_reachable(&spike, &claim),
            Reachability::Shadowed(_)
        ),
        "the shipped NFT-2b spike redirect must not be shadowed"
    );
}

/// NEGATIVE — NFT-3 per-session allow-set class. The OUTPUT-chain accept that
/// admits a proxy connect to an allow-set IP, authored at a LATER output priority
/// behind an earlier catch-all proxy-uid `drop`, is shadowed: admitted egress is
/// silently dropped. (The allow-set verdict is an `accept`, but it is the
/// DECLARED authoritative verdict for an admitted flow — its reachability is what
/// matters, and a terminal `drop` ahead of it on the hook pre-empts it.)
#[test]
fn nft3_allow_set_accept_behind_an_earlier_drop_is_shadowed() {
    let claim = TerminalVerdictClaim {
        hook: Hook::Output,
        label: "NFT-3 per-session allow-set accept",
        claim_selector: &|c: &str| c.contains("@allow4_") && c.contains("accept"),
        shadowing_selector: &|c: &str| c.contains("skuid") && !c.contains("@allow4_"),
    };
    let shadowed = "\
table inet ds_floor {
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid 1000 drop
  }
}
table inet ds_proxy_out {
  chain proxy_output {
    type filter hook output priority filter + 1; policy accept;
    ip daddr @allow4_0 accept
  }
}
";
    assert!(
        matches!(
            check_terminal_verdict_reachable(shadowed, &claim),
            Reachability::Shadowed(_)
        ),
        "an NFT-3 allow-set accept behind an earlier-priority terminal drop must be Shadowed"
    );
}

/// NEGATIVE — NFT-5 ct-mark accounting class. The ct-mark-keyed per-session admit
/// (a `meta mark ... vmap @session_out` dispatch / accept), authored at a LATER
/// output priority behind an earlier catch-all `drop`, is shadowed: the marked
/// flow is dropped before its session chain runs.
#[test]
fn nft5_ct_mark_dispatch_behind_an_earlier_drop_is_shadowed() {
    let claim = TerminalVerdictClaim {
        hook: Hook::Output,
        label: "NFT-5 ct-mark per-session dispatch",
        claim_selector: &|c: &str| c.contains("mark") && c.contains("vmap"),
        shadowing_selector: &|c: &str| c.contains("drop") && !c.contains("mark"),
    };
    let shadowed = "\
table inet ds_floor {
  chain output {
    type filter hook output priority filter; policy accept;
    iifname \"dstap-*\" drop
  }
}
table inet ds_proxy_out {
  chain proxy_output {
    type filter hook output priority filter + 1; policy accept;
    meta mark & 0xFF003FFF vmap @session_out
  }
}
";
    assert!(
        matches!(
            check_terminal_verdict_reachable(shadowed, &claim),
            Reachability::Shadowed(_)
        ),
        "an NFT-5 ct-mark dispatch behind an earlier-priority terminal drop must be Shadowed"
    );
    // The same dispatch placed at an EARLIER priority than the drop is reachable.
    let reachable = "\
table inet ds_proxy_out {
  chain proxy_output {
    type filter hook output priority filter; policy accept;
    meta mark & 0xFF003FFF vmap @session_out
  }
}
table inet ds_floor {
  chain output {
    type filter hook output priority filter + 1; policy accept;
    iifname \"dstap-*\" drop
  }
}
";
    assert_eq!(
        check_terminal_verdict_reachable(reachable, &claim),
        Reachability::Reachable,
        "an NFT-5 dispatch ahead of the drop must be reachable"
    );
}
