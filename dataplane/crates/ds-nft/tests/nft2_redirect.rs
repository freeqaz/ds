//! NFT-2 interface-matched transparent redirect — the shape proof (D69, doc 09
//! §3 NFT-2; round2/04 "Frozen vs free" / "Assurance tests").
//!
//! Two halves, both sandbox-runnable with no kernel:
//!
//! 1. **The contract lint has teeth** — synthetic fixtures prove every NFT-2
//!    invariant the [`ds_nft::redirect`] predicate enforces: interface-matched
//!    never source-IP (the doc 06 (c) in-VM-spoofing invariant at the ruleset
//!    layer), a redirect/dnat verdict that is never `dnat to 127.0.0.1`, and
//!    both transports of port 53 covered.
//! 2. **The real NFT-1 artifact satisfies the shape** — the tracked
//!    `dataplane/artifacts/nft/nft-1-bootstrap.nft`, now carrying the NFT-2
//!    redirect rules, passes the lint with zero violations and covers both
//!    transports. This is the golden-file half: a regression here means the
//!    shipped ruleset drifted off the frozen NFT-2 contract.
//!
//! The live-kernel half — that a forged `ip saddr` packet is actually caught by
//! the `iifname` rule — is `tests/nft2_spoofing_netns.rs` (it needs a loadable
//! kernel; this file needs nothing).

use ds_nft::redirect::{
    check_text, covers_both_transports, satisfies_nft2_redirect_shape, ViolationKind,
};
use std::path::PathBuf;

/// The repo path to the NFT-1 artifact carrying the NFT-2 redirect rules.
/// CARGO_MANIFEST_DIR = .../dataplane/crates/ds-nft.
fn nft1_artifact_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // dataplane
    p.push("artifacts");
    p.push("nft");
    p.push("nft-1-bootstrap.nft");
    p
}

// ---- Half 1: the lint has teeth (synthetic fixtures) -----------------------

/// The canonical compliant fragment — the exact shape the NFT-1 artifact's
/// prerouting chain carries.
const COMPLIANT: &str = "\
table inet ds_boundary {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname \"dstap-*\" udp dport 53 redirect to :15353
    iifname \"dstap-*\" tcp dport 53 redirect to :15353
  }
}
";

#[test]
fn positive_iifname_both_transport_redirect_passes() {
    assert!(
        check_text("ds.nft", COMPLIANT).is_empty(),
        "the iifname-anchored both-transport redirect must pass"
    );
    assert!(satisfies_nft2_redirect_shape("ds.nft", COMPLIANT));
    assert!(covers_both_transports("ds.nft", COMPLIANT));
}

/// NEGATIVE: a source-IP-selected redirect — the precise ruleset-layer form of
/// the doc 06 (c) in-VM-spoofing failure. NFT-2 forbids `ip saddr` selection
/// because the VM forges its source address (doc 03 §3).
#[test]
fn negative_source_ip_match_fails() {
    let bad = "ip saddr 10.0.0.5 udp dport 53 redirect to :15353\n";
    let v = check_text("bad.nft", bad);
    assert!(
        v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch),
        "an ip-saddr-selected redirect must be a SourceIpMatch violation: {v:?}"
    );
    assert!(!satisfies_nft2_redirect_shape("bad.nft", bad));
}

/// NEGATIVE: `dnat to 127.0.0.1` — the route_localnet footgun D69 prohibits.
#[test]
fn negative_dnat_to_loopback_fails() {
    let bad = "\
iifname \"dstap-*\" udp dport 53 dnat to 127.0.0.1:15353
iifname \"dstap-*\" tcp dport 53 dnat to 127.0.0.1:15353
";
    let v = check_text("bad.nft", bad);
    assert!(
        v.iter().any(|x| x.kind == ViolationKind::DnatToLoopback),
        "dnat to 127.0.0.1 must be a DnatToLoopback violation: {v:?}"
    );
    assert!(!satisfies_nft2_redirect_shape("bad.nft", bad));
}

/// NEGATIVE: redirecting only one transport leaves the other as a resolver
/// bypass hole (NFT-4 — DNS-over-TCP must not escape).
#[test]
fn negative_single_transport_fails() {
    let udp_only = "iifname \"dstap-*\" udp dport 53 redirect to :15353\n";
    let v = check_text("bad.nft", udp_only);
    assert!(
        v.iter().any(|x| x.kind == ViolationKind::MissingTransport),
        "udp-only port-53 redirect must be a MissingTransport violation: {v:?}"
    );
    assert!(!covers_both_transports("bad.nft", udp_only));
}

/// The lint is a pure function of ruleset text — like the NFT-4 predicate, it
/// has no DNS/session/kernel input, so its verdict is invariant across any
/// imagined runtime context. (The same independence property the quic_reject
/// suite pins, for the redirect side.)
#[test]
fn verdict_is_independent_of_any_runtime_context() {
    let baseline = check_text("ds.nft", COMPLIANT);
    assert!(baseline.is_empty());
    for _imagined_runtime in [
        "no_sessions",
        "1000_sessions",
        "conntrack_full",
        "kernel_6_12",
    ] {
        // The ruleset text is the only input; there is nowhere to pass a runtime
        // context, so the verdict cannot vary with one.
        assert_eq!(check_text("ds.nft", COMPLIANT), baseline);
    }
}

// ---- Half 2: the real artifact satisfies the shape (golden file) -----------

#[test]
fn real_nft1_artifact_satisfies_the_nft2_redirect_shape() {
    let path = nft1_artifact_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {} must succeed: {e}", path.display()));

    let violations = check_text(&path.display().to_string(), &text);
    assert!(
        violations.is_empty(),
        "the shipped NFT-1 artifact must satisfy the NFT-2 redirect shape; \
         violations in {}:\n{:#?}",
        path.display(),
        violations
    );
    assert!(
        covers_both_transports(&path.display().to_string(), &text),
        "the shipped NFT-1 artifact must redirect BOTH udp/53 and tcp/53"
    );
    assert!(
        satisfies_nft2_redirect_shape(&path.display().to_string(), &text),
        "the shipped NFT-1 artifact must satisfy the full NFT-2 redirect shape"
    );
}

/// The artifact must not regress to source-IP selection on the redirect path —
/// asserted directly against the tracked file so a future hand-edit that added
/// an `ip saddr` selector to the redirect chain fails CI here.
#[test]
fn real_nft1_artifact_never_selects_redirect_on_source_ip() {
    let path = nft1_artifact_path();
    let text = std::fs::read_to_string(&path).expect("artifact must be readable");
    let v = check_text(&path.display().to_string(), &text);
    assert!(
        !v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch),
        "the NFT-1 artifact's redirect rules must never match on source IP \
         (doc 03 §3 / doc 06 (c) spoofing): {v:?}"
    );
}
