//! NFT-4 udp/443 QUIC reject — the companion proof that doc 11 §3.3 suppression
//! and the NFT-4 reject are **two independent controls** (D70; doc 11 §3.3's
//! "two independent tests, never merged"; doc 14 §10).
//!
//! Deliberately structurally separate from the §3.3 suppression tests (which
//! live in `ds-dnsgate`): this proof imports NOTHING from the dnsgate /
//! suppression side, so the independence is a property of the dependency graph,
//! not just an assertion. It exercises the reject side's three invariants —
//! reject-not-drop, per-session counting, and the [`RejectReason::QuicBlocked`]
//! vs [`RejectReason::DefaultDeny`] distinctness — entirely against synthetic
//! ruleset-text fixtures. No live nft, no live DNS (the NFT-1 bootstrap artifact
//! is scope-fenced default-deny and is NOT this rule).

use ds_contracts::reject::RejectReason;
use ds_nft::quic_reject::{check_text, satisfies_quic_reject_shape, ViolationKind};

/// The compliant fixture — the exact shape the future NFT-4 udp/443 rule (the
/// Stage-2 reject, doc 14 §10 row 3) must satisfy: `reject with icmpx type
/// port-unreachable`, plus a `counter`.
const COMPLIANT_RULESET: &str = "\
table inet ds_filter {
  chain egress {
    type filter hook forward priority 0; policy drop;
    # NFT-4: the sole control for non-cooperative QUIC clients (doc 14 §10).
    udp dport 443 counter reject with icmpx type port-unreachable
  }
}
";

/// POSITIVE: reject + counter passes.
#[test]
fn positive_reject_with_counter_passes() {
    assert!(
        check_text("ds.nft", COMPLIANT_RULESET).is_empty(),
        "the reject (icmpx port-unreachable) + per-session counter shape must pass"
    );
    assert!(
        satisfies_quic_reject_shape("ds.nft", COMPLIANT_RULESET),
        "the compliant ruleset must satisfy the udp/443 reject shape"
    );
}

/// NEGATIVE: a silent drop fails reject-not-drop. This is the precise regression
/// D70 amended away ("dropped" → "rejected (icmp port-unreachable) + counted").
#[test]
fn negative_silent_drop_fails() {
    let silent_drop = "udp dport 443 counter drop\n";
    let v = check_text("bad.nft", silent_drop);
    assert!(
        v.iter().any(|x| x.kind == ViolationKind::SilentDrop),
        "a silent drop must be a SilentDrop violation: {v:?}"
    );
    assert!(
        !satisfies_quic_reject_shape("bad.nft", silent_drop),
        "a silent-drop ruleset must not satisfy the shape"
    );
}

/// NEGATIVE: a reject with no counter fails per-session counting.
#[test]
fn negative_missing_counter_fails() {
    let no_counter = "udp dport 443 reject with icmpx type port-unreachable\n";
    let v = check_text("bad.nft", no_counter);
    assert!(
        v.iter().any(|x| x.kind == ViolationKind::MissingCounter),
        "a reject with no counter must be a MissingCounter violation: {v:?}"
    );
    assert!(
        !satisfies_quic_reject_shape("bad.nft", no_counter),
        "a counterless reject must not satisfy the shape"
    );
}

/// INDEPENDENCE: the predicate's verdict is a pure function of ruleset text and
/// has NO input from DNS / suppression / steering state. We prove it the only
/// way a property like this can be proven: by feeding the SAME ruleset text
/// while every "DNS outcome" varies, and asserting the verdict is invariant.
///
/// A client that ignores DNS-4 rule 4 steering (the §3.3 suppression NODATA)
/// still hits this reject — so the reject's verdict cannot depend on whether the
/// client was steered. The function signature itself carries no DNS/suppression
/// parameter; this test pins that the verdict therefore stays fixed across all
/// imagined steering outcomes.
#[test]
fn verdict_is_independent_of_any_dns_or_suppression_state() {
    // A stand-in for "whatever DNS did": cooperative-steered, ignored-steering,
    // AAAA stripped, HTTPS(65) suppressed, no DNS at all. None of these are
    // inputs to check_text — there is nowhere to pass them — and the verdict on
    // a fixed ruleset must be identical for all of them.
    let imagined_dns_outcomes = [
        "client_was_steered_cooperatively",
        "client_ignored_steering_and_used_raw_quic",
        "aaaa_stripped",
        "https65_suppressed",
        "no_dns_query_at_all",
    ];

    let baseline = check_text("ds.nft", COMPLIANT_RULESET);
    assert!(baseline.is_empty(), "compliant baseline must pass");

    for outcome in imagined_dns_outcomes {
        // The ruleset text is the ONLY input; the DNS outcome string is, by
        // construction, never consulted by the predicate.
        let verdict = check_text("ds.nft", COMPLIANT_RULESET);
        assert_eq!(
            verdict, baseline,
            "verdict must not vary with DNS/suppression outcome {outcome:?}"
        );
        assert!(
            satisfies_quic_reject_shape("ds.nft", COMPLIANT_RULESET),
            "the reject holds regardless of the DNS steering outcome {outcome:?}"
        );
    }

    // And the negative case is equally DNS-independent: a silent drop fails no
    // matter what the (absent) DNS input would have been.
    let bad = "udp dport 443 counter drop\n";
    for outcome in imagined_dns_outcomes {
        assert!(
            !satisfies_quic_reject_shape("bad.nft", bad),
            "a silent drop fails regardless of DNS outcome {outcome:?}"
        );
    }
}

/// DISTINCTNESS: the reason code this on-box reject feeds is `QuicBlocked`, and
/// `QuicBlocked` is a frozen-distinct reason from generic `DefaultDeny` (D70) —
/// so QUIC-reject volume is countable per session without conflating it with
/// everything else the default-deny posture drops. This is the off-box half of
/// the same control whose on-box shape the predicate above enforces.
#[test]
fn quic_blocked_is_distinct_from_default_deny() {
    assert_ne!(
        RejectReason::QuicBlocked,
        RejectReason::DefaultDeny,
        "QuicBlocked must stay distinct from DefaultDeny (D70)"
    );
    assert!(
        RejectReason::QuicBlocked.is_quic_carveout(),
        "QuicBlocked is the flip-to-inspect carveout"
    );
    assert!(
        !RejectReason::DefaultDeny.is_quic_carveout(),
        "DefaultDeny is NOT the QUIC carveout"
    );

    // The predicate's violation kinds all map to the QuicBlocked reason — the
    // on-box shape and the off-box reason are the same control.
    for kind in [
        ViolationKind::SilentDrop,
        ViolationKind::NotPortUnreachable,
        ViolationKind::MissingCounter,
    ] {
        assert_eq!(
            kind.reject_reason(),
            RejectReason::QuicBlocked,
            "every udp/443 reject-shape violation feeds the QuicBlocked reason"
        );
        assert_ne!(
            kind.reject_reason(),
            RejectReason::DefaultDeny,
            "the udp/443 reject is never the generic default-deny reason"
        );
    }
}
