//! NFT-4 port-853 DNS-over-TLS (DoT) drop-rule-shape predicate (doc 09 §3 NFT-4,
//! D42/D69; doc 03 §3 in-VM-spoofing).
//!
//! This is the **DoT leg** of the resolver-bypass-closure controls (the other two
//! being the [`crate::redirect`] port-53 interface-match and the
//! [`crate::quic_reject`] udp/443 reject-not-drop). DNS-over-TLS on port 853 must
//! be **dropped on both transports** so a client cannot tunnel resolution past
//! ds-dnsgate inside TLS (doc 09 §3 NFT-4). Each DoT drop is a *session-scoped*
//! control, so — exactly like the QUIC reject and the port-53 redirect — it MUST
//! key on the **unforgeable `iifname`** (the `dstap-*` attachment point the
//! session is bound to), and MUST NEVER consult the **forgeable `ip saddr`** the
//! in-VM agent can spoof (doc 03 §3, the doc 06 (c) in-VM-spoofing invariant,
//! D44/D69).
//!
//! This is the **Rust mirror** of the Go conformance-adapter sentinel
//! `ErrDoTNotInterfaceAnchored` (`assurance/conformance-adapter/resolverlock/
//! nft4_closure.go`). The Go offline driver reads the SAME shipped NFT-4 artifact
//! and asserts the DoT 853 drop rules are iifname-anchored on `dstap-*`, never
//! source-IP; this predicate is the executable shape with TEETH against synthetic
//! fixtures on the Rust side, completing the **per-control anchoring trilogy**
//! (port-53 redirect, udp/443 QUIC reject, DoT 853 drop): a future ruleset edit
//! could drop `iifname` on JUST a 853 rule (or add an `ip saddr` match to it)
//! without tripping the port-53 or QUIC sentinels, so DoT anchoring is asserted in
//! its own right.
//!
//! This is a **contract lint, not an nft parser** — the same pure-`std` text
//! analysis the [`crate::quic_reject`] and [`crate::redirect`] lints use
//! (comment-stripped, lowercased, word-boundary token tests). It is validated
//! against synthetic fixtures, never the live artifact; no live nft, no live DNS.

/// A port-853 (DoT) drop-rule-shape violation found by the predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The file/source the violation was found in (as passed to the predicate).
    pub file: String,
    /// 1-based line number of the offending port-853 rule.
    pub line: usize,
    /// The offending source line, trimmed.
    pub text: String,
    /// What invariant was broken.
    pub kind: ViolationKind,
}

/// The category of a port-853 DoT drop-rule-shape violation (doc 09 §3 NFT-4,
/// D42/D69).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// The port-853 drop rule is not anchored on the unforgeable `iifname`
    /// (`dstap-*`) attachment point — or worse, matches the forgeable `ip saddr`.
    /// This is the Rust mirror of the Go `ErrDoTNotInterfaceAnchored` sentinel: a
    /// session-scoped control MUST key on the interface the session is bound to,
    /// never on a source IP the in-VM agent can spoof (doc 03 §3, doc 06 (c)
    /// in-VM-spoofing, D44/D69).
    NotInterfaceAnchored,
    /// The port-853 rule does not `drop` — DoT must be dropped so it cannot
    /// tunnel resolution past ds-dnsgate inside TLS (doc 09 §3 NFT-4). An `accept`
    /// (or any non-drop verdict) on a 853 rule is the exact failure this control
    /// forbids.
    NotDropped,
}

/// Whether a (comment-stripped, lowercased) line is a port-853 (DoT) rule — a
/// `dport 853` selector. We isolate the `853` as a whole token (split on any
/// non-alphanumeric byte) so `dport 8530` or an address octet never matches —
/// the same token boundary the Go `isPort853Rule` and the [`crate::quic_reject`]
/// lint use.
fn is_port_853_rule(code_lc: &str) -> bool {
    has_word(code_lc, "dport") && has_word(code_lc, "853")
}

/// Whether `word` appears as a whole token in `code_lc` (split on any
/// non-alphanumeric byte) — the same token-boundary idiom the QUIC/redirect lints
/// and the Go `hasWord` use, so `853` does not match inside `8530` and `drop`
/// does not match inside `dropper`.
fn has_word(code_lc: &str, word: &str) -> bool {
    code_lc
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == word)
}

/// Whether the rule matches on the forgeable `ip saddr` / `ip6 saddr` — the
/// source the rules must NEVER consult (doc 03 §3). Mirror of the Go
/// `matchesSourceIP`.
fn matches_source_ip(code_lc: &str) -> bool {
    code_lc.contains("ip saddr") || code_lc.contains("ip6 saddr")
}

/// Whether a (comment-stripped, lowercased) line anchors its `iifname` match on
/// the session-scoped `dstap-` interface pattern — the D50/D66 interface-naming
/// contract. Anchoring on the `iifname` KEYWORD alone is too weak: a rule could
/// read `iifname "eth0"` (or any non-session interface) and still satisfy a bare
/// presence check, yet it would NOT be scoped to the session's dstap-prefixed tap.
///
/// This is the operand-level companion to [`matches_source_ip`]: where that
/// rejects the forgeable source, this requires the interface operand be the
/// unforgeable session attachment point. It is the exact mirror of the Go
/// `anchorsOnDstapGlob`, accepting every spelling nft tolerates:
///   - `iifname "dstap-*"`       — the shipped/quoted glob form
///   - `iifname "dstap-abc12"`   — a concrete per-session interface name
///   - `iifname dstap-*`         — the unquoted form nft also tolerates
///   - `iifname { "dstap-..." }` — an anonymous set of dstap interfaces
///
/// The operand is normalised by trimming the surrounding nft punctuation (quotes,
/// set braces, a leading comma) before the `dstap-` prefix test, so the check keys
/// on the interface NAME, not the syntactic wrapping. Returns false when no
/// `iifname` token is present or its operand is not dstap-prefixed (e.g. `eth0`).
fn anchors_on_dstap(code_lc: &str) -> bool {
    let fields: Vec<&str> = code_lc.split_whitespace().collect();
    for (i, f) in fields.iter().enumerate() {
        if *f != "iifname" {
            continue;
        }
        let Some(next) = fields.get(i + 1) else {
            continue;
        };
        // The interface operand is the next field. For the `{` set form nft
        // tokenises the brace as its own field, so the name is the field after it.
        let mut operand = trim_nft_punct(next);
        if operand.is_empty() {
            if let Some(after_brace) = fields.get(i + 2) {
                operand = trim_nft_punct(after_brace);
            }
        }
        if operand.starts_with("dstap-") {
            return true;
        }
    }
    false
}

/// Trim the surrounding nft punctuation (quotes, set braces, a leading comma)
/// from an interface operand so the `dstap-` prefix test keys on the interface
/// NAME, not the syntactic wrapping. Mirror of the Go `anchorsOnDstapGlob`
/// `strings.Trim(..., "\"{},")`.
fn trim_nft_punct(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '{' || c == '}' || c == ',')
}

/// Whether the rule carries a `drop` verdict.
fn has_drop(code_lc: &str) -> bool {
    has_word(code_lc, "drop")
}

/// Strip a trailing `#`-comment from an nft line, returning the code part (same as
/// the [`crate::quic_reject`]/[`crate::redirect`] lints' `strip_comment`).
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Check a single ruleset's text for the port-853 DoT drop-rule shape. `file` is
/// used only for reporting. Returns every violation found on every port-853 rule
/// line (empty = the port-853 rule(s), if any, are compliant).
///
/// This is a pure function of the ruleset text alone — it reads no DNS state and
/// no live kernel, by construction. The anchoring check is asserted FIRST (and the
/// drop check only after), mirroring the Go driver's order: an unanchored or
/// source-IP-matched rule is the spoofing failure regardless of its verdict.
pub fn check_text(file: &str, text: &str) -> Vec<Violation> {
    let mut violations = Vec::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let code = strip_comment(raw_line);
        let code_lc = code.to_ascii_lowercase();
        if !is_port_853_rule(&code_lc) {
            continue;
        }

        let push = |violations: &mut Vec<Violation>, kind: ViolationKind| {
            violations.push(Violation {
                file: file.to_string(),
                line: line_no,
                text: code.trim().to_string(),
                kind,
            });
        };

        // Invariant 1: iifname-anchored on the session tap, never source-IP. The
        // Rust mirror of ErrDoTNotInterfaceAnchored: a 853 rule that matches the
        // forgeable `ip saddr`, OR lacks `iifname`, OR anchors on a non-dstap
        // interface (e.g. "eth0") is NOT scoped to the unforgeable session tap.
        if matches_source_ip(&code_lc) || !anchors_on_dstap(&code_lc) {
            push(&mut violations, ViolationKind::NotInterfaceAnchored);
        }

        // Invariant 2: DoT must be dropped. A 853 rule that does not `drop`
        // (e.g. a stray `accept`) would let DoT tunnel resolution past ds-dnsgate.
        if !has_drop(&code_lc) {
            push(&mut violations, ViolationKind::NotDropped);
        }
    }

    violations
}

/// Whether `text` contains a **compliant DoT-853 drop on BOTH transports**: at
/// least one udp/853 rule AND at least one tcp/853 rule are present, AND no
/// port-853 rule has any violation. Convenience wrapper for callers that only need
/// a yes/no; the future NFT-4 ruleset must make this return `true`.
///
/// Both transports are required because DoT runs over either; dropping only one
/// leg leaves the other open (the Go driver's `sawDoTUDP && sawDoTTCP` gate).
pub fn satisfies_dot_drop_shape(file: &str, text: &str) -> bool {
    let mut saw_udp = false;
    let mut saw_tcp = false;
    for l in text.lines() {
        let code_lc = strip_comment(l).to_ascii_lowercase();
        if !is_port_853_rule(&code_lc) {
            continue;
        }
        if has_word(&code_lc, "udp") {
            saw_udp = true;
        }
        if has_word(&code_lc, "tcp") {
            saw_tcp = true;
        }
    }
    saw_udp && saw_tcp && check_text(file, text).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical compliant ruleset — the shape the future NFT-4 DoT rules must
    /// emit: both transports' 853 dropped, iifname-anchored on the dstap-* tap,
    /// counter+log for observability (the shipped artifact's wording).
    const COMPLIANT: &str = "table inet ds_filter {\n  \
        chain prerouting {\n    \
        iifname \"dstap-*\" udp dport 853 counter log prefix \"ds-nft4 dot-drop \" group 4 drop\n    \
        iifname \"dstap-*\" tcp dport 853 counter log prefix \"ds-nft4 dot-drop \" group 4 drop\n  \
        }\n}\n";

    #[test]
    fn compliant_both_transport_drop_has_no_violations() {
        assert!(
            check_text("ds.nft", COMPLIANT).is_empty(),
            "the iifname-anchored both-transport DoT drop must pass"
        );
        assert!(satisfies_dot_drop_shape("ds.nft", COMPLIANT));
    }

    #[test]
    fn unanchored_drop_is_not_interface_anchored() {
        // A 853 drop with NO iifname selector — matches every interface, not the
        // session tap. The Rust mirror of the Go ErrDoTNotInterfaceAnchored case
        // "drop rule drops the unforgeable iifname anchor".
        let bad = "udp dport 853 counter log prefix \"ds-nft4 dot-drop \" group 4 drop\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter()
                .any(|x| x.kind == ViolationKind::NotInterfaceAnchored),
            "an unanchored 853 drop must be NotInterfaceAnchored: {v:?}"
        );
        assert!(!satisfies_dot_drop_shape("bad.nft", bad));
    }

    #[test]
    fn source_ip_matched_853_is_not_interface_anchored() {
        // A 853 drop that keys on the FORGEABLE `ip saddr` instead of the
        // unforgeable iifname — the exact spoofing failure D44/D69 forbid. Mirror
        // of the Go "matches the forgeable ip saddr" ErrDoTNotInterfaceAnchored
        // case.
        let bad = "ip saddr 10.0.0.0/8 udp dport 853 counter drop\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter()
                .any(|x| x.kind == ViolationKind::NotInterfaceAnchored),
            "a source-IP-matched 853 drop must be NotInterfaceAnchored: {v:?}"
        );
        assert!(!satisfies_dot_drop_shape("bad.nft", bad));
    }

    #[test]
    fn non_dstap_iifname_is_not_interface_anchored() {
        // A 853 drop anchored on a NON-dstap iifname ("eth0") — present but NOT
        // the session attachment point. A bare `has iifname` presence check would
        // pass this; the operand-level dstap-* check is what bites. Mirror of the
        // Go "anchors on a NON-dstap iifname" case.
        let bad = "iifname \"eth0\" udp dport 853 counter drop\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter()
                .any(|x| x.kind == ViolationKind::NotInterfaceAnchored),
            "a non-dstap iifname 853 drop must be NotInterfaceAnchored: {v:?}"
        );
        assert!(!satisfies_dot_drop_shape("bad.nft", bad));
    }

    #[test]
    fn anchored_853_that_does_not_drop_is_not_dropped() {
        // An iifname-anchored 853 rule that ACCEPTS instead of dropping — DoT
        // would tunnel resolution past ds-dnsgate. Anchored correctly, so the only
        // violation is NotDropped (proving the two invariants are independent).
        let bad = "iifname \"dstap-*\" udp dport 853 counter accept\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::NotDropped),
            "an anchored 853 accept must be NotDropped: {v:?}"
        );
        assert!(
            !v.iter()
                .any(|x| x.kind == ViolationKind::NotInterfaceAnchored),
            "a correctly-anchored rule must NOT also be flagged NotInterfaceAnchored: {v:?}"
        );
        assert!(!satisfies_dot_drop_shape("bad.nft", bad));
    }

    #[test]
    fn only_one_transport_dropped_fails_the_both_transport_gate() {
        // Only the udp/853 leg is dropped; tcp/853 is left open. Each present rule
        // is individually compliant (so check_text is empty), but the both-
        // transport convenience gate must still fail — the open tcp leg lets DoT
        // through. This is the NON-VACUOUS check that the gate is a conjunction.
        let udp_only = "iifname \"dstap-*\" udp dport 853 counter drop\n";
        assert!(
            check_text("u.nft", udp_only).is_empty(),
            "the single present rule is well-formed, so per-rule check is clean"
        );
        assert!(
            !satisfies_dot_drop_shape("u.nft", udp_only),
            "dropping only udp/853 must FAIL the both-transport gate (tcp leg open)"
        );
    }

    #[test]
    fn non_853_lines_are_ignored() {
        // A port-53 redirect and a port-443 rule are not this rule; and dport 8530
        // must NOT match the 853 token boundary.
        let txt = "iifname \"dstap-*\" udp dport 53 redirect to :15353\n  \
            iifname \"dstap-*\" tcp dport 8530 drop\n";
        assert!(
            check_text("x.nft", txt).is_empty(),
            "non-853 rules (and dport 8530) must be ignored"
        );
        // ...and with no 853 rule present, the convenience wrapper is false.
        assert!(!satisfies_dot_drop_shape("x.nft", txt));
    }

    #[test]
    fn comment_only_anchor_does_not_smuggle_compliance() {
        // An `iifname "dstap-*"` that appears ONLY in a trailing comment must not
        // satisfy a rule whose code matches `ip saddr`. The comment is stripped
        // before analysis, so the real (source-IP) selector still fails.
        let bad =
            "ip saddr 10.0.0.0/8 udp dport 853 counter drop # iifname \"dstap-*\" was intended\n";
        let v = check_text("c.nft", bad);
        assert!(
            v.iter()
                .any(|x| x.kind == ViolationKind::NotInterfaceAnchored),
            "a commented-out anchor must not smuggle compliance: {v:?}"
        );
    }

    #[test]
    fn unquoted_and_set_form_dstap_anchors_pass() {
        // nft tolerates the unquoted operand and an anonymous set; both are still
        // the dstap session tap, so both must pass the anchoring check.
        let unquoted = "iifname dstap-7 udp dport 853 counter drop\n";
        assert!(
            check_text("uq.nft", unquoted).is_empty(),
            "the unquoted dstap operand must pass anchoring: {:?}",
            check_text("uq.nft", unquoted)
        );
        let set_form = "iifname { \"dstap-7\" } tcp dport 853 counter drop\n";
        assert!(
            check_text("set.nft", set_form).is_empty(),
            "the set-form dstap operand must pass anchoring: {:?}",
            check_text("set.nft", set_form)
        );
    }
}
