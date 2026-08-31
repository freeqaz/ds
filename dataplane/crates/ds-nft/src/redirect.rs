//! NFT-2 interface-matched transparent-redirect rule-shape predicate (doc 09 §3
//! NFT-2, D69; doc 14 §5 lint idiom; round2/04 "Frozen vs free").
//!
//! This is the **on-box shape** the NFT-2 prerouting redirect rule must satisfy:
//! the udp/tcp 53 → `ds-dnsgate` redirect (Stage 1) and, later, the tcp 80/443 →
//! `ds-tlsproxy` cutover (NFT-2b). Like [`crate::quic_reject`] it is a **contract
//! lint over ruleset text, not an nft parser** — the same pure-`std` text
//! analysis [`ds_contracts::nft_lint`] uses (doc 14 §5), so it runs in CI with no
//! kernel, no loadable nat module, and no live nft. The companion namespace test
//! (`tests/nft2_spoofing_netns.rs`) exercises the *iifname-vs-forged-saddr* half
//! against a real kernel where one is available; this predicate is the
//! mechanism-agnostic, always-runnable half.
//!
//! # The frozen NFT-2 invariants this enforces (round2/04, D69/D44)
//!
//! 1. **Interface-matched, never source-IP.** A redirect rule that selects the
//!    flow on `ip saddr` / `ip6 saddr` is the exact failure doc 03 §3 forbids —
//!    the VM forges its source address, so source-IP selection lets a spoofed
//!    packet escape (or mis-attribute) the redirect. The selector must be
//!    `iifname` (the unforgeable attachment point). This is the load-bearing
//!    half of the doc 06 (c) in-VM-spoofing assertion at the ruleset layer.
//!    (`ip daddr` is fine — that selects on the *destination* the rule rewrites,
//!    not the forgeable source.)
//! 2. **Redirect/DNAT verdict to a named proxy port — never `dnat to
//!    127.0.0.1`.** D69 mandates `redirect` or an explicit per-tap `dnat`; a
//!    `dnat to 127.0.0.1` is prohibited (the `route_localnet` footgun, round2/04).
//!    A redirect rule with no redirect/dnat verdict, or one aimed at loopback, is
//!    a violation.
//! 3. **The port-53 redirect covers BOTH udp and tcp.** udp/53 carries the
//!    common path; tcp/53 carries large answers and the foreign-resolver bypass
//!    (DNS over TCP must not escape — NFT-4). A ruleset that redirects only one
//!    transport leaves the other as a resolver-bypass hole.
//!
//! Invariants (1) and (2) are checked **per matching redirect rule**; invariant
//! (3) is a **whole-ruleset** property (both transports must appear), so it is a
//! distinct entry point ([`covers_both_transports`]) the convenience wrapper
//! folds in.
//!
//! Scope: this governs the *redirect rules*. The NFT-1 bootstrap artifact's
//! prerouting chain shell, the default-deny floor, and the NFT-5 mark machinery
//! are other steps' shapes; this predicate only inspects lines that are
//! themselves interface-matched port-53 (or 80/443) redirects.

/// A NFT-2 redirect-rule-shape violation found by the predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The file/source the violation was found in (as passed to the predicate).
    pub file: String,
    /// 1-based line number of the offending rule (0 for whole-ruleset findings).
    pub line: usize,
    /// The offending source line, trimmed (empty for whole-ruleset findings).
    pub text: String,
    /// What invariant was broken.
    pub kind: ViolationKind,
}

/// The category of a NFT-2 redirect-rule-shape violation (D69/D44).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// The redirect rule selects the flow on a forgeable SOURCE-address key —
    /// any `saddr` match (`ip saddr` / `ip6 saddr` / `ether saddr` / an `saddr`
    /// set). NFT-2 forbids this: only `iifname` (the attachment point) may anchor
    /// the redirect (doc 03 §3, round2/04). This is the ruleset-layer form of the
    /// doc 06 (c) in-VM-spoofing failure. R6 keys on the `saddr` token (not just
    /// the literal `ip saddr`) so a non-ip source match cannot evade it.
    SourceIpMatch,
    /// The redirect rule has no `iifname` selector at all — it matches every
    /// arriving interface, not the per-session tap. NFT-2 anchors on the
    /// unforgeable interface; an unanchored redirect is not interface-matched.
    MissingIifname,
    /// The rule is a port-53 (or 80/443) selector but carries no `redirect` /
    /// `dnat` verdict — it does not actually transparently redirect.
    NoRedirectVerdict,
    /// The rule `dnat`s to `127.0.0.1` (loopback) — the prohibited
    /// `route_localnet` footgun (D69/round2/04). Use `redirect` or an explicit
    /// per-tap dnat to the tap's boundary-side address instead.
    DnatToLoopback,
    /// Whole-ruleset: the port-53 redirect is present for one transport but not
    /// the other (only udp OR only tcp). Both must be redirected or the missing
    /// transport is a resolver-bypass hole (NFT-4). The `line`/`text` of this
    /// finding are 0/empty.
    MissingTransport,
}

/// Strip a trailing `#`-comment from an nft line, returning the code part.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Whether the whole word `comment` begins at byte `i` in `s`, on word
/// boundaries (so it does not match inside `comments` / `xcomment`).
fn is_comment_keyword_at(s: &[u8], i: usize) -> bool {
    const KW: &[u8] = b"comment";
    if i + KW.len() > s.len() || &s[i..i + KW.len()] != KW {
        return false;
    }
    let is_word = |b: u8| b.is_ascii_alphanumeric();
    if i > 0 && is_word(s[i - 1]) {
        return false;
    }
    let end = i + KW.len();
    if end < s.len() && is_word(s[end]) {
        return false;
    }
    true
}

/// Remove the nft `comment "<...>"` keyword + quoted-string clause(s) from a
/// line, returning the rule code with the human-readable comment text excised
/// (R1, mirrored from the Go `stripNftCommentKeyword`).
///
/// THE HOLE: nft rules carry an optional `comment "free text"` clause the lint
/// would otherwise tokenize verbatim — so a rule such as
///
/// ```text
/// iifname "dstap-*" udp dport 53 accept comment "redirect to :15353"
/// ```
///
/// would leak the `redirect` token out of the human comment into the bag, making
/// an `accept` (no real redirect verdict) satisfy [`has_redirect_verdict`] and
/// pass. Worse, a comment could smuggle an `iifname` / `redirect` / `dnat` token
/// into a rule that carries none. [`strip_comment`] only handles the trailing
/// `#`-comment, not this keyword form, so it is stripped here BEFORE tokenizing
/// (and before the `;`-split, so a `;` inside a comment string is never read as a
/// statement separator).
///
/// Scans byte-by-byte tracking double-quote state, removing from the `comment`
/// keyword through its closing quote (replacing the clause with a single space so
/// adjacent tokens do not fuse). An unterminated comment string (no closing
/// quote) drops the rest of the line — the fail-closed choice. Multiple `comment`
/// clauses on one line are all removed.
fn strip_comment_keyword(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut in_quote = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_quote {
            out.push(c as char);
            if c == b'"' {
                in_quote = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_quote = true;
            out.push(c as char);
            i += 1;
            continue;
        }
        if is_comment_keyword_at(bytes, i) {
            let mut j = i + "comment".len();
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                if j < bytes.len() {
                    j += 1; // consume the closing quote
                }
                out.push(' ');
                i = j;
                continue;
            }
            // A `comment` keyword not followed by a quoted string is not the nft
            // comment clause (defensive); fall through and emit it verbatim.
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// Split one physical nft line into its `;`-separated statements, respecting
/// double-quoted strings so a `;` inside a quoted string (e.g. a
/// `log prefix "a;b "`) is NOT a separator (R3, mirrored from the Go
/// `splitStatements`).
///
/// THE HOLE: the lint scanned the ruleset only line-by-line, so several
/// `;`-joined statements on ONE physical line collapsed into a single token bag —
/// hiding a permissive second statement. For example
///
/// ```text
/// iifname "dstap-*" udp dport 53 redirect to :15353; ip saddr 10.0.0.5 udp dport 53 redirect to :15353
/// ```
///
/// has a compliant first statement and a forgeable source-IP-selected second
/// statement; analyzed as one bag the iifname of the first laundered the second.
/// Splitting on `;` first means each statement is analyzed on its own.
///
/// Returns the trimmed, non-empty statements in order. The split happens AFTER
/// [`strip_comment_keyword`], so no `;` inside a human comment string reaches here.
fn split_statements(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut stmts = Vec::new();
    let mut in_quote = false;
    let mut start = 0;
    // Split only on the ASCII bytes `;` / `"`, never inside a multibyte UTF-8
    // sequence, so the byte offsets are always char boundaries.
    for i in 0..bytes.len() {
        match bytes[i] {
            b'"' => in_quote = !in_quote,
            b';' if !in_quote => {
                let s = line[start..i].trim();
                if !s.is_empty() {
                    stmts.push(s);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let s = line[start..].trim();
    if !s.is_empty() {
        stmts.push(s);
    }
    stmts
}

/// Whether a token appears as a whole word in the comment-stripped, lowercased
/// code (split on any non-alphanumeric so `dport`/`saddr`/`redirect` are matched
/// exactly, never as a substring of an unrelated identifier).
fn has_word(code_lc: &str, word: &str) -> bool {
    code_lc
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == word)
}

/// Whether `code_lc` names a destination port equal to `port`.
fn names_dport(code_lc: &str, port: &str) -> bool {
    code_lc.contains("dport")
        && code_lc
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|tok| tok == port)
}

/// Whether the line is a NFT-2-governed redirect *candidate*: it is a transparent
/// redirect/dnat rule for one of the intercepted ports (53 at Stage 1; 80/443 at
/// NFT-2b). We key off "this line is trying to redirect an intercepted port" so
/// the verdict/selector invariants are checked on exactly the rules NFT-2 owns —
/// not on the NFT-1 default-deny lines or NFT-3 allow-set lines.
fn is_redirect_candidate(code_lc: &str) -> bool {
    let intercepted_port =
        names_dport(code_lc, "53") || names_dport(code_lc, "80") || names_dport(code_lc, "443");
    // A candidate either already carries a redirect/dnat verdict, or is a
    // port-intercept rule in a nat-type context (so a port-53 rule that *forgot*
    // its verdict is still caught as NoRedirectVerdict rather than skipped).
    let nat_shaped =
        has_word(code_lc, "redirect") || has_word(code_lc, "dnat") || has_word(code_lc, "iifname");
    // ...but a rule carrying an EXPLICIT terminal reject/drop verdict (and no
    // redirect/dnat) is an intentional verdict, NOT a forgot-the-redirect rule —
    // e.g. the NFT-1 floor's own D70 `udp dport 443 ... counter reject` QUIC reject,
    // or a `ct state new drop`. Those are NOT NFT-2 redirect candidates; judging
    // them here would wrongly raise NoRedirectVerdict. Verdict-less port-intercept
    // rules (the real "forgot the redirect verdict" case) are still caught, because
    // they carry neither a redirect/dnat nor a reject/drop.
    let explicit_reject_or_drop = (has_word(code_lc, "reject") || has_word(code_lc, "drop"))
        && !has_redirect_verdict(code_lc);
    intercepted_port && nat_shaped && !explicit_reject_or_drop
}

/// Whether the rule selects the flow on a forgeable SOURCE key.
///
/// R6 (broaden the source-key guard): the original check named only the literal
/// `ip saddr` / `ip6 saddr` selectors, so a source match keyed on a different
/// layer — `ether saddr <mac>`, an `ip6 saddr` set, or any other `... saddr ...`
/// form — evaded it. nft spells EVERY source-address match with the `saddr`
/// keyword (the `daddr` destination twin is never a source), so keying on the
/// `saddr` TOKEN catches the whole family while `ip daddr` (a destination match)
/// still never trips it. Mirrors the Go `matchesSourceIP` R6 broadening.
fn matches_source_ip(code_lc: &str) -> bool {
    has_word(code_lc, "saddr")
}

/// Whether the rule carries an `iifname` selector.
fn matches_iifname(code_lc: &str) -> bool {
    has_word(code_lc, "iifname")
}

/// Whether the rule carries a `redirect` or `dnat` verdict.
fn has_redirect_verdict(code_lc: &str) -> bool {
    has_word(code_lc, "redirect") || has_word(code_lc, "dnat")
}

/// Whether the rule dnats to loopback (`127.0.0.1`) — the prohibited
/// route_localnet footgun.
fn dnats_to_loopback(code_lc: &str) -> bool {
    has_word(code_lc, "dnat") && code_lc.contains("127.0.0.1")
}

/// Check a single ruleset's text for the NFT-2 redirect-rule shape. `file` is
/// used only for reporting. Returns every per-rule violation (invariants 1/2)
/// **and** the whole-ruleset transport-coverage violation (invariant 3) if a
/// port-53 redirect is present for only one transport.
///
/// A pure function of the ruleset text alone — no kernel, no live nft, no DNS
/// state.
pub fn check_text(file: &str, text: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut saw_udp_53_redirect = false;
    let mut saw_tcp_53_redirect = false;

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        // R1: drop the trailing `#`-comment AND the nft `comment "<...>"` keyword
        // clause BEFORE tokenizing, so the quoted comment text cannot leak a
        // redirect/iifname/dnat token into the bag. Done before the `;`-split so a
        // `;` inside a comment string is not read as a statement separator.
        let line = strip_comment_keyword(strip_comment(raw_line));

        // R3: a single physical line may carry several `;`-joined statements;
        // analyze each on its own token bag so a permissive (e.g. source-IP
        // selected) second statement does not collapse into the first's bag.
        for code in split_statements(&line) {
            let code_lc = code.to_ascii_lowercase();
            if !is_redirect_candidate(&code_lc) {
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

            // Invariant 1: interface-matched, never source-IP.
            if matches_source_ip(&code_lc) {
                push(&mut violations, ViolationKind::SourceIpMatch);
            }
            if !matches_iifname(&code_lc) {
                push(&mut violations, ViolationKind::MissingIifname);
            }

            // Invariant 2: redirect/dnat verdict, never dnat-to-loopback.
            if !has_redirect_verdict(&code_lc) {
                push(&mut violations, ViolationKind::NoRedirectVerdict);
            }
            if dnats_to_loopback(&code_lc) {
                push(&mut violations, ViolationKind::DnatToLoopback);
            }

            // Track transport coverage for invariant 3 — count only well-formed
            // port-53 redirects (an iifname rule that actually redirects). A
            // malformed line is already flagged above; it does not also satisfy
            // coverage.
            let well_formed = matches_iifname(&code_lc)
                && has_redirect_verdict(&code_lc)
                && !matches_source_ip(&code_lc)
                && !dnats_to_loopback(&code_lc);
            if names_dport(&code_lc, "53") && well_formed {
                if has_word(&code_lc, "udp") {
                    saw_udp_53_redirect = true;
                }
                if has_word(&code_lc, "tcp") {
                    saw_tcp_53_redirect = true;
                }
            }
        }
    }

    // Invariant 3 (whole-ruleset): if a port-53 redirect exists for one transport
    // but not the other, the missing transport is a resolver-bypass hole. We only
    // raise this when at least one transport is present — a ruleset with no
    // port-53 redirect at all (e.g. an 80/443-only NFT-2b fragment, or the NFT-1
    // empty shell) is out of scope, not a violation.
    if saw_udp_53_redirect != saw_tcp_53_redirect {
        violations.push(Violation {
            file: file.to_string(),
            line: 0,
            text: String::new(),
            kind: ViolationKind::MissingTransport,
        });
    }

    violations
}

/// Whether `text` redirects BOTH udp/53 and tcp/53 with a well-formed,
/// interface-matched, non-loopback redirect verdict. The whole-ruleset half of
/// invariant 3, exposed for callers (and the namespace test) that need the
/// coverage answer directly.
pub fn covers_both_transports(file: &str, text: &str) -> bool {
    let v = check_text(file, text);
    // Both transports present iff there is no MissingTransport finding AND at
    // least one well-formed port-53 redirect was seen (so an empty ruleset is
    // not vacuously "covered").
    let has_port_53_redirect = text.lines().any(|l| {
        // Probe through the same R1/R3 pipeline check_text uses so a comment-hidden
        // token cannot count and a `;`-joined statement is seen.
        let line = strip_comment_keyword(strip_comment(l));
        split_statements(&line).iter().any(|code| {
            let code_lc = code.to_ascii_lowercase();
            names_dport(&code_lc, "53")
                && matches_iifname(&code_lc)
                && has_redirect_verdict(&code_lc)
        })
    });
    has_port_53_redirect && !v.iter().any(|x| x.kind == ViolationKind::MissingTransport)
}

/// Whether `text` contains a compliant NFT-2 port-53 transparent redirect: at
/// least one port-53 redirect is present, both transports are covered, and no
/// redirect candidate has any per-rule violation. The future NFT-2 rule (and the
/// NFT-1 artifact once it gains the redirect rules) must make this return `true`.
pub fn satisfies_nft2_redirect_shape(file: &str, text: &str) -> bool {
    check_text(file, text).is_empty() && covers_both_transports(file, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical compliant fragment — the exact shape the NFT-1 artifact's
    /// prerouting chain carries: iifname-anchored, redirect verdict, both
    /// transports, no source-IP match, no loopback dnat.
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
    fn compliant_fragment_has_no_violations() {
        assert!(
            check_text("ds.nft", COMPLIANT).is_empty(),
            "the iifname-anchored both-transport redirect must pass"
        );
        assert!(satisfies_nft2_redirect_shape("ds.nft", COMPLIANT));
        assert!(covers_both_transports("ds.nft", COMPLIANT));
    }

    #[test]
    fn source_ip_match_is_a_violation() {
        // The load-bearing spoofing failure at the ruleset layer: selecting the
        // redirect on a forgeable source IP.
        let bad = "ip saddr 10.0.0.5 udp dport 53 redirect to :15353\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch),
            "an ip-saddr-selected redirect must be a SourceIpMatch violation: {v:?}"
        );
        assert!(!satisfies_nft2_redirect_shape("bad.nft", bad));
    }

    #[test]
    fn ip6_saddr_match_is_also_a_violation() {
        let bad = "ip6 saddr fe80::1 tcp dport 53 redirect to :15353\n";
        let v = check_text("bad.nft", bad);
        assert!(v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch));
    }

    #[test]
    fn ip_daddr_match_is_fine() {
        // daddr selects on the destination the rule rewrites, not the forgeable
        // source — it must NOT trip the source-IP invariant.
        let ok = "\
iifname \"dstap-*\" ip daddr != 10.0.0.1 udp dport 53 redirect to :15353
iifname \"dstap-*\" ip daddr != 10.0.0.1 tcp dport 53 redirect to :15353
";
        let v = check_text("ok.nft", ok);
        assert!(
            !v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch),
            "ip daddr is a destination match, not a source-IP match: {v:?}"
        );
    }

    #[test]
    fn missing_iifname_is_a_violation() {
        // A port-53 redirect that matches no interface is unanchored.
        let bad = "udp dport 53 redirect to :15353\n  tcp dport 53 redirect to :15353\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter()
                .filter(|x| x.kind == ViolationKind::MissingIifname)
                .count()
                == 2,
            "both unanchored redirects must be MissingIifname: {v:?}"
        );
    }

    #[test]
    fn no_redirect_verdict_is_a_violation() {
        // An iifname port-53 rule that forgot its verdict (e.g. a bare accept).
        let bad = "iifname \"dstap-*\" udp dport 53 accept\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::NoRedirectVerdict),
            "a verdict-less port-53 intercept must be NoRedirectVerdict: {v:?}"
        );
    }

    #[test]
    fn explicit_udp443_reject_is_not_a_redirect_candidate() {
        // The NFT-1 floor's own D70 QUIC reject (`udp dport 443 ... reject`) is an
        // intentional terminal verdict, NOT a forgot-the-redirect NFT-2b rule, so it
        // must not be judged a redirect candidate (would wrongly raise
        // NoRedirectVerdict and red the golden NFT-1 artifact test).
        let ok = "iifname \"dstap-*\" ct state new udp dport 443 counter reject with icmpx type port-unreachable\n";
        let v = check_text("ok.nft", ok);
        assert!(
            v.is_empty(),
            "an explicit udp/443 reject verdict is not an NFT-2 redirect candidate: {v:?}"
        );
        // ...but the exclusion is NARROW: a verdict-less udp/443 intercept is still
        // caught (the real "forgot the redirect verdict" case), so this carve-out
        // can never hide a genuinely missing redirect.
        let bad = "iifname \"dstap-*\" udp dport 443 accept\n";
        let vb = check_text("bad.nft", bad);
        assert!(
            vb.iter()
                .any(|x| x.kind == ViolationKind::NoRedirectVerdict),
            "a verdict-less udp/443 intercept must still be NoRedirectVerdict: {vb:?}"
        );
    }

    #[test]
    fn dnat_to_loopback_is_a_violation() {
        // The route_localnet footgun D69 prohibits.
        let bad = "\
iifname \"dstap-*\" udp dport 53 dnat to 127.0.0.1:15353
iifname \"dstap-*\" tcp dport 53 dnat to 127.0.0.1:15353
";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter()
                .filter(|x| x.kind == ViolationKind::DnatToLoopback)
                .count()
                == 2,
            "dnat to 127.0.0.1 must be a DnatToLoopback violation: {v:?}"
        );
        assert!(!satisfies_nft2_redirect_shape("bad.nft", bad));
    }

    #[test]
    fn explicit_per_tap_dnat_is_fine() {
        // An explicit per-tap dnat to the tap's boundary-side address (not
        // loopback) is the D69-permitted alternative to `redirect`.
        let ok = "\
iifname \"dstap-7\" udp dport 53 dnat to 10.99.7.1:15353
iifname \"dstap-7\" tcp dport 53 dnat to 10.99.7.1:15353
";
        let v = check_text("ok.nft", ok);
        assert!(
            v.is_empty(),
            "per-tap dnat to a non-loopback addr must pass: {v:?}"
        );
        assert!(satisfies_nft2_redirect_shape("ok.nft", ok));
    }

    #[test]
    fn udp_only_53_redirect_is_a_missing_transport_violation() {
        let bad = "iifname \"dstap-*\" udp dport 53 redirect to :15353\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::MissingTransport),
            "udp-only port-53 redirect leaves tcp as a bypass hole: {v:?}"
        );
        assert!(!covers_both_transports("bad.nft", bad));
    }

    #[test]
    fn tcp_only_53_redirect_is_a_missing_transport_violation() {
        let bad = "iifname \"dstap-*\" tcp dport 53 redirect to :15353\n";
        let v = check_text("bad.nft", bad);
        assert!(v.iter().any(|x| x.kind == ViolationKind::MissingTransport));
    }

    #[test]
    fn ruleset_with_no_port53_redirect_is_out_of_scope() {
        // The NFT-1 empty shell / an 80/443-only fragment: no port-53 redirect at
        // all → no MissingTransport (it is not in scope for the 53 coverage rule).
        let shell = "\
chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
}
";
        let v = check_text("shell.nft", shell);
        assert!(
            !v.iter().any(|x| x.kind == ViolationKind::MissingTransport),
            "an empty shell is out of scope, not a MissingTransport violation: {v:?}"
        );
        // ...but it does not satisfy the redirect shape either (nothing redirects).
        assert!(!satisfies_nft2_redirect_shape("shell.nft", shell));
    }

    #[test]
    fn comment_cannot_smuggle_a_verdict() {
        // A `redirect` only in a comment must not satisfy an accept rule.
        let bad = "iifname \"dstap-*\" udp dport 53 accept # redirect to :15353\n";
        let v = check_text("c.nft", bad);
        assert!(v.iter().any(|x| x.kind == ViolationKind::NoRedirectVerdict));
    }

    // ── R6: broaden the source-key guard from `ip saddr` to the `saddr` token ──
    #[test]
    fn ether_saddr_source_match_is_a_violation() {
        // A link-layer source match (`ether saddr <mac>`) is just as forgeable as
        // `ip saddr`. Before R6 the literal-only `ip saddr` check let it evade.
        let bad =
            "iifname \"dstap-*\" ether saddr 02:00:00:00:00:01 udp dport 53 redirect to :15353\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch),
            "an ether-saddr-selected redirect must be a SourceIpMatch violation: {v:?}"
        );
        assert!(!satisfies_nft2_redirect_shape("bad.nft", bad));
    }

    #[test]
    fn ip6_saddr_set_source_match_is_a_violation() {
        // An `ip6 saddr { ... }` set source match keys on the forgeable source —
        // R6's `saddr`-token guard catches the set form, not just the scalar.
        let bad =
            "iifname \"dstap-*\" ip6 saddr { fe80::1, fe80::2 } tcp dport 53 redirect to :15353\n";
        let v = check_text("bad.nft", bad);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch),
            "an ip6-saddr-set-selected redirect must be a SourceIpMatch violation: {v:?}"
        );
    }

    #[test]
    fn ip_daddr_is_still_fine_under_the_broadened_guard() {
        // The broadened `saddr`-token guard must NOT catch `ip daddr` (a
        // destination match): `daddr` has no `saddr` token.
        let ok = "\
iifname \"dstap-*\" ip daddr != 10.0.0.1 udp dport 53 redirect to :15353
iifname \"dstap-*\" ip daddr != 10.0.0.1 tcp dport 53 redirect to :15353
";
        let v = check_text("ok.nft", ok);
        assert!(
            !v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch),
            "ip daddr must not trip the broadened source-key guard: {v:?}"
        );
        assert!(satisfies_nft2_redirect_shape("ok.nft", ok));
    }

    // ── R1: nft `comment "..."` keyword cannot smuggle a redirect verdict ──
    #[test]
    fn comment_keyword_cannot_smuggle_a_redirect_verdict() {
        // An `accept` (no real redirect verdict) whose comment STRING names
        // `redirect to :15353` must NOT satisfy has_redirect_verdict. Before R1
        // the `comment "..."` clause was tokenized verbatim.
        let bad = "iifname \"dstap-*\" udp dport 53 accept comment \"redirect to :15353\"\n";
        let v = check_text("c.nft", bad);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::NoRedirectVerdict),
            "an accept must stay NoRedirectVerdict even when its comment names a redirect: {v:?}"
        );
    }

    #[test]
    fn comment_keyword_does_not_break_a_compliant_redirect() {
        // The keyword strip must not red a genuinely compliant redirect carrying a
        // trailing comment clause.
        let ok = "\
iifname \"dstap-*\" udp dport 53 redirect to :15353 comment \"dns to dnsgate\"
iifname \"dstap-*\" tcp dport 53 redirect to :15353 comment \"dns to dnsgate\"
";
        assert!(
            check_text("ok.nft", ok).is_empty(),
            "a compliant redirect with a trailing comment clause must pass"
        );
        assert!(satisfies_nft2_redirect_shape("ok.nft", ok));
    }

    // ── R3: `;`-joined source-IP second statement is evaluated on its own ──
    #[test]
    fn semicolon_joined_source_ip_second_statement_is_caught() {
        // A compliant first redirect followed by a `;`-joined forgeable
        // source-IP-selected second redirect: before R3 they collapsed into one
        // bag and the iifname of the first laundered the second. Now the second
        // statement is its own bag and trips SourceIpMatch.
        let bad = "iifname \"dstap-*\" udp dport 53 redirect to :15353; ip saddr 10.0.0.5 udp dport 53 redirect to :15353\n";
        let v = check_text("s.nft", bad);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch),
            "a `;`-joined source-IP second redirect must be caught: {v:?}"
        );
        assert!(!satisfies_nft2_redirect_shape("s.nft", bad));
    }

    #[test]
    fn semicolon_inside_a_quoted_log_prefix_is_not_a_separator_redirect() {
        // A `;` inside a quoted log-prefix string must NOT split the statement.
        let ok = "\
iifname \"dstap-*\" udp dport 53 log prefix \"dns; redirect \" redirect to :15353
iifname \"dstap-*\" tcp dport 53 redirect to :15353
";
        let v = check_text("q.nft", ok);
        assert!(
            v.is_empty(),
            "a `;` inside a quoted log prefix must not be a statement separator: {v:?}"
        );
        assert!(satisfies_nft2_redirect_shape("q.nft", ok));
    }

    #[test]
    fn nft2b_80_443_redirect_candidates_are_judged_too() {
        // The NFT-2b cutover lines (80/443 → ds-tlsproxy) are governed by the
        // same iifname/verdict invariants; a source-IP-selected 443 redirect is
        // just as forgeable.
        let bad = "ip saddr 10.0.0.9 tcp dport 443 redirect to :18443\n";
        let v = check_text("nft2b.nft", bad);
        assert!(v.iter().any(|x| x.kind == ViolationKind::SourceIpMatch));
    }
}
