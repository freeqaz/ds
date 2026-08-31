//! NFT-4 udp/443 QUIC reject-rule-shape predicate (doc 14 §10/§2, D70; doc 11
//! §3.3 companion).
//!
//! This is the **reject side** of doc 11 §3.3's "two independent controls" pair.
//! DNS-4 rule 4 steers *cooperative* clients away from QUIC (AAAA/HTTPS(65)/
//! SVCB(64) suppression, §3.3); a client that ignores that steering still hits
//! this NFT-4 reject, which is the *sole* control for non-cooperative clients
//! (curl `--http3-only`, WebTransport, MASQUE, raw QUIC libraries — doc 14 §10).
//! The two layers are tested independently and **never merged into one
//! assertion** (D70). Accordingly this predicate takes ruleset text and NOTHING
//! else: it has no input from DNS state, suppression state, or any steering
//! outcome — its verdict holds regardless of what DNS did.
//!
//! D70's frozen verdict wording: the udp/443 control is **"rejected (icmp
//! port-unreachable) + counted per session"**, an amendment of the original
//! "dropped" wording (doc 14 §6 D70, amending D42/NFT-4). Two shape invariants
//! follow, and this predicate enforces both against ruleset text:
//!
//! 1. **Reject-not-drop.** The udp/443 rule's verdict must be a `reject` with an
//!    icmp(x) `port-unreachable` type — a silent `drop` is a violation. A drop
//!    stalls clients (RFC-4074-style ~5 s hangs) and, more importantly, erases
//!    the observable refusal the off-box flip-to-inspect trigger counts.
//! 2. **Per-session counting.** The rule must carry a `counter` so QUIC-reject
//!    volume is countable per session (the [`ds_contracts::reject::RejectReason::
//!    QuicBlocked`] reason code is the off-box half; this counter is the on-box
//!    half). A reject with no counter is a violation.
//!
//! This is a **contract lint, not an nft parser** — the same pure-`std` text
//! analysis the [`ds_contracts::nft_lint`] mark lint uses (doc 14 §5). It is the
//! executable shape the NFT-1 floor's udp/443 reject (the LIVE reject, doc 14 §10
//! row 3 — NFT-2 is the unrelated iifname three-keys-agree drop) and NFT-4's
//! defense-in-depth copy must satisfy.
//!
//! # The composer role (RowQUICReject wiring; taskdb 01KTZV3XN / 01KV8YYA7N)
//!
//! Beyond the per-rule shape lint, this module is the ds-nft **composer's single
//! source** for the floor's udp/443 QUIC-reject rule, in the same sense
//! [`crate::session`] is the single source for the per-session allow-set name:
//!
//! - [`floor_quic_reject_rule`] renders the canonical reject line (anchored on the
//!   unforgeable `dstap-*` tap, `ct state new`-scoped, `counter`ed, `reject with
//!   icmpx type port-unreachable`) so the shipped artifacts and the composer cannot
//!   drift; [`floor_quic_reject_reason`] ties it to [`RejectReason::QuicBlocked`].
//! - [`floor_quic_reject_composition`] / [`floor_quic_reject_is_unshadowed`] are
//!   the **composition-order guard**: a base-chain `drop` is TERMINAL across
//!   chains, so a udp/443 reject placed only in NFT-4's later-priority `forward`
//!   chain was SHADOWED by NFT-1's earlier `ct state new drop` — QUIC was silently
//!   DROPPED, not REJECTED, violating D70. The per-rule shape lint could not see
//!   this (each rule was individually compliant; the gap was cross-rule ORDER), so
//!   this guard reads the whole floor fragment and asserts the reject precedes the
//!   terminal drop. The shipped NFT-1 artifact must satisfy it.
//!
//! The shape predicate ([`check_text`]) still takes ruleset text and NOTHING else:
//! it has no input from DNS state, suppression state, or any steering outcome — its
//! verdict holds regardless of what DNS did. The synthetic-fixture lint and the
//! shipped-artifact composition guard are both kernel-free; the live-kernel proof
//! (a real udp/443 packet on a tap getting ICMP port-unreachable) is the
//! CAP_NET_ADMIN conformance row `RowQUICReject` (deferred operator step).
//! No live nft, no live DNS.

use ds_contracts::reject::RejectReason;

/// A udp/443 QUIC reject-rule-shape violation found by the predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The file/source the violation was found in (as passed to the predicate).
    pub file: String,
    /// 1-based line number of the offending udp/443 rule.
    pub line: usize,
    /// The offending source line, trimmed.
    pub text: String,
    /// What invariant was broken.
    pub kind: ViolationKind,
}

/// The category of a udp/443 reject-rule-shape violation (D70).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// The udp/443 rule's verdict is a silent `drop` (or otherwise not a
    /// `reject`). D70 requires reject-not-drop so the refusal is observable.
    SilentDrop,
    /// The udp/443 rule carries an explicit `accept` verdict (R2 anti-permit).
    /// An `accept` PERMITS udp/443 — the precise D70 failure — and at runtime an
    /// `accept` short-circuits any reject/drop on the same rule, so a
    /// contradictory `counter accept reject with icmpx type port-unreachable`
    /// (accept wins; the reject is dead) would otherwise sail past the
    /// reject-not-drop checks, which never inspect for `accept`. There is no
    /// legitimate `accept` on a control that must REJECT, so it fails closed.
    /// Mirrors the Go `ErrQUICNotRejected` accept leg (resolverlock/nft4 R2).
    PermitVerdict,
    /// The udp/443 rule `reject`s but with no icmp(x) `port-unreachable` type —
    /// the verdict must be the explicit port-unreachable form, not a bare reject
    /// or a reset/tcp-reset shape (which is meaningless for UDP anyway).
    NotPortUnreachable,
    /// The udp/443 rule has no `counter`, so QUIC rejects cannot be counted per
    /// session (D70's "+ counted per session").
    MissingCounter,
}

impl ViolationKind {
    /// The off-box reason code this on-box control feeds. Every udp/443 reject
    /// shape this predicate governs is, by D70, the [`RejectReason::QuicBlocked`]
    /// carveout — *distinct* from [`RejectReason::DefaultDeny`]. Exposed so a
    /// caller (or test) can assert the on-box shape and the off-box reason are
    /// the same control without reaching across crates for the constant.
    pub const fn reject_reason(&self) -> RejectReason {
        RejectReason::QuicBlocked
    }
}

/// Whether a (comment-stripped, lowercased) line is the udp/443 rule this
/// predicate governs. We match on the destination-port selector in either of
/// nft's spellings (`udp dport 443`, `meta l4proto udp ... th dport 443`) — the
/// load-bearing tokens are a udp match and a dport of 443.
fn is_udp_443_rule(code_lc: &str) -> bool {
    let mentions_udp = code_lc.contains("udp")
        // `meta l4proto udp` / `ip protocol udp` spellings also count.
        || code_lc.contains("l4proto udp");
    let mentions_443 = code_lc
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == "443");
    let mentions_dport = code_lc.contains("dport");
    mentions_udp && mentions_dport && mentions_443
}

/// Whether the rule carries a `reject` verdict (as opposed to a bare `drop`).
fn has_reject(code_lc: &str) -> bool {
    code_lc
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == "reject")
}

/// Whether the rule carries a silent `drop` verdict.
fn has_drop(code_lc: &str) -> bool {
    code_lc
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == "drop")
}

/// Whether the rule carries an explicit `accept` verdict — the permit verdict
/// R2's anti-permit guard fails closed on (a control that must REJECT can never
/// legitimately `accept`).
fn has_accept(code_lc: &str) -> bool {
    code_lc
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == "accept")
}

/// Whether the `reject` verdict names an icmp(x) `port-unreachable` type. nft
/// spells the type with a hyphen (`port-unreachable`); we also tolerate the
/// underscore form defensively. The icmp family (`icmp` / `icmpv6` / `icmpx`)
/// must be present so a bare `reject` or a `reject with tcp reset` does not pass.
fn has_port_unreachable(code_lc: &str) -> bool {
    let names_port_unreachable =
        code_lc.contains("port-unreachable") || code_lc.contains("port_unreachable");
    let names_icmp_family = code_lc.contains("icmp"); // covers icmp / icmpv6 / icmpx
    names_port_unreachable && names_icmp_family
}

/// Whether the rule carries a `counter` so rejects are countable per session.
fn has_counter(code_lc: &str) -> bool {
    code_lc
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == "counter")
}

/// Strip a trailing `#`-comment from an nft line, returning the code part.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Whether the whole word `comment` begins at byte `i` in `s`, on word
/// boundaries (so it does not match inside `comments` / `xcomment`). The token
/// boundary is the same ASCII-alphanumeric class the verdict scans split on.
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
/// THE HOLE: nft rules carry an optional `comment "free text"` clause that the
/// lint would otherwise tokenize verbatim — so a rule such as
///
/// ```text
/// udp dport 443 counter reject comment "use icmp type port-unreachable"
/// ```
///
/// would leak the `icmp`, `port-unreachable`, and `port` tokens out of the human
/// comment into the lowercased token bag, making a BARE `reject` (no real
/// `reject with icmp type port-unreachable` verdict) satisfy
/// [`has_port_unreachable`] and pass. Worse, a comment could smuggle a `reject` /
/// `drop` / `accept` verdict token into a rule that carries none. [`strip_comment`]
/// only handles the trailing `#`-comment, not this keyword form, so the keyword
/// string is stripped here BEFORE tokenizing (and before the `;`-split, so a `;`
/// inside a comment string is never read as a statement separator).
///
/// It scans byte-by-byte tracking double-quote state, so a `comment` token inside
/// a DIFFERENT quoted string (e.g. `log prefix "comment "`) is never treated as
/// the keyword, and removes from the `comment` keyword through its closing quote
/// (replacing the whole clause with a single space so adjacent tokens do not
/// fuse). An unterminated comment string (no closing quote) drops the rest of the
/// line — the conservative, fail-closed choice (trailing bytes after a `comment "`
/// opener are part of the comment, not rule code). Multiple `comment` clauses on
/// one line are all removed.
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
            // Skip whitespace between the keyword and its quoted string.
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                // Skip the opening quote and everything up to and including the close.
                j += 1;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                if j < bytes.len() {
                    j += 1; // consume the closing quote
                }
                // Replace the removed clause with a single space so the tokens on
                // either side stay separated.
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
/// udp dport 443 counter drop; udp dport 443 counter accept
/// ```
///
/// has a DROP first statement and a PERMISSIVE accept second statement; analyzed
/// as one bag the rule's verdict reads as a mix and the stray `accept` is
/// invisible. Splitting on `;` first means each statement is analyzed on its own
/// token bag.
///
/// Returns the trimmed, non-empty statements in order. A line with no `;` yields
/// the single (trimmed) statement; an all-whitespace line yields none. The split
/// happens AFTER [`strip_comment_keyword`], so no `;` inside a human comment
/// string reaches here.
fn split_statements(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut stmts = Vec::new();
    let mut in_quote = false;
    let mut start = 0;
    // Statements are split only on the ASCII bytes `;` / `"`, never inside a
    // multibyte UTF-8 sequence, so the byte offsets are always char boundaries.
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

/// Check a single ruleset's text for the udp/443 reject-rule shape. `file` is
/// used only for reporting. Returns every violation found on every udp/443 rule
/// line (empty = the udp/443 rule(s), if any, are compliant).
///
/// This is a pure function of the ruleset text alone — it reads no DNS state, no
/// suppression state, and no steering outcome, by construction (D70: the two
/// controls are tested independently and never merged).
pub fn check_text(file: &str, text: &str) -> Vec<Violation> {
    let mut violations = Vec::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        // R1: drop the trailing `#`-comment AND the nft `comment "<...>"` keyword
        // clause BEFORE tokenizing — otherwise the quoted comment text leaks
        // icmp / port-unreachable / verdict tokens into the bag (a bare
        // `reject comment "use icmp type port-unreachable"` would otherwise
        // satisfy has_port_unreachable). Done before the `;`-split so a `;`
        // inside a comment string is not read as a statement separator.
        let line = strip_comment_keyword(strip_comment(raw_line));

        // R3: a single physical line may carry several `;`-joined statements
        // (`... drop; udp dport 443 counter accept`). Analyze each statement on
        // its own token bag — otherwise a permissive second statement collapses
        // into the first rule's bag and goes invisible.
        for code in split_statements(&line) {
            let code_lc = code.to_ascii_lowercase();
            if !is_udp_443_rule(&code_lc) {
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

            // R2 (anti-permit): an explicit `accept` PERMITS udp/443 — the precise
            // D70 failure — and at runtime an `accept` short-circuits any reject on
            // the same statement (the reject-not-drop check below keys only on
            // reject PRESENCE, so a contradictory `counter accept reject with
            // icmpx type port-unreachable` sails past it). There is no legitimate
            // `accept` on a control that must REJECT; fail closed on it directly.
            if has_accept(&code_lc) {
                push(&mut violations, ViolationKind::PermitVerdict);
            }

            // Invariant 1: reject-not-drop.
            if !has_reject(&code_lc) {
                // No reject at all — a plain `drop` (or any non-reject verdict) is
                // a silent-drop violation. If it neither rejects nor drops we
                // still flag it: a udp/443 rule with no observable refusal verdict
                // is the exact failure D70 forbids.
                push(&mut violations, ViolationKind::SilentDrop);
            } else if !has_port_unreachable(&code_lc) {
                // It rejects, but not with the icmp(x) port-unreachable type.
                push(&mut violations, ViolationKind::NotPortUnreachable);
            }

            // A rule that BOTH drops and rejects is contradictory; flag the drop
            // so it can never masquerade as compliant on the strength of the
            // reject token alone.
            if has_drop(&code_lc) && has_reject(&code_lc) {
                push(&mut violations, ViolationKind::SilentDrop);
            }

            // Invariant 2: per-session counting.
            if !has_counter(&code_lc) {
                push(&mut violations, ViolationKind::MissingCounter);
            }
        }
    }

    violations
}

/// Whether `text` contains a compliant udp/443 QUIC reject rule: at least one
/// udp/443 rule is present AND no udp/443 rule has any violation. Convenience
/// wrapper for callers that only need a yes/no; the future NFT-4 rule must make
/// this return `true`.
pub fn satisfies_quic_reject_shape(file: &str, text: &str) -> bool {
    // Probe for a udp/443 rule through the SAME R1/R3 pipeline check_text uses
    // (strip `#`-comment, strip the `comment "..."` keyword, split `;`-joined
    // statements) so a udp/443 token hidden in a comment string can never count
    // as a present rule, and a `;`-joined second statement is seen.
    let has_udp_443 = text.lines().any(|l| {
        let line = strip_comment_keyword(strip_comment(l));
        split_statements(&line)
            .iter()
            .any(|code| is_udp_443_rule(&code.to_ascii_lowercase()))
    });
    has_udp_443 && check_text(file, text).is_empty()
}

/// The canonical, single-source udp/443 QUIC-reject rule line the ds-nft composer
/// emits for the NFT-1 floor (`forward` chain, before the terminal `ct state new
/// drop`) — the LIVE reject that issues [`RejectReason::QuicBlocked`] per session
/// (D70; the un-shadowing fix, taskdb 01KTZV3XN). ds-nft is the authority on this
/// rule's text exactly as it is the single source for the per-session allow-set
/// NAME ([`ds_contracts::session::allow_set_name`], [`crate::session`]): the
/// shipped NFT-1 / NFT-4 artifacts and this renderer cannot drift, because the
/// composition guard ([`floor_quic_reject_is_unshadowed`]) lints the artifacts and
/// the renderer's own self-witness test pins the shape.
///
/// The rule is, in order:
///  * `iifname "dstap-*"` — anchored on the UNFORGEABLE session attachment point,
///    never the forgeable `ip saddr` (doc 03 §3, the doc 06 (c) in-VM-spoofing
///    invariant), completing the per-control anchoring trilogy with
///    [`crate::redirect`] (port-53) and [`crate::dot853`] (port-853);
///  * `ct state new` — NARROWER than the terminal drop it precedes: only NEW
///    udp/443 is rejected here, so a future per-session-admitted QUIC stream
///    (accepted earlier, riding `ct state established,related accept`) is never
///    severed (the unadmitted-QUIC default, not a permanent block);
///  * `counter` — the on-box per-session [`RejectReason::QuicBlocked`] tally
///    (D70's "+ counted per session");
///  * `reject with icmpx type port-unreachable` — reject-not-drop so the refusal
///    is OBSERVABLE (no RFC-4074 ~5 s client hang; the flip-to-inspect trigger can
///    see it), family-appropriate via `icmpx` (icmp v4 / icmpv6 v6, D75).
///
/// This rule MUST be placed BEFORE the `iifname "dstap-*" ct state new drop` in
/// the same `forward` base chain: nftables base chains run per-hook in ascending
/// priority and a `drop` is TERMINAL across chains, so a reject in a later-priority
/// chain (the original NFT-4 placement) would be shadowed by the floor's drop —
/// the exact regression this renderer + [`floor_quic_reject_is_unshadowed`] guard
/// against.
pub fn floor_quic_reject_rule() -> &'static str {
    "iifname \"dstap-*\" ct state new udp dport 443 counter reject with icmpx type port-unreachable"
}

/// The off-box reason code the [`floor_quic_reject_rule`] feeds. Exposed so a
/// caller (or test) can assert the renderer and the off-box reason are the same
/// control without reaching across crates for the constant. Always
/// [`RejectReason::QuicBlocked`] — never generic [`RejectReason::DefaultDeny`]
/// (D70's per-session carveout).
pub const fn floor_quic_reject_reason() -> RejectReason {
    RejectReason::QuicBlocked
}

/// Whether a (comment-stripped, lowercased) udp/443 rule anchors its match on the
/// session-scoped `dstap-` attachment point — the unforgeable interface the
/// session is bound to (D50/D66). The exact mirror of [`crate::dot853`]'s
/// `anchors_on_dstap`: anchoring on the bare `iifname` keyword is too weak (a rule
/// could read `iifname "eth0"` and still pass a presence check), so the operand is
/// normalised (quotes / set braces / a leading comma trimmed) before the `dstap-`
/// prefix test. The companion to [`matches_source_ip`]: where that REJECTS the
/// forgeable source, this REQUIRES the interface operand be the session tap.
fn anchors_on_dstap(code_lc: &str) -> bool {
    let fields: Vec<&str> = code_lc.split_whitespace().collect();
    for (i, f) in fields.iter().enumerate() {
        if *f != "iifname" {
            continue;
        }
        let Some(next) = fields.get(i + 1) else {
            continue;
        };
        // The interface operand is the next field; for the `{ ... }` set form nft
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

/// Trim the surrounding nft punctuation (quotes, set braces, a leading comma) from
/// an interface operand so the `dstap-` prefix test keys on the interface NAME, not
/// the syntactic wrapping. Mirror of [`crate::dot853`]'s `trim_nft_punct`.
fn trim_nft_punct(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '{' || c == '}' || c == ',')
}

/// Whether a (comment-stripped, lowercased) line selects the flow on a FORGEABLE
/// source IP — `ip saddr` / `ip6 saddr`. A udp/443 reject keyed on the source the
/// in-VM agent can spoof is the doc 06 (c) in-VM-spoofing failure at the ruleset
/// layer (doc 03 §3). Mirror of [`crate::dot853`]'s `matches_source_ip`.
fn matches_source_ip(code_lc: &str) -> bool {
    code_lc.contains("ip saddr") || code_lc.contains("ip6 saddr")
}

/// Whether a (comment-stripped, lowercased) line is the terminal `ct state new`
/// drop the floor applies to ALL new session-tap egress — the verdict that, being
/// `drop` (terminal across base chains), would SHADOW any later-priority udp/443
/// reject. It is anchored on `dstap-*`, scoped to `ct state new`, and drops; it is
/// deliberately NOT a udp/443 rule (no dport), so the un-shadowing guard can find
/// the floor's catch-all drop and prove the QUIC reject precedes it.
fn is_terminal_session_drop(code_lc: &str) -> bool {
    anchors_on_dstap(code_lc)
        && code_lc.contains("ct state new")
        && has_drop(code_lc)
        && !is_udp_443_rule(code_lc)
}

/// The composition-order verdict for a floor ruleset: is the udp/443 QUIC reject
/// REACHABLE — i.e. present, compliant, anchored on the session tap, AND placed
/// BEFORE the terminal `ct state new drop` so the drop cannot shadow it (D70; the
/// regression tracked as taskdb 01KTZV3XN)?
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FloorComposition {
    /// The udp/443 reject is present, shape-compliant, `dstap-*`-anchored, and
    /// precedes the terminal `ct state new drop` (or no terminal drop exists in
    /// this fragment): QUIC is REJECTED, not silently dropped.
    RejectReachable,
    /// No udp/443 rule at all in this ruleset (e.g. a fragment that does not
    /// author the QUIC control) — neither reachable nor shadowed here.
    NoQuicRule,
    /// A udp/443 rule exists but is not a compliant, anchored reject (a silent
    /// drop, a counterless reject, a bare reject, an `accept`, or an unanchored /
    /// source-IP-matched rule). The udp/443 control itself is broken regardless of
    /// ordering — see [`check_text`] / the anchoring legs.
    RejectNonCompliant,
    /// A compliant udp/443 reject exists but a terminal `ct state new drop`
    /// precedes it in the SAME forward chain — the reject is SHADOWED (drop is
    /// terminal across base chains) and QUIC is silently dropped, violating D70.
    /// This is the exact failure the un-shadowing fix removed.
    RejectShadowedByDrop,
}

/// Decide the [`FloorComposition`] of a floor ruleset fragment: is the floor's
/// udp/443 QUIC reject reachable, or is it shadowed by an earlier terminal
/// `ct state new drop`?
///
/// This is the composition-order companion to [`check_text`] (which judges a
/// single udp/443 rule's SHAPE in isolation). The shadowing regression (taskdb
/// 01KTZV3XN) was invisible to a per-rule shape lint because each rule was
/// individually compliant; the gap was the cross-rule ORDER across the merged
/// base chains on the `forward` hook. This guard reads the whole fragment and
/// asserts the reject is both compliant AND ordered before the catch-all drop.
///
/// **Single-source delegation.** This module owns the QUIC-SPECIFIC half: the
/// udp/443 reject's shape ([`check_text`]) and its `dstap-*` anchoring. The
/// GENERAL cross-base-chain ordering decision — is a declared terminal verdict
/// pre-empted by an earlier-priority terminal `drop` once the base chains on a
/// hook are priority-merged? — is the shared
/// [`ds_contracts::nft_lint::check_terminal_verdict_reachable`] predicate. This
/// function is its QUIC-specialized caller: it supplies the udp/443 selector and
/// the floor's `ct state new drop` terminal, so the two readers cannot drift,
/// exactly as `ds-nft` is the single source for the per-session allow-set NAME.
/// (When the fragment carries no `type ... hook ... priority` base-chain
/// declaration — a bare statement list or a single un-hooked `chain { }` block —
/// the shared predicate sees no base chains, so we fall back to the equivalent
/// in-fragment ordering scan; the verdict is identical for a single chain.)
///
/// Pure text — no live kernel. The live-kernel proof (a real udp/443 packet on a
/// `dstap` tap getting ICMP port-unreachable, not a silent drop) is the
/// CAP_NET_ADMIN conformance row `RowQUICReject` (deferred operator step); this is
/// the kernel-free guard that ships with the artifact in CI.
pub fn floor_quic_reject_composition(file: &str, text: &str) -> FloorComposition {
    // QUIC-SPECIFIC half (owned here): is there a SHAPE-compliant, `dstap-*`-
    // anchored udp/443 reject anywhere in the fragment? The shared predicate is
    // selector-agnostic; this compliance gate is the udp/443 control's own.
    let mut saw_udp_443 = false;
    let mut saw_compliant_reject = false;
    for raw_line in text.lines() {
        let line = strip_comment_keyword(strip_comment(raw_line));
        for code in split_statements(&line) {
            let code_lc = code.to_ascii_lowercase();
            if !is_udp_443_rule(&code_lc) {
                continue;
            }
            saw_udp_443 = true;
            let shape_ok = check_text(file, code).is_empty();
            let anchored = anchors_on_dstap(&code_lc) && !matches_source_ip(&code_lc);
            if shape_ok && anchored {
                saw_compliant_reject = true;
            }
        }
    }

    if !saw_udp_443 {
        return FloorComposition::NoQuicRule;
    }
    if !saw_compliant_reject {
        return FloorComposition::RejectNonCompliant;
    }

    // GENERAL half (delegated): is the (now-known-compliant) udp/443 reject
    // ordered before the floor's terminal `ct state new drop` once the forward
    // base chains are priority-merged? The shared predicate is the single source
    // for this cross-base-chain ordering verdict.
    if reject_shadowed_by_terminal_drop(text) {
        return FloorComposition::RejectShadowedByDrop;
    }
    FloorComposition::RejectReachable
}

/// Whether the (compliant) udp/443 reject is SHADOWED by an earlier-priority
/// terminal `ct state new drop` once the `forward` base chains are priority-
/// merged. Delegates to the shared
/// [`ds_contracts::nft_lint::check_terminal_verdict_reachable`] predicate — the
/// single source for the cross-base-chain ordering decision (taskdb 01KTZV3XN).
///
/// The QUIC specialization supplies the predicate's two selectors:
///  * `claim_selector` — the compliant udp/443 reject ([`is_udp_443_rule`] +
///    `reject`), the declared terminal verdict that MUST stay reachable;
///  * `shadowing_selector` — the floor's catch-all `ct state new drop` (an
///    [`is_terminal_session_drop`]-shaped rule with no `dport`), the earlier
///    terminal `drop` whose selector OVERLAPS any new udp/443.
///
/// If the fragment carries no base-chain declaration the shared predicate reports
/// no claim (the merge has no chains); we then fall back to the equivalent single-
/// pass in-fragment scan so the verdict on a bare chain body is unchanged.
fn reject_shadowed_by_terminal_drop(text: &str) -> bool {
    use ds_contracts::nft_lint::{
        check_terminal_verdict_reachable, Hook, Reachability, TerminalVerdictClaim,
    };

    let claim = TerminalVerdictClaim {
        hook: Hook::Forward,
        label: "udp/443 QUIC reject (D70; taskdb 01KTZV3XN)",
        claim_selector: &|c: &str| is_udp_443_rule(c) && has_reject(c),
        // The floor's terminal catch-all `iifname dstap-* ct state new drop`
        // overlaps ANY new udp/443 packet; a `dport`-bearing drop is a specific
        // rule, not the catch-all, so it never counts as the shadowing terminal.
        shadowing_selector: &|c: &str| is_terminal_session_drop(c),
    };

    match check_terminal_verdict_reachable(text, &claim) {
        Reachability::Shadowed(_) => true,
        Reachability::Reachable => false,
        // No base chain in this fragment (a bare statement list / un-hooked
        // `chain { }`): the shared merge has nothing to order. Fall back to the
        // equivalent in-fragment ordering scan over the statement stream.
        Reachability::ClaimAbsent => in_fragment_drop_precedes_reject(text),
    }
}

/// Fallback in-fragment ordering scan for fragments with no base-chain
/// declaration (the shared predicate, which merges base chains, sees none). Walks
/// the statement stream in source order and reports whether a terminal session
/// drop precedes the first compliant udp/443 reject — the single-chain
/// equivalent of the shared cross-base-chain decision.
fn in_fragment_drop_precedes_reject(text: &str) -> bool {
    let mut saw_terminal_drop_before_reject = false;
    let mut saw_compliant_reject = false;
    for raw_line in text.lines() {
        let line = strip_comment_keyword(strip_comment(raw_line));
        for code in split_statements(&line) {
            let code_lc = code.to_ascii_lowercase();
            if is_terminal_session_drop(&code_lc) && !saw_compliant_reject {
                saw_terminal_drop_before_reject = true;
            }
            if is_udp_443_rule(&code_lc)
                && check_text("frag", code).is_empty()
                && anchors_on_dstap(&code_lc)
                && !matches_source_ip(&code_lc)
            {
                saw_compliant_reject = true;
            }
        }
    }
    saw_terminal_drop_before_reject && saw_compliant_reject
}

/// Whether the floor ruleset's udp/443 QUIC reject is reachable (the only
/// non-violating [`FloorComposition`]). Convenience wrapper: the shipped NFT-1
/// artifact MUST make this return `true` (D70; taskdb 01KTZV3XN).
pub fn floor_quic_reject_is_unshadowed(file: &str, text: &str) -> bool {
    floor_quic_reject_composition(file, text) == FloorComposition::RejectReachable
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical compliant rule — the shape the future NFT-4 udp/443 rule
    /// must emit: reject with icmpx port-unreachable, plus a counter.
    const COMPLIANT: &str = "table inet ds_filter {\n  \
        chain forward {\n    \
        udp dport 443 counter reject with icmpx type port-unreachable\n  \
        }\n}\n";

    #[test]
    fn compliant_rule_has_no_violations() {
        assert!(
            check_text("ds.nft", COMPLIANT).is_empty(),
            "the reject+counter shape must pass"
        );
        assert!(satisfies_quic_reject_shape("ds.nft", COMPLIANT));
    }

    #[test]
    fn silent_drop_is_a_violation() {
        let txt = "udp dport 443 counter drop\n";
        let v = check_text("bad.nft", txt);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::SilentDrop),
            "a silent drop must fail reject-not-drop: {v:?}"
        );
        assert!(!satisfies_quic_reject_shape("bad.nft", txt));
    }

    #[test]
    fn missing_counter_is_a_violation() {
        let txt = "udp dport 443 reject with icmpx type port-unreachable\n";
        let v = check_text("bad.nft", txt);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::MissingCounter),
            "a reject with no counter must fail per-session counting: {v:?}"
        );
        assert!(!satisfies_quic_reject_shape("bad.nft", txt));
    }

    #[test]
    fn bare_reject_without_port_unreachable_is_a_violation() {
        let txt = "udp dport 443 counter reject\n";
        let v = check_text("bad.nft", txt);
        assert!(
            v.iter()
                .any(|x| x.kind == ViolationKind::NotPortUnreachable),
            "a reject must name icmp(x) port-unreachable: {v:?}"
        );
    }

    #[test]
    fn non_udp_443_lines_are_ignored() {
        // A tcp/443 accept and a udp/53 redirect are not this rule.
        let txt = "tcp dport 443 accept\n  udp dport 53 redirect to :5353\n";
        assert!(check_text("x.nft", txt).is_empty());
        // ...and with no udp/443 rule present, the convenience wrapper is false.
        assert!(!satisfies_quic_reject_shape("x.nft", txt));
    }

    #[test]
    fn icmpv6_port_unreachable_also_passes() {
        let txt =
            "meta l4proto udp udp dport 443 counter reject with icmpv6 type port-unreachable\n";
        assert!(check_text("v6.nft", txt).is_empty());
    }

    #[test]
    fn comments_do_not_smuggle_a_verdict() {
        // A `reject ... port-unreachable` only in a comment must not satisfy a
        // rule that actually drops.
        let txt =
            "udp dport 443 counter drop # should be reject with icmpx type port-unreachable\n";
        let v = check_text("c.nft", txt);
        assert!(v.iter().any(|x| x.kind == ViolationKind::SilentDrop));
    }

    // ── R1: nft `comment "..."` keyword cannot smuggle verdict/type tokens ──
    #[test]
    fn comment_keyword_cannot_smuggle_port_unreachable() {
        // A BARE `reject` (no real `with icmp ... port-unreachable` verdict) whose
        // comment STRING names `icmp port-unreachable` must NOT pass on the
        // strength of the comment tokens. Before R1 the `comment "..."` clause was
        // tokenized verbatim and satisfied has_port_unreachable.
        let txt = "udp dport 443 counter reject comment \"use icmp type port-unreachable\"\n";
        let v = check_text("c.nft", txt);
        assert!(
            v.iter()
                .any(|x| x.kind == ViolationKind::NotPortUnreachable),
            "a bare reject must stay NotPortUnreachable even when its comment names port-unreachable: {v:?}"
        );
        assert!(!satisfies_quic_reject_shape("c.nft", txt));
    }

    #[test]
    fn comment_keyword_cannot_smuggle_a_reject_onto_a_drop() {
        // A udp/443 rule that DROPS, with a comment string naming `reject ...
        // port-unreachable`, must still be a SilentDrop — the comment's `reject`
        // token must not launder the drop into a compliant reject.
        let txt =
            "udp dport 443 counter drop comment \"should be reject with icmpx type port-unreachable\"\n";
        let v = check_text("c.nft", txt);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::SilentDrop),
            "a drop must stay SilentDrop even when its comment names a reject verdict: {v:?}"
        );
    }

    #[test]
    fn unterminated_comment_keyword_string_is_fail_closed() {
        // An unterminated `comment "` opener drops the rest of the line — so a
        // would-be port-unreachable verdict hidden after an unclosed comment quote
        // cannot rescue a bare reject. The udp/443 rule stays NotPortUnreachable.
        let txt = "udp dport 443 counter reject comment \"icmpx type port-unreachable\n";
        let v = check_text("c.nft", txt);
        assert!(
            v.iter()
                .any(|x| x.kind == ViolationKind::NotPortUnreachable),
            "an unterminated comment string must be dropped fail-closed: {v:?}"
        );
    }

    #[test]
    fn comment_keyword_does_not_break_a_genuinely_compliant_rule() {
        // The keyword strip must not red a rule whose REAL verdict is the
        // compliant reject+icmpx+counter shape — the comment is only annotation.
        let txt =
            "udp dport 443 counter reject with icmpx type port-unreachable comment \"quic blocked\"\n";
        assert!(
            check_text("ok.nft", txt).is_empty(),
            "a genuinely compliant rule with a trailing comment clause must pass"
        );
        assert!(satisfies_quic_reject_shape("ok.nft", txt));
    }

    // ── R2: verdict-aware anti-permit (accept on a reject control fails) ──
    #[test]
    fn accept_mixed_with_reject_is_a_permit_violation() {
        // A contradictory `counter accept reject with icmpx type port-unreachable`:
        // the reject/port-unreachable/counter tokens are all present, so the
        // shape checks alone read compliant — but `accept` wins at runtime and the
        // reject is dead. R2 fails closed on the permit verdict.
        let txt = "udp dport 443 counter accept reject with icmpx type port-unreachable\n";
        let v = check_text("p.nft", txt);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::PermitVerdict),
            "an accept on a udp/443 reject control must be a PermitVerdict violation: {v:?}"
        );
        assert!(!satisfies_quic_reject_shape("p.nft", txt));
    }

    #[test]
    fn bare_accept_on_udp443_is_a_permit_violation() {
        // A plain `udp dport 443 counter accept` PERMITS QUIC outright.
        let txt = "udp dport 443 counter accept\n";
        let v = check_text("p.nft", txt);
        assert!(v.iter().any(|x| x.kind == ViolationKind::PermitVerdict));
    }

    // ── R3: `;`-joined permissive second statement is evaluated on its own ──
    #[test]
    fn semicolon_joined_permissive_second_statement_is_caught() {
        // A compliant first statement followed by a `;`-joined permissive second
        // udp/443 statement: before R3 they collapsed into one bag and the stray
        // accept was invisible. Now the second statement is its own token bag and
        // trips the anti-permit guard.
        let txt = "udp dport 443 counter reject with icmpx type port-unreachable; udp dport 443 counter accept\n";
        let v = check_text("s.nft", txt);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::PermitVerdict),
            "a `;`-joined permissive second udp/443 statement must be caught: {v:?}"
        );
        assert!(!satisfies_quic_reject_shape("s.nft", txt));
    }

    #[test]
    fn semicolon_joined_drop_second_statement_is_caught() {
        // The second statement is a silent drop — it must be flagged on its own,
        // not laundered by the compliant first statement.
        let txt =
            "udp dport 443 counter reject with icmpx type port-unreachable; udp dport 443 drop\n";
        let v = check_text("s.nft", txt);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::SilentDrop),
            "a `;`-joined drop second statement must be SilentDrop: {v:?}"
        );
    }

    #[test]
    fn semicolon_inside_a_quoted_log_prefix_is_not_a_separator() {
        // A `;` inside a quoted log-prefix string must NOT split the statement —
        // the single compliant rule stays compliant.
        let txt = "udp dport 443 counter log prefix \"quic; blocked \" reject with icmpx type port-unreachable\n";
        assert!(
            check_text("q.nft", txt).is_empty(),
            "a `;` inside a quoted log prefix must not be a statement separator"
        );
    }

    #[test]
    fn the_governed_reason_is_quic_blocked_distinct_from_default_deny() {
        // The on-box shape this predicate governs feeds exactly the off-box
        // QuicBlocked carveout — never generic default-deny.
        assert_eq!(
            ViolationKind::SilentDrop.reject_reason(),
            RejectReason::QuicBlocked
        );
        assert_ne!(
            ViolationKind::MissingCounter.reject_reason(),
            RejectReason::DefaultDeny
        );
    }

    // ── The composer renderer: single source for the floor's QUIC reject ──

    #[test]
    fn rendered_floor_rule_satisfies_its_own_shape_lint() {
        // The renderer's output must pass the very shape predicate this module
        // enforces — ds-nft cannot emit a rule it would itself flag (the
        // single-source-cannot-drift invariant). It also carries the
        // session-tap anchor and the `ct state new` narrowing.
        let rule = floor_quic_reject_rule();
        assert!(
            check_text("rendered", rule).is_empty(),
            "the composer's rendered floor reject must be shape-compliant: {:?}",
            check_text("rendered", rule)
        );
        assert!(satisfies_quic_reject_shape("rendered", rule));
        assert!(
            anchors_on_dstap(&rule.to_ascii_lowercase()),
            "the rendered rule must anchor on the dstap-* tap"
        );
        assert!(
            !matches_source_ip(&rule.to_ascii_lowercase()),
            "the rendered rule must never key on the forgeable source IP"
        );
        assert!(
            rule.to_ascii_lowercase().contains("ct state new"),
            "the rendered rule must be `ct state new`-scoped so admitted streams survive"
        );
    }

    #[test]
    fn rendered_floor_rule_feeds_the_quic_blocked_reason() {
        // The on-box rule the composer emits and the off-box reason it feeds are
        // the SAME control — QuicBlocked, never generic default-deny (D70).
        assert_eq!(floor_quic_reject_reason(), RejectReason::QuicBlocked);
        assert_ne!(floor_quic_reject_reason(), RejectReason::DefaultDeny);
        assert!(
            floor_quic_reject_reason().is_quic_carveout(),
            "the floor reject feeds the flip-to-inspect QUIC carveout"
        );
    }

    // ── The composition-order guard (the un-shadowing fix, 01KTZV3XN) ──

    /// The floor `forward` chain in the un-shadowed (correct) order: the udp/443
    /// reject precedes the terminal `ct state new drop`.
    const FLOOR_REJECT_BEFORE_DROP: &str = "\
table inet ds_boundary {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    iifname \"dstap-*\" ct state new udp dport 443 counter reject with icmpx type port-unreachable
    iifname \"dstap-*\" ct state new drop
  }
}
";

    /// The SHADOWED (regression) order: the terminal `ct state new drop` precedes
    /// the udp/443 reject, so a NEW QUIC packet is dropped before the reject runs.
    const FLOOR_DROP_BEFORE_REJECT: &str = "\
table inet ds_boundary {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    iifname \"dstap-*\" ct state new drop
    iifname \"dstap-*\" ct state new udp dport 443 counter reject with icmpx type port-unreachable
  }
}
";

    #[test]
    fn unshadowed_floor_order_is_reject_reachable() {
        assert_eq!(
            floor_quic_reject_composition("floor.nft", FLOOR_REJECT_BEFORE_DROP),
            FloorComposition::RejectReachable
        );
        assert!(floor_quic_reject_is_unshadowed(
            "floor.nft",
            FLOOR_REJECT_BEFORE_DROP
        ));
    }

    #[test]
    fn drop_before_reject_is_shadowed_the_d70_regression() {
        // The precise regression D70 / 01KTZV3XN: a terminal `ct state new drop`
        // ahead of the reject shadows it (drop is terminal across base chains), so
        // QUIC is SILENTLY DROPPED, not rejected. The guard must catch it.
        assert_eq!(
            floor_quic_reject_composition("floor.nft", FLOOR_DROP_BEFORE_REJECT),
            FloorComposition::RejectShadowedByDrop
        );
        assert!(!floor_quic_reject_is_unshadowed(
            "floor.nft",
            FLOOR_DROP_BEFORE_REJECT
        ));
    }

    #[test]
    fn the_rendered_rule_placed_before_the_floor_drop_is_reachable() {
        // Compose the floor from the renderer itself: the composer's rule, placed
        // before the terminal drop, is reachable — the composer is internally
        // consistent with the guard.
        let composed = format!(
            "chain forward {{\n  ct state established,related accept\n  {reject}\n  iifname \"dstap-*\" ct state new drop\n}}\n",
            reject = floor_quic_reject_rule(),
        );
        assert!(floor_quic_reject_is_unshadowed("composed", &composed));
    }

    #[test]
    fn a_fragment_with_no_quic_rule_is_no_quic_rule() {
        let txt = "chain forward {\n  iifname \"dstap-*\" ct state new drop\n}\n";
        assert_eq!(
            floor_quic_reject_composition("x.nft", txt),
            FloorComposition::NoQuicRule
        );
        assert!(!floor_quic_reject_is_unshadowed("x.nft", txt));
    }

    #[test]
    fn an_unanchored_floor_reject_is_non_compliant() {
        // A udp/443 reject with the right SHAPE but missing the `dstap-*` anchor is
        // not a compliant floor reject (it is not scoped to the unforgeable session
        // tap) — the composition guard reports RejectNonCompliant, not Reachable.
        let txt =
            "chain forward {\n  udp dport 443 counter reject with icmpx type port-unreachable\n}\n";
        assert_eq!(
            floor_quic_reject_composition("x.nft", txt),
            FloorComposition::RejectNonCompliant
        );
    }

    #[test]
    fn a_source_ip_matched_floor_reject_is_non_compliant() {
        // Keying the reject on the FORGEABLE source IP (doc 06 (c) in-VM-spoofing)
        // is non-compliant even though the verdict shape is right.
        let txt = "chain forward {\n  ip saddr 10.0.0.5 udp dport 443 counter reject with icmpx type port-unreachable\n}\n";
        assert_eq!(
            floor_quic_reject_composition("x.nft", txt),
            FloorComposition::RejectNonCompliant
        );
    }

    #[test]
    fn a_silently_dropped_quic_rule_is_non_compliant() {
        // A udp/443 rule that DROPS (not rejects) — the floor reject is the D70
        // failure regardless of ordering.
        let txt =
            "chain forward {\n  iifname \"dstap-*\" ct state new udp dport 443 counter drop\n}\n";
        assert_eq!(
            floor_quic_reject_composition("x.nft", txt),
            FloorComposition::RejectNonCompliant
        );
    }

    // ── The shipped artifacts: the composition guard with TEETH ──
    //
    // These read the REAL shipped NFT-1 / NFT-4 artifacts (the un-shadowing fix
    // landed there) and prove, kernel-free, that the live floor reject is present,
    // compliant, anchored, and ORDERED before the terminal drop — the empirical
    // refutation of the shadowing regression the per-rule lint could not see.

    /// The repo path to a shipped nft artifact. CARGO_MANIFEST_DIR =
    /// .../dataplane/crates/ds-nft (same idiom as tests/nft2_redirect.rs).
    fn artifact_path(name: &str) -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop(); // crates
        p.pop(); // dataplane
        p.push("artifacts");
        p.push("nft");
        p.push(name);
        p
    }

    #[test]
    fn shipped_nft1_floor_reject_is_unshadowed() {
        // The LIVE reject rides NFT-1's forward chain BEFORE its terminal
        // `ct state new drop`. The composition guard must confirm it is reachable
        // against the real artifact — the regression guard for 01KTZV3XN / D70.
        let path = artifact_path("nft-1-bootstrap.nft");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let verdict = floor_quic_reject_composition(&path.display().to_string(), &text);
        assert_eq!(
            verdict,
            FloorComposition::RejectReachable,
            "the shipped NFT-1 floor's udp/443 reject must be reachable (un-shadowed) — D70/01KTZV3XN; got {verdict:?}"
        );
        // And the reject rule the floor carries is exactly the composer's
        // single-source rendering (no drift between artifact and renderer).
        assert!(
            text.contains(floor_quic_reject_rule()),
            "the shipped NFT-1 floor reject must be the composer's single-source rule line"
        );
    }

    #[test]
    fn shipped_nft4_keeps_a_compliant_defense_in_depth_reject() {
        // NFT-4 keeps an identical reject as defense-in-depth (the conformance/lint
        // ownership home). Its udp/443 rule must still be shape-compliant.
        let path = artifact_path("nft-4-resolver-closure.nft");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            satisfies_quic_reject_shape(&path.display().to_string(), &text),
            "the shipped NFT-4 defense-in-depth udp/443 reject must be shape-compliant"
        );
    }
}
