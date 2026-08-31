//! NFT-1 mark-discipline lint (doc 14 §5, D76 — the Tailscale PR-5606 lesson).
//!
//! Scans nftables ruleset text and fails on any mark-discipline violation:
//!
//! 1. **Unclaimed bits 14–23.** Any mark literal whose value sets a bit in the
//!    permanently-unclaimed gap ([`crate::mark::UNCLAIMED_MASK`]) — Dream
//!    Serpent never sets and never matches those bits (kube-proxy, Weave,
//!    Tailscale, UniFi live there).
//! 2. **Unmasked / full-register mark writes.** A `meta mark set` / `ct mark
//!    set` that assigns a value without an explicit `& <mask>` clamp on the
//!    same statement — full-register writes are forbidden; the only sanctioned
//!    form is `meta mark set (meta mark & ~DS_MARK_MASK) | <value>`.
//! 3. **Raw mark literals not sourced from `ds-contracts`.** Any hex literal on
//!    a mark statement that is not the frozen [`crate::mark::DS_MARK_MASK`] mask
//!    constant and is not a `@`/`$`-referenced symbol fed from the constants —
//!    mark *values* must come from `ds-contracts`, never be typed inline.
//!
//! Pure-`std` text analysis: this is a contract lint, not an nft parser. It is
//! invoked from a Rust test (`tests/nft_mark_lint.rs`) and from
//! `scripts/lint-nft-artifacts.sh` in CI. It passes on an empty artifacts
//! directory and on a compliant ruleset; the negative fixture lives in the test
//! suite.

use crate::mark::{DS_MARK_MASK, UNCLAIMED_MASK};

/// A single mark-discipline violation found by the lint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The file the violation was found in (as passed to the lint).
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// The offending source line, trimmed.
    pub text: String,
    /// What rule was broken.
    pub kind: ViolationKind,
}

/// The category of a mark-discipline violation (doc 14 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// A mark literal sets a bit in the permanently-unclaimed gap (23–14).
    UnclaimedBits {
        /// The literal as written.
        literal: u32,
        /// The unclaimed bits it set.
        offending: u32,
    },
    /// A mark write with no explicit mask clamp on the statement.
    UnmaskedWrite,
    /// A raw mark literal that is not the sanctioned `DS_MARK_MASK` constant and
    /// is not symbol-referenced from `ds-contracts`.
    RawLiteral {
        /// The literal as written.
        literal: u32,
    },
}

/// Whether a line is a mark statement the lint must inspect: it mentions a mark
/// register (`meta mark`, `ct mark`, or bare `mark`/`fwmark` in a set/match
/// context). Comments are stripped before this is called.
fn is_mark_statement(code: &str) -> bool {
    let l = code.to_ascii_lowercase();
    l.contains("meta mark")
        || l.contains("ct mark")
        || l.contains("fwmark")
        // a bare "mark" token used as a selector/target, not inside a word.
        || l.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|tok| tok == "mark")
}

/// Whether a mark *write* statement carries an explicit mask clamp. The
/// sanctioned form is `meta mark set (meta mark & ~MASK) | value` (or a `& MASK`
/// match); the presence of a `&` bitwise-and on the statement is the discipline
/// signal. Pure clears with no value (`set 0x0`) are not writes we gate.
fn has_mask_clamp(code: &str) -> bool {
    code.contains('&')
}

/// Whether a statement is a mark *write* (assigns the register) rather than a
/// match (compares it). `set` is the nft assignment keyword.
fn is_mark_write(code: &str) -> bool {
    code.split_whitespace().any(|tok| tok == "set")
}

/// Strip a trailing `#`-comment from an nft line, returning the code part.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Parse every hex literal (`0x...`) on a line into `(text, value)`.
fn hex_literals(code: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let bytes = code.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'0' && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            let start = i;
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > i + 2 {
                let text = &code[start..j];
                if let Ok(v) = u32::from_str_radix(&text[2..], 16) {
                    out.push((text.to_string(), v));
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Lint a single ruleset's text. `file` is used only for reporting. Returns
/// every violation found (empty = clean).
pub fn lint_text(file: &str, text: &str) -> Vec<Violation> {
    let mut violations = Vec::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let code = strip_comment(raw_line);
        if !is_mark_statement(code) {
            continue;
        }

        let literals = hex_literals(code);
        let is_write = is_mark_write(code);

        // 2. Unmasked / full-register write: a write that assigns a value with
        //    no `&` clamp anywhere on the statement.
        if is_write && !has_mask_clamp(code) && !literals.is_empty() {
            violations.push(Violation {
                file: file.to_string(),
                line: line_no,
                text: code.trim().to_string(),
                kind: ViolationKind::UnmaskedWrite,
            });
        }

        for (lit_text, value) in &literals {
            // 1. Unclaimed bits 14–23 — always a violation, mask or no mask.
            let offending = value & UNCLAIMED_MASK;
            if offending != 0 {
                violations.push(Violation {
                    file: file.to_string(),
                    line: line_no,
                    text: code.trim().to_string(),
                    kind: ViolationKind::UnclaimedBits {
                        literal: *value,
                        offending,
                    },
                });
                // an unclaimed-bits literal is reported once; still check the
                // remaining literals on the line.
                continue;
            }

            // 3. Raw mark literal not sourced from ds-contracts. The ONLY hex
            //    literal allowed to appear inline is the frozen DS_MARK_MASK
            //    (and its inverse `~DS_MARK_MASK`, same magnitude) — mask
            //    constants are structural, not "values". Mark *values* must
            //    come through a named symbol (`@set`, `$define`), never a raw
            //    literal.
            if *value != DS_MARK_MASK {
                let _ = lit_text;
                violations.push(Violation {
                    file: file.to_string(),
                    line: line_no,
                    text: code.trim().to_string(),
                    kind: ViolationKind::RawLiteral { literal: *value },
                });
            }
        }
    }

    violations
}

/// Lint every `*.nft` file under `dir` (recursively). A missing or empty
/// directory is clean — the lint passes on an empty artifacts dir by design
/// (the ruleset is authored in a parallel task; doc 14 §5 note). Returns every
/// violation across all files, or an `io::Error` if the directory walk itself
/// fails.
pub fn lint_dir(dir: &std::path::Path) -> std::io::Result<Vec<Violation>> {
    let mut violations = Vec::new();
    if !dir.exists() {
        return Ok(violations);
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("nft") {
                let text = std::fs::read_to_string(&path)?;
                violations.extend(lint_text(&path.display().to_string(), &text));
            }
        }
    }
    Ok(violations)
}

// ─────────────────────────────────────────────────────────────────────────
//  Composition-order lint: cross-base-chain terminal-verdict reachability.
// ─────────────────────────────────────────────────────────────────────────
//
// The mark lint above judges single rules in isolation. THIS lint judges the
// EFFECTIVE ruleset that emerges when several base chains layer on one hook.
//
// The defect class (taskdb 01KTZV3XN / 01KV8YYA7N): the boundary closures do
// NOT insert into one shared chain — each ships its OWN `inet` table with a base
// chain on a hook at a DISTINCT priority (NFT-1 `forward` priority filter / 0;
// NFT-4 `forward` priority 1; the NFT-2b redirect / NFT-3 allow-set / NFT-5
// ct-mark closures the same way). nftables runs every base chain on a hook in
// ASCENDING priority order, and a `drop` verdict is TERMINAL across chains (an
// `accept` is NOT — it ends THAT chain but the packet still traverses the later
// chains on the hook). So a closure's declared terminal verdict, authored in a
// LATER-priority chain, is SILENTLY PRE-EMPTED if an EARLIER-priority chain
// already terminally `drop`s a packet on an OVERLAPPING selector — the verdict
// never fires. The per-rule shape lints cannot see this: each rule is
// individually compliant; the gap is the cross-base-chain ORDER.
//
// The first confirmed instance is the QUIC reject — NFT-4's forward-priority-1
// `udp/443 reject` shadowed by NFT-1's forward-priority-0 `ct state new drop`
// (D70: QUIC must be REJECTED, not silently dropped). The `ds-nft`
// `quic_reject` module is the QUIC-specialized caller of this general predicate
// (it supplies the udp/443 selector + the `ct state new drop` terminal), so the
// two readers cannot drift — the same single-source discipline `ds-nft` follows
// for the allow-set name. The check is parameterized over
// `(priority, selector-predicate, declared-terminal-verdict)`, NOT hardcoded to
// udp/443, so it generalizes to the NFT-2b 80/443 redirect, NFT-3 allow-sets,
// and NFT-5 ct-mark closures named in the task body.
//
// Pure-`std` text analysis, kernel-free — the same contract-lint discipline the
// mark lint and the `ds-nft` shape lints use. It models nft's base-chain merge,
// not the packet path; the live-kernel proof (a real packet getting the
// declared verdict) is the CAP_NET_ADMIN conformance row.

/// A base-chain's hook (the nftables hook a `type ... hook <H> priority <P>`
/// declaration binds to). Only the hooks the boundary closures use are modelled;
/// an unrecognised hook keyword is carried verbatim so two chains on the SAME
/// unknown hook still merge (string equality), but never collide with a known one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Hook {
    /// `hook input`.
    Input,
    /// `hook forward` — where the floor default-deny drop and the udp/443 reject
    /// live (the first confirmed shadowing instance).
    Forward,
    /// `hook output` — the NFT-3b proxy-egress containment hook.
    Output,
    /// `hook prerouting` — the NFT-2 / NFT-2b redirect hook.
    Prerouting,
    /// `hook postrouting`.
    Postrouting,
    /// A hook keyword outside the modelled set, carried verbatim.
    Other(String),
}

impl Hook {
    fn from_keyword(kw: &str) -> Hook {
        match kw {
            "input" => Hook::Input,
            "forward" => Hook::Forward,
            "output" => Hook::Output,
            "prerouting" => Hook::Prerouting,
            "postrouting" => Hook::Postrouting,
            other => Hook::Other(other.to_string()),
        }
    }
}

/// Resolve an nft priority token — a standard alias (`filter`, `dstnat`, …), a
/// bare signed integer, or an alias/integer with a `+ N` / `- N` adjustment
/// (`filter + 1`, `dstnat - 1`) — to its numeric value. nft chains merge in
/// ASCENDING priority, so this number is the only thing that orders two chains
/// on the same hook. Returns `None` if the token is not a priority we can resolve
/// (the chain is then treated conservatively as priority 0, the filter default).
fn resolve_priority(tokens: &[&str]) -> Option<i64> {
    // The first token is the alias/number; an optional `+`/`-` and an integer
    // follow. nft also accepts `filter+1` with no spaces — handle both.
    let alias_value = |s: &str| -> Option<i64> {
        match s {
            "raw" => Some(-300),
            "mangle" => Some(-150),
            "dstnat" => Some(-100),
            "filter" => Some(0),
            "security" => Some(50),
            "srcnat" => Some(100),
            "out" => Some(0), // nft `priority out` alias (output filter)
            _ => s.parse::<i64>().ok(),
        }
    };

    let first = tokens.first()?;
    // Spaced form: `filter + 1`.
    if tokens.len() >= 3 {
        if let (Some(base), op) = (alias_value(first), tokens[1]) {
            if let Ok(delta) = tokens[2].parse::<i64>() {
                return match op {
                    "+" => Some(base + delta),
                    "-" => Some(base - delta),
                    _ => Some(base),
                };
            }
        }
    }
    // No-space form: `filter+1` / `filter-1` / `-101`.
    if let Some(base) = alias_value(first) {
        return Some(base);
    }
    for (i, c) in first.char_indices() {
        if (c == '+' || c == '-') && i > 0 {
            if let (Some(base), Ok(delta)) =
                (alias_value(&first[..i]), first[i + 1..].parse::<i64>())
            {
                return Some(if c == '+' { base + delta } else { base - delta });
            }
        }
    }
    None
}

/// One base chain extracted from the merged ruleset text: which hook + priority
/// it binds to, and the rule statements it carries IN ORDER. Built by
/// [`parse_base_chains`]; consumed by [`check_terminal_verdict_reachable`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseChain {
    /// The hook this chain binds to.
    pub hook: Hook,
    /// The numeric priority (lower runs first); the merge orders on this.
    pub priority: i64,
    /// The 1-based source line of the `type ... hook ...` declaration.
    pub decl_line: usize,
    /// Each rule statement, in source order, as `(line_no, lowercased_code)`.
    pub rules: Vec<(usize, String)>,
}

/// Parse the merged ruleset text into its BASE chains (chains carrying a
/// `type ... hook <H> priority <P>` declaration). Regular (non-base) chains have
/// no hook and never participate in the cross-hook merge, so they are skipped.
///
/// This is a contract lint, not an nft parser: it tracks `{`/`}` nesting depth so
/// rule statements are attributed to the chain that encloses them, strips
/// `#`-comments, and lowercases rule text for the selector/verdict scans. The
/// `type ... hook ... priority ...;` line itself is the declaration, not a rule.
pub fn parse_base_chains(text: &str) -> Vec<BaseChain> {
    let mut chains = Vec::new();
    let mut current: Option<BaseChain> = None;
    // Depth tracking: a base chain's rules live exactly one brace-level inside
    // the chain header.
    let mut chain_depth: i64 = 0;
    let mut depth: i64 = 0;

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let code = strip_comment(raw_line);
        let trimmed = code.trim();
        let code_lc = code.to_ascii_lowercase();

        // The base-chain declaration line: `type <t> hook <h> priority <p>;`. We
        // only treat it as one when the line actually begins `type ` (so a `hook`
        // token inside a comment-stripped rule does not masquerade as a decl).
        let is_base_decl = code_lc.trim_start().starts_with("type ") && code_lc.contains("hook ");

        if is_base_decl {
            // Flush any prior base chain before starting this one.
            if let Some(c) = current.take() {
                chains.push(c);
            }
            let hook_pos = code_lc.find("hook ").unwrap();
            let after_hook = &code_lc[hook_pos + "hook ".len()..];
            let hook_kw = after_hook.split_whitespace().next().unwrap_or("");
            let hook = Hook::from_keyword(hook_kw);
            let priority = match code_lc.find("priority ") {
                Some(p) => {
                    let after = &code_lc[p + "priority ".len()..];
                    // Priority runs up to the `;` / end-of-line.
                    let end = after.find(';').unwrap_or(after.len());
                    let pri_str = &after[..end];
                    let toks: Vec<&str> = pri_str.split_whitespace().collect();
                    resolve_priority(&toks).unwrap_or(0)
                }
                None => 0,
            };
            current = Some(BaseChain {
                hook,
                priority,
                decl_line: line_no,
                rules: Vec::new(),
            });
            // The decl line sits at the chain body's depth; rules are at the same
            // depth (one inside the `chain { ... }` braces).
            chain_depth = depth;
        } else if let Some(c) = current.as_mut() {
            // A rule line inside the active base chain: at the chain body depth,
            // non-empty, not a brace-only or `policy ...;`-only line.
            if depth == chain_depth
                && !trimmed.is_empty()
                && trimmed != "}"
                && trimmed != "{"
                && !trimmed.starts_with("policy ")
            {
                c.rules.push((line_no, code_lc.trim().to_string()));
            }
        }

        // Brace accounting (after the line is classified): a `chain {` raises
        // depth; the matching `}` lowers it and, at chain_depth, closes the chain.
        let opens = code.matches('{').count() as i64;
        let closes = code.matches('}').count() as i64;
        depth += opens;
        depth -= closes;
        if closes > 0 && current.is_some() && depth < chain_depth {
            chains.push(current.take().unwrap());
        }
    }
    if let Some(c) = current.take() {
        chains.push(c);
    }
    chains
}

/// A claim a caller makes about the effective ruleset: the rule matching
/// `claim_selector` on `hook` carries a DECLARED TERMINAL VERDICT that MUST be
/// reachable — i.e. must not be pre-empted by an earlier-priority terminal `drop`
/// on an overlapping selector. The QUIC caller supplies the udp/443 selector
/// against the floor's `ct state new drop`; the same shape serves the NFT-2b
/// 80/443 redirect, NFT-3 allow-sets, and NFT-5 ct-mark closures.
///
/// `claim_selector` and `shadowing_selector` are predicates over a lowercased
/// rule line. `claim_selector` identifies the protected verdict line;
/// `shadowing_selector` identifies an EARLIER terminal `drop` whose selector
/// OVERLAPS the claim (i.e. could also match the same packets) — only an
/// overlapping drop shadows. Keeping both as closures means the overlap relation
/// is the caller's to define precisely (the lint never guesses port/selector
/// containment it cannot prove).
pub struct TerminalVerdictClaim<'a> {
    /// The hook the claim and any shadowing drop both live on.
    pub hook: Hook,
    /// A human label for the claim, used in the violation message.
    pub label: &'a str,
    /// Identifies the protected verdict rule line (lowercased).
    pub claim_selector: &'a dyn Fn(&str) -> bool,
    /// Identifies an earlier terminal `drop` whose selector overlaps the claim.
    pub shadowing_selector: &'a dyn Fn(&str) -> bool,
}

/// A composition-order violation: a declared terminal verdict pre-empted in the
/// effective (priority-merged) ruleset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositionViolation {
    /// The claim label (from [`TerminalVerdictClaim::label`]).
    pub label: String,
    /// The hook the shadowing happened on.
    pub hook: Hook,
    /// The priority of the chain carrying the EARLIER terminal `drop`.
    pub shadowing_priority: i64,
    /// The priority of the chain carrying the shadowed declared verdict.
    pub claim_priority: i64,
    /// The selector text of the shadowing drop (for the message).
    pub shadowing_rule: String,
}

/// The reachability verdict for one [`TerminalVerdictClaim`] against the merged
/// base chains of `text`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reachability {
    /// The declared terminal verdict is reachable: no earlier-priority terminal
    /// `drop` on an overlapping selector pre-empts it.
    Reachable,
    /// No rule matching `claim_selector` is present on the hook at all — the
    /// closure that should author the verdict is absent (neither reachable nor
    /// shadowed; the caller decides whether absence is itself an error).
    ClaimAbsent,
    /// The declared terminal verdict is SHADOWED by an earlier-priority terminal
    /// `drop` on an overlapping selector — it never fires in the effective
    /// ruleset.
    Shadowed(CompositionViolation),
}

/// Whether a lowercased rule line carries a terminal `drop` verdict (terminal
/// across base chains). Word-boundary match so `dropped` / a `drop` inside a
/// comment-stripped log prefix is not it.
fn line_is_terminal_drop(code_lc: &str) -> bool {
    code_lc
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|tok| tok == "drop")
}

/// Decide whether a claimed terminal verdict is REACHABLE in the effective
/// ruleset that emerges from merging the base chains of `text` on the claim's
/// hook in ascending priority.
///
/// The model (faithful to nft): collect every base chain on the claim's hook,
/// sort by priority; the effective rule sequence on the hook is those chains
/// concatenated in priority order, each chain's rules in source order. The
/// claimed verdict is SHADOWED iff some EARLIER point in that sequence (strictly
/// lower priority, OR same priority but earlier in source) is a terminal `drop`
/// whose selector overlaps the claim. A `drop` is terminal across chains; an
/// `accept` is not, so accepts never shadow.
pub fn check_terminal_verdict_reachable(text: &str, claim: &TerminalVerdictClaim) -> Reachability {
    let mut chains: Vec<BaseChain> = parse_base_chains(text)
        .into_iter()
        .filter(|c| c.hook == claim.hook)
        .collect();
    chains.sort_by_key(|c| c.priority);

    // The effective sequence on the hook: (priority, code) in merge order.
    // Within equal priority nft's resolution is registration order; we
    // approximate it with source order, which is what the artifacts assume.
    let mut seq: Vec<(i64, &str)> = Vec::new();
    for c in &chains {
        for (_ln, code) in &c.rules {
            seq.push((c.priority, code.as_str()));
        }
    }

    let mut shadowing: Option<(i64, &str)> = None;
    for (pri, code) in &seq {
        if (claim.claim_selector)(code) {
            // Reached the claimed verdict. If an overlapping terminal drop
            // appeared earlier, it is shadowed; otherwise reachable.
            return match shadowing {
                Some((spri, srule)) => Reachability::Shadowed(CompositionViolation {
                    label: claim.label.to_string(),
                    hook: claim.hook.clone(),
                    shadowing_priority: spri,
                    claim_priority: *pri,
                    shadowing_rule: srule.to_string(),
                }),
                None => Reachability::Reachable,
            };
        }
        // Track the FIRST earlier terminal drop on an overlapping selector. Only
        // a real terminal `drop` shadows (accept does not); only one whose
        // selector overlaps the claim per the caller's relation.
        if shadowing.is_none() && line_is_terminal_drop(code) && (claim.shadowing_selector)(code) {
            shadowing = Some((*pri, code));
        }
    }

    Reachability::ClaimAbsent
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mark::{compose, Leg};

    #[test]
    fn empty_text_is_clean() {
        assert!(lint_text("x.nft", "").is_empty());
        assert!(lint_text("x.nft", "# just a comment\n").is_empty());
    }

    #[test]
    fn non_mark_lines_are_ignored() {
        let txt = "table inet ds {\n  chain forward { tcp dport 443 accept }\n}\n";
        assert!(lint_text("x.nft", txt).is_empty());
    }

    #[test]
    fn a_compliant_masked_match_passes() {
        // The sanctioned forms: a masked write clamping with ~DS_MARK_MASK, and
        // a masked match against DS_MARK_MASK with a symbol-fed value.
        let mask = format!("0x{DS_MARK_MASK:X}");
        let txt = format!(
            "ct mark set (ct mark & ~{mask}) | @ds_session_mark\n\
             meta mark & {mask} == @ds_session_mark accept\n"
        );
        assert!(
            lint_text("ds.nft", &txt).is_empty(),
            "compliant ruleset must pass"
        );
    }

    #[test]
    fn unmasked_full_register_write_fails() {
        // The PR-5606 lesson: a full-register write with no mask clamp.
        let value = compose(Leg::AgentVm, 7);
        let txt = format!("meta mark set 0x{value:X}\n");
        let v = lint_text("bad.nft", &txt);
        assert!(
            v.iter().any(|x| x.kind == ViolationKind::UnmaskedWrite),
            "unmasked write must be flagged: {v:?}"
        );
    }

    #[test]
    fn unclaimed_bits_make_the_lint_fail() {
        // NEGATIVE FIXTURE (brief verification): a mark literal using bits 14–23
        // must make the lint fail. Bit 16 (Tailscale's territory) is in the gap.
        let mask = format!("0x{DS_MARK_MASK:X}");
        let bad = 0xD000_0000u32 | (1u32 << 16); // magic + an unclaimed bit
        let txt = format!("ct mark set (ct mark & ~{mask}) | 0x{bad:X}\n");
        let v = lint_text("bad.nft", &txt);
        assert!(
            v.iter().any(|x| matches!(
                x.kind,
                ViolationKind::UnclaimedBits { offending, .. } if offending == (1 << 16)
            )),
            "bits 14–23 must fail the lint: {v:?}"
        );
    }

    #[test]
    fn every_bit_in_the_gap_is_caught() {
        let mask = format!("0x{DS_MARK_MASK:X}");
        for bit in 14..=23u32 {
            let bad = 0xD000_0000u32 | (1u32 << bit);
            let txt = format!("meta mark & {mask} == 0x{bad:X} accept\n");
            let v = lint_text("g.nft", &txt);
            assert!(
                v.iter()
                    .any(|x| matches!(x.kind, ViolationKind::UnclaimedBits { .. })),
                "bit {bit} in the unclaimed gap must be caught"
            );
        }
    }

    #[test]
    fn raw_inline_value_literal_is_flagged() {
        // A mark value typed inline (not symbol-fed from ds-contracts) is a
        // RawLiteral violation even when masked and even though it touches no
        // unclaimed bit.
        let mask = format!("0x{DS_MARK_MASK:X}");
        let value = compose(Leg::TlsproxyUpstream, 3); // clean, no gap bits
        assert_eq!(value & UNCLAIMED_MASK, 0);
        let txt = format!("ct mark set (ct mark & ~{mask}) | 0x{value:X}\n");
        let v = lint_text("raw.nft", &txt);
        assert!(
            v.iter()
                .any(|x| matches!(x.kind, ViolationKind::RawLiteral { .. })),
            "an inline mark value must be flagged as a raw literal: {v:?}"
        );
    }

    #[test]
    fn the_mask_constant_itself_is_not_a_raw_literal() {
        // DS_MARK_MASK appearing inline is structural, not a "value".
        let mask = format!("0x{DS_MARK_MASK:X}");
        let txt = format!("meta mark & {mask} == @ds_mark accept\n");
        let v = lint_text("ok.nft", &txt);
        assert!(v.is_empty(), "the mask constant is allowed inline: {v:?}");
    }

    #[test]
    fn missing_directory_is_clean() {
        let p = std::path::Path::new("/nonexistent/dir/for/ds/lint/test");
        assert_eq!(lint_dir(p).unwrap(), vec![]);
    }

    // ── Composition-order lint: cross-base-chain terminal-verdict reachability ──

    /// Two `forward` base chains modelling the floor (priority 0, a terminal
    /// `ct state new drop`) and a later closure (priority 1, a udp/443 verdict).
    /// Parameterised so a test can put the closure's verdict BEFORE or AFTER the
    /// floor drop and toggle the verdict word.
    fn two_forward_chains(reject_before_drop: bool, closure_verdict: &str) -> String {
        let floor_drop = "    iifname \"dstap-*\" ct state new drop";
        let closure =
            format!("    iifname \"dstap-*\" ct state new udp dport 443 counter {closure_verdict}");
        let (p0_extra, p1) = if reject_before_drop {
            // The reject in the FLOOR (priority 0) before its own drop.
            (format!("{closure}\n{floor_drop}"), String::new())
        } else {
            // The reject ONLY in the later-priority (1) chain — shadowed by the
            // floor drop at priority 0.
            (floor_drop.to_string(), closure)
        };
        format!(
            "table inet ds_boundary {{\n  \
               chain forward {{\n    \
                 type filter hook forward priority filter; policy drop;\n    \
                 ct state established,related accept\n{p0_extra}\n  \
               }}\n}}\n\
             table inet ds_resolver_closure {{\n  \
               chain resolver_closure_forward {{\n    \
                 type filter hook forward priority 1; policy accept;\n{p1}\n  \
               }}\n}}\n"
        )
    }

    fn udp443_claim<'a>() -> TerminalVerdictClaim<'a> {
        TerminalVerdictClaim {
            hook: Hook::Forward,
            label: "udp/443 QUIC reject",
            claim_selector: &|c: &str| c.contains("dport 443") && c.contains("reject"),
            // The floor's catch-all `ct state new drop` overlaps any new udp/443.
            shadowing_selector: &|c: &str| c.contains("ct state new") && !c.contains("dport"),
        }
    }

    #[test]
    fn priority_resolution_handles_aliases_and_arithmetic() {
        assert_eq!(resolve_priority(&["filter"]), Some(0));
        assert_eq!(resolve_priority(&["dstnat"]), Some(-100));
        assert_eq!(resolve_priority(&["filter", "+", "1"]), Some(1));
        assert_eq!(resolve_priority(&["dstnat", "-", "1"]), Some(-101));
        assert_eq!(resolve_priority(&["filter+1"]), Some(1));
        assert_eq!(resolve_priority(&["-101"]), Some(-101));
        assert_eq!(resolve_priority(&["1"]), Some(1));
        assert_eq!(resolve_priority(&["raw"]), Some(-300));
    }

    #[test]
    fn parse_base_chains_splits_two_tables_by_hook_and_priority() {
        let txt = two_forward_chains(false, "reject with icmpx type port-unreachable");
        let chains = parse_base_chains(&txt);
        let fwd: Vec<&BaseChain> = chains.iter().filter(|c| c.hook == Hook::Forward).collect();
        assert_eq!(fwd.len(), 2, "two forward base chains: {chains:#?}");
        let priorities: Vec<i64> = fwd.iter().map(|c| c.priority).collect();
        assert!(
            priorities.contains(&0) && priorities.contains(&1),
            "priorities {priorities:?}"
        );
        // The floor chain (priority 0) carries the established accept + the drop;
        // its `type ... policy drop` decl line is NOT a rule.
        let floor = fwd.iter().find(|c| c.priority == 0).unwrap();
        assert!(
            floor
                .rules
                .iter()
                .all(|(_, r)| !r.starts_with("type ") && !r.starts_with("policy ")),
            "the decl/policy lines must not be rules: {:?}",
            floor.rules
        );
    }

    #[test]
    fn later_priority_verdict_shadowed_by_earlier_terminal_drop() {
        // The exact 01KTZV3XN / D70 class: the udp/443 reject lives ONLY in the
        // priority-1 closure chain, behind the floor's priority-0 terminal drop.
        let txt = two_forward_chains(false, "reject with icmpx type port-unreachable");
        let r = check_terminal_verdict_reachable(&txt, &udp443_claim());
        match r {
            Reachability::Shadowed(v) => {
                assert_eq!(v.shadowing_priority, 0, "the floor drop is priority 0");
                assert_eq!(
                    v.claim_priority, 1,
                    "the reject is in the priority-1 closure"
                );
                assert!(v.shadowing_rule.contains("drop"));
            }
            other => panic!("expected Shadowed, got {other:?}"),
        }
    }

    #[test]
    fn verdict_in_the_floor_before_its_drop_is_reachable() {
        // The landed fix: the reject rides the FLOOR (priority 0) before its own
        // terminal drop — reachable in the effective merge.
        let txt = two_forward_chains(true, "reject with icmpx type port-unreachable");
        assert_eq!(
            check_terminal_verdict_reachable(&txt, &udp443_claim()),
            Reachability::Reachable
        );
    }

    #[test]
    fn an_absent_claim_is_claim_absent_not_shadowed() {
        // No udp/443 reject anywhere: ClaimAbsent (the caller decides if absence
        // is itself an error) — never a false Shadowed.
        let txt = "table inet ds_boundary {\n  chain forward {\n    \
                   type filter hook forward priority filter; policy drop;\n    \
                   iifname \"dstap-*\" ct state new drop\n  }\n}\n";
        assert_eq!(
            check_terminal_verdict_reachable(txt, &udp443_claim()),
            Reachability::ClaimAbsent
        );
    }

    #[test]
    fn an_earlier_accept_does_not_shadow() {
        // An `accept` is NOT terminal across base chains, so a priority-0 accept
        // ahead of a priority-1 verdict does not shadow it (only `drop` does).
        let txt = "table inet a {\n  chain forward {\n    \
                   type filter hook forward priority filter; policy drop;\n    \
                   ct state new accept\n  }\n}\n\
                   table inet b {\n  chain forward {\n    \
                   type filter hook forward priority 1; policy accept;\n    \
                   udp dport 443 counter reject with icmpx type port-unreachable\n  }\n}\n";
        assert_eq!(
            check_terminal_verdict_reachable(txt, &udp443_claim()),
            Reachability::Reachable
        );
    }

    #[test]
    fn a_non_overlapping_earlier_drop_does_not_shadow() {
        // A priority-0 terminal drop whose selector does NOT overlap the claim
        // (here: a tcp/853 DoT drop, no `ct state new` catch-all) must not be read
        // as shadowing the udp/443 reject — only an overlapping drop shadows.
        let txt = "table inet a {\n  chain forward {\n    \
                   type filter hook forward priority filter; policy drop;\n    \
                   iifname \"dstap-*\" tcp dport 853 counter drop\n  }\n}\n\
                   table inet b {\n  chain forward {\n    \
                   type filter hook forward priority 1; policy accept;\n    \
                   iifname \"dstap-*\" ct state new udp dport 443 counter reject with icmpx type port-unreachable\n  }\n}\n";
        assert_eq!(
            check_terminal_verdict_reachable(txt, &udp443_claim()),
            Reachability::Reachable
        );
    }

    #[test]
    fn a_drop_on_a_different_hook_does_not_shadow() {
        // A terminal drop on `prerouting` cannot shadow a `forward` claim — the
        // merge is per-hook. The forward closure verdict stays reachable.
        let txt = "table inet a {\n  chain prerouting {\n    \
                   type nat hook prerouting priority dstnat; policy accept;\n    \
                   iifname \"dstap-*\" ct state new drop\n  }\n}\n\
                   table inet b {\n  chain forward {\n    \
                   type filter hook forward priority 1; policy accept;\n    \
                   iifname \"dstap-*\" ct state new udp dport 443 counter reject with icmpx type port-unreachable\n  }\n}\n";
        assert_eq!(
            check_terminal_verdict_reachable(txt, &udp443_claim()),
            Reachability::Reachable
        );
    }

    #[test]
    fn generalizes_to_an_nft2b_redirect_claim() {
        // The defect class is NOT udp/443-specific. An NFT-2b tcp/80 → proxy
        // redirect authored at a LATER prerouting priority, behind an earlier
        // `iifname dstap-* drop` on prerouting, is equally shadowed — proving the
        // predicate is parameterised, not hardcoded to QUIC.
        let redirect_claim = TerminalVerdictClaim {
            hook: Hook::Prerouting,
            label: "NFT-2b tcp/80 redirect",
            claim_selector: &|c: &str| c.contains("dport 80") && c.contains("redirect"),
            shadowing_selector: &|c: &str| c.contains("iifname") && !c.contains("dport"),
        };
        // Shadowed: the catch-all tap drop at dstnat precedes the redirect at
        // dstnat + 1.
        let shadowed = "table inet a {\n  chain prerouting {\n    \
                        type nat hook prerouting priority dstnat; policy accept;\n    \
                        iifname \"dstap-*\" drop\n  }\n}\n\
                        table inet b {\n  chain prerouting {\n    \
                        type nat hook prerouting priority dstnat + 1; policy accept;\n    \
                        iifname \"dstap-0\" tcp dport 80 redirect to :18080\n  }\n}\n";
        assert!(matches!(
            check_terminal_verdict_reachable(shadowed, &redirect_claim),
            Reachability::Shadowed(_)
        ));
        // Reachable: the redirect at dstnat runs BEFORE the catch-all drop at
        // dstnat + 1.
        let reachable = "table inet b {\n  chain prerouting {\n    \
                         type nat hook prerouting priority dstnat; policy accept;\n    \
                         iifname \"dstap-0\" tcp dport 80 redirect to :18080\n  }\n}\n\
                         table inet a {\n  chain prerouting {\n    \
                         type nat hook prerouting priority dstnat + 1; policy accept;\n    \
                         iifname \"dstap-*\" drop\n  }\n}\n";
        assert_eq!(
            check_terminal_verdict_reachable(reachable, &redirect_claim),
            Reachability::Reachable
        );
    }
}
