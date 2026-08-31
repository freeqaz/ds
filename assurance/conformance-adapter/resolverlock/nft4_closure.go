// SPDX-License-Identifier: Apache-2.0

package resolverlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ── NFT-4 resolver-bypass-closure artifact shape driver ────────────────────────
//
// This is the OFFLINE (gated-off) form of the doc 06 (c) port-53 / DoT / QUIC
// bypass assertions: a stdlib-only reader over the SHIPPED NFT-4 artifact
// (dataplane/artifacts/nft/nft-4-resolver-closure.nft) that proves the three
// resolver-bypass-closure controls D70/NFT-4 (doc 09 §3) are present and shaped
// correctly — WITHOUT a live kernel, live nft, or CAP_NET_ADMIN. It is the
// conformance-adapter companion to the Rust ds-nft contract lints
// (crates/ds-nft/src/quic_reject.rs, crates/ds-nft/src/redirect.rs): the Rust
// side proves the shape predicates have teeth against synthetic fixtures; this
// Go side reads the SAME shipped artifact those predicates govern and asserts
// the doc 06 (c) bypass rows hold over it. One artifact, the offline truth.
//
// The three controls, per doc 09 §3 NFT-4 / D69 / D70:
//
//  1. Port-53 capture observability — the foreign-resolver bypass-attempt
//     counter + nflog rule (D69, round2/04): a session-tap port-53 packet is
//     counted and logged on the unforgeable `iifname` (never `ip saddr`), the
//     bypass-attempt signal ds-flowlog joins to the session. (Delivery itself —
//     the udp/tcp 53 → ds-dnsgate redirect — is NFT-1's prerouting rule, asserted
//     by the Rust redirect lint over nft-1-bootstrap.nft; here we assert NFT-4's
//     observability half is present and iifname-anchored.)
//  2. DNS-over-TLS (853) DROPPED — DoT cannot tunnel resolution past ds-dnsgate.
//  3. udp/443 (QUIC) REJECTED, never silently dropped (D70) — `reject with
//     icmp(x) port-unreachable` + a `counter`, so the refusal is observable and
//     counted per session (the on-box half of the QuicBlocked reason code).
//
// These are the SAME invariants the live half asserts on the wire; offline we
// prove the ruleset that WILL enforce them is shaped right, which is what keeps
// CI honest before the live tier lands.

// nft4ArtifactRelPath is the path from THIS source file to the shipped NFT-4
// resolver-bypass-closure artifact. Anchored off runtime.Caller (same technique
// as ShippedPackPath) so the offline driver works under `go test` from any cwd.
// The read routes THROUGH the tracked in-module symlink testdata/srclinks/… (not
// ../../../dataplane/… directly) so Go's test cache re-hashes the shipped artifact
// on change — see srclinks.go for the test-cache-correctness rationale.
const nft4ArtifactRelPath = "testdata/srclinks/" + srcLinkNFT4Closure

// NFT4ArtifactPath returns the absolute path to the shipped NFT-4
// resolver-bypass-closure ruleset, anchored off this package's source location.
// It is the ONE artifact this offline driver and the Rust ds-nft contract lints
// govern.
func NFT4ArtifactPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return nft4ArtifactRelPath
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), nft4ArtifactRelPath))
}

// Named NFT-4 closure-shape failure modes. Each names ONE doc 06 (c) bypass row
// the shipped artifact must satisfy, so a ruleset rewrite that weakens a control
// fails LOUDLY (and actionably) here rather than passing vacuously. Tests assert
// the specific error via errors.Is. The wording mirrors the Rust ds-nft
// quic_reject/redirect ViolationKind set so the two readers stay legible
// together.
var (
	// ErrNoPort53Capture fires when the artifact carries no iifname-anchored
	// port-53 bypass-attempt observe rule — the D69 capture/observability half is
	// missing, so a foreign-resolver bypass attempt would be invisible.
	ErrNoPort53Capture = errors.New("resolverlock/nft4: no iifname-anchored port-53 bypass-attempt rule (counter+log) in the shipped NFT-4 artifact — the D69 foreign-resolver bypass observability is missing (a ruleset change must update BOTH readers: this Go driver AND the Rust ds-nft redirect/quic_reject lints)")
	// ErrPort53SourceIPMatch fires when a port-53 rule matches `ip saddr` — the
	// VM can forge its source; the rule must match the unforgeable `iifname` only
	// (doc 03 §3, the doc 06 (c) in-VM-spoofing invariant).
	ErrPort53SourceIPMatch = errors.New("resolverlock/nft4: a port-53 rule matches `ip saddr` — match the unforgeable `iifname` attachment point only, never the forgeable source IP (doc 03 §3, doc 06 (c) in-VM-spoofing)")
	// ErrNoDoTDrop fires when udp/tcp 853 (DNS-over-TLS) is not dropped — DoT
	// would tunnel resolution past ds-dnsgate inside TLS.
	ErrNoDoTDrop = errors.New("resolverlock/nft4: DNS-over-TLS (port 853) is not dropped for both transports in the shipped NFT-4 artifact — DoT would tunnel resolution past ds-dnsgate (doc 09 §3 NFT-4)")
	// ErrQUICNotRejected fires when the udp/443 rule is a silent drop (or any
	// non-reject verdict). D70 requires reject-not-drop so the refusal is
	// observable, never a silent ~5s client hang.
	ErrQUICNotRejected = errors.New("resolverlock/nft4: the udp/443 (QUIC) rule is a silent `drop` (or has no reject verdict) — D70 requires it be `reject`ed, never silently dropped, so the refusal is observable and forces TCP fallback the egress gateway can see")
	// ErrQUICNotPortUnreachable fires when the udp/443 reject does not name an
	// icmp(x) port-unreachable type — a bare reject or a reset shape is wrong.
	ErrQUICNotPortUnreachable = errors.New("resolverlock/nft4: the udp/443 (QUIC) reject does not name an icmp(x) `port-unreachable` type — D70's frozen verdict wording is `reject with icmp(x) type port-unreachable`")
	// ErrQUICMissingCounter fires when the udp/443 reject carries no `counter` —
	// QUIC rejects must be countable per session (D70's "+ counted per session").
	ErrQUICMissingCounter = errors.New("resolverlock/nft4: the udp/443 (QUIC) reject has no `counter` — D70 requires it be counted per session (the on-box half of the QuicBlocked reason code)")
	// ErrNoUDP443Rule fires when the artifact carries no udp/443 rule at all —
	// the sole control for non-cooperative QUIC clients is absent.
	ErrNoUDP443Rule = errors.New("resolverlock/nft4: no udp/443 (QUIC) rule in the shipped NFT-4 artifact — the sole control for non-cooperative QUIC clients (curl --http3-only, WebTransport, MASQUE, raw QUIC libs) is missing (D70)")
	// ErrQUICNotInterfaceAnchored fires when the udp/443 (QUIC) reject rule is not
	// anchored on the unforgeable `iifname` (the dstap-* attachment point) — or
	// worse, matches the forgeable `ip saddr`. The QUIC rule is a session-scoped
	// control, so it MUST key on the interface the session is bound to, never on a
	// source IP the in-VM agent can forge (doc 03 §3, the doc 06 (c) in-VM-spoofing
	// invariant, D44/D69). This is the per-control mirror, for the QUIC rule, of the
	// global ErrPort53SourceIPMatch source-IP-never-matched scan: a future ruleset
	// edit could drop iifname on JUST this rule (or add an ip-saddr match to it)
	// without tripping the port-53 sentinel, so the QUIC anchoring is asserted in
	// its own right.
	ErrQUICNotInterfaceAnchored = errors.New("resolverlock/nft4: the udp/443 (QUIC) reject rule is not anchored on the unforgeable `iifname` (the dstap-* attachment point) — match the interface the session is bound to, never the forgeable `ip saddr` the in-VM agent can spoof (doc 03 §3, doc 06 (c) in-VM-spoofing, D44/D69)")
	// ErrDoTNotInterfaceAnchored fires when a port-853 (DNS-over-TLS) drop rule is
	// not anchored on the unforgeable `iifname` (the dstap-* attachment point) — or
	// worse, matches the forgeable `ip saddr`. Like the QUIC reject, each DoT drop
	// is a session-scoped control, so it MUST key on the interface the session is
	// bound to, never on a source IP the in-VM agent can forge (doc 03 §3, the doc
	// 06 (c) in-VM-spoofing invariant, D44/D69). This is the per-control mirror, for
	// the DoT 853 drop rules, of the global ErrPort53SourceIPMatch
	// source-IP-never-matched scan and the per-control ErrQUICNotInterfaceAnchored:
	// a future ruleset edit could drop iifname on JUST a 853 rule (or add an
	// ip-saddr match to it) without tripping the port-53 or QUIC sentinels, so the
	// DoT anchoring is asserted in its own right — completing the per-control
	// anchoring trilogy (port-53, QUIC, DoT).
	ErrDoTNotInterfaceAnchored = errors.New("resolverlock/nft4: a DNS-over-TLS (port 853) drop rule is not anchored on the unforgeable `iifname` (the dstap-* attachment point) — match the interface the session is bound to, never the forgeable `ip saddr` the in-VM agent can spoof (doc 03 §3, doc 06 (c) in-VM-spoofing, D44/D69)")
)

// AssertNFT4ClosureShape reads the shipped NFT-4 artifact and asserts all three
// resolver-bypass-closure controls are present and correctly shaped. It returns
// the FIRST named error on a violation (loud, actionable), or nil when the
// shipped artifact satisfies every doc 06 (c) bypass row. A read failure is
// returned as-is (never silently treated as "no controls" — a false green the
// resolver lock cannot afford).
func AssertNFT4ClosureShape() error {
	path := NFT4ArtifactPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return assertNFT4ClosureShape(string(data))
}

// assertNFT4ClosureShape is the pure text→verdict analyzer (separated so it is
// unit-testable against synthetic ruleset strings without the file read — the
// negative cases are proven against synthetic strings, never by mutating the
// shipped artifact). It mirrors the token analysis of the Rust ds-nft
// quic_reject/redirect lints: comment-stripped, lowercased, word-boundary token
// tests.
func assertNFT4ClosureShape(text string) error {
	var (
		sawPort53Capture bool
		sawDoTUDP        bool
		sawDoTTCP        bool
		sawUDP443        bool
	)

	for _, raw := range strings.Split(text, "\n") {
		// R1: drop the nft `comment "<...>"` keyword+quoted-string BEFORE
		// tokenizing — otherwise the quoted comment text leaks icmp /
		// port-unreachable / verdict tokens into the bag (a bare `reject comment
		// "use icmp port-unreachable"` would otherwise satisfy namesPortUnreachable).
		// Done after the `#`-comment strip and before the `;`-split (a `;` inside a
		// comment string must not be read as a statement separator).
		line := stripNftCommentKeyword(stripNftComment(raw))

		// R3: a single physical line may carry several `;`-joined statements
		// (`... drop; iifname "dstap-*" udp dport 853 counter accept`). Split on
		// `;` (respecting quoted strings) so each statement is analyzed on its own
		// token bag — otherwise a permissive second statement collapses into the
		// first rule's bag and goes invisible.
		for _, code := range splitStatements(line) {
			lc := strings.ToLower(code)

			// ── Control 1: port-53 capture observability (iifname, never saddr) ──
			if isPort53Rule(lc) {
				// In-VM-spoofing invariant for THIS rule (doc 03 §3, doc 06 (c),
				// D44/D69): the port-53 bypass-attempt observe rule MUST NEVER consult
				// the forgeable `ip saddr`, AND when it anchors on `iifname` that
				// interface operand MUST be the session-scoped `dstap-*` pattern (the
				// D50/D66 interface-naming contract) — anchoring on a non-dstap iifname
				// (e.g. "eth0") is NOT the session attachment point and would observe
				// the wrong traffic. A bare-keyword presence check is too weak: a
				// ruleset edit could swap the operand to "eth0" and still satisfy
				// hasWord(lc, "iifname"), so the dstap-* VALUE is asserted, not merely
				// the keyword.
				if matchesSourceIP(lc) || (hasWord(lc, "iifname") && !anchorsOnDstapGlob(lc)) {
					return fmt.Errorf("%w (offending rule: %q)", ErrPort53SourceIPMatch, strings.TrimSpace(code))
				}
				// A port-53 observability rule must anchor on iifname and carry the
				// counter+log shape D69 froze. The NFT-1 redirect owns delivery; this
				// is NFT-4's bypass-attempt observation.
				if hasWord(lc, "iifname") && hasWord(lc, "counter") &&
					(hasWord(lc, "log") || hasWord(lc, "nflog")) {
					sawPort53Capture = true
				}
			}

			// ── Control 2: DoT (853) dropped, both transports, iifname-anchored ──
			if isPort853Rule(lc) {
				// In-VM-spoofing invariant for THIS rule (doc 03 §3, doc 06 (c),
				// D44/D69): each session-scoped DoT drop MUST key on the unforgeable
				// `iifname` whose operand is the session-scoped `dstap-*` pattern (the
				// D50/D66 interface-naming contract), and MUST NEVER consult the
				// forgeable `ip saddr`. The global no-saddr scan covers spoofing
				// indirectly, but a ruleset edit could drop iifname on JUST a 853 rule
				// (or add an ip-saddr match to it) without tripping the port-53 or QUIC
				// sentinels, so it is asserted per-control — the DoT leg of the
				// per-control anchoring trilogy (port-53, QUIC, DoT). The iifname VALUE
				// is asserted, not merely the keyword: a rule that anchors on a
				// non-dstap iifname (e.g. "eth0") is NOT scoped to the session tap and
				// would still satisfy a bare hasWord(lc, "iifname") presence check.
				if matchesSourceIP(lc) || !hasWord(lc, "iifname") || !anchorsOnDstapGlob(lc) {
					return fmt.Errorf("%w (offending rule: %q)", ErrDoTNotInterfaceAnchored, strings.TrimSpace(code))
				}
				// R2 (anti-permit, DoT leg): an explicit `accept` verdict on a 853
				// rule would PERMIT DNS-over-TLS past ds-dnsgate — the exact bypass
				// this control closes — even when the rule ALSO names `drop` (the
				// !hasWord(drop) check below still passes on a contradictory
				// `accept ... drop`). Key on the permit verdict directly so a
				// verdict-token presence game cannot launder an accept through.
				if hasWord(lc, "accept") {
					return fmt.Errorf("%w (offending rule: %q)", ErrNoDoTDrop, strings.TrimSpace(code))
				}
				if !hasWord(lc, "drop") {
					return fmt.Errorf("%w (offending rule: %q)", ErrNoDoTDrop, strings.TrimSpace(code))
				}
				if hasWord(lc, "udp") {
					sawDoTUDP = true
				}
				if hasWord(lc, "tcp") {
					sawDoTTCP = true
				}
			}

			// ── Control 3: udp/443 QUIC reject-not-drop + counter, iifname-anchored ──
			if isUDP443Rule(lc) {
				sawUDP443 = true
				// In-VM-spoofing invariant for THIS rule (doc 03 §3, doc 06 (c),
				// D44/D69): the session-scoped QUIC reject MUST key on the unforgeable
				// `iifname` whose operand is the session-scoped `dstap-*` pattern (the
				// D50/D66 interface-naming contract), and MUST NEVER consult the
				// forgeable `ip saddr`. The global no-saddr scan covers spoofing
				// indirectly, but a ruleset edit could drop iifname on JUST this rule
				// without tripping the port-53 sentinel, so it is asserted per-control.
				// The iifname VALUE is asserted, not merely the keyword: a rule that
				// anchors on a non-dstap iifname (e.g. "eth0") is NOT scoped to the
				// session tap and would still satisfy a bare hasWord(lc, "iifname").
				if matchesSourceIP(lc) || !hasWord(lc, "iifname") || !anchorsOnDstapGlob(lc) {
					return fmt.Errorf("%w (offending rule: %q)", ErrQUICNotInterfaceAnchored, strings.TrimSpace(code))
				}
				// R2 (anti-permit, QUIC leg): an explicit `accept` verdict PERMITS
				// udp/443 — the precise D70 failure — yet the reject-not-drop check
				// below keys only on reject PRESENCE and drop ABSENCE, so a
				// contradictory `counter accept reject with icmpx type port-unreachable`
				// (accept wins at runtime; the reject is dead) sails past it. There is
				// no legitimate `accept` on a control that must REJECT, so fail closed
				// on the permit verdict directly, before the reject/drop shape checks
				// (which never inspect for accept).
				if hasWord(lc, "accept") {
					return fmt.Errorf("%w (offending rule: %q)", ErrQUICNotRejected, strings.TrimSpace(code))
				}
				// reject-not-drop: a non-reject verdict, or a contradictory
				// drop-and-reject, is the exact failure D70 forbids.
				if !hasWord(lc, "reject") || hasWord(lc, "drop") {
					return fmt.Errorf("%w (offending rule: %q)", ErrQUICNotRejected, strings.TrimSpace(code))
				}
				if !namesPortUnreachable(lc) {
					return fmt.Errorf("%w (offending rule: %q)", ErrQUICNotPortUnreachable, strings.TrimSpace(code))
				}
				if !hasWord(lc, "counter") {
					return fmt.Errorf("%w (offending rule: %q)", ErrQUICMissingCounter, strings.TrimSpace(code))
				}
			}
		}
	}

	if !sawPort53Capture {
		return ErrNoPort53Capture
	}
	if !sawDoTUDP || !sawDoTTCP {
		return ErrNoDoTDrop
	}
	if !sawUDP443 {
		return ErrNoUDP443Rule
	}
	return nil
}

// isPort53Rule reports whether a (lowercased, comment-stripped) line is a port-53
// rule — a `dport 53` selector. We isolate the 53 as a whole token so `dport 530`
// or an address octet never matches.
func isPort53Rule(lc string) bool {
	return hasWord(lc, "dport") && hasWord(lc, "53")
}

// isPort853Rule reports whether a line is a port-853 (DNS-over-TLS) rule.
func isPort853Rule(lc string) bool {
	return hasWord(lc, "dport") && hasWord(lc, "853")
}

// isUDP443Rule reports whether a line is a udp/443 rule — a udp match and a
// dport-443 selector (the same load-bearing tokens the Rust quic_reject lint
// keys on: a udp protocol match, a dport, and a 443 token).
func isUDP443Rule(lc string) bool {
	mentionsUDP := hasWord(lc, "udp") || strings.Contains(lc, "l4proto udp")
	return mentionsUDP && hasWord(lc, "dport") && hasWord(lc, "443")
}

// matchesSourceIP reports whether a line matches on a forgeable SOURCE key — the
// source the session-scoped rules must NEVER consult (doc 03 §3); the unforgeable
// `iifname` attachment point is the only legitimate match key.
//
// R6 (broaden the source-key guard): the original check named only the literal
// `ip saddr` / `ip6 saddr` selectors, so a source match keyed on a different layer
// — `ether saddr <mac>`, an `ip6 saddr` set, or any other `... saddr ...` form —
// evaded it. nft spells EVERY source-address match with the `saddr` keyword (the
// `daddr` destination twin is never a source), so keying on the `saddr` TOKEN
// catches the whole family. This is defense-in-depth: the per-control dstap-anchor
// already independently constrains the three known controls, but a future ruleset
// edit could add a non-ip saddr match to a control rule, and the global no-saddr
// scan (TestNFT4SourceIPNeverMatchedInShippedArtifact) must catch every form.
func matchesSourceIP(lc string) bool {
	return hasWord(lc, "saddr")
}

// anchorsOnDstapGlob reports whether a (lowercased, comment-stripped) line anchors
// its `iifname` match on the session-scoped `dstap-*` interface pattern — the
// D50/D66 interface-naming contract. Anchoring on the `iifname` KEYWORD alone is
// too weak: a rule could read `iifname "eth0"` (or any non-session interface) and
// still satisfy a bare hasWord(lc, "iifname") presence check, yet it would NOT be
// scoped to the session's dstap-prefixed tap. This is the operand-level companion
// to matchesSourceIP: where that rejects the forgeable source, this requires the
// interface operand be the unforgeable session attachment point.
//
// It scans the whitespace fields for an `iifname` token and inspects the operand
// that follows, accepting any `dstap-`-prefixed interface name regardless of how
// it is written:
//   - `iifname "dstap-*"`     — the shipped/quoted glob form
//   - `iifname "dstap-abc12"` — a concrete per-session interface name
//   - `iifname dstap-*`       — the unquoted form nft also tolerates
//   - `iifname { "dstap-..." }` — an anonymous set of dstap interfaces
//
// The operand is normalised by trimming the surrounding nft punctuation (quotes,
// set braces, a leading comma) before the `dstap-` prefix test, so the check keys
// on the interface NAME, not the syntactic wrapping. Returns false when no iifname
// token is present or its operand is not dstap-prefixed (e.g. "eth0").
//
// ANON-SET TOTALITY (adversarial-pass fix): for the anonymous-set form
// `iifname { "dstap-a", "eth0" }` EVERY member of the set must be dstap-prefixed,
// not merely the FIRST one found. A mixed set that admitted even one non-dstap
// interface ("eth0") would NOT be scoped to the session tap, yet an
// accept-on-first-match scan would pass it. We collect ALL the interface operands
// the iifname match keys on (the single operand for the scalar forms, every
// brace-enclosed member for the anon-set form) and require the set be NON-EMPTY
// and EVERY member dstap-prefixed — a single non-dstap member fails the line.
func anchorsOnDstapGlob(lc string) bool {
	operands := iifnameOperands(lc)
	if len(operands) == 0 {
		return false
	}
	for _, operand := range operands {
		if !strings.HasPrefix(operand, "dstap-") {
			return false
		}
	}
	return true
}

// iifnameOperands extracts the interface operand(s) an `iifname` match keys on from
// a (lowercased, comment-stripped) line, normalising away the surrounding nft
// punctuation (quotes, set braces, a leading/trailing comma) so the caller keys on
// the interface NAME, not its syntactic wrapping. It handles every operand shape:
//
//   - `iifname "dstap-*"`            — a single quoted operand (one element)
//   - `iifname dstap-*`              — the unquoted form (one element)
//   - `iifname { "dstap-a", "eth0" }` — an anonymous set (ALL members, in order)
//
// For the anonymous-set form it walks fields from the opening `{` until the closing
// `}`, returning EVERY interface name in the set — so a caller can enforce a
// per-member predicate (e.g. all-dstap, anchorsOnDstapGlob) rather than being fooled
// by the first member. Returns nil when no iifname token (with an operand) is present.
// Only the FIRST iifname match on the line is read; nft rules carry one iifname match.
func iifnameOperands(lc string) []string {
	fields := strings.Fields(lc)
	for i, f := range fields {
		if f != "iifname" || i+1 >= len(fields) {
			continue
		}
		// SET FORM: `iifname { "m1", "m2", ... }`. The braces and commas may be spaced
		// out as their own fields, glued to the members (`{"m1","m2"}`), or any mix —
		// so accumulate the raw fields from the `{` up to and including the field
		// carrying the closing `}`, then split the joined text on commas. Each piece
		// is trimmed of the nft punctuation (quotes, braces, commas, spaces) so a
		// member survives regardless of how it was wrapped. Returning EVERY member is
		// load-bearing: the all-dstap totality check must see a non-dstap member even
		// when it is not the FIRST in the set.
		if strings.HasPrefix(fields[i+1], "{") {
			var raw strings.Builder
			for j := i + 1; j < len(fields); j++ {
				raw.WriteString(fields[j])
				raw.WriteByte(' ')
				if strings.Contains(fields[j], "}") {
					break
				}
			}
			var members []string
			for _, piece := range strings.Split(raw.String(), ",") {
				member := strings.Trim(piece, ` "{}`)
				if member != "" {
					members = append(members, member)
				}
			}
			return members
		}
		// SCALAR FORM: the operand is the single next field.
		operand := strings.Trim(fields[i+1], `"{},`)
		if operand == "" {
			return nil
		}
		return []string{operand}
	}
	return nil
}

// namesPortUnreachable reports whether the reject names an icmp(x)
// port-unreachable type. nft spells it with a hyphen; tolerate the underscore
// form defensively. The icmp family token (`icmp` covers icmp/icmpv6/icmpx) must
// be present so a bare `reject` or a tcp-reset shape never passes.
func namesPortUnreachable(lc string) bool {
	namesType := strings.Contains(lc, "port-unreachable") || strings.Contains(lc, "port_unreachable")
	return namesType && strings.Contains(lc, "icmp")
}

// hasWord reports whether `word` appears as a whole token in `lc` (split on any
// non-alphanumeric byte), mirroring the Rust lints' token boundary so `53` does
// not match inside `530` and `drop` does not match inside `dropper`.
func hasWord(lc, word string) bool {
	for _, tok := range strings.FieldsFunc(lc, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		if tok == word {
			return true
		}
	}
	return false
}

// stripNftComment drops a trailing `#`-comment from an nft line, returning the
// code part (same as the Rust lints' strip_comment).
func stripNftComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

// stripNftCommentKeyword removes the nft `comment "<...>"` keyword + quoted-string
// clause(s) from a line, returning the rule code with the human-readable comment
// text excised (R1).
//
// THE HOLE: nft rules carry an optional `comment "free text"` clause that the
// analyzer would otherwise tokenize verbatim — so a rule such as
//
//	... counter reject comment "use icmp port-unreachable"
//
// would leak the `icmp`, `port-unreachable`, and `port` tokens out of the human
// comment into the lowercased token bag, making a BARE `reject` (no real
// `reject with icmp type port-unreachable` verdict) satisfy namesPortUnreachable
// and pass. Worse, a comment could smuggle a `reject` / `drop` / `accept` verdict
// token into a rule that carries none. stripNftComment only handles the trailing
// `#`-comment, not this keyword form, so the keyword string is stripped here BEFORE
// tokenizing.
//
// It scans byte-by-byte, tracking double-quote state so a `comment` token inside a
// DIFFERENT quoted string (e.g. `log prefix "comment "`) is never treated as the
// keyword, and removes from the `comment` keyword through its closing quote
// (replacing the whole clause with a single space so adjacent tokens do not fuse).
// An unterminated comment string (no closing quote) drops the rest of the line —
// the conservative, fail-closed choice, since trailing un-quoted bytes after a
// `comment "` opener are part of the comment, not rule code. Multiple `comment`
// clauses on one line are all removed.
func stripNftCommentKeyword(line string) string {
	var out strings.Builder
	inQuote := false
	for i := 0; i < len(line); {
		c := line[i]
		if inQuote {
			out.WriteByte(c)
			if c == '"' {
				inQuote = false
			}
			i++
			continue
		}
		if c == '"' {
			inQuote = true
			out.WriteByte(c)
			i++
			continue
		}
		// Outside any quote: is this the start of a `comment` keyword token? It must
		// be on a word boundary (preceded by a non-word byte or start of line) and
		// be the whole word `comment` (followed by a non-word byte or end of line),
		// so `comments` or `xcomment` never match.
		if isCommentKeywordAt(line, i) {
			j := i + len("comment")
			// Skip whitespace between the keyword and its quoted string.
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			if j < len(line) && line[j] == '"' {
				// Skip the opening quote and everything up to and including the close.
				j++
				for j < len(line) && line[j] != '"' {
					j++
				}
				if j < len(line) {
					j++ // consume the closing quote
				}
				// Replace the removed clause with a single space so the tokens on
				// either side stay separated.
				out.WriteByte(' ')
				i = j
				continue
			}
			// A `comment` keyword not followed by a quoted string is not the nft
			// comment clause (defensive); fall through and emit it verbatim.
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

// isCommentKeywordAt reports whether the whole word `comment` begins at byte i in
// s, on word boundaries (so it does not match inside `comments` / `xcomment`). The
// token boundary is the same alphanumeric class hasWord splits on.
func isCommentKeywordAt(s string, i int) bool {
	const kw = "comment"
	if i+len(kw) > len(s) || s[i:i+len(kw)] != kw {
		return false
	}
	isWordByte := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
	}
	if i > 0 && isWordByte(s[i-1]) {
		return false
	}
	if end := i + len(kw); end < len(s) && isWordByte(s[end]) {
		return false
	}
	return true
}

// splitStatements splits one physical nft line into its `;`-separated statements,
// respecting double-quoted strings so a `;` inside a quoted string (e.g. a
// `log prefix "a;b "`) is NOT a separator (R3).
//
// THE HOLE: the analyzer split the artifact only on newlines, so several
// `;`-joined statements on ONE physical line collapsed into a single token bag —
// hiding a permissive second statement. For example
//
//	iifname "dstap-*" udp dport 853 counter drop; iifname "dstap-*" udp dport 853 counter accept
//
// has a DROP first statement and a PERMISSIVE accept second statement; analyzed as
// one bag the rule satisfies `hasWord(drop)` and the stray `accept` is invisible.
// Splitting on `;` first means each statement is analyzed on its own — so the
// accept second statement now trips the DoT control's anti-permit guard.
//
// Returns the trimmed, non-empty statements in order. A line with no `;` yields the
// single (trimmed) statement; an all-whitespace line yields none. The split happens
// AFTER stripNftCommentKeyword, so no `;` inside a human comment string reaches here.
func splitStatements(line string) []string {
	var stmts []string
	inQuote := false
	start := 0
	flush := func(end int) {
		if s := strings.TrimSpace(line[start:end]); s != "" {
			stmts = append(stmts, s)
		}
	}
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				flush(i)
				start = i + 1
			}
		}
	}
	flush(len(line))
	return stmts
}
