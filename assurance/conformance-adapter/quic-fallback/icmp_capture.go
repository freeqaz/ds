// SPDX-License-Identifier: Apache-2.0

package quicfallback

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// icmp_capture.go — the capture-side primitives for the QUIC fast-fail / fallback
// conformance row (doc 12 §10 "QUIC fast-fail / fallback"). It carries three
// things, all stdlib-only (this module is stdlib-only by charter):
//
//  1. The ICMP type/code constants the doc 12 §10 row names verbatim ("ICMP type
//     3 code 3 asserted by capture") plus the icmpv6 twin, and the predicate that
//     decides whether a captured ICMP packet IS the port-unreachable the D70
//     udp/443 reject must emit (reject-not-drop). This is the SHAPE the live
//     packet-capture half asserts on the wire; the offline half drives the same
//     predicate over synthetic captures.
//
//  2. The CapturedICMP / fast-fail observation types the env-gated LIVE half fills
//     in from a real tcpdump/scapy capture of `curl --http3-only` to the baseline
//     domain, and the pure verdict the offline half asserts against synthetic
//     observations — proving "fails in <1s with an ICMP port-unreachable, never a
//     silent-drop hang" without root, raw sockets, or a running boundary.
//
//  3. The dormant-v6-twin reader: a stdlib scan over the SHIPPED NFT-4 artifact
//     (dataplane/artifacts/nft/nft-4-resolver-closure.nft) that shape-verifies the
//     v6 reject twin is present-but-dormant (D75 feature gate). It reuses the SAME
//     artifact the resolverlock NFT-4 closure driver and the Rust ds-nft
//     quic_reject lint govern — one artifact, three readers, no drift.
//
// # Two populations, never merged (doc 12 §10, D70)
//
// This file is the udp/443-REJECT side ONLY. The cooperative-client steering
// (DNS-4 rule 4 HTTPS/SVCB suppression ⇒ TCP fallback within budget) is the
// OTHER population and is asserted separately in fallback_test.go. The doc 12 §10
// row and D70 are explicit: the two controls are tested independently and NEVER
// merged into one assertion. Nothing in this file consults DNS/steering state.

// ── ICMP port-unreachable shape (doc 12 §10 "ICMP type 3 code 3") ─────────────

// ICMP (v4) Destination Unreachable type/codes. The doc 12 §10 canary row names
// "ICMP type 3 code 3" verbatim: type 3 is Destination Unreachable, code 3 is
// Port Unreachable (RFC 792). This is what the v4 udp/443 reject MUST emit so a
// raw-QUIC client (curl --http3-only) sees ECONNREFUSED instantly instead of a
// multi-second silent-drop hang (D70 reject-not-drop, doc 12 §13.5).
const (
	// ICMPv4TypeDestUnreachable is ICMP type 3 (Destination Unreachable, RFC 792).
	ICMPv4TypeDestUnreachable = 3
	// ICMPv4CodePortUnreachable is ICMP code 3 (Port Unreachable) under type 3.
	// "type 3 code 3" is the doc 12 §10 row's verbatim assertion.
	ICMPv4CodePortUnreachable = 3
)

// ICMPv6 (v6) Destination Unreachable type/code. nft's `icmpx` verdict emits the
// family-appropriate port-unreachable: ICMP type 3 / code 3 for v4, and ICMPv6
// type 1 (Destination Unreachable) / code 4 (Port Unreachable, RFC 4443) for v6.
// The v6 twin is DORMANT (D75) but its shape is asserted now (Assertion 3).
const (
	// ICMPv6TypeDestUnreachable is ICMPv6 type 1 (Destination Unreachable, RFC 4443).
	ICMPv6TypeDestUnreachable = 1
	// ICMPv6CodePortUnreachable is ICMPv6 code 4 (Port Unreachable) under type 1.
	ICMPv6CodePortUnreachable = 4
)

// AddrFamily is the IP address family a captured ICMP / reject rule belongs to.
// The v4 leg is live; the v6 leg is the dormant twin (D75).
type AddrFamily string

const (
	// FamilyV4 is the live IPv4 leg — the udp/443 reject the canary exercises today.
	FamilyV4 AddrFamily = "v4"
	// FamilyV6 is the dormant IPv6 twin — asserted present-but-dormant until D75
	// enables v6 end to end (Assertion 3). The shipped `inet`/`icmpx` rule carries
	// it without a second rule.
	FamilyV6 AddrFamily = "v6"
)

// IsPortUnreachable reports whether (family, icmpType, icmpCode) is the
// port-unreachable shape the D70 udp/443 reject must emit for that family — ICMP
// type 3 code 3 for v4, ICMPv6 type 1 code 4 for v6. This is the single predicate
// both the live capture half and the offline synthetic half decide against, so
// "did the boundary reject-not-drop?" has one definition.
func IsPortUnreachable(family AddrFamily, icmpType, icmpCode int) bool {
	switch family {
	case FamilyV4:
		return icmpType == ICMPv4TypeDestUnreachable && icmpCode == ICMPv4CodePortUnreachable
	case FamilyV6:
		return icmpType == ICMPv6TypeDestUnreachable && icmpCode == ICMPv6CodePortUnreachable
	default:
		return false
	}
}

// ── Fast-fail capture observation + verdict ──────────────────────────────────

// CapturedICMP is one ICMP / ICMPv6 packet a capture (tcpdump/scapy/raw socket)
// observed in response to the raw-QUIC first-contact. The live half fills it in
// from a real capture; the offline half synthesizes it to assert the verdict.
type CapturedICMP struct {
	// Family is the address family the ICMP packet belongs to (v4 ⇒ ICMP,
	// v6 ⇒ ICMPv6).
	Family AddrFamily
	// Type / Code are the captured ICMP type and code. The fast-fail row requires
	// type 3 / code 3 (v4) — a destination-unreachable / port-unreachable.
	Type int
	Code int
}

// FastFailObservation is the result of probing udp/443 to the baseline domain
// with a raw-QUIC client (curl --http3-only) and capturing the response. It is
// the input to FastFailVerdict — the live half collects it over the wire, the
// offline half synthesizes it.
type FastFailObservation struct {
	// Family is the address family probed (v4 today; v6 is the dormant twin and is
	// not probed live until D75).
	Family AddrFamily
	// ConnectFailed reports whether the udp/443 first-contact FAILED (the correct
	// outcome — the reject ⇒ ECONNREFUSED). A SUCCESS means udp/443 reached an
	// upstream: the reject is not controlling (a boundary hole).
	ConnectFailed bool
	// FailLatency is how long the failure took. The reject must fail FAST
	// (< FastFailThreshold); a slow failure signals a silent drop, not the fast
	// ICMP reject D70 requires.
	FailLatency time.Duration
	// ICMP is the captured ICMP/ICMPv6 packet, if any. The doc 12 §10 row requires
	// the failure be PROVEN by a captured port-unreachable, not merely inferred
	// from the timeout — a silent drop also "fails", but with NO ICMP, which is the
	// exact mode D70 forbids.
	ICMP *CapturedICMP
	// ICMPCaptured reports whether the capture observed ANY ICMP response. A
	// failure with ICMPCaptured=false is a silent drop (the doc 12 §13.5 defect),
	// distinct from the fast ICMP reject.
	ICMPCaptured bool
}

// FastFailThreshold is the ceiling a raw-QUIC udp/443 first-contact FAILURE must
// land under for the reject to count as "fails fast" (doc 12 §10: "fails in <1s";
// doc 12 §13.5: ECONNREFUSED in <1s, never a multi-second silent-drop hang). A
// failure that takes longer signals a silent drop, itself a boundary defect.
const FastFailThreshold = time.Second

// Named fast-fail / capture failure modes. Each names ONE doc 12 §10 row the
// observation must satisfy, so a regression surfaces the SPECIFIC actionable
// sentinel (errors.Is), never a vacuous green or an anonymous error.
var (
	// ErrUDP443NotRejected fires when the raw-QUIC udp/443 first-contact SUCCEEDED
	// — udp/443 reached an upstream, so the NFT-4 reject is NOT controlling the
	// non-cooperative population. This is a boundary HOLE, not just a latency miss.
	ErrUDP443NotRejected = errors.New("quicfallback: raw-QUIC (curl --http3-only) udp/443 first-contact SUCCEEDED — udp/443 reached upstream, so the NFT-4 reject is NOT controlling the non-cooperative population (doc 12 §10, two-populations framing, D70)")
	// ErrSlowFail fires when the failure took longer than FastFailThreshold — a
	// silent drop, not the fast ICMP port-unreachable reject D70 requires (the
	// multi-second RFC-4074-style hang reject-not-drop exists to prevent).
	ErrSlowFail = errors.New("quicfallback: raw-QUIC udp/443 first-contact failed SLOWLY (> the fast-fail threshold) — a silent drop, not the fast ICMP port-unreachable reject D70 requires; the udp/443 rule must reject-not-drop (doc 12 §10, §13.5)")
	// ErrNoICMPCaptured fires when the failure carried NO captured ICMP — a silent
	// drop. doc 12 §10 requires the failure be PROVEN by a captured port-unreachable;
	// a timeout with no ICMP is precisely the silent-drop mode the reject forbids.
	ErrNoICMPCaptured = errors.New("quicfallback: raw-QUIC udp/443 first-contact failed but NO ICMP was captured — a silent drop, not the observable reject D70 requires; the capture must see an ICMP port-unreachable, never just a timeout (doc 12 §10 'asserted by capture', §13.5)")
	// ErrWrongICMPShape fires when an ICMP WAS captured but it is not the
	// port-unreachable shape — type 3 code 3 for v4 (icmpv6 type 1 code 4 for v6).
	// A bare reject or a different unreachable code is the wrong shape.
	ErrWrongICMPShape = errors.New("quicfallback: the captured ICMP is not the port-unreachable shape D70 froze (v4: type 3 code 3; v6: icmpv6 type 1 code 4) — a bare reject, a different unreachable code, or a reset shape is wrong (doc 12 §10, D70)")
	// ErrICMPFamilyMismatch fires when the captured ICMP's family disagrees with
	// the probed family — a v4 probe that captured an ICMPv6 packet (or vice versa)
	// is a capture/wiring defect, not a valid reject observation.
	ErrICMPFamilyMismatch = errors.New("quicfallback: the captured ICMP family disagrees with the probed address family — the capture is wired wrong (doc 12 §10)")
)

// FastFailVerdict decides whether a raw-QUIC udp/443 first-contact observation
// satisfies the doc 12 §10 fast-fail row: the connect FAILED, it failed FAST
// (< FastFailThreshold), and the failure was PROVEN by a captured ICMP
// port-unreachable of the right shape/family (not a silent drop). It returns nil
// on a clean fast-fail, else the SPECIFIC named sentinel. This is the pure
// function the offline half asserts and the live capture half feeds its real
// observation into — both halves agree on the spec.
func FastFailVerdict(obs FastFailObservation) error {
	// A SUCCESS is the boundary hole: udp/443 reached an upstream.
	if !obs.ConnectFailed {
		return fmt.Errorf("%w: %s udp/443 succeeded", ErrUDP443NotRejected, obs.Family)
	}
	// It failed — but it must fail FAST (the reject, not a silent-drop hang).
	if obs.FailLatency > FastFailThreshold {
		return fmt.Errorf("%w: %s failed in %s (> %s)", ErrSlowFail, obs.Family, obs.FailLatency, FastFailThreshold)
	}
	// The failure must be PROVEN by a captured ICMP — a timeout with no ICMP is a
	// silent drop (doc 12 §10 "asserted by capture").
	if !obs.ICMPCaptured || obs.ICMP == nil {
		return fmt.Errorf("%w: %s failed in %s with no ICMP", ErrNoICMPCaptured, obs.Family, obs.FailLatency)
	}
	// The captured ICMP's family must match the probed family.
	if obs.ICMP.Family != obs.Family {
		return fmt.Errorf("%w: probed %s, captured %s", ErrICMPFamilyMismatch, obs.Family, obs.ICMP.Family)
	}
	// And it must be the port-unreachable shape (type 3 code 3 / icmpv6 1/4).
	if !IsPortUnreachable(obs.ICMP.Family, obs.ICMP.Type, obs.ICMP.Code) {
		return fmt.Errorf("%w: captured %s type %d code %d", ErrWrongICMPShape, obs.ICMP.Family, obs.ICMP.Type, obs.ICMP.Code)
	}
	return nil // clean fast-fail: failed, fast, with a captured port-unreachable.
}

// ── The shipped NFT-4 artifact (the v4 reject + dormant v6 twin) ─────────────

// nft4ArtifactRelPath is the path from THIS source file to the shipped NFT-4
// resolver-bypass-closure artifact — the ONE ruleset that carries both the live
// v4 udp/443 reject and the dormant v6 twin (via the `inet`/`icmpx` unification,
// D75). Anchored off runtime.Caller so the offline reader works under `go test`
// from any cwd (same technique as resolverlock.NFT4ArtifactPath).
//
// The read routes THROUGH the tracked in-module symlink testdata/srclinks/… (not
// ../../../dataplane/… directly) so Go's test cache re-hashes the shipped artifact
// on change instead of serving a stale PASS — see srclinks.go for the
// test-cache-correctness rationale.
const nft4ArtifactRelPath = "testdata/srclinks/" + srcLinkNFT4Closure

// NFT4ArtifactPath returns the absolute path to the shipped NFT-4 artifact,
// anchored off this package's source location. It is the SAME artifact the
// resolverlock NFT-4 closure driver and the Rust ds-nft quic_reject lint govern —
// one artifact, three readers.
func NFT4ArtifactPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return nft4ArtifactRelPath
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), nft4ArtifactRelPath))
}

// ── D75 feature gate (v6) ────────────────────────────────────────────────────

// D75EnvVar is the v6 feature gate. The v6 twin reject is written NOW but DORMANT
// until v6 turns on end to end (D75, doc 12 §10 "v6 twin … asserted dormant-but-
// present"; doc 14 §11). Unset (or != "1"), the v6 leg is dormant: its rule SHAPE
// is asserted (Assertion 3) but the live v6 probe is SKIPPED. Set to "1", an
// operator opts into the v6 leg (live v6 probing remains a deferred manual step).
const D75EnvVar = "DS_QUIC_V6_LIVE"

// V6Enabled reports whether D75 has been flipped on (the v6 leg is live). The
// default (unset) is false — the v6 twin stays dormant, asserted by shape only.
func V6Enabled() bool { return os.Getenv(D75EnvVar) == "1" }

// LiveEnvVar is the switch for the env-gated LIVE half (the real curl + raw
// packet capture). Unset (or != "1"), the live half SKIPS — the default
// `go test ./...` is offline and deterministic, exercising the pure verdict +
// the shipped-artifact shape only. Set to "1", an operator opts into the live
// capture run, which fails LOUDLY until the real capture driver is wired.
const LiveEnvVar = "DS_QUIC_FALLBACK_LIVE"

// LiveEnabled reports whether the operator opted into the live capture half.
func LiveEnabled() bool { return os.Getenv(LiveEnvVar) == "1" }

// ErrLiveCaptureNotWired fires from the env-gated live half until an operator
// wires the real curl --http3-only driver + raw ICMP capture (needs a running
// boundary, CAP_NET_RAW, and the real client binaries the wave sandbox lacks) —
// so DS_QUIC_FALLBACK_LIVE=1 fails LOUDLY rather than reporting a false green.
var ErrLiveCaptureNotWired = errors.New("quicfallback: live capture driver not wired — DS_QUIC_FALLBACK_LIVE=1 requires a running boundary + curl --http3-only + a raw ICMP capture (CAP_NET_RAW) the wave sandbox lacks; this is a DEFERRED MANUAL step (doc 12 §10, doc 14 §10 Stage-2 NFT-4 rig extension)")

// RunLiveFastFail is the env-gated live driver entry point: it would drive
// `curl --http3-only` to the baseline domain over udp/443 while a raw ICMP
// capture runs, then return the observation for FastFailVerdict. Until an
// operator wires the real driver it returns ErrLiveCaptureNotWired so
// DS_QUIC_FALLBACK_LIVE=1 never reports a false green over an unimplemented
// capture. The verdict logic (FastFailVerdict) is unchanged when the live body
// lands.
func RunLiveFastFail(family AddrFamily) (FastFailObservation, error) {
	if !LiveEnabled() {
		// Caller must gate on LiveEnabled(); returning the sentinel here keeps a
		// misuse from silently producing an empty (vacuously-failing) observation.
		return FastFailObservation{}, fmt.Errorf("%w: live half not enabled (%s != 1)", ErrLiveCaptureNotWired, LiveEnvVar)
	}
	return FastFailObservation{}, ErrLiveCaptureNotWired
}

// ── Dormant-v6-twin shape verification (Assertion 3) ─────────────────────────

// V6TwinShape is the parsed shape of the udp/443 reject's v6 leg as it sits in
// the shipped artifact: the family the rule is authored in, whether the reject
// verdict carries the family-appropriate port-unreachable, whether it counts, and
// whether v6 is currently dormant. Assertion 3 verifies it carries the SAME
// reject-icmp-port-unreachable shape as v4, present but dormant until D75.
type V6TwinShape struct {
	// InetUnified reports whether the udp/443 reject rule is authored in the `inet`
	// family — the unification that lets ONE rule carry both v4 and the v6 twin
	// (the shipped shape, doc 12 §10 / NFT-4 header "Authored inet so the IPv6
	// twins are dropped by the dormant-v6 default"). When true, the v6 twin rides
	// the SAME rule rather than a second explicit rule.
	InetUnified bool
	// UsesICMPx reports whether the reject verdict uses `icmpx` — the family-
	// agnostic spelling that emits ICMP port-unreachable on v4 and ICMPv6
	// port-unreachable on v6 from ONE rule (NFT-4 header §FAMILY, D75). This is how
	// the v6 twin carries "the same reject-icmp-port-unreachable shape as v4".
	UsesICMPx bool
	// PortUnreachable reports whether the reject names the port-unreachable type
	// (the shape D70 froze — the v6 twin must carry it too).
	PortUnreachable bool
	// HasCounter reports whether the reject carries a `counter` (per-session
	// counting, D70 — the v6 twin must carry it too).
	HasCounter bool
	// Dormant reports whether the v6 leg is currently DORMANT (D75 not flipped on).
	// The shape is asserted now; the live v6 probe waits for D75.
	Dormant bool
}

// Named v6-twin shape-verification failure modes (Assertion 3).
var (
	// ErrNoUDP443Rule fires when the shipped artifact carries no udp/443 reject
	// rule at all — neither the v4 reject nor its dormant v6 twin exists.
	ErrNoUDP443Rule = errors.New("quicfallback: no udp/443 (QUIC) reject rule in the shipped NFT-4 artifact — neither the v4 reject nor its dormant v6 twin exists (doc 12 §10, D70)")
	// ErrV6TwinNotUnified fires when the udp/443 reject rule does NOT carry the v6
	// twin: it is neither authored in the `inet` family nor uses the `icmpx`
	// family-agnostic verdict, so the v6 reject would NOT exist dormantly — a
	// future v6 enable (D75) would leak udp/443 over v6. The shipped design carries
	// the v6 twin via inet+icmpx in ONE rule (doc 12 §10, NFT-4 §FAMILY header).
	ErrV6TwinNotUnified = errors.New("quicfallback: the udp/443 reject does not carry the dormant v6 twin — it is neither authored `inet` nor uses `icmpx`, so v6 udp/443 would leak once D75 enables v6; the v6 twin must be present-but-dormant NOW (doc 12 §10 'v6 twin … dormant-but-present', D75, NFT-4 §FAMILY)")
	// ErrV6TwinNotPortUnreachable fires when the v6 twin does not carry the same
	// port-unreachable reject shape as v4 — the dormant twin must match the v4
	// shape, not a bare reject or a drop.
	ErrV6TwinNotPortUnreachable = errors.New("quicfallback: the udp/443 reject does not name an icmp(x) port-unreachable type — the dormant v6 twin must carry the SAME reject-icmp-port-unreachable shape as v4 (doc 12 §10, D70)")
	// ErrV6TwinMissingCounter fires when the v6 twin's reject carries no counter —
	// the dormant twin must match v4's per-session counting.
	ErrV6TwinMissingCounter = errors.New("quicfallback: the udp/443 reject carries no `counter` — the dormant v6 twin must match v4's per-session counting (doc 12 §10, D70)")
)

// AssertV6TwinDormantShape reads the shipped NFT-4 artifact and verifies the
// dormant v6 reject twin is present-but-dormant in the SAME reject-icmp-port-
// unreachable shape as v4 (Assertion 3). A read failure is returned as-is (never
// silently treated as "no twin" — a false green the canary cannot afford). The
// shape is asserted regardless of D75; the returned V6TwinShape.Dormant reflects
// whether the v6 leg is currently live (D75) so the live probe knows to skip.
func AssertV6TwinDormantShape() (V6TwinShape, error) {
	data, err := os.ReadFile(NFT4ArtifactPath())
	if err != nil {
		return V6TwinShape{}, err
	}
	return assertV6TwinDormantShape(string(data))
}

// assertV6TwinDormantShape is the pure text→shape analyzer (separated so it is
// unit-testable against synthetic ruleset strings without the file read — the
// negative cases are proven against synthetic strings, never by mutating the
// shipped artifact). It mirrors the token analysis of the Rust ds-nft quic_reject
// lint and the resolverlock NFT-4 driver: comment-stripped, lowercased,
// word-boundary token tests.
func assertV6TwinDormantShape(text string) (V6TwinShape, error) {
	var (
		shape     V6TwinShape
		sawUDP443 bool
	)
	shape.Dormant = !V6Enabled()

	for _, raw := range strings.Split(text, "\n") {
		code := stripNftComment(raw)
		lc := strings.ToLower(code)

		// The artifact is authored in an `inet` table — record the family
		// unification at the table-declaration line, which is what lets ONE rule
		// carry both v4 and the v6 twin.
		if strings.Contains(lc, "table") && hasWord(lc, "inet") {
			shape.InetUnified = true
		}

		if !isUDP443Rule(lc) {
			continue
		}
		sawUDP443 = true
		if hasWord(lc, "icmpx") {
			shape.UsesICMPx = true
		}
		if namesPortUnreachable(lc) {
			shape.PortUnreachable = true
		}
		if hasWord(lc, "counter") {
			shape.HasCounter = true
		}
	}

	if !sawUDP443 {
		return shape, ErrNoUDP443Rule
	}
	// The v6 twin exists dormantly IFF the reject is family-unified: either the
	// `icmpx` family-agnostic verdict (emits icmpv6 port-unreachable on v6) OR an
	// `inet`-family authoring (the v6 twin rides the same table). The shipped shape
	// uses BOTH; either alone carries the dormant twin, neither means v6 would leak.
	if !shape.UsesICMPx && !shape.InetUnified {
		return shape, ErrV6TwinNotUnified
	}
	if !shape.PortUnreachable {
		return shape, ErrV6TwinNotPortUnreachable
	}
	if !shape.HasCounter {
		return shape, ErrV6TwinMissingCounter
	}
	return shape, nil
}

// ── shared nft text tokenizers (mirror resolverlock / ds-nft quic_reject) ─────

// isUDP443Rule reports whether a (lowercased, comment-stripped) line is a udp/443
// rule — a udp match plus a dport-443 selector. Same load-bearing tokens the Rust
// quic_reject lint and the resolverlock NFT-4 driver key on.
func isUDP443Rule(lc string) bool {
	mentionsUDP := hasWord(lc, "udp") || strings.Contains(lc, "l4proto udp")
	return mentionsUDP && hasWord(lc, "dport") && hasWord(lc, "443")
}

// namesPortUnreachable reports whether the reject names an icmp(x) port-unreachable
// type. nft spells it with a hyphen; tolerate the underscore form defensively. The
// icmp family token (`icmp` covers icmp/icmpv6/icmpx) must be present so a bare
// `reject` or a tcp-reset shape never passes.
func namesPortUnreachable(lc string) bool {
	namesType := strings.Contains(lc, "port-unreachable") || strings.Contains(lc, "port_unreachable")
	return namesType && strings.Contains(lc, "icmp")
}

// hasWord reports whether `word` appears as a whole token in `lc` (split on any
// non-alphanumeric byte), mirroring the Rust lints' token boundary so `443` does
// not match inside `4430` and `drop` does not match inside `dropper`.
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
// code part (same as the Rust lints' strip_comment and the resolverlock driver).
func stripNftComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}
