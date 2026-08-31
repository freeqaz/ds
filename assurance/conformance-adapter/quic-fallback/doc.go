// SPDX-License-Identifier: Apache-2.0

// Package quicfallback is the conformance adapter for the doc 12 §10 "QUIC
// fast-fail / fallback" assurance row — the runnable bridge that proves the D70
// udp/443 posture ("block-with-fallback": reject-not-drop + observable ICMP
// port-unreachable + per-session counter) keeps non-cooperative raw-QUIC clients
// FAST-FAILED and cooperative happy-eyeballs clients fast on TCP. It builds on the
// tlsproxyinspect (TLS-3) and resolverlock (NFT-4) conformance-adapter precedents
// and attaches to the SAME boundary/tlsproxy contract seams the TLS-1/TLS-3 tests
// consume (the acceptance side is the same proxy under test).
//
// It is the sibling of the quiccanary package: quiccanary owns the NIGHTLY
// latest-stable-client conformance matrix + the standing flip-to-inspect trigger
// verdict; this package owns the THREE doc 12 §10 row assertions — the fast-fail
// reject (with ICMP capture), the happy-eyeballs TCP fallback, and the dormant v6
// twin shape — that the canary's two-populations framing rests on.
//
// # The three assertions (doc 12 §10 verbatim row)
//
// "QUIC fast-fail / fallback: `curl --http3-only` to an allowed domain fails in
// <1s (ICMP type 3 code 3 asserted by capture); `curl --http3` succeeds over TCP
// within budget. v6 twin of the reject rule asserted dormant-but-present."
//
//	(1) FAST-FAIL (raw-QUIC, the udp/443 reject): a raw-QUIC client
//	    (curl --http3-only) to an allowed baseline domain (api.anthropic.com, in
//	    the D74 baseline pack) FAILS in <1s, and a packet CAPTURE asserts the
//	    failure was an ICMP type 3 code 3 (port-unreachable) — reject-not-drop, NOT
//	    a silent-drop timeout (D70, doc 12 §13.5). icmp_capture.go's
//	    FastFailVerdict is the pure decision; the env-gated live half feeds it a
//	    real tcpdump/scapy capture, the offline half feeds it synthetic
//	    observations including the silent-drop / wrong-shape / boundary-hole
//	    negatives.
//	(2) FALLBACK (cooperative, happy-eyeballs): a fallback-enabled client
//	    (curl --http3) to the SAME domain SUCCEEDS over TCP within the latency
//	    budget — DNS-4 rule 4 (HTTPS/SVCB suppression) steers it onto TCP, where it
//	    is fast. This reuses the quiccanary cooperative verdict (the
//	    PopulationCooperative latency-budget logic), so the two packages share one
//	    definition of "fast on TCP".
//	(3) DORMANT V6 TWIN (D75 feature gate): the v6 reject is asserted
//	    present-but-dormant NOW — the shipped NFT-4 ruleset's udp/443 reject is
//	    family-unified (`inet` table + `icmpx` verdict) so the SAME rule emits ICMP
//	    port-unreachable on v4 and ICMPv6 port-unreachable on v6, carrying the v6
//	    twin in the identical reject-icmp-port-unreachable + counter shape, gated
//	    off until D75 enables v6 end to end. AssertV6TwinDormantShape shape-verifies
//	    it from the ruleset artifact; written now, exercised live when D75 flips.
//
// # Two populations, NEVER merged (doc 12 §10, D70, doc 11 §3.3)
//
// The doc 12 §10 row and D70 are explicit: the udp/443-reject control (the SOLE
// control for non-cooperative raw QUIC — curl --http3-only, WebTransport, MASQUE,
// raw quic libs) and the HTTPS/SVCB-suppression control (DNS-4 rule 4 steering
// for COOPERATIVE clients) are two INDEPENDENT controls, tested independently and
// NEVER merged into one assertion. Accordingly assertion (1) and assertion (2)
// live in SEPARATE tests with opposite pass conditions: a raw-QUIC client PASSES
// by failing fast; a cooperative client PASSES by succeeding on TCP. Nothing in
// the fast-fail path consults DNS/steering state, and nothing in the fallback
// path consults the reject. The shipped NFT-4 ruleset header restates the same
// invariant ("two independent controls, never merged into one assertion").
//
// # Offline + env-gated live (the precedent split)
//
//   - OFFLINE (default, always runs; no network, no root): the pure verdict logic
//     (FastFailVerdict over synthetic FastFailObservations; the cooperative
//     latency budget) AND the shipped-artifact shape (AssertV6TwinDormantShape
//     over the real NFT-4 ruleset) — exactly as resolverlock asserts the NFT-4
//     shape offline before the live tier, and as tlsproxyinspect drives its golden
//     traces offline. This is what keeps CI honest about the contract before the
//     live tier lands.
//   - LIVE (env-gated DS_QUIC_FALLBACK_LIVE=1, default SKIPPED): drives the REAL
//     curl --http3-only / curl --http3 to the baseline domain through a running
//     boundary while a raw ICMP capture (CAP_NET_RAW) runs, then feeds the
//     observation to the SAME FastFailVerdict. It is a DEFERRED MANUAL step (it
//     needs a running boundary + the real client binaries + CAP_NET_RAW the wave
//     sandbox lacks), so until an operator wires the driver it fails LOUDLY with
//     ErrLiveCaptureNotWired — never a vacuous green.
//
// # The D75 v6 gate
//
//   - DS_QUIC_V6_LIVE unset or != "1" (default): the v6 twin is DORMANT — its rule
//     SHAPE is asserted (assertion 3) but the live v6 probe is SKIPPED. This is
//     the standing CI posture: v6 is not enabled end to end (D75).
//   - "1": an operator opts the v6 leg live (the live v6 probe remains a deferred
//     manual step). The shape assertion holds either way.
//
// # What this package does NOT own
//
// The udp/443 REJECT itself (the on-box NFT-4 reject-not-drop + ICMP
// port-unreachable + per-session counter) is owned by the ds-nft ruleset and its
// quic_reject contract lint (dataplane/crates/ds-nft/src/quic_reject.rs, already
// in place, D70), and asserted offline by the resolverlock NFT-4 closure driver
// (resolverlock.AssertNFT4ClosureShape). This package reuses the SAME shipped
// artifact those two readers govern for assertion 3 — one artifact, three readers,
// no drift. The HTTPS/SVCB suppression (DNS-4 rule 4) is owned by ds-dnsgate. The
// nightly client matrix + flip-to-inspect verdict is owned by quiccanary. This
// package is the doc 12 §10 row's runnable proof that those controls, working
// together, fail raw QUIC fast (with a captured ICMP) and keep cooperative clients
// fast on TCP — with the v6 twin written now and dormant until D75.
//
// # Egress-gateway / TLS-termination vocabulary
//
// ds-tlsproxy is the EGRESS GATEWAY — the TLS-terminating boundary service on the
// egress path. The TCP/443 fallback the reject forces non-cooperative clients onto
// is the path this egress gateway can see and (at TLS-1/TLS-3) terminate; the
// dormant flip-to-inspect would slot a separate non-pingora UDP terminator behind
// the same mechanism-agnostic recovery seam (doc 12 §7 clean seam, D69) — no
// roadmap commitment, only a measured, queryable trigger this row helps gate.
package quicfallback
