// SPDX-License-Identifier: Apache-2.0

// Package quiccanary is the conformance adapter for the D70 nightly QUIC
// conformance canary + standing flip-to-inspect trigger evaluation (doc 12 §7,
// doc 14 §10/§9). It is the doc 06 (c)/(d) rig extension that lands WITH NFT-4
// at Stage 2: a nightly job runs the pinned latest-stable client matrix against
// an api.anthropic.com-shaped baseline domain over BOTH QUIC and a TCP-direct
// control, measures p95 first-contact latency, and gates the D70 flip from
// block-QUIC to must-inspect-QUIC.
//
// # The guarantee (doc 12 §7, D70)
//
// QUIC posture is "udp/443 rejected + counted; keep block-with-fallback". The
// flip from block to must-inspect fires on any of three triggers; this package
// owns the FIRST and standing-est one:
//
//	(1) a NIGHTLY conformance canary — the latest stable versions of the pinned
//	    client set (curl, git, Node LTS+current/undici/npm, Python requests+httpx,
//	    Go net/http, Rust reqwest, gRPC, Anthropic Python+TS SDKs, headless Chrome
//	    stable) FAIL first-contact to a baseline domain OR regress p95 first-contact
//	    latency beyond budget vs a TCP-direct control.
//
// Trigger evaluation is a STANDING weekly/nightly check, NOT a judgment call
// (doc 12 §7). This package makes "does the canary fire the trigger?" a pure,
// testable verdict (Evaluate / Report.FlipToInspect).
//
// # Two populations, opposite pass conditions (doc 12 §7 — the corrected framing)
//
// The canary preserves the two-populations framing and NEVER merges the two
// layers into one assertion:
//
//   - DNS-4 rule 4 (HTTPS/SVCB suppression) is the STEERING control for
//     COOPERATIVE clients — it removes the only first-contact H3 path, so
//     happy-eyeballs clients (Chrome, curl --http3) fall back to TCP invisibly.
//     Their pass condition is: TCP first-contact SUCCEEDS within the p95 budget
//     (PopulationCooperative). A cooperative QUIC first-contact "failure" is the
//     EXPECTED, correct H3-suppression outcome — never a trigger.
//   - The NFT-4 udp/443 reject is the SOLE control for NON-COOPERATIVE clients
//     running raw QUIC (curl --http3-only, WebTransport, MASQUE, arbitrary quic
//     libraries). Their pass condition is the OPPOSITE: QUIC first-contact FAILS
//     FAST (the ICMP port-unreachable reject ⇒ ECONNREFUSED in <1s, never a
//     multi-second silent-drop hang). A raw-QUIC client that SUCCEEDS is a
//     boundary HOLE; a raw-QUIC client that fails SLOWLY signals a silent drop
//     (also a defect) — both surface as distinct named sentinels
//     (PopulationRawQUIC).
//
// # Golden-image neutrality (doc 12 §7)
//
// No HTTP/3-forcing config ships in the golden image. Headless Chrome runs
// default-QUIC-enabled so the canary measures REAL behavior; --disable-quic is a
// documented knob, not a default. The matrix records each client's stock QUIC
// posture (QUICPosture) so the harness never silently assumes a forcing flag.
//
// # Latency budget is FREE (doc 12 §9 / §13 free column, doc 14 §10)
//
// "Canary latency budget is free." The budget here (DefaultBudget:
// DefaultP95Budget absolute ceiling + DefaultRegressionMargin over the
// TCP-direct control) is BUILD GUIDANCE, not a frozen contract — tunable knobs
// the nightly job owner adjusts as the baseline is characterized. The relative
// margin over the TCP-direct control is the primary regression signal (the
// canary's whole "boundary TCP vs TCP-direct control" framing); the absolute
// ceiling is the backstop when no control measurement is available.
//
// # Two halves, one verdict logic
//
//   - OFFLINE (default, always runs; no network): harness_test.go drives the
//     PURE verdict/trigger logic (LatencyBudget, Percentile/p95, VerdictFor,
//     Evaluate, Report.FlipToInspect) against SYNTHETIC measurements — proving
//     each named trigger/hole condition fires (and the happy paths do not) the
//     same way resolverlock asserts the NFT-4 shape offline before the live tier.
//   - LIVE (env-gated DS_QUIC_CANARY_LIVE=1, default SKIPPED): RunLive drives the
//     REAL pinned clients over the wire against DS_QUIC_CANARY_BASELINE (or the
//     BaselineDomain default) through a running boundary, then feeds the
//     measurements to the same Evaluate. It is a DEFERRED MANUAL step — it needs
//     a running boundary + the real client binaries the wave sandbox lacks — so
//     until an operator wires the drivers it fails LOUDLY with
//     ErrLiveDriverNotWired (never a vacuous green).
//
// # The shared workload matrix (doc 14 §10)
//
// The pinned-version table (workload_matrix.go: Matrix) is deliberately NOT in a
// _test.go file: the live half reuses it verbatim, AND "the same workload matrix
// serves the D74 baseline-endpoint discovery sessions" (doc 14 §10). The Client
// rows carry the pinned latest-stable Version the nightly job bumps; a version
// bump that regresses first-contact or p95 is itself a flip-trigger signal.
//
// # The env-gate contract
//
//   - DS_QUIC_CANARY_LIVE unset or != "1" (default, the CI posture): LiveEnabled()
//     is false, the live test SKIPS naming this var, no network is touched.
//   - "1": the operator opts in; the live driver fails loudly until wired.
//   - DS_QUIC_CANARY_BASELINE (LiveBaseline): points the live run at a
//     deployment's baseline domain; it only resolves WHERE — the gate above still
//     governs WHETHER.
//
// # What this package does NOT own
//
// The udp/443 REJECT itself (the on-box NFT-4 reject-not-drop + ICMP
// port-unreachable + per-session counter) is owned by the ds-nft ruleset and
// asserted offline by the resolverlock NFT-4 closure driver
// (resolverlock.AssertNFT4ClosureShape) and over the wire by the doc 06 (c)
// bypass rows. The HTTPS/SVCB suppression (DNS-4 rule 4) is owned by ds-dnsgate.
// This package is the runnable bridge that MEASURES whether those two controls,
// working together, keep the pinned developer-value clients fast on TCP and the
// raw-QUIC population fast-failed — and that turns "should we flip to inspect?"
// into a standing, non-judgment-call verdict.
//
// # Egress-gateway / TLS-termination vocabulary
//
// ds-tlsproxy is the EGRESS GATEWAY — the TLS-terminating boundary service on the
// egress path. The flip-to-inspect this canary gates is the D70 carveout: if QUIC
// is ever inspected it would be a SEPARATE non-pingora UDP terminator slotting in
// behind the same mechanism-agnostic recovery interface (doc 12 §7 clean seam) —
// no roadmap commitment, only a measured, queryable trigger.
package quiccanary
