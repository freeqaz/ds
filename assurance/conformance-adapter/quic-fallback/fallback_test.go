// SPDX-License-Identifier: Apache-2.0

package quicfallback

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	quiccanary "github.com/dream-serpent/dream-serpent/assurance/conformance-adapter/quic-canary"
)

// fallback_test.go — the three doc 12 §10 "QUIC fast-fail / fallback" assertions:
//
//	(1) raw-QUIC (curl --http3-only) fails in <1s, ICMP type 3 code 3 captured;
//	(2) cooperative (curl --http3) succeeds over TCP within budget;
//	(3) the v6 reject twin is asserted dormant-but-present (D75 feature gate).
//
// Assertions (1) and (2) are SEPARATE tests with OPPOSITE pass conditions — the
// two-populations framing is NEVER merged into one assertion (doc 12 §10, D70,
// doc 11 §3.3). The offline half (default) drives the pure verdict + shipped
// artifact shape; the env-gated live half drives real clients + capture.

// ── Assertion 1: raw-QUIC fast-fail with captured ICMP port-unreachable ───────

// goodFastFail is the canonical correct raw-QUIC observation: the udp/443
// first-contact FAILED, FAST (well under the threshold), and a captured ICMP
// type 3 code 3 (v4 port-unreachable) PROVES it was the reject, not a silent
// drop. This is the shape the live curl --http3-only capture must produce.
func goodFastFail() FastFailObservation {
	return FastFailObservation{
		Family:        FamilyV4,
		ConnectFailed: true,
		FailLatency:   120 * time.Millisecond, // ECONNREFUSED, ~instant
		ICMPCaptured:  true,
		ICMP:          &CapturedICMP{Family: FamilyV4, Type: ICMPv4TypeDestUnreachable, Code: ICMPv4CodePortUnreachable},
	}
}

// TestAssertion1_RawQUICFastFailWithCapturedICMP is the doc 12 §10 fast-fail row:
// curl --http3-only to the allowed baseline domain FAILS in <1s and the capture
// asserts an ICMP type 3 code 3 (port-unreachable). The verdict must pass on the
// correct shape with NO trigger.
func TestAssertion1_RawQUICFastFailWithCapturedICMP(t *testing.T) {
	obs := goodFastFail()
	if obs.FailLatency >= FastFailThreshold {
		t.Fatalf("the canonical fast-fail observation must fail under the <1s threshold; got %s ≥ %s", obs.FailLatency, FastFailThreshold)
	}
	if err := FastFailVerdict(obs); err != nil {
		t.Fatalf("a fast-fail with a captured ICMP type 3 code 3 must pass cleanly; got: %v", err)
	}
	// The captured ICMP must be the doc 12 §10 verbatim shape: type 3 code 3.
	if obs.ICMP.Type != 3 || obs.ICMP.Code != 3 {
		t.Fatalf("doc 12 §10 names ICMP type 3 code 3 verbatim; the constants resolved to type %d code %d", obs.ICMP.Type, obs.ICMP.Code)
	}
	if !IsPortUnreachable(FamilyV4, 3, 3) {
		t.Fatal("IsPortUnreachable(v4, 3, 3) must be true — ICMP type 3 code 3 is v4 port-unreachable")
	}
}

// TestAssertion1_FastFailNegatives is the table-driven failure gate: each row is
// ONE way the fast-fail row can break, asserting the verdict fires the SPECIFIC
// named sentinel (errors.Is) rather than passing vacuously. These prove the
// assertion has teeth — especially that a SILENT DROP (the exact mode D70 forbids)
// is rejected as loudly as a boundary hole.
func TestAssertion1_FastFailNegatives(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(FastFailObservation) FastFailObservation
		wantErr error
	}{
		{
			// udp/443 SUCCEEDED — the reject is not controlling: a boundary hole.
			name:    "raw-QUIC succeeded (boundary hole)",
			mutate:  func(o FastFailObservation) FastFailObservation { o.ConnectFailed = false; return o },
			wantErr: ErrUDP443NotRejected,
		},
		{
			// Failed, but SLOWLY — a silent-drop hang, not the fast ICMP reject.
			name: "slow fail (silent-drop hang)",
			mutate: func(o FastFailObservation) FastFailObservation {
				o.FailLatency = 5 * time.Second
				return o
			},
			wantErr: ErrSlowFail,
		},
		{
			// Failed fast, but NO ICMP captured — a silent drop, the doc 12 §13.5
			// defect reject-not-drop exists to prevent (a timeout proves nothing).
			name: "fast fail but no ICMP captured (silent drop)",
			mutate: func(o FastFailObservation) FastFailObservation {
				o.ICMPCaptured = false
				o.ICMP = nil
				return o
			},
			wantErr: ErrNoICMPCaptured,
		},
		{
			// An ICMP WAS captured but it is the WRONG code (host-unreachable, code
			// 1) — not the port-unreachable (code 3) shape D70 froze.
			name: "wrong ICMP code (host-unreachable, not port)",
			mutate: func(o FastFailObservation) FastFailObservation {
				o.ICMP = &CapturedICMP{Family: FamilyV4, Type: 3, Code: 1}
				return o
			},
			wantErr: ErrWrongICMPShape,
		},
		{
			// The capture observed an ICMPv6 packet for a v4 probe — wiring defect.
			name: "captured family mismatch (v6 ICMP for v4 probe)",
			mutate: func(o FastFailObservation) FastFailObservation {
				o.ICMP = &CapturedICMP{Family: FamilyV6, Type: ICMPv6TypeDestUnreachable, Code: ICMPv6CodePortUnreachable}
				return o
			},
			wantErr: ErrICMPFamilyMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := tc.mutate(goodFastFail())
			err := FastFailVerdict(obs)
			if err == nil {
				t.Fatalf("expected the fast-fail verdict to fail with %v; got nil (vacuous pass)", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected sentinel %v; got %v", tc.wantErr, err)
			}
		})
	}
}

// TestAssertion1_Live is the env-gated live half (DS_QUIC_FALLBACK_LIVE=1): it
// drives the REAL curl --http3-only to the baseline domain with a raw ICMP
// capture, then feeds the observation to the SAME FastFailVerdict. SKIPPED by
// default (the standing CI posture); when opted in it fails LOUDLY until an
// operator wires the capture driver (never a vacuous green).
func TestAssertion1_Live(t *testing.T) {
	if !LiveEnabled() {
		t.Skipf("offline by default; set %s=1 to drive curl --http3-only + raw ICMP capture against %s", LiveEnvVar, quiccanary.BaselineDomain)
	}
	obs, err := RunLiveFastFail(FamilyV4)
	if err != nil {
		// Until the operator wires the real driver this is the expected loud
		// failure — DS_QUIC_FALLBACK_LIVE=1 must never report a false green.
		t.Fatalf("live fast-fail capture against %s not wired (a DEFERRED MANUAL step): %v", quiccanary.BaselineDomain, err)
	}
	if verr := FastFailVerdict(obs); verr != nil {
		t.Fatalf("live curl --http3-only to %s did not fast-fail with a captured ICMP port-unreachable: %v", quiccanary.BaselineDomain, verr)
	}
}

// ── Assertion 2: cooperative happy-eyeballs TCP fallback within budget ─────────
//
// This is the SEPARATE population — pass condition is the OPPOSITE of assertion 1.
// It reuses the quiccanary cooperative latency-budget verdict so the two packages
// share ONE definition of "fast on TCP" (the canary's whole framing) and never
// merge with the udp/443-reject assertion above (doc 12 §10, D70, doc 11 §3.3).

// TestAssertion2_HappyEyeballsTCPFallbackWithinBudget is the doc 12 §10 fallback
// row: curl --http3 (happy-eyeballs) to the SAME baseline domain SUCCEEDS over
// TCP within budget. DNS-4 rule 4 suppresses H3, so the client falls back to TCP
// invisibly; the pass condition is a successful, in-budget TCP first-contact.
func TestAssertion2_HappyEyeballsTCPFallbackWithinBudget(t *testing.T) {
	// curl --http3 is the cooperative happy-eyeballs row in the shared matrix.
	const client = "curl-http3"
	var coop quiccanary.Client
	for _, c := range quiccanary.CooperativeClients() {
		if c.Name == client {
			coop = c
			break
		}
	}
	if coop.Name == "" {
		t.Fatalf("the shared workload matrix must carry the cooperative happy-eyeballs row %q (curl --http3)", client)
	}
	if coop.Population != quiccanary.PopulationCooperative {
		t.Fatalf("%s must be PopulationCooperative (its pass condition is TCP success, the OPPOSITE of the raw-QUIC reject)", client)
	}

	budget := quiccanary.DefaultBudget()
	// Synthetic measurements: TCP first-contact SUCCEEDS, fast (well within the
	// p95 ceiling); the QUIC leg "fails" (H3 suppressed) — the EXPECTED cooperative
	// outcome, never a trigger. This is what a real curl --http3 capture produces.
	tcpSamples := []time.Duration{180 * time.Millisecond, 210 * time.Millisecond, 240 * time.Millisecond}
	ms := []quiccanary.Measurement{
		{Client: client, Transport: quiccanary.TransportTCP, FirstContactOK: true, Latencies: tcpSamples},
		{Client: client, Transport: quiccanary.TransportQUIC, FirstContactOK: false, Latencies: []time.Duration{90 * time.Millisecond}},
	}
	// A representative TCP-direct control (no boundary) for the relative-regression
	// check; the boundary leg is well within DefaultRegressionMargin of it.
	control := 160 * time.Millisecond

	report := quiccanary.Evaluate(ms, budget, control)
	var got quiccanary.ClientVerdict
	for _, v := range report.Verdicts {
		if v.Client == client {
			got = v
			break
		}
	}
	if got.Client == "" {
		t.Fatalf("Evaluate did not return a verdict for %q", client)
	}
	if got.Triggered {
		t.Fatalf("cooperative %s succeeding on TCP within budget must NOT trigger the flip; got: %v", client, got.Err)
	}
	if got.TCPP95 > budget.P95Ceiling {
		t.Fatalf("%s TCP p95 %s must be within the budget ceiling %s", client, got.TCPP95, budget.P95Ceiling)
	}
}

// TestAssertion2_FallbackFailureIsATrigger pins the negative: a cooperative
// client whose TCP first-contact FAILS (the developer-value endpoint unreachable
// over the transport DNS-4 steers it onto) fires the flip trigger. This proves
// assertion 2 has teeth — a broken TCP fallback is loud, not silent.
func TestAssertion2_FallbackFailureIsATrigger(t *testing.T) {
	const client = "curl-http3"
	budget := quiccanary.DefaultBudget()
	ms := []quiccanary.Measurement{
		{Client: client, Transport: quiccanary.TransportTCP, FirstContactOK: false, Latencies: nil},
	}
	report := quiccanary.Evaluate(ms, budget, 0)
	for _, v := range report.Verdicts {
		if v.Client != client {
			continue
		}
		if !v.Triggered {
			t.Fatalf("a cooperative %s with a FAILED TCP first-contact must trigger the flip", client)
		}
		if !errors.Is(v.Err, quiccanary.ErrFirstContactFailed) {
			t.Fatalf("expected ErrFirstContactFailed; got %v", v.Err)
		}
		return
	}
	t.Fatalf("Evaluate returned no verdict for %q", client)
}

// TestPopulationsAreSeparate guards the doc 12 §10 / D70 "never merged" invariant
// directly: curl supplies BOTH populations through TWO distinct matrix rows
// (curl-http3 cooperative, curl-http3-only raw-QUIC) with OPPOSITE pass
// conditions, and they are evaluated by DIFFERENT code paths (the cooperative
// latency verdict vs the udp/443-reject FastFailVerdict). If a refactor ever
// collapsed them into one row/one verdict, this test fails.
func TestPopulationsAreSeparate(t *testing.T) {
	var sawCoop, sawRaw bool
	for _, c := range quiccanary.Matrix() {
		switch c.Name {
		case "curl-http3":
			sawCoop = true
			if c.Population != quiccanary.PopulationCooperative {
				t.Fatalf("curl-http3 must be the cooperative population (TCP-success pass condition)")
			}
		case "curl-http3-only":
			sawRaw = true
			if c.Population != quiccanary.PopulationRawQUIC {
				t.Fatalf("curl-http3-only must be the raw-QUIC population (fast-fail pass condition)")
			}
		}
	}
	if !sawCoop || !sawRaw {
		t.Fatalf("the shared matrix must carry BOTH curl populations as SEPARATE rows (never merged): coop=%v raw=%v", sawCoop, sawRaw)
	}
	// The two pass conditions are opposite: a cooperative success is a pass; a
	// raw-QUIC success is a FAILURE (the boundary hole). The fast-fail verdict and
	// the cooperative latency verdict are distinct functions — assert the fast-fail
	// path treats a raw-QUIC success as a hole.
	hole := FastFailVerdict(FastFailObservation{Family: FamilyV4, ConnectFailed: false})
	if !errors.Is(hole, ErrUDP443NotRejected) {
		t.Fatalf("the raw-QUIC pass condition is the OPPOSITE of cooperative: a udp/443 SUCCESS must be a hole, not a pass; got %v", hole)
	}
}

// ── Assertion 3: dormant v6 twin shape, verified from the ruleset artifact ─────

// TestAssertion3_ShippedV6TwinDormantShape verifies the dormant v6 reject twin is
// present-but-dormant in the SHIPPED NFT-4 artifact, in the SAME reject-icmp-
// port-unreachable + counter shape as v4. With D75 not set (the standing CI
// posture) the v6 leg is dormant: its shape is asserted now, the live v6 probe is
// deferred until D75 flips. This is the doc 12 §10 "v6 twin … dormant-but-present"
// row, asserted offline over the real artifact (the resolverlock NFT-4 precedent).
func TestAssertion3_ShippedV6TwinDormantShape(t *testing.T) {
	shape, err := AssertV6TwinDormantShape()
	if err != nil {
		t.Fatalf("shipped NFT-4 artifact (%s) fails the dormant-v6-twin shape: %v", NFT4ArtifactPath(), err)
	}
	// The shipped design carries the v6 twin via the inet/icmpx unification — ONE
	// rule emits the family-appropriate port-unreachable (icmp v4, icmpv6 v6).
	if !shape.UsesICMPx && !shape.InetUnified {
		t.Fatalf("the shipped udp/443 reject must carry the v6 twin (inet table and/or icmpx verdict); shape=%+v", shape)
	}
	if !shape.PortUnreachable {
		t.Fatalf("the v6 twin must carry the same port-unreachable reject shape as v4; shape=%+v", shape)
	}
	if !shape.HasCounter {
		t.Fatalf("the v6 twin must carry the same per-session counter as v4; shape=%+v", shape)
	}
	// D75 is not set in standing CI, so the v6 leg must report dormant — the shape
	// is verified now, the live v6 probe waits for D75.
	if V6Enabled() {
		t.Logf("DS_QUIC_V6_LIVE=1: v6 leg opted live; the live v6 probe is a deferred manual step")
	} else if !shape.Dormant {
		t.Fatalf("with D75 (%s) unset the v6 leg must be dormant; shape=%+v", D75EnvVar, shape)
	}
}

// goodV6Twin is a minimal well-formed synthetic NFT-4 fragment carrying the v6
// twin via inet+icmpx — the BASELINE the negative cases perturb. Negative cases
// are proven against synthetic strings, NEVER by mutating the shipped artifact
// (which stays read-only, asserted by the test above).
const goodV6Twin = `table inet ds_resolver_closure {
  chain resolver_closure_forward {
    iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable
  }
}
`

// TestAssertion3_GoodV6TwinPasses pins that the well-formed synthetic fragment
// passes the shape analyzer cleanly (no false positive).
func TestAssertion3_GoodV6TwinPasses(t *testing.T) {
	shape, err := assertV6TwinDormantShape(goodV6Twin)
	if err != nil {
		t.Fatalf("a well-formed inet+icmpx udp/443 reject must pass the v6-twin shape cleanly; got %v", err)
	}
	if !shape.InetUnified || !shape.UsesICMPx || !shape.PortUnreachable || !shape.HasCounter {
		t.Fatalf("the good fragment must satisfy every shape field; got %+v", shape)
	}
}

// TestAssertion3_V6TwinNegatives is the table-driven failure gate for the v6-twin
// shape: each row perturbs the good fragment into ONE shape failure, asserting the
// analyzer fires the SPECIFIC named sentinel (errors.Is). These prove the dormant
// twin cannot silently rot into a v6-leaking shape.
func TestAssertion3_V6TwinNegatives(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		wantErr error
	}{
		{
			// No udp/443 rule at all — neither the v4 reject nor its v6 twin exists.
			name: "no udp/443 rule",
			text: strings.Replace(goodV6Twin,
				`    iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable
`, "", 1),
			wantErr: ErrNoUDP443Rule,
		},
		{
			// A v4-ONLY reject (ip table + icmp, not inet/icmpx) — the v6 twin would
			// NOT exist, so v6 udp/443 would leak once D75 enables v6.
			name: "v4-only reject (no inet/icmpx unification)",
			text: `table ip ds_v4_only {
  chain forward {
    iifname "dstap-*" udp dport 443 counter reject with icmp type port-unreachable
  }
}
`,
			wantErr: ErrV6TwinNotUnified,
		},
		{
			// inet table but a BARE reject — the inet authoring still carries the
			// family unification (ErrV6TwinNotUnified is NOT tripped), so this
			// isolates the port-unreachable check: the v6 twin does not carry the
			// reject-icmp-port-unreachable shape.
			name: "bare reject (no port-unreachable)",
			text: strings.Replace(goodV6Twin,
				`reject with icmpx type port-unreachable`,
				`reject`, 1),
			wantErr: ErrV6TwinNotPortUnreachable,
		},
		{
			// inet/icmpx, names icmpx, but NO counter — the v6 twin lacks per-session
			// counting.
			name: "missing counter",
			text: strings.Replace(goodV6Twin,
				`udp dport 443 counter reject with icmpx type port-unreachable`,
				`udp dport 443 reject with icmpx type port-unreachable`, 1),
			wantErr: ErrV6TwinMissingCounter,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := assertV6TwinDormantShape(tc.text)
			if err == nil {
				t.Fatalf("expected the v6-twin shape to fail with %v; got nil (vacuous pass)", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected sentinel %v; got %v", tc.wantErr, err)
			}
		})
	}
}

// TestAssertion3_PortUnreachableNotUnified exercises the port-unreachable failure
// path distinctly: an inet table whose udp/443 rule rejects with a NON-icmp shape
// (a tcp-reset spelling) but keeps a counter — inet carries the family
// unification, so ErrV6TwinNotUnified is not tripped, isolating the
// port-unreachable check.
func TestAssertion3_PortUnreachableNotUnified(t *testing.T) {
	text := `table inet ds_resolver_closure {
  chain forward {
    iifname "dstap-*" udp dport 443 counter reject with tcp reset
  }
}
`
	_, err := assertV6TwinDormantShape(text)
	if !errors.Is(err, ErrV6TwinNotPortUnreachable) {
		t.Fatalf("an inet reject without icmp port-unreachable must fire ErrV6TwinNotPortUnreachable; got %v", err)
	}
}

// TestICMPv6PortUnreachableShape pins the v6 ICMP constants: once D75 flips, the
// icmpx verdict emits ICMPv6 type 1 code 4 (port-unreachable) on the v6 leg — the
// shape the live v6 probe will assert. Written now so the constants do not drift.
func TestICMPv6PortUnreachableShape(t *testing.T) {
	if !IsPortUnreachable(FamilyV6, ICMPv6TypeDestUnreachable, ICMPv6CodePortUnreachable) {
		t.Fatal("IsPortUnreachable(v6, 1, 4) must be true — ICMPv6 type 1 code 4 is v6 port-unreachable")
	}
	if IsPortUnreachable(FamilyV6, 3, 3) {
		t.Fatal("v4's type 3 code 3 must NOT count as a v6 port-unreachable (the families differ)")
	}
	if IsPortUnreachable(FamilyV4, ICMPv6TypeDestUnreachable, ICMPv6CodePortUnreachable) {
		t.Fatal("v6's type 1 code 4 must NOT count as a v4 port-unreachable (the families differ)")
	}
}

// TestD75GateDefaultDormant guards the standing posture directly: with the D75
// env var UNSET the v6 leg is dormant (V6Enabled false), and with it set to "1"
// it reports live. This is the feature gate that keeps the v6 twin written-now /
// exercised-when-D75.
func TestD75GateDefaultDormant(t *testing.T) {
	t.Setenv(D75EnvVar, "")
	if V6Enabled() {
		t.Fatalf("with %s unset the v6 leg must be dormant", D75EnvVar)
	}
	t.Setenv(D75EnvVar, "1")
	if !V6Enabled() {
		t.Fatalf("with %s=1 the v6 leg must report live", D75EnvVar)
	}
}

// TestLiveGateDefaultOffline guards that the live capture half is offline by
// default (the standing CI posture) and that RunLiveFastFail refuses loudly when
// the gate is off — never a vacuous empty observation.
func TestLiveGateDefaultOffline(t *testing.T) {
	t.Setenv(LiveEnvVar, "")
	if LiveEnabled() {
		t.Fatalf("with %s unset the live capture half must be offline", LiveEnvVar)
	}
	if _, err := RunLiveFastFail(FamilyV4); !errors.Is(err, ErrLiveCaptureNotWired) {
		t.Fatalf("RunLiveFastFail with the live gate off must refuse with ErrLiveCaptureNotWired; got %v", err)
	}
}

// TestMain keeps the package's env-gate reads honest under `go test`: it does NOT
// set any DS_QUIC_* var, so the default run is offline + v6-dormant exactly as CI
// sees it. (Present so a future global setup has a home; currently a pass-through.)
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
