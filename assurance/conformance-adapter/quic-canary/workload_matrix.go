// SPDX-License-Identifier: Apache-2.0

package quiccanary

// workload_matrix.go — the pinned-client workload matrix for the D70 nightly
// QUIC conformance canary (doc 12 §7, doc 14 §10/§9). One table of clients
// drives BOTH halves of the canary suite: the offline half (harness_test.go)
// evaluates the matrix shape + the latency-budget / regression verdict logic
// against synthetic measurements with no network, and the env-gated live half
// (gated behind LiveEnvVar) replays the SAME matrix against real client wire
// shapes over both QUIC and a TCP-direct control. Keeping the matrix here — not
// inside a _test.go file — is what lets the live half reuse it verbatim, and is
// also what lets the D74 baseline-endpoint discovery sessions share the exact
// same pinned-version table (doc 14 §10: "the same workload matrix serves the
// D74 baseline-endpoint discovery sessions").
//
// # The two populations (doc 12 §7, the corrected framing)
//
// DNS-4 rule 4 (HTTPS/SVCB suppression) is the STEERING control for cooperative
// (spec-following) clients — it removes the only first-contact H3 path, so a
// happy-eyeballs client (Chrome, curl --http3) falls back to TCP invisibly. The
// NFT-4 udp/443 reject is the SOLE control for NON-cooperative clients running
// raw QUIC (curl --http3-only, WebTransport, MASQUE, arbitrary quic libraries).
// The two layers are tested independently, never merged into one assertion
// (doc 12 §7 two-populations framing):
//
//   - PopulationCooperative clients are measured over BOTH transports. They must
//     succeed first-contact and stay inside the p95 latency budget over TCP (the
//     transport DNS-4 steers them onto); their QUIC leg is measured for
//     observability but a QUIC first-contact "failure" is the EXPECTED, correct
//     outcome when the boundary suppresses H3 — a cooperative client that cannot
//     do H3 simply uses TCP, which is the pass condition.
//   - PopulationRawQUIC clients (curl --http3-only) are QUIC-ONLY: they have no
//     TCP fallback. They are measured SEPARATELY to VALIDATE the reject mechanism
//     — the correct outcome is a FAST first-contact FAILURE (ICMP port-unreachable
//     ⇒ ECONNREFUSED in <1s, never a multi-second silent-drop hang). A raw-QUIC
//     client that SUCCEEDS is the boundary hole.
//
// # Golden-image neutrality (doc 12 §7)
//
// No HTTP/3-forcing config ships in the golden image. Headless Chrome runs
// default-QUIC-enabled so the canary measures REAL behavior; --disable-quic is a
// documented knob, not a default. The matrix records each client's stock
// QUIC-enablement posture so the harness never silently assumes a forcing flag.

// Population labels which of the two doc 12 §7 populations a pinned client
// belongs to. The canary verdict logic treats the two populations with opposite
// pass conditions (see VerdictFor), so this is load-bearing, not descriptive.
type Population string

const (
	// PopulationCooperative: a spec-following client that does happy-eyeballs or
	// honors HTTPS/SVCB suppression. Steered onto TCP by DNS-4 rule 4. Pass
	// condition: TCP first-contact succeeds within the p95 budget.
	PopulationCooperative Population = "cooperative"
	// PopulationRawQUIC: a non-cooperative QUIC-only client (curl --http3-only)
	// with no TCP fallback. Controlled solely by the NFT-4 udp/443 reject. Pass
	// condition: QUIC first-contact FAILS FAST (the reject mechanism validated).
	PopulationRawQUIC Population = "raw-quic"
)

// Transport is one of the two legs every cooperative client is measured over.
// Raw-QUIC clients are measured over QUIC only.
type Transport string

const (
	// TransportTCP: the TCP-direct control leg — HTTP/1.1 or HTTP/2 over TCP 443.
	// This is the transport DNS-4 steers cooperative clients onto, and the
	// control the QUIC leg's latency is compared against.
	TransportTCP Transport = "tcp"
	// TransportQUIC: the QUIC / HTTP/3 leg (--http3 or default-enabled). For
	// cooperative clients it is the suppressed/fallback leg; for raw-QUIC clients
	// it is the only leg.
	TransportQUIC Transport = "quic"
)

// QUICPosture records how a pinned client engages QUIC out of the box, so the
// harness never silently assumes an HTTP/3-forcing flag the golden image does
// not ship (doc 12 §7 golden-image neutrality).
type QUICPosture string

const (
	// PostureHappyEyeballs: races H3 against TCP and falls back invisibly
	// (Chrome default-QUIC-enabled, curl --http3). Cooperative.
	PostureHappyEyeballs QUICPosture = "happy-eyeballs"
	// PostureTCPOnly: the stock client speaks no QUIC at all (git, Go net/http
	// default, Python requests, Rust reqwest default). Cooperative; its QUIC leg
	// is not measured (NoQUICLeg=true).
	PostureTCPOnly QUICPosture = "tcp-only"
	// PostureQUICForced: a deliberately QUIC-only invocation with no TCP fallback
	// (curl --http3-only). Raw-QUIC; used ONLY to validate the reject mechanism,
	// never shipped as a workload default.
	PostureQUICForced QUICPosture = "quic-forced"
)

// Client is one pinned entry of the conformance workload matrix: a real client
// at a pinned latest-stable version, its population, and its QUIC posture.
type Client struct {
	// Name is the stable client identifier, used as the Go subtest name in both
	// halves and as the join key the D74 baseline-discovery sessions share.
	Name string
	// Version is the pinned latest-stable version the nightly canary tests
	// against (doc 12 §7: "latest stable versions of the pinned client set").
	// The nightly job bumps these; a bump that regresses first-contact or p95
	// latency is itself a flip-to-inspect trigger signal.
	Version string
	// Population decides the pass condition (cooperative ⇒ TCP succeeds in budget;
	// raw-quic ⇒ QUIC fails fast).
	Population Population
	// Posture is the client's stock QUIC engagement (doc 12 §7 golden-image
	// neutrality — informs which legs are measured without forcing config).
	Posture QUICPosture
	// NoQUICLeg marks a cooperative client that speaks no QUIC at all (git,
	// Go net/http, Python requests, Rust reqwest stock): only its TCP leg is
	// measured. A TCP-only client can never exercise the QUIC reject, so the
	// harness must not fabricate a QUIC measurement for it.
	NoQUICLeg bool
	// Invocation is the documented live-driver command shape (informational —
	// the live half scaffolds each as a DEFERRED MANUAL step). Carries the exact
	// QUIC/TCP flags so a reader of a failure sees how the leg was measured.
	Invocation string
	// Why ties the row back to the doc 12 §7 / doc 14 §10 pinned-set enumeration.
	Why string
}

// BaselineDomain is the api.anthropic.com-shaped baseline domain the canary
// probes for first-contact + p95 latency (doc 12 §7: "a baseline domain
// (api.anthropic.com-shaped)"). It is the D64 baseline-pack endpoint the canary
// measures against; the live half points the real drivers at it (or at the
// DS_QUIC_CANARY_BASELINE override). It is deliberately the real
// developer-value endpoint the canary's whole reason-to-exist protects: the flip
// trigger fires when first-contact to THIS domain fails or regresses.
const BaselineDomain = "api.anthropic.com"

// Matrix returns the full pinned-client workload matrix. The offline half
// asserts every row's shape + verdict logic against synthetic measurements; the
// live half drives every row against real wire shapes; the D74
// baseline-discovery sessions reuse the exact pinned-version table.
//
// The pinned set is doc 12 §7 / doc 14 §10 verbatim: curl, git, Node LTS+current
// (undici/npm), Python requests+httpx, Go net/http, Rust reqwest, gRPC, the
// Anthropic Python+TS SDKs, and headless Chrome stable (default-QUIC-enabled).
// Versions are the latest-stable pins the nightly job bumps.
func Matrix() []Client {
	return []Client{
		// ── curl: BOTH a cooperative happy-eyeballs row AND the raw-QUIC probe ──
		// curl is the one client that supplies BOTH populations: --http3 races
		// (cooperative) while --http3-only is QUIC-only (the reject validator).
		{
			Name: "curl-http3", Version: "8.18.0",
			Population: PopulationCooperative, Posture: PostureHappyEyeballs,
			Invocation: "curl --http3 https://" + BaselineDomain + "/  (races H3, falls back to TCP)",
			Why:        "doc 12 §7 pinned set: curl, happy-eyeballs cooperative — H3 raced, TCP fallback within budget",
		},
		{
			Name: "curl-http3-only", Version: "8.18.0",
			Population: PopulationRawQUIC, Posture: PostureQUICForced,
			Invocation: "curl --http3-only https://" + BaselineDomain + "/  (QUIC-only, NO TCP fallback)",
			Why:        "doc 12 §7: the non-cooperative raw-QUIC probe — validates the NFT-4 reject fails fast (<1s ECONNREFUSED)",
		},

		// ── git over HTTPS: TCP-only cooperative ──
		{
			Name: "git-https", Version: "2.52.0",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "git clone https://" + BaselineDomain + "/repo.git  (libcurl, TCP only)",
			Why:        "doc 12 §7 pinned set: git, no QUIC leg — TCP first-contact within budget",
		},

		// ── Node LTS + current (undici / npm) ──
		{
			Name: "node-lts-undici", Version: "22.20.0",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "node (undici fetch) https://" + BaselineDomain + "/  (Node LTS, TCP)",
			Why:        "doc 12 §7 pinned set: Node LTS undici — stock fetch is TCP; first-contact within budget",
		},
		{
			Name: "node-current-undici", Version: "25.2.0",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "node (undici fetch) https://" + BaselineDomain + "/  (Node current, TCP)",
			Why:        "doc 12 §7 pinned set: Node current undici — newest line, catches an undici H3 default landing early",
		},
		{
			Name: "npm-install", Version: "11.6.2",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "npm install (against a baseline-shaped registry)  (TCP)",
			Why:        "doc 12 §7 pinned set: npm — the package-manager first-contact path",
		},

		// ── Python: requests + httpx ──
		{
			Name: "python-requests", Version: "2.32.5",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "python -c 'requests.get(...)' https://" + BaselineDomain + "/  (urllib3, TCP)",
			Why:        "doc 12 §7 pinned set: Python requests — TCP only",
		},
		{
			Name: "python-httpx", Version: "0.28.1",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "python -c 'httpx.get(...)' https://" + BaselineDomain + "/  (httpcore, TCP default)",
			Why:        "doc 12 §7 pinned set: Python httpx — stock is TCP (h3 is an opt-in extra); catches an h3-default flip",
		},

		// ── Go net/http ──
		{
			Name: "go-nethttp", Version: "1.25.11",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "go run (net/http client) https://" + BaselineDomain + "/  (TCP, H2)",
			Why:        "doc 12 §7 pinned set: Go net/http — stdlib has no H3 client; TCP first-contact within budget",
		},

		// ── Rust reqwest ──
		{
			Name: "rust-reqwest", Version: "0.12.24",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "cargo run (reqwest) https://" + BaselineDomain + "/  (TCP; http3 is a feature flag)",
			Why:        "doc 12 §7 pinned set: Rust reqwest — default build is TCP; catches an http3-feature default flip",
		},

		// ── gRPC ──
		{
			Name: "grpc", Version: "1.81.1",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "grpc client unary call to a baseline-shaped endpoint  (H2 over TCP)",
			Why:        "doc 12 §7 pinned set: gRPC — H2 over TCP; an H3-bound gRPC API is itself a separate flip trigger (doc 12 §7 trigger 3)",
		},

		// ── Anthropic SDKs: Python + TypeScript ──
		{
			Name: "anthropic-sdk-python", Version: "0.75.0",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "python -c 'anthropic.Anthropic().messages.create(...)'  (httpx, TCP)",
			Why:        "doc 12 §7 pinned set: Anthropic Python SDK — the developer-value first-contact path the canary most directly protects",
		},
		{
			Name: "anthropic-sdk-ts", Version: "0.70.0",
			Population: PopulationCooperative, Posture: PostureTCPOnly, NoQUICLeg: true,
			Invocation: "node (anthropic-ts SDK) messages.create(...)  (undici, TCP)",
			Why:        "doc 12 §7 pinned set: Anthropic TS SDK — the second developer-value SDK first-contact path",
		},

		// ── headless Chrome stable (default-QUIC-enabled) ──
		{
			Name: "headless-chrome", Version: "143.0.7295.0",
			Population: PopulationCooperative, Posture: PostureHappyEyeballs,
			Invocation: "chrome --headless --no-sandbox " + BaselineDomain + "  (default-QUIC-enabled; the disable-quic flag is deliberately NOT shipped)",
			Why:        "doc 12 §7 pinned set: headless Chrome stable — runs default-QUIC-enabled so the canary measures REAL behavior; disabling QUIC is a documented knob, not a default",
		},
	}
}

// CooperativeClients returns the spec-following population — measured over both
// transports (or TCP only for NoQUICLeg rows). Pass condition: TCP first-contact
// within the p95 budget.
func CooperativeClients() []Client {
	var out []Client
	for _, c := range Matrix() {
		if c.Population == PopulationCooperative {
			out = append(out, c)
		}
	}
	return out
}

// RawQUICClients returns the non-cooperative QUIC-only population (curl
// --http3-only) — measured over QUIC only, SEPARATELY, to validate the NFT-4
// reject mechanism. Pass condition: QUIC first-contact fails fast.
func RawQUICClients() []Client {
	var out []Client
	for _, c := range Matrix() {
		if c.Population == PopulationRawQUIC {
			out = append(out, c)
		}
	}
	return out
}
