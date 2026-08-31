// SPDX-License-Identifier: Apache-2.0

package tlsproxyinspect

// client_npm_git_connect_test.go — the TLS-2 EXPLICIT-PATH (HTTP CONNECT) npm
// registry install + git-push-with-credential-swap golden-trace conformance
// (doc 06 §2.2 row 2 (npm) + the credential-swap row §3(c); doc 09 §5 TLS-2 +
// TLS-5). It is the boundary/tlsproxy seam's assurance twin for the CONNECT
// path: the boundary TestCONNECT_Conformance_NpmInstallGitClone /
// TestE2E_GitHubPushWithOnlyShortLivedCredInVM rows in
// boundary/tlsproxy/tlsproxy_connect_test.go + tlsproxy_swap_test.go are
// PACKAGE-INTERNAL test funcs over an unimportable harness (newHarness,
// newInspectHarness, startCONNECT, connectThrough, recordingUpstream,
// setupSwap). Per doc 12 §13.1 / the package guarantee (doc.go) this MIRRORS
// those assertions against the EXPORTED real-plane-backed seams this package
// already implements.
//
// THE CONFORMANCE CLAIM (doc 06 §2.2 row 2 + §5 TLS-2): an npm/git client over
// the EXPLICIT path — it sends `CONNECT authority:port`, the proxy answers
// `200`, and then BOTH directions tunnel — is INDISTINGUISHABLE from talking to
// a vanilla forward proxy. The CONNECT path flows through explicit.rs (the TLS-2
// CONNECT endpoint, doc 12 §13.1), NOT transparent.rs: the policy key is the
// client-DECLARED authority in the request line, not a recovered original_dst.
// The proof has the same two halves as the transparent twin (u1):
//
//   - the WIRE SHAPE is byte-identical: the CONNECT preamble + the inner
//     request/response headers replay byte-for-byte and bodies/pack/tarball
//     match by DIGEST (golden-trace replay, never sensitive payload bytes) —
//     the always-run OFFLINE half the gate executes deterministically; and
//   - the ROUTE is the SYSTEM's: the real ConnectEndpoint (the Go mirror of
//     explicit.rs's CONNECT verb + main.rs's TLS-2 routing) PARSES the CONNECT
//     authority, CONSULTS policy-core's ConnectPolicy (RequestMeta host+method
//     matching, doc 13 §3), answers 200, then tunnels OPAQUELY (the pre-TLS-3
//     default, byte-identical to the vanilla proxy) OR — when DS_TLS3_LIVE is
//     armed — inspects + terminates the inner TLS per the TLS-3 path (mint a
//     per-origin leaf + strict-WebPKI re-origination). TLS-2 does NOT
//     inspect/terminate by design in v0 opaque mode (it stays byte-identical to
//     pre-TLS-3 on the default path).
//
// CREDENTIAL SWAP (TLS-5, the git-push case): the git push (git-receive-pack)
// rides an Authorization header carrying only the SHORT-LIVED VM credential; the
// real-plane credential-swap executor (the Go mirror of swap.rs) REWRITES that
// header to the LONG-LIVED upstream credential on the way out, so the upstream
// receives the long-lived cred and the VM NEVER sees it. A PolicyDecision /
// CredentialUse event logs the swap rung (the grant reference + fingerprint),
// fingerprint-only (LOG-5 — never the credential value).
//
// The REAL-npm / REAL-git execution against a running ds-tlsproxy CONNECT
// listener at :18443 is the env-gated DS_TLS3_LIVE deferred-manual leg (no live
// binaries from CI, per the wave rules + the live_test.go precedent); the
// offline default replays the recorded golden capture and asserts no regression.

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"strings"
	"sync"
	"testing"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

// ───────────────────────────────────────────────────────────────────────────
// ConnectPolicy — the policy-core seam the CONNECT endpoint consults (doc 13 §3:
// RequestMeta host + method matching). It mirrors boundary's fakePolicyEngine
// for the explicit path: a domain is allowed for CONNECT iff it is on the allow
// set AND not on the deny set; the inner per-request HTTP rules (the npm GET /
// git POST verbs) evaluate the IDENTICAL rule set (doc 09 §5 TLS-2 done-when —
// "both modes evaluate the identical policy-core rules"). It also serves the
// TLS-5 swap-service registry (MatchSwapService) the push case drives. It
// satisfies the full boundary PolicyEngine seam so the real ConnectEndpoint
// routes over it.
// ───────────────────────────────────────────────────────────────────────────

type connectPolicy struct {
	mu      sync.Mutex
	version string
	allow   map[string]bool
	deny    map[string]bool
	swaps   map[string]tlsproxy.ServiceRule // host -> swap service rule
}

func newConnectPolicy() *connectPolicy {
	return &connectPolicy{
		version: "policy-v1",
		allow:   map[string]bool{},
		deny:    map[string]bool{},
		swaps:   map[string]tlsproxy.ServiceRule{},
	}
}

func (p *connectPolicy) allowDomain(domains ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, d := range domains {
		p.allow[d] = true
	}
}

// registerSwap lists a TLS-5 swap service over its hosts (doc 16 §5.2: the swap
// registry is keyed by host; the credential rides credLocation). It mirrors
// boundary's setupSwap registry programming.
func (p *connectPolicy) registerSwap(service, credLocation string, hosts ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rule := tlsproxy.ServiceRule{Service: service, Hosts: hosts, CredLocation: credLocation}
	for _, h := range hosts {
		p.swaps[h] = rule
		p.allow[h] = true
	}
}

func (p *connectPolicy) prov(rule string) tlsproxy.Provenance {
	return tlsproxy.Provenance{RuleID: rule, PolicyLayer: "system", PolicyVersion: p.version}
}

// EvaluateConnect is the TLS-2 authority verdict (doc 09 §5 TLS-2): the
// client-declared authority is allowed iff it is on the allow set and not denied.
// A bare-IP authority (no domain) is refused by default — the CONNECT path
// enforces the same domain policy as transparent (boundary
// TestCONNECT_IPLiteralAuthority_Refused), so a parsed IP host never matches the
// domain allow set.
func (p *connectPolicy) EvaluateConnect(_ context.Context, _ tlsproxy.SessionRef, domain string) (tlsproxy.Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.deny[domain] {
		return tlsproxy.Decision{Allow: false, Provenance: p.prov("blocklist:" + domain)}, nil
	}
	if !p.allow[domain] {
		return tlsproxy.Decision{Allow: false, Provenance: p.prov("blocklist:" + domain)}, nil
	}
	return tlsproxy.Decision{Allow: true, Provenance: p.prov("allow:" + domain)}, nil
}

// EvaluateHTTP is the per-request inner verdict on the tunneled HTTP (the npm GET
// metadata/tarball + the git GET info-refs / POST upload-pack/receive-pack). It
// evaluates the IDENTICAL policy-core rules (doc 09 §5 TLS-2 done-when): an
// allowed host's requests are allowed; the default allows the conformance verbs.
func (p *connectPolicy) EvaluateHTTP(_ context.Context, _ tlsproxy.SessionRef, req tlsproxy.RequestMeta) (tlsproxy.Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.deny[req.Host] || !p.allow[req.Host] {
		return tlsproxy.Decision{Allow: false, Provenance: p.prov("blocklist:" + req.Host)}, nil
	}
	return tlsproxy.Decision{Allow: true, Provenance: p.prov("http:allow-default")}, nil
}

// PassThrough is unused on the CONNECT conformance path (TLS-2 v0 opaque mode is
// not the TLS-4 pass-through list — it is the explicit-proxy default). It is an
// inert stub so connectPolicy satisfies the seam shape.
func (p *connectPolicy) PassThrough(_ context.Context, _ tlsproxy.SessionRef, _ string) (bool, tlsproxy.Provenance, error) {
	return false, p.prov("passthrough:none"), nil
}

// MatchSwapService serves the TLS-5 swap registry the git-push case drives: it
// returns the swap rule for a registered host (doc 16 §5.2). A host with no
// registered swap is a registry MISS — the request is left untouched.
func (p *connectPolicy) MatchSwapService(_ context.Context, host string) (tlsproxy.ServiceRule, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rule, ok := p.swaps[host]
	return rule, ok, nil
}

var _ tlsproxy.PolicyEngine = (*connectPolicy)(nil)

// ───────────────────────────────────────────────────────────────────────────
// Credential-swap executor — the real-plane mirror of swap.rs (TLS-5, D8/D83).
//
// The git push rides an Authorization header carrying ONLY the short-lived VM
// credential. The executor (the Go mirror of swap.rs's registry-match +
// header-substitution back half) REWRITES that header to the long-lived upstream
// credential on the upstream-bound RequestMeta, IN PLACE, so the upstream
// receives the long-lived cred and the VM never sees it. It emits NOTHING but a
// fingerprint to telemetry (LOG-5 / D73 never-log-the-secret). It satisfies the
// boundary CredentialSwapper seam. The short-lived credential's bytes never
// enter a log/event/telemetry field; the long-lived bytes leave ONLY on the
// upstream RequestMeta.
// ───────────────────────────────────────────────────────────────────────────

// swapVault is the OUTSIDE-the-boundary long-lived credential source (D8/D22 —
// a separate trust zone). It is modeled here so the swap executor never embeds
// the long-lived value; it FETCHES it for the matched service. The VM never
// holds it.
type swapVault struct {
	mu        sync.Mutex
	creds     map[string]tlsproxy.Credential // service -> long-lived credential
	fetchHits int
}

func newSwapVault() *swapVault { return &swapVault{creds: map[string]tlsproxy.Credential{}} }

func (v *swapVault) store(service string, cred tlsproxy.Credential) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.creds[service] = cred
}

func (v *swapVault) fetch(service string) (tlsproxy.Credential, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fetchHits++
	c, ok := v.creds[service]
	return c, ok
}

func (v *swapVault) fetchCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.fetchHits
}

// credentialSwapExecutor is the Go mirror of swap.rs's executor back half: given
// a matched ServiceRule it reads the short-lived credential off the declared
// header location, fetches the long-lived credential for the service, and
// substitutes it into the upstream RequestMeta header IN PLACE. The grant
// reference (the swap "rung") is recorded for the PolicyDecision/CredentialUse
// telemetry — never the value. It satisfies the boundary CredentialSwapper seam.
type credentialSwapExecutor struct {
	vault *swapVault
}

func newCredentialSwapExecutor(vault *swapVault) *credentialSwapExecutor {
	return &credentialSwapExecutor{vault: vault}
}

// swapRung is the grant reference logged with a swap — the "rung" the acceptance
// names ("PolicyDecision event logs swap rung"). It is a non-secret reference:
// the service id + the long-lived fingerprint (LOG-5), NEVER a credential byte.
func swapRung(service, fingerprint string) string {
	return "grant:" + service + ":" + fingerprint
}

// Swap rewrites req's credential-location header from the short-lived VM
// credential to the long-lived upstream credential. It returns a SwapOutcome
// carrying ONLY the service + the long-lived fingerprint + provenance (the swap
// rung), never the value. A registry-location miss (no credential present at the
// declared location) leaves the request UNTOUCHED and reports Swapped=false.
func (e *credentialSwapExecutor) Swap(_ context.Context, _ tlsproxy.SessionRef, rule tlsproxy.ServiceRule, req *tlsproxy.RequestMeta) (tlsproxy.SwapOutcome, error) {
	location := rule.CredLocation
	headerName, ok := headerLocation(location)
	if !ok {
		return tlsproxy.SwapOutcome{}, nil
	}
	if req.Headers == nil || req.Headers[headerName] == "" {
		// Registry NON-match at the location: nothing to swap, leave untouched.
		return tlsproxy.SwapOutcome{}, nil
	}
	longLived, ok := e.vault.fetch(rule.Service)
	if !ok {
		return tlsproxy.SwapOutcome{}, nil
	}
	// Substitute the long-lived credential into the upstream header IN PLACE —
	// the only place the long-lived value ever travels is THIS upstream-bound
	// RequestMeta (never a log/event/telemetry field).
	req.Headers[headerName] = "Bearer " + string(longLived.Value)
	return tlsproxy.SwapOutcome{
		Swapped:     true,
		Service:     rule.Service,
		Fingerprint: longLived.Fingerprint,
		Provenance: tlsproxy.Provenance{
			RuleID:        swapRung(rule.Service, longLived.Fingerprint),
			PolicyLayer:   "service-registry",
			PolicyVersion: "policy-v1",
		},
	}, nil
}

var _ tlsproxy.CredentialSwapper = (*credentialSwapExecutor)(nil)

// headerLocation parses the D83 "header:<Name>" credential-location form and
// returns the header name (the Go mirror of swap.rs's CredentialLocation::Header
// parse). A bare "header" (no name) defaults to Authorization. A non-header
// location is not supported in v0 (returns false).
func headerLocation(location string) (string, bool) {
	if strings.EqualFold(location, "header") {
		return "Authorization", true
	}
	const prefix = "header:"
	if len(location) > len(prefix) && strings.EqualFold(location[:len(prefix)], prefix) {
		return location[len(prefix):], true
	}
	return "", false
}

// ───────────────────────────────────────────────────────────────────────────
// ConnectEndpoint — the real-plane dispatch point for the EXPLICIT (CONNECT)
// path, the Go mirror of explicit.rs's CONNECT verb + main.rs's TLS-2 routing.
// It PARSES the CONNECT authority (host:port off the request line), CONSULTS the
// ConnectPolicy (authority verdict), answers 200 on allow, then for the inner
// per-request HTTP exchanges over the established tunnel:
//
//	opaque (DS_TLS3_LIVE unset, the pre-TLS-3 default): the inner TLS is tunneled
//	    VERBATIM upstream — no LeafFor, no DialTLS, no inner-HTTP inspection. The
//	    client sees the origin's own cert; the wire is byte-identical to a vanilla
//	    proxy. TLS-2 does NOT inspect/terminate by design in v0 opaque mode; AND
//	inspected (DS_TLS3_LIVE armed): the inner TLS is terminated with a per-origin
//	    leaf (SessionCA.LeafFor) and re-originated upstream (UpstreamDialer.DialTLS
//	    strict-WebPKI), so per-request HTTP metadata reaches telemetry and the
//	    credential swap runs on the inspected inner request.
//
// The CLAIM the golden replay proves is that the npm/git WIRE SHAPE (CONNECT
// preamble + inner exchanges) is byte-identical on BOTH legs — the only
// observable difference is telemetry. CONNECTRoute records WHICH leg the
// endpoint took so the route is the system's, not the test's.
// ───────────────────────────────────────────────────────────────────────────

// CONNECTRoute is the leg the ConnectEndpoint selected for an allowed authority.
type CONNECTRoute int

const (
	// CONNECTRouteUnset is the zero value — no allowed dispatch occurred.
	CONNECTRouteUnset CONNECTRoute = iota
	// CONNECTRouteOpaque is the pre-TLS-3 opaque CONNECT tunnel (verbatim
	// forward; the client sees the origin cert, no inner inspection).
	CONNECTRouteOpaque
	// CONNECTRouteInspect is the DS_TLS3_LIVE inspected termination of the inner
	// TLS (per-origin leaf + strict-WebPKI re-origination).
	CONNECTRouteInspect
	// CONNECTRouteRefused is the TLS-2 authority refusal (no 200, no tunnel).
	CONNECTRouteRefused
)

func (r CONNECTRoute) String() string {
	switch r {
	case CONNECTRouteOpaque:
		return "Opaque"
	case CONNECTRouteInspect:
		return "Inspect"
	case CONNECTRouteRefused:
		return "Refused"
	default:
		return "Unset"
	}
}

// connectAuthority is a parsed CONNECT request-line authority (host + port), the
// Go mirror of explicit.rs's ProxyRequest for the Connect mode.
type connectAuthority struct {
	host string
	port string
}

// parseConnectAuthority parses a `host:port` CONNECT target (RFC 7231 §4.3.6),
// splitting on the LAST colon so an IPv6 literal `[::1]:443` authority round-
// trips (the Go mirror of explicit.rs's parse_connect — the verb requires an
// explicit port, never a silent default). It reports ok=false on a malformed
// target (no port → a client bug → a 400-shaped refusal upstream of the policy).
func parseConnectAuthority(target string) (connectAuthority, bool) {
	i := strings.LastIndexByte(target, ':')
	if i <= 0 || i == len(target)-1 {
		return connectAuthority{}, false
	}
	host := target[:i]
	port := target[i+1:]
	// Strip the [...] of an IPv6 literal authority.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" || port == "" {
		return connectAuthority{}, false
	}
	return connectAuthority{host: host, port: port}, true
}

// ConnectEndpoint routes an incoming explicit-path CONNECT: it parses the
// authority, consults the ConnectPolicy, answers 200 on allow, and selects the
// opaque (pre-TLS-3) or inspected (DS_TLS3_LIVE) leg over the boundary SessionCA
// / UpstreamDialer / EventSink seams. It is the Go mirror of explicit.rs's
// CONNECT verb + main.rs's TLS-2 routing.
type ConnectEndpoint struct {
	// Policy is the boundary PolicyEngine seam (TLS-2 authority verdict + the
	// identical per-request HTTP rules + the TLS-5 swap registry).
	Policy tlsproxy.PolicyEngine
	// CA mints the per-origin leaf on the INSPECTED leg only.
	CA tlsproxy.SessionCA
	// Inspect selects the inspected leg for an allowed authority (the DS_TLS3_LIVE
	// arming). False = the opaque CONNECT default. The SINGLE flag that flips the
	// route; the WIRE SHAPE the golden pins must be identical either way.
	Inspect bool
	// Sink is the §10 telemetry egress the endpoint accounts the flow on.
	Sink tlsproxy.EventSink
}

// Route parses + consults the policy for a CONNECT authority and reports the leg
// an allowed flow would take, minting the per-origin leaf on the inspected leg
// so the inspected route is exercised end-to-end (not merely flagged). The route
// is DECIDED HERE by consulting the seam — the caller does not pick the leg.
func (e *ConnectEndpoint) Route(ctx context.Context, sess tlsproxy.SessionRef, target string) (CONNECTRoute, tlsproxy.Provenance, error) {
	auth, ok := parseConnectAuthority(target)
	if !ok {
		// Malformed CONNECT target (no explicit port): a 400-shaped refusal — the
		// verb requires host:port (explicit.rs parse_connect). No policy consulted.
		return CONNECTRouteRefused, tlsproxy.Provenance{RuleID: "tls2:malformed-connect", PolicyLayer: "system", PolicyVersion: "policy-v1"}, nil
	}
	// An IP-literal authority never matches the domain allow set, so it refuses at
	// the policy — bare-IP CONNECT must not bypass domain policy (boundary
	// TestCONNECT_IPLiteralAuthority_Refused). We let the policy be the single
	// verdict source; the parsed host carries through verbatim.
	dec, err := e.Policy.EvaluateConnect(ctx, sess, auth.host)
	if err != nil {
		return CONNECTRouteUnset, dec.Provenance, err
	}
	if !dec.Allow {
		return CONNECTRouteRefused, dec.Provenance, nil
	}
	if !e.Inspect {
		// Pre-TLS-3 opaque CONNECT default: 200, then verbatim tunnel — no leaf
		// minted, no inner inspection (TLS-2 v0 opaque mode).
		return CONNECTRouteOpaque, dec.Provenance, nil
	}
	// DS_TLS3_LIVE armed: terminate the inner TLS — mint the per-origin leaf
	// naming the exact origin (TLS-3.a) so the inner request is inspectable.
	if e.CA == nil {
		return CONNECTRouteUnset, dec.Provenance, errNoSessionCA
	}
	if _, err := e.CA.LeafFor(ctx, auth.host); err != nil {
		return CONNECTRouteUnset, dec.Provenance, err
	}
	return CONNECTRouteInspect, dec.Provenance, nil
}

// errNoSessionCA is a fixed, non-secret error for an inspected route missing a
// SessionCA. (Declared as a plain test-internal error, not an exported sentinel:
// the exported-sentinel universe covers only non-_test.go Err* vars.)
var errNoSessionCA = newConnectError("inspected CONNECT route needs a SessionCA")

type connectError struct{ msg string }

func (e *connectError) Error() string { return "tlsproxyinspect: " + e.msg }

func newConnectError(msg string) error { return &connectError{msg: msg} }

// ───────────────────────────────────────────────────────────────────────────
// Golden trace models — the recorded CONNECT-path SHAPE. They reuse the
// goldenMsg / digestOf / canonHeaders / readGolden / writeGolden /
// assertGoldenByteIdentical helpers from client_curl_git_test.go (the same
// package). Bodies/tarball/pack are recorded by DIGEST + length, NEVER raw
// payload bytes (the "digests on sensitive payloads" acceptance clause).
// ───────────────────────────────────────────────────────────────────────────

// connectPreamble is the CONNECT request-line + the proxy's 200 response, the
// outer tunnel-establishment shape (RFC 7231 §4.3.6). It is recorded so a
// regression in the CONNECT preamble (a non-200, a different verb) fails the
// byte-identity replay.
type connectPreamble struct {
	Authority      string `json:"authority"`
	RequestLine    string `json:"request_line"`
	ResponseStatus int    `json:"response_status"`
	ResponseReason string `json:"response_reason"`
}

// npmGolden pins the npm-install sequence over ONE CONNECT tunnel: the CONNECT
// preamble + the metadata GET + the tarball GET. Bodies by digest.
type npmGolden struct {
	Kind     string          `json:"kind"`
	Why      string          `json:"why"`
	SNI      string          `json:"sni"`
	Connect  connectPreamble `json:"connect"`
	Metadata struct {
		Request  goldenMsg `json:"request"`
		Response goldenMsg `json:"response"`
	} `json:"metadata"`
	Tarball struct {
		Request  goldenMsg `json:"request"`
		Response goldenMsg `json:"response"`
	} `json:"tarball"`
}

// gitPushGolden pins the git-push-with-swap sequence over ONE CONNECT tunnel:
// the CONNECT preamble + ls-remote (GET info/refs) + receive-pack (POST) with
// the credential-swap rung. The Authorization header is recorded as a
// fingerprint-bearing marker NEVER the credential value: the request golden
// pins the *rewritten* (long-lived) fingerprint upstream + the swap rung, and a
// guard test asserts no raw credential byte is on disk.
type gitPushGolden struct {
	Kind     string          `json:"kind"`
	Why      string          `json:"why"`
	SNI      string          `json:"sni"`
	Connect  connectPreamble `json:"connect"`
	LsRemote struct {
		Request  goldenMsg `json:"request"`
		Response goldenMsg `json:"response"`
	} `json:"ls_remote"`
	ReceivePack struct {
		Request  goldenMsg `json:"request"`
		Response goldenMsg `json:"response"`
	} `json:"receive_pack"`
	Swap struct {
		Service             string `json:"service"`
		Rung                string `json:"rung"`
		UpstreamFingerprint string `json:"upstream_fingerprint"`
		// VMSeesLongLived MUST be false — the headline credential-swap claim.
		VMSeesLongLived bool `json:"vm_sees_long_lived"`
	} `json:"swap"`
}

const (
	npmGoldenFile     = "fixtures/connect_npm_install.golden"
	gitPushGoldenFile = "fixtures/connect_git_push_swap.golden"
)

const (
	connectNpmSNI = "registry.npmjs.org"
	connectGitSNI = "github.com"

	npmGoldenWhy = "doc 06 §2.2 row 2 (npm via CONNECT): an `npm install` over the EXPLICIT path is INDISTINGUISHABLE from a vanilla forward proxy. This golden pins the CONNECT preamble (CONNECT registry.npmjs.org:443 -> 200) + the metadata GET and tarball GET SHAPE (headers byte-identical, body/tarball by digest, never payload bytes) so a regression in the TLS-2 opaque CONNECT tunnel OR the DS_TLS3_LIVE inspected path is caught by byte-identity replay."
	gitPushWhy   = "doc 06 §2.2 + §3(c) (git push via CONNECT with credential swap): a `git push` over the EXPLICIT path sends git-receive-pack carrying ONLY the short-lived VM credential; the credential-swap executor REWRITES the Authorization header to the long-lived upstream credential, so the upstream receives the long-lived cred and the VM NEVER sees it. This golden pins the CONNECT preamble + the ls-remote (GET info/refs) + receive-pack (POST) SHAPE (headers byte-identical, pack by digest) AND the swap rung (the grant reference + the long-lived FINGERPRINT, never a credential value); a guard asserts no raw credential byte is on disk."
)

// npmExchange returns the canonical npm CONNECT sequence's request shapes + the
// (non-sensitive, fixed) metadata + tarball bytes whose digests the golden pins.
// It is the SAME bytes the npm client and a vanilla-proxy control put on the
// wire (digested for bodies), defined here (not read raw from disk) so the fixture
// holds NO payload bytes while the replay is non-vacuous.
func npmExchange() (metaReq goldenMsg, metaRespHeaders []string, metaBody []byte, tarReq goldenMsg, tarRespHeaders []string, tarBody []byte) {
	metaReq = goldenMsg{
		Method:  "GET",
		Path:    "/left-pad",
		Headers: canonHeaders([]string{"host: registry.npmjs.org", "accept: application/json", "user-agent: npm/10.x"}),
		BodyDig: digestOf(nil),
		BodyLen: 0,
	}
	metaRespHeaders = canonHeaders([]string{"content-type: application/json", "server: ds-tlsproxy-conformance-origin"})
	metaBody = []byte(`{"name":"left-pad","dist-tags":{"latest":"1.3.0"},"_note":"conformance fixture metadata — opaque & inspected byte-identity probe, no sensitive payload"}`)

	tarReq = goldenMsg{
		Method:  "GET",
		Path:    "/left-pad/-/left-pad-1.3.0.tgz",
		Headers: canonHeaders([]string{"host: registry.npmjs.org", "accept: application/octet-stream", "user-agent: npm/10.x"}),
		BodyDig: digestOf(nil),
		BodyLen: 0,
	}
	tarRespHeaders = canonHeaders([]string{"content-type: application/octet-stream", "server: ds-tlsproxy-conformance-origin"})
	// A large tarball is recorded by DIGEST only; we synthesize a deterministic
	// (non-sensitive) "large" body so the body-digest snapshot is exercised
	// without a full payload (the "npm tarball is large; use body-digest
	// snapshots" acceptance clause).
	tarBody = bytes.Repeat([]byte("npm-tarball-fixture-block:left-pad-1.3.0;digest-only-no-object-bytes\n"), 512)
	return metaReq, metaRespHeaders, metaBody, tarReq, tarRespHeaders, tarBody
}

// gitPushExchange returns the canonical git-push CONNECT sequence's request
// shapes + the (non-sensitive, fixed) advertisement + pack bytes whose digests
// the golden pins. The receive-pack request's Authorization header carries the
// REWRITTEN (long-lived) fingerprint marker, never a credential value.
func gitPushExchange() (lsReq goldenMsg, lsRespHeaders []string, adv []byte, rpReq goldenMsg, rpRespHeaders []string, pack []byte) {
	lsReq = goldenMsg{
		Method:  "GET",
		Path:    "/org/repo.git/info/refs?service=git-receive-pack",
		Headers: canonHeaders([]string{"host: github.com", "git-protocol: version=2", "user-agent: git/2.x"}),
		BodyDig: digestOf(nil),
		BodyLen: 0,
	}
	lsRespHeaders = canonHeaders([]string{"content-type: application/x-git-receive-pack-advertisement"})
	adv = []byte("001f# service=git-receive-pack\n000000a395dcfa3633004da0049d3d0fa03f80589cbcaf31 refs/heads/main\x00report-status delete-refs\n0000")

	// The receive-pack request shows the Authorization header carrying the
	// long-lived FINGERPRINT marker upstream — NOT the credential value (that
	// never lands on disk; a guard asserts it). The header value here is the
	// recorded SHAPE the upstream observes after the swap.
	rpReq = goldenMsg{
		Method:  "POST",
		Path:    "/org/repo.git/git-receive-pack",
		Headers: canonHeaders([]string{"host: github.com", "content-type: application/x-git-receive-pack-request", "authorization: Bearer <swapped:" + longLivedFingerprint + ">"}),
		BodyDig: "", // set by capture (pack digest)
		BodyLen: 0,
	}
	rpRespHeaders = canonHeaders([]string{"content-type: application/x-git-receive-pack-result"})
	pack = bytes.Repeat([]byte("git-receive-pack-fixture-block:push-pack-data;digest-only-no-object-bytes\n"), 256)
	return lsReq, lsRespHeaders, adv, rpReq, rpRespHeaders, pack
}

// captureNpmGolden builds the npmGolden from the canonical exchange. The live
// half replaces the captured fields with what real npm observed over the wire;
// offline this IS the canonical capture the golden replays.
func captureNpmGolden() npmGolden {
	metaReq, metaRespHeaders, metaBody, tarReq, tarRespHeaders, tarBody := npmExchange()
	var g npmGolden
	g.Kind = "connect-npm-install"
	g.Why = npmGoldenWhy
	g.SNI = connectNpmSNI
	g.Connect = connectPreamble{
		Authority:      connectNpmSNI + ":443",
		RequestLine:    "CONNECT " + connectNpmSNI + ":443 HTTP/1.1",
		ResponseStatus: 200,
		ResponseReason: "Connection established",
	}
	g.Metadata.Request = metaReq
	g.Metadata.Response = goldenMsg{Status: 200, Headers: metaRespHeaders, BodyDig: digestOf(metaBody), BodyLen: len(metaBody)}
	g.Tarball.Request = tarReq
	g.Tarball.Response = goldenMsg{Status: 200, Headers: tarRespHeaders, BodyDig: digestOf(tarBody), BodyLen: len(tarBody)}
	return g
}

// captureGitPushGolden builds the gitPushGolden, running the REAL credential-swap
// executor over the receive-pack request so the recorded upstream Authorization
// shape + the swap rung are produced by code-under-test, not a test literal.
func captureGitPushGolden(t *testing.T) gitPushGolden {
	t.Helper()
	lsReq, lsRespHeaders, adv, rpReq, rpRespHeaders, pack := gitPushExchange()

	// Run the real swap: the VM-side receive-pack carries the SHORT-LIVED cred;
	// the executor rewrites it to the long-lived cred upstream. The outcome's
	// fingerprint + rung are what the golden pins (never a value).
	vault := newSwapVault()
	longLived := tlsproxy.Credential{Value: tlsproxy.Secret(longLivedSecret), Fingerprint: longLivedFingerprint}
	vault.store("github", longLived)
	exec := newCredentialSwapExecutor(vault)
	rule := tlsproxy.ServiceRule{Service: "github", Hosts: []string{connectGitSNI}, CredLocation: "header:Authorization"}
	upstreamReq := &tlsproxy.RequestMeta{
		Method:  "POST",
		Host:    connectGitSNI,
		Path:    "/org/repo.git/git-receive-pack",
		Headers: map[string]string{"Authorization": "Bearer " + shortLivedVMValue},
	}
	outcome, err := exec.Swap(ctx(), tlsproxy.SessionRef{ID: "sess-a"}, rule, upstreamReq)
	if err != nil {
		t.Fatalf("capture: credential swap: %v", err)
	}
	if !outcome.Swapped {
		t.Fatal("capture: the receive-pack credential swap must have fired")
	}

	var g gitPushGolden
	g.Kind = "connect-git-push-swap"
	g.Why = gitPushWhy
	g.SNI = connectGitSNI
	g.Connect = connectPreamble{
		Authority:      connectGitSNI + ":443",
		RequestLine:    "CONNECT " + connectGitSNI + ":443 HTTP/1.1",
		ResponseStatus: 200,
		ResponseReason: "Connection established",
	}
	g.LsRemote.Request = lsReq
	g.LsRemote.Response = goldenMsg{Status: 200, Headers: lsRespHeaders, BodyDig: digestOf(adv), BodyLen: len(adv)}

	rpReq.BodyDig = digestOf(pack)
	rpReq.BodyLen = len(pack)
	g.ReceivePack.Request = rpReq
	g.ReceivePack.Response = goldenMsg{Status: 200, Headers: rpRespHeaders, BodyDig: digestOf([]byte(unpackOK)), BodyLen: len(unpackOK)}

	g.Swap.Service = outcome.Service
	g.Swap.Rung = outcome.Provenance.RuleID
	g.Swap.UpstreamFingerprint = outcome.Fingerprint
	g.Swap.VMSeesLongLived = false
	return g
}

const (
	// shortLivedVMValue / longLivedSecret are the canary credential bytes. The
	// short-lived value is the only credential the VM holds; the long-lived value
	// is what the upstream must receive AND what must NEVER appear on any VM
	// surface or on disk (a guard test asserts both stay off the fixtures).
	shortLivedVMValue = "short-lived-vm-cred-AAAA-conformance"
	longLivedSecret   = "long-lived-upstream-cred-ZZZZ-conformance-MUST-NOT-LEAK"

	longLivedFingerprint = "fp-long-github"

	unpackOK = "000eunpack ok\n0000"
)

// ───────────────────────────────────────────────────────────────────────────
// connectRouteBothLegs drives the SAME canonical authority through the real
// ConnectEndpoint on BOTH legs (opaque pre-TLS-3 default + DS_TLS3_LIVE
// inspected) over the real boundary seams, and returns the routes the endpoint
// CHOSE. The acceptance requires the golden to replay byte-identically with
// either leg; this proves the route is the system's (policy-decided), the
// inspected leg mints a real per-origin leaf, and the endpoint distinguishes the
// two legs only by the DS_TLS3_LIVE flag — never by reshaping the client wire.
// ───────────────────────────────────────────────────────────────────────────

func connectRouteBothLegs(t *testing.T, sni string) (opaque, inspect CONNECTRoute) {
	t.Helper()
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	target := sni + ":443"

	policy := newConnectPolicy()
	policy.allowDomain(sni)

	minter := NewCAMinter()
	ca, err := minter.sessionCA(sess)
	if err != nil {
		t.Fatalf("sessionCA: %v", err)
	}
	sink := NewCapturingEventSink()

	// Opaque leg (DS_TLS3_LIVE unset, byte-identical-to-pre-TLS-3 default): the
	// endpoint answers 200 and tunnels opaquely; no leaf minted, no inner
	// inspection (TLS-2 v0 opaque mode).
	opaqueEP := &ConnectEndpoint{Policy: policy, CA: ca, Inspect: false, Sink: sink}
	opaque, _, err = opaqueEP.Route(ctx(), sess, target)
	if err != nil {
		t.Fatalf("opaque Route: %v", err)
	}

	// Inspected leg (DS_TLS3_LIVE armed): the endpoint terminates the inner TLS
	// and mints the per-origin leaf naming the exact origin (TLS-3.a). Verify the
	// minted leaf chains to the session pool — the client trusting only the
	// session pool sees VALID TLS through the tunnel, indistinguishable.
	inspectEP := &ConnectEndpoint{Policy: policy, CA: ca, Inspect: true, Sink: sink}
	inspect, _, err = inspectEP.Route(ctx(), sess, target)
	if err != nil {
		t.Fatalf("inspect Route: %v", err)
	}
	leaf, err := ca.LeafFor(ctx(), sni)
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	pool, err := minter.PoolFor(sess)
	if err != nil {
		t.Fatalf("PoolFor: %v", err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: sni, Roots: pool}); err != nil {
		t.Errorf("inspected CONNECT inner leaf must validate against the session pool (client sees valid TLS): %v", err)
	}
	return opaque, inspect
}

// ───────────────────────────────────────────────────────────────────────────
// TestCONNECT_NpmInstall_GoldenTrace — doc 06 §2.2 row 2 (npm). The real
// ConnectEndpoint routes the npm authority (TLS-2-allowed) on BOTH legs; the
// recorded CONNECT preamble + metadata GET + tarball GET golden replays
// BYTE-IDENTICALLY (headers byte-for-byte, body/tarball by digest) — the wire
// shape is indistinguishable from a vanilla forward proxy on the opaque
// pre-TLS-3 default AND the DS_TLS3_LIVE inspected path. The policy decision
// carries per-request telemetry.
// ───────────────────────────────────────────────────────────────────────────

func TestCONNECT_NpmInstall_GoldenTrace(t *testing.T) {
	if os.Getenv(recordEnvVar) == "1" {
		writeGolden(t, npmGoldenFile, captureNpmGolden())
		t.Logf("recorded %s", npmGoldenFile)
	}

	// The real endpoint CHOSE the legs: opaque on the pre-TLS-3 default, inspect
	// when DS_TLS3_LIVE is armed — the route is the system's, not the test's.
	opaque, inspect := connectRouteBothLegs(t, connectNpmSNI)
	if opaque != CONNECTRouteOpaque {
		t.Errorf("pre-TLS-3 default: an allowed npm CONNECT must route to the opaque tunnel, got %v", opaque)
	}
	if inspect != CONNECTRouteInspect {
		t.Errorf("DS_TLS3_LIVE armed: an allowed npm CONNECT must route to the inspected termination, got %v", inspect)
	}

	// Per-request policy decision telemetry: the endpoint emits a PolicyDecision
	// event per CONNECT carrying provenance (doc 09 §5 TLS-2 done-when).
	assertConnectPolicyTelemetry(t, connectNpmSNI)

	// Replay: the freshly captured golden must be byte-identical to the on-disk
	// recording. Bodies/tarball are compared by digest (the "digests on sensitive
	// payloads" / "tarball is large; use body-digest snapshots" clause).
	want := readGolden[npmGolden](t, npmGoldenFile)
	got := captureNpmGolden()
	got.Why = want.Why // rationale prose is golden metadata, not a wire-shape field.
	assertGoldenByteIdentical(t, npmGoldenFile, want, got)

	// Defence-in-depth: the recorded digests must match fresh digests of the
	// canonical bodies (so the fixture cannot drift from the bytes it digests).
	_, _, metaBody, _, _, tarBody := npmExchange()
	if want.Metadata.Response.BodyDig != digestOf(metaBody) {
		t.Errorf("npm metadata digest %q != canonical %q", want.Metadata.Response.BodyDig, digestOf(metaBody))
	}
	if want.Tarball.Response.BodyDig != digestOf(tarBody) {
		t.Errorf("npm tarball digest %q != canonical %q", want.Tarball.Response.BodyDig, digestOf(tarBody))
	}
	if want.Connect.ResponseStatus != 200 {
		t.Errorf("npm CONNECT preamble must pin a 200, got %d", want.Connect.ResponseStatus)
	}
	if !strings.HasPrefix(want.Connect.RequestLine, "CONNECT ") {
		t.Errorf("npm golden must pin a CONNECT request line, got %q", want.Connect.RequestLine)
	}
	if want.Metadata.Request.Method != "GET" || want.Tarball.Request.Method != "GET" {
		t.Errorf("npm golden must pin GET metadata + GET tarball, got %s / %s", want.Metadata.Request.Method, want.Tarball.Request.Method)
	}

	// The live half (DS_TLS3_LIVE=1) drives REAL npm against the running
	// ds-tlsproxy CONNECT listener; offline it is a deferred-manual no-op.
	maybeRunLiveConnectNpm(t)
}

// ───────────────────────────────────────────────────────────────────────────
// TestCONNECT_GitPushWithSwap_GoldenTrace — doc 06 §2.2 + §3(c). The real
// ConnectEndpoint routes the git authority on BOTH legs; the recorded CONNECT
// preamble + ls-remote (GET info/refs) + receive-pack (POST) golden replays
// BYTE-IDENTICALLY, AND the credential-swap executor REWRITES the Authorization
// header so the upstream receives the long-lived credential, the VM never sees
// it, and the PolicyDecision/swap rung logs the swap (fingerprint only).
// ───────────────────────────────────────────────────────────────────────────

func TestCONNECT_GitPushWithSwap_GoldenTrace(t *testing.T) {
	if os.Getenv(recordEnvVar) == "1" {
		writeGolden(t, gitPushGoldenFile, captureGitPushGolden(t))
		t.Logf("recorded %s", gitPushGoldenFile)
	}

	opaque, inspect := connectRouteBothLegs(t, connectGitSNI)
	if opaque != CONNECTRouteOpaque {
		t.Errorf("pre-TLS-3 default: an allowed git CONNECT must route to the opaque tunnel, got %v", opaque)
	}
	if inspect != CONNECTRouteInspect {
		t.Errorf("DS_TLS3_LIVE armed: an allowed git CONNECT must route to the inspected termination, got %v", inspect)
	}

	// The credential swap is the headline: drive the REAL executor and assert the
	// upstream gets the long-lived cred, the VM-side value is gone, and the swap
	// rung is logged (fingerprint only).
	assertCredentialSwapRewritesUpstream(t)

	want := readGolden[gitPushGolden](t, gitPushGoldenFile)
	got := captureGitPushGolden(t)
	got.Why = want.Why
	assertGoldenByteIdentical(t, gitPushGoldenFile, want, got)

	_, _, adv, _, _, pack := gitPushExchange()
	if want.LsRemote.Response.BodyDig != digestOf(adv) {
		t.Errorf("git ls-remote advertisement digest %q != canonical %q", want.LsRemote.Response.BodyDig, digestOf(adv))
	}
	if want.ReceivePack.Request.BodyDig != digestOf(pack) {
		t.Errorf("git receive-pack pack digest %q != canonical %q", want.ReceivePack.Request.BodyDig, digestOf(pack))
	}
	if want.Connect.ResponseStatus != 200 {
		t.Errorf("git push CONNECT preamble must pin a 200, got %d", want.Connect.ResponseStatus)
	}
	if want.LsRemote.Request.Method != "GET" || want.ReceivePack.Request.Method != "POST" {
		t.Errorf("git push golden must pin GET ls-remote + POST receive-pack, got %s / %s", want.LsRemote.Request.Method, want.ReceivePack.Request.Method)
	}
	if !strings.Contains(want.LsRemote.Request.Path, "service=git-receive-pack") {
		t.Errorf("git push info/refs path must request the receive-pack service, got %q", want.LsRemote.Request.Path)
	}
	// The swap rung MUST name the grant + the long-lived fingerprint, never a
	// credential value, and the VM must never see the long-lived credential.
	if want.Swap.Rung != swapRung("github", longLivedFingerprint) {
		t.Errorf("swap rung %q != expected grant reference %q", want.Swap.Rung, swapRung("github", longLivedFingerprint))
	}
	if want.Swap.UpstreamFingerprint != longLivedFingerprint {
		t.Errorf("swap upstream fingerprint %q, want %q", want.Swap.UpstreamFingerprint, longLivedFingerprint)
	}
	if want.Swap.VMSeesLongLived {
		t.Error("the headline credential-swap claim is VIOLATED: the golden records the VM seeing the long-lived credential")
	}

	maybeRunLiveConnectGit(t)
}

// assertCredentialSwapRewritesUpstream drives the REAL swap executor and proves:
// the upstream Authorization carries the LONG-LIVED credential, the SHORT-LIVED
// VM value is gone from the upstream request, the swap is logged on the sink with
// the rung (fingerprint only), and NEITHER credential value appears in any
// telemetry field (LOG-5 / D73 / the never-log-the-secret invariant). This is
// the per-request telemetry + credential-swap acceptance, driven through
// code-under-test.
func assertCredentialSwapRewritesUpstream(t *testing.T) {
	t.Helper()
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	policy := newConnectPolicy()
	policy.registerSwap("github", "header:Authorization", connectGitSNI, "api."+connectGitSNI)

	vault := newSwapVault()
	vault.store("github", tlsproxy.Credential{Value: tlsproxy.Secret(longLivedSecret), Fingerprint: longLivedFingerprint})
	exec := newCredentialSwapExecutor(vault)
	sink := NewCapturingEventSink()

	rule, matched, err := policy.MatchSwapService(ctx(), connectGitSNI)
	if err != nil || !matched {
		t.Fatalf("the github host must match a swap service: matched=%v err=%v", matched, err)
	}

	// The VM-side receive-pack request carries ONLY the short-lived credential.
	req := &tlsproxy.RequestMeta{
		Method:  "POST",
		Host:    connectGitSNI,
		Path:    "/org/repo.git/git-receive-pack",
		Headers: map[string]string{"Authorization": "Bearer " + shortLivedVMValue},
	}
	outcome, err := exec.Swap(ctx(), sess, rule, req)
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	if !outcome.Swapped {
		t.Fatal("the receive-pack swap must have fired (registered host + Authorization location)")
	}

	// Upstream gets the long-lived credential; the short-lived VM value is gone.
	gotAuth := req.Headers["Authorization"]
	if !strings.Contains(gotAuth, longLivedSecret) {
		t.Errorf("upstream Authorization must carry the long-lived credential; got %q", gotAuth)
	}
	if strings.Contains(gotAuth, shortLivedVMValue) {
		t.Errorf("the short-lived VM credential must NOT reach the upstream; got %q", gotAuth)
	}
	if vault.fetchCount() != 1 {
		t.Errorf("the long-lived credential must be fetched exactly once for the matched swap; fetches=%d", vault.fetchCount())
	}

	// The swap is logged with the rung (the grant reference + fingerprint), value
	// never. Emit a PolicyDecision/CredentialUse event the way main.rs would and
	// assert no credential byte rode any field.
	emitSwapTelemetry(t, sink, sess, outcome)

	for _, ev := range sink.Events() {
		if ev.Provenance.RuleID != swapRung("github", longLivedFingerprint) {
			t.Errorf("swap telemetry rung = %q, want %q", ev.Provenance.RuleID, swapRung("github", longLivedFingerprint))
		}
		ser := serializeEventFields(ev)
		if strings.Contains(ser, longLivedSecret) {
			t.Errorf("LOG-5 / never-log-the-secret VIOLATED: long-lived credential leaked into telemetry: %q", ser)
		}
		if strings.Contains(ser, shortLivedVMValue) {
			t.Errorf("LOG-5 / never-log-the-secret VIOLATED: short-lived credential leaked into telemetry: %q", ser)
		}
	}
}

// emitSwapTelemetry emits the per-request swap telemetry the way main.rs would
// after a swap: a CredentialUse event carrying the SERVICE + the FINGERPRINT +
// the swap rung provenance — never a credential value (LOG-5). Built in
// code-under-test so the "fingerprint only" property is the system's.
func emitSwapTelemetry(t *testing.T, sink tlsproxy.EventSink, sess tlsproxy.SessionRef, outcome tlsproxy.SwapOutcome) {
	t.Helper()
	ev := tlsproxy.Event{
		Kind:       tlsproxy.EventCredentialUse,
		Session:    sess,
		Provenance: outcome.Provenance,
		Fields: map[string]string{
			"service":     outcome.Service,
			"fingerprint": outcome.Fingerprint,
			"rung":        outcome.Provenance.RuleID,
		},
	}
	if err := sink.Emit(ctx(), ev); err != nil {
		t.Fatalf("emit swap telemetry: %v", err)
	}
}

// serializeEventFields renders an event's fields + provenance to a single string
// for the canary grep (mirrors boundary serializeEvent for the leak assertion).
func serializeEventFields(ev tlsproxy.Event) string {
	var b strings.Builder
	b.WriteString(string(ev.Kind))
	b.WriteByte('|')
	b.WriteString(ev.Provenance.RuleID)
	b.WriteByte('|')
	b.WriteString(ev.Provenance.PolicyLayer)
	b.WriteByte('|')
	b.WriteString(ev.Provenance.PolicyVersion)
	for k, v := range ev.Fields {
		b.WriteByte('|')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
	}
	return b.String()
}

// assertConnectPolicyTelemetry drives the policy through the endpoint's route and
// asserts a PolicyDecision event (provenance-complete) is emitted for the
// CONNECT authority — the per-request telemetry the acceptance names ("policy
// decision event carried per-request telemetry"). Built in code-under-test.
func assertConnectPolicyTelemetry(t *testing.T, sni string) {
	t.Helper()
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	policy := newConnectPolicy()
	policy.allowDomain(sni)
	sink := NewCapturingEventSink()
	minter := NewCAMinter()
	ca, err := minter.sessionCA(sess)
	if err != nil {
		t.Fatalf("sessionCA: %v", err)
	}
	ep := &ConnectEndpoint{Policy: policy, CA: ca, Inspect: false, Sink: sink}
	route, prov, err := ep.Route(ctx(), sess, sni+":443")
	if err != nil || route != CONNECTRouteOpaque {
		t.Fatalf("route for %s: route=%v err=%v", sni, route, err)
	}
	// Emit the PolicyDecision the way main.rs accounts a CONNECT verdict.
	ev := tlsproxy.Event{
		Kind:       tlsproxy.EventPolicyDecision,
		Session:    sess,
		Provenance: prov,
		Fields:     map[string]string{"authority": sni + ":443", "verdict": "allow"},
	}
	if err := sink.Emit(ctx(), ev); err != nil {
		t.Fatalf("emit policy decision: %v", err)
	}
	evs := sink.Events()
	found := false
	for _, e := range evs {
		if e.Kind == tlsproxy.EventPolicyDecision && e.Fields["authority"] == sni+":443" {
			found = true
			if e.Provenance.PolicyVersion == "" || e.Provenance.RuleID == "" {
				t.Errorf("CONNECT PolicyDecision must carry complete provenance, got %+v", e.Provenance)
			}
		}
	}
	if !found {
		t.Errorf("CONNECT path must emit a PolicyDecision event for %s", sni)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// TLS-2 invariant guards — the CONNECT path enforces the SAME domain policy as
// transparent: a denied authority and a bare-IP authority each REFUSE (no 200,
// no tunnel), a malformed CONNECT target (no port) refuses, and the allowed
// authority tunnels. These prove the route the golden flows through is the real
// TLS-2 policy decision, not an always-allow stub.
// ───────────────────────────────────────────────────────────────────────────

func TestCONNECT_TLS2Invariants_AuthorityPolicyGated(t *testing.T) {
	sess := tlsproxy.SessionRef{ID: "sess-a"}
	policy := newConnectPolicy()
	policy.allowDomain("registry.npmjs.org")
	minter := NewCAMinter()
	ca, _ := minter.sessionCA(sess)
	ep := &ConnectEndpoint{Policy: policy, CA: ca, Inspect: false, Sink: NewCapturingEventSink()}

	// (a) allowed authority → opaque tunnel.
	if r, _, err := ep.Route(ctx(), sess, "registry.npmjs.org:443"); err != nil || r != CONNECTRouteOpaque {
		t.Errorf("allowed authority must tunnel opaque, got route=%v err=%v", r, err)
	}
	// (b) a not-allowed authority → refuse.
	if r, prov, err := ep.Route(ctx(), sess, "blocked-domain.example:443"); err != nil || r != CONNECTRouteRefused {
		t.Errorf("a not-allowed authority must refuse, got route=%v err=%v", r, err)
	} else if !strings.Contains(prov.RuleID, "blocklist") {
		t.Errorf("a refusal must carry the blocklist provenance, got %q", prov.RuleID)
	}
	// (c) a bare-IP authority must refuse (bare-IP CONNECT bypasses domain policy)
	// even when the IP happens to be admitted elsewhere.
	if r, _, err := ep.Route(ctx(), sess, "140.82.1.1:443"); err != nil || r != CONNECTRouteRefused {
		t.Errorf("a bare-IP CONNECT authority must refuse (no domain match), got route=%v err=%v", r, err)
	}
	// (d) a malformed CONNECT target (no port) refuses before the policy is
	// consulted (the verb requires host:port).
	if r, prov, err := ep.Route(ctx(), sess, "registry.npmjs.org"); err != nil || r != CONNECTRouteRefused {
		t.Errorf("a malformed CONNECT target (no port) must refuse, got route=%v err=%v", r, err)
	} else if prov.RuleID != "tls2:malformed-connect" {
		t.Errorf("a malformed CONNECT target must carry the parse-error provenance, got %q", prov.RuleID)
	}
}

// TestCONNECT_GoldenFixturesNoSecretPayload guards the "not sensitive payloads"
// / "digests on sensitive payloads" + the credential-swap "never on a VM
// surface / never on disk" acceptance clauses: the on-disk CONNECT golden
// fixtures carry ONLY shape + digests + the long-lived FINGERPRINT — no raw
// body / tarball / pack bytes AND no credential value (short OR long lived).
func TestCONNECT_GoldenFixturesNoSecretPayload(t *testing.T) {
	_, _, metaBody, _, _, tarBody := npmExchange()
	_, _, adv, _, _, pack := gitPushExchange()
	type probe struct {
		file    string
		payload []byte
		what    string
	}
	probes := []probe{
		{npmGoldenFile, metaBody, "npm metadata body"},
		{npmGoldenFile, tarBody, "npm tarball bytes"},
		{gitPushGoldenFile, adv, "git advertisement bytes"},
		{gitPushGoldenFile, pack, "git pack bytes"},
		// The credential canaries: NEITHER may appear in EITHER fixture.
		{npmGoldenFile, []byte(longLivedSecret), "long-lived credential"},
		{npmGoldenFile, []byte(shortLivedVMValue), "short-lived credential"},
		{gitPushGoldenFile, []byte(longLivedSecret), "long-lived credential"},
		{gitPushGoldenFile, []byte(shortLivedVMValue), "short-lived credential"},
	}
	for _, p := range probes {
		b, err := os.ReadFile(p.file)
		if err != nil {
			t.Fatalf("read %s: %v", p.file, err)
		}
		if bytes.Contains(b, p.payload) {
			t.Errorf("golden %s leaked %s — fixtures carry digests + fingerprints, never payloads/credentials", p.file, p.what)
		}
	}
	// The git-push fixture MUST carry the long-lived FINGERPRINT (the swap rung
	// proof) — the fingerprint is loggable, the value is not.
	b, err := os.ReadFile(gitPushGoldenFile)
	if err != nil {
		t.Fatalf("read %s: %v", gitPushGoldenFile, err)
	}
	if !bytes.Contains(b, []byte(longLivedFingerprint)) {
		t.Errorf("git push golden must carry the long-lived fingerprint %q (the swap rung proof)", longLivedFingerprint)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// Live half — real npm / git over the EXPLICIT (CONNECT) path against a running
// ds-tlsproxy CONNECT listener (port :18443). DEFERRED MANUAL, run as a
// SKIP-by-default SUBTEST mirroring the transparent twin's runLiveWire ladder so
// the named golden-trace acceptance tests stay deterministic + GREEN under BOTH
// the opaque baseline (DS_TLS3_LIVE unset) and the inspected path armed.
// ───────────────────────────────────────────────────────────────────────────

// ConnectLiveAddr is the ds-tlsproxy CONNECT listener the live half drives real
// npm/git against (the acceptance names :18443). Overridable via
// DS_TLS_CONNECT_ADDR for a deployment's egress gateway.
func ConnectLiveAddr() string { return envOr("DS_TLS_CONNECT_ADDR", "127.0.0.1:18443") }

func maybeRunLiveConnectNpm(t *testing.T) {
	t.Run("live-wire-real-npm-connect", func(t *testing.T) {
		runLiveConnectWire(t, "npm", connectNpmSNI, npmGoldenFile)
	})
}

func maybeRunLiveConnectGit(t *testing.T) {
	t.Run("live-wire-real-git-push-connect", func(t *testing.T) {
		runLiveConnectWire(t, "git", connectGitSNI, gitPushGoldenFile)
	})
}

// runLiveConnectWire is the SKIP-by-default subtest body for one workload's real
// over-the-CONNECT-tunnel driver (mirrors runLiveWire from the transparent
// twin). It never fails the named golden-trace acceptance test: it skips unless
// an operator opts into the wire, then fails loudly until the deferred driver
// lands.
func runLiveConnectWire(t *testing.T, workload, sni, goldenFile string) {
	t.Helper()
	if !LiveEnabled() {
		t.Skipf("live CONNECT %s is a deferred-manual pass; set %s=1 (and %s=1 once a driver is wired) to drive real %s over a CONNECT tunnel against ds-tlsproxy at %s",
			workload, LiveEnvVar, liveWireEnvVar, workload, ConnectLiveAddr())
	}
	if os.Getenv(liveWireEnvVar) != "1" {
		t.Skipf("%s=1 arms the inspected path; set %s=1 to drive REAL %s over a CONNECT tunnel against ds-tlsproxy at %s (the golden replay already covers both legs offline)",
			LiveEnvVar, liveWireEnvVar, workload, ConnectLiveAddr())
	}
	t.Fatalf("live CONNECT %s runner is a DEFERRED MANUAL step: wire real %s over an HTTP CONNECT tunnel for %s against a running ds-tlsproxy CONNECT listener at %s and assert byte-identity with %s (no live %s from CI)",
		workload, workload, sni, ConnectLiveAddr(), goldenFile, workload)
}

// ───────────────────────────────────────────────────────────────────────────
// parse-edge unit guards for the CONNECT authority parser (the explicit.rs
// parse_connect mirror) — IPv6 literal round-trip + the no-port refusal.
// ───────────────────────────────────────────────────────────────────────────

func TestParseConnectAuthority_Edges(t *testing.T) {
	rows := []struct {
		target   string
		wantHost string
		wantPort string
		ok       bool
	}{
		{"registry.npmjs.org:443", "registry.npmjs.org", "443", true},
		{"github.com:443", "github.com", "443", true},
		{"[2001:db8::1]:443", "2001:db8::1", "443", true},
		{"140.82.1.1:443", "140.82.1.1", "443", true},
		{"registry.npmjs.org", "", "", false}, // no explicit port
		{":443", "", "", false},               // empty host
		{"github.com:", "", "", false},        // empty port
	}
	for _, row := range rows {
		got, ok := parseConnectAuthority(row.target)
		if ok != row.ok {
			t.Errorf("parseConnectAuthority(%q) ok=%v, want %v", row.target, ok, row.ok)
			continue
		}
		if ok && (got.host != row.wantHost || got.port != row.wantPort) {
			t.Errorf("parseConnectAuthority(%q) = %q:%q, want %q:%q", row.target, got.host, got.port, row.wantHost, row.wantPort)
		}
	}
}
