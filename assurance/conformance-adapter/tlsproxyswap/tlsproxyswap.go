// SPDX-License-Identifier: Apache-2.0

package tlsproxyswap

// tlsproxyswap.go — the adapter core wiring the real ds-tlsproxy TLS-5
// (credential swap: registry-match → D22 validate → D8/D39 secret fetch →
// upstream substitution → response scrub → CredentialUseEvent) data plane behind
// the boundary/tlsproxy EXPORTED Go seams (PolicyEngine, IdentityValidator,
// SecretStore, CredentialSwapper, ResponseScrubber, EventSink, LeakProbe). See
// doc.go for the guarantee, the seam-mirroring rationale, the headline canary
// grep, the sentinel convention, and the DS_TLS5_LIVE env-gate contract.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	tlsproxy "github.com/dream-serpent/dream-serpent/boundary/tlsproxy"
)

// ───────────────────────────────────────────────────────────────────────────
// Exported sentinels (Err prefix + errors.New — the load-bearing convention
// mirrored from tlsproxyinspect; see exportedSentinelUniverse +
// TestExportedSentinelUniverseComplete in the test file).
// ───────────────────────────────────────────────────────────────────────────

var (
	// ErrNoSwapRule is returned when no service-registry rule matches the request
	// host — NOT a swap. The request is forwarded untouched and neither the
	// IdentityValidator nor the SecretStore is consulted (doc 09 §5 TLS-5: swap
	// rules live in the service registry; boundary TestSwap_NoRegistryMatch_-
	// RequestUntouched).
	ErrNoSwapRule = errors.New("tlsproxyswap: no credential-swap service-registry rule matches the request (not a swap; forwarded untouched, no validate, no fetch)")

	// ErrIdentityRejected is returned when the presented short-lived credential
	// fails D22 validation against THIS session (cross-session / forged / expired /
	// tampered / wrong-service). The secret store is NEVER consulted on this path
	// (doc 09 §5 TLS-5; boundary TestSwap_CrossSessionShortLivedCred_RejectedNoFetch).
	ErrIdentityRejected = errors.New("tlsproxyswap: short-lived credential rejected by the D22 identity validator (no secret-store fetch on a validation failure)")

	// ErrSecretUnavailable is returned when the SecretStore has no long-lived
	// credential for an ALLOWED swap — the upstream dial fails mid-swap and the
	// proxy answers with its own error page (a VM surface the headline grep covers).
	ErrSecretUnavailable = errors.New("tlsproxyswap: long-lived credential unavailable from the secret store for an allowed swap (proxy answers its own error page)")

	// ErrCredentialLeaked is the test-facing sentinel for the headline invariant
	// breach: a long-lived (or short-lived) credential byte was observed on a
	// VM-bound surface or in an event/log path after a swap. The headline grep
	// asserts this never happens (doc 06 §3(c); D73 §5.1).
	ErrCredentialLeaked = errors.New("tlsproxyswap: credential observed on a VM surface or log path (TLS-5 headline breach: long-lived credential never enters the VM)")
)

// ───────────────────────────────────────────────────────────────────────────
// Credential location parsing — the rule's CredLocation (e.g. header:Authorization)
// names WHERE the presented short-lived credential lives and where the long-lived
// one is substituted (doc 09 §5 TLS-5; swap.rs CredentialLocation).
// ───────────────────────────────────────────────────────────────────────────

// CredLocationHeaderPrefix is the recognized credential-location scheme: a
// request header (e.g. "header:Authorization"). It is the only location the M1
// GitHub-first service uses; an unrecognized scheme is treated as no-location
// (the request passes through untouched, never fabricating a swap).
const CredLocationHeaderPrefix = "header:"

// headerForLocation returns the header name a CredLocation names, or ("", false)
// for a non-header / unrecognized location. A non-header location is not a swap
// site, so the request forwards untouched (boundary "credential in a non-
// registered location (cookie)" row).
func headerForLocation(loc string) (string, bool) {
	if name, ok := strings.CutPrefix(loc, CredLocationHeaderPrefix); ok && name != "" {
		return name, true
	}
	return "", false
}

// ───────────────────────────────────────────────────────────────────────────
// The fingerprint — the LOGGABLE, secret-free credential identifier (LOG-5).
//
// Every event carries the fingerprint, NEVER the value. fingerprintFor mirrors
// swap.rs's Fingerprint: it is derived from secret-FREE inputs (the service id)
// in the fakes' "fp-long-<service>" shape so the boundary assertions that look
// for "fp-long-github" hold, and it NEVER incorporates a credential byte.
// ───────────────────────────────────────────────────────────────────────────

// LongLivedFingerprint returns the loggable fingerprint for a service's long-
// lived credential. It is secret-free by construction (service id only) and
// matches the boundary fakes' "fp-long-<service>" convention so the
// CredentialUseEvent carries the expected fingerprint (boundary
// TestSwap_EveryLogPathScrubbed_FingerprintOnly asserts fp-long-github).
func LongLivedFingerprint(service string) string { return "fp-long-" + service }

// ShortLivedFingerprint returns the loggable fingerprint for a session's short-
// lived credential — secret-free (service + session id), the boundary fakes'
// "fp-short-<service>-<session>" convention.
func ShortLivedFingerprint(service string, sess tlsproxy.SessionRef) string {
	return "fp-short-" + service + "-" + sess.ID
}

// ───────────────────────────────────────────────────────────────────────────
// AdapterPolicyEngine — the boundary PolicyEngine seam over a swap registry.
//
// Only the TLS-5 surface (MatchSwapService) carries swap behavior; the other
// methods default-allow (the swap pipeline reaches the engine only for an
// already-admitted, already-allowed flow — TLS-1/TLS-3 enforced upstream). It is
// the Go mirror of swap.rs's SwapRegistry::match_request.
// ───────────────────────────────────────────────────────────────────────────

// AdapterPolicyEngine serves the boundary PolicyEngine seam over a credential-
// swap service registry. It satisfies tlsproxy.PolicyEngine.
type AdapterPolicyEngine struct {
	mu      sync.Mutex
	rules   []tlsproxy.ServiceRule
	version string
}

// NewPolicyEngine builds an empty-registry policy engine (the D74 default:
// nothing swaps until a rule is registered). version stamps provenance.
func NewPolicyEngine(version string) *AdapterPolicyEngine {
	if version == "" {
		version = "policy-v1"
	}
	return &AdapterPolicyEngine{version: version}
}

// Register adds one swap service rule to the registry (the service-registry
// programming the boundary setupSwap helper performs).
func (p *AdapterPolicyEngine) Register(rule tlsproxy.ServiceRule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = append(p.rules, rule)
}

// MatchSwapService returns the first registry rule whose host list contains host,
// or (zero, false) for a registry miss. A miss is NOT a swap (the caller forwards
// untouched). Mirrors swap.rs SwapRegistry::match_request.
func (p *AdapterPolicyEngine) MatchSwapService(_ context.Context, host string) (tlsproxy.ServiceRule, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.rules {
		for _, h := range r.Hosts {
			if h == host {
				return r, true, nil
			}
		}
	}
	return tlsproxy.ServiceRule{}, false, nil
}

// EvaluateConnect default-allows (TLS-1 admission is enforced upstream of swap).
func (p *AdapterPolicyEngine) EvaluateConnect(_ context.Context, _ tlsproxy.SessionRef, _ string) (tlsproxy.Decision, error) {
	return tlsproxy.Decision{Allow: true, Provenance: p.prov("connect:default-allow")}, nil
}

// EvaluateHTTP default-allows (HTTP policy is enforced upstream of swap; the swap
// pipeline reaches the engine only for an already-allowed flow).
func (p *AdapterPolicyEngine) EvaluateHTTP(_ context.Context, _ tlsproxy.SessionRef, _ tlsproxy.RequestMeta) (tlsproxy.Decision, error) {
	return tlsproxy.Decision{Allow: true, Provenance: p.prov("http:default-allow")}, nil
}

// PassThrough reports false (the empty-list D74 default — the swap pipeline runs
// on the inspected path; a pass-through flow never reaches it).
func (p *AdapterPolicyEngine) PassThrough(_ context.Context, _ tlsproxy.SessionRef, _ string) (bool, tlsproxy.Provenance, error) {
	return false, p.prov("passthrough:empty-list-default"), nil
}

func (p *AdapterPolicyEngine) prov(rule string) tlsproxy.Provenance {
	return tlsproxy.Provenance{RuleID: rule, PolicyLayer: "system", PolicyVersion: p.version}
}

// ───────────────────────────────────────────────────────────────────────────
// AdapterIdentityValidator — the boundary IdentityValidator (D22) seam.
//
// Mirrors swap.rs's IdentityValidator: the presented short-lived credential must
// validate against THIS session before any secret-store fetch. Cross-session,
// forged, expired, tampered, and wrong-service creds fail HERE. It records its
// call count so a test can prove the validator was (or was NOT) consulted.
// ───────────────────────────────────────────────────────────────────────────

// AdapterIdentityValidator serves the boundary IdentityValidator seam. It
// satisfies tlsproxy.IdentityValidator.
type AdapterIdentityValidator struct {
	mu    sync.Mutex
	now   func() time.Time
	valid map[string]tlsproxy.IdentityClaims // key: string(Credential.Value)
	calls int
}

// NewIdentityValidator builds a validator over the injected clock (nil ⇒
// time.Now), so credential expiry is advanced logically, never slept for.
func NewIdentityValidator(now func() time.Time) *AdapterIdentityValidator {
	if now == nil {
		now = time.Now
	}
	return &AdapterIdentityValidator{now: now, valid: map[string]tlsproxy.IdentityClaims{}}
}

// Mint issues a fresh, session-bound short-lived credential valid for ttl. The
// VALUE is high-entropy (a usable leak needle) and the session/subject binding
// lives in the claims map, not the value shape (boundary CONVENTIONS canary
// rule). It returns the loggable short-lived fingerprint too.
func (v *AdapterIdentityValidator) Mint(sess tlsproxy.SessionRef, subject string, ttl time.Duration) tlsproxy.Credential {
	v.mu.Lock()
	defer v.mu.Unlock()
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		panic("tlsproxyswap: identity mint entropy: " + err.Error())
	}
	val := fmt.Sprintf("sl-%s-%s-%s", sess.ID, subject, hex.EncodeToString(entropy[:]))
	v.valid[val] = tlsproxy.IdentityClaims{Session: sess, Subject: subject, Expiry: v.now().Add(ttl)}
	return tlsproxy.Credential{Value: tlsproxy.Secret(val), Fingerprint: ShortLivedFingerprint(subject, sess)}
}

// ValidateShortLived validates the presented credential against sess. An unknown/
// forged value, a value bound to another session, or an expired value all fail
// with an ErrIdentityRejected-wrapped error (a readable refusal upstream maps to
// a 4xx). Mirrors swap.rs's synchronous Validate.
func (v *AdapterIdentityValidator) ValidateShortLived(_ context.Context, sess tlsproxy.SessionRef, presented tlsproxy.Credential) (tlsproxy.IdentityClaims, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	claims, ok := v.valid[string(presented.Value)]
	if !ok {
		return tlsproxy.IdentityClaims{}, fmt.Errorf("%w: unknown or forged credential", ErrIdentityRejected)
	}
	if claims.Session != sess {
		return tlsproxy.IdentityClaims{}, fmt.Errorf("%w: identity mismatch (credential bound to another session)", ErrIdentityRejected)
	}
	if !claims.Expiry.After(v.now()) {
		return tlsproxy.IdentityClaims{}, fmt.Errorf("%w: credential expired", ErrIdentityRejected)
	}
	return claims, nil
}

// CallCount reports how many times the validator was consulted — a test asserts
// it was NOT called on a registry miss, and WAS called before any fetch.
func (v *AdapterIdentityValidator) CallCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

// ───────────────────────────────────────────────────────────────────────────
// AdapterSecretStore — the boundary SecretStore (D8/D39) seam.
//
// The real-credential source OUTSIDE the boundary. Mirrors swap.rs's secret-store
// fetch: it is consulted ONLY on an ALLOW (a registry+location match that
// validated). It records its calls so a test proves it is never reached on a
// validation failure or registry miss, and that its returned value reaches only
// the upstream leg.
// ───────────────────────────────────────────────────────────────────────────

// AdapterSecretStore serves the boundary SecretStore seam. It satisfies
// tlsproxy.SecretStore.
type AdapterSecretStore struct {
	mu    sync.Mutex
	creds map[string]tlsproxy.Credential // key: service
	calls []string                       // service ids fetched, in order
}

// NewSecretStore builds an empty secret store outside the boundary.
func NewSecretStore() *AdapterSecretStore {
	return &AdapterSecretStore{creds: map[string]tlsproxy.Credential{}}
}

// Program installs the long-lived credential for service (the real credential
// the upstream — and only the upstream — receives). The fingerprint is the
// loggable LOG-5 identifier the CredentialUseEvent carries.
func (s *AdapterSecretStore) Program(service string, longLived []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[service] = tlsproxy.Credential{Value: tlsproxy.Secret(longLived), Fingerprint: LongLivedFingerprint(service)}
}

// FetchLongLived returns the long-lived credential for service, recording the
// call. An unprogrammed service fails with ErrSecretUnavailable (the proxy then
// answers its own error page). Mirrors swap.rs's secret-store fetch trait.
func (s *AdapterSecretStore) FetchLongLived(_ context.Context, service string, _ tlsproxy.IdentityClaims) (tlsproxy.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, service)
	if c, ok := s.creds[service]; ok {
		return c, nil
	}
	return tlsproxy.Credential{}, fmt.Errorf("%w: service %q", ErrSecretUnavailable, service)
}

// FetchCount reports how many times the store was consulted — a test asserts it
// is ZERO on a validation failure or registry miss.
func (s *AdapterSecretStore) FetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// ───────────────────────────────────────────────────────────────────────────
// AdapterScrubber — the boundary ResponseScrubber (TLS-5) seam.
//
// The VM-bound-leg scrubber: an upstream echoing the swapped Authorization value
// back must never deliver the long-lived credential downstream. It scrubs EVERY
// encoded form (raw/base64/base64url/hex/url-encoded — encoded forms are in
// scope, D73 §5.1) of every secret it is told to guard, replacing each with a
// fixed redaction marker, and reports a ScrubHit per hit. Mirrors swap.rs's
// type-level scrub (the never-log-the-secret property).
// ───────────────────────────────────────────────────────────────────────────

// ScrubMarker is the fixed byte sequence every scrubbed credential occurrence is
// replaced with on the VM-bound leg. It carries zero credential bytes.
const ScrubMarker = "[REDACTED-BY-EGRESS-GATEWAY]"

// AdapterScrubber serves the boundary ResponseScrubber seam over a registered set
// of secrets to guard. It satisfies tlsproxy.ResponseScrubber.
type AdapterScrubber struct {
	mu      sync.Mutex
	secrets [][]byte // raw credential bytes to scrub in every encoded form
}

// NewScrubber builds an empty scrubber. Guard secrets are registered per swap so
// the scrubber knows which credential bytes to strip from the VM-bound response.
func NewScrubber() *AdapterScrubber { return &AdapterScrubber{} }

// Guard registers a secret whose every encoded form must be scrubbed from the
// VM-bound response. Both the long-lived and short-lived credentials are guarded
// (boundary TestSwap_EveryLogPathScrubbed: scrub BOTH credentials).
func (s *AdapterScrubber) Guard(secret []byte) {
	if len(secret) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = append(s.secrets, append([]byte(nil), secret...))
}

// ScrubResponse strips every guarded secret (every encoded form) from the body
// stream, returning the scrubbed reader and one ScrubHit per (secret, form) that
// was present. The header map is scrubbed in place. Encoded forms are in scope:
// a base64-of-the-credential echo is caught (D73 §5.1).
func (s *AdapterScrubber) ScrubResponse(_ context.Context, _ tlsproxy.SessionRef, resp *tlsproxy.ResponseMeta, body io.Reader) (io.Reader, []tlsproxy.ScrubHit, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsproxyswap: read upstream body to scrub: %w", err)
	}
	s.mu.Lock()
	guarded := make([][]byte, len(s.secrets))
	copy(guarded, s.secrets)
	s.mu.Unlock()

	var hits []tlsproxy.ScrubHit
	marker := []byte(ScrubMarker)
	for _, secret := range guarded {
		for form, enc := range EncodedForms(secret) {
			if bytes.Contains(raw, enc) {
				raw = bytes.ReplaceAll(raw, enc, marker)
				hits = append(hits, tlsproxy.ScrubHit{Location: "body", Form: form})
			}
			if resp != nil {
				for name, val := range resp.Headers {
					if strings.Contains(val, string(enc)) {
						resp.Headers[name] = strings.ReplaceAll(val, string(enc), ScrubMarker)
						hits = append(hits, tlsproxy.ScrubHit{Location: "header:" + name, Form: form})
					}
				}
			}
		}
	}
	return bytes.NewReader(raw), hits, nil
}

// ───────────────────────────────────────────────────────────────────────────
// CapturingEventSink — the boundary EventSink seam (LOG-1 mirror / LOG-5 audit).
//
// Captures every emission so the adapter can assert the CredentialUseEvent
// (which session used the key, when, for what request — fingerprint only), the
// ScrubEvent, the deny ErrorEvent, and that NO event carries a credential byte.
// ───────────────────────────────────────────────────────────────────────────

// CapturingEventSink captures every telemetry emission for assertion. It
// satisfies tlsproxy.EventSink.
type CapturingEventSink struct {
	mu  sync.Mutex
	evs []tlsproxy.Event
}

// NewCapturingEventSink builds an empty capturing sink.
func NewCapturingEventSink() *CapturingEventSink { return &CapturingEventSink{} }

// Emit records the event (deep-copying Fields so later mutation cannot
// retroactively change a captured emission).
func (s *CapturingEventSink) Emit(_ context.Context, ev tlsproxy.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := ev
	cp.Fields = map[string]string{}
	for k, v := range ev.Fields {
		cp.Fields[k] = v
	}
	s.evs = append(s.evs, cp)
	return nil
}

// Events returns a copy of every captured emission.
func (s *CapturingEventSink) Events() []tlsproxy.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tlsproxy.Event(nil), s.evs...)
}

// ───────────────────────────────────────────────────────────────────────────
// AdapterLeakProbe — the boundary LeakProbe seam over the VM-observable surfaces.
//
// Records every byte the proxy sent toward the VM (the downstream-bytes surface)
// plus disk / env / CoW-delta surfaces, then greps all of them for the canary in
// every encoded form. The headline test drives this; zero hits is the pass.
// ───────────────────────────────────────────────────────────────────────────

// AdapterLeakProbe serves the boundary LeakProbe seam. It satisfies
// tlsproxy.LeakProbe.
type AdapterLeakProbe struct {
	mu   sync.Mutex
	bufs map[tlsproxy.Surface][]byte
}

// NewLeakProbe builds a probe with an empty buffer for every VM surface.
func NewLeakProbe() *AdapterLeakProbe {
	return &AdapterLeakProbe{bufs: map[tlsproxy.Surface][]byte{
		tlsproxy.SurfaceDisk:            nil,
		tlsproxy.SurfaceEnv:             nil,
		tlsproxy.SurfaceCoWDelta:        nil,
		tlsproxy.SurfaceDownstreamBytes: nil,
	}}
}

// Add appends bytes to a VM surface's recording (the downstream-bytes surface is
// every byte the proxy sent toward the VM).
func (p *AdapterLeakProbe) Add(s tlsproxy.Surface, b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bufs[s] = append(p.bufs[s], b...)
}

// SnapshotEnv records the process environment on the env surface (a swap that
// stashed a credential in the environment would surface here).
func (p *AdapterLeakProbe) SnapshotEnv() {
	p.Add(tlsproxy.SurfaceEnv, []byte(strings.Join(os.Environ(), "\n")))
}

// Search returns one LeakHit per occurrence of needle on any VM surface.
func (p *AdapterLeakProbe) Search(_ context.Context, _ tlsproxy.SessionRef, needle []byte) ([]tlsproxy.LeakHit, error) {
	if len(needle) == 0 {
		return nil, nil
	}
	p.mu.Lock()
	bufs := map[tlsproxy.Surface][]byte{}
	for s, b := range p.bufs {
		bufs[s] = append([]byte(nil), b...)
	}
	p.mu.Unlock()

	var hits []tlsproxy.LeakHit
	for surf, hay := range bufs {
		off := 0
		for {
			i := bytes.Index(hay[off:], needle)
			if i < 0 {
				break
			}
			hits = append(hits, tlsproxy.LeakHit{Surface: surf, Offset: int64(off + i), Context: string(surf)})
			off += i + 1
		}
	}
	return hits, nil
}

// ───────────────────────────────────────────────────────────────────────────
// EncodedForms — the VM-observable encodings of a credential the grep/scrub
// cover (mirrors the boundary encForms helper): raw, base64 (std + url), hex,
// url-encoded. Encoded forms ARE in scope (D73 §5.1).
// ───────────────────────────────────────────────────────────────────────────

// EncodedForms returns the credential's VM-observable encodings keyed by form.
func EncodedForms(needle []byte) map[string][]byte {
	return map[string][]byte{
		"raw":        needle,
		"base64":     []byte(base64.StdEncoding.EncodeToString(needle)),
		"base64url":  []byte(base64.RawURLEncoding.EncodeToString(needle)),
		"hex":        []byte(hex.EncodeToString(needle)),
		"urlencoded": []byte(url.QueryEscape(string(needle))),
	}
}

// ───────────────────────────────────────────────────────────────────────────
// Upstream — the upstream the swapped request reaches (the egress leg). The fake
// upstream models a real service: it receives the SUBSTITUTED Authorization
// header (the long-lived credential) and produces a response the scrubber then
// guards on the VM-bound leg.
// ───────────────────────────────────────────────────────────────────────────

// UpstreamRequest is what the upstream observed — the SUBSTITUTED request. A
// test asserts the upstream's Authorization carries the LONG-lived credential
// and never the short-lived one.
type UpstreamRequest struct {
	Method  string
	Host    string
	Path    string
	Headers map[string]string
}

// UpstreamResponse is what the upstream returned, before scrubbing. The
// AdapterSwapEngine scrubs it on the VM-bound leg.
type UpstreamResponse struct {
	Status  int
	Headers map[string]string
	Body    []byte
}

// Upstream is the egress-leg server the swapped request reaches. handler shapes
// the response from the substituted request (so an echoing/redirecting/erroring
// upstream can be modeled). dialErr, when set, models an upstream that fails to
// dial mid-swap (the proxy then answers its own error page).
type Upstream struct {
	mu      sync.Mutex
	handler func(req UpstreamRequest) UpstreamResponse
	dialErr error
	reqs    []UpstreamRequest
}

// NewUpstream builds an upstream whose default handler returns 200 with a small
// JSON body and no echo.
func NewUpstream() *Upstream {
	return &Upstream{handler: func(UpstreamRequest) UpstreamResponse {
		return UpstreamResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(`{"login":"agent"}`)}
	}}
}

// SetHandler installs the response shaper (echo, redirect, error, reflection).
func (u *Upstream) SetHandler(h func(req UpstreamRequest) UpstreamResponse) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.handler = h
}

// FailDial makes the next dial fail with err (the proxy answers its own error
// page; ErrSecretUnavailable's sibling on the upstream leg).
func (u *Upstream) FailDial(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.dialErr = err
}

// Requests returns every request the upstream observed (the SUBSTITUTED ones).
func (u *Upstream) Requests() []UpstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]UpstreamRequest(nil), u.reqs...)
}

// serve records the (substituted) request and produces the upstream response, or
// the dial error.
func (u *Upstream) serve(req UpstreamRequest) (UpstreamResponse, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.dialErr != nil {
		return UpstreamResponse{}, u.dialErr
	}
	u.reqs = append(u.reqs, req)
	return u.handler(req), nil
}

// ───────────────────────────────────────────────────────────────────────────
// AdapterSwapEngine — THE CODE UNDER TEST: the single dispatch point that drives
// one request through the real TLS-5 pipeline over the boundary seams, in the
// exact order swap.rs does. The route is DECIDED HERE by consulting the seams —
// the caller does not choose the leg — so a test observing which seam methods ran
// (and in which order) proves the system's behavior, not the test's.
// ───────────────────────────────────────────────────────────────────────────

// SwapResult is the outcome of one engine dispatch: the response delivered toward
// the VM (status/headers/body, already scrubbed) and the verdict.
type SwapResult struct {
	// Swapped reports whether a credential substitution occurred.
	Swapped bool
	// Service is the matched service id (empty on a no-swap).
	Service string
	// Status is the status delivered toward the VM (a deny ⇒ 4xx, a proxy error
	// page ⇒ 502).
	Status int
	// Headers is the VM-bound response header set (scrubbed).
	Headers map[string]string
	// Body is the VM-bound response body (scrubbed).
	Body []byte
	// Fingerprint is the long-lived credential's loggable fingerprint on a swap.
	Fingerprint string
}

// HTTPRequest is one VM-originated request the engine dispatches. Headers holds
// the presented credential at the rule's location (header:Authorization).
type HTTPRequest struct {
	Method  string
	Host    string
	Path    string
	Headers map[string]string
}

// AdapterSwapEngine is the real-plane swap dispatcher (the Go mirror of swap.rs
// SwapExecutor + the PE9N-u2 back half). It consults the boundary PolicyEngine /
// IdentityValidator / SecretStore / ResponseScrubber / EventSink seams and emits
// onto the LeakProbe's downstream-bytes surface.
type AdapterSwapEngine struct {
	Policy   tlsproxy.PolicyEngine
	Identity tlsproxy.IdentityValidator
	Secrets  tlsproxy.SecretStore
	Scrubber tlsproxy.ResponseScrubber
	Events   tlsproxy.EventSink
	Probe    *AdapterLeakProbe
	Upstream *Upstream
	// Now is the injected clock for the CredentialUseEvent timestamp (LOG-5).
	Now func() time.Time
}

// compile-time proof the adapter types satisfy the boundary seams.
var (
	_ tlsproxy.PolicyEngine      = (*AdapterPolicyEngine)(nil)
	_ tlsproxy.IdentityValidator = (*AdapterIdentityValidator)(nil)
	_ tlsproxy.SecretStore       = (*AdapterSecretStore)(nil)
	_ tlsproxy.ResponseScrubber  = (*AdapterScrubber)(nil)
	_ tlsproxy.EventSink         = (*CapturingEventSink)(nil)
	_ tlsproxy.LeakProbe         = (*AdapterLeakProbe)(nil)
)

// now resolves the engine clock (nil ⇒ time.Now).
func (e *AdapterSwapEngine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Dispatch drives one request through the TLS-5 pipeline:
//
//  1. registry match → miss ⇒ NoSwap (forward untouched; no validate, no fetch);
//  2. credential location → absent ⇒ NoSwap (forward untouched);
//  3. D22 validate → fail ⇒ 4xx deny (no fetch), ErrorEvent with provenance;
//  4. secret-store fetch → fail ⇒ 502 proxy error page (no swapped request reaches
//     the upstream), ErrorEvent;
//  5. substitute long-lived into the outbound header IN PLACE → upstream serve;
//  6. scrub the VM-bound response (both credentials, every encoded form),
//     ScrubEvent on a hit;
//  7. emit CredentialUseEvent (session, when, request line, fingerprint only);
//  8. record the VM-bound bytes on the leak probe.
//
// The returned SwapResult is what the VM observes. Every error path returns a
// READABLE response (never a dead conn): a 4xx deny, a 502 proxy error page.
func (e *AdapterSwapEngine) Dispatch(ctx context.Context, sess tlsproxy.SessionRef, req HTTPRequest) (SwapResult, error) {
	prov := tlsproxy.Provenance{RuleID: "swap:registry", PolicyLayer: "system", PolicyVersion: "policy-v1"}

	// (1) registry match.
	rule, matched, err := e.Policy.MatchSwapService(ctx, req.Host)
	if err != nil {
		return SwapResult{}, fmt.Errorf("tlsproxyswap: registry match: %w", err)
	}
	if !matched {
		return e.forwardUntouched(ctx, sess, req)
	}

	// (2) credential location.
	hdrName, isHeaderLoc := headerForLocation(rule.CredLocation)
	if !isHeaderLoc {
		return e.forwardUntouched(ctx, sess, req)
	}
	presentedVal, present := lookupHeader(req.Headers, hdrName)
	short, hasCred := parseBearer(presentedVal)
	if !present || !hasCred {
		return e.forwardUntouched(ctx, sess, req)
	}

	// (3) D22 validate — the secret store is NOT reachable from a deny.
	claims, err := e.Identity.ValidateShortLived(ctx, sess, tlsproxy.Credential{Value: tlsproxy.Secret(short)})
	if err != nil {
		_ = e.Events.Emit(ctx, tlsproxy.Event{
			Kind: tlsproxy.EventError, Session: sess, At: e.now(),
			Provenance: tlsproxy.Provenance{RuleID: "swap:identity-deny", PolicyLayer: "system", PolicyVersion: "policy-v1"},
			Fields:     map[string]string{"service": rule.Service, "reason": denyReason(err)},
		})
		return e.denyResponse(ctx, sess, rule.Service, err), nil
	}

	// (4) secret-store fetch — only on an ALLOW.
	long, err := e.Secrets.FetchLongLived(ctx, rule.Service, claims)
	if err != nil {
		_ = e.Events.Emit(ctx, tlsproxy.Event{
			Kind: tlsproxy.EventError, Session: sess, At: e.now(), Provenance: prov,
			Fields: map[string]string{"service": rule.Service, "reason": "secret-store-unavailable"},
		})
		return e.proxyErrorPage(ctx, sess), nil
	}

	// (5) substitute long-lived into the outbound header IN PLACE → upstream.
	outHeaders := cloneHeaders(req.Headers)
	outHeaders[hdrName] = "Bearer " + string(long.Value)
	upResp, dialErr := e.Upstream.serve(UpstreamRequest{
		Method: req.Method, Host: req.Host, Path: req.Path, Headers: outHeaders,
	})
	if dialErr != nil {
		_ = e.Events.Emit(ctx, tlsproxy.Event{
			Kind: tlsproxy.EventError, Session: sess, At: e.now(), Provenance: prov,
			Fields: map[string]string{"service": rule.Service, "reason": "upstream-dial-failed"},
		})
		return e.proxyErrorPage(ctx, sess), nil
	}

	// (6) scrub the VM-bound response (both credentials, every encoded form).
	respMeta := &tlsproxy.ResponseMeta{Status: upResp.Status, Headers: cloneHeaders(upResp.Headers)}
	scrubbed, hits, err := e.Scrubber.ScrubResponse(ctx, sess, respMeta, bytes.NewReader(upResp.Body))
	if err != nil {
		return SwapResult{}, fmt.Errorf("tlsproxyswap: scrub response: %w", err)
	}
	body, err := io.ReadAll(scrubbed)
	if err != nil {
		return SwapResult{}, fmt.Errorf("tlsproxyswap: read scrubbed body: %w", err)
	}
	if len(hits) > 0 {
		_ = e.Events.Emit(ctx, tlsproxy.Event{
			Kind: tlsproxy.EventScrub, Session: sess, At: e.now(), Provenance: prov,
			Fields: map[string]string{"service": rule.Service, "hits": fmt.Sprintf("%d", len(hits))},
		})
	}

	// (7) CredentialUseEvent (LOG-5): session, when, request line, fingerprint only.
	_ = e.Events.Emit(ctx, tlsproxy.Event{
		Kind: tlsproxy.EventCredentialUse, Session: sess, At: e.now(),
		Provenance: tlsproxy.Provenance{RuleID: "swap:credential-use", PolicyLayer: "system", PolicyVersion: "policy-v1"},
		Fields: map[string]string{
			"service":     rule.Service,
			"fingerprint": long.Fingerprint,
			"method":      req.Method,
			"path":        req.Path,
		},
	})

	// (8) record the VM-bound bytes on the leak probe.
	if e.Probe != nil {
		e.Probe.Add(tlsproxy.SurfaceDownstreamBytes, dumpResponse(respMeta, body))
	}

	return SwapResult{
		Swapped: true, Service: rule.Service, Status: respMeta.Status,
		Headers: respMeta.Headers, Body: body, Fingerprint: long.Fingerprint,
	}, nil
}

// forwardUntouched delivers the upstream's response for a non-swap flow WITHOUT
// any header rewrite (the request reaches the upstream byte-identical) and emits
// no CredentialUseEvent. The validator and secret store are never consulted here.
func (e *AdapterSwapEngine) forwardUntouched(ctx context.Context, sess tlsproxy.SessionRef, req HTTPRequest) (SwapResult, error) {
	upResp, dialErr := e.Upstream.serve(UpstreamRequest{
		Method: req.Method, Host: req.Host, Path: req.Path, Headers: cloneHeaders(req.Headers),
	})
	if dialErr != nil {
		return e.proxyErrorPage(ctx, sess), nil
	}
	if e.Probe != nil {
		e.Probe.Add(tlsproxy.SurfaceDownstreamBytes, dumpResponse(&tlsproxy.ResponseMeta{Status: upResp.Status, Headers: upResp.Headers}, upResp.Body))
	}
	return SwapResult{Swapped: false, Status: upResp.Status, Headers: upResp.Headers, Body: upResp.Body}, nil
}

// denyResponse builds the readable 4xx refusal for a validation failure. The
// status is 401 (unknown/forged/expired) or 403 (cross-session mismatch). The
// body carries NO credential byte.
func (e *AdapterSwapEngine) denyResponse(_ context.Context, sess tlsproxy.SessionRef, service string, cause error) SwapResult {
	status := 401
	if strings.Contains(cause.Error(), "identity mismatch") {
		status = 403
	}
	body := []byte(fmt.Sprintf(`{"error":"credential rejected","service":%q}`, service))
	res := SwapResult{Swapped: false, Service: service, Status: status, Headers: map[string]string{"Content-Type": "application/json"}, Body: body}
	if e.Probe != nil {
		e.Probe.Add(tlsproxy.SurfaceDownstreamBytes, dumpResponse(&tlsproxy.ResponseMeta{Status: status, Headers: res.Headers}, body))
	}
	return res
}

// proxyErrorPage is the proxy-generated 502 the egress gateway answers when the
// upstream dial fails mid-swap (a readable VM surface, not a dead conn). It
// carries NO credential byte.
func (e *AdapterSwapEngine) proxyErrorPage(_ context.Context, _ tlsproxy.SessionRef) SwapResult {
	body := []byte(`{"error":"bad gateway","detail":"upstream unreachable"}`)
	res := SwapResult{Swapped: false, Status: 502, Headers: map[string]string{"Content-Type": "application/json"}, Body: body}
	if e.Probe != nil {
		e.Probe.Add(tlsproxy.SurfaceDownstreamBytes, dumpResponse(&tlsproxy.ResponseMeta{Status: 502, Headers: res.Headers}, body))
	}
	return res
}

// ───────────────────────────────────────────────────────────────────────────
// small request/response helpers.
// ───────────────────────────────────────────────────────────────────────────

// lookupHeader does a case-insensitive header lookup (HTTP headers are
// case-insensitive; the canonical "Authorization" is what callers set).
func lookupHeader(h map[string]string, name string) (string, bool) {
	if v, ok := h[name]; ok {
		return v, true
	}
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// parseBearer extracts the bare credential bytes from a "Bearer <cred>" value.
// An empty value or a non-bearer value yields ("", false) — not a swap.
func parseBearer(v string) ([]byte, bool) {
	if v == "" {
		return nil, false
	}
	if rest, ok := strings.CutPrefix(v, "Bearer "); ok && rest != "" {
		return []byte(rest), true
	}
	return nil, false
}

// cloneHeaders deep-copies a header map (nil-safe).
func cloneHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// dumpResponse renders a response as VM-observable bytes (status line + headers +
// body) — exactly what the leak probe greps on the downstream-bytes surface.
func dumpResponse(meta *tlsproxy.ResponseMeta, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d\r\n", meta.Status)
	for k, v := range meta.Headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

// denyReason maps a validation error to a stable, secret-free reason code for the
// ErrorEvent (the boundary identity-mismatch row greps the event for "identity
// mismatch" and asserts no credential byte).
func denyReason(err error) string {
	switch {
	case err == nil:
		return ""
	case strings.Contains(err.Error(), "identity mismatch"):
		return "identity mismatch"
	case strings.Contains(err.Error(), "expired"):
		return "expired"
	default:
		return "invalid credential"
	}
}

// serializeEvent renders an event as a loggable string — the form the headline
// grep scans for credential leakage (mirrors the boundary serializeEvent).
func serializeEvent(ev tlsproxy.Event) []byte {
	return []byte(fmt.Sprintf("kind=%s session=%s at=%s prov=%+v fields=%v",
		ev.Kind, ev.Session.ID, ev.At.UTC().Format(time.RFC3339Nano), ev.Provenance, ev.Fields))
}

// serializeEvents concatenates serialized events for a single grep pass.
func serializeEvents(evs []tlsproxy.Event) []byte {
	var b bytes.Buffer
	for _, ev := range evs {
		b.Write(serializeEvent(ev))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// ───────────────────────────────────────────────────────────────────────────
// Live half env-gate contract (mirrors DS_TLS3_LIVE — see doc.go).
// ───────────────────────────────────────────────────────────────────────────

// LiveEnvVar is the env gate for the live TLS-5 conformance run. Set to "1" the
// live half drives a git push to real GitHub through a running ds-tlsproxy and
// asserts the swap works end to end with only a short-lived credential in the VM;
// unset (the default) the live half SKIPS. It is a deferred manual step: it needs
// a running ds-tlsproxy + a live kernel/network + a real long-lived credential
// the wave sandbox lacks (the offline half covers the in-process swap pipeline +
// all-surfaces canary grep).
const LiveEnvVar = "DS_TLS5_LIVE"

// LiveEnabled reports whether the env gate opts into the live half.
func LiveEnabled() bool { return os.Getenv(LiveEnvVar) == "1" }

// LiveTarget addresses the running ds-tlsproxy the live half drives against.
type LiveTarget struct {
	// TLSProxyAddr is the ds-tlsproxy transparent/CONNECT listener (host:port) the
	// inspected swap flow is terminated on (the egress gateway).
	TLSProxyAddr string
}

// LiveTargetFromEnv builds the live target from DS_TLS5_* env vars, with a
// localhost dev default. It does NOT itself require the gate.
func LiveTargetFromEnv() LiveTarget {
	return LiveTarget{TLSProxyAddr: envOr("DS_TLS5_TLSPROXY_ADDR", "127.0.0.1:443")}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
