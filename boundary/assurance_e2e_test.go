package boundary

// §8 end-to-end lifecycle (E2E-*) and §1 developer-value halves (DV-*).
// All RED until the real data plane satisfies the documented outcomes.

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"
)

// planRef: doc 09 §8 e2e; doc 06 (b). Full lifecycle end to end.
func TestLifecycle_CreateAttachWorkSnapshotSuspendResumeDestroy(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	sess := h.newSession(t)
	if _, err := h.b.Attach(ctx, sess.Ref); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// Representative workload pre-snapshot: resolve + flow + HTTP.
	h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
	_, addrs := h.resolveOK(t, sess.Ref, "github.com")
	if _, err := h.b.VM(sess.Ref).Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(addrs[0], 443)}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := h.http.SetResponse(ctx, "github.com", "/work", 200, nil, []byte("pre-snapshot-marker")); err != nil {
		t.Fatalf("SetResponse: %v", err)
	}
	preResp, err := h.b.VM(sess.Ref).HTTP(ctx, HTTPRequest{Method: "GET", Host: "github.com", Path: "/work"})
	if err != nil {
		t.Fatalf("pre-snapshot HTTP: %v", err)
	}
	if preResp.Status != 200 {
		t.Fatalf("pre-snapshot HTTP status = %d, want 200", preResp.Status)
	}

	snap, err := h.b.Snapshot(ctx, sess.Ref)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.ID == "" {
		t.Fatal("Snapshot returned empty ref")
	}

	if err := h.b.Suspend(ctx, sess.Ref, SuspendReasonOperator); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if err := h.b.Resume(ctx, sess.Ref); err != nil {
		t.Fatalf("Resume: %v", err)
	}

	// The pre-snapshot work is intact post-resume.
	postResp, err := h.b.VM(sess.Ref).HTTP(ctx, HTTPRequest{Method: "GET", Host: "github.com", Path: "/work"})
	if err != nil {
		t.Fatalf("post-resume HTTP: %v", err)
	}
	if postResp.Status != 200 || !bytes.Equal(postResp.Body, preResp.Body) {
		t.Fatalf("post-resume work differs: status=%d body=%q (pre %q)", postResp.Status, postResp.Body, preResp.Body)
	}

	if err := h.b.DestroySession(ctx, sess.Ref); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
}

// planRef: doc 09 doc 06 (b) seconds-to-start; doc 04 §4. create->attach budget.
func TestLifecycle_CreateToAttach_StartTimeBudget(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	const iterations = 20
	samples := make([]time.Duration, 0, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		sess, err := h.b.CreateSession(ctx, CreateSessionRequest{Posture: PostureStandard, Identity: IdentityRef{ID: "budget"}})
		if err != nil {
			t.Fatalf("CreateSession[%d]: %v", i, err)
		}
		if _, err := h.b.Attach(ctx, sess.Ref); err != nil {
			t.Fatalf("Attach[%d]: %v", i, err)
		}
		samples = append(samples, time.Since(start))
		_ = h.b.DestroySession(ctx, sess.Ref)
	}

	sortDurations(samples)
	p95 := percentile(samples, 95)
	if p95 > StartTimeBudget {
		t.Fatalf("create->attach p95 = %v exceeds budget %v (release blocker)", p95, StartTimeBudget)
	}
}

// planRef: doc 09 NFT-6 Done-when; doc 06 (b) clean-teardown. Byte-identical.
func TestTeardown_NoLeakedNFTRulesOrSets_ByteIdentical(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	bootstrap, err := h.b.Inspect().NFTRuleset(ctx)
	if err != nil {
		t.Fatalf("NFTRuleset(bootstrap): %v", err)
	}
	if len(bootstrap.Bytes) == 0 {
		t.Fatal("bootstrap ruleset is empty; cannot prove byte-identity")
	}

	const N = 5
	var lastSess SessionRef
	for i := 0; i < N; i++ {
		sess := h.newSession(t)
		lastSess = sess.Ref
		if _, err := h.b.Attach(ctx, sess.Ref); err != nil {
			t.Fatalf("Attach[%d]: %v", i, err)
		}
		h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
		h.resolveOK(t, sess.Ref, "github.com")
		if err := h.b.DestroySession(ctx, sess.Ref); err != nil {
			t.Fatalf("DestroySession[%d]: %v", i, err)
		}
	}

	final, err := h.b.Inspect().NFTRuleset(ctx)
	if err != nil {
		t.Fatalf("NFTRuleset(final): %v", err)
	}
	if !bytes.Equal(final.Bytes, bootstrap.Bytes) {
		t.Fatalf("ruleset not byte-identical after %d create->destroy cycles (bootstrap %d bytes, final %d bytes)", N, len(bootstrap.Bytes), len(final.Bytes))
	}

	if set := h.allowSet(t, lastSess); len(set) != 0 {
		t.Fatalf("destroyed session retains %d allow-set entries", len(set))
	}
	if amap := h.admissionMap(t, lastSess); len(amap) != 0 {
		t.Fatalf("destroyed session retains %d admission entries", len(amap))
	}
}

// planRef: doc 09 doc 06 (b) clean-teardown (overlay/identity/proxy session).
func TestTeardown_NoDanglingOverlayIdentityOrProxySession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	sess := h.newSession(t)
	if _, err := h.b.Attach(ctx, sess.Ref); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
	h.resolveOK(t, sess.Ref, "github.com")

	// The minted identity validates while the session is live.
	ident := NewIdentitySeam()
	if _, err := ident.Validate(ctx, sess.Ref, sess.ShortLivedCred); err != nil {
		t.Fatalf("identity should validate while live: %v", err)
	}

	if err := h.b.DestroySession(ctx, sess.Ref); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}

	// Zero residue: admission map empty.
	if amap := h.admissionMap(t, sess.Ref); len(amap) != 0 {
		t.Fatalf("admission map not flushed: %d entries", len(amap))
	}

	// The minted identity no longer validates (it is gone, not merely invalid).
	if _, err := ident.Validate(ctx, sess.Ref, sess.ShortLivedCred); err == nil {
		t.Fatal("minted identity still validates after destroy; expected revocation")
	}

	// No stranded proxy session: a flow attempt on the dead session is denied.
	res, err := h.b.VM(sess.Ref).Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(rotatedAddrA, 443)})
	if err == nil && res.Outcome != OutcomeDropped {
		t.Fatalf("destroyed session still has a live proxy path: %+v", res)
	}
}

// planRef: doc 09 doc 06 (b) state-survives; doc 03 §7 / OQ8. Invisible resume.
func TestResumeInvisible_StateSurvivesRoundTrip(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	sess := h.newSession(t)
	if _, err := h.b.Attach(ctx, sess.Ref); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	h.setUpstreamA(t, "api.anthropic.com", 5*time.Minute, rotatedAddrA)
	_, addrs := h.resolveOK(t, sess.Ref, "api.anthropic.com")

	// In-flight TCP stream open at snapshot time.
	stream, err := h.b.VM(sess.Ref).Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(addrs[0], 443)})
	if err != nil {
		t.Fatalf("Dial(stream): %v", err)
	}
	if stream.Outcome == OutcomeDropped {
		t.Fatalf("stream dial dropped: %+v", stream)
	}

	snap, err := h.b.Snapshot(ctx, sess.Ref)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := h.b.Suspend(ctx, sess.Ref, SuspendReasonOperator); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if err := h.b.Resume(ctx, sess.Ref); err != nil {
		t.Fatalf("Resume: %v", err)
	}

	// State matches pre-suspend: the admission map and allow-set still hold the
	// stream's address (the resume is invisible to the agent).
	if !allowSetContains(h.allowSet(t, sess.Ref), addrs[0]) {
		t.Fatal("allow-set lost the in-flight stream's address across the round trip")
	}
	if e, ok := admissionFor(h.admissionMap(t, sess.Ref), "api.anthropic.com"); !ok || !admissionHasAddr(e, addrs[0]) {
		t.Fatal("admission map state did not survive snapshot->suspend->resume")
	}

	// The in-flight stream's flow record is still open (not severed).
	ev := h.events(t, sess.Ref)
	open := false
	for _, f := range ev.Flows {
		if f.Dst == netip.AddrPortFrom(addrs[0], 443) && f.End.IsZero() {
			open = true
		}
	}
	if !open {
		t.Fatalf("in-flight stream severed across suspend/resume (snapshot %s)", snap.ID)
	}
}

// planRef: doc 09 §1 reachability half; POL-2; Stage 2.
func TestReachabilityHalf_BaselineDomainsFlow_EverythingElseDrops_ZeroConfig(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Zero policy config: the shipped D64 baseline must be active by default.
	sess := h.newSession(t)
	vm := h.b.VM(sess.Ref)

	for _, dom := range BaselineDomains {
		h.setUpstreamA(t, dom, 5*time.Minute, rotatedAddrA)
	}

	for _, dom := range BaselineDomains {
		t.Run("baseline_"+dom, func(t *testing.T) {
			resp, addrs := h.resolveOK(t, sess.Ref, dom)
			if resp.ServedBy != ServedByDNSGate {
				t.Fatalf("ServedBy = %q", resp.ServedBy)
			}
			tls, err := vm.TLSConnect(ctx, TLSConnectRequest{SNI: dom, DstIP: addrs[0]})
			if err != nil {
				t.Fatalf("TLSConnect(%s): %v", dom, err)
			}
			if tls.Outcome == TLSRefused {
				t.Fatalf("baseline domain %s HTTPS refused; want a flow", dom)
			}
		})
	}

	t.Run("control_domain_denied", func(t *testing.T) {
		const control = "not-allowed.example"
		resp, err := vm.ResolveDNS(ctx, DNSQuery{Name: control, Type: DNSTypeA})
		if err != nil {
			t.Fatalf("ResolveDNS: %v", err)
		}
		if resp.Rcode == RcodeNoError && len(resp.Answers) > 0 {
			t.Fatalf("control domain resolved (%d answers); want denied", len(resp.Answers))
		}
		// Denied at L3/4 too: a dial to an arbitrary public addr drops.
		res, err := vm.Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(evilAddr, 443)})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if res.Outcome != OutcomeDropped {
			t.Fatalf("control dial = %q, want Dropped", res.Outcome)
		}
	})
}

// planRef: doc 09 DNS-2 Done-when (registry.npmjs.org CNAME chain). [contract]
func TestReachabilityHalf_CNAMEChainedCDN_TerminalsOnlyAdmitted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sess := h.newSession(t)
	const name = "registry.npmjs.org"
	const intermediate = "npm.map.fastly.net"
	terminal := netip.MustParseAddr("151.101.0.162")

	// Upstream: name -CNAME-> intermediate -A-> terminal, with the terminal
	// carrying the chain-minimum TTL.
	if err := h.dns.SetAnswers(ctx, name, []DNSRecord{
		{Name: name, Type: DNSTypeCNAME, Target: intermediate, TTL: 30 * time.Minute},
		{Name: intermediate, Type: DNSTypeA, Addr: terminal, TTL: 2 * time.Minute},
	}); err != nil {
		t.Fatalf("SetAnswers: %v", err)
	}

	resp, addrs := h.resolveOK(t, sess.Ref, name)
	if len(addrs) != 1 || addrs[0] != terminal {
		t.Fatalf("answered %v, want only terminal [%v]", addrs, terminal)
	}

	// AllowSet holds only the terminal address.
	set := h.allowSet(t, sess.Ref)
	if !allowSetContains(set, terminal) {
		t.Fatal("terminal address not admitted")
	}
	if len(set) != 1 {
		t.Fatalf("allow-set has %d entries, want exactly the terminal", len(set))
	}

	// Admission keyed on the ORIGINAL query name, never the intermediate CDN host.
	if _, ok := admissionFor(h.admissionMap(t, sess.Ref), intermediate); ok {
		t.Fatalf("intermediate CNAME host %q was admitted; only the original name may key the entry", intermediate)
	}
	e, ok := admissionFor(h.admissionMap(t, sess.Ref), name)
	if !ok {
		t.Fatalf("no admission entry keyed on the original query name %q", name)
	}
	if !admissionHasAddr(e, terminal) {
		t.Fatalf("admission entry for %q lacks the terminal address", name)
	}

	// Chain-minimum TTL drives the timeout (clamped): the 2-minute terminal
	// TTL, not the 30-minute CNAME TTL.
	if resp.MinTTL > 2*time.Minute {
		t.Fatalf("answered TTL %v exceeds chain-minimum 2m (chain-min TTL must drive the clamp)", resp.MinTTL)
	}
}

// planRef: doc 09 §1 credentialed half; Stage 3; NFT-3 established-flow rule.
func TestCredentialedHalf_AnthropicAPICall_StreamingSurvivesExpiry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sess := h.newSession(t)
	const name = "api.anthropic.com"

	h.setUpstreamA(t, name, TTLClampMin, rotatedAddrA)
	resp, _ := h.resolveOK(t, sess.Ref, name)

	// A long streaming request that OUTLIVES the allow-set element timeout.
	// The harness advances the clock past expiry mid-stream; the established
	// flow must ride conntrack and complete uninterrupted.
	streamDur := resp.MinTTL + AllowSetGraceMax + 30*time.Second
	if err := h.http.SetResponse(ctx, name, "/v1/messages", 200,
		map[string]string{"X-Stream-Duration": streamDur.String()},
		[]byte("event: complete\n")); err != nil {
		t.Fatalf("SetResponse: %v", err)
	}

	done := make(chan HTTPResponse, 1)
	errc := make(chan error, 1)
	go func() {
		r, err := h.b.VM(sess.Ref).HTTP(ctx, HTTPRequest{
			Method:  "POST",
			Host:    name,
			Path:    "/v1/messages",
			Headers: map[string]string{"Authorization": "Bearer " + string(sess.ShortLivedCred)},
			Body:    []byte(`{"stream":true}`),
		})
		if err != nil {
			errc <- err
			return
		}
		done <- r
	}()

	// Synchronize on stream START before touching the clock: wait until the
	// flow is observably open, so the expiry deterministically lands
	// MID-STREAM (never before the request begins, which would silently
	// degrade this into a post-expiry re-admission scenario).
	streamDst := netip.AddrPortFrom(rotatedAddrA, 443)
	openFlow := func() bool {
		ev := h.events(t, sess.Ref)
		for _, f := range ev.Flows {
			if f.Dst == streamDst && f.Outcome != OutcomeDropped && f.End.IsZero() {
				return true
			}
		}
		return false
	}
	startDeadline := time.Now().Add(30 * time.Second)
	for !openFlow() {
		select {
		case err := <-errc:
			t.Fatalf("streaming request failed before it observably started: %v", err)
		default:
		}
		if time.Now().After(startDeadline) {
			t.Fatal("stream never observably started (no open FlowRecord); cannot exercise mid-stream expiry")
		}
		time.Sleep(time.Millisecond)
	}

	// Expire the allow-set entry while the stream is verifiably in flight:
	// past TTL+grace, but short of the stream's end.
	h.clock.Advance(resp.MinTTL + AllowSetGraceMax + time.Second)
	if allowSetContains(h.allowSet(t, sess.Ref), rotatedAddrA) {
		t.Fatal("allow-set entry survived TTL+grace; the scenario never exercised mid-stream expiry")
	}
	// The SAME flow remains open across the expiry (established rides conntrack).
	if !openFlow() {
		t.Fatal("established streaming flow severed by allow-set expiry (no open FlowRecord after the advance)")
	}

	// Let the stream run to completion.
	h.clock.Advance(streamDur)

	select {
	case err := <-errc:
		t.Fatalf("streaming response severed by allow-set expiry: %v", err)
	case r := <-done:
		if r.Status != 200 {
			t.Fatalf("stream status = %d, want 200 (uninterrupted)", r.Status)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("streaming request did not complete")
	}

	// HttpEvent metadata recorded.
	ev := h.events(t, sess.Ref)
	seen := false
	for _, e := range ev.Http {
		if e.Host == name && e.Path == "/v1/messages" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("no HttpEvent metadata for the streaming call")
	}
}

// planRef: doc 09 §1 credentialed half; TLS-5 + LOG-5; Stage 3.
func TestCredentialedHalf_GitHubPush_NoLongLivedCred_AuditEmitted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.SeedCredential(ctx, "github", Secret(realGitHubToken)); err != nil {
		t.Fatalf("SeedCredential: %v", err)
	}
	sess := h.newSession(t)
	vm := h.b.VM(sess.Ref)

	h.setUpstreamA(t, "api.github.com", 5*time.Minute, rotatedAddrA)

	resp, err := vm.HTTP(ctx, HTTPRequest{
		Method:  "POST",
		Host:    "api.github.com",
		Path:    "/repos/acme/app/git/refs",
		Headers: map[string]string{"Authorization": "Bearer " + string(sess.ShortLivedCred)},
		Body:    []byte(`{"ref":"refs/heads/main"}`),
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		t.Fatalf("push status = %d, want 2xx", resp.Status)
	}

	// The real token never entered the VM, in any encoding.
	for form, needle := range needleForms(realGitHubToken) {
		scan, err := vm.ScanInterior(ctx, InteriorScanRequest{
			Targets: []ScanTarget{ScanDisk, ScanEnv, ScanCoWDelta, ScanResponseBodies},
			Needle:  needle,
		})
		if err != nil {
			t.Fatalf("ScanInterior(%s): %v", form, err)
		}
		if scan.Found {
			t.Fatalf("long-lived credential (%s) found in the VM at %v", form, scan.Locations)
		}
	}

	// LOG-5: a CredentialUseEvent answers who/when/what — value absent.
	ev := h.events(t, sess.Ref)
	var use *CredentialUseEvent
	for i := range ev.Creds {
		if ev.Creds[i].Service == "github" {
			use = &ev.Creds[i]
		}
	}
	if use == nil {
		t.Fatal("no CredentialUseEvent for the GitHub push")
	}
	if use.Session != sess.Ref {
		t.Fatalf("event attributed to %+v, want %+v", use.Session, sess.Ref)
	}
	if use.Fingerprint == "" {
		t.Fatal("CredentialUseEvent missing fingerprint")
	}
	if use.Request == "" || use.At.IsZero() {
		t.Fatalf("CredentialUseEvent incomplete: request=%q at=%v", use.Request, use.At)
	}
	if bytes.Contains([]byte(use.Fingerprint), []byte(realGitHubToken)) {
		t.Fatal("CredentialUseEvent carries the credential value")
	}
}
