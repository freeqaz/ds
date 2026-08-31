package boundary

// §9 guardrail-assurance matrix, rows C9-16..C9-27: re-admission, session
// isolation, credential isolation, pass-through, suspend-on-breach, control
// invisibility, per-session CA scoping, reconciliation, provenance, expiry,
// insert-then-answer, and the inbound secret-scan gate. RED until real.

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"
)

// planRef: doc 09 TLS-1 Done-when (resolve-once client); OQ3; DNS-2b.
func TestResolveOnceClient_SetExpiryMidSession_ReAdmittedNotRefused(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()
	const name = "api.anthropic.com"

	h.setUpstreamA(t, name, TTLClampMin, rotatedAddrA)
	resp, addrs := h.resolveOK(t, sess.Ref, name)
	cached := addrs[0] // the client resolved once and will cache forever

	// Let admission + set entry expire (TTL + max grace), and rotate the CDN.
	h.clock.Advance(resp.MinTTL + AllowSetGraceMax + time.Second)
	h.setUpstreamA(t, name, TTLClampMin, rotatedAddrB)

	if e, ok := admissionFor(h.admissionMap(t, sess.Ref), name); ok && !Now().After(e.Expiry) {
		t.Fatalf("admission for %s still live after TTL+grace: %+v", name, e)
	}

	// Pooled client redials the CACHED original IP without re-resolving.
	res, err := h.b.VM(sess.Ref).TLSConnect(ctx, TLSConnectRequest{SNI: name, DstIP: cached})
	if err != nil {
		t.Fatalf("TLSConnect: %v", err)
	}
	if res.Outcome == TLSRefused {
		t.Fatal("policy-allowed domain with expired admission was Refused; want re-admission (TLS-1 edge rule 3)")
	}
	if !res.UpstreamCertValidated {
		t.Fatal("upstream connection not validated against the hostname")
	}

	// Re-admission went through the DNS-2 path: a fresh entry exists, pointing
	// at the freshly resolved address (CDN rotated to B).
	e, ok := admissionFor(h.admissionMap(t, sess.Ref), name)
	if !ok {
		t.Fatalf("no fresh admission recorded for %s after re-admission", name)
	}
	if !admissionHasAddr(e, rotatedAddrB) {
		t.Fatalf("re-admission used %v, want freshly resolved %v (our resolution, not the client's claim)", e.Addrs, rotatedAddrB)
	}
}

// planRef: doc 09 §9 row "Session A cannot reach session B" (§2 placement + NFT-1). ADVERSARIAL.
func TestSessionIsolation_AtoB_NoL2Path(t *testing.T) {
	h := newHarness(t)
	sessA := h.newSession(t)
	sessB := h.newSession(t)
	ctx := context.Background()

	attachB, err := h.b.Attach(ctx, sessB.Ref)
	if err != nil {
		t.Fatalf("Attach(B): %v", err)
	}
	if !attachB.VMAddr.IsValid() {
		t.Fatal("Attach(B) returned no VM address")
	}

	vmA := h.b.VM(sessA.Ref)
	for _, probe := range []struct {
		name  string
		proto L4Proto
		port  uint16
	}{
		{"tcp_22", ProtoTCP, 22},
		{"tcp_443", ProtoTCP, 443},
		{"tcp_8080", ProtoTCP, 8080},
		{"udp_53", ProtoUDP, 53},
		{"udp_9999", ProtoUDP, 9999},
	} {
		t.Run(probe.name, func(t *testing.T) {
			res, err := vmA.Dial(ctx, DialRequest{Proto: probe.proto, Dst: netip.AddrPortFrom(attachB.VMAddr, probe.port)})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if res.Outcome != OutcomeDropped {
				t.Fatalf("A->B %s = %q, want Dropped (no agent-to-agent path)", probe.name, res.Outcome)
			}
		})
	}

	// No L2 path either: ARP/NDP neighbor discovery from A toward B's
	// address must find nothing (C9-17 "incl. ARP/L2 reach probe").
	for _, kind := range []L2ProbeKind{L2ProbeARP, L2ProbeNDP} {
		t.Run("l2_"+string(kind), func(t *testing.T) {
			res, err := vmA.ProbeL2(ctx, L2ProbeRequest{Kind: kind, Target: attachB.VMAddr})
			if err != nil {
				t.Fatalf("ProbeL2(%s): %v", kind, err)
			}
			if res.Outcome != OutcomeDropped {
				t.Fatalf("A->B %s probe = %q, want Dropped (no agent-to-agent L2 path)", kind, res.Outcome)
			}
			if res.PeerMAC != "" {
				t.Fatalf("A learned B's link-layer address (%s) via %s; no L2 reachability may exist", res.PeerMAC, kind)
			}
		})
	}

	// Ground truth: no flow from A's interface ever shows B's address as a
	// successfully connected destination.
	ev := h.events(t, sessA.Ref)
	for _, f := range ev.Flows {
		if f.Dst.Addr() == attachB.VMAddr && f.Outcome != OutcomeDropped {
			t.Fatalf("flow A->B transited (%+v); only the gateway path may exist", f)
		}
	}
}

// planRef: doc 09 §9 row "Long-lived credential never enters the VM" (TLS-5 Done-when). ADVERSARIAL.
func TestCredentialNeverInVM_DiskEnvCoWResponse(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.SeedCredential(ctx, "github", Secret(realGitHubToken)); err != nil {
		t.Fatalf("SeedCredential: %v", err)
	}
	sess := h.newSession(t)
	vm := h.b.VM(sess.Ref)

	// Perform a credential-swapped GitHub request using the SHORT-LIVED cred.
	resp, err := vm.HTTP(ctx, HTTPRequest{
		Method:  "GET",
		Host:    "api.github.com",
		Path:    "/user",
		Headers: map[string]string{"Authorization": "Bearer " + string(sess.ShortLivedCred)},
	})
	if err != nil {
		t.Fatalf("swapped GitHub request: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("swapped request status = %d, want 200", resp.Status)
	}

	// Canary scan: the real token, in every encoding, on every surface.
	for form, needle := range needleForms(realGitHubToken) {
		t.Run("needle_"+form, func(t *testing.T) {
			scan, err := vm.ScanInterior(ctx, InteriorScanRequest{
				Targets: []ScanTarget{ScanDisk, ScanEnv, ScanCoWDelta, ScanResponseBodies},
				Needle:  needle,
			})
			if err != nil {
				t.Fatalf("ScanInterior: %v", err)
			}
			if scan.Found {
				t.Fatalf("long-lived credential (%s form) found inside the VM at %v", form, scan.Locations)
			}
		})
	}

	// The short-lived cred IS present (it is the one the agent holds).
	scan, err := vm.ScanInterior(ctx, InteriorScanRequest{
		Targets: []ScanTarget{ScanDisk, ScanEnv},
		Needle:  []byte(sess.ShortLivedCred),
	})
	if err != nil {
		t.Fatalf("ScanInterior(short-lived): %v", err)
	}
	if !scan.Found {
		t.Fatal("short-lived credential not present in the VM; the swap seam is miswired")
	}

	// Audit: a CredentialUseEvent with a fingerprint, never the value.
	ev := h.events(t, sess.Ref)
	if len(ev.Creds) == 0 {
		t.Fatal("no CredentialUseEvent recorded for the swapped request")
	}
	for _, c := range ev.Creds {
		if c.Fingerprint == "" {
			t.Fatalf("CredentialUseEvent missing fingerprint: %+v", c)
		}
		for form, needle := range needleForms(realGitHubToken) {
			if bytes.Contains([]byte(c.Fingerprint+c.Request+c.Service), needle) {
				t.Fatalf("CredentialUseEvent carries the credential value (%s form)", form)
			}
		}
	}
}

// planRef: doc 09 §9 row "Pinned pass-through opaque, no swap; all else inspected" (TLS-4). ADVERSARIAL.
func TestPinnedPassThrough_OpaqueNoSwap_OffListInspected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const pinned = "pinned.example"
	const plain = "github.com"

	// Policy: pinned.example on the pass-through list, both domains allowed.
	if _, err := h.b.Policy().Load(ctx, PolicySnapshot{Layers: []PolicyLayer{{
		Name:        "system",
		Allow:       append([]string{pinned}, BaselineDomains...),
		PassThrough: []string{pinned},
	}}}); err != nil {
		t.Fatalf("Policy.Load: %v", err)
	}
	sess := h.newSession(t)
	vm := h.b.VM(sess.Ref)

	h.setUpstreamA(t, pinned, 5*time.Minute, rotatedAddrA)
	h.setUpstreamA(t, plain, 5*time.Minute, rotatedAddrB)
	_, pinnedAddrs := h.resolveOK(t, sess.Ref, pinned)
	_, plainAddrs := h.resolveOK(t, sess.Ref, plain)

	t.Run("pinned_tunneled_opaque", func(t *testing.T) {
		res, err := vm.TLSConnect(ctx, TLSConnectRequest{SNI: pinned, DstIP: pinnedAddrs[0]})
		if err != nil {
			t.Fatalf("TLSConnect: %v", err)
		}
		if res.Outcome != TLSTunneled {
			t.Fatalf("pinned outcome = %q, want Tunneled", res.Outcome)
		}
		if res.LeafCAIssuer != "" {
			t.Fatalf("pinned tunnel presented an interception leaf (issuer %q); must be opaque", res.LeafCAIssuer)
		}
		ev := h.events(t, sess.Ref)
		for _, c := range ev.Creds {
			if c.Service == pinned {
				t.Fatalf("credential swap performed on a pass-through flow: %+v", c)
			}
		}
		// Still SNI/allow-set enforced + netflow-accounted.
		accounted := false
		for _, f := range ev.Flows {
			if f.Dst.Addr() == pinnedAddrs[0] && f.AdmittingDomain == pinned {
				accounted = true
			}
		}
		if !accounted {
			t.Fatal("pass-through flow not netflow-accounted with its admitting domain")
		}
	})

	t.Run("pinned_still_sni_enforced", func(t *testing.T) {
		res, err := vm.TLSConnect(ctx, TLSConnectRequest{SNI: "evil-notadmitted.example", DstIP: pinnedAddrs[0]})
		if err != nil {
			t.Fatalf("TLSConnect: %v", err)
		}
		if res.Outcome != TLSRefused {
			t.Fatalf("non-admitted SNI at pinned IP = %q, want Refused", res.Outcome)
		}
	})

	t.Run("off_list_inspected", func(t *testing.T) {
		res, err := vm.TLSConnect(ctx, TLSConnectRequest{SNI: plain, DstIP: plainAddrs[0]})
		if err != nil {
			t.Fatalf("TLSConnect: %v", err)
		}
		if res.Outcome != TLSInspected {
			t.Fatalf("off-list outcome = %q, want Inspected", res.Outcome)
		}
		if res.LeafCAIssuer != sess.InterceptCA.ID {
			t.Fatalf("inspected leaf chains to %q, want this session's CA %q", res.LeafCAIssuer, sess.InterceptCA.ID)
		}
		// HTTP metadata appears for inspected flows.
		if _, err := vm.HTTP(ctx, HTTPRequest{Method: "GET", Host: plain, Path: "/"}); err != nil {
			t.Fatalf("HTTP via inspected path: %v", err)
		}
		ev := h.events(t, sess.Ref)
		seen := false
		for _, e := range ev.Http {
			if e.Host == plain && e.Method == "GET" {
				seen = true
			}
		}
		if !seen {
			t.Fatal("no HttpEvent metadata for the inspected flow")
		}
	})
}

// planRef: doc 09 §9 row "Suspend-on-breach fires; resume invisible" (TLS-6).
func TestSuspendOnBreach_FiresAndResumeInvisible(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const capLimit = 3

	if _, err := h.b.Policy().Load(ctx, PolicySnapshot{Layers: []PolicyLayer{{
		Name:  "system",
		Allow: BaselineDomains,
		Caps:  map[string]int{"api.github.com": capLimit},
	}}}); err != nil {
		t.Fatalf("Policy.Load: %v", err)
	}
	sess := h.newSession(t)
	vm := h.b.VM(sess.Ref)

	// Drive requests past the cap; the breaching request is the in-flight one.
	type result struct {
		resp HTTPResponse
		err  error
	}
	results := make(chan result, capLimit+1)
	for i := 0; i <= capLimit; i++ {
		go func() {
			resp, err := vm.HTTP(ctx, HTTPRequest{Method: "GET", Host: "api.github.com", Path: "/rate-limited"})
			results <- result{resp, err}
		}()
	}

	// The breach must emit exactly the documented one-way suspend signal.
	deadline := time.After(2 * time.Second)
	var sig *SuspendSignal
	for sig == nil {
		select {
		case <-deadline:
			t.Fatal("no SuspendSignal observed after cap breach")
		default:
		}
		sigs, err := h.b.Orchestrator().SuspendSignals(ctx)
		if err != nil {
			t.Fatalf("SuspendSignals: %v", err)
		}
		for i := range sigs {
			if sigs[i].Session == sess.Ref {
				sig = &sigs[i]
			}
		}
	}
	if sig.Reason != SuspendReasonCapBreach {
		t.Fatalf("suspend reason = %q, want %q", sig.Reason, SuspendReasonCapBreach)
	}
	if sig.At.IsZero() {
		t.Fatal("suspend signal carries no timestamp")
	}

	// The VM is ACTUALLY paused, not merely signalled: no in-flight request
	// may have completed while suspended (a signal-only impl that lets
	// traffic continue past the cap must fail here).
	select {
	case r := <-results:
		t.Fatalf("request completed while suspended (the containment action is unenforced): %+v", r)
	default:
	}

	// Ground truth: no flow/HTTP event for the capped resource completed
	// between the SuspendSignal timestamp and Resume.
	paused := h.events(t, sess.Ref)
	for _, e := range paused.Http {
		if e.Host == "api.github.com" && e.Status != 0 && !e.At.Before(sig.At) {
			t.Fatalf("HttpEvent for the capped resource completed during the suspension: %+v", e)
		}
	}
	for _, f := range paused.Flows {
		if f.AdmittingDomain == "api.github.com" && !f.End.IsZero() && !f.End.Before(sig.At) {
			t.Fatalf("flow for the capped resource completed during the suspension: %+v", f)
		}
	}

	// Resume: the in-flight actions complete with no agent-visible gap.
	if err := h.b.Resume(ctx, sess.Ref); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	for i := 0; i <= capLimit; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("in-flight request observed the suspension: %v", r.err)
		}
		if r.resp.Status != 200 {
			t.Fatalf("in-flight request status = %d after resume, want 200 (invisible resume)", r.resp.Status)
		}
	}
}

// planRef: doc 09 §9 row "Controls unobservable/unmodifiable from inside the VM"
// (NFT-1 + §2 placement). ADVERSARIAL.
func TestControlsUnobservable_FromInsideVM(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()
	vm := h.b.VM(sess.Ref)

	scan, err := vm.ScanInterior(ctx, InteriorScanRequest{Targets: []ScanTarget{ScanControls}})
	if err != nil {
		t.Fatalf("ScanInterior(Controls): %v", err)
	}
	if scan.Found {
		t.Fatalf("control artifacts observable from inside the VM: %v", scan.Locations)
	}

	// Admit one address first so the set is non-empty: a same-cardinality
	// mutation (entry replacement) cannot hide behind a length comparison.
	h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
	h.resolveOK(t, sess.Ref, "github.com")
	before := h.allowSet(t, sess.Ref)
	if len(before) == 0 {
		t.Fatal("no admitted entry before the mutation attempts; the no-mutation check needs a non-empty set")
	}

	// Reach/modify attempts at the boundary's own control surfaces (the
	// documented vectors for writing the firewall sets from inside).
	for _, port := range []uint16{22, 53, 80, 443, 8080, 9090} {
		res, err := vm.Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(hostGatewayAddr, port)})
		if err != nil {
			t.Fatalf("Dial(gateway:%d): %v", port, err)
		}
		// Port 53 may be redirected into the gate; everything else must drop,
		// and nothing may Connect to the host itself.
		if res.Outcome == OutcomeConnected {
			t.Fatalf("VM connected to the boundary host on port %d", port)
		}
		if port != 53 && res.Outcome != OutcomeDropped {
			t.Fatalf("gateway:%d = %q, want Dropped", port, res.Outcome)
		}
	}

	// No allow-set mutation possible from inside: compare full set CONTENTS
	// (addrs + expiries), not lengths.
	after := h.allowSet(t, sess.Ref)
	asMap := func(entries []AllowSetEntry) map[netip.Addr]time.Time {
		m := make(map[netip.Addr]time.Time, len(entries))
		for _, e := range entries {
			m[e.Addr] = e.Expiry
		}
		return m
	}
	beforeM, afterM := asMap(before), asMap(after)
	if len(afterM) != len(beforeM) {
		t.Fatalf("allow-set mutated by in-VM activity: %d -> %d entries", len(beforeM), len(afterM))
	}
	for addr, exp := range beforeM {
		got, ok := afterM[addr]
		if !ok {
			t.Fatalf("allow-set entry %v removed by in-VM activity", addr)
		}
		if !got.Equal(exp) {
			t.Fatalf("allow-set entry %v expiry mutated by in-VM activity: %v -> %v", addr, exp, got)
		}
	}
}

// planRef: doc 09 TLS-3 Done-when (per-session CA scoping). ADVERSARIAL.
func TestPerSessionCA_SessionAUselessAgainstB(t *testing.T) {
	h := newHarness(t)
	sessA := h.newSession(t)
	sessB := h.newSession(t)
	ctx := context.Background()
	mint := NewCAMintSeam()

	caA, err := mint.MintSessionCA(ctx, sessA.Ref)
	if err != nil {
		t.Fatalf("MintSessionCA(A): %v", err)
	}
	caB, err := mint.MintSessionCA(ctx, sessB.Ref)
	if err != nil {
		t.Fatalf("MintSessionCA(B): %v", err)
	}
	if caA.ID == "" || caA.ID == caB.ID {
		t.Fatalf("session CAs not distinct: A=%q B=%q", caA.ID, caB.ID)
	}

	h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
	_, addrs := h.resolveOK(t, sessB.Ref, "github.com")

	// The adversarial premise, made real: install A's CA as TRUSTED inside
	// B's VM (the VM may trust anything; the boundary must not care).
	if err := h.b.VM(sessB.Ref).InstallTrustedCA(ctx, caA); err != nil {
		t.Fatalf("InstallTrustedCA(A's CA inside B's VM): %v", err)
	}

	// B's inspected flow: even with A's CA trusted inside B, the leaf B
	// observes chains to B's CA only.
	res, err := h.b.VM(sessB.Ref).TLSConnect(ctx, TLSConnectRequest{SNI: "github.com", DstIP: addrs[0]})
	if err != nil {
		t.Fatalf("TLSConnect(B): %v", err)
	}
	if res.Outcome != TLSInspected {
		t.Fatalf("B's flow = %q, want Inspected", res.Outcome)
	}
	if res.LeafCAIssuer != caB.ID && res.LeafCAIssuer != sessB.InterceptCA.ID {
		t.Fatalf("B's leaf chains to %q, want B's own CA", res.LeafCAIssuer)
	}
	if res.LeafCAIssuer == caA.ID {
		t.Fatal("cross-session interception: B's leaf chains to A's CA")
	}

	// A's CA cannot issue for B: LeafFor under A's CA must not yield a cert
	// that names B's session.
	leaf, err := mint.LeafFor(ctx, caA, "github.com")
	if err != nil {
		t.Fatalf("LeafFor(A): %v", err)
	}
	if leaf.IssuerCA.Session == sessB.Ref {
		t.Fatal("A's CA minted a leaf scoped to session B")
	}
	if leaf.IssuerCA.ID != caA.ID {
		t.Fatalf("leaf issuer = %q, want A's CA %q", leaf.IssuerCA.ID, caA.ID)
	}
}

// planRef: doc 09 LOG-4 Done-when; §9 self-audit. ADVERSARIAL.
func TestReconciliation_MisruledHost_TripsAlarm(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()

	// Clean host first: everything explained, no alarm.
	clean, err := h.b.Inspect().Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile(clean): %v", err)
	}
	if clean.Alarm {
		t.Fatalf("clean host raised the reconciliation alarm: %+v", clean.UnexplainedFlows)
	}

	// Deliberately mis-rule the host so a flow bypasses the redirect.
	undo, err := h.fault.BypassRedirect(ctx, sess.Ref)
	if err != nil {
		t.Fatalf("FaultInjector.BypassRedirect: %v", err)
	}
	defer func() { _ = undo() }()

	h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
	_, addrs := h.resolveOK(t, sess.Ref, "github.com")
	if _, err := h.b.VM(sess.Ref).Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(addrs[0], 443)}); err != nil {
		t.Fatalf("Dial through the hole: %v", err)
	}

	rep, err := h.b.Inspect().Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile(misruled): %v", err)
	}
	if !rep.Alarm {
		t.Fatal("mis-ruled host did NOT trip the alarm: a flow bypassed the redirect unexplained")
	}
	if len(rep.UnexplainedFlows) == 0 {
		t.Fatal("alarm raised but the unexplained flow is not listed")
	}
	found := false
	for _, f := range rep.UnexplainedFlows {
		if f.Session == sess.Ref || f.Iface == sess.Ref.Iface {
			found = true
		}
	}
	if !found {
		t.Fatalf("unexplained flows not attributed to the bypassing session: %+v", rep.UnexplainedFlows)
	}
}

// planRef: doc 09 POL-3 Done-when (provenance on every decision). [contract]
func TestProvenance_EveryEventCarriesRuleLayerVersion(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.b.Policy().Load(ctx, PolicySnapshot{Layers: []PolicyLayer{{
		Name:        "system",
		Allow:       BaselineDomains,
		Block:       BaselineBlockedResolvers,
		AskUser:     []string{"ask-me.example"},
		PassThrough: []string{"pinned.example"},
		Caps:        map[string]int{"api.github.com": 2},
	}}}); err != nil {
		t.Fatalf("Policy.Load: %v", err)
	}
	sess := h.newSession(t)
	vm := h.b.VM(sess.Ref)

	// Drive the (a) suite of decision kinds: allow / deny / ask / swap /
	// pass-through / cap.
	h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
	_, _ = vm.ResolveDNS(ctx, DNSQuery{Name: "github.com", Type: DNSTypeA})                                                                                                  // allow
	_, _ = vm.ResolveDNS(ctx, DNSQuery{Name: "dns.google", Type: DNSTypeA})                                                                                                  // deny (blocklist)
	_, _ = vm.ResolveDNS(ctx, DNSQuery{Name: "ask-me.example", Type: DNSTypeA})                                                                                              // ask
	_, _ = vm.HTTP(ctx, HTTPRequest{Method: "GET", Host: "api.github.com", Path: "/", Headers: map[string]string{"Authorization": "Bearer " + string(sess.ShortLivedCred)}}) // swap
	_, _ = vm.TLSConnect(ctx, TLSConnectRequest{SNI: "pinned.example", DstIP: rotatedAddrA})                                                                                 // pass-through
	for i := 0; i < 3; i++ {                                                                                                                                                 // cap breach
		_, _ = vm.HTTP(ctx, HTTPRequest{Method: "GET", Host: "api.github.com", Path: "/capped"})
	}

	ev := h.events(t, sess.Ref)
	if len(ev.Decisions) < 6 {
		t.Fatalf("expected >=6 PolicyDecisions for the driven flows, got %d", len(ev.Decisions))
	}
	kinds := map[string]bool{}
	for i, d := range ev.Decisions {
		if d.Rule.RuleID == "" || d.Rule.Layer == "" || d.Rule.PolicyVersion == "" {
			t.Fatalf("decision[%d] (%s %s) missing provenance: %+v — a missing-provenance event fails CI", i, d.Decision, d.Resource, d.Rule)
		}
		kinds[d.Decision] = true
	}
	// ALL six driven decision kinds must surface with provenance — an impl
	// that performs swaps / pass-throughs / cap breaches without emitting a
	// provenance-carrying decision event fails here.
	for _, want := range []string{"allow", "deny", "ask", "swap", "pass-through", "cap"} {
		if !kinds[want] {
			t.Fatalf("no %q decision recorded; decision kinds seen: %v", want, kinds)
		}
	}
}

// planRef: doc 09 NFT-3 Done-when (expiry semantics).
func TestAllowSet_EntryExpires_NewDroppedEstablishedSurvives_ReResolveRestores(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()
	const name = "github.com"
	vm := h.b.VM(sess.Ref)

	h.setUpstreamA(t, name, TTLClampMin, rotatedAddrA)
	resp, addrs := h.resolveOK(t, sess.Ref, name)
	admitted := addrs[0]

	// Open a long-lived stream (established before expiry).
	stream, err := vm.Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(admitted, 443)})
	if err != nil {
		t.Fatalf("Dial(stream): %v", err)
	}
	if stream.Outcome == OutcomeDropped {
		t.Fatalf("pre-expiry dial dropped: %+v", stream)
	}

	// Expire the entry (TTL + grace).
	h.clock.Advance(resp.MinTTL + AllowSetGraceMax + time.Second)
	if allowSetContains(h.allowSet(t, sess.Ref), admitted) {
		t.Fatalf("allow-set entry for %v not reaped after TTL+grace", admitted)
	}

	// New flow to the expired address drops.
	fresh, err := vm.Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(admitted, 443)})
	if err != nil {
		t.Fatalf("Dial(post-expiry): %v", err)
	}
	if fresh.Outcome != OutcomeDropped {
		t.Fatalf("new flow to expired address = %q, want Dropped (ct state new gated)", fresh.Outcome)
	}

	// The established stream survives: its flow record is still open.
	ev := h.events(t, sess.Ref)
	open := false
	for _, f := range ev.Flows {
		if f.Dst == netip.AddrPortFrom(admitted, 443) && f.Outcome != OutcomeDropped && f.End.IsZero() {
			open = true
		}
	}
	if !open {
		t.Fatal("established stream severed by allow-set expiry (no open flow record)")
	}

	// Re-resolution restores exactly that address, set otherwise unchanged.
	_, addrs2 := h.resolveOK(t, sess.Ref, name)
	if len(addrs2) != 1 || addrs2[0] != admitted {
		t.Fatalf("re-resolution answered %v, want [%v]", addrs2, admitted)
	}
	set := h.allowSet(t, sess.Ref)
	if !allowSetContains(set, admitted) {
		t.Fatal("re-resolution did not restore the address")
	}
	if len(set) != 1 {
		t.Fatalf("re-resolution widened the set: %d entries, want 1", len(set))
	}
}

// planRef: doc 09 DNS-2 Done-when; DNS-2b (insert-then-answer). ADVERSARIAL.
func TestAdmission_InsertThenAnswer_NoWindow(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()
	const name = "registry.npmjs.org"

	h.setUpstreamA(t, name, 5*time.Minute, rotatedAddrA)
	_, addrs := h.resolveOK(t, sess.Ref, name)

	// After the answer: the address must be in both the allow-set and the
	// admission map (necessary, but not sufficient — see the trace below).
	set := h.allowSet(t, sess.Ref)
	amap := h.admissionMap(t, sess.Ref)
	for _, a := range addrs {
		if !allowSetContains(set, a) {
			t.Fatalf("window: VM holds %v but the allow-set lacks it (answer preceded insert)", a)
		}
		e, ok := admissionFor(amap, name)
		if !ok || !admissionHasAddr(e, a) {
			t.Fatalf("window: VM holds %v but the admission map lacks (%s -> %v)", a, name, a)
		}
		if !e.Expiry.After(Now()) {
			t.Fatalf("admission for %v already expired at answer time", a)
		}
	}

	// The ordering itself, against ground truth — not wall-clock luck: the
	// ordered admission trace must show, for every answered address, the
	// kernel/admission insert sequenced strictly BEFORE the answer was
	// published to the VM. An answer-then-insert impl whose insert lands
	// microseconds later fails here.
	trace, err := h.b.Inspect().AdmissionTrace(ctx, sess.Ref)
	if err != nil {
		t.Fatalf("AdmissionTrace: %v", err)
	}
	for _, a := range addrs {
		var insertSeq, answerSeq uint64
		var haveInsert, haveAnswer bool
		for _, te := range trace {
			if te.Domain != name || te.Addr != a {
				continue
			}
			switch te.Kind {
			case TraceInsert:
				if !haveInsert {
					insertSeq, haveInsert = te.Seq, true
				}
			case TraceAnswer:
				if !haveAnswer {
					answerSeq, haveAnswer = te.Seq, true
				}
			}
		}
		if !haveInsert {
			t.Fatalf("no insert trace event for (%s -> %v); the admission pipeline is unaccounted", name, a)
		}
		if !haveAnswer {
			t.Fatalf("no answer trace event for (%s -> %v); the publish step is unaccounted", name, a)
		}
		if insertSeq >= answerSeq {
			t.Fatalf("window: answer published (seq %d) before insert (seq %d) for %v — VM held an IP the firewall lacked", answerSeq, insertSeq, a)
		}
	}

	// And the dial that immediately follows the answer must not race a hole.
	res, err := h.b.VM(sess.Ref).Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(addrs[0], 443)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if res.Outcome == OutcomeDropped {
		t.Fatal("first-connection race: dial immediately after the answer was dropped")
	}
}

// planRef: doc 09 TLS-7 Done-when (inbound secret-scanning gate).
func TestSecretScanInbound_SeededTokenDetected_HookFires(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()

	var fired []SecretScanEvent
	SetSecretScanHook(func(e SecretScanEvent) { fired = append(fired, e) })
	t.Cleanup(func() { SetSecretScanHook(nil) })

	// Upstream serves an inspected response carrying a seeded long-lived token.
	const seeded = "ghp_SeededInboundLongLived7tokenJq2Xw9PzR4mY"
	if err := h.http.SetResponse(ctx, "raw.githubusercontent.com", "/leak.txt", 200, nil,
		[]byte("config:\n  token: "+seeded+"\n")); err != nil {
		t.Fatalf("SetResponse: %v", err)
	}

	resp, err := h.b.VM(sess.Ref).HTTP(ctx, HTTPRequest{Method: "GET", Host: "raw.githubusercontent.com", Path: "/leak.txt"})
	if err != nil {
		t.Fatalf("HTTP: %v", err)
	}
	_ = resp // response disposition (block vs deliver) is OQ8; the gate is the deliverable.

	if len(fired) == 0 {
		t.Fatal("seeded long-lived token entered the VM on the inspected path and the hook did not fire")
	}
	ev := fired[0]
	if ev.Session != sess.Ref {
		t.Fatalf("detection attributed to %+v, want %+v", ev.Session, sess.Ref)
	}
	if ev.Fingerprint == "" {
		t.Fatal("detection event missing fingerprint")
	}
	if bytes.Contains([]byte(ev.Fingerprint), []byte(seeded)) {
		t.Fatal("detection event carries the token value")
	}
}
