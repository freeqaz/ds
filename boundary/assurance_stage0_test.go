package boundary

// Stage-0 contract seams (S0-*): the frozen seams neighbor workstreams code
// against — contract-parity (real vs fake), the one-way ask-user seam,
// approval-as-grant, REFUSED denial semantics, the LOG-1 schema freeze,
// identity-validation, CA-mint, suspend-signal, and layered policy compose.
// All RED until either the real impl or the fake is wired.

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// planRef: doc 09 doc 06 §2 contract-twice; Stage 0. [contract]
func TestContractParity_BoundaryRealVsFake(t *testing.T) {
	t.Run("real", func(t *testing.T) { RunBoundaryContract(t, NewRealBoundary) })
	t.Run("fake", func(t *testing.T) { RunBoundaryContract(t, NewFakeBoundary) })
}

// planRef: doc 09 Stage 0 ask-user seam. [contract]
func TestAskUserSeam_OneWayNotification_NoDecisionReturn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sess := h.newSession(t)

	// Pin the one-way SHAPE: Notify returns exactly one value, of type error.
	mt, ok := reflect.TypeOf((*AskUserSeam)(nil)).Elem().MethodByName("Notify")
	if !ok {
		t.Fatal("AskUserSeam has no Notify method")
	}
	if n := mt.Type.NumOut(); n != 1 {
		t.Fatalf("Notify returns %d values, want 1 (one-way: error only, no decision)", n)
	}
	if got := mt.Type.Out(0); got != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("Notify return type = %v, want error (no synchronous approval path may exist)", got)
	}

	// Trigger an ask-posture flow.
	if _, err := h.b.Policy().Load(ctx, PolicySnapshot{Layers: []PolicyLayer{{
		Name: "system", Allow: BaselineDomains, AskUser: []string{"ask-me.example"},
	}}}); err != nil {
		t.Fatalf("Policy.Load: %v", err)
	}
	if _, err := h.b.VM(sess.Ref).ResolveDNS(ctx, DNSQuery{Name: "ask-me.example", Type: DNSTypeA}); err != nil {
		t.Fatalf("ResolveDNS(ask): %v", err)
	}

	reqs, err := h.b.Orchestrator().AskUserRequests(ctx)
	if err != nil {
		t.Fatalf("AskUserRequests: %v", err)
	}
	var found *AskUserRequest
	for i := range reqs {
		if reqs[i].Name == "ask-me.example" && reqs[i].Session == sess.Ref {
			found = &reqs[i]
		}
	}
	if found == nil {
		t.Fatal("no AskUserRequest recorded for the ask-posture name")
	}
	if found.Kind != ResourceDomain {
		t.Fatalf("Kind = %q, want Domain", found.Kind)
	}
	requireProvenance(t, found.MatchedRule, "AskUserRequest matched rule")
}

// planRef: doc 09 Stage 0; DNS-3; POL-5. [contract]
func TestAskUser_ApprovalAsPolicyGrant_PostApprovalRetrySucceeds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const name = "ask-me.example"

	// No separate approval-response API may exist on the orchestrator seam:
	// approvals must come back via PolicyControl.Grant. Assert the seam carries
	// no synchronous decision-returning method.
	ot := reflect.TypeOf((*OrchestratorFake)(nil)).Elem()
	for i := 0; i < ot.NumMethod(); i++ {
		m := ot.Method(i)
		// Approve returns a PolicyVersion (a grant handle), never a Decision.
		if m.Name == "Approve" {
			continue
		}
		for j := 0; j < m.Type.NumOut(); j++ {
			if m.Type.Out(j).Name() == "Decision" {
				t.Fatalf("orchestrator method %s returns a Decision; approvals must be policy grants only", m.Name)
			}
		}
	}

	if _, err := h.b.Policy().Load(ctx, PolicySnapshot{Layers: []PolicyLayer{{
		Name: "system", Allow: BaselineDomains, AskUser: []string{name},
	}}}); err != nil {
		t.Fatalf("Policy.Load: %v", err)
	}
	h.setUpstreamA(t, name, TTLClampMin, rotatedAddrA)
	sess := h.newSession(t)

	// Ask-posture resolve triggers the notification (REFUSED for now).
	first, err := h.b.VM(sess.Ref).ResolveDNS(ctx, DNSQuery{Name: name, Type: DNSTypeA})
	if err != nil {
		t.Fatalf("ResolveDNS(pre-approval): %v", err)
	}
	if first.Rcode != RcodeRefused {
		t.Fatalf("pre-approval rcode = %s, want REFUSED", first.Rcode)
	}

	reqs, err := h.b.Orchestrator().AskUserRequests(ctx)
	if err != nil || len(reqs) == 0 {
		t.Fatalf("AskUserRequests: %v (got %d)", err, len(reqs))
	}
	var req *AskUserRequest
	for i := range reqs {
		if reqs[i].Name == name && reqs[i].Session == sess.Ref {
			req = &reqs[i]
		}
	}
	// Fail fast: never approve a zero-valued request on a missed match.
	if req == nil {
		t.Fatalf("no AskUserRequest recorded for %q under session %+v", name, sess.Ref)
	}

	// Approve with a TTL: the grant lands on the policy stream.
	const ttl = 10 * time.Minute
	ver, err := h.b.Orchestrator().Approve(ctx, *req, ttl)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if ver == "" {
		t.Fatal("Approve did not produce a policy version (grant must land on the stream)")
	}
	if active, err := h.b.Policy().Active(ctx); err != nil || active != ver {
		t.Fatalf("active policy = %q (err %v), want the granted version %q", active, err, ver)
	}

	// First post-approval retry succeeds.
	retry, addrs := h.resolveOK(t, sess.Ref, name)
	if retry.Rcode != RcodeNoError || len(addrs) == 0 {
		t.Fatalf("post-approval retry rcode = %s answers=%d, want NOERROR", retry.Rcode, len(addrs))
	}

	// The grant is SESSION-SCOPED (S0-3): a second session must still get
	// REFUSED while the approving session's grant is live — a fleet-wide
	// grant fails here.
	other := h.newSession(t)
	otherResp, err := h.b.VM(other.Ref).ResolveDNS(ctx, DNSQuery{Name: name, Type: DNSTypeA})
	if err != nil {
		t.Fatalf("ResolveDNS(other session): %v", err)
	}
	if otherResp.Rcode != RcodeRefused || len(otherResp.Answers) > 0 {
		t.Fatalf("approval leaked beyond the approving session: other session got rcode=%s answers=%d, want REFUSED (session-scoped grant)",
			otherResp.Rcode, len(otherResp.Answers))
	}

	// And the grant expires at TTL.
	h.clock.Advance(ttl + time.Second)
	expired, err := h.b.VM(sess.Ref).ResolveDNS(ctx, DNSQuery{Name: name, Type: DNSTypeA})
	if err != nil {
		t.Fatalf("ResolveDNS(post-TTL): %v", err)
	}
	if expired.Rcode == RcodeNoError && len(expired.Answers) > 0 {
		t.Fatal("grant did not expire at TTL; name still resolves after the grant window")
	}
}

// planRef: doc 09 DNS-3 Done-when; OQ6. ADVERSARIAL.
func TestAskUser_DenyIsREFUSED_NotCacheableSignal(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const name = "ask-me.example"

	if _, err := h.b.Policy().Load(ctx, PolicySnapshot{Layers: []PolicyLayer{{
		Name: "system", Allow: BaselineDomains, AskUser: []string{name},
	}}}); err != nil {
		t.Fatalf("Policy.Load: %v", err)
	}
	sess := h.newSession(t)

	resp, err := h.b.VM(sess.Ref).ResolveDNS(ctx, DNSQuery{Name: name, Type: DNSTypeA})
	if err != nil {
		t.Fatalf("ResolveDNS: %v", err)
	}
	if resp.Rcode != RcodeRefused {
		t.Fatalf("ask-posture rcode = %s, want REFUSED (never NXDOMAIN/SERVFAIL — those negatively cache)", resp.Rcode)
	}
	if resp.Rcode == RcodeNXDomain || resp.Rcode == RcodeServFail {
		t.Fatalf("got cacheable negative signal %s", resp.Rcode)
	}
	// A REFUSED answer must carry no cacheable TTL.
	if resp.MinTTL != 0 {
		t.Fatalf("REFUSED answer carries MinTTL %v, want 0 (no cacheable negative answer)", resp.MinTTL)
	}
}

// planRef: doc 09 LOG-1 Done-when; Stage 0 freeze. [contract]
func TestFlowLogSchema_LOG1Frozen_BufGreen(t *testing.T) {
	sess := SessionRef{ID: "s1", Iface: IfacePrefix + "s1"}
	at := time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)

	// All five LOG-1 messages must exist, share a SessionRef, and be
	// metadata-only (no packet-capture fields). Constructing them pins the
	// frozen shape; the buf gate fixture asserts lint+breaking green.
	flow := FlowRecord{Session: sess, Iface: sess.Iface, AdmittingDomain: "github.com",
		Dst: netip.MustParseAddrPort("203.0.113.10:443"), Proto: ProtoTCP, BytesIn: 1, BytesOut: 2, Start: at, End: at}
	dns := DnsEvent{Session: sess, Query: "github.com", Type: DNSTypeA, Rcode: RcodeNoError, At: at}
	http := HttpEvent{Session: sess, Method: "GET", Host: "github.com", Path: "/", Status: 200, At: at}
	dec := PolicyDecision{Session: sess, Decision: "allow", Resource: "github.com",
		Rule: RuleRef{RuleID: "r1", Layer: "system", PolicyVersion: "v1"}, At: at}
	cred := CredentialUseEvent{Session: sess, Service: "github", Fingerprint: "fp", Request: "POST /x", At: at}

	for _, msg := range []struct {
		name string
		s    SessionRef
	}{
		{"FlowRecord", flow.Session},
		{"DnsEvent", dns.Session},
		{"HttpEvent", http.Session},
		{"PolicyDecision", dec.Session},
		{"CredentialUseEvent", cred.Session},
	} {
		if msg.s != sess {
			t.Fatalf("%s does not share the common SessionRef", msg.name)
		}
	}

	// Metadata-only invariant, structurally: every field of every LOG-1
	// message is pinned by an explicit per-message allowlist (any extra,
	// missing, or reordered field breaks the freeze), and no field may be a
	// raw-bytes type — so a payload field named Body/Data/Content/Bytes
	// cannot slip past a name blocklist.
	frozenFields := map[string][]string{
		"FlowRecord":         {"Session", "Iface", "AdmittingDomain", "Dst", "Proto", "Outcome", "CtMark", "BytesIn", "BytesOut", "Start", "End"},
		"DnsEvent":           {"Session", "Query", "Type", "Rcode", "Kind", "Admitted", "Scrubbed", "Rule", "At"},
		"HttpEvent":          {"Session", "Method", "Host", "Path", "Status", "Blocked", "Rule", "At"},
		"PolicyDecision":     {"Session", "Decision", "Resource", "Rule", "At"},
		"CredentialUseEvent": {"Session", "Service", "Fingerprint", "Request", "At"},
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(flow), reflect.TypeOf(dns), reflect.TypeOf(http), reflect.TypeOf(dec), reflect.TypeOf(cred),
	} {
		want, ok := frozenFields[typ.Name()]
		if !ok {
			t.Fatalf("no frozen field allowlist for %s", typ.Name())
		}
		if typ.NumField() != len(want) {
			t.Fatalf("%s has %d fields, frozen schema pins %d — LOG-1 messages are frozen (S0-5)", typ.Name(), typ.NumField(), len(want))
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.Name != want[i] {
				t.Fatalf("%s field[%d] = %q, frozen schema pins %q", typ.Name(), i, f.Name, want[i])
			}
			if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
				t.Fatalf("%s.%s is a raw-bytes ([]byte) field; LOG-1 is metadata-only", typ.Name(), f.Name)
			}
		}
	}

	// The buf gate: lint + breaking must be green against the frozen schema.
	if err := runBufGate(t); err != nil {
		t.Fatalf("buf gate not green: %v", err)
	}
}

// planRef: doc 09 Stage 0 identity-validation seam (D22). [contract, ADVERSARIAL]
func TestIdentityValidationSeam_Contract_RealVsFake(t *testing.T) {
	run := func(t *testing.T, seam IdentitySeam) {
		clock := installFakeClock(t)
		ctx := context.Background()
		sessA := SessionRef{ID: "A", Iface: IfacePrefix + "A"}
		sessB := SessionRef{ID: "B", Iface: IfacePrefix + "B"}
		const validity = 5 * time.Minute

		// Mint a genuinely valid cred for A through the seam itself.
		credA, identA, err := seam.MintCredential(ctx, sessA, validity)
		if err != nil {
			t.Fatalf("MintCredential(A): %v", err)
		}
		if credA == "" || identA.ID == "" {
			t.Fatalf("MintCredential(A) yielded empty cred/identity: cred=%q ident=%+v", credA, identA)
		}

		// A-valid -> the EXACT IdentityRef the cred was minted for.
		id, err := seam.Validate(ctx, sessA, credA)
		if err != nil {
			t.Fatalf("Validate(A, credA): %v", err)
		}
		if id != identA {
			t.Fatalf("Validate(A, credA) = %+v, want the minted identity %+v", id, identA)
		}

		// A's cred under session B -> the documented mismatch sentinel.
		if _, err := seam.Validate(ctx, sessB, credA); !errors.Is(err, ErrIdentityMismatch) {
			t.Fatalf("Validate(B, credA) err = %v, want ErrIdentityMismatch (cross-session)", err)
		}

		// A once-valid cred PAST its validity -> the documented expiry
		// sentinel (clock-driven, not a never-valid string).
		clock.Advance(validity + time.Second)
		if _, err := seam.Validate(ctx, sessA, credA); !errors.Is(err, ErrCredentialExpired) {
			t.Fatalf("Validate(A, credA) post-validity err = %v, want ErrCredentialExpired", err)
		}
	}

	t.Run("real", func(t *testing.T) { run(t, NewIdentitySeam()) })
	t.Run("fake", func(t *testing.T) { run(t, NewFakeIdentitySeam()) })
}

// planRef: doc 09 Stage 0 CA-mint seam (D17). [contract, ADVERSARIAL]
func TestCAMintSeam_Contract_PerSessionScoped(t *testing.T) {
	run := func(t *testing.T, mint CAMintSeam) {
		ctx := context.Background()
		sessA := SessionRef{ID: "A", Iface: IfacePrefix + "A"}
		sessB := SessionRef{ID: "B", Iface: IfacePrefix + "B"}

		caA, err := mint.MintSessionCA(ctx, sessA)
		if err != nil {
			t.Fatalf("MintSessionCA(A): %v", err)
		}
		caB, err := mint.MintSessionCA(ctx, sessB)
		if err != nil {
			t.Fatalf("MintSessionCA(B): %v", err)
		}
		if caA.ID == "" || caA.ID == caB.ID {
			t.Fatalf("CAs not distinct: A=%q B=%q", caA.ID, caB.ID)
		}

		leafA, err := mint.LeafFor(ctx, caA, "github.com")
		if err != nil {
			t.Fatalf("LeafFor(A): %v", err)
		}
		leafB, err := mint.LeafFor(ctx, caB, "github.com")
		if err != nil {
			t.Fatalf("LeafFor(B): %v", err)
		}
		// Each leaf chains only to its own session CA.
		if leafA.IssuerCA.ID != caA.ID {
			t.Fatalf("leafA issuer = %q, want %q", leafA.IssuerCA.ID, caA.ID)
		}
		if leafB.IssuerCA.ID != caB.ID {
			t.Fatalf("leafB issuer = %q, want %q", leafB.IssuerCA.ID, caB.ID)
		}
		// A's leaf is unusable on a session-B validation path: its issuing
		// CA is scoped to session A and never to session B (and vice versa).
		if leafA.IssuerCA.Session != sessA {
			t.Fatalf("leafA's CA scoped to %+v, want session A %+v", leafA.IssuerCA.Session, sessA)
		}
		if leafB.IssuerCA.Session != sessB {
			t.Fatalf("leafB's CA scoped to %+v, want session B %+v", leafB.IssuerCA.Session, sessB)
		}
		if leafA.IssuerCA.Session == sessB {
			t.Fatal("LeafFor(caA, origin) satisfies a session-B validation path; cross-session issuance must fail")
		}
	}
	// Contract-twice (S0-7): the same body runs against the REAL seam and
	// the published FAKE — real/fake divergence fails one of the legs.
	t.Run("real", func(t *testing.T) { run(t, NewCAMintSeam()) })
	t.Run("fake", func(t *testing.T) { run(t, NewFakeCAMintSeam()) })
}

// planRef: doc 09 Stage 0 suspend signal. [contract]
func TestSuspendSignalSeam_Contract_OneWayObservable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// No synchronous suspend-decision return path: the only suspend-related
	// orchestrator method is the read-side SuspendSignals.
	ot := reflect.TypeOf((*OrchestratorFake)(nil)).Elem()
	for i := 0; i < ot.NumMethod(); i++ {
		m := ot.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			if m.Type.Out(j).Name() == "SuspendDecision" {
				t.Fatalf("orchestrator method %s returns a SuspendDecision; suspend is one-way", m.Name)
			}
		}
	}

	if _, err := h.b.Policy().Load(ctx, PolicySnapshot{Layers: []PolicyLayer{{
		Name: "system", Allow: BaselineDomains, Caps: map[string]int{"api.github.com": 1},
	}}}); err != nil {
		t.Fatalf("Policy.Load: %v", err)
	}
	sess := h.newSession(t)

	// Drive a breach.
	for i := 0; i < 3; i++ {
		_, _ = h.b.VM(sess.Ref).HTTP(ctx, HTTPRequest{Method: "GET", Host: "api.github.com", Path: "/capped"})
	}

	sigs, err := h.b.Orchestrator().SuspendSignals(ctx)
	if err != nil {
		t.Fatalf("SuspendSignals: %v", err)
	}
	var sig *SuspendSignal
	for i := range sigs {
		if sigs[i].Session == sess.Ref {
			sig = &sigs[i]
		}
	}
	if sig == nil {
		t.Fatal("no SuspendSignal recorded for the breach")
	}
	if sig.Reason == "" {
		t.Fatal("SuspendSignal missing reason")
	}
	if sig.At.IsZero() {
		t.Fatal("SuspendSignal missing timestamp")
	}
}

// planRef: doc 09 POL-1 Done-when; Stage 0 policy stream. [contract]
func TestPolicySnapshot_LayeredCompose_DenyOverrides_RoundTrip(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const name = "blocked.example"
	h.setUpstreamA(t, name, 5*time.Minute, rotatedAddrA)

	// Positive control FIRST: the same layered snapshot WITHOUT the org
	// block must let the session-layer allow resolve the name. This proves
	// session allows are honored, so the deny below is load-bearing on the
	// org block — not on plain default-deny against the system allowlist.
	control := PolicySnapshot{Layers: []PolicyLayer{
		{Name: "system", Allow: BaselineDomains, Block: []string{}},
		{Name: "org"},
		{Name: "session", Allow: []string{name}},
	}}
	if _, err := h.b.Policy().Load(ctx, control); err != nil {
		t.Fatalf("Policy.Load(control): %v", err)
	}
	ctrlSess := h.newSession(t)
	h.resolveOK(t, ctrlSess.Ref, name) // session-layer allow must be honored

	// session-layer ALLOWs the name, but org-layer BLOCKs it, and a blocklist
	// entry also matches: deny-overrides must win.
	snap := PolicySnapshot{Layers: []PolicyLayer{
		{Name: "system", Allow: BaselineDomains, Block: []string{}},
		{Name: "org", Block: []string{name}},
		{Name: "session", Allow: []string{name}},
	}}
	ver, err := h.b.Policy().Load(ctx, snap)
	if err != nil {
		t.Fatalf("Policy.Load: %v", err)
	}
	if ver == "" {
		t.Fatal("Load did not stamp a version on the snapshot")
	}
	if active, err := h.b.Policy().Active(ctx); err != nil || active != ver {
		t.Fatalf("Active = %q (err %v), want %q (round-trip)", active, err, ver)
	}

	sess := h.newSession(t)
	resp, err := h.b.VM(sess.Ref).ResolveDNS(ctx, DNSQuery{Name: name, Type: DNSTypeA})
	if err != nil {
		t.Fatalf("ResolveDNS: %v", err)
	}
	if resp.Rcode == RcodeNoError && len(resp.Answers) > 0 {
		t.Fatalf("deny-overrides failed: %q resolved despite an org/blocklist block", name)
	}
	// Attribution must name the WINNING layer: the org blocklist rule — not
	// a system default-deny rule, and certainly not the session allow.
	d := requireDenyDecision(t, h.events(t, sess.Ref), name)
	if d.Rule.Layer != "org" {
		t.Fatalf("deny attributed to layer %q, want %q (the org blocklist rule won deny-overrides)", d.Rule.Layer, "org")
	}
}
