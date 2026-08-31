// SPDX-License-Identifier: Apache-2.0

package netflowadapter

// schema_audit_test.go — conformance assertions for the LOG-1 wire schema and
// LOG-5 credential audit, proving the adapter's real implementations satisfy
// what boundary/flowlog/flowlog_schema_test.go + flowlog_audit_test.go assert
// (the boundary suite stays RED against its in-package stubs by design, D26;
// this is the assurance twin that demonstrates the contract is satisfiable from
// the conformance adapter).

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	flowlog "github.com/dream-serpent/dream-serpent/boundary/flowlog"
)

// ───────────────────────────────────────────────────────────────────────────
// fixtures mirrored from boundary/flowlog/fakes_test.go
// ───────────────────────────────────────────────────────────────────────────

func schemaValidDecision(ref flowlog.SessionRef, v flowlog.Verdict, ruleID, resource string, at time.Time) flowlog.PolicyDecision {
	return flowlog.PolicyDecision{
		Session: ref, Verdict: v, RuleID: ruleID,
		PolicyLayer: "session", PolicyVersion: "policy-v1",
		Resource: resource, At: at,
	}
}

func schemaValidFlow(ref flowlog.SessionRef, seq uint32, at time.Time) flowlog.FlowRecord {
	return flowlog.FlowRecord{
		Session: ref, Iface: ref.Iface, AdmittingDomain: "registry.npmjs.org",
		Dst:      mustAP("104.16.0.5:443"),
		Protocol: flowlog.ProtoTCP, BytesIn: 2048, BytesOut: 512,
		Start: at, End: at.Add(time.Second), Duration: time.Second,
		CtMark: seq, Verdict: flowlog.FlowAccepted,
	}
}

func schemaValidHTTP(ref flowlog.SessionRef, host string, at time.Time) flowlog.HttpEvent {
	return flowlog.HttpEvent{
		Session: ref, Method: "GET", Host: host, Path: "/", Status: 200,
		ReqBytes: 512, RespBytes: 2048, Start: at, Duration: 80 * time.Millisecond,
		Decision: schemaValidDecision(ref, flowlog.VerdictAllow, "POL-2.allow", host, at),
	}
}

func schemaValidCredUse(ref flowlog.SessionRef, fp flowlog.CredentialFingerprint, at time.Time) flowlog.CredentialUseEvent {
	return flowlog.CredentialUseEvent{
		Session: ref, Service: "github", Fingerprint: fp,
		Request: flowlog.HttpRequestMeta{Method: "POST", Host: "api.github.com", Path: "/repos/x/git-receive-pack", At: at},
	}
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-1 — wire codec is lossless and byte-stable.
// ───────────────────────────────────────────────────────────────────────────

func TestSchema_RoundTrip_LosslessAndByteStable(t *testing.T) {
	refA := mkRef("sess-a")
	dec := schemaValidDecision(refA, flowlog.VerdictAllow, "POL-2.allow.npm", "registry.npmjs.org", t0)

	cases := []struct {
		name string
		ev   flowlog.Event
	}{
		{"FlowRecord", schemaValidFlow(refA, 0xA001, t0)},
		{"DnsEvent", dnsEvent(refA, "registry.npmjs.org", mustAddr("104.16.0.5"), t0)},
		{"HttpEvent", schemaValidHTTP(refA, "registry.npmjs.org", t0)},
		{"PolicyDecision", dec},
		{"CredentialUseEvent", schemaValidCredUse(refA, mustFP(t, []byte("ghp_roundtrip01234567890123456789ABCD")), t0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := MarshalEvent(tc.ev)
			if err != nil {
				t.Fatalf("MarshalEvent: %v", err)
			}
			if len(enc) == 0 {
				t.Fatalf("MarshalEvent produced empty encoding")
			}
			decoded, err := UnmarshalEvent(enc)
			if err != nil {
				t.Fatalf("UnmarshalEvent: %v", err)
			}
			// Lossless: decoded equals the original (timestamps compared via
			// re-marshal to dodge monotonic-clock differences — fixtures use UTC).
			enc2, err := MarshalEvent(decoded)
			if err != nil {
				t.Fatalf("re-MarshalEvent: %v", err)
			}
			if !bytes.Equal(enc, enc2) {
				t.Errorf("re-encode is not byte-for-byte stable:\n got: %s\nwant: %s", enc2, enc)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-1 — Validate: SessionRef required (the error names the missing field).
// ───────────────────────────────────────────────────────────────────────────

func TestSchema_Validate_SessionRefRequired(t *testing.T) {
	mkEvents := func(ref flowlog.SessionRef) []flowlog.Event {
		return []flowlog.Event{
			schemaValidFlow(ref, 1, t0),
			dnsEvent(ref, "registry.npmjs.org", mustAddr("104.16.0.5"), t0),
			schemaValidHTTP(ref, "registry.npmjs.org", t0),
			schemaValidDecision(ref, flowlog.VerdictAllow, "POL-2.allow.npm", "registry.npmjs.org", t0),
			schemaValidCredUse(ref, mustFP(t, []byte("ghp_validate0123456789012345678ABCDEF")), t0),
		}
	}
	rows := []struct {
		name, wantField string
		ref             flowlog.SessionRef
	}{
		{"zero_value", "SessionID", flowlog.SessionRef{}},
		{"missing_session_id", "SessionID", flowlog.SessionRef{HostID: "host-1", Iface: "dstap-x"}},
		{"missing_iface", "Iface", flowlog.SessionRef{SessionID: "sess-x", HostID: "host-1"}},
	}
	for _, row := range rows {
		for _, ev := range mkEvents(row.ref) {
			t.Run(row.name+"/"+typeName(ev), func(t *testing.T) {
				err := ValidateEvent(ev)
				if err == nil {
					t.Fatalf("Validate must reject %T with %s missing", ev, row.wantField)
				}
				if !strings.Contains(err.Error(), row.wantField) {
					t.Errorf("Validate error must name the missing field %q, got: %v", row.wantField, err)
				}
			})
		}
	}
	for _, ev := range mkEvents(mkRef("sess-valid")) {
		t.Run("valid_passes/"+typeName(ev), func(t *testing.T) {
			if err := ValidateEvent(ev); err != nil {
				t.Errorf("fully attributed %T must pass Validate, got: %v", ev, err)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-1 / POL-3 — PolicyDecision provenance required.
// ───────────────────────────────────────────────────────────────────────────

func TestSchema_PolicyDecision_RequiresProvenance(t *testing.T) {
	refA := mkRef("sess-a")
	base := schemaValidDecision(refA, flowlog.VerdictDeny, "POL-1.deny.default", "evil.example", t0)
	rows := []struct {
		name, wantField string
		mutate          func(*flowlog.PolicyDecision)
		wantOK          bool
	}{
		{"missing_rule_id", "RuleID", func(d *flowlog.PolicyDecision) { d.RuleID = "" }, false},
		{"missing_policy_layer", "PolicyLayer", func(d *flowlog.PolicyDecision) { d.PolicyLayer = "" }, false},
		{"missing_policy_version", "PolicyVersion", func(d *flowlog.PolicyDecision) { d.PolicyVersion = "" }, false},
		{"fully_populated", "", func(*flowlog.PolicyDecision) {}, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			d := base
			row.mutate(&d)
			err := ValidateEvent(d)
			if row.wantOK {
				if err != nil {
					t.Errorf("complete provenance must pass Validate, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("decision missing %s must fail Validate", row.wantField)
			}
			if !strings.Contains(err.Error(), row.wantField) {
				t.Errorf("Validate error must name %q, got: %v", row.wantField, err)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-5 — a raw secret smuggled into the fingerprint field fails Validate.
// ───────────────────────────────────────────────────────────────────────────

func TestSchema_CredentialUse_RejectsRawSecretShapedFingerprint(t *testing.T) {
	refA := mkRef("sess-a")
	seeded := "ghp_seededAdversaria1Token0123456789abcd"
	adversarial := []struct {
		name string
		fp   flowlog.CredentialFingerprint
	}{
		{"github_token_shaped_value", flowlog.CredentialFingerprint(seeded)},
		{"high_entropy_not_format", flowlog.CredentialFingerprint("9f8e7d6c5b4a39281706f5e4d3c2b1a0deadbeefcafebabe0011223344556677X")},
		{"prefix_plus_raw_token", flowlog.CredentialFingerprint(flowlog.FingerprintPrefix + seeded)},
		{"prefix_plus_63_hex", flowlog.CredentialFingerprint(flowlog.FingerprintPrefix + strings.Repeat("ab", 31) + "c")},
		{"prefix_plus_65_hex", flowlog.CredentialFingerprint(flowlog.FingerprintPrefix + strings.Repeat("ab", 32) + "c")},
		{"prefix_plus_64_uppercase", flowlog.CredentialFingerprint(flowlog.FingerprintPrefix + strings.Repeat("AB", 32))},
		{"prefix_plus_64_nonhex", flowlog.CredentialFingerprint(flowlog.FingerprintPrefix + strings.Repeat("zy", 32))},
	}
	for _, row := range adversarial {
		t.Run(row.name, func(t *testing.T) {
			err := ValidateEvent(schemaValidCredUse(refA, row.fp, t0))
			if err == nil {
				t.Fatalf("a raw credential in the fingerprint field must fail Validate (fp=%q)", row.fp)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "fingerprint") {
				t.Errorf("error must name the fingerprint violation, got: %v", err)
			}
		})
	}
	t.Run("sanctioned_passes", func(t *testing.T) {
		fp := mustFP(t, []byte(seeded))
		if err := ValidateEvent(schemaValidCredUse(refA, fp, t0)); err != nil {
			t.Errorf("FingerprintCredential output must pass Validate, got: %v", err)
		}
	})
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-5 — fingerprint is stable, joinable, avalanche, non-reversible, fixed.
// ───────────────────────────────────────────────────────────────────────────

func TestFingerprint_StableJoinableNonReversible(t *testing.T) {
	fpFormat := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	secret := []byte("ghp_stableSecretZQXWVYwsrqponmZYXWVU9900")

	t.Run("same_secret_identical", func(t *testing.T) {
		fp1, fp2 := mustFP(t, secret), mustFP(t, secret)
		if fp1 != fp2 {
			t.Errorf("same secret must fingerprint identically: %q vs %q", fp1, fp2)
		}
		if !fpFormat.MatchString(string(fp1)) {
			t.Errorf("fingerprint %q does not match LOG-1.e format", fp1)
		}
		if got, want := len(fp1), len(flowlog.FingerprintPrefix)+flowlog.FingerprintHexLen; got != want {
			t.Errorf("fingerprint length %d, want %d", got, want)
		}
		scanForSecretWindows(t, "fingerprint", []byte(fp1), "secret", secret)
	})

	t.Run("avalanche_every_region", func(t *testing.T) {
		fp0 := mustFP(t, secret)
		seen := map[flowlog.CredentialFingerprint]int{fp0: -1}
		for _, pos := range []int{0, 1, len(secret) / 2, len(secret) - 1} {
			mut := append([]byte(nil), secret...)
			mut[pos] ^= 0x01
			fpM := mustFP(t, mut)
			if fpM == fp0 {
				t.Errorf("flipping byte %d did not change the fingerprint", pos)
			}
			if prev, dup := seen[fpM]; dup {
				t.Errorf("flips at %d and %d collide", pos, prev)
			}
			seen[fpM] = pos
		}
	})

	t.Run("empty_rejected", func(t *testing.T) {
		for _, empty := range [][]byte{nil, {}} {
			if _, err := FingerprintCredential(empty); !errors.Is(err, flowlog.ErrEmptySecret) {
				t.Errorf("empty secret must be rejected with ErrEmptySecret, got %v", err)
			}
		}
	})

	t.Run("large_fixed_length", func(t *testing.T) {
		fp := mustFP(t, bytes.Repeat([]byte{0x5a}, 10<<10))
		if got, want := len(fp), len(flowlog.FingerprintPrefix)+flowlog.FingerprintHexLen; got != want {
			t.Errorf("10 KiB secret fingerprint length %d, want %d", got, want)
		}
		if !fpFormat.MatchString(string(fp)) {
			t.Errorf("fingerprint %q does not match the fixed format", fp)
		}
	})
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-5 — the credential value appears nowhere on any log surface (windowed,
// multi-encoding scan of the fingerprint + the serialized wire bytes).
// ───────────────────────────────────────────────────────────────────────────

func TestCredentialValue_AppearsNowhereInAnyLogPath(t *testing.T) {
	refA := mkRef("sess-a")
	const longCanary = "ghp_LONGCANARY9aF3xQ7mZ2kW8pL1nV5rT0uY4s"
	const shortCanary = "ds_SHORTCANARY6bE2yR8nX3jU9qM0oW7sZ1vT5a"

	fp := mustFP(t, []byte(longCanary))
	fpShort := mustFP(t, []byte(shortCanary))

	for _, surf := range []struct {
		name string
		fp   flowlog.CredentialFingerprint
	}{{"long fingerprint", fp}, {"short fingerprint", fpShort}} {
		scanForSecretWindows(t, surf.name, []byte(surf.fp), "longCanary", []byte(longCanary))
		scanForSecretWindows(t, surf.name, []byte(surf.fp), "shortCanary", []byte(shortCanary))
	}

	// The serialized wire bytes of a credential-use event carrying ONLY the
	// fingerprint must not leak any window of either canary.
	shortUse := schemaValidCredUse(refA, fpShort, t0.Add(5*time.Second))
	shortUse.Service = "session-credential"
	for _, ev := range []flowlog.Event{schemaValidCredUse(refA, fp, t0), shortUse} {
		enc, err := MarshalEvent(ev)
		if err != nil {
			t.Fatalf("MarshalEvent: %v", err)
		}
		scanSurface(t, "serialized "+typeName(ev), enc)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-5 — "which session used the GitHub key, when, for what request" returns
// the answer for a scripted test push, queried from the shipped store.
// ───────────────────────────────────────────────────────────────────────────

func TestCredentialAudit_WhichSessionUsedTheGitHubKey(t *testing.T) {
	refA := mkRef("sess-a")
	fp := mustFP(t, []byte("ghp_testPushKey0123456789abcdefABCDEF012"))

	sink := NewSink()
	spool := NewSpool(8 << 20)
	col := NewCollector(spool)
	const audit flowlog.SinkID = "audit"
	shipper := NewShipper(spool, NewRouter(flowlog.RouterConfig{Default: audit, CustomerSide: audit}),
		map[flowlog.SinkID]flowlog.Sink{audit: sink}, flowlog.TierSaaS)

	tPush := t0.Add(90 * time.Second)
	use := flowlog.CredentialUseEvent{
		Session: refA, Service: "github", Fingerprint: fp,
		Request: flowlog.HttpRequestMeta{Method: "POST", Host: "api.github.com", Path: "/repos/x/git-receive-pack", At: tPush},
	}
	if err := col.Ingest(bg, use); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if err := shipper.Ship(bg); err != nil {
		t.Fatalf("Ship: %v", err)
	}

	q := NewAuditQuerier(sink)
	uses, err := q.CredentialUses(bg, flowlog.CredentialUseQuery{Service: "github", SessionID: refA.SessionID, Window: flowlog.Window{From: t0, To: t0.Add(time.Hour)}})
	if err != nil {
		t.Fatalf("CredentialUses: %v", err)
	}
	if len(uses) != 1 {
		t.Fatalf("want exactly one credential use, got %d", len(uses))
	}
	got := uses[0]
	if got.Session.SessionID != refA.SessionID || got.Service != "github" || !got.Request.At.Equal(tPush) {
		t.Errorf("audit answer wrong: %+v", got)
	}
	if got.Request.Method != "POST" || got.Request.Host != "api.github.com" || got.Request.Path != "/repos/x/git-receive-pack" {
		t.Errorf("request metadata wrong: %+v", got.Request)
	}
	if got.Fingerprint != fp {
		t.Errorf("fingerprint %q, want %q", got.Fingerprint, fp)
	}

	before, err := q.CredentialUses(bg, flowlog.CredentialUseQuery{Service: "github", SessionID: refA.SessionID, Window: flowlog.Window{From: t0.Add(-time.Hour), To: t0}})
	if err != nil {
		t.Fatalf("CredentialUses (pre-push): %v", err)
	}
	if len(before) != 0 {
		t.Errorf("a window before the push must be empty, got %d", len(before))
	}
}

// ───────────────────────────────────────────────────────────────────────────
// LOG-5 — pass-through flows produce NO CredentialUseEvent but ARE accounted.
// ───────────────────────────────────────────────────────────────────────────

func TestCredentialAudit_PassThroughFlows_NoUseEventButAccounted(t *testing.T) {
	refA := mkRef("sess-a")
	sink := NewSink()
	spool := NewSpool(8 << 20)
	col := NewCollector(spool)
	const audit flowlog.SinkID = "audit"
	shipper := NewShipper(spool, NewRouter(flowlog.RouterConfig{Default: audit, CustomerSide: audit}),
		map[flowlog.SinkID]flowlog.Sink{audit: sink}, flowlog.TierSaaS)

	passDec := schemaValidDecision(refA, flowlog.VerdictPassthrough, "TLS-4.passthrough.pinned", "pinned.bank.example", t0.Add(1*time.Second))
	flow := schemaValidFlow(refA, 7, t0.Add(2*time.Second))
	flow.AdmittingDomain = "pinned.bank.example"

	for _, ev := range []flowlog.Event{passDec, flow} {
		if err := col.Ingest(bg, ev); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}
	if err := shipper.Ship(bg); err != nil {
		t.Fatalf("Ship: %v", err)
	}

	q := NewAuditQuerier(sink)
	uses, err := q.CredentialUses(bg, flowlog.CredentialUseQuery{SessionID: refA.SessionID, Window: flowlog.Window{From: t0, To: t0.Add(time.Hour)}})
	if err != nil {
		t.Fatalf("CredentialUses: %v", err)
	}
	if len(uses) != 0 {
		t.Fatalf("pass-through traffic must never produce a CredentialUseEvent, got %d", len(uses))
	}

	story, err := sink.Query(bg, flowlog.StoryQuery{SessionID: refA.SessionID, Window: flowlog.Window{From: t0, To: t0.Add(time.Hour)}})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(story) != 2 {
		t.Fatalf("pass-through story must hold the flow + the decision, got %d", len(story))
	}
	var gotFlow, gotDec bool
	for _, ev := range story {
		switch e := ev.(type) {
		case flowlog.FlowRecord:
			gotFlow = true
			if e.AdmittingDomain != "pinned.bank.example" {
				t.Errorf("pass-through flow lost its domain: %q", e.AdmittingDomain)
			}
		case flowlog.PolicyDecision:
			gotDec = true
			if e.Verdict != flowlog.VerdictPassthrough {
				t.Errorf("decision verdict %q, want passthrough", e.Verdict)
			}
		}
	}
	if !gotFlow || !gotDec {
		t.Errorf("story must hold the FlowRecord and the passthrough decision (flow=%v dec=%v)", gotFlow, gotDec)
	}
}

// ───────────────────────────────────────────────────────────────────────────
// secret-window scanning helpers (mirrored from boundary/flowlog_audit_test.go)
// ───────────────────────────────────────────────────────────────────────────

func scanForSecretWindows(t *testing.T, surface string, data []byte, secretName string, secret []byte) {
	t.Helper()
	const minWindow = 6
	for l := minWindow; l <= len(secret); l++ {
		for i := 0; i+l <= len(secret); i++ {
			win := secret[i : i+l]
			for form, enc := range map[string]string{
				"raw":       string(win),
				"hex":       hex.EncodeToString(win),
				"base64":    base64.StdEncoding.EncodeToString(win),
				"base64url": base64.RawURLEncoding.EncodeToString(win),
			} {
				if bytes.Contains(data, []byte(enc)) {
					t.Errorf("credential window leaked: %s [%d:%d) (%s) on surface %q", secretName, i, i+l, form, surface)
				}
			}
		}
	}
}

func scanSurface(t *testing.T, surface string, data []byte) {
	t.Helper()
	const longCanary = "ghp_LONGCANARY9aF3xQ7mZ2kW8pL1nV5rT0uY4s"
	const shortCanary = "ds_SHORTCANARY6bE2yR8nX3jU9qM0oW7sZ1vT5a"
	forms := func(needle string) map[string][]byte {
		return map[string][]byte{
			"raw":        []byte(needle),
			"base64":     []byte(base64.StdEncoding.EncodeToString([]byte(needle))),
			"base64url":  []byte(base64.RawURLEncoding.EncodeToString([]byte(needle))),
			"hex":        []byte(hex.EncodeToString([]byte(needle))),
			"urlencoded": []byte(url.QueryEscape(needle)),
		}
	}
	for _, needle := range []string{longCanary, shortCanary} {
		for form, enc := range forms(needle) {
			if n := bytes.Count(data, enc); n > 0 {
				t.Errorf("canary leaked: %d× %s… (%s) on %q", n, needle[:14], form, surface)
			}
		}
		scanForSecretWindows(t, surface, data, needle[:14]+"…", []byte(needle))
	}
}
