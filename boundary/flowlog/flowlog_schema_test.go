package flowlog

// LOG-1 — Event schema: stable wire contract, SessionRef required, metadata
// only, provenance required, fingerprint-format enforced.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Frozen golden schema descriptors — the Go-harness stand-in for buf-breaking:
// any re-shape of an event struct diffs against these and turns the suite RED.
const (
	goldenSessionRef      = "SessionRef{SessionID string;HostID string;Iface string;}"
	goldenHttpRequestMeta = "HttpRequestMeta{Method string;Host string;Path string;At time.Time;}"
	goldenPolicyDecision  = "PolicyDecision{Session " + goldenSessionRef + ";Verdict flowlog.Verdict;RuleID string;PolicyLayer string;PolicyVersion string;Resource string;At time.Time;}"
	goldenFlowRecord      = "FlowRecord{Session " + goldenSessionRef + ";Iface string;AdmittingDomain string;Dst netip.AddrPort;Protocol flowlog.Proto;BytesIn uint64;BytesOut uint64;Start time.Time;End time.Time;Duration time.Duration;CtMark uint32;Verdict flowlog.FlowVerdict;}"
	goldenDnsEvent        = "DnsEvent{Session " + goldenSessionRef + ";QueryName string;AdmittedIPs []netip.Addr;TTL time.Duration;ExpiresAt time.Time;Decision " + goldenPolicyDecision + ";}"
	goldenHttpEvent       = "HttpEvent{Session " + goldenSessionRef + ";Method string;Host string;Path string;Status int;ReqBytes uint64;RespBytes uint64;Start time.Time;Duration time.Duration;Decision " + goldenPolicyDecision + ";}"
	goldenCredentialUse   = "CredentialUseEvent{Session " + goldenSessionRef + ";Service string;Fingerprint flowlog.CredentialFingerprint;Request " + goldenHttpRequestMeta + ";}"
)

// schemaDescriptor renders a deterministic structural descriptor of a type.
func schemaDescriptor(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Struct:
		switch t {
		case reflect.TypeOf(time.Time{}):
			return "time.Time"
		case reflect.TypeOf(netip.Addr{}):
			return "netip.Addr"
		case reflect.TypeOf(netip.AddrPort{}):
			return "netip.AddrPort"
		}
		var b strings.Builder
		b.WriteString(t.Name())
		b.WriteString("{")
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			b.WriteString(f.Name)
			b.WriteString(" ")
			b.WriteString(schemaDescriptor(f.Type))
			b.WriteString(";")
		}
		b.WriteString("}")
		return b.String()
	case reflect.Slice:
		return "[]" + schemaDescriptor(t.Elem())
	case reflect.Pointer:
		return "*" + schemaDescriptor(t.Elem())
	default:
		return t.String()
	}
}

// planRef: doc 09 §7 LOG-1 Done-when (Stage-0 contract freeze); doc 06 §2 contract model
func TestEventSchema_RoundTrip_AllMessages(t *testing.T) {
	refA := mkRef("sess-a")
	dec := validDecision(refA, VerdictAllow, "POL-2.allow.npm", "registry.npmjs.org", t0)

	cases := []struct {
		name   string
		ev     Event
		golden string
	}{
		{
			name: "FlowRecord_zero_duration_ipv6_dst",
			ev: FlowRecord{
				Session: refA, Iface: refA.Iface, AdmittingDomain: "registry.npmjs.org",
				Dst:      netip.MustParseAddrPort("[2606:4700::6810:1005]:443"),
				Protocol: ProtoTCP, BytesIn: 0, BytesOut: 0,
				Start: t0, End: t0, Duration: 0,
				CtMark: 0xA001, Verdict: FlowAccepted,
			},
			golden: goldenFlowRecord,
		},
		{
			name: "DnsEvent_multi_ip",
			ev: DnsEvent{
				Session: refA, QueryName: "registry.npmjs.org",
				AdmittedIPs: []netip.Addr{
					netip.MustParseAddr("104.16.0.5"),
					netip.MustParseAddr("2606:4700::6810:1005"),
				},
				TTL: 60 * time.Second, ExpiresAt: t0.Add(60 * time.Second),
				Decision: dec,
			},
			golden: goldenDnsEvent,
		},
		{
			name: "HttpEvent",
			ev: HttpEvent{
				Session: refA, Method: "GET", Host: "registry.npmjs.org", Path: "/react",
				Status: 200, ReqBytes: 312, RespBytes: 48211,
				Start: t0, Duration: 87 * time.Millisecond, Decision: dec,
			},
			golden: goldenHttpEvent,
		},
		{
			name:   "PolicyDecision",
			ev:     dec,
			golden: goldenPolicyDecision,
		},
		{
			name:   "CredentialUseEvent",
			ev:     validCredUse(refA, testFingerprint, t0),
			golden: goldenCredentialUse,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Golden descriptor diff: a re-shape of the schema fails here
			// (stand-in for buf-breaking in the Go harness).
			if got := schemaDescriptor(reflect.TypeOf(tc.ev)); got != tc.golden {
				t.Fatalf("schema shape drifted from frozen golden descriptor:\n got: %s\nwant: %s", got, tc.golden)
			}
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
			if !reflect.DeepEqual(decoded, tc.ev) {
				t.Errorf("round-trip not lossless:\n got: %#v\nwant: %#v", decoded, tc.ev)
			}
			enc2, err := MarshalEvent(decoded)
			if err != nil {
				t.Fatalf("re-MarshalEvent: %v", err)
			}
			if !bytes.Equal(enc, enc2) {
				t.Errorf("re-encode is not byte-for-byte stable")
			}

			// Golden WIRE-BYTES fixture (buf-breaking stand-in for the bytes,
			// not just the struct shape): once frozen, the encoded bytes of
			// the canonical fixture may never drift between harness runs.
			// On the very first green encoding the fixture is recorded and
			// the test fails, demanding the freeze be committed; thereafter
			// any encoding drift diffs against the committed golden.
			goldenPath := filepath.Join("testdata", "wire", tc.name+".hex")
			gotHex := hex.EncodeToString(enc)
			wantHex, gerr := os.ReadFile(goldenPath)
			if errors.Is(gerr, fs.ErrNotExist) {
				if merr := os.MkdirAll(filepath.Dir(goldenPath), 0o755); merr != nil {
					t.Fatalf("creating golden wire fixture dir: %v", merr)
				}
				if werr := os.WriteFile(goldenPath, []byte(gotHex+"\n"), 0o644); werr != nil {
					t.Fatalf("recording golden wire fixture: %v", werr)
				}
				t.Fatalf("golden wire-bytes fixture %s recorded at contract freeze — commit it and re-run; until it is committed the wire encoding is not frozen", goldenPath)
			}
			if gerr != nil {
				t.Fatalf("reading golden wire fixture %s: %v", goldenPath, gerr)
			}
			if gotHex != strings.TrimSpace(string(wantHex)) {
				t.Fatalf("wire encoding drifted from the frozen golden fixture %s (Stage-0 contract freeze / buf-breaking stand-in):\n got: %s\nwant: %s",
					goldenPath, gotHex, strings.TrimSpace(string(wantHex)))
			}
		})
	}
}

// planRef: doc 09 §7 LOG-1 (all messages share a SessionRef)
func TestEventValidate_SessionRefRequired(t *testing.T) {
	mkEvents := func(ref SessionRef) []Event {
		return []Event{
			validFlowRecord(ref, 1, t0),
			validDnsEvent(ref, "registry.npmjs.org", t0),
			validHttpEvent(ref, "registry.npmjs.org", t0),
			validDecision(ref, VerdictAllow, "POL-2.allow.npm", "registry.npmjs.org", t0),
			validCredUse(ref, testFingerprint, t0),
		}
	}

	rows := []struct {
		name      string
		ref       SessionRef
		wantField string
	}{
		{"zero_value_sessionref", SessionRef{}, "SessionID"},
		{"missing_session_id", SessionRef{HostID: "host-1", Iface: "dstap-x"}, "SessionID"},
		{"missing_iface", SessionRef{SessionID: "sess-x", HostID: "host-1"}, "Iface"},
	}

	for _, row := range rows {
		for _, ev := range mkEvents(row.ref) {
			t.Run(fmt.Sprintf("%s/%T", row.name, ev), func(t *testing.T) {
				err := ev.Validate()
				if err == nil {
					t.Fatalf("Validate must reject %T with %s missing — no event exists without session attribution", ev, row.wantField)
				}
				if !strings.Contains(err.Error(), row.wantField) {
					t.Errorf("Validate error must name the missing field %q, got: %v", row.wantField, err)
				}
			})
		}
	}

	for _, ev := range mkEvents(mkRef("sess-valid")) {
		t.Run(fmt.Sprintf("valid_sessionref_passes/%T", ev), func(t *testing.T) {
			if err := ev.Validate(); err != nil {
				t.Errorf("fully attributed %T must pass Validate, got: %v", ev, err)
			}
		})
	}
}

// planRef: doc 09 §7 LOG-1 ("netflow-style metadata only; full packet capture is explicitly out", doc 03 §4)
//
// Schema-shape ratchet: this test is green against the frozen seam by design;
// adding any payload/body/header-value-capable field to an event type turns
// it RED.
func TestEventSchema_MetadataOnly_NoPayloadCapture(t *testing.T) {
	selfPkg := reflect.TypeOf(SessionRef{}).PkgPath()

	allowedStd := map[reflect.Type]bool{
		reflect.TypeOf(time.Time{}):      true,
		reflect.TypeOf(netip.Addr{}):     true,
		reflect.TypeOf(netip.AddrPort{}): true,
	}

	// The exact allowlist of fields, in declaration order. Any added field
	// fails the diff below.
	allow := map[string][]string{
		"FlowRecord":         {"Session", "Iface", "AdmittingDomain", "Dst", "Protocol", "BytesIn", "BytesOut", "Start", "End", "Duration", "CtMark", "Verdict"},
		"DnsEvent":           {"Session", "QueryName", "AdmittedIPs", "TTL", "ExpiresAt", "Decision"},
		"HttpEvent":          {"Session", "Method", "Host", "Path", "Status", "ReqBytes", "RespBytes", "Start", "Duration", "Decision"},
		"PolicyDecision":     {"Session", "Verdict", "RuleID", "PolicyLayer", "PolicyVersion", "Resource", "At"},
		"CredentialUseEvent": {"Session", "Service", "Fingerprint", "Request"},
		"SessionRef":         {"SessionID", "HostID", "Iface"},
		"HttpRequestMeta":    {"Method", "Host", "Path", "At"},
		"SpoolOverflow":      {"Session", "Dropped", "At"},
	}

	forbidden := []string{"body", "payload", "capture", "raw", "header", "content", "packet", "pcap", "dump", "value"}

	seen := map[reflect.Type]bool{}
	var walk func(path string, rt reflect.Type)
	walk = func(path string, rt reflect.Type) {
		switch rt.Kind() {
		case reflect.Slice, reflect.Array:
			if rt.Elem().Kind() == reflect.Uint8 {
				t.Errorf("%s: []byte-shaped field is payload-capable — forbidden in the metadata-only schema", path)
				return
			}
			walk(path+"[]", rt.Elem())
		case reflect.Map:
			t.Errorf("%s: map-typed field (headers-with-values shaped) is forbidden in the metadata-only schema", path)
		case reflect.Interface:
			t.Errorf("%s: interface-typed field is an opaque payload channel — forbidden", path)
		case reflect.Pointer:
			walk(path+"*", rt.Elem())
		case reflect.Struct:
			if rt.PkgPath() != selfPkg {
				if !allowedStd[rt] {
					t.Errorf("%s: non-allowlisted external struct %v could smuggle payload", path, rt)
				}
				return
			}
			if seen[rt] {
				return
			}
			seen[rt] = true
			want, ok := allow[rt.Name()]
			if !ok {
				t.Errorf("%s: struct %s reachable from an event but absent from the frozen field allowlist", path, rt.Name())
				return
			}
			var got []string
			for i := 0; i < rt.NumField(); i++ {
				got = append(got, rt.Field(i).Name)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s fields drifted from the frozen metadata-only allowlist:\n got: %v\nwant: %v", rt.Name(), got, want)
			}
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				lowerName := strings.ToLower(f.Name)
				lowerTag := strings.ToLower(string(f.Tag))
				for _, bad := range forbidden {
					if strings.Contains(lowerName, bad) {
						t.Errorf("%s.%s: field name contains forbidden payload-capable token %q", rt.Name(), f.Name, bad)
					}
					if strings.Contains(lowerTag, bad) {
						t.Errorf("%s.%s: field tag %q contains forbidden token %q", rt.Name(), f.Name, f.Tag, bad)
					}
				}
				walk(rt.Name()+"."+f.Name, f.Type)
			}
		}
	}

	for _, root := range []Event{FlowRecord{}, DnsEvent{}, HttpEvent{}, PolicyDecision{}, CredentialUseEvent{}, SpoolOverflow{}} {
		walk(fmt.Sprintf("%T", root), reflect.TypeOf(root))
	}
}

// planRef: doc 09 §6 POL-3 Done-when ("a missing-provenance event fails CI") as enforced at the LOG-1 schema
func TestPolicyDecision_RequiresProvenance(t *testing.T) {
	refA := mkRef("sess-a")
	base := validDecision(refA, VerdictDeny, "POL-1.deny.default", "evil.example", t0)

	rows := []struct {
		name      string
		mutate    func(*PolicyDecision)
		wantField string
		wantOK    bool
	}{
		{"missing_rule_id", func(d *PolicyDecision) { d.RuleID = "" }, "RuleID", false},
		{"missing_policy_layer", func(d *PolicyDecision) { d.PolicyLayer = "" }, "PolicyLayer", false},
		{"missing_policy_version", func(d *PolicyDecision) { d.PolicyVersion = "" }, "PolicyVersion", false},
		{"fully_populated", func(*PolicyDecision) {}, "", true},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			d := base
			row.mutate(&d)
			err := d.Validate()
			if row.wantOK {
				if err != nil {
					t.Errorf("complete provenance must pass Validate — 'why was this blocked?' always has a one-line answer; got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("decision missing %s must fail Validate", row.wantField)
			}
			if !strings.Contains(err.Error(), row.wantField) {
				t.Errorf("Validate error must name the missing field %q, got: %v", row.wantField, err)
			}
		})
	}
}

// planRef: doc 09 §7 LOG-1/LOG-5 (CredentialUseEvent: "credential fingerprint — never the credential") [ADVERSARIAL]
func TestCredentialUseEvent_RejectsRawSecretShapedFingerprint(t *testing.T) {
	refA := mkRef("sess-a")
	seededToken := "ghp_seededAdversaria1Token0123456789abcd"

	adversarial := []struct {
		name string
		fp   CredentialFingerprint
	}{
		{"github_token_shaped_value", CredentialFingerprint(seededToken)},
		{"arbitrary_high_entropy_not_fingerprint_format", CredentialFingerprint("9f8e7d6c5b4a39281706f5e4d3c2b1a0deadbeefcafebabe0011223344556677X")},
		// Prefix-carrying smuggles: a Validate implemented as a bare
		// HasPrefix("sha256:") check accepts all of these — each must fail
		// the FULL fingerprint format (prefix + exactly 64 lowercase hex).
		{"prefix_plus_raw_token_smuggled_behind_prefix", CredentialFingerprint(FingerprintPrefix + seededToken)},
		{"prefix_plus_63_hex_chars_too_short", CredentialFingerprint(FingerprintPrefix + strings.Repeat("ab", 31) + "c")},
		{"prefix_plus_65_hex_chars_too_long", CredentialFingerprint(FingerprintPrefix + strings.Repeat("ab", 32) + "c")},
		{"prefix_plus_64_uppercase_hex_chars", CredentialFingerprint(FingerprintPrefix + strings.Repeat("AB", 32))},
		{"prefix_plus_64_non_hex_chars", CredentialFingerprint(FingerprintPrefix + strings.Repeat("zy", 32))},
	}

	for _, row := range adversarial {
		t.Run(row.name, func(t *testing.T) {
			ev := validCredUse(refA, row.fp, t0)
			err := ev.Validate()
			if err == nil {
				t.Fatalf("a raw credential smuggled into the fingerprint field must fail Validate (fp=%q)", row.fp)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "fingerprint") {
				t.Errorf("Validate error must name the fingerprint-format violation, got: %v", err)
			}
		})
	}

	t.Run("sanctioned_fingerprint_passes", func(t *testing.T) {
		fp := mustFingerprint(t, []byte(seededToken))
		ev := validCredUse(refA, fp, t0)
		if err := ev.Validate(); err != nil {
			t.Errorf("FingerprintCredential output must pass Validate, got: %v", err)
		}
	})
}
