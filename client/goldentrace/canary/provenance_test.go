// provenance_test.go — proves the D50 provenance/scrub gate is enforced and
// NON-VACUOUS: a clean synthetic candidate passes, and each D50 violation
// (missing/wrong header, a token-shaped VALUE, a raw-tree path) is BLOCKED
// before fixtures/ landing. The token scan must miss the redacted placeholders
// that legitimately live in the docs (HARDENING-NOTES §2.2 / §4).
package canary

import (
	"strings"
	"testing"
)

const syntheticHeader = `{"ds_fixture":{"provenance":"synthetic","seam":"attach.cc-wire","created":"2026-06-12","tool":"goldentrace"}}`

// a clean synthetic candidate: header + a couple of innocuous NDJSON lines.
func cleanCandidate() []byte {
	return []byte(syntheticHeader + "\n" +
		`{"type":"system","subtype":"init","session_id":"f24b8a07-0000-0000-0000-000000000001"}` + "\n" +
		`{"type":"assistant","message":{"content":[{"type":"text","text":"PONG"}]}}` + "\n")
}

func TestProvenanceGatePassesCleanSynthetic(t *testing.T) {
	r := EnforceProvenanceGate("fixtures/new-scenario.cc-wire.ndjson", cleanCandidate())
	if !r.OK {
		t.Fatalf("clean synthetic candidate was BLOCKED: %v", r.Violations)
	}
}

func TestProvenanceGateBlocksMissingHeader(t *testing.T) {
	noHeader := []byte(`{"type":"assistant","message":{"content":[{"type":"text","text":"PONG"}]}}` + "\n")
	r := EnforceProvenanceGate("fixtures/x.cc-wire.ndjson", noHeader)
	if r.OK {
		t.Fatal("a candidate with no ds_fixture header was allowed — D50 header gate is vacuous")
	}
	assertViolation(t, r, "header")
}

func TestProvenanceGateBlocksNonSyntheticProvenance(t *testing.T) {
	dogfood := strings.Replace(syntheticHeader, `"provenance":"synthetic"`, `"provenance":"dogfood"`, 1)
	candidate := []byte(dogfood + "\n" + `{"type":"system"}` + "\n")
	r := EnforceProvenanceGate("fixtures/x.cc-wire.ndjson", candidate)
	if r.OK {
		t.Fatal("a dogfood-tagged candidate was allowed into the git-side flow — only synthetic may enter")
	}
	assertViolation(t, r, "synthetic")
}

// tokenBody is 50 synthetic token chars assembled at RUNTIME from harmless
// pieces, so this SOURCE file never carries a literal value that the repo's
// git-side secret scan (scripts/check-fixture-provenance.sh) would flag. The
// gate under test sees the ASSEMBLED value at runtime — the scan bites on that,
// not on a committed literal.
func tokenBody() string {
	return strings.Repeat("ab12CD34", 7)[:50] // 50 [A-Za-z0-9] chars, built, not literal
}

// TestProvenanceGateBlocksBearerToken proves the secret VALUE scan bites: a
// candidate carrying a real-shaped Bearer token is BLOCKED, and the report
// fingerprints the token (never logs the value). The token is assembled at
// runtime (tokenBody) so the literal never lands in git.
func TestProvenanceGateBlocksBearerToken(t *testing.T) {
	body := tokenBody() // >= the 40-char Bearer threshold
	leak := []byte(syntheticHeader + "\n" +
		`{"headers":{"authorization":"Bearer ` + body + `"}}` + "\n")
	r := EnforceProvenanceGate("fixtures/x.cc-wire.ndjson", leak)
	if r.OK {
		t.Fatal("a Bearer-token-shaped candidate was allowed — the D50 secret scan is vacuous")
	}
	assertViolation(t, r, "secret leak")
	// never-log-the-secret: the report must carry a fingerprint, not the value.
	joined := strings.Join(r.Violations, " ")
	if strings.Contains(joined, body[:16]) {
		t.Errorf("violation report leaked the token value (never-log-the-secret): %s", joined)
	}
	if !strings.Contains(joined, "<bearer:len=") {
		t.Errorf("violation report should fingerprint the token shape, got: %s", joined)
	}
}

// TestProvenanceGateBlocksSkAntToken proves the sk-ant value scan bites. The
// token value is assembled at runtime so no matching literal is committed.
func TestProvenanceGateBlocksSkAntToken(t *testing.T) {
	// "sk-ant-" + "<class>NN-" + >=20 token chars, assembled at runtime.
	skant := "sk-" + "ant-" + "oat" + "01-" + tokenBody()[:30]
	leak := []byte(syntheticHeader + "\n" +
		`{"x-api-key":"` + skant + `"}` + "\n")
	r := EnforceProvenanceGate("fixtures/x.cc-wire.ndjson", leak)
	if r.OK {
		t.Fatal("an sk-ant-token-shaped candidate was allowed — the D50 secret scan is vacuous")
	}
	assertViolation(t, r, "secret leak")
}

// TestProvenanceGateMissesRedactedPlaceholders proves the scan does NOT
// false-positive on the redacted placeholders that legitimately appear in the
// goldentrace docs (HARDENING-NOTES §2.2 / §4): a bare "sk-ant-oat01-…" prefix,
// a lone "x-api-key", "Bearer …" with no token suffix. A clean candidate that
// MENTIONS these prefixes (no value suffix) must still pass on the token scan.
func TestProvenanceGateMissesRedactedPlaceholders(t *testing.T) {
	doc := []byte(syntheticHeader + "\n" +
		`{"note":"the bearer is Authorization: Bearer sk-ant-oat01-… and x-api-key on an API box"}` + "\n")
	r := EnforceProvenanceGate("fixtures/x.cc-wire.ndjson", doc)
	for _, v := range r.Violations {
		if strings.Contains(v, "secret leak") {
			t.Errorf("the token scan false-positived on a redacted placeholder: %s", v)
		}
	}
}

// TestProvenanceGateBlocksRawTreePath proves the raw → synthetic → fixtures
// one-directional flow: a candidate promoted directly from a raw/job-tmp tree
// path is BLOCKED even if its content is clean (HARDENING-NOTES §2.1).
func TestProvenanceGateBlocksRawTreePath(t *testing.T) {
	for _, rawPath := range []string{
		"/home/op/tmp/cap/baseline.ndjson",
		"/work/job/cia-rt/flow.json",
		"/home/op/.cia/sessions/x.api.json",
		"/jobdir/baseline.api.json",
	} {
		r := EnforceProvenanceGate(rawPath, cleanCandidate())
		if r.OK {
			t.Errorf("candidate promoted directly from raw-tree path %q was allowed — "+
				"raw must be re-authored to synthetic first (D50)", rawPath)
		}
	}
}

// TestProvenanceGateAllowsCleanFixturePath confirms a normal fixtures/ path with
// clean content is not falsely flagged by the raw-tree check.
func TestProvenanceGateAllowsCleanFixturePath(t *testing.T) {
	r := EnforceProvenanceGate("client/fixtures/canary-baseline.cc-wire.ndjson", cleanCandidate())
	if !r.OK {
		t.Fatalf("a clean candidate at a normal fixtures path was BLOCKED: %v", r.Violations)
	}
}

func assertViolation(t *testing.T, r ProvenanceResult, substr string) {
	t.Helper()
	for _, v := range r.Violations {
		if strings.Contains(v, substr) {
			return
		}
	}
	t.Errorf("expected a violation containing %q, got: %v", substr, r.Violations)
}
