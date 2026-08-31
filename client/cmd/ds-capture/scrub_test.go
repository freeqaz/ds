// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/cmd/ds-capture/internal/cassette"
)

// rawishCassette builds a cassette carrying auth/volatile headers (as a live
// capture would, before scrub). It does NOT embed a real-shaped token literal
// in the source (which would trip the repo's committed-file secret scan); the
// auth header values are short synthetic placeholders. The scrub-strips test
// proves the auth HEADERS themselves are removed; the no-secret-survives test
// uses a runtime-assembled token-shaped value that scrub must reject.
func rawishCassette() *cassette.Cassette {
	c := cassette.New()
	c.Record("POST", "/v1/messages",
		map[string]any{"model": "claude-synthetic-test-1", "system": "syn",
			"messages": []any{map[string]any{"role": "user", "content": "say hi"}}},
		200,
		map[string]string{"content-type": "text/event-stream"},
		"event: message_stop\ndata: {}\n\n")
	// Record already filters headers, so inject auth/volatile headers directly
	// to simulate a cassette that still carries them (a hand-edited cassette, or
	// one produced by a tool that did not strip) — exactly what scrub defends
	// against. Values are short synthetic placeholders below the secret-scan
	// length thresholds.
	c.Interactions[0].Headers["authorization"] = "Bearer synthetic-short"
	c.Interactions[0].Headers["x-api-key"] = "synthetic-short"
	c.Interactions[0].Headers["request-id"] = "<synthetic-volatile>"
	return c
}

// TestScrubStripsAuthHeaders proves scrub removes auth/volatile headers, keeping
// only content-type (the allow-list), and reports the strip count.
func TestScrubStripsAuthHeaders(t *testing.T) {
	c := rawishCassette()
	res, err := scrubCassette(c, "synthetic", false)
	if err != nil {
		t.Fatalf("scrub: %v", err)
	}
	if res.StrippedHeaders < 3 {
		t.Errorf("expected >=3 stripped headers (auth, x-api-key, request-id), got %d", res.StrippedHeaders)
	}
	h := c.Interactions[0].Headers
	if len(h) != 1 || h["content-type"] != "text/event-stream" {
		t.Errorf("only content-type should survive, got %v", h)
	}
	for _, gone := range []string{"authorization", "x-api-key", "request-id"} {
		if _, ok := h[gone]; ok {
			t.Errorf("auth/volatile header %q survived scrub", gone)
		}
	}
}

// TestScrubAssertsNoSecretSurvives proves scrub fails loudly when a
// token-shaped value would survive anywhere in the cassette (the D50 wall). The
// secret value is assembled at runtime so the test source itself never embeds a
// committable token literal.
func TestScrubAssertsNoSecretSurvives(t *testing.T) {
	// Assemble a sk-ant-shaped value at runtime: prefix + 30 token chars.
	secret := "sk-ant-oat01-" + strings.Repeat("A", 30)
	c := cassette.New()
	// Plant the secret in a body (the response text), the worst case.
	c.Record("POST", "/v1/messages",
		map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "x"}}},
		200, map[string]string{"content-type": "text/event-stream"},
		"event: leak\ndata: "+secret+"\n\n")

	_, err := scrubCassette(c, "synthetic", true)
	if err == nil {
		t.Fatal("scrub must FAIL when a sk-ant token survives in the body")
	}
	if !strings.Contains(err.Error(), "D50 WALL VIOLATION") {
		t.Errorf("expected D50 wall violation error, got: %v", err)
	}
	// The error must NOT echo the secret value (never-log-the-secret).
	if strings.Contains(err.Error(), secret) {
		t.Errorf("scrub error leaked the secret value: %v", err)
	}
}

// TestScrubAssertsNoBearerSurvives proves a Bearer token-shaped value is caught.
func TestScrubAssertsNoBearerSurvives(t *testing.T) {
	bearer := "Bearer " + strings.Repeat("x", 50)
	c := cassette.New()
	c.Record("POST", "/v1/messages",
		map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "x"}}},
		200, map[string]string{"content-type": "text/event-stream"},
		"event: leak\ndata: "+bearer+"\n\n")
	_, err := scrubCassette(c, "synthetic", true)
	if err == nil {
		t.Fatal("scrub must FAIL when a Bearer token survives in the body")
	}
	if !strings.Contains(err.Error(), "D50 WALL VIOLATION") {
		t.Errorf("expected D50 wall violation, got: %v", err)
	}
}

// TestScrubProvenanceGate proves scrub refuses to emit a committable artifact
// unless provenance is synthetic.
func TestScrubProvenanceGate(t *testing.T) {
	// dogfood: not committable.
	if _, err := scrubCassette(rawishCassette(), "dogfood", true); err == nil {
		t.Error("scrub must refuse a committable dogfood artifact")
	}
	// partner-consented: not committable.
	if _, err := scrubCassette(rawishCassette(), "partner-consented", true); err == nil {
		t.Error("scrub must refuse a committable partner-consented artifact")
	}
	// no provenance + want committable: refused.
	if _, err := scrubCassette(rawishCassette(), "", true); err == nil {
		t.Error("scrub must refuse a committable artifact with no declared provenance")
	}
	// unknown provenance: rejected.
	if _, err := scrubCassette(rawishCassette(), "bogus", true); err == nil {
		t.Error("scrub must reject an unknown provenance value")
	}
	// synthetic + want committable: allowed.
	res, err := scrubCassette(rawishCassette(), "synthetic", true)
	if err != nil {
		t.Fatalf("synthetic should be committable: %v", err)
	}
	if !res.Committable {
		t.Error("synthetic result should be marked committable")
	}
}

// TestScrubReportOnlyNoProvenanceOK proves the report-only path (no write) does
// not require provenance — the wall still holds (auth stripped) but the
// committable gate only applies when emitting an artifact.
func TestScrubReportOnlyNoProvenanceOK(t *testing.T) {
	if _, err := scrubCassette(rawishCassette(), "", false); err != nil {
		t.Errorf("report-only scrub with no provenance should succeed: %v", err)
	}
}

// TestScrubCatchesSurvivingAuthHeaderName proves that an auth header surviving
// in the cassette (e.g. a hand-edited cassette) is itself flagged as a wall
// breach, even with a harmless value.
func TestScrubCatchesSurvivingAuthHeaderName(t *testing.T) {
	c := cassette.New()
	it := &cassette.Interaction{
		Key:        "k",
		StatusCode: 200,
		Headers:    map[string]string{"content-type": "text/event-stream"},
		Body:       "event: x\ndata: {}\n\n",
	}
	c.Add(it)
	// Inject an auth header AFTER Record so the scrub's strip pass would
	// normally remove it; we call scanSecrets directly to prove the detector
	// flags a surviving auth header name.
	it.Headers["authorization"] = "Bearer harmless"
	hits := scanSecrets(c)
	found := false
	for _, h := range hits {
		if strings.Contains(h, "authorization") {
			found = true
		}
	}
	if !found {
		t.Errorf("scanSecrets should flag a surviving authorization header, got %v", hits)
	}
}

// fixtureProvenancePredicate re-implements the per-file provenance check from
// scripts/check-fixture-provenance.sh (the validate_header function) in Go, so
// the test proves a scrub --out sidecar would pass the CI gate WITHOUT exec'ing
// the shell script or depending on jq. It mirrors the gate exactly: the first
// line of the sidecar must parse as JSON and carry
// .ds_fixture.provenance == "synthetic".
func fixtureProvenancePredicate(t *testing.T, sidecar []byte) error {
	t.Helper()
	// The gate reads `head -n 1` of the sidecar.
	first := sidecar
	if i := bytes.IndexByte(sidecar, '\n'); i >= 0 {
		first = sidecar[:i]
	}
	if len(strings.TrimSpace(string(first))) == 0 {
		return errPredicate("empty (no header record)")
	}
	var doc struct {
		DSFixture struct {
			Provenance *string `json:"provenance"`
		} `json:"ds_fixture"`
	}
	if err := json.Unmarshal(first, &doc); err != nil {
		return errPredicate("first record is not valid JSON")
	}
	if doc.DSFixture.Provenance == nil {
		return errPredicate("missing ds_fixture.provenance")
	}
	if *doc.DSFixture.Provenance != "synthetic" {
		return errPredicate("provenance=" + *doc.DSFixture.Provenance + " (only synthetic may live in git; D50)")
	}
	return nil
}

type predicateErr string

func (e predicateErr) Error() string { return string(e) }
func errPredicate(s string) error    { return predicateErr(s) }

// writeRawishCassetteFile saves a rawish cassette to a temp file and returns its
// path, so cmdScrub (which loads from disk) has an input to scrub.
func writeRawishCassetteFile(t *testing.T, dir string) string {
	t.Helper()
	in := filepath.Join(dir, "in.json")
	if err := rawishCassette().Save(in); err != nil {
		t.Fatalf("save input cassette: %v", err)
	}
	return in
}

// TestScrubOutEmitsSidecar proves that `scrub --out` writes BOTH the cassette
// and a <out>.provenance sidecar, and that the sidecar passes the Go
// re-implementation of the check-fixture-provenance predicate with seam/created/
// note populated.
func TestScrubOutEmitsSidecar(t *testing.T) {
	dir := t.TempDir()
	in := writeRawishCassetteFile(t, dir)
	out := filepath.Join(dir, "fixtures", "syn.json")

	rc := cmdScrub([]string{
		"--out", out,
		"--provenance", "synthetic",
		"--seam", "syn-seam",
		"--note", "obviously synthetic fixture",
		in,
	})
	if rc != 0 {
		t.Fatalf("cmdScrub returned %d, want 0", rc)
	}

	// Both files must exist.
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("cassette not written: %v", err)
	}
	side := out + ".provenance"
	raw, err := os.ReadFile(side)
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}

	// The sidecar must pass the gate predicate (synthetic).
	if err := fixtureProvenancePredicate(t, raw); err != nil {
		t.Fatalf("sidecar fails check-fixture-provenance predicate: %v", err)
	}

	// First line must be exactly one JSON object with the expected fields.
	first := raw
	if i := bytes.IndexByte(raw, '\n'); i >= 0 {
		first = raw[:i]
		// Exactly one JSON line: nothing but a trailing newline should follow.
		if rest := strings.TrimSpace(string(raw[i+1:])); rest != "" {
			t.Errorf("sidecar has content after the first line: %q", rest)
		}
	}
	var doc struct {
		DSFixture struct {
			Provenance string `json:"provenance"`
			Seam       string `json:"seam"`
			Created    string `json:"created"`
			Note       string `json:"note"`
		} `json:"ds_fixture"`
	}
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatalf("sidecar first line not JSON: %v", err)
	}
	if doc.DSFixture.Provenance != "synthetic" {
		t.Errorf("provenance=%q, want synthetic", doc.DSFixture.Provenance)
	}
	if doc.DSFixture.Seam != "syn-seam" {
		t.Errorf("seam=%q, want syn-seam", doc.DSFixture.Seam)
	}
	if doc.DSFixture.Note != "obviously synthetic fixture" {
		t.Errorf("note=%q not populated as given", doc.DSFixture.Note)
	}
	// created is a YYYY-MM-DD date stamp.
	if len(doc.DSFixture.Created) != len("2006-01-02") ||
		doc.DSFixture.Created[4] != '-' || doc.DSFixture.Created[7] != '-' {
		t.Errorf("created=%q is not a YYYY-MM-DD date stamp", doc.DSFixture.Created)
	}

	// Never-log-the-secret: no scrubbed/redacted credential value may appear in
	// the sidecar. The rawish input carried auth headers; none of their values
	// (nor any token shape) may leak into the provenance file.
	for _, banned := range []string{"Bearer", "authorization", "x-api-key", "synthetic-short", "redacted", "REDACTED"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("sidecar leaked %q: %q", banned, string(raw))
		}
	}
}

// TestScrubRejectsTokenShapedSeamNote proves --seam/--note carrying a
// token-shaped value are REJECTED before the provenance sidecar is written —
// the D50 never-log-the-secret invariant on these operator-supplied metadata
// fields is ENFORCED, not trusted — that neither the cassette nor the sidecar
// lands, and that the rejection error never echoes the token body.
func TestScrubRejectsTokenShapedSeamNote(t *testing.T) {
	// Assemble a token-shaped value at runtime so no full sk-ant literal is a
	// committed source string (which would trip the repo's secret scan). It
	// matches secretPatterns: sk-ant-<class>NN-<>=20 chars>.
	tokenBody := strings.Repeat("Z", 28)
	token := "sk-ant-" + "oat01-" + tokenBody

	for _, tc := range []struct {
		name string
		flag string
	}{
		{"seam", "--seam"},
		{"note", "--note"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeRawishCassetteFile(t, dir)
			out := filepath.Join(dir, "fixtures", "syn.json")

			// Capture stderr to a temp file (no io import needed) to prove the
			// rejection error never echoes the token body.
			errPath := filepath.Join(dir, "stderr.txt")
			ef, err := os.Create(errPath)
			if err != nil {
				t.Fatalf("create stderr capture: %v", err)
			}
			oldStderr := os.Stderr
			os.Stderr = ef
			rc := cmdScrub([]string{"--out", out, "--provenance", "synthetic", tc.flag, token, in})
			os.Stderr = oldStderr
			ef.Close()

			if rc == 0 {
				t.Fatalf("cmdScrub must REJECT a token-shaped %s (got rc=0)", tc.flag)
			}
			// The wall must not leave either half of the pair on disk.
			if _, err := os.Stat(out); err == nil {
				t.Errorf("cassette written despite token-shaped %s — wall breached", tc.flag)
			}
			if _, err := os.Stat(out + ".provenance"); err == nil {
				t.Errorf("sidecar written despite token-shaped %s — wall breached", tc.flag)
			}
			// never-log-the-secret: the error reports the redacted label, never bytes.
			errOut, _ := os.ReadFile(errPath)
			if bytes.Contains(errOut, []byte(tokenBody)) {
				t.Error("rejection error echoed the token body — never-log-the-secret breach")
			}
			if !bytes.Contains(errOut, []byte("value redacted")) {
				t.Errorf("rejection error should carry the redacted match label; got %q", errOut)
			}
		})
	}
}

// TestScrubDefaultSeam proves --seam defaults to "ds-capture".
func TestScrubDefaultSeam(t *testing.T) {
	dir := t.TempDir()
	in := writeRawishCassetteFile(t, dir)
	out := filepath.Join(dir, "fixtures", "syn.json")

	if rc := cmdScrub([]string{"--out", out, "--provenance", "synthetic", in}); rc != 0 {
		t.Fatalf("cmdScrub returned %d, want 0", rc)
	}
	raw, err := os.ReadFile(out + ".provenance")
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	var doc struct {
		DSFixture struct {
			Seam string `json:"seam"`
		} `json:"ds_fixture"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("sidecar not JSON: %v", err)
	}
	if doc.DSFixture.Seam != "ds-capture" {
		t.Errorf("default seam=%q, want ds-capture", doc.DSFixture.Seam)
	}
}

// TestScrubReportOnlyNoSidecar proves the report-only path (no --out) writes NO
// sidecar anywhere.
func TestScrubReportOnlyNoSidecar(t *testing.T) {
	dir := t.TempDir()
	in := writeRawishCassetteFile(t, dir)

	if rc := cmdScrub([]string{in}); rc != 0 {
		t.Fatalf("cmdScrub (report-only) returned %d, want 0", rc)
	}
	// No .provenance file should exist anywhere under the temp dir.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".provenance") {
			t.Errorf("report-only emitted a sidecar: %s", e.Name())
		}
	}
}

// TestScrubSidecarWriteFailureIsHardError proves a sidecar-write failure makes
// cmdScrub fail (return non-zero) AND leaves NO cassette on disk: the wall must
// never half-emit a cassette without its sidecar. We force the failure by
// pre-creating a DIRECTORY at the sidecar path, so os.WriteFile cannot write it.
// Because the sidecar is written before the cassette, the cassette must never
// have been created.
func TestScrubSidecarWriteFailureIsHardError(t *testing.T) {
	dir := t.TempDir()
	in := writeRawishCassetteFile(t, dir)
	out := filepath.Join(dir, "syn.json")

	// Pre-create a directory exactly where the sidecar file would go.
	if err := os.Mkdir(out+".provenance", 0o755); err != nil {
		t.Fatal(err)
	}

	if rc := cmdScrub([]string{"--out", out, "--provenance", "synthetic", in}); rc == 0 {
		t.Fatal("cmdScrub must FAIL when the provenance sidecar cannot be written")
	}
	// No orphan cassette: the scrubbed cassette must not exist without a sidecar.
	if _, err := os.Stat(out); err == nil {
		t.Fatalf("cassette %s was left on disk despite a sidecar-write failure (half-emission)", out)
	}
}

// TestScrubCassetteWriteFailureCleansUpSidecar proves that if the sidecar lands
// but the cassette write then fails, cmdScrub fails (non-zero) AND removes the
// orphan sidecar — neither half of the pair survives a failed scrub. We force
// the cassette write to fail by pre-creating a DIRECTORY at the --out path while
// leaving the sidecar path writable.
func TestScrubCassetteWriteFailureCleansUpSidecar(t *testing.T) {
	dir := t.TempDir()
	in := writeRawishCassetteFile(t, dir)
	out := filepath.Join(dir, "syn.json")

	// Pre-create a directory exactly where the cassette file would go, so
	// cas.Save fails while the sidecar (out+".provenance") still writes cleanly.
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}

	if rc := cmdScrub([]string{"--out", out, "--provenance", "synthetic", in}); rc == 0 {
		t.Fatal("cmdScrub must FAIL when the cassette cannot be written")
	}
	// The orphan sidecar must have been cleaned up: no lone .provenance survives.
	if _, err := os.Stat(out + ".provenance"); err == nil {
		t.Fatalf("orphan sidecar %s.provenance was left after a cassette-write failure", out)
	}
}

// TestWriteProvenanceSidecarHardError unit-tests the helper directly: a write to
// an unwritable path is a hard error returned to the caller.
func TestWriteProvenanceSidecarHardError(t *testing.T) {
	dir := t.TempDir()
	// A path whose parent is a regular file cannot be created.
	notADir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(notADir, "nested.json.provenance")
	if err := writeProvenanceSidecar(bad, "ds-capture", "", "2026-01-01"); err == nil {
		t.Fatal("writeProvenanceSidecar must return an error for an unwritable path")
	}
}

// TestWriteProvenanceSidecarSingleLineSynthetic proves the helper emits exactly
// one JSON line that always declares synthetic provenance and a YYYY-MM-DD
// created stamp, and carries no secret-shaped value.
func TestWriteProvenanceSidecarSingleLineSynthetic(t *testing.T) {
	dir := t.TempDir()
	side := filepath.Join(dir, "c.json.provenance")
	if err := writeProvenanceSidecar(side, "ds-capture", "synthetic note", "2026-01-01"); err != nil {
		t.Fatalf("writeProvenanceSidecar: %v", err)
	}
	raw, err := os.ReadFile(side)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixtureProvenancePredicate(t, raw); err != nil {
		t.Errorf("helper output fails the gate predicate: %v", err)
	}
	// Exactly one line (single trailing newline).
	if strings.Count(string(raw), "\n") != 1 || !strings.HasSuffix(string(raw), "\n") {
		t.Errorf("sidecar must be exactly one JSON line + newline, got %q", string(raw))
	}
}

// scrubOnce runs `scrub --out` for the given created stamp into a fresh temp
// dir and returns the sidecar bytes. Each call uses its own input + output so
// the two runs share nothing on disk — only the inputs (cassette content +
// --created) match, which is exactly what byte-stability must depend on.
func scrubOnce(t *testing.T, createdFlag string) []byte {
	t.Helper()
	dir := t.TempDir()
	in := writeRawishCassetteFile(t, dir)
	out := filepath.Join(dir, "fixtures", "syn.json")
	args := []string{"--out", out, "--provenance", "synthetic",
		"--seam", "syn-seam", "--note", "obviously synthetic fixture"}
	if createdFlag != "" {
		args = append(args, "--created", createdFlag)
	}
	args = append(args, in)
	if rc := cmdScrub(args); rc != 0 {
		t.Fatalf("cmdScrub returned %d, want 0", rc)
	}
	raw, err := os.ReadFile(out + ".provenance")
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	return raw
}

// TestScrubCreatedOverrideIsByteStable proves the core reproducibility property:
// two independent scrubs of the same input with the same --created stamp yield
// BYTE-IDENTICAL sidecar bytes, so a committed sidecar can be golden-diffed.
func TestScrubCreatedOverrideIsByteStable(t *testing.T) {
	const stamp = "2026-01-02"
	first := scrubOnce(t, stamp)
	second := scrubOnce(t, stamp)
	if !bytes.Equal(first, second) {
		t.Fatalf("sidecar bytes differ across re-scrubs with the same --created:\n  first=%q\n second=%q",
			string(first), string(second))
	}
	// The override must actually land in the file (not silently ignored).
	var doc struct {
		DSFixture struct {
			Created string `json:"created"`
		} `json:"ds_fixture"`
	}
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatalf("sidecar not JSON: %v", err)
	}
	if doc.DSFixture.Created != stamp {
		t.Errorf("created=%q, want the --created override %q", doc.DSFixture.Created, stamp)
	}
	// Never-log-the-secret: the byte-stable sidecar still leaks nothing.
	for _, banned := range []string{"Bearer", "authorization", "x-api-key", "synthetic-short", "redacted", "REDACTED"} {
		if strings.Contains(string(first), banned) {
			t.Errorf("sidecar leaked %q: %q", banned, string(first))
		}
	}
}

// TestScrubCreatedFromSourceDateEpoch proves a SOURCE_DATE_EPOCH-style env feeds
// the sidecar stamp when --created is unset, and is interpreted in UTC. The
// epoch below (2021-01-02 00:00:00 UTC) sits well inside a single UTC day so the
// expected date is unambiguous regardless of the test host's local zone.
func TestScrubCreatedFromSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1609545600") // 2021-01-02T00:00:00Z
	dir := t.TempDir()
	in := writeRawishCassetteFile(t, dir)
	out := filepath.Join(dir, "fixtures", "syn.json")
	if rc := cmdScrub([]string{"--out", out, "--provenance", "synthetic", in}); rc != 0 {
		t.Fatalf("cmdScrub returned %d, want 0", rc)
	}
	raw, err := os.ReadFile(out + ".provenance")
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	var doc struct {
		DSFixture struct {
			Created string `json:"created"`
		} `json:"ds_fixture"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("sidecar not JSON: %v", err)
	}
	if doc.DSFixture.Created != "2021-01-02" {
		t.Errorf("created=%q, want 2021-01-02 from SOURCE_DATE_EPOCH (UTC)", doc.DSFixture.Created)
	}
}

// TestScrubCreatedDefaultIsTodayUTC proves the default (no --created, no
// SOURCE_DATE_EPOCH) preserves the original behavior: today's UTC date.
func TestScrubCreatedDefaultIsTodayUTC(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "") // ensure the env path is not taken
	dir := t.TempDir()
	in := writeRawishCassetteFile(t, dir)
	out := filepath.Join(dir, "fixtures", "syn.json")
	if rc := cmdScrub([]string{"--out", out, "--provenance", "synthetic", in}); rc != 0 {
		t.Fatalf("cmdScrub returned %d, want 0", rc)
	}
	raw, err := os.ReadFile(out + ".provenance")
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	var doc struct {
		DSFixture struct {
			Created string `json:"created"`
		} `json:"ds_fixture"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("sidecar not JSON: %v", err)
	}
	if doc.DSFixture.Created != time.Now().UTC().Format("2006-01-02") {
		t.Errorf("default created=%q, want today's UTC date", doc.DSFixture.Created)
	}
}

// TestScrubCreatedRejectsMalformed proves a malformed --created fails fast with
// a clean non-zero exit and writes NO sidecar/cassette (the all-or-nothing
// ordering is preserved: a bad stamp never produces a partial artifact).
func TestScrubCreatedRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"2026-13-40", "not-a-date", "20260102", "2026-1-2", "2026-01-02 ", "0000-00-00"} {
		dir := t.TempDir()
		in := writeRawishCassetteFile(t, dir)
		out := filepath.Join(dir, "fixtures", "syn.json")
		rc := cmdScrub([]string{"--out", out, "--provenance", "synthetic", "--created", bad, in})
		if rc == 0 {
			t.Errorf("cmdScrub accepted malformed --created %q (want non-zero)", bad)
		}
		// No partial artifact: neither the cassette nor the sidecar may exist.
		if _, err := os.Stat(out); err == nil {
			t.Errorf("malformed --created %q left a cassette on disk", bad)
		}
		if _, err := os.Stat(out + ".provenance"); err == nil {
			t.Errorf("malformed --created %q left a sidecar on disk", bad)
		}
	}
}

// TestResolveCreatedUnit unit-tests the stamp resolver directly across its three
// branches and its validation, without touching the filesystem.
func TestResolveCreatedUnit(t *testing.T) {
	// (1) explicit override wins, even when an env is also set.
	if got, err := resolveCreated("2026-03-04", "1609545600"); err != nil || got != "2026-03-04" {
		t.Errorf("override: got %q, err %v; want 2026-03-04", got, err)
	}
	// (2) env used when override empty, interpreted in UTC.
	if got, err := resolveCreated("", "1609545600"); err != nil || got != "2021-01-02" {
		t.Errorf("env: got %q, err %v; want 2021-01-02", got, err)
	}
	// (3) default = today UTC when both empty.
	if got, err := resolveCreated("", ""); err != nil || got != time.Now().UTC().Format("2006-01-02") {
		t.Errorf("default: got %q, err %v; want today UTC", got, err)
	}
	// Malformed override is a clean error.
	if _, err := resolveCreated("2026-13-99", ""); err == nil {
		t.Error("resolveCreated must reject an impossible date")
	}
	// Malformed env (non-numeric) is a clean error.
	if _, err := resolveCreated("", "not-an-epoch"); err == nil {
		t.Error("resolveCreated must reject a non-numeric SOURCE_DATE_EPOCH")
	}
	// Error text never echoes a token shape (it only carries the operator stamp).
	_, err := resolveCreated("2026-99-99", "")
	if err != nil && (strings.Contains(err.Error(), "Bearer") || strings.Contains(err.Error(), "sk-ant-")) {
		t.Errorf("resolveCreated error unexpectedly carries a token shape: %v", err)
	}
}

// findCheckFixtureProvenanceScript walks up from the test's working directory
// (the package dir client/cmd/ds-capture) looking for
// scripts/check-fixture-provenance.sh. Returns "" if not found (caller skips).
func findCheckFixtureProvenanceScript() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		cand := filepath.Join(dir, "scripts", "check-fixture-provenance.sh")
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// TestScrubShellGateEndToEnd drives `scrub --out` into a temp fixtures/-shaped
// layout and execs the REAL scripts/check-fixture-provenance.sh against it,
// closing the Go-predicate-vs-shell-gate drift risk.
//
// It is ENV-GATED on DS_SCRUB_SHELLGATE=1 and skips cleanly (t.Skip — never a
// failure) when the gate is unarmed, the script is absent, or no POSIX shell is
// available. The ungated `go test` run therefore depends on neither a shell nor
// the script being present.
//
// The script is invoked in FIXTURE_SCAN_ROOT mode (filesystem walk) with the
// git-side secret scan disabled (SECRET_SCAN_FILES=""), so the real per-file
// validate_header check runs over the sidecar this unit produced, in a temp dir
// that is not a git repo.
func TestScrubShellGateEndToEnd(t *testing.T) {
	if os.Getenv("DS_SCRUB_SHELLGATE") != "1" {
		t.Skip("DS_SCRUB_SHELLGATE != 1: shell-gate proof not armed (ungated runs do not need a shell)")
	}
	script := findCheckFixtureProvenanceScript()
	if script == "" {
		t.Skip("scripts/check-fixture-provenance.sh not found: skipping shell-gate proof")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX sh on PATH: skipping shell-gate proof")
	}

	// Build a fixtures/-shaped layout the script's directory walk understands:
	//   <root>/fixtures/PROVENANCE.md       (directory-level contract, check 0)
	//   <root>/fixtures/syn.json            (non-NDJSON fixture)
	//   <root>/fixtures/syn.json.provenance (sidecar scrub --out wrote)
	root := t.TempDir()
	fixturesDir := filepath.Join(root, "fixtures")
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The directory-level contract file (content is synthetic boilerplate, no
	// secret-shaped value — never-log-the-secret holds for the test's own bytes).
	if err := os.WriteFile(filepath.Join(fixturesDir, "PROVENANCE.md"),
		[]byte("# synthetic fixtures (test)\nif it is in git, it is synthetic.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	in := writeRawishCassetteFile(t, root)
	out := filepath.Join(fixturesDir, "syn.json")
	if rc := cmdScrub([]string{"--out", out, "--provenance", "synthetic",
		"--seam", "shellgate", "--created", "2026-01-02", in}); rc != 0 {
		t.Fatalf("cmdScrub --out returned %d, want 0", rc)
	}

	// Exec the real gate over the temp layout. FIXTURE_SCAN_ROOT triggers the
	// filesystem-walk branch; SECRET_SCAN_FILES="" disables the git-ls-files
	// secret scan (there is no git repo here, and the values are synthetic).
	cmd := exec.Command(shell, script)
	cmd.Env = append(os.Environ(),
		"FIXTURE_SCAN_ROOT="+root,
		"SECRET_SCAN_FILES=",
	)
	combined, runErr := cmd.CombinedOutput()
	if runErr != nil {
		t.Fatalf("real check-fixture-provenance.sh REJECTED a scrub --out sidecar it should accept: %v\n%s",
			runErr, combined)
	}
	// The gate must NOT have echoed any secret-shaped value into its output
	// (never-log-the-secret holds for the shelled-out gate's stdout/stderr too).
	for _, banned := range []string{"Bearer", "sk-ant-", "synthetic-short"} {
		if bytes.Contains(combined, []byte(banned)) {
			t.Errorf("gate output leaked %q:\n%s", banned, combined)
		}
	}

	// Negative half (same exec path, proves the gate is non-vacuous here):
	// flip the sidecar to a non-synthetic provenance and confirm the REAL gate
	// now REJECTS it. This keeps the Go re-implementation honest against the
	// shell's actual validate_header.
	bad := `{"ds_fixture":{"provenance":"dogfood","seam":"shellgate","created":"2026-01-02","note":""}}` + "\n"
	if err := os.WriteFile(out+".provenance", []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(shell, script)
	cmd.Env = append(os.Environ(), "FIXTURE_SCAN_ROOT="+root, "SECRET_SCAN_FILES=")
	if out2, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("real gate ACCEPTED a non-synthetic sidecar it must reject:\n%s", out2)
	}
}
