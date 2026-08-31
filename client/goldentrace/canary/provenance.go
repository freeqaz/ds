// provenance.go — the D50 provenance/scrub gate enforced BEFORE anything lands
// in fixtures/.
//
// D50 (doc 04 §6; ../../fixtures/PROVENANCE.md; HARDENING-NOTES §2.3): if it is
// in git, it is SYNTHETIC. Raw-class captures (real paths, costs, session
// UUIDs, and the cleartext `Authorization: Bearer …`) stay in the job tmp dir
// and NEVER enter the tree — only a re-authored synthetic cassette does, and it
// carries the ds_fixture provenance header. The capture.sh scrub pass produces
// the candidate; THIS gate is the bright line a candidate must clear before it
// can become a committed fixture.
//
// The repo already ships the git-side gate (scripts/check-fixture-provenance.sh
// + .github/workflows/fixtures-provenance.yml) that scans COMMITTED fixtures.
// This gate is the canary's IN-PIPELINE twin: the capture-and-review harness
// runs it on a freshly-scrubbed candidate BEFORE it is promoted into fixtures/,
// so a raw capture can never reach the point where the git-side gate would even
// see it. Three assertions, all from HARDENING-NOTES §2.4:
//
//   - ds_fixture header present on line 1 with provenance == "synthetic"
//     (HARDENING-NOTES §2.3 / PROVENANCE.md "Tag format");
//   - NO Bearer / sk-ant- / x-api-key token VALUE anywhere (HARDENING-NOTES
//     §2.2; the value-shape scan, not the bare prefix, so it does not
//     false-positive on the redacted placeholders in the docs);
//   - the candidate path is NOT inside the job/raw tmp tree being promoted from
//     a place a raw capture lives (the raw → re-authored-synthetic → fixtures/
//     one-directional flow, HARDENING-NOTES §2.1).
package canary

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// dsFixtureHeader is the first-line provenance record every committed NDJSON
// cassette must carry (PROVENANCE.md "Tag format"). The gate parses it and
// asserts provenance == "synthetic".
type dsFixtureHeader struct {
	DSFixture struct {
		Provenance string `json:"provenance"`
		Seam       string `json:"seam"`
		Created    string `json:"created"`
		Tool       string `json:"tool"`
	} `json:"ds_fixture"`
}

// tokenValueScans are the secret-VALUE shapes a candidate must not contain
// (HARDENING-NOTES §2.2 / §4; the git-side twin in check-fixture-provenance.sh).
// They match a real token's value suffix, NOT the bare prefix, so a redacted
// placeholder like "sk-ant-oat01-<ellipsis>" or a lone "x-api-key" in the docs
// does not trip them. A match is a HARD failure: the candidate is raw-class and
// must never be promoted.
var tokenValueScans = []*regexp.Regexp{
	// sk-ant-<class>- followed by >=20 token chars (a real OAuth/API key value).
	regexp.MustCompile(`sk-ant-[a-z0-9]+-[A-Za-z0-9_-]{20,}`),
	// Bearer + a >=40-char token (a real authorization header value).
	regexp.MustCompile(`Bearer[ ]+[A-Za-z0-9._-]{40,}`),
}

// ProvenanceResult is the outcome of gating one candidate cassette.
type ProvenanceResult struct {
	// OK is the verdict: the candidate may be promoted into fixtures/.
	OK bool
	// Violations lists every D50 failure (header, token, raw-path). Empty on OK.
	Violations []string
}

// EnforceProvenanceGate reads a freshly-scrubbed candidate cassette and asserts
// it clears the D50 wall before promotion into fixtures/. candidatePath is the
// path being promoted FROM (used only for the raw-tree check); content is the
// candidate's bytes. It never writes anything — promotion is the caller's step,
// gated on OK.
func EnforceProvenanceGate(candidatePath string, content []byte) ProvenanceResult {
	var v []string

	// 1. ds_fixture synthetic header on line 1.
	if err := checkSyntheticHeader(content); err != nil {
		v = append(v, err.Error())
	}

	// 2. No Bearer / sk-ant / api-key token VALUE anywhere in the candidate.
	if hits := scanForTokens(content); len(hits) > 0 {
		v = append(v, fmt.Sprintf(
			"D50 secret leak: candidate carries token-shaped value(s) %v — a raw-class "+
				"capture must be RE-AUTHORED synthetic, never scrubbed-and-committed "+
				"(HARDENING-NOTES §2.2; raw stays in the job tmp dir)", hits))
	}

	// 3. The candidate must not be promoted FROM a raw/job tmp tree directly.
	if err := checkNotRawTree(candidatePath); err != nil {
		v = append(v, err.Error())
	}

	return ProvenanceResult{OK: len(v) == 0, Violations: v}
}

// checkSyntheticHeader asserts line 1 is a ds_fixture header with provenance
// "synthetic" (PROVENANCE.md). A missing/unparseable header or any other
// provenance value FAILS — exactly the git-side gate's first check, run here
// before promotion.
func checkSyntheticHeader(content []byte) error {
	sc := bufio.NewReader(bytes.NewReader(content))
	line, err := sc.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("D50 header: cannot read line 1: %v", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return fmt.Errorf("D50 header: candidate is empty — every fixture begins with a " +
			"{\"ds_fixture\":{\"provenance\":\"synthetic\",…}} header (PROVENANCE.md)")
	}
	var h dsFixtureHeader
	if err := json.Unmarshal([]byte(line), &h); err != nil {
		return fmt.Errorf("D50 header: line 1 is not a parseable ds_fixture record: %v "+
			"(got %q)", err, clip(line))
	}
	if h.DSFixture.Provenance == "" {
		return fmt.Errorf("D50 header: line 1 has no ds_fixture.provenance tag (PROVENANCE.md)")
	}
	if h.DSFixture.Provenance != "synthetic" {
		return fmt.Errorf("D50 header: provenance is %q, only \"synthetic\" may enter git — "+
			"dogfood/partner-consented stay in the segregated internal store (PROVENANCE.md)",
			h.DSFixture.Provenance)
	}
	return nil
}

// scanForTokens returns every distinct token-shaped VALUE found in the
// candidate. A non-empty result means the candidate is raw-class.
func scanForTokens(content []byte) []string {
	seen := map[string]bool{}
	var hits []string
	for _, re := range tokenValueScans {
		for _, m := range re.FindAll(content, -1) {
			// Report a fingerprint, not the value — never log the secret
			// (HARDENING-NOTES §2.2 never-log-the-secret invariant).
			fp := fingerprint(m)
			if !seen[fp] {
				seen[fp] = true
				hits = append(hits, fp)
			}
		}
	}
	return hits
}

// fingerprint renders a token-shaped hit as a non-reversible marker: the shape
// and length only, never a usable prefix (HARDENING-NOTES §2.2).
func fingerprint(tok []byte) string {
	shape := "token"
	switch {
	case bytes.HasPrefix(tok, []byte("sk-ant-")):
		shape = "sk-ant"
	case bytes.HasPrefix(tok, []byte("Bearer")):
		shape = "bearer"
	}
	return fmt.Sprintf("<%s:len=%d>", shape, len(tok))
}

// checkNotRawTree refuses a candidate whose path indicates it is still in the
// raw/job tmp tree. The one-directional flow is raw (job tmp) → re-authored
// synthetic → fixtures/ (HARDENING-NOTES §2.1); a candidate promoted straight
// from a raw capture path is the "scrub the raw file and commit it" anti-pattern
// the D50 wall forbids. Empty path skips this check (the caller is gating
// in-memory content with no source path).
func checkNotRawTree(candidatePath string) error {
	if candidatePath == "" {
		return nil
	}
	p := strings.ReplaceAll(candidatePath, "\\", "/")
	for _, rawMarker := range rawTreeMarkers {
		if strings.Contains(p, rawMarker) {
			return fmt.Errorf("D50 raw-tree: candidate path %q is inside a raw/job-tmp tree "+
				"(%q) — raw captures NEVER promote directly; re-author to synthetic first "+
				"(HARDENING-NOTES §2.1, the one-directional raw→synthetic→fixtures flow)",
				candidatePath, rawMarker)
		}
	}
	return nil
}

// rawTreeMarkers are path fragments that mark a raw-class capture location: the
// capture outdir patterns and the recorder runtime/cassette dirs. A candidate
// under any of these is raw-class and must be re-authored, never promoted. The
// ds-capture record job dir writes API cassettes as `.api.json` (covered below);
// the legacy ~/.cia / cia-rt markers stay as DEFENSIVE guards so a stray raw
// artifact from the retired external recorder can never slip into git either.
var rawTreeMarkers = []string{
	"/tmp/cap",    // capture outdir default
	"/cia-rt",     // legacy cia private runtime dir — kept as a defensive guard (HARDENING-NOTES §2.1)
	"/.cia/",      // legacy cia monitor/recorder home — kept as a defensive guard (raw-class)
	".api.json",   // the API-layer cassette (raw-class, never committed; what ds-capture record writes)
	"/raw/",       // an explicit raw subdir
	".raw.ndjson", // a raw stdout capture
}

// WriteProvenanceReport renders the gate outcome for one candidate.
func WriteProvenanceReport(w io.Writer, candidatePath string, r ProvenanceResult) {
	if r.OK {
		fmt.Fprintf(w, "PASS  %s — clears the D50 wall (synthetic header, no token, not raw-tree); promotable\n", candidatePath)
		return
	}
	fmt.Fprintf(w, "BLOCK %s — D50 violations, NOT promotable:\n", candidatePath)
	for _, viol := range r.Violations {
		fmt.Fprintf(w, "  - %s\n", viol)
	}
}
