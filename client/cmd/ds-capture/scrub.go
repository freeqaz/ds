// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dream-serpent/dream-serpent/client/cmd/ds-capture/internal/cassette"
)

// validProvenance is the D50 provenance tag set. Only `synthetic` may become a
// committable artifact; `dogfood`/`partner-consented` live in the segregated
// internal store and enter git solely by being re-authored as synthetic
// (HARDENING-NOTES.md §2.3 / fixtures/PROVENANCE.md).
var validProvenance = map[string]bool{
	"synthetic":         true,
	"dogfood":           true,
	"partner-consented": true,
}

// secretPatterns are the raw-credential shapes that must NEVER survive a scrub
// anywhere in the cassette (HARDENING-NOTES.md §2.2 / §4). They target real
// token *values* (a token body), never the bare redacted prefixes that appear
// in docs, so a scrubbed/synthetic cassette does not false-positive.
var secretPatterns = []*regexp.Regexp{
	// sk-ant-<class>NN- followed by >=20 token chars.
	regexp.MustCompile(`sk-ant-(oat|api|sid|adm|art|key)[0-9]{2}-[A-Za-z0-9_-]{20,}`),
	// Bearer <>=40-char token>.
	regexp.MustCompile(`Bearer[ ]+[A-Za-z0-9_.\-]{40,}`),
}

// scrubResult reports what a scrub did, for the test and the human summary.
type scrubResult struct {
	StrippedHeaders int
	Interactions    int
	Provenance      string
	Committable     bool
}

// cmdScrub enforces the D50 wall on a cassette and (optionally) writes a
// scrubbed copy. It refuses to emit a committable artifact unless the
// provenance is `synthetic`.
func cmdScrub(args []string) int {
	fs := flag.NewFlagSet("scrub", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "write the scrubbed cassette here (default: in-place report only, no write)")
	provenance := fs.String("provenance", "", "declared provenance: synthetic|dogfood|partner-consented (required to write)")
	seam := fs.String("seam", "ds-capture", "seam tag recorded in the <out>.provenance sidecar")
	note := fs.String("note", "", "free-text note recorded in the <out>.provenance sidecar")
	created := fs.String("created", "", "UTC date stamp (YYYY-MM-DD) for the <out>.provenance sidecar; "+
		"set this (or SOURCE_DATE_EPOCH) for byte-stable re-scrubs (default: today UTC)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: ds-capture scrub <cassette> [--out PATH --provenance synthetic [--seam TAG --note TEXT --created YYYY-MM-DD]]\n")
		fmt.Fprintf(os.Stderr, "\nEnforces the D50 wall: strips auth/volatile headers (keeps content-type),\n")
		fmt.Fprintf(os.Stderr, "asserts no Bearer/sk-ant/x-api-key survives, and refuses to emit a\n")
		fmt.Fprintf(os.Stderr, "committable artifact unless --provenance synthetic. When --out is set,\n")
		fmt.Fprintf(os.Stderr, "also writes a <out>.provenance sidecar so the fixture-provenance gate passes.\n")
		fmt.Fprintf(os.Stderr, "The sidecar's `created` stamp defaults to today (UTC); pass --created\n")
		fmt.Fprintf(os.Stderr, "YYYY-MM-DD (or set SOURCE_DATE_EPOCH) so re-scrubbing the same input yields\n")
		fmt.Fprintf(os.Stderr, "byte-identical sidecar bytes (reproducible builds).\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Resolve the sidecar's `created` stamp before touching the cassette so a
	// malformed override fails fast with a clean error and writes nothing.
	createdStamp, err := resolveCreated(*created, os.Getenv("SOURCE_DATE_EPOCH"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture scrub: %v\n", err)
		return 2
	}

	// Reject token-shaped --seam/--note BEFORE they can reach the provenance
	// sidecar. scanSecrets covers cassette content (the real secret source) but
	// not these operator-supplied free-text fields, so the sidecar's
	// never-log-the-secret guarantee for them is ENFORCED here, not merely
	// trusted. The error names the field + a redacted label only, never the
	// token bytes (HARDENING-NOTES.md §2.2). Fail-fast: no cassette is touched.
	for _, f := range []struct{ name, val string }{{"seam", *seam}, {"note", *note}} {
		if err := scanMetaSecret(f.name, f.val); err != nil {
			fmt.Fprintf(os.Stderr, "ds-capture scrub: %v\n", err)
			return 2
		}
	}

	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "ds-capture scrub: exactly one cassette path is required")
		fs.Usage()
		return 2
	}
	path := rest[0]

	cas, err := cassette.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture scrub: %v\n", err)
		return 1
	}

	res, err := scrubCassette(cas, *provenance, *out != "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-capture scrub: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "ds-capture scrub: %d interaction(s), %d auth/volatile header(s) stripped\n",
		res.Interactions, res.StrippedHeaders)

	if *out != "" {
		// The committed artifact is an API-layer cassette (a single JSON doc, not
		// NDJSON), so the fixture-provenance gate requires a <out>.provenance
		// sidecar carrying the synthetic header. Reaching this point means the
		// provenance gate in scrubCassette passed (provenance == "synthetic"),
		// so the sidecar always declares synthetic.
		//
		// Emit the sidecar FIRST, then the cassette. A sidecar write failure is a
		// HARD error and leaves NO cassette on disk — the wall must never leave a
		// scrubbed cassette without its sidecar (an orphan cassette under a
		// fixtures/ dir would itself fail the provenance gate at commit time). If
		// the sidecar lands but the cassette write then fails, remove the orphan
		// sidecar so neither half of the pair survives a failed scrub. (A lone
		// sidecar is gate-harmless — check-fixture-provenance.sh only validates a
		// sidecar that pairs a real fixture — but removing it keeps "all or
		// nothing" literally true.)
		side := provenanceSidecarPath(*out)
		if err := writeProvenanceSidecar(side, *seam, *note, createdStamp); err != nil {
			fmt.Fprintf(os.Stderr, "ds-capture scrub: write provenance sidecar %s: %v\n", side, err)
			return 1
		}
		if err := cas.Save(*out); err != nil {
			fmt.Fprintf(os.Stderr, "ds-capture scrub: write %s: %v\n", *out, err)
			// Don't leave an orphan sidecar for a cassette that never landed.
			if rmErr := os.Remove(side); rmErr != nil && !os.IsNotExist(rmErr) {
				fmt.Fprintf(os.Stderr, "ds-capture scrub: also failed to remove orphan sidecar %s: %v\n", side, rmErr)
			}
			return 1
		}
		fmt.Fprintf(os.Stderr, "ds-capture scrub: scrubbed cassette written to %s (provenance=%s, committable=%v)\n",
			*out, res.Provenance, res.Committable)
		fmt.Fprintf(os.Stderr, "ds-capture scrub: provenance sidecar written to %s\n", side)
	} else {
		fmt.Fprintln(os.Stderr, "ds-capture scrub: report-only (no --out); the D50 wall held.")
	}
	return 0
}

// provenanceSidecarPath returns the sidecar path the fixture-provenance gate
// expects for a committed non-NDJSON fixture: "<out>.provenance".
func provenanceSidecarPath(out string) string { return out + ".provenance" }

// createdDateLayout is the canonical UTC date stamp shape for the sidecar's
// `created` field, matching what check-fixture-provenance.sh records.
const createdDateLayout = "2006-01-02"

// resolveCreated decides the `created` stamp the sidecar records, in priority
// order, so re-scrubbing the same input with the same inputs yields a
// byte-identical sidecar (reproducible builds):
//
//  1. an explicit --created override (preferred);
//  2. else a SOURCE_DATE_EPOCH-style env (Unix seconds, interpreted in UTC);
//  3. else today's UTC date (preserving the original time.Now() behavior).
//
// The override and the env value are both validated to the YYYY-MM-DD shape; a
// malformed value is a clean error (no sidecar is written). The error never
// echoes cassette content — only the operator-supplied stamp, which carries no
// secret (never-log-the-secret, HARDENING-NOTES.md §2.2).
func resolveCreated(override, sourceDateEpoch string) (string, error) {
	if override != "" {
		if err := validateCreated(override); err != nil {
			return "", fmt.Errorf("invalid --created %q: %w", override, err)
		}
		return override, nil
	}
	if sourceDateEpoch != "" {
		secs, err := strconv.ParseInt(strings.TrimSpace(sourceDateEpoch), 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid SOURCE_DATE_EPOCH %q: want Unix seconds", sourceDateEpoch)
		}
		return time.Unix(secs, 0).UTC().Format(createdDateLayout), nil
	}
	return time.Now().UTC().Format(createdDateLayout), nil
}

// validateCreated checks a stamp is exactly a real YYYY-MM-DD UTC calendar date.
// time.Parse in UTC both pins the shape and rejects impossible dates (e.g.
// 2026-13-40); a strict round-trip rejects shapes time.Parse would otherwise
// normalize (it does not, for this layout, but the round-trip is belt-and-braces
// against zero-padding/whitespace slop).
func validateCreated(s string) error {
	t, err := time.Parse(createdDateLayout, s)
	if err != nil {
		return fmt.Errorf("want YYYY-MM-DD")
	}
	if t.UTC().Format(createdDateLayout) != s {
		return fmt.Errorf("want YYYY-MM-DD")
	}
	return nil
}

// writeProvenanceSidecar writes the single-JSON-line ds_fixture sidecar that
// scripts/check-fixture-provenance.sh validates for non-NDJSON fixtures. The
// provenance is always "synthetic": only a synthetic cassette reaches a write
// (scrubCassette gates committability), and only synthetic may live in git
// (D50 / HARDENING-NOTES.md §2.3). created is the UTC date stamp (YYYY-MM-DD),
// resolved by resolveCreated so re-scrubbing the same input with the same stamp
// yields byte-identical sidecar bytes.
//
// Never-log-the-secret (HARDENING-NOTES.md §2.2): the sidecar carries only the
// provenance metadata (provenance/seam/created/note) — never any scrubbed or
// redacted credential value. seam/note/created are operator-supplied tags, not
// cassette content, so no secret-bearing value flows into this file.
func writeProvenanceSidecar(path, seam, note, created string) error {
	type dsFixture struct {
		Provenance string `json:"provenance"`
		Seam       string `json:"seam"`
		Created    string `json:"created"`
		Note       string `json:"note"`
	}
	type sidecar struct {
		DSFixture dsFixture `json:"ds_fixture"`
	}
	doc := sidecar{DSFixture: dsFixture{
		Provenance: "synthetic",
		Seam:       seam,
		Created:    created,
		Note:       note,
	}}
	// Marshal (not encode) so the result is exactly one line; the gate reads the
	// first line of the sidecar and parses it as JSON.
	line, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	// Ensure the parent directory exists. The sidecar is written before the
	// cassette (so a sidecar failure leaves no orphan cassette), so it cannot
	// rely on cas.Save having created the directory first; mirror cas.Save's own
	// os.MkdirAll. The sidecar and cassette share the same parent.
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, line, 0o644)
}

// scrubCassette enforces the D50 wall on a loaded cassette in place:
//
//  1. strip auth/volatile request headers from every interaction, keeping only
//     content-type (the allow-list);
//  2. assert no Bearer / sk-ant / x-api-key token value survives ANYWHERE in
//     the cassette (headers, normalized form, or body) — fail loudly if one does;
//  3. gate provenance: refuse to mark the artifact committable unless the
//     declared provenance is `synthetic` (HARDENING-NOTES.md §2.2/§2.3).
//
// `wantCommittable` is true when the caller intends to write the result out (a
// committable artifact); the provenance gate then applies.
func scrubCassette(cas *cassette.Cassette, provenance string, wantCommittable bool) (scrubResult, error) {
	res := scrubResult{Interactions: cas.Len(), Provenance: provenance}

	// (1) Strip auth/volatile headers, keeping only the replay allow-list
	// (content-type). A header is counted as "stripped" if it was present
	// before and is not the kept content-type.
	for _, it := range cas.Interactions {
		for name := range it.Headers {
			if !strings.EqualFold(name, "content-type") {
				res.StrippedHeaders++
			}
		}
		it.Headers = cassette.FilterReplayHeaders(it.Headers)
	}

	// (2) Assert no secret-shaped value survives anywhere.
	if hits := scanSecrets(cas); len(hits) > 0 {
		sort.Strings(hits)
		return res, fmt.Errorf("D50 WALL VIOLATION: secret-shaped value(s) survive the scrub: %s "+
			"(refusing to proceed; this cassette is raw-class and must not be committed)",
			strings.Join(hits, "; "))
	}

	// (3) Provenance gate.
	if provenance != "" && !validProvenance[provenance] {
		return res, fmt.Errorf("unknown provenance %q (want synthetic|dogfood|partner-consented)", provenance)
	}
	res.Committable = provenance == "synthetic"
	if wantCommittable && !res.Committable {
		if provenance == "" {
			return res, fmt.Errorf("refusing to emit a committable artifact without --provenance; " +
				"only `synthetic` may live in git (D50)")
		}
		return res, fmt.Errorf("refusing to emit a committable artifact with provenance=%q; "+
			"only `synthetic` may live in git — re-author dogfood/partner-consented as synthetic (D50)",
			provenance)
	}
	return res, nil
}

// scanSecrets walks every persisted string in the cassette and returns the
// distinct secret-pattern names that matched. Used both by scrub (fail-closed)
// and by the test (proving no Bearer/sk-ant survives).
func scanSecrets(cas *cassette.Cassette) []string {
	seen := map[string]bool{}
	check := func(s string) {
		for _, re := range secretPatterns {
			if re.MatchString(s) {
				seen[redactedMatchLabel(re, s)] = true
			}
		}
		// A bare x-api-key header *name* surviving as a header key is itself a
		// wall breach even without a value (auth header must be gone).
	}
	for _, it := range cas.Interactions {
		for k, v := range it.Headers {
			if cassette.VolatileRequestHeader(k) {
				seen[fmt.Sprintf("auth/volatile header %q survived", strings.ToLower(k))] = true
			}
			check(k)
			check(v)
		}
		check(it.Body)
		check(it.Normalized.System)
		for _, t := range it.Normalized.Sequence {
			check(t.Content)
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// redactedMatchLabel describes a secret match WITHOUT echoing the token value
// (never-log-the-secret, HARDENING-NOTES.md §2.2). It reports only which
// pattern fired and a non-reversible length hint.
func redactedMatchLabel(re *regexp.Regexp, s string) string {
	m := re.FindString(s)
	return fmt.Sprintf("matched secret pattern (len=%d, value redacted)", len(m))
}

// scanMetaSecret rejects an operator-supplied sidecar metadata field (--seam,
// --note) whose value is token-shaped, BEFORE it is written into the provenance
// sidecar. scanSecrets guards cassette content (the real secret-bearing
// source); these free-text fields are a separate, previously-untrusted ingress
// into the committed sidecar, so the same secretPatterns are applied here to
// convert the D50 never-log-the-secret invariant from trusted to enforced. The
// returned error names the FIELD and a redacted match label only — never the
// matched token bytes (HARDENING-NOTES.md §2.2).
func scanMetaSecret(field, value string) error {
	for _, re := range secretPatterns {
		if re.MatchString(value) {
			return fmt.Errorf("--%s value rejected: %s — refusing to write a token-shaped value "+
				"into the provenance sidecar (never-log-the-secret, HARDENING-NOTES.md §2.2)",
				field, redactedMatchLabel(re, value))
		}
	}
	return nil
}
