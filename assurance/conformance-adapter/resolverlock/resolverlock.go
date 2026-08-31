// SPDX-License-Identifier: Apache-2.0

package resolverlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// shippedPackRelPath is the path from THIS package to the single source of truth
// — the shipped POL-2 baseline pack the open data plane actually ships. The Rust
// TLS-1 suite (dataplane/crates/policy-core/tests/resolver_lock_tls1.rs) parses
// the SAME file, so the two language suites read ONE artifact and can never
// drift: one source, two readers. The path is anchored off this source file's
// location (runtime.Caller) rather than the process working directory, so the
// offline half works under `go test` from any cwd.
//
// TEST-CACHE CORRECTNESS: the read goes THROUGH the in-module tracked symlink
// testdata/srclinks/dataplane_pol2_baseline_pack, never via ../../../dataplane/…
// directly. Go's test cache (cmd/go computeTestInputsID) hashes only files opened
// at paths lexically inside this module's root, so a direct cross-tree read lets a
// warm cache serve a stale PASS after the shipped pack changes. The in-module link
// path IS tracked and the open FOLLOWS the link, so the tracked size+mtime are the
// real file's and the pin re-runs the moment the pack changes. SourceLinks +
// TestSourceLinksResolve (srclinks.go / srclinks_test.go) guard the link target so
// a stale COPY cannot silently freeze the read against a dead snapshot.
const shippedPackRelPath = "testdata/srclinks/" + srcLinkPol2BaselinePack

// ShippedPackPath returns the absolute path to the shipped baseline pack file,
// anchored off this package's source location. It is the ONE artifact both the
// offline Go half here and the Rust TLS-1 suite read.
func ShippedPackPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		// Fall back to a cwd-relative best effort; the read will fail loudly with
		// a clear path if this is wrong, never silently produce an empty set.
		return shippedPackRelPath
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), shippedPackRelPath))
}

// ── Drift-corpus location (coupling assertion) ─────────────────────────────────
//
// The drifted-pack corpus is ONE directory read by TWO readers:
//
//   Go  (this package): CorpusFixturesDir() — anchored via runtime.Caller
//   Rust (policy-core): corpus_dir() — anchored via env!("CARGO_MANIFEST_DIR")
//
// BOTH readers verify their resolved path ends with CorpusFixturesCanonicalSuffix,
// which encodes the single canonical corpus location relative to the repo root.  A
// corpus move that does not update BOTH source files (this one and pack_drift_corpus.rs)
// fails BOTH readers loudly — the path-identity assertion, not just a missing-dir
// panic, names the mismatch. This is the lint-asserted coupling the task requires.

// CorpusFixturesCanonicalSuffix is the repo-root-relative path suffix that both
// readers verify against their independently-resolved absolute paths.  Changing this
// constant without moving the corpus fails the Go path-identity test; changing the
// corpus location without updating this constant fails the same test AND the Rust
// path-identity test (corpus_path_identity in pack_drift_corpus.rs).
const CorpusFixturesCanonicalSuffix = "assurance/conformance-adapter/resolverlock/testdata/drift-corpus/fixtures"

// corpusFixturesRelPath is the path from THIS source file to the corpus directory.
// Anchored off runtime.Caller so it works under `go test` from any cwd (same
// technique as shippedPackRelPath / ShippedPackPath above).
const corpusFixturesRelPath = "testdata/drift-corpus/fixtures"

// CorpusFixturesDir returns the absolute path to the shared drifted-pack corpus
// fixtures directory, anchored off this source file's location via runtime.Caller.
// This is the SAME directory the Rust reader (dataplane/crates/policy-core/tests/
// pack_drift_corpus.rs) reaches via its CARGO_MANIFEST_DIR-relative path.  Both
// readers verify their resolved path ends with CorpusFixturesCanonicalSuffix — a
// corpus move that updates only one reader fails the other's path-identity test
// (TestCorpusPathIdentity here, corpus_path_identity in pack_drift_corpus.rs).
func CorpusFixturesDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		// Fall back to a package-relative best effort; the read will fail loudly with
		// a clear path if this is wrong, never silently produce an empty set.
		return corpusFixturesRelPath
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), corpusFixturesRelPath))
}

// ResolverLockEntry is one parsed `blocklist:` item from the shipped pack — the
// resolver-lock unit of enforcement. Only the fields the conformance half needs
// are modeled (the full BlockEntry schema lives in ds-contracts): the exact FQDN,
// its reason (e.g. "doh-resolver"), and its severing rung (block+log on every
// shipped resolver-lock entry, §5/D53), which the live half asserts severs.
type ResolverLockEntry struct {
	// FQDN is the exact blocklisted resolver host (D74 exact-FQDNs-only — the
	// resolver lock does NOT match subdomains by suffix; a new resolver host is a
	// new exact entry). Normalized lowercase, the form the egress gateway folds
	// the peeked SNI into before the policy query (doc 13 §1.1).
	FQDN string
	// Reason is the free-string `reason:` (e.g. "doh-resolver", "dot-resolver").
	Reason string
	// Rung is the `rung:` (e.g. "block+log"); a block-or-higher rung severs
	// established flows on revocation (§5/D53), which the resolver-lock row needs.
	Rung string
}

// Named shape-drift failure modes. The Go side here is a hand-rolled stdlib line
// scanner over the SHIPPED pack (the module is stdlib-only by charter); the Rust
// ds_contracts parser is a real YAML engine reading the SAME bytes. A pack rewrite
// to flow-style sequences, anchors/aliases, renamed keys, or malformed entries
// could UNDER-extract on the Go side while the Rust suite stays authoritative —
// silently breaking the one-artifact-two-readers guarantee. Each sentinel below
// names one drift class so the scanner fails LOUDLY (and actionably) rather than
// extracting partial data; tests assert the specific error via errors.Is. A pack
// format change that trips any of these MUST update BOTH readers (this Go scanner
// and the Rust TLS-1 suite) in lockstep — that is the message every wrapped error
// carries.
var (
	// ErrNoBlocklistSection fires when the top-level `blocklist:` key is absent —
	// the scanner has nothing to extract, which a renamed/removed key would cause.
	ErrNoBlocklistSection = errors.New("resolverlock: no top-level `blocklist:` section in the shipped pack (renamed or removed key?) — a pack format change must update BOTH readers in lockstep: this Go scanner AND the Rust ds_contracts TLS-1 suite")
	// ErrEmptyBlocklist fires when the section exists but carries zero entries —
	// the resolver lock cannot ship empty (D64); empty extraction is a false green.
	ErrEmptyBlocklist = errors.New("resolverlock: the `blocklist:` section is empty — the shipped pack must carry a non-empty resolver-lock blocklist (D64)")
	// ErrUnsupportedShape fires when the section uses a YAML construct this stdlib
	// line scanner does not model — a flow-style `[`/`{` sequence opener, or an
	// anchor/alias (`&`/`*`). The Rust engine would still read these, so the Go
	// scanner would silently UNDER-extract; fail loudly instead.
	ErrUnsupportedShape = errors.New("resolverlock: the `blocklist:` section uses an unsupported YAML shape (flow-style sequence `[`/`{`, or anchor/alias `&`/`*`) — this stdlib line scanner only models block-style `- domain:` items; a pack format change must update BOTH readers in lockstep: this Go scanner AND the Rust ds_contracts TLS-1 suite")
	// ErrEntryMissingFields fires when a block-style entry omits its `reason:` or
	// `rung:` — every shipped resolver-lock entry carries both (§5/D53).
	ErrEntryMissingFields = errors.New("resolverlock: a `blocklist:` entry is missing a `reason:` or `rung:` field — every shipped resolver-lock entry carries both (§5/D53)")
	// ErrBadFQDN fires when an entry's domain is not an exact, lowercase FQDN: a
	// wildcard (`*.`) or any uppercase byte. The resolver lock is exact-FQDNs-only
	// (D74), normalized lowercase (the form ds-tlsproxy folds the peeked SNI into).
	ErrBadFQDN = errors.New("resolverlock: a `blocklist:` entry domain is not an exact, lowercase FQDN (wildcard `*.` or uppercase) — the resolver lock is exact-FQDNs-only (D74), normalized lowercase")
	// ErrCountMismatch fires when the number of extracted entries disagrees with an
	// independently-derived count of `domain:` occurrences inside the section text.
	// This is the under-extraction tripwire: if the scanner harvested fewer entries
	// than the raw text declares, something about the shape drifted past it.
	ErrCountMismatch = errors.New("resolverlock: extracted entry count disagrees with the raw `domain:` occurrence count inside the `blocklist:` section — the scanner UNDER-extracted; a pack format change must update BOTH readers in lockstep: this Go scanner AND the Rust ds_contracts TLS-1 suite")
)

// ExtractResolverLockBlocklist reads the resolver-lock blocklist out of the
// SHIPPED pack the SAME way the host reader does in spirit — pull every
// `- domain:` (with its `reason:`/`rung:`) under the top-level `blocklist:` key.
// It is deliberately a tiny stdlib-only line scanner (this module is stdlib-only
// by charter, conformance-adapter/go.mod): the point is to extract the shipped
// set from the artifact text, not to re-implement a YAML engine — the
// authoritative parser is ds_contracts::pol1::parse_layer, which the Rust suite
// drives against the SAME bytes. The returned slice is in file order.
//
// A read or parse failure returns an error; the offline test fails loudly rather
// than treating "couldn't read the pack" as "empty blocklist" (a false green the
// resolver lock cannot afford). The parse now hardens against pack YAML shape
// drift — missing section, unsupported shape, missing fields, bad FQDN, empty
// set, and under-extraction each surface a NAMED error (see the Err* sentinels).
func ExtractResolverLockBlocklist() ([]ResolverLockEntry, error) {
	path := ShippedPackPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseResolverLockBlocklist(string(data))
}

// parseResolverLockBlocklist is the pure text→entries scanner (separated so it is
// unit-testable without the file read). It harvests the items under the
// top-level `blocklist:` key; a `reason:`/`rung:` line attaches to the entry it
// follows. It fails LOUDLY with a NAMED error (the Err* sentinels, wrapped with
// the offending line for actionability) on any shape it does not model, rather
// than silently extracting partial data.
func parseResolverLockBlocklist(text string) ([]ResolverLockEntry, error) {
	var out []ResolverLockEntry
	inBlocklist := false
	sawBlocklist := false
	rawDomainCount := 0 // independent count of `domain:` lines inside the section
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		// Strip trailing inline comments and the line's surrounding space for the
		// key/item tests; the pack uses `# ...` comments on their own lines, but
		// be defensive about trailing ones on data lines too.
		trimmed := strings.TrimSpace(stripComment(line))
		if trimmed == "" {
			continue
		}
		// A top-level key (no leading indentation, not a list item) opens or closes
		// a block. The shipped `blocklist:` key is bare (`blocklist:` with nothing
		// after the colon, modulo comments); a `blocklist: [...]` flow-style opener
		// renames nothing but is a shape this scanner cannot harvest — name it.
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '-' &&
			strings.HasPrefix(trimmed, "blocklist:") {
			sawBlocklist = true
			inBlocklist = true
			if rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "blocklist:")); rest != "" {
				// `blocklist: [` / `blocklist: {` / `blocklist: &anchor` — a flow
				// or anchored opener on the key line itself.
				return nil, fmt.Errorf("%w (offending line: %q)", ErrUnsupportedShape, trimmed)
			}
			continue
		}
		// Any other column-0 mapping key closes the section — whether it is a bare
		// `key:` (block value follows on indented lines) or `key: value` /
		// `key: [...]` with an inline value. We detect it as a column-0 line whose
		// first token before any space is `<name>:`; this is what lets the blocklist
		// scan stop at the next top-level key (e.g. `passthrough: []`, `services:`)
		// instead of treating its value as section content.
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '-' &&
			isColumnZeroKey(trimmed) {
			inBlocklist = false
			continue
		}
		if !inBlocklist {
			continue
		}
		// Inside the section: reject the YAML constructs this scanner does not model
		// before harvesting, so a flow-style or anchored rewrite fails loudly rather
		// than under-extracting. `[`/`{` open flow-style collections; `&`/`*` are
		// anchors/aliases the real engine would resolve and we would miss.
		if strings.ContainsAny(trimmed, "[{") || hasAnchorOrAlias(trimmed) {
			return nil, fmt.Errorf("%w (offending line: %q)", ErrUnsupportedShape, trimmed)
		}
		switch {
		case strings.HasPrefix(trimmed, "- domain:"):
			rawDomainCount++
			d := strings.TrimSpace(strings.TrimPrefix(trimmed, "- domain:"))
			if err := validateFQDN(d); err != nil {
				return nil, err
			}
			out = append(out, ResolverLockEntry{FQDN: d})
		case strings.HasPrefix(trimmed, "domain:"):
			// A bare `domain:` line (block-style item folded onto the next line, or
			// a renamed list indentation) is a shape we do not harvest as an entry —
			// count it for the under-extraction tripwire so it fires.
			rawDomainCount++
		case strings.HasPrefix(trimmed, "reason:") && len(out) > 0:
			out[len(out)-1].Reason = strings.TrimSpace(strings.TrimPrefix(trimmed, "reason:"))
		case strings.HasPrefix(trimmed, "rung:") && len(out) > 0:
			out[len(out)-1].Rung = strings.TrimSpace(strings.TrimPrefix(trimmed, "rung:"))
		}
	}

	if !sawBlocklist {
		return nil, ErrNoBlocklistSection
	}
	if len(out) == 0 {
		return nil, ErrEmptyBlocklist
	}
	// Under-extraction tripwire: the entries we built must equal the raw count of
	// `domain:` occurrences inside the section. A flow-style/anchored rewrite that
	// slipped past the shape guards, or a `- domain:` the harvester could not parse,
	// would leave rawDomainCount > len(out) — name it loudly.
	if rawDomainCount != len(out) {
		return nil, fmt.Errorf("%w (extracted %d, raw `domain:` count %d)",
			ErrCountMismatch, len(out), rawDomainCount)
	}
	// Every entry must carry its reason and rung (the shape the live half asserts
	// severs). A missing field is a drift the scanner names rather than passing on.
	for _, e := range out {
		if e.Reason == "" || e.Rung == "" {
			return nil, fmt.Errorf("%w (entry %q: reason=%q rung=%q)",
				ErrEntryMissingFields, e.FQDN, e.Reason, e.Rung)
		}
	}
	return out, nil
}

// validateFQDN enforces D74 exact-FQDNs-only, lowercase: a non-empty domain with
// no wildcard (`*`) and no uppercase byte. It returns the NAMED ErrBadFQDN
// (wrapped with the offending value) so a drifted pack entry fails actionably.
func validateFQDN(d string) error {
	if d == "" {
		return fmt.Errorf("%w (empty domain)", ErrBadFQDN)
	}
	if strings.Contains(d, "*") {
		return fmt.Errorf("%w (wildcard domain %q — exact FQDNs only, D74)", ErrBadFQDN, d)
	}
	for i := 0; i < len(d); i++ {
		if d[i] >= 'A' && d[i] <= 'Z' {
			return fmt.Errorf("%w (non-lowercase domain %q — normalize to lowercase, D74)", ErrBadFQDN, d)
		}
	}
	return nil
}

// isColumnZeroKey reports whether a trimmed, column-0 line is a YAML mapping key
// — `<name>:` (bare, value on following indented lines) or `<name>: value` /
// `<name>: [...]` (inline value). The key name runs up to the first `:`; a real
// mapping key has the colon either at the end of the line or immediately before a
// space, and no whitespace inside the name. This is what lets the blocklist scan
// terminate at the next top-level key (`passthrough: []`, `services:`) rather than
// swallowing its value as section content. It is intentionally conservative: it is
// only consulted for column-0 lines that are NOT the `blocklist:` opener and NOT
// list items, so it just answers "does this top-level line start a new key?".
func isColumnZeroKey(trimmed string) bool {
	i := strings.IndexByte(trimmed, ':')
	if i <= 0 {
		return false
	}
	name := trimmed[:i]
	if strings.ContainsAny(name, " \t") {
		return false
	}
	// Colon must end the line or be followed by a space (so `http://x` inside a
	// value is never mistaken for a key — though such a value would be indented,
	// not column-0, in this pack).
	rest := trimmed[i+1:]
	return rest == "" || rest[0] == ' '
}

// hasAnchorOrAlias reports whether a line carries a YAML anchor (`&name`) or alias
// (`*name`) token — a construct the real engine resolves and this scanner cannot.
// It looks for `&`/`*` immediately followed by an anchor-name character, so a
// stray `*` inside a quoted string is not what we key on here (validateFQDN owns
// the wildcard-domain check); this guards the structural anchor/alias shape.
func hasAnchorOrAlias(line string) bool {
	for i := 0; i < len(line)-1; i++ {
		c := line[i]
		if c != '&' && c != '*' {
			continue
		}
		n := line[i+1]
		if n == '_' || (n >= 'A' && n <= 'Z') || (n >= 'a' && n <= 'z') || (n >= '0' && n <= '9') {
			return true
		}
	}
	return false
}

// stripComment drops a trailing `# ...` comment from a line. The pack's data
// lines have no inline comments, but the scanner stays robust if one appears.
func stripComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

// ResolverLockFQDNs returns just the exact FQDNs of the shipped resolver-lock
// blocklist, sorted and de-duplicated — the comparison form for the offline
// single-source assertions. The Rust suite's shipped_blocklist_entries_are_exact_
// lowercase_fqdns reads the SAME artifact, so the two extracted sets agree by
// construction.
func ResolverLockFQDNs() ([]string, error) {
	entries, err := ExtractResolverLockBlocklist()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.FQDN)
	}
	sort.Strings(out)
	return dedup(out), nil
}

func dedup(sorted []string) []string {
	if len(sorted) == 0 {
		return sorted
	}
	out := sorted[:1]
	for _, s := range sorted[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// ───────────────────────────────────────────────────────────────────────────────
// Live half (env-gated, DEFERRED to NFT-4 — taskdb 01KTWJ68H01HR03Q1X1VQC5DB7).
// ───────────────────────────────────────────────────────────────────────────────

// LiveEnvVar is the env gate for the live resolver-lock conformance run. When set
// to "1" the live half drives a DoH-style client against running
// ds-dnsgate/ds-tlsproxy; unset (the default) it is skipped. It is a documented
// deferred manual step until NFT-4 lands the resolver-bypass-closure ruleset and
// the running boundary services it asserts against.
const LiveEnvVar = "DS_RESOLVERLOCK_LIVE"

// LiveEnabled reports whether the env gate opts into the live half. The live test
// calls this and SKIPS when false, so the default `go test` run is offline-only.
func LiveEnabled() bool {
	return os.Getenv(LiveEnvVar) == "1"
}

// LiveTarget addresses the running boundary services the live half drives against,
// read from the environment so a deployment points the conformance run at its own
// boundary host. All fields have safe localhost defaults for a dev boundary; the
// live half still only runs when LiveEnabled() is true.
type LiveTarget struct {
	// DNSGateAddr is the ds-dnsgate listener (host:port) the DoH-style client's
	// resolution is forced through (DNS-3 denial layer).
	DNSGateAddr string
	// TLSProxyAddr is the ds-tlsproxy redirect listener (host:port) the SNI check
	// runs on (TLS-1 layer).
	TLSProxyAddr string
}

// LiveTargetFromEnv builds the live target from DS_RESOLVERLOCK_* env vars, with
// localhost dev defaults. It does NOT itself require the gate — the caller checks
// LiveEnabled() — it only resolves where the live half would connect.
func LiveTargetFromEnv() LiveTarget {
	return LiveTarget{
		DNSGateAddr:  envOr("DS_RESOLVERLOCK_DNSGATE_ADDR", "127.0.0.1:53"),
		TLSProxyAddr: envOr("DS_RESOLVERLOCK_TLSPROXY_ADDR", "127.0.0.1:443"),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
