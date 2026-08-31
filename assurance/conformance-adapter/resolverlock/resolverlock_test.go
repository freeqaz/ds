// SPDX-License-Identifier: Apache-2.0

package resolverlock

import (
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
)

// ── Offline half: the single-source consistency check (always runs) ────────────

// TestShippedBlocklistIsNonEmpty proves the OFFLINE half can read the shipped
// pack and that the resolver-lock blocklist is present. A read failure or an
// empty blocklist fails LOUDLY — "couldn't read the pack" is never silently
// treated as "no resolvers blocked" (the false green the resolver lock cannot
// afford). The Rust suite asserts the mirror over the SAME bytes
// (every_shipped_blocklist_entry_denies_on_the_tls_connect_surface starts by
// asserting the parsed blocklist is non-empty).
func TestShippedBlocklistIsNonEmpty(t *testing.T) {
	entries, err := ExtractResolverLockBlocklist()
	if err != nil {
		t.Fatalf("reading the shipped resolver-lock blocklist from %s: %v", ShippedPackPath(), err)
	}
	if len(entries) == 0 {
		t.Fatalf("the shipped pack must carry a non-empty resolver-lock blocklist (D64); read %s",
			ShippedPackPath())
	}
}

// TestShippedBlocklistShape pins the shape of every shipped resolver-lock entry:
// a non-empty, lowercase exact FQDN (the form ds-tlsproxy normalizes the peeked
// SNI into before the policy query — doc 13 §1.1) carrying a reason and a severing
// rung. A regression that admitted an empty or mixed-case entry, or dropped the
// block+log rung, would silently weaken the resolver lock; this catches it on the
// Go side as the Rust shipped_blocklist_entries_are_exact_lowercase_fqdns and
// every_shipped_blocklist_entry_severs_established_flows_on_the_tls_path catch it
// on theirs — both reading the SAME artifact.
func TestShippedBlocklistShape(t *testing.T) {
	entries, err := ExtractResolverLockBlocklist()
	if err != nil {
		t.Fatalf("reading the shipped resolver-lock blocklist: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.FQDN == "" {
			t.Error("empty resolver-lock entry FQDN")
			continue
		}
		if lower := toLowerASCII(e.FQDN); lower != e.FQDN {
			t.Errorf("resolver-lock entry %q must be stored lowercase (got %q)", e.FQDN, lower)
		}
		if seen[e.FQDN] {
			t.Errorf("duplicate resolver-lock entry %q", e.FQDN)
		}
		seen[e.FQDN] = true
		if e.Reason == "" {
			t.Errorf("resolver-lock entry %q must carry a reason (e.g. doh-resolver)", e.FQDN)
		}
		// Every shipped resolver-lock entry pins block+log — the first severing
		// rung (§5/D53) — so the block tears down an in-flight DoH/DoT tunnel and
		// not just new connects. The Rust TLS-1 suite asserts the verdict severs;
		// here we assert the shipped rung the verdict carries.
		if e.Rung != "block+log" {
			t.Errorf("resolver-lock entry %q must pin a block-or-higher rung (block+log, §5/D53), got %q",
				e.FQDN, e.Rung)
		}
	}
}

// TestResolverLockFQDNsSortedAndDeduped guards the FQDN extractor's contract
// (sorted, deduped) independently of file order — the comparison form the
// single-source assertions use.
func TestResolverLockFQDNsSortedAndDeduped(t *testing.T) {
	got, err := ResolverLockFQDNs()
	if err != nil {
		t.Fatalf("extracting resolver-lock FQDNs: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("resolver-lock FQDN set must not be empty")
	}
	if !sort.StringsAreSorted(got) {
		t.Errorf("ResolverLockFQDNs must return a sorted slice: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i] == got[i-1] {
			t.Errorf("ResolverLockFQDNs must dedup: %q repeated", got[i])
		}
	}
}

// ── Shape-drift hardening: one perturbed-YAML case per named failure mode ──────

// A minimal, well-formed synthetic blocklist section — the BASELINE the drift
// cases perturb. Built from synthetic YAML strings in-test (the task body's
// requirement: negative cases are proven against synthetic strings, NEVER by
// mutating the shipped pack, which stays read-only). It mirrors the shipped
// block-style shape so the perturbations isolate one drift class each.
const goodSection = `schema_version: pol1/v0
layer: system-baseline
blocklist:
  - domain: dns.example
    reason: doh-resolver
    rung: block+log
  - domain: dot.example
    reason: dot-resolver
    rung: block+log
passthrough: []
`

// TestParseGoodSection pins that the hardened scanner still parses a well-formed
// block-style section cleanly (no false positive from the new shape guards) and
// that the section terminates at the next top-level key (`passthrough: []`) rather
// than swallowing its inline value.
func TestParseGoodSection(t *testing.T) {
	entries, err := parseResolverLockBlocklist(goodSection)
	if err != nil {
		t.Fatalf("well-formed synthetic section must parse cleanly, got: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}
	if entries[0].FQDN != "dns.example" || entries[0].Reason != "doh-resolver" || entries[0].Rung != "block+log" {
		t.Errorf("entry[0] mis-parsed: %+v", entries[0])
	}
	if entries[1].FQDN != "dot.example" {
		t.Errorf("entry[1] mis-parsed: %+v", entries[1])
	}
}

// TestParseShapeDrift is the table-driven drift gate: each row is a synthetic YAML
// section perturbed into ONE shape-drift class, asserting the scanner fails with
// the SPECIFIC named sentinel (errors.Is) rather than silently under-extracting.
// This is the Go-side tripwire for the one-artifact-two-readers guarantee — a pack
// rewrite that drifts past the hand-rolled scanner must trip exactly here, naming
// the lockstep both readers (this scanner + the Rust ds_contracts suite) require.
func TestParseShapeDrift(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr error
	}{
		{
			// Drift class: the `blocklist:` key is renamed/removed — nothing to scan.
			name: "missing blocklist section",
			yaml: `schema_version: pol1/v0
resolver_denylist:
  - domain: dns.example
    reason: doh-resolver
    rung: block+log
passthrough: []
`,
			wantErr: ErrNoBlocklistSection,
		},
		{
			// Drift class: the section exists but carries zero entries.
			name: "empty blocklist section",
			yaml: `schema_version: pol1/v0
blocklist:
passthrough: []
`,
			wantErr: ErrEmptyBlocklist,
		},
		{
			// Drift class: flow-style sequence opener — `[` after `blocklist:`.
			name: "flow-style sequence on the key line",
			yaml: `schema_version: pol1/v0
blocklist: [dns.example, dot.example]
passthrough: []
`,
			wantErr: ErrUnsupportedShape,
		},
		{
			// Drift class: flow-style mapping inside a block item — `{` opener.
			name: "flow-style mapping inside the section",
			yaml: `schema_version: pol1/v0
blocklist:
  - { domain: dns.example, reason: doh-resolver, rung: block+log }
passthrough: []
`,
			wantErr: ErrUnsupportedShape,
		},
		{
			// Drift class: anchor/alias inside the section — the engine resolves it,
			// the line scanner cannot.
			name: "anchor/alias inside the section",
			yaml: `schema_version: pol1/v0
common: &blk
  reason: doh-resolver
  rung: block+log
blocklist:
  - domain: dns.example
    <<: *blk
passthrough: []
`,
			wantErr: ErrUnsupportedShape,
		},
		{
			// Drift class: an entry omits its `reason:` field.
			name: "entry missing reason",
			yaml: `schema_version: pol1/v0
blocklist:
  - domain: dns.example
    rung: block+log
passthrough: []
`,
			wantErr: ErrEntryMissingFields,
		},
		{
			// Drift class: an entry omits its `rung:` field.
			name: "entry missing rung",
			yaml: `schema_version: pol1/v0
blocklist:
  - domain: dns.example
    reason: doh-resolver
passthrough: []
`,
			wantErr: ErrEntryMissingFields,
		},
		{
			// Drift class: a non-lowercase FQDN (D74 normalize-to-lowercase).
			name: "non-lowercase FQDN",
			yaml: `schema_version: pol1/v0
blocklist:
  - domain: DNS.Example
    reason: doh-resolver
    rung: block+log
passthrough: []
`,
			wantErr: ErrBadFQDN,
		},
		{
			// Drift class: a wildcard FQDN (D74 exact-FQDNs-only).
			name: "wildcard FQDN",
			yaml: `schema_version: pol1/v0
blocklist:
  - domain: "*.example"
    reason: doh-resolver
    rung: block+log
passthrough: []
`,
			wantErr: ErrBadFQDN,
		},
		{
			// Drift class: a `domain:` declared in the section that the harvester did
			// not turn into an entry — the under-extraction tripwire. Here a second
			// block item folds the `domain:` onto its own indented line in a shape the
			// `- domain:` harvester does not catch, so the raw count exceeds the
			// extracted count.
			name: "under-extraction count mismatch",
			yaml: `schema_version: pol1/v0
blocklist:
  - domain: dns.example
    reason: doh-resolver
    rung: block+log
  -
    domain: dot.example
    reason: dot-resolver
    rung: block+log
passthrough: []
`,
			wantErr: ErrCountMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseResolverLockBlocklist(tc.yaml)
			if err == nil {
				t.Fatalf("drift case %q must fail loudly, got nil error (silent under-extraction)", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("drift case %q: want error %v, got %v", tc.name, tc.wantErr, err)
			}
			// The named errors must stay actionable: every one names the lockstep or
			// the offending value, never a bare opaque string.
			if strings.TrimSpace(err.Error()) == "" {
				t.Errorf("drift case %q: error message must be non-empty", tc.name)
			}
		})
	}
}

// TestShippedPackHasNoDrift is the live tripwire over the SHIPPED artifact (read
// only): the real pack must parse with NONE of the drift sentinels firing. If a
// future pack rewrite introduces flow-style/anchored shape, a renamed key, or a
// malformed entry, THIS test goes red against the shipped bytes — the signal that
// a pack format change must update BOTH readers (this Go scanner AND the Rust
// ds_contracts TLS-1 suite) in lockstep.
func TestShippedPackHasNoDrift(t *testing.T) {
	_, err := ExtractResolverLockBlocklist()
	if err != nil {
		for _, sentinel := range []error{
			ErrNoBlocklistSection, ErrEmptyBlocklist, ErrUnsupportedShape,
			ErrEntryMissingFields, ErrBadFQDN, ErrCountMismatch,
		} {
			if errors.Is(err, sentinel) {
				t.Fatalf("shipped pack tripped a shape-drift guard (%v): a pack format "+
					"change must update BOTH readers (this Go scanner AND the Rust "+
					"ds_contracts TLS-1 suite) in lockstep — full error: %v", sentinel, err)
			}
		}
		t.Fatalf("reading the shipped pack failed for a non-drift reason: %v", err)
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// ── Live half: env-gated, default-skipped, deferred to NFT-4 ───────────────────

// TestLiveResolverLockBlocked is the wire-matrix "DoH client that must be blocked"
// row (assurance/conformance-adapter/doc.go): a DoH-style client driven against
// running ds-dnsgate/ds-tlsproxy must be refused at BOTH the DNS-3 denial layer
// and the TLS-1 SNI check, for every shipped resolver-lock FQDN.
//
// It is DEFERRED MANUAL: it runs only when DS_RESOLVERLOCK_LIVE=1 and needs the
// NFT-4 resolver-bypass-closure ruleset plus the running boundary services
// (taskdb 01KTWJ68H01HR03Q1X1VQC5DB7). The default `go test` run SKIPS it — so CI
// stays green offline — and when the gate IS set before NFT-4 lands, the scaffold
// fails LOUDLY rather than passing vacuously (an unwired live assertion that
// "passed" would be the false-green this row exists to prevent). No live `claude`
// / `cia run` / `podman run` of an agent is involved: the client is driven
// straight at the real boundary binaries.
func TestLiveResolverLockBlocked(t *testing.T) {
	if !LiveEnabled() {
		t.Skipf("live resolver-lock conformance skipped: set %s=1 to run "+
			"(deferred manual until NFT-4 lands — taskdb 01KTWJ68H01HR03Q1X1VQC5DB7)", LiveEnvVar)
	}

	entries, err := ExtractResolverLockBlocklist()
	if err != nil {
		t.Fatalf("reading the shipped resolver-lock blocklist for the live run: %v", err)
	}

	// Offline precondition the live run is grounded on: the shipped NFT-4
	// resolver-bypass-closure artifact must satisfy the doc 06 (c) port-53 / DoT /
	// QUIC closure shape (the same controls the live probes assert on the wire).
	// If the ruleset that WILL enforce the block is itself malformed, a live run
	// would be testing against a broken floor — fail loudly before we ever dial.
	if err := AssertNFT4ClosureShape(); err != nil {
		t.Fatalf("NFT-4 resolver-bypass-closure artifact (%s) fails its shape check; the live "+
			"run cannot be grounded on a malformed closure ruleset: %v", NFT4ArtifactPath(), err)
	}

	target := LiveTargetFromEnv()
	t.Logf("live resolver-lock conformance against ds-dnsgate=%s ds-tlsproxy=%s (NFT-4 closure shape OK)",
		target.DNSGateAddr, target.TLSProxyAddr)

	// The live client/driver is intentionally NOT wired here: it lands with NFT-4,
	// which provides the resolver-bypass-closure ruleset and the running services
	// this asserts against. Failing (not skipping) once the gate is explicitly set
	// keeps an operator from mistaking "no driver" for "passed". Each shipped
	// resolver FQDN is the per-row probe the wired driver will run (DNS-3 refusal
	// + TLS-1 SNI refusal); naming them here documents the matrix the live half
	// must cover — and the set comes from the SAME shipped artifact the offline
	// half and the Rust TLS-1 suite read.
	for _, e := range entries {
		fqdn := e.FQDN
		t.Run(fqdn, func(t *testing.T) {
			t.Fatalf("live resolver-lock driver not wired for %q: this is the NFT-4 "+
				"deferred step (taskdb 01KTWJ68H01HR03Q1X1VQC5DB7) — DoH client must be "+
				"refused at DNS-3 (%s) and the TLS-1 SNI check (%s); until the driver lands, "+
				"%s=1 must not report a false pass", fqdn, target.DNSGateAddr, target.TLSProxyAddr, LiveEnvVar)
		})
	}
}

// TestLiveGateDefaultsOff documents and pins the default posture: with the env var
// unset, the live half does not run. This test ALWAYS runs (it is the proof the
// suite is offline-by-default) and never touches the network.
func TestLiveGateDefaultsOff(t *testing.T) {
	orig, had := os.LookupEnv(LiveEnvVar)
	if err := os.Unsetenv(LiveEnvVar); err != nil {
		t.Fatalf("unset %s: %v", LiveEnvVar, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(LiveEnvVar, orig)
		}
	})
	if LiveEnabled() {
		t.Fatalf("%s unset must leave the live half disabled", LiveEnvVar)
	}
}
