// SPDX-License-Identifier: Apache-2.0

package resolverlock

// Shared drifted-pack corpus walk — the GO half of the one-artifact-two-readers
// lockstep proof (D64/D74, D50 synthetic).
//
// ONE corpus, two readers, zero per-language copies. The drifted-pack fixtures
// under testdata/drift-corpus/fixtures/ are the SAME bytes the Rust integration
// test dataplane/crates/policy-core/tests/pack_drift_corpus.rs walks (it reaches
// them via a CARGO_MANIFEST_DIR-relative path into THIS testdata directory). The
// shipped pack itself proves one-artifact-two-readers for the WELL-FORMED case
// (resolverlock_test.go TestShippedPackHasNoDrift + the Rust TLS-1 suite both
// read pol2-system-baseline.pol1.yaml); this corpus closes the MALFORMED case —
// the gap the task names: a shape both readers must reject was never proven to
// produce the same verdict on both sides.
//
// The honest lockstep model. The two readers do NOT have identical rejection
// surfaces — and pretending they did would be a false claim. The Go offline
// scanner (parseResolverLockBlocklist) is a resolver-lock-shape tripwire: it
// guards the `blocklist:` section's shape (renamed/quoted key, flow/anchor
// shapes, missing reason/rung, non-exact-lowercase FQDN) and is blind to the
// rest of the document. The Rust ds_contracts::pol1::parse_layer is a full POL-1
// schema reader: it guards schema drift (unknown tier, missing provenance,
// missing/invalid rung token, multi-document/tab syntax) and tolerates a
// resolver-lock blocklist the Go side would reject. So each fixture carries an
// EXPECTED (go, rust) verdict PAIR, and the corpus proves three things at once:
//
//   1. the TRUE both-reject case (anchor/alias) — a malformed shape BOTH readers
//      must reject DOES reject on both, on the identical bytes;
//   2. COMPLEMENTARY COVERAGE — every other malformed fixture is caught by at
//      least ONE reader (never silently accepted by BOTH), and the table records
//      WHICH reader owns each class so a coverage hole is visible;
//   3. the both-ACCEPT agreement cases (duplicate FQDN, reordered/comment-only
//      families) — benign shapes neither reader rejects, pinned so a future
//      regression that started rejecting one on a SINGLE side is caught.
//
// This file asserts the GO column of every pair AND the full-coverage count, so
// a fixture added to the corpus directory but not registered here fails THIS
// side until wired — the lockstep fail-closed the task requires (the Rust test
// enforces the mirror on its column). Adding a fixture for one reader therefore
// fails the OTHER reader's build until both tables list it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

// goVerdict is the Go offline scanner's expected outcome for a corpus fixture:
// either it ACCEPTS (extracts a non-empty blocklist with no error) or it REJECTS.
//
// Two reject strengths, mirroring the Rust column's RustVerdict (Reject /
// RejectExact in pack_drift_corpus.rs):
//
//   - PRESENCE (exact==false): the named rejectVia sentinel must appear SOMEWHERE
//     in the returned error tree (errors.Is). The right tool for a SINGLE-cause
//     drift class — it pins the rejection reason without over-constraining an error
//     tree that might legitimately wrap more than one sentinel.
//   - EXACT SET (exact==true): the DISTINCT set of KNOWN resolverlock sentinels
//     present in the returned error tree must EQUAL exactly the rejectVia sentinel
//     — no extras, no substitutes. Presence-only is too weak for the COMPOUND
//     both-reject fixtures (20-23): each drifts BOTH reader surfaces on one
//     artifact under INDEPENDENT causes, so a regression that JOINED a spurious
//     EXTRA sentinel into the scanner's error tree would still satisfy errors.Is
//     and slip through. The exact-set arm bites that — any sentinel from the
//     exported universe outside the declared one fails the fixture.
type goVerdict struct {
	accept bool
	// rejectVia is the named sentinel the scanner must return when accept==false;
	// nil when accept==true. Naming the SPECIFIC sentinel (not just "an error")
	// keeps the per-class verdict precise — a drift that started failing for a
	// DIFFERENT reason than declared is itself a regression this catches.
	rejectVia error
	// exact, when true, upgrades the presence check (errors.Is over rejectVia) to
	// an EXACT-SET check over the exported sentinel universe: the set of KNOWN
	// sentinels present in the error tree must equal exactly {rejectVia}. Mirrors
	// the Rust RejectExact arm. Used for the compound both-reject rows 20-23.
	exact bool
}

func goAccept() goVerdict        { return goVerdict{accept: true} }
func goReject(s error) goVerdict { return goVerdict{accept: false, rejectVia: s} }

// goRejectExact is the exact-set mirror of the Rust RejectExact arm: the scanner
// must reject AND the DISTINCT set of KNOWN resolverlock sentinels present in the
// returned error tree must equal EXACTLY {s} — no extra cause sentinel may have
// crept in. Applied to the compound both-reject rows 20-23, where presence-only
// (errors.Is) is too weak to catch a spurious extra sentinel joined into the tree.
func goRejectExact(s error) goVerdict {
	return goVerdict{accept: false, rejectVia: s, exact: true}
}

// goExactSetMatches is the PURE exact-set MEMBERSHIP decision the goRejectExact arm of the
// corpus walk (TestDriftCorpusGoVerdicts) makes: the parsed DISTINCT set of KNOWN sentinels
// (present, from presentSentinels) must equal EXACTLY the declared wanted SET — it carries every
// wanted sentinel and NOTHING ELSE. It is VARIADIC over the wanted sentinels so it generalizes
// from the SINGLETON case (the original `len(present) == 1 && errors.Is(present[0], want)`, the
// shape every committed goRejectExact row uses today) to the MULTI-ELEMENT case the Rust
// RejectExact arm already exercises on fixture 27 (`RejectExact(&[BadValue, MissingProvenance])`)
// — so the moment a multi-sentinel goRejectExact row lands on the Go column, the bite already
// compares the WHOLE declared set, not just a singleton.
//
// The semantic is EXACT-SET EQUALITY (mirroring the Rust RejectExact): the DISTINCT present set
// and the DISTINCT wanted set must have the SAME size AND every wanted sentinel must be
// errors.Is-present. So, unlike the presence check (errors.Is over the whole tree):
//   - a SUPERSET (a spurious EXTRA sentinel joined into a compound reject path) does NOT match
//     (size differs) and is FLAGGED — the case presence-only would still pass;
//   - a SUBSTITUTE member (right size, wrong member) does NOT match (a wanted member is absent);
//   - a proper SUBSET (a wanted member missing, e.g. under-extraction) does NOT match;
//   - a DISJOINT set does NOT match.
//
// Only the EXACT set passes. The production guard CALLS this function (with a single rejectVia),
// and so does the table self-test (TestGoExactSetMatches) over synthetic singleton AND
// multi-element wanted sets — mirroring how siblingRejectsOnGoColumn / allowlistExempts /
// nameReconciledAcrossSets lift their inlined decision into a pinned pure helper. A future edit
// that weakened the bite (dropped the size clause so an extra sentinel slipped through, or
// stopped requiring every wanted member) flips the self-test RED rather than silently widening
// the exact-set arm the goRejectExact rows depend on.
func goExactSetMatches(present []error, want ...error) bool {
	// DISTINCT wanted set (the caller may legitimately repeat a sentinel; dedupe so the size
	// comparison is over distinct cause classes, matching presentSentinels' distinct semantics).
	wantDistinct := sortedDistinctSentinels(want)
	if len(present) != len(wantDistinct) {
		return false
	}
	for _, w := range wantDistinct {
		found := false
		for _, p := range present {
			if errors.Is(p, w) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// TestGoExactSetMatches pins the goRejectExact arm's FAIL-CLOSED exact-set membership semantic
// against accidental weakening. The corpus walk's exact-set bite (TestDriftCorpusGoVerdicts)
// passes a goRejectExact fixture ONLY when its parsed distinct sentinel set is EXACTLY the
// declared singleton — the declared sentinel present and no other. That behaviour was previously
// INLINED (`len(got) != 1 || !errors.Is(got[0], want.rejectVia)`) and proven only by code reading,
// so an edit that dropped the length clause (letting a spurious EXTRA sentinel slip past) or
// compared the wrong member would silently widen the exact-set arm while the per-class verdict
// stayed green. This table drives the SAME goExactSetMatches helper the production guard calls over
// SYNTHETIC sentinel sets (D50 — no corpus fixture is touched; the real verdict table is unchanged),
// asserting the four exact-set membership axes: the EXACT singleton MATCHES; an extra-sentinel
// SUPERSET does NOT; a SUBSTITUTE member (right size, wrong sentinel) does NOT; a DISJOINT
// multi-element set (no member is the declared one) does NOT; and the empty set — the only proper
// SUBSET of a singleton want — does NOT. Only the EXACT set passes.
func TestGoExactSetMatches(t *testing.T) {
	// Synthetic distinct sentinel sets built from the exported universe values (D50 — no fixture,
	// no production table touched). Each input mirrors a presentSentinels result shape (sorted,
	// distinct); the want is the declared singleton the goRejectExact row carries.
	cases := []struct {
		name    string
		present []error
		want    []error
		match   bool
		comment string
	}{
		{
			name:    "exact singleton -> MATCHES",
			present: []error{ErrBadFQDN},
			want:    []error{ErrBadFQDN},
			match:   true,
			comment: "the declared sentinel present and nothing else — the only singleton set the goRejectExact arm accepts",
		},
		{
			name:    "superset (declared + spurious extra) -> does NOT match",
			present: sortedDistinctSentinels([]error{ErrBadFQDN, ErrUnsupportedShape}),
			want:    []error{ErrBadFQDN},
			match:   false,
			comment: "an EXTRA sentinel joined into the compound reject path must fail the exact-set bite (the case presence-only errors.Is would still pass)",
		},
		{
			name:    "substitute member (right size, wrong sentinel) -> does NOT match",
			present: []error{ErrUnsupportedShape},
			want:    []error{ErrBadFQDN},
			match:   false,
			comment: "a single sentinel that is NOT the declared one is a wrong-reason reject; the exact-set arm must flag it",
		},
		{
			name:    "disjoint multi-element set (no member is the declared one) -> does NOT match",
			present: sortedDistinctSentinels([]error{ErrUnsupportedShape, ErrEntryMissingFields}),
			want:    []error{ErrBadFQDN},
			match:   false,
			comment: "a multi-element set DISJOINT from the declared singleton (neither member is it) is the generalized substitute — it fails on BOTH clauses (wrong size AND no member errors.Is the want); the exact-set arm must flag it",
		},
		{
			name:    "empty set (the only proper SUBSET of a singleton want) -> does NOT match",
			present: nil,
			want:    []error{ErrBadFQDN},
			match:   false,
			comment: "no known sentinel present is the empty set — the only proper subset of the declared singleton {want}; under-extraction (the declared sentinel absent) cannot equal {want} and must be flagged",
		},
		// ── MULTI-ELEMENT exact-set axes (the generalized arm) ─────────────────────────────────
		// Synthetic multi-sentinel wanted sets (D50 — no committed goRejectExact row is multi-element
		// today; the Go scanner's compound rows 20-23/27 are singletons). These pin that the moment a
		// multi-sentinel goRejectExact row lands, the bite already compares the WHOLE declared set —
		// mirroring the Rust RejectExact(&[BadValue, MissingProvenance]) shape fixture 27 carries.
		{
			name:    "exact MULTI-ELEMENT set -> MATCHES",
			present: sortedDistinctSentinels([]error{ErrBadFQDN, ErrUnsupportedShape}),
			want:    []error{ErrBadFQDN, ErrUnsupportedShape},
			match:   true,
			comment: "the POSITIVE multi-element MATCH axis: the distinct present set equals EXACTLY the two-element wanted set (every wanted member present, no extra) — this is the case the generalized goExactSetMatches must accept and the original singleton-only form could never reach",
		},
		{
			name:    "exact MULTI-ELEMENT set, want order permuted -> MATCHES (order-insensitive)",
			present: sortedDistinctSentinels([]error{ErrBadFQDN, ErrUnsupportedShape}),
			want:    []error{ErrUnsupportedShape, ErrBadFQDN},
			match:   true,
			comment: "the wanted set is a SET — its declaration order must not matter; the same two members in either order match the same present set",
		},
		{
			name:    "MULTI-ELEMENT want with a duplicate -> MATCHES (deduped to its distinct set)",
			present: []error{ErrBadFQDN},
			want:    []error{ErrBadFQDN, ErrBadFQDN},
			match:   true,
			comment: "a wanted set that repeats a sentinel (mirroring fixture 22's MissingProvenance-twice benign duplication) is deduped to its DISTINCT set {ErrBadFQDN}, which equals the singleton present set",
		},
		{
			name:    "MULTI-ELEMENT want, present MISSING one member (proper subset) -> does NOT match",
			present: []error{ErrBadFQDN},
			want:    []error{ErrBadFQDN, ErrUnsupportedShape},
			match:   false,
			comment: "the present set is a proper SUBSET of the two-element wanted set (one wanted cause class absent) — under-extraction on a multi-cause reject must fail the exact-set bite",
		},
		{
			name:    "MULTI-ELEMENT want, present carries a SPURIOUS extra beyond the set -> does NOT match",
			present: sortedDistinctSentinels([]error{ErrBadFQDN, ErrUnsupportedShape, ErrEntryMissingFields}),
			want:    []error{ErrBadFQDN, ErrUnsupportedShape},
			match:   false,
			comment: "a three-element present SUPERSET of the two-element wanted set (one spurious extra cause) must fail — the multi-element generalization keeps the no-extra bite presence-only would miss",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := goExactSetMatches(tc.present, tc.want...)
			if got != tc.match {
				t.Fatalf("goExactSetMatches(%v, %v) = %v, want %v — %s. The goRejectExact arm must "+
					"match ONLY on the EXACT declared set: a SUPERSET carrying a spurious extra "+
					"sentinel, a SUBSTITUTE member, a DISJOINT set, or a proper SUBSET (missing a wanted "+
					"member) must NOT match, while the EXACT set — singleton OR multi-element, in any "+
					"order — MUST; a future edit that dropped the size clause or stopped requiring every "+
					"wanted member would silently widen the exact-set bite the compound both-reject rows "+
					"depend on.", tc.present, tc.want, got, tc.match, tc.comment)
			}
		})
	}
}

// sentinelPresent is the PURE broader PRESENCE decision the reject arm of the corpus walk
// (TestDriftCorpusGoVerdicts) makes BEFORE the goRejectExact exact-set bite layers on top:
// the named want sentinel must appear SOMEWHERE in the returned error tree (`errors.Is(err,
// want)`). It is the SINGLE-cause-precise companion of goExactSetMatches — every reject row
// (presence-only goReject AND exact-set goRejectExact) routes its reason check through this
// helper, and the exact-set rows THEN tighten it with the set-equality bite. The production
// guard CALLS this function, and so does the table self-test (TestSentinelPresent), so both
// exercise the SAME errors.Is presence code path — mirroring how goExactSetMatches /
// siblingRejectsOnGoColumn / allowlistExempts / nameReconciledAcrossSets each lift their
// inlined decision into a pinned pure helper.
//
// It is DELIBERATELY the LOOSER of the two reject checks: unlike goExactSetMatches (which
// FLAGS an error tree carrying a sentinel beyond the wanted one), sentinelPresent ACCEPTS a
// tree that wraps EXTRA sentinels as long as the wanted one is present — that gap is exactly
// what the exact-set arm exists to tighten on the compound both-reject rows (20-23, 27). A
// future edit that swapped the errors.Is presence semantic for an equality/exact-match check
// (or for a shallow == that misses a wrapped sentinel) would flip the self-test RED rather
// than silently changing the reason check every reject row depends on.
func sentinelPresent(err error, want error) bool {
	return errors.Is(err, want)
}

// TestSentinelPresent pins the reject arm's broader PRESENCE semantic against accidental
// weakening or tightening. TestDriftCorpusGoVerdicts gates every reject fixture with a
// PRESENCE check (the wanted sentinel must be errors.Is-present SOMEWHERE in the returned
// error tree) before the goRejectExact rows layer the exact-set bite on top. That check was
// previously INLINED (`!errors.Is(perr, want.rejectVia)`) and proven only by code reading, so
// an edit that replaced it with a tighter equality (rejecting a tree that wraps EXTRA
// sentinels — the very shape the presence arm must TOLERATE and the exact-set arm exists to
// catch) or a shallow comparison (missing a deeply-wrapped sentinel) would silently change the
// reason check every reject row depends on. This table drives the SAME sentinelPresent helper
// the production guard calls over SYNTHETIC error trees (D50 — no corpus fixture is touched;
// the real verdict table is unchanged), asserting: a tree wrapping the wanted sentinel returns
// true; a tree wrapping a DIFFERENT known sentinel returns false; a nil/plain error returns
// false; and — the load-bearing FAIL-CLOSED looseness — a tree carrying EXTRA sentinels BEYOND
// the wanted one still returns true (the presence helper is deliberately the looser of the two;
// pinning that EXTRA-sentinel tree returns true is what makes the exact-set arm's job visible).
func TestSentinelPresent(t *testing.T) {
	// Synthetic error trees built from the exported universe values (D50 — no fixture, no
	// production table touched). fmt.Errorf("%w") wrapping mirrors how the scanner layers a
	// sentinel into a returned tree; a multi-%w wrap mirrors a compound reject path carrying
	// more than one known sentinel.
	wantedWrapped := fmt.Errorf("scanner context: %w", ErrBadFQDN)
	deeplyWrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", ErrBadFQDN))
	otherWrapped := fmt.Errorf("scanner context: %w", ErrUnsupportedShape)
	extraSentinels := fmt.Errorf("compound reject: %w and %w", ErrBadFQDN, ErrUnsupportedShape)
	cases := []struct {
		name    string
		err     error
		want    error
		present bool
		comment string
	}{
		{
			name:    "tree wrapping the wanted sentinel -> PRESENT",
			err:     wantedWrapped,
			want:    ErrBadFQDN,
			present: true,
			comment: "the wanted sentinel errors.Is-present in the tree is the reason check passing — the only shape a reject row's presence gate accepts at minimum",
		},
		{
			name:    "tree DEEPLY wrapping the wanted sentinel -> PRESENT",
			err:     deeplyWrapped,
			want:    ErrBadFQDN,
			present: true,
			comment: "errors.Is must unwrap the WHOLE chain — a shallow == would miss a deeply-nested sentinel the scanner legitimately wraps",
		},
		{
			name:    "tree wrapping a DIFFERENT known sentinel -> NOT present",
			err:     otherWrapped,
			want:    ErrBadFQDN,
			present: false,
			comment: "a reject for the WRONG reason (a substitute sentinel) must fail the presence gate — this is the wrong-reason regression the named-sentinel check catches",
		},
		{
			name:    "nil error -> NOT present",
			err:     nil,
			want:    ErrBadFQDN,
			present: false,
			comment: "a clean accept (nil) carries no sentinel; the presence gate must reject it (silent under-extraction is the failure the corpus exists to catch)",
		},
		{
			name:    "plain (sentinel-free) error -> NOT present",
			err:     errors.New("some unrelated failure"),
			want:    ErrBadFQDN,
			present: false,
			comment: "an error tree that carries NO known sentinel cannot satisfy the wanted-sentinel presence check",
		},
		{
			name:    "tree carrying EXTRA sentinels beyond the wanted one -> STILL present (deliberately loose)",
			err:     extraSentinels,
			want:    ErrBadFQDN,
			present: true,
			comment: "the load-bearing fail-closed looseness: presence ACCEPTS a tree wrapping extra sentinels as long as the wanted one is there — that is the exact gap the goRejectExact exact-set arm exists to tighten (goExactSetMatches FLAGS this same tree)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sentinelPresent(tc.err, tc.want)
			if got != tc.present {
				t.Fatalf("sentinelPresent(%v, %v) = %v, want %v — %s. The reject arm's "+
					"broader presence check must be the LOOSER errors.Is membership test (the "+
					"wanted sentinel present SOMEWHERE in the tree, extra sentinels tolerated): "+
					"a tighter equality that rejected an extra-sentinel tree would usurp the "+
					"exact-set arm's job, and a shallow comparison that missed a deeply-wrapped "+
					"sentinel would fail a legitimate reject — either silently changing the reason "+
					"check every reject row depends on.", tc.err, tc.want, got, tc.present, tc.comment)
			}
		})
	}
}

// namedSentinel pairs an exported resolverlock sentinel VALUE with its source-level
// NAME. The value drives the exact-set errors.Is scan (presentSentinels); the name
// is what TestExportedSentinelUniverseComplete reconciles against the `Err* =
// errors.New(...)` declarations parsed out of EVERY non-_test.go file in the package,
// so a sentinel added to the source but not to this universe (or vice versa) fails
// LOUDLY by name rather
// than slipping past the value-only scan. Carrying the name here is the test-file-
// local structural tweak the completeness guard needs; it does not weaken the
// value-based exact-set assertion that consumes the universe (presentSentinels still
// ranges over the VALUES via universeSentinelErrors()).
type namedSentinel struct {
	name string
	err  error
}

// exportedSentinelUniverse is the COMPLETE set of resolverlock sentinels the
// scanner can return — the universe the exact-set assertion scans for in a
// returned error tree. It must enumerate every Err* the package exports; the
// scanner cannot reject with any sentinel outside this set, so an exact-set check
// over it is a check over the WHOLE cause space. Mirrors the Rust column, whose
// RejectExact compares against the bundle's full distinct PolicyErrorCode set.
//
// Each row carries the source NAME alongside the VALUE so the completeness guard
// (TestExportedSentinelUniverseComplete) can reconcile this table against the
// `Err* = errors.New(...)` declarations across ALL non-_test.go package files BY NAME
// — fail-closed in BOTH directions. The name MUST match the identifier exactly as
// declared in source.
var exportedSentinelUniverse = []namedSentinel{
	// POL-2 pack shape-drift sentinels (resolverlock.go) — the cause space the
	// drift-corpus exact-set scan (presentSentinels) actually exercises.
	{"ErrNoBlocklistSection", ErrNoBlocklistSection},
	{"ErrEmptyBlocklist", ErrEmptyBlocklist},
	{"ErrUnsupportedShape", ErrUnsupportedShape},
	{"ErrEntryMissingFields", ErrEntryMissingFields},
	{"ErrBadFQDN", ErrBadFQDN},
	{"ErrCountMismatch", ErrCountMismatch},
	// NFT-4 resolver-bypass-closure shape sentinels (nft4_closure.go). The
	// completeness guard reconciles this table against EVERY non-_test.go package
	// file BY NAME, so these must be enumerated here; they belong to the NFT-4
	// artifact-shape cause space (port-53 / DoT / QUIC), never the POL-2 pack
	// parse, so they never appear in a drift-corpus presentSentinels result.
	{"ErrNoPort53Capture", ErrNoPort53Capture},
	{"ErrPort53SourceIPMatch", ErrPort53SourceIPMatch},
	{"ErrNoDoTDrop", ErrNoDoTDrop},
	{"ErrQUICNotRejected", ErrQUICNotRejected},
	{"ErrQUICNotPortUnreachable", ErrQUICNotPortUnreachable},
	{"ErrQUICMissingCounter", ErrQUICMissingCounter},
	{"ErrNoUDP443Rule", ErrNoUDP443Rule},
	// Per-control iifname-anchoring sentinels (nft4_closure.go): the udp/443 QUIC
	// reject and the port-853 DoT drops must read the unforgeable iifname (the
	// dstap-* attachment point), never a forgeable ip saddr (doc 03 §3, doc 06 (c),
	// D44/D69). Same NFT-4 artifact-shape cause space as the rows above, so they
	// never appear in a drift-corpus presentSentinels result either.
	{"ErrQUICNotInterfaceAnchored", ErrQUICNotInterfaceAnchored},
	{"ErrDoTNotInterfaceAnchored", ErrDoTNotInterfaceAnchored},
}

// universeSentinelErrors returns the VALUE view of the universe — the []error the
// value-based exact-set scan (presentSentinels) consumes. Keeping the scan on the
// values (not names) preserves the landed value-based exact-set assertion verbatim;
// the names ride alongside purely for the completeness reconciliation.
func universeSentinelErrors() []error {
	out := make([]error, 0, len(exportedSentinelUniverse))
	for _, s := range exportedSentinelUniverse {
		out = append(out, s.err)
	}
	return out
}

// presentSentinels returns the SORTED, distinct subset of the exported sentinel
// universe that errors.Is finds in the returned error tree — the scanner's actual
// cause SET for a rejection. Sorted by the sentinel's message string for a stable,
// deterministic order (no production change needed), matching the Rust column's
// sorted_code_labels discipline for set comparison.
func presentSentinels(err error) []error {
	var present []error
	for _, s := range universeSentinelErrors() {
		if errors.Is(err, s) {
			present = append(present, s)
		}
	}
	for i := 1; i < len(present); i++ {
		for j := i; j > 0 && present[j].Error() < present[j-1].Error(); j-- {
			present[j], present[j-1] = present[j-1], present[j]
		}
	}
	return present
}

// goCorpusExpectations is the GO column of the per-class (go, rust) verdict
// table, keyed by fixture filename. The Rust test holds the mirror table for its
// column. Every fixture file in the corpus MUST appear here exactly once; the
// coverage assertion below fails closed on any unlisted (or stale) key. The
// trailing comment on each row records the RUST column for the reader, so the
// full lockstep pair is visible in one place even though Rust asserts it.
var goCorpusExpectations = map[string]goVerdict{
	// ── both ACCEPT — the well-formed control + benign-shape agreement cases ──
	"00-good-baseline.pol1.yaml":         goAccept(), // rust: accept (control)
	"17-duplicate-fqdn.pol1.yaml":        goAccept(), // rust: accept (benign dup)
	"18-reordered-families.pol1.yaml":    goAccept(), // rust: accept (order-insensitive)
	"19-comment-only-families.pol1.yaml": goAccept(), // rust: accept (comments stripped)

	// ── GO rejects, RUST accepts — resolver-lock-shape drift the schema parser
	//    tolerates (the Go offline half is the tripwire) ──────────────────────
	"01-missing-blocklist.pol1.yaml":    goReject(ErrNoBlocklistSection), // rust: accept
	"02-empty-blocklist.pol1.yaml":      goReject(ErrEmptyBlocklist),     // rust: accept
	"03-wildcard-fqdn.pol1.yaml":        goReject(ErrBadFQDN),            // rust: accept
	"04-uppercase-fqdn.pol1.yaml":       goReject(ErrBadFQDN),            // rust: accept
	"05-entry-missing-rung.pol1.yaml":   goReject(ErrEntryMissingFields), // rust: accept
	"06-entry-missing-reason.pol1.yaml": goReject(ErrEntryMissingFields), // rust: accept
	"07-flow-blocklist.pol1.yaml":       goReject(ErrUnsupportedShape),   // rust: accept
	"08-quoted-keys.pol1.yaml":          goReject(ErrNoBlocklistSection), // rust: accept

	// ── both REJECT — the TRUE lockstep case (identical bytes, reject on both) ─
	"09-anchor-alias-families.pol1.yaml": goReject(ErrUnsupportedShape), // rust: reject (Syntax)

	// ── GO accepts, RUST rejects — POL-1 schema drift outside the blocklist the
	//    Go scanner never inspects (the Rust schema parser is the tripwire) ─────
	"10-unknown-tier.pol1.yaml":             goAccept(), // rust: reject (BadValue)
	"11-empty-family-tier.pol1.yaml":        goAccept(), // rust: reject (BadValue)
	"12-entry-missing-provenance.pol1.yaml": goAccept(), // rust: reject (MissingProvenance)
	"13-missing-rung-guardrail.pol1.yaml":   goAccept(), // rust: reject (MissingRung)
	"14-bad-rung-token.pol1.yaml":           goAccept(), // rust: reject (BadRung)
	"15-multi-document.pol1.yaml":           goAccept(), // rust: reject (Syntax)
	"16-tab-indent.pol1.yaml":               goAccept(), // rust: reject (Syntax)

	// ── COMPOUND both REJECT — one artifact drifts BOTH reader surfaces at once
	//    (resolver-lock SHAPE + POL-1 SCHEMA) under INDEPENDENT causes: the Go
	//    sentinel and the Rust kind name DIFFERENT failures on the SAME bytes, so
	//    neither reader can mask the other's error. Distinct from 09 (both reject
	//    for the SAME cause, Syntax). Each Go row asserts its own SHAPE sentinel;
	//    the Rust mirror asserts its own SCHEMA kind.
	//
	//    These four are the EXACT-SET rows (goRejectExact, mirroring the Rust
	//    RejectExact arm): each declares the WHOLE distinct sentinel set its error
	//    tree may carry, not merely one sentinel present (goReject). Presence-only
	//    (errors.Is) is too weak HERE — a regression that JOINED a spurious extra
	//    sentinel into one of these compound scanner reject paths would still
	//    satisfy errors.Is and pass silently; the exact-set arm fails the fixture if
	//    ANY sentinel outside the declared one appears in the tree. The GO declared
	//    sets are SINGLETONS on EVERY row (the scanner returns on the FIRST shape it
	//    cannot model, one sentinel per reject), so the Go bite is always "no NEW
	//    sentinel crept in." The MULTI-element exact set lives on the RUST column:
	//    row 27 is the first committed fixture whose Rust bundle carries TWO distinct
	//    codes ({BadValue, MissingProvenance}); the Go mirror for 27 stays the
	//    SINGLETON goRejectExact(ErrBadFQDN) (uppercase blocklist FQDN), mirroring
	//    row 23. ─────────────────────────────────────────────────────────────────
	"20-quoted-key-unknown-tier.pol1.yaml":                 goRejectExact(ErrNoBlocklistSection), // rust: reject (BadValue)
	"21-flow-blocklist-bad-guardrail-rung.pol1.yaml":       goRejectExact(ErrUnsupportedShape),   // rust: reject (BadRung)
	"22-entry-missing-reason-missing-provenance.pol1.yaml": goRejectExact(ErrEntryMissingFields), // rust: reject (MissingProvenance)
	"23-uppercase-fqdn-missing-guardrail-rung.pol1.yaml":   goRejectExact(ErrBadFQDN),            // rust: reject (MissingRung)
	// Row 27 — the COMMITTED multi-cause fixture. Go rejects the uppercase blocklist
	// FQDN with the SINGLETON ErrBadFQDN (mirroring row 23); the MULTI-element exact
	// set is on the Rust column ({BadValue, MissingProvenance}), the first non-
	// singleton RejectExact on committed data.
	"27-uppercase-fqdn-unknown-tier-missing-provenance.pol1.yaml": goRejectExact(ErrBadFQDN), // rust: reject (BadValue, MissingProvenance)

	// ── COMPOUND both ACCEPT — the complement of 20-23: one artifact exercises
	//    BOTH reader surfaces at once (resolver-lock SHAPE + POL-1 SCHEMA) under
	//    INDEPENDENT benign axes, and BOTH accept. Each Go row is a benign SHAPE
	//    variation (the 17/18/19 classes: benign duplication, family reorder,
	//    comment-only block) paired with a Rust-benign SCHEMA variation on the SAME
	//    bytes. Pins benign acceptance across both axes so a regression that started
	//    REJECTING a benign compound on EITHER reader is caught (a fixture wired on
	//    one side only fails the other side's coverage gate). ─────────────────────
	"24-duplicate-fqdn-provenanced-entry.pol1.yaml":     goAccept(), // rust: accept (provenanced entry)
	"25-reordered-families-guardrail-rung.pol1.yaml":    goAccept(), // rust: accept (valid guardrail rung)
	"26-comment-only-guardrails-enabled-tier.pol1.yaml": goAccept(), // rust: accept (valid family tier)
}

// rustCorpusVerdict is the RUST column of the per-class (go, rust) verdict pair, as DATA
// rather than the trailing comment on each goCorpusExpectations row. Until this table the
// Rust verdict lived ONLY in `// rust: ...` prose — a comment is NOT machine-readable, so
// the per-class COMPLEMENTARY-COVERAGE invariant (every malformed fixture caught by at
// least ONE reader, never silently accepted by BOTH) could not be reconciled as a pinned
// predicate: a row edited to (accept, accept) for a malformed shape would silently widen the
// benign set with nothing going RED. Lifting the Rust column to DATA closes that gap (task
// 01KV3J6BKZZ90GSC5W2JZE4A37, implementation note (a)).
//
// This is the Go-test-local TRANSCRIPTION of the Rust verdict each fixture's trailing comment
// already declares (D50 synthetic — it touches no corpus byte and no production crate; the
// authoritative Rust assertion still lives in pack_drift_corpus.rs). It carries only what the
// complementary-coverage reconciliation needs:
//
//   - accept: whether the Rust POL-1 schema reader (ds_contracts::pol1::parse_layer) ACCEPTS
//     the fixture, mirroring the `// rust: accept` / `// rust: reject (...)` column comment;
//   - malformed: whether the fixture is a MALFORMED shape that SOME reader MUST catch (the
//     complementary-coverage invariant applies to it) versus a BENIGN / well-formed shape
//     whose (accept, accept) agreement is by DESIGN (the control + benign-shape rows
//     00/17/18/19 and their compound complements 24/25/26). For a benign fixture a both-accept
//     pair is CORRECT, not a coverage hole; the malformed flag is what lets the pure helper
//     tell a legitimate both-accept from a silent both-accept HOLE.
//
// Keyed by the SAME fixture filenames as goCorpusExpectations; the complementary-coverage gate
// (TestDriftCorpusComplementaryCoverage) reconciles the two tables key-for-key and fails closed
// on any fixture missing from EITHER, so a row added to one table but not the other cannot slip
// the gate. The Rust `accept` values transcribed here MUST stay in lockstep with the trailing
// `// rust: ...` comment on the matching goCorpusExpectations row (and with pack_drift_corpus.rs).
type rustCorpusVerdict struct {
	accept    bool
	malformed bool
}

var rustCorpusVerdicts = map[string]rustCorpusVerdict{
	// ── both ACCEPT — the well-formed control + benign-shape agreement cases. These are
	//    BENIGN (malformed:false): a both-accept pair is the CORRECT verdict, never a hole. ──
	"00-good-baseline.pol1.yaml":         {accept: true, malformed: false}, // rust: accept (control)
	"17-duplicate-fqdn.pol1.yaml":        {accept: true, malformed: false}, // rust: accept (benign dup)
	"18-reordered-families.pol1.yaml":    {accept: true, malformed: false}, // rust: accept (order-insensitive)
	"19-comment-only-families.pol1.yaml": {accept: true, malformed: false}, // rust: accept (comments stripped)

	// ── GO rejects, RUST accepts — resolver-lock-shape drift the schema parser tolerates.
	//    MALFORMED: the Go offline scanner is the sole reader that catches each (complementary
	//    coverage on the GO side). ────────────────────────────────────────────────────────
	"01-missing-blocklist.pol1.yaml":    {accept: true, malformed: true}, // rust: accept
	"02-empty-blocklist.pol1.yaml":      {accept: true, malformed: true}, // rust: accept
	"03-wildcard-fqdn.pol1.yaml":        {accept: true, malformed: true}, // rust: accept
	"04-uppercase-fqdn.pol1.yaml":       {accept: true, malformed: true}, // rust: accept
	"05-entry-missing-rung.pol1.yaml":   {accept: true, malformed: true}, // rust: accept
	"06-entry-missing-reason.pol1.yaml": {accept: true, malformed: true}, // rust: accept
	"07-flow-blocklist.pol1.yaml":       {accept: true, malformed: true}, // rust: accept
	"08-quoted-keys.pol1.yaml":          {accept: true, malformed: true}, // rust: accept

	// ── both REJECT — the TRUE lockstep case (identical bytes, reject on both). MALFORMED. ─
	"09-anchor-alias-families.pol1.yaml": {accept: false, malformed: true}, // rust: reject (Syntax)

	// ── GO accepts, RUST rejects — POL-1 schema drift outside the blocklist the Go scanner
	//    never inspects. MALFORMED: the Rust schema parser is the sole reader that catches each
	//    (complementary coverage on the RUST side). ───────────────────────────────────────
	"10-unknown-tier.pol1.yaml":             {accept: false, malformed: true}, // rust: reject (BadValue)
	"11-empty-family-tier.pol1.yaml":        {accept: false, malformed: true}, // rust: reject (BadValue)
	"12-entry-missing-provenance.pol1.yaml": {accept: false, malformed: true}, // rust: reject (MissingProvenance)
	"13-missing-rung-guardrail.pol1.yaml":   {accept: false, malformed: true}, // rust: reject (MissingRung)
	"14-bad-rung-token.pol1.yaml":           {accept: false, malformed: true}, // rust: reject (BadRung)
	"15-multi-document.pol1.yaml":           {accept: false, malformed: true}, // rust: reject (Syntax)
	"16-tab-indent.pol1.yaml":               {accept: false, malformed: true}, // rust: reject (Syntax)

	// ── COMPOUND both REJECT — one artifact drifts BOTH reader surfaces at once. MALFORMED. ─
	"20-quoted-key-unknown-tier.pol1.yaml":                        {accept: false, malformed: true}, // rust: reject (BadValue)
	"21-flow-blocklist-bad-guardrail-rung.pol1.yaml":              {accept: false, malformed: true}, // rust: reject (BadRung)
	"22-entry-missing-reason-missing-provenance.pol1.yaml":        {accept: false, malformed: true}, // rust: reject (MissingProvenance)
	"23-uppercase-fqdn-missing-guardrail-rung.pol1.yaml":          {accept: false, malformed: true}, // rust: reject (MissingRung)
	"27-uppercase-fqdn-unknown-tier-missing-provenance.pol1.yaml": {accept: false, malformed: true}, // rust: reject (BadValue, MissingProvenance)

	// ── COMPOUND both ACCEPT — the complement of 20-23: a benign SHAPE variation paired with
	//    a Rust-benign SCHEMA variation on ONE artifact. BENIGN (malformed:false): both-accept
	//    is the CORRECT verdict. ──────────────────────────────────────────────────────────
	"24-duplicate-fqdn-provenanced-entry.pol1.yaml":     {accept: true, malformed: false}, // rust: accept (provenanced entry)
	"25-reordered-families-guardrail-rung.pol1.yaml":    {accept: true, malformed: false}, // rust: accept (valid guardrail rung)
	"26-comment-only-guardrails-enabled-tier.pol1.yaml": {accept: true, malformed: false}, // rust: accept (valid family tier)
}

// ── The AUTHORITATIVE malformed-class source ────────────────────────────────────────────────
//
// rustCorpusVerdict.malformed is the load-bearing discriminator that lets the complementary-
// coverage gate (complementaryCoverage / TestDriftCorpusComplementaryCoverage) tell a legitimate
// benign both-accept (the control + benign-shape agreement rows 00/17/18/19/24/25/26) from a
// silent both-accept HOLE (a malformed shape NEITHER reader catches). But in rustCorpusVerdicts
// above it is HAND-SET per row with only a trailing prose comment — so a row mislabeled
// malformed:false on a genuinely MALFORMED class silently EXEMPTS itself from the both-accept-hole
// check (the gate treats it as coverageBenignAgreement), and nothing goes RED. The hand-set bool
// can drift from the truth and only a reviewer would catch it.
//
// These two sets are the AUTHORITATIVE malformed-class membership the lockstep already references
// — the SAME partition the file header draws: the well-formed control plus the benign-shape
// agreement classes (00/17/18/19 and their compound complements 24/25/26) are BENIGN, every other
// drift class is MALFORMED (a shape SOME reader must catch). They are keyed by the DRIFT-CLASS
// LABEL — classOf(fixture), which equals the `drift_class` tag the committed `<name>.provenance`
// D50 sidecar carries beside every fixture (testdata/drift-corpus/fixtures/*.provenance) — so the
// authoritative source is the fixture-provenance class, NOT the hand-set bool. malformedByClass
// derives the malformed flag from this partition; TestRustCorpusMalformedPinnedToClass reconciles
// every rustCorpusVerdicts row's hand-set malformed against the derived flag and fails CLOSED on
// any drift, so a mislabel goes RED instead of being reviewer-caught.
//
// Maintained fail-closed in BOTH directions (mirroring nameReconciledAcrossSets): every corpus
// drift class must appear in EXACTLY ONE set — a class in NEITHER is UNCLASSIFIED (a new fixture
// whose authoritative malformed-status was never declared) and is flagged, never silently
// defaulted; a class in BOTH is a contradiction and is flagged. This is test-only/additive (D50):
// no corpus byte and no production crate is touched, and the authoritative Rust assertion still
// lives in pack_drift_corpus.rs.
var benignDriftClasses = map[string]bool{
	// The well-formed control + the benign-shape agreement classes: a both-accept pair is the
	// CORRECT verdict for each (malformed:false), never a coverage hole.
	"good-baseline":                        true, // 00 — the well-formed control
	"duplicate-fqdn":                       true, // 17 — benign duplicate FQDN (shape, order-insensitive)
	"reordered-families":                   true, // 18 — benign family reorder (order-insensitive)
	"comment-only-families":                true, // 19 — comment-only block (comments stripped)
	"duplicate-fqdn-provenanced-entry":     true, // 24 — compound benign (dup FQDN ∪ provenanced entry)
	"reordered-families-guardrail-rung":    true, // 25 — compound benign (reorder ∪ valid guardrail rung)
	"comment-only-guardrails-enabled-tier": true, // 26 — compound benign (comment-only ∪ valid family tier)
}

var malformedDriftClasses = map[string]bool{
	// GO rejects, RUST accepts — resolver-lock-SHAPE drift the schema parser tolerates (the Go
	// offline scanner is the sole catcher).
	"missing-blocklist":    true, // 01
	"empty-blocklist":      true, // 02
	"wildcard-fqdn":        true, // 03
	"uppercase-fqdn":       true, // 04
	"entry-missing-rung":   true, // 05
	"entry-missing-reason": true, // 06
	"flow-blocklist":       true, // 07
	"quoted-keys":          true, // 08
	// both REJECT — the TRUE lockstep case (identical bytes reject on both).
	"anchor-alias-families": true, // 09
	// GO accepts, RUST rejects — POL-1 SCHEMA drift outside the blocklist (the Rust schema reader
	// is the sole catcher).
	"unknown-tier":             true, // 10
	"empty-family-tier":        true, // 11
	"entry-missing-provenance": true, // 12
	"missing-rung-guardrail":   true, // 13
	"bad-rung-token":           true, // 14
	"multi-document":           true, // 15
	"tab-indent":               true, // 16
	// COMPOUND both REJECT — one artifact drifts BOTH reader surfaces under INDEPENDENT causes.
	"quoted-key-unknown-tier":                        true, // 20
	"flow-blocklist-bad-guardrail-rung":              true, // 21
	"entry-missing-reason-missing-provenance":        true, // 22
	"uppercase-fqdn-missing-guardrail-rung":          true, // 23
	"uppercase-fqdn-unknown-tier-missing-provenance": true, // 27
}

// malformedByClass is the PURE per-class decision that DERIVES a fixture's authoritative malformed
// flag from the canonical malformed-class membership (benignDriftClasses / malformedDriftClasses)
// rather than trusting the hand-set rustCorpusVerdict.malformed bool. Given a drift-class label
// (classOf(fixture) — equal to the provenance sidecar's `drift_class`) it returns:
//
//   - malformed: true if the class is in malformedDriftClasses, false if in benignDriftClasses;
//   - classified: whether the class was found in EXACTLY ONE set. A class in NEITHER set is
//     UNCLASSIFIED (classified==false, malformed defaulting to true — fail-closed: an undeclared
//     class is treated as malformed-must-catch, never silently benign); a class in BOTH is a
//     contradiction (classified==false) the gate flags. The classified flag is what forbids a new
//     corpus fixture from silently defaulting its authoritative malformed-status.
//
// The reconciliation gate (TestRustCorpusMalformedPinnedToClass) CALLS this helper over the LIVE
// rustCorpusVerdicts rows, and the table self-test (TestMalformedByClass) drives it over SYNTHETIC
// class labels (D50 — no corpus fixture, no production crate touched), so both exercise the SAME
// membership code path — mirroring how nameReconciledAcrossSets / siblingRejectsOnGoColumn /
// goExactSetMatches / allowlistExempts each lift their inlined decision into a pinned pure helper.
// A future edit that weakened the partition (moved a malformed class into the benign set, or
// dropped a class so it silently defaulted) flips the self-test or the gate RED rather than
// silently widening the benign set the complementary-coverage check depends on.
func malformedByClass(class string) (malformed, classified bool) {
	inBenign := benignDriftClasses[class]
	inMalformed := malformedDriftClasses[class]
	switch {
	case inBenign && !inMalformed:
		return false, true
	case inMalformed && !inBenign:
		return true, true
	default:
		// NEITHER set (unclassified, undeclared) OR BOTH sets (contradiction): not cleanly
		// classified. Fail closed by reporting malformed=true (an undeclared class is treated as a
		// shape SOME reader must catch, never silently benign); the gate surfaces the !classified
		// signal and fails LOUDLY rather than trusting this default.
		return true, false
	}
}

// TestMalformedByClass pins the authoritative malformed-class derivation's FAIL-CLOSED semantic
// against accidental weakening. TestRustCorpusMalformedPinnedToClass reconciles every
// rustCorpusVerdicts row's hand-set malformed against malformedByClass(classOf(name)); the helper
// must report a benign class as malformed=false (classified), a malformed class as malformed=true
// (classified), and an UNCLASSIFIED class (in NEITHER set, or — a contradiction — in BOTH) as
// classified=false with malformed defaulting to true. That partition was the load-bearing
// authoritative source; an edit that moved a malformed class into the benign set (silently
// EXEMPTING it from the both-accept-hole check) or that let an undeclared class default to benign
// would re-open the silent-drift gap the hand-set bool already had. This table drives the SAME
// malformedByClass helper the gate calls over SYNTHETIC class labels (D50 — the real corpus,
// benignDriftClasses, and malformedDriftClasses partition are unchanged), asserting all four
// outcomes.
func TestMalformedByClass(t *testing.T) {
	cases := []struct {
		name           string
		class          string
		wantMalformed  bool
		wantClassified bool
		comment        string
	}{
		{
			name:           "benign class -> malformed=false, classified",
			class:          "good-baseline",
			wantMalformed:  false,
			wantClassified: true,
			comment:        "a well-formed/benign class is authoritatively malformed:false — a both-accept pair is correct by design, not a hole",
		},
		{
			name:           "malformed (go-only) class -> malformed=true, classified",
			class:          "missing-blocklist",
			wantMalformed:  true,
			wantClassified: true,
			comment:        "a resolver-lock-shape drift some reader must catch is authoritatively malformed:true; a hand-set malformed:false would be flagged by the gate",
		},
		{
			name:           "malformed (compound) class -> malformed=true, classified",
			class:          "uppercase-fqdn-unknown-tier-missing-provenance",
			wantMalformed:  true,
			wantClassified: true,
			comment:        "a compound both-reject class is authoritatively malformed:true",
		},
		{
			name:           "unclassified class (in NEITHER set) -> malformed=true, NOT classified",
			class:          "some-future-undeclared-class",
			wantMalformed:  true,
			wantClassified: false,
			comment:        "a class declared in NO partition set is UNCLASSIFIED: it defaults malformed=true (fail-closed — never silently benign) and classified=false so the gate flags it for explicit classification",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotMalformed, gotClassified := malformedByClass(tc.class)
			if gotMalformed != tc.wantMalformed || gotClassified != tc.wantClassified {
				t.Fatalf("malformedByClass(%q) = (malformed=%v, classified=%v), want (malformed=%v, "+
					"classified=%v) — %s. The authoritative derivation must report a benign class as "+
					"malformed:false and a malformed class as malformed:true (both classified), and an "+
					"UNCLASSIFIED class as classified=false with malformed defaulting to true: a helper "+
					"that let a malformed class read benign, or let an undeclared class default to benign, "+
					"would re-open the silent-drift gap the hand-set bool already had.", tc.class,
					gotMalformed, gotClassified, tc.wantMalformed, tc.wantClassified, tc.comment)
			}
		})
	}
}

// TestRustCorpusMalformedPinnedToClass PINS each rustCorpusVerdicts row's hand-set malformed flag
// against the AUTHORITATIVE malformed-class source (malformedByClass over classOf(fixture), the
// drift-class label the committed provenance sidecar carries), so the flag can no longer silently
// DRIFT from the canonical malformed-class membership the lockstep relies on. This closes the gap
// the task names: the malformed bool is the load-bearing discriminator the complementary-coverage
// gate uses to tell a legitimate benign both-accept from a silent both-accept HOLE, yet it was
// hand-asserted per row with only a prose comment — a row mislabeled malformed:false on a
// genuinely malformed class would EXEMPT itself from the both-accept-hole check and nothing would
// go RED.
//
// For EVERY fixture in rustCorpusVerdicts it derives the authoritative malformed flag from the
// fixture's drift class and asserts the hand-set value EQUALS it. A drift in EITHER direction is a
// hard failure, named:
//
//	(a) a row hand-set malformed:false on a MALFORMED class — the dangerous direction: it silently
//	    exempts a malformed fixture from the both-accept-hole check (the gate would read it as
//	    coverageBenignAgreement). Caught here.
//	(b) a row hand-set malformed:true on a BENIGN class — over-claims a benign shape as malformed,
//	    making the complementary-coverage gate demand a reader reject a legitimately-accepted shape.
//	    Caught here too.
//
// Fail-closed completeness: a fixture whose drift class is UNCLASSIFIED (in NEITHER partition set,
// or — a contradiction — in BOTH) fails LOUDLY (classified==false) — a new corpus fixture must be
// explicitly placed in benignDriftClasses or malformedDriftClasses, never default silently. The
// derivation (malformedByClass) is the pure predicate pinned fail-closed by TestMalformedByClass;
// the gate CALLS it over the LIVE table and the self-test drives it over synthetic labels, so both
// exercise the SAME membership code path — mirroring TestDriftCorpusComplementaryCoverage.
func TestRustCorpusMalformedPinnedToClass(t *testing.T) {
	if len(rustCorpusVerdicts) == 0 {
		t.Fatal("rustCorpusVerdicts is empty — the malformed-flag reconciliation has nothing to " +
			"pin; refusing to vacuously pass")
	}
	// Deterministic, name-stable iteration so a failure names the same fixture run-to-run.
	names := make([]string, 0, len(rustCorpusVerdicts))
	for name := range rustCorpusVerdicts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rustV := rustCorpusVerdicts[name]
		class := classOf(name)
		t.Run(name, func(t *testing.T) {
			wantMalformed, classified := malformedByClass(class)
			if !classified {
				t.Fatalf("fixture %s (drift class %q): its drift class is UNCLASSIFIED in the "+
					"authoritative malformed-class source — it is in NEITHER benignDriftClasses NOR "+
					"malformedDriftClasses (or, a contradiction, in BOTH). A fixture's authoritative "+
					"malformed-status must be DECLARED, never silently defaulted: place the class in "+
					"EXACTLY ONE of benignDriftClasses (a both-accept pair is correct) or "+
					"malformedDriftClasses (some reader must catch it). Until then the hand-set "+
					"malformed:%v cannot be reconciled.", name, class, rustV.malformed)
			}
			if rustV.malformed != wantMalformed {
				t.Fatalf("fixture %s (drift class %q): rustCorpusVerdicts hand-set malformed:%v, but "+
					"the AUTHORITATIVE malformed-class source says malformed:%v. The malformed flag is "+
					"the load-bearing discriminator the complementary-coverage gate uses to tell a "+
					"legitimate benign both-accept from a silent both-accept HOLE; a hand-set bool that "+
					"DRIFTS from the canonical class membership re-opens the silent-exemption gap (a row "+
					"mislabeled malformed:false on a malformed class would exempt itself from the "+
					"both-accept-hole check). Fix the hand-set flag to match the class, or — if the "+
					"class's malformed-status genuinely changed — move it between benignDriftClasses and "+
					"malformedDriftClasses (and update pack_drift_corpus.rs + the trailing comment in "+
					"lockstep).", name, class, rustV.malformed, wantMalformed)
			}
		})
	}
}

// ── Machine cross-pin against the Rust AUTHORITATIVE corpus (pack_drift_corpus.rs) ─────────────
//
// rustCorpusVerdicts transcribes the Rust verdict column (accept vs reject) by HAND, with the
// authority living only in the trailing `// rust: ...` prose comment — a comment is not
// machine-checked, so the Go transcription could silently drift from the actual Rust source. The
// AUTHORITATIVE Rust corpus is dataplane/crates/policy-core/tests/pack_drift_corpus.rs, whose verdict
// table is a sequence of `m.insert("<fixture>", <Accept|Reject(..)|RejectExact(..)>)` rows. This
// reader parses those rows at Go-test time and reconciles the Go `accept` column against them, so a
// ONE-SIDED edit — the Rust source changing a fixture's verdict without the Go transcription
// following (or vice-versa) — reddens loudly instead of being reviewer-caught. (We assert the
// accept/reject DISCRIMINATOR, the load-bearing axis the malformed-class partition and complementary-
// coverage gate consume; the specific reject CODE/sentinel mapping legitimately differs across the two
// readers and stays owned by each side's own per-class verdict test.)
//
// rustCorpusVerdict.malformed is itself cross-pinned to the provenance partition by
// TestRustCorpusMalformedPinnedToClass; this test pins the OTHER field, accept, to the Rust source —
// together they make rustCorpusVerdicts machine-authoritative on BOTH axes.

// packDriftCorpusRelPath is the path from THIS test file to the authoritative Rust corpus, anchored
// off runtime.Caller (same technique as CorpusFixturesDir / NFT4ArtifactPath) so the read works under
// `go test` from any cwd. Read-only: dataplane/** is never edited from the conformance adapter.
// The read routes THROUGH the tracked in-module symlink testdata/srclinks/… (not ../../../dataplane/…
// directly) so a warm test cache re-hashes the authoritative Rust corpus on change instead of serving
// a stale PASS after a one-sided verdict edit — see srclinks.go.
const packDriftCorpusRelPath = "testdata/srclinks/" + srcLinkPackDriftCorpus

// rustSourceAccepts parses the authoritative Rust corpus source and returns, per fixture filename, the
// Rust reader's ACCEPT verdict as DATA: Accept -> true, Reject(...) / RejectExact(...) -> false. It
// scans the `m.insert("<fixture>.pol1.yaml", <verdict>)` rows — tolerating the single-line and the
// multi-line (filename and verdict on separate lines) forms the source uses — by locating each quoted
// `*.pol1.yaml` key and reading the FIRST verdict keyword (Accept / Reject / RejectExact) that follows
// it before the next insert key. A read failure, zero parsed rows, or an unrecognised verdict token is
// a HARD failure (the cross-pin must never vacuously pass on a source it could not parse).
func rustSourceAccepts(t *testing.T) map[string]bool {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — cannot anchor the path to the authoritative Rust corpus")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(thisFile), packDriftCorpusRelPath))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the authoritative Rust corpus %s for the accept-column cross-pin: %v — the "+
			"Go rustCorpusVerdicts.accept column is reconciled against this source", path, err)
	}
	src := string(data)

	// SCOPE the parse to the verdict table function body (rust_corpus_expectations) only — the file
	// also defines compound_sibling_map(), whose m.insert(...) rows carry vec![...] of fixture names,
	// NOT verdicts; scanning the whole file would mis-read those. Slice from the function signature to
	// the next top-level `fn ` declaration.
	const verdictFn = "fn rust_corpus_expectations("
	fnStart := strings.Index(src, verdictFn)
	if fnStart < 0 {
		t.Fatalf("the authoritative Rust corpus %s no longer defines %q — the verdict-table function "+
			"was renamed or removed; the cross-pin parser must be updated in lockstep", path, verdictFn)
	}
	body := src[fnStart+len(verdictFn):]
	if nextFn := strings.Index(body, "\nfn "); nextFn >= 0 {
		body = body[:nextFn]
	}
	src = body

	out := make(map[string]bool)
	const insertTok = "m.insert("
	// Walk every `m.insert(` occurrence left-to-right via an advancing cursor.
	for cursor := 0; ; {
		rel := strings.Index(src[cursor:], insertTok)
		if rel < 0 {
			break
		}
		// rest begins at the insert's argument list; advance the cursor past this token so the
		// next iteration finds the FOLLOWING insert.
		rest := src[cursor+rel+len(insertTok):]
		cursor = cursor + rel + len(insertTok)

		// Find the quoted fixture key that opens this insert.
		q1 := strings.IndexByte(rest, '"')
		if q1 < 0 {
			break
		}
		q2 := strings.IndexByte(rest[q1+1:], '"')
		if q2 < 0 {
			break
		}
		key := rest[q1+1 : q1+1+q2]
		if !strings.HasSuffix(key, ".pol1.yaml") {
			// Not a fixture insert (defensive — the table inserts only fixture keys); skip it.
			continue
		}
		// The verdict is the FIRST Accept/Reject/RejectExact keyword after the key, up to the next
		// insert (so a multi-line insert's verdict on the following line is still captured).
		afterKey := rest[q1+1+q2:]
		if nextInsert := strings.Index(afterKey, insertTok); nextInsert >= 0 {
			afterKey = afterKey[:nextInsert]
		}
		accept, found := firstRustVerdictAccepts(afterKey)
		if !found {
			t.Fatalf("the authoritative Rust corpus row for fixture %q (in %s) carries no recognised "+
				"verdict keyword (Accept / Reject / RejectExact) — the cross-pin parser cannot classify "+
				"it; the source row shape changed and the parser must be updated in lockstep", key, path)
		}
		out[key] = accept
	}
	if len(out) == 0 {
		t.Fatalf("parsed ZERO m.insert(...) verdict rows from the authoritative Rust corpus %s — the "+
			"source layout changed out from under the cross-pin parser; refusing to vacuously pass", path)
	}
	return out
}

// firstRustVerdictAccepts inspects a slice of Rust source (the text right after a fixture key, up to
// the next insert) and returns (accept, found) for the FIRST verdict keyword it carries: an Accept
// token -> (true, true); a Reject or RejectExact token -> (false, true); none found -> (false, false).
// RejectExact is tested BEFORE Reject so the longer keyword is not mis-read as a bare Reject (both map
// to accept=false, but the precedence keeps the classification unambiguous).
func firstRustVerdictAccepts(s string) (accept, found bool) {
	iAccept := strings.Index(s, "Accept")
	iReject := strings.Index(s, "Reject")
	switch {
	case iAccept < 0 && iReject < 0:
		return false, false
	case iReject < 0:
		return true, true
	case iAccept < 0:
		return false, true
	case iAccept < iReject:
		return true, true
	default:
		return false, true
	}
}

// TestRustCorpusAcceptPinnedToRustSource machine cross-pins every Go rustCorpusVerdicts.accept value
// against the AUTHORITATIVE Rust corpus source (pack_drift_corpus.rs), so the hand transcription can no
// longer silently drift from the Rust verdict the `// rust: ...` prose claims. It reconciles the two
// tables key-for-key, fail-closed in BOTH directions:
//
//	(a) every fixture in rustCorpusVerdicts MUST appear in the Rust source, with the SAME accept value
//	    (a Go row claiming accept where the Rust source rejects — or vice-versa — is the silent-drift
//	    the task names; caught here naming the fixture);
//	(b) every fixture row in the Rust source MUST appear in rustCorpusVerdicts (a fixture added to the
//	    Rust authority but not transcribed Go-side is a coverage hole on the Go column).
//
// Together with TestRustCorpusMalformedPinnedToClass (which pins the malformed field to the provenance
// partition) this makes rustCorpusVerdicts machine-authoritative on BOTH fields. Test-only/additive
// (D50): it READS the Rust source, touches no corpus byte and no production crate, and the
// authoritative Rust assertion still lives in pack_drift_corpus.rs.
func TestRustCorpusAcceptPinnedToRustSource(t *testing.T) {
	rustAccepts := rustSourceAccepts(t)
	if len(rustCorpusVerdicts) == 0 {
		t.Fatal("rustCorpusVerdicts is empty — nothing to cross-pin against the Rust source")
	}

	// (a) FORWARD: every Go row matches the Rust source.
	goNames := make([]string, 0, len(rustCorpusVerdicts))
	for name := range rustCorpusVerdicts {
		goNames = append(goNames, name)
	}
	sort.Strings(goNames)
	for _, name := range goNames {
		rustAccept, present := rustAccepts[name]
		if !present {
			t.Errorf("fixture %q is in the Go rustCorpusVerdicts table but NOT in the authoritative "+
				"Rust corpus (pack_drift_corpus.rs) — the Go transcription references a fixture the Rust "+
				"authority does not declare; add it to the Rust source or drop the stale Go row", name)
			continue
		}
		if rustCorpusVerdicts[name].accept != rustAccept {
			t.Errorf("fixture %q: the Go rustCorpusVerdicts hand-set accept:%v DISAGREES with the "+
				"authoritative Rust corpus, which says accept:%v (Accept -> accept; Reject/RejectExact -> "+
				"reject). The hand transcription drifted from the Rust source the `// rust: ...` prose "+
				"claims — fix the Go accept value to match pack_drift_corpus.rs (or, if the Rust verdict "+
				"genuinely changed, update BOTH the Rust source and the Go row in lockstep).", name,
				rustCorpusVerdicts[name].accept, rustAccept)
		}
	}

	// (b) REVERSE: every Rust source row is transcribed Go-side.
	rustNames := make([]string, 0, len(rustAccepts))
	for name := range rustAccepts {
		rustNames = append(rustNames, name)
	}
	sort.Strings(rustNames)
	for _, name := range rustNames {
		if _, present := rustCorpusVerdicts[name]; !present {
			t.Errorf("fixture %q is declared in the authoritative Rust corpus (pack_drift_corpus.rs) but "+
				"is MISSING from the Go rustCorpusVerdicts table — a fixture added to the Rust authority "+
				"without a Go transcription leaves the Go accept column blind to it; add the row", name)
		}
	}
}

// TestMalformedClassPartitionTotalAndDisjoint reconciles the authoritative malformed-class source
// (benignDriftClasses ∪ malformedDriftClasses) against the LIVE corpus, fail-closed in BOTH
// directions, so the partition can neither go stale nor leave a fixture unclassified:
//
//	(a) DISJOINT: no drift class appears in BOTH sets (a class in both would make malformedByClass
//	    report classified=false — a contradiction — for a fixture the gate then rejects).
//	(b) TOTAL: every fixture present in rustCorpusVerdicts has its drift class declared in EXACTLY
//	    ONE set — a corpus fixture whose class is in NEITHER set is unclassified and is flagged here
//	    (so a new fixture lands with an explicit benign-or-malformed classification, mirroring the
//	    append-only-at-the-tail corpus convention in PROVENANCE.md).
//	(c) NO STALE ROW: every class listed in either partition set corresponds to an actual fixture
//	    in rustCorpusVerdicts — a partition row for a renamed/removed class is a stale entry that
//	    can never match, eroding the source's meaning (the direction-(b) stale-row guard
//	    TestExportedSentinelUniverseComplete enforces for the sentinel universe).
//
// This is the structural completeness companion to TestRustCorpusMalformedPinnedToClass (which
// pins each row's VALUE): together they make the authoritative source TOTAL, DISJOINT, and free of
// stale rows. Test-only/additive (D50): no corpus byte, no production crate touched.
func TestMalformedClassPartitionTotalAndDisjoint(t *testing.T) {
	// (a) DISJOINT — no class in both sets.
	for class := range benignDriftClasses {
		if malformedDriftClasses[class] {
			t.Errorf("drift class %q is listed in BOTH benignDriftClasses AND malformedDriftClasses "+
				"— the authoritative malformed-class source must be a clean PARTITION (each class in "+
				"exactly one set); a class in both makes malformedByClass report classified=false (a "+
				"contradiction) for every fixture of that class", class)
		}
	}

	// Collect the drift classes the live corpus actually carries.
	corpusClasses := make(map[string]bool, len(rustCorpusVerdicts))
	for name := range rustCorpusVerdicts {
		corpusClasses[classOf(name)] = true
	}

	// (b) TOTAL — every corpus class is declared in exactly one partition set.
	for class := range corpusClasses {
		_, classified := malformedByClass(class)
		if !classified {
			t.Errorf("corpus drift class %q is UNCLASSIFIED — it is declared in NEITHER "+
				"benignDriftClasses NOR malformedDriftClasses (or, a contradiction, in both). Every "+
				"corpus fixture must carry an explicit authoritative malformed-status; add the class "+
				"to EXACTLY ONE partition set (a both-accept pair is correct -> benign; some reader "+
				"must catch it -> malformed)", class)
		}
	}

	// (c) NO STALE ROW — every partition entry corresponds to an actual corpus fixture.
	for class := range benignDriftClasses {
		if !corpusClasses[class] {
			t.Errorf("benignDriftClasses lists drift class %q but NO fixture of that class exists in "+
				"rustCorpusVerdicts — a stale/renamed partition row that can never match; drop or "+
				"rename it to track the corpus", class)
		}
	}
	for class := range malformedDriftClasses {
		if !corpusClasses[class] {
			t.Errorf("malformedDriftClasses lists drift class %q but NO fixture of that class exists "+
				"in rustCorpusVerdicts — a stale/renamed partition row that can never match; drop or "+
				"rename it to track the corpus", class)
		}
	}
}

// ── The .provenance sidecar: the MACHINE-AUTHORITATIVE drift-class source ──────────────────────
//
// Every committed fixture carries a `<name>.pol1.yaml.provenance` D50 sidecar (JSON) beside it
// under testdata/drift-corpus/fixtures/, declaring the fixture's `drift_class` (plus provenance/
// seam/created/note). Until this reader the Go partition (benignDriftClasses / malformedDriftClasses)
// keyed on classOf(filename) — the class STRIPPED FROM THE FILENAME — while the sidecar's
// authoritative drift_class tag was never read, so a COORDINATED RENAME (rename the fixture file AND
// its partition row in lockstep, but diverge from the sidecar — or rename the sidecar's drift_class
// without renaming the file) went uncaught: the filename-derived class and the authoritative sidecar
// class could silently drift apart and only a reviewer would notice.
//
// driftClassSidecar parses the sidecar JSON; sidecarDriftClass(fixture) reads the sidecar beside a
// fixture and returns its declared drift_class. TestDriftClassDerivedFromProvenanceSidecar makes the
// sidecar the SINGLE AUTHORITATIVE SOURCE: for every fixture on disk it asserts the filename-derived
// classOf EQUALS the sidecar's drift_class AND that class is partition-classified — so a one-sided
// rename (file vs. sidecar vs. partition) reddens loudly instead of slipping past.
type driftClassSidecar struct {
	DSFixture struct {
		Provenance string `json:"provenance"`
		Seam       string `json:"seam"`
		DriftClass string `json:"drift_class"`
	} `json:"ds_fixture"`
}

// provenanceSidecarSuffix is appended to a fixture filename to name its sidecar
// (e.g. "09-anchor-alias-families.pol1.yaml" -> "...pol1.yaml.provenance").
const provenanceSidecarSuffix = ".provenance"

// sidecarDriftClass reads the committed .provenance sidecar beside a fixture and returns its
// declared, authoritative drift_class. A missing sidecar, unreadable bytes, malformed JSON, or an
// empty drift_class is a HARD failure (the sidecar is the single source of truth — a fixture without
// a well-formed one cannot be machine-classified, and refusing to default keeps the derivation
// fail-closed). The sidecar carries SYNTHETIC provenance only (D50): this reader touches no live
// system and no production crate.
func sidecarDriftClass(t *testing.T, fixture string) string {
	t.Helper()
	path := filepath.Join(CorpusFixturesDir(), fixture+provenanceSidecarSuffix)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the provenance sidecar %s for fixture %q: %v — every corpus fixture MUST "+
			"carry a <name>.provenance sidecar declaring its authoritative drift_class (the single "+
			"source the partition is derived from)", path, fixture, err)
	}
	var sc driftClassSidecar
	if err := json.Unmarshal(data, &sc); err != nil {
		t.Fatalf("parsing the provenance sidecar %s for fixture %q: %v — the sidecar must be the "+
			"D50 {\"ds_fixture\":{... \"drift_class\":...}} JSON shape", path, fixture, err)
	}
	if sc.DSFixture.DriftClass == "" {
		t.Fatalf("the provenance sidecar %s for fixture %q carries an EMPTY drift_class — the "+
			"authoritative drift-class source cannot be empty; declare it", path, fixture)
	}
	return sc.DSFixture.DriftClass
}

// TestDriftClassDerivedFromProvenanceSidecar makes the committed .provenance sidecar the SINGLE
// MACHINE-AUTHORITATIVE drift-class source the partition is cross-checked against. For EVERY fixture
// present on disk it reconciles three things that previously could silently diverge:
//
//	(1) PROVENANCE ⇔ FILENAME: the sidecar's declared drift_class EQUALS classOf(filename). A
//	    coordinated rename that touched the filename (and the hand-maintained partition rows) but NOT
//	    the sidecar — or the reverse — makes these disagree and reddens here. This is the "one-sided
//	    edit fails loudly" provenance single-source the task requires: the filename-stripped class can
//	    no longer drift from the authoritative sidecar tag unnoticed.
//	(2) PROVENANCE ⇒ PARTITION: that authoritative class is classified in EXACTLY ONE partition set
//	    (benignDriftClasses xor malformedDriftClasses). A fixture whose sidecar declares a class the
//	    partition never placed is UNCLASSIFIED and fails — the authoritative malformed-status must be
//	    DECLARED, never silently defaulted.
//	(3) NO VACUOUS PASS: the corpus is non-empty (listCorpusFixtures fatals on an empty dir), so the
//	    loop cannot pass over zero fixtures.
//
// This closes the gap the task names: the Go drift partition is now DERIVED FROM / CROSS-CHECKED
// AGAINST the authoritative sidecar source rather than being a hand-maintained filename mirror. It is
// test-only/additive (D50): it reads the committed synthetic sidecars, touches no corpus byte and no
// production crate, and the authoritative Rust assertion still lives in pack_drift_corpus.rs.
func TestDriftClassDerivedFromProvenanceSidecar(t *testing.T) {
	fixtures := listCorpusFixtures(t) // fatals on an empty corpus — no vacuous pass.
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			authoritative := sidecarDriftClass(t, name)
			derived := classOf(name)
			// (1) PROVENANCE ⇔ FILENAME single-source.
			if authoritative != derived {
				t.Fatalf("fixture %q: the AUTHORITATIVE .provenance sidecar declares drift_class %q "+
					"but the filename-derived class is %q — these MUST agree. The partition "+
					"(benignDriftClasses/malformedDriftClasses) is keyed on the filename-derived class, "+
					"so a one-sided rename (the file/partition renamed without the sidecar, or the "+
					"sidecar's drift_class renamed without the file) silently diverges the partition from "+
					"its authoritative source. Rename ALL of {fixture file, its .provenance drift_class, "+
					"the partition row} in lockstep.", name, authoritative, derived)
			}
			// (2) PROVENANCE ⇒ PARTITION classification.
			if _, classified := malformedByClass(authoritative); !classified {
				t.Fatalf("fixture %q: its authoritative drift_class %q (from the .provenance sidecar) is "+
					"UNCLASSIFIED — it is in NEITHER benignDriftClasses NOR malformedDriftClasses (or, a "+
					"contradiction, in BOTH). The sidecar is the single source the partition derives from; "+
					"place this class in EXACTLY ONE partition set so its authoritative malformed-status is "+
					"declared, never silently defaulted.", name, authoritative)
			}
		})
	}
}

// coverageOwner labels WHICH reader(s) catch a fixture under the complementary-coverage
// invariant — surfaced by the gate and the self-test so a coverage hole names itself rather
// than failing with a bare boolean. Mirrors the file header's promise that "the table records
// WHICH reader owns each class so a coverage hole is visible".
type coverageOwner int

const (
	// coverageHole: a MALFORMED fixture that BOTH readers accept — the silent both-accept hole
	// the complementary-coverage invariant exists to forbid. NEVER a passing state.
	coverageHole coverageOwner = iota
	// coverageGoOnly: the Go offline scanner rejects, the Rust schema reader accepts (a
	// resolver-lock-SHAPE drift the schema parser tolerates).
	coverageGoOnly
	// coverageRustOnly: the Rust schema reader rejects, the Go scanner accepts (a POL-1 SCHEMA
	// drift outside the blocklist the Go scanner never inspects).
	coverageRustOnly
	// coverageBoth: BOTH readers reject (the true both-reject lockstep case).
	coverageBoth
	// coverageBenignAgreement: a BENIGN / well-formed fixture both readers ACCEPT — by DESIGN,
	// not a hole. The complementary-coverage invariant does not apply.
	coverageBenignAgreement
)

func (o coverageOwner) String() string {
	switch o {
	case coverageHole:
		return "HOLE (malformed, both readers ACCEPT — silent both-accept)"
	case coverageGoOnly:
		return "go-only (Go scanner rejects, Rust accepts)"
	case coverageRustOnly:
		return "rust-only (Rust schema reader rejects, Go accepts)"
	case coverageBoth:
		return "both (Go and Rust both reject)"
	case coverageBenignAgreement:
		return "benign-agreement (well-formed/benign, both accept by design)"
	default:
		return "unknown"
	}
}

// coverageOwnerUniverse is the COMPLETE, hand-declared set of coverageOwner enum values —
// the universe the complementary-coverage gate's owner labels range over, mirroring the
// exportedSentinelUniverse backstop for the Err* sentinels. It pairs each value with its
// source NAME so the completeness guard (TestCoverageOwnerUniverseComplete) can reconcile
// this table against the `const ( … coverageOwner = iota … )` block parsed out of THIS
// test file's AST — fail-closed in BOTH directions, exactly as TestExportedSentinelUniverse-
// Complete reconciles the sentinel universe against the source `Err* = errors.New(...)`
// declarations.
//
// WHY this sweep exists. The conform4 wave closed the silent-weakening gap for the
// PolicyErrorCode universe (Rust) and the resolverlock Err* sentinel universe (Go): an
// exact-set bite scanning a HAND-DECLARED universe is only as strong as that universe being
// pinned exhaustive against the production definition. The SAME pattern — a switch/map keyed
// on enum values with a `default` catch-all, fed from a hand-listed universe with no compile-
// time exhaustiveness trip — recurs HERE for the in-package coverageOwner enum the corpus
// asserts on (the Go-mirror analog of the Rust Rung/Tier/PolicyLayer enum sweep: those POL-1
// schema enums live on the Rust side; coverageOwner is the enum THIS Go reader owns). Go has
// no compile-time exhaustive `match`, so a new coverageOwner constant appended to the const
// block without a String() case would fall to the `default: "unknown"` arm and a new value
// returned by complementaryCoverage without a universe row would go unchecked — silently,
// with only code review standing guard. This guard removes that gap: it pins the universe
// EXHAUSTIVE against the declared constants AND pins every declared value to a non-"unknown"
// String() label (so no value reaches the default arm). Test-only/additive (D50): no
// production-crate change, no corpus fixture touched.
var coverageOwnerUniverse = []struct {
	name  string
	value coverageOwner
}{
	{"coverageHole", coverageHole},
	{"coverageGoOnly", coverageGoOnly},
	{"coverageRustOnly", coverageRustOnly},
	{"coverageBoth", coverageBoth},
	{"coverageBenignAgreement", coverageBenignAgreement},
}

// declaredCoverageOwnerConsts parses THIS test file's AST and returns the source NAMES of
// every package-level const declared with the explicit type `coverageOwner` OR riding the
// same `= iota` const group (a const block whose first spec types itself `coverageOwner =
// iota` carries its type implicitly down the group). This is the test-file-local analog of
// declaredExportedSentinels (which parses the package source for `Err* = errors.New(...)`):
// it lets the completeness guard reconcile the hand-declared coverageOwnerUniverse against
// the ACTUAL enum constants, so a constant added to the const block but not the universe
// table (or a stale universe row) is caught by NAME, fail-closed, rather than slipping past.
func declaredCoverageOwnerConsts(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, thisTestFilePath(t), nil, 0)
	if err != nil {
		t.Fatalf("parsing this test file for the coverageOwner enum scan: %v", err)
	}
	var names []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		// A const GROUP inherits the type of its first typed spec down the iota run, so we
		// track whether THIS group is the coverageOwner group: it is iff some spec in the
		// group names the type `coverageOwner`.
		groupIsCoverageOwner := false
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if id, ok := vs.Type.(*ast.Ident); ok && id.Name == "coverageOwner" {
				groupIsCoverageOwner = true
				break
			}
		}
		if !groupIsCoverageOwner {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, ident := range vs.Names {
				if ident.Name == "_" {
					continue
				}
				names = append(names, ident.Name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// TestCoverageOwnerUniverseComplete is the fail-closed UNIVERSE-COMPLETENESS sweep for the
// coverageOwner enum — the Go-mirror analog of the Rust Rung/Tier/PolicyLayer enum sweep, and
// the structural twin of TestExportedSentinelUniverseComplete. It removes the silent-weakening
// gap that a hand-declared enum universe (with a `default`-armed String() switch and no Go
// compile-time exhaustive match) carries: a new coverageOwner constant added to the const
// block without a universe row / String() case would otherwise fall to the "unknown" arm
// unnoticed. It asserts THREE things, each a real (non-vacuous) bite:
//
//	(a) EXHAUSTIVE in BOTH directions: the coverageOwnerUniverse table and the const block
//	    parsed from this file's AST enumerate the SAME set of names — a constant declared but
//	    missing from the universe (it would escape the owner-label range) and a universe row
//	    with no declared constant (a stale entry) BOTH fail LOUDLY, named.
//	(b) NO DEFAULT ARM: every value in the universe has a NON-"unknown" String() label, so no
//	    declared coverageOwner value reaches the `default: "unknown"` arm — the arm exists only
//	    as a fail-safe for an UNlisted value, and a listed value hitting it is a regression.
//	(c) DISTINCT VALUES + LABELS: the universe values are distinct (a duplicated iota would
//	    collapse two owners) and the String() labels are distinct (no two owners share a label,
//	    so a coverage-hole message always names the right owner).
//
// Proven (via a reverted SCRATCH, never committed): appending a sixth `coverageUnknownFuture`
// constant to the const block without adding a universe row trips direction-(a) naming it;
// deleting a String() case so a listed value returns "unknown" trips direction-(b) naming it.
func TestCoverageOwnerUniverseComplete(t *testing.T) {
	declared := declaredCoverageOwnerConsts(t)
	if len(declared) == 0 {
		t.Fatalf("parsed this test file but found ZERO coverageOwner enum constants — the const " +
			"block (coverageHole = iota …) must declare the enum values; the scan is broken, " +
			"refusing to vacuously pass the universe-completeness sweep")
	}

	declaredSet := make(map[string]bool, len(declared))
	for _, n := range declared {
		declaredSet[n] = true
	}
	universeSet := make(map[string]bool, len(coverageOwnerUniverse))
	for _, o := range coverageOwnerUniverse {
		if universeSet[o.name] {
			t.Errorf("coverageOwnerUniverse lists %q more than once — each enum value must appear "+
				"exactly once so the owner-label range is a clean set", o.name)
		}
		universeSet[o.name] = true
	}

	// (a) EXHAUSTIVE — reuse the SAME by-name reconciliation the sentinel universe uses
	//     (nameReconciledAcrossSets, pinned fail-closed by TestNameReconciledAcrossSets):
	//     a name in only ONE set does NOT reconcile and is flagged.
	for _, n := range declared {
		if !nameReconciledAcrossSets(universeSet, declaredSet, n) {
			t.Errorf("coverageOwner constant %s is declared in the const block but is MISSING from "+
				"coverageOwnerUniverse — it would escape the universe-completeness sweep and the "+
				"complementary-coverage gate's owner-label range. Add {%q, %s} to "+
				"coverageOwnerUniverse (and a String() case) so the enum universe stays exhaustive",
				n, n, n)
		}
	}
	for _, o := range coverageOwnerUniverse {
		if !nameReconciledAcrossSets(universeSet, declaredSet, o.name) {
			t.Errorf("coverageOwnerUniverse lists %q but NO coverageOwner constant by that name is "+
				"declared in the const block — a stale/renamed universe row that can never match; "+
				"drop or rename it to track the enum", o.name)
		}
	}
	// Count parity belt-and-suspenders (catches a duplicate masking a gap), mirroring the
	// sentinel universe's count check.
	if len(coverageOwnerUniverse) != len(declared) {
		t.Fatalf("coverageOwner universe count mismatch: %d constants declared %v, %d rows in "+
			"coverageOwnerUniverse — the universe must enumerate the enum values EXACTLY "+
			"(fail-closed completeness)", len(declared), declared, len(coverageOwnerUniverse))
	}

	// (b) NO DEFAULT ARM — every declared value has a non-"unknown" String() label, so no
	//     listed coverageOwner value reaches the `default: "unknown"` fail-safe. A listed value
	//     returning "unknown" means a String() case was dropped (the enum drifted from its
	//     label map without a compile-time trip — exactly the gap this sweep closes).
	for _, o := range coverageOwnerUniverse {
		if got := o.value.String(); got == "unknown" {
			t.Errorf("coverageOwner value %s (=%d) renders String()=%q — it reached the "+
				"`default: \"unknown\"` arm, meaning its String() case is MISSING. Every declared "+
				"enum value must carry an explicit label; the default arm is a fail-safe for an "+
				"UNLISTED value only, never a declared one", o.name, int(o.value), got)
		}
	}

	// (c) DISTINCT VALUES + LABELS — distinct iota values (a duplicate would collapse two
	//     owners into one) and distinct labels (no two owners share a message, so a coverage-
	//     hole report always names the right owner).
	seenValue := make(map[coverageOwner]string, len(coverageOwnerUniverse))
	seenLabel := make(map[string]string, len(coverageOwnerUniverse))
	for _, o := range coverageOwnerUniverse {
		if prev, dup := seenValue[o.value]; dup {
			t.Errorf("coverageOwner values %s and %s share the SAME underlying int (%d) — two "+
				"distinct owners must not collapse to one iota value (an owner mislabel would "+
				"follow)", prev, o.name, int(o.value))
		}
		seenValue[o.value] = o.name
		label := o.value.String()
		if prev, dup := seenLabel[label]; dup {
			t.Errorf("coverageOwner values %s and %s share the SAME String() label %q — each owner "+
				"must render a distinct message so a coverage-hole report names the right one",
				prev, o.name, label)
		}
		seenLabel[label] = o.name
	}
}

// complementaryCoverage is the PURE per-class complementary-coverage decision the drift
// corpus gate (TestDriftCorpusComplementaryCoverage) makes for each fixture: given the GO
// reader's accept/reject verdict, the RUST reader's accept/reject verdict, and whether the
// fixture is MALFORMED, it reports WHICH reader(s) own the class (coverageOwner) and whether
// the per-class complementary-coverage invariant RECONCILES (reconciles==true) or is a silent
// both-accept HOLE (reconciles==false).
//
// The load-bearing invariant — every MALFORMED fixture is caught by at least ONE reader,
// NEVER silently accepted by BOTH — is exactly: a malformed (accept, accept) pair does NOT
// reconcile (it is coverageHole); every other malformed pair reconciles because some reader
// rejects (go-only / rust-only / both); and a BENIGN fixture's (accept, accept) reconciles
// by design (coverageBenignAgreement — both-accept is the CORRECT verdict, not a hole). A
// benign fixture that REJECTED on a reader would be a different regression, owned by the
// per-class verdict walk (TestDriftCorpusGoVerdicts) and the Rust mirror; here a benign reject
// is still reported by owner (go-only/rust-only/both) and reconciles==true, because this gate's
// ONE job is the both-accept-hole prohibition, not re-asserting benign acceptance.
//
// This was previously INLINED only as the file header's prose ("COMPLEMENTARY COVERAGE — every
// other malformed fixture is caught by at least ONE reader") and the trailing `// rust: ...`
// comments — proven by code reading, never as a reconcilable predicate. Lifting it into this
// pure helper, which the production gate CALLS over the LIVE (go, rust) tables and the table
// self-test (TestComplementaryCoverage) drives over SYNTHETIC pairs, pins it so a fixture row
// edited to a malformed (accept, accept) — the silent both-accept hole — flips the gate (and a
// weakening of the helper flips the self-test) RED rather than silently widening the benign set.
// Mirrors how reconcileCorpusCoverage / siblingRejectsOnGoColumn / goExactSetMatches /
// allowlistExempts / nameReconciledAcrossSets each lift their inlined decision into a pinned
// pure helper the production guard and its self-test share.
func complementaryCoverage(goAccepts, rustAccepts, malformed bool) (owner coverageOwner, reconciles bool) {
	switch {
	case goAccepts && rustAccepts:
		if malformed {
			// The silent both-accept HOLE: a malformed shape NEITHER reader catches. The one
			// state the complementary-coverage invariant forbids.
			return coverageHole, false
		}
		// A benign/well-formed shape both readers accept — correct by design.
		return coverageBenignAgreement, true
	case !goAccepts && rustAccepts:
		// Go scanner is the sole catcher (resolver-lock-shape drift).
		return coverageGoOnly, true
	case goAccepts && !rustAccepts:
		// Rust schema reader is the sole catcher (POL-1 schema drift).
		return coverageRustOnly, true
	default:
		// Both readers reject — the true both-reject lockstep case.
		return coverageBoth, true
	}
}

// TestComplementaryCoverage pins the per-class complementary-coverage invariant's FAIL-CLOSED
// semantic against accidental weakening. TestDriftCorpusComplementaryCoverage reconciles, for
// every fixture, that a MALFORMED shape is caught by at least ONE reader — that NO malformed
// fixture is a silent (accept, accept) hole — and labels which reader(s) own each class. That
// reconciliation lived ONLY as the file-header prose and the trailing `// rust: ...` comments,
// proven by code reading; an edit that flipped a malformed row to (accept, accept), or that
// loosened the helper to treat a malformed both-accept as benign, would silently widen the
// benign set while every per-class verdict stayed green. This table drives the SAME
// complementaryCoverage helper the production gate calls over SYNTHETIC (go, rust, malformed)
// triples (D50 — no corpus fixture is touched; the real rustCorpusVerdicts / goCorpusExpectations
// tables are unchanged), asserting: a fully complementary-covered malformed class (some reader
// rejects) RECONCILES with the right owner; a malformed class accepted by BOTH is FLAGGED (a
// coverageHole, reconciles==false); and a benign both-accept reconciles by design.
func TestComplementaryCoverage(t *testing.T) {
	cases := []struct {
		name           string
		goAccepts      bool
		rustAccepts    bool
		malformed      bool
		wantOwner      coverageOwner
		wantReconciles bool
		comment        string
	}{
		{
			name:           "malformed, go rejects rust accepts -> reconciles (go-only)",
			goAccepts:      false,
			rustAccepts:    true,
			malformed:      true,
			wantOwner:      coverageGoOnly,
			wantReconciles: true,
			comment:        "a resolver-lock-shape drift the schema parser tolerates: the Go offline scanner is the sole reader that catches it — complementary coverage on the Go side",
		},
		{
			name:           "malformed, go accepts rust rejects -> reconciles (rust-only)",
			goAccepts:      true,
			rustAccepts:    false,
			malformed:      true,
			wantOwner:      coverageRustOnly,
			wantReconciles: true,
			comment:        "a POL-1 schema drift outside the blocklist the Go scanner never inspects: the Rust schema reader is the sole catcher — complementary coverage on the Rust side",
		},
		{
			name:           "malformed, both reject -> reconciles (both)",
			goAccepts:      false,
			rustAccepts:    false,
			malformed:      true,
			wantOwner:      coverageBoth,
			wantReconciles: true,
			comment:        "the true both-reject lockstep case (identical bytes reject on both) — covered, not a hole",
		},
		{
			name:           "malformed, BOTH accept -> FLAGGED (coverage hole)",
			goAccepts:      true,
			rustAccepts:    true,
			malformed:      true,
			wantOwner:      coverageHole,
			wantReconciles: false,
			comment:        "THE fail-closed bite: a malformed shape NEITHER reader catches is the silent both-accept hole the complementary-coverage invariant forbids — it must NOT reconcile, or a fixture row edited to (accept, accept) for a malformed shape would silently widen the benign set",
		},
		{
			name:           "benign, both accept -> reconciles (benign agreement)",
			goAccepts:      true,
			rustAccepts:    true,
			malformed:      false,
			wantOwner:      coverageBenignAgreement,
			wantReconciles: true,
			comment:        "a well-formed/benign shape both readers accept is the CORRECT verdict by design — the malformed flag is what distinguishes it from a silent hole, so the invariant does not apply",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotOwner, gotReconciles := complementaryCoverage(tc.goAccepts, tc.rustAccepts, tc.malformed)
			if gotReconciles != tc.wantReconciles {
				t.Fatalf("complementaryCoverage(goAccepts=%v, rustAccepts=%v, malformed=%v) reconciles "+
					"= %v, want %v — %s. The complementary-coverage invariant must FLAG a malformed "+
					"(accept, accept) pair as a silent both-accept HOLE (reconciles==false) and "+
					"reconcile every pair where at least one reader rejects (or a benign both-accept); "+
					"a helper that treated a malformed both-accept as covered would silently widen the "+
					"benign set the corpus exists to bound.", tc.goAccepts, tc.rustAccepts, tc.malformed,
					gotReconciles, tc.wantReconciles, tc.comment)
			}
			if gotOwner != tc.wantOwner {
				t.Fatalf("complementaryCoverage(goAccepts=%v, rustAccepts=%v, malformed=%v) owner = %q, "+
					"want %q — %s. The owner label records WHICH reader(s) catch each class so a coverage "+
					"hole names itself; a mislabel would hide which reader's coverage drifted.",
					tc.goAccepts, tc.rustAccepts, tc.malformed, gotOwner, tc.wantOwner, tc.comment)
			}
		})
	}
}

// TestDriftCorpusComplementaryCoverage is the per-class COMPLEMENTARY-COVERAGE gate (the GO
// half). It reconciles, for EVERY fixture in the corpus, that a MALFORMED shape is caught by at
// least ONE reader — that NO malformed fixture is a silent (accept, accept) hole — and surfaces
// WHICH reader(s) own each class. It is the third pillar named in the file header (item 2,
// "COMPLEMENTARY COVERAGE"), previously asserted only in prose + the trailing `// rust: ...`
// comments; this pins it as a reconcilable invariant.
//
// The per-fixture decision — owner + reconciles — is the pure predicate complementaryCoverage,
// pinned fail-closed by TestComplementaryCoverage. The gate CALLS it over the LIVE (go, rust)
// verdict tables (goCorpusExpectations.accept × rustCorpusVerdicts.accept, with the malformed
// flag from rustCorpusVerdicts), so the gate keeps biting on the real tables while the self-test
// exercises the SAME code path over synthetic triples (D50) — mirroring how reconcileCorpusCoverage
// / goExactSetMatches lift their inlined decision into a pinned pure helper.
//
// Fail-closed in BOTH directions: a fixture present in one verdict table but not the other fails
// HERE (a row added to the Go column but not the Rust column, or vice versa, cannot slip the
// gate), and a malformed fixture accepted by BOTH readers fails as a coverageHole. So a fixture
// row edited to a malformed (accept, accept) — the silent both-accept hole — goes RED here rather
// than silently widening the benign set.
func TestDriftCorpusComplementaryCoverage(t *testing.T) {
	// Fail-closed key reconciliation: the Go and Rust verdict tables must enumerate the SAME
	// fixtures, so the complementary-coverage pairing is total. A fixture in one table but not
	// the other is a coverage gap (the per-class pair is undefined), flagged before the walk.
	for name := range goCorpusExpectations {
		if _, ok := rustCorpusVerdicts[name]; !ok {
			t.Errorf("fixture %s has a Go verdict (goCorpusExpectations) but NO Rust verdict "+
				"(rustCorpusVerdicts) — the per-class complementary-coverage pair is undefined; "+
				"every fixture must carry BOTH columns (fail-closed: a row added to one column "+
				"must be wired into the other)", name)
		}
	}
	for name := range rustCorpusVerdicts {
		if _, ok := goCorpusExpectations[name]; !ok {
			t.Errorf("fixture %s has a Rust verdict (rustCorpusVerdicts) but NO Go verdict "+
				"(goCorpusExpectations) — the per-class complementary-coverage pair is undefined; "+
				"every fixture must carry BOTH columns (fail-closed)", name)
		}
	}

	// Walk the corpus in a deterministic, name-stable order and reconcile each fixture's
	// (go, rust) pair through the pure helper. A malformed both-accept (coverageHole) fails.
	names := make([]string, 0, len(goCorpusExpectations))
	for name := range goCorpusExpectations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		goV := goCorpusExpectations[name]
		rustV, ok := rustCorpusVerdicts[name]
		if !ok {
			// Already reported above by the key reconciliation; skip the body so the
			// dedicated key check owns the fail-closed message.
			continue
		}
		t.Run(name, func(t *testing.T) {
			owner, reconciles := complementaryCoverage(goV.accept, rustV.accept, rustV.malformed)
			if !reconciles {
				t.Fatalf("fixture %s (drift class %q): COMPLEMENTARY-COVERAGE HOLE — it is a "+
					"MALFORMED shape that BOTH readers ACCEPT (go accepts=%v, rust accepts=%v). The "+
					"corpus invariant is that every malformed fixture is caught by at least ONE reader, "+
					"NEVER silently accepted by BOTH; a both-accept malformed fixture would silently "+
					"widen the benign set. Either the fixture is genuinely benign (set malformed:false "+
					"in rustCorpusVerdicts AND document why) or a reader's verdict drifted to accept "+
					"where it must reject (fix the verdict, not the flag). owner=%s", name, classOf(name),
					goV.accept, rustV.accept, owner)
			}
		})
	}
}

// listCorpusFixtures returns the sorted set of fixture filenames actually present
// on disk (the *.pol1.yaml files; the .provenance sidecars are excluded). This is
// the ground truth the coverage assertion reconciles against the expectation map.
// It uses CorpusFixturesDir() (runtime.Caller-anchored) so the walk works under
// `go test` from any cwd — same technique as ShippedPackPath.
func listCorpusFixtures(t *testing.T) []string {
	t.Helper()
	dir := CorpusFixturesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the drift corpus dir %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pol1.yaml") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatalf("the drift corpus at %s is empty — expected the shared drifted-pack "+
			"fixtures both readers walk", dir)
	}
	// names from os.ReadDir are already in directory order (sorted on Linux); sort
	// explicitly for cross-platform reproducibility.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// TestDriftCorpusGoVerdicts walks the shared corpus and asserts the GO column of
// every fixture's (go, rust) verdict pair against the SAME bytes the Rust test
// reads. A drift fixture that must reject does so with its NAMED sentinel; an
// accept fixture extracts a non-empty blocklist cleanly. The deny/extract verdict
// is asserted per class, not in bulk, so a fixture that drifted to a DIFFERENT
// verdict than declared (e.g. now rejects for the wrong reason, or now silently
// extracts where it should reject) fails loudly and names itself.
func TestDriftCorpusGoVerdicts(t *testing.T) {
	for _, name := range listCorpusFixtures(t) {
		want, ok := goCorpusExpectations[name]
		if !ok {
			// Coverage is asserted separately (TestDriftCorpusCoverageLockstep);
			// skip the per-class body here so the dedicated coverage test owns the
			// fail-closed message.
			continue
		}
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(CorpusFixturesDir(), name))
			if err != nil {
				t.Fatalf("reading corpus fixture %s: %v", name, err)
			}
			entries, perr := parseResolverLockBlocklist(string(data))
			if want.accept {
				if perr != nil {
					t.Fatalf("fixture %s must ACCEPT on the Go scanner (it is a "+
						"well-formed-or-Go-benign shape), got reject: %v", name, perr)
				}
				if len(entries) == 0 {
					t.Fatalf("fixture %s accepted but extracted an empty blocklist — "+
						"an accept must yield a non-empty resolver-lock set", name)
				}
				return
			}
			// Reject case: must fail, AND with the specific named sentinel.
			if perr == nil {
				t.Fatalf("fixture %s must REJECT on the Go scanner (drift class %q), "+
					"got a clean accept (silent under-extraction is the failure this "+
					"corpus exists to catch)", name, classOf(name))
			}
			// The broader PRESENCE decision — is the declared sentinel errors.Is-present
			// SOMEWHERE in the returned error tree? — is the pure predicate sentinelPresent,
			// pinned fail-closed by TestSentinelPresent. The production guard CALLS it and so
			// does the self-test, so both exercise the SAME errors.Is presence code path
			// (mirroring goExactSetMatches / siblingRejectsOnGoColumn / allowlistExempts). This
			// is the LOOSER reject check the goRejectExact exact-set bite below layers on top of;
			// an edit that tightened it (rejecting an extra-sentinel tree the exact-set arm owns)
			// flips the self-test RED rather than silently usurping that arm's job.
			if !sentinelPresent(perr, want.rejectVia) {
				t.Fatalf("fixture %s: Go scanner rejected for the WRONG reason — want "+
					"sentinel %v, got %v", name, want.rejectVia, perr)
			}
			if want.exact {
				// EXACT-SET bite (mirrors the Rust RejectExact arm): the DISTINCT set
				// of KNOWN sentinels errors.Is finds in the returned error tree must
				// equal EXACTLY {want.rejectVia}. Unlike the presence check above, this
				// FAILS if the tree carries ANY sentinel outside the declared one — so
				// a regression that JOINED a spurious extra sentinel into a compound
				// scanner reject path (which the presence check above would still pass)
				// is caught here.
				got := presentSentinels(perr)
				// The exact-set membership decision — does the parsed distinct sentinel SET
				// equal EXACTLY {want.rejectVia}? — is the pure predicate goExactSetMatches,
				// pinned fail-closed by TestGoExactSetMatches. The production guard CALLS it
				// and so does the self-test, so both exercise the SAME membership code path
				// (mirroring siblingRejectsOnGoColumn / allowlistExempts). An edit that
				// loosened the bite (accepted an extra sentinel, or a substitute) flips the
				// self-test RED rather than silently widening the exact-set arm.
				if !goExactSetMatches(got, want.rejectVia) {
					t.Fatalf("fixture %s: Go scanner's compound error sentinel SET drifted "+
						"— want EXACTLY {%v} (no more, no less), got %v. The compound "+
						"both-reject fixtures (20-23) declare INDEPENDENT causes; a sentinel "+
						"beyond the declared one means a spurious extra rejection cause crept "+
						"into the error tree. Full error: %v", name, want.rejectVia, got, perr)
				}
			}
		})
	}
}

// harvestBlocklistView reads a corpus fixture off disk and returns the Go offline
// scanner's EXTRACTED resolver-lock view ([]ResolverLockEntry) — the only thing the
// scanner can SEE. It harvests at the SAME layer the verdict test uses
// (parseResolverLockBlocklist) so the equality below compares the scanner's actual
// field of view, not a re-derivation. A scanner change that began surfacing the
// families/guardrails sections into this view is exactly what the premise test catches.
func harvestBlocklistView(t *testing.T, fixture string) []ResolverLockEntry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(CorpusFixturesDir(), fixture))
	if err != nil {
		t.Fatalf("reading corpus fixture %s: %v", fixture, err)
	}
	entries, perr := parseResolverLockBlocklist(string(data))
	if perr != nil {
		t.Fatalf("fixture %s must ACCEPT on the Go scanner to harvest its blocklist "+
			"view (it is a Go-benign both-accept shape), got reject: %v", fixture, perr)
	}
	if len(entries) == 0 {
		t.Fatalf("fixture %s accepted but harvested an empty blocklist view — an "+
			"accept must yield a non-empty resolver-lock set to compare", fixture)
	}
	return entries
}

// TestDriftCorpusGoInvisiblePremise pins the Go-INVISIBLE-SECTION premise the
// compound both-accept fixtures 25 and 26 rely on. Their (accept, accept) verdict
// holds on the Go side ONLY because the offline line scanner is STRUCTURALLY BLIND
// to the `baseline_pack.families` and `guardrails` sections: those are top-level
// keys that CLOSE the `blocklist:` section (isColumnZeroKey), so their contents
// never reach the scanner's harvested view. The fixture comments DOCUMENT this as
// "Go-invisible", but nothing PINNED it — if the scanner ever began reading those
// sections the verdict could shift silently while the comments went stale.
//
// The proof: the scanner's harvested blocklist view of a COMPOUND fixture (whose
// EXTRA benign axis is a differing families/guardrails section) must be byte-for-byte
// identical to the view of its SINGLE-AXIS sibling (which shares the resolver-lock
// SHAPE axis but lacks the extra section). Equal harvested views means the extra
// section contributed NOTHING the scanner can see — it is Go-invisible. If the
// scanner started surfacing families/guardrails into the view, the compound fixture's
// view would diverge from its sibling's and THIS test fails loudly, before the
// verdict drifts silently.
//
//   - fixture 25 (reordered families + valid guardrail RUNG) vs fixture 18
//     (reordered families, single-axis): same blocklist, 25 adds a `guardrails:`
//     section 18 lacks — invisible iff the views are equal.
//   - fixture 26 (comment-only guardrails + enabled family TIER) vs fixture 19
//     (comment-only families, single-axis): same blocklist, 26 adds a `guardrails:`
//     section and a live family 19 lacks — invisible iff the views are equal.
func TestDriftCorpusGoInvisiblePremise(t *testing.T) {
	cases := []struct {
		name             string
		compound, single string
		extraAxis        string // the benign section the compound adds that must stay Go-invisible
	}{
		{
			name:      "25-reordered-families-guardrail-rung vs 18-reordered-families",
			compound:  "25-reordered-families-guardrail-rung.pol1.yaml",
			single:    "18-reordered-families.pol1.yaml",
			extraAxis: "a `guardrails:` section with a valid rung",
		},
		{
			name:      "26-comment-only-guardrails-enabled-tier vs 19-comment-only-families",
			compound:  "26-comment-only-guardrails-enabled-tier.pol1.yaml",
			single:    "19-comment-only-families.pol1.yaml",
			extraAxis: "a comment-only `guardrails:` section and an enabled family tier",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compoundView := harvestBlocklistView(t, tc.compound)
			singleView := harvestBlocklistView(t, tc.single)
			if !reflect.DeepEqual(compoundView, singleView) {
				t.Fatalf("Go-invisible-section premise BROKEN: the scanner's harvested "+
					"blocklist view of compound fixture %s differs from its single-axis "+
					"sibling %s.\n  compound view: %#v\n  single   view: %#v\nThe ONLY "+
					"difference between these fixtures is %s — a `baseline_pack.families`/"+
					"`guardrails` section the compound adds. Those are top-level keys that "+
					"CLOSE the blocklist section, so the scanner must NOT see them. A "+
					"divergence here means the line scanner began reading the families/"+
					"guardrails sections; the compound fixtures' (accept, accept) verdict "+
					"and their \"Go-invisible\" comments are now STALE — update both the "+
					"scanner and the fixture documentation in lockstep", tc.compound,
					tc.single, compoundView, singleView, tc.extraAxis)
			}
		})
	}
}

// domainLineSpan is a TEST-LOCAL mirror walk of a corpus fixture's bytes that counts
// `domain:`-bearing lines (`- domain:` and bare `domain:` — the SAME two shapes the
// production scanner counts into rawDomainCount) INSIDE versus OUTSIDE the `blocklist:`
// section span. It tracks the section span by mirroring the production scanner's OWN
// open/close rules — the column-0 `blocklist:` opener and the isColumnZeroKey closer
// (parseResolverLockBlocklist, resolverlock.go ~165-205) — over the SAME stripComment-
// trimmed lines, so the span it computes is the span the scanner SHOULD harvest from. It
// deliberately does NOT call parseResolverLockBlocklist: it is an INDEPENDENT second
// witness of "which lines lie in the blocklist span", computed from the bytes by test
// logic only (no resolverlock.go instrumentation), so the equality below compares the
// scanner's harvested COUNT against a mirror that was derived without trusting the
// scanner's section-state bookkeeping.
//
// Returns (inSection, outSection): the count of domain-bearing lines whose section span
// is the blocklist, and the count that fall OUTSIDE it (under families/guardrails/any
// other top-level key). Used by TestDriftCorpusGoInvisibleHarvestInternal to assert the
// harvest is FULLY attributable to in-section domain lines and that the extra benign
// sections contribute EXACTLY ZERO domain-bearing lines to the harvest — not merely zero
// NET. A scanner change that began keeping inBlocklist=true across a families:/guardrails:
// header (a side-effect-only read of a benign section) would diverge the scanner's
// harvested view count from this mirror's inSection count, biting the subtler class the
// view-equality premise above cannot see.
func domainLineSpan(t *testing.T, fixture string) (inSection, outSection int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(CorpusFixturesDir(), fixture))
	if err != nil {
		t.Fatalf("reading corpus fixture %s: %v", fixture, err)
	}
	inBlocklist := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(stripComment(line))
		if trimmed == "" {
			continue
		}
		// Column-0 `blocklist:` opener — mirrors the scanner's section-open rule. A
		// flow/anchored opener (`blocklist: [`) is a reject shape the scanner names; it
		// never appears on the both-ACCEPT fixtures this premise drives, so the bare
		// opener is all this mirror must model.
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '-' &&
			strings.HasPrefix(trimmed, "blocklist:") {
			inBlocklist = true
			continue
		}
		// Any OTHER column-0 mapping key CLOSES the section — the SAME isColumnZeroKey
		// closer the scanner consults (so a families:/guardrails: top-level key ends the
		// span exactly as the scanner does).
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '-' &&
			isColumnZeroKey(trimmed) {
			inBlocklist = false
			continue
		}
		// Count the two domain-bearing shapes the scanner counts into rawDomainCount,
		// attributing each to the span it falls in.
		if strings.HasPrefix(trimmed, "- domain:") || strings.HasPrefix(trimmed, "domain:") {
			if inBlocklist {
				inSection++
			} else {
				outSection++
			}
		}
	}
	return inSection, outSection
}

// TestDriftCorpusGoInvisibleHarvestInternal HARDENS the Go-invisible-section premise with
// HARVEST-INTERNAL side-effect invariants — the gap TestDriftCorpusGoInvisiblePremise
// above leaves open. That premise compares only the FINAL []ResolverLockEntry view of a
// compound fixture against its single-axis sibling, so a scanner change that READS the
// families/guardrails sections WITHOUT minting a domain entry — a transient inBlocklist
// flip on a benign-section header that nets to the same view because those sections carry
// no `domain:` lines — would leave the view unchanged and slip past the view-equality
// check. This test closes that class by asserting the harvest is fully attributable to
// IN-SECTION domain lines and that the benign sections contribute EXACTLY ZERO, not merely
// zero NET.
//
// Two invariants, per fixture, over a TEST-LOCAL mirror walk (domainLineSpan — independent
// of the scanner's own section bookkeeping):
//
//	(1) ATTRIBUTION: the count of domain-bearing lines INSIDE the blocklist span equals
//	    len(harvested view). The scanner's harvest is exactly the in-section domain lines —
//	    no entry was minted from a line the mirror places outside the span, and no in-section
//	    domain line was dropped.
//	(2) ZERO LEAK: the count of domain-bearing lines OUTSIDE the blocklist span is ZERO on
//	    these fixtures, AND none reached the harvest. The extra benign families/guardrails
//	    sections the compound adds contribute no domain line to the span at all — so the
//	    invisibility is structural (the section never enters the harvest span), not a netting
//	    coincidence.
//
// Together with the view-equality premise these pin BOTH that the benign sections are
// invisible to the final view (premise above) AND that they were never even read into the
// harvest span (here). A scanner that began keeping inBlocklist=true across a
// families:/guardrails: header would make its harvested view count exceed this mirror's
// in-section count for any fixture whose benign section DID carry a domain-shaped line —
// the side-effect-only class the view-equality check (which only sees the NET view) cannot
// catch. This is test logic ONLY: no resolverlock.go instrumentation, no fixture change.
func TestDriftCorpusGoInvisibleHarvestInternal(t *testing.T) {
	// The SAME compound/single fixtures the view-equality premise drives, plus the control
	// — every fixture here is a Go-benign both-ACCEPT shape with one blocklist entry.
	for _, fixture := range []string{
		"25-reordered-families-guardrail-rung.pol1.yaml",
		"18-reordered-families.pol1.yaml",
		"26-comment-only-guardrails-enabled-tier.pol1.yaml",
		"19-comment-only-families.pol1.yaml",
		"00-good-baseline.pol1.yaml",
	} {
		t.Run(fixture, func(t *testing.T) {
			view := harvestBlocklistView(t, fixture) // fatals unless ACCEPT with a non-empty view
			inSection, outSection := domainLineSpan(t, fixture)

			// (1) ATTRIBUTION — the harvested entry count equals the IN-SECTION domain-line
			//     count the mirror walk found. Equal counts mean every harvested entry traces
			//     to a domain line inside the blocklist span (no entry minted from outside it),
			//     and no in-section domain line was dropped.
			if len(view) != inSection {
				t.Fatalf("harvest-internal ATTRIBUTION broken on %s: the scanner harvested %d "+
					"entr(ies) but the test-local mirror walk found %d domain-bearing line(s) "+
					"INSIDE the blocklist span. A harvest that does not equal the in-section "+
					"domain-line count means the scanner minted an entry from a line OUTSIDE the "+
					"span (it began reading a families/guardrails section) or dropped an in-section "+
					"domain line — either way the Go-invisible-section premise is unsound. View: "+
					"%#v", fixture, len(view), inSection, view)
			}

			// (2) ZERO LEAK — no domain-bearing line lies outside the blocklist span on these
			//     fixtures, so the extra benign sections contribute EXACTLY ZERO domain lines to
			//     the harvest (not merely zero NET). A non-zero out-of-section count would mean a
			//     benign section grew a domain-shaped line that the scanner must NOT harvest; the
			//     attribution check above plus this ensure such a line never reaches the view.
			if outSection != 0 {
				t.Fatalf("harvest-internal ZERO-LEAK broken on %s: the test-local mirror walk found "+
					"%d domain-bearing line(s) OUTSIDE the blocklist span (under a "+
					"families/guardrails/other top-level section). The Go-invisible-section premise "+
					"requires the extra benign sections to contribute EXACTLY ZERO domain lines to "+
					"the harvest — a domain line outside the span is a section the scanner must stay "+
					"blind to; if the scanner began harvesting it, the (accept, accept) verdict and "+
					"the \"Go-invisible\" fixture comments would be stale", fixture, outSection)
			}

			// Belt-and-suspenders non-vacuity: the in-section count is the harvested count, which
			// harvestBlocklistView already pinned non-empty — so the attribution check above is
			// never a vacuous 0==0. Pin it explicitly at the assertion site.
			if inSection == 0 {
				t.Fatalf("harvest-internal premise vacuous on %s: zero in-section domain lines — "+
					"harvestBlocklistView requires a non-empty accept, so this mirror walk must find "+
					"at least one in-section domain line for the attribution check to bite", fixture)
			}
		})
	}
}

// ── domainLineSpan ↔ production-scanner grammar LOCKSTEP guard ──────────────────
//
// domainLineSpan (above) is a TEST-LOCAL second witness of the blocklist span: it
// re-derives the production scanner's column-0 section grammar — the `blocklist:`
// column-0 OPENER and the isColumnZeroKey CLOSER (parseResolverLockBlocklist,
// resolverlock.go ~181-202) — in test code, WITHOUT calling the scanner, so the
// harvest-internal invariants compare the scanner's harvested view against a span
// computed independently of its bookkeeping. That second-witness soundness holds
// ONLY while the mirror stays in LOCKSTEP with the production grammar. Today that
// coupling is COMMENT-asserted (domainLineSpan's doc names the resolverlock.go
// lines it mirrors) but nothing PINNED it: a production change to the column-0
// opener-prefix or the isColumnZeroKey closer that the mirror does not also make
// would silently desynchronize the witness — re-opening the false-positive /
// false-negative premise the harvest-internal invariants exist to close.
//
// The two guards below pin that coupling structurally, so such a drift is FLAGGED:
//
//	(A) BEHAVIORAL span-partition lockstep (TestDomainLineSpanPartitionMatchesScanner):
//	    drives the PRODUCTION scanner (parseResolverLockBlocklist) and the mirror
//	    (domainLineSpan) over the SAME on-disk corpus fixtures and asserts identical
//	    in-section span partitioning — the scanner's harvested entry count equals the
//	    mirror's inSection count on EVERY Go-accept fixture. The real corpus already
//	    exercises all three column-0 closer shapes at the section boundary (bare
//	    `baseline_pack:`/`guardrails:`, inline-value `posture: standard`, inline-list
//	    `passthrough: []`), so a grammar divergence on any of those shapes diverges the
//	    two counts and bites here.
//
//	(B) STRUCTURAL grammar-token lockstep (TestScannerGrammarTokensMirroredBySpan):
//	    a go/ast walk of the PRODUCTION parseResolverLockBlocklist body that asserts the
//	    exact grammar tokens the mirror hardcodes are STILL PRESENT in the scanner — the
//	    `"blocklist:"` column-0 opener prefix literal and the `isColumnZeroKey(...)`
//	    closer call — AND that the production isColumnZeroKey recognizer still admits
//	    EXACTLY the three column-0 key shapes the mirror's span walk relies on (bare
//	    `key:`, inline-value `key: value`, inline-list `key: [...]`), failing CLOSED if
//	    the production scanner grows a NEW section-boundary key shape the mirror enumerates
//	    nothing for. Together (A) catches a behavioral divergence the current corpus can
//	    exercise; (B) catches a structural rename/removal/new-shape the corpus might not
//	    yet exercise — the subtler class that would let a drift through until a fixture
//	    happened to hit it.
//
// READ-ONLY on the production scanner: both guards SCAN/DRIVE resolverlock.go, neither
// edits it. ADDITIVE: every existing scan/guard/verdict row stays unweakened.

// goAcceptCorpusFixtures returns the SORTED set of corpus fixtures the Go offline
// scanner ACCEPTS — the goAccept() rows of goCorpusExpectations. These are the only
// fixtures parseResolverLockBlocklist harvests a view from (a reject fixture errors
// before yielding a span), so they are the corpus over which the behavioral
// span-partition lockstep below can compare the scanner's harvest against the mirror.
// Derived from the SAME goCorpusExpectations table the verdict walk drives, so a
// fixture added/removed there is reflected here automatically — never a hand-kept list.
func goAcceptCorpusFixtures() []string {
	var out []string
	for fixture, want := range goCorpusExpectations {
		if want.accept {
			out = append(out, fixture)
		}
	}
	sort.Strings(out)
	return out
}

// TestDomainLineSpanPartitionMatchesScanner is the BEHAVIORAL half of the
// domainLineSpan ↔ production-scanner grammar lockstep: it drives the PRODUCTION
// scanner (parseResolverLockBlocklist, via harvestBlocklistView) and the TEST-LOCAL
// mirror (domainLineSpan) over the SAME on-disk corpus bytes for every Go-accept
// fixture, and asserts they PARTITION the blocklist span IDENTICALLY — the scanner's
// harvested entry count equals the mirror's in-section domain-line count, and no
// domain line falls outside the span. Where TestDriftCorpusGoInvisibleHarvestInternal
// pins this over a HAND-PICKED handful of Go-invisible-section fixtures (its narrower
// premise), THIS guard widens the pin to the WHOLE Go-accept corpus, so any accept
// fixture whose section boundary the mirror and scanner walk DIFFERENTLY is caught —
// including the inline-value (`posture: standard`) and inline-list (`passthrough: []`)
// column-0 closer shapes the real fixtures already carry at the boundary.
//
// The bite (proven via a reverted SCRATCH, never committed): mutate domainLineSpan's
// closer rule so it no longer mirrors isColumnZeroKey — e.g. drop the inline-list
// recognition by making it stop the section only on a BARE `key:` — and a fixture whose
// `passthrough: []` closes the section before its blocklist entries would shift the
// mirror's inSection count away from the scanner's harvest, failing THIS test loudly
// while resolverlock.go is untouched. The production scanner is READ-ONLY here.
func TestDomainLineSpanPartitionMatchesScanner(t *testing.T) {
	fixtures := goAcceptCorpusFixtures()
	if len(fixtures) == 0 {
		t.Fatal("no Go-accept fixtures in goCorpusExpectations — the span-partition " +
			"lockstep has nothing to drive; the verdict table is broken")
	}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			// PRODUCTION side: the scanner's harvested view. harvestBlocklistView fatals
			// unless the fixture ACCEPTS with a non-empty view, so every row is non-vacuous.
			view := harvestBlocklistView(t, fixture)
			// MIRROR side: the independent span walk's in/out-of-section partition.
			inSection, outSection := domainLineSpan(t, fixture)

			// IDENTICAL PARTITIONING: the scanner harvested exactly the in-section domain
			// lines the mirror placed in the blocklist span. A divergence means the mirror's
			// open/close grammar drifted from the production scanner's — the lockstep is broken.
			if len(view) != inSection {
				t.Fatalf("scanner↔mirror span-partition DIVERGED on %s: the production scanner "+
					"(parseResolverLockBlocklist) harvested %d entr(ies) but the test-local mirror "+
					"(domainLineSpan) placed %d domain-bearing line(s) INSIDE the blocklist span. "+
					"domainLineSpan re-derives the scanner's column-0 `blocklist:` opener / "+
					"isColumnZeroKey closer grammar in TEST code; an unequal partition means that "+
					"re-derivation no longer matches the production scanner — a resolverlock.go "+
					"grammar change (opener prefix or isColumnZeroKey closer) was NOT mirrored into "+
					"domainLineSpan, or vice versa. Update BOTH in lockstep. View: %#v",
					fixture, len(view), inSection, view)
			}
			// On the Go-accept corpus every domain line lies inside the span (the benign
			// families/guardrails sections carry none); a non-zero out-of-section count would
			// mean the mirror placed a domain line outside the span that the scanner harvested
			// anyway — also a partition divergence. Pin it so the equality above is never
			// satisfied by an offsetting out-of-section miscount.
			if outSection != 0 {
				t.Fatalf("scanner↔mirror span-partition DIVERGED on %s: the mirror (domainLineSpan) "+
					"placed %d domain-bearing line(s) OUTSIDE the blocklist span, yet the production "+
					"scanner harvested %d entr(ies) (all in-section by construction). A Go-accept "+
					"fixture's domain lines must all lie in the blocklist span on BOTH witnesses; a "+
					"non-zero out-of-section count means the mirror's closer grammar terminates the "+
					"section where the scanner does NOT — the column-0 closer rules have drifted apart",
					fixture, outSection, len(view))
			}
		})
	}
}

// scannerGrammarMirror enumerates the production grammar TOKENS domainLineSpan's span
// walk hardcodes as its mirror of the resolverlock.go scanner. Each row pins ONE token
// the mirror depends on staying present in the production scanner; TestScannerGrammar-
// TokensMirroredBySpan below reconciles this enumeration against the parsed production
// source, failing CLOSED if a pinned token is GONE (the scanner's grammar moved out from
// under the mirror). This is the SINGLE place the test-side "what the mirror assumes
// about the scanner grammar" is written down, so a future contributor changing the
// scanner sees exactly which test-side assumption their change invalidates.
var scannerGrammarMirror = struct {
	// openerPrefixLiteral is the column-0 section-OPENER prefix the scanner tests with
	// `strings.HasPrefix(trimmed, "blocklist:")` and the mirror copies verbatim
	// (domainLineSpan's opener branch). If the production scanner renames this key, the
	// mirror would open the section on a key that no longer exists.
	openerPrefixLiteral string
	// closerFuncName is the column-0 section-CLOSER predicate the scanner consults
	// (`isColumnZeroKey(trimmed)`) and the mirror calls IDENTICALLY. If the scanner stops
	// closing the section via isColumnZeroKey, the mirror's closer no longer tracks it.
	closerFuncName string
}{
	openerPrefixLiteral: "blocklist:",
	closerFuncName:      "isColumnZeroKey",
}

// columnZeroShapeProbe is one synthetic column-0 line and the section-boundary verdict
// the mirror's grammar requires the production isColumnZeroKey to return for it. The
// three shapes are EXACTLY the column-0 key forms domainLineSpan's closer relies on to
// terminate the blocklist span; the negative probes pin that isColumnZeroKey does NOT
// close on a non-key line (so the mirror does not terminate the span early). Driving the
// PRODUCTION isColumnZeroKey over this table is the fail-CLOSED reconciliation the task
// requires: if the scanner grows a new recognized section-boundary shape the mirror does
// not model, a probe added here to cover it (or an existing probe's flipped verdict)
// surfaces the divergence.
type columnZeroShapeProbe struct {
	name      string
	line      string // a trimmed, column-0 line (as domainLineSpan/​scanner feed isColumnZeroKey)
	wantClose bool   // whether the mirror's grammar requires this to CLOSE the blocklist section
	why       string
}

// columnZeroShapeProbes is the synthetic shape corpus (D50) enumerating the three
// recognized column-0 key shapes the mirror's span walk relies on as section closers,
// plus negative controls. It is driven over the PRODUCTION isColumnZeroKey so the mirror's
// dependency on each shape is reconciled against the real recognizer — not a test re-impl.
var columnZeroShapeProbes = []columnZeroShapeProbe{
	{
		name:      "bare-key",
		line:      "guardrails:",
		wantClose: true,
		why:       "a bare `key:` (block value on following indented lines) closes the section — the mirror terminates the span on it",
	},
	{
		name:      "inline-value-key",
		line:      "posture: standard",
		wantClose: true,
		why:       "a `key: value` inline-value mapping key closes the section — the mirror terminates the span on it",
	},
	{
		name:      "inline-list-key",
		line:      "passthrough: []",
		wantClose: true,
		why:       "a `key: [...]` inline-list mapping key closes the section — the mirror terminates the span on it (the `passthrough: []` shape real fixtures carry)",
	},
	{
		name:      "negative-list-item",
		line:      "- domain: a.example.com",
		wantClose: false,
		why:       "a `- ` list item is NOT a column-0 key — it must NOT close the section, or the mirror would drop in-section entries",
	},
	{
		name:      "negative-spaced-name",
		line:      "two words: x",
		wantClose: false,
		why:       "a name with internal whitespace is not a mapping key — isColumnZeroKey must reject it so the mirror does not close on prose",
	},
	{
		name:      "negative-no-colon",
		line:      "plainline",
		wantClose: false,
		why:       "a line with no colon is not a mapping key — it must NOT close the section",
	},
}

// TestScannerGrammarTokensMirroredBySpan is the STRUCTURAL half of the domainLineSpan ↔
// production-scanner grammar lockstep. It pins the test-side mirror to the production
// scanner's grammar in two ways that the behavioral half (over the current corpus) cannot
// fully cover:
//
//	(1) TOKEN PRESENCE — a go/ast walk of the PRODUCTION parseResolverLockBlocklist body
//	    asserts the exact opener-prefix string literal (scannerGrammarMirror.openerPrefixLiteral,
//	    `"blocklist:"`) and the closer-predicate call (scannerGrammarMirror.closerFuncName,
//	    `isColumnZeroKey(...)`) the mirror hardcodes are STILL PRESENT in the scanner. The
//	    opener-prefix check is SCOPED to the column-0 OPENER-DECISION site — the literal must
//	    appear as an argument to a `strings.HasPrefix(...)` call, not merely anywhere in the
//	    body. The scanner carries `"blocklist:"` TWICE (the `strings.HasPrefix` opener decision
//	    AND the sibling `strings.TrimPrefix` flow-opener guard); a body-wide presence check
//	    would still pass after a rename that touched ONLY the opener decision because the
//	    TrimPrefix literal survives — so the pin scopes to the HasPrefix argument site to bite
//	    that precise drift. A production change that renames the opener key at the HasPrefix
//	    decision or replaces the isColumnZeroKey closer leaves the mirror copying a token the
//	    scanner no longer uses — caught here, naming the missing token, BEFORE a corpus fixture
//	    happens to exercise the divergence.
//
//	(2) RECOGNIZED-SHAPE RECONCILIATION — drives the PRODUCTION isColumnZeroKey over the
//	    synthetic columnZeroShapeProbes corpus and asserts each of the three column-0 key
//	    shapes the mirror's span walk relies on (bare `key:`, inline-value `key: value`,
//	    inline-list `key: [...]`) STILL closes the section, and the negative controls do not.
//	    If the scanner's column-0 recognizer drifts — stops recognizing one of the three
//	    shapes (the mirror would then keep the section open past a real boundary) or starts
//	    recognizing a NEW boundary shape the mirror enumerates nothing for — a probe verdict
//	    flips and this fails CLOSED.
//
// Both arms SCAN/DRIVE the production scanner; NEITHER edits resolverlock.go. The bite
// (proven via a reverted SCRATCH, never committed): renaming the mirror's hardcoded
// openerPrefixLiteral to a key the scanner no longer opens on, or flipping a probe's
// wantClose to disagree with the real isColumnZeroKey, fails THIS test — exactly the
// "mirror silently stopped tracking the scanner grammar" drift the guard exists to flag.
func TestScannerGrammarTokensMirroredBySpan(t *testing.T) {
	// ── Arm (1): the mirror's hardcoded grammar tokens are present in the production scanner.
	scanner, scannerFile := parseResolverLockBlocklistFile(t)
	// Resolve how the production source binds `strings` (default name, an `import str
	// "strings"` alias, or a dot-import) so the call-site pins below cannot be defeated by an
	// import-aliasing/dot-import rewrite — a renamed/aliased `strings` would otherwise make the
	// HasPrefix/site detection silently MISS and the structural guard go blind exactly when it
	// must bite.
	stringsBinding := resolveStringsImportBinding(scannerFile)
	// SCOPE the opener-prefix presence to the column-0 OPENER-DECISION site specifically:
	// the literal must appear as an argument to a `strings.HasPrefix(...)` call, not merely
	// anywhere in the body. The scanner carries the SAME `"blocklist:"` literal TWICE — once
	// in the column-0 `strings.HasPrefix(trimmed, "blocklist:")` opener decision (the rule
	// domainLineSpan mirrors), and once in the `strings.TrimPrefix(trimmed, "blocklist:")`
	// flow-opener guard that strips it to inspect the rest of the key line. A body-wide
	// presence check would still pass if a rename touched ONLY the opener-decision HasPrefix
	// (the TrimPrefix literal survives), so the structural pin would miss the precise drift it
	// names. Scoping to the HasPrefix call-argument site makes a rename at the opener decision
	// FLAG here even though the sibling TrimPrefix literal is untouched. The match is resolved
	// under whatever local name the scanner imports `strings` as (stringsBinding), so an
	// aliased/dot-imported `strings` cannot make this pin go blind.
	if !astBodyContainsStringLiteralInStringsCall(scanner.Body, stringsBinding, "HasPrefix", scannerGrammarMirror.openerPrefixLiteral) {
		t.Fatalf("scanner-grammar token MISSING: the production parseResolverLockBlocklist body "+
			"no longer passes the column-0 opener prefix literal %q to a strings.HasPrefix(...) call "+
			"— the opener-DECISION site that domainLineSpan's span walk hardcodes as its section-open "+
			"rule. The scanner's section-opener key was renamed or removed at the HasPrefix decision "+
			"(a surviving `strings.TrimPrefix(trimmed, %q)` flow-opener guard would no longer count: "+
			"the pin is scoped to the opener decision, not anywhere in the body); domainLineSpan still "+
			"opens the blocklist span on %q, so the test-local second witness is now desynchronized "+
			"from the production grammar. Update BOTH the scanner and domainLineSpan (and "+
			"scannerGrammarMirror.openerPrefixLiteral) in lockstep.",
			scannerGrammarMirror.openerPrefixLiteral, scannerGrammarMirror.openerPrefixLiteral,
			scannerGrammarMirror.openerPrefixLiteral)
	}
	// UNIFORM ALIAS-ROBUSTNESS for the remaining strings.* call sites. The HasPrefix
	// opener-decision pin above is the ONLY site-scoped strings.* call-site grammar
	// assertion this test makes today, and it now resolves the call under whatever local
	// name the scanner imports `strings` as (stringsBinding) via the shared import-binding
	// matcher (resolveStringsImportBinding + callTargetsStringsFunc, both reused verbatim
	// here — not forked). The production parseResolverLockBlocklist body, however, ALSO
	// gates on other strings.* calls that a future structural pin could legitimately key on:
	//   strings.Split        (the line splitter)
	//   strings.TrimRight    (the CR strip)
	//   strings.TrimSpace    (whitespace normalize)
	//   strings.TrimPrefix   (the section-key/`- domain:`/`domain:`/`reason:`/`rung:` openers)
	//   strings.ContainsAny  (the `[{` anchor/alias reject and the ` \t` whitespace reject)
	//   strings.Contains     (the `*` wildcard reject)
	//   strings.IndexByte / strings.Index (the `:`/`#` locators)
	// Any NEW site-scoped pin for one of those MUST route through the SAME alias-robust
	// matcher — astBodyContainsStringLiteralInStringsCall(scanner.Body, stringsBinding, "<Fn>",
	// …) or callTargetsStringsFunc(call, stringsBinding, "<Fn>") — rather than a by-name
	// receiver check, so an `import str "strings"` / `import . "strings"` rewrite cannot make
	// THAT site's detection silently MISS the way it could for HasPrefix before orch91 U3. The
	// matcher already takes `fn` as a parameter, so it is generalized-and-ready for every name
	// above; TestStringsAliasRobustMatcherIsUniformAcrossFunctions proves it bites for each of
	// them (and that a by-name check would miss the aliased/dot-imported forms) hermetically.
	// We do NOT invent a behavioral pin for those functions here — only the opener decision is
	// a grammar token domainLineSpan mirrors, so pinning the others would over-constrain the
	// scanner past what the mirror actually depends on (an ADDITIVE-only change must not add a
	// guard the mirror does not need).
	//
	// SCOPE the closer-predicate presence to the column-0 CLOSE-DECISION site specifically:
	// isColumnZeroKey must be called in the condition of the `if` whose then-branch CLOSES the
	// blocklist span (the scanner's `inBlocklist = false; continue`), not merely ANYWHERE in
	// the body. The body-wide astBodyContainsCallToIdent passes if isColumnZeroKey is called
	// from any incidental spot in parseResolverLockBlocklist, so a refactor that kept an
	// isColumnZeroKey call somewhere but stopped gating the section CLOSE on it would slip past
	// a body-wide pin while desynchronizing the mirror's closer. Scoping to the close-decision
	// branch gives the closer arm the SAME site-precision the opener arm has (its HasPrefix
	// opener-decision pin). The body-wide astBodyContainsCallToIdent helper stays available for
	// other callers — this only tightens THIS arm.
	if !astBodyContainsCallToIdentAtCloseDecisionSite(scanner.Body, scannerGrammarMirror.closerFuncName) {
		t.Fatalf("scanner-grammar token MISSING: the production parseResolverLockBlocklist body no "+
			"longer calls %s(...) at the column-0 CLOSE-DECISION site — the `if` whose then-branch "+
			"closes the blocklist span (`inBlocklist = false`) that domainLineSpan's span walk "+
			"mirrors as its section-close rule. The scanner's closer was replaced or removed, or the "+
			"section CLOSE is no longer gated on %s (an incidental %s call elsewhere does NOT count: "+
			"the pin is scoped to the close decision, not anywhere in the body); domainLineSpan still "+
			"closes the blocklist span via %s, so the second witness no longer tracks the production "+
			"grammar. Update BOTH the scanner and domainLineSpan in lockstep.",
			scannerGrammarMirror.closerFuncName, scannerGrammarMirror.closerFuncName,
			scannerGrammarMirror.closerFuncName, scannerGrammarMirror.closerFuncName)
	}

	// ── Arm (2): the production isColumnZeroKey still recognizes EXACTLY the three column-0 key
	// shapes the mirror relies on as section closers (and nothing the mirror would mis-close on).
	if len(columnZeroShapeProbes) == 0 {
		t.Fatal("columnZeroShapeProbes is empty — the recognized-shape reconciliation has nothing " +
			"to drive; the mirror's column-0 grammar dependency is unpinned")
	}
	sawClosePositive := false
	for _, p := range columnZeroShapeProbes {
		// isColumnZeroKey is the PRODUCTION recognizer — same-package unexported call, no new
		// symbol imported. Drive it over the synthetic probe and reconcile against the verdict the
		// mirror's grammar requires.
		got := isColumnZeroKey(p.line)
		if got != p.wantClose {
			t.Fatalf("scanner column-0 RECOGNIZED-SHAPE drift on probe %q: production isColumnZeroKey(%q) "+
				"= %v, but domainLineSpan's span grammar requires %v (%s). The set of column-0 key shapes "+
				"the scanner closes the blocklist section on no longer matches what the mirror's closer "+
				"models — a recognized shape was added or dropped on the production side that domainLineSpan "+
				"does not mirror. A NEW boundary shape the mirror ignores would let a false section span "+
				"through; a dropped shape would over-extend it. Update domainLineSpan AND this probe table "+
				"in lockstep with the scanner.", p.name, p.line, got, p.wantClose, p.why)
		}
		if p.wantClose {
			sawClosePositive = true
		}
	}
	// Non-vacuity: at least one probe must REQUIRE a close, so a future table edit that left only
	// negative probes (every isColumnZeroKey==false, trivially satisfiable) cannot pass vacuously.
	if !sawClosePositive {
		t.Fatal("columnZeroShapeProbes carries no wantClose=true probe — the recognized-shape " +
			"reconciliation would pass vacuously; at least one column-0 key shape the mirror closes " +
			"the section on must be pinned to bite")
	}
}

// trimPrefixOpenerPin is one production strings.TrimPrefix section-key opener whose stripped
// literal domainLineSpan's span walk GENUINELY depends on — so a behavioral, site-scoped pin
// on that TrimPrefix call is ADDITIVE (it tracks a token the mirror already needs), not an
// over-constraint. The scanner harvests each section item by stripping its opener prefix with
// `strings.TrimPrefix(trimmed, "<opener>")`, the sibling of the `strings.HasPrefix(trimmed,
// "<opener>")` DECISION that domainLineSpan mirrors. The two strings.* calls carry the SAME
// opener literal; the existing grammar pin (TestScannerGrammarTokensMirroredBySpan arm 1)
// scopes the `"blocklist:"` opener to its HasPrefix DECISION site only, leaving the sibling
// TrimPrefix openers structurally UNPINNED (the gap the UNIFORM ALIAS-ROBUSTNESS note names:
// a refactor that renamed/aliased the opener at the TrimPrefix harvest site — without touching
// the HasPrefix decision — would slip past every structural pin). Each row here closes that
// gap for ONE mirror-tracked opener.
type trimPrefixOpenerPin struct {
	name    string // sub-test label
	openLit string // the opener literal stripped by strings.TrimPrefix at the harvest/flow-decision site
	why     string // why domainLineSpan depends on this opener (the additive-not-over-constraint justification)
}

// trimPrefixOpenerPins enumerates EXACTLY the strings.TrimPrefix section-key openers
// domainLineSpan's span walk depends on. It is deliberately SCOPED to the two openers the
// mirror genuinely tracks:
//
//   - `"blocklist:"` — domainLineSpan opens the blocklist span on `strings.HasPrefix(trimmed,
//     "blocklist:")` (its opener branch); the scanner's sibling `strings.TrimPrefix(trimmed,
//     "blocklist:")` flow-opener guard strips that SAME literal to inspect the rest of the key
//     line. The mirror needs this opener present.
//   - `"- domain:"` — domainLineSpan COUNTS in-section entries on `strings.HasPrefix(trimmed,
//     "- domain:")` (its domain-count branch); the scanner harvests each entry by stripping
//     that SAME literal with `strings.TrimPrefix(trimmed, "- domain:")`. The mirror needs this
//     opener present.
//
// It deliberately EXCLUDES the scanner's `reason:`/`rung:` TrimPrefix openers: domainLineSpan
// does NOT track those literals (they are entry-field strippers the span walk ignores), so
// pinning them here would add a guard the mirror does not need — an over-constraint the
// UNIFORM ALIAS-ROBUSTNESS note warns against (an ADDITIVE-only change must not constrain the
// scanner past what the second witness depends on). The bare `domain:` opener carries NO
// TrimPrefix in the scanner (it is counted, not harvested), so it is not a TrimPrefix-site
// candidate at all.
var trimPrefixOpenerPins = []trimPrefixOpenerPin{
	{
		name:    "blocklist-flow-opener-guard",
		openLit: "blocklist:",
		why: "domainLineSpan opens the blocklist span on strings.HasPrefix(trimmed, \"blocklist:\"); " +
			"the scanner's sibling strings.TrimPrefix(trimmed, \"blocklist:\") flow-opener guard strips " +
			"the SAME mirror-tracked literal",
	},
	{
		name:    "list-domain-harvest-opener",
		openLit: "- domain:",
		why: "domainLineSpan counts in-section entries on strings.HasPrefix(trimmed, \"- domain:\"); " +
			"the scanner harvests each entry by stripping the SAME mirror-tracked literal with " +
			"strings.TrimPrefix(trimmed, \"- domain:\")",
	},
}

// TestScannerTrimPrefixSectionKeyOpenersSiteScoped is the BEHAVIORAL, site-scoped pin the
// UNIFORM ALIAS-ROBUSTNESS note (TestScannerGrammarTokensMirroredBySpan) flags as still owed
// for the strings.TrimPrefix section-key OPENERS. The existing grammar test pins the
// `"blocklist:"` opener to its `strings.HasPrefix(...)` DECISION site only; this test pins the
// SIBLING `strings.TrimPrefix(trimmed, "<opener>")` harvest/flow-decision call for each opener
// domainLineSpan genuinely tracks, so a rename/alias of the opener at the TrimPrefix site —
// which the HasPrefix-scoped pin would NOT catch — is FLAGGED here.
//
// The match routes through the SAME alias-robust matcher the opener-decision pin uses
// (resolveStringsImportBinding + astBodyContainsStringLiteralInStringsCall, reused VERBATIM,
// not forked), so an `import str "strings"` / `import . "strings"` rewrite of the scanner
// cannot make this pin go blind — the precise "silently miss under an import alias" failure
// orch91 U3 hardened the opener decision against, now extended to the TrimPrefix openers.
//
// It scans the PRODUCTION parseResolverLockBlocklist via go/ast and edits NOTHING in
// resolverlock.go (the scanner stays READ-ONLY). It is ADDITIVE: each pinned opener is a
// literal domainLineSpan already depends on (trimPrefixOpenerPins documents the dependency),
// so it constrains the scanner only where the second witness already requires the token —
// it does NOT pin reason:/rung:, which the mirror does not track.
//
// The bite (proven via a reverted SCRATCH, never committed): rename the scanner's
// `strings.TrimPrefix(trimmed, "- domain:")` opener (e.g. to `"- host:"`) — or alias `strings`
// at that site — and this test fails, naming the missing opener; the sibling HasPrefix-scoped
// grammar pin would NOT fire on a TrimPrefix-only rename. NON-VACUITY is proven in-test by the
// negative control: a synthetic scanner body MISSING the TrimPrefix opener call is NOT matched.
func TestScannerTrimPrefixSectionKeyOpenersSiteScoped(t *testing.T) {
	scanner, scannerFile := parseResolverLockBlocklistFile(t)
	// Resolve how the production source binds `strings` (default name, an `import str
	// "strings"` alias, or a dot-import) so the TrimPrefix-site pins below cannot be defeated
	// by an import-aliasing/dot-import rewrite — the SAME binding the opener-decision pin uses.
	stringsBinding := resolveStringsImportBinding(scannerFile)

	if len(trimPrefixOpenerPins) == 0 {
		t.Fatal("trimPrefixOpenerPins is empty — the behavioral TrimPrefix-opener pin has nothing " +
			"to assert; the mirror's dependency on the scanner's TrimPrefix section-key openers is unpinned")
	}

	for _, p := range trimPrefixOpenerPins {
		t.Run(p.name, func(t *testing.T) {
			// POSITIVE: the production scanner passes the mirror-tracked opener literal to a
			// strings.TrimPrefix(...) call — SCOPED to the TrimPrefix harvest/flow-decision site
			// (not anywhere in the body), resolved under whatever local name the scanner imports
			// `strings` as. A rename/alias of the opener at the TrimPrefix site FLAGS here even
			// though the sibling HasPrefix literal (and its opener-decision pin) is untouched.
			if !astBodyContainsStringLiteralInStringsCall(scanner.Body, stringsBinding, "TrimPrefix", p.openLit) {
				t.Fatalf("scanner-grammar token MISSING: the production parseResolverLockBlocklist body "+
					"no longer passes the section-key opener literal %q to a strings.TrimPrefix(...) call "+
					"— the harvest/flow-decision site that strips this opener. %s, so the mirror requires "+
					"this opener present; the sibling strings.HasPrefix(...) opener-decision pin would NOT "+
					"catch a TrimPrefix-only rename/alias here (the pin is scoped to the TrimPrefix site). "+
					"The match resolves `strings` under the scanner's import binding, so an aliased/"+
					"dot-imported `strings` cannot make it go blind. Update BOTH the scanner and "+
					"domainLineSpan (and this pin) in lockstep.", p.openLit, p.why)
			}

			// NON-VACUITY / bite control: a synthetic scanner body that strips the opener with a
			// strings.TrimPrefix call carrying a DIFFERENT literal (a renamed opener) must NOT be
			// matched on p.openLit — proving the pin keys on the exact opener literal at the
			// TrimPrefix site and would BITE a rename. Hermetic (parsed in memory; no production
			// source read, nothing on disk).
			renamed := "- renamed-" + p.openLit
			scratchSrc := fmt.Sprintf(
				"package p\n\nimport \"strings\"\n\nfunc f(trimmed string) {\n\t_ = strings.TrimPrefix(trimmed, %q)\n}\n",
				renamed)
			fset := token.NewFileSet()
			scratchFile, err := parser.ParseFile(fset, "scratch.go", scratchSrc, 0)
			if err != nil {
				t.Fatalf("parsing scratch source for the bite control failed: %v\nsource:\n%s", err, scratchSrc)
			}
			scratchBody, ok := singleFuncBody(scratchFile, "f")
			if !ok {
				t.Fatalf("scratch source did not yield function f with a body:\n%s", scratchSrc)
			}
			scratchBinding := resolveStringsImportBinding(scratchFile)
			if astBodyContainsStringLiteralInStringsCall(scratchBody, scratchBinding, "TrimPrefix", p.openLit) {
				t.Fatalf("bite control FAILED: a synthetic body whose strings.TrimPrefix strips the RENAMED "+
					"opener %q was still matched on the original opener %q — the pin is vacuous (it does not "+
					"key on the exact opener literal at the TrimPrefix site), so it would not bite a rename",
					renamed, p.openLit)
			}
		})
	}
}

// TestStringsAliasRobustMatcherIsUniformAcrossFunctions proves the import-binding matcher
// the grammar pins route through (resolveStringsImportBinding + callTargetsStringsFunc, and
// its literal-argument wrapper astBodyContainsStringLiteralInStringsCall) is uniformly
// alias/dot-import robust for EVERY strings.* function the production scanner gates on — not
// just the HasPrefix opener decision orch91 U3 first hardened. It is the "reverted scratch"
// proof, captured as a permanent hermetic guard: it parses SYNTHETIC source (no live calls,
// no production file read) that imports `strings` three ways and confirms (a) the alias-robust
// matcher DETECTS the call under all three forms, and (b) the pre-hardening by-name receiver
// check (callTargetsStringsFunc against a default-only binding) MISSES the aliased/dot-imported
// forms — the precise "silently miss" failure the uniform routing closes. If a future
// site-scoped pin for Split/ContainsAny/TrimPrefix/Contains (etc.) were to revert to a by-name
// receiver check, this test documents — and the bite below demonstrates — why that would go
// blind under an import alias.
func TestStringsAliasRobustMatcherIsUniformAcrossFunctions(t *testing.T) {
	// The strings.* functions parseResolverLockBlocklist (and its helpers isColumnZeroKey/
	// stripComment) gate on whose future structural pins must route through the alias-robust
	// matcher. This set is the COMPLETE enumeration from the grammar test's UNIFORM
	// ALIAS-ROBUSTNESS note — HasPrefix, TrimPrefix, Split, ContainsAny, Contains, TrimRight,
	// TrimSpace, IndexByte, Index — so EVERY gated strings.* matcher (not just the harvest-path
	// subset) is proven alias-robust here. HasPrefix is included so the function already pinned
	// at its site shares the same proof. Each carries a representative literal argument so the
	// literal-argument wrapper is exercised, not only the bare call-target matcher.
	gatedFns := []struct {
		fn     string // the strings.<fn> the scanner calls
		litArg string // a string literal passed at the call (drives the wrapper)
	}{
		{"HasPrefix", "blocklist:"},
		{"TrimPrefix", "- domain:"},
		{"Split", "\n"},
		{"ContainsAny", "[{"},
		{"Contains", "*"},
		// The remaining strings.* functions parseResolverLockBlocklist (and its helpers
		// isColumnZeroKey/stripComment) gate on, so EVERY gated strings.* matcher is proven
		// alias-robust — not only the harvest-path subset above. The literal args are
		// representative drivers for the literal-argument wrapper; the synthetic source is
		// PARSED (never type-checked), so a string literal where production passes a byte/rune
		// (IndexByte/Index `:`/`#` locators) is a legitimate matcher-routing probe.
		{"TrimRight", "\r"}, // the CR strip (strings.TrimRight(raw, "\r"))
		{"TrimSpace", " "},  // whitespace normalize (strings.TrimSpace(stripComment(line)))
		{"IndexByte", ":"},  // the `:` key/value locator (isColumnZeroKey: strings.IndexByte(trimmed, ':'))
		{"Index", "#"},      // the `#` comment locator (stripComment: strings.Index(line, "#"))
	}
	// Three ways a production file may bind `strings`: the default name, an alias, and a
	// dot-import (the call becomes a BARE ident). The matcher must detect the call under ALL
	// three; a by-name `strings`-receiver check only sees the first.
	importForms := []struct {
		name       string // sub-test label
		importDecl string // the import line for `strings`
		callExpr   func(fn, arg string) string
	}{
		{
			name:       "default",
			importDecl: `"strings"`,
			callExpr:   func(fn, arg string) string { return fmt.Sprintf("strings.%s(s, %q)", fn, arg) },
		},
		{
			name:       "alias",
			importDecl: `str "strings"`,
			callExpr:   func(fn, arg string) string { return fmt.Sprintf("str.%s(s, %q)", fn, arg) },
		},
		{
			name:       "dotimport",
			importDecl: `. "strings"`,
			callExpr:   func(fn, arg string) string { return fmt.Sprintf("%s(s, %q)", fn, arg) },
		},
	}
	for _, g := range gatedFns {
		for _, form := range importForms {
			t.Run(g.fn+"/"+form.name, func(t *testing.T) {
				// Build a tiny, self-contained source file whose lone function body calls
				// strings.<fn>(s, <litArg>) under the chosen import form. Hermetic: parsed in
				// memory, nothing on disk, no production source touched.
				src := fmt.Sprintf("package p\n\nimport %s\n\nfunc f(s string) {\n\t_ = %s\n}\n",
					form.importDecl, form.callExpr(g.fn, g.litArg))
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", src, 0)
				if err != nil {
					t.Fatalf("parsing synthetic %s/%s source failed: %v\nsource:\n%s", g.fn, form.name, err, src)
				}
				fnDecl, ok := singleFuncBody(file, "f")
				if !ok {
					t.Fatalf("synthetic source did not yield function f with a body:\n%s", src)
				}
				// The matcher resolves `strings` from THIS file's imports — exactly the
				// production path (resolveStringsImportBinding(scannerFile) feeds the grammar
				// pins). Robustness lives in the binding, not in any per-call assumption.
				binding := resolveStringsImportBinding(file)
				if !astBodyContainsStringLiteralInStringsCall(fnDecl, binding, g.fn, g.litArg) {
					t.Fatalf("alias-robust matcher MISSED strings.%s(%q) under import form %q — the "+
						"site-scoped pin would go blind here. A future structural pin for strings.%s must "+
						"route through resolveStringsImportBinding + callTargetsStringsFunc so an "+
						"aliased/dot-imported `strings` cannot defeat it.\nsource:\n%s",
						g.fn, g.litArg, form.name, g.fn, src)
				}

				// BITE: a by-name receiver check (the pre-orch91-U3 shape) — modeled here as the
				// matcher run against a binding that knows ONLY the default `strings` name — must
				// MISS the aliased and dot-imported forms. This is the reverted-scratch proof that
				// the alias-robustness is load-bearing, not incidental: without it, exactly the
				// alias/dot-import sites go undetected.
				byNameOnly := stringsImportBinding{localNames: map[string]bool{"strings": true}}
				detectedByName := astBodyContainsStringLiteralInStringsCall(fnDecl, byNameOnly, g.fn, g.litArg)
				switch form.name {
				case "default":
					if !detectedByName {
						t.Fatalf("by-name check unexpectedly MISSED the DEFAULT-import strings.%s(%q) — the "+
							"default form must always be detectable; the matcher self-test premise is broken",
							g.fn, g.litArg)
					}
				default: // alias, dotimport
					if detectedByName {
						t.Fatalf("by-name `strings`-receiver check unexpectedly DETECTED the %s-import "+
							"strings.%s(%q) — the bite proof requires the non-alias-robust check to MISS the "+
							"aliased/dot-imported form so the alias-robust routing is demonstrably load-bearing",
							form.name, g.fn, g.litArg)
					}
				}
			})
		}
	}
}

// singleFuncBody returns the *ast.BlockStmt body of the top-level function named want in
// file, and whether it was found. It is the synthetic-source counterpart of
// parseResolverLockBlocklistFile's decl walk, used only by the matcher self-test to feed a
// parsed body to the alias-robust matchers. Hermetic helper — no production source, no I/O.
func singleFuncBody(file *ast.File, want string) (*ast.BlockStmt, bool) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == want && fn.Body != nil {
			return fn.Body, true
		}
	}
	return nil, false
}

// parseResolverLockBlocklistDecl parses the production package source and returns the
// *ast.FuncDecl of parseResolverLockBlocklist — the scanner whose column-0 grammar
// domainLineSpan mirrors. It walks EVERY non-_test.go package file (packageSourceFiles,
// reused from the sentinel scan) so the function is found regardless of which file it
// lives in (layout-drift robust), and fatals if the function is absent — the structural
// guard must never vacuously pass because it could not locate the scanner it pins.
func parseResolverLockBlocklistDecl(t *testing.T) *ast.FuncDecl {
	t.Helper()
	fn, _ := parseResolverLockBlocklistFile(t)
	return fn
}

// parseResolverLockBlocklistFile is parseResolverLockBlocklistDecl's source of truth: it
// returns BOTH the scanner *ast.FuncDecl AND the *ast.File that declares it. The file is
// the import-context the import-aliasing-hardened call-site helpers need — the local name
// the production source binds the `strings` package to (default `strings`, an alias like
// `import str "strings"`, or a dot-import `import . "strings"`) is recorded ONLY in the
// file's import declarations, not on the call expressions themselves. Returning the file
// lets the strings.HasPrefix(...) opener-decision pin (and the site-scoped closer pin)
// resolve `strings` calls under whatever local name the scanner actually imported, so a
// renamed/aliased/dot-imported `strings` cannot make the HasPrefix/site detection silently
// MISS (and so falsely fail-or-pass the structural guard). It walks EVERY non-_test.go
// package file (layout-drift robust) and fatals if the scanner is absent — the structural
// guard must never vacuously pass because it could not locate the scanner it pins.
func parseResolverLockBlocklistFile(t *testing.T) (*ast.FuncDecl, *ast.File) {
	t.Helper()
	const target = "parseResolverLockBlocklist"
	fset := token.NewFileSet()
	for _, src := range packageSourceFiles(t) {
		f, err := parser.ParseFile(fset, src, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s for the scanner-grammar token scan: %v", src, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && fn.Name.Name == target && fn.Body != nil {
				return fn, f
			}
		}
	}
	t.Fatalf("did not find the production function %s in any package source file — the "+
		"scanner-grammar lockstep guard cannot pin a scanner it cannot locate (was it renamed "+
		"or moved? domainLineSpan mirrors its grammar and must be updated in lockstep)", target)
	return nil, nil // unreachable: t.Fatalf stops the test
}

// astBodyContainsStringLiteral reports whether any string-literal in the statement block
// equals want (the unquoted Go string). Used to assert the scanner body still carries the
// mirror's hardcoded opener-prefix literal. The comparison is against the Go double-quoted
// rendering of want (fmt %q — stdlib, no new import) so it matches the source literal's
// token text directly; the mirror's literals are plain ASCII keys with no escapes.
func astBodyContainsStringLiteral(body *ast.BlockStmt, want string) bool {
	quoted := fmt.Sprintf("%q", want)
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if lit.Value == quoted {
			found = true
			return false
		}
		return true
	})
	return found
}

// astBodyContainsCallToIdent reports whether the statement block contains a call to a
// bare identifier named name (an unqualified, same-package function call such as
// `isColumnZeroKey(trimmed)`). Used to assert the scanner body still invokes the mirror's
// hardcoded closer predicate.
func astBodyContainsCallToIdent(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// astBodyContainsStringLiteralInCallTo reports whether the statement block contains a
// call to the package-qualified function pkg.fn(...) (a SelectorExpr `pkg`.`fn`, e.g.
// `strings`.`HasPrefix`) that takes the want string as ONE of its arguments. Unlike
// astBodyContainsStringLiteral (which finds the literal anywhere in the body), this
// SCOPES the presence to a specific call site, so the opener-prefix pin tracks the
// column-0 OPENER-DECISION rule (`strings.HasPrefix(trimmed, "blocklist:")`) and is
// NOT satisfied by the sibling `strings.TrimPrefix(trimmed, "blocklist:")` flow-opener
// guard that carries the identical literal. The string comparison is against the Go
// double-quoted rendering of want (fmt %q — stdlib, no new import), matching the source
// literal's token text directly; the mirror's literals are plain ASCII keys with no
// escapes. Selector match is by the call's `pkg`.`fn` SelectorExpr where the receiver is
// a bare identifier (the package name as imported) — the form the scanner uses.
func astBodyContainsStringLiteralInCallTo(body *ast.BlockStmt, pkg, fn, want string) bool {
	quoted := fmt.Sprintf("%q", want)
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != fn {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || recv.Name != pkg {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if lit.Value == quoted {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// stringsImportBinding records how a production source FILE binds the `strings` standard
// library package — the import-context the site-scoped call pins resolve calls against, so
// a renamed/aliased/dot-imported `strings` cannot make the HasPrefix detection silently
// MISS. A bare `astBodyContainsStringLiteralInCallTo(body, "strings", "HasPrefix", …)` only
// matches a `strings.HasPrefix(...)` SelectorExpr whose receiver Ident is literally named
// `strings`; an `import str "strings"` (receiver `str`) or `import . "strings"` (the call
// becomes a BARE `HasPrefix(...)` Ident, no selector) would slip past it and the opener-pin
// (or the new closer-site pin) would go blind exactly when it must bite. This binding lets
// the pins accept the call under whatever local name the scanner actually imported.
type stringsImportBinding struct {
	// localNames is the set of package-qualifier identifiers `strings` is reachable
	// under in this file (the default `strings`, plus any `import alias "strings"`
	// aliases). Empty if `strings` is imported ONLY via dot-import or blank-import, or
	// is not imported at all.
	localNames map[string]bool
	// dotImported is true when the file carries `import . "strings"`, in which case
	// strings functions are called as BARE identifiers (`HasPrefix(...)`) with no
	// package selector.
	dotImported bool
}

// resolveStringsImportBinding walks file.Imports and resolves how `strings` is bound. It
// HARDENS the site-scoped call pins against import-aliasing and dot-import: the pins match a
// call to strings.<fn> under ANY local name the file actually imported `strings` as, and —
// for a dot-import — match the bare `<fn>(...)` form too. A blank import (`import _
// "strings"`) contributes no usable binding (it cannot name a call) and is intentionally
// skipped. The import path literal is the canonical `"strings"`; the comparison is against
// its Go double-quoted rendering (token text), matching the source literal directly.
func resolveStringsImportBinding(file *ast.File) stringsImportBinding {
	const wantPath = `"strings"`
	b := stringsImportBinding{localNames: map[string]bool{}}
	for _, imp := range file.Imports {
		if imp.Path == nil || imp.Path.Value != wantPath {
			continue
		}
		if imp.Name == nil {
			// Default import: bound under the package's own name, `strings`.
			b.localNames["strings"] = true
			continue
		}
		switch imp.Name.Name {
		case ".":
			b.dotImported = true
		case "_":
			// blank import — no usable qualifier; skip.
		default:
			b.localNames[imp.Name.Name] = true
		}
	}
	return b
}

// astBodyContainsStringLiteralInStringsCall is the import-aliasing-HARDENED form of
// astBodyContainsStringLiteralInCallTo for the `strings` package specifically: it reports
// whether body contains a call to strings.fn(...) — under WHATEVER local name `binding`
// records `strings` is imported as (default, alias, or dot-import) — that takes want as one
// of its arguments. This is the site-scoped, import-robust opener-decision detector: a
// `strings.HasPrefix(trimmed, "blocklist:")` matches whether the scanner imports `strings`
// plainly, as `import str "strings"` (call `str.HasPrefix(...)`), or as `import . "strings"`
// (BARE call `HasPrefix(...)`), so an aliased/dot-imported rewrite cannot make the pin go
// blind. String comparison is against the Go double-quoted rendering of want (token text).
func astBodyContainsStringLiteralInStringsCall(body *ast.BlockStmt, binding stringsImportBinding, fn, want string) bool {
	quoted := fmt.Sprintf("%q", want)
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !callTargetsStringsFunc(call, binding, fn) {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if lit.Value == quoted {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// callTargetsStringsFunc reports whether call invokes strings.fn(...) under the import
// binding — either as a SelectorExpr `<local>.fn(...)` where `<local>` is one of the
// resolved local names `strings` is bound to, or (when dot-imported) as a BARE `fn(...)`
// Ident call. It is the shared import-aliasing-aware matcher the strings-call pins route
// through, so aliasing/dot-import hardening lives in ONE place.
func callTargetsStringsFunc(call *ast.CallExpr, binding stringsImportBinding, fn string) bool {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		if f.Sel == nil || f.Sel.Name != fn {
			return false
		}
		recv, ok := f.X.(*ast.Ident)
		return ok && binding.localNames[recv.Name]
	case *ast.Ident:
		// Bare call — only a strings function under a dot-import.
		return binding.dotImported && f.Name == fn
	default:
		return false
	}
}

// astBodyContainsCallToIdentAtCloseDecisionSite is the SITE-SCOPED twin of the body-wide
// astBodyContainsCallToIdent for the column-0 section-CLOSER. It reports whether body calls
// the bare ident closerFn (e.g. `isColumnZeroKey(...)`) SPECIFICALLY in the condition of the
// `if` whose then-branch CLOSES the blocklist span — the close-decision branch domainLineSpan
// mirrors, where the scanner flips its in-section flag OFF:
//
//	if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '-' &&
//	    isColumnZeroKey(trimmed) {
//	    inBlocklist = false   // ← the close action this pin keys on
//	    continue
//	}
//
// The body-wide astBodyContainsCallToIdent passes if isColumnZeroKey is called from ANY
// incidental spot in parseResolverLockBlocklist; this scopes the closer pin to the close
// DECISION, giving the closer arm the SAME site-precision the opener arm gained when it was
// tightened to the strings.HasPrefix(...) opener-decision call site. The shape it keys on —
// an `if` whose CONDITION calls closerFn and whose then-BODY assigns a `false` boolean
// literal to a variable — is exactly the section-close branch; the sibling opener `if`
// assigns `true` (and calls strings.HasPrefix in its condition, not closerFn), so it is not
// matched, and an incidental isColumnZeroKey call elsewhere (not gating a close) is not
// matched either.
func astBodyContainsCallToIdentAtCloseDecisionSite(body *ast.BlockStmt, closerFn string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if ifs.Cond == nil || !astExprContainsCallToIdent(ifs.Cond, closerFn) {
			return true
		}
		if ifs.Body != nil && astBlockAssignsFalse(ifs.Body) {
			found = true
			return false
		}
		return true
	})
	return found
}

// astExprContainsCallToIdent reports whether expr's subtree contains a call to the bare
// identifier named name (an unqualified same-package call such as `isColumnZeroKey(trimmed)`).
// It is the condition-scoped analogue of astBodyContainsCallToIdent — the closer call sits in
// a chained `&&` BinaryExpr that forms the close-decision `if` condition, so the walk descends
// the whole condition expression to find it.
func astExprContainsCallToIdent(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// astBlockAssignsFalse reports whether block contains an assignment of the `false` boolean
// literal to a variable (`<ident> = false`) — the close ACTION the section-close branch
// performs (the scanner's `inBlocklist = false`). This is the discriminator that separates
// the close-decision `if` from its sibling opener `if`, which assigns `true`. `false` is a
// predeclared identifier (an *ast.Ident named "false"), so the RHS is matched as such.
func astBlockAssignsFalse(block *ast.BlockStmt) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, rhs := range as.Rhs {
			if id, ok := rhs.(*ast.Ident); ok && id.Name == "false" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// compoundGoShapeSibling maps each COMPOUND both-reject fixture (20-23, 27) to its
// single-axis Go-SHAPE sibling — the single-axis fixture whose resolver-lock SHAPE
// drift the compound joins with INDEPENDENT, Go-INVISIBLE schema axis/axes on ONE
// artifact. This is the GO mirror of the Rust compound_sibling_map's Go-rejecting
// element (verified against BOTH expectation tables: the Go column rejects each
// compound for the SAME sentinel as its shape sibling; the schema axis is invisible
// to the line scanner):
//
//   - 20 quoted-key-unknown-tier        -> 08 quoted-keys    (ErrNoBlocklistSection)
//   - 21 flow-blocklist-bad-guardrail-rung -> 07 flow-blocklist (ErrUnsupportedShape)
//   - 22 entry-missing-reason-missing-provenance -> 06 entry-missing-reason (ErrEntryMissingFields)
//   - 23 uppercase-fqdn-missing-guardrail-rung   -> 04 uppercase-fqdn       (ErrBadFQDN)
//   - 27 uppercase-fqdn-unknown-tier-missing-provenance -> 04 uppercase-fqdn (ErrBadFQDN)
//
// The Rust schema sibling(s) (10/14/12/13; 10+12 for row 27) are invisible to the Go
// scanner, which is exactly why the compound and its Go-shape sibling reject
// IDENTICALLY here. Row 27 is the first committed MULTI-element exact set on the RUST
// column ({BadValue, MissingProvenance}); on the GO column it is a CLEAN SINGLE-shape
// match — the uppercase blocklist FQDN — so its Go-shape sibling is 04, identical to
// row 23, and the exact-set sentinel comparison ({ErrBadFQDN}) holds for 27 exactly as
// it does for 23.
var compoundGoShapeSibling = map[string]string{
	"20-quoted-key-unknown-tier.pol1.yaml":                        "08-quoted-keys.pol1.yaml",
	"21-flow-blocklist-bad-guardrail-rung.pol1.yaml":              "07-flow-blocklist.pol1.yaml",
	"22-entry-missing-reason-missing-provenance.pol1.yaml":        "06-entry-missing-reason.pol1.yaml",
	"23-uppercase-fqdn-missing-guardrail-rung.pol1.yaml":          "04-uppercase-fqdn.pol1.yaml",
	"27-uppercase-fqdn-unknown-tier-missing-provenance.pol1.yaml": "04-uppercase-fqdn.pol1.yaml",
}

// rejectingSentinelSet parses a corpus fixture off disk through the SAME Go offline
// scanner the verdict walk uses (parseResolverLockBlocklist) and returns the SORTED,
// distinct set of KNOWN exported sentinels its rejection error tree carries
// (presentSentinels) — the scanner's actual runtime cause SET for that fixture, read
// off the BYTES (not the declared verdict table). The fixture MUST reject: a clean
// accept is a hard failure (the fixture is not a valid reject-side premise input).
// This is the reject-side mirror of harvestBlocklistView (which harvests the parsed
// VIEW for the accept premise); this one harvests the parsed CAUSE SET.
func rejectingSentinelSet(t *testing.T, fixture string) []error {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(CorpusFixturesDir(), fixture))
	if err != nil {
		t.Fatalf("reading corpus fixture %s: %v", fixture, err)
	}
	_, perr := parseResolverLockBlocklist(string(data))
	if perr == nil {
		t.Fatalf("fixture %s must REJECT on the Go scanner for the reject-equivalence "+
			"premise (it is a both-reject / Go-rejecting shape), got a clean accept — "+
			"silent under-extraction is the failure this corpus exists to catch", fixture)
	}
	return presentSentinels(perr)
}

// TestDriftCorpusGoRejectEquivalencePremise pins the RUNTIME reject-equivalence
// premise the compound both-REJECT fixtures 20-23 AND 27 rely on — the GO mirror of
// the Rust compound_reject_parse_equivalence_premise(_row27_union), and the
// reject-side companion of TestDriftCorpusGoInvisiblePremise (which pins the
// both-ACCEPT compounds 25/26).
//
// Row 27 is the first committed MULTI-element exact set on the RUST column
// ({BadValue, MissingProvenance}); on the GO column it is a CLEAN SINGLE-shape match
// — the uppercase blocklist FQDN — so it folds into this premise IDENTICALLY to row
// 23: its Go-shape sibling is 04-uppercase-fqdn (ErrBadFQDN), and the parsed sentinel
// SET equality (compound == {ErrBadFQDN}) holds for 27 exactly as for 23. The Rust
// MULTI-element union is exercised on the Rust side; the Go side stays the singleton
// shape comparison it is for every row.
//
// The wave-1 corpus walk (TestDriftCorpusGoVerdicts) pins each compound's exact-set
// verdict against bytes, and the Rust compound_reject_set_is_union_of_siblings pins
// the EXPECTATION TABLE's self-consistency. But nothing asserted that the compound,
// PARSED FROM BYTES, rejects errors.Is-IDENTICAL to its single-axis Go-SHAPE sibling
// on the SHARED SHAPE AXIS — that the Rust-owned SCHEMA axis present only in the
// compound neither CHANGES nor MASKS the Go-side cause. So a regression that kept the
// reject yet RELOCATED or DROPPED the shape-axis sentinel ONLY in the compound
// presence of the other axis (while the verdict still named the right sentinel) could
// slip past. This premise closes that gap from the PARSED side.
//
// The proof, per compound: the scanner's parsed cause SET (presentSentinels) of the
// COMPOUND fixture must EQUAL the parsed cause set of its single-axis Go-SHAPE sibling
// (compoundGoShapeSibling) — expressed in the landed exact-set presentSentinels form.
// Equal sets means the schema axis the compound adds neither changed the shape cause
// nor joined a new sentinel; the shared shape cause survives the compound presence
// IDENTICALLY. The premise also asserts (a) both reject, (b) the set EQUALS the
// sibling's, (c) the shared shape cause SURVIVES (the set is exactly {the sibling's
// declared sentinel}, non-empty — no vacuous both-empty pass).
func TestDriftCorpusGoRejectEquivalencePremise(t *testing.T) {
	for _, compound := range []string{
		"20-quoted-key-unknown-tier.pol1.yaml",
		"21-flow-blocklist-bad-guardrail-rung.pol1.yaml",
		"22-entry-missing-reason-missing-provenance.pol1.yaml",
		"23-uppercase-fqdn-missing-guardrail-rung.pol1.yaml",
		"27-uppercase-fqdn-unknown-tier-missing-provenance.pol1.yaml",
	} {
		t.Run(compound, func(t *testing.T) {
			sibling, ok := compoundGoShapeSibling[compound]
			if !ok {
				t.Fatalf("compound %s is covered by the reject-equivalence premise but has "+
					"NO Go-shape sibling in compoundGoShapeSibling — a rename or drop must "+
					"update both (fail-closed)", compound)
			}
			// The shared shape cause is the sibling's DECLARED sentinel; pull it from the
			// expectation table so this premise stays anchored to the same per-class
			// sentinel the verdict walk asserts (a sibling whose verdict drifts is caught).
			sibVerdict, ok := goCorpusExpectations[sibling]
			if !ok {
				t.Fatalf("Go-shape sibling %s of compound %s is missing from "+
					"goCorpusExpectations — the sibling map names a fixture with no verdict "+
					"row (fail-closed)", sibling, compound)
			}
			if sibVerdict.accept || sibVerdict.rejectVia == nil {
				t.Fatalf("Go-shape sibling %s of compound %s is not a single-axis REJECT row "+
					"(verdict %#v) — the reject-equivalence premise compares against the "+
					"sibling's SHAPE-reject cause, which it must declare", sibling, compound,
					sibVerdict)
			}

			// (a) both reject (helper fatals on a clean accept), and harvest the PARSED
			//     distinct sentinel sets — off the bytes, not the declared table.
			compoundSet := rejectingSentinelSet(t, compound)
			siblingSet := rejectingSentinelSet(t, sibling)

			// (c) the shared shape cause must SURVIVE: the sibling's set is exactly its
			//     ONE declared sentinel (a non-empty, single-cause shape reject). A
			//     both-empty equality would be a vacuous pass, so pin the sibling shape.
			if len(siblingSet) != 1 || !errors.Is(siblingSet[0], sibVerdict.rejectVia) {
				t.Fatalf("Go-shape sibling %s parsed to cause set %v, expected EXACTLY its one "+
					"declared sentinel {%v} — the reject-equivalence premise cannot anchor a "+
					"vacuous or multi-cause sibling comparison", sibling, siblingSet,
					sibVerdict.rejectVia)
			}

			// (b) the compound's PARSED cause set must EQUAL the sibling's PARSED cause
			//     set. The Rust-owned schema axis present only in the compound must
			//     neither change the shape cause nor join a new sentinel; the shape cause
			//     must survive the compound presence IDENTICALLY. Relocating/dropping the
			//     shape sentinel only-under-the-compound (but not in the sibling), or
			//     joining an extra sentinel only under the compound, fails HERE.
			if !sameSentinelSet(compoundSet, siblingSet) {
				t.Fatalf("compound %s: its PARSED cause set %v does NOT equal its single-axis "+
					"Go-SHAPE sibling %s's parsed cause set %v. The compound joins this "+
					"sibling's resolver-lock SHAPE drift with a Go-INVISIBLE schema axis on ONE "+
					"artifact; the shared SHAPE cause must reject IDENTICALLY (same sentinel, "+
					"same axis) whether or not the schema axis is present — a divergence means a "+
					"regression relocated, dropped, or joined a sentinel ONLY in the compound "+
					"presence of the other axis (a runtime drift the verdict/exact-set checks "+
					"cannot see)", compound, compoundSet, sibling, siblingSet)
			}
		})
	}
}

// sameSentinelSet reports whether two SORTED sentinel sets (as returned by
// presentSentinels) are equal element-for-element by errors.Is. Both inputs are
// already sorted by message string, so a positional walk is a faithful set compare.
func sameSentinelSet(a, b []error) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !errors.Is(a[i], b[i]) {
			return false
		}
	}
	return true
}

// compoundGoSiblingMap is the GO mirror of the Rust compound_sibling_map: each
// COMPOUND both-reject fixture (20-23, 27) -> the FULL list of single-axis sibling
// fixtures whose INDEPENDENT drifts it composes on ONE artifact. It transcribes into a
// MACHINE-CHECKED map the compound->sibling decomposition that the row 20-23 / 27
// comments in goCorpusExpectations (and the 1:1 compoundGoShapeSibling map above)
// express only in PROSE — the author-time gap this premise closes.
//
// Unlike the 1:1 compoundGoShapeSibling map (which names ONLY the Go-rejecting SHAPE
// sibling), this map lists EVERY single-axis sibling, INCLUDING the Go-INVISIBLE schema
// siblings that ACCEPT on the Go scanner (they bite only the Rust SCHEMA reader). That
// is what makes it the faithful Go analog of the Rust compound_sibling_map: the SAME
// fixtures, the SAME decomposition. The Go-rejecting filter (goShapeRejectingSiblings)
// then selects, per compound, only the siblings that REJECT on the Go column — the
// mirror of the Rust rust_schema_rejecting_siblings filter, which selects the siblings
// that reject on the Rust column. The honest lockstep asymmetry shows up exactly here:
//
//   - 20 quoted-key-unknown-tier = 08 quoted-keys (Go: reject NoBlocklistSection)
//     ∪ 10 unknown-tier (Go: accept — invisible)
//   - 21 flow-blocklist-bad-guardrail-rung = 07 flow-blocklist (Go: reject
//     UnsupportedShape) ∪ 14 bad-rung-token (Go: accept — invisible)
//   - 22 entry-missing-reason-missing-provenance = 06 entry-missing-reason (Go: reject
//     EntryMissingFields) ∪ 12 entry-missing-provenance (Go: accept — invisible)
//   - 23 uppercase-fqdn-missing-guardrail-rung = 04 uppercase-fqdn (Go: reject BadFQDN)
//     ∪ 13 missing-rung-guardrail (Go: accept — invisible)
//   - 27 uppercase-fqdn-unknown-tier-missing-provenance = 04 uppercase-fqdn (Go: reject
//     BadFQDN) ∪ 10 unknown-tier (Go: accept) ∪ 12 entry-missing-provenance (Go: accept)
//
// On the RUST column row 27 is the first MULTI-element union ({BadValue,
// MissingProvenance}: TWO Rust-rejecting siblings, 10 and 12). On the GO column the Go-
// rejecting filter leaves EXACTLY ONE sibling on every row (the SHAPE sibling; the
// schema siblings are Go-invisible), so every Go union collapses to a SINGLETON — row 27
// to {ErrBadFQDN}, identical to row 23. Same map, same loop, same union; the differing
// arity per column is the honest lockstep, not a divergence.
//
// Keyed by the SAME fixture names as compoundGoShapeSibling (kept in lockstep below);
// the two maps must agree — compoundGoShapeSibling's value must be the SOLE Go-rejecting
// member of this map's sibling list, which TestDriftCorpusGoSiblingMapsAgree pins.
var compoundGoSiblingMap = map[string][]string{
	"20-quoted-key-unknown-tier.pol1.yaml": {
		"08-quoted-keys.pol1.yaml",
		"10-unknown-tier.pol1.yaml",
	},
	"21-flow-blocklist-bad-guardrail-rung.pol1.yaml": {
		"07-flow-blocklist.pol1.yaml",
		"14-bad-rung-token.pol1.yaml",
	},
	"22-entry-missing-reason-missing-provenance.pol1.yaml": {
		"06-entry-missing-reason.pol1.yaml",
		"12-entry-missing-provenance.pol1.yaml",
	},
	"23-uppercase-fqdn-missing-guardrail-rung.pol1.yaml": {
		"04-uppercase-fqdn.pol1.yaml",
		"13-missing-rung-guardrail.pol1.yaml",
	},
	"27-uppercase-fqdn-unknown-tier-missing-provenance.pol1.yaml": {
		"04-uppercase-fqdn.pol1.yaml",
		"10-unknown-tier.pol1.yaml",
		"12-entry-missing-provenance.pol1.yaml",
	},
}

// goShapeRejectingSiblings is the GO mirror of the Rust rust_schema_rejecting_siblings
// resolver: given a compound's FULL single-axis sibling list (from compoundGoSiblingMap),
// it returns the subset that REJECTS on the Go column — the resolver-lock SHAPE siblings
// the compound shares with THIS reader. The Go-INVISIBLE schema siblings (an Accept row
// on the Go column — their drift bites only the Rust SCHEMA surface) are filtered out:
// they contribute no Go cause to the union, exactly as the Rust resolver filters out the
// Rust-benign Go-shape siblings on its side.
//
// This is the ONE resolver the data-driven union premise drives BOTH the singleton and
// the (Rust-)multi-element compounds off, reusing the EXISTING compoundGoSiblingMap as
// the single source of truth. On the Go column every compound resolves to a ONE-element
// set (one SHAPE sibling), so the union over it collapses to that sibling's parsed cause
// set — but the SAME loop would range over a multi-element result without change, which
// is what keeps it the faithful structural mirror of the Rust premise that DOES resolve
// row 27 to two siblings.
func goShapeRejectingSiblings(t *testing.T, siblings []string) []string {
	t.Helper()
	var rejecting []string
	for _, s := range siblings {
		v, ok := goCorpusExpectations[s]
		if !ok {
			t.Fatalf("sibling %s named in compoundGoSiblingMap has NO entry in "+
				"goCorpusExpectations — a renamed or dropped sibling fixture must update the "+
				"sibling map (fail-closed)", s)
		}
		// The skip decision — does THIS sibling contribute to the Go-rejecting set, or is
		// it filtered out as a Go-INVISIBLE schema sibling? — is the pure predicate
		// siblingRejectsOnGoColumn, pinned fail-closed by TestSiblingRejectsOnGoColumn.
		// The production resolver and the self-test exercise the SAME predicate, so an
		// edit that flipped the skip semantic (e.g. began INCLUDING the Go-invisible
		// accept-row siblings, polluting every union with phantom causes) fails the
		// self-test RED rather than silently widening the union the premise compares.
		if siblingRejectsOnGoColumn(v) {
			rejecting = append(rejecting, s)
		}
	}
	return rejecting
}

// siblingRejectsOnGoColumn is the PURE skip decision the sibling-completeness resolver
// (goShapeRejectingSiblings) makes for each single-axis sibling: a sibling contributes to
// the Go-rejecting set iff its Go verdict REJECTS — i.e. `!verdict.accept`. The inverse,
// a verdict that ACCEPTS, is the Go-INVISIBLE schema sibling that the resolver SKIPS
// (filtered out: it bites only the Rust SCHEMA surface and contributes no Go cause to the
// union). This mirrors how allowlistExempts lifts the construction-guard's exemption into a
// pure helper: goShapeRejectingSiblings CALLS this function, and so does the table self-test
// (TestSiblingRejectsOnGoColumn), so both exercise the SAME code path — a future edit that
// flipped the skip semantic (began counting the accept-row schema siblings as Go-rejecting,
// or dropped a genuine reject sibling) would flip the self-test RED, not silently widen or
// narrow the union the reject-union-equivalence premise compares against.
func siblingRejectsOnGoColumn(verdict goVerdict) bool {
	return !verdict.accept
}

// TestSiblingRejectsOnGoColumn pins the sibling-completeness resolver's FAIL-CLOSED skip
// semantic against accidental weakening. goShapeRejectingSiblings includes a sibling in the
// Go-rejecting set ONLY when its verdict rejects; a Go-INVISIBLE schema sibling (an Accept
// verdict) must be SKIPPED — it contributes no cause to the reject-union the premise
// compares. That behaviour was previously proven only by code reading, so an edit that began
// INCLUDING the accept-row siblings (or DROPPING a genuine reject sibling) would silently
// widen or narrow every compound's union while the table-level checks stayed green. This
// table drives the SAME siblingRejectsOnGoColumn helper the production resolver calls over
// SYNTHETIC verdicts (D50 — no corpus fixture is touched; the real verdict table is
// unchanged), asserting both directions: a genuinely-rejecting verdict (every reject
// strength) is INCLUDED; an accepting verdict is SKIPPED.
func TestSiblingRejectsOnGoColumn(t *testing.T) {
	cases := []struct {
		name    string
		verdict goVerdict
		want    bool
		comment string
	}{
		{
			name:    "accept verdict -> SKIPPED (Go-invisible schema sibling)",
			verdict: goAccept(),
			want:    false,
			comment: "an accept-row sibling bites only the Rust schema surface; it contributes no Go cause and must be filtered out",
		},
		{
			name:    "presence reject verdict -> INCLUDED (Go-shape sibling)",
			verdict: goReject(ErrBadFQDN),
			want:    true,
			comment: "a single-cause shape reject is a genuine Go-rejecting sibling and must enter the union",
		},
		{
			name:    "exact-set reject verdict -> INCLUDED (Go-shape sibling)",
			verdict: goRejectExact(ErrUnsupportedShape),
			want:    true,
			comment: "the exact-set reject strength still rejects on the Go column, so it too is a Go-rejecting sibling",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := siblingRejectsOnGoColumn(tc.verdict)
			if got != tc.want {
				t.Fatalf("siblingRejectsOnGoColumn(%#v) = %v, want %v — %s. The "+
					"sibling-completeness resolver must include a sibling in the Go-rejecting set "+
					"ONLY when its verdict REJECTS: an accept-row (Go-invisible) sibling must be "+
					"SKIPPED, or a future edit would silently pollute every compound's reject-union "+
					"with phantom causes (or drop a genuine shape cause).", tc.verdict, got, tc.want,
					tc.comment)
			}
		})
	}
}

// rejectExactCompounds enumerates EVERY compound whose Go verdict is goRejectExact —
// straight from goCorpusExpectations, NOT a hand-maintained list. The Go mirror of the
// Rust premise's `reject_exact_compounds` filter: coverage cannot drift behind a hardcoded
// array, so a goRejectExact compound added to the verdict table is enumerated here
// automatically (and fails fail-closed in the premise below if it lacks a sibling-map
// entry). Returned sorted for a deterministic iteration order.
func rejectExactCompounds() []string {
	var names []string
	for name, v := range goCorpusExpectations {
		if !v.accept && v.exact {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// TestDriftCorpusGoRejectUnionEquivalencePremise is the GO mirror of the Rust
// compound_reject_parse_equivalence_premise — the data-driven UNION-over-siblings
// invariant on the reject side. It BALANCES the lockstep proof: the Rust column already
// machine-checks that each compound's parsed cause set equals the UNION over its
// Rust-SCHEMA-rejecting siblings of each sibling's parsed cause set; this asserts the
// analogous invariant on the GO column, closing the author-time gap where the Go
// compound->sibling relationship lived only in prose/comments.
//
// ## The one proof shape, data-driven over the whole corpus
//
// Every goRejectExact compound in the corpus satisfies ONE invariant: its cause set,
// PARSED FROM BYTES, equals the UNION over its Go-SHAPE-rejecting siblings of each
// sibling's cause set, PARSED FROM BYTES. The SAME loop handles both arities the Rust
// mirror exercises: the SINGLETON compounds (rows 20-23 — each composes ONE Go-shape
// sibling and one Go-INVISIBLE schema sibling) are the 1-sibling special case (a union
// over a single sibling collapses to that sibling's set, so parse(compound) ==
// parse(sibling)); row 27 — whose FULL sibling list has THREE entries (one Go-shape, two
// Go-invisible schema) — resolves through goShapeRejectingSiblings to the SAME one Go-
// shape sibling (04 uppercase-fqdn), so on the Go column it is the singleton case too,
// mirroring row 23. (The MULTI-element union for 27 lives on the RUST column, where the
// two schema siblings BOTH reject; that is the honest lockstep asymmetry, not a gap.)
//
// This enumerates every goRejectExact compound straight from goCorpusExpectations via
// rejectExactCompounds() and drives the union off the SAME compoundGoSiblingMap +
// goShapeRejectingSiblings resolver — retiring any per-row hardcoded list, exactly as the
// Rust premise retired its bespoke `covered` array.
//
// ## Why this bites where the table-level / 1:1 checks cannot
//
// The corpus walk (TestDriftCorpusGoVerdicts) pins each compound's goRejectExact set
// against bytes, and TestDriftCorpusGoRejectEquivalencePremise above pins each compound
// against its ONE 1:1 Go-shape sibling. This premise adds the data-driven UNION shape the
// Rust column carries: it proves the compound's parsed cause set equals the UNION over
// ALL its Go-rejecting siblings (resolved from the FULL sibling decomposition), so the
// Go-INVISIBLE schema axis/axes present only in the compound neither CHANGE a shape cause
// nor JOIN a new Go sentinel, and every shared shape cause survives the merge.
//
// For each goRejectExact compound this asserts, over the PARSED DISTINCT collected
// sentinel SETs (read off the bytes via rejectingSentinelSet, NOT the declared table
// rows):
//
//	(a) the compound and ALL its Go-shape siblings REJECT (a clean accept is a hard
//	    failure — rejectingSentinelSet fatals);
//	(b) the compound's parsed cause set EQUALS the UNION of its Go-shape siblings' parsed
//	    cause sets — the Go-invisible schema axis present only in the compound neither
//	    changed a shape cause nor added a new Go sentinel, and EVERY shape cause survived
//	    the merge; and
//	(c) the union is NON-VACUOUS — at least one Go-shape sibling, each contributing a
//	    NON-EMPTY set, so a both-empty (silent) equality cannot pass.
//
// Fail-closed (mirroring the Rust posture): a goRejectExact compound with NO sibling-map
// entry, or whose siblings ALL accept on the Go column (zero Go-shape siblings), fails
// LOUDLY with a named message — never silently skipped.
func TestDriftCorpusGoRejectUnionEquivalencePremise(t *testing.T) {
	// ENUMERATE every goRejectExact compound straight from the verdict table — no
	// hardcoded list to drift behind the corpus. Each is a both-REJECT artifact whose
	// parsed cause set must equal the UNION over its Go-SHAPE-rejecting siblings.
	compounds := rejectExactCompounds()

	// Sanity: a table edit that accidentally emptied the goRejectExact class (turning the
	// whole loop vacuous) fails LOUDLY rather than passing on zero iterations — the Go
	// mirror of the Rust premise's non-empty reject_exact_compounds assertion.
	if len(compounds) == 0 {
		t.Fatalf("goCorpusExpectations declares NO goRejectExact compound rows — the " +
			"reject-union-equivalence premise has nothing to enumerate; the compound both-reject " +
			"corpus (rows 20-23, 27) must carry goRejectExact verdicts for the data-driven union " +
			"proof to bite")
	}

	for _, compound := range compounds {
		t.Run(compound, func(t *testing.T) {
			siblings, ok := compoundGoSiblingMap[compound]
			if !ok {
				t.Fatalf("goRejectExact compound %s has NO entry in compoundGoSiblingMap — the "+
					"data-driven reject-union-equivalence premise enumerates EVERY goRejectExact "+
					"compound from goCorpusExpectations and resolves its Go-shape siblings here; a "+
					"compound without a sibling-map entry is an unproven cause set (fail-closed — "+
					"wire its sibling decomposition into compoundGoSiblingMap)", compound)
			}

			// Resolve the Go-SHAPE-rejecting siblings off the FULL compoundGoSiblingMap (the
			// single source of truth — no duplicate map) via the verdict-kind resolver. Every
			// Go compound resolves to ONE Go-shape sibling (its schema sibling(s) are Go-
			// invisible and contribute nothing); the union below ranges over whatever the
			// resolver returns, so the SAME loop handles any arity (mirroring Rust, which
			// resolves row 27 to two).
			shapeSiblings := goShapeRejectingSiblings(t, siblings)
			if len(shapeSiblings) == 0 {
				t.Fatalf("goRejectExact compound %s resolves to ZERO Go-SHAPE-rejecting siblings "+
					"in compoundGoSiblingMap (its siblings %v all ACCEPT on the Go column) — a "+
					"both-reject compound that rejects on the Go shape reader MUST compose at least "+
					"one Go-shape sibling whose cause it shares; the union premise cannot anchor its "+
					"parsed cause set against an empty sibling set", compound, siblings)
			}

			// (a) the compound rejects, and project its PARSED distinct cause set off the
			//     bytes (the helper fatals on a clean accept).
			compoundSet := rejectingSentinelSet(t, compound)

			// (b)+(c) UNION the Go-shape siblings' PARSED cause sets — read off the bytes, not
			//         the declared table. Each sibling MUST reject (helper fatals on a clean
			//         accept) and MUST contribute a NON-EMPTY set, so the union is provably
			//         non-vacuous.
			var perSiblingSets [][]error
			for _, sibling := range shapeSiblings {
				siblingSet := rejectingSentinelSet(t, sibling)
				if len(siblingSet) == 0 {
					t.Fatalf("Go-shape sibling %s of compound %s parsed to an EMPTY cause set — a "+
						"rejecting error tree must carry at least one known sentinel; the reject-union-"+
						"equivalence premise cannot anchor a vacuous (empty-contribution) sibling in "+
						"the union", sibling, compound)
				}
				perSiblingSets = append(perSiblingSets, siblingSet)
			}
			// Collapse the per-sibling sets into ONE sorted, distinct union set for the
			// compare. The concat + sorted-distinct UNION arithmetic — previously inlined
			// here and proven only by code reading — is now the pure helper
			// unionSentinelSets, pinned fail-closed by TestUnionSentinelSets, so the
			// production premise and the self-test exercise the SAME aggregation code path
			// (mirroring how siblingRejectsOnGoColumn / allowlistExempts lift their inlined
			// decision into a pinned pure helper). The SAME helper handles both arities the
			// Rust mirror exercises: a SINGLETON union (every Go column row collapses to one
			// shape sibling's set) and the MULTI-element collapse (the Rust-side shape the
			// self-test drives over synthetic sets).
			unionSet := unionSentinelSets(perSiblingSets)

			// (c) the union must be NON-VACUOUS — a both-empty equality would be a silent
			//     pass. Guaranteed by the per-sibling non-empty checks above plus the
			//     non-empty sibling SET, but pinned explicitly so the proof's anchor is
			//     visible at the comparison site.
			if len(unionSet) == 0 {
				t.Fatalf("compound %s: the UNION of its Go-shape siblings' parsed cause sets is "+
					"EMPTY — a rejecting compound must share at least one non-empty shape cause "+
					"with its siblings; the reject-union-equivalence premise cannot anchor a "+
					"vacuous comparison", compound)
			}

			// (b) the compound's PARSED cause set must EQUAL the UNION of its Go-shape
			//     siblings' PARSED cause sets. The Go-invisible schema axis present only in
			//     the compound must neither change a shape cause nor add a new Go sentinel;
			//     EVERY shared shape cause must survive the compound presence UNCHANGED.
			//     Relocating / dropping a sentinel only-under-the-compound (but not in its
			//     sibling), or surfacing an extra sentinel only under the compound, fails HERE
			//     with the UNION-set diff — while the verdict / exact-set / 1:1 checks stay
			//     green.
			if !sameSentinelSet(compoundSet, unionSet) {
				t.Fatalf("compound %s: its PARSED cause set %v does NOT equal the UNION of its "+
					"single-axis Go-SHAPE siblings' parsed cause sets %v (Go-shape siblings: %v). "+
					"The compound joins its shape siblings' resolver-lock drift with a Go-INVISIBLE "+
					"schema axis on ONE artifact; EVERY shared SHAPE cause must reject IDENTICALLY "+
					"(same sentinels, same axis) whether or not the schema axis is present — a "+
					"divergence means a regression relocated, dropped, or joined a sentinel ONLY in "+
					"the compound presence of the other axis (a runtime drift the verdict / exact-set "+
					"checks cannot see)", compound, compoundSet, unionSet, shapeSiblings)
			}
		})
	}
}

// TestDriftCorpusGoSiblingMapsAgree pins the two Go sibling maps in lockstep: the FULL
// compoundGoSiblingMap (every single-axis sibling) and the 1:1 compoundGoShapeSibling
// (only the Go-rejecting SHAPE sibling) must agree — the value of compoundGoShapeSibling
// must be the SOLE Go-rejecting member of the corresponding compoundGoSiblingMap list,
// and the two maps must cover the SAME compounds. Without this, the two decompositions
// could drift apart silently (e.g. a sibling rename applied to only one map). Fail-closed
// in both directions and over the shape-sibling identity.
func TestDriftCorpusGoSiblingMapsAgree(t *testing.T) {
	if len(compoundGoSiblingMap) != len(compoundGoShapeSibling) {
		t.Fatalf("sibling-map cardinality mismatch: compoundGoSiblingMap has %d compounds, "+
			"compoundGoShapeSibling has %d — both maps must decompose the SAME set of compound "+
			"fixtures (fail-closed)", len(compoundGoSiblingMap), len(compoundGoShapeSibling))
	}
	for compound, full := range compoundGoSiblingMap {
		shape, ok := compoundGoShapeSibling[compound]
		if !ok {
			t.Errorf("compound %s is in compoundGoSiblingMap but NOT in compoundGoShapeSibling "+
				"— both maps must cover the same compounds", compound)
			continue
		}
		rejecting := goShapeRejectingSiblings(t, full)
		if len(rejecting) != 1 || rejecting[0] != shape {
			t.Errorf("compound %s: compoundGoShapeSibling names %s as the single Go-shape "+
				"sibling, but goShapeRejectingSiblings over compoundGoSiblingMap's full list %v "+
				"resolves to %v — the 1:1 shape map must equal the SOLE Go-rejecting member of "+
				"the full sibling list (a sibling rename must update both maps)", compound, shape,
				full, rejecting)
		}
	}
}

// sortedDistinctSentinels returns the SORTED, DISTINCT set of sentinels from the input —
// the union-merge discipline the reject-union-equivalence premise applies after
// concatenating per-sibling sets. Distinctness is by errors.Is identity; the sort key is
// the sentinel's message string, matching presentSentinels' stable order so a unioned set
// compares positionally against a presentSentinels result via sameSentinelSet.
func sortedDistinctSentinels(in []error) []error {
	var out []error
	for _, e := range in {
		dup := false
		for _, kept := range out {
			if errors.Is(e, kept) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, e)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Error() < out[j-1].Error(); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// unionSentinelSets is the PURE union/aggregation arithmetic the reject-union-equivalence
// premise (TestDriftCorpusGoRejectUnionEquivalencePremise) runs over its Go-shape siblings:
// given each sibling's parsed cause SET, it CONCATENATES them and COLLAPSES the result into
// one SORTED, DISTINCT union set (via sortedDistinctSentinels). The premise CALLS this
// function and so does the table self-test (TestUnionSentinelSets), so both exercise the SAME
// aggregation code path — mirroring how siblingRejectsOnGoColumn / allowlistExempts /
// nameReconciledAcrossSets lift their inlined decision into a pinned pure helper.
//
// The aggregation is the SAME loop for BOTH arities the Rust mirror exercises: a SINGLETON
// (one per-sibling set — every Go column row collapses to one shape sibling's parsed cause
// set) and the MULTI-element collapse (overlapping per-sibling sets union to a strictly larger
// distinct set; deduplicated by errors.Is identity). Distinctness and ordering are inherited
// from sortedDistinctSentinels, so the unioned set compares positionally against a
// presentSentinels result via sameSentinelSet — exactly the compare the premise performs. A
// future edit that broke the union arithmetic (dropped a sibling's contribution, failed to
// dedupe an overlap, or mis-sorted the result) would flip TestUnionSentinelSets RED rather
// than silently changing the union the premise compares against.
func unionSentinelSets(perSiblingSets [][]error) []error {
	var concatenated []error
	for _, set := range perSiblingSets {
		concatenated = append(concatenated, set...)
	}
	return sortedDistinctSentinels(concatenated)
}

// TestUnionSentinelSets pins the reject-union-equivalence premise's UNION arithmetic against
// accidental weakening. The premise concatenates each Go-shape sibling's parsed cause set and
// collapses the result into one sorted, distinct union set (unionSentinelSets); that aggregation
// was previously INLINED in the premise body and proven only by code reading, so an edit that
// dropped a sibling's contribution, failed to dedupe an overlapping sentinel, or mis-ordered the
// merge would silently change the union the premise compares against while the table-level checks
// stayed green. This table drives the SAME unionSentinelSets helper the production premise calls
// over SYNTHETIC sentinel sets (D50 — no corpus fixture is touched; the real verdict table and
// sibling maps are unchanged), exercising BOTH arities the Rust mirror carries: the SINGLETON case
// (one sibling set — a union over a single sibling collapses to that sibling's set, the Go column's
// shape) AND the MULTI-element collapse (two sibling sets that OVERLAP must union to the merged
// DISTINCT set, deduping the shared sentinel — the Rust-side shape). A near-miss (a missing or
// extra sentinel) is correctly EXCLUDED by the exact set-equality assertion via sameSentinelSet.
func TestUnionSentinelSets(t *testing.T) {
	// Synthetic sentinel sets built from the exported universe values (D50 — no fixture,
	// no production table touched). Each per-sibling input is itself a SORTED, distinct set,
	// as rejectingSentinelSet returns; the helper concatenates and collapses across siblings.
	cases := []struct {
		name    string
		input   [][]error
		want    []error
		comment string
	}{
		{
			name:    "singleton union -> collapses to the single sibling's set",
			input:   [][]error{sortedDistinctSentinels([]error{ErrBadFQDN})},
			want:    sortedDistinctSentinels([]error{ErrBadFQDN}),
			comment: "the Go column shape: every compound resolves to ONE Go-shape sibling, so the union over it is that sibling's set",
		},
		{
			name: "multi-element disjoint union -> merged distinct set",
			input: [][]error{
				sortedDistinctSentinels([]error{ErrBadFQDN}),
				sortedDistinctSentinels([]error{ErrUnsupportedShape}),
			},
			want:    sortedDistinctSentinels([]error{ErrBadFQDN, ErrUnsupportedShape}),
			comment: "the Rust-side shape: two distinct sibling causes union to a strictly larger set",
		},
		{
			name: "multi-element OVERLAPPING union -> deduped to the distinct merge",
			input: [][]error{
				sortedDistinctSentinels([]error{ErrBadFQDN, ErrUnsupportedShape}),
				sortedDistinctSentinels([]error{ErrUnsupportedShape, ErrEntryMissingFields}),
			},
			want:    sortedDistinctSentinels([]error{ErrBadFQDN, ErrUnsupportedShape, ErrEntryMissingFields}),
			comment: "the shared sentinel (ErrUnsupportedShape) must appear ONCE — the collapse must dedupe by errors.Is identity, not concatenate blindly",
		},
		{
			name:    "empty input -> empty union",
			input:   nil,
			want:    nil,
			comment: "no siblings contributes no causes; the union is empty (the premise separately guards against a vacuous compare)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unionSentinelSets(tc.input)
			if !sameSentinelSet(got, tc.want) {
				t.Fatalf("unionSentinelSets(%v) = %v, want %v — %s. The reject-union-equivalence "+
					"premise's aggregation must CONCATENATE every sibling's parsed cause set and "+
					"COLLAPSE the result into one sorted, DISTINCT union (dedupe by errors.Is): "+
					"dropping a contribution, double-counting an overlap, or mis-ordering the merge "+
					"would silently change the union the premise compares against.", tc.input, got,
					tc.want, tc.comment)
			}
		})
	}
}

// reconcileCorpusCoverage is the PURE coverage/lockstep COUNT reconciliation decision the
// fixture coverage gate (TestDriftCorpusCoverageLockstep) makes: given the fixture filenames
// ON DISK and the KEY SET of the Go expectation table, it reports BOTH asymmetric set
// differences —
//
//   - missingExpectation: fixtures present on disk but ABSENT from the expectation keys (the
//     onDisk ⊄ expectations gap — a fixture added to the corpus directory for the Rust reader,
//     or anyone, that the Go reader has not wired; the lockstep-fail-closed direction the task
//     names);
//   - staleExpectation: expectation keys with NO fixture on disk (the expectations ⊄ onDisk
//     gap — a stale row whose fixture was deleted).
//
// Each return slice is SORTED for a deterministic, name-stable verdict (no map-iteration
// order leaks into the gate). When BOTH are empty the two sets are EQUAL element-for-element,
// which makes the count parity (len(onDisk) == len(expectationKeys)) a DERIVED consequence,
// not an independent floor — a set equality is exactly count parity PLUS membership parity, so
// the helper carries the WHOLE lockstep reconciliation the gate previously inlined across its
// two loops and its count check.
//
// The production guard CALLS this function and so does the table self-test
// (TestReconcileCorpusCoverage), so both exercise the SAME reconciliation code path —
// mirroring how nameReconciledAcrossSets / siblingRejectsOnGoColumn / allowlistExempts /
// goExactSetMatches lift their inlined decision into a pinned pure helper. A future edit that
// compared the WRONG direction (e.g. dropped the stale-expectation arm so a deleted fixture
// stopped being flagged), or that lost the count parity by dropping one arm, flips the
// self-test RED rather than silently widening the lockstep gate the corpus depends on.
func reconcileCorpusCoverage(onDisk []string, expectationKeys map[string]bool) (missingExpectation, staleExpectation []string) {
	onDiskSet := make(map[string]bool, len(onDisk))
	for _, n := range onDisk {
		onDiskSet[n] = true
		if !expectationKeys[n] {
			// On disk but no expectation row — the lockstep-fail-closed gap the task names.
			missingExpectation = append(missingExpectation, n)
		}
	}
	for name := range expectationKeys {
		if !onDiskSet[name] {
			// An expectation row with no fixture on disk — a stale row to drop.
			staleExpectation = append(staleExpectation, name)
		}
	}
	sort.Strings(missingExpectation)
	sort.Strings(staleExpectation)
	return missingExpectation, staleExpectation
}

// expectationKeySet is the small projection the coverage gate passes reconcileCorpusCoverage:
// the KEY SET of the Go expectation table as a membership map. It exists only so the gate hands
// the pure helper a plain set (not the verdict-valued map) — the helper reconciles set
// membership, never verdict bodies, so projecting the keys keeps its signature honest.
func expectationKeySet(expectations map[string]goVerdict) map[string]bool {
	keys := make(map[string]bool, len(expectations))
	for k := range expectations {
		keys[k] = true
	}
	return keys
}

// TestReconcileCorpusCoverage pins the coverage gate's FAIL-CLOSED reconciliation semantic
// against accidental weakening. TestDriftCorpusCoverageLockstep flags a fixture on disk with no
// expectation row (the onDisk ⊄ expectations gap — the lockstep-fail-closed direction a fixture
// added for one reader hits) AND a stale expectation key with no fixture on disk (the
// expectations ⊄ onDisk gap), and its count parity falls out of BOTH sets being equal. That
// reconciliation was previously INLINED across two loops plus a len() check and proven only by
// code reading, so an edit that dropped one arm (a deleted fixture stops being flagged, or a
// new unwired fixture slips through) or compared the wrong direction would silently widen the
// lockstep gate while the per-class verdict stayed green. This table drives the SAME
// reconcileCorpusCoverage helper the production gate calls over SYNTHETIC in-memory name sets
// (D50 — no corpus fixture is touched; the real on-disk corpus and goCorpusExpectations are
// unchanged), asserting: matched sets reconcile (both diffs empty, count parity holds); a
// fixture present on disk but absent from expectations is flagged (a SHORT expectation count);
// an expectation with no on-disk fixture is flagged (an OVER expectation count); and a mix of
// both arms is reported on BOTH sides at once.
func TestReconcileCorpusCoverage(t *testing.T) {
	// Synthetic on-disk fixture lists and expectation key sets (D50 — no fixture, no
	// production table touched). These literals exist only to exercise the pure helper's
	// reconciliation arms; the real corpus walk and goCorpusExpectations are untouched.
	cases := []struct {
		name        string
		onDisk      []string
		expectKeys  map[string]bool
		wantMissing []string
		wantStale   []string
		comment     string
	}{
		{
			name:        "matched sets -> reconciles (both diffs empty, count parity holds)",
			onDisk:      []string{"00-a.pol1.yaml", "01-b.pol1.yaml", "02-c.pol1.yaml"},
			expectKeys:  map[string]bool{"00-a.pol1.yaml": true, "01-b.pol1.yaml": true, "02-c.pol1.yaml": true},
			wantMissing: nil,
			wantStale:   nil,
			comment:     "the equal-set case: every fixture wired, every key on disk, equal counts — the only state the gate passes",
		},
		{
			name:        "fixture on disk absent from expectations -> flagged (SHORT count)",
			onDisk:      []string{"00-a.pol1.yaml", "01-b.pol1.yaml", "02-unwired.pol1.yaml"},
			expectKeys:  map[string]bool{"00-a.pol1.yaml": true, "01-b.pol1.yaml": true},
			wantMissing: []string{"02-unwired.pol1.yaml"},
			wantStale:   nil,
			comment:     "the lockstep-fail-closed direction: a fixture added to the corpus (for the Rust reader, or anyone) with no Go expectation row must be flagged, never silently accepted",
		},
		{
			name:        "expectation with no on-disk fixture -> flagged (OVER count)",
			onDisk:      []string{"00-a.pol1.yaml", "01-b.pol1.yaml"},
			expectKeys:  map[string]bool{"00-a.pol1.yaml": true, "01-b.pol1.yaml": true, "99-stale.pol1.yaml": true},
			wantMissing: nil,
			wantStale:   []string{"99-stale.pol1.yaml"},
			comment:     "a stale expectation row whose fixture was deleted must be flagged — dropping this arm would let a deleted fixture's row rot unnoticed",
		},
		{
			name:        "both arms drift at once -> BOTH reported, sorted",
			onDisk:      []string{"00-a.pol1.yaml", "03-extra-disk.pol1.yaml", "01-extra-disk-b.pol1.yaml"},
			expectKeys:  map[string]bool{"00-a.pol1.yaml": true, "98-stale-b.pol1.yaml": true, "99-stale-a.pol1.yaml": true},
			wantMissing: []string{"01-extra-disk-b.pol1.yaml", "03-extra-disk.pol1.yaml"},
			wantStale:   []string{"98-stale-b.pol1.yaml", "99-stale-a.pol1.yaml"},
			comment:     "both asymmetric differences must be reported INDEPENDENTLY and SORTED — a one-armed reconciliation would mask one direction of the lockstep gap",
		},
		{
			name:        "empty on disk, non-empty expectations -> all expectations stale",
			onDisk:      nil,
			expectKeys:  map[string]bool{"00-a.pol1.yaml": true},
			wantMissing: nil,
			wantStale:   []string{"00-a.pol1.yaml"},
			comment:     "an empty corpus against a non-empty table flags every key stale (the count-mismatch the gate's parity check guards, surfaced by name)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotMissing, gotStale := reconcileCorpusCoverage(tc.onDisk, tc.expectKeys)
			if !reflect.DeepEqual(gotMissing, tc.wantMissing) {
				t.Fatalf("reconcileCorpusCoverage(%v, %v) missingExpectation = %v, want %v — %s. "+
					"A fixture on disk with NO expectation row must be flagged (the onDisk ⊄ "+
					"expectations arm): dropping or inverting it would let an unwired fixture slip "+
					"the lockstep gate.", tc.onDisk, tc.expectKeys, gotMissing, tc.wantMissing, tc.comment)
			}
			if !reflect.DeepEqual(gotStale, tc.wantStale) {
				t.Fatalf("reconcileCorpusCoverage(%v, %v) staleExpectation = %v, want %v — %s. "+
					"An expectation key with NO on-disk fixture must be flagged (the expectations ⊄ "+
					"onDisk arm): dropping it would let a deleted fixture's stale row rot unnoticed.",
					tc.onDisk, tc.expectKeys, gotStale, tc.wantStale, tc.comment)
			}
			// Count parity is a DERIVED consequence of a CLEAN reconciliation, ONE direction
			// only: a clean reconciliation (both diffs empty = full set equality) IMPLIES equal
			// counts (equal sets are count parity PLUS membership parity). The converse does NOT
			// hold — equal counts with a SWAPPED membership (the "both arms drift at once" case:
			// one extra on disk balanced by one stale key) reconciles DIRTY while counts match,
			// which is exactly why the gate cannot rely on the count parity ALONE and must run
			// both reconciliation arms. Pin the sound implication (reconciled => countParity) so
			// a helper that lost an arm — letting a dirty case report clean — would break it.
			reconciled := len(gotMissing) == 0 && len(gotStale) == 0
			countParity := len(tc.onDisk) == len(tc.expectKeys)
			if reconciled && !countParity {
				t.Fatalf("reconcileCorpusCoverage(%v, %v): reported a CLEAN reconciliation "+
					"(both diffs empty) yet counts differ (%d on disk vs %d expectation keys) — "+
					"a clean reconciliation is full set equality, which MUST imply equal counts. "+
					"If these diverge the helper has lost an arm and the count parity the gate "+
					"derives from set equality is no longer sound — %s.", tc.onDisk, tc.expectKeys,
					len(tc.onDisk), len(tc.expectKeys), tc.comment)
			}
		})
	}
}

// TestDriftCorpusCoverageLockstep is the fail-closed coverage gate (the GO half).
// It reconciles the fixtures ON DISK against the expectation table: every fixture
// must be registered, and every registered key must exist on disk. A fixture
// added to the corpus directory for the Rust reader (or anyone) without a Go
// expectation row fails HERE — so a fixture added for one reader fails the other
// until BOTH tables list it. The Rust test enforces the identical reconciliation
// on its side, completing the two-sided lockstep.
//
// The set reconciliation itself — both asymmetric differences AND the count parity
// they derive — is the pure predicate reconcileCorpusCoverage, pinned fail-closed by
// TestReconcileCorpusCoverage. The gate CALLS it over the LIVE on-disk corpus and the
// real goCorpusExpectations key set, so the gate keeps biting on the real sets while the
// self-test exercises the SAME reconciliation code path over synthetic sets (D50) —
// mirroring how nameReconciledAcrossSets / goExactSetMatches lift their inlined decision
// into a pinned pure helper. An edit that dropped an arm (a deleted fixture stops being
// flagged, or a new unwired fixture slips through) flips the self-test RED rather than
// silently widening this gate.
func TestDriftCorpusCoverageLockstep(t *testing.T) {
	onDisk := listCorpusFixtures(t)
	missingExpectation, staleExpectation := reconcileCorpusCoverage(onDisk, expectationKeySet(goCorpusExpectations))
	for _, n := range missingExpectation {
		t.Errorf("corpus fixture %s has NO Go verdict expectation — every shared "+
			"fixture must be wired into goCorpusExpectations (lockstep fail-closed: "+
			"a fixture added for one reader must be wired on both)", n)
	}
	for _, name := range staleExpectation {
		t.Errorf("goCorpusExpectations lists %s but no such fixture exists on disk "+
			"(stale expectation — deleting a fixture must drop its row here)", name)
	}
	// Count parity: the table and the directory must enumerate the SAME set, so
	// the count is exact, not a floor. (Belt-and-suspenders over the two diffs —
	// equal sets are count parity plus membership parity, both reconciled above.)
	if len(goCorpusExpectations) != len(onDisk) {
		t.Fatalf("drift-corpus count mismatch: %d fixtures on disk, %d Go expectations — "+
			"the Go reader's coverage must enumerate the corpus exactly (lockstep "+
			"fail-closed)", len(onDisk), len(goCorpusExpectations))
	}
}

// TestCorpusPathIdentity is the Go half of the coupling assertion.  It verifies
// that CorpusFixturesDir() resolves to a path whose canonical suffix matches
// CorpusFixturesCanonicalSuffix (the single declared corpus location).  The Rust
// test (corpus_path_identity in pack_drift_corpus.rs) enforces the mirror on its
// side with the SAME canonical suffix string.
//
// A corpus move that updates only this file (without updating pack_drift_corpus.rs)
// fails the Rust test.  A corpus move that updates only pack_drift_corpus.rs fails
// THIS test.  A move that updates neither fails both readers' directory-not-found
// panics.  Any of the three cases is LOUD — the coupling gap the task requires
// closing.
func TestCorpusPathIdentity(t *testing.T) {
	dir := CorpusFixturesDir()
	// Normalise to forward-slash for a portable suffix check.
	normalized := filepath.ToSlash(dir)
	want := CorpusFixturesCanonicalSuffix
	if !strings.HasSuffix(normalized, want) {
		t.Fatalf("CorpusFixturesDir() resolved to %q, which does NOT end with the "+
			"canonical corpus suffix %q — the Go and Rust readers must both resolve to "+
			"the SAME corpus location; a corpus move or a path-constant change must "+
			"update BOTH readers (this file AND dataplane/crates/policy-core/tests/"+
			"pack_drift_corpus.rs) to keep the coupling assertion green", dir, want)
	}
	// Also assert the directory actually exists and is non-empty, so a symlink that
	// points at a moved-but-not-updated corpus is not accepted as "correct path".
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("corpus directory %s does not exist or is not accessible: %v "+
			"(coupling assertion: both readers must reach the SAME live corpus)", dir, err)
	}
}

// resolverlockPackageDir returns the absolute path to the package SOURCE directory,
// anchored off THIS test file's location via runtime.Caller — the same cwd-independent
// discipline the production code uses (ShippedPackPath / CorpusFixturesDir). The
// completeness guard walks EVERY non-_test.go .go file in this directory to enumerate
// the exported sentinels actually declared, so a sentinel added to ANY package file
// (not just resolverlock.go) is in scope — robust to file-layout drift.
func resolverlockPackageDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed — cannot locate the test source to anchor " +
			"the package directory for the sentinel-universe completeness scan")
	}
	return filepath.Dir(thisFile)
}

// packageSourceFiles returns the SORTED set of absolute paths to the package's
// non-_test.go Go source files — the WHOLE production surface the sentinel scan must
// cover. Walking the directory (os.ReadDir, stdlib) rather than hard-coding a single
// file is the layout-drift fix the task requires: the package already carries a second
// non-_test.go file (doc.go), and any future file that declares an Err* sentinel must
// be visible to the completeness guard, or the exact-set bite silently re-opens. The
// _test.go files (including THIS one) are excluded — a test-only Err* var is not part
// of the scanner's reject surface.
func packageSourceFiles(t *testing.T) []string {
	t.Helper()
	dir := resolverlockPackageDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the package source dir %s for the exported-sentinel scan: %v",
			dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	if len(files) == 0 {
		t.Fatalf("found ZERO non-_test.go .go files in the package dir %s — the "+
			"sentinel scan has nothing to read; the package layout is broken", dir)
	}
	sort.Strings(files)
	return files
}

// declaredExportedSentinels parses EVERY non-_test.go .go file in the package and
// returns the SORTED set of exported package-level sentinel names — every
// `Err<Name> = errors.New(...)` var spec at file scope whose identifier is exported,
// collected ACROSS THE WHOLE PACKAGE. This is the source-of-truth the completeness
// guard reconciles the universe table against. Using go/parser + go/ast (stdlib) makes
// the scan structural, not a brittle line grep: a sentinel renamed, added, or removed
// in source is reflected here automatically. Walking ALL package files (not just
// resolverlock.go) makes the guard robust to file-layout drift — a sentinel introduced
// in a NEW or DIFFERENT package file is still caught.
func declaredExportedSentinels(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	var names []string
	for _, src := range packageSourceFiles(t) {
		f, err := parser.ParseFile(fset, src, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s for the exported-sentinel scan: %v", src, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range vs.Names {
					// Only exported `Err*` identifiers — the sentinel naming convention.
					if !ident.IsExported() || !strings.HasPrefix(ident.Name, "Err") {
						continue
					}
					// Confirm the RHS is an errors.New(...) call, so this counts only the
					// sentinel declarations (not, e.g., an exported Err-prefixed non-sentinel
					// var that might appear later). A package-level sentinel var ALWAYS has a
					// value, so a names-without-values block (rare for vars) is skipped safely.
					if i >= len(vs.Values) {
						continue
					}
					if !isErrorsNewCall(vs.Values[i]) {
						continue
					}
					names = append(names, ident.Name)
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// isErrorsNewCall reports whether an expression is a call to `errors.New(...)` — the
// shape every resolverlock sentinel is declared with. Keeps the completeness scan
// pinned to actual sentinels rather than any exported Err-prefixed var.
func isErrorsNewCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "errors" && sel.Sel.Name == "New"
}

// declaredExportedErrorVars is the NAMING-AGNOSTIC, CONSTRUCTOR-AGNOSTIC companion to
// declaredExportedSentinels: it TYPE-CHECKS the whole package and returns the SORTED set
// of exported, file-scope, error-TYPED package-level var names — every exported var whose
// inferred type satisfies the universe `error` interface, regardless of how it is NAMED or
// CONSTRUCTED. Where declaredExportedSentinels keys on the load-bearing Err-prefix +
// errors.New convention (a fast, syntactic scan), THIS scan asks the type checker the
// structural question the convention is a proxy for: "is this exported var an error?" So a
// sentinel built with fmt.Errorf, a custom constructor, or NAMED without an Err prefix —
// any of which slips past the syntactic scan — is still enumerated here and reconciled
// against the universe by TestExportedErrorVarsCoveredByUniverse below.
//
// It uses go/types with the SOURCE importer (stdlib, no new deps): the package's non-_test
// .go files (packageSourceFiles — the SAME production surface the syntactic scan walks) are
// parsed and type-checked, then the package scope is enumerated for exported *types.Var
// objects whose type Implements(error). _test.go files (including THIS one) are excluded for
// the SAME reason as the syntactic scan: a test-only error var is not part of the scanner's
// reject surface. A type-check error is a HARD failure (the scan must not vacuously pass on
// a package that does not compile).
func declaredExportedErrorVars(t *testing.T) []string {
	t.Helper()
	// HOIST: the parse + go/types SOURCE-importer check is ~0.25s and DETERMINISTIC per
	// test binary (it reads the SAME non-_test.go package files no matter which test
	// calls it). After orch49 this function has two callers in the same binary
	// (TestExportedErrorVarsCoveredByUniverse + TestExportedErrorSentinelsFollowConstructionConvention),
	// so without a cache the check runs once PER caller and the duplicated cost grows
	// linearly as more type-driven guards land. Compute it ONCE behind a package-level
	// sync.Once and return the cached (sorted names) result.
	//
	// FAIL-LOUD UNDER THE CACHE: the computation is t-FREE — it captures any failure as a
	// STRING (errString) instead of routing it through the FIRST caller's *testing.T. The
	// wrapper then RE-RAISES that captured failure via t.Fatalf on EVERY call, using the
	// CURRENT test's t, so a non-compiling package (or zero-vars scope, or a parse/read
	// failure) FATALS whichever test asked — no later caller silently skips the check. The
	// cache stores only a PURE result; it never swallows.
	exportedErrorVarsOnce.Do(func() {
		// COMPUTE-ONCE COUNTER (test-only instrumentation, ZERO behavior change): bump a
		// package-level counter INSIDE the Once closure so the expensive parse + go/types
		// check that ran here can be ASSERTED to have run exactly once across BOTH type-aware
		// guards (TestExportedErrorVarsCoveredByUniverse +
		// TestExportedErrorSentinelsFollowConstructionConvention). The closure runs exactly
		// once per test binary (serialized by exportedErrorVarsOnce), so the increment is
		// race-free and pins the compute-once invariant — TestComputeExportedErrorVarsRunsOnce
		// asserts the counter == 1, so a future refactor that DROPPED the sync.Once (re-running
		// the ~0.25s type-check per caller) is caught LOUDLY instead of silently regressing cost.
		exportedErrorVarsComputeCount++
		exportedErrorVarsCache.names, exportedErrorVarsCache.errString = computeExportedErrorVars()
	})
	if s := exportedErrorVarsCache.errString; s != "" {
		// Re-raise on the CURRENT t, every call — the captured failure fails THIS test.
		t.Fatalf("%s", s)
	}
	// Defensive copy so a caller that mutates (e.g. sorts/appends to) the returned slice
	// cannot corrupt the shared cache for the next caller. The result is already sorted.
	out := make([]string, len(exportedErrorVarsCache.names))
	copy(out, exportedErrorVarsCache.names)
	return out
}

// exportedErrorVarsResult is the cached, t-FREE result of the go/types exported-error-var
// scan: the SORTED names on success, or a non-empty errString capturing the FIRST failure
// (the wrapper re-raises it via t.Fatalf on every call). Exactly one of the two is
// meaningful — a non-empty errString means names is nil/unused.
type exportedErrorVarsResult struct {
	names     []string
	errString string
}

var (
	// exportedErrorVarsOnce guards the single per-test-binary computation of the parsed +
	// type-checked exported-error-var set (the hoist this unit adds).
	exportedErrorVarsOnce sync.Once
	// exportedErrorVarsCache holds the result of that single computation; read by every
	// declaredExportedErrorVars call after the Once fires.
	exportedErrorVarsCache exportedErrorVarsResult
	// exportedErrorVarsComputeCount is TEST-ONLY instrumentation: incremented INSIDE the
	// exportedErrorVarsOnce closure, it counts how many times the expensive parse + go/types
	// compute actually ran. The Once fires the closure exactly once per test binary regardless
	// of how many guards call declaredExportedErrorVars, so this counter is 1 after the first
	// call ever — TestComputeExportedErrorVarsRunsOnce asserts == 1 to PIN the compute-once
	// invariant the hoist provides (no production effect; the guards' results are unchanged).
	exportedErrorVarsComputeCount int
)

// computeExportedErrorVars runs the parse + go/types SOURCE-importer check ONCE (under the
// package-level sync.Once) and returns the SORTED set of exported, file-scope, error-TYPED
// package-level var names — identical to the pre-hoist declaredExportedErrorVars body, but
// t-FREE: every failure path returns a non-empty error STRING (captured into the cache and
// re-raised via t.Fatalf by the wrapper on every call) instead of touching a *testing.T. On
// success the returned string is empty. It is the SAME production surface and SAME
// inclusion/exclusion rules as the syntactic scan: the package's non-_test.go .go files are
// parsed and type-checked, then the package scope is enumerated for exported *types.Var
// objects whose type Implements(error). A read/parse/type-check failure yields a non-empty
// errString so the scan never vacuously passes on a package that does not compile.
func computeExportedErrorVars() (names []string, errString string) {
	dir, err := resolverlockPackageDirErr()
	if err != nil {
		return nil, err.Error()
	}
	srcs, err := packageSourceFilesIn(dir)
	if err != nil {
		return nil, err.Error()
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, src := range srcs {
		f, perr := parser.ParseFile(fset, src, nil, 0)
		if perr != nil {
			return nil, fmt.Sprintf("parsing %s for the error-typed exported-var scan: %v", src, perr)
		}
		files = append(files, f)
	}
	// Capture the FIRST type error the checker surfaces (the t-free analog of the original
	// Error callback's t.Errorf): the scan must fail LOUDLY on a non-compiling package,
	// never enumerate a half-checked scope.
	var firstTypeErr error
	conf := types.Config{
		// SOURCE importer: type-check the package's imports (errors/fmt/os/…) from their
		// source, so this works offline and without prebuilt export data — stdlib only.
		Importer: importer.ForCompiler(fset, "source", nil),
		Error: func(err error) {
			if firstTypeErr == nil {
				firstTypeErr = err
			}
		},
	}
	pkg, err := conf.Check("resolverlock", fset, files, nil)
	if err != nil {
		return nil, fmt.Sprintf("type-checking the resolverlock package for the error-typed "+
			"exported-var scan failed: %v (the naming-agnostic completeness guard cannot "+
			"enumerate the error-typed vars of a package that does not type-check)", err)
	}
	if firstTypeErr != nil {
		return nil, fmt.Sprintf("type-checking the resolverlock package for the error-typed "+
			"exported-var scan: %v", firstTypeErr)
	}
	errIface, ok := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	if !ok {
		return nil, "the universe `error` type is not an interface — go/types is broken"
	}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || !v.Exported() {
			continue
		}
		// TYPE-driven, not name-driven: assignable-to-error is the whole test. Catches a
		// non-Err-prefixed / fmt.Errorf / custom-constructor exported error var the
		// syntactic Err*+errors.New scan misses.
		if types.Implements(v.Type(), errIface) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, ""
}

// resolverlockPackageDirErr is the t-FREE companion of resolverlockPackageDir: it returns the
// package directory (or an error) so the hoisted, sync.Once-guarded computation can capture a
// failure as a string instead of touching a *testing.T. runtime.Caller(0) anchors to THIS test
// file (same directory the t-based helper resolves), so the result is identical.
func resolverlockPackageDirErr() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller(0) failed — cannot locate the test source to " +
			"anchor the package directory for the error-typed exported-var scan")
	}
	return filepath.Dir(thisFile), nil
}

// packageSourceFilesIn is the t-FREE companion of packageSourceFiles: given the package
// directory, it returns the SORTED set of non-_test.go .go source paths (or an error). Same
// inclusion/exclusion rules as packageSourceFiles (skip dirs, skip non-.go, skip _test.go,
// fail on an empty result), so the hoisted computation walks the identical production surface.
func packageSourceFilesIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading the package source dir %s for the exported-sentinel "+
			"scan: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("found ZERO non-_test.go .go files in the package dir %s — the "+
			"sentinel scan has nothing to read; the package layout is broken", dir)
	}
	sort.Strings(files)
	return files, nil
}

// TestExportedErrorVarsCoveredByUniverse is the NAMING-AGNOSTIC hardening the task adds: a
// fail-closed guard that EVERY exported, file-scope, error-TYPED package-level var (found by
// TYPE via declaredExportedErrorVars, regardless of name or constructor) is enumerated in
// exportedSentinelUniverse. It closes the gap the syntactic completeness guard
// (TestExportedSentinelUniverseComplete) leaves open: that guard keys on the Err-prefix +
// errors.New convention, so an exported package-level error built with fmt.Errorf, a custom
// constructor, or NAMED without the Err prefix escapes BOTH the universe reconciliation AND
// the exact-set bite (presentSentinels only scans the universe's values). Such a sentinel
// could become a NEW resolverlock reject cause that the goRejectExact exact-set rows can
// never see — silently weakening the bite.
//
// This guard reconciles the TYPE-derived universe against the table in the FORWARD direction
// (every error-typed exported var must be in the universe) and FAILS LOUDLY naming the
// offending var by PACKAGE + IDENTIFIER — it never skips or swallows. The REVERSE direction
// (a stale universe row no longer declared in source) and the BY-NAME Err*+errors.New
// reconciliation are owned by TestExportedSentinelUniverseComplete and stay UNWEAKENED; this
// test only BROADENS coverage to the convention-violating shapes, it does not replace the
// existing bite.
//
// Proven (via a reverted SCRATCH mutation, never committed): adding an exported
// `var Foo = fmt.Errorf(...)` WITHOUT an Err prefix to a package source file fails THIS test
// naming resolverlock.Foo — while TestExportedSentinelUniverseComplete (Err-prefix-keyed)
// would not have seen it.
func TestExportedErrorVarsCoveredByUniverse(t *testing.T) {
	errorVars := declaredExportedErrorVars(t)
	if len(errorVars) == 0 {
		t.Fatalf("type-checked the package's non-_test.go source files but found ZERO "+
			"exported error-typed package-level vars under %s — the resolverlock scanner "+
			"declares Err* sentinels, so the type-aware scan finding none means it is broken; "+
			"refusing to vacuously pass", resolverlockPackageDir(t))
	}

	universeSet := make(map[string]bool, len(exportedSentinelUniverse))
	for _, s := range exportedSentinelUniverse {
		universeSet[s.name] = true
	}

	// FORWARD direction only (the reverse + the Err*+errors.New by-name reconciliation are
	// owned, unweakened, by TestExportedSentinelUniverseComplete): every error-TYPED exported
	// var must be in the universe, regardless of naming convention or constructor.
	for _, name := range errorVars {
		if !universeSet[name] {
			t.Errorf("exported error-typed package-level var resolverlock.%s is NOT in "+
				"exportedSentinelUniverse — it is assignable to error (the type checker says so) "+
				"yet escapes the universe, so the exact-set scan (presentSentinels) would NEVER "+
				"look for it and a goRejectExact reject path carrying it would slip through. This "+
				"guard is NAMING-AGNOSTIC: it catches sentinels built with fmt.Errorf or a custom "+
				"constructor, or named WITHOUT the load-bearing Err prefix, that the Err*+errors.New "+
				"completeness scan (TestExportedSentinelUniverseComplete) misses. Add {%q, %s} to "+
				"the universe table so the exact-set check covers the WHOLE cause space (and, if it "+
				"is a real sentinel, give it the Err prefix + errors.New form the convention "+
				"requires — see the package comment in doc.go).", name, name, name)
		}
	}
}

// ── The exported-sentinel CAUSE-SPACE partition (pack-scanner vs NFT-4-artifact) ───────────────
//
// exportedSentinelUniverse enumerates BOTH the POL-2 pack shape-drift sentinels the offline scanner
// (parseResolverLockBlocklist) can return AND the NFT-4 resolver-bypass-closure artifact-shape
// sentinels (nft4_closure.go). They live in ONE universe because the by-name completeness guard
// (TestExportedErrorVarsCoveredByUniverse) reconciles the table against EVERY exported error var in
// the package. But they occupy DISJOINT cause spaces: the comments next to the NFT-4 rows CLAIM they
// "never appear in a drift-corpus presentSentinels result" — a prose claim no machine pin enforced.
// These two sets lift that partition into DATA, and the self-tests below pin it fail-closed.
var (
	// packScannerSentinelNames are the POL-2 pack shape-drift sentinels the corpus walk's
	// presentSentinels scan CAN find in a fixture's reject tree (resolverlock.go).
	packScannerSentinelNames = map[string]bool{
		"ErrNoBlocklistSection": true,
		"ErrEmptyBlocklist":     true,
		"ErrUnsupportedShape":   true,
		"ErrEntryMissingFields": true,
		"ErrBadFQDN":            true,
		"ErrCountMismatch":      true,
	}
)

// The NFT-4 artifact-shape sentinels (nft4_closure.go) — the port-53/DoT/QUIC + per-control-anchoring
// cause space the OFFLINE nft analyzer returns — are NOT enumerated by hand: the partition self-test
// DERIVES that set as exportedSentinelUniverse \ packScannerSentinelNames, so a new universe row lands
// on exactly one side and cannot silently default. Those NFT-4 sentinels NEVER appear in a drift-corpus
// presentSentinels result (a different reader over a different artifact), which TestSentinelCauseSpace-
// Partition pins.

// TestSentinelCauseSpacePartition pins the cause-space partition the universe-row comments only
// CLAIMED in prose, fail-closed in BOTH directions:
//
//	(1) TOTAL + DISJOINT: every exportedSentinelUniverse row is a pack-scanner sentinel XOR an
//	    NFT-4-artifact sentinel — the pack set is exactly packScannerSentinelNames, and the NFT-4 set
//	    is the rest. A universe row in NEITHER (a new sentinel never placed) or a pack-scanner row
//	    that vanished from the universe reddens here.
//	(2) NO NFT-4 SENTINEL IN A CORPUS REJECT: for EVERY corpus fixture, presentSentinels(perr) carries
//	    ONLY pack-scanner sentinels — never an NFT-4 artifact sentinel. This is the machine pin behind
//	    the "never appear in a drift-corpus presentSentinels result" comments: the offline pack scanner
//	    and the offline nft analyzer read DIFFERENT artifacts, so a regression that leaked an NFT-4
//	    cause into the pack scanner's error tree (or mis-placed a sentinel) fails LOUDLY.
//
// Test-only/additive (D50): it reads the committed corpus and the in-package sentinel values, touches
// no corpus byte and no production crate.
func TestSentinelCauseSpacePartition(t *testing.T) {
	// (1) TOTAL + DISJOINT over the universe. An NFT-4 sentinel is precisely a universe row NOT in the
	// pack set, so the only checks needed are: every pack name is a real universe row (no stale pack
	// entry), and the pack set is non-empty (below) — totality then follows because the NFT-4 side is
	// DERIVED as the complement.
	// Every pack-scanner name must be an actual universe row (no stale partition entry).
	universeNames := make(map[string]bool, len(exportedSentinelUniverse))
	for _, s := range exportedSentinelUniverse {
		universeNames[s.name] = true
	}
	for name := range packScannerSentinelNames {
		if !universeNames[name] {
			t.Errorf("packScannerSentinelNames lists %q but it is NOT in exportedSentinelUniverse — a "+
				"stale partition row that can never match; the pack-scanner cause set must be a subset of "+
				"the universe", name)
		}
	}
	if len(packScannerSentinelNames) == 0 {
		t.Fatal("packScannerSentinelNames is empty — the pack scanner declares Err* sentinels, so an " +
			"empty pack set means the partition is broken; refusing a vacuous pass")
	}

	// Build the value→name lookup and the NFT-4 VALUE set (universe \ pack) for the corpus scan.
	nameOf := make(map[error]string, len(exportedSentinelUniverse))
	nft4SentinelValues := make(map[error]string)
	for _, s := range exportedSentinelUniverse {
		nameOf[s.err] = s.name
		if !packScannerSentinelNames[s.name] {
			nft4SentinelValues[s.err] = s.name
		}
	}
	if len(nft4SentinelValues) == 0 {
		t.Fatal("the NFT-4 cause set (universe \\ pack-scanner) is empty — nft4_closure.go exports " +
			"artifact-shape sentinels, so an empty NFT-4 set means the partition collapsed; refusing a " +
			"vacuous pass")
	}

	// (2) NO NFT-4 SENTINEL IN ANY CORPUS REJECT TREE.
	fixtures := listCorpusFixtures(t) // fatals on empty corpus — no vacuous pass.
	for _, name := range fixtures {
		want, ok := goCorpusExpectations[name]
		if !ok || want.accept {
			continue // only reject fixtures produce a presentSentinels result to inspect.
		}
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(CorpusFixturesDir(), name))
			if err != nil {
				t.Fatalf("reading corpus fixture %s: %v", name, err)
			}
			_, perr := parseResolverLockBlocklist(string(data))
			if perr == nil {
				return // coverage of the verdict itself is owned by TestDriftCorpusGoVerdicts.
			}
			for _, s := range presentSentinels(perr) {
				if nftName, isNFT4 := nft4SentinelValues[s]; isNFT4 {
					t.Fatalf("corpus fixture %s rejected with NFT-4 artifact sentinel %s in its "+
						"presentSentinels result — the POL-2 pack scanner and the NFT-4 nft analyzer read "+
						"DIFFERENT artifacts, so an NFT-4 cause must NEVER appear in a drift-corpus reject "+
						"tree (the partition the universe-row comments claim). A leaked NFT-4 cause means "+
						"the scanners' cause spaces crossed.", name, nftName)
				}
			}
		})
	}
}

// TestComputeExportedErrorVarsRunsOnce PINS the compute-once invariant the orch65 sync.Once
// hoist provides: the expensive parse + go/types full-package type-check inside
// computeExportedErrorVars (~0.25s) runs EXACTLY ONCE per test binary even though BOTH
// type-aware guards (TestExportedErrorVarsCoveredByUniverse +
// TestExportedErrorSentinelsFollowConstructionConvention) call declaredExportedErrorVars. That
// speedup was previously only OBSERVATIONAL — nothing failed if a future refactor dropped the
// sync.Once (or moved the compute out from under exportedErrorVarsOnce.Do), silently re-running
// the type-check per caller and regressing cost back to linear.
//
// The proof is a TEST-ONLY invocation counter (exportedErrorVarsComputeCount) incremented INSIDE
// the once.Do closure. Because exportedErrorVarsOnce fires the closure exactly once EVER (lazily,
// on the first declaredExportedErrorVars call), the counter is 1 regardless of which guard ran
// first — so this assertion is ROBUST TO TEST-EXECUTION ORDER. To make it self-contained (it must
// not depend on another test having run), this test CALLS declaredExportedErrorVars itself,
// guaranteeing at least one compute has happened, then asserts the counter == 1.
//
// ZERO behavior change: the counter is pure test instrumentation; it does NOT alter what the
// guards assert (the sorted exported-error-var names, the fail-loud-on-non-compile, the universe
// / construction-convention reconciliation) and touches NO production-crate file. A regression
// that re-runs the type-check per caller makes this counter exceed 1 and fails LOUDLY here.
func TestComputeExportedErrorVarsRunsOnce(t *testing.T) {
	// Drive the shared compute path so at least one invocation has happened in THIS binary —
	// makes the assertion independent of which other guard ran first (the Once may already have
	// fired, in which case this call hits the cache and does NOT bump the counter; either way the
	// counter is exactly 1). The result is exercised for its usual fail-loud behaviour.
	got := declaredExportedErrorVars(t)
	if len(got) == 0 {
		t.Fatalf("declaredExportedErrorVars returned ZERO exported error-typed vars — the "+
			"resolverlock scanner declares Err* sentinels, so an empty result means the type-aware "+
			"compute is broken; refusing to assert the compute-once invariant over a vacuous result "+
			"(package dir %s)", resolverlockPackageDir(t))
	}

	if exportedErrorVarsComputeCount != 1 {
		t.Fatalf("compute-once invariant BROKEN: the parse + go/types type-check inside the "+
			"exportedErrorVarsOnce closure ran %d times, want EXACTLY 1. The orch65 hoist computes "+
			"the ~0.25s exported-error-var scan ONCE per test binary behind exportedErrorVarsOnce and "+
			"shares the cached result across BOTH type-aware guards "+
			"(TestExportedErrorVarsCoveredByUniverse + "+
			"TestExportedErrorSentinelsFollowConstructionConvention). A count > 1 means a refactor "+
			"dropped the sync.Once (or moved the compute out from under once.Do), re-running the "+
			"type-check per caller and silently regressing cost back to linear — restore the "+
			"Once-guarded single compute.", exportedErrorVarsComputeCount)
	}

	// ORDER-INDEPENDENT, SELF-CONTAINED DROPPED-ONCE TRAP (orch77). The assertions above are
	// real but, on their own, have a test-ORDER blind spot: this test (and the sibling guards)
	// each call declaredExportedErrorVars EXACTLY ONCE, so whichever runs FIRST in source order
	// sees the counter at 1 even if the Once were dropped — a single compute leaves the counter
	// at 1 regardless of the Once. To fail LOUDLY no matter the execution order, this test now
	// drives the cached scan through MULTIPLE callers ITSELF (mirroring the two production guards
	// that both call it) and pins TWO independent fingerprints of the single-compute, EACH of
	// which a dropped Once flips:
	//
	//   (1) COUNT STABILITY across a re-drive: the counter must be 1 BEFORE the second call and
	//       STILL 1 after — drop the Once and the second call recomputes, bumping it to 2. This
	//       no longer relies on being the first caller; the re-drive is local to this test.
	//   (2) CACHE BACKING-SLICE IDENTITY: the cached result is computed once and SERVED from the
	//       same backing array to every caller. exportedErrorVarsCache.names is the shared
	//       backing slice (the wrapper hands out a defensive COPY, so we fingerprint the CACHE,
	//       not the returned slice). Drop the Once and the second compute REASSIGNS
	//       exportedErrorVarsCache.names to a fresh slice from computeExportedErrorVars, so the
	//       &names[0] address changes. Same address proves a single compute backed both calls.
	//
	// The cache is non-empty here (the len(got) > 0 guard above already proved the compute is
	// not vacuous), so &exportedErrorVarsCache.names[0] is safe to take.
	countBeforeRedrive := exportedErrorVarsComputeCount
	cacheBackingBefore := &exportedErrorVarsCache.names[0]

	// Second explicit caller: a healthy Once serves this from the cache WITHOUT recomputing, so
	// the counter and the cache backing array are unchanged; a dropped Once recomputes here.
	gotAgain := declaredExportedErrorVars(t)
	if len(gotAgain) == 0 {
		t.Fatalf("declaredExportedErrorVars returned ZERO exported error-typed vars on the SECOND "+
			"drive — the cached scan must serve a stable non-empty result to every caller; an empty "+
			"re-drive means the compute is broken (package dir %s)", resolverlockPackageDir(t))
	}
	if exportedErrorVarsComputeCount != countBeforeRedrive {
		t.Fatalf("compute-once invariant BROKEN (re-drive): a SECOND declaredExportedErrorVars call "+
			"bumped the compute counter from %d to %d — the orch65 exportedErrorVarsOnce must serve the "+
			"cached result to every caller WITHOUT recomputing. A bump means the sync.Once was dropped "+
			"(or the compute moved out from under once.Do), re-running the ~0.25s type-check per caller. "+
			"This re-drive makes the trap ORDER-INDEPENDENT: it fires no matter which guard ran first.",
			countBeforeRedrive, exportedErrorVarsComputeCount)
	}
	if exportedErrorVarsComputeCount != 1 {
		t.Fatalf("compute-once invariant BROKEN: after driving declaredExportedErrorVars through "+
			"TWO callers in THIS test the compute counter is %d, want EXACTLY 1. Exactly one compute "+
			"must back every caller — any other value means the Once-guarded single compute regressed.",
			exportedErrorVarsComputeCount)
	}
	if cacheBackingAfter := &exportedErrorVarsCache.names[0]; cacheBackingAfter != cacheBackingBefore {
		t.Fatalf("compute-once invariant BROKEN (cache identity): the exportedErrorVarsCache.names "+
			"backing array changed across two declaredExportedErrorVars calls (%p -> %p) — the cached "+
			"result must be the SAME backing slice for every caller. A changed address means the second "+
			"call recomputed and REASSIGNED the cache, i.e. the sync.Once was dropped and the cached "+
			"scan now recomputes per caller. Restore the Once-guarded single compute.",
			cacheBackingBefore, cacheBackingAfter)
	}
}

// computeOncePinnedScanOnces is the REGISTRY of every package-level sync.Once GUARD in THIS test
// file that guards a cached (expensive, deterministic-per-binary) type-aware scan AND is
// proven compute-once by a counter==1 assertion. It is the source of truth the forward-looking
// structural pin (TestCachedScanOncesAreComputeOncePinned) reconciles the AST-discovered set of
// sync.Once guard vars against, BOTH directions. The discovered set spans every form isSyncOnceType
// recognizes — the VALUE `sync.Once`, the POINTER `*sync.Once`, and the Once-EMBEDDING struct
// (orch74 widened the orch72 value-only recognition) — so a guard in ANY of those forms must be
// registered:
//
//   - every cached-scan sync.Once guard declared in this file (value, pointer, or embedding form)
//     MUST be registered here (a new one added without a compute-once counter fails LOUDLY, naming
//     the unregistered var);
//   - every name registered here MUST actually be a declared sync.Once guard var in this file (a
//     stale registry row — a guard renamed or dropped without updating the registry — fails too).
//
// Each row names the compute-once COUNTER var and the GUARD TEST that asserts it == 1, so the
// pairing the registry CLAIMS is auditable in one place. Adding a row is the deliberate act that
// records "this cached-scan Once carries a compute-once counter pin"; the structural pin makes
// that act MANDATORY for any future cached-scan Once, so the compute-once discipline cannot be
// silently skipped by a later contributor.
//
// Anchored on the orch65 exportedErrorVarsOnce — the ONE cached-scan Once the package has today
// (it guards the ~0.25s go/types SOURCE-importer exported-error-var scan; its counter
// exportedErrorVarsComputeCount is pinned ==1 by TestComputeExportedErrorVarsRunsOnce). The
// anchor is load-bearing: it means a zero-Once AST result (e.g. a parse regression that found no
// vars) cannot vacuously pass — the known Once MUST be discovered AND reconciled, or the pin
// fails.
var computeOncePinnedScanOnces = map[string]struct {
	counterVar string // the package-level compute-once counter incremented inside the Once closure
	guardTest  string // the test that asserts counterVar == 1 (the compute-once pin)
}{
	"exportedErrorVarsOnce": {
		counterVar: "exportedErrorVarsComputeCount",
		guardTest:  "TestComputeExportedErrorVarsRunsOnce",
	},
	// orch76: the type-resolved sync.Once scan's OWN cache Once. typeResolvedSyncOnceGuardVars now
	// hoists its ~0.5s whole-package go/types check behind typeResolvedSyncOnceGuardVarsOnce (the
	// same compute-once pattern these pins enforce). That cache Once IS itself a cached-scan
	// sync.Once guard, so it MUST be registered here — otherwise the very pins it powers
	// (TestCachedScanOncesAreComputeOncePinned forward, and the alias/init pin's forward + reverse
	// arms) would flag it as an unpinned cached-scan Once. Registering it keeps the discipline
	// SELF-CONSISTENT: the cache that serves the pins satisfies the pins.
	"typeResolvedSyncOnceGuardVarsOnce": {
		counterVar: "typeResolvedSyncOnceGuardVarsComputeCount",
		guardTest:  "TestComputeTypeResolvedSyncOnceGuardVarsRunsOnce",
	},
}

// thisTestFilePath returns the absolute path of THIS _test.go source, anchored via
// runtime.Caller(0) so the AST self-scan works under `go test` from any cwd — the same
// cwd-independent technique resolverlockPackageDir / CorpusFixturesDir use. The forward-looking
// structural pin parses exactly this one file (it reasons about THIS file's sync.Once vars, not
// the production surface), so it deliberately does NOT walk the package directory.
func thisTestFilePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed — cannot locate this test source to anchor the " +
			"sync.Once structural self-scan")
	}
	return thisFile
}

// isSyncOnceSelector reports whether an expression is the bare selector `sync.Once` — a
// SelectorExpr whose X is the `sync` package ident and whose Sel is `Once`. This is the CORE
// shape every cached-scan-guard form below reduces to: the value form IS this selector, the
// pointer form wraps it in a StarExpr, and the embedding form carries it as an anonymous struct
// field's type. Factored out (mirroring isErrorsNewCall's selector-detection style) so the value,
// pointer, and embedded matchers share ONE selector test rather than three copies that could
// drift apart.
func isSyncOnceSelector(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "sync" && sel.Sel.Name == "Once"
}

// isSyncOnceType reports whether a ValueSpec type expression is a cached-scan-GUARD candidate
// built on sync.Once — the structural shape the self-scan keys on. It recognizes the THREE forms
// a package-level var can use to carry a sync.Once that guards a cached type-aware scan, so none
// slips past the compute-once registry reconciliation (TestCachedScanOncesAreComputeOncePinned):
//
//   - VALUE form `var foo sync.Once`: the type is the bare SelectorExpr `sync.Once` (the orch65
//     exportedErrorVarsOnce shape, the anchor this pin is built on);
//   - POINTER form `var foo *sync.Once`: the type is an ast.StarExpr wrapping that selector — a
//     future cached scan guarded by a pointer-Once (e.g. `foo.Do(...)` on a heap Once) would
//     otherwise escape the value-only match and so escape the registry;
//   - EMBEDDING form `var foo struct{ sync.Once; ... }` (or `*sync.Once` embedded): the type is
//     an ast.StructType with an ANONYMOUS field (empty Names) whose type is the `sync.Once`
//     selector (or a StarExpr over it) — a future cached scan guarded by a Once-embedding struct
//     would likewise slip the value-only match.
//
// orch72 (the original pin) matched ONLY the value form; orch74 WIDENS the recognition to the
// pointer and embedding forms so any such guard NOT paired with a compute-once counter is flagged
// loudly, never silently re-introducing the per-caller ~0.25s cost the orch65 cache removed. The
// value-form match (and so the anchor's discovery) is UNWEAKENED — the widening is a strict
// SUPERSET. It deliberately does NOT match an ALIASED `sync` import (the import is unaliased
// everywhere in this file); the three concrete forms above are the shapes the compute-once
// discipline actually applies to.
func isSyncOnceType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		// VALUE form: the bare `sync.Once` selector (the orch72 shape, unweakened).
		return isSyncOnceSelector(t)
	case *ast.StarExpr:
		// POINTER form: `*sync.Once` — a StarExpr wrapping the selector.
		return isSyncOnceSelector(t.X)
	case *ast.StructType:
		// EMBEDDING form: a struct that EMBEDS sync.Once (an anonymous field whose type is the
		// selector or a pointer to it). A named field typed sync.Once is NOT an embed and is not a
		// package-level guard var on its own, so only anonymous (empty-Names) fields count.
		return structEmbedsSyncOnce(t)
	default:
		return false
	}
}

// structEmbedsSyncOnce reports whether a struct type EMBEDS sync.Once — i.e. carries an ANONYMOUS
// field (empty Names) whose type is the `sync.Once` selector or `*sync.Once`. An embedded Once
// promotes its Do method onto the struct, so `var g someStruct` with such an embed is a
// cached-scan-guard candidate exactly like a bare `var g sync.Once`. Named fields are skipped:
// `struct{ once sync.Once }` does not promote Do and the field is not the guard var itself.
func structEmbedsSyncOnce(st *ast.StructType) bool {
	if st.Fields == nil {
		return false
	}
	for _, field := range st.Fields.List {
		// An EMBEDDED field has no names; a named field (`once sync.Once`) is not an embed.
		if len(field.Names) != 0 {
			continue
		}
		// The embedded type is the selector (`sync.Once`) or a pointer to it (`*sync.Once`).
		switch ft := field.Type.(type) {
		case *ast.SelectorExpr:
			if isSyncOnceSelector(ft) {
				return true
			}
		case *ast.StarExpr:
			if isSyncOnceSelector(ft.X) {
				return true
			}
		}
	}
	return false
}

// syncOnceVarSpecKind classifies an *ast.ValueSpec by the sync.Once cached-scan-GUARD shape it
// carries, making the INITIALIZER ground truth EXPLICIT where declaredSyncOnceVars previously left
// it IMPLICIT. The orch72/orch74 scan matched any spec with a non-nil Type isSyncOnceType accepts
// and SILENTLY relied on the "no initializer" assumption (the spec's own docstring claimed "no
// initializer", but nothing asserted vs.Values == nil), so a future contributor's DEGENERATE
// INITIALIZED guard `var x sync.Once = sync.Once{}` — structurally a guard, with a non-nil Type AND
// a non-nil initializer — was accepted under an UNSTATED premise rather than a DETERMINISTIC rule.
// This helper makes that decision explicit so the degenerate form is RECOGNIZED-AND-FLAGGED by an
// asserted classification, never silently swept in under an implicit assumption (task
// 01KV3RDMBA740SMDGA7C3PRFDZ).
type syncOnceVarSpecKind int

const (
	// syncOnceVarNotAGuard: the spec's declared type is NOT a sync.Once cached-scan-guard shape
	// (or has no explicit type — the `var x = sync.Once{}` form, owned by the type-resolved
	// companion typeResolvedSyncOnceGuardVars, not this syntactic scan). Skipped by the scan.
	syncOnceVarNotAGuard syncOnceVarSpecKind = iota
	// syncOnceVarCanonical: the canonical NO-INITIALIZER guard `var x sync.Once` (or the pointer /
	// embedding forms isSyncOnceType accepts), vs.Values == nil. The original orch72/orch74 shape,
	// UNWEAKENED — captured exactly as before.
	syncOnceVarCanonical
	// syncOnceVarDegenerateInitialized: a typed guard carrying an explicit INITIALIZER —
	// `var x sync.Once = sync.Once{}` (non-nil Type isSyncOnceType accepts AND non-nil vs.Values).
	// No such form exists in this file today; this is the case the implicit "no initializer"
	// assumption silently swept in. It IS a genuine sync.Once guard, so the scan still CAPTURES it
	// (recognition is additive — the registry must still cover it), but now under an EXPLICIT,
	// deterministic classification rather than an unstated premise: a future degenerate form is
	// FLAGGED by this distinct kind, not silently accepted.
	syncOnceVarDegenerateInitialized
)

// classifySyncOnceVarSpec is the PURE per-spec decision declaredSyncOnceVars makes for every
// package-level var spec: given an *ast.ValueSpec it reports WHICH sync.Once-guard shape the spec
// carries, asserting the INITIALIZER ground truth (vs.Values == nil for the canonical form) the
// orch72/orch74 scan left implicit. It keys on TWO axes, both explicit:
//
//   - TYPE: vs.Type must be non-nil AND isSyncOnceType-accepted (the VALUE `sync.Once`, POINTER
//     `*sync.Once`, or EMBEDDING `struct{ sync.Once; ... }` forms — unweakened from orch74). A
//     nil-Type spec (`var x = sync.Once{}`) is NotAGuard here: it carries no syntactic type, so the
//     type-resolved companion (typeResolvedSyncOnceGuardVars) owns it, not this syntactic scan.
//   - INITIALIZER: vs.Values == nil is the CANONICAL no-initializer guard; vs.Values != nil is the
//     DEGENERATE INITIALIZED guard `var x sync.Once = sync.Once{}`. Both are real sync.Once guards
//     the registry must cover, so both are CAPTURED — but they are returned as DISTINCT kinds so the
//     initialized form is recognized DETERMINISTICALLY rather than slipping in under the implicit
//     no-initializer assumption.
//
// The self-test (TestClassifySyncOnceVarSpec) drives this helper over SYNTHETIC ValueSpec shapes —
// including the degenerate `var x sync.Once = sync.Once{}` the file does not yet contain — proving
// the initializer assertion bites, mirroring how isSyncOnceType / goExactSetMatches / malformedByClass
// each lift their inlined decision into a pinned pure helper. The two GUARD kinds (canonical and
// degenerate-initialized) both count toward declaredSyncOnceVars; isDeclaredSyncOnceGuard folds them.
func classifySyncOnceVarSpec(vs *ast.ValueSpec) syncOnceVarSpecKind {
	if vs == nil || vs.Type == nil || !isSyncOnceType(vs.Type) {
		return syncOnceVarNotAGuard
	}
	if vs.Values != nil {
		// Typed AND initialized: `var x sync.Once = sync.Once{}`. The implicit "no initializer"
		// assumption is now EXPLICIT — this degenerate form is recognized as its own kind, not
		// silently folded into the canonical match.
		return syncOnceVarDegenerateInitialized
	}
	return syncOnceVarCanonical
}

// isDeclaredSyncOnceGuard folds classifySyncOnceVarSpec down to the boolean declaredSyncOnceVars
// needs: whether the spec is a sync.Once cached-scan-guard var the registry must cover — TRUE for
// BOTH the canonical no-initializer form AND the degenerate initialized form, FALSE for a non-guard
// spec. Both guard kinds are captured (recognition is additive: the orch72/orch74 canonical match is
// UNWEAKENED, and the degenerate initialized form is now deterministically RECOGNIZED rather than
// silently accepted), so no real sync.Once guard escapes the compute-once registry reconciliation.
func isDeclaredSyncOnceGuard(vs *ast.ValueSpec) bool {
	return classifySyncOnceVarSpec(vs) != syncOnceVarNotAGuard
}

// declaredSyncOnceVars parses THIS _test.go file and returns the SORTED set of package-level
// var names whose declared type is a sync.Once cached-scan-GUARD candidate — the AST ground truth
// the structural pin reconciles against the compute-once registry. A candidate is a file-scope
// var spec whose type isSyncOnceType accepts: the VALUE form `var x sync.Once`, the POINTER form
// `var x *sync.Once`, OR the EMBEDDING form `var x struct{ sync.Once; ... }` (orch74 widened the
// orch72 value-only recognition to the pointer and embedding forms so a future cached scan guarded
// by a pointer-Once or an embedded Once cannot slip the registry). The candidate decision is made
// by classifySyncOnceVarSpec (via isDeclaredSyncOnceGuard), which makes the INITIALIZER ground truth
// EXPLICIT: the orch72/orch74 scan SILENTLY relied on the "no initializer" assumption (matching any
// non-nil Type without asserting vs.Values == nil), so a degenerate `var x sync.Once = sync.Once{}`
// — structurally a guard, but carrying an initializer — was accepted under an UNSTATED premise.
// classifySyncOnceVarSpec now asserts vs.Values == nil for the canonical form and returns the
// initialized form as a DISTINCT kind, so the degenerate form is recognized DETERMINISTICALLY (still
// captured — it is a real guard the registry must cover — but no longer silently). var blocks and
// standalone vars both surface here. Using go/parser + go/ast (stdlib, already imported) makes the
// discovery STRUCTURAL, not a brittle grep: a guard renamed, added, or removed is reflected
// automatically, and a PARSE error is a HARD failure (the pin must not vacuously pass on a file that
// does not parse).
func declaredSyncOnceVars(t *testing.T) []string {
	t.Helper()
	src := thisTestFilePath(t)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s for the sync.Once structural self-scan: %v (a parse error is a HARD "+
			"failure — the compute-once structural pin must not vacuously pass on a file that does "+
			"not parse)", src, err)
	}
	var out []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// classifySyncOnceVarSpec makes the initializer ground truth EXPLICIT: it captures
			// BOTH the canonical no-initializer guard and the degenerate `var x sync.Once =
			// sync.Once{}` initialized guard (as distinct kinds), so neither slips the registry and
			// the initialized form is recognized deterministically rather than silently accepted.
			if !isDeclaredSyncOnceGuard(vs) {
				continue
			}
			// A `var a, b sync.Once` block would declare BOTH names with the one type; range the
			// names so every package-level sync.Once is captured, not just the first.
			for _, id := range vs.Names {
				out = append(out, id.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestClassifySyncOnceVarSpec pins the INITIALIZER ground truth classifySyncOnceVarSpec now makes
// EXPLICIT, proving the degenerate `var x sync.Once = sync.Once{}` form is recognized
// DETERMINISTICALLY rather than silently swept into the canonical match under the orch72/orch74
// implicit "no initializer" assumption. It parses SYNTHETIC one-var source snippets (D50 — no
// corpus fixture, no production crate, and NOT this file's own real vars are touched; the snippets
// are parsed in-memory) covering every axis the classifier decides on:
//
//   - canonical no-initializer guard `var x sync.Once` -> syncOnceVarCanonical (the orch72 shape,
//     UNWEAKENED — still captured);
//   - pointer / embedding no-initializer guards -> syncOnceVarCanonical (the orch74 widening,
//     UNWEAKENED);
//   - the DEGENERATE INITIALIZED guard `var x sync.Once = sync.Once{}` -> syncOnceVarDegenerateInitialized:
//     the case the implicit assumption silently accepted, now FLAGGED as its own deterministic kind
//     (and still folded INTO declaredSyncOnceVars by isDeclaredSyncOnceGuard — it is a real guard);
//   - a typed-and-initialized POINTER guard `var x *sync.Once = &sync.Once{}` -> degenerate-initialized too;
//   - a non-Once typed var and a non-Once initialized var -> syncOnceVarNotAGuard;
//   - the nil-Type initialized form `var x = sync.Once{}` -> syncOnceVarNotAGuard HERE (it carries no
//     syntactic type, so the type-resolved companion owns it, not this syntactic scan).
//
// An edit that dropped the vs.Values check (collapsing the degenerate-initialized kind back into the
// canonical match, re-burying the assumption) or weakened the type match would flip a case RED here.
func TestClassifySyncOnceVarSpec(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		want      syncOnceVarSpecKind
		wantGuard bool
		comment   string
	}{
		{
			name:      "canonical no-initializer value guard",
			src:       "package p\nimport \"sync\"\nvar x sync.Once",
			want:      syncOnceVarCanonical,
			wantGuard: true,
			comment:   "`var x sync.Once` is the orch72 canonical form, vs.Values == nil — captured, UNWEAKENED",
		},
		{
			name:      "canonical no-initializer pointer guard",
			src:       "package p\nimport \"sync\"\nvar x *sync.Once",
			want:      syncOnceVarCanonical,
			wantGuard: true,
			comment:   "`var x *sync.Once` is the orch74 pointer widening, no initializer — captured, UNWEAKENED",
		},
		{
			name:      "canonical no-initializer embedding guard",
			src:       "package p\nimport \"sync\"\nvar x struct{ sync.Once }",
			want:      syncOnceVarCanonical,
			wantGuard: true,
			comment:   "`var x struct{ sync.Once }` is the orch74 embedding widening, no initializer — captured, UNWEAKENED",
		},
		{
			name:      "DEGENERATE typed-and-initialized value guard -> flagged as its own kind, still captured",
			src:       "package p\nimport \"sync\"\nvar x sync.Once = sync.Once{}",
			want:      syncOnceVarDegenerateInitialized,
			wantGuard: true,
			comment:   "the case the implicit `no initializer` assumption SILENTLY accepted: non-nil Type isSyncOnceType-accepted AND non-nil vs.Values — now recognized DETERMINISTICALLY as the degenerate-initialized kind (and folded into declaredSyncOnceVars: a real guard the registry must cover)",
		},
		{
			name:      "DEGENERATE typed-and-initialized pointer guard -> flagged, still captured",
			src:       "package p\nimport \"sync\"\nvar x *sync.Once = &sync.Once{}",
			want:      syncOnceVarDegenerateInitialized,
			wantGuard: true,
			comment:   "the pointer degenerate form: `var x *sync.Once = &sync.Once{}` carries a non-nil Type AND an initializer — same deterministic flag",
		},
		{
			name:      "nil-Type initialized form -> NotAGuard here (type-resolved companion owns it)",
			src:       "package p\nimport \"sync\"\nvar x = sync.Once{}",
			want:      syncOnceVarNotAGuard,
			wantGuard: false,
			comment:   "`var x = sync.Once{}` has NO syntactic type (vs.Type == nil), so the syntactic scan skips it; typeResolvedSyncOnceGuardVars catches it by resolved type",
		},
		{
			name:      "non-Once typed var -> NotAGuard",
			src:       "package p\nvar x int",
			want:      syncOnceVarNotAGuard,
			wantGuard: false,
			comment:   "a non-sync.Once type is not a cached-scan guard candidate",
		},
		{
			name:      "non-Once typed-and-initialized var -> NotAGuard",
			src:       "package p\nvar x int = 7",
			want:      syncOnceVarNotAGuard,
			wantGuard: false,
			comment:   "a non-Once type stays NotAGuard even with an initializer — the initializer axis only refines a TYPE that already matches",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vs := firstValueSpec(t, tc.src)
			got := classifySyncOnceVarSpec(vs)
			if got != tc.want {
				t.Fatalf("classifySyncOnceVarSpec(%q) = %d, want %d — %s. The initializer ground "+
					"truth must be EXPLICIT: the canonical no-initializer guard is syncOnceVarCanonical "+
					"(vs.Values == nil) and the degenerate `var x sync.Once = sync.Once{}` is "+
					"syncOnceVarDegenerateInitialized — collapsing the two would re-bury the implicit "+
					"assumption the orch72/orch74 scan silently relied on.", tc.src, got, tc.want, tc.comment)
			}
			if gotGuard := isDeclaredSyncOnceGuard(vs); gotGuard != tc.wantGuard {
				t.Fatalf("isDeclaredSyncOnceGuard(%q) = %v, want %v — %s. BOTH guard kinds (canonical "+
					"and degenerate-initialized) must fold to true so no real sync.Once guard escapes "+
					"the compute-once registry; only a non-guard spec folds to false.", tc.src, gotGuard,
					tc.wantGuard, tc.comment)
			}
		})
	}
}

// firstValueSpec parses a synthetic one-var source snippet and returns its FIRST package-level
// *ast.ValueSpec, the input classifySyncOnceVarSpec decides on. Test-only (D50): it parses the
// in-memory snippet string, never this file or any corpus byte. A snippet that does not parse or
// carries no var spec is a HARD test-author error (t.Fatalf), so a malformed case can never
// vacuously pass.
func firstValueSpec(t *testing.T, src string) *ast.ValueSpec {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parsing synthetic snippet %q: %v (a test-author error — the snippet must parse so "+
			"classifySyncOnceVarSpec is exercised over a real ValueSpec)", src, err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok {
				return vs
			}
		}
	}
	t.Fatalf("synthetic snippet %q declared no package-level var spec — cannot exercise "+
		"classifySyncOnceVarSpec", src)
	return nil
}

// TestCachedScanOncesAreComputeOncePinned is the FORWARD-LOOKING structural pin that makes the
// compute-once discipline SELF-ENFORCING for this file. The orch68 counter==1 guard
// (TestComputeExportedErrorVarsRunsOnce) pins the EXISTING exportedErrorVarsOnce, but nothing
// stopped a FUTURE contributor from adding a SECOND cached type-aware scan behind its own
// sync.Once WITHOUT a compute-once counter — silently re-introducing the per-caller ~0.25s cost
// the orch65 cache removed, with no test going red. This pin closes that gap: it AST-parses THIS
// _test.go, enumerates every package-level sync.Once guard it declares — in ANY recognized form:
// the VALUE `sync.Once`, the POINTER `*sync.Once`, or a Once-EMBEDDING struct (orch74 widened the
// orch72 value-only recognition so a pointer-Once or embedded-Once guard cannot slip past) — and
// asserts each is REGISTERED in computeOncePinnedScanOnces (whose rows name the compute-once
// counter + the guard test that asserts it == 1). A cached-scan Once guard added later without
// registering its compute-once pin fails HERE, LOUDLY, naming the offending var — so the author
// MUST either add the counter==1 pin and register it, or justify it.
//
// FAIL-CLOSED, both directions:
//   - FORWARD: every declared sync.Once guard (value, pointer, or embedding form) must be in the
//     registry (catches an UNPINNED new Once);
//   - REVERSE: every registry row must be a declared sync.Once guard (catches a STALE row after a
//     Once is renamed/removed — so the registry cannot rot into a false claim of coverage);
//   - ANCHOR: the known exportedErrorVarsOnce MUST be discovered by the AST scan AND present in
//     the registry — a zero-Once result (a parse/structure regression) therefore cannot mask the
//     existing Once with a vacuous pass.
//
// This is purely test-only, in-process, offline (D50): it reads this one source file via
// runtime.Caller-anchored go/parser, touches NO production-crate file, and does NOT weaken the
// orch68 counter==1 guard or any other guard — it ADDS a self-enforcing structural layer on top.
func TestCachedScanOncesAreComputeOncePinned(t *testing.T) {
	declared := declaredSyncOnceVars(t)

	// ANCHOR (no-vacuous-pass): the AST scan MUST find the known orch65 Once. A zero-Once result
	// — e.g. a refactor that hid the declaration from the structural scan — would otherwise let
	// the forward reconciliation pass over an empty set while the existing cached-scan Once went
	// unpinned. Pin the anchor explicitly so the structural guard cannot silently go blind.
	const anchorOnce = "exportedErrorVarsOnce"
	foundAnchor := false
	for _, name := range declared {
		if name == anchorOnce {
			foundAnchor = true
			break
		}
	}
	if !foundAnchor {
		t.Fatalf("the AST self-scan of %s found these package-level sync.Once vars %v but NOT the "+
			"known cached-scan Once %q — the compute-once structural pin anchors on it, so a result "+
			"missing it means the structural scan went blind (a refactor hid the declaration). A "+
			"vacuous pass over a Once-less view would let an UNPINNED cached-scan Once slip through; "+
			"restore the scan or update the anchor in lockstep.", thisTestFilePath(t), declared,
			anchorOnce)
	}
	if _, ok := computeOncePinnedScanOnces[anchorOnce]; !ok {
		t.Fatalf("the anchor cached-scan Once %q is missing from computeOncePinnedScanOnces — the "+
			"registry must record its compute-once counter pin (counter exportedErrorVarsComputeCount, "+
			"guard TestComputeExportedErrorVarsRunsOnce). Re-add the row; the structural pin depends on "+
			"the anchor being registered.", anchorOnce)
	}

	// FORWARD: every package-level sync.Once declared in this file must carry a compute-once pin
	// (be registered). A new cached-scan Once added WITHOUT a counter==1 assertion is caught here,
	// named, with the remedy spelled out.
	for _, name := range declared {
		if _, ok := computeOncePinnedScanOnces[name]; !ok {
			t.Errorf("package-level sync.Once %q is declared in %s but is NOT registered in "+
				"computeOncePinnedScanOnces — every sync.Once that guards a cached type-aware scan "+
				"must be paired with a COMPUTE-ONCE COUNTER asserted == 1 (the way "+
				"exportedErrorVarsOnce carries exportedErrorVarsComputeCount, pinned by "+
				"TestComputeExportedErrorVarsRunsOnce). An unpinned cached-scan Once silently re-"+
				"introduces the per-caller cost the cache removes, with no test going red. Add a "+
				"package-level counter incremented INSIDE %s.Do(...), a Test asserting it == 1, and a "+
				"row {%q: {counterVar, guardTest}} to computeOncePinnedScanOnces. If this Once does "+
				"NOT guard a cached scan, that exception still belongs in the registry with a counter/"+
				"guard that documents why (the pin is fail-closed by design — silence is not an "+
				"option).", name, thisTestFilePath(t), name, name)
		}
	}

	// REVERSE: every registered Once must still be a declared sync.Once in this file, so the
	// registry cannot rot into a stale claim of coverage after a rename/removal.
	declaredSet := make(map[string]bool, len(declared))
	for _, name := range declared {
		declaredSet[name] = true
	}
	for name := range computeOncePinnedScanOnces {
		if !declaredSet[name] {
			t.Errorf("computeOncePinnedScanOnces registers %q but the AST self-scan of %s found NO "+
				"package-level sync.Once by that name (declared Onces: %v) — the registry row is STALE "+
				"(the Once was renamed or removed). Update the registry so it cannot falsely claim "+
				"compute-once coverage for a Once that no longer exists.", name, thisTestFilePath(t),
				declared)
		}
	}

	// SELF-CONSISTENCY: each registry row must name a non-empty counter var and guard test, so a
	// row cannot claim coverage while pointing at nothing. (The named counter/guard are documented
	// anchors the message above tells a future author to add; an empty one is a meaningless row.)
	for name, pin := range computeOncePinnedScanOnces {
		if pin.counterVar == "" || pin.guardTest == "" {
			t.Errorf("computeOncePinnedScanOnces row %q is incomplete — counterVar=%q guardTest=%q; "+
				"a compute-once pin must name BOTH the counter var incremented inside the Once closure "+
				"and the test that asserts it == 1, or the registry records an empty (unverifiable) "+
				"claim of coverage.", name, pin.counterVar, pin.guardTest)
		}
	}
}

// typeResolvesToSyncOnce reports whether a go/types type — after stripping ONE level of pointer
// and resolving through ANY chain of local type ALIASES — is the named stdlib type `sync.Once`.
// It is the TYPE-RESOLVED analog of the syntactic isSyncOnceType: where the AST matcher keys on
// the SOURCE SHAPE (`sync.Once`, `*sync.Once`, an embedding struct), this keys on the type the
// checker actually resolved the declared type to, so it sees THROUGH a local alias the syntactic
// scan is blind to.
//
//   - ALIAS form `type onceT = sync.Once; var g onceT`: the declared type AST is a bare Ident
//     (`onceT`), so isSyncOnceType (which only matches a SelectorExpr/StarExpr/StructType) rejects
//     it and the var escapes the syntactic registry — silently re-introducing the per-caller cost
//     the orch65 cache removed. types.Unalias collapses `onceT` to the underlying `sync.Once`
//     *types.Named, so this matcher catches it. (Go 1.23+ materialises aliases as *types.Alias by
//     default; Unalias handles a chain of them.)
//   - POINTER-of-alias `var g *onceT` / POINTER `var g *sync.Once`: one *types.Pointer is peeled
//     before the alias resolution, so a heap-Once reached through an alias is caught too.
//
// A DISTINCT named type — `type onceN sync.Once` (a definition, NOT an alias) — is deliberately
// NOT matched: it is a different type whose method set does NOT promote Once.Do, so it cannot
// serve as a drop-in cached-scan guard. Unalias leaves such a *types.Named as itself (obj.Name()
// == "onceN", pkg the local package), so it correctly returns false. The embedding form stays
// owned by the syntactic structEmbedsSyncOnce (its var type resolves to an anonymous struct, not
// sync.Once); this matcher's job is the alias + initialized hole, a strict ADDITION on top.
func typeResolvesToSyncOnce(t types.Type) bool {
	// Peel a single pointer so `*sync.Once` and `*onceAlias` resolve like their value forms.
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	// Collapse any chain of local aliases to the underlying named target. This is the whole
	// point: a same-file `type onceT = sync.Once` is INVISIBLE to the syntactic matcher but
	// Unalias resolves it to the stdlib sync.Once *types.Named here.
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == "sync" && obj.Name() == "Once"
}

// typeResolvedSyncOnceGuardVars TYPE-CHECKS this package (all its .go files, incl. _test.go, via
// the offline SOURCE importer — the same machinery computeExportedErrorVars uses, stdlib only) and
// returns the SORTED set of package-level var names whose RESOLVED type is sync.Once — reaching
// THROUGH a local type alias AND including INITIALIZED declarations (`var g = sync.Once{}`,
// `var g onceAlias = onceAlias{}`). It is the type-resolved companion of the AST-syntactic
// declaredSyncOnceVars, and it closes two escape hatches that scan leaves open:
//
//   - TYPE-ALIAS guard `type onceT = sync.Once; var g onceT`: the declared type is a plain Ident,
//     so declaredSyncOnceVars (syntactic) never sees it; the type checker resolves g's type to
//     sync.Once and typeResolvesToSyncOnce matches it here.
//   - DEGENERATE INITIALIZED guard `var g = sync.Once{}` (or the alias form): declaredSyncOnceVars
//     skips it because the ValueSpec has no explicit Type (the `vs.Type == nil` initialized form),
//     so an initialized Once guarding a cached scan slips the syntactic registry; the checker
//     assigns g a concrete type regardless of how it was initialized, so it surfaces here.
//
// The two scans are COMPLEMENTARY, both unweakened: declaredSyncOnceVars keeps the orch72/orch74
// syntactic value/pointer/embedding match; this widens recognition by RESOLVED TYPE. The result
// is reconciled against the SAME computeOncePinnedScanOnces registry by
// TestCachedScanOnceAliasAndInitGuardsAreComputeOncePinned, so an alias/initialized cached-scan
// Once added later without a compute-once counter fails LOUDLY. A read/parse/type-check failure is
// a HARD error (t.Fatalf) so the pin never vacuously passes over a package that does not compile.
//
// Test-only, in-process, offline (D50): it reads the package's own sources via a
// runtime.Caller-anchored directory walk and type-checks with the SOURCE importer — no network, no
// prebuilt export data, no production-crate file touched.
//
// COMPUTE-ONCE CACHE (orch76): the parse + whole-package go/types SOURCE-importer check this scan
// performs is ~0.5s and DETERMINISTIC per test binary (it reads the SAME package sources no matter
// which test asks). Two pins now reconcile against the result — the FORWARD arm AND the new REVERSE
// arm of TestCachedScanOnceAliasAndInitGuardsAreComputeOncePinned — and more type-resolved pins are
// expected, so without a cache the ~0.5s type-check would run once PER caller, growing the (a)-tier
// budget linearly. This wrapper computes it ONCE behind typeResolvedSyncOnceGuardVarsOnce (the SAME
// compute-once pattern these pins ENFORCE — and which the registry now records, so the cache's own
// Once satisfies the pin it powers) and returns the cached, defensively-copied result. It fails
// LOUD under the cache: computeTypeResolvedSyncOnceGuardVars is t-FREE and captures any failure as a
// STRING re-raised via t.Fatalf on EVERY call, so a non-compiling package fatals whichever test
// asked — no later caller silently skips.
func typeResolvedSyncOnceGuardVars(t *testing.T) []string {
	t.Helper()
	typeResolvedSyncOnceGuardVarsOnce.Do(func() {
		// COMPUTE-ONCE COUNTER (test-only instrumentation, ZERO behavior change): bump a
		// package-level counter INSIDE the Once closure so the expensive parse + whole-package
		// go/types check that ran here can be ASSERTED to have run exactly once across every
		// type-resolved pin (the FORWARD + REVERSE arms today, more later). The closure runs exactly
		// once per test binary (serialized by typeResolvedSyncOnceGuardVarsOnce), so the increment is
		// race-free and pins the compute-once invariant — TestComputeTypeResolvedSyncOnceGuardVarsRunsOnce
		// asserts the counter == 1, so a future refactor that DROPPED the sync.Once (re-running the
		// ~0.5s type-check per caller) is caught LOUDLY instead of silently regressing the (a)-tier cost.
		typeResolvedSyncOnceGuardVarsComputeCount++
		typeResolvedSyncOnceGuardVarsCache.names, typeResolvedSyncOnceGuardVarsCache.errString =
			computeTypeResolvedSyncOnceGuardVars()
	})
	if s := typeResolvedSyncOnceGuardVarsCache.errString; s != "" {
		// Re-raise on the CURRENT t, every call — the captured failure fails THIS test.
		t.Fatalf("%s", s)
	}
	// Defensive copy so a caller that mutates (sorts/appends to) the returned slice cannot corrupt
	// the shared cache for the next caller. The result is already sorted.
	out := make([]string, len(typeResolvedSyncOnceGuardVarsCache.names))
	copy(out, typeResolvedSyncOnceGuardVarsCache.names)
	return out
}

// typeResolvedSyncOnceGuardVarsResult is the cached, t-FREE result of the whole-package type-resolved
// sync.Once scan: the SORTED names on success, or a non-empty errString capturing the FIRST failure
// (the wrapper re-raises it via t.Fatalf on every call). Exactly one of the two is meaningful — a
// non-empty errString means names is nil/unused.
type typeResolvedSyncOnceGuardVarsResult struct {
	names     []string
	errString string
}

var (
	// typeResolvedSyncOnceGuardVarsOnce guards the single per-test-binary computation of the parsed +
	// whole-package type-checked sync.Once-resolved var set (the orch76 hoist). It is ITSELF a
	// cached-scan sync.Once guarding an expensive type-aware scan, so it is REGISTERED in
	// computeOncePinnedScanOnces (counter typeResolvedSyncOnceGuardVarsComputeCount, guard
	// TestComputeTypeResolvedSyncOnceGuardVarsRunsOnce) — keeping the pin it powers self-consistent:
	// the compute-once cache the type-resolved pins demand of every other guard applies to this one too.
	typeResolvedSyncOnceGuardVarsOnce sync.Once
	// typeResolvedSyncOnceGuardVarsCache holds the result of that single computation; read by every
	// typeResolvedSyncOnceGuardVars call after the Once fires.
	typeResolvedSyncOnceGuardVarsCache typeResolvedSyncOnceGuardVarsResult
	// typeResolvedSyncOnceGuardVarsComputeCount is TEST-ONLY instrumentation: incremented INSIDE the
	// typeResolvedSyncOnceGuardVarsOnce closure, it counts how many times the expensive parse +
	// whole-package go/types compute actually ran. The Once fires the closure exactly once per test
	// binary regardless of how many pins call typeResolvedSyncOnceGuardVars, so this counter is 1 after
	// the first call ever — TestComputeTypeResolvedSyncOnceGuardVarsRunsOnce asserts == 1 to PIN the
	// compute-once invariant the hoist provides (no production effect; the pins' results are unchanged).
	typeResolvedSyncOnceGuardVarsComputeCount int
)

// computeTypeResolvedSyncOnceGuardVars runs the parse + whole-package go/types SOURCE-importer check
// ONCE (under typeResolvedSyncOnceGuardVarsOnce) and returns the SORTED set of package-level var
// names whose RESOLVED type is sync.Once — identical to the pre-hoist typeResolvedSyncOnceGuardVars
// body, but t-FREE: every failure path returns a non-empty error STRING (captured into the cache and
// re-raised via t.Fatalf by the wrapper on every call) instead of touching a *testing.T. On success
// the returned string is empty. Same package surface (ALL .go files, incl. _test.go — the
// cached-scan Onces live in the test files) and same resolved-type match (typeResolvesToSyncOnce,
// through a local alias and/or one pointer level, regardless of initializer). A read/parse/type-check
// failure yields a non-empty errString so the scan never vacuously passes on a package that does not
// compile.
func computeTypeResolvedSyncOnceGuardVars() (names []string, errString string) {
	dir, derr := resolverlockPackageDirErr()
	if derr != nil {
		return nil, derr.Error()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Sprintf("reading the package dir %s for the type-resolved sync.Once alias/init "+
			"scan: %v (a read failure is a HARD failure — the pin must not vacuously pass)", dir, err)
	}
	var srcs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// ALL .go files (incl. _test.go): the cached-scan Onces live in the test files, so unlike
		// computeExportedErrorVars (which scans only the production surface) this scan must include
		// _test.go to type-check the Once declarations themselves.
		if !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		srcs = append(srcs, filepath.Join(dir, e.Name()))
	}
	if len(srcs) == 0 {
		return nil, fmt.Sprintf("found ZERO .go files in the package dir %s — the type-resolved "+
			"sync.Once scan has nothing to type-check; the package layout is broken", dir)
	}
	sort.Strings(srcs)

	fset := token.NewFileSet()
	var files []*ast.File
	for _, src := range srcs {
		f, perr := parser.ParseFile(fset, src, nil, 0)
		if perr != nil {
			return nil, fmt.Sprintf("parsing %s for the type-resolved sync.Once alias/init scan: %v (a "+
				"parse error is a HARD failure — the pin must not vacuously pass on a file that does not "+
				"parse)", src, perr)
		}
		files = append(files, f)
	}
	var firstTypeErr error
	conf := types.Config{
		// SOURCE importer: type-check the package's imports (sync/testing/go-types/…) from their
		// source, so this runs offline with no prebuilt export data — stdlib only (D50).
		Importer: importer.ForCompiler(fset, "source", nil),
		Error: func(err error) {
			if firstTypeErr == nil {
				firstTypeErr = err
			}
		},
	}
	pkg, err := conf.Check("resolverlock", fset, files, nil)
	if err != nil {
		return nil, fmt.Sprintf("type-checking the resolverlock package for the type-resolved sync.Once "+
			"alias/init scan failed: %v (the alias/init pin cannot enumerate the sync.Once-typed vars of "+
			"a package that does not type-check — refusing to vacuously pass)", err)
	}
	if firstTypeErr != nil {
		return nil, fmt.Sprintf("type-checking the resolverlock package for the type-resolved sync.Once "+
			"alias/init scan: %v", firstTypeErr)
	}

	scope := pkg.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok {
			continue
		}
		// RESOLVED-TYPE driven, not source-shape driven: a var whose type resolves to sync.Once
		// (through a local alias and/or one pointer level), no matter how it was declared or
		// initialized, is a cached-scan-guard candidate the compute-once registry must cover.
		if typeResolvesToSyncOnce(v.Type()) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, ""
}

// TestComputeTypeResolvedSyncOnceGuardVarsRunsOnce PINS the compute-once invariant the orch76 cache
// (typeResolvedSyncOnceGuardVarsOnce) provides: the ~0.5s parse + whole-package go/types check inside
// computeTypeResolvedSyncOnceGuardVars runs EXACTLY ONCE per test binary even though MULTIPLE pins
// (the FORWARD + REVERSE arms of TestCachedScanOnceAliasAndInitGuardsAreComputeOncePinned today, more
// type-resolved pins later) call typeResolvedSyncOnceGuardVars. Before the cache the type-resolved
// scan re-ran per caller, so the (a)-tier cost grew linearly as type-resolved pins landed; a future
// refactor that dropped the sync.Once (or moved the compute out from under
// typeResolvedSyncOnceGuardVarsOnce.Do) would silently re-introduce that per-caller cost with no test
// going red.
//
// The proof is the TEST-ONLY invocation counter typeResolvedSyncOnceGuardVarsComputeCount incremented
// INSIDE the once.Do closure. Because the Once fires the closure exactly once EVER (lazily, on the
// first typeResolvedSyncOnceGuardVars call), the counter is 1 regardless of which pin ran first. This
// test calls the wrapper once to GUARANTEE at least one compute has happened (mirroring
// TestComputeExportedErrorVarsRunsOnce), exercises the result for its usual fail-loud behaviour, then
// asserts the counter == 1. ZERO behavior change: the counter is pure test instrumentation; it does
// NOT alter what the scan returns. A refactor that re-runs the type-check per caller makes this
// counter exceed 1 and fails LOUDLY here.
func TestComputeTypeResolvedSyncOnceGuardVarsRunsOnce(t *testing.T) {
	// Force the Once to have fired at least once (it may already have, if another type-resolved pin
	// ran first — in which case this call hits the cache and does NOT bump the counter; either way the
	// counter is exactly 1). The result is exercised for its usual fail-loud (no-vacuous) behaviour.
	resolved := typeResolvedSyncOnceGuardVars(t)
	if len(resolved) == 0 {
		t.Fatalf("the type-resolved sync.Once scan returned ZERO vars — the package declares at least " +
			"the anchor exportedErrorVarsOnce (and now typeResolvedSyncOnceGuardVarsOnce), so the compute " +
			"is broken; refusing to assert the compute-once invariant over a vacuous result that could " +
			"mask a dropped sync.Once")
	}
	if typeResolvedSyncOnceGuardVarsComputeCount != 1 {
		t.Fatalf("compute-once invariant BROKEN: the parse + whole-package go/types type-check inside "+
			"the typeResolvedSyncOnceGuardVarsOnce closure ran %d times, want EXACTLY 1. The orch76 cache "+
			"computes the ~0.5s type-resolved sync.Once scan ONCE per test binary behind "+
			"typeResolvedSyncOnceGuardVarsOnce and serves every type-resolved pin from the cache; a count "+
			">1 means a refactor dropped the sync.Once (or moved the compute out from under once.Do), "+
			"re-running the expensive scan per caller. Restore the Once-guarded single compute.",
			typeResolvedSyncOnceGuardVarsComputeCount)
	}

	// ORDER-INDEPENDENT, SELF-CONTAINED DROPPED-ONCE TRAP (orch77). The assertion above shares the
	// test-ORDER blind spot the orch65 counter pin had: this test (and every type-resolved pin)
	// calls typeResolvedSyncOnceGuardVars EXACTLY ONCE, so the FIRST caller in source order reads
	// the counter at 1 even with the Once dropped — one compute leaves the counter at 1 regardless.
	// To fail LOUDLY no matter the execution order, this test drives the cached scan through
	// MULTIPLE callers ITSELF (mirroring the FORWARD + REVERSE type-resolved pins, which both call
	// it) and pins TWO independent fingerprints of the single-compute, EACH of which a dropped Once
	// flips:
	//
	//   (1) COUNT STABILITY across a re-drive: the counter must be 1 BEFORE the second call and
	//       STILL 1 after — drop the Once and the second call recomputes, bumping it to 2.
	//   (2) CACHE BACKING-SLICE IDENTITY: typeResolvedSyncOnceGuardVarsCache.names is the shared
	//       backing slice served to every caller (the wrapper returns a defensive COPY, so we
	//       fingerprint the CACHE, not the returned slice). Drop the Once and the second compute
	//       REASSIGNS typeResolvedSyncOnceGuardVarsCache.names to a fresh slice from
	//       computeTypeResolvedSyncOnceGuardVars, so the &names[0] address changes. Same address
	//       proves a single compute backed both calls.
	//
	// The cache is non-empty here (the len(resolved) > 0 guard above already proved the compute is
	// not vacuous), so &typeResolvedSyncOnceGuardVarsCache.names[0] is safe to take.
	countBeforeRedrive := typeResolvedSyncOnceGuardVarsComputeCount
	cacheBackingBefore := &typeResolvedSyncOnceGuardVarsCache.names[0]

	// Second explicit caller: a healthy Once serves this from the cache WITHOUT recomputing, so the
	// counter and the cache backing array are unchanged; a dropped Once recomputes here.
	resolvedAgain := typeResolvedSyncOnceGuardVars(t)
	if len(resolvedAgain) == 0 {
		t.Fatalf("the type-resolved sync.Once scan returned ZERO vars on the SECOND drive — the " +
			"cached scan must serve a stable non-empty result to every caller; an empty re-drive means " +
			"the compute is broken and could mask a dropped sync.Once")
	}
	if typeResolvedSyncOnceGuardVarsComputeCount != countBeforeRedrive {
		t.Fatalf("compute-once invariant BROKEN (re-drive): a SECOND typeResolvedSyncOnceGuardVars "+
			"call bumped the compute counter from %d to %d — the orch76 typeResolvedSyncOnceGuardVarsOnce "+
			"must serve the cached result to every caller WITHOUT recomputing. A bump means the sync.Once "+
			"was dropped (or the compute moved out from under once.Do), re-running the ~0.5s whole-package "+
			"type-check per caller. This re-drive makes the trap ORDER-INDEPENDENT: it fires no matter "+
			"which pin ran first.", countBeforeRedrive, typeResolvedSyncOnceGuardVarsComputeCount)
	}
	if typeResolvedSyncOnceGuardVarsComputeCount != 1 {
		t.Fatalf("compute-once invariant BROKEN: after driving typeResolvedSyncOnceGuardVars through "+
			"TWO callers in THIS test the compute counter is %d, want EXACTLY 1. Exactly one compute "+
			"must back every caller — any other value means the Once-guarded single compute regressed.",
			typeResolvedSyncOnceGuardVarsComputeCount)
	}
	if cacheBackingAfter := &typeResolvedSyncOnceGuardVarsCache.names[0]; cacheBackingAfter != cacheBackingBefore {
		t.Fatalf("compute-once invariant BROKEN (cache identity): the "+
			"typeResolvedSyncOnceGuardVarsCache.names backing array changed across two "+
			"typeResolvedSyncOnceGuardVars calls (%p -> %p) — the cached result must be the SAME backing "+
			"slice for every caller. A changed address means the second call recomputed and REASSIGNED "+
			"the cache, i.e. the sync.Once was dropped and the type-resolved scan now recomputes per "+
			"caller. Restore the Once-guarded single compute.", cacheBackingBefore, cacheBackingAfter)
	}
}

// TestCachedScanOnceAliasAndInitGuardsAreComputeOncePinned is the TYPE-RESOLVED extension of the
// orch72/orch74 structural pin (TestCachedScanOncesAreComputeOncePinned). That pin is SYNTACTIC:
// declaredSyncOnceVars matches the source SHAPE of a no-initializer var (`sync.Once`, `*sync.Once`,
// an embedding struct), so two cached-scan-guard forms still escape it and so escape the
// compute-once registry — silently re-introducing the per-caller ~0.25s cost the orch65 cache
// removed, with no test going red:
//
//   - a LOCAL TYPE-ALIAS guard `type onceT = sync.Once; var g onceT` — the declared type is a bare
//     Ident the syntactic matcher rejects (it parallels the documented aliased-import exclusion,
//     but for the TYPE not the import);
//   - a DEGENERATE INITIALIZED guard `var g = sync.Once{}` / `var g onceT = onceT{}` — the
//     no-initializer-only syntactic scan skips any var with an initializer, so an initialized Once
//     guarding a cached scan slips through.
//
// This pin closes BOTH holes by TYPE: it type-checks the package with the offline SOURCE importer
// and enumerates every package-level var whose RESOLVED type is sync.Once (through a local alias,
// one pointer level, and regardless of initializer), then asserts each is REGISTERED in
// computeOncePinnedScanOnces — the SAME registry, SAME rows (counter var + guard test asserting it
// == 1) the syntactic pin reconciles against. An alias/initialized cached-scan Once added later
// without its compute-once counter fails HERE, LOUDLY, naming the offending var.
//
// FAIL-CLOSED, both directions:
//   - FORWARD: every type-resolved sync.Once guard var must be in the registry (catches the
//     UNPINNED alias/initialized Once — the new bite);
//   - REVERSE (orch76): every registry row must resolve to a REAL type-resolved sync.Once var still
//     present in the package (catches an ORPHANED counter — a registry row whose Once was renamed or
//     removed, leaving a vacuous/stale compute-once claim). The syntactic
//     TestCachedScanOncesAreComputeOncePinned already checks reverse against the SYNTACTIC scan, but a
//     row backed only by an ALIAS/INITIALIZED-form Once is invisible to that syntactic set, so a
//     stale alias/init row could rot unseen. This reverse arm closes the loop over the TYPE-RESOLVED
//     set — the broader, authoritative one — the way reconcileCorpusCoverage's staleExpectation does
//     for fixtures;
//   - ANCHOR: the known exportedErrorVarsOnce MUST be discovered by the type-resolved scan AND be
//     registered — a zero-var result (a parse/type-check regression) therefore cannot mask the
//     existing Once with a vacuous pass.
//
// This test BROADENS recognition forward to the alias/initialized forms AND now closes the reverse
// loop over the type-resolved set. It does NOT touch declaredSyncOnceVars, isSyncOnceType, the orch68
// counter==1 guard, the syntactic pin's own reverse arm, or any production-crate file — it ADDS a
// type-resolved layer on top (D50: in-process, offline, synthetic). Proven via reverted SCRATCH
// additions (a type-alias once and a degenerate initialized once guarding a cached scan with no
// compute-once counter → confirmed flagged forward here while the syntactic scan stayed blind; and an
// orphaned registry row whose Once is removed → confirmed flagged by the reverse arm — then reverted).
func TestCachedScanOnceAliasAndInitGuardsAreComputeOncePinned(t *testing.T) {
	resolved := typeResolvedSyncOnceGuardVars(t)

	// ANCHOR (no-vacuous-pass): the type-resolved scan MUST find the known orch65 Once
	// (`var exportedErrorVarsOnce sync.Once`). A zero-var result — a type-check regression that hid
	// every var — would otherwise let the forward reconciliation pass over an empty set while the
	// existing cached-scan Once went unpinned by this layer. Pin the anchor so the scan cannot go
	// silently blind.
	const anchorOnce = "exportedErrorVarsOnce"
	foundAnchor := false
	for _, name := range resolved {
		if name == anchorOnce {
			foundAnchor = true
			break
		}
	}
	if !foundAnchor {
		t.Fatalf("the type-resolved scan of the resolverlock package found these package-level "+
			"sync.Once-typed vars %v but NOT the known cached-scan Once %q — the alias/init pin "+
			"anchors on it, so a result missing it means the type-resolved scan went blind (a "+
			"refactor or a type-check regression hid the declaration). A vacuous pass over a "+
			"Once-less view would let an UNPINNED alias/initialized cached-scan Once slip through; "+
			"restore the scan or update the anchor in lockstep.", resolved, anchorOnce)
	}
	if _, ok := computeOncePinnedScanOnces[anchorOnce]; !ok {
		t.Fatalf("the anchor cached-scan Once %q is missing from computeOncePinnedScanOnces — the "+
			"registry must record its compute-once counter pin (counter exportedErrorVarsComputeCount, "+
			"guard TestComputeExportedErrorVarsRunsOnce). Re-add the row; the alias/init pin depends "+
			"on the anchor being registered.", anchorOnce)
	}

	// FORWARD: every var whose RESOLVED type is sync.Once must carry a compute-once pin (be
	// registered). An alias-typed or degenerate-initialized cached-scan Once added WITHOUT a
	// counter==1 assertion — the two forms the syntactic pin cannot see — is caught here, named,
	// with the remedy spelled out.
	for _, name := range resolved {
		if _, ok := computeOncePinnedScanOnces[name]; !ok {
			t.Errorf("package-level var %q resolves (through a local type alias and/or pointer, "+
				"INCLUDING an initialized declaration) to sync.Once in the resolverlock package but is "+
				"NOT registered in computeOncePinnedScanOnces — every sync.Once that guards a cached "+
				"type-aware scan must be paired with a COMPUTE-ONCE COUNTER asserted == 1 (the way "+
				"exportedErrorVarsOnce carries exportedErrorVarsComputeCount, pinned by "+
				"TestComputeExportedErrorVarsRunsOnce). This pin sees THROUGH a `type onceT = sync.Once` "+
				"alias and through a degenerate `var %s = sync.Once{}` initializer that the syntactic "+
				"scan (declaredSyncOnceVars) misses, so neither escape hatch can silently re-introduce "+
				"the per-caller cost the cache removes. Add a package-level counter incremented INSIDE "+
				"%s.Do(...), a Test asserting it == 1, and a row {%q: {counterVar, guardTest}} to "+
				"computeOncePinnedScanOnces. If this var does NOT guard a cached scan, that exception "+
				"still belongs in the registry with a counter/guard that documents why (the pin is "+
				"fail-closed by design — silence is not an option).", name, name, name, name)
		}
	}

	// REVERSE (orch76): every REGISTRY ROW must resolve to a REAL type-resolved sync.Once var still
	// present in the package — so an ORPHANED row (a compute-once counter whose backing Once was
	// renamed or removed) cannot rot into a vacuous claim of coverage. The syntactic pin
	// (TestCachedScanOncesAreComputeOncePinned) already checks reverse against the SYNTACTIC scan, but
	// a row backed only by an alias/initialized-form Once is invisible to that syntactic set, so a
	// stale alias/init row could go unflagged there. The type-resolved set is the BROADER,
	// authoritative one: it covers the value/pointer/embedding forms the syntactic scan sees PLUS the
	// alias/initialized forms it misses, so reconciling the registry against it closes the loop for
	// every registered Once. This mirrors how reconcileCorpusCoverage flags a staleExpectation for a
	// fixture that no longer exists.
	resolvedSet := make(map[string]bool, len(resolved))
	for _, name := range resolved {
		resolvedSet[name] = true
	}
	for name := range computeOncePinnedScanOnces {
		if !resolvedSet[name] {
			t.Errorf("computeOncePinnedScanOnces registers %q but the type-resolved scan of the "+
				"resolverlock package found NO package-level var whose type resolves to sync.Once by that "+
				"name (resolved Onces: %v) — the registry row is STALE/ORPHANED (the Once was renamed or "+
				"removed but its compute-once counter row was left behind, a vacuous claim of coverage). "+
				"This reverse arm reconciles the registry against the TYPE-RESOLVED set (value, pointer, "+
				"embedding, alias, AND initialized forms), so it catches a stale alias/init row the "+
				"syntactic reverse check in TestCachedScanOncesAreComputeOncePinned cannot see. Drop or "+
				"rename the registry row to track the real Once, or restore the Once it claims to pin.",
				name, resolved)
		}
	}
}

// TestSyncOnceScanComplementaritySuperset PINS the COMPLEMENTARITY/SUPERSET relationship the
// declaredSyncOnceVars and typeResolvedSyncOnceGuardVars docstrings CLAIM but nothing enforces. The
// two scans reconcile INDEPENDENTLY against the SAME computeOncePinnedScanOnces registry —
// TestCachedScanOncesAreComputeOncePinned drives the SYNTACTIC set, and
// TestCachedScanOnceAliasAndInitGuardsAreComputeOncePinned drives the TYPE-RESOLVED set — but no test
// asserts the two name-sets AGREE the way "type-resolved is the broader authoritative SUPERSET;
// syntactic is the narrower no-initializer SUBSET" requires. Today every package-level sync.Once is a
// no-initializer value-form guard (exportedErrorVarsOnce, typeResolvedSyncOnceGuardVarsOnce) so the
// two sets are equal and the claim is LATENT, but a future contributor could add a degenerate guard
// that satisfies ONE scan arm while escaping the OTHER — e.g. a `type onceT = sync.Once; var g onceT`
// alias or a degenerate `var g = sync.Once{}` initializer the syntactic scan skips but the
// type-resolved scan catches — and no existing test would notice the divergence. This pin closes that
// gap by reconciling the two scans AGAINST EACH OTHER and against the registry's type-resolved-arm
// coverage:
//
//   - CONTAINMENT (superset): every name in declaredSyncOnceVars (syntactic) MUST appear in
//     typeResolvedSyncOnceGuardVars (type-resolved). The syntactic forms (value/pointer/embedding,
//     no-initializer) all carry a RESOLVED type of sync.Once, so the type checker that powers the
//     type-resolved scan MUST see every one of them — syntactic ⊆ type-resolved. A syntactically
//     declared guard MISSING from the type-resolved set means the type-resolved scan went blind to a
//     form the syntactic scan caught (a regression that would let a guard satisfy the syntactic arm
//     while escaping the type-resolved arm), and fails LOUDLY here naming the offender.
//
//   - DEGENERATE-ONLY DELTA: the set type-resolved MINUS syntactic is EXACTLY the registry rows the
//     SYNTACTIC scan cannot see — i.e. the alias/degenerate-initialized guards pinned ONLY through
//     the registry's type-resolved arm (TestCachedScanOnceAliasAndInitGuardsAreComputeOncePinned).
//     Every delta member MUST be registered (a degenerate guard that resolves by type but escapes the
//     syntactic scan still has to carry a compute-once pin — it cannot satisfy the type-resolved arm
//     while escaping coverage), AND every registry row invisible to the syntactic scan MUST be a delta
//     member (a registry row covered ONLY by the type-resolved arm must actually be an alias/degenerate
//     guard the type-resolved scan resolves — it cannot be double-pinned inconsistently or claim
//     type-resolved-only coverage for a Once that does not exist). The two together pin
//     delta == (registry \ syntactic), so a degenerate guard can NEITHER satisfy one arm while
//     escaping the other NOR be inconsistently double-pinned across the two arms.
//
//   - ANCHOR: exportedErrorVarsOnce — the known no-initializer value-form guard — MUST be present in
//     BOTH sets, so a zero-var result from either scan (a parse/type-check regression that hid every
//     var) cannot let the containment or delta checks pass vacuously over an empty view.
//
// TEST-ONLY, ADDITIVE, ZERO production change: it drives the EXISTING declaredSyncOnceVars and
// typeResolvedSyncOnceGuardVars (no new scan, no registry edit, no weakened assertion) and reconciles
// their results in-process and offline (D50). It does NOT touch declaredSyncOnceVars,
// typeResolvedSyncOnceGuardVars, isSyncOnceType, typeResolvesToSyncOnce, the registry, the orch68/orch76
// counter==1 guards, either scan's own registry-reconciliation arm, or any production-crate file — it
// ADDS the cross-scan complementarity layer the docstrings promise.
// syncOnceContainmentViolations is the PURE CONTAINMENT (syntactic ⊆ type-resolved) decision the
// complementarity guard (TestSyncOnceScanComplementaritySuperset) makes: given the SYNTACTIC scan's
// declared guard names and the TYPE-RESOLVED scan's name SET, it returns the SORTED set of syntactic
// names MISSING from the type-resolved set — every CONTAINMENT VIOLATION. An empty result means
// syntactic ⊆ type-resolved holds. The production guard CALLS this over the LIVE scans (whose sets are
// equal today, so it returns nothing — the arm is latent); the build-tagged fault-injection double
// (TestSyncOnceContainmentArmBites) drives it over a SYNTHETIC diverging pair and asserts it returns
// the injected offender — so the containment arm's bite is PROVEN, not merely code-read. Lifting the
// inlined loop into a pinned pure helper mirrors goExactSetMatches / nameReconciledAcrossSets.
func syncOnceContainmentViolations(declared []string, resolvedSet map[string]bool) []string {
	var violations []string
	for _, name := range declared {
		if !resolvedSet[name] {
			violations = append(violations, name)
		}
	}
	sort.Strings(violations)
	return violations
}

func TestSyncOnceScanComplementaritySuperset(t *testing.T) {
	declared := declaredSyncOnceVars(t)          // SYNTACTIC: the narrower no-initializer subset.
	resolved := typeResolvedSyncOnceGuardVars(t) // TYPE-RESOLVED: the broader authoritative superset.

	resolvedSet := make(map[string]bool, len(resolved))
	for _, name := range resolved {
		resolvedSet[name] = true
	}
	declaredSet := make(map[string]bool, len(declared))
	for _, name := range declared {
		declaredSet[name] = true
	}

	// ANCHOR (no-vacuous-pass): the known no-initializer value-form guard must surface in BOTH scans.
	// A scan that returned the empty set (a parse or type-check regression that hid every var) would
	// otherwise let the containment and delta checks below pass vacuously — syntactic ⊆ type-resolved
	// is trivially true when syntactic is empty, and the delta collapses to nothing. Pin the anchor in
	// each set so neither scan can go silently blind under this complementarity guard.
	const anchorOnce = "exportedErrorVarsOnce"
	if !declaredSet[anchorOnce] {
		t.Fatalf("the SYNTACTIC scan (declaredSyncOnceVars) found these guards %v but NOT the known "+
			"no-initializer value-form guard %q — the complementarity pin anchors on it being present "+
			"in BOTH scans, so a syntactic result missing it means the AST self-scan went blind. A "+
			"vacuous pass over an empty syntactic set would make syntactic ⊆ type-resolved trivially "+
			"true and the degenerate-only delta collapse; restore the scan or update the anchor in "+
			"lockstep.", declared, anchorOnce)
	}
	if !resolvedSet[anchorOnce] {
		t.Fatalf("the TYPE-RESOLVED scan (typeResolvedSyncOnceGuardVars) found these guards %v but NOT "+
			"the known no-initializer value-form guard %q — the complementarity pin anchors on it being "+
			"present in BOTH scans, so a type-resolved result missing it means the whole-package "+
			"go/types check went blind. A vacuous pass over an empty type-resolved set would mask a "+
			"containment violation; restore the scan or update the anchor in lockstep.", resolved,
			anchorOnce)
	}

	// CONTAINMENT (SUPERSET): syntactic ⊆ type-resolved. Every syntactically-declared guard
	// (value/pointer/embedding, no-initializer) carries a RESOLVED type of sync.Once, so the type
	// checker powering the type-resolved scan MUST also enumerate it. A name in the syntactic set but
	// MISSING from the type-resolved set means a guard could satisfy the SYNTACTIC arm while escaping
	// the TYPE-RESOLVED arm — the divergence the docstrings' "type-resolved is the broader superset"
	// claim forbids — so fail LOUDLY, naming the offender, with the relationship spelled out. The pure
	// containment predicate is lifted into syncOnceContainmentViolations so the build-tagged
	// fault-injection double (TestSyncOnceContainmentArmBites, //go:build resolverlock_faultinject)
	// can drive the SAME logic over a synthetic diverging pair and prove the arm REDDENS — the bite
	// the real scans, being equal today, leave latent.
	for _, name := range syncOnceContainmentViolations(declared, resolvedSet) {
		t.Errorf("COMPLEMENTARITY/SUPERSET VIOLATION: the syntactically-declared sync.Once guard %q "+
			"(from declaredSyncOnceVars %v) is NOT in the type-resolved set "+
			"(typeResolvedSyncOnceGuardVars %v). The docstrings CLAIM the type-resolved scan is the "+
			"broader AUTHORITATIVE SUPERSET and the syntactic scan the narrower no-initializer SUBSET "+
			"— every syntactic value/pointer/embedding guard carries a RESOLVED type of sync.Once, so "+
			"the whole-package go/types check MUST see it. A syntactic guard missing from the "+
			"type-resolved set means a guard can satisfy the SYNTACTIC registry arm while ESCAPING the "+
			"TYPE-RESOLVED arm, breaking complementarity. Restore the type-resolved scan so it sees "+
			"every syntactic form, or reconcile the two scans in lockstep.", name, declared, resolved)
	}

	// DEGENERATE-ONLY DELTA: type-resolved MINUS syntactic. By the containment check above this delta
	// is precisely the guards the type-resolved scan catches that the syntactic scan does NOT — the
	// alias-typed and degenerate-initialized forms. The complementarity invariant requires this delta
	// to be EXACTLY the registry rows the SYNTACTIC scan cannot see (the rows pinned ONLY through the
	// registry's type-resolved arm). We pin BOTH inclusions so the delta cannot drift either way:
	delta := make([]string, 0, len(resolved))
	for _, name := range resolved {
		if !declaredSet[name] {
			delta = append(delta, name)
		}
	}
	sort.Strings(delta)

	// The registry rows the syntactic scan cannot see — the type-resolved-arm-only coverage. (Every
	// registry row resolves to a real type-resolved sync.Once var by the orch76 reverse arm of
	// TestCachedScanOnceAliasAndInitGuardsAreComputeOncePinned, so a registry row absent from the
	// syntactic set is exactly a row covered ONLY through the type-resolved arm.)
	registryTypeResolvedArmOnly := make(map[string]bool)
	for name := range computeOncePinnedScanOnces {
		if !declaredSet[name] {
			registryTypeResolvedArmOnly[name] = true
		}
	}

	// (a) delta ⊆ registry-type-resolved-arm: every degenerate-only guard (type-resolved but NOT
	// syntactic) MUST be registered — pinned through the type-resolved arm, the ONLY arm that sees it.
	// A delta member NOT in the registry means a degenerate guard satisfies the type-resolved arm yet
	// escapes compute-once coverage entirely, the exact "satisfy one arm but not the other" hole.
	for _, name := range delta {
		if !registryTypeResolvedArmOnly[name] {
			t.Errorf("COMPLEMENTARITY DELTA VIOLATION: the degenerate-only guard %q is in the "+
				"type-resolved set but NOT the syntactic set (delta type-resolved\\syntactic = %v), yet it "+
				"is NOT a registry row the syntactic scan misses — so it escapes the type-resolved registry "+
				"arm that is the ONLY arm able to pin it. A degenerate/alias guard that resolves by type "+
				"but is invisible to declaredSyncOnceVars MUST carry a compute-once pin registered in "+
				"computeOncePinnedScanOnces; otherwise it satisfies the type-resolved scan while escaping "+
				"the syntactic one AND coverage. Register its counter==1 pin (it is already flagged by "+
				"TestCachedScanOnceAliasAndInitGuardsAreComputeOncePinned forward).", name, delta)
		}
	}

	// (b) registry-type-resolved-arm ⊆ delta: every registry row the syntactic scan cannot see MUST be
	// a real degenerate-only guard the type-resolved scan resolves. A type-resolved-arm-only row NOT in
	// the delta means the registry claims type-resolved-only coverage for a name the type-resolved scan
	// does not even resolve to sync.Once — an inconsistently/doubly pinned row that the syntactic
	// reverse arm cannot catch (it is invisible to the syntactic set) and the type-resolved reverse arm
	// already guards against; pinning it HERE cross-checks the two arms agree on the delta.
	for name := range registryTypeResolvedArmOnly {
		if !resolvedSet[name] {
			t.Errorf("COMPLEMENTARITY DELTA VIOLATION: computeOncePinnedScanOnces row %q is invisible to "+
				"the syntactic scan (not in declaredSyncOnceVars %v) yet is NOT in the type-resolved set "+
				"either (typeResolvedSyncOnceGuardVars %v) — so it is neither a syntactic guard nor a "+
				"degenerate-only guard the type-resolved arm resolves, an inconsistently double-pinned "+
				"row claiming type-resolved-only coverage for a Once that does not resolve to sync.Once. "+
				"The degenerate-only delta (type-resolved\\syntactic = %v) MUST equal the registry rows "+
				"the syntactic scan misses; reconcile the registry so the two scan arms agree.", name,
				declared, resolved, delta)
		}
	}
}

// nameReconciledAcrossSets is the PURE per-name reconciliation decision the by-name
// exact-set completeness guard (TestExportedSentinelUniverseComplete) makes in BOTH
// directions: a sentinel name reconciles iff it appears in BOTH the source-declared set
// AND the universe set — `declaredSet[name] && universeSet[name]`. This encodes the
// load-bearing FAIL-CLOSED semantic the guard depends on: a name present in only ONE set
// (declared-but-not-in-universe, the direction-(a) gap; or in-universe-but-not-declared,
// the stale direction-(b) row) does NOT reconcile and MUST be flagged. The conjunction is
// load-bearing — an OR here would EXEMPT a half-reconciled name from both directions,
// silently re-opening the exact-set bite. The production guard CALLS this function in both
// loops, and so does the table self-test (TestNameReconciledAcrossSets), so both exercise
// the SAME code path — mirroring how allowlistExempts lifts the construction-guard
// exemption into a pinned pure helper. A future edit that weakened the AND to an OR (or
// dropped a clause) flips the self-test RED, not silently disabling a direction of the
// guard.
func nameReconciledAcrossSets(universeSet, declaredSet map[string]bool, name string) bool {
	return universeSet[name] && declaredSet[name]
}

// TestNameReconciledAcrossSets pins the by-name completeness guard's FAIL-CLOSED
// reconciliation semantic against accidental weakening. TestExportedSentinelUniverseComplete
// flags a sentinel name unless it appears in BOTH the source-declared set and the universe
// set; a name in only ONE set (an unlisted declared sentinel, or a stale universe row) must
// NOT reconcile — it falls through to the per-direction error. That behaviour was previously
// proven only by code reading, so an edit that loosened the conjunction (an OR where the AND
// belongs) would have silently exempted half-reconciled names, re-opening BOTH the
// missing-from-universe gap and the stale-row gap. This table drives the SAME
// nameReconciledAcrossSets helper the production guard calls over SYNTHETIC declared/universe
// sets (D50 — the real exportedSentinelUniverse and the source scan are untouched), asserting:
// only a name in BOTH sets reconciles; presence in just one set (either direction) does NOT.
func TestNameReconciledAcrossSets(t *testing.T) {
	// Synthetic declared/universe sets with one name in BOTH, one declared-only, one
	// universe-only, and one in NEITHER. Distinct from the package's real source scan and
	// exportedSentinelUniverse (both unchanged); this literal exists only to exercise the
	// pure helper's reconciliation branches.
	declaredSet := map[string]bool{
		"ErrInBoth":       true,
		"ErrDeclaredOnly": true,
	}
	universeSet := map[string]bool{
		"ErrInBoth":       true,
		"ErrUniverseOnly": true,
	}
	cases := []struct {
		name    string
		key     string
		want    bool
		comment string
	}{
		{
			name:    "name in BOTH sets -> reconciles",
			key:     "ErrInBoth",
			want:    true,
			comment: "a sentinel both declared in source AND listed in the universe is fully reconciled",
		},
		{
			name:    "declared-only name -> does NOT reconcile (direction-a gap)",
			key:     "ErrDeclaredOnly",
			want:    false,
			comment: "a source sentinel missing from the universe is invisible to the exact-set scan; it must be flagged",
		},
		{
			name:    "universe-only name -> does NOT reconcile (direction-b stale row)",
			key:     "ErrUniverseOnly",
			want:    false,
			comment: "a universe row no longer declared in source is a stale entry that can never match; it must be flagged",
		},
		{
			name:    "name in NEITHER set -> does NOT reconcile",
			key:     "ErrNeither",
			want:    false,
			comment: "an unknown name is in no set, so it trivially does not reconcile",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nameReconciledAcrossSets(universeSet, declaredSet, tc.key)
			if got != tc.want {
				t.Fatalf("nameReconciledAcrossSets(universeSet, declaredSet, %q) = %v, want %v — "+
					"%s. The by-name completeness guard must reconcile ONLY on a name present in "+
					"BOTH sets (the conjunction is load-bearing): presence in just one set must NOT "+
					"reconcile, or a future edit that weakened the AND to an OR would silently exempt "+
					"a half-reconciled sentinel and re-open the exact-set bite.", tc.key, got, tc.want,
					tc.comment)
			}
		})
	}
}

// TestExportedSentinelUniverseComplete is the fail-closed completeness guard for the
// exportedSentinelUniverse table. The landed exact-set assertion (presentSentinels +
// the goRejectExact rows) is only as strong as this universe enumerating EVERY
// exported resolverlock Err* sentinel: a sentinel added to ANY non-_test.go package
// file but NOT to the table would be INVISIBLE to the exact-set scan, silently
// weakening the bite with only code review standing guard. This test removes that gap
// by reconciling the table against the source BY NAME — scanning EVERY non-_test.go
// file in the package, not just resolverlock.go, so a sentinel introduced in a new or
// different file is still caught — fail-closed in BOTH directions:
//
//	(a) a sentinel declared in any package source file but ABSENT from the universe —
//	    the exact-set scan would never look for it, so a spurious extra cause carrying it
//	    would slip through goRejectExact. Caught here, named.
//	(b) a universe entry no longer declared in source (renamed/removed) — a stale row
//	    that can never match, eroding the table's meaning. Caught here, named.
//
// Same lockstep-fail-closed ethos as the fixture coverage gate
// (TestDriftCorpusCoverageLockstep): the assertion NAMES the offending sentinel and
// FAILS — it never skips.
func TestExportedSentinelUniverseComplete(t *testing.T) {
	declared := declaredExportedSentinels(t)
	if len(declared) == 0 {
		t.Fatalf("parsed the package's non-_test.go source files but found ZERO exported "+
			"`Err* = errors.New(...)` sentinels under %s — the scan is broken (it must "+
			"enumerate the package's sentinel declarations across ALL files); refusing to "+
			"vacuously pass", resolverlockPackageDir(t))
	}

	declaredSet := make(map[string]bool, len(declared))
	for _, n := range declared {
		declaredSet[n] = true
	}
	universeSet := make(map[string]bool, len(exportedSentinelUniverse))
	for _, s := range exportedSentinelUniverse {
		if universeSet[s.name] {
			t.Errorf("exportedSentinelUniverse lists sentinel %q more than once — each "+
				"sentinel must appear exactly once so the exact-set scan is over a clean "+
				"set", s.name)
		}
		universeSet[s.name] = true
	}

	// Both directions of the by-name reconciliation make the SAME per-name decision —
	// "does this sentinel name reconcile, i.e. appear in BOTH the declared set and the
	// universe set?" — routed through the pure predicate nameReconciledAcrossSets (pinned
	// fail-closed by TestNameReconciledAcrossSets). A name present in only ONE set does NOT
	// reconcile and is FLAGGED; the production guard and the self-test exercise the SAME
	// predicate, so an edit that loosened the membership test (e.g. an OR where the AND
	// belongs, exempting a half-reconciled name) flips the self-test RED rather than
	// silently letting a stale or unlisted sentinel through.

	// Direction (a): every sentinel DECLARED anywhere in the package must be in the
	// universe.
	for _, n := range declared {
		if !nameReconciledAcrossSets(universeSet, declaredSet, n) {
			t.Errorf("sentinel %s is declared in a package source file but is MISSING from "+
				"exportedSentinelUniverse — it would be INVISIBLE to the exact-set scan "+
				"(presentSentinels), silently weakening the goRejectExact bite. Add "+
				"{%q, %s} to the universe table so the exact-set check covers the WHOLE "+
				"cause space", n, n, n)
		}
	}
	// Direction (b): every sentinel in the universe must still be DECLARED somewhere in
	// the package source.
	for _, s := range exportedSentinelUniverse {
		if !nameReconciledAcrossSets(universeSet, declaredSet, s.name) {
			t.Errorf("exportedSentinelUniverse lists %q but no exported `%s = errors.New"+
				"(...)` sentinel is declared in any package source file — a stale/renamed "+
				"entry that can never match. Drop or rename the universe row to track the "+
				"source", s.name, s.name)
		}
	}

	// Belt-and-suspenders count parity: the table and the source must enumerate the
	// SAME set, so the count is exact, not a floor. (The two loops above already cover
	// both directions; this catches a duplicate row that would otherwise mask a gap.)
	if len(exportedSentinelUniverse) != len(declared) {
		t.Fatalf("sentinel-universe count mismatch: %d declared across the package's "+
			"source files %v, %d rows in exportedSentinelUniverse — the universe must "+
			"enumerate the exported sentinels EXACTLY (fail-closed completeness)",
			len(declared), declared, len(exportedSentinelUniverse))
	}
}

// constructionConventionAllowlist names the exported error-typed package-level vars
// that are a DELIBERATE, documented exception to the Err-prefix + errors.New
// construction convention (doc.go "The sentinel naming convention is LOAD-BEARING").
// It is keyed by the EXACT source identifier and maps to a human justification, so an
// intentional non-Err-prefixed / fmt.Errorf / custom-constructor exported error var is
// OPT-IN and explained here — never silently tolerated. The forward construction guard
// (TestExportedErrorSentinelsFollowConstructionConvention) consults this map and skips a
// listed var ONLY when its justification is non-empty, so adding a row is a conscious,
// reviewable act. It is EMPTY today: every resolver-lock and NFT-4 sentinel keeps the
// convention, and the by-name exact-set bite (TestExportedSentinelUniverseComplete) and
// the by-construction enforcement below both depend on that staying true. Add a row here
// ONLY with a real reason, and update doc.go if the convention's load-bearing role changes.
var constructionConventionAllowlist = map[string]string{}

// exportedErrorVarInitializers parses EVERY non-_test.go package file and returns a map
// from exported package-level var IDENTIFIER to its AST initializer expression — the RHS
// the construction guard inspects to tell errors.New(...) from fmt.Errorf(...) / a custom
// constructor. It pairs with the TYPE-driven declaredExportedErrorVars: that function answers
// "which exported vars ARE errors?" (naming- and constructor-agnostic, via go/types); this one
// answers "HOW was each constructed?" (structurally, via go/ast). Walking the SAME
// packageSourceFiles surface the type scan walks keeps the two views over one production set.
//
// Only exported file-scope vars WITH a single-expression initializer are recorded (the shape a
// package-level sentinel always has: `var Foo = <call>`). A var declared without an initializer,
// or with a names/values arity mismatch, is simply absent from the map; the guard treats a missing
// initializer for an error-typed var as a convention violation (it cannot be an errors.New call),
// failing LOUDLY rather than skipping — fail-closed, matching the package ethos.
func exportedErrorVarInitializers(t *testing.T) map[string]ast.Expr {
	t.Helper()
	fset := token.NewFileSet()
	inits := make(map[string]ast.Expr)
	for _, src := range packageSourceFiles(t) {
		f, err := parser.ParseFile(fset, src, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s for the construction-convention scan: %v", src, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range vs.Names {
					if !ident.IsExported() {
						continue
					}
					// Record the per-name initializer only when the spec assigns one value
					// per name (the `var X = expr` form sentinels use). A bare `var X T`
					// (no initializer) leaves X out of the map; the guard then flags it,
					// because an error-typed var with no errors.New(...) RHS cannot satisfy
					// the construction convention.
					if i >= len(vs.Values) {
						continue
					}
					inits[ident.Name] = vs.Values[i]
				}
			}
		}
	}
	return inits
}

// allowlistExempts is the PURE exemption decision for the construction-convention guard:
// a var named `name` is exempt iff its allowlist row carries a NON-EMPTY justification —
// i.e. `allowlist[name] != ""`. This encodes the load-bearing FAIL-CLOSED semantic: mere
// KEY-PRESENCE never exempts (a missing key yields the zero value "", so the absent case
// and the half-filled empty-reason case BOTH fold to "" and BOTH return false). Only a real,
// reviewable justification opts a var out. The production guard
// (TestExportedErrorSentinelsFollowConstructionConvention) calls THIS function, and so does
// the table self-test (TestAllowlistExemptsRequiresJustification), so both exercise the SAME
// code path — a future edit that weakened the gate to mere key-presence (dropping the
// non-empty-reason clause) would flip the self-test RED, not silently disable the guard.
func allowlistExempts(allowlist map[string]string, name string) bool {
	return allowlist[name] != ""
}

// TestAllowlistExemptsRequiresJustification pins the construction-guard allowlist's
// FAIL-CLOSED exemption semantic against accidental weakening. The guard exempts a listed
// var ONLY when its justification is non-empty; a half-filled row (key present, reason == "")
// must NOT exempt — it falls through to the prefix + errors.New checks. That behavior was
// previously proven only by code reading, so an edit that exempted on mere key-presence
// (dropping the `reason != ""` clause) would have silently disabled the guard for any listed
// var. This table drives the SAME allowlistExempts helper the production guard calls over a
// SYNTHETIC map literal (the real constructionConventionAllowlist stays EMPTY — D50, no real
// rows added), asserting: present-key alone never exempts; only a real justification does.
func TestAllowlistExemptsRequiresJustification(t *testing.T) {
	// A synthetic allowlist with one EMPTY-reason row and one JUSTIFIED row. Distinct from
	// the package's real constructionConventionAllowlist (which stays empty); this literal
	// exists only to exercise the pure helper's three branches.
	synthetic := map[string]string{
		"ErrHalfFilled": "",                     // key present, justification empty
		"ErrJustified":  "deliberate exception", // key present, justification non-empty
	}
	cases := []struct {
		name    string
		key     string
		want    bool
		comment string
	}{
		{
			name:    "empty-reason row -> NOT exempt",
			key:     "ErrHalfFilled",
			want:    false,
			comment: "a half-filled row (present key, empty justification) must fall through to the checks",
		},
		{
			name:    "non-empty-reason row -> exempt",
			key:     "ErrJustified",
			want:    true,
			comment: "a row with a real justification is the documented opt-out",
		},
		{
			name:    "absent key -> NOT exempt",
			key:     "ErrNotListed",
			want:    false,
			comment: "an unlisted var is never exempt — the default is to enforce the convention",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := allowlistExempts(synthetic, tc.key)
			if got != tc.want {
				t.Fatalf("allowlistExempts(synthetic, %q) = %v, want %v — %s. The "+
					"construction-guard allowlist must exempt ONLY on a NON-EMPTY justification: "+
					"mere key-presence (or an absent key) must NOT exempt, or a future edit that "+
					"dropped the `reason != \"\"` clause would silently disable the guard for any "+
					"listed var.", tc.key, got, tc.want, tc.comment)
			}
		})
	}
}

// TestExportedErrorSentinelsFollowConstructionConvention is the FORWARD, type-driven guard
// that enforces the load-bearing sentinel construction convention BY CONSTRUCTION rather than
// only by universe presence. It closes the residual gap left by the two completeness guards:
//
//   - TestExportedSentinelUniverseComplete reconciles NAMES only (it parses out exactly the
//     `Err* = errors.New(...)` specs, so a convention-breaking var is invisible to it once a
//     maintainer hand-adds the var to the universe — it never asserts the var KEPT the form).
//   - TestExportedErrorVarsCoveredByUniverse requires only PRESENCE in the universe — an
//     exported sentinel that IS in the universe yet was built via fmt.Errorf, or named WITHOUT
//     the Err prefix, satisfies it and goes unflagged, silently breaking the documented
//     convention (doc.go) the by-name exact-set bite depends on.
//
// This guard walks the SAME exported, file-scope, error-TYPED vars the orch48 type scan
// enumerates (declaredExportedErrorVars — naming- and constructor-agnostic, via go/types) and,
// for each, asserts BOTH clauses of the convention:
//
//	(i)  its IDENTIFIER has the Err prefix; AND
//	(ii) it is CONSTRUCTED via errors.New(...) — detected from the AST initializer
//	     (errors.New(...) vs fmt.Errorf(...) / any other constructor), reusing isErrorsNewCall.
//
// A var that violates EITHER clause FAILS LOUDLY, naming resolverlock.<Ident> and stating WHICH
// clause it broke (prefix vs construction) — it never skips or swallows, matching the package's
// fail-closed ethos. A DELIBERATE exception must be opted into, with a justification, via
// constructionConventionAllowlist; nothing is tolerated silently. Reusing the orch48 go/types +
// AST machinery (declaredExportedErrorVars / packageSourceFiles / resolverlockPackageDir) keeps
// this stdlib-only and offline; a type-check error is a HARD failure (it propagates out of
// declaredExportedErrorVars) and a zero-vars result is Fatal — no vacuous pass.
//
// This is the FORWARD direction the convention needs: the universe-coverage and by-name guards
// stay UNWEAKENED and own PRESENCE / NAME reconciliation; this test owns the SHAPE of every
// exported error sentinel, so a convention break now fails the BUILD, not merely a universe
// staleness check. Proven (via a reverted SCRATCH mutation, never committed): an in-universe
// exported sentinel rewritten to fmt.Errorf(...), or renamed off the Err prefix, fails THIS test
// naming it — while the universe-presence guard would have stayed green.
func TestExportedErrorSentinelsFollowConstructionConvention(t *testing.T) {
	errorVars := declaredExportedErrorVars(t)
	if len(errorVars) == 0 {
		t.Fatalf("type-checked the package's non-_test.go source files but found ZERO "+
			"exported error-typed package-level vars under %s — the resolverlock scanner "+
			"declares Err* sentinels, so the type-aware scan finding none means it is broken; "+
			"refusing to vacuously pass the construction-convention guard", resolverlockPackageDir(t))
	}

	inits := exportedErrorVarInitializers(t)

	for _, name := range errorVars {
		if allowlistExempts(constructionConventionAllowlist, name) {
			// Opted-in, documented exception — skip with intent (the allowlist row IS the
			// audit trail). An empty justification does NOT exempt (allowlistExempts requires
			// a non-empty reason): a half-filled allowlist row falls through to the checks
			// below, so it cannot silently disable the guard. allowlistExempts is the SAME
			// helper TestAllowlistExemptsRequiresJustification pins, so the fail-closed
			// semantic is exercised by a table self-test, not just code-read here.
			continue
		}

		// Clause (i): the load-bearing Err prefix.
		if !strings.HasPrefix(name, "Err") {
			t.Errorf("exported error-typed package-level var resolverlock.%s VIOLATES the "+
				"construction convention (clause: NAMING): it is assignable to error (the type "+
				"checker says so) but its identifier lacks the load-bearing `Err` prefix. The "+
				"by-name exact-set bite (TestExportedSentinelUniverseComplete) reconciles only "+
				"`Err* = errors.New(...)` specs, so a non-Err-prefixed sentinel is INVISIBLE to it "+
				"even once added to exportedSentinelUniverse — silently weakening the goRejectExact "+
				"bite. Rename it to `Err%s = errors.New(...)` (see doc.go 'The sentinel naming "+
				"convention is LOAD-BEARING'), or, if this is a DELIBERATE non-sentinel exception, "+
				"add a justified row to constructionConventionAllowlist.", name, name)
		}

		// Clause (ii): constructed via errors.New(...), not fmt.Errorf / a custom constructor.
		init, found := inits[name]
		if !found {
			t.Errorf("exported error-typed package-level var resolverlock.%s VIOLATES the "+
				"construction convention (clause: CONSTRUCTION): it is assignable to error but the "+
				"AST scan found NO single-expression initializer for it, so it cannot be an "+
				"`errors.New(...)` sentinel (a package-level sentinel is always `var %s = "+
				"errors.New(...)`). Declare it as `errors.New(...)` (see doc.go), or add a justified "+
				"row to constructionConventionAllowlist if it is a deliberate exception.", name, name)
			continue
		}
		if !isErrorsNewCall(init) {
			t.Errorf("exported error-typed package-level var resolverlock.%s VIOLATES the "+
				"construction convention (clause: CONSTRUCTION): it is assignable to error but is "+
				"NOT constructed via errors.New(...) — its initializer is fmt.Errorf(...) or a "+
				"custom constructor. The package-level SENTINEL must stay an `errors.New(...)` Err* "+
				"var so errors.Is matching and the by-name completeness scan "+
				"(TestExportedSentinelUniverseComplete) both hold; wrap runtime detail with "+
				"`fmt.Errorf(\"%%w …\", %s, …)` at the RETURN site instead (see doc.go 'The "+
				"sentinel naming convention is LOAD-BEARING'). If this is a DELIBERATE exception, "+
				"add a justified row to constructionConventionAllowlist.", name, name)
		}
	}
}

// classOf strips the NN- prefix and the .pol1.yaml suffix to recover the drift
// class label for messages (e.g. "09-anchor-alias-families.pol1.yaml" ->
// "anchor-alias-families").
func classOf(fixture string) string {
	base := fixture
	if i := len(".pol1.yaml"); len(base) > i && base[len(base)-i:] == ".pol1.yaml" {
		base = base[:len(base)-i]
	}
	// drop a leading "NN-" numeric prefix if present.
	if len(base) >= 3 && base[0] >= '0' && base[0] <= '9' && base[1] >= '0' && base[1] <= '9' && base[2] == '-' {
		base = base[3:]
	}
	return base
}
