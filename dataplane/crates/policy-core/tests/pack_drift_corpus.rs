// SPDX-License-Identifier: Apache-2.0

//! Shared drifted-pack corpus walk — the RUST half of the one-artifact-two-readers
//! lockstep proof (D64/D74, D50 synthetic).
//!
//! ONE corpus, two readers, zero per-language copies. This test walks the SAME
//! drifted-pack fixtures the Go corpus walk reads
//! (`assurance/conformance-adapter/resolverlock/drift_corpus_test.go`): the bytes
//! live ONCE, under that crate's `testdata/drift-corpus/fixtures/`, and we reach
//! them from here via a `CARGO_MANIFEST_DIR`-relative `std::fs` path (no copy, no
//! per-language fork). The companion `resolver_lock_tls1.rs` + `pol2_baseline.rs`
//! suites already prove one-artifact-two-readers for the WELL-FORMED shipped pack
//! (`dataplane/artifacts/policy-packs/pol2-system-baseline.pol1.yaml`); this file
//! closes the MALFORMED case the task names — a shape both readers must reject was
//! never proven to produce the same verdict on both sides.
//!
//! ## The honest lockstep model
//!
//! The two readers do NOT share a rejection surface, and the test does not pretend
//! they do. The Go offline scanner is a resolver-lock-SHAPE tripwire (it guards the
//! `blocklist:` section's shape and is blind to the rest of the document). This
//! Rust reader is the full POL-1 SCHEMA reader [`ds_contracts::pol1::parse_layer`]
//! (it guards schema drift — unknown tier, missing provenance, missing/invalid
//! rung token, multi-document / tab syntax — and tolerates a resolver-lock
//! blocklist shape the Go side would reject). So each fixture carries an EXPECTED
//! `(go, rust)` verdict PAIR; this file asserts the RUST column and the full-corpus
//! coverage count, the Go test asserts the GO column and the mirror count. Together
//! they prove:
//!
//!   1. the TRUE both-reject case (`09-anchor-alias-families`) — a malformed shape
//!      BOTH readers must reject DOES reject on both, on the identical bytes;
//!   2. COMPLEMENTARY COVERAGE — every other malformed fixture is caught by at
//!      least ONE reader (never silently accepted by both), and the table records
//!      WHICH reader owns each class;
//!   3. the both-ACCEPT agreement cases (duplicate FQDN, reordered / comment-only
//!      families) — benign shapes neither reader rejects, pinned so a regression
//!      that started rejecting one on a SINGLE side is caught.
//!
//! The coverage assertion reconciles the fixtures ON DISK against this table and
//! fails closed on any unlisted or stale key — so a fixture added to the corpus
//! directory for the Go reader (or anyone) without a Rust expectation row fails
//! HERE until wired. The Go test enforces the identical reconciliation on its side.

use ds_contracts::pol1::{parse_layer, PolicyErrorCode, PolicyLayer, Rung, Tier};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The Rust reader's expected outcome for a corpus fixture: either `parse_layer`
/// ACCEPTS (returns `Ok`), or it REJECTS.
///
/// Two reject strengths, deliberately distinct:
///
///   * [`RustVerdict::Reject`] — PRESENCE: the named [`PolicyErrorCode`] must
///     appear SOMEWHERE in the collected bundle (`errs.has`). The right tool for
///     a SINGLE-cause drift class: it pins the rejection reason without over-
///     constraining a bundle that legitimately collects more than one violation.
///
///   * [`RustVerdict::RejectExact`] — EXACT SET: the bundle's DISTINCT code set
///     must equal the declared set, no more and no less. Presence-only is too
///     weak for the COMPOUND both-reject fixtures (20-23): each declares
///     INDEPENDENT causes on one artifact, so a regression that ADDED a spurious
///     extra rejection cause would still satisfy `has(code)` and slip through.
///     The exact-set arm bites that — the declared codes are the WHOLE cause set,
///     and any code outside it fails the fixture.
///
/// The compound codes are compared as a SET (distinct codes), not a multiset:
/// a bundle may collect the SAME code twice (e.g. fixture 22 surfaces
/// `MissingProvenance` once for the missing reason and once for the missing
/// provenance URL), which is benign duplication of an already-declared cause —
/// what `RejectExact` guards is the arrival of a NEW, undeclared cause CLASS.
#[derive(Clone, Copy, Debug)]
enum RustVerdict {
    Accept,
    Reject(PolicyErrorCode),
    RejectExact(&'static [PolicyErrorCode]),
}

/// The sorted, de-duplicated DEBUG labels of a code set. `PolicyErrorCode` derives
/// `Eq`/`Hash` but NOT `Ord` (and this test may not touch the production crate to
/// add it), so the stable ordering for set-equality is the `Debug` string — a
/// total, deterministic order over the variants that needs no production change.
fn sorted_code_labels<'a>(codes: impl IntoIterator<Item = &'a PolicyErrorCode>) -> Vec<String> {
    let mut labels: Vec<String> = codes.into_iter().map(|c| format!("{c:?}")).collect();
    labels.sort();
    labels.dedup();
    labels
}

/// The directory holding the shared corpus, reached from THIS crate
/// (`dataplane/crates/policy-core`) up THREE levels to the repo root and back down
/// into the conformance-adapter's testdata — the SAME bytes the Go test reads in
/// place. Anchored off `CARGO_MANIFEST_DIR` (like `resolver_lock_tls1.rs`'s
/// `shipped_pack_path`), so the walk works under `cargo test` from any cwd; unlike
/// the shipped pack (which lives INSIDE `dataplane/`), this corpus is one tree
/// over under `assurance/`, hence three pops rather than two.
fn corpus_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // policy-core
    p.pop(); // crates
    p.pop(); // dataplane
    p.push("assurance");
    p.push("conformance-adapter");
    p.push("resolverlock");
    p.push("testdata");
    p.push("drift-corpus");
    p.push("fixtures");
    p
}

/// The RUST column of the per-class `(go, rust)` verdict table, keyed by fixture
/// filename. The Go test holds the mirror table for its column. Every fixture on
/// disk MUST appear here exactly once; the coverage test fails closed otherwise.
/// The trailing comment on each row records the GO column so the full lockstep
/// pair is visible in one place even though the Go test asserts it.
fn rust_corpus_expectations() -> BTreeMap<&'static str, RustVerdict> {
    use PolicyErrorCode::*;
    use RustVerdict::*;
    let mut m: BTreeMap<&'static str, RustVerdict> = BTreeMap::new();

    // ── both ACCEPT — well-formed control + benign-shape agreement cases ──────
    m.insert("00-good-baseline.pol1.yaml", Accept); // go: accept (control)
    m.insert("17-duplicate-fqdn.pol1.yaml", Accept); // go: accept (benign dup)
    m.insert("18-reordered-families.pol1.yaml", Accept); // go: accept (order-insensitive)
    m.insert("19-comment-only-families.pol1.yaml", Accept); // go: accept (comments stripped)

    // ── RUST accepts, GO rejects — resolver-lock-shape drift the schema parser
    //    tolerates (the Go offline half is the tripwire on these) ─────────────
    m.insert("01-missing-blocklist.pol1.yaml", Accept); // go: reject (NoBlocklistSection)
    m.insert("02-empty-blocklist.pol1.yaml", Accept); // go: reject (EmptyBlocklist)
    m.insert("03-wildcard-fqdn.pol1.yaml", Accept); // go: reject (BadFQDN)
    m.insert("04-uppercase-fqdn.pol1.yaml", Accept); // go: reject (BadFQDN)
    m.insert("05-entry-missing-rung.pol1.yaml", Accept); // go: reject (EntryMissingFields)
    m.insert("06-entry-missing-reason.pol1.yaml", Accept); // go: reject (EntryMissingFields)
    m.insert("07-flow-blocklist.pol1.yaml", Accept); // go: reject (UnsupportedShape)
    m.insert("08-quoted-keys.pol1.yaml", Accept); // go: reject (NoBlocklistSection)

    // ── both REJECT — the TRUE lockstep case (identical bytes, reject on both) ─
    m.insert("09-anchor-alias-families.pol1.yaml", Reject(Syntax)); // go: reject (UnsupportedShape)

    // ── RUST rejects, GO accepts — POL-1 schema drift outside the blocklist the
    //    Go scanner never inspects (the Rust schema parser is the tripwire) ─────
    m.insert("10-unknown-tier.pol1.yaml", Reject(BadValue)); // go: accept
    m.insert("11-empty-family-tier.pol1.yaml", Reject(BadValue)); // go: accept
    m.insert(
        "12-entry-missing-provenance.pol1.yaml",
        Reject(MissingProvenance),
    ); // go: accept
    m.insert("13-missing-rung-guardrail.pol1.yaml", Reject(MissingRung)); // go: accept
    m.insert("14-bad-rung-token.pol1.yaml", Reject(BadRung)); // go: accept
    m.insert("15-multi-document.pol1.yaml", Reject(Syntax)); // go: accept
    m.insert("16-tab-indent.pol1.yaml", Reject(Syntax)); // go: accept

    // ── COMPOUND both REJECT — one artifact drifts BOTH reader surfaces at once
    //    (resolver-lock SHAPE + POL-1 SCHEMA) under INDEPENDENT causes: the Rust
    //    RejectKind and the Go sentinel name DIFFERENT failures on the SAME bytes,
    //    so neither reader can mask the other's error. Distinct from 09 (both
    //    reject for the SAME cause, Syntax). Each Rust row asserts its own SCHEMA
    //    kind; the Go mirror asserts its own SHAPE sentinel.
    //
    //    These four are the EXACT-SET rows: each declares the WHOLE distinct code
    //    set its bundle must carry (`RejectExact`), not merely one code present
    //    (`Reject`). Presence-only is too weak HERE — a regression that ADDED a
    //    spurious extra rejection cause to one of these compound bundles would
    //    still satisfy `has(code)` and pass silently; the exact-set arm fails the
    //    fixture if ANY code outside the declared set appears. Rows 20-23 declare
    //    SINGLETON sets (each schema drift surfaces one cause CLASS; fixture 22
    //    emits `MissingProvenance` twice — benign duplication of an already-declared
    //    cause, deduped by the set comparison), so their bite is exactly "no NEW
    //    cause class crept in." Row 27 is the FIRST genuine MULTI-ELEMENT exact set
    //    on committed data: ONE document collects TWO distinct cause classes
    //    (`BadValue` for the unknown family tier AND `MissingProvenance` for the
    //    provenance-less entry), proving the multi-element comparison path bites on
    //    a COMMITTED bundle — until now it was exercised only under scratch
    //    mutation, since rows 20-23 are singletons. ──────────────────────────────
    m.insert(
        "20-quoted-key-unknown-tier.pol1.yaml",
        RejectExact(&[BadValue]),
    ); // go: reject (NoBlocklistSection)
    m.insert(
        "21-flow-blocklist-bad-guardrail-rung.pol1.yaml",
        RejectExact(&[BadRung]),
    ); // go: reject (UnsupportedShape)
    m.insert(
        "22-entry-missing-reason-missing-provenance.pol1.yaml",
        RejectExact(&[MissingProvenance]),
    ); // go: reject (EntryMissingFields)
    m.insert(
        "23-uppercase-fqdn-missing-guardrail-rung.pol1.yaml",
        RejectExact(&[MissingRung]),
    ); // go: reject (BadFQDN)
       // Row 27 — the FIRST MULTI-ELEMENT RejectExact set on committed data. ONE
       // artifact co-collects TWO INDEPENDENT POL-1 SCHEMA causes: BadValue for the
       // unknown `core` family tier (`turbo`) AND MissingProvenance for the
       // provenance-less baseline-pack entry. parse_layer COLLECT-ALLs both (§8.1):
       // build_pack pushes BadValue without short-circuiting, validate_layer pushes
       // MissingProvenance, and parse_layer appends the validate bundle onto the build
       // bundle. The Go scanner rejects the uppercase blocklist FQDN (ErrBadFQDN) — a
       // third, INDEPENDENT cause on the resolver-lock SHAPE surface it owns. This is
       // the committed proof the exact-set bite distinguishes {BadValue,
       // MissingProvenance} from a regression that dropped or added a code.
    m.insert(
        "27-uppercase-fqdn-unknown-tier-missing-provenance.pol1.yaml",
        RejectExact(&[BadValue, MissingProvenance]),
    ); // go: reject (BadFQDN)

    // ── COMPOUND both ACCEPT — the complement of 20-23: one artifact exercises
    //    BOTH reader surfaces at once (resolver-lock SHAPE + POL-1 SCHEMA) under
    //    INDEPENDENT benign axes, and BOTH accept. Each Rust row is a benign SCHEMA
    //    variation (provenanced entry, valid guardrail rung, valid family tier)
    //    paired with a Go-benign SHAPE variation (the 17/18/19 classes) on the SAME
    //    bytes. Pins benign acceptance across both axes so a regression that started
    //    REJECTING a benign compound on EITHER reader is caught (a fixture wired on
    //    one side only fails the other side's coverage gate). ────────────────────
    m.insert("24-duplicate-fqdn-provenanced-entry.pol1.yaml", Accept); // go: accept (benign dup)
    m.insert("25-reordered-families-guardrail-rung.pol1.yaml", Accept); // go: accept (reordered families)
    m.insert("26-comment-only-guardrails-enabled-tier.pol1.yaml", Accept); // go: accept (comment-only guardrails)

    m
}

/// The sorted set of fixture filenames present on disk (`*.pol1.yaml`; the
/// `.provenance` sidecars are excluded). Ground truth for the coverage check.
fn list_corpus_fixtures() -> Vec<String> {
    let dir = corpus_dir();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading the drift corpus dir {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".pol1.yaml"))
        .collect();
    assert!(
        !names.is_empty(),
        "the drift corpus at {} is empty — expected the shared drifted-pack fixtures \
         both readers walk",
        dir.display()
    );
    names.sort();
    names
}

/// The canonical repo-root-relative suffix both readers verify their resolved path
/// against (the Rust half).  The Go reader asserts the mirror via
/// `CorpusFixturesCanonicalSuffix` in `resolverlock.go`.  Keeping the two strings
/// identical is the coupling pin: if the corpus moves and only ONE reader's path
/// constant is updated, the OTHER reader's `corpus_path_identity` (or
/// `TestCorpusPathIdentity`) test fails loudly.
const CORPUS_CANONICAL_SUFFIX: &str =
    "assurance/conformance-adapter/resolverlock/testdata/drift-corpus/fixtures";

/// The Rust half of the coupling assertion: verifies that `corpus_dir()` resolves
/// to a path whose canonical suffix matches `CORPUS_CANONICAL_SUFFIX` (the single
/// declared corpus location) and that the directory actually exists.
///
/// The Go test `TestCorpusPathIdentity` (in `drift_corpus_test.go`) enforces the
/// mirror on its side with the SAME canonical suffix string.
///
/// A corpus move that updates only `pack_drift_corpus.rs` (without updating
/// `resolverlock.go`) fails the Go test.  A move that updates only `resolverlock.go`
/// fails THIS test.  A move that updates neither fails both readers' directory-not-
/// found panics.  Any of the three cases is loud — the coupling gap this task closes.
#[test]
fn corpus_path_identity() {
    let dir = corpus_dir();
    // Canonicalize the path to resolve any symlinks, then convert to forward-slash
    // for a portable suffix check.
    let canonical = dir.canonicalize().unwrap_or_else(|e| {
        panic!(
            "corpus_dir() resolved to {} which cannot be canonicalized: {} \
                 (coupling assertion: both readers must reach the SAME live corpus; \
                 a corpus move or a path-constant change must update BOTH readers — \
                 this file AND assurance/conformance-adapter/resolverlock/resolverlock.go)",
            dir.display(),
            e
        )
    });
    let path_str = canonical.to_string_lossy().replace('\\', "/");
    assert!(
        path_str.ends_with(CORPUS_CANONICAL_SUFFIX),
        "corpus_dir() resolved to {path_str:?}, which does NOT end with the canonical \
         corpus suffix {CORPUS_CANONICAL_SUFFIX:?} — the Go and Rust readers must both \
         resolve to the SAME corpus location; a corpus move or a path-constant change \
         must update BOTH readers (this file AND assurance/conformance-adapter/\
         resolverlock/resolverlock.go) to keep the coupling assertion green"
    );
}

/// Walk the shared corpus and assert the RUST column of every fixture's
/// `(go, rust)` verdict pair against the SAME bytes the Go test reads. An accept
/// fixture parses with zero `PolicyError`s; a `Reject` fixture surfaces the NAMED
/// `PolicyErrorCode` SOMEWHERE in its collected bundle (presence); a `RejectExact`
/// fixture's bundle DISTINCT code set must EQUAL the declared set (no extra cause).
/// Asserted per class (not in bulk), so a fixture that drifted to a different
/// verdict than declared names itself.
#[test]
fn drift_corpus_rust_verdicts() {
    let dir = corpus_dir();
    let table = rust_corpus_expectations();
    for name in list_corpus_fixtures() {
        let Some(want) = table.get(name.as_str()) else {
            // Coverage is asserted in the dedicated test below; skip the body so
            // that test owns the fail-closed message.
            continue;
        };
        let path = dir.join(&name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading corpus fixture {}: {e}", path.display()));
        let result = parse_layer(&text);
        match want {
            RustVerdict::Accept => {
                assert!(
                    result.is_ok(),
                    "fixture {name} must ACCEPT on the Rust schema reader (it is a \
                     well-formed-or-Rust-benign shape), got reject: {:?}",
                    result.err()
                );
            }
            RustVerdict::Reject(code) => {
                let errs = match result {
                    Ok(_) => panic!(
                        "fixture {name} must REJECT on the Rust schema reader (drift class \
                         {:?}), got a clean accept — silent acceptance of a malformed shape \
                         is the failure this corpus exists to catch",
                        class_of(&name)
                    ),
                    Err(e) => e,
                };
                assert!(
                    errs.has(*code),
                    "fixture {name}: Rust reader rejected for the WRONG reason — want code \
                     {code:?} in the bundle, got {errs}"
                );
            }
            RustVerdict::RejectExact(codes) => {
                let errs = match result {
                    Ok(_) => panic!(
                        "fixture {name} must REJECT on the Rust schema reader (compound drift \
                         class {:?}), got a clean accept — silent acceptance of a malformed \
                         shape is the failure this corpus exists to catch",
                        class_of(&name)
                    ),
                    Err(e) => e,
                };
                // EXACT-SET bite: build the SORTED, distinct collected code set from
                // the bundle's public `PolicyErrors(pub Vec<PolicyError>)` field
                // (each `PolicyError` exposes a public `code`) and assert it equals
                // the declared set. Unlike `errs.has(code)`, this FAILS if the bundle
                // carries ANY code outside the declared set — so a regression that
                // ADDED a spurious extra rejection cause to a compound fixture (which
                // a presence-only check would still pass) is caught here.
                let got = sorted_code_labels(errs.0.iter().map(|e| &e.code));
                let want = sorted_code_labels(codes.iter());
                assert_eq!(
                    got, want,
                    "fixture {name}: Rust reader's compound bundle code SET drifted — want \
                     exactly {want:?} (no more, no less), got {got:?}. The compound both-reject \
                     fixtures (20-23) declare INDEPENDENT causes; an extra cause class beyond \
                     the declared set means a spurious rejection crept in. Full bundle: {errs}"
                );
            }
        }
    }
}

/// The fail-closed coverage gate (the RUST half). Reconciles the fixtures ON DISK
/// against the expectation table: every fixture must be registered, every
/// registered key must exist on disk, and the counts must match exactly. A fixture
/// added to the corpus directory for the Go reader (or anyone) without a Rust
/// expectation row fails HERE — so a fixture added for one reader fails the other
/// until BOTH tables list it. The Go test enforces the identical reconciliation.
#[test]
fn drift_corpus_coverage_lockstep() {
    let on_disk = list_corpus_fixtures();
    let table = rust_corpus_expectations();

    for name in &on_disk {
        assert!(
            table.contains_key(name.as_str()),
            "corpus fixture {name} has NO Rust verdict expectation — every shared fixture \
             must be wired into rust_corpus_expectations (lockstep fail-closed: a fixture \
             added for one reader must be wired on both)"
        );
    }
    for name in table.keys() {
        assert!(
            on_disk.iter().any(|d| d == name),
            "rust_corpus_expectations lists {name} but no such fixture exists on disk \
             (stale expectation — deleting a fixture must drop its row here)"
        );
    }
    assert_eq!(
        table.len(),
        on_disk.len(),
        "drift-corpus count mismatch: {} fixtures on disk, {} Rust expectations — the Rust \
         reader's coverage must enumerate the corpus exactly (lockstep fail-closed)",
        on_disk.len(),
        table.len()
    );
}

/// SINGLE-SOURCE enumeration of the `PolicyErrorCode` universe. This macro takes ONE
/// comma-separated list of variants and emits, from that ONE list, BOTH lockstep
/// halves so they CANNOT drift from each other:
///
///   * [`code_canonical_label`] — the COMPILE-TIME completeness anchor: an EXHAUSTIVE
///     `match` over `ds_contracts::pol1::PolicyErrorCode` with one arm PER variant and
///     NO wildcard arm. When a new variant is added to
///     `dataplane/crates/ds-contracts/src/pol1.rs`, the macro-emitted match stops
///     compiling (`error[E0004]: non-exhaustive patterns: ... not covered`) and the
///     build of this test crate FAILS until the variant is added to the ONE list below
///     — a stronger bite than any runtime check, since the universe can never drift
///     from the enum and still compile. The arm maps each variant to its own
///     `stringify!`'d name, i.e. its `Debug` label (the same total order
///     [`sorted_code_labels`] uses for the exact-set comparison).
///
///   * [`CODE_UNIVERSE`] — the universe `const` array, built arm-by-arm from the SAME
///     list, so each universe member is emitted right alongside its match arm. There
///     is NO second hand-kept variant list and NO hand-kept count: the universe size
///     is `CODE_UNIVERSE.len()`, derived. A variant added to the list lands in BOTH
///     the match and the universe automatically; a variant added to the enum but NOT
///     to the list breaks the exhaustive-match build before any runtime check runs.
///
/// This collapses what were THREE hand-synced tripwires (the match arms, a separate
/// `code_universe` slice, and an `EXPECTED_CODE_COUNT` literal) into ONE canonical
/// list. The exhaustive match REMAINS the source of truth (the compile-time bite); the
/// universe + count now DERIVE from the same enumeration.
macro_rules! policy_error_code_universe {
    ($($variant:ident),+ $(,)?) => {
        /// The COMPILE-TIME completeness anchor for the `PolicyErrorCode` universe —
        /// an EXHAUSTIVE, wildcard-free `match` mapping each variant to its `Debug`
        /// label. Emitted by [`policy_error_code_universe!`] from the single canonical
        /// variant list, alongside [`CODE_UNIVERSE`]. A new `ds_contracts` variant
        /// added to the enum but NOT to that list breaks THIS match's build (the
        /// primary lockstep bite); the runtime [`code_universe_matches_enum`] guard is
        /// the belt-and-suspenders that the universe array is exactly this arm set.
        fn code_canonical_label(code: PolicyErrorCode) -> &'static str {
            use PolicyErrorCode::*;
            // EXHAUSTIVE — the macro emits one arm per variant and NO `_ =>` wildcard.
            // The compiler enforcing this match covers every variant is exactly the
            // lockstep guard: a new ds_contracts variant must be added to the single
            // `policy_error_code_universe!` list (which feeds BOTH this match AND
            // `CODE_UNIVERSE`) or this test crate will not build.
            match code {
                $( $variant => stringify!($variant), )+
            }
        }

        /// The Rust-side UNIVERSE of `PolicyErrorCode`s the drift corpus scans for —
        /// the complete set of codes the verdict table (`rust_corpus_expectations`) may
        /// name in a `Reject` / `RejectExact` row and the exact-set bite reconciles
        /// against. The Rust mirror of the Go `exportedSentinelUniverse` table: the
        /// exact-set arm (`RejectExact`) is only as strong as this universe enumerating
        /// EVERY code the enum can produce, so a code added to
        /// `ds_contracts::PolicyErrorCode` but NOT scanned for would be invisible to the
        /// bite.
        ///
        /// DERIVED — emitted arm-by-arm from the SAME canonical variant list as the
        /// exhaustive [`code_canonical_label`] match by [`policy_error_code_universe!`],
        /// so it CANNOT drift from the match: every member here has a match arm and
        /// vice versa, by construction. Its length is the derived code count (no
        /// hand-kept literal). Kept honest by TWO interlocking guards:
        ///   * the COMPILE-TIME exhaustive [`code_canonical_label`] match (a new variant
        ///     breaks the build), and
        ///   * the runtime [`code_universe_matches_enum`] reconciliation (this array must
        ///     equal the exhaustive match's variant set, no more, no less — fail-closed,
        ///     naming any offending code).
        const CODE_UNIVERSE: &[PolicyErrorCode] = &[
            $( PolicyErrorCode::$variant, )+
        ];
    };
}

// The ONE canonical variant list — the single source feeding BOTH the exhaustive
// `code_canonical_label` match AND the `CODE_UNIVERSE` array (and thus the derived
// count). Mirror of `ds_contracts::pol1::PolicyErrorCode`; a variant added to that enum
// but not here breaks the exhaustive-match build.
policy_error_code_universe! {
    Syntax,
    BadPosture,
    BadLayer,
    BadRung,
    BadGuardrailClass,
    MissingRung,
    GenericRungCap,
    FailOpenIllegal,
    EscapeHatchBareAddress,
    MissingProvenance,
    BadValue,
    BadAddress,
}

/// Accessor for the macro-derived [`CODE_UNIVERSE`] array, preserved so the existing
/// call sites read unchanged. The universe is now a `const` built arm-by-arm from the
/// same canonical list as the exhaustive [`code_canonical_label`] match, so the two can
/// never diverge.
fn code_universe() -> &'static [PolicyErrorCode] {
    CODE_UNIVERSE
}

/// The fail-closed completeness guard for the `PolicyErrorCode` universe — the RUST
/// mirror of the Go `TestExportedSentinelUniverseComplete` sentinel-universe guard.
/// The landed exact-set assertion (`drift_corpus_rust_verdicts`'s `RejectExact` arm,
/// via `sorted_code_labels`) is only as strong as [`code_universe`] enumerating EVERY
/// `PolicyErrorCode` the `ds_contracts` enum can produce: a code added to the enum but
/// NOT to the universe would be invisible to the exact-set scan, silently weakening
/// the bite. This guard removes that gap, reconciling the [`code_universe`] table
/// against the COMPILE-TIME exhaustive [`code_canonical_label`] match BY VARIANT,
/// fail-closed in BOTH directions:
///
///   (a) a variant covered by the exhaustive match but ABSENT from [`code_universe`]
///       — the exact-set scan would never look for it, so a spurious extra cause
///       carrying it would slip through a `RejectExact` row. Caught here, named.
///   (b) a [`code_universe`] entry not covered by the exhaustive match (impossible
///       while the match is exhaustive and wildcard-free AND both are emitted from the
///       ONE `policy_error_code_universe!` list, but the duplicate check below still
///       catches a malformed list that REPEATS a code).
///
/// The PRIMARY bite is the COMPILE-TIME exhaustive match: when a variant is added to
/// `ds_contracts::PolicyErrorCode`, [`code_canonical_label`] stops compiling and this
/// whole test crate fails to build until the variant is wired into the SINGLE
/// `policy_error_code_universe!` list (which feeds BOTH the match and [`CODE_UNIVERSE`]).
/// This runtime guard is the belt-and-suspenders that proves the [`code_universe`] array
/// itself is the EXACT variant set the exhaustive match covers — neither short nor
/// padded with a duplicate. The universe + its count now DERIVE from that one list, so
/// there is no separate `code_universe` slice or `EXPECTED_CODE_COUNT` literal to drift.
///
/// Same lockstep-fail-closed ethos as the fixture coverage gate
/// (`drift_corpus_coverage_lockstep`): the assertion NAMES the offending code and
/// FAILS — it never skips.
#[test]
fn code_universe_matches_enum() {
    let universe = code_universe();

    // Every code in the universe must round-trip through the EXHAUSTIVE match (its
    // canonical label must equal its own Debug label) and must appear EXACTLY ONCE —
    // a duplicated row would let the count check below pass while masking an omission.
    let mut seen: BTreeMap<&'static str, usize> = BTreeMap::new();
    for code in universe {
        let label = code_canonical_label(*code);
        assert_eq!(
            label,
            format!("{code:?}"),
            "code_universe entry {code:?} maps to canonical label {label:?} in the exhaustive \
             code_canonical_label match, which disagrees with its Debug label — the exhaustive \
             match arm for this variant must label it by its own name so the universe reconciles \
             by variant"
        );
        *seen.entry(label).or_insert(0) += 1;
    }
    for (label, count) in &seen {
        assert_eq!(
            *count, 1,
            "code_universe lists PolicyErrorCode::{label} {count} times — each code must appear \
             exactly once so the exact-set scan (sorted_code_labels) ranges over a CLEAN universe; \
             a duplicate row would pad the count and mask a missing variant"
        );
    }

    // The COMPILE-TIME exhaustive match is the ground-truth variant set: build the set
    // of canonical labels it covers by feeding it EVERY universe code, then assert the
    // universe enumerates EXACTLY that set. Because code_canonical_label has NO wildcard
    // arm, the only way a variant exists in the enum is to have an arm here AND a row in
    // code_universe — so a new ds_contracts variant fails the BUILD (exhaustive match)
    // before this runtime check, and a universe row that lost its variant fails the
    // count parity below, named.
    //
    // We cannot iterate the enum's variants directly (no production-crate change to add
    // a strum/IntoEnumIterator derive is permitted), so the universe table IS the
    // declared variant list and the exhaustive match is what forces it complete: this
    // guard proves the table is internally consistent (every row a real variant, no
    // duplicates) and the build proves it is exhaustive over the enum.
    let universe_labels = sorted_code_labels(universe.iter());
    assert_eq!(
        universe_labels.len(),
        universe.len(),
        "code_universe has {} rows but only {} DISTINCT codes — the universe must be a clean set \
         with no duplicate variant (a duplicate masks a missing one in the count parity the \
         exact-set bite relies on)",
        universe.len(),
        universe_labels.len()
    );

    // DERIVED cardinality anchor: the universe size is `CODE_UNIVERSE.len()`, no longer
    // a hand-kept `EXPECTED_CODE_COUNT` literal that had to be bumped in lockstep with
    // the enum. Both the exhaustive `code_canonical_label` match AND `CODE_UNIVERSE` are
    // emitted from the ONE `policy_error_code_universe!` variant list, so they CANNOT
    // diverge: a variant added to `ds_contracts::PolicyErrorCode` but not to that list
    // fails the exhaustive-match BUILD before this runtime guard ever runs, and a variant
    // added to the list lands in BOTH the match and the universe (and thus this derived
    // count) atomically. The distinct-set parity above is the residual runtime bite —
    // it catches a malformed list that REPEATS a variant (which would pad the count and
    // mask an omission). The count below is asserted positive so the guard can never run
    // vacuously over an empty universe (e.g. if the macro list were emptied).
    assert!(
        !universe.is_empty(),
        "code_universe (CODE_UNIVERSE) is EMPTY — the single-source policy_error_code_universe! \
         list must enumerate every ds_contracts::pol1::PolicyErrorCode variant; an empty universe \
         would make the exact-set scan (sorted_code_labels) range over nothing and silently \
         disarm the RejectExact bite"
    );
    assert_eq!(
        universe.len(),
        CODE_UNIVERSE.len(),
        "code_universe accessor and CODE_UNIVERSE disagree on length — the accessor must return \
         the macro-derived single-source array unchanged"
    );
}

/// Reconcile the verdict table's NAMED codes against the [`code_universe`]: every
/// `PolicyErrorCode` a `Reject` / `RejectExact` row names MUST be a member of the
/// universe the exact-set bite scans for. Without this, a verdict row could name a
/// code the universe omitted — the exact-set comparison would still pass (it compares
/// the bundle's codes against the declared row), but the universe completeness guard
/// would be silently bypassed for that code. This pins the verdict table INSIDE the
/// reconciled universe, so the [`code_universe_matches_enum`] lockstep covers every
/// code the corpus actually asserts on.
#[test]
fn verdict_table_codes_are_in_universe() {
    let universe: Vec<PolicyErrorCode> = code_universe().to_vec();
    let universe_labels: Vec<String> = sorted_code_labels(universe.iter());
    for (fixture, verdict) in rust_corpus_expectations() {
        for code in declared_codes(&verdict) {
            assert!(
                universe_labels.contains(&format!("{code:?}")),
                "fixture {fixture} names PolicyErrorCode::{code:?} in its verdict, but that code is \
                 NOT in code_universe — the exact-set bite (RejectExact) scans for the universe, so \
                 a verdict naming a code outside it escapes the universe completeness guard. Add the \
                 code to the exhaustive code_canonical_label match AND code_universe"
            );
        }
    }
}

/// Strip the `NN-` prefix and `.pol1.yaml` suffix to recover the drift-class label
/// for messages (e.g. `09-anchor-alias-families.pol1.yaml` ->
/// `anchor-alias-families`).
fn class_of(fixture: &str) -> String {
    let base = fixture.strip_suffix(".pol1.yaml").unwrap_or(fixture);
    let bytes = base.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2] == b'-'
    {
        base[3..].to_string()
    } else {
        base.to_string()
    }
}

/// Parse a single named corpus fixture through the FULL POL-1 schema reader
/// [`parse_layer`], reading the SAME bytes the verdict walk reads (the shared
/// corpus, no per-language copy). The fixture MUST accept — this helper is used
/// only by the both-ACCEPT premise below, and a reject here is a hard failure
/// (the fixture would not be a valid accept-side premise input), reported with
/// the collected bundle so a regression names itself.
fn parse_accepting_fixture(name: &str) -> PolicyLayer {
    let path = corpus_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading corpus fixture {}: {e}", path.display()));
    parse_layer(&text).unwrap_or_else(|errs| {
        panic!(
            "fixture {name} must ACCEPT on the Rust schema reader for the parse-equivalence \
             premise (it is a both-ACCEPT corpus row), got reject: {errs}"
        )
    })
}

/// The PARSE-EQUIVALENCE premise for the compound both-ACCEPT pairs (25 vs 18,
/// 26 vs 19). The wave-1 corpus walk (`drift_corpus_rust_verdicts`) pins only
/// Ok-NESS for these rows: it proves each parses without a `PolicyError`, but it
/// never looks INSIDE the parsed [`PolicyLayer`]. So a Rust regression that kept
/// the compound ACCEPT yet silently DROPPED or PERTURBED one benign-axis content
/// ONLY in the compound presence of the other axis would still satisfy that
/// Ok-only gate. This premise closes that gap — the symmetric companion of the
/// wave-1 Go premise, which pinned the OTHER half (that the Go LINE SCANNER is
/// blind to the `baseline_pack.families` / `guardrails` sections).
///
/// Each compound fixture is the both-ACCEPT join of a single-axis sibling and one
/// EXTRA, INDEPENDENT benign axis on ONE artifact:
///
///   * 25 (reordered-families + valid guardrail rung) joins 18 (reordered-families)
///     with a guardrail rule carrying a valid `rung`. The SHARED benign axis is the
///     reordered `baseline_pack.families` mapping; the COMPOUND-ONLY axis is the
///     guardrail rung on `guardrails`.
///   * 26 (comment-only-guardrails + enabled family tier) joins 19 (comment-only-
///     families) with a `baseline_pack` family carrying a valid `tier: enabled`. The
///     SHARED benign axis is the comment-stripped-to-EMPTY `guardrails` sequence
///     (plus the intact `blocklist`); the COMPOUND-ONLY axis is the family `Tier`.
///
/// For each pair this asserts, over STABLE PUBLIC PROJECTIONS of the fully-`pub`
/// [`PolicyLayer`] (typed views with `PartialEq`/`Eq` — `baseline_pack.families:
/// BTreeMap<String, Tier>`, `guardrails: Vec<GuardrailRule>`, `blocklist:
/// Vec<BlockEntry>` — NOT `Debug` dumps):
///
///   (a) BOTH accept (via [`parse_accepting_fixture`]);
///   (b) the parsed projections AGREE wherever the EXTRA benign axis must NOT
///       perturb them (the compound parse equals the sibling parse on that axis);
///   (c) the COMPOUND-ONLY axis (the guardrail rung / the family tier) SURVIVES
///       into the parsed structure EXACTLY AS DECLARED — it is neither dropped nor
///       perturbed by the presence of the other benign axis.
///
/// Asserting (b) and (c) is what bites where the Ok-only walk cannot: dropping the
/// guardrail from 25 (but not its sibling-shared family reorder), or perturbing /
/// dropping the `core` family tier in 26 (but not its sibling-shared empty
/// guardrails), keeps the ACCEPT yet breaks this premise.
#[test]
fn compound_accept_parse_equivalence_premise() {
    // ── 25 vs 18 — SHARED axis: reordered `baseline_pack.families`; COMPOUND-ONLY
    //    axis: the guardrail rung on `guardrails`. ─────────────────────────────
    let p25 = parse_accepting_fixture("25-reordered-families-guardrail-rung.pol1.yaml");
    let p18 = parse_accepting_fixture("18-reordered-families.pol1.yaml");

    // (b) The reordered families mapping is the SHARED benign axis: the compound's
    //     `BTreeMap` projection (order-insensitive by construction) must EQUAL the
    //     single-axis sibling's. The added guardrail must NOT perturb the families
    //     mapping. Drop or perturb a family only-when-a-guardrail-is-present and
    //     this disagrees.
    assert_eq!(
        p25.baseline_pack.families, p18.baseline_pack.families,
        "compound 25 vs sibling 18: the reordered `baseline_pack.families` projection \
         (the SHARED benign axis) must AGREE — the extra guardrail-rung axis present only \
         in 25 must NOT perturb the order-insensitive families mapping. 25 families: {:?}, \
         18 families: {:?}",
        p25.baseline_pack.families, p18.baseline_pack.families
    );
    // The sibling shares 25's blocklist too; pin it so a perturbation of the shared
    // resolver-lock shape in the compound presence is caught here as well.
    assert_eq!(
        p25.blocklist, p18.blocklist,
        "compound 25 vs sibling 18: the shared `blocklist` projection must AGREE — the \
         compound-only guardrail-rung axis must not perturb it"
    );

    // (c) The COMPOUND-ONLY axis — the guardrail rung — must SURVIVE into the parsed
    //     structure AS DECLARED. 18 has NO guardrails (empty `Vec`); 25 declares
    //     exactly one rule whose rung is the declared `block+log`. A regression that
    //     dropped the guardrail in the compound presence would empty this `Vec` and
    //     fail here while the Ok-only walk still passes.
    assert!(
        p18.guardrails.is_empty(),
        "sibling 18 must declare NO guardrails (the compound-only axis is absent in the \
         single-axis sibling), got {:?}",
        p18.guardrails
    );
    assert_eq!(
        p25.guardrails.len(),
        1,
        "compound 25 must carry its ONE declared guardrail rule (the compound-only axis) \
         through parse, got {} rule(s): {:?}",
        p25.guardrails.len(),
        p25.guardrails
    );
    assert_eq!(
        p25.guardrails[0].rung,
        Rung::BlockLog,
        "compound 25: the guardrail rung (the compound-only axis) must SURVIVE parse AS \
         DECLARED (`block+log` -> Rung::BlockLog), got {:?}",
        p25.guardrails[0].rung
    );

    // ── 26 vs 19 — SHARED axis: comment-stripped-to-EMPTY `guardrails` (plus the
    //    intact `blocklist`); COMPOUND-ONLY axis: the `core` family `Tier`. ──────
    let p26 = parse_accepting_fixture("26-comment-only-guardrails-enabled-tier.pol1.yaml");
    let p19 = parse_accepting_fixture("19-comment-only-families.pol1.yaml");

    // (b) The comment-only guardrails block parses to an EMPTY sequence on BOTH
    //     sides (19 declares no guardrails; 26's are comment-only) — the SHARED
    //     benign axis. The added family tier must NOT perturb the guardrails
    //     projection. The intact blocklist is shared too.
    assert_eq!(
        p26.guardrails, p19.guardrails,
        "compound 26 vs sibling 19: the `guardrails` projection (the SHARED benign axis — \
         comment-stripped to EMPTY on both) must AGREE; the compound-only family-tier axis \
         must not perturb it. 26 guardrails: {:?}, 19 guardrails: {:?}",
        p26.guardrails, p19.guardrails
    );
    assert!(
        p26.guardrails.is_empty(),
        "compound 26: the comment-only `guardrails` block must strip to an EMPTY sequence \
         (a comment-only block yields no rules), got {:?}",
        p26.guardrails
    );
    assert_eq!(
        p26.blocklist, p19.blocklist,
        "compound 26 vs sibling 19: the shared `blocklist` projection must AGREE — the \
         compound-only family-tier axis must not perturb it"
    );

    // (c) The COMPOUND-ONLY axis — the `core` family `Tier` — must SURVIVE into the
    //     parsed `baseline_pack.families` map AS DECLARED. 19 has comment-only (EMPTY)
    //     families; 26 declares `core: { tier: enabled }`. A regression that dropped
    //     or perturbed the family tier in the compound presence would change this
    //     projection while the Ok-only walk still passes.
    assert!(
        p19.baseline_pack.families.is_empty(),
        "sibling 19 must parse its comment-only families to an EMPTY map (the compound-only \
         axis is absent in the single-axis sibling), got {:?}",
        p19.baseline_pack.families
    );
    let mut want_families: BTreeMap<String, Tier> = BTreeMap::new();
    want_families.insert("core".to_string(), Tier::Enabled);
    assert_eq!(
        p26.baseline_pack.families, want_families,
        "compound 26: the family tier (the compound-only axis) must SURVIVE parse AS \
         DECLARED (`core: {{ tier: enabled }}` -> {{core: Enabled}}), got {:?}",
        p26.baseline_pack.families
    );
}

/// The declared Rust cause set of a single expectation row, as a code `Vec`. A
/// [`RustVerdict::Reject`] single-axis sibling carries exactly ONE cause; a
/// [`RustVerdict::Accept`] sibling is Rust-BENIGN and contributes ZERO causes (its
/// drift bites only the Go SHAPE surface, never the Rust SCHEMA reader); a
/// [`RustVerdict::RejectExact`] compound carries its WHOLE declared set. The helper
/// below projects each over [`sorted_code_labels`] so the compound==union(siblings)
/// comparison is a deterministic, total-ordered set diff.
fn declared_codes(v: &RustVerdict) -> Vec<PolicyErrorCode> {
    match v {
        RustVerdict::Accept => Vec::new(),
        RustVerdict::Reject(code) => vec![*code],
        RustVerdict::RejectExact(codes) => codes.to_vec(),
    }
}

/// The compound -> (single-axis sibling, single-axis sibling, …) map, transcribed
/// from the INLINE-COMMENT sibling annotations on rows 20-23 and 27 of
/// [`rust_corpus_expectations`]. Each compound fixture is the BOTH-REJECT join of
/// independent single-axis drifts on ONE artifact; this map names, per compound,
/// the single-axis sibling FIXTURES whose drifts it composes. The invariant the
/// test below machine-checks is: a compound's declared `RejectExact` cause SET
/// equals the UNION of its siblings' declared Rust cause sets (each Rust-rejecting
/// sibling contributing its one cause, each Rust-benign sibling contributing none),
/// with the compound-only cause(s) surviving the merge.
///
/// The sibling decomposition, verified against the expectation table:
///
///   * 20 `quoted-key-unknown-tier` = 08 `quoted-keys` (Rust-benign; Go rejects
///     NoBlocklistSection) ∪ 10 `unknown-tier` (Rust `BadValue`)
///     => union {BadValue} == row 20's RejectExact set.
///   * 21 `flow-blocklist-bad-guardrail-rung` = 07 `flow-blocklist` (Rust-benign;
///     Go rejects UnsupportedShape) ∪ 14 `bad-rung-token` (Rust `BadRung`)
///     => union {BadRung} == row 21's RejectExact set.
///   * 22 `entry-missing-reason-missing-provenance` = 06 `entry-missing-reason`
///     (Rust-benign; Go rejects EntryMissingFields) ∪ 12
///     `entry-missing-provenance` (Rust `MissingProvenance`)
///     => union {MissingProvenance} == row 22's RejectExact set.
///   * 23 `uppercase-fqdn-missing-guardrail-rung` = 04 `uppercase-fqdn` (Rust-
///     benign; Go rejects BadFQDN) ∪ 13 `missing-rung-guardrail` (Rust
///     `MissingRung`)
///     => union {MissingRung} == row 23's RejectExact set.
///   * 27 `uppercase-fqdn-unknown-tier-missing-provenance` = 04 `uppercase-fqdn`
///     (Rust-benign; Go rejects BadFQDN) ∪ 10 `unknown-tier` (Rust `BadValue`) ∪
///     12 `entry-missing-provenance` (Rust `MissingProvenance`)
///     => union {BadValue, MissingProvenance} == row 27's MULTI-ELEMENT
///     RejectExact set (the two Rust-rejecting siblings each supply ONE cause).
fn compound_sibling_map() -> BTreeMap<&'static str, Vec<&'static str>> {
    let mut m: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
    m.insert(
        "20-quoted-key-unknown-tier.pol1.yaml",
        vec!["08-quoted-keys.pol1.yaml", "10-unknown-tier.pol1.yaml"],
    );
    m.insert(
        "21-flow-blocklist-bad-guardrail-rung.pol1.yaml",
        vec!["07-flow-blocklist.pol1.yaml", "14-bad-rung-token.pol1.yaml"],
    );
    m.insert(
        "22-entry-missing-reason-missing-provenance.pol1.yaml",
        vec![
            "06-entry-missing-reason.pol1.yaml",
            "12-entry-missing-provenance.pol1.yaml",
        ],
    );
    m.insert(
        "23-uppercase-fqdn-missing-guardrail-rung.pol1.yaml",
        vec![
            "04-uppercase-fqdn.pol1.yaml",
            "13-missing-rung-guardrail.pol1.yaml",
        ],
    );
    m.insert(
        "27-uppercase-fqdn-unknown-tier-missing-provenance.pol1.yaml",
        vec![
            "04-uppercase-fqdn.pol1.yaml",
            "10-unknown-tier.pol1.yaml",
            "12-entry-missing-provenance.pol1.yaml",
        ],
    );
    m
}

/// MACHINE-CHECK the compound/sibling cause-set invariant that rows 20-23 and 27
/// previously asserted only in hand-written INLINE COMMENTS: each COMPOUND both-
/// reject row's declared `RejectExact` cause SET must equal the UNION of its single-
/// axis siblings' declared Rust cause sets (the compound-only cause surviving the
/// merge). Before this test the relationship was prose only — a mis-declared
/// multi-element set (e.g. row 27's `RejectExact(&[BadValue, MissingProvenance])`
/// gaining or losing a code) could slip past author-time; this closes that gap.
///
/// For each compound in [`compound_sibling_map`] the test:
///   1. confirms the compound row is a `RejectExact` (the EXACT-SET arm — a presence-
///      only `Reject` here would silently weaken the multi-element bite);
///   2. confirms each named sibling EXISTS in the expectation table (a renamed or
///      dropped sibling fails LOUDLY here, naming the missing key);
///   3. unions the siblings' declared Rust cause sets and asserts, over
///      [`sorted_code_labels`] for a deterministic diff, that it EQUALS the
///      compound's declared `RejectExact` set — naming the compound row and BOTH
///      sides of the mismatch on divergence.
///
/// This is ADDITIVE: it neither parses fixtures nor touches the verdict walk, the
/// lockstep coverage gate, or the parse-equivalence premise. It asserts a property
/// of the TABLE itself, so it bites at author-time the instant a compound's declared
/// set drifts from its siblings' union (in EITHER direction — a dropped cause or a
/// spurious extra cause).
#[test]
fn compound_reject_set_is_union_of_siblings() {
    let table = rust_corpus_expectations();
    let sibling_map = compound_sibling_map();

    for (compound, siblings) in &sibling_map {
        let compound_verdict = table.get(compound).unwrap_or_else(|| {
            panic!(
                "compound row {compound} is named in compound_sibling_map but has NO entry in \
                 rust_corpus_expectations — the compound/sibling invariant references a row that \
                 does not exist (a rename or drop must update BOTH tables)"
            )
        });

        // (1) The compound MUST be a RejectExact: the union-of-siblings invariant is
        //     a property of the EXACT cause SET. A presence-only Reject (or an Accept)
        //     in the compound slot means the exact-set bite was silently dropped.
        assert!(
            matches!(compound_verdict, RustVerdict::RejectExact(_)),
            "compound row {compound} must declare a RejectExact cause SET (it is a COMPOUND \
             both-reject row whose set must equal the union of its single-axis siblings), but \
             its verdict is {compound_verdict:?} — a presence-only Reject or an Accept here \
             silently weakens the exact-set bite the compound/sibling invariant depends on"
        );

        // (2)+(3) Union the siblings' declared Rust cause sets. Each named sibling
        //         MUST exist in the expectation table; a Rust-rejecting sibling
        //         contributes its one cause, a Rust-benign (Accept) sibling
        //         contributes none.
        let mut union_codes: Vec<PolicyErrorCode> = Vec::new();
        for sibling in siblings {
            let sibling_verdict = table.get(sibling).unwrap_or_else(|| {
                panic!(
                    "compound row {compound} names sibling {sibling} in compound_sibling_map, \
                     but {sibling} has NO entry in rust_corpus_expectations — a renamed or \
                     dropped sibling fixture must update the sibling map (fail-closed)"
                )
            });
            union_codes.extend(declared_codes(sibling_verdict));
        }

        let got = sorted_code_labels(union_codes.iter());
        let want = sorted_code_labels(declared_codes(compound_verdict).iter());
        assert_eq!(
            got, want,
            "compound row {compound}: its declared RejectExact cause SET {want:?} does NOT equal \
             the UNION of its single-axis siblings' declared Rust cause sets {got:?} (siblings: \
             {siblings:?}). The compound both-reject fixtures (20-23, 27) compose INDEPENDENT \
             single-axis drifts on ONE artifact; the compound's cause set must be exactly the \
             union of its siblings' causes (the compound-only cause surviving) — a divergence \
             means the declared set gained or lost a code relative to the siblings it composes"
        );
    }
}

/// Parse a single named corpus fixture through the FULL POL-1 schema reader
/// [`parse_layer`] and return its SORTED, DISTINCT collected `PolicyErrorCode`
/// label set — the runtime cause set the bundle actually carries, read off the
/// public `PolicyErrors(pub Vec<PolicyError>)` field (each `PolicyError` exposes a
/// public `code`) via [`sorted_code_labels`]. The fixture MUST reject — this helper
/// feeds the reject-equivalence premise below, and an ACCEPT here is a hard failure
/// (the fixture would not be a valid reject-side premise input). Mirrors
/// [`parse_accepting_fixture`] on the reject side: that helper projects the parsed
/// STRUCTURE, this one projects the parsed ERROR-CODE SET.
fn parse_rejecting_fixture_codes(name: &str) -> Vec<String> {
    let path = corpus_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading corpus fixture {}: {e}", path.display()));
    match parse_layer(&text) {
        Ok(_) => panic!(
            "fixture {name} must REJECT on the Rust schema reader for the reject-equivalence \
             premise (it is a both-REJECT / Rust-rejecting corpus row), got a clean accept — \
             silent acceptance of a malformed shape is the failure this corpus exists to catch"
        ),
        Err(errs) => sorted_code_labels(errs.0.iter().map(|e| &e.code)),
    }
}

/// Collect ALL the Rust-SCHEMA-rejecting siblings of a compound both-reject row from
/// its [`compound_sibling_map`] entry — the siblings whose verdict is `Reject` /
/// `RejectExact` (the schema axes the compound shares with THIS reader), in entry
/// order. The Go-rejecting / Rust-BENIGN shape siblings (an `Accept` row on the Rust
/// column — their drift bites only the Go SHAPE surface) are filtered out: they
/// contribute no Rust schema cause to the union.
///
/// This is the ONE resolver the data-driven reject-equivalence premise drives BOTH the
/// singleton and the multi-element compounds off. A SINGLETON compound (rows 20-23 —
/// each composes ONE schema sibling and one Rust-benign Go-shape sibling) resolves to a
/// ONE-element set, so the union over it collapses to that sibling's parsed cause set
/// (`parse(compound) == parse(sibling)`). Row 27 — the FIRST committed compound that
/// composes TWO schema siblings (10 `unknown-tier` → `BadValue` ∪ 12
/// `entry-missing-provenance` → `MissingProvenance`) plus the Rust-benign Go-shape
/// sibling (04 `uppercase-fqdn`) — resolves to a TWO-element set, so the union over it
/// is the multi-element `{BadValue, MissingProvenance}`. Returning the full set (rather
/// than insisting on exactly one) is what lets the SAME loop prove both arities. This
/// REUSES the EXISTING [`compound_sibling_map`] as the single source of truth (no second
/// hand-maintained map); the union premise feeds the resolved siblings through
/// [`parse_rejecting_fixture_codes`].
fn rust_schema_rejecting_siblings<'a>(
    siblings: &'a [&'static str],
    table: &BTreeMap<&'static str, RustVerdict>,
) -> Vec<&'a &'static str> {
    siblings
        .iter()
        .filter(|s| {
            matches!(
                table.get(**s),
                Some(RustVerdict::Reject(_)) | Some(RustVerdict::RejectExact(_))
            )
        })
        .collect()
}

/// The RUNTIME reject-equivalence premise for EVERY compound both-REJECT row — the
/// mirror of [`compound_accept_parse_equivalence_premise`] on the reject side, and the
/// PARSE-layer companion of the DECLARATION-level
/// [`compound_reject_set_is_union_of_siblings`].
///
/// ## The one proof shape, data-driven over the whole corpus
///
/// Every `RejectExact` compound in the corpus satisfies ONE invariant: its
/// cause set, PARSED FROM BYTES, equals the UNION over its Rust-SCHEMA-rejecting
/// siblings of each sibling's cause set, PARSED FROM BYTES. The SINGLETON compounds
/// (rows 20-23 — each composes ONE schema sibling and one Rust-benign Go-shape sibling)
/// are simply the 1-element-union special case: a union over a single sibling collapses
/// to that sibling's set, so `parse(compound) == parse(sibling)`. The MULTI-element
/// compound (row 27 — TWO schema siblings: 10 `unknown-tier` → `BadValue` ∪ 12
/// `entry-missing-provenance` → `MissingProvenance`) is the same union over two. This
/// test drives BOTH off the SAME `rust_schema_rejecting_siblings` resolver +
/// [`compound_sibling_map`] in a SINGLE loop, retiring the old singleton/union test
/// split AND the bespoke hardcoded `covered` array: the loop ENUMERATES every
/// `RejectExact` compound straight from [`rust_corpus_expectations`], so coverage
/// cannot drift behind a hand-maintained list — a `RejectExact` compound added to the
/// table is covered automatically (or fails fail-closed here if it lacks a sibling-map
/// entry).
///
/// ## Why this bites where the table-level checks cannot
///
/// The wave-1 corpus walk (`drift_corpus_rust_verdicts`) pins each compound's
/// `RejectExact` set against bytes, and `compound_reject_set_is_union_of_siblings` pins
/// the EXPECTATION TABLE's self-consistency (declared compound set == union of siblings'
/// DECLARED sets). But BOTH operate on DECLARED codes: nothing else asserts that the
/// compound, PARSED FROM BYTES, rejects with the SAME collected cause set — on the SAME
/// SCHEMA AXES — as the UNION of its schema siblings parsed from bytes. So a regression
/// that kept the reject yet RELOCATED or DROPPED a schema-axis cause ONLY in the
/// compound presence of the other (Go-shape) axis — while a declared-set mutation kept
/// the table consistent — would still pass the table-level check. This premise closes
/// that gap from the PARSED side, exercising the multi-element set comparison on
/// COMMITTED data (row 27) and the singleton case (rows 20-23) through one loop.
///
/// For each `RejectExact` compound this asserts, over the PARSED DISTINCT collected code
/// SETs (read off the bundles' bytes via [`parse_rejecting_fixture_codes`], NOT the
/// declared table rows):
///
///   (a) the compound and ALL its schema siblings REJECT (a clean accept is a hard
///       failure — the helper panics);
///   (b) the compound's parsed cause set EQUALS the UNION of its schema siblings' parsed
///       cause sets — the Go-shape axis present only in the compound neither CHANGED a
///       schema cause nor ADDED a new Rust cause, and EVERY schema cause survived the
///       merge; and
///   (c) the union is NON-VACUOUS — at least one schema sibling, each contributing a
///       NON-EMPTY set, so a both-empty (silent) equality cannot pass. (The committed
///       multi-element row 27 additionally yields a two-element union; the singletons
///       a one-element union — both non-empty.)
///
/// Asserting (b) and (c) bites where the table-level checks cannot: relocate or drop a
/// schema cause from a compound's parse (but not from its sibling), or surface an EXTRA
/// Rust cause only under the compound, and this premise goes red with an actionable
/// UNION-set diff while the declared-set / table checks stay green.
///
/// Kept SEPARATE from `compound_accept_parse_equivalence_premise`: that premise
/// projects PARSED STRUCTURES (`baseline_pack.families` / `guardrails` / `blocklist`),
/// this one projects PARSED ERROR-CODE SETS — different projection shapes that do not
/// cleanly factor onto one helper without weakening either side's assertions.
#[test]
fn compound_reject_parse_equivalence_premise() {
    let table = rust_corpus_expectations();
    let sibling_map = compound_sibling_map();

    // ENUMERATE every RejectExact compound straight from the verdict table — no
    // hardcoded `covered` list to drift behind the corpus. Each such compound is a
    // both-REJECT artifact whose parsed cause set must equal the UNION over its
    // Rust-SCHEMA-rejecting siblings of each sibling's parsed cause set. The singleton
    // compounds (rows 20-23) are the 1-sibling special case (union over one); the
    // multi-element compound (row 27) is the union over two.
    let reject_exact_compounds: Vec<&'static str> = table
        .iter()
        .filter(|(_, v)| matches!(v, RustVerdict::RejectExact(_)))
        .map(|(name, _)| *name)
        .collect();

    // Sanity: the corpus has at least the known committed RejectExact compounds, so a
    // table edit that accidentally emptied the RejectExact class (turning the whole
    // loop vacuous) fails LOUDLY rather than passing on zero iterations.
    assert!(
        !reject_exact_compounds.is_empty(),
        "rust_corpus_expectations declares NO RejectExact compound rows — the reject-equivalence \
         premise has nothing to enumerate; the compound both-reject corpus (rows 20-23, 27) must \
         carry RejectExact verdicts for the data-driven union proof to bite"
    );

    for compound in reject_exact_compounds {
        let siblings = sibling_map.get(compound).unwrap_or_else(|| {
            panic!(
                "RejectExact compound row {compound} has NO entry in compound_sibling_map — the \
                 data-driven reject-equivalence premise enumerates EVERY RejectExact compound from \
                 rust_corpus_expectations and resolves its schema siblings here; a compound without \
                 a sibling-map entry is an unproven cause set (fail-closed — wire its sibling \
                 decomposition into compound_sibling_map)"
            )
        });

        // Resolve the Rust-SCHEMA-rejecting siblings off the EXISTING
        // compound_sibling_map (the single source of truth — no duplicate map) via the
        // multi-sibling verdict-kind resolver. A singleton compound (20-23) resolves to
        // ONE schema sibling (its Go-shape sibling is Rust-benign and contributes
        // nothing); row 27 resolves to TWO. The union below ranges over whatever the
        // resolver returns, so the SAME loop handles both arities.
        let schema_siblings = rust_schema_rejecting_siblings(siblings, &table);
        assert!(
            !schema_siblings.is_empty(),
            "RejectExact compound row {compound} resolves to ZERO Rust-SCHEMA-rejecting siblings \
             in compound_sibling_map (its siblings {siblings:?} are all Rust-benign) — a both-reject \
             compound that rejects on the Rust schema reader MUST compose at least one schema \
             sibling whose cause it shares; the union premise cannot anchor its parsed cause set \
             against an empty sibling set"
        );

        // (a) the compound rejects, and project its PARSED distinct cause set off the
        //     bytes (the helper panics on a clean accept).
        let compound_codes = parse_rejecting_fixture_codes(compound);

        // (b)+(c) UNION the schema siblings' PARSED cause sets — read off the bytes, not
        //         the declared table. Each sibling MUST reject (helper panics on a clean
        //         accept) and MUST contribute a NON-EMPTY set, so the union is provably
        //         non-vacuous (the singleton case yields a one-element union; row 27 a
        //         two-element one).
        let mut union_codes: Vec<String> = Vec::new();
        for sibling in &schema_siblings {
            let sibling_codes = parse_rejecting_fixture_codes(sibling);
            assert!(
                !sibling_codes.is_empty(),
                "schema sibling {sibling} of compound {compound} parsed to an EMPTY cause set — a \
                 rejecting bundle must carry at least one PolicyErrorCode; the reject-equivalence \
                 premise cannot anchor a vacuous (empty-contribution) sibling in the union"
            );
            union_codes.extend(sibling_codes);
        }
        // Collapse the per-sibling sets into ONE sorted, distinct union set for the
        // compare (the same set discipline `sorted_code_labels` enforces, applied to the
        // already-sorted-distinct labels each sibling contributed).
        union_codes.sort();
        union_codes.dedup();

        // (c) the union must be NON-VACUOUS — a both-empty equality would be a silent
        //     pass. Guaranteed by the per-sibling non-empty checks above plus the
        //     non-empty sibling SET, but pinned explicitly so the proof's anchor is
        //     visible at the comparison site.
        assert!(
            !union_codes.is_empty(),
            "compound row {compound}: the UNION of its schema siblings' parsed cause sets is EMPTY \
             — a rejecting compound must share at least one non-empty schema cause with its \
             siblings; the reject-equivalence premise cannot anchor a vacuous comparison"
        );

        // (b) the compound's PARSED cause set must EQUAL the UNION of its schema
        //     siblings' PARSED cause sets. The Go-shape axis present only in the compound
        //     must neither change a schema cause nor add a new Rust cause; EVERY shared
        //     schema cause must survive the compound presence UNCHANGED. Relocating /
        //     dropping a cause only-under-the-compound (but not in its sibling), or
        //     surfacing an extra Rust cause only under the compound, fails HERE with the
        //     UNION-set diff — while the verdict / exact-set / declaration-level table
        //     (`compound_reject_set_is_union_of_siblings`) checks stay green.
        assert_eq!(
            compound_codes, union_codes,
            "compound {compound}: its PARSED collected cause set {compound_codes:?} does NOT equal \
             the UNION of its single-axis Rust-SCHEMA siblings' parsed cause sets {union_codes:?} \
             (schema siblings: {schema_siblings:?}). The compound joins its schema siblings' drifts \
             with a Rust-benign Go-shape axis on ONE artifact; EVERY shared SCHEMA cause must reject \
             IDENTICALLY (same codes, same axes) whether or not the Go-shape axis is present — a \
             divergence means a regression relocated, dropped, or added a Rust cause ONLY in the \
             compound presence of the other axis (a runtime drift the declared-set / table checks \
             cannot see)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS-1 union/exact-set HELPER-PINNING SWEEP (the RUST mirror of the Go
// orch64/orch66/orch69 helper-pinning sweep in
// `assurance/conformance-adapter/resolverlock/drift_corpus_test.go`).
//
// doc 06 §2.2 requires the Rust ds_contracts/POL-1 reader to model the SAME pack
// semantics in LOCKSTEP with the Go reader (ONE corpus, two readers). The Go side
// routes its union / exact-set membership / sibling-rejecting decisions through
// PINNED pure helpers (`sortedDistinctSentinels` / `unionSentinelSets`,
// `siblingRejectsOnGoColumn`, `nameReconciledAcrossSets`, `reconcileCorpusCoverage`)
// each carrying a `#[test]`-style self-test over SYNTHETIC inputs (D50 — no corpus
// fixture, no verdict pair touched), so the set/union/exact arithmetic the corpus
// premises depend on is proven by EXECUTION, not only by code reading.
//
// The Rust column already FACTORS those same decisions into pure helpers — the
// exact-set / union / dedup arithmetic in [`sorted_code_labels`], the per-row cause
// projection in [`declared_codes`], and the sibling-rejecting-on-the-Rust-column
// predicate in [`rust_schema_rejecting_siblings`]. What this sweep ADDS is the
// matching self-tests: it drives those EXISTING helpers (the very functions the
// `RejectExact` walk, `compound_reject_set_is_union_of_siblings`, and
// `compound_reject_parse_equivalence_premise` call) over SYNTHETIC inputs, so a
// future edit that weakened the union arithmetic (dropped a contribution, failed to
// dedupe an overlap, mis-ordered the merge), broke the per-row cause projection, or
// inverted the sibling-kind filter flips a self-test RED rather than silently
// changing the set the corpus premises compare against. This is ADDITIVE: it touches
// no fixture, no verdict pair, and no production premise — it pins the helpers those
// premises already share.
// ─────────────────────────────────────────────────────────────────────────────

/// Pin [`sorted_code_labels`] — the SORT + DISTINCT (set-collapse) arithmetic EVERY
/// set/union/exact-set comparison in this file routes through (the `RejectExact`
/// walk's `got`/`want`, `compound_reject_set_is_union_of_siblings`'s union, the
/// parse-side union premise's collapse). It is the Rust mirror of the Go
/// `sortedDistinctSentinels` / `unionSentinelSets` aggregation helper, and like that
/// helper it was previously proven only by code reading. This self-test drives it
/// over SYNTHETIC `PolicyErrorCode` inputs (D50) and pins the three properties the
/// premises rely on:
///
///   (1) SORTED — the output is the deterministic total order (`Debug` label
///       ascending), so two set-equal inputs in DIFFERENT orders compare EQUAL
///       (the contract-free total order the Ord-less enum needs);
///   (2) DISTINCT — duplicates collapse to ONE entry (fixture 22's twice-emitted
///       `MissingProvenance` is benign; a union that double-counted an overlap would
///       drift the compared set);
///   (3) the collapse is by VALUE, not by input multiplicity — N copies of one code
///       and one copy compare equal.
///
/// A near-miss (a missing or extra distinct code) is correctly EXCLUDED by the exact
/// set-equality the premises assert, exercised here directly.
#[test]
fn sorted_code_labels_is_sorted_distinct_set_collapse() {
    use PolicyErrorCode::*;

    // (1) SORTED + order-insensitive: the SAME set in two orders collapses to the
    //     SAME sorted label vector. (Debug labels sort lexicographically:
    //     "BadValue" < "MissingProvenance" < "Syntax".)
    let a = [Syntax, BadValue, MissingProvenance];
    let b = [MissingProvenance, Syntax, BadValue];
    assert_eq!(
        sorted_code_labels(a.iter()),
        sorted_code_labels(b.iter()),
        "sorted_code_labels must be order-insensitive — two set-equal inputs in different orders \
         must collapse to the SAME sorted label vector (the contract-free total order the Ord-less \
         PolicyErrorCode enum relies on for set equality)"
    );
    assert_eq!(
        sorted_code_labels(a.iter()),
        vec![
            "BadValue".to_string(),
            "MissingProvenance".to_string(),
            "Syntax".to_string()
        ],
        "sorted_code_labels must emit the ascending Debug-label order"
    );

    // (2) DISTINCT — a duplicated code (fixture 22's twice-emitted MissingProvenance
    //     shape) collapses to ONE entry, so a union does not double-count an overlap.
    let dup = [MissingProvenance, BadValue, MissingProvenance, BadValue];
    assert_eq!(
        sorted_code_labels(dup.iter()),
        vec!["BadValue".to_string(), "MissingProvenance".to_string()],
        "sorted_code_labels must DEDUPE — a code emitted twice (the benign fixture-22 duplication) \
         must appear once, so the set-collapse never inflates the compared cause set"
    );

    // (3) collapse-by-value: N copies of ONE code and a single copy compare EQUAL —
    //     the set ranges over DISTINCT codes, not input multiplicity.
    let many = [Syntax, Syntax, Syntax];
    let one = [Syntax];
    assert_eq!(
        sorted_code_labels(many.iter()),
        sorted_code_labels(one.iter()),
        "sorted_code_labels collapses by VALUE — multiple copies of one code equal a single copy \
         (a multiset is reduced to its underlying set)"
    );

    // (set inequality) — a near-miss (one extra distinct code) must NOT compare equal,
    // the exact-set bite the RejectExact / union premises depend on.
    assert_ne!(
        sorted_code_labels([BadValue].iter()),
        sorted_code_labels([BadValue, MissingProvenance].iter()),
        "sorted_code_labels exact-set equality must DISTINGUISH a near-miss (an extra distinct \
         cause) — this is the bite that catches a spurious extra rejection cause"
    );

    // (empty) — an empty input is the empty set (the premises separately guard a
    // vacuous compare; here we pin the collapse handles it cleanly).
    let empty: [PolicyErrorCode; 0] = [];
    assert!(
        sorted_code_labels(empty.iter()).is_empty(),
        "sorted_code_labels of no codes is the empty set"
    );
}

/// Pin [`declared_codes`] — the per-verdict-row CAUSE PROJECTION the table-level
/// union invariant (`compound_reject_set_is_union_of_siblings`) unions over. It is
/// the Rust analogue of the Go `siblingRejectsOnGoColumn` / `rejectingSentinelSet`
/// projection: it maps each `RustVerdict` to the cause set it CONTRIBUTES to a union
/// — an `Accept` (Rust-benign Go-shape) sibling contributes NOTHING (zero causes), a
/// `Reject` contributes its ONE cause, a `RejectExact` contributes its WHOLE declared
/// set. Getting the `Accept => empty` arm wrong (e.g. contributing a phantom cause)
/// would silently inflate every compound's sibling union; this self-test pins all
/// three arms over SYNTHETIC verdicts (D50).
#[test]
fn declared_codes_projects_each_verdict_arm() {
    use PolicyErrorCode::*;

    // Accept (a Rust-benign Go-shape sibling) contributes ZERO causes — the
    // load-bearing arm: a benign sibling must add NOTHING to a compound's union.
    assert!(
        declared_codes(&RustVerdict::Accept).is_empty(),
        "declared_codes(Accept) must be EMPTY — a Rust-benign Go-shape sibling contributes no \
         schema cause to a compound's union; a phantom cause here would inflate every union"
    );

    // Reject contributes exactly its ONE named cause.
    assert_eq!(
        declared_codes(&RustVerdict::Reject(BadValue)),
        vec![BadValue],
        "declared_codes(Reject(c)) must be exactly [c]"
    );

    // RejectExact contributes its WHOLE declared set, order preserved off the slice
    // (the set discipline is applied by sorted_code_labels at the union site).
    assert_eq!(
        declared_codes(&RustVerdict::RejectExact(&[BadValue, MissingProvenance])),
        vec![BadValue, MissingProvenance],
        "declared_codes(RejectExact(set)) must be the whole declared set"
    );
}

/// Pin [`rust_schema_rejecting_siblings`] — the SIBLING-REJECTING-ON-THE-RUST-COLUMN
/// filter the data-driven reject-equivalence premise
/// (`compound_reject_parse_equivalence_premise`) drives BOTH arities off. It is the
/// Rust mirror of the Go `siblingRejectsOnGoColumn` predicate: from a compound's full
/// sibling list it keeps ONLY the siblings whose Rust verdict REJECTS (`Reject` /
/// `RejectExact` — the schema axes the compound shares with THIS reader) and drops the
/// Rust-BENIGN (`Accept`) Go-shape siblings (their drift bites only the Go SHAPE
/// surface). Inverting this filter (keeping the benign sibling, or dropping a schema
/// one) would make the union premise anchor against the WRONG sibling set; this
/// self-test pins it over a SYNTHETIC table + sibling list (D50), proving the
/// singleton (one schema sibling) and the multi-element (two) shapes the corpus
/// carries, plus the order-preservation and the all-benign (empty) edge.
#[test]
fn rust_schema_rejecting_siblings_filters_to_rust_rejecters() {
    use PolicyErrorCode::*;

    // Synthetic table: two Rust-benign Go-shape siblings (Accept) and two
    // Rust-rejecting schema siblings (Reject / RejectExact). No fixture is touched —
    // these keys are synthetic stand-ins for the corpus rows' verdict KINDS.
    let mut table: BTreeMap<&'static str, RustVerdict> = BTreeMap::new();
    table.insert("benign-a", RustVerdict::Accept);
    table.insert("benign-b", RustVerdict::Accept);
    table.insert("schema-reject", RustVerdict::Reject(BadValue));
    table.insert(
        "schema-exact",
        RustVerdict::RejectExact(&[MissingProvenance]),
    );

    // SINGLETON shape (rows 20-23): one benign Go-shape sibling + one schema sibling
    // resolves to EXACTLY the one schema sibling.
    let singleton = ["benign-a", "schema-reject"];
    let got = rust_schema_rejecting_siblings(&singleton, &table);
    assert_eq!(
        got.iter().map(|s| **s).collect::<Vec<_>>(),
        vec!["schema-reject"],
        "a singleton compound (one Go-shape + one schema sibling) must resolve to ONLY the schema \
         sibling — the Rust-benign Go-shape sibling contributes no schema cause"
    );

    // MULTI-element shape (row 27): one benign Go-shape sibling + TWO schema siblings
    // resolves to BOTH schema siblings, IN ENTRY ORDER (the union ranges over them).
    let multi = ["benign-a", "schema-reject", "schema-exact"];
    let got = rust_schema_rejecting_siblings(&multi, &table);
    assert_eq!(
        got.iter().map(|s| **s).collect::<Vec<_>>(),
        vec!["schema-reject", "schema-exact"],
        "a multi-element compound (one Go-shape + two schema siblings) must resolve to BOTH schema \
         siblings in entry order — the union over them is the multi-element cause set"
    );

    // ALL-BENIGN edge: a sibling list with NO Rust-rejecting member resolves to the
    // EMPTY set (the premise then fails-closed on the empty resolution — pinned in
    // `compound_reject_parse_equivalence_premise`; here we pin the filter returns
    // empty, never silently keeping a benign sibling).
    let all_benign = ["benign-a", "benign-b"];
    assert!(
        rust_schema_rejecting_siblings(&all_benign, &table).is_empty(),
        "an all-Rust-benign sibling list must resolve to ZERO schema siblings — the filter must \
         never keep an Accept sibling (which would anchor the union against a vacuous cause)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// PER-CLASS COMPLEMENTARY-COVERAGE GATE (the RUST mirror of the Go
// `complementaryCoverage` / `TestComplementaryCoverage` /
// `TestDriftCorpusComplementaryCoverage` cluster in
// `assurance/conformance-adapter/resolverlock/drift_corpus_test.go`).
//
// ## The gap this closes
//
// Until now the Rust mirror had a per-class VERDICT walk (`drift_corpus_rust_verdicts`)
// and a fixture-COUNT lockstep (`drift_corpus_coverage_lockstep`), but NO per-class
// COMPLEMENTARY-COVERAGE gate — the load-bearing invariant the file header names as
// item 2 ("COMPLEMENTARY COVERAGE — every other malformed fixture is caught by at
// least ONE reader, never silently accepted by BOTH"). The Go side LIFTED that prose
// into a reconcilable predicate (`complementaryCoverage`) the production gate calls
// over the LIVE `(go, rust, malformed)` tables; the Rust side asserted it only in the
// trailing `// go: ...` column comments. So a Rust verdict that DRIFTED to ACCEPT on a
// MALFORMED shape whose Go column ALSO accepts (a silent both-accept HOLE) — while the
// Go-test-local hand-transcription stayed stale — passed BOTH sides silently: the Rust
// verdict walk would still match the (stale-edited) expectation, and the Go gate reads
// its OWN hand-transcribed Rust column, not this file. This gate closes that seam on
// the RUST side, reconciling key-for-key against `rust_corpus_expectations` (the Rust
// column, authoritative HERE) and a Rust transcription of the Go column.
//
// ## The authoritative `malformed` discriminator (no hand-set bool)
//
// The complementary-coverage decision needs a third input beyond the two verdicts:
// whether the fixture is MALFORMED (a shape SOME reader MUST catch) or BENIGN (a
// well-formed / benign shape whose both-accept agreement is correct BY DESIGN). The Go
// side learned the hard way that a HAND-SET `malformed` bool per row is a footgun — a
// row mislabeled `malformed:false` on a genuinely malformed class silently EXEMPTS
// itself from the both-accept-hole check — and so DERIVES the flag from an authoritative
// drift-CLASS partition (`benignDriftClasses` / `malformedDriftClasses` →
// `malformedByClass`). This Rust mirror takes the SAME authoritative route: the
// `BENIGN_DRIFT_CLASSES` / `MALFORMED_DRIFT_CLASSES` partition below is keyed by the
// drift-CLASS label (`class_of(fixture)`), and `malformed_by_class` derives the flag
// from it — never a per-row bool. A class in NEITHER set is UNCLASSIFIED (fail-closed:
// treated as malformed-must-catch, never silently benign); a class in BOTH is a
// contradiction. `complementary_coverage_gate` reconciles every fixture's class against
// this partition and fails CLOSED on an unclassified / contradictory class, so a new
// corpus fixture can never silently default its authoritative malformed-status.
//
// All ADDITIVE / test-only (D50): no production crate change, no corpus byte touched,
// no existing verdict pair or premise edited. The gate lives in this integration test.
// ─────────────────────────────────────────────────────────────────────────────

impl RustVerdict {
    /// Whether the Rust POL-1 schema reader ACCEPTS this fixture: `Accept` accepts,
    /// `Reject` / `RejectExact` reject. The single projection of the Rust verdict
    /// column onto the accept/reject boolean the complementary-coverage decision
    /// consumes (so the gate cannot disagree with the verdict walk on what "accepts"
    /// means — both read it off the SAME `rust_corpus_expectations` table).
    fn accepts(&self) -> bool {
        matches!(self, RustVerdict::Accept)
    }
}

/// WHICH reader(s) catch a fixture under the per-class complementary-coverage
/// invariant — the RUST mirror of the Go `coverageOwner` enum. Surfaced by the gate
/// and the self-test so a coverage hole NAMES itself rather than failing with a bare
/// boolean (the file header's promise that "the table records WHICH reader owns each
/// class").
///
/// Derived `PartialEq`/`Eq`/`Debug` so the self-test can assert the owner by value and
/// a failure message can print it; the `label()` method is the Rust analogue of the Go
/// `String()` method, kept EXHAUSTIVE (no wildcard arm) so a new variant added below
/// stops compiling until it is given a label — the compile-time completeness bite the
/// Go side can only approximate with a runtime AST sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoverageOwner {
    /// A MALFORMED fixture that BOTH readers ACCEPT — the silent both-accept hole the
    /// complementary-coverage invariant exists to forbid. NEVER a reconciling state.
    Hole,
    /// The Go offline scanner rejects, the Rust schema reader accepts (a resolver-lock-
    /// SHAPE drift the schema parser tolerates).
    GoOnly,
    /// The Rust schema reader rejects, the Go scanner accepts (a POL-1 SCHEMA drift
    /// outside the blocklist the Go scanner never inspects).
    RustOnly,
    /// BOTH readers reject (the true both-reject lockstep case).
    Both,
    /// A BENIGN / well-formed fixture both readers ACCEPT — by DESIGN, not a hole. The
    /// complementary-coverage invariant does not apply.
    BenignAgreement,
}

impl CoverageOwner {
    /// The human-readable label for this owner — the Rust analogue of the Go
    /// `coverageOwner.String()`. EXHAUSTIVE and wildcard-free: adding a variant to the
    /// enum without a label arm here breaks the BUILD of this test crate (the
    /// compile-time completeness bite the Go side reproduces with the runtime
    /// `TestCoverageOwnerUniverseComplete` AST sweep, since Go lacks an exhaustive
    /// match). The `coverage_owner_labels_are_distinct` self-test pins that no two
    /// owners share a label, so a coverage-hole report always names the right one.
    fn label(self) -> &'static str {
        match self {
            CoverageOwner::Hole => "HOLE (malformed, both readers ACCEPT — silent both-accept)",
            CoverageOwner::GoOnly => "go-only (Go scanner rejects, Rust accepts)",
            CoverageOwner::RustOnly => "rust-only (Rust schema reader rejects, Go accepts)",
            CoverageOwner::Both => "both (Go and Rust both reject)",
            CoverageOwner::BenignAgreement => {
                "benign-agreement (well-formed/benign, both accept by design)"
            }
        }
    }
}

/// The PURE per-class complementary-coverage decision — the RUST mirror of the Go
/// `complementaryCoverage`. Given the GO reader's accept/reject verdict, the RUST
/// reader's accept/reject verdict, and whether the fixture is MALFORMED, it reports
/// WHICH reader(s) own the class ([`CoverageOwner`]) and whether the per-class
/// complementary-coverage invariant RECONCILES (`reconciles == true`) or is a silent
/// both-accept HOLE (`reconciles == false`).
///
/// The load-bearing invariant — every MALFORMED fixture is caught by at least ONE
/// reader, NEVER silently accepted by BOTH — is exactly: a malformed (accept, accept)
/// pair does NOT reconcile (it is [`CoverageOwner::Hole`]); every other malformed pair
/// reconciles because some reader rejects (go-only / rust-only / both); and a BENIGN
/// fixture's (accept, accept) reconciles by design ([`CoverageOwner::BenignAgreement`]
/// — both-accept is the CORRECT verdict, not a hole). A benign fixture that REJECTED on
/// a reader is a DIFFERENT regression, owned by the per-class verdict walk
/// (`drift_corpus_rust_verdicts` here, `TestDriftCorpusGoVerdicts` on the Go side); this
/// gate's ONE job is the both-accept-hole prohibition, so a benign reject is still
/// reported by owner and `reconciles == true`.
fn complementary_coverage(
    go_accepts: bool,
    rust_accepts: bool,
    malformed: bool,
) -> (CoverageOwner, bool) {
    match (go_accepts, rust_accepts) {
        (true, true) => {
            if malformed {
                // The silent both-accept HOLE: a malformed shape NEITHER reader
                // catches. The one state the complementary-coverage invariant forbids.
                (CoverageOwner::Hole, false)
            } else {
                // A benign / well-formed shape both readers accept — correct by design.
                (CoverageOwner::BenignAgreement, true)
            }
        }
        // Go scanner is the sole catcher (resolver-lock-shape drift).
        (false, true) => (CoverageOwner::GoOnly, true),
        // Rust schema reader is the sole catcher (POL-1 schema drift).
        (true, false) => (CoverageOwner::RustOnly, true),
        // Both readers reject — the true both-reject lockstep case.
        (false, false) => (CoverageOwner::Both, true),
    }
}

/// The GO reader's accept/reject column, keyed by fixture filename — a RUST
/// transcription of the Go `goCorpusExpectations.accept` values, sourced ONE-FOR-ONE
/// from the trailing `// go: ...` annotation already on each `rust_corpus_expectations`
/// row (the lockstep pair the file header documents). `true` = the Go offline scanner
/// ACCEPTS the fixture, `false` = it REJECTS.
///
/// This is the Rust-side analogue of the Go test's `rustCorpusVerdicts.accept`
/// transcription (which mirrors THIS file's Rust column on the GO side): each reader's
/// test holds a hand-transcription of the OTHER reader's column so the complementary-
/// coverage pairing is computable WITHOUT either test importing the other tree. The
/// transcription is reconciled key-for-key against `rust_corpus_expectations` by
/// `go_column_is_total_over_corpus` (fail-closed on any fixture missing from EITHER
/// table), so a row added to one column but not the other cannot slip the gate.
fn go_corpus_column() -> BTreeMap<&'static str, bool> {
    let mut m: BTreeMap<&'static str, bool> = BTreeMap::new();

    // ── both ACCEPT — well-formed control + benign-shape agreement cases ──────
    m.insert("00-good-baseline.pol1.yaml", true); // go: accept (control)
    m.insert("17-duplicate-fqdn.pol1.yaml", true); // go: accept (benign dup)
    m.insert("18-reordered-families.pol1.yaml", true); // go: accept (order-insensitive)
    m.insert("19-comment-only-families.pol1.yaml", true); // go: accept (comments stripped)

    // ── GO rejects, RUST accepts — resolver-lock-shape drift the schema parser
    //    tolerates (the Go offline half is the tripwire on these) ─────────────
    m.insert("01-missing-blocklist.pol1.yaml", false); // go: reject (NoBlocklistSection)
    m.insert("02-empty-blocklist.pol1.yaml", false); // go: reject (EmptyBlocklist)
    m.insert("03-wildcard-fqdn.pol1.yaml", false); // go: reject (BadFQDN)
    m.insert("04-uppercase-fqdn.pol1.yaml", false); // go: reject (BadFQDN)
    m.insert("05-entry-missing-rung.pol1.yaml", false); // go: reject (EntryMissingFields)
    m.insert("06-entry-missing-reason.pol1.yaml", false); // go: reject (EntryMissingFields)
    m.insert("07-flow-blocklist.pol1.yaml", false); // go: reject (UnsupportedShape)
    m.insert("08-quoted-keys.pol1.yaml", false); // go: reject (NoBlocklistSection)

    // ── both REJECT — the TRUE lockstep case ─────────────────────────────────
    m.insert("09-anchor-alias-families.pol1.yaml", false); // go: reject (UnsupportedShape)

    // ── GO accepts, RUST rejects — POL-1 schema drift the Go scanner never inspects ─
    m.insert("10-unknown-tier.pol1.yaml", true); // go: accept
    m.insert("11-empty-family-tier.pol1.yaml", true); // go: accept
    m.insert("12-entry-missing-provenance.pol1.yaml", true); // go: accept
    m.insert("13-missing-rung-guardrail.pol1.yaml", true); // go: accept
    m.insert("14-bad-rung-token.pol1.yaml", true); // go: accept
    m.insert("15-multi-document.pol1.yaml", true); // go: accept
    m.insert("16-tab-indent.pol1.yaml", true); // go: accept

    // ── COMPOUND both REJECT — one artifact drifts BOTH reader surfaces ───────
    m.insert("20-quoted-key-unknown-tier.pol1.yaml", false); // go: reject (NoBlocklistSection)
    m.insert("21-flow-blocklist-bad-guardrail-rung.pol1.yaml", false); // go: reject (UnsupportedShape)
    m.insert(
        "22-entry-missing-reason-missing-provenance.pol1.yaml",
        false,
    ); // go: reject (EntryMissingFields)
    m.insert("23-uppercase-fqdn-missing-guardrail-rung.pol1.yaml", false); // go: reject (BadFQDN)
    m.insert(
        "27-uppercase-fqdn-unknown-tier-missing-provenance.pol1.yaml",
        false,
    ); // go: reject (BadFQDN)

    // ── COMPOUND both ACCEPT — the complement of 20-23 ───────────────────────
    m.insert("24-duplicate-fqdn-provenanced-entry.pol1.yaml", true); // go: accept (benign dup)
    m.insert("25-reordered-families-guardrail-rung.pol1.yaml", true); // go: accept (reordered families)
    m.insert("26-comment-only-guardrails-enabled-tier.pol1.yaml", true); // go: accept (comment-only guardrails)

    m
}

/// The AUTHORITATIVE benign drift-CLASS set — the RUST mirror of the Go
/// `benignDriftClasses`. Keyed by the drift-class LABEL (`class_of(fixture)`, equal to
/// the `drift_class` tag each committed `<name>.provenance` D50 sidecar carries). A
/// class here is BENIGN: a both-accept pair is the CORRECT verdict, never a coverage
/// hole. Pairs with [`MALFORMED_DRIFT_CLASSES`] as a fail-closed partition reconciled
/// against the live corpus by `drift_class_partition_total_and_disjoint`.
const BENIGN_DRIFT_CLASSES: &[&str] = &[
    "good-baseline",                        // 00 — the well-formed control
    "duplicate-fqdn",                       // 17 — benign duplicate FQDN (order-insensitive)
    "reordered-families",                   // 18 — benign family reorder (order-insensitive)
    "comment-only-families",                // 19 — comment-only block (comments stripped)
    "duplicate-fqdn-provenanced-entry",     // 24 — compound benign (dup FQDN ∪ provenanced entry)
    "reordered-families-guardrail-rung",    // 25 — compound benign (reorder ∪ valid guardrail rung)
    "comment-only-guardrails-enabled-tier", // 26 — compound benign (comment-only ∪ valid family tier)
];

/// The AUTHORITATIVE malformed drift-CLASS set — the RUST mirror of the Go
/// `malformedDriftClasses`. Keyed by the drift-class LABEL. A class here is MALFORMED:
/// a shape SOME reader MUST catch, so a both-accept pair for it is a silent coverage
/// HOLE. Pairs with [`BENIGN_DRIFT_CLASSES`] as a fail-closed partition.
const MALFORMED_DRIFT_CLASSES: &[&str] = &[
    // GO rejects, RUST accepts — resolver-lock-SHAPE drift (Go scanner is the sole catcher).
    "missing-blocklist",    // 01
    "empty-blocklist",      // 02
    "wildcard-fqdn",        // 03
    "uppercase-fqdn",       // 04
    "entry-missing-rung",   // 05
    "entry-missing-reason", // 06
    "flow-blocklist",       // 07
    "quoted-keys",          // 08
    // both REJECT — the TRUE lockstep case.
    "anchor-alias-families", // 09
    // GO accepts, RUST rejects — POL-1 SCHEMA drift (Rust schema reader is the sole catcher).
    "unknown-tier",             // 10
    "empty-family-tier",        // 11
    "entry-missing-provenance", // 12
    "missing-rung-guardrail",   // 13
    "bad-rung-token",           // 14
    "multi-document",           // 15
    "tab-indent",               // 16
    // COMPOUND both REJECT — one artifact drifts BOTH reader surfaces under INDEPENDENT causes.
    "quoted-key-unknown-tier",                        // 20
    "flow-blocklist-bad-guardrail-rung",              // 21
    "entry-missing-reason-missing-provenance",        // 22
    "uppercase-fqdn-missing-guardrail-rung",          // 23
    "uppercase-fqdn-unknown-tier-missing-provenance", // 27
];

/// The PURE per-class MALFORMED derivation — the RUST mirror of the Go
/// `malformedByClass`. Given a drift-class label (`class_of(fixture)`) it returns
/// `(malformed, classified)`:
///
///   * `malformed`: `true` if the class is in [`MALFORMED_DRIFT_CLASSES`], `false` if
///     in [`BENIGN_DRIFT_CLASSES`];
///   * `classified`: whether the class was found in EXACTLY ONE set. A class in NEITHER
///     set is UNCLASSIFIED (`classified == false`, `malformed` defaulting to `true` —
///     fail-closed: an undeclared class is treated as malformed-must-catch, never
///     silently benign); a class in BOTH is a contradiction (`classified == false`).
///
/// This derives the authoritative `malformed` discriminator from the drift-CLASS
/// partition rather than a per-row bool, matching the Go side — a row mislabeled benign
/// on a genuinely malformed class cannot silently exempt itself from the both-accept-
/// hole check, because the gate reads the flag from this class membership, never a hand-
/// set field. The `complementary_coverage_gate` surfaces the `!classified` signal and
/// fails LOUDLY rather than trusting the default.
fn malformed_by_class(class: &str) -> (bool, bool) {
    let in_benign = BENIGN_DRIFT_CLASSES.contains(&class);
    let in_malformed = MALFORMED_DRIFT_CLASSES.contains(&class);
    match (in_benign, in_malformed) {
        (true, false) => (false, true),
        (false, true) => (true, true),
        // NEITHER set (unclassified) OR BOTH sets (contradiction): not cleanly
        // classified. Fail closed by reporting malformed=true (an undeclared class is a
        // shape SOME reader must catch); the gate fails LOUDLY on the !classified signal
        // rather than trusting this default.
        _ => (true, false),
    }
}

/// FAIL-CLOSED self-test of [`complementary_coverage`] — the RUST mirror of the Go
/// `TestComplementaryCoverage`. Pins the per-class invariant's semantic against
/// accidental weakening by driving the SAME pure helper the gate calls over SYNTHETIC
/// `(go, rust, malformed)` triples (D50 — no corpus fixture touched): a fully
/// complementary-covered malformed class (some reader rejects) RECONCILES with the
/// right owner; a malformed class accepted by BOTH is FLAGGED (a `Hole`,
/// `reconciles == false`); and a benign both-accept reconciles by design. THE bite is
/// the malformed both-accept row: a helper that treated it as covered would silently
/// widen the benign set the corpus exists to bound.
#[test]
fn complementary_coverage_semantic() {
    struct Case {
        name: &'static str,
        go_accepts: bool,
        rust_accepts: bool,
        malformed: bool,
        want_owner: CoverageOwner,
        want_reconciles: bool,
    }
    let cases = [
        Case {
            name: "malformed, go rejects rust accepts -> reconciles (go-only)",
            go_accepts: false,
            rust_accepts: true,
            malformed: true,
            want_owner: CoverageOwner::GoOnly,
            want_reconciles: true,
        },
        Case {
            name: "malformed, go accepts rust rejects -> reconciles (rust-only)",
            go_accepts: true,
            rust_accepts: false,
            malformed: true,
            want_owner: CoverageOwner::RustOnly,
            want_reconciles: true,
        },
        Case {
            name: "malformed, both reject -> reconciles (both)",
            go_accepts: false,
            rust_accepts: false,
            malformed: true,
            want_owner: CoverageOwner::Both,
            want_reconciles: true,
        },
        Case {
            // THE fail-closed bite: a malformed shape NEITHER reader catches is the
            // silent both-accept hole the complementary-coverage invariant forbids — it
            // must NOT reconcile, or a fixture row edited to (accept, accept) for a
            // malformed shape would silently widen the benign set.
            name: "malformed, BOTH accept -> FLAGGED (coverage hole)",
            go_accepts: true,
            rust_accepts: true,
            malformed: true,
            want_owner: CoverageOwner::Hole,
            want_reconciles: false,
        },
        Case {
            // A well-formed / benign shape both readers accept is the CORRECT verdict by
            // design — the malformed flag is what distinguishes it from a silent hole.
            name: "benign, both accept -> reconciles (benign agreement)",
            go_accepts: true,
            rust_accepts: true,
            malformed: false,
            want_owner: CoverageOwner::BenignAgreement,
            want_reconciles: true,
        },
    ];
    for c in &cases {
        let (owner, reconciles) = complementary_coverage(c.go_accepts, c.rust_accepts, c.malformed);
        assert_eq!(
            reconciles, c.want_reconciles,
            "complementary_coverage(go_accepts={}, rust_accepts={}, malformed={}) reconciles = {}, \
             want {} — case {:?}. The complementary-coverage invariant must FLAG a malformed \
             (accept, accept) pair as a silent both-accept HOLE (reconciles == false) and reconcile \
             every pair where at least one reader rejects (or a benign both-accept); a helper that \
             treated a malformed both-accept as covered would silently widen the benign set the \
             corpus exists to bound.",
            c.go_accepts, c.rust_accepts, c.malformed, reconciles, c.want_reconciles, c.name
        );
        assert_eq!(
            owner, c.want_owner,
            "complementary_coverage(go_accepts={}, rust_accepts={}, malformed={}) owner = {:?}, \
             want {:?} — case {:?}. The owner label records WHICH reader(s) catch each class so a \
             coverage hole names itself; a mislabel would hide which reader's coverage drifted.",
            c.go_accepts, c.rust_accepts, c.malformed, owner, c.want_owner, c.name
        );
    }
}

/// FAIL-CLOSED self-test of [`malformed_by_class`] — the RUST mirror of the Go
/// `TestMalformedByClass`. Pins the authoritative malformed-class derivation's semantic
/// over SYNTHETIC class labels (D50): a benign class is `malformed=false` (classified),
/// a malformed class is `malformed=true` (classified), and an UNCLASSIFIED class — in
/// NEITHER partition set, or (a contradiction) in BOTH — is `classified=false` with
/// `malformed` defaulting to `true`. A weakening that moved a malformed class into the
/// benign set (silently exempting it from the both-accept-hole check) or let an
/// undeclared class default to benign flips THIS test RED.
#[test]
fn malformed_by_class_semantic() {
    // A representative benign class — both-accept is correct by design.
    let (malformed, classified) = malformed_by_class("good-baseline");
    assert!(
        !malformed && classified,
        "malformed_by_class(\"good-baseline\") must be (malformed=false, classified=true) — a \
         benign class's both-accept pair is the CORRECT verdict, not a hole; got \
         (malformed={malformed}, classified={classified})"
    );

    // A representative malformed class — some reader must catch it.
    let (malformed, classified) = malformed_by_class("unknown-tier");
    assert!(
        malformed && classified,
        "malformed_by_class(\"unknown-tier\") must be (malformed=true, classified=true) — a \
         malformed class is a shape SOME reader must catch; got \
         (malformed={malformed}, classified={classified})"
    );

    // UNCLASSIFIED (in NEITHER set): fail-closed to malformed=true, classified=false —
    // an undeclared class is never silently treated as benign.
    let (malformed, classified) = malformed_by_class("a-class-declared-in-neither-set");
    assert!(
        malformed && !classified,
        "malformed_by_class on an UNDECLARED class must fail closed to (malformed=true, \
         classified=false) — an undeclared class is treated as malformed-must-catch, never \
         silently benign; got (malformed={malformed}, classified={classified})"
    );
}

/// Pin the [`CoverageOwner`] labels DISTINCT and the [`RustVerdict::accepts`]
/// projection — the RUST mirror of the Go `TestCoverageOwnerUniverseComplete`'s
/// distinct-label arm. Go needs a runtime AST sweep to prove its enum universe
/// exhaustive and every value non-"unknown"-labeled because it has no compile-time
/// exhaustive match; the Rust [`CoverageOwner::label`] match is ALREADY exhaustive and
/// wildcard-free (a new variant breaks the BUILD until labeled), so the only residual
/// runtime bite is that no two owners share a label (a coverage-hole report must name
/// the right owner). This also pins the `accepts()` projection both the gate and the
/// verdict walk read the Rust column through, so they cannot disagree on what "accepts"
/// means.
#[test]
fn coverage_owner_labels_are_distinct() {
    // Every owner the gate / helper can return. EXHAUSTIVE by construction: the
    // `label()` match below is wildcard-free, so a CoverageOwner variant added without a
    // label arm breaks the build before this list could go stale.
    let owners = [
        CoverageOwner::Hole,
        CoverageOwner::GoOnly,
        CoverageOwner::RustOnly,
        CoverageOwner::Both,
        CoverageOwner::BenignAgreement,
    ];
    let mut labels: BTreeMap<&'static str, CoverageOwner> = BTreeMap::new();
    for owner in owners {
        let label = owner.label();
        assert!(
            !label.is_empty(),
            "CoverageOwner::{owner:?} renders an EMPTY label — every owner must carry a distinct, \
             non-empty message so a coverage-hole report names it"
        );
        if let Some(prev) = labels.insert(label, owner) {
            panic!(
                "CoverageOwner::{owner:?} and CoverageOwner::{prev:?} share the SAME label {label:?} \
                 — each owner must render a distinct message so a coverage-hole report names the \
                 right one"
            );
        }
    }

    // The accepts() projection the gate and the verdict walk both read the Rust column
    // through: Accept accepts; Reject / RejectExact reject. A drift here would make the
    // gate disagree with `drift_corpus_rust_verdicts` on the SAME table.
    use PolicyErrorCode::*;
    assert!(
        RustVerdict::Accept.accepts(),
        "RustVerdict::Accept must project to accepts() == true"
    );
    assert!(
        !RustVerdict::Reject(BadValue).accepts(),
        "RustVerdict::Reject must project to accepts() == false"
    );
    assert!(
        !RustVerdict::RejectExact(&[BadValue]).accepts(),
        "RustVerdict::RejectExact must project to accepts() == false"
    );
}

/// FAIL-CLOSED reconciliation that the Go-column transcription [`go_corpus_column`] is
/// TOTAL over the corpus: it must enumerate EXACTLY the same fixtures as
/// [`rust_corpus_expectations`] (the Rust column), key-for-key. A fixture in the Rust
/// column but not the Go column (or vice versa) means the complementary-coverage pair is
/// undefined for it — so the per-class gate below could not compute its owner. This is
/// the RUST mirror of the Go gate's key-reconciliation preamble (which reconciles
/// `goCorpusExpectations` against `rustCorpusVerdicts`): a row added to ONE column but
/// not the other cannot slip the gate.
#[test]
fn go_column_is_total_over_corpus() {
    let rust = rust_corpus_expectations();
    let go = go_corpus_column();

    for name in rust.keys() {
        assert!(
            go.contains_key(name),
            "fixture {name} has a RUST verdict (rust_corpus_expectations) but NO Go-column \
             transcription (go_corpus_column) — the per-class complementary-coverage pair is \
             undefined; every fixture must carry BOTH columns (fail-closed: a row added to one \
             column must be wired into the other)"
        );
    }
    for name in go.keys() {
        assert!(
            rust.contains_key(name),
            "fixture {name} has a Go-column transcription (go_corpus_column) but NO Rust verdict \
             (rust_corpus_expectations) — the per-class complementary-coverage pair is undefined; \
             every fixture must carry BOTH columns (fail-closed)"
        );
    }
    assert_eq!(
        rust.len(),
        go.len(),
        "Go-column / Rust-column count mismatch: {} Rust verdicts, {} Go-column entries — the two \
         columns must enumerate the corpus identically for the complementary-coverage pairing to \
         be total (lockstep fail-closed)",
        rust.len(),
        go.len()
    );
}

/// The per-class COMPLEMENTARY-COVERAGE gate (the RUST half) — the mirror of the Go
/// `TestDriftCorpusComplementaryCoverage`. For EVERY fixture in the corpus it reconciles
/// that a MALFORMED shape is caught by at least ONE reader — that NO malformed fixture is
/// a silent (accept, accept) HOLE — and surfaces WHICH reader(s) own each class. This is
/// the third pillar named in the file header (item 2, "COMPLEMENTARY COVERAGE"),
/// previously asserted on the Rust side only in the trailing `// go: ...` column
/// comments; this pins it as a reconcilable invariant HERE.
///
/// The per-fixture decision — owner + reconciles — is the pure [`complementary_coverage`]
/// helper (pinned fail-closed by `complementary_coverage_semantic`). The gate CALLS it
/// over the LIVE columns: the RUST accept verdict off [`rust_corpus_expectations`] (via
/// [`RustVerdict::accepts`]), the GO accept verdict off the [`go_corpus_column`]
/// transcription, and the MALFORMED flag DERIVED from the authoritative drift-class
/// partition via [`malformed_by_class`] (never a hand-set bool). So the gate keeps biting
/// on the real Rust column while the self-test exercises the SAME code path over synthetic
/// triples (D50).
///
/// Fail-closed on EVERY axis:
///   * a fixture present in the Rust column but absent from the Go transcription (the
///     key-reconciliation preamble — duplicated as a dedicated test for its own message);
///   * an UNCLASSIFIED / contradictory drift class (`malformed_by_class` reports
///     `classified == false`) — a new fixture whose authoritative malformed-status was
///     never declared cannot silently default;
///   * a malformed fixture ACCEPTED by BOTH readers — the [`CoverageOwner::Hole`] the
///     invariant forbids.
///
/// So a Rust verdict edited to ACCEPT a malformed shape whose Go column also accepts (the
/// silent both-accept hole) goes RED HERE — the seam the file-header prose left
/// unmachine-reconciled on the Rust side until now.
#[test]
fn drift_corpus_complementary_coverage() {
    let rust = rust_corpus_expectations();
    let go = go_corpus_column();

    // Walk in a deterministic, name-stable order (BTreeMap iterates sorted) and
    // reconcile each fixture's (go, rust, malformed) triple through the pure helper.
    for (name, rust_verdict) in &rust {
        let go_accepts = match go.get(name) {
            Some(v) => *v,
            None => {
                // Reported with its own message by go_column_is_total_over_corpus; skip
                // the body so that dedicated test owns the fail-closed key message.
                continue;
            }
        };
        let rust_accepts = rust_verdict.accepts();

        // Derive the authoritative MALFORMED flag from the drift-CLASS partition — never
        // a per-row bool. An unclassified / contradictory class fails CLOSED here.
        let class = class_of(name);
        let (malformed, classified) = malformed_by_class(&class);
        assert!(
            classified,
            "fixture {name} (drift class {class:?}): its drift class is UNCLASSIFIED — it is in \
             NEITHER BENIGN_DRIFT_CLASSES NOR MALFORMED_DRIFT_CLASSES (or, a contradiction, in \
             BOTH). The complementary-coverage gate derives the authoritative malformed flag from \
             that partition; an undeclared class cannot silently default. Place the class in \
             EXACTLY ONE set (a both-accept pair is correct -> benign; some reader must catch it \
             -> malformed)"
        );

        let (owner, reconciles) = complementary_coverage(go_accepts, rust_accepts, malformed);
        assert!(
            reconciles,
            "fixture {name} (drift class {class:?}): COMPLEMENTARY-COVERAGE HOLE — it is a \
             MALFORMED shape that BOTH readers ACCEPT (go accepts={go_accepts}, rust \
             accepts={rust_accepts}). The corpus invariant is that every malformed fixture is \
             caught by at least ONE reader, NEVER silently accepted by BOTH; a both-accept malformed \
             fixture would silently widen the benign set. Either the fixture is genuinely benign \
             (move its class into BENIGN_DRIFT_CLASSES AND document why) or a reader's verdict \
             drifted to accept where it must reject (fix the verdict, not the partition). owner={}",
            owner.label()
        );
    }
}
