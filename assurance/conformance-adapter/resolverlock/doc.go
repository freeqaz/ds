// SPDX-License-Identifier: Apache-2.0

// Package resolverlock is the conformance adapter for the doc 09 §9 resolver-lock
// guarantee — the "DoH client that must be blocked" row of the egress-gateway
// wire-conformance matrix (assurance/conformance-adapter/doc.go; doc 09 NFT-4 /
// line 144 "Resolver lock").
//
// # The guarantee
//
// Known public DoH/DoT resolver domains ship in the D64 baseline blocklist
// (POL-2); blocklists always win (POL-1 §1.2 deny-overrides). Doc 09 enforces the
// block in two boundary layers over that ONE list:
//
//   - DNS-3 denial — ds-dnsgate refuses the resolver qname (a DoH client that
//     tries to resolve dns.google through us gets a hard NXDOMAIN, D71).
//   - the TLS-1 SNI check — ds-tlsproxy peeks the ClientHello SNI and refuses the
//     connect when the SNI is a blocklisted resolver host (so a client that
//     resolved the IP out-of-band and dialed the egress gateway directly is still
//     cut off).
//
// (HTTP-level DoH detection on otherwise-allowed hosts is a later layer, TLS-6;
// this package is the named-resolver half only.)
//
// # Two halves, one source
//
// This package has an OFFLINE half and a LIVE half, and they share ONE source of
// truth for which domains the resolver lock covers — the SHIPPED pack artifact
// dataplane/artifacts/policy-packs/pol2-system-baseline.pol1.yaml. The Rust TLS-1
// suite (dataplane/crates/policy-core/tests/resolver_lock_tls1.rs) parses the
// SAME file through ds_contracts::pol1::parse_layer, so the policy-core TLS-1
// assertions and this adapter read one artifact and cannot drift: one source, two
// readers.
//
//   - OFFLINE (default, always runs): extracts the resolver-lock blocklist from
//     the shipped pack and asserts it is non-empty and shaped as exact, lowercase
//     FQDNs — the form the egress gateway normalizes the peeked SNI into. Because
//     both suites read the SAME bytes, the Go-extracted set equals the Rust side
//     by construction. No network, no running services; this is what keeps CI
//     honest about the contract the live half WILL check. The Go extractor is a
//     stdlib line scanner (this module is stdlib-only by charter), so it is
//     hardened against pack YAML SHAPE DRIFT: a renamed/removed `blocklist:` key,
//     a flow-style (`[`/`{`) or anchored (`&`/`*`) rewrite of the section, an
//     entry missing its reason/rung, a wildcard or non-lowercase FQDN, an empty
//     set, or any under-extraction (raw `domain:` count > harvested entries) each
//     surfaces a NAMED, actionable error (the Err* sentinels in resolverlock.go)
//     rather than silently extracting partial data while the authoritative Rust
//     ds_contracts engine stays correct. Every such error names the rule: a pack
//     format change must update BOTH readers — this Go scanner AND the Rust TLS-1
//     suite — in lockstep, preserving the one-artifact-two-readers guarantee.
//
//   - LIVE (env-gated DS_RESOLVERLOCK_LIVE=1, default SKIPPED): drives a DoH-style
//     client against running ds-dnsgate + ds-tlsproxy and asserts the refusal at
//     both the DNS-3 and TLS-1 SNI layers — the wire-matrix row proper. It is a
//     DEFERRED MANUAL step: it needs the NFT-4 resolver-bypass-closure ruleset and
//     the running boundary services, which land with NFT-4
//     (taskdb 01KTWJ68H01HR03Q1X1VQC5DB7). Until then the gate stays off; running
//     a real `claude` / `cia run` / `podman run` of Claude Code is out of scope
//     here — the live half is exercised against the real boundary binaries, not an
//     agent. The full live-tier wiring (replacing the fail-loud scaffold in
//     resolverlock_test.go with the real per-FQDN driver) is tracked by
//     taskdb 01KTY0Q6JHNSJ12NXD0AFJYCM5; only the env gate, the default-SKIP
//     posture, and this documentation are autonomously buildable today.
//
// # The DS_RESOLVERLOCK_LIVE env-gate contract
//
// DS_RESOLVERLOCK_LIVE (the LiveEnvVar constant) is the single switch for the live
// half. Its contract:
//
//   - UNSET or any value other than "1" (the default, and the CI posture): the live
//     half is disabled — LiveEnabled() returns false, TestLiveResolverLockBlocked
//     SKIPS with a message naming this var and the NFT-4 blocker
//     (taskdb 01KTWJ68H01HR03Q1X1VQC5DB7), and no network is touched. CI never sets
//     it, so the default `go test ./resolverlock/...` is offline and deterministic.
//   - "1": the operator opts into the live run. Until the NFT-4 driver lands the
//     scaffold then fails LOUDLY per shipped FQDN (never a vacuous pass), because a
//     gate that is explicitly on but unwired must not report a false green for the
//     "DoH client that must be blocked" row.
//   - DS_RESOLVERLOCK_DNSGATE_ADDR / DS_RESOLVERLOCK_TLSPROXY_ADDR (read by
//     LiveTargetFromEnv): point the live run at a deployment's boundary host;
//     localhost dev defaults otherwise. These only resolve WHERE the live half would
//     connect — they do not by themselves enable it; the gate above still governs.
//
// # Egress-gateway / TLS-termination vocabulary
//
// This package uses the project's network-proxy vocabulary consistently, and the
// live half asserts against it: ds-tlsproxy is the EGRESS GATEWAY — the
// TLS-TERMINATING boundary service on the egress path. The TLS-1 SNI check is the
// egress-gateway decision this package exercises: ds-tlsproxy inspects the egress
// ClientHello's SNI, normalizes it to an exact lowercase FQDN, and refuses the
// connect when that host is a blocklisted resolver — for a blocklisted resolver the
// refusal lands at SNI inspection, before TLS termination would complete.
// "Egress gateway" and "TLS termination" are the canonical terms throughout (the
// project's network-proxy prose vocabulary); the DNS-3 layer (ds-dnsgate) is the
// resolution-side companion to this egress-gateway check, and the live half drives
// both as the two enforcement points of the one resolver-lock verdict.
//
// # The sentinel naming convention is LOAD-BEARING (Err prefix + errors.New)
//
// Every exported resolver-lock SHAPE-drift cause is declared as a package-level
// var of the form `Err<Name> = errors.New("resolverlock: …")` (resolverlock.go),
// and every NFT-4 artifact-shape cause likewise (`Err<Name> = errors.New(
// "resolverlock/nft4: …")`, nft4_closure.go). This is not mere style: it is a
// CONTRACT the offline scan's completeness guard relies on. drift_corpus_test.go's
// exact-set bite (the goRejectExact rows + presentSentinels) is only as strong as
// exportedSentinelUniverse enumerating EVERY exported sentinel; its completeness
// guard (TestExportedSentinelUniverseComplete) reconciles that table against the
// source by parsing out exactly the `Err* = errors.New(...)` var specs across all
// non-_test.go package files. A sentinel that kept the convention is therefore
// reconciled automatically; a sentinel that BROKE it would slip past the syntactic
// scan. So:
//
//   - DO declare every new exported reject cause as `Err<Name> = errors.New(...)`,
//     and add it to exportedSentinelUniverse. Wrap runtime detail with
//     `fmt.Errorf("%w …", ErrName, …)` at the RETURN site (as the scanner already
//     does) — the package-level SENTINEL stays an `errors.New` Err* var so the
//     by-name completeness scan and errors.Is matching both hold.
//   - Do NOT introduce an exported package-level error var that is named WITHOUT the
//     Err prefix, or constructed with fmt.Errorf / a custom constructor instead of
//     errors.New. Such a var would be a reject cause invisible to the by-name scan.
//
// Because a convention is only as safe as its enforcement, the test file ALSO
// carries a NAMING-AGNOSTIC backstop (TestExportedErrorVarsCoveredByUniverse): it
// TYPE-CHECKS the package and flags ANY exported, file-scope, error-TYPED var — by
// type, regardless of name or constructor — that is missing from
// exportedSentinelUniverse, failing LOUDLY and naming the offending identifier. So a
// convention-violating sentinel (non-Err name, or fmt.Errorf / custom constructor)
// no longer escapes silently: it now fails the build, pointing back here. The
// broadened guard catches the shapes the convention forbids; this comment records
// WHY the convention exists so the fix is to restore it, not to suppress the guard.
//
// PRESENCE is not the whole convention, though: the coverage backstop only requires an
// error-typed var be ENUMERATED in exportedSentinelUniverse. An exported sentinel that
// IS in the universe yet was built with fmt.Errorf, or named WITHOUT the Err prefix,
// satisfies the coverage guard and would still break the form the by-name exact-set bite
// relies on. So the convention is ALSO enforced BY CONSTRUCTION — a type-driven FORWARD
// guard (TestExportedErrorSentinelsFollowConstructionConvention) walks the SAME exported,
// file-scope, error-TYPED vars and asserts BOTH clauses of the convention on each: (i) its
// identifier carries the Err prefix, AND (ii) it is constructed via errors.New(...) (not
// fmt.Errorf or a custom constructor), detected from the AST initializer. A var that breaks
// EITHER clause fails LOUDLY, naming resolverlock.<Ident> and which clause it violated; a
// DELIBERATE exception must be opted into, with a justification, via the test's
// constructionConventionAllowlist (empty today). The net effect: a convention break now
// fails the BUILD by construction, not merely a universe-staleness check — the load-bearing
// convention is enforced, not just documented and presence-checked.
//
// # The two compound sibling-drift detectors divide labor (do not weaken either)
//
// drift_corpus_test.go carries TWO Go-side detectors over the compound both-reject fixtures
// (20-23, 27), and they are NOT redundant — each catches a drift the other structurally
// cannot, so neither should be weakened as duplicative:
//
//   - The want.exact verdict walk in TestDriftCorpusGoVerdicts pins each compound's PARSED
//     cause set to EXACTLY {rejectVia} ("want EXACTLY {..} (no more, no less)" via
//     goExactSetMatches). It catches SPURIOUS-EXTRA-sentinel drift ON THE COMPOUND — a
//     regression that joined an extra reject cause into the compound's own error tree. But it
//     never parses the compound's single-axis SIBLING, so it is blind to drift on the sibling
//     side of the compound==sibling tie.
//   - TestDriftCorpusGoRejectEquivalencePremise adds the cross-fixture compound==sibling tie
//     PLUS its load-bearing (c) anchor: the sibling's parsed cause set must be EXACTLY its one
//     declared sentinel (the `len(siblingSet) != 1 || !errors.Is(siblingSet[0], ...)` non-empty
//     single-sentinel assertion). That anchor is what catches SIBLING-SIDE drift the per-compound
//     exact-set walk cannot see — and it forbids a vacuous both-empty equality from passing.
//
// So: the exact-set walk owns the COMPOUND's cause set; the reject-equivalence premise's (c)
// anchor owns the SIBLING's. Weakening or deleting either re-opens a drift class the other does
// not cover — keep both. (The union-equivalence premise generalizes the same compound==∪siblings
// tie data-driven over the full corpus; its non-vacuity anchor plays the same SIBLING-side role.)
//
// This package carries NO guardrail assertions of its own beyond wiring the spec
// to the real services (assurance/conformance-adapter/doc.go "What must NOT live
// here"): the resolver-lock VERDICT is owned by policy-core (the TLS-1 half lives
// in dataplane/crates/policy-core/tests/resolver_lock_tls1.rs) and the boundary/
// spec; this is the runnable bridge to the live boundary, plus the offline
// cross-language consistency check that proves the two suites read one artifact.
package resolverlock
