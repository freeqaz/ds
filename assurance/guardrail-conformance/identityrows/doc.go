// SPDX-License-Identifier: Apache-2.0

// Package identityrows holds the executable form of the doc 16 §13 identity
// (c)-tier guardrail-conformance rows that are NOT already implemented by a
// sibling package. It is part of the D51 public claims package (../README.md):
// every guardrail the docs promise becomes a test that tries to make the
// guardrail FAIL and asserts it doesn't (doc 06 §3c). Each row below is a small,
// deterministic check over SYNTHETIC fixtures (D50) — Go-literal inputs built by
// the test, never a live mint service, key store, ds-tlsproxy, VM, host-agent,
// KVM, or podman run — exactly the way the orchctl/ sibling models its five
// orchestrator (c) rows. The shape per row: a typed fixture + a typed
// ViolationClass taxonomy + a pure Check* function the test exercises with a
// CONFORMING control and one fixture per NAMED violation class.
//
// THE doc 06 §3c LANGUAGE NOTE IS BINDING HERE. Nothing in this package is named
// attack / redteam / intrusion / exploit. Every check is phrased as "the
// guardrail HOLDS, and this is the named way a regression would let it slip." A
// fixture that models a defeat (a stolen cert that still validates, a digest not
// matchable before first egress) is named for the PROPERTY it probes, never for
// an attacker. A guard test (TestNoAttackVocabulary) pins this.
//
// SYNTHETIC ONLY (D50). The fixtures are in-code Go literals built by the test
// against the DOCUMENTED wire shapes of the FROZEN identity.v1 / boundary.v1
// contracts (doc 16 §4/§5/§8/§9 IdentityMint + IdentityValidation seams; doc 14
// §7 digest-entry shape) — "synthetic only" is STRUCTURAL: there is no fixtures/
// dir, no file I/O, and no working-directory dependency. Nothing here mints a
// real certificate, opens a real key store, runs a real swap, reads a VM, or
// emits a real LOG-1 event; the credential "values" are synthetic fingerprint
// placeholders and the validation/mint/revocation observations are DATA. There
// is NO live claude / qemu(VM-run) / podman / Vault / OpenBao / KVM invocation
// anywhere in this package, and no DS_*_LIVE token is read or set (the nftgate/
// live_test.go env-gated-live precedent would house any future live runner; this
// package has none — the claims are a pure data diff).
//
// IN ASSURANCE, NOT IN identity/. This package asserts the DOCUMENTED contract
// shapes from outside; it imports no identity/ code (the D80 service-boundary
// rule — the claims package drives no production code, README.md). The contracts
// it models (identity.v1, boundary.v1) are FROZEN: it asserts their documented
// shapes, never adds a stub message body.
//
// THE ROW SPLIT (doc 16 §13). The §13 list names thirteen identity (c)-row
// candidates. THREE are already implemented by siblings and are EXCLUDED here, so
// the same row is never asserted twice:
//
//	cred-never-in-VM/host  → credswap/        (cred-swap-never-leaks)
//	canary-never-egresses  → secretegress/    (secret-egress-canary-blocked)
//	App-install read-level → appinstall/      (the §5.2 read-level-subset diff)
//
// The remaining TEN §13 rows are implemented here (one Check* + tag per row;
// where one §13 bullet bundles distinct claims — the §4 CA bullet's per-session
// isolation AND D82 hierarchy separation; the §8 socket-hold bullet's
// in-window/timeout/detach/post-detach paths — the bullet is ONE row with several
// named violation classes, not several rows):
//
//	ROW 1  mint-before-attach              — a freshly minted session's digests are
//	                                         matchable before its FIRST egress byte
//	                                         (round2/08 test 6); digest-write failure
//	                                         fails session create FAIL-CLOSED (§6.1).
//	ROW 2  per-session-ca-isolation        — session A's CA never validates against
//	                                         session B (§4); AND (D82) an interception
//	                                         root signature never validates as workload
//	                                         identity — the two-hierarchy separation.
//	ROW 3  issued-cred-routing-asymmetry    — intended-service egress swaps EXACTLY
//	                                         once and the scan never flags the
//	                                         proxy-injected credential; the same cred
//	                                         to any OTHER destination → block+log
//	                                         (the doc 12 OQ2 double-fire test, §11.1).
//	ROW 4  fleet-revocation-clock          — a registered FORBIDDEN digest is enforced
//	                                         fleet-wide inside the POL-4 bar INCLUDING
//	                                         sweep-plus-flush; NO proxy build/restart
//	                                         for any rule/digest change (§6.2).
//	ROW 5  validation-failure-403          — a DENY surfaces as the in-band structured
//	                                         403 with a machine-readable reason; a
//	                                         revoked-session cert fails Validate
//	                                         IMMEDIATELY on liveness (stale-cert, §5.4);
//	                                         kill-mid-flight flushes session digests.
//	ROW 6  socket-hold-paths               — approval-in-window proceeds; timeout
//	                                         closes and the first post-approval retry
//	                                         succeeds (ask-grant atomicity); detach-
//	                                         mid-hold runs to timeout (D78); a NEW ask
//	                                         post-detach blocks immediately (§8.2).
//	ROW 7  attendedness-flip               — the same unknown-domain ask socket-holds
//	                                         when ATTENDED and block+logs when
//	                                         UNATTENDED, driven ONLY by the distributed
//	                                         signal; a spectate attach never flips the
//	                                         attended bit (D78, §8.1).
//	ROW 8  git-https-pin                    — git-over-SSH from the golden image fails
//	                                         closed; remotes resolve to HTTPS — guards
//	                                         the §5.3 bypass (an SSH path would skip the
//	                                         swap AND scan planes).
//	ROW 9  log5-join                        — "which session used the GitHub key, when,
//	                                         for what request" is answerable for a test
//	                                         push (the SessionRef join key); fingerprint-
//	                                         only across ALL identity events (§11.1
//	                                         step 6; §9 LOG-1 row; D73 invariant).
//	ROW 10 park-resume-tiers               — at 60 s / 5 min / 15 min (D46 tiers): grants
//	                                         + digests SURVIVE park, liveness is re-checked
//	                                         on resume, and EXPIRED creds re-mint (§5.4).
//
// RUNNABILITY (../README.md "OSS-runnable vs paid-dependent"). Every row here is a
// static data diff with no data-plane or key-store dependency — D85 placed the
// minimal CA, swap mechanics, and digest producer in OSS precisely so the identity
// claims stay OSS-runnable — so the package executes on any checkout via
// `GOWORK=off go test ./...` from any cwd (the fixtures are in-code, so there is
// not even a fixture-path dependency).
//
// REGISTRATION (claim metadata; ../README.md "When it runs"). This is a MULTI-ROW
// package: its ten guardrail tags are single-sourced in identityrows.go as the
// ordered Tags slice, so the package's claim metadata and any future
// guardrail-map.yaml identityrows row name the SAME rows (the orchctl Tags / const
// Tag discipline, extended to ten rows). TestTagsStable pins the slice so a silent
// drift fails HERE rather than against a differently-named map row. The repo-root
// guardrail-map.yaml is NOT edited here (it is Boundary-owned via CODEOWNERS); a
// new unmapped subdir is fail-closed to the FULL matrix (D47), so these rows
// self-gate without a map edit — a map edit buys only a CI-scope narrowing.
//
//	guardrail tags: see Tags (identityrows.go), in REGISTRATION order
//	runnability:    oss-runnable (see RUNNABILITY above)
//	anchor:         doc 16 §13 "Assurance hooks" — the ten identity (c) rows not
//	                already implemented by credswap/secretegress/appinstall
//	                (D50 synthetic; D51/D26 public claims package; D82/D77/D78/D46)
package identityrows
