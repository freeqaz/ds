// SPDX-License-Identifier: Apache-2.0

// Package injectdigest holds the executable form of the inject-class
// **ISSUED{service_id} wrong-destination egress-block** guardrail-conformance row
// (doc 06 §3c "Credential swap never leaks long-lived secrets", the inject-class
// twin: "Inject-class (STS-style short-lived) creds assert the TTL bound and the
// presence of the `ISSUED{service_id}` digest"; doc 16 §5.1/§6/§10; D8/D51/D73).
// It is part of the D51 public claims package (README.md): every guardrail the
// docs promise becomes a test that tries to make the guardrail FAIL and asserts
// it doesn't. It promotes the DIGEST half of the twin; the sibling credttl
// package (credttl.Tag = identity-inject-class-ttl-bound) owns the TTL half.
//
// THE CLAIM (doc 06 §3c inject-class twin; doc 16 §5.1/§6/§10). An inject-class
// credential's ISSUED{service_id} digest is tagged with its INTENDED service, and
// that tag is DERIVED FROM THE GRANT RECORD — a digest's intended service is a
// grant fact (doc 16 §5.1). So the boundary's SecretMatcher knows, for every
// ISSUED digest, the one destination it is issued to:
//
//	(i)  on egress to that INTENDED destination the injected credential fires
//	     exactly once and is NOT flagged (the swap/scan filter-ordering interlock,
//	     doc 16 §10 / §5.5 step 7); and
//	(ii) on egress to any OTHER destination the digest match is a
//	     "keyed-issued-to-wrong-destination" event whose rung default is block+log
//	     (doc 16 §5.5 table; D73 supersedes D53's rung-2 listing) — the wrong
//	     destination is BLOCKED.
//
// This is the enforceable form of the same interlock the production swap path
// turns on (doc 16 §5.5 step 7 / §10), restated here as a public (c)-tier claim
// that runs standalone without the digest feed, the SecretMatcher, or a gRPC seam.
//
// THE CHECK (mechanical destination diff). A synthetic fixture **presentation** —
// one row recording {issued_service_id, egress_destination, blocked} — is diffed
// against the destination fence its own issued service names. The diff FAILS on:
//
//	(a) WRONG-DESTINATION-EGRESSED — the digest was presented to a destination
//	    OTHER than its issued service and was NOT blocked; the ISSUED{service_id}
//	    credential egressed to the wrong destination (doc 16 §5.5
//	    keyed-issued-to-wrong-destination). This is the leg the row exists to
//	    catch: the wrong-destination block regressing to a silent pass.
//	(b) INTENDED-DESTINATION-BLOCKED — the digest was presented to its OWN
//	    intended service but was blocked; the injected credential must fire exactly
//	    once and pass on the intended egress (doc 16 §10), so a block here breaks
//	    the swap. INDEPENDENT of leg (a).
//	(c) UNDECIDABLE — a presentation with a blank issued service or a blank egress
//	    destination names no destination fence, so the wrong-vs-intended verdict is
//	    undecidable; an undecidable destination is treated as a breach, never
//	    silently passed (kin to the credttl UNDECIDABLE-TTL verdict).
//
// A conforming presentation is EITHER an intended-destination egress that was NOT
// blocked (the credential fires and passes) OR a wrong-destination egress that
// WAS blocked (the block held). The conforming control fixture carries BOTH, so
// the green case proves the matching destination passes AND the wrong destination
// is blocked in one picture.
//
// THE ANCHOR (one source for the fence). The intended service is carried
// explicitly in each presentation's `issued_service_id` (so a fixture pins the
// exact destination it asserts against), never fetched from a live grant record
// or digest feed — the check is a static data diff, deterministic across any
// checkout (D50).
//
// SYNTHETIC ONLY (D50). Every fixture under fixtures/ is a hand-authored egress
// picture against the DOCUMENTED ISSUED{service_id}-vs-destination shape (doc 16
// §5.1/§6/§10) reusing the credswap 02-inject-class fixture style, and carries a
// `.provenance` sidecar. Nothing here mints a real credential, computes a real
// HMAC digest, dials the digest feed / SecretMatcher, or opens a grant record —
// the runtime destination match is modeled as fixed rows. There is NO live
// claude / qemu / podman invocation and no DS_*_LIVE token read or set anywhere
// in this package.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). This row is
// oss-runnable: a static presentation-vs-fence diff with no data-plane, seam, or
// credential dependency, so it executes on any checkout via `go test ./...` from
// any cwd (fixture paths are anchored off runtime.Caller, not the process working
// directory).
//
// REGISTRATION (claim metadata — the row is wired into the fail-closed map). This
// adapter is registered in the repo-root guardrail-map.yaml (D47) under the glob
// `assurance/guardrail-conformance/injectdigest/**` with the single guardrail tag
// below; a diff confined to this row runs that tag instead of the full matrix (a
// CI-scope narrowing, fail-closed: an unmapped path still selects the full
// matrix, D47). The tag string is single-sourced as the package's `const Tag`
// (pinned by TestTagStable) so the package's claim metadata and the map row name
// the SAME row:
//
//	guardrail tag: identity-inject-class-wrong-destination-blocked
//	runnability:   oss-runnable (see RUNNABILITY above)
//	anchor:        doc 06 §3c inject-class twin (the ISSUED{service_id} digest half);
//	               doc 16 §5.1/§6/§10 (the wrong-destination egress block)
//
// FOLLOW-UP (doc 06 §3c): the authoritative §3c claims table is owned elsewhere
// and is intentionally NOT edited here. The TTL-bound half of the inject-class
// twin is the SEPARATE credttl row (identity-inject-class-ttl-bound); this
// package promotes ONLY the ISSUED{service_id} wrong-destination egress block. If
// a future change adds an inject-class-digest ROW to the §3c table it must reuse
// this same tag name (identity-inject-class-wrong-destination-blocked) so the
// table, this package, and the guardrail-map stay single-sourced; until then this
// row is registered via the guardrail-map glob + this metadata only (README.md:
// claims are contributed by the workstream that owns each guarantee).
package injectdigest
