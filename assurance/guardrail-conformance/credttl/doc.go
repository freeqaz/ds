// SPDX-License-Identifier: Apache-2.0

// Package credttl holds the executable form of the inject-class **credential-TTL
// bound** guardrail-conformance row (doc 06 §3c "Credential swap never leaks
// long-lived secrets", the inject-class twin: "Inject-class (STS-style
// short-lived) creds assert the TTL bound and the presence of the
// `ISSUED{service_id}` digest"; doc 16 §13 / §5.1 / §5.4; D8/D39/D51). It is part
// of the D51 public claims package (README.md): every guardrail the docs promise
// becomes a test that tries to make the guardrail FAIL and asserts it doesn't.
//
// THE CLAIM (doc 06 §3c inject-class twin; doc 16 §4/§5.4 "TTL-as-revocation").
// The minimal CA ships NO CRL/OCSP (doc 16 §5.4): a short-lived inject-class
// credential is bounded by TTL, so a stolen-but-unswept credential fails the
// moment its horizon passes. A swap-path presentation carries TWO independent
// freshness horizons the validator must both enforce (doc 16 §5.1, doc 19 §8):
//
//	(i)  the presented TOKEN's own TTL (the credential the agent holds), and
//	(ii) the matched GRANT's own TTL (the identity×service×scope×TTL record the
//	     swap executor fetched and cached ≤ session, doc 16 §5.1 / §5.4).
//
// A presentation is fresh iff BOTH horizons are unexpired as of the validation
// fence, and — the intersection-narrowing property — the ALLOW horizon it earns
// is the TIGHTER of the two (min(token TTL, grant TTL)): a token narrower than
// its grant is bounded by the token, a grant narrower than its token is bounded
// by the grant (doc 16 §5.1, doc 19 §8). This is the enforceable form of the
// same two legs the production reference validator turns on
// (identity-validate/refimpl.go HonestDecision: step 3 the token-TTL leg, step 4
// the grant-TTL leg — both DENY `credential_expired`), restated here as a public
// (c)-tier claim that runs standalone without a gRPC seam.
//
// THE CHECK (mechanical TTL diff). A synthetic fixture **presentation** — one row
// recording {token_ttl_unix, grant_ttl_unix} — is diffed against the validation
// policy {now_unix}. The diff FAILS on:
//
//	(a) TOKEN-EXPIRED — the presented token's own TTL is at or before the fence
//	    (token_ttl_unix ≤ now_unix); the credential the agent holds has lapsed
//	    (the token-TTL leg, refimpl.go HonestDecision step 3).
//	(b) GRANT-EXPIRED — the matched grant's own TTL is at or before the fence
//	    (grant_ttl_unix ≤ now_unix); the cached grant has lapsed even if the token
//	    is still fresh (the grant-TTL leg, HonestDecision step 4). The two legs are
//	    INDEPENDENT: either lapsing denies the swap `credential_expired`.
//	(c) UNDECIDABLE — a TTL that is non-positive (≤ 0) names no real horizon, so
//	    the ttl-vs-now arithmetic yields no usable verdict; an undecidable TTL is
//	    treated as a breach, never silently passed (kin to the goldenfreshness
//	    UNROTATABLE verdict for a future-dated mtime). A zero/negative TTL would
//	    otherwise read as "already ≤ now" and be reported as merely expired,
//	    masking a malformed credential as a routine lapse.
//
// A conforming presentation is BOTH horizons strictly in the future; its earned
// ALLOW horizon is min(token_ttl_unix, grant_ttl_unix) — AllowHorizon — the
// tighter horizon that WINS. The boundary is inclusive-lapse (`≤ now` is expired,
// `> now` is fresh), byte-for-byte the refimpl.go comparison, so a credential
// EXACTLY at the fence is expired, not fresh.
//
// THE ANCHOR (one source for the fence). The validation fence is carried
// explicitly in each fixture's `policy.now_unix` (so a fixture pins the exact
// fence it asserts against), never read from a wall clock — the check is a static
// data diff, deterministic across any checkout (D50).
//
// SYNTHETIC ONLY (D50). Every fixture under fixtures/ is a hand-authored
// presentation against the DOCUMENTED two-horizon shape (doc 16 §5.1 / §5.4) and
// carries a `.provenance` sidecar. Nothing here mints a real credential, opens a
// keystore, dials the Validate seam, or reads a wall clock — the runtime
// ttl-vs-now comparison is modeled as fixed rows. There is NO live claude / qemu
// / podman invocation and no DS_*_LIVE token read or set anywhere in this package.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). This row is
// oss-runnable: a static presentation-vs-policy diff with no data-plane, seam, or
// credential dependency, so it executes on any checkout via `go test ./...` from
// any cwd (fixture paths are anchored off runtime.Caller, not the process working
// directory).
//
// REGISTRATION (claim metadata — the row is wired into the fail-closed map). This
// adapter is registered in the repo-root guardrail-map.yaml (D47) under the glob
// `assurance/guardrail-conformance/credttl/**` with the single guardrail tag
// below; a diff confined to this row runs that tag instead of the full matrix (a
// CI-scope narrowing, fail-closed: an unmapped path still selects the full
// matrix, D47). The tag string is single-sourced as the package's `const Tag`
// (pinned by TestTagStable) so the package's claim metadata and the map row name
// the SAME row:
//
//	guardrail tag: identity-inject-class-ttl-bound
//	runnability:   oss-runnable (see RUNNABILITY above)
//	anchor:        doc 06 §3c inject-class twin (the TTL bound); doc 16 §5.1/§5.4
//	               (the token-TTL + grant-TTL freshness legs, TTL-as-revocation)
//
// FOLLOW-UP (doc 06 §3c): the authoritative §3c claims table is owned elsewhere
// and is intentionally NOT edited here. The `ISSUED{service_id}` digest half of
// the inject-class twin is a SEPARATE assertion (the wrong-destination egress
// block, doc 16 §6/§10) owned by its own row; this package promotes ONLY the TTL
// bound. If a future change adds an inject-class-TTL ROW to the §3c table it must
// reuse this same tag name (identity-inject-class-ttl-bound) so the table, this
// package, and the guardrail-map stay single-sourced; until then this row is
// registered via the guardrail-map glob + this metadata only (README.md: claims
// are contributed by the workstream that owns each guarantee).
package credttl
