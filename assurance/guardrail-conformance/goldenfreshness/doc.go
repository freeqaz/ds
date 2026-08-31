// SPDX-License-Identifier: Apache-2.0

// Package goldenfreshness holds the executable form of the golden-image
// **rotation / freshness** guardrail-conformance row (doc 03 §6 "Package & build
// caching", the "Nightly golden images" bullet — what this tree names the
// "CVE-roll SLA"; D12/D29/D49). "CVE-roll SLA" is the rotation policy's coined
// name, not a doc 03 section title. It is part of the D51 public claims package
// (README.md): every guardrail the docs promise becomes a test that tries to make
// the guardrail FAIL and asserts it doesn't.
//
// THE CLAIM (doc 03 §6 "Package & build caching", "Nightly golden images" bullet:
// "no instance lives long enough to drift"). A nightly job rebuilds the golden
// image every session clones from (D29), so a dropped CVE is answered by rolling
// the image rather than patching a long-lived box. The enforceable form is a
// **freshness / max-age check** (images/golden/README.md "The rotation policy —
// the CVE-roll SLA"): the golden a session clones from is
// never older than the **rotation window**, and an opted-in `(repo, branch)`
// whose golden has never been baked cannot back a session. This is the row that
// makes the rotation SLA mechanically checkable rather than merely documented —
// the same promise images/golden/nightly-rebuild.sh `--check-rotation` enforces
// at runtime, restated here as a public (c)-tier claim.
//
// THE CHECK (mechanical freshness diff). A synthetic fixture **golden manifest**
// — one row per opted-in `(repo, branch)` recording {repo, branch, present,
// age_hours} — is diffed against the rotation policy {max_age_hours}. The diff
// FAILS on:
//
//	(a) STALE — a present golden whose age exceeds the rotation window
//	    (max_age_hours); it must be rolled before any new session clones from it.
//	(b) MISSING — an opted-in golden that has never been baked (present=false);
//	    it cannot back a session until the first bake produces it.
//	(c) UNROTATABLE — a present golden whose age is NEGATIVE (a mtime in the
//	    future), so the now−mtime freshness arithmetic yields no usable verdict;
//	    an undecidable golden is treated as a breach, never silently passed. This
//	    is the SAME verdict the runtime emits (images/golden/nightly-rebuild.sh
//	    check_rotation's UNROTATABLE row, token UNROTATABLE_VERDICT_CLASS): a
//	    future-dated golden would otherwise slip past the `age > window` test and
//	    read FRESH forever. Runtime classification == this public claim; the
//	    runtime self-test asserts its verdict token equals ViolationUnrotatable.
//
// A conforming manifest is every opted-in golden present and within the window.
//
// THE ANCHOR (one source for the window default). The rotation window default
// (24h — the nightly cadence) and the DS_GOLDEN_MAX_AGE_HOURS override name are
// fixed by doc 03 §6 "Package & build caching" ("Nightly golden images" bullet) /
// images/golden/README.md. The policy a manifest is diffed
// against is carried explicitly in each fixture's `policy.max_age_hours` (so a
// fixture pins the exact window it asserts against), and DefaultRotationWindow
// restates the documented 24h default the runtime check uses when no override is
// set — a guard test asserts that default matches the documented cadence, so a
// silent drift of the constant fails HERE.
//
// SYNTHETIC ONLY (D50). Every fixture under fixtures/ is a hand-authored golden
// manifest against the DOCUMENTED rotation-policy shape (doc 03 §6 "Package &
// build caching", "Nightly golden images" bullet / images/golden/README.md) and
// carries a `.provenance` sidecar. Nothing here
// stats a real image, opens a qcow2, runs qemu/libguestfs, or fires a bake — the
// runtime stat+arithmetic of nightly-rebuild.sh is modeled as fixed manifest
// rows. There is NO live claude / qemu(VM-run) / podman / libguestfs invocation
// anywhere in this package, and no DS_GOLDEN_BAKE_LIVE / DS_KVM_LIVE token is
// read or set: the manifests record age and presence as DATA, never by touching
// the filesystem.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). This row is
// oss-runnable: it is a static manifest-vs-policy diff with no data-plane or
// image dependency, so it executes on any checkout via `go test ./...` from any
// cwd (the fixture paths are anchored off runtime.Caller, not the process working
// directory).
//
// REGISTRATION (claim metadata — the row is now wired into the fail-closed map).
// This adapter is registered in the repo-root guardrail-map.yaml (D47) under the
// glob `assurance/guardrail-conformance/goldenfreshness/**` with the single
// guardrail tag below; a diff confined to this row runs that tag instead of the
// full matrix (a CI-scope narrowing, fail-closed: an unmapped path still selects
// the full matrix, D47). The tag string is single-sourced here so the package's
// claim metadata and the map row name the SAME row:
//
//	guardrail tag: golden-rotation-freshness
//	runnability:   oss-runnable (see RUNNABILITY above)
//	anchor:        doc 03 §6 "Package & build caching", "Nightly golden images"
//	               bullet (the rotation / CVE-roll-SLA freshness check)
//
// FOLLOW-UP (doc 06 §3c): the authoritative §3c claims table is owned elsewhere
// and is intentionally NOT edited here. If a future change adds a golden-rotation
// /freshness ROW to the §3c table, it must reuse this same tag name
// (golden-rotation-freshness) so the table, this package, and the guardrail-map
// stay single-sourced; until then this row is registered via the guardrail-map
// glob + this metadata only (README.md: claims are contributed by the workstream
// that owns each guarantee).
package goldenfreshness
