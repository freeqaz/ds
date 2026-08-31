# Suspend-on-breach-fires conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** trip picture exercising one disposition of
the doc 06 §3c
"Suspend-on-breach fires" claim (doc 03 §7 BIC; the D77 taxonomy revising D53;
the D46 tiered pause budget): a blocklist hit or an `action: suspend` rule
suspends the VM mid-action and resumes transparently within the D46
fully-transparent pause budget (≤5 min), while an `action: block` behavioral cap
serves an in-band machine-readable error + async notification and never
suspends. The dispositions covered are conforming, suspend-class-did-not-suspend,
and resume-over-budget.

Each fixture records a set of guardrail trips and their outcomes/latencies as
DATA; the conformance test mechanically diffs them against the D77/D46 contract,
but no real policy engine, no real suspend/resume, no real VM, and no real clock
is involved. No `DS_KVM_LIVE` token is read or set; no live qemu / KVM is invoked
(D50).

This is an **assurance test for a property we advertise** (suspension reserved
for genuine threats, resume transparent within budget), framed positively per
doc 06 §3c (binding vocabulary). "Breach" is the §3c "suspend-on-breach" claim
name, a guardrail-trip class.

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only
legal `provenance` value in this directory is `synthetic`. Recorded enforcement
traces never enter this repository — re-author them as synthetic equivalents
first, per the canonical contract.
