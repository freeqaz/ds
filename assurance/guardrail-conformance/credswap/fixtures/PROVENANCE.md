# Cred-swap-never-leaks conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** credential picture exercising one
disposition of the doc 06 §3c
"Credential swap never leaks long-lived secrets" claim (D8/D39/D83; doc 16 §13;
the inject-class split per doc 20 §7.3): a swap-class long-lived credential that
must be absent from all five enumerated in-VM/host surfaces (disk, env, CoW
delta, agent-readable response, metal host), and an inject-class credential that
lives in the VM by design but is bounded by a TTL and an `ISSUED{service_id}`
digest. The dispositions covered are conforming, swap-class-leak-in-VM, and the
inject-class twin (TTL-unbounded + missing ISSUED digest).

Each fixture records the credential class and its surface observations as DATA;
the conformance test mechanically scans them, but no real credential is minted,
no key store is opened, no swap is run, and no real VM disk/env/CoW overlay or
metal host is touched. No `DS_KVM_LIVE` token is read or set; no live Vault /
OpenBao / qemu / KVM is invoked (D50).

Each fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only
legal `provenance` value in this directory is `synthetic`. Recorded credential
material never enters this repository — re-author it as synthetic placeholder
strings first, per the canonical contract.
