# tlsproxyinspect conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

## What these fixtures are

These `*.golden` files are the recorded request/response **SHAPE** of the
TLS-3 egress-gateway conformance workloads (curl / npm / git / DoH / pinned
pass-through over the egress gateway; doc 06 §2.2, doc 09 §5 TLS-3/4/6, doc 12
§5.3). They are produced by the conformance test itself, not captured from a
live service: the offline test (the default `go test ./tlsproxyinspect/...`
posture, the one CI runs) builds each trace IN-PROCESS from a canonical,
fixed exchange — invented documentation hostnames (`conformance.example`,
`git.conformance.example`, `pinned.example`), fixed non-sensitive bodies, and
the SYSTEM's own real verdicts (the policy/dispatcher decide blocked vs
forwarded for DoH; the real credential-swap executor rewrites the git-push
Authorization) — then replays it byte-identically against the on-disk golden as
the no-regression assert. The fixtures are (re)written ONLY on the record pass,
`DS_TLS_GOLDEN_RECORD=1` (`writeGolden`); CI never sets it.

Bodies, pack data, tarballs, and the DoH DNS wireformat query are pinned by
**digest + length only** — never payload bytes — and guard tests
(`Test*GoldenFixturesNoSecretPayload`, `TestDoH_GoldenFixtureNoQueryPayload`)
assert no raw payload, DNS query, or credential value is ever on disk. The
git-push golden carries the long-lived upstream FINGERPRINT (the swap-rung
proof) but never a credential value. So every byte here is authored/generated,
documentation-shaped, and credential-free: class `synthetic` (D50). Nothing is
recorded from a live boundary, a live upstream, or any real session.

## Tag format

Non-NDJSON fixtures carry the D50 provenance object in a `<name>.provenance`
sidecar file committed beside the fixture (the non-NDJSON convention from the
canonical contract). `scripts/check-fixture-provenance.sh` scans this directory
and fails on a missing `PROVENANCE.md`, a missing sidecar, or any `provenance`
value other than `synthetic`. The only legal `provenance` value in this
directory is `synthetic`. Recorded traces never enter this repository —
re-author them as synthetic equivalents (the record pass over canonical
in-process exchanges) first, per the canonical contract.

## Committed fixtures

| File | Workload | Class | Role |
|---|---|---|---|
| `transparent_curl_get.golden` | curl GET over the transparent path (doc 06 §2.2 row 1) | synthetic | positive: request/response shape, headers byte-identical, body by digest |
| `transparent_git_handshake.golden` | git-over-HTTPS smart-HTTP handshake over the transparent path (doc 06 §2.2 row 2) | synthetic | positive: info/refs advertisement + upload-pack/pack-data shape, pack by digest |
| `connect_npm_install.golden` | npm install over the EXPLICIT CONNECT path (doc 06 §2.2 row 2) | synthetic | positive: CONNECT preamble + metadata GET + tarball GET shape, body/tarball by digest |
| `connect_git_push_swap.golden` | git push with credential swap over the CONNECT path (doc 06 §2.2 + §3(c)) | synthetic | positive: CONNECT preamble + ls-remote + receive-pack shape + the swap rung (long-lived FINGERPRINT, never a credential value) |
| `doh_blocked.golden` | DoH bypass blocked at the inspected path (doc 06 §2.2 row 5; TLS-6/NFT-4; D42/D68/D70) | synthetic | block verdict + rule provenance (`doh-blocked`/`boundary`) per DoH shape; the DNS wireformat query is pinned by digest only |
| `passthrough_pinned_cert.golden` | cert-pinned client through an opaque pass-through tunnel (doc 06 §2.2 row 4; TLS-4; D17/D74) | synthetic | opaque-tunnel trace shape + non-claim flags (pin_holds, swap_occurred=false, inspected=false, leaf_minted_for_origin=false); tunneled handshake by digest |
