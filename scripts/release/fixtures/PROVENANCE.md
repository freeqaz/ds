# Fixture provenance — D50

**Rule: if it is in git, it is synthetic.** No exceptions.

D50 (doc 04 §6) tags every test
fixture with a provenance class; in this directory the only legal value is
`synthetic` (authored by hand, contains no real user/partner data and no real
credentials). Non-NDJSON fixtures carry the same `ds_fixture` JSON object in a
`<name>.provenance` sidecar.

## What lives here — negative-control fixtures for the D33 gate

These are the **negative controls** that prove the
[cloud-coupling scan](../cloud-coupling-scan.sh) has teeth: a gate that cannot
fail is not a gate, so we keep a file the scan is REQUIRED to reject. The scan
that gates releases is wired in
the `release-vanilla-metal` CI workflow
(D33: the OSS data plane installs on vanilla Linux metal with no cloud deps).

### `cloud-coupled-negative-control.txt`

A **synthetic, deliberately cloud-coupled** blob (never built, never imported —
not a `.go` file under any module, so the Go toolchain never compiles or links
it). It embeds **one line per cloud deny-list entry** — every AWS / Google Cloud
/ Azure SDK import path and every cloud instance-metadata endpoint the scan
looks for (see the deny-list table in [`../README.md`](../README.md)). Its only
job is to be flagged:

```sh
# Must exit NON-ZERO (the fixture IS cloud-coupled):
scripts/release/cloud-coupling-scan.sh --scan-file \
    scripts/release/fixtures/cloud-coupled-negative-control.txt

# The gate's self-test asserts exactly that rejection, alongside the real
# closure scan coming back clean:
scripts/release/cloud-coupling-scan.sh --self-test
```

If you add a new entry to the cloud deny-list in `cloud-coupling-scan.sh`, add a
matching line to the fixture so the self-test continues to exercise every lens.
If this fixture ever stops being rejected, the gate has lost its teeth — fix the
scan, not the fixture.

## Tag format

Every non-NDJSON fixture in this directory carries a `<name>.provenance` sidecar
holding the `ds_fixture` header object:

```
{"ds_fixture":{"provenance":"synthetic","seam":"release/cloud-coupling-scan deny-list (D33)","created":"YYYY-MM-DD","note":"…"}}
```

- `provenance` is the D50 tag; here the only legal value is `synthetic`.
- `seam` names what the fixture pins (the D33 cloud-coupling deny-list).

CI (`.github/workflows/fixtures-provenance.yml` + `make repo-lints` →
`scripts/check-fixture-provenance.sh`) scans fixture directories and fails on a
missing `PROVENANCE.md` contract, a missing sidecar, or any provenance value
other than `synthetic`.
