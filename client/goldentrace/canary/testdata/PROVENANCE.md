# Canary canon goldens — provenance

**Synthetic by derivation.** Every `*.canon.ndjson` here is the
id-relative, timing-erased CANON projection of a committed synthetic
`../../../fixtures/*.cc-wire.ndjson` cassette — regenerated **by command**:

```sh
cd client && go run ./goldentrace/canary/cmd/canary regen -update
```

Because the source cassettes are `synthetic` (D50; `client/fixtures/PROVENANCE.md`)
and the canon transform (`fidelity.Canonicalize`) **erases** every volatile id,
timing, cost, and token magnitude (replacing ids with correlation-preserving
`<kind#N>` placeholders and reducing usage to a `<present>` marker), these
goldens carry **no real path, no credential, no session UUID, no cost** — they
are clean-by-construction, never a scrub of a raw capture.

These files live under `testdata/`, not under a `fixtures/` directory, so the
git-side fixture-provenance gate (`.github/workflows/fixtures-provenance.yml`)
does not require a `ds_fixture` header on them — they are regenerable goldens,
not seam fixtures. The secret-shaped-value scan over `git ls-files` still
covers them (and passes: id-relative canon contains no token-shaped value).

## What each golden pins

One golden per committed cassette. The canary's always-on lane regenerates each
by command and diffs it against the committed golden; a divergence is a STALE
cassette (re-author it) or — on the DS_E2E_LIVE-gated CC-latest tier — genuine
CC drift queued for review (D49). Refresh a golden with `regen -update` only
after reviewing the diff (the insta-style refresh, `../../README.md` §Refresh).
