# proto/baselines/ — breaking-change baselines

Committed descriptor sets that `buf breaking` gates merges against (D24; see
[../buf.yaml](../buf.yaml) and `.github/workflows/contracts.yml`).

**Empty until the first freeze PR — by design.** A baseline lands here only as part of
a freeze PR (the PR that lands a package's `.proto` bodies, flips its
[FREEZE.md](../FREEZE.md) row to FROZEN, and ships its generated fakes). From that point
the baseline is frozen-by-CI: only a subsequent freeze PR for the same package (additive,
checklist-cited) may update it. Hand edits here are never legitimate.
