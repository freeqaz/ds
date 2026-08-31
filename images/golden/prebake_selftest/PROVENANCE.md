# prebake_selftest fixture provenance — D50

**Rule: if it is in git, it is synthetic.** No exceptions.

D50 (doc 04 §6) tags every test
fixture with a provenance class. These fixtures are all `synthetic`: they are
hand-authored prebake configs that exist only to drive `prebake.sh --self-test`.

## What these fixtures are

`prebake.sh` is the CI-to-golden-image pre-bake orchestration (doc 03 §6, D12);
its `--self-test` proves the **config-gating logic** offline — a configured
(repo, branch) drives the bake (a dry-run plan is emitted), an unconfigured one
is skipped/untouched — without invoking any live qemu/libguestfs tooling.

| File | Shape | Class | Role |
|---|---|---|---|
| `configured.config.yaml` | prebake config | synthetic | positive: global `enabled: true`, one repo opted IN (`prebake: true`) + one opted OUT (`prebake: false`); the self-test asserts opted-in emits a PLAN, opted-out + absent repos skip |
| `disabled.config.yaml` | prebake config | synthetic | NEGATIVE: global `enabled: false` (the D12 default) with the same repo opted in below; the self-test asserts the kill-switch short-circuits and NO repo is baked |

The repo names (`github.com/acme/monorepo`, `github.com/acme/scratch`,
`github.com/acme/not-listed`) are invented — never a real repo, never a real
credential. Non-NDJSON fixtures carry the D50 provenance object in a
`<name>.provenance` sidecar.
