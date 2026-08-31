<!-- SPDX-License-Identifier: Apache-2.0 -->
# scripts/release/ — the D33 vanilla-Linux-metal release gate

This directory holds the **release-candidate gate that proves every OSS
data-plane release installs on a clean vanilla Linux machine with NO cloud
dependencies** and passes smoke checks — the CI enforcement of **D33** (doc 04
§6). The CI lane that runs it is
the `release-vanilla-metal` CI workflow.

> **D33 (binding).** *"Nothing cloud-specific" is a hard, CI-enforced constraint
> for the data plane: every release installs on vanilla Linux metal.* It backs
> the D15 home-lab guarantee and the D19 bring-compute / on-prem tiers.

> **D80 (binding).** The OSS single-host **all-in-one is `orchestrator-lite`**
> (create/attach/destroy, single-host placement, env-config recording, local
> policy_log + snapshot serving) **plus the host-side `host-agent`**. The paid
> fleet control plane is a *distinct M3 service* speaking the same public protos
> — the OSS/paid line falls on a service boundary, never through a binary. So
> the "release artifact" this gate builds + installs is exactly those two OSS
> binaries (Apache-2.0, D25; listed in `oss-manifest.yaml`).

## What the gate does (and why it has teeth)

The workflow runs three steps on a clean `ubuntu-latest` runner — the **vanilla
Linux metal stand-in** (no cloud SDK pre-installed, no cloud metadata-endpoint
reliance):

1. **Cloud-coupling guard** ([`cloud-coupling-scan.sh`](cloud-coupling-scan.sh))
   — FAIL-CLOSED mechanical scan of the OSS data-plane import/dependency closure
   for cloud-SDK packages and cloud metadata-endpoint coupling. This is the
   **load-bearing claim**: if a cloud dependency is introduced, the scan exits
   non-zero and the release is blocked. Its `--self-test` also asserts the
   synthetic negative-control fixture is rejected (proving the gate has teeth).
2. **Install** ([`install-vanilla-metal.sh`](install-vanilla-metal.sh)) — build
   `orchestrator-lite` + `host-agent` (`cd orchestrator && go build ./cmd/...`)
   and lay them + the `roles/` catalog down under a clean prefix, with **no
   network** (`DS_RELEASE_OFFLINE=1` → `GOPROXY=off`). Stdlib + the repo only.
3. **Smoke** ([`smoke-vanilla-metal.sh`](smoke-vanilla-metal.sh)) — confirm the
   installed all-in-one **starts**, drives its in-process
   create→attach→destroy assembly to completion, and **serves** on a local
   listener. All synthetic/offline (D50): no cloud, no live KVM/metal.

### Triggers — release-candidate only (NOT per-commit)

The lane fires on a **release tag push (`v*`) and manual `workflow_dispatch`**,
never on every push/PR to `main`. Ordinary commits are already covered by the
per-commit Go lanes (`ci.yml`, `go.yml`, `e2e.yml`); this gate exists to catch a
cloud-coupled change at the point it would *ship*.

## The cloud deny-list

`cloud-coupling-scan.sh` matches the OSS data-plane closure + sources against
these cloud-SDK package paths and cloud metadata endpoints (case-insensitive).
Keep this list in sync with `DENY_PATTERNS` in the script and with the
negative-control fixture in [`fixtures/`](fixtures/):

| Provider | Denied import path / endpoint |
|---|---|
| AWS | `github.com/aws/aws-sdk-go` (v1) |
| AWS | `github.com/aws/aws-sdk-go-v2` (v2) |
| AWS | `github.com/aws/smithy-go` (v2 transport runtime) |
| Google Cloud | `cloud.google.com/go` |
| Google Cloud | `google.golang.org/api/compute` (GCE compute client) |
| Azure | `github.com/Azure/azure-sdk-for-go` |
| Azure | `github.com/Azure/go-autorest` |
| Metadata (any) | `169.254.169.254` (EC2/GCE/Azure IMDS link-local IP) |
| Metadata (GCE) | `metadata.google.internal` |
| Metadata (EC2) | `instance-data.ec2.internal` |

**Why this is correct, not arbitrary.** The OSS all-in-one's actual build
closure (`go list -deps ./cmd/orchestrator-lite ./cmd/host-agent`) contains none
of these. The cloud EC2 demo driver
(`orchestrator/internal/hypervisor/ec2demo/`) is a **separate
capability-flagged control-plane tool** (D32/D35) that the all-in-one does not
import — its own `doc.go` records the D33 scope note ("the cloud-SDK ban is a
DATA-PLANE constraint … this demo driver is control-plane tooling … removing it
removes nothing else"). The closure scan proves ec2demo stays out of the OSS
data-plane build; the textual lens explicitly excludes it (it is a deliberate
cloud driver behind the public hypervisor.v1 contract, not part of the artifact).

## Running it locally

```sh
# The cloud-coupling guard (closure scan + negative-control rejection):
scripts/release/cloud-coupling-scan.sh --self-test     # exit 0 = clean + gate has teeth
scripts/release/cloud-coupling-scan.sh                 # exit 0 = OSS closure clean

# Prove the negative control IS rejected (exit 1 expected):
scripts/release/cloud-coupling-scan.sh --scan-file \
    scripts/release/fixtures/cloud-coupled-negative-control.txt

# Install + smoke in one shot (installs to a temp prefix, smokes it, cleans up):
scripts/release/smoke-vanilla-metal.sh

# Or install to a chosen prefix, then smoke that prefix:
PREFIX="$(scripts/release/install-vanilla-metal.sh --prefix /tmp/ds-metal)"
scripts/release/smoke-vanilla-metal.sh --prefix "$PREFIX"

# Offline install (proves no-network: GOPROXY=off, a fetch attempt fails closed):
DS_RELEASE_OFFLINE=1 scripts/release/install-vanilla-metal.sh --prefix /tmp/ds-metal
```

## DEFERRED: the live on-real-metal run (env-gated, NOT in CI)

This gate is deliberately **synthetic and offline** (D50): the smoke drives the
all-in-one's in-process assembly with live backends OFF (`DS_ORCH_LITE_LIVE`
unset → synthetic seams ack create→attach→destroy; `DS_HOSTAGENT_LIVE` unset).
No CI step ever dials a cloud API, a real hypervisor (KVM), a live Identity
service, or external Postgres.

The end-to-end **live-on-real-metal** validation — install the artifact on an
actual vanilla Linux box and run the all-in-one against a real local host agent
/ KVM (and, optionally, external Postgres + the Identity service) — is a
**manual operator procedure** behind documented env gates, intentionally NOT
automated here (it needs a real host this CI runner does not have):

```sh
# On a real vanilla Linux host, after `install-vanilla-metal.sh`:
#   1. Bring up the host agent (live, beside the all-in-one) — needs KVM/libvirt:
DS_HOSTAGENT_LIVE=1 "$PREFIX/bin/ds-host-agent"           # (once contracts freeze)

#   2. Run the all-in-one LIVE against that host agent (+ optional Postgres/Identity):
DS_ORCH_LITE_LIVE=1 \
  DS_ORCH_LITE_LISTEN=127.0.0.1:9091 \
  DS_ORCH_ROLES_DIR="$PREFIX/share/ds/roles" \
  DS_ORCH_LITE_PG_DSN="postgres://…"           `# optional external store (D6)` \
  "$PREFIX/bin/ds-orchestrator-lite"

#   3. Drive a real CreateSession over the served orchestrator.v1 surface and
#      confirm a real VM lifecycle. This is the live leg the synthetic smoke
#      stands in for; it stays a runbook step until a self-hosted virtual-metal
#      runner exists (see the e2e.yml metal-nightly lane, D34).
```

When a self-hosted virtual-metal runner lands (D34), this live leg can flip into
a nightly lane the same way `e2e.yml`'s `metal-nightly` job is scaffolded —
**still no timing budget before M2 (D81)**.
