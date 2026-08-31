<!-- SPDX-License-Identifier: Apache-2.0 -->
# scripts/live-mvp — the single-box serpent→VM live-validation harness

Operator scripts that bring up the **production-shaped service stack** on one box
and drive a **real Claude Code running inside a per-session KVM VM** through
`serpent claude --vm`. This is the **Milestone-1 LIVE CLOSE** harness; the
authoritative runbook + data-path diagram is
[`../../orchestrator/cmd/host-agent/LIVE-SMOKE.md` §A](../../orchestrator/cmd/host-agent/LIVE-SMOKE.md).

> **MVP posture (contained to a single trusted box).** NO auth
> (fake/no-op attach token + identity), **SLIRP-direct egress**, and the operator's
> own Claude OAuth token injected into the VM. This is **validation**, NOT the
> production credential-swap or the gated egress gateways (ds-dnsgate/ds-tlsproxy)
> — those are the separate `ds-gated-egress*.sh` phase. Runtime artifacts (binaries,
> overlays, ISOs, logs) live under `~/tmp` (btrfs/reflink), never `/tmp`.
>
> **Secrets (D50):** none are embedded here, and none are on an argv.
> `ds-serve-stack.sh` renders the in-guest CC credential at runtime into a **0600
> `KEY=VALUE` file** the host-agent consumes **once** via `-launch-env-file` at
> flag-parse time; the script deletes it as soon as the child is alive. (The old
> `-launch-env CLAUDE_CODE_OAUTH_TOKEN=…` form published the token to every local
> process through the world-readable `/proc/<pid>/cmdline` — that smell is fixed.
> The MVP posture itself is unchanged: the operator's own credential still enters
> the VM.) Only **addresses** ride the argv, per the host-agent's own `-launch-env`
> contract (non-secret references only, D7/D39).
>
> **Residual, measured 2026-07-30:** closing the argv leak does *not* make the
> credential unreadable to other local uids. The per-session **config-drive ISO**
> under the overlay dir is created **0644** and the token is in it verbatim (the
> 0700 `…config.d` staging dir it is built from is fine). That is the MVP
> config-drive design, not a regression — `DestroySession` purges the ISO
> (§4.2 teardown) and `down --purge` sweeps any the backstop path left — but until
> the ISO is tightened, argv-hardening alone is not a multi-uid boundary.
> `down --purge` also removes the per-session serial logs, attach tokens, minted
> CA + private key, session-mode markers and session records, which the
> domain-destroy backstop leaves behind.

## Auth postures (`DS_AUTH_POSTURE`)

| value | credential source | in-guest effect |
| --- | --- | --- |
| `oauth` (default) | `.claudeAiOauth.accessToken` from `~/.claude/.credentials.json` (needs `jq`) | `CLAUDE_CODE_OAUTH_TOKEN` |
| `swap` | `DS_SWAP_TOKEN_FILE` (default `~/.config/dream-serpent/proxy-auth-token`) | `ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL=$DS_SWAP_BASE_URL` |

Use `swap` when the host runs a **token-swap proxy** and the on-disk OAuth
credential is a stub (zero-length `accessToken` — the `oauth` posture then fails
loudly and points here). `DS_SWAP_BASE_URL` defaults to `http://10.0.2.2:8787`:
`10.0.2.2` is SLIRP's alias for the host, so the guest reaches a host-local proxy
without any LAN routing. `DS_AUTH_POSTURE=swap scripts/live-mvp/ds-serve-stack.sh up`
is the whole posture, in-repo — no side-launcher needed.

Check either posture without booting anything:

```sh
DS_AUTH_POSTURE=swap scripts/live-mvp/ds-serve-stack.sh preflight
```

It verifies the artifacts + binaries **and** renders the credential to a scratch
0600 file under `$DS_RUN_DIR`, then deletes it. Nothing starts, no VM boots.

## Images and kernel cmdline

Defaults point at the artifacts the current rootless bake produces, under
`$DS_IMAGES_DIR` (default `~/tmp/ds-images`):

| default | override |
| --- | --- |
| `m0-base-routed-cc.raw` | `DS_BASE_IMAGE` |
| `m0-vmlinuz-routed-cc` | `DS_KERNEL_PATH` |
| `m0-initrd-routed-cc.img` | `DS_INITRD_PATH` |

`preflight` names the missing file **and** its override var, so a stale default
can never silently boot the wrong image.

`DS_KERNEL_CMDLINE` defaults to
`root=LABEL=DS_M0ROOT console=ttyS0,115200 rw ip=dhcp` — `libvirt.DefaultKernelCmdline`
plus `ip=dhcp`. That suffix is a **workaround for a defect in the routed-cc
image**, not a preference: the bake installs with `--no-install-recommends` and
never lists `dbus`, so the guest has no system bus; `ds-slirp-net.service` (which
drops the SLIRP DHCP `.network`) ends with `networkctl reload`, which on systemd
252 requires that bus. The reload fails → the unit fails → the already-running
`systemd-networkd` never re-reads the dropped config → the NIC is never addressed
→ in-guest CC dies with `API Error: FailedToOpenSocket`. `ip=dhcp` sidesteps the
reload entirely: `systemd-network-generator` renders the config into
`/run/systemd/network` *before* networkd starts. This stack is SLIRP-only (it
never passes `-routed-tap`, whose guests take a static `10.77.<idx>.1/31` from
the config-drive), so there is no DHCP-vs-static race. The **source fix (adding
`dbus` to both bakes) is landed but needs a rebake + live validation** — tracked
in the taskdb; drop the `ip=dhcp` default once that image is proven.

## The everyday command — test it yourself

```sh
# 1. bring the stack up (builds 6 binaries from THIS checkout into the repo's
#    .bin/ — DS_BIN_DIR overrides — starts the orchestrator + host-agent, and
#    opens the recover-before-serve latch):
scripts/live-mvp/ds-serve-stack.sh up

# 2. in a real terminal, drop into the interactive in-VM Claude Code TUI:
export DS_ORCHESTRATOR=127.0.0.1:18090
PATH=./.bin:$PATH serpent claude --vm \
  --repo demo --env-config-ref demo-env --launching-user mvp-user
#   type a prompt — you are talking to the real CC running INSIDE a KVM VM.

# 3. tear down when done (stops the daemons; destroy any leftover VM with
#    `virsh -c qemu:///session destroy <ds-sess-…>`):
scripts/live-mvp/ds-serve-stack.sh down
```

`ds-serve-stack.sh {up|down|build|preflight|status|command}` prints the exact command on
`up`/`command`. The plain `serpent claude` (no `--vm`) still runs LOCAL CC through
the ds-capture gateway, unchanged.

## Non-interactive verification (smoke)

```sh
scripts/live-mvp/ds-serpent-claude-run.sh    # drives 'Reply with exactly: PONG',
                                             # asserts the answer + session success
```

## What's here

| script | role |
| --- | --- |
| `ds-serve-stack.sh` | bring up / tear down the orchestrator + host-agent stack (the front door) |
| `ds-serpent-claude-run.sh` | headless scripted-prompt smoke through `serpent claude --vm` |
| `ds-genisoimage-podman.sh` | drop-in `genisoimage` via rootless podman (config-drive ISO on a host with no iso tool); `ds-serve-stack.sh`'s default `DS_HOSTAGENT_GENISOIMAGE_BIN` |
| `ds-test-cc-drive.sh` | reproduce the proven MVP CC-drive end to end, idempotently |
| `ds-gated-egress.sh` | the NEXT phase: stand up the gated egress (ds-dnsgate/ds-tlsproxy) ruleset |
| `ds-gated-egress-validate.sh` | netns-only validation of the gated-egress ruleset |
| `setup-local-kvm.sh` | one-time host provisioning (rootless KVM/vhost-vsock) for this box |
