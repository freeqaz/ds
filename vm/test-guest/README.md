# vm/test-guest/ — the local test-guest fixture for the sudo-free qemu rig

**Owner:** VM & runtime · **OSS** (Apache-2.0, D15/D25) ·
**Decisions:** D5/D31 (virtual-metal local substitute), D29 (raw-base/overlay
disk stance), D50 (synthetic-only — no secrets baked) ·
**Source:** doc 01 §4 (QEMU/KVM
stack), doc 13 §3/§4
(per-session-tap addressing)

## What this is

A **small, reproducible, pinned + sha256-verified bootable test guest** for the
**sudo-free qemu rig** (`~/.local/opt/qemu`, qemu 11, KVM via the 0666
`/dev/kvm`). It exists so the local boot + network path can be exercised
end-to-end without sudo: build a verified image, generate a NoCloud cloud-init
seed, and boot it under qemu **user-net** for a self-asserting smoke (shell +
`curl` + curl-out), or under a **dstap-0 tap** attach for the boundary
integration step.

It is a **TEST FIXTURE**, explicitly **NOT** the heavyweight
[`images/golden/`](../../images/golden/) M0 session image and **NOT** the
glibc/Debian + pinned-Claude-Code base [`vm/m0-image/`](../m0-image/)
hand-builds. See [`IMAGE-IDENTITY.md`](IMAGE-IDENTITY.md) for why a musl/Alpine
fixture is correct here.

**The committed artifact is the reproducible builder + scripts + tests + docs —
never the image/seed blob.** All blobs live under `~/tmp/ds-test-guest`
(btrfs/CoW; `.gitignore`); no file in this tree exceeds 1 MB.

## Files

| File | Role |
|---|---|
| [`test-guest.env`](test-guest.env) | **Single source of truth** for every pin (Alpine version, sha256/sha512, static `10.77.0.x` net, qemu rig paths, artifact dir). Sourced by every script. |
| [`build-test-guest.sh`](build-test-guest.sh) | Fetch (`curl --noproxy '*'`) + sha256/sha512-verify the pinned image, then generate the NoCloud seed (`--smoke` user-net DHCP / `--tap` static dstap-0). `--plan` and `--self-test` run offline. |
| [`boot-test-guest.sh`](boot-test-guest.sh) | Boot wrapper for the sudo-free qemu: `--smoke` (user-net, self-asserting) or `--tap` (attach `dstap-0`). Plan-only unless `DS_TG_BOOT=1`; snapshot=on (base never mutated). |
| [`mkseed.py`](mkseed.py) | Pure-stdlib ISO9660 writer for the NoCloud seed (used when `genisoimage`/`xorriso`/`mkisofs`/`cloud-localds` are absent — e.g. the sandbox). Emits the `cidata`-labelled seed cloud-init keys on. |
| [`verify-test-guest.sh`](verify-test-guest.sh) | Anti-drift guard: env-pin consistency, doc↔env token agreement, SPDX headers, proxy-bypass fetch, no committed blob, and shebang↔parser agreement (each `*.sh` parses under the parser its shebang names; a bash-array body can't carry a `/bin/sh` shebang; `shellcheck --shell=bash` when present, soft-skip when absent). `--self-test` injects drift and confirms each guard catches it. |
| [`IMAGE-IDENTITY.md`](IMAGE-IDENTITY.md) | The pins + provenance + integrity chain (sha256 ⇐ Alpine's published sha512). |
| [`BUILD-NOTES.md`](BUILD-NOTES.md) | Recorded boot-smoke evidence (shell + curl + curl-out over user-net) and the environment it ran in. |
| [`.gitignore`](.gitignore) | Belt-and-suspenders: nothing image/seed-shaped or >1 MB is committable. |

## Build & boot

```sh
# Offline sanity (no network, no qemu): pins + seed-gen + cidata label + negative case.
vm/test-guest/build-test-guest.sh --self-test
vm/test-guest/verify-test-guest.sh --self-test

# Print the plan and validate pins (no download).
vm/test-guest/build-test-guest.sh --plan

# Fetch the pinned image (curl --noproxy) + sha256/sha512-verify + smoke seed.
vm/test-guest/build-test-guest.sh --smoke

# Boot it under the sudo-free qemu (user-net) and self-assert shell+curl+egress.
DS_TG_BOOT=1 vm/test-guest/boot-test-guest.sh --smoke
```

The smoke seed makes cloud-init DHCP on the NIC, ensure `curl`, run a
self-asserting `curl`-out (sentinels to the serial console), then `poweroff` —
so the harness verifies the done-when and **exits on its own**. A PASS is the
three sentinels with an HTTP `2xx/3xx`:

```
===DS-SMOKE-BEGIN===
DS-SMOKE-CURL-PRESENT
DS-SMOKE-HTTP-200
===DS-SMOKE-END===
```

## Network modes — user-net smoke vs the dstap-0 tap (§E2)

- **`--smoke` (user-net):** qemu `-netdev user` (slirp). No sudo, no tap. This is
  the **self-contained boot-smoke this unit owns** — DHCP `10.0.2.x` with a
  working slirp gateway/DNS, so the curl-out assert has real egress.
- **`--tap` (dstap-0):** qemu `-netdev tap,ifname=dstap-0,script=no,downscript=no`
  with the **static** `10.77.0.2/24` gw/DNS `10.77.0.1`
  (doc 13) seed. **Creating**
  `dstap-0` (needs sudo) and the live tap attach are the **SEPARATE §E2 task** —
  this wrapper only **attaches** to an already-present tap and **refuses** if it
  is absent.

## Network note (proxy)

A global `HTTPS_PROXY=:18080` breaks non-API egress, so the builder always
fetches the base image with `curl --noproxy '*'`. The in-guest smoke `curl`
runs inside the VM over qemu user-net and is unaffected by the host proxy.

## Reproducibility & integrity

The base image is pinned to **Alpine 3.21.7** (`bios-cloudinit` nocloud qcow2)
and **sha256-verified** on every fetch (fail-closed on mismatch). The sha256 pin
chains to Alpine's own published `.sha512` sidecar — see
[`IMAGE-IDENTITY.md`](IMAGE-IDENTITY.md) and [`BUILD-NOTES.md`](BUILD-NOTES.md).
`mkseed.py` is byte-deterministic, so the same seed inputs reproduce the same
seed ISO.

## Gate

This tree is shell + Python + config (no Go). Its gate legs:

```sh
for f in vm/test-guest/*.sh; do [ -f "$f" ] && bash -n "$f"; done   # parse-check (bash -n; see note)
vm/test-guest/build-test-guest.sh --self-test    # offline pins + seed-gen + negative case
vm/test-guest/verify-test-guest.sh --self-test   # anti-drift (incl. shebang/parser-agreement), injected-drift harness
```

> **Parse-check uses `bash -n`, not `sh -n`.** Every script here is
> `#!/usr/bin/env bash`, and `boot-test-guest.sh` builds the qemu invocation as a
> **bash array** (`QEMU_ARGV`, the no-eval/quoting-safe form). A strict POSIX
> parser (`dash`, the `/bin/sh` on a stock CI runner) **rejects** that array
> syntax at parse time, so **`bash -n` — the parser the shebang names — is the
> canonical/CI checker** (CI's lane, `.github/workflows/vm-test-guest.yml`, runs
> `bash -n`). An `sh -n` leg only passes where `/bin/sh` happens to be symlinked
> to bash; do not rely on that assumption. `verify-test-guest.sh` adds a
> **shebang/parser-agreement** guard (run in CI and by `--self-test`) that
> asserts each script parses under the parser its shebang names and that a
> bash-array body can never carry a `/bin/sh` shebang — closing this drift in
> either direction. Mirrors [`BUILD-NOTES.md`](BUILD-NOTES.md) §4a.

`verify-test-guest.sh` is deliberately **not** named `images/*/lint-*.sh` and
lives under `vm/`, so it stays outside the repo-wide `check-image-drift` glob
(Image & cache builder owns that); it is invoked directly here. The SPDX headers
on the shell scripts and `mkseed.py` are covered by `make check-spdx` (the `vm/`
tree is in scope).

## Neighbors

| Tree | Relation |
|---|---|
| [`vm/m0-image/`](../m0-image/) | The heavyweight hand-built M0 base image — this fixture is the **light** counterpart for the local qemu rig, not a replacement. |
| [`images/golden/`](../../images/golden/) | Industrializes the real session image from M1; unrelated to this local fixture. |
| boundary / per-session-tap (`dstap-0`) | The §E2 task creates `dstap-0` and runs the live tap attach this wrapper supports; the static seed applies the doc-13 addressing. |
