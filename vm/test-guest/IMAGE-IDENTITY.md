# vm/test-guest/ — image identity & pins (local test fixture)

**Owner:** VM & runtime · **OSS** (Apache-2.0, D15/D25) ·
**Decisions:** D5/D31 (the virtual-metal substitute), D29 (raw-base/overlay
disk stance the rig respects), D50 (synthetic/scrubbed only — no secrets baked)
· **Source:** doc 13 §3/§4
(per-session-tap addressing), doc 01
§4 (QEMU/KVM stack)

## What this image IS — and is NOT

This is a **lightweight, pinned, sha256-verified bootable test guest** for the
**sudo-free qemu rig** — a fixture that exercises the local boot + network path
(`-netdev user` smoke, `-netdev tap` dstap-0 attach). It is **explicitly NOT**
the heavyweight [`images/golden/`](../../images/golden/) M0 session image, and
not the glibc/Debian + pinned-Claude-Code base [`vm/m0-image/`](../m0-image/)
hand-builds. A musl/Alpine fixture is correct here precisely because **nothing
in this tree resolves through `ds-dnsgate`'s ask path** — the doc 11 §8.6
musl-REFUSED adjudication governs the *production guest userland*, not a local
boot fixture whose only egress is a smoke `curl` over qemu user-net.

The committed artifact is the **reproducible builder + scripts + tests + docs**.
**No image/seed blob is ever committed** (`.gitignore`); the qcow2 and seed ISO
live under `$TG_ARTIFACT_DIR` (`~/tmp/ds-test-guest`, btrfs/CoW). No file in
this tree exceeds 1 MB.

## Pins (single source of truth: [`test-guest.env`](test-guest.env))

`verify-test-guest.sh` enforces that the values below match `test-guest.env`
token-for-token, so a pin bump is one reviewed diff that cannot drift this doc
out from under it.

| Pin | Value | `test-guest.env` key |
|---|---|---|
| Base image | Alpine **3.21.7** `x86_64` `bios-cloudinit-r0` (nocloud cloud qcow2) | `TG_ALPINE_VERSION` / `TG_ALPINE_ARCH` / `TG_ALPINE_FLAVOR` |
| Image file | `nocloud_alpine-3.21.7-x86_64-bios-cloudinit-r0.qcow2` | `TG_IMAGE_NAME` |
| Fetch base | `https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/cloud` | `TG_IMAGE_BASE_URL` |
| **sha256 (the pin)** | `17bdcba6c3cf1694d3d6f841acc0ec87dc201aef3dca2673f2f948b401c1e516` | `TG_IMAGE_SHA256` |
| sha512 (vendor sidecar) | `5b22a46e9aa6bbacf585c055e87362c8be1993e53c121bdaf74203ac3490c70bdbbf714df4276eef36184ea8c11fd7cd3b28c9ccc74f6a9a82c430d441fa2f95` | `TG_IMAGE_SHA512` |
| Static guest addr (tap) | `10.77.0.2/24`, gw/DNS `10.77.0.1` | `TG_GUEST_IP` / `TG_GUEST_CIDR` / `TG_GUEST_GATEWAY` / `TG_GUEST_DNS` |
| Host tap (tap mode) | `dstap-0` | `TG_TAP_IFNAME` |

### Why an Alpine **nocloud** image

The `nocloud` cloud images auto-consume a NoCloud cloud-init seed
(`DataSourceNoCloud`), so the generated seed sets the static `10.77.0.x`
address, hostname, and an autologin/known-root-password posture without baking
anything image-specific. The `bios-cloudinit` flavor boots under **SeaBIOS**
(bundled with the sudo-free qemu — `bios.bin` in `$TG_QEMU_SHARE`). The base
image does **not** preinstall `curl`; the generated seed's `runcmd` does
`apk add --no-cache curl` at first boot (recorded in [`BUILD-NOTES.md`](BUILD-NOTES.md)),
which is part of the boot-smoke that proves shell + `curl` + curl-out.

### Integrity chain (how the sha256 pin is trustworthy)

Alpine publishes a `<image>.sha512` sidecar for the cloud qcow2 (it does **not**
publish a `.sha256`). The `TG_IMAGE_SHA256` pin was computed from the authentic
image whose `sha512sum` **matched Alpine's published `.sha512` sidecar**
(recorded in [`BUILD-NOTES.md`](BUILD-NOTES.md)) — so the sha256 pin chains to
Alpine's own release-integrity statement. The builder enforces the sha256 pin on
every fetch (fail-closed on mismatch) and re-verifies the vendor sha512 when the
sidecar is reachable.

## Static network identity (tap mode) — doc 13

The tap-mode NoCloud `network-config` applies the
doc 13 §3/§4 per-session-tap
addressing inside the guest: static `10.77.0.2/24`, default route + DNS via
`10.77.0.1` (the boundary host's per-session-tap address — the in-guest belt to
`ds-dnsgate`). The **smoke** seed instead uses DHCP, because qemu user-net
(slirp) hands out `10.0.2.x` with a working gateway/DNS — the static
`10.77.0.x` config only makes sense once attached to the real `dstap-0`.

## D50 — no secrets baked

Everything in this tree is synthetic/scrubbed (D50). The seed sets a **known,
non-secret** root password (`ds`) purely so the local fixture has a serial-login
the operator can use; it is not a credential and carries no production
authority. No long-lived credential, token, key, or CA material is ever baked
into the image, the seed, or any committed file. The per-session interception CA
(D17) belongs to the *golden* image path, not this fixture.

## dstap-0 vs the §E2 task

The boot wrapper supports **both** a user-net smoke (`--smoke`, no sudo) and a
tap attach (`--tap`, `ifname=dstap-0,script=no,downscript=no`). **Creating**
`dstap-0` on the host is the SEPARATE §E2 task (it needs sudo / a pre-created
tap); this wrapper only **attaches** to an already-present tap and refuses if it
is absent. The self-contained boot-smoke this unit owns is the user-net path.
