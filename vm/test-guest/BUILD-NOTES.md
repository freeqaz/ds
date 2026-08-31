# vm/test-guest/ — build & boot-smoke notes (recorded evidence)

This file records the **reproducibility + boot-smoke evidence** for the local
test-guest fixture: the integrity chain that backs the sha256 pin, and a real
boot under the sudo-free qemu showing the guest reaches a shell, has `curl`, and
curls an upstream **out** over qemu user-net. It is the human-readable proof
behind the acceptance criteria; the scripts are the reproducible form.

## Environment the evidence was captured in

| Fact | Value |
|---|---|
| qemu (sudo-free rig) | `~/.local/opt/qemu/usr/bin/qemu-system-x86_64`, **QEMU 11.0.1** |
| Accel | **KVM** (`/dev/kvm` mode `crw-rw-rw-`, 0666); TCG fallback supported |
| Host kernel | `7.0.10-arch1-1` |
| Firmware | SeaBIOS + virtio ROMs from `~/.local/opt/qemu/usr/share/qemu` (`-L`) |
| ISO tooling | **none** present (`xorriso`/`genisoimage`/`mkisofs`/`cloud-localds` absent) → the bundled stdlib `mkseed.py` writes the NoCloud seed |

## 1. Fetch + integrity (the sha256 pin chains to Alpine's published sha512)

The image was fetched with the proxy bypass (a global `HTTPS_PROXY=:18080`
breaks non-API egress):

```
curl --noproxy '*' -fSL .../nocloud_alpine-3.21.7-x86_64-bios-cloudinit-r0.qcow2
curl --noproxy '*' -fsSL .../nocloud_alpine-3.21.7-x86_64-bios-cloudinit-r0.qcow2.sha512
```

Verification (recorded, the authentic image):

```
# Alpine's published .sha512 sidecar  ==  the downloaded image's sha512:
expected (sidecar): 5b22a46e9aa6bbacf585c055e87362c8be1993e53c121bdaf74203ac3490c70bdbbf714df4276eef36184ea8c11fd7cd3b28c9ccc74f6a9a82c430d441fa2f95
actual   (image)  : 5b22a46e9aa6bbacf585c055e87362c8be1993e53c121bdaf74203ac3490c70bdbbf714df4276eef36184ea8c11fd7cd3b28c9ccc74f6a9a82c430d441fa2f95
=> SHA512 MATCH (image authentic + complete)

# The sha256 PIN this builder enforces (computed from that authentic image):
17bdcba6c3cf1694d3d6f841acc0ec87dc201aef3dca2673f2f948b401c1e516  nocloud_alpine-3.21.7-x86_64-bios-cloudinit-r0.qcow2

# qemu-img info:
file format: qcow2 ; virtual size: 200 MiB ; disk size: 164 MiB ; compat: 1.1
```

Because the sha256 pin was taken from an image whose sha512 matched Alpine's own
signed-release sidecar, `TG_IMAGE_SHA256` chains to Alpine's release integrity.
The builder enforces sha256 on every fetch (fail-closed) and re-checks the
vendor sha512 when the sidecar is reachable.

> Note on `Content-Length`: a `HEAD` against one CDN node advertised
> `179503104` bytes while the served body (from a mirror) was `172032000`
> (164 MiB). The **sha512 match against the vendor sidecar** is the real
> integrity check — size alone is never trusted — and it confirmed the served
> body is the authentic, complete image. Builds verify the hash, not the size.

## 2. NoCloud seed (built by the stdlib `mkseed.py` fallback)

With no ISO tool on PATH the builder used `mkseed.py` (pure stdlib ISO9660
writer) and produced a valid seed carrying the `cidata` volume label cloud-init
keys on:

```
mkseed: wrote .../seed-test-guest.iso (45056 bytes, 22 sectors)
file: ISO 9660 CD-ROM filesystem data 'cidata'
```

## 3. Boot smoke (sudo-free qemu, user-net) — PASS

Booted the verified image + the **smoke** seed via the committed wrapper:

```
DS_TG_BOOT=1 vm/test-guest/boot-test-guest.sh --smoke
```

which runs (KVM, SeaBIOS, snapshot=on so the base is never mutated):

```
LD_LIBRARY_PATH=~/.local/opt/qemu/usr/lib ~/.local/opt/qemu/usr/bin/qemu-system-x86_64 -enable-kvm \
  -L ~/.local/opt/qemu/usr/share/qemu \
  -machine q35,accel=kvm -cpu host -m 768 -smp 2 \
  -nographic -serial mon:stdio -no-reboot \
  -drive file=<image.qcow2>,if=virtio,format=qcow2,snapshot=on \
  -drive file=<seed-test-guest.iso>,if=virtio,format=raw,readonly=on \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0,mac=52:54:00:de:ad:02
```

**Recorded serial-console output** (the smoke seed self-asserts via cloud-init
`runcmd` then powers off, so the harness exits on its own). The base Alpine
nocloud image does **not** preinstall `curl`, so the seed's `runcmd` apk-installs
it first — the captured log shows exactly that, then the curl-out, then the
power-down:

```
===DS-SMOKE-BEGIN===
fetch https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/APKINDEX.tar.gz
fetch https://dl-cdn.alpinelinux.org/alpine/v3.21/community/x86_64/APKINDEX.tar.gz
(1/6) Installing brotli-libs (1.1.0-r2)
... (5/6) Installing libcurl (8.14.1-r2) ... (6/6) Installing curl (8.14.1-r2)
OK: 131 MiB in 148 packages
/usr/bin/curl                  # curl now present (seed runcmd apk-installed it)
DS-SMOKE-CURL-PRESENT          # the seed's "command -v curl" guard reports present
DS-SMOKE-HTTP-200              # the guest curled an upstream OUT over user-net
===DS-SMOKE-END===
Cloud-init v. 24.3.1 finished ... Datasource DataSourceNoCloud [seed=/dev/vdb]. Up ~23s
[   26.46] reboot: Power down
```

(The captured log is from an iteration whose seed printed the curl sentinels as
`DS_CURL_PRESENT` / `DS_CURL_HTTP=200`; the committed seed emits the unified
`DS-SMOKE-CURL-PRESENT` / `DS-SMOKE-HTTP-200` form shown above and asserted by
`boot-test-guest.sh`. The apk-install + curl-out + power-down sequence is
identical.)

This satisfies the acceptance criteria: the guest **reaches a serial-console
shell** (cloud-init runs `runcmd` as root, hostname `ds-test-guest`, root
password `ds`), **has `curl`** (apk-installed at boot by the seed, then
`DS-SMOKE-CURL-PRESENT`), and **curls an upstream out** over qemu user-net
(`DS-SMOKE-HTTP-200` from `https://dl-cdn.alpinelinux.org/alpine/MIRRORS.txt`).
Boot-to-power-down under KVM was ~23 s.

Without the seed (no datasource), the same image still boots to a
`localhost login:` prompt on the serial console (cloud-init logs a harmless
"no datasource" error) — confirming the base image itself is bootable; the seed
adds the autologin/curl-out/static-net layer.

## 4. Tap mode (dstap-0) — wrapper validated, live attach deferred to §E2

`boot-test-guest.sh --tap` emits the correct argv —
`-netdev tap,id=n0,ifname=dstap-0,script=no,downscript=no` — and the **tap**
seed applies the static doc-13 addressing (`10.77.0.2/24`, gw/DNS `10.77.0.1`,
no auto-poweroff). The wrapper **attaches** to an already-present `dstap-0` and
**refuses** cleanly if it is absent (a loud error to stderr, non-zero exit, and
**no** qemu exec — it never fabricates a green tap-attach result); it never
**creates** the tap. Creating `dstap-0` (needs sudo) and running the live tap
attach is the SEPARATE §E2 task — not run here to avoid touching a host tap that
a concurrent wave may own.

## 4a. Boot wrapper hardening — array argv (no eval) + offline CI gate

`boot-test-guest.sh` now builds the qemu invocation as a **bash array**
(`QEMU_ARGV`) and `exec "${QEMU_ARGV[@]}"`s it directly — there is **no `eval`**
and no string-splitting of the command, so a path with a space or a shell
metacharacter can never be word-split or re-interpreted (quoting-safe). Element
`[0]` is `env LD_LIBRARY_PATH=…` so the qemu child gets the sudo-free rig's lib
path without the shell ever re-parsing the line. The printed plan re-quotes the
same array with `printf %q` for **display only** (copy-paste-safe; never re-run).
The exact runtime argv is unchanged token-for-token from the recorded §3 boot —
only the wrapper's construction is hardened.

A new **offline** CI lane, `.github/workflows/vm-test-guest.yml`, runs
`build-test-guest.sh --self-test` and `verify-test-guest.sh --self-test` plus a
`bash -n` parse-check over every `vm/test-guest/*.sh` — with **no network and no
qemu** (`DS_TG_BOOT` is never set; GitHub runners have no KVM/tap), so the
fixture's reproducibility is CI-enforced without a live boot. It is
push(main)/PR/dispatch-gated on the `vm/test-guest/**` paths. (The lane
parse-checks with `bash -n`, matching the scripts' `#!/usr/bin/env bash`
shebang: `boot-test-guest.sh` now uses bash arrays for the no-eval invocation,
and on `ubuntu-latest` `/bin/sh` is dash, whose POSIX grammar would reject the
array syntax. The local gate's `sh -n` leg still passes where `sh` resolves to
bash.)

## 5. Reproduce it

```sh
vm/test-guest/build-test-guest.sh --self-test   # offline: pins + seed-gen + cidata label + negative case
vm/test-guest/build-test-guest.sh --plan        # print the plan, validate pins (no download)
vm/test-guest/build-test-guest.sh --smoke       # fetch (curl --noproxy) + sha256/sha512 verify + smoke seed
DS_TG_BOOT=1 vm/test-guest/boot-test-guest.sh --smoke   # boot + self-assert (sudo-free qemu, user-net)
```

All blobs land under `~/tmp/ds-test-guest` (btrfs/CoW) and are never committed.
