# vm/m0-image/ — the hand-built M0 base image

**Owner:** VM & runtime · **OSS** (D15/D25) · **Decisions:** D12, D29, D38, D49,
D75 (doc 04 §6) · **Source:**
doc 05 §3 (M0 base-image seam),
§8 (M0 scope)

## What this is

The **single base image the one M0 VM is cloned from** — built and owned by VM &
runtime at M0 per the doc 05 §3 seam
statement. It is a **hand-built artifact, not a CI product** (D12: v0
environments stay dynamic). The `images/golden/` pipeline (Image & cache
builder, `—` at M0) **industrializes this same image from M1** — until then this
directory is the whole of it.

**The committed artifact is the reproducible build _procedure_** — the scripts
and config in this directory plus this README — **never the image blob.** The
qcow2/raw disk is built under `~/tmp/ds-images/` (btrfs, CoW) and never enters
the repo (see [What never gets committed](#what-never-gets-committed)). This is
the D12 "hand-built, not CI" stance made concrete: a reviewer reads the
procedure, an operator runs it.

## Content spec (what the image carries, and why)

| Element | Where | Decision / doc |
|---|---|---|
| The **VM entrypoint binary**, staged at `/usr/local/bin/ds-entrypoint`, launched at boot to start + supervise the runtime and open the VM-local event socket back to the host agent | [`guest-config/ds-entrypoint.service`](guest-config/ds-entrypoint.service) | D38; doc 15 §5.4 |
| The **per-session config-drive mount** (gap-1) — a read-only second disk the host attaches holding `config.pb`, mounted by `LABEL=DS_ENTRYPOINT` (`iso9660`) at `/run/ds/entrypoint`, **ordered `Before=ds-entrypoint.service`** so `loadConfig` finds the config | [`guest-config/run-ds-entrypoint.mount`](guest-config/run-ds-entrypoint.mount) | D38; doc 15 §4.1 (step 8); matches `orchestrator/internal/hypervisor/libvirt/configdrive.go` |
| The **per-session guest static net config** (U4) — a **SECOND** file `ds-net.env` on the SAME config-drive (alongside `config.pb`, host-rendered **only when the routed tap is active**) carrying `10.77.<idx>.1/31` + default route via `10.77.<idx>.0`; `ds-netcfg.service` applies it `Before=ds-entrypoint.service`, and **no-ops when the file is absent** (the SLIRP/offline path is byte-identical) | [`guest-config/ds-netcfg.service`](guest-config/ds-netcfg.service), [`guest-config/ds-apply-netcfg.sh`](guest-config/ds-apply-netcfg.sh) | doc 15 §4.1; matches `orchestrator/internal/hypervisor/libvirt/netconfig.go`; the routed tap + gateway are the dataplane nft4 lane |
| The **attach-carriage forwarder** (gap-3), staged at `/usr/local/bin/ds-attachfwd`, started `Before=ds-entrypoint.service` — a 1:1 byte splice between the guest event-socket UDS and the `:4242` TCP carriage the host-agent dials over the tap | [`guest-config/ds-attachfwd.service`](guest-config/ds-attachfwd.service) | doc 15 §5.4; [`vm/attachfwd/`](../attachfwd/) |
| The **D49-pinned Claude Code runtime**, `@anthropic-ai/claude-code@2.1.173` | installed by [`build-m0-image.sh`](build-m0-image.sh) step 3 | D49 |
| The **terminal/PTY-mode `TERM`** (`M0_PTY_TERM=xterm-256color`) and its **baked terminfo entry** at `/lib/terminfo/x/xterm-256color` — the TERM the in-guest pty launch-mode sets for the interactive CC TUI; `build-m0-image.sh` step 4a **hard-asserts** the terminfo entry exists in the rootfs (fail the bake if absent) | [`m0-image.env`](m0-image.env) `M0_PTY_TERM`; asserted by [`build-m0-image.sh`](build-m0-image.sh) step 4a | doc serpent-cli-mvp 02 §2.9, 10 §A2/§B |
| **CC workspace pre-trust** — `/home/ds/.claude.json` seeded so CC's first-run "trust this folder?" prompt does **not** gate the dev in a fresh VM; carries **no** credential (a UX latch only) | seeded by [`build-m0-image.sh`](build-m0-image.sh) step 4b | doc serpent-cli-mvp 10 §B |
| A **glibc userland** (Debian bookworm), **not musl/Alpine** | [`m0-image.env`](m0-image.env) base pins | doc 11 §3.2/§8.6 |
| The **D75 guest-interior IPv6 posture** — v6 disabled per egress NIC, `lo` keeps `::1`, kernel `ipv6.disable=1` forbidden | [`guest-config/99-ds-disable-ipv6.conf`](guest-config/99-ds-disable-ipv6.conf) | D75 |
| The **git-over-HTTPS pin** — `insteadOf` rewrite (ssh→https) + credential helper at `/etc/gitconfig`, so git-over-SSH cannot silently bypass the credential-swap / scanning planes; SSH-git is a tested non-goal | [`guest-config/git-https-pin.gitconfig`](guest-config/git-https-pin.gitconfig) | D83 (doc 16 §5.3; doc 09 POL-2) |

### The entrypoint binary is a separate task

`proto/dreamserpent/runtime/v1` is **README-reserved and unfrozen** (its M0
freeze PR is OPEN in `proto/FREEZE.md`), and `vm/entrypoint/` ships only its
README today. So **the entrypoint binary does not exist yet** — building it is a
separate task. This image build **stages whatever artifact that task produces**
at `M0_ENTRYPOINT_PATH` and wires the boot to launch it; it does **not** embed
the contract or invent a binary. Until that binary lands, `ds-entrypoint.service`
is staged anyway and **fails closed at boot** (`ConditionFileIsExecutable`),
which is the expected M0-skeleton state — [`boot-validate.sh`](boot-validate.sh)
reports it as such, not as a build failure.

### Terminal/PTY mode — `M0_PTY_TERM`, terminfo, and devpts

The same baked `ds-entrypoint` runs CC two ways, selected **per-session** from the
host-resolved `LaunchSpec.stdio` on the config-drive — **the image is identical
between modes** (same `claude` pin, same units, same drive):

- **PIPES** (the structured default): three pipes, `io.Copy` of stream-json onto
  the event socket — the historical headless path.
- **PTY** (terminal mode): `ds-entrypoint` allocates a pseudo-terminal, execs
  `claude` as its controlling terminal, and carries **raw terminal bytes** +
  window-resize over the **same** attach carriage so the dev sees the real
  interactive CC TUI (doc serpent-cli-mvp 02).

For a usable TUI three things must be present in the guest, and this image owns
two of them:

1. **`TERM`** — `M0_PTY_TERM=xterm-256color`. The host sets `TERM` via
   `LaunchSpec.env` (a host-resolved launch fact, **not** a guest CC-ism); the pin
   is documentation+enforcement so host and image agree on the value.
2. **terminfo** — the matching `xterm-256color` terminfo entry, shipped by Debian
   `ncurses-base` at **`/lib/terminfo/x/xterm-256color`** (confirmed present in the
   baked image, doc 10 §B). `build-m0-image.sh` step 4a **hard-asserts** this entry
   exists in the rootfs and **fails the bake** if it is missing, so a slimmed base
   or a future `M0_PTY_TERM` bump cannot silently produce a garbled TUI (doc 02 R4).
   `verify-image-pins.sh` enforces README↔env agreement on the pin.
3. **devpts** — unprivileged pty allocation via `/dev/ptmx` + `grantpt`/`unlockpt`
   works for `User=ds` on the standard `devpts` mount (the M0 Debian kernel mounts
   it by default); **no privilege escalation** is introduced — it is the same
   privilege the structured pipe path runs at.

**Workspace pre-trust.** CC's interactive TUI shows a first-run *"Do you trust the
files in this folder?"* prompt the first time it runs in a workspace; unanswered it
would **block the dev** in a fresh VM. The bake (step 4b) seeds
`/home/ds/.claude.json` keying CC's global per-path trust registry on the working
dir `/home/ds` (`hasTrustDialogAccepted` + onboarding-seen), so a fresh session
starts straight in the TUI. The seed carries **no credential** (a UX latch only;
creds never enter the image, D8/D39). **Cross-tree complement (guest-launch /
host-producer unit, out of `vm/m0-image`):** the env knob
`CLAUDE_TRUST_WORKSPACE=1` is a `LaunchSpec.env` launch fact the guest-launch unit
SHOULD also set (alongside `TERM=xterm-256color`, `HOME=/home/ds`,
`CLAUDE_CONFIG_DIR=/home/ds/.claude` in `scripts/live-mvp/ds-serve-stack.sh`) so a
working dir other than `/home/ds` is still un-gated — this image owns only the
baked `/home/ds` seed.

### The per-session guest static net config (U4) — a second config-drive file

For the VM to egress over the **routed tap** (the nft4 keystone egress path), the
**guest** must address its tap NIC with a static per-session address + default
route. The host renders those L3 facts into a **SECOND file**, `ds-net.env`, on the
**same** per-session config-drive that already carries `config.pb`
(`orchestrator/internal/hypervisor/libvirt/netconfig.go`, `configdrive.go`). The
derivation is keyed on the never-recycled `HostSessionIndex`: the guest is
`10.77.<idx>.1`, the per-session gateway is `10.77.<idx>.0` (a point-to-point `/31`
pair). **`config.pb` is untouched** — this is purely additive.

**Gated on the routed tap, default off.** The host emits `ds-net.env` **only when
the routed tap is active** (`LiveConfig.RoutedTap`, default `false`). On the
M0-minimal usermode SLIRP path (the default, and every synthetic/offline boot) the
host writes **no** second file, so the config-drive is **byte-identical** to the
historical single-file drive and the guest's `ds-apply-netcfg.sh` **no-ops** — the
SLIRP NIC is addressed by DHCP instead (see below), never by this static apply. The
file's **presence is the routed-tap signal in-guest**, mirroring the host-side gate
exactly.

### SLIRP/dev egress — systemd-networkd DHCP, gated off the routed tap

The M0-minimal usermode SLIRP NIC has **no** static config and **no** `ds-net.env`;
without a DHCP client the guest gets no IP/DNS and Claude Code loops on `api_retry`
forever (a hang, live-found 2026-06-18). The image ships a **systemd-networkd DHCP
`.network`** (`ds-slirp-dhcp.network`, matching the SLIRP NIC as `eth0` under
`net.ifnames=0` **and** `en*` under default naming) that leases an address + resolver
from the SLIRP userspace stack (qemu's built-in DHCP/DNS on `10.0.2.x`).

The SLIRP NIC and the routed tap **share NIC names** (both `eth0`/`en*`, both
virtio-net), so a blanket DHCP `.network` in `/etc/systemd/network` would also try
DHCP on the routed tap and **race** `ds-netcfg`'s static apply. To make that
**impossible**, the `.network` is **staged off networkd's search path**
(`M0_SLIRP_NETWORK_STAGE`, e.g. `/usr/local/share/ds/`); `ds-slirp-net.service`
copies it into `/run/systemd/network` + `networkctl reload`s **only when `ds-net.env`
is absent** (`ConditionPathExists=!…/ds-net.env`, ordered `After=run-ds-entrypoint.mount`
so the signal is read off the mounted drive). On a **routed-tap boot** the unit is
skipped, the `.network` is **never loaded**, and networkd has no `.network` matching
the tap — so its `[Match]` **provably cannot catch the routed tap**; `ds-netcfg`
owns that NIC. Both bake paths `systemctl enable systemd-networkd` + `ds-slirp-net.service`.

The `networkctl reload` leg is a **D-Bus system-bus call** on systemd 252, so the image
must contain **`dbus`** — which both bake paths now install **explicitly**, because
`--no-install-recommends`/`debootstrap --variant=minbase` drop systemd's `Recommends:
dbus`. An image baked **without** `dbus` fails `ds-slirp-net.service` at execution and
the SLIRP NIC is never addressed (live-found 2026-07-29; in-guest Claude Code dies with
`API Error: FailedToOpenSocket`). The interim workaround for **already-baked** images is
`ip=dhcp` on the kernel cmdline — `systemd-network-generator` writes the config before
networkd starts, so no reload (and no bus) is needed.

**Ordering + fail-posture.** `ds-netcfg.service` is a oneshot run
`After=run-ds-entrypoint.mount` (the net config rides the mounted config-drive) and
`Before=ds-entrypoint.service` (the network is configured before the egressing
runtime launches). It **must never gate on `network-online.target`** — it *is* the
unit that brings the NIC up, so waiting on the NIC being up would deadlock (the same
reasoning `ds-entrypoint.service` / `ds-attachfwd.service` already apply). The
fail-posture lives in the **script**: absent ⇒ clean no-op (a SLIRP boot is never
held hostage to a unit that legitimately does nothing); present-but-unappliable ⇒
**exit non-zero**, failing the unit before the entrypoint runs (under an active
routed tap a guest with no address has no egress).

**The tap + the per-session gateway are NOT this image's.** This image owns only
the **guest-side** apply of the address the host wired. The routed tap itself, the
per-session host gateway, and the per-session NFT allow are the **dataplane nft4
lane** (a declared dependency, never written here). The host gateway leg (U3) must
key its address off the **same** `10.77.<idx>` derivation `netconfig.go` pins.

### glibc, not musl — the adjudication

The userland is **glibc** because `ds-dnsgate`'s ask-path returns REFUSED and
**musl's stub silently ignores REFUSED**, stalling the full 5 s resolver timeout
then failing `EAI_AGAIN`; **glibc fails fast** (≤2 attempts). Keeping the image
glibc confines that stall to musl userlands the agent itself spawns (Alpine
containers, musl-built tools), never the image's own resolver path. This is
adjudicated, measured, and accepted in
doc 11 §8.6 (and the AAAA-strip rationale
in §3.3); no mitigation is owed.

### The D75 split — guest interior vs host netns

This image owns only the **guest-interior** half of D75: v6 off on the egress
NIC, `lo` keeps `::1`. The **host-netns side** of every per-session tap
(`disable_ipv6=1` + `accept_ra=0` on the host-side tap; no RA/DHCPv6 on the
per-session segment) is the **Boundary-owned host-baseline artifact**
([`dataplane/artifacts/host-baseline/`](../../dataplane/artifacts/host-baseline/),
D75) — a different artifact for a different netns. The two are complementary and
must never be merged into one file. `ds-dnsgate` already answers AAAA with
NODATA (doc 11 §3.3), so a v4-only guest never resolves a v6 target; this
drop-in is the in-guest belt to that suspenders.

### D17 trust-store injection point (not the mint)

The image ships a real glibc trust store (`ca-certificates`). The **host agent
injects the per-session interception CA** at create (D17; doc 15 §4.1 step 7,
fail-closed: no anchor, no session). The image only **provides the store** — it
**never generates CA material** (that is `identity/mint/`, D82).

## Files

| File | Role |
|---|---|
| [`m0-image.env`](m0-image.env) | **Single source of truth** for every pin (CC version, glibc base, entrypoint path, **`M0_PTY_TERM` terminal/PTY TERM**, D75 egress-NIC glob, disk size). Sourced by every script. |
| [`build-m0-image.sh`](build-m0-image.sh) | The reproducible build procedure. `--plan` (default) prints + validates inputs with no privileges; `--build` is the operator bake (needs debootstrap + root). |
| [`boot-validate.sh`](boot-validate.sh) | Local boot validation with the sudo-free user qemu (`~/.local/opt/qemu`, KVM via the 0666 `/dev/kvm`, TCG fallback). Plan-only by default; `DS_BOOT=1` boots a built image. |
| [`verify-image-pins.sh`](verify-image-pins.sh) | Anti-drift guard: README↔env pin agreement + the D75/D38 guest-config invariants. `--self-test` injects drift and confirms each is caught. |
| [`guest-config/99-ds-disable-ipv6.conf`](guest-config/99-ds-disable-ipv6.conf) | D75 per-egress-NIC v6 sysctl drop-in (template; `__IFACE__` expanded at bake). |
| [`guest-config/ds-entrypoint.service`](guest-config/ds-entrypoint.service) | D38 boot wiring that launches the entrypoint binary (template; tokens expanded at bake). |
| [`guest-config/run-ds-entrypoint.mount`](guest-config/run-ds-entrypoint.mount) | gap-1 config-drive mount unit: read-only `LABEL=DS_ENTRYPOINT`/`iso9660` at `/run/ds/entrypoint`, `Before=ds-entrypoint.service` (template; label/fs/mount-point expanded at bake, single-sourced from `m0-image.env`, matched to `configdrive.go`). |
| [`guest-config/ds-attachfwd.service`](guest-config/ds-attachfwd.service) | gap-3 attach-carriage forwarder boot wiring (`vm/attachfwd`): UDS `/run/ds/attach.sock` ⇄ TCP `:4242`, `Before=ds-entrypoint.service`, fail-closed on a missing binary (template; tokens expanded at bake). |
| [`guest-config/ds-apply-netcfg.sh`](guest-config/ds-apply-netcfg.sh) | U4 per-session net-config apply: reads `ds-net.env` off the config-drive, **no-ops when absent** (SLIRP/offline), applies `ip addr`/`route` when present, **fail-closed** when present-but-unappliable (template; config-dir / NIC glob / file-name expanded at bake, single-sourced from `m0-image.env`, matched to `netconfig.go`). |
| [`guest-config/ds-netcfg.service`](guest-config/ds-netcfg.service) | U4 net-config unit: oneshot, `After=run-ds-entrypoint.mount`, `Before=ds-entrypoint.service`, **never gates on `network-online.target`** (it brings the NIC up), fail-closed on a missing script (template; script path expanded at bake). |
| [`guest-config/git-https-pin.gitconfig`](guest-config/git-https-pin.gitconfig) | D83/§5.3 git-over-HTTPS pin baked at `/etc/gitconfig` — `insteadOf` rewrite (ssh→https) + credential helper, so no git-over-SSH path silently bypasses the credential-swap / scanning planes. |
| [`verify-git-pin.sh`](verify-git-pin.sh) | Executable assertion for the git pin: insteadOf rewrites ssh→https, git-over-SSH fails closed, remotes resolve to HTTPS. `--self-test` runs a non-vacuous negative case; the in-guest leg is `DS_KVM_LIVE`-gated (deferred manual step). |

## Build it

```sh
# Review the procedure and validate the pins/guest-config (no privileges):
vm/m0-image/build-m0-image.sh           # == --plan

# Actually bake (on a debootstrap + root-capable operator host):
DS_IMAGES_DIR=~/tmp/ds-images vm/m0-image/build-m0-image.sh --build
```

## Boot validation

```sh
vm/m0-image/boot-validate.sh            # print the boot plan (no image needed)
DS_BOOT=1 vm/m0-image/boot-validate.sh  # boot ~/tmp/ds-images/m0-base-*.qcow2
```

The local validator boots the image headless with the user qemu and checks: it
reaches a glibc multi-user userland; the egress NIC has no global v6 address
while `lo` keeps `::1` (D75); and `ds-entrypoint.service` is enabled and — once
the D38 binary is staged — launched the pinned CC runtime.

**ENVIRONMENT — local substitute (ratified).** The production M0 host is
a **virtual-metal ESXi** node running KVM/libvirt/qcow2 nested (D5/D31), which
this build environment does not have. Per the ratified local substitute we build
and **boot-validate with the sudo-free user qemu** under `~/.local/opt/qemu` on
btrfs scratch. **Boot-on-ESXi validation explicitly transfers to the [human]
follow-up task** — the local qemu boot is a representative substitute for the
guest userland / entrypoint launch / v6 posture, not a substitute for the
production hypervisor.

## What never gets committed

The image blob — qcow2/raw disk, rootfs tarball, anything under
`~/tmp/ds-images/` — is **never committed**, and **no file in this directory may
exceed 1 MB** (D12 hand-built stance: the reproducible procedure is the
artifact, not the bytes). Image references, when the `images/golden/` pipeline
later industrializes this, follow the
[`images/` pinning convention](../../images/README.md) (`tag@sha256:<digest>`,
never registry-side drift).

## Gate

This directory's gate legs are the `vm/` Go module (`go build`/`vet`/`test` —
unchanged by this tree, which is shell + config, but in the SPDX-lint scope) and
the two self-checking scripts:

```sh
sh -n vm/m0-image/*.sh vm/m0-image/guest-config/*.sh vm/m0-image/guest-config/*.service   # parse-check
vm/m0-image/build-m0-image.sh --plan        # validate pins + guest-config
vm/m0-image/verify-image-pins.sh --self-test # anti-drift, with injected-drift harness
vm/m0-image/verify-git-pin.sh --self-test    # D83/§5.3 git-HTTPS pin, with non-vacuous negative case
```

`verify-image-pins.sh` is deliberately **not** named `images/*/lint-*.sh` and
lives under `vm/`, so it is outside the repo-wide `check-image-drift` glob (which
the Image & cache builder owns); it is invoked directly here.

## Neighbors

| Tree | Relation |
|---|---|
| [`vm/entrypoint/`](../entrypoint/) | Produces the D38 entrypoint binary this image stages + boots |
| [`proto/dreamserpent/runtime/v1/`](../../proto/dreamserpent/runtime/v1/) | The contract the entrypoint implements; freezes at M0 (README-reserved today) |
| [`images/golden/`](../../images/golden/) | Industrializes this same base image from M1 (D17 hook, D49 pin, nightly cadence) |
| [`dataplane/artifacts/host-baseline/`](../../dataplane/artifacts/host-baseline/) | The host-netns half of the D75 v6 posture (this image owns the guest half) |
| [`client/wrapper/adapters/claude-code/`](../../client/wrapper/adapters/claude-code/) | Targets the same D49 CC pin (`2.1.173`) baked here |
| `scripts/cc-sandbox/` | The host-side drive-tier *container* image at the same CC pin — sibling, different machine |
