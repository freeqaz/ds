<!-- SPDX-License-Identifier: Apache-2.0 -->
# scripts/nested-testbed — 2-level nested-VM NFTables / egress-gateway testbed

Test the dream-serpent **nftables egress floor + the boundary gateways
(`ds-dnsgate` / `ds-tlsproxy`) SAFELY**, by running them inside a disposable VM
instead of on the host.

```
HOST                ── untouched: rootless qemu + SLIRP only, NO `sudo nft`, NO host ip_forward
  │
  └─ L1 VM  (full network via SLIRP; the DEVICE UNDER TEST)
     │   • the REAL appliance nft floor — `chain input policy drop` + `forward policy drop`
     │   • ds-dnsgate (:15353) + ds-tlsproxy (:18080/:18443)
     │   • nested KVM (host `-cpu host` passes AMD-V through; kvm_amd loaded)
     │
     └─ L2 VM  (NESTED; the agent VM)
            • only NIC is the routed tap dstap-7 (10.77.7.1/31) — NO direct egress
            • every DNS/HTTP/HTTPS flow is REDIRECTed into L1's gateways; everything
              else hits the forward DROP
```

## Why this exists (the safety story)

The canonical floor (`dataplane/artifacts/nft/nft-1-bootstrap.nft`) sets `chain
input policy drop`. Applying that **on the host** would cut the host's own
VPN/SSH management path and fall it off the network (an outage this project has
hit for real). So
`scripts/live-mvp/ds-gated-egress.sh` was forced into an `input=accept` compromise
and never run for real.

Nesting removes the hazard **by construction**: the floor runs inside **L1**, a
throwaway VM. If a ruleset change breaks L1's networking, you reboot L1 — the host
and its VPN mesh are never touched. This is the architecture choice the
"gated-egress safety" question was waiting on.

### Posture update 2026-07-29 — this testbed is the REHEARSAL vehicle, no longer the only venue

The earlier standing constraint ("all live work runs in the nested testbed; **never** host
nft") is **retired for a host that has been prepared for it**: such a box runs the gated stack live
on the host under the C1-safe floor plus a dead-man rollback kit, with all four keystone proofs
positive and a real Claude Code turn driven over the attach.v1 writer seat.

What did **not** change, and is why the host floor is shaped the way it is:

- The hazard above is real. The host floor does **not** use the canonical `policy drop` shape — it
  uses `forward policy accept` plus an explicit terminal **unqualified** `iifname "dstap-*" drop`,
  because an nft base chain with `policy drop` on the forward hook is terminal across that hook and
  would kill a mesh-VPN host's **exit-node forwarding** before the VPN's own accept chain ever
  ran (the C1 finding). Same containment, no VPN blast radius.
- Every host apply still goes through the dead-man harness (watchdog preflight, C1 screen, armed
  auto-revert timers, connectivity self-test) — never a hand-typed `nft` command.
- The retirement is scoped to a host prepared with that floor plus kit. **netns/D66 remains the
  production datapath target**, and doc 11's stance — typing ad-hoc nft into a production host shell
  is doing it wrong — still stands.

So: use this testbed to rehearse a ruleset change, to run CI, or when you want a disposable venue;
use the host stack when you want the real thing. Both are valid.

## Quick start

```sh
scripts/nested-testbed/run-testbed.sh up         # bake L1 (once) → boot L1 → gate-up → boot L2 → validate
scripts/nested-testbed/run-testbed.sh validate   # re-run the gating proof
scripts/nested-testbed/run-testbed.sh enforce    # flip ds-tlsproxy to TLS-1 SNI-admission enforce + validate
scripts/nested-testbed/run-testbed.sh l2shell    # root shell inside the nested agent VM
scripts/nested-testbed/run-testbed.sh down       # tear everything down
```

### What `validate` proves (observed, opaque mode)

| check | result |
| --- | --- |
| L2 has only the routed tap (no SLIRP) | `eth0=10.77.7.1/31`, default via `10.77.7.0` |
| **[A] direct egress** `nc 1.1.1.1:22` | **DROPPED** by `forward policy drop` (nft counter increments) |
| **[B] direct DNS** `dig @8.8.8.8` | transparently **intercepted by ds-dnsgate** (never reaches 8.8.8.8) |
| **[C] HTTPS** `https://api.anthropic.com/` | reaches the **real API only via ds-tlsproxy** (`http_code=404`) |
| **[D] nft forward counters** | the drop / quic-reject rules show hits |

`enforce` mode additionally shows ds-tlsproxy refusing any SNI the policy pack
doesn't admit (`tls1-policy-deny`).

### Posture-(b) credential swap (D39) — live proof

```sh
DS_GATE_TLS_MODE=swap DS_L2_FLAVOR=m0 DS_DRIVE_SEAT=1 \
  scripts/nested-testbed/run-testbed.sh up-orch
```

This runs the full **credential-swap** datapath host-safe: ds-tlsproxy *terminates*
the VM's TLS with a per-session leaf, swaps the in-VM **placeholder** credential for
the **real** long-lived token at egress, and re-originates to the real origin — the
real token never enters the VM (it lives only in the host secret store at
`~/tmp/ds-nested/share/secrets/cc-oauth-token` → `/run/ds-gate/secrets/grant-anthropic`,
D50). `ds-seat-drive` then drives one real Claude Code turn over the writer seat and
the proxy log shows `CredentialUseEvent`s with **zero** `connection reset`.

Two things must line up for the guest to trust the terminating TLS (both are handled
by the defaults, called out here so a fresh box is reproducible):

- **The guest trusts the interception CA.** The m0 image must carry it at
  `/etc/ds/intercept-ca.crt`. Bake it in reproducibly:
  `DS_M0_INTERCEPT_CA_CERT=~/tmp/ds-nested/ca/intercept-ca.crt vm/m0-image/build-m0-image-rootless.sh`
  (the default `m0-base-routed-cc` base is built this way — no manual image patching).
- **The proxy presents that same CA.** Stage the CA at `~/tmp/ds-nested/share/ca/`
  (`intercept-ca.crt` + `.key`); under swap mode `orchestrator-boot-l2.sh` exports it as
  `DS_TLSPROXY_SESSION_CA_CERT`/`_KEY`, so the leaf the guest sees chains to the CA it
  trusts. A CA mismatch here is an RST right after the TLS Finished ("downstream
  handshake reset").

## Files

| file | role |
| --- | --- |
| `run-testbed.sh` | one-command driver (host side) |
| `build-l1-image.sh` | rootless bake of the L1 "fat" image (podman → `podman unshare` mke2fs -d → direct-kernel) |
| `l1.Containerfile` | the L1 rootfs recipe (Debian + qemu + nftables + ssh + nested-virt module autoload) |
| `boot-l1.sh` | boot/ssh/console/down the L1 VM on the host (rootless qemu, SLIRP+hostfwd, 9p `/opt/ds`, vsock) |
| `inside-l1/gate-up.sh` | apply the floor + routed tap + start the gateways (runs inside L1) |
| `inside-l1/l2-up.sh` | boot the nested L2 agent VM on the routed tap (runs inside L1) |
| `inside-l1/validate.sh` | run the gating probes from L2 + read the nft counters (runs inside L1) |
| `inside-l1/gate-down.sh` | tear down the boundary + L2 (runs inside L1) |

## Design notes / gotchas baked in

- **Host-compatible binaries.** `ds-dnsgate`/`ds-tlsproxy` are built **inside a
  `debian:bookworm` container** (glibc 2.36) — an Arch-host build links glibc 2.39
  and won't run in L1. They land at `~/tmp/ds-nested/bin/` and are 9p-mounted.
- **GAP-1 fix.** `ds-dnsgate` gained a `DS_DNSGATE_LISTEN` env knob so it binds
  `0.0.0.0:15353` (the nft REDIRECT lands on the tap address, not loopback).
- **Policy pack path.** `ds-dnsgate` reads `pol2-system-baseline.pol1.yaml` from a
  compile-time-baked path; `gate-up.sh` symlinks `/work/dataplane/artifacts` to the
  staged copy so it starts.
- **Iterate without rebaking.** Binaries, the L2 image, the nft artifacts, and the
  `inside-l1/` scripts are mounted into L1 via 9p (`/opt/ds`) — edit on the host,
  re-run; only image-level changes (packages, ssh, networkd) need a rebake.
- **L2 self-configures** its routed-tap IP via a MAC-matched systemd-networkd drop-in
  (`05-l2-routedtap.network`) — no DHCP server on the /31, no console scripting.
- Everything lives under `~/tmp` (btrfs/reflink), never `/tmp`.
