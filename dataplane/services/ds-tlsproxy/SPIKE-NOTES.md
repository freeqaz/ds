# SPIKE — Pingora transparent listener + original-dst recovery (REDIRECT path)

**Unit:** `egress2/spike-pingora-transparent` · **taskdb:** `01KTWJ29JG8JWXXV4KAT3EHF8H`
**Governing decisions:** D2/D40 (Pingora), **D69** (REDIRECT v0 behind the frozen
mechanism-agnostic `ConnOrigin` recovery seam), D70 (QUIC carveout — the same seam).
**Docs:** doc 03 §3 (interface-matched redirect), doc 09 NFT-2, doc 12 §2/§2.1/§13.1.

This is the doc 03 §3 / doc 09 NFT-2 transparent-proxy foundation in `ds-tlsproxy`:
a transparent listener that recovers the original destination via the stock
`SocketDigest::original_dst()` primitive (the frozen `ConnOrigin` recovery seam) and
forwards upstream; **recovery failure refuses**. It also authors the `iifname`-matched
nft REDIRECT ruleset (`nft/transparent-redirect.nft`).

---

## 1. What is VALIDATED NOW (green, in this sandbox)

Everything here runs offline with `--locked` and is exercised by
`cargo test -p ds-tlsproxy` + the netns validation script. No live `claude`/`cia`/
`podman`; synthetic fixtures + the real OS syscall path only.

| Claim | How it is proven | Where |
|---|---|---|
| The `ConnOrigin { original_dst, session }` recovery seam (D69 §2.1, invariants 1–4) | unit tests: dst pairs with interface-anchored session, admission key consumes only `ConnOrigin` fields | `src/transparent.rs` `recovery_pairs_*`, `admission_signature_consumes_only_*` |
| **Recovery FAILURE refuses** (invariant 3 — the graded core) | unit tests over the seam fake AND over a **real loopback socket**: a non-redirected connection's `SO_ORIGINAL_DST` returns the listener's own address (the kernel `getsockname` fallback) → refused; every error class refuses; the §10 recovery-failure event carries session attribution + a secret-free reason, no client bytes | `recovery_failure_refuses_*`, `every_recovery_error_class_refuses`, `socket2_recovery_refuses_a_non_redirected_socket` |
| The **real `SO_ORIGINAL_DST` getsockopt path** (the exact mechanism `SocketDigest::original_dst()` performs) decodes a kernel value on this host | unit test runs `Socket2OriginalDst::v4` against a real accepted loopback socket and decodes the returned `SockAddr` → `SocketAddr` | `socket2_recovery_succeeds_and_decodes_a_real_getsockopt_value` |
| Address-family discipline: a v6 recovery over a v4 socket refuses, never reinterprets | unit test over a real socket | `family_mismatch_is_refused_never_reinterpreted` |
| **E2E: outbound HTTP arrives at the listener and is forwarded upstream** | integration test: real HTTP/1.1 client → transparent listener (loopback redirect-target stand-in) → `recover_conn_origin` → `forward` splice → **real upstream HTTP origin** → `200 OK` + body back to the client; bytes counted both ways | `tests/e2e_transparent_forward.rs` |
| The `iifname` interface-match control LOADS (the NFT-2 control — match the interface, never source IP) | `unshare -rn` loads an `iifname "dstap-0"` filter rule; the repo's existing golden attach ruleset also loads | `nft/validate-transparent-redirect.sh` check 1 |
| The nat-type prerouting chain at `dstnat` priority LOADS | `unshare -rn` | `nft/validate-transparent-redirect.sh` check 2 |
| **LIVE REDIRECT: `SO_ORIGINAL_DST` recovers the real pre-DNAT dst on a genuinely-redirected socket** (the §2.1 / §E1 case, no longer reboot-pending — see below) | gated e2e: a real OUTPUT-hook nft `redirect` (the `nft_redir`/`nft_nat` modules are loadable again) DNATs a loopback connection; the production `Socket2OriginalDst` getsockopt recovers the pre-DNAT dst (`127.0.0.9:80`, ≠ the listener addr), and a direct non-redirected connect refuses `NoOriginalDst` | `tests/e2e_live_redirect.rs` (`DS_REDIRECT_LIVE=1`, under `unshare -rn`); `nft/validate-transparent-redirect.sh` check 3 = PASS |

Run them:

```sh
cd dataplane
cargo test  -p ds-tlsproxy --locked          # 51 unit + 1 e2e, all green
cargo clippy -p ds-tlsproxy --locked -- -D warnings
cargo fmt   -p ds-tlsproxy --check
./services/ds-tlsproxy/nft/validate-transparent-redirect.sh   # nft controls + honest REDIRECT status
```

### Why the recovery primitive is `socket2`, not `pingora-core`

`SocketDigest::original_dst()` is a thin, stock wrapper over the
`SO_ORIGINAL_DST` (v4) / `IP6T_SO_ORIGINAL_DST` (v6) **getsockopt** — the
conntrack-backed kernel read of a redirected socket's pre-DNAT destination
(doc 12 §2). `pingora-core` is **not yet vendored** in this workspace (doc 14 §6;
it lands with the service's full prestage, D40), so depending on it would break the
offline `--locked` build. `socket2` (already in the vendored/locked set as a
tokio/hickory transitive — the direct edge adds **no** new `Cargo.lock` package)
exposes the **same getsockopt** through safe `Socket::original_dst_v4()` /
`original_dst_v6()`, so the recovery module stays `#![forbid(unsafe_code)]`-clean.

The seam is `trait OriginalDst` (doc 12 §2.1 — the mechanism-agnostic interface):
`Socket2OriginalDst` is the production impl; a TPROXY `getsockname` backend (the
D70 QUIC carveout) or `pingora-core`'s `SocketDigest` slot in behind the **same**
trait without touching policy or TLS-1 (invariant 4). The production `accept/` layer
(doc 12 §13.1) swaps `SocketDigest::original_dst()` in for `Socket2OriginalDst` —
**same getsockopt, byte-identical recovery** — and that is the only line that changes.

### The getsockname-fallback nuance (a real correctness point)

On a socket that **never transited a REDIRECT**, the kernel's
`getsockopt(SO_ORIGINAL_DST)` does **not** error on this host — it falls back to
`getsockname()` and returns the listener's **own bind address**. A naive recovery
would treat that as a valid origin and forward to *itself*. `Socket2OriginalDst`
therefore refuses when the recovered dst equals the listener's local address — this
is exactly D69 invariant 3's "a direct connect to the proxy port that never transited
the NAT rule → refuse". (A genuine REDIRECT recovers the **pre-DNAT** upstream, which
is never the proxy's own `ip:port`.) This is unit-tested against a real socket.

---

## 2. Deferred-step status

### 2.1 The live `iifname`-REDIRECT transparent demo — RESOLVED (2026-06-13, no reboot)

Originally reboot-pending: the running kernel could not program the nft
`redirect`/`nat` statement because the `nft_redir`/`nft_nat` statement modules were
absent. Root cause was a stale running kernel — the `linux` package had updated
(7.0.10 → 7.0.11), so `/lib/modules/$(uname -r)` for the *running* kernel was gone
and `modprobe` could not load anything new. **Fixed without a reboot** by restoring
the running kernel's module tree from the pacman cache and loading the statement
modules:

```sh
sudo bsdtar -xpf /var/cache/pacman/pkg/linux-7.0.10.arch1-1-x86_64.pkg.tar.zst \
  -C / usr/lib/modules/7.0.10-arch1-1
sudo depmod 7.0.10-arch1-1
sudo modprobe nft_redir nft_nat nft_masq
```

After this, `validate-transparent-redirect.sh` **check 3 = PASS** (the `redirect`
statement loads), and the §E1 demo is exercised by `tests/e2e_live_redirect.rs`: a
real nft `redirect` DNATs a connection and the production `Socket2OriginalDst`
getsockopt recovers the REAL pre-DNAT destination (not the `getsockname` fallback),
with the non-redirected direct connect refusing. This was always a **substrate gap,
not a design gap** (the D34/D66 pattern: live nft NAT is metal-only); the recovery
wiring was already validated over loopback + the real getsockopt syscall (§1), and
is now also validated over a genuinely-redirected socket.

### 2.2 The qemu-guest-on-`dstap-0` live e2e (no guest image; explicit-proxy variant)

`dstap-0` exists (`10.77.0.1/24`) but is `NO-CARRIER / state DOWN` (no guest attached),
and the operator's user-local QEMU build (`$QEMU_PREFIX/usr/bin/qemu-system-x86_64`)
is QEMU 11.0.1 but needs its bundled
libs on `LD_LIBRARY_PATH` and **no guest disk image is provisioned in this sandbox**.
So the live guest e2e is a documented manual step, gated behind `DS_SPIKE_LIVE=1` (§E2).
The **same datapath** (accept → recover → forward → upstream) is proven over loopback
in `tests/e2e_transparent_forward.rs` now.

---

## 3. The `iifname`-matched REDIRECT ruleset (golden text)

Full file: [`nft/transparent-redirect.nft`](nft/transparent-redirect.nft). The core:

```nft
table ip ds_transparent {
	chain prerouting {
		type nat hook prerouting priority dstnat   # -100; TPROXY would be -150 (D69)
		policy accept
		# Match the INTERFACE (NFT-2 control), NEVER `ip saddr` — addresses can be
		# forged from inside the VM, the attachment point cannot (doc 03 §3).
		iifname "dstap-0" tcp dport 80  redirect to :18080  # VM http  -> ds-tlsproxy
		iifname "dstap-0" tcp dport 443 redirect to :18443  # VM https -> ds-tlsproxy
	}
}
```

Frozen non-edge (doc 12 §4.2, D76): in production this is programmed by
`ds-dnsgate` / the host agent, **never by `ds-tlsproxy`** (CAP_NET_RAW only — a
compromised proxy must not rewrite the ruleset that contains it). This spike file is
golden text the spike authored; the full NFT-1 artifact also carries udp/53 →
`ds-dnsgate` and the udp/443 reject (D70), out of this unit's scope.

---

## E1 — live iifname-REDIRECT + SO_ORIGINAL_DST recovery (NOW RUNNABLE — see §2.1)

The kernel now has `nft_redir`/`nft_nat`, so this is no longer deferred. The
recovery half is automated and reproducible as `tests/e2e_live_redirect.rs`
(`DS_REDIRECT_LIVE=1`, under `unshare -rn` — a rootless OUTPUT-hook redirect; the
DNAT and conntrack-backed `SO_ORIGINAL_DST` read are mechanism-identical to the
PREROUTING/`iifname` form). The full-metal host+tap variant below stays a manual
step (it needs real root for the host ruleset + a guest); it still refuses to
fabricate a result — the rule add fails loudly if the modules are ever absent.

```sh
# 1. program the transparent redirect on the agent tap (needs CAP_NET_ADMIN):
sudo nft -f dataplane/services/ds-tlsproxy/nft/transparent-redirect.nft
# 2. bind the production ds-tlsproxy transparent listener on :18080/:18443 with the
#    pingora-core SocketDigest::original_dst() recovery (the M0-host wiring seam,
#    doc 12 §13.1 — swap SocketDigest in for Socket2OriginalDst, same getsockopt).
# 3. from the guest on dstap-0, a plain `curl http://<any-upstream>/` is redirected;
#    the listener recovers the REAL upstream from SO_ORIGINAL_DST (now SUCCEEDS,
#    returning the pre-DNAT dst, not the getsockname fallback) and forwards.
# Expectation: the request reaches ds-tlsproxy and is forwarded to the recovered
# upstream; a direct `curl http://10.77.0.1:18080/` (no redirect transit) is REFUSED
# as a recovery-failure (invariant 3). DO NOT mark green unless step 1 succeeded.
```

## E2 — DEFERRED manual step: qemu guest on dstap-0 via EXPLICIT proxy

Because the live kernel REDIRECT is reboot-pending, the guest reaches the proxy by
**explicit** proxy (the golden image sets `HTTP_PROXY`; doc 09 §5 TLS-2, the
`ds_tlsproxy::explicit` path), pointed at the host-side tap gateway. Gated behind
`DS_SPIKE_LIVE=1` and a provisioned guest image — synthetic/no-network by default.

```sh
[ "${DS_SPIKE_LIVE:-0}" = 1 ] || { echo "live step gated (set DS_SPIKE_LIVE=1 + provide a guest image)"; exit 0; }
ip link set dstap-0 up                                   # bring the routed tap up
export LD_LIBRARY_PATH="$HOME/.local/opt/qemu/usr/lib"   # qemu 11 bundled libs
"$HOME/.local/opt/qemu/usr/bin/qemu-system-x86_64" \
  -enable-kvm -m 512 -nographic \
  -netdev tap,id=n0,ifname=dstap-0,script=no,downscript=no \
  -device virtio-net-pci,netdev=n0 \
  -drive file="$GUEST_IMG",if=virtio   # GUEST_IMG: a small distro with curl
# inside the guest (10.77.0.2/24, gw 10.77.0.1):
#   HTTP_PROXY=http://10.77.0.1:18080 curl -s http://<upstream>/   # explicit proxy
# host-side direct checks must use --noproxy (a global HTTPS_PROXY is set):
#   curl --noproxy '*' http://10.77.0.1:18080/
# Expectation: the guest's request arrives at ds-tlsproxy on :18080 and is forwarded
# upstream (the explicit-proxy datapath; the transparent SO_ORIGINAL_DST path is E1).
```

---

## 4. Files this unit owns (all under `dataplane/services/ds-tlsproxy/`)

- `src/transparent.rs` — the `ConnOrigin` recovery seam, `Socket2OriginalDst`
  (the `SO_ORIGINAL_DST` getsockopt provider), refuse-on-failure, the §10
  recovery-failure event, and the `forward` splice. + 10 unit tests (the
  transparent module) — see §1 for the e2e.
- `tests/e2e_transparent_forward.rs` — the outbound-HTTP-forwarded e2e.
- `nft/transparent-redirect.nft` — the golden `iifname`-matched REDIRECT ruleset.
- `nft/validate-transparent-redirect.sh` — the netns validation (honest live status).
- `Cargo.toml` — adds the `socket2` direct edge (vendored/locked, no new package).
- `src/lib.rs` — registers `pub mod transparent`.
- `SPIKE-NOTES.md` — this file.

## 5. Frozen contracts this unit RESPECTS (renegotiates nothing)

- D69 §2.1 invariants 1–4 are enforced, not redefined; the recovery seam is the
  mechanism-agnostic interface (REDIRECT ↔ TPROXY ↔ pingora `SocketDigest` ↔ the
  test provider all produce the same `ConnOrigin`).
- D76 / doc 12 §4.2: no `ds-nft` dependency, no conntrack/netlink **write**; the
  getsockopt is a read of NAT state on the proxy's own accepted socket.
- The `ds-contracts` `SessionRef` (the `dstap-<idx>` join key) is consumed as-is;
  `session` is interface-anchored, never the raw source IP (invariant 2, D44).
- pingora-core wiring is the documented M0-host integration seam (doc 12 §13.1),
  not built here; `SocketDigest::original_dst()` is on the D40 vendored-API watch list.
