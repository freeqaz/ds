<!-- SPDX-License-Identifier: Apache-2.0 -->

# AttachPrimitive — the host-agent networking substrate (the last Milestone-1 gate)

> **Build guide for the nft4 / dataplane agent who picks this up.** It is the
> durable spec for the ONE substrate between "all of Milestone-1's code is
> landed" and "a human drives Claude Code running INSIDE a per-session KVM VM
> from the writer seat." Every fact below is extracted from the LANDED code/docs
> on this branch's base; nothing here is invented. Keystone task:
> **`01KV8XSNEX`** (`taskdb task get 01KV8XSNEX`).

---

## 1. WHY — what is missing, and why it is the last gate

Today the `AttachPrimitive` is a **no-op**. The offline stand-in `deferredAttach`
([`../../../cmd/host-agent/seams.go`](../../../cmd/host-agent/seams.go), the
`deferredAttach` type + its three methods) programs **nothing** in the kernel,
and it is the binding wired into the production composition root in BOTH
directions:

- `host, err := libvirt.NewHostAgentWithEntrypoint(alloc, deferredAttach{}, …)`
  — the create driver ([`../../../cmd/host-agent/main.go`](../../../cmd/host-agent/main.go),
  `buildDriverServiceWithBridge`).
- `destroyer, err := libvirt.NewDestroyer(domainDestroyer, deferredAttach{}, …)`
  — the teardown driver (same file).

So a booted session VM has **no tap interface and no per-session NFT objects**.
The two consequences are exactly the two halves of Milestone-1 that cannot
close:

1. **Claude Code cannot egress.** With no session NFT there is no default-deny
   base, no `dstap`-anchored redirect of `53 → ds-dnsgate` / `80,443 →
   ds-tlsproxy`, and no per-session allow-set — i.e. no gated path to the model
   API, which is the entire D28 security model.
2. **The writer-seat drive cannot complete.** The host-agent attach bridge
   dials `GuestIP:4242` (`M0_ATTACH_PORT == libvirt.DefaultAttachPort`), but
   with no tap + no host↔guest allow rule that dial cannot reach the in-guest
   forwarder, so [`../../../cmd/host-agent/LIVE-SMOKE.md`](../../../cmd/host-agent/LIVE-SMOKE.md)
   §A can only be exercised **reader-only**.

**Everything else for M1 is landed**: `ds-entrypoint` launches Claude Code on
config-presence; the gap-1 config-drive delivers the `EntrypointConfig`; the
orchestrator dials the real host-agent `HypervisorDriverService`; the
`ds-hostbridge` serving leg + `serpent up` are on `main`. This substrate is what
gives the VM its NIC, gates that NIC through the boundary gateways, and opens the
writer seat.

---

## 2. THE SEAM — what is already invoked, and who owns it

The contract is **already modeled and already invoked**; only the real body is
missing (the deferred-binding posture
[`seams.go`](seams.go) / [`../../nftbridge/doc.go`](../../nftbridge/doc.go)
describe for every host-side seam):

```go
// orchestrator/internal/hypervisor/libvirt/seams.go
type AttachPrimitive interface {
	CreateTap(ctx context.Context, b Binding) error
	InstantiateSessionNFT(ctx context.Context, sessionUUID string, b Binding) error
	FlushSession(ctx context.Context, sessionUUID string) error
}
```

**RACI (doc 14 §1/§4):** the host agent is the **INVOKER**; `ds-nft` is the
**SINGLE writer** of tap/nft objects. The host agent never writes an nft object
itself — every method here crosses into `ds-nft` through the cgo edge
([`../../nftbridge/doc.go`](../../nftbridge/doc.go): "THE explicit Go↔Rust edge
… No other Go code may touch nftables, and no other Go package may link Rust").
Boundary is Accountable for the primitive semantics + the `dstap-<idx>` naming;
the Orchestrator is Accountable for index allocation, the never-recycle window,
and the session-record binding.

**Where it is invoked (verify before you change anything):**

| Method | Invoked at | §-step |
| --- | --- | --- |
| `CreateTap` | [`create.go`](create.go) `CreateSession` (the `h.attach.CreateTap(ctx, binding)` call) | doc 15 §4.1 step 4 (`StepAllocate`) |
| `InstantiateSessionNFT` | [`create.go`](create.go) `CreateSession` (the `h.attach.InstantiateSessionNFT(ctx, req.SessionUUID, binding)` call, right after `CreateTap`) | §4.1 step 4 |
| `FlushSession` | [`destroy.go`](destroy.go) `Destroy` (step 2, `d.attach.FlushSession`), and create-rollback from step 4 onward | doc 15 §4.2 step 2 (NFT-6) |

**The `Binding` it is handed** ([`binding.go`](binding.go), the three keys that
must agree, D44/D66):

- `HostSessionIndex` — the host-local never-recycled index (D66); its 14-bit
  residue rides the ct mark as a disambiguator (D76).
- `TapName` — `dstap-<idx>` (≤ `IFNAMSIZ`), the **authoritative join key** (the
  NFT-2 `iifname`, the NFT-5 ct-mark key, the LOG-2 attribution key).
- `GuestIP` — the per-session `GuestAddress` (family-tagged bytes, D44/D75).
- `OverlayPath` — populated at step 7; not relevant to the attach NFT objects.

`CreateTap` derives `dstap-<idx>` from `HostSessionIndex` (the `Binding` already
carries it); `InstantiateSessionNFT` programs the per-session NFT objects keyed
on that tap name; `FlushSession` tears them down. Every method is **idempotent
on the session** (doc 15 §5.1) so a create/rollback retry converges.

---

## 3. WHAT `InstantiateSessionNFT` MUST PROGRAM

The full per-session enforcement surface (doc 15 §4.1 step 4 +
doc 09 §3
NFT controls). The `dstap-<idx>` tap name is the `iifname` anchor for every
interface-matched rule — **never `ip saddr`** (the doc 06 (c) spoofing
invariant: addresses can be forged from inside the VM, the attachment point
cannot):

1. **Session chains + EMPTY allow-sets.** The per-session chains plus the EMPTY
   `allow4_<session>` / `allow6_<session>` named sets (the doc 14 §4 / doc 09 §3
   NFT-3 naming). The sets start **empty** — DNS-admitted destinations land
   later through the policy path (ds-dnsgate's DNS-2 insert-then-answer), not
   here. `allow6_<session>` stays empty under the **D75 Phase-B** guest-invariant
   posture (IPv6 dormant; AAAA stripped at the resolver).
2. **NFT-2 dnsgate redirect** — `udp/tcp 53 → ds-dnsgate`, `iifname`-anchored on
   the `dstap`, REDIRECT/DNAT per **D69** (never `dnat to 127.0.0.1`). Matches
   the rule-shape predicate `ds-nft` already ships (the `redirect` module).
3. **NFT-2b tlsproxy cutover** — `tcp 80/443 → ds-tlsproxy`, same `iifname`
   anchoring (doc 09 §3 NFT-2b).
4. **NFT-4 resolver-bypass closure** — `udp/443` (QUIC) **reject** (icmp
   port-unreachable, counted per session — never silently dropped, D70) + port
   `853` (DoT) **drop** on both transports, `iifname`-anchored (**D42/D69**).
   Matches the `quic_reject` + `dot853` rule-shape predicates `ds-nft` ships.
5. **Default-deny base** — the NFT-1 posture: a VM behind a freshly programmed
   session reaches nothing except the gateways above (doc 09 §3 NFT-1; **D3** —
   NFTables has no policy brain of its own).
6. **The host↔guest `:4242` attach allow** — the writer-seat carriage leg: allow
   the host-agent bridge to dial `GuestIP:4242` over the tap. The port is fixed:
   `M0_ATTACH_PORT == libvirt.DefaultAttachPort` (`= 4242`, defined in
   [`attachminter.go`](attachminter.go) as `DefaultAttachPort`). This is the
   `:4242` allow tracked as keystone child **`01KV7SBQ6C`**.

**Where the GAP is.** `ds-nft` (`dataplane/crates/ds-nft`) ALREADY has: the
rule-shape predicates ([`redirect`](../../../../dataplane/crates/ds-nft/src/redirect.rs),
[`dot853`](../../../../dataplane/crates/ds-nft/src/dot853.rs),
[`quic_reject`](../../../../dataplane/crates/ds-nft/src/quic_reject.rs) — pure-text
contract lints), the `flush` body (`flush_session`), the dual-kernel `refresh`
paths (D68), and the D72 two-phase policy-apply (`apply` — the policy-snapshot
**consumer**). What does **not** exist yet is the **per-session
CREATE/INSTANTIATE write path**: tap-create (`dstap-<idx>`) + session-chain/set
instantiation + the control rules + the `:4242` allow. That write path is this
build's center of mass.

---

## 4. DECOMPOSITION — the build, in order

> The `ds-nft` crate (`dataplane/`) is **nft4/dataplane territory**, owned by
> parallel dataplane waves — do NOT fan an orchestrator/assurance wave onto it
> (it WILL collide at land, per keystone `01KV8XSNEX`). The Go-side units (c/d)
> are the orchestrator/host-agent half.

**(a) `ds-nft` per-session CREATE/INSTANTIATE write API** —
[`dataplane/crates/ds-nft`](../../../../dataplane/crates/ds-nft/README.md). A new
write path on the `NftBackend` (real netlink + the `RecordingBackend` fake): create
the `dstap-<idx>` tap, instantiate the session chains + empty `allow4_/allow6_`
sets, the NFT-2/2b/4 control rules, and the `:4242` attach allow. Single-writer +
mark-mask (**D76**) discipline; constants come ONLY from `ds-contracts` (no local
mark literals).

**(b) the Go↔ds-nft cgo WRITE edge** —
[`../../nftbridge`](../../nftbridge/doc.go). Today `nftbridge` is
**canonicalization / content-hash ONLY** (the `staticlib` crate-type + cgo
binding "lands with the first ds-nft staticlib artifact", per its `doc.go`).
Task **`01KV481M7N`** is the **flush-half** FFI + the metal-nightly e2e lane —
extend that SAME edge for create/instantiate. Behind `DS_NFTGATE_LIVE`.

**(c) the real `AttachPrimitive` Go impl** — replace `deferredAttach`
([`../../../cmd/host-agent/seams.go`](../../../cmd/host-agent/seams.go)) with a
real impl whose `CreateTap`/`InstantiateSessionNFT`/`FlushSession` call the (b)
cgo edge; select it in [`../../../cmd/host-agent/main.go`](../../../cmd/host-agent/main.go)
at the `NewHostAgentWithEntrypoint` + `NewDestroyer` sites **behind
`DS_HOSTAGENT_LIVE`** — off the gate the no-touch `deferredAttach` stays (the
gate-clean offline default, D50/D80). This mirrors how the overlay/boot/CA seams
already flip gate-aware in `buildDriverServiceWithBridge`.

**(d) the `:4242` host↔guest attach allow** — the writer-seat leg inside
`InstantiateSessionNFT` (keystone child **`01KV7SBQ6C`**). `M0_ATTACH_PORT =
4242 = libvirt.DefaultAttachPort`; the bridge execs `ds-hostbridge` to dial
`guestIP:4242`. `01KV7SBQ6C` is the unit that also flips the LIVE-SMOKE.md
`:4242` framing from "declared-only" to a now-closable live leg.

**(e) the metal-nightly e2e lane** — clone → tap → NFT → boot → drive → destroy
on a real kernel, on the virtual-metal box. Relates to `01KV481M7N`'s e2e-lane
half. Gated `DS_HOSTAGENT_LIVE` + `DS_NFTGATE_LIVE`.

---

## 5. GATES, D-NUMBERS, FILE MAP, ACCEPTANCE

### Gates (offline default = no-touch fake; live = real kernel)

| Gate | Scope |
| --- | --- |
| `DS_HOSTAGENT_LIVE` | the host-agent live legs (real `AttachPrimitive` selected; real overlay/boot already gated on this) |
| `DS_NFTGATE_LIVE` | the `ds-nft` live-kernel cgo edge (the (b) write path) |

With BOTH unset (the sandbox / CI / `go test ./...` default, and the only path
the wave gate exercises) the daemon serves over `deferredAttach` and touches
nothing: no `ds-nft`, no libvirt/KVM/qemu (the
[`../../../cmd/host-agent/main.go`](../../../cmd/host-agent/main.go) package-doc
"LIVE-GATING" + "STILL DEFERRED" notes). The whole §4.1/§4.2 choreography is
already tested against that no-touch fake (**D50**).

### D-numbers

- doc 14 §1
  (contract index), §4
  (session-index join-key RACI), §5
  (mark-space layout, mask discipline, `flush_session` / NFT-6).
- doc 15
  §4.1 step 4 (host-side allocation + tap-create + per-session NFT instantiation),
  §4.2
  (unconditional `flush_session(legs=all)` + NFT-6 order).
- doc 09 §3
  (NFT-1 default-deny, NFT-2 redirect, NFT-2b cutover, NFT-3 allow-sets, NFT-4
  bypass closure, NFT-6 teardown).
- **D3** (NFTables has no policy brain — the DNS gate programs it); **D68**
  (`flush_session`; both kernel refresh paths in CI); **D69** (`iifname`-anchored
  REDIRECT, never source-IP); **D75** (`allow6` empty under Phase-B; the egress
  NIC); **D76** (mark-mask discipline); **D42** (DoT 853 drop + QUIC reject).

### File map

| Path | Role |
| --- | --- |
| [`seams.go`](seams.go) | the `AttachPrimitive` interface (the seam, with the full per-method contract doc) |
| [`create.go`](create.go) | invokes `CreateTap` → `InstantiateSessionNFT` at §4.1 step 4 |
| [`destroy.go`](destroy.go) | invokes `FlushSession` (NFT-6) at §4.2 step 2 + create-rollback |
| [`binding.go`](binding.go) | the three-keys-agree `Binding` (`dstap-<idx>`, `GuestIP`, index) |
| [`attachminter.go`](attachminter.go) | `DefaultAttachPort = 4242` (the `:4242` carriage port) |
| [`../../../cmd/host-agent/seams.go`](../../../cmd/host-agent/seams.go) | `deferredAttach` — the offline stub to REPLACE (unit c) |
| [`../../../cmd/host-agent/main.go`](../../../cmd/host-agent/main.go) | the wiring sites (`NewHostAgentWithEntrypoint` + `NewDestroyer`) to select the real impl behind `DS_HOSTAGENT_LIVE` |
| [`../../nftbridge`](../../nftbridge/doc.go) | the Go↔Rust cgo edge to extend with the create/instantiate write FFI (unit b) |
| [`../../../../dataplane/crates/ds-nft`](../../../../dataplane/crates/ds-nft/README.md) | the SINGLE nft writer crate; add the per-session create/instantiate API (unit a) |
| [`../../../cmd/host-agent/LIVE-SMOKE.md`](../../../cmd/host-agent/LIVE-SMOKE.md) | the operator live-close runbook gated on this substrate |

### Acceptance

Under `DS_HOSTAGENT_LIVE` + `DS_NFTGATE_LIVE` on the KVM box, a created session:

1. gets a **real `dstap` tap + per-session session NFT** (default-deny base +
   the NFT-2/2b dnsgate/tlsproxy redirects + the NFT-4 QUIC-reject/DoT-drop +
   the EMPTY `allow4_/allow6_` sets + the `:4242` host↔guest allow);
2. **Claude Code inside the VM egresses ONLY through the gateways** — no path
   bypasses `ds-dnsgate` / `ds-tlsproxy` (the doc 06 (c) default-deny + spoofing
   matrix holds against the live ruleset);
3. **the host-agent bridge dials `GuestIP:4242` and the writer-seat drive
   completes** (LIVE-SMOKE.md §A is no longer reader-only);
4. **destroy `flush_session(legs=all)` reaps cleanly** — the doc 06 (b)
   byte-identical clean-teardown + (c) default-deny conformance hold on real
   kernel state;
5. **the offline path stays byte-identical** — with the gates unset the daemon
   touches nothing and `go test ./...` + the wave gate stay green against the
   no-touch fake (D50/D80).

When (1)–(5) hold, the M1 live smoke closes (LIVE-SMOKE.md §A drives the full
`serpent up` → VM-hosted Claude Code over `attach.v1` writer-seat path).

---

## 6. Cross-links

- **Keystone task `01KV8XSNEX`** — `taskdb task get 01KV8XSNEX` (the substrate
  gate; this guide is its build doc).
- **`01KV481M7N`** — the live `ds-nft` cgo `FlushSession` bridge behind
  `DS_NFTGATE_LIVE` + the metal-nightly e2e lane (extend the SAME edge for
  create/instantiate).
- **`01KV7SBQ6C`** — the per-session host↔guest `:4242` tap allow real body (the
  writer-seat leg) + the LIVE-SMOKE.md `:4242` reframe.
- [`../../../../dataplane/crates/ds-nft/README.md`](../../../../dataplane/crates/ds-nft/README.md)
  — the SINGLE nft/netlink writer crate (charter, frozen invariants, module map).
- [`../../nftbridge/doc.go`](../../nftbridge/doc.go) — the one Go↔Rust cgo edge.
- [`../../../cmd/host-agent/LIVE-SMOKE.md`](../../../cmd/host-agent/LIVE-SMOKE.md)
  — the operator live-close runbook the writer-seat drive is gated on.
