# artifacts/nft — NFT-1 bootstrap ruleset (+ NFT-2 redirect) + NFT-4 closure + NFT-5 flow-tag + systemd units

Home of the **versioned NFT-1 host bootstrap ruleset and the systemd units that install
it** at boundary start: one `inet` table, base chains with default drop for all traffic
originating on agent-VM (per-session tap) interfaces, established/related allowed back
in, and — as of `artifact-version: 2` — the **NFT-2 transparent redirect** (udp/tcp 53 →
ds-dnsgate) in the nat prerouting chain
(doc 09 §3, NFT-1/NFT-2).
The **NFT-4 resolver-bypass-closure** ruleset (`nft-4-resolver-closure.nft`) layers on top
in its own `inet` table, adding the foreign-resolver bypass-attempt counter+nflog and the
DNS-over-TLS (853) drop, plus a **defense-in-depth** copy of the udp/443 QUIC reject
(doc 09 §3, NFT-4). The
**LIVE udp/443 (QUIC) reject** (D70) now rides the **NFT-1 floor** itself, in its `forward`
chain before the terminal drop, so the floor is self-sufficient (it rejects QUIC without
depending on the separately-installed NFT-4 table; a base-chain `drop` is terminal, so a
reject placed only in NFT-4's later-priority forward chain would be shadowed — taskdb
01KTZV3XN). NFT-4 keeps the reject anyway as a redundant companion, which also keeps it the
home of the RowQUICReject conformance ownership and the ds-nft `quic_reject` shape lint.

- **Owner workstream:** Boundary (NFT-1 step owner)
- **License:** OSS — Apache-2.0 (ships with the open data plane, D15/D25)
- **Governing decisions:** D3/D4 (default-deny, DNS-gated sets), D44/D69 (NFT-2
  interface-matched redirect — `iifname` only, never source IP; the mechanism-agnostic
  `ConnOrigin` recovery seam), D66 (boundary host netns vocabulary), D69 (one nat-type
  prerouting REDIRECT chain), D70 (udp/443 **rejected** with icmp port-unreachable +
  counted — never silently dropped; the live reject rides the NFT-1 floor with an NFT-4
  defense-in-depth copy), D76
  (mark lint, doc 14 §5)

## Rules of this directory

- **Versioned artifacts, never hand-applied state** (doc 09 NFT-1): the ruleset is a
  build artifact installed by a systemd unit; runtime mutations come only through
  `ds-nft` writes layered on top of it. If you are typing `nft` into a host shell,
  you are doing it wrong.
- **CI-linted against `ds-contracts` mark constants** (D76): any use of mark bits
  14–23 or any unmasked mark write fails the build (`rust-dataplane.yml` lint stub).
  Mark literals never appear here — constants come only from `ds-contracts`
  (doc 13 §4).
- Rulesets are authored in the `inet` family so IPv6 is dropped by default while
  dormant (D75, doc 14 §11).
- The udp/443 verdict wording is frozen: "rejected (icmp port-unreachable) + counted
  per session" (D70 — the Stage-2 errata row, doc 14 §10).

## Contents

- **`nft-1-bootstrap.nft`** — the versioned ruleset (`artifact-version: 2`).
  One `inet` table `ds_boundary`: `input`/`forward` chains default **DROP** with
  established/related allowed back in, an `output` chain (host egress unconstrained
  at NFT-1; the Stage-3 enforcement layer lands later), and the nat-type
  `prerouting` chain (the single REDIRECT chain the D69 closure assigns to NFT-1)
  now carrying the **NFT-2** udp/tcp 53 → ds-dnsgate redirect (`redirect to :15353`,
  a free strawman port). Both forward-chain drops and the NFT-2 redirect match on
  `iifname "dstap-*"` (the attachment point, **never** source IP — doc 03 §3, the
  doc 06 (c) in-VM-spoofing invariant); a forged `ip saddr` cannot escape because the
  rule never reads the source. No marks anywhere (D76). The `forward` chain ALSO carries
  the **live udp/443 (QUIC) reject** (`ct state new udp dport 443 counter reject with
  icmpx type port-unreachable`) immediately before its terminal `ct state new drop`, so
  the floor rejects QUIC self-sufficiently (D70 reject-not-drop; no dependence on NFT-4;
  the `ct state new` scope leaves a future per-session-admitted QUIC stream untouched —
  the unadmitted-QUIC default, overridable by a future NFT-3-style admit). The NFT-2b
  80/443 cutover is the only later step not in this artifact yet.
- **`nft-4-resolver-closure.nft`** — the versioned NFT-4 resolver-bypass-closure ruleset
  (`artifact-version: 1`). A SEPARATE `inet` table `ds_resolver_closure` (so NFT-1 keeps its
  frozen default-deny + port-53-redirect scope fence, and the closure is reversible with a
  single `nft delete table inet ds_resolver_closure`) carrying the three D70/NFT-4 controls:
  (1) the **foreign-resolver bypass-attempt** counter + `nflog` observe rules (D69,
  round2/04) — `iifname`-anchored port-53 packets are counted and logged (the bypass signal
  ds-flowlog joins to the session via `DnsEvent.aimed_resolver`); delivery itself stays NFT-1's
  redirect; (2) **DNS-over-TLS (853) dropped** for both transports; (3) **udp/443 (QUIC)
  rejected** — `reject with icmpx type port-unreachable` + a `counter`, **never silently
  dropped** (D70), so the refusal is observable and counted per session (the on-box half of
  `RejectReason::QuicBlocked`) and non-cooperative clients fall back to the TCP/443 path the
  egress gateway can see. **The LIVE QUIC reject is now NFT-1's** (priority 0, before its
  terminal drop); this NFT-4 copy is a redundant **defense-in-depth** companion kept so the
  RowQUICReject conformance ownership and the ds-nft `quic_reject` shape lint stay anchored
  here (taskdb 01KTZV3XN). Every session-scoped rule matches `iifname "dstap-*"` (the
  unforgeable attachment point, **never** `ip saddr` — doc 03 §3, the doc 06 (c) in-VM-spoofing
  invariant). No marks anywhere (D76). The DoH closure (DNS-3 denial + TLS-1 SNI over the D64
  baseline blocklist, POL-2) is a policy/service control asserted by the resolverlock
  conformance adapter and policy-core, NOT an L3/4 rule, so it is out of scope for this file.
- **`nft-5-flowtag.nft`** — the versioned NFT-5 per-session `ct mark` flow-tag stamping
  ruleset (`artifact-version: 1`). A SEPARATE `inet` table `ds_flowtag` (independently
  installable, reversible with a single `nft delete table inet ds_flowtag`) so the NFT-1 floor
  stays **mark-free by design** (the `check-nft-mark-constants` land gate; marks arrive only
  here with NFT-5, sourced from `ds-contracts`). It ships the SKELETON — a `flowtag_forward`
  base chain at `priority mangle` (-150, strictly EARLIER than NFT-1's filter (0), so the
  stamp lands on a NEW flow's conntrack entry BEFORE the floor's terminal drop and a dropped
  flow's nflog still carries the session) dispatching `meta iifname vmap @session_tag`, and the
  empty `session_tag` (`type ifname : verdict`) map — plus the documented per-session
  stamp-chain template. Per-session STATE is runtime, written by `ds-nft`
  (`flowtag::NftWriter::stamp_session` / `unstamp_session`): a `tag_<idx>` chain carrying the
  masked read-modify-write `ct mark set ct mark & ~DS_MARK_MASK | compose(Leg::AgentVm, idx)`
  + a `counter` (**no verdict** — the floor keeps drop authority), and the `session_tag`
  element keying `dstap-<idx>` → `jump tag_<idx>`. No mark VALUE and no complement-mask literal
  is authored inline (the stamp body is a COMMENTED template; the value is `ds-contracts`
  runtime state, D76 — the mark lint enforces it). The stamp keys on the unforgeable
  `dstap-*` attachment point, **never** `ip saddr` (doc 03 §3, doc 06 (c)). Conntrack
  accounting (`nf_conntrack_acct=1` / `nf_conntrack_timestamp=1`, host baseline doc 14 §11) is
  a precondition, consumed by reference. The kernel event streams map to LOG-1 `FlowRecord`s +
  drop events via `ds-telemetry::flow` (the `ds-nft5-drop ` nflog prefix + conntrack
  accounting); the live-kernel proof is the env-gated `DS_NFT5_LIVE` netns arm (deferred-manual,
  D50). See doc 09 §3, NFT-5.
- **`ds-nft-bootstrap.service`** — the systemd unit that installs the ruleset
  declaratively at boundary start.

## Install & rollback

Install is **declarative, via the systemd unit only** — never an interactive
`nft` shell (doc 09 §3):

- The artifact ships to `/etc/ds/nft/ds-nft-bootstrap.nft` as part of the boundary
  image; `ds-nft-bootstrap.service` runs `nft -f` on it at boundary start
  (`After=ds-host-baseline.service`, `Before=ds-dnsgate.service ds-tlsproxy.service`
  — the default-deny floor exists before any boundary service or session).
- **Idempotent:** the ruleset's `delete table inet ds_boundary` preamble means a
  re-install or service restart converges to the same state and touches no other
  table in the netns (ops-access WireGuard, systemd-networkd, etc.).
- **Rollback:** `ExecStop` runs `nft delete table inet ds_boundary`, removing only
  our table. NFT-6 session teardown operates on rules layered on top at runtime,
  not on this bootstrap floor.

Parse-check the artifact before shipping: `nft -c -f nft-1-bootstrap.nft` (a full
kernel-aware check; needs `nf_conntrack` loadable for the `ct state` rules, `nft_nat`/
`nft_redir` for the NFT-2 `redirect` rules, **and** `nft_reject` for the udp/443 `reject`
— in a container/sandbox without those modules, `-c` still reports "Could not process
rule" on the redirect/ct-state/reject lines because nft binds the expression to the
kernel even in check-only mode; run on a host with the modules loadable, or strip the
`redirect`/`ct state`/`reject` lines to confirm pure syntax). The structural shape of the
NFT-2 redirect rules **is** CI-checkable with
no kernel via the `ds-nft` `redirect`-module contract lint
([`crates/ds-nft/src/redirect.rs`](../../crates/ds-nft/src/redirect.rs)), and the
`iifname`-vs-forged-`saddr` half is exercised against a real kernel — where the modules
are loadable — by `crates/ds-nft/tests/nft2_spoofing_netns.rs` under `unshare -rn`.
Verify the unit with `systemd-analyze verify ds-nft-bootstrap.service`.

## Pending integration (not yet provable in-repo)

The artifact's full *done-when* — "a VM behind a freshly bootstrapped host can reach
nothing at all" plus the doc 06 (c) default-deny assertion — requires the M0
virtual-metal host with real per-session taps and a live conntrack kernel. That is
the pending integration step; the in-repo half (parse-check clean, valid unit, rules
honored) is what lands here. See the NFT-1 taskdb note.

Neighbors: `../host-baseline/` (the sysctl/kernel floor the ruleset assumes),
`crates/ds-nft/` (runtime writer), `crates/ds-contracts/` (lint source of truth).
