# Spike findings — the per-session Linux attachment primitive (OQ1/D66, Stage 1)

| | |
|---|---|
| **Status** | **Spike findings — proposed, bind nothing.** Mints no D-number. D66 already ratified the dissolution and froze the contract; this spike picks only the FREE implementation detail (which of the three D66 primitives) and produces the three exit-criterion findings. Ratification stays with the doc 04 §6 log. |
| **Task** | taskdb 01KTWJ3WBGRHXQF310FH0VR4AY — "Run the Linux per-session attachment-primitive spike (OQ1/D66)". |
| **Sources** | doc 09 §2 placement note, §8 Stage 1, OQ1/D66 · sessions/round2/01 (D66 research + verdict) · doc 14 §4 (the 2026-06-13 joint-settled tap-create RACI row this spike consumes) · D69/D44/D34/D76. |
| **Procedure** | [`run-attach-spike.sh`](run-attach-spike.sh) (this directory) — the runnable artifact; this doc records what it shows and what only a real host can show. |
| **Date** | 2026-06-13 |

## 0. What was open and what was already frozen

D66 (sessions/round2/01) dissolved OQ1's ESXi half entirely and **froze** the
attachment *contract* (one host-visible `dstap-<idx>` tap per session, ≤15 chars,
never-recycled index, the NFT-2 `iifname` / NFT-5 ct-mark / LOG-2 attribution key),
the **isolation invariant** (no two agent devices share an L2 segment;
`br_netfilter` forbidden), the **addressing constraint** (D69: a per-session
interface-anchored gateway IP), and the **placement** (boundary stack in the
virtual-metal VM's host netns). What it left FREE — and what this spike picks — is
the single line in its "Frozen vs free" table:

> *Which structural primitive: per-session bridge vs routed tap vs shared bridge +
> `<port isolated='yes'/>`. Default lean: per-session bridge or routed tap
> (structural proof); isolated-ports acceptable only with a continuous blocking
> flag audit.*

This spike also discharges the three named D66 exit criteria — the no-L2-path
proof, per-session interface-anchored addressing, and a measured uplink-throughput
number — and consumes the tap-create RACI row joint-settled in doc 14 §4 on
2026-06-13 (placement (C): Boundary accountable for primitive semantics + naming,
Orchestrator for index allocation, the host agent the invoker).

## 1. Recommendation (proposed)

**Default to the routed tap (candidate 1); per-session bridge (candidate 2) is the
equally-sound structural alternative; shared-bridge + `BR_ISOLATED` (candidate 3) is
accepted only behind the continuous flag audit.** Rationale:

- **Both 1 and 2 give a *structural* no-L2-path proof** — there is no shared L2
  segment by construction, so the §9 "session A cannot reach session B" row is
  proved by *enumeration* (no bridge carries two agent taps), never inherited from
  the inet ruleset (which D66 forbids relying on, because bridged frames bypass the
  inet forward chain). The routed tap is the thinner of the two: it creates **zero
  bridge objects at all** (libvirt `type='ethernet'`, a host route + static neigh
  per tap), so there is not even a single-member bridge to enumerate — the audit
  surface is the route/neigh table, and the "no shared segment" property is
  trivially total.
- **Candidate 3's proof is weaker by kind, not degree.** `BR_ISOLATED` is a
  *per-port flag* that must survive every tap re-create, libvirt restart, and
  migration; silent flag loss restores full inter-session L2 with no ruleset change.
  D66 already names this fragility and leans away from it. It stays a supported
  option (some operators will want one bridge for ops simplicity) **only** with the
  structural auditor wired as a blocking runtime alarm — which this spike provides
  (`run-attach-spike.sh` PHASE A / `--self-test`).
- **Addressing (D69) is satisfied identically by all three:** each session gets its
  own /31 (`10.77.<idx>.0/31`, host gateway `.0`, guest `.1`), so the per-session
  gateway IP is interface-anchored and no two sessions share one — the spike's
  addressing exit criterion. The /31 (RFC 3021) is the tightest point-to-point
  allocation and leaves the `host_session_index` the sole varying field, keeping
  the derive-from-`ds-contracts`-constants path (doc 15 §4.1 step 4) one subtraction
  wide.

The recommendation does **not** re-open D66 and adds no decision; it records which
of D66's already-listed primitives the v0 implementation should default to.

## 2. The three exit criteria — findings

### (i) No-L2-path proof — STRUCTURAL for 1/2, FLAG-AUDITED for 3

- **Structural half (sandbox-verified logic, host-verified traffic).** The
  enumerate-and-audit logic is the load-bearing mechanism, and it is exercised in
  PHASE A against synthetic membership maps: it **passes** a per-tap/per-bridge or
  routed layout and **fails** the exact D66 sharp edge — two agent taps on one
  non-isolated bridge — and the `--self-test` proves this rejection is non-vacuous.
  The *live traffic* proof (ARP / gratuitous ARP / raw-eth unicast / IPv6 ND /
  forged-MAC from guest A, asserting zero frames on `dstap-B`) is **host-only**: it
  needs two real guests on the real kernel; the verbatim procedure is printed by
  PHASE C.
- **`br_netfilter` forbidden** (D66, not merely unused) — checked in PHASE A:
  `bridge-nf-call-iptables` must be absent or `0`. On the dev sandbox the sysctl is
  absent (the `bridge` module isn't even loaded), which is the desired posture; on
  a real host the check is a standing assertion against environment drift (Docker /
  k8s stacks auto-pull `br_netfilter` and would silently mask isolation bugs).

### (ii) Per-session interface-anchored addressing (D69) — VERIFIED (logic)

PHASE A audits the generated ruleset: 3 sessions present 3 **distinct**
interface-anchored guest IPs, none shared. A shared-gateway configuration fails the
spike by D66 item (ii); the generator structurally cannot emit one (the IP is a
function of the index). This is the half D69 leans on — session identity derived
from an interface-anchored signal, never raw source IP.

### (iii) Uplink-throughput number — HOST-ONLY (measured on the nested v0 substrate)

**No number is produced in this sandbox, and producing a fake one would be
theater.** A meaningful aggregate-uplink figure requires the nested v0 substrate
(the virtual-metal VM on ESXi) with real guests driving traffic through the single
uplink under many-VMs load — exactly the D66 exit criterion (iii) and the Stage-5
(d)-rig capacity input. The reproducible measurement procedure (iperf3 server +
per-session clients, aggregate Gbps recorded) is printed verbatim by PHASE C.
Per D34, this is **recorded** on nested and **asserted** (with thresholds) only on
metal — so the missing number is a substrate gap, not a spike failure: the
procedure is the deliverable, the number is filled in on first nested run and feeds
the scheduler's per-host session-capacity input.

## 3. Sandbox-verified vs host-only (the honest split)

The dev sandbox kernel (`7.0.10-arch1-1`) ships **no module tree** —
`CONFIG_BRIDGE=m` / `CONFIG_VETH=m` but `/lib/modules/<kver>` has no `bridge.ko` /
`veth.ko` to load — and an unprivileged `unshare -rn` netns has **no conntrack
hooks** (even `nft -c` rejects a `ct state` expression there). That draws a sharp,
honest line:

| Half | Status | What proves it |
|---|---|---|
| `dstap-<idx>` naming width (15 OK / 16 kernel-refused) | **Sandbox-verified** | PHASE B: `ip tuntap add` of the widest name succeeds, 16-char refused by the kernel |
| `iifname` + `ip saddr` enforcement match application | **Sandbox-verified** | PHASE B: the noct golden ruleset is `nft -f`-applied in a netns and read back |
| Structural-audit logic (no-L2-path enumeration) | **Sandbox-verified** | PHASE A + `--self-test` (non-vacuous: rejects the shared bridge) |
| Per-session distinct-guest-IP addressing (D69) | **Sandbox-verified** | PHASE A: audits the generated ruleset text |
| `br_netfilter`-forbidden posture | **Sandbox-verified** | PHASE A: sysctl absent on the sandbox |
| Golden ruleset text reproducibility | **Sandbox-verified** | PHASE A: generator output == golden |
| `bridge` / `veth` / `BR_ISOLATED` device build | **HOST-ONLY** | no loadable modules in the sandbox kernel |
| Live L2-isolation traffic proof (frames don't cross) | **HOST-ONLY** | needs two real guests on a shared/structurally-separated segment |
| `ct state established,related` rules | **HOST-ONLY** | no conntrack hooks in the unprivileged netns |
| Teardown-to-bootstrap byte-identity (NFT-6) | **HOST-ONLY** | needs the real bridge/route/neigh objects to leak-check |
| Aggregate uplink throughput (Gbps) | **HOST-ONLY** | needs the nested v0 substrate + traffic generators |

The sandbox-verified rows are the parts a CI lane can gate per-commit *today* (and
should — wire `run-attach-spike.sh --self-test` next to the other `--self-test`
gates). The host-only rows are exactly the `nested-ok` / metal-asserted assurance
tests sessions/round2/01 enumerates; they belong on the virtual-metal VM lane and
are blocked here only by substrate, not by design.

## 4. What this freezes downstream (and what it does not)

- **Feeds NFT-2's interface design:** the `iifname "dstap-<idx>"` match is the
  enforcement key, applied against a real netfilter path in PHASE B — NFT-2 can
  design on top of it.
- **Feeds §7/LOG-2 attribution:** the tap name is the attribution join key (already
  frozen by D66; this spike confirms the width and kernel round-trip).
- **Feeds the host-baseline artifact (`../README.md`):** "routed tap or per-session
  bridge, structural proof; `BR_ISOLATED` only with the blocking audit;
  `br_netfilter` forbidden" is the attachment-primitive posture the NFT-1
  host-baseline consumes (it already carries the `br_netfilter`-forbidden and
  libvirt >=6.1.0-iff-isolated floors from D66).
- **Does NOT touch:** the D76 mark layout (NFT-5's, frozen separately), the
  three-keys-agree *third* key (ct mark — NFT-5, not this spike; the ruleset here
  enforces the iif + guest-IP pair only), or any proto/§6 freeze. No decision-log
  row, no P-row flip.
