# artifacts/host-baseline — the virtual-metal host baseline

Home of the **versioned host-baseline artifact**: the kernel floor, sysctls, per-session
tap settings, and capability posture the boundary stack requires of the virtual-metal
VM's host network namespace
(doc 14 §11;
schema strawman in doc 13 §4).

- **Owner workstream:** Boundary (consolidated under NFT-1)
- **License:** OSS — Apache-2.0 (D15/D25)
- **Governing decisions:** D68 (kernel ≥6.12; `nf_conntrack_tcp_loose=0` or
  `flush_session` is a no-op; `nf_conntrack_acct=1`, `nf_conntrack_timestamp=1`),
  D66 (structural isolation; **`br_netfilter` is forbidden, not merely unused**;
  libvirt ≥6.1.0 iff isolated ports), D75 (per-session taps: `disable_ipv6=1`,
  `accept_ra=0`; no RA/DHCPv6 on any per-session segment), D76 (CAP_NET_RAW-only
  posture for ds-tlsproxy; mark constants only from `ds-contracts`)

## The one rule that gives this directory its existence

This is a **distinct versioned artifact, NOT pushed over the policy stream**
(doc 14 §11; doc 13 §4). It versions with the NFT-1 ruleset artifact and the host
image, ships like code, and is applied at host bring-up. Drift is caught by CI and the
doc 06 (c) suite — "sysctl drift = failure, not log line" — never by the D72 revocation
sweep. Keeping it in its own directory (separate from `../policy-packs/`, which IS live
policy) encodes that lifecycle split structurally (final-design resolution 13).

## The versioned artifact: `host-baseline.v0.json`

`host-baseline.v0.json` is the machine-readable v0 baseline — every doc 14 §11
obligation in one file, keyed by governing D-number:

| Field | Obligation | D |
|---|---|---|
| `kernel.min_version` = `6.12`, `kernel.fallback` = `delete+add`, `both_paths_in_ci` | kernel floor for the in-place nft element-timeout refresh; the delete+add fallback ships behind the same nft-writer API with both paths in CI | D68 |
| `sysctls.net.netfilter.nf_conntrack_tcp_loose` = 0, `…_acct` = 1, `…_timestamp` = 1 | without `tcp_loose=0` the revocation `flush_session` kill is a no-op; acct/timestamp back the D43/NFT-5 counters | D68 |
| `libvirt.min_version_if_isolated_ports` = `6.1.0` (only if `isolated_ports_chosen`) | libvirt floor **iff** the shared-bridge `<port isolated='yes'/>` primitive is chosen; the structural per-session bridge / routed tap is preferred | D66 |
| `l2_isolation.structural` + `l2_isolation.br_netfilter_forbidden` | no two agent-session devices share an L2 segment; `br_netfilter` is **forbidden, not merely unused** | D66 |
| `per_session_tap.disable_ipv6` = 1, `accept_ra` = 0, `ra_dhcpv6_on_segment` = false, `ruleset_family` = `inet` | per-session taps disable v6 / RA; no RA/DHCPv6 on any per-session segment; rulesets authored `inet` so v6 drops by default | D75 |
| `nft_mark_lint.forbid_bits_14_23` + `forbid_unmasked_writes` + `constants_source` = `ds-contracts` | the mark-constant CI lint of the NFT-1 ruleset — no bits 14–23, no unmasked writes, constants only from ds-contracts | D76 |

**JSON, not the doc 13 §4 YAML strawman.** The doc 13 §4 schema is authored as
YAML for readability; the shipped artifact is JSON so the **stdlib-only** doc 06
(c) suite parses it with `encoding/json` and no dependency. This table is the
single source of the field semantics.

### Consumers (who reads this artifact)

- **The NFT-1 bootstrap ruleset** (`../nft/nft-1-bootstrap.nft`) assumes this
  baseline: its `inet` family is exactly `per_session_tap.ruleset_family`.
- **The bring-up unit** (`../nft/ds-nft-bootstrap.service`) applies the baseline
  sysctls/taps (via `ds-host-baseline.service`, ordered `After=`) before loading
  the ruleset, so conntrack is configured before the ct-state rules load.
- **The doc 06 (c) suite** (`assurance/guardrail-conformance/nftgate/hostbaseline_test.go`)
  loads this artifact and fails RED on any drifted §11 obligation — "sysctl drift
  = failure, not log line" — plus an artifact↔ruleset family cross-check. A
  synthetic violated-baseline fixture proves the red path is non-vacuous.
- **The mark-constant lint** (`scripts/check-nft-mark-constants.sh`, wired into
  `make repo-lints`) is the `nft_mark_lint` obligation's cargo-free enforcement:
  the NFT-1 floor stays mark-free (the full D76 bit-discipline model is the Rust
  `ds-nft-mark-lint` over the whole `../nft/` dir).

**Versioning.** This is `v0`. Any change to a §11 obligation bumps the version and
adds `host-baseline.vN.json`; the (c) suite tracks the current version. The guest-
side golden image (`images/golden/`) is a **different artifact for a different
machine** and is not governed here.

## Sub-directories

- **`attach-spike/`** — the D66 per-session attachment-primitive spike
  (OQ1/D66, Stage 1's first task; doc 09 §2/§8).
  Runnable procedure + golden ruleset text + findings (`FINDINGS.md`, **proposed**).
  Picks the attachment-primitive posture this baseline consumes: routed tap or
  per-session bridge (structural no-L2-path proof), `BR_ISOLATED` only behind the
  continuous flag audit, `br_netfilter` forbidden.

Neighbors: `../nft/` (the ruleset that assumes this baseline), `images/golden/`
(guest-side golden image — a different artifact for a different machine),
`crates/ds-nft/` (consumes the dual-kernel-path requirement).
