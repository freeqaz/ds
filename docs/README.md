# Documentation

- [architecture.md](architecture.md) — the three isolation layers, the two Rust boundary
  services, the control plane, the identity and credential-swap model, the threat model, and
  what is built vs. designed.
- [development.md](development.md) — repo layout, build and test commands per tree, the
  `proto/` contract rules, the four testing tiers, and why `boundary/` is red on purpose.

Depth lives next to the code — each tree's README states its charter, owner, and governing
decision numbers:

- Data plane: [`dataplane/`](../dataplane/README.md) ·
  [`ds-dnsgate`](../dataplane/services/ds-dnsgate/README.md) ·
  [`ds-tlsproxy`](../dataplane/services/ds-tlsproxy/README.md) ·
  [`ds-flowlog`](../dataplane/services/ds-flowlog/README.md)
- Control plane & runtime: [`orchestrator/`](../orchestrator/README.md) ·
  [`vm/`](../vm/README.md) · [`identity/`](../identity/README.md)
- Client: [`client/`](../client/README.md) · [`serpent-tui/`](../serpent-tui/README.md)
- Contracts & assurance: [`proto/`](../proto/README.md) ·
  [`proto/FREEZE.md`](../proto/FREEZE.md) · [`assurance/`](../assurance/README.md) ·
  [`boundary/`](../boundary/README.md)
