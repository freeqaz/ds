# vm/attachfwd — guest-side attach carriage forwarder

The M0 realization of the **guest↔host attach carriage** (runtime.v1 `AttachWiring`
OQ-C: the contract pins a guest-local UDS for the attach event socket but leaves the
carriage across the VM boundary FREE). `ds-attachfwd` bridges that guest-local UDS to
a TCP carriage the host-agent dials over the tap.

```
  CLIENT ──(host-local attach endpoint)──▶ host-agent attach Server   ← token-auth + D61 seat + fan-out (host-side)
                                                  │ dials guestIP:port over the tap
                                                  ▼
  ds-attachfwd  ──LISTEN guestIP:port (TCP)──▶ accept the host-agent ─┐
       │                                                              │ 1:1 splice
       └──LISTEN /run/ds/attach.sock (UDS)──▶ accept ds-entrypoint ───┘
                                                  │
                                          ds-entrypoint bridges CC stdio ⇄ the UDS (N2)
                                                  ▼
                                                 CC
```

**It is a 1:1 byte splice, not a fan-out.** Exactly one pipe crosses the VM boundary —
CC's single stdio stream. The D61 one-writer/N-reader fan-out, the token-auth, and the
writer-seat arbitration all live HOST-SIDE at the host-agent attach Server: the guest
is the untrusted runtime, so enforcement must never live here. The forwarder holds the
one `ds-entrypoint` UDS connection and splices it to the one host-agent TCP
connection; the host-agent multiplexes clients on its own side.

RUNTIME-AGNOSTIC (D20/D38, the `vm/entrypoint/transport.go` posture): it never parses
the bytes — `io.Copy` in both directions and nothing else.

## Decisions

- Carriage = guest-IP TCP over the tap (maintainer ruling, 2026-06-16). vsock (`AF_VSOCK`) is the
  cleaner long-term home — it moves the carriage off the egress-controlled tap — and
  is recorded as the follow-on.
- The host-agent (not the guest) is where the client terminates (doc 15 §5.4); the
  guest forwarder only carries the one CC stream.

## Status

Built + offline-tested (the `Splice` byte path + the `Listen`/`Serve` end-to-end over
real loopback UDS+TCP). REMAINING for a live "client drives CC in a VM" e2e: the M0
image bake + `ds-attachfwd.service` (ordered `Before=ds-entrypoint.service`), the
host-agent attach Server + its per-session bridge that dials this forwarder, the
minter endpoint repoint to the host-agent address, and the tap NFT allow-rule for the
host↔guest attach port. Tracked under the serving-leg task `01KV71VST0`.
