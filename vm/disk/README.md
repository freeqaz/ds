# vm/disk/ — qcow2 overlay & delta-inspection tooling

**Owner:** VM & runtime · **OSS** (D15/D25) · **Decision:** D29 (doc 04 §6)

Tooling around the D29 disk stack: **raw golden image + per-session qcow2
overlay** (libvirt external snapshots). The overlay is one artifact serving
three jobs at once — the session's delta store, the durability-stream unit
(dirty bitmaps drive the incremental stream), and the inspectable record
behind the doc 02 §5
promise: *show the user the delta of everything the agent did*.

What lands here:

- **Delta inspection** — host-side via libguestfs / `virt-diff` / `qemu-nbd`
  (invoked as tools, not Go deps; see `../go.mod`).
- **Overlay lifecycle helpers** consumed by the host agent around
  `Snapshot` / `ExportDiskDelta` (doc 15 §5.1); `overlay_path` arrives in
  `CloneFromImageResponse`.

Boundaries: ZFS/dm-thin remain **benchmark-gated alternatives behind the same
contract** (D29) — no second backend lands here without the benchmark. The
hypervisor calls themselves (external-snapshot creation at clone time) belong
to the host agent's libvirt driver (doc 15 §5.1), not here; this directory is
tooling over the artifacts those calls produce. The durability-stream
*consumer* (ingest/storage/restore) is scoped to the orchestrator at M3
(doc 15 OQ5).
