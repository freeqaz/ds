# ds-nethelper — stateless per-op privileged helper

**Charter.** `ds-nethelper` is the ROOT-HELPER privilege model for the Arch-1
bare-metal dogfood host (maintainer ruling 2026-07-09, chosen over setcap-on-host-agent /
run-as-root): a small, stateless, per-operation binary carrying
`setcap cap_net_admin+eip` (see **Capability Propagation** below — `+ep` alone is
WRONG), fronting EXACTLY the CAP_NET_ADMIN subset of the ds-nft write edge —
per-session tap create/delete and per-session NFT admit-surface
instantiate/flush/teardown. The host-agent process runs fully unprivileged and forks
the helper once per action; the capability lives on the HELPER binary, never on the
agent. It is a **dogfood-bringup piece, NOT the D66 netns production endpoint** —
retire when the netns datapath lands.

Charter **RATIFIED 2026-07-30 as D148** (round-4 packet §12 P-NH1 → doc 04 §6
D148; the doc 14 §6
linker set now reads "only ds-dnsgate / `ds-nethelper` link the write path; the
host agent invokes `ds-nethelper` and runs fully unprivileged"). The **live wiring
is UNGATED**: `backend_live.go` (the `nftbridge` cgo-edge relocation out of the
host agent), the boundary-readiness re-key onto the helper `Probe`, and the
`setcap cap_net_admin+eip` install may now land.

- **Owner:** Orchestrator workstream (the invoker; doc 14 §4 RACI). Privileged-op
  *semantics* stay Boundary-owned (ds-nft single-writer, doc 14 §6).
- **License side:** OSS (`orchestrator/` tree, already in `oss-manifest.yaml`; D80 —
  no paid import, only `proto/gen/go` legal cross-tree anyway; the helper imports no
  proto at all).
- **Mark:** OSS · dogfood-bringup privileged host helper · live backend LANDED
  (`-tags nftgatelive`; default build stays the fail-closed stub) · NOT the D66
  netns endpoint — sunsets when the netns datapath lands.
- **Final in-repo home:** `orchestrator/cmd/ds-nethelper/` +
  `orchestrator/internal/nethelper/{nethelperproto,nethelperclient}` (scripts under
  `orchestrator/cmd/ds-nethelper/scripts/`).
- **What must NOT live here (closed vocabulary):** any generic ruleset-apply verb;
  policy / allow-set content (that flows via ds-dnsgate, the OTHER ds-nft linker);
  any long-lived privileged process; any socket/listener; any state; any capability
  beyond CAP_NET_ADMIN. The verb set is frozen at the five ds-nft write ops + the
  read-only probe — nothing else.
- **D-numbers touched:** D2 (routed tap addressing), D44/D66 (binding join keys /
  never-recycled index; D66 = the helper is NOT the netns endpoint), D76 (14-bit mark
  residue → index ceiling), D80 (license side), doc 14 §4/§6 — **§6's linker set was
  REOPENED by the cgo move and re-frozen by D148** (ratified 2026-07-30: "only
  ds-dnsgate / `ds-nethelper` link the write path; the host agent invokes
  `ds-nethelper` and runs fully unprivileged"). Guardrail-map glob (D47) added on
  graft.

## Capability Propagation — why `+ep` is wrong, `+eip` + PR_CAP_AMBIENT_RAISE is right

`setcap cap_net_admin+ep` on the helper is the OBVIOUS choice and it is WRONG for
this helper, because the privileged backend (ds-nft) does its work by **exec'ing
`ip` and `nft`** (mechanism only — no libnetlink linkage). File capabilities do NOT
survive an `execve` into a child that has no file capabilities of its own: the
kernel computes a child's capabilities from the parent's *inheritable* and *ambient*
sets crossed with the child file's own sets. `ip`/`nft` on disk carry no file caps,
so:

- With `+ep` only, the helper process itself has CAP_NET_ADMIN **effective** — it
  passes its OWN probe (`CapEff` has bit 12) — yet every `ip`/`nft` child it spawns
  starts with an **empty** capability set and fails `EPERM`. This is the exact
  half-configured-host trap: the self-check is green, the real work is silently
  stranded.

The pinned mechanism is therefore:

1. **`setcap cap_net_admin+eip`** on the installed helper (effective +
   **inheritable** — the `i` is what `+ep` omits and what lets the capability be
   handed to children).
2. **`PR_CAP_AMBIENT_RAISE(CAP_NET_ADMIN)`** in-process, immediately around the
   backend call, scoped as narrowly as possible. Ambient is the set the kernel
   actually copies into an exec'd child's permitted/effective sets (bounded by the
   file's inheritable bits — hence step 1). Raising it only around the backend keeps
   the helper's default posture minimal and makes the privileged window auditable.
3. **The probe verb verifies inheritable/ambient**, not just effective. `+ep`-only
   passes an effective-only probe; the probe MUST additionally report whether
   CAP_NET_ADMIN is **inheritable** (`CapInh`) so a half-configured host — helper
   effective-green but children stranded — **fails loud at bring-up** instead of at
   the first live tap create. `Probe` reads `/proc/self/status` `CapEff`/`CapInh`
   (fail-closed to false where `/proc` is absent, so the probe never claims a
   capability it cannot prove).

## Env Scrub — the backend's children are not in secure-execution mode

The helper is exec'd by the (unprivileged) host-agent and inherits the agent's
environment verbatim. The backend then `exec`s `ip`/`nft`, which read the
environment. Because the helper does not change uid (setcap is not setuid), those
children are **NOT** in glibc secure-execution mode — nothing scrubs the untrusted
variables an unprivileged caller could have planted. Before the backend runs the
helper therefore does a **full env scrub**:

- **`os.Clearenv()`**, then
- set a **pinned `PATH`** (`/usr/sbin:/usr/bin:/sbin:/bin`) — nothing is resolved from
  the caller's `PATH`.

Any variable the backend legitimately needs is set explicitly after the scrub; the
caller can plant nothing that a privileged `ip`/`nft` child will read.

## Confused Deputy — 0750 root:agent-group narrows WHAT, not WHO

The install posture is `0750 root:<agent-group>` (`scripts/install-ds-nethelper.sh`).
That is the **authn** boundary on WHO may exec the helper (agent-group members only)
— but it does NOT distinguish WHICH agent-uid process invokes: **any** process
running as an agent-group member can fork the helper and drive a privileged tap/nft
op. The semantic gate narrows WHAT that op may touch (owner-uid == caller-uid,
`dstap-<idx>` grammar, index ceilings, never eth0/tailscale0 or an arbitrary
ruleset), so a confused/compromised caller still cannot escape the helper's
namespace — but on a shared host it could still act *as* the agent.

For the **single-user Arch-1 dogfood host this is acceptable** (one trusted operator,
one agent uid). Tighter mitigations are tracked as **separate multi-tenant hardening**
(maintainer-gate questions), not built here:

- a **dedicated helper group** (helper-group ⊊ agent-group) so only the host-agent,
  not every agent-uid tool, can exec it;
- an **agent-uid vs qemu-uid split** so the tap-owner uid the helper enforces is
  distinct from the process that drives QEMU;
- per-op rate/quibble limits or an invoker allowlist.

## Readiness Re-Key — LANDED (D148)

`newBoundaryReadiness` (host-agent, `seams.go`) used to gate on
`libvirt.LiveEnabled() && nftbridge.Built`. With the cgo edge relocated into this
helper the host-agent builds **untagged forever**, so `nftbridge.Built` is a
build-tag const that is **permanently `false`** in the agent — that key would have
silently never armed the live readiness gate. The re-key has landed:

- **`-nethelper-path` (also `DS_NETHELPER_PATH`)** is the agent's one new input: the
  ABSOLUTE path of the installed helper. `nethelperclient.New` rejects a relative
  path (no cwd/PATH substitution of a privileged binary).
- **`verifyHelperReady` (`cmd/host-agent/nethelperseams.go`) is a FATAL bring-up
  check.** Under `DS_HOSTAGENT_LIVE` with a helper path SET, the daemon forks the
  helper's read-only `probe` once and REFUSES to serve unless it reports
  `built && cap_net_admin_effective && ambient_raise_ok`. Each failure mode carries
  its own remediation — stub build, missing setcap, and (the important one) the
  **`+ep` half-configuration**, which is effective-green yet strands every `ip`/`nft`
  child. Fail closed, never degrade-to-fake.
- **`helperProbeReadiness` re-probes per admission.** Capabilities are an xattr on
  the INSTALLED file, so a rebuild/recopy disarms a helper *while the daemon is
  running*. The boundary-readiness gate therefore forks the probe on every
  admission and refuses at `StepNone` (nothing to unwind) rather than failing
  mid-create; only a Ready helper delegates to the real boundary probe.
- **`newAttachPrimitive` re-keys the same way** — `helperAttach` (fork-per-op) under
  `LiveEnabled() && client != nil`, the no-touch `deferredAttach` otherwise.
- An **EMPTY** `-nethelper-path` under `DS_HOSTAGENT_LIVE` is deliberately **not**
  fatal: the live MVP flows (SLIRP-direct egress) legitimately run the deferred
  no-touch attach. Fatality is scoped to "path set but helper not Ready".
- The agent can never re-link the edge by accident: `nftgatelive_refuse.go` makes a
  `-tags nftgatelive` host-agent build a **compile error** naming the rule (D148).

## Layout

| Path | What |
|---|---|
| `../../internal/nethelper/nethelperproto/` | The trust-boundary protocol both sides compile: closed verb vocabulary, params/Result shapes, exit codes, ALL input validation (tap-grammar + tap↔index cross-check, owner-uid==caller rule, MAC grammar, cap fields). |
| `.` (`cmd/ds-nethelper/`) | The helper: one op per invocation, **full env scrub (`os.Clearenv` + pinned PATH) before the backend**, strict stdin decode, validate → backend → one Result line (stdout) + one audit line (stderr) → exit. Default build = cgo-free stub backend (fail-closed `ENOTBUILT`); the `-tags nftgatelive` live backend is `backend_live.go`. |
| `backend_live.go` | The LIVE privileged backend (`//go:build nftgatelive`): a zero-adaptation pass-through to `orchestrator/internal/nftbridge` (the ds-nft cgo write edge), every verb wrapped in the ambient-capability bracket. The ONE cgo-linked binary in the stack. |
| `ambient_linux.go` | The ONE capability-MUTATING primitive: `withAmbientNetAdmin` = `runtime.LockOSThread` (ambient caps are per-THREAD and Go migrates goroutines) → `PR_CAP_AMBIENT_RAISE(CAP_NET_ADMIN)` → backend → best-effort LOWER. **Fail-closed** (a failed raise never runs the backend); **skips the raise at euid 0** (root children inherit via the kernel root rule, and a fresh userns cannot raise at all). Untagged, so it is unit-tested in the default build (`ambient_linux_test.go`); `ambient_other.go` is the non-Linux fail-closed stub. |
| `../../internal/nethelper/nethelperclient/` | The unprivileged agent-side client: fork-per-op, sentinel error mapping (`ErrValidation`/`ErrBackend`/`ErrNotBuilt`/`ErrProtocol`), bring-up `Probe`, and the best-effort idempotent `TeardownAll` rollback trio. The body of the host-agent's live `helperAttach` seam (`cmd/host-agent/nethelperseams.go`). |
| `scripts/netns-validate.sh` | Host-safe validation: protocol conformance of the real binary, the `unshare -rn` rehearsal vehicle, and the **`+ep`-trap detector** — a fresh userns has a full permitted but EMPTY inheritable set, i.e. exactly the `+ep` capability signature, so the three-field probe's ability to catch the trap is proven with no setcap and no privilege. |
| `scripts/install-ds-nethelper.sh` | Operator-apply installer (0750 root:agent-group + `setcap cap_net_admin+eip` + a real `verify`). The armed install refuses without `DS_NETHELPER_APPLY=1`; the **`verify <path>`** subcommand is read-only, needs no arming, and is what both the armed install's last step and `scripts/host-bringup/stack-up-host.sh`'s preflight key on (`installsh_test.go`). |
| `scripts/host-bringup/stack-up.sh` | The dogfood-host bring-up narrative as an executable dry-run (DEFAULT). Live mode is still refused — not as a ratification hold, but because applying belongs to `install-ds-nethelper.sh` and `scripts/host-bringup/stack-up-host.sh`; two copies of the install posture is the drift this prevents. `stackup_test.go` is its host-safe smoke driver. |

An archived **daemon** design variant (long-lived UDS-fronted helper; `ds-nethelperd`)
was kept beside the skeleton workdir as the maintainer-gate comparison artifact — **not
in-tree** — so the gate can compare one primary (stateless-argv, this component)
against one alternative (uds-daemon). It is deliberately absent from this repo.

## Verify

```sh
# from the orchestrator module:
go vet ./cmd/ds-nethelper/... ./internal/nethelper/...
go test ./cmd/ds-nethelper/... ./internal/nethelper/...
gofmt -l cmd/ds-nethelper internal/nethelper   # no output = clean

# host-safe end-to-end (builds the stub binary, runs unshare -rn rehearsal):
./cmd/ds-nethelper/scripts/netns-validate.sh
# bring-up narrative as a dry run (executes nothing):
./cmd/ds-nethelper/scripts/host-bringup/stack-up.sh --dry-run
```
