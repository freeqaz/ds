# host-agent LIVE smoke — `DS_HOSTAGENT_LIVE` create→boot→destroy over the M0 golden

This runbook is the COORDINATOR's on-host procedure for the unit **u5-live-smoke**:
drive the real libvirt host-agent create choreography (doc 15 §4.1) and destroy
ordering (§4.2) against the **M0 golden base** on the operator host, and prove the
**D29 read-only-base invariant** end to end.

It exercises the PRODUCTION `DriverService` gRPC surface (the same canonical
surface `cmd/host-agent` serves and `service.go` implements — there is **no second
gRPC surface**) over the **u3 production live bindings** (`live.go`: the
`overlay-create.sh` clone + `virsh` define/boot, reached through the gate-aware
`NewOverlayStore` / `NewBooter` / `NewDomainDestroyer`). The only deferred seams
kept as fakes are the ones whose real bodies have not landed (CA injection,
tap/NFT attach, routability gate, durability/flow accounting); the
`DomainDestroyer` is the **production** live body (`destroyer_libvirt.go` —
`virsh destroy ds-<uuid>`, the same §4.2 step 1 the daemon wires), so the smoke
tears the booted domain down through production code.

The smoke is a Go test, `TestLiveSmokeCloneBootDestroy`
(`orchestrator/internal/hypervisor/libvirt/live_smoke_test.go`). It **SKIPS
cleanly when `DS_HOSTAGENT_LIVE` is unset** — i.e. in the sandbox, in CI, and in
every `go test ./...` run. It touches libvirt/KVM/qemu **only** on the operator
host, gated.

> SAFETY: run this **only** on the operator M0 host (`user@<operator-host>`), never
> in the sandbox. It boots a real transient KVM domain and writes a real qcow2
> overlay. It never writes the golden base (that is the invariant it asserts).

> **This file has TWO parts.** §A below is the **Milestone-1 LIVE CLOSE** — the
> full operator arc *type on the box → `serpent up` → Claude Code running INSIDE
> a per-session KVM VM, writer-seat driven over `attach.v1`*. The original
> `TestLiveSmokeCloneBootDestroy` create→boot→destroy smoke (§B onward, from
> "Host facts") is the **driver-only** leg the live close subsumes — run it first
> to prove the substrate, then drive the full close. Both run only on the operator
> host, behind their env gates.

---

# §A — the Milestone-1 LIVE CLOSE (`serpent up` → VM-hosted Claude Code over attach.v1)

This is the SINGLE operator runbook for the M1 live close: lighting up the whole
path so an operator types `serpent up …` on the box and drives a **real** Claude
Code running inside a per-session KVM VM from the writer seat over `attach.v1`.
It folds three landed arcs into one pass — the host-agent attach serving leg
(gap-3), the orchestrator's per-host driver dial, and the two new guest systemd
units (gap-1 config-drive mount + gap-3 attach carriage) — and cross-links the
client side ([`../../../client/hostbridge/LIVE-VALIDATION.md`](../../../client/hostbridge/LIVE-VALIDATION.md))
rather than duplicating it.

Every leg is **env-gated and operator-driven**: nothing here runs in the sandbox
or CI. The data-plane gates are `DS_HOSTAGENT_LIVE=1` (host-agent: the real
overlay clone + virsh boot + config-drive iso + the per-session `ds-hostbridge`
serving-child exec + the `GuestIP:4242` relay) and `DS_ORCH_LIVE=1` (orchestrator:
the live per-host driver dial). With both unset every binary serves the offline
no-touch path (D50) — exactly what `go test ./...` and the wave gate exercise.

## A.0 — the end-to-end data path (what you are lighting up)

```
operator types: serpent up --orchestrator <addr> --repo <id> --env-config-ref <ref>
   │  (client/cmd/serpent EXECs the serpent-tui sibling; D80 keeps grpc out of the
   │   stdlib client — serpent-tui is the ONLY place grpc + orchestratorv1 live)
   ▼
serpent-tui up  ──CreateSession──▶  orchestrator (DS_ORCH_LIVE=1)
   │                                   │  resolves host_id→driver endpoint from
   │                                   │  DS_ORCH_HOST_DRIVERS, dials the host
   │                                   │  agent's HypervisorDriverService, runs
   │                                   │  CloneFromImage (doc 15 §4.1 create)
   │                                   ▼
   │                                host-agent (DS_HOSTAGENT_LIVE=1)
   │                                   • overlay-create.sh clone of the RO golden
   │                                   • gap-1: builds config.pb → per-session
   │                                     READ-ONLY iso9660 config-drive
   │                                     (LABEL=DS_ENTRYPOINT) and attaches it as
   │                                     the 2nd <disk>
   │                                   • virsh boot of the session domain
   │                                   • post-boot hook: AttachBridge.Serve →
   │                                     EXECs ds-hostbridge --serve-uds … as a
   │                                     per-session child
   │
   └──Attach(WRITER)──▶ orchestrator ──▶ AttachHandle{ DIRECT endpoint =
                                          host-local UDS under /run/ds/attach,
                                          short-lived session token }
   ▼
serpent-tui dials the DIRECT-candidate UDS (hostbridge.SocketTransport)
   ▼  host-local framed UDS  (/run/ds/attach/<uuid>.sock)
ds-hostbridge serving child  (validates the token against the SAME
   │                           <OverlayDir>/.ds-attach-tokens/<uuid>.json store
   │                           the libvirt attach minter wrote)
   ▼  TCP  GuestIP:4242        (M0_ATTACH_PORT == libvirt.DefaultAttachPort; the
   │                           host↔guest :4242 tap allow is nft4's — DECLARED)
ds-attachfwd.service          (in-guest: LISTENs :4242 + the guest UDS; 1:1 splice)
   ▼  guest UDS  /run/ds/attach.sock   (M0_ATTACHFWD_UDS_PATH == EntrypointConfig
   │                                    .AttachWiring.event_socket_path)
ds-entrypoint                 (dials /run/ds/attach.sock; reads config.pb off the
   │                           mounted config-drive at /run/ds/entrypoint)
   ▼
Claude Code (the D49-pinned runtime, M0_CC_VERSION) — driven from the writer seat
```

The exact constants this path is built on (extracted from the landed code, **not
invented** — `vm/m0-image/m0-image.env` is the single source of truth and
`build-m0-image.sh` / `verify-image-pins.sh` enforce it):

| constant | value | source | role |
| --- | --- | --- | --- |
| `M0_ATTACH_PORT` | `4242` | m0-image.env; `== libvirt.DefaultAttachPort` | the host→guest TCP carriage port (the bridge dials `GuestIP:4242`) |
| `M0_ATTACHFWD_UDS_PATH` | `/run/ds/attach.sock` | m0-image.env; `== EntrypointConfig.AttachWiring.event_socket_path` | the guest UDS ds-attachfwd serves and ds-entrypoint dials |
| `M0_ENTRYPOINT_CONFIG_DIR` | `/run/ds/entrypoint` | m0-image.env | the config-drive mount point; `DS_ENTRYPOINT_CONFIG_DIR` |
| `M0_CONFIG_DRIVE_LABEL` / `_FS` | `DS_ENTRYPOINT` / `iso9660` | m0-image.env; `== configdrive.go` | the config-drive `LABEL=` the mount unit finds + the read-only fs |
| `M0_ENTRYPOINT_PATH` | `/usr/local/bin/ds-entrypoint` | m0-image.env (D38) | the guest entrypoint `ds-entrypoint.service` launches |
| `M0_CC_VERSION` | `2.1.173` | m0-image.env (D49) | the pinned in-guest Claude Code runtime |
| AttachSocketDir | `/run/ds/attach` | `hostagent.DefaultAttachSocketDir` | the host-local served-UDS dir, single-sourced with the orchestrator endpoint resolver |
| token store | `<OverlayDir>/.ds-attach-tokens/<uuid>.json` | `attachminter.go` / `attachbridge.go` | mint host-side, validate in the serving child — one shared store |

> The two host-side ↔ guest-side constants are equal **by construction**: the host
> agent's bridge dials `GuestIP:M0_ATTACH_PORT` where `AttachPort` falls back to
> `libvirt.DefaultAttachPort = 4242`, and `verify-image-pins.sh` plus
> `build-m0-image.sh`'s `--tcp-addr 0.0.0.0:${M0_ATTACH_PORT}` assertion keep the
> guest forwarder on the same port. The served-UDS dir is single-sourced so a
> handle the orchestrator issues resolves to exactly the socket the bridge serves.

## A.1 — bake the M0 golden image

The per-session VM is cloned from the M0 golden base (raw, D29). Bake it with the
hand-build procedure; it now stages the two new guest units alongside the
entrypoint unit (the config-drive mount + the attach forwarder).

```sh
# print + validate the procedure and the pins (no privileges; CI/sandbox-safe):
vm/m0-image/build-m0-image.sh --plan
# the real bake (operator host, needs root + debootstrap):
DS_IMAGES_DIR=~/tmp/ds-images vm/m0-image/build-m0-image.sh --build
```

`--plan` validates the pins AND asserts the gap-1 mount unit
(`run-ds-entrypoint.mount`: `LABEL=DS_ENTRYPOINT`, mounted read-only at
`/run/ds/entrypoint`, ordered `Before=ds-entrypoint.service`) and the gap-3
forwarder unit (`ds-attachfwd.service`: `--uds-path /run/ds/attach.sock
--tcp-addr 0.0.0.0:4242`, ordered `Before=ds-entrypoint.service`). The
entrypoint + forwarder binaries are SEPARATE tasks (proto `runtime/v1` unfrozen);
absent, both units are staged and fail-closed at boot
(`ConditionFileIsExecutable`) — the expected M0-skeleton state.

Local boot-test the baked image short of ESXi with the sudo-free user qemu:

```sh
vm/m0-image/boot-validate.sh             # print the local boot plan (no image)
DS_BOOT=1 vm/m0-image/boot-validate.sh   # really boot the qcow2 and assert in-guest
```

`boot-validate.sh`'s in-guest assertions now cover BOTH new units (gap-1 mount +
gap-3 forwarder) as skeleton-state-aware live-leg checks — see
[`../../../vm/m0-image/boot-validate.sh`](../../../vm/m0-image/boot-validate.sh)
(`[gap-1]` / `[gap-3]` blocks). Boot-on-ESXi (virtual-metal, D5/D31) remains the
human follow-up.

## A.2 — the nft4 host↔guest `:4242` tap allow (gated on the AttachPrimitive substrate)

The host→guest TCP carriage reaches the guest forwarder at `GuestIP:4242`. That
reachability is the **Boundary-owned per-session tap NFT allow** — nft4's
`AttachPrimitive` — applied in `boundary/`. **This runbook declares it; nothing
here writes an NFT rule.** The guest `ds-attachfwd.service` only LISTENs; the
host-agent bridge only dials; the per-session allow rule (scoping which host
process may dial `GuestIP:4242` over the tap) is nft4's to apply. Until nft4's
real `AttachPrimitive` body lands the host-agent runs the deferred offline stub
(`seams.go`), so the serving-child exec works host-local but the `GuestIP:4242`
relay is the leg nft4 closes. Confirm the allow exists before driving the writer
seat (it is a precondition for the relay leg, not something this runbook installs).

> **STATUS — this whole `:4242` writer-seat leg is gated on the AttachPrimitive
> substrate.** The booted VM gets its tap + per-session NFT objects (the
> default-deny base, the dnsgate/tlsproxy redirects, and this `:4242` allow) only
> when nft4's real `AttachPrimitive` body replaces the offline `deferredAttach`
> stub. Until then this live close runs **reader-only** (see §A.5). The durable
> build guide for that substrate — the seam, what `InstantiateSessionNFT` must
> program, the decomposition, gates, D-numbers, and acceptance — is
> [`../../internal/hypervisor/libvirt/ATTACH-PRIMITIVE.md`](../../internal/hypervisor/libvirt/ATTACH-PRIMITIVE.md)
> (keystone task `01KV8XSNEX`; the `:4242` allow itself is child task
> `01KV7SBQ6C`). It is the LAST Milestone-1 gate — both Claude Code's gated
> egress AND this writer-seat drive depend on it.

## A.3 — start the host-agent daemon (live)

The daemon (`cmd/host-agent`) is the composition root: it serves the
`HypervisorDriverService` and, on the live path, owns the real overlay clone +
virsh boot + config-drive build + the per-session `ds-hostbridge` serving child.

```sh
# Build the serving child the AttachBridge execs (resolved like serpent→ds-capture:
# explicit --hostbridge-bin, then $DS_HOSTBRIDGE_BIN, then PATH, then a sibling).
( cd client && go build -o ../.bin/ds-hostbridge ./cmd/ds-hostbridge )

DS_HOSTAGENT_LIVE=1 \
DS_HOSTBRIDGE_BIN="$PWD/.bin/ds-hostbridge" \
go run ./orchestrator/cmd/host-agent \
  -listen 127.0.0.1:9000 \
  -host-id m0-host \
  -base-image       /var/lib/libvirt/images/ds-build/m0-base-bookworm-cc2.1.173.qcow2 \
  -overlay-dir      /var/lib/ds/overlays \
  -overlay-create-script "$PWD/vm/cow/overlay-create.sh" \
  -attach-socket-dir /run/ds/attach \
  -launch-command  claude \
  -event-socket-path /run/ds/attach.sock \
  -http-proxy  http://<tlsproxy-host>:<port> \
  -https-proxy http://<tlsproxy-host>:<port> \
  -session-token-endpoint    vsock://host:8200/token \
  -session-token-listen-port 8200 \
  -identity-mint-addr        <identity-mint-host>:<port>
```

Key bring-up facts (doc 13 §4; flag defaults in `cmd/host-agent/main.go`):

- `-attach-socket-dir` is the host-local dir the per-session attach UDS is served
  under. Empty takes `hostagent.DefaultAttachSocketDir` (`/run/ds/attach`), which
  is **single-sourced** with the orchestrator endpoint resolver — so a handle the
  orchestrator issued resolves to exactly the socket this bridge serves. Pass the
  same value to both sides if overriding.
- `-launch-command` is the runtime the in-guest **`ds-entrypoint` supervises**
  (`EntrypointConfig.Launch.Command`, D7/D20) — i.e. the pinned Claude Code
  (`claude`), NOT `ds-entrypoint` itself. `ds-entrypoint` is the supervisor the
  systemd unit launches at `M0_ENTRYPOINT_PATH` (`/usr/local/bin/ds-entrypoint`);
  it reads `config.pb` and execs `Launch.Command`. The builder rejects an empty
  command.
- `-event-socket-path` is the guest-local attach UDS the entrypoint emits onto —
  set it to `M0_ATTACHFWD_UDS_PATH` (`/run/ds/attach.sock`) so the structured
  `EntrypointConfig.AttachWiring.event_socket_path` matches what `ds-attachfwd`
  serves in-guest.
- `-overlay-dir` is also where the per-session attach **token store** lives
  (`<overlay-dir>/.ds-attach-tokens/<uuid>.json`): the libvirt attach minter
  writes it, the `ds-hostbridge` serving child validates against it — one shared
  store. The bridge refuses to serve a session whose token is absent (fail-closed,
  D39).
- `-session-token-endpoint` is the **vsock reference** the GUEST is told to dial to
  reach the host-local D22 session-token shim (reference only, never the token value,
  D39 — threaded into `EntrypointFacts.SessionTokenEndpoint`). The U5 authz hardening
  serves the token over **AF_VSOCK** and authorizes by the connecting guest's
  **unforgeable peer CID** (the host derives the session from the CID and serves ONLY
  that session's token — no session id on the wire, no secret in the VM, network-
  independent under SLIRP or the routed tap). Set it to `vsock://host:<port>/token`
  (the `host` component is the conventional placeholder for `VMADDR_CID_HOST(2)`; only
  the PORT is read).
- `-session-token-listen-port` is the well-known AF_VSOCK **port** the shim listens on
  (host side, `VMADDR_CID_HOST`; default `8200`, distinct from the attach carriage port
  `4242`). Match it to the `<port>` in the `-session-token-endpoint` reference. The
  host requires the `vhost_vsock` kernel module loaded.
- `-identity-mint-addr` is the gRPC dial endpoint of the identity mint the LIVE
  token source dials. NOTE: minting a real D22 token is BLOCKED — `MintSessionToken`
  is RESERVED-only in `ca_mint.proto`, so the live source fails closed (the shim
  closes the vsock conn with NO bytes) behind a stubbed seam until that additive RPC
  is promoted; offline serves a clearly-marked non-secret placeholder (D50).
- The bring-up log line names the substrate: `substrate=LIVE (overlay-create.sh
  + virsh, DS_HOSTAGENT_LIVE=1)`. Off the gate it reads `offline (no-touch)`.

> Off `DS_HOSTAGENT_LIVE` the daemon serves the offline no-touch bindings and
> `AttachBridge.Serve` launches NOTHING (it returns the rendered UDS path with
> `Launched=false`); that is the sandbox/CI/test path — never run that as the
> live close.

## A.4 — start the orchestrator (live-dial posture, pointed at the host agent)

The orchestrator dials the host agent's `HypervisorDriverService` per host_id.
On the live path it resolves the endpoint from `DS_ORCH_HOST_DRIVERS`
(`host_id=addr` pairs) and dials/caches the connection.

```sh
DS_ORCH_LIVE=1 \
DS_ORCH_LISTEN=:9090 \
DS_ORCH_HOST_DRIVERS="m0-host=127.0.0.1:9000" \
go run ./orchestrator/cmd/orchestrator
#   add the internal-fabric mTLS triplet if the link is fronted with it
#   (the SAME triplet both live dial legs read; half-set fails loudly):
#   DS_ORCH_TLS_CERT=… DS_ORCH_TLS_KEY=… DS_ORCH_TLS_CA=…
#   add DS_ORCH_IDENTITY_ENDPOINT / DS_ORCH_PG_DSN for the identity + store legs.
```

- `DS_ORCH_HOST_DRIVERS` is the static per-host driver endpoint map (doc 15 §5.1:
  one `HypervisorDriver` per virtual-metal host). The `host_id` must match the
  host agent's `-host-id` (`m0-host` above) so a placement resolves the right
  driver. An empty/missing entry makes every placement miss with an attributable
  no-driver-for-host — not a panic.
- Off `DS_ORCH_LIVE` the orchestrator prints its wiring and exits without dialing
  (D50). The live close needs `DS_ORCH_LIVE=1`.
- The orchestrator↔host-agent edge defaults to the internal, network-isolated
  insecure transport (doc 15 §2); front it with the `DS_ORCH_TLS_*` triplet for
  mutual TLS.

## A.5 — `serpent up` and drive the writer seat

With the daemons up, run the one-command provision-then-attach from the box:

```sh
( cd client && go build -o ../.bin/serpent ./cmd/serpent )
# build the serpent-tui sibling serpent EXECs (out of go.work — GOWORK=off):
( cd serpent-tui && GOWORK=off go build -o ../.bin/serpent-tui ./cmd/serpent-tui )
export PATH="$PWD/.bin:$PATH"   # so serpent resolves serpent-tui as a sibling

serpent up \
  --orchestrator 127.0.0.1:9090 \
  --repo <repo-id> \
  --env-config-ref <checked-in-env-spec-ref>
#   optional: --launching-user U  --role-ref R  (the D56/D99 create keys)
```

The flag set is exactly the landed one: `serpent up` forwards
`--orchestrator/--repo/--env-config-ref` (and the optional `--launching-user` /
`--role-ref`) verbatim to `serpent-tui up`, which `CreateSession`s (the D56
two-key create refuses without both `--repo` and `--env-config-ref`) then
`Attach`es as `ROLE_WRITER` and drops into the interactive loop. `--orchestrator`
may be omitted if `DS_ORCHESTRATOR` is set.

**Reader-only fallback (gap-3 not yet relayable):** if the `Attach` reply carries
no servable DIRECT endpoint (a host-local UDS the `SocketTransport` can dial),
serpent-tui attaches READER-ONLY (input refused, never fabricated — D61) and
prints `handle carries no servable direct endpoint`. A full writer-seat drive
needs the host-agent's `IssueAttachHandle` to mint a servable DIRECT endpoint
(the `attachminter.go` live minter under `DS_HOSTAGENT_LIVE`) AND the
`ds-hostbridge` serving child up for that session.

## A.6 — per-session DESTROY reap (the §4.2 teardown live check)

When the session ends, the libvirt `Destroyer` runs the frozen §4.2 order (domain
destroy → unconditional `flush_session`+NFT-6 → overlay dispose/durability) and
then **reaps the per-session attach serving leg**: the daemon wires
`Destroyer.WithPostDestroyHook(attachReapHook(bridge))` →
`AttachBridge.Destroy(sessionUUID)`, which SIGINTs + reaps the `ds-hostbridge`
serving child and unlinks the per-session UDS (`attachbridge.go §Destroy`). It is
best-effort/NON-FATAL — a reap fault never turns a clean §4.2 teardown into an
abort, and off `DS_HOSTAGENT_LIVE` the bridge owns no child so the reap is a clean
no-op. At daemon stop, `bridge.Shutdown()` reaps every remaining serving child.

**Then it purges the session's per-session HOST STATE.** The §4.2 ordering unwinds
the substrate the session ran *on*; these are the artifacts the create path wrote
*beside* it under `<OverlayDir>`, which no destroy step owned — so before this
wiring each one survived every teardown. `DriverService.Destroy` disposes them
AFTER a **converged** teardown (a faulted destroy keeps them for the reconciler's
re-drive) and after the reap hook above, so the token file is never pulled out from
under a still-serving child that holds it open via `--session-token-file`:

| artifact | path | posture |
|---|---|---|
| attach token (D39 bearer credential) | `<OverlayDir>/.ds-attach-tokens/<uuid>.json` | **fail-loud** — its TTL (15 min) is the store's only revocation mechanism, so an undeleted token stays *valid* |
| config drive + staging | `<OverlayDir>/<uuid>.config.iso`, `<uuid>.config.d/` | **fail-loud** — the staging dir holds `config.pb` 0400, the rendered `EntrypointConfig` with the injected env creds |
| interception-CA bundle (cert + proxy-bound key) | `<OverlayDir>/.ds-ca-bundles/<sanitize(caRef)>.pem`, `<sanitize(caRef)>.key.pem` | **fail-loud** — the `.key.pem` is live TLS-interception key material (D82: minted at create, dies at teardown) |
| resolved-mode marker | `<OverlayDir>/.ds-session-mode/<uuid>` | best-effort (logged) — host-internal bookkeeping, same class as the durable session record |
| durable session record | `<OverlayDir>/.ds-sessions/<uuid>.json` | best-effort (logged) — landed earlier, `5237de62` |

The CA bundle is keyed on the **`ca_bundle_ref`, not the session UUID**, and the frozen
`DestroyRequest` carries only the UUID — so the ref rides the durable `SessionRecord`
(`ca_bundle_ref`, written at create) and the daemon-root `recordDestroyResolver` lowers it
into `DestroyState.CABundleRef` for the purge. A **pre-upgrade** record (written before that
column existed) lowers to an empty ref, which the disposer treats as "nothing to purge" — so
those sessions' bundles still need `ds-serve-stack.sh down --purge`.

Each removal is idempotent (an absent artifact is a clean no-op), so a §4.2 re-drive
converges. This is the doc 06 (b) clean-teardown row — *"no orphaned VM, no leaked
NFTables rules, no dangling CoW overlay, no stranded proxy session, **no leftover
minted identity**"* — and the first two rows are minted identity literally.

**Live checks at destroy:**

- the per-session UDS under `/run/ds/attach/<uuid>.sock` is gone;
- no `ds-hostbridge --serve-uds …<uuid>…` child remains (`pgrep -af ds-hostbridge`);
- the per-session host state is gone — one sweep over the overlay dir:
  ```sh
  ls "$OVERLAY_DIR"/.ds-attach-tokens/"$UUID".json \
     "$OVERLAY_DIR"/.ds-session-mode/"$UUID" \
     "$OVERLAY_DIR"/.ds-sessions/"$UUID".json \
     "$OVERLAY_DIR"/"$UUID".config.iso 2>&1   # -> all "No such file or directory"
  test ! -d "$OVERLAY_DIR/$UUID.config.d"     # -> the 0400 config.pb staging dir is gone
  ```
- the §4.2 ruleset-byte-identical-to-bootstrap invariant still holds (the
  driver-only `TestLiveSmokeCloneBootDestroy` in §B asserts the base byte-stability
  + idempotent re-destroy half of this).

**CA-bundle disposal check (D82).** The bundle files are written by the *orchestrator-side*
producer (`controlplane/liveedges.go` `fileCABundleProducer.drop`), so a §A live run only
lays them down when the orchestrator actually mints a CA. To verify the host-agent's disposal
arc deterministically, seed them yourself in the producer's exact on-disk shape and then
destroy:

```sh
# 1. after a live CreateSession: the durable record carries the ref the purge needs.
grep -o '"ca_bundle_ref":"[^"]*"' "$OVERLAY_DIR"/.ds-sessions/"$UUID".json
#   -> "ca_bundle_ref":"ca:<uuid>"      (the DS_HOSTAGENT_SKIP_CA_INJECT=1 MVP default)
#   an ABSENT key means a pre-upgrade record -> nothing to purge; re-create first.

# 2. emulate the producer drop. trustpath.Sanitize maps "ca:<uuid>" -> "ca_<uuid>",
#    so the leaves are exactly these two names.
CA_DIR="$OVERLAY_DIR/.ds-ca-bundles"
mkdir -p "$CA_DIR" && chmod 700 "$CA_DIR"
printf 'not-a-real-cert\n' > "$CA_DIR/ca_$UUID.pem"
printf 'not-a-real-key\n'  > "$CA_DIR/ca_$UUID.key.pem"
chmod 600 "$CA_DIR"/ca_"$UUID".*

# 3. DestroySession (the same call as the checks above), then assert BOTH are gone.
ls "$CA_DIR/ca_$UUID.pem" "$CA_DIR/ca_$UUID.key.pem" 2>&1
#   -> both "No such file or directory"

# 4. a repeat destroy still converges (an absent bundle is a clean no-op).
```

Step 4 matters because the purge is **fail-loud**: it must fail on an *undeletable* bundle
(a real leak of interception key material) but never on an *already-gone* one, or the
reconciler's re-drive of a partially-faulted teardown would never converge.

> The driver-only smoke (§B) drives `DriverService.Destroy` over an in-process
> gRPC client with a binding-less request, so its overlay disposal is a documented
> no-op there; the live close exercises the FULL daemon path (post-boot serve →
> post-destroy reap → per-session host-state purge) the smoke does not.

## A.7 — the two new guest systemd units as in-guest live checks

Inside a booted session guest, the two gap units are the in-guest half of this
path. `boot-validate.sh` prints the exact assertions; the live-close operator
re-runs them in a real session guest (over the serial console / a vsock probe):

```sh
# gap-1 config-drive mount (delivers config.pb):
systemctl is-enabled run-ds-entrypoint.mount        # -> enabled
systemctl show -p Before run-ds-entrypoint.mount    # -> ds-entrypoint.service
findmnt -no FSTYPE,OPTIONS /run/ds/entrypoint        # -> iso9660 ... ro
test -f /run/ds/entrypoint/config.pb                 # -> the delivered config

# gap-3 attach carriage forwarder (the host→guest relay terminus):
systemctl is-enabled ds-attachfwd.service           # -> enabled
systemctl show -p Before ds-attachfwd.service       # -> ds-entrypoint.service
systemctl is-active ds-attachfwd.service            # -> active (binary staged)
ss -ltn 'sport = :4242'                              # -> LISTEN on :4242
test -S /run/ds/attach.sock                          # -> the guest UDS is served
```

In the M0 skeleton state (the forwarder/entrypoint binaries not yet staged) both
units are present + enabled + ordered but inactive on `ConditionFileIsExecutable`
— the expected fail-closed state, which `boot-validate.sh` reports as such rather
than a failure. The `DS_ENTRYPOINT` config-drive label and `iso9660` fs are the
contract `configdrive.go` stamps (replicated in the unit, never imported — D80).

---

# §B — the driver-only create→boot→destroy smoke (`TestLiveSmokeCloneBootDestroy`)

> The driver-only leg the live close (§A) subsumes — run it first to prove the
> overlay/boot/destroy substrate and the D29 read-only-base invariant before
> driving the full close.

## Host facts (operator-supplied, never hardcoded)

| env var | meaning |
| --- | --- |
| `DS_HOSTAGENT_LIVE` | the live gate — must be `1` or the test skips |
| `DS_HOSTAGENT_LIVE_BASE` | abs path to the **read-only raw golden base** (D29) |
| `DS_HOSTAGENT_LIVE_OVERLAY_DIR` | a **writable** dir for per-session overlays |
| `DS_HOSTAGENT_LIVE_OVERLAY_SCRIPT` | abs path to `vm/cow/overlay-create.sh` (the D29 clone primitive) |
| `DS_HOSTAGENT_LIVE_VIRSH` | optional `virsh` binary override (default: PATH `virsh`) |

On the M0 host the golden lives at:

```
/var/lib/libvirt/images/ds-build/m0-base-bookworm-cc2.1.173.qcow2
```

---

## Pre-flight on the host (`user@<operator-host>`)

```sh
# 1. Tools present.
command -v virsh qemu-img

# 2. The golden base is the read-only 0444 raw base (the D29 static invariant the
#    smoke also re-asserts up front). If it is not 0444, fix it BEFORE running —
#    the smoke fails loudly on a writable base rather than risk a write-through.
ls -l /var/lib/libvirt/images/ds-build/m0-base-bookworm-cc2.1.173.qcow2
#   -> expect mode -r--r--r-- (0444)

# 3. A writable overlay dir on the same filesystem (btrfs/CoW; reflink-friendly).
mkdir -p /var/lib/ds/overlays

# 4. Repo present so overlay-create.sh is on disk (the proven D29 clone primitive).
#    (clone or pull the repo onto the host; path below is illustrative)
ls -l ~/code/dream-serpent/vm/cow/overlay-create.sh
```

---

## Run the smoke

From the repo checkout on the host:

```sh
cd ~/code/dream-serpent/orchestrator

DS_HOSTAGENT_LIVE=1 \
DS_HOSTAGENT_LIVE_BASE=/var/lib/libvirt/images/ds-build/m0-base-bookworm-cc2.1.173.qcow2 \
DS_HOSTAGENT_LIVE_OVERLAY_DIR=/var/lib/ds/overlays \
DS_HOSTAGENT_LIVE_OVERLAY_SCRIPT="$PWD/../vm/cow/overlay-create.sh" \
go test ./internal/hypervisor/libvirt/ -run TestLiveSmokeCloneBootDestroy -v -count=1
```

`PASS` means the full create→boot→destroy flow ran over the live substrate AND the
golden base was never written through.

---

## What the smoke drives, and the D29 invariants it asserts

The test stands up the production `DriverService` over the live `OverlayStore` +
`Booter` and drives it over an in-process gRPC client (the canonical surface), then:

1. **`CloneFromImage`** — the §4.1 create choreography clones the golden into a
   per-session qcow2 overlay (`<overlay-dir>/<session>.qcow2`) via `overlay-create.sh`,
   injects the (faked) interception CA, and **boots** the session domain via
   `virsh create` over the overlay. The smoke asserts:
   - **the overlay exists and is non-empty**, and is a **separate file** from the
     base (the clone writes a per-session overlay, never the base — D29);
   - **the overlay's qcow2 backing chain names the golden base** — `qemu-img info`
     is the **load-bearing, required** check (the smoke `Fatal`s if qemu-img is
     absent rather than degrading to a substring scan; a tightened header scan is
     kept only as a qemu-img-absent fallback) — the overlay is a CoW layer **on**
     the base (the D29 backing invariant);
   - **the domain boots** — `virsh domuuid ds-<session>` reports a uuid.
2. **`Destroy`** — the §4.2 teardown ordering destroys the transient domain
   (test-local `virsh destroy`) and runs the unconditional flush. The smoke asserts:
   - **the transient domain is gone** (`virsh domuuid` no longer resolves it).

   > **Overlay disposal is NOT yet wired through the gRPC `Destroy` surface.**
   > `DriverService.Destroy` converges from the `session_uuid` alone and drives a
   > **binding-less** `DestroyRequest` (empty `OverlayPath`/`DomainUUID`), so the
   > `destroy.go` overlay-disposal step — guarded by `if req.OverlayPath != ""` — is
   > a no-op over gRPC. Threading the recorded clone binding
   > (`OverlayPath`/`DomainUUID`/`HasBinding`) into the request is the
   > **deferred destroy-wiring unit's** job. Until it lands, the smoke asserts the
   > per-session overlay **survives** the gRPC `Destroy` and disposes it via
   > `t.Cleanup`. Once the wiring lands, that assertion flips to **overlay-gone**.
3. **The golden base is byte-stable** — across the **whole** clone→boot→destroy
   flow (and a second idempotent re-destroy) the base stays **mode 0444** with an
   **unchanged size + mtime**. This is the load-bearing D29 assertion: every write
   landed in the overlay; the shared read-only base was **never written through**,
   and destroy never touches the base.

`Destroy` is also asserted **idempotent**: a second teardown of the now-gone
session is a clean success and still never touches the base.

---

## Cleanup / re-run

The test pre-cleans a leftover overlay/domain for its fixed session uuid and
registers a `t.Cleanup` that destroys the session + removes the overlay, so a
re-run is self-healing. If an aborted run leaves residue, clear it by hand:

```sh
virsh destroy ds-00000000-0000-4000-8000-00000000a5e5 2>/dev/null || true
rm -f /var/lib/ds/overlays/00000000-0000-4000-8000-00000000a5e5.qcow2
```

---

## Why this is gated (live-gating discipline)

Per the host-agent live-wiring arc, real-substrate ops land **behind**
`DS_HOSTAGENT_LIVE` and the default (unset) path stays the tested offline/fake
path. Offline, `TestLiveSmokeCloneBootDestroy` **skips** and the rest of the
suite + the hypervisor conformance suite stay green against fakes (D50). The
frozen `hypervisor/v1` contract is satisfied throughout and never changed; the
proto generated code is import-only (D80); no CA material is ever baked (the CA
is injected per-session at create), and no secret bytes are logged.

---

# §C — the vsock-attach carriage live check (`DS_HOSTAGENT_LIVE`, virtio-vsock)

This section is the operator runbook for the **AF_VSOCK host↔guest attach
carriage** — the leg the M1 vsock-hybrid swap (the spike note
`../../../docs/sessions/spikes/m1-live-session-transport.md`)
proves **offline-only against synthetic fixtures**, deferred here for an operator
to validate on the box. It folds the two near-identical per-unit smoke proposals
(the guest forwarder's smoke + the host serve-leg's smoke) into ONE end-to-end
check: boot a session VM, dial the real guest CID over virtio-vsock, splice a byte
each way, and take the writer seat.

> Run this **only** on the operator KVM host (`user@<operator-host>`), never in the
> sandbox or CI. Every command below is `DS_HOSTAGENT_LIVE`-gated; off the gate the
> serving leg launches nothing and dials no vsock (D50). **No live commands run
> when this file is authored — it is a runbook, not a test.**

## C.0 — the carriage at a glance (what this check exercises)

The attach control channel rides **virtio-vsock**, not the routed-tap TCP — vsock
needs no tap, no guest IP, and no per-session nft, which is why this check is *not*
gated on the `:4242` AttachPrimitive nft allow (§A.2). The byte path is:

```
serpent-tui  ──DIRECT→Unix──▶  /run/ds/attach/<uuid>.sock   (host-local served UDS)
ds-hostbridge serving child    (validates the token against
   │                            <OverlayDir>/.ds-attach-tokens/<uuid>.json)
   ▼  virtio-vsock  guestCID:4242   (host-agent dials the DERIVED Binding.VsockCID;
   │                                 the guest LISTENs on VMADDR_CID_ANY:4242)
ds-attachfwd  (in-guest)        (1:1 splice: AF_VSOCK ⇄ guest UDS)
   ▼  guest UDS  /run/ds/attach.sock
ds-entrypoint → Claude Code
```

| constant | value | source | role |
| --- | --- | --- | --- |
| vsock attach port | `4242` | `attachminter.go` `DefaultAttachPort` `== vm/attachfwd` `WireAttachPort` | the host→guest **virtio-vsock** carriage port (host dials `guestCID:4242`; guest LISTENs `VMADDR_CID_ANY:4242`) |
| guest CID | derived `Binding.VsockCID` | `alloc.go` (host-predictable); pinned on the domain by `01KV91MAWSZ` | the AF_VSOCK context id the serving child dials; **must** be predictable host-side |

> **PORT agreement.** The two trees cannot import each other, so the port is held
> in lockstep by construction: the host bridge's `DefaultAttachPort = 4242`
> (`attachminter.go`) equals the guest forwarder's `WireAttachPort = 4242`
> (`vm/attachfwd/forwarder.go`). The host↔guest leg moved from TCP `GuestIP:4242`
> to **vsock `guestCID:4242`** in the m1vsock wave — the port number is unchanged.

## C.1 — prerequisite: predictable guest CID (Boot CID threading `01KV91MAWSZ`)

This check **requires** the Boot CID threading (`01KV91MAWSZ`) landed first. Until
it does, `liveBooter.Boot` renders `<cid auto='yes'/>` and libvirt assigns a CID
the host-agent's serve leg cannot predict — but the serve leg dials the **derived**
`Binding.VsockCID` (`attachbridge.go` `Serve(ctx, sessionUUID, binding.VsockCID, …)`,
fail-closed on a zero/un-derived CID). The two disagree and the dial misses. With
`01KV91MAWSZ` landed the live domain pins `<cid auto='no' address=<derived cid>/>`
so the dialed CID and the booted CID are the same.

Verify the booted domain pins the derived CID before driving the carriage:

```sh
# on the host, against a booted session domain ds-<uuid>:
virsh dumpxml ds-<uuid> | grep -A1 "<vsock"
#   -> expect <cid auto='no' address='<derived cid>'/>  (NOT auto='yes')
```

The host also needs the vsock substrate up (see the spike note's operator
persistence note): `vhost_vsock` loaded and `/dev/vhost-vsock` group-readable.

```sh
lsmod | grep -q vhost_vsock || sudo modprobe vhost_vsock
ls -l /dev/vhost-vsock     # -> group-readable (kvm 0660), same drift as /dev/kvm
```

## C.2 — boot a session VM (the §A daemons, live)

Bring up the host-agent + orchestrator on the live gates exactly as §A.3 / §A.4,
then provision a session as §A.5 (`serpent up …`). That gets a session domain
booted with the config-drive mounted and the per-session `ds-hostbridge` serving
child execed. This section assumes that state; it focuses on the **vsock carriage**
assertions §A leaves to the AttachPrimitive-gated path.

```sh
# the two daemons, both gates on (full flag sets in §A.3 / §A.4):
DS_HOSTAGENT_LIVE=1 … go run ./orchestrator/cmd/host-agent …      # §A.3
DS_ORCH_LIVE=1       … go run ./orchestrator/cmd/orchestrator     # §A.4
# provision + attach (writer seat):
serpent up --orchestrator 127.0.0.1:9090 --repo <repo-id> --env-config-ref <ref>   # §A.5
```

## C.3 — host-agent execs `ds-hostbridge` against the real guest CID:4242

On the live path the post-boot hook runs `AttachBridge.Serve(ctx, sessionUUID,
binding.VsockCID, mode)`, which execs the serving child bound to the host-local UDS
and the `guestCID:4242` vsock carriage. Confirm the child is up and dialing the
**derived** CID over virtio-vsock:

```sh
# the serving child is up with the derived CID + the 4242 port (NOT a TCP GuestIP):
pgrep -af 'ds-hostbridge --serve-uds'
#   -> ds-hostbridge --serve-uds /run/ds/attach/<uuid>.sock \
#        --guest-vsock-cid <derived cid> --guest-vsock-port 4242 \
#        --session-token-file <overlay-dir>/.ds-attach-tokens/<uuid>.json \
#        --session-uuid <uuid>   [--mode terminal  for a TERMINAL session]

# the host-local served UDS exists (the DIRECT-candidate the orchestrator minted):
test -S /run/ds/attach/<uuid>.sock && echo "served UDS present"

# in the guest, the forwarder LISTENs on AF_VSOCK:4242 and serves the guest UDS:
#   (over the serial console / a vsock probe into the session guest)
ss -lx 'src = /run/ds/attach.sock'        # -> the guest UDS is served
#   AF_VSOCK listeners are not shown by ss; assert via the forwarder's own log line
#   ("attachfwd: listening vsock VMADDR_CID_ANY:4242") or the splice round-trip below.
```

The serving child **refuses fail-closed** if the per-session token file is absent
(`<OverlayDir>/.ds-attach-tokens/<uuid>.json`, the SAME store the libvirt attach
minter writes and the child validates against — D39), and the bridge refuses to
`Serve` on a zero/un-derived CID. Both are preconditions for the dial to succeed.

## C.4 — drive a byte each way through `ds-attachfwd`'s splice

With the serving child dialing `guestCID:4242` and the in-guest forwarder LISTENing
there, a byte written at the host-local UDS must traverse host UDS → vsock →
guest UDS and back (the forwarder's 1:1 splice). The clean proof is the writer-seat
round-trip in C.5 (a real `attach.v1` session over the carriage); a lower-level
sanity check is to confirm the splice is live end-to-end:

```sh
# host side: write to the served UDS and read the echo the guest splices back.
#   (the production driver IS serpent-tui in C.5; this is the raw-carriage sanity
#    check only — it needs the guest end to echo, e.g. ds-entrypoint's UDS up.)
printf 'PING\n' | socat - UNIX-CONNECT:/run/ds/attach/<uuid>.sock
#   -> the byte is carried host UDS → vsock guestCID:4242 → guest UDS and back;
#      a hang/refuse means the vsock dial missed (re-check the CID pin in C.1).
```

If the byte does not round-trip, the failure is almost always the CID mismatch
(C.1) or the guest forwarder not LISTENing — not the splice itself, which is the
offline-proven 1:1 path (`vm/attachfwd/forwarder.go`).

## C.5 — `serpent-tui` takes the WRITER seat via the DIRECT→Unix endpoint

The acceptance leg: `serpent up` attaches as `ROLE_WRITER` and, given an `Attach`
reply carrying a **servable DIRECT endpoint** (the host-local UDS the
`SocketTransport` can dial), drops into the interactive loop with the **writer
seat** (one-writer/N-reader, D79; the `DIRECT`→`hostbridge.TransportUnix` mapping).
Drive a turn and confirm input reaches the in-guest runtime:

```sh
# from §A.5, serpent up has attached. Confirm the writer seat (NOT reader-only):
#  - serpent-tui did NOT print "handle carries no servable direct endpoint"
#    (that is the reader-only fallback, §A.5 — input refused, never fabricated, D61);
#  - a keystroke typed in the TUI reaches Claude Code in the guest and its output
#    streams back over the same carriage.
```

A reader-only attach here means the `IssueAttachHandle` live minter did not mint a
servable DIRECT endpoint, or the serving child is down for that session — re-check
C.3. A **writer-seat** drive over the carriage is the end-to-end proof this whole
check exists for.

## C.6 — teardown reap

When the session ends, the §4.2 destroy reaps the per-session serving leg exactly
as §A.6: `AttachBridge.Destroy(sessionUUID)` SIGINTs + reaps the `ds-hostbridge`
child and unlinks the per-session UDS (best-effort/non-fatal). Confirm:

```sh
test ! -S /run/ds/attach/<uuid>.sock && echo "per-session UDS gone"
pgrep -af 'ds-hostbridge --serve-uds.*<uuid>' || echo "no serving child remains"
```

## C.7 — observed result (fill in on the operator pass)

This block is **deferred** — fill it in when an operator runs §C on the box (the
spike note's deferred-validation posture). Until then every row is UNVALIDATED
(offline-proven only).

```
date / operator:        ____________________
host:                   user@<operator-host>
Boot CID threading (01KV91MAWSZ) landed?   [ ] yes  [ ] no   (prerequisite, C.1)
DS_HOSTAGENT_LIVE=1 + DS_ORCH_LIVE=1 set?  [ ] yes  [ ] no

C.1  domain pins <cid auto='no' address=<derived>/>     [ ] PASS  [ ] FAIL  notes: ____
C.3  ds-hostbridge serving child dials guestCID:4242     [ ] PASS  [ ] FAIL  notes: ____
     served UDS /run/ds/attach/<uuid>.sock present        [ ] PASS  [ ] FAIL  notes: ____
     guest ds-attachfwd LISTENing VMADDR_CID_ANY:4242      [ ] PASS  [ ] FAIL  notes: ____
C.4  byte round-trips host UDS ⇄ vsock ⇄ guest UDS        [ ] PASS  [ ] FAIL  notes: ____
C.5  serpent-tui takes WRITER seat via DIRECT→Unix        [ ] PASS  [ ] FAIL  notes: ____
     writer-seat keystroke reaches Claude Code in guest    [ ] PASS  [ ] FAIL  notes: ____
C.6  destroy reaps serving child + unlinks UDS            [ ] PASS  [ ] FAIL  notes: ____
```

---

# §D — captured-ref durability rehearsal (`DS_HOSTAGENT_LIVE`, **no** libvirt/host)

Unlike §A–§C, this leg needs **no operator host** — it is a synthetic-filesystem
rehearsal that runs anywhere `DS_HOSTAGENT_LIVE=1` is set (D50: no libvirt, no VM,
no qemu, no network). It closes the last untested link in the D29/D30 captured-ref
producer arc: the **daemon's real composition root** (`buildDriverServiceWithBridge`)
building the durable `CapturedRefStore` + the captured-ref-aware `SessionRecoverer`
(`NewSessionRecoverer` → `NewSessionRecovererWithCapturedRefs`) over an on-disk
`<OverlayDir>/.ds-sessions` area, then reading a captured ref back into
`RecoveredSession.SnapshotRefs` across a **driver restart**.

The rehearsal is the Go test `TestCapturedRefDurabilityThroughLiveComposition`
(`orchestrator/cmd/host-agent/capturedref_live_test.go`). It **SKIPS cleanly when
`DS_HOSTAGENT_LIVE` is unset** (sandbox, CI, every `go test ./...`). Under the gate
it writes a session record + captured ref to the SAME durable stores the
composition wires, reconstructs the composition, and asserts the ref survives — the
"resident domain" the recoverer joins comes from a **synthetic `virsh` stand-in**
(`-virsh-bin`), so the real recoverer runs its real code path with no hypervisor.

```sh
# runs anywhere — no host, no libvirt (a DEFERRED MANUAL/CI step, not an operator leg)
cd orchestrator
DS_HOSTAGENT_LIVE=1 go test ./cmd/host-agent/ \
  -run TestCapturedRefDurabilityThroughLiveComposition -v
# expect: PASS — the durable captured ref reads back into SnapshotRefs post-restart
```

---

# §E — CI regression leg (`.github/workflows/hostagent-live.yml`)

Because the §D rehearsal (and its DS_HOSTAGENT_LIVE-gated siblings) SKIP under the
default `go test ./...`, a regression in `buildDriverServiceWithBridge`'s live
store+recoverer wiring would otherwise pass CI silently. The workflow
`.github/workflows/hostagent-live.yml`
closes that gap: it flips the gate on with `DS_HOSTAGENT_LIVE=1
DS_HOSTAGENT_SKIP_CA_INJECT=1` and runs the two gated packages
(`./cmd/host-agent/` and `./internal/hypervisor/libvirt/`) on every push/PR that
touches them. Its setup shape (toolchain via `go.work`, `cache: false`,
self-hosted debian runner) mirrors `go.yml` so the two lanes cannot drift.

**This is a SYNTHETIC-ONLY leg** — the §D posture (D50: no libvirt, no qemu, no
VM, no network on the runner; the recoverer joins a `virsh` stand-in). It is NOT
the operator-host arc: the §A/§B/§C legs (`TestLiveSmokeCloneBootDestroy`,
`TestLiveTrustAnchor_*`, the vsock carriage check) REQUIRE a real M0 golden base
and only run on the operator host, so the workflow **`-skip`s them by name**
(they `t.Fatal` without `DS_HOSTAGENT_LIVE_BASE`). `TestDaemonServesFrozenDriverOffline`
is likewise skipped there — it is an offline-composition assertion already covered
green by `go.yml`'s default lane. Every other gated sibling in these packages is
picked up automatically; only a new *operator-host* test needs a matching skip
entry (add it with a one-line reason rather than widening the runner's needs).
