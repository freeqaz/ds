# vm/entrypoint/ — guest-side runtime/v1 implementation

**Owner:** VM & runtime · **OSS** (D15/D25) · **Decisions:** D38, D20 (doc 04 §6)

The guest-side implementation of the **VM entrypoint contract** — one of the
two contracts the D38 runtime seam splits into (the other is the protobuf
attach event schema, owned by Attach & client). This is what the host agent
launches inside the VM: it supervises the runtime process, injects session
material, and honors the launch/supervise/inject obligations of
`proto/dreamserpent/runtime/v1/` (contract freezes at M0; README-reserved
there until the freeze PR — see `proto/FREEZE.md`).

**Runtime-agnostic, always** (D20). The entrypoint receives an opaque
`entrypoint_config_ref` through `VmSpec` (doc 15 §5.1) — the orchestrator is
runtime-ignorant and so is this binary. Anything Claude-Code-specific belongs
in `client/wrapper/adapters/claude-code/`, the single sanctioned home for
runtime-specific code; dropping OpenClaw or our own agent loop into the VM
must be a config change here, not a code change.

Design note (skeleton Part 4, resolution 8): `runtime/v1` is its own proto
package because this seam (host-agent→guest) has a different owner and
consumer set than `attach/v1` (wrapper→consumer). Owners may merge the
packages at freeze time; the implementation home stays here either way.

## The `ds-entrypoint` binary

`runtime/v1` FROZE at M0 (2026-06-15), so this package now ships the binary the
golden image bakes at `/usr/local/bin/ds-entrypoint` and `ds-entrypoint.service`
launches on boot:

- `cmd/ds-entrypoint/main.go` — the thin process shell (`entrypoint.Main`).
- `config.go` — load + **TOTAL** validation of `EntrypointConfig` from
  `DS_ENTRYPOINT_CONFIG_DIR/config.pb`; fail-closed if absent/empty/malformed/invalid.
- `runtimev1_bridge.go` — the **single** proto-bound file: `fromProto` projects the
  frozen `runtimev1.EntrypointConfig` onto an internal, proto-free struct; the wire
  decode and the best-effort `EntrypointService` reporter also live here. Nothing
  else in the package touches the generated code (the require + replace for
  `proto/gen/go` in `vm/go.mod` make it build under `GOWORK=off` too).
- `supervise.go` — boot → launch the `LaunchSpec` → wire stdio → supervise → teardown,
  fail-closed at every step (no valid config ⇒ no runtime ⇒ no egress). Tests drive a
  re-exec helper child, so the state machine runs against a real OS process with no
  Claude Code/VM.
- `transport.go` — `io.Copy` byte-bridge between the runtime's stdio and the
  `AttachWiring` event-socket UDS. **No protocol parsing** (D20/D38): runtime-agnostic,
  the attach byte-path only.
- `notify.go` — stdlib `sd_notify` readiness at the D81 boot-to-entrypoint boundary
  (the load-bearing `Type=notify` signal); the `EntrypointService` app report is a
  best-effort secondary (the §3 state machine is the lifecycle authority).
- `env.go` — threads the `EgressWiring` proxy/CA **references** into the runtime env
  plus `NODE_USE_ENV_PROXY=1`; this binary OWNS the proxy keys (a stale value can never
  bypass the egress gateway). No credentials are ever carried (D17/D39/D50): the session
  token is fetched in-guest via `session_token_endpoint`.
- `tokenfetch.go` — the in-guest **session-token fetch** (D39/D50). When
  `session_token_endpoint` is set, at boot ds-entrypoint GETs the short-lived
  token from the host-local D22 shim (U5) and injects it as
  `CLAUDE_CODE_OAUTH_TOKEN` into the **launched runtime's env only** — fetched
  fresh per boot, never written to disk, never logged. The fetch uses a dedicated
  `http.Client` with `Transport.Proxy: nil` so it does **NOT** traverse
  `HTTP(S)_PROXY` / the egress gateway (the shim is a host-local link-local
  address reached directly; the proxy keys env.go sets are for the runtime). The
  runtime then presents the token to the egress gateway, which swaps it for the
  real upstream key (U7). **Fail posture:** an empty endpoint skips the fetch (the
  synthetic/offline launch path is unaffected); an endpoint set-but-unreachable
  (or non-2xx / empty body) fails closed BEFORE launch — no runtime may run
  without auth. The token is appended in the supervisor AFTER `buildRuntimeEnv`,
  so env.go's credential-free invariant is unchanged.

**Config-presence launch signal** (maintainer ruling 2026-06-15): a valid
`EntrypointConfig` present in `DS_ENTRYPOINT_CONFIG_DIR` is itself the signal to
launch and supervise the runtime — there is no separate env gate. The only
no-launch path is `loadConfig` failing (absent/empty/invalid `config.pb`), which
is the boot-validate / dry-boot case (it drops no config) and returns the
fail-closed exit without exec-ing a runtime. The package's offline tests drive
the live leg with a re-exec helper child, so no real Claude Code/VM is needed.
