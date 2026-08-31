# TLS-3 termination repro harness

Test infra, **not production code**. An isolated reproduction of the
ds-tlsproxy posture-(b) per-session-CA TLS termination path, built to answer one
question: does a real JS TLS client complete the handshake **and** send an
HTTP/1.1 request, or does it abort shortly after the handshake?

This is a **diagnostic**, and it is deliberately separate from
`tests/tls3_inspect.rs` — that file is the TLS-3 *acceptance* suite (the
crate-local mirror of the boundary executable spec, D26). This harness is the
thing you reach for when the acceptance suite is green but a real client still
misbehaves, because it lets you vary the server-side drive strategy and the
client independently.

## The two server modes

Both drive the *same* `rustls::ServerConnection`; only the I/O strategy differs.
That is the point of the harness — it isolates a config bug from a pump bug.

- `--mode adapter` — rustls's own blocking sync adapter (`rustls::Stream` /
  `complete_io`) over a std `TcpStream`, reading straight off the socket. This
  tests the **config** (cert / ALPN / cipher).
- `--mode pump` — a replica of the proxy's manual pump
  (`drive_server_handshake`): peek the complete ClientHello record(s) off the
  socket first, replay them via `read_tls` / `process_new_packets` before
  reading anything further, then loop `write_tls` → socket → `read_tls`. This
  tests the **pump**.

The rustls config is built by a verbatim copy of `build_session_server_config`
(the original is private in `src/main.rs`), ALPN logic included, so the harness
cannot drift into testing a different config than production uses.

## Running it

```sh
./run.sh [adapter|pump] [--alpn-default] [client-alpn]   # one variant, verbose
./matrix.sh                                              # all 6 cells, terse
```

Both scripts locate the workspace relative to their own path and build the
example on demand; `DP`, `BIN`, and `CA` can be overridden by environment
variable. `matrix.sh` covers {adapter, pump} × {node `tls.connect`, bun
`tls.connect` via the node:tls shim, bun native `fetch` (BoringSSL)}.

The example is gated behind the crate's **`test-ca`** feature, because it
self-mints a throwaway session CA and an example does not inherit `cfg(test)`.
The `[[example]]` stanza in `Cargo.toml` sets `required-features`, so a bare
`cargo build --examples` *skips* it rather than failing. The runner scripts
build with `--features test-ca` automatically.

## Credentials

The session CA is a throwaway self-signed cert minted per run and written to a
`mktemp` PEM that the scripts delete on exit — never a real credential and never
a real CA key (D50 / D73). The client trusts it explicitly rather than through
any system trust store.

## Status as of the last run

All six cells report `handshake COMPLETE + request READ`; the bun-native-fetch
cells return `status=200`. So on this codebase the termination path is **not**
the source of a post-handshake abort, under either drive strategy.

One trap worth preserving: Bun's `fetch` resolves the URL host through real DNS,
so pointing it at `https://api.anthropic.com:<port>` connects to the *public
internet*, not the local server. An earlier draft of `bun-fetch-client.mjs` did
exactly that and produced a ~135s hang and a misleading "Unable to connect" —
which reads like a repro of the bug under investigation but is pure harness
error. The client now connects to `127.0.0.1` by IP and overrides SNI and trust
anchor via Bun's `tls` option bag.
