#!/usr/bin/env bash
# Definitive matrix: {adapter, pump} server variants x {node tls.connect, bun
# tls.connect (node:tls shim), bun native fetch} clients. Reports per cell
# whether the handshake completed and a request round-tripped.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DP="${DP:-$(cd "$HERE/../../../.." && pwd)}"   # -> dataplane/
BIN="${BIN:-$DP/target/debug/examples/tls3_repro}"
# The example is gated on `test-ca` (see ds-tlsproxy/Cargo.toml [[example]]).
if [ ! -x "$BIN" ]; then
  ( cd "$DP" && cargo build -p ds-tlsproxy --features test-ca --example tls3_repro ) || exit 1
fi
# Throwaway session-CA PEM (D50/D73: never a real credential). Ephemeral by design.
CA="${CA:-$(mktemp -t ds-tls3-repro-ca.XXXXXX.pem)}"
trap 'rm -f "$CA"' EXIT
PROXYCLEAR="NO_PROXY=* no_proxy=* HTTPS_PROXY= HTTP_PROXY= https_proxy= http_proxy= ALL_PROXY="

start() { # $1=mode -> echoes PORT; sets SRV/SRVLOG globals
  MODE="$1"; PORT=$(( (RANDOM%20000)+32000 )); SRVLOG=$(mktemp)
  "$BIN" --mode "$MODE" --port "$PORT" --ca-out "$CA" >"$SRVLOG" 2>&1 & SRV=$!
  for i in $(seq 1 60); do grep -q "LISTENING $PORT" "$SRVLOG" && break; sleep 0.05; done
}
stop() { sleep 0.25; kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; }
verdict() { # reads SRVLOG, prints SERVER verdict
  if grep -q "RESULT: client sent" "$SRVLOG" && grep -q "GOT a complete HTTP request head" "$SRVLOG"; then
    echo "SERVER: handshake COMPLETE + request READ"
  elif grep -q "handshake FAILED\|handshake/flush FAILED" "$SRVLOG"; then
    echo "SERVER: HANDSHAKE FAILED ($(grep -m1 'FAILED' "$SRVLOG"))"
  else echo "SERVER: (no request) $(grep -m1 'RESULT\|FAILED\|abort' "$SRVLOG")"; fi
}

for MODE in adapter pump; do
  echo "################# SERVER mode=$MODE #################"

  start "$MODE"
  echo "--- client: node tls.connect (Node $(node -p process.versions.node)) ALPN http/1.1 ---"
  C=$(node "$HERE/node-tls3-client.mjs" "$PORT" "$CA" http/1.1 2>&1 | grep -E 'secureConnect|RESULT|close hadError|ERROR|GOT|DATA')
  echo "$C" | grep -E 'secureConnect|close hadError|ERROR|DATA' | head -4
  stop; verdict; echo

  start "$MODE"
  echo "--- client: bun tls.connect (node:tls shim, Bun $(bun -p 'Bun.version')) ALPN http/1.1 ---"
  C=$(bun "$HERE/node-tls3-client.mjs" "$PORT" "$CA" http/1.1 2>&1 | grep -E 'secureConnect|close hadError|ERROR|DATA')
  echo "$C" | head -4
  stop; verdict; echo

  start "$MODE"
  echo "--- client: BUN NATIVE FETCH (BoringSSL, CC's real path) ---"
  C=$(env $PROXYCLEAR bun "$HERE/bun-fetch-client.mjs" "$PORT" "$CA" 2>&1 | grep -E 'status=|ERROR|body:')
  echo "$C" | head -4
  stop; verdict; echo
done
