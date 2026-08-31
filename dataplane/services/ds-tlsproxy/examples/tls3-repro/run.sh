#!/usr/bin/env bash
# Orchestrate: start the repro server (mode=$1, alpn flag $2), run the Node
# client against it with NODE_DEBUG=tls, collect both sides' output.
set -u
MODE="${1:-adapter}"
SRV_ALPN_FLAG="${2:-}"        # "" => http/1.1 only; "--alpn-default" => h2,http/1.1
CLIENT_ALPN="${3:-http/1.1}"  # what the Node client offers
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DP="${DP:-$(cd "$HERE/../../../.." && pwd)}"   # -> dataplane/
BIN="${BIN:-$DP/target/debug/examples/tls3_repro}"
# The example is gated on `test-ca` (see ds-tlsproxy/Cargo.toml [[example]]).
if [ ! -x "$BIN" ]; then
  ( cd "$DP" && cargo build -p ds-tlsproxy --features test-ca --example tls3_repro ) || exit 1
fi
# Throwaway session-CA PEM (D50/D73: never a real credential). Ephemeral by design.
CA="${CA:-$(mktemp -t ds-tls3-repro-ca.XXXXXX.pem)}"
PORT=$(( (RANDOM % 20000) + 20000 ))

echo "############################################################"
echo "## VARIANT mode=$MODE server_alpn_flag='$SRV_ALPN_FLAG' client_alpn='$CLIENT_ALPN' port=$PORT"
echo "############################################################"

SRVLOG=$(mktemp)
"$BIN" --mode "$MODE" --port "$PORT" --ca-out "$CA" $SRV_ALPN_FLAG >"$SRVLOG" 2>&1 &
SRV_PID=$!
# wait for LISTENING line (the example prints it to stdout, captured in SRVLOG)
for i in $(seq 1 50); do
  grep -q "LISTENING $PORT" "$SRVLOG" && break
  sleep 0.05
done

echo "----- NODE CLIENT (NODE_DEBUG=tls) -----"
NODE_DEBUG=tls node "$HERE/node-tls3-client.mjs" "$PORT" "$CA" "$CLIENT_ALPN" 2>&1 \
  | grep -E '\[node\]|onread|onhandshake|secure|alert|emitClose|resume|TLS|tls:|write|destroy|fatal|verify|client emit|read|onError|onConnectSecure' \
  | head -120

# give the server a moment to log its post-handshake result, then stop it
sleep 0.4
kill "$SRV_PID" 2>/dev/null
wait "$SRV_PID" 2>/dev/null

echo "----- SERVER (rustls side) -----"
cat "$SRVLOG"
rm -f "$SRVLOG" "$CA"
echo
