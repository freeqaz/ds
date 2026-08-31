// Isolated Node TLS client reproducing what Claude Code's Node tls stack does:
// tls.connect with servername=api.anthropic.com, the throwaway interception CA
// trusted via `ca:`, ALPN [http/1.1]. On secureConnect, log authorized/alpn/
// protocol, then write a GET /v1/models HTTP/1.1 request and log the response or
// the post-handshake abort. Run with NODE_DEBUG=tls to capture the TLS-level
// reason for any abort.
//
// Usage: node node-tls3-client.mjs <port> <ca_pem_path> [alpn]
//   alpn defaults to "http/1.1"; pass "h2,http/1.1" to offer both.

import tls from 'node:tls';
import fs from 'node:fs';

const port = parseInt(process.argv[2], 10);
const caPath = process.argv[3];
const alpnArg = process.argv[4] || 'http/1.1';
const ALPNProtocols = alpnArg.split(',');
const ca = fs.readFileSync(caPath, 'utf8');

console.error(`[node] connecting to 127.0.0.1:${port} servername=api.anthropic.com ALPN=${JSON.stringify(ALPNProtocols)}`);

const t0 = process.hrtime.bigint();
const socket = tls.connect({
  host: '127.0.0.1',
  port,
  servername: 'api.anthropic.com',
  ca,
  ALPNProtocols,
  // CC's Node stack uses the default ciphers/minVersion; do NOT override so we
  // reproduce CC's exact client capabilities.
});

let secureAt = null;
let sentRequest = false;
let gotData = false;

socket.on('secureConnect', () => {
  secureAt = process.hrtime.bigint();
  const dtMs = Number(secureAt - t0) / 1e6;
  console.error(`[node] secureConnect @ +${dtMs.toFixed(3)}ms`);
  console.error(`[node]   authorized      = ${socket.authorized}`);
  console.error(`[node]   authorizationError = ${socket.authorizationError}`);
  console.error(`[node]   alpnProtocol    = ${socket.alpnProtocol}`);
  console.error(`[node]   getProtocol()   = ${socket.getProtocol()}`);
  const cipher = socket.getCipher?.();
  console.error(`[node]   cipher          = ${cipher ? cipher.name + ' ' + cipher.version : 'n/a'}`);
  const peer = socket.getPeerCertificate?.();
  if (peer && peer.subject) {
    console.error(`[node]   peerCert subject CN = ${peer.subject.CN}, issuer CN = ${peer.issuer && peer.issuer.CN}`);
    console.error(`[node]   peerCert subjectaltname = ${peer.subjectaltname}`);
  }

  // Send the request CC would send (over http/1.1).
  const req = 'GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n\r\n';
  const ok = socket.write(req, 'utf8', () => {
    const dt2 = Number(process.hrtime.bigint() - secureAt) / 1e6;
    console.error(`[node] request WRITE callback fired @ +${dt2.toFixed(3)}ms after secureConnect (write flushed to socket)`);
  });
  sentRequest = true;
  console.error(`[node] socket.write returned ${ok} (request queued)`);
});

socket.on('data', (chunk) => {
  gotData = true;
  console.error(`[node] DATA (${chunk.length} bytes):\n---\n${chunk.toString('utf8').slice(0, 300)}\n---`);
});

socket.on('end', () => {
  console.error('[node] socket end (peer closed write side)');
});

socket.on('close', (hadError) => {
  const dt = secureAt ? Number(process.hrtime.bigint() - secureAt) / 1e6 : null;
  console.error(`[node] close hadError=${hadError} secureConnectReached=${secureAt !== null} sentRequest=${sentRequest} gotData=${gotData}` + (dt !== null ? ` (+${dt.toFixed(3)}ms after secureConnect)` : ''));
  process.exit(hadError ? 1 : 0);
});

socket.on('error', (err) => {
  const dt = secureAt ? Number(process.hrtime.bigint() - secureAt) / 1e6 : null;
  console.error(`[node] ERROR: ${err.code || ''} ${err.message}` + (dt !== null ? ` (+${dt.toFixed(3)}ms after secureConnect)` : ' (before secureConnect)'));
});

setTimeout(() => {
  console.error('[node] TIMEOUT (5s) — no close; destroying.');
  socket.destroy();
  process.exit(3);
}, 5000);
