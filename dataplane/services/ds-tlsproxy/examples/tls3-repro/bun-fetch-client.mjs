// Faithful reproduction of CC's ACTUAL client: Bun's native fetch (BoringSSL
// HTTP client), the path the Anthropic SDK uses -- as opposed to the node:tls
// shim that node-tls3-client.mjs exercises. This is the third matrix client.
//
// Usage: bun bun-fetch-client.mjs <port> <ca-pem-path>
//
// We must hit the LOCAL repro server while still presenting SNI
// `api.anthropic.com` (the SAN the session CA mints the leaf for). Bun's fetch
// resolves the URL host via real DNS, so a URL of https://api.anthropic.com:<port>
// connects to the PUBLIC internet -- which is exactly what an earlier draft of
// this file did, and why this matrix cell used to hang ~135s and then report a
// misleading "Unable to connect". Instead: connect by IP, and override the SNI
// and trust anchor through Bun's `tls` option bag.

const port = parseInt(process.argv[2], 10);
const caPath = process.argv[3];

if (!Number.isFinite(port) || !caPath) {
  console.error('[bun-fetch] usage: bun bun-fetch-client.mjs <port> <ca-pem-path>');
  process.exit(2);
}

const ca = await Bun.file(caPath).text();

const t0 = performance.now();
try {
  const res = await fetch(`https://127.0.0.1:${port}/v1/models`, {
    tls: {
      // Trust ONLY the throwaway session CA, verification stays ON (as CC does).
      ca,
      // Present the SAN the session CA actually minted, so the handshake
      // exercises the real per-origin leaf rather than an IP cert.
      serverName: 'api.anthropic.com',
    },
    headers: { host: 'api.anthropic.com', connection: 'close' },
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  console.error(`[bun-fetch] status=${res.status} (+${(performance.now() - t0).toFixed(2)}ms)`);
  const body = await res.text();
  console.error(`[bun-fetch] body[0..200]: ${body.slice(0, 200)}`);
} catch (e) {
  console.error(`[bun-fetch] FETCH ERROR (+${(performance.now() - t0).toFixed(2)}ms): ${e}`);
  if (e && e.cause) console.error(`[bun-fetch]   cause: ${e.cause}`);
  if (e && e.code) console.error(`[bun-fetch]   code: ${e.code}`);
  process.exitCode = 1;
}
