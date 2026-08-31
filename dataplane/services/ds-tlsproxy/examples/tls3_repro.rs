//! Isolated TLS-3 termination repro (NOT production code; test infra only).
//!
//! Replicates the ds-tlsproxy posture-(b) per-session-CA TLS termination
//! server-side, two ways, so we can determine whether a real Node tls client
//! (what Claude Code uses) completes the handshake AND sends an HTTP/1.1
//! request, or aborts ~28us post-handshake:
//!
//!   --mode adapter : drive the per-session `ServerConnection` with rustls's
//!                    OWN blocking sync adapter (`rustls::Stream` /
//!                    `complete_io`) over a std `TcpStream` — the STANDARD
//!                    adapter that reads straight off the socket. Tests the
//!                    CONFIG (cert/ALPN/cipher).
//!
//!   --mode pump    : drive the SAME `ServerConnection` with a replica of the
//!                    proxy's manual pump (`drive_server_handshake`): peek the
//!                    COMPLETE ClientHello record(s) off the socket FIRST, then
//!                    replay them into the connection via read_tls/
//!                    process_new_packets BEFORE reading anything further, then
//!                    loop write_tls->socket / socket->read_tls. Tests the PUMP.
//!
//! Both modes use a throwaway self-signed session CA (D50/D73: never a real
//! credential / real CA key). The CA cert PEM is written to a file so the Node
//! client can trust it via NODE_EXTRA_CA_CERTS / `ca:`.
//!
//! The config is built by a byte-for-byte copy of `build_session_server_config`
//! (the original is a private fn in src/main.rs; copied here verbatim, ALPN
//! logic included).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use ds_tlsproxy::ca::{LeafCert, SessionCa};

// ── ALPN constants (mirror ds_tlsproxy::http2) ──────────────────────────────
const ALPN_HTTP11: &[u8] = b"http/1.1";
const ALPN_H2: &[u8] = b"h2";

const TLS_RECORD_HEADER_LEN: usize = 5;

/// VERBATIM copy of src/main.rs `certified_key_from_leaf`.
fn certified_key_from_leaf(
    leaf: &LeafCert,
) -> Result<Arc<rustls::sign::CertifiedKey>, rustls::Error> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    let cert_chain = vec![CertificateDer::from(leaf.cert_der.clone())];
    let key = PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes())
        .map_err(|e| rustls::Error::General(format!("leaf key parse: {e}")))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(
        cert_chain,
        signing_key,
    )))
}

/// VERBATIM copy of src/main.rs `SessionCaResolver`.
struct SessionCaResolver {
    session_ca: Arc<SessionCa>,
}

impl std::fmt::Debug for SessionCaResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCaResolver")
            .field("session_id", &self.session_ca.session_id())
            .finish()
    }
}

impl rustls::server::ResolvesServerCert for SessionCaResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let leaf = self.session_ca.leaf_for(sni).ok()?;
        certified_key_from_leaf(&leaf).ok()
    }
}

/// VERBATIM copy of src/main.rs `build_session_server_config` (ALPN logic incl.).
fn build_session_server_config(
    session_ca: Arc<SessionCa>,
    http1_only: bool,
) -> Result<Arc<rustls::ServerConfig>, rustls::Error> {
    let resolver = Arc::new(SessionCaResolver { session_ca });
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    config.alpn_protocols = if http1_only {
        vec![ALPN_HTTP11.to_vec()]
    } else {
        vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()]
    };
    Ok(Arc::new(config))
}

// ── ClientHello peek (replica of the proxy's peek_client_hello intent) ──────
// Read the COMPLETE first TLS record(s) carrying the ClientHello off the
// socket, returning the raw on-wire bytes so they can be REPLAYED into the
// ServerConnection (the proxy's `replay` precondition). CC's ClientHello is a
// single ~517B record, so one record header + body is the whole hello here.
fn peek_client_hello(sock: &mut std::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; TLS_RECORD_HEADER_LEN];
    sock.read_exact(&mut hdr)?;
    // content_type=22 (handshake) expected; len = hdr[3..5] BE.
    let rec_len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
    let mut body = vec![0u8; rec_len];
    sock.read_exact(&mut body)?;
    let mut out = Vec::with_capacity(TLS_RECORD_HEADER_LEN + rec_len);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&body);
    eprintln!(
        "[pump] peeked ClientHello record: content_type={} version={:02x}{:02x} len={} (total {} bytes)",
        hdr[0],
        hdr[1],
        hdr[2],
        rec_len,
        out.len()
    );
    Ok(out)
}

/// Replica of src/main.rs `drive_server_handshake`, but SYNC over a std
/// TcpStream (same logic: replay the peeked ClientHello FIRST, then loop
/// write_tls->socket / socket->read_tls until !is_handshaking).
fn drive_server_handshake_pump(
    tls: &mut rustls::ServerConnection,
    replay: &[u8],
    sock: &mut std::net::TcpStream,
) -> std::io::Result<()> {
    if !replay.is_empty() {
        let mut rd = replay;
        while !rd.is_empty() {
            let consumed = tls.read_tls(&mut rd)?;
            if consumed == 0 {
                break;
            }
            tls.process_new_packets().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?;
        }
    }
    let mut iters = 0u32;
    loop {
        iters += 1;
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out)?;
            if out.is_empty() {
                break;
            }
            eprintln!("[pump]   iter {iters}: flushed {} bytes of TLS to client (is_handshaking={})", out.len(), tls.is_handshaking());
            sock.write_all(&out)?;
            sock.flush()?;
        }
        if !tls.is_handshaking() {
            eprintln!("[pump]   iter {iters}: RETURN at !is_handshaking. wants_read={} wants_write={}", tls.wants_read(), tls.wants_write());
            return Ok(());
        }
        if tls.wants_read() {
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf)?;
            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            let mut rd = &buf[..n];
            while !rd.is_empty() {
                let consumed = tls.read_tls(&mut rd)?;
                if consumed == 0 {
                    break;
                }
                tls.process_new_packets().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;
            }
        } else if tls.is_handshaking() {
            tls.process_new_packets().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?;
        }
    }
}

fn handle_pump(mut sock: std::net::TcpStream, config: Arc<rustls::ServerConfig>) {
    // peek the ClientHello FIRST (consumes it off the socket).
    let replay = match peek_client_hello(&mut sock) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[pump] peek failed: {e}");
            return;
        }
    };
    // EXPERIMENT: run_inspected_flow dials the upstream (blocking dial_tls) BEFORE the
    // downstream handshake; that stalls CC's server flight by the upstream RTT. Simulate
    // that delay between the peek and the downstream handshake to find the reset threshold.
    if let Ok(v) = std::env::var("DS_REPRO_PREDIAL_MS") {
        if let Ok(ms) = v.parse::<u64>() {
            eprintln!("[pump] PREDIAL delay {ms}ms (simulating dial_tls before downstream handshake)");
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    let mut tls = match rustls::ServerConnection::new(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[pump] ServerConnection::new failed: {e}");
            return;
        }
    };
    if let Err(e) = drive_server_handshake_pump(&mut tls, &replay, &mut sock) {
        eprintln!("[pump] handshake FAILED: {} ({e})", e.kind());
        return;
    }
    eprintln!(
        "[pump] handshake COMPLETE. alpn={:?} proto_version={:?}",
        tls.alpn_protocol().map(|p| String::from_utf8_lossy(p).to_string()),
        tls.protocol_version()
    );
    // Now read the decrypted request using rustls's Reader (post-handshake).
    read_and_report_request(&mut tls, &mut sock, "pump");
}

fn handle_adapter(mut sock: std::net::TcpStream, config: Arc<rustls::ServerConfig>) {
    let mut tls = match rustls::ServerConnection::new(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[adapter] ServerConnection::new failed: {e}");
            return;
        }
    };
    // STANDARD adapter: rustls::Stream drives complete_io transparently —
    // reads straight off the socket (NO peek/replay).
    {
        let mut stream = rustls::Stream::new(&mut tls, &mut sock);
        // Force the handshake to complete by flushing (no app data yet).
        if let Err(e) = stream.flush() {
            eprintln!("[adapter] handshake/flush FAILED: {} ({e})", e.kind());
            return;
        }
    }
    eprintln!(
        "[adapter] handshake COMPLETE. alpn={:?} proto_version={:?}",
        tls.alpn_protocol().map(|p| String::from_utf8_lossy(p).to_string()),
        tls.protocol_version()
    );
    read_and_report_request(&mut tls, &mut sock, "adapter");
}

/// Post-handshake: pump TLS records and surface the decrypted plaintext (the
/// HTTP/1.1 request CC was supposed to send), or report the post-handshake
/// abort (connection reset / EOF with no request).
fn read_and_report_request(
    tls: &mut rustls::ServerConnection,
    sock: &mut std::net::TcpStream,
    tag: &str,
) {
    let mut plaintext: Vec<u8> = Vec::new();
    let mut io_buf = [0u8; 4096];
    loop {
        // Drain any already-decrypted plaintext.
        let mut rdbuf = [0u8; 4096];
        loop {
            match std::io::Read::read(&mut tls.reader(), &mut rdbuf) {
                Ok(0) => break,
                Ok(n) => plaintext.extend_from_slice(&rdbuf[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("[{tag}] reader error: {} ({e})", e.kind());
                    report_plaintext(tag, &plaintext);
                    return;
                }
            }
        }
        if plaintext.windows(4).any(|w| w == b"\r\n\r\n") {
            eprintln!("[{tag}] GOT a complete HTTP request head from the client.");
            report_plaintext(tag, &plaintext);
            // Send a minimal HTTP/1.1 response so the client sees a clean reply
            // (proves the round-trip; without it the client sees ECONNRESET on close).
            let body = b"{\"ok\":true}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let mut out: Vec<u8> = Vec::new();
            out.extend_from_slice(resp.as_bytes());
            out.extend_from_slice(body);
            if let Err(e) = std::io::Write::write_all(&mut tls.writer(), &out) {
                eprintln!("[{tag}] response writer error: {e}");
            }
            // flush the encrypted response to the socket.
            while tls.wants_write() {
                let mut cipher = Vec::new();
                if tls.write_tls(&mut cipher).is_err() || cipher.is_empty() { break; }
                if sock.write_all(&cipher).is_err() { break; }
            }
            let _ = sock.flush();
            eprintln!("[{tag}] wrote 200 OK response; closing.");
            // brief linger so the client drains before close.
            std::thread::sleep(std::time::Duration::from_millis(50));
            return;
        }
        // Need more ciphertext from the socket.
        match sock.read(&mut io_buf) {
            Ok(0) => {
                eprintln!(
                    "[{tag}] socket EOF after handshake. plaintext so far = {} bytes.",
                    plaintext.len()
                );
                report_plaintext(tag, &plaintext);
                return;
            }
            Ok(n) => {
                let mut rd = &io_buf[..n];
                if let Err(e) = tls.read_tls(&mut rd) {
                    eprintln!("[{tag}] read_tls error: {} ({e})", e.kind());
                    return;
                }
                if let Err(e) = tls.process_new_packets() {
                    eprintln!("[{tag}] process_new_packets error post-handshake: {e}");
                    report_plaintext(tag, &plaintext);
                    return;
                }
            }
            Err(e) => {
                // ECONNRESET surfaces here: the post-handshake RST the live capture saw.
                eprintln!(
                    "[{tag}] socket read error after handshake: {} ({e}). plaintext so far = {} bytes (THIS is the post-handshake abort).",
                    e.kind(),
                    plaintext.len()
                );
                report_plaintext(tag, &plaintext);
                return;
            }
        }
    }
}

fn report_plaintext(tag: &str, plaintext: &[u8]) {
    if plaintext.is_empty() {
        eprintln!("[{tag}] RESULT: client sent ZERO application bytes (post-handshake abort / reset before request).");
    } else {
        let head = String::from_utf8_lossy(&plaintext[..plaintext.len().min(200)]);
        eprintln!("[{tag}] RESULT: client sent {} plaintext bytes. First 200:\n---\n{}\n---", plaintext.len(), head);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut mode = "adapter".to_string();
    let mut port: u16 = 0;
    let mut ca_out = "/tmp/ds-tls3-repro-ca.pem".to_string();
    let mut http1_only = true;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => { mode = args[i + 1].clone(); i += 2; }
            "--port" => { port = args[i + 1].parse().unwrap(); i += 2; }
            "--ca-out" => { ca_out = args[i + 1].clone(); i += 2; }
            "--alpn-default" => { http1_only = false; i += 1; } // offer h2,http/1.1
            other => { eprintln!("unknown arg {other}"); std::process::exit(2); }
        }
    }

    // Throwaway per-session interception CA (D50/D73: never a real key).
    let session_ca = Arc::new(
        SessionCa::new_self_signed_for_test("repro-session")
            .expect("self-mint throwaway session CA"),
    );
    std::fs::write(&ca_out, session_ca.cert_pool_pem()).expect("write CA cert PEM");
    eprintln!("CA cert PEM written to {ca_out}");
    eprintln!(
        "issuer CN = {}, http1_only(ALPN http/1.1 only) = {}",
        session_ca.issuer_common_name(),
        http1_only
    );

    let config = build_session_server_config(session_ca, http1_only).expect("build config");
    eprintln!("ALPN advertised = {:?}", config.alpn_protocols.iter().map(|p| String::from_utf8_lossy(p).to_string()).collect::<Vec<_>>());

    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    let actual = listener.local_addr().unwrap();
    println!("LISTENING {} mode={}", actual.port(), mode);
    eprintln!("listening on {actual} mode={mode}");

    // Single-shot: handle ONE connection then exit (the harness drives one client).
    if let Some(Ok(sock)) = listener.incoming().next() {
        sock.set_nodelay(true).ok();
        match mode.as_str() {
            "pump" => handle_pump(sock, config),
            "adapter" => handle_adapter(sock, config),
            other => eprintln!("unknown mode {other}"),
        }
    }
}
