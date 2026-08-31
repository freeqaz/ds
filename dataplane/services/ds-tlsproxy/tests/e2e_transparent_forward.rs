//! E2E: an outbound HTTP request arrives at the (Pingora-shaped) transparent
//! listener and is forwarded upstream (doc 09 NFT-2; doc 12 §2/§2.1/§13.1;
//! D69 graded-core "an e2e proves outbound HTTP(S) arrives at the proxy process
//! and is forwarded upstream").
//!
//! # What this proves, and how it stands in for the live REDIRECT
//!
//! The live kernel `iifname`-REDIRECT cannot be programmed on this host (the
//! nft redirect/nat statement modules are absent for the running kernel —
//! reboot-pending; see `SPIKE-NOTES.md`). So this e2e exercises the FULL proxy
//! datapath — accept → `recover_conn_origin` → `forward` splice → real upstream
//! → response back to the client — over **loopback**, with the recovery seam
//! standing in for the kernel `SO_ORIGINAL_DST` getsockopt:
//!
//! - a real HTTP **upstream origin** on loopback (a one-shot HTTP/1.1 server);
//! - the **transparent listener** binds a loopback "redirect-target" port (the
//!   stand-in for `:18080`), accepts the client connection, resolves
//!   [`ds_tlsproxy::transparent::ConnOrigin`] (the recovered `original_dst` is
//!   the real upstream — exactly what the kernel returns for a redirected
//!   socket; here supplied by a faithful test recovery provider since no live
//!   REDIRECT exists), then runs the production [`ds_tlsproxy::transparent::forward`]
//!   splice between the accepted downstream socket and the upstream connection;
//! - a real HTTP **client** (`std::net`, raw HTTP/1.1) that sends
//!   `GET / HTTP/1.1` and reads the body back.
//!
//! The bytes the client sends arrive at the proxy and are forwarded upstream;
//! the upstream's response is forwarded back. The ONLY piece swapped for the
//! reboot-pending live path is *where the recovered `original_dst` comes from* —
//! the getsockopt vs the test provider — and that swap is exactly the doc 12
//! §2.1 mechanism-agnostic seam (`SocketDigest::original_dst()` ↔ TPROXY ↔ this
//! test provider all produce the same `ConnOrigin`). The actual getsockopt
//! syscall path is separately exercised against a real socket in the unit tests
//! (`socket2_recovery_*`). For the explicit-proxy (`HTTP_PROXY`) variant of this
//! same datapath against the qemu guest on `dstap-0`, see `SPIKE-NOTES.md` §E2.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use ds_contracts::session::SessionRef;
use ds_tlsproxy::transparent::{
    forward, recover_conn_origin, ConnOrigin, OriginalDst, RecoveryError,
};

/// A faithful stand-in for the kernel `SO_ORIGINAL_DST` getsockopt on a genuinely
/// redirected socket: it returns the REAL upstream address (which, on a live
/// REDIRECT, is exactly the pre-DNAT destination the kernel hands back). The unit
/// tests cover the actual syscall + the refuse-on-no-redirect path; this e2e
/// drives the forward datapath end to end with a successful recovery.
struct RedirectedTo(SocketAddr);

impl OriginalDst for RedirectedTo {
    fn original_dst(&self) -> Result<SocketAddr, RecoveryError> {
        Ok(self.0)
    }
}

fn session() -> SessionRef {
    SessionRef::new(
        "11111111-2222-3333-4444-555555555555".into(),
        "host-a".into(),
        0,
        "dstap-0".into(),
    )
}

/// A one-shot HTTP/1.1 origin: accept one connection, read the request headers,
/// answer `200 OK` with a fixed body. Returns its bound address.
fn spawn_http_origin(body: &'static str) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        // read until end of request headers (\r\n\r\n) — a GET has no body.
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = conn.read(&mut byte).unwrap();
            if n == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        conn.write_all(response.as_bytes()).unwrap();
        conn.shutdown(std::net::Shutdown::Write).unwrap();
    });
    (addr, handle)
}

#[test]
fn outbound_http_reaches_the_listener_and_is_forwarded_upstream() {
    const BODY: &str = "hello-from-upstream-origin";

    // 1. the real upstream HTTP origin (what the VM intended to reach).
    let (upstream_addr, origin_handle) = spawn_http_origin(BODY);

    // 2. the transparent listener — a loopback "redirect-target" port standing in
    //    for :18080. A real REDIRECT would point the VM's :80 socket here.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let redirect_target = listener.local_addr().unwrap();

    let proxy_handle = thread::spawn(move || {
        let (downstream, _peer) = listener.accept().unwrap();

        // 3a. recover ConnOrigin at accept time, BEFORE reading a client byte
        //     (D69 invariant 3 ordering). On a live REDIRECT the recovered
        //     original_dst is the real upstream; here the faithful provider
        //     returns it. Recovery FAILURE would refuse here (unit-tested).
        let s = session();
        let recovery = RedirectedTo(upstream_addr);
        let origin: ConnOrigin =
            recover_conn_origin(&s, &recovery).expect("recovery succeeds on a redirected socket");
        assert_eq!(origin.original_dst, upstream_addr);
        assert_eq!(origin.session.tap_name, "dstap-0");

        // 3b. connect upstream to the RECOVERED destination (never a client claim;
        //     invariant 1) and splice (the opaque-tunnel forward, TLS-1 shape).
        let upstream = TcpStream::connect(origin.original_dst).unwrap();
        forward(downstream, upstream).expect("forward splices to EOF")
    });

    // 4. the real HTTP client: dial the redirect-target (as the kernel would have
    //    pointed it), send a raw HTTP/1.1 GET, read the whole response.
    let mut client = TcpStream::connect(redirect_target).unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: upstream.example\r\nConnection: close\r\n\r\n")
        .unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();

    // the request reached the proxy, was forwarded upstream, and the upstream's
    // response came back through the splice to the client.
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected a forwarded 200, got: {response:?}"
    );
    assert!(
        response.ends_with(BODY),
        "expected the upstream body to be forwarded back, got: {response:?}"
    );

    let (n_down_up, n_up_down) = proxy_handle.join().unwrap();
    origin_handle.join().unwrap();
    // bytes flowed both ways through the proxy.
    assert!(n_down_up > 0, "client request bytes reached upstream");
    assert!(n_up_down > 0, "upstream response bytes returned to client");
}
