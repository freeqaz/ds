//! LIVE redirect e2e — `getsockname()` on a REDIRECT'd accepted socket == the
//! per-session `/31` host-side gateway (OQ1/D66; doc 12 §2.1 invariant 2, §2.2,
//! §13.1).
//!
//! # What this proves that `e2e_live_redirect.rs` does NOT
//!
//! `e2e_live_redirect.rs` exercises the **`SO_ORIGINAL_DST`** signal — a *conntrack*
//! read of the pre-DNAT *destination* (the real upstream the VM intended,
//! [`transparent::ConnOrigin::original_dst`], invariant 1). That is one of the two
//! kernel facts the transparent path resolves at accept time.
//!
//! This test closes the OTHER, independent kernel signal: after a REDIRECT DNATs a
//! guest-bound connection to the proxy's per-session loopback listener, the accepted
//! socket's **`getsockname()`** returns the listener's own post-NAT **local address**
//! — the per-session `/31` host-side gateway `10.77.<idx>.0` (RFC 3021). That local
//! address is what [`transparent::session_from_local_addr`] consumes to recover the
//! interface-anchored `session` (invariant 2): `host_session_index` = the third
//! octet, `tap_name` = `dstap-<idx>`. `SO_ORIGINAL_DST` never touches this path
//! (it reads the *destination*, not the socket's *local* address), so no existing
//! test — offline or live — exercises the `getsockname() -> /31 -> session` recovery
//! against a genuinely-redirected socket. This does.
//!
//! # The mechanism (self-contained, loopback-only)
//!
//! 1. Bring `lo` up in the fresh net namespace and add the per-session host-side
//!    gateway `10.77.<idx>.0/31` to it — so a listener can BIND that address and
//!    `getsockname()` can return it.
//! 2. Bind the "proxy" listener on `10.77.<idx>.0:0` (the per-session gateway, an
//!    ephemeral port) — the REDIRECT target, exactly as the production transparent
//!    listener binds the per-session gateway (§13.1).
//! 3. Program an OUTPUT-hook DNAT: a connection to the guest side of the `/31`
//!    (`10.77.<idx>.1`, a synthetic guest-bound dst) is DNAT'd EXPLICITLY to the
//!    per-session gateway `10.77.<idx>.0:<proxy_port>` (the doc 12 §13.1 per-session
//!    `dnat to <host-side-ip>:<port>` form, so the post-NAT local address is
//!    deterministically the gateway `.0`). The kernel then reports that gateway as
//!    the accepted socket's LOCAL address via `getsockname()`.
//! 4. Accept the redirected connection, read `accepted.local_addr()`
//!    (`getsockname()`), and assert (a) its IP == the `/31` gateway `.0`, and
//!    (b) the REAL [`transparent::session_from_local_addr`] recovers
//!    `host_session_index == <idx>` AND `tap_name == dstap-<idx>`.
//! 5. NEGATIVE control: a local address that is NOT a per-session `/31`
//!    (loopback `127.0.0.1`) does not resolve to a session (`None`).
//!
//! The `getsockname()` -> `/31` -> `session` arithmetic is NOT duplicated here — the
//! test calls the production [`transparent::session_from_local_addr`] and asserts on
//! its output, so a change to that arithmetic is caught by this live proof.
//!
//! Gated behind `DS_REDIRECT_LIVE=1` AND a net namespace with `CAP_NET_ADMIN`.
//! Without the env var it SKIPS (so the normal `cargo test` gate stays green and
//! never fabricates a result — no `unshare`, no privileged syscall, no network).
//! Run it live:
//!
//! ```sh
//! cd dataplane
//! unshare -rn bash -c 'DS_REDIRECT_LIVE=1 \
//!   cargo test -p ds-tlsproxy --test redirect_getsockname_live --locked --offline -- --nocapture'
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use ds_tlsproxy::transparent::session_from_local_addr;

/// The per-session `/31` index used for the live rehearsal. Any value in `1..=255`
/// works; `77` is a distinctive, valid third octet (it is NOT the base prefix's
/// second octet — the derivation reads the THIRD octet as the index).
const SESSION_IDX: u8 = 77;

fn run(args: &[&str]) -> Result<(), String> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| format!("spawn {args:?}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[test]
fn live_redirect_getsockname_recovers_the_session_31_gateway() {
    if std::env::var("DS_REDIRECT_LIVE").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP live_redirect_getsockname_recovers_the_session_31_gateway: set \
             DS_REDIRECT_LIVE=1 and run inside `unshare -rn` to exercise the live REDIRECT + \
             getsockname() -> per-session /31 gateway -> session recovery path (the OQ1/D66 \
             signal SO_ORIGINAL_DST does not exercise). Skipping: no unshare, no privileged \
             syscall, no network performed."
        );
        return;
    }

    // The per-session /31 host-side gateway (.0) and guest side (.1), RFC 3021.
    let gateway = Ipv4Addr::new(10, 77, SESSION_IDX, 0);
    let guest = Ipv4Addr::new(10, 77, SESSION_IDX, 1);

    // A fresh net namespace has `lo` DOWN; bring it up so 127.0.0.0/8 + added
    // addresses are reachable.
    run(&["ip", "link", "set", "lo", "up"])
        .expect("bring lo up — run under `unshare -rn` so the ns has CAP_NET_ADMIN");
    // Add the per-session /31 host-side gateway to `lo` so the proxy can BIND it and
    // `getsockname()` can return it. The guest half (.1) rides the same /31.
    run(&["ip", "addr", "add", &format!("{gateway}/31"), "dev", "lo"])
        .expect("add the per-session /31 gateway to lo (needs CAP_NET_ADMIN)");

    // The "proxy": a listener bound on the per-session GATEWAY address (the REDIRECT
    // target, exactly as the production transparent listener binds the per-session
    // gateway — §13.1). getsockname() on the accepted socket returns THIS address.
    let listener = TcpListener::bind(SocketAddrV4::new(gateway, 0))
        .expect("bind proxy listener on the per-session /31 gateway");
    let proxy_addr: SocketAddr = listener.local_addr().unwrap();
    let proxy_port = proxy_addr.port();

    // Program an OUTPUT-hook DNAT: a connection to the GUEST side of the /31
    // (10.77.<idx>.1:443, a synthetic guest-bound dst) is DNAT'd EXPLICITLY to the
    // per-session GATEWAY address 10.77.<idx>.0:<proxy_port>. After the DNAT the
    // accepted socket's local address is that gateway — which getsockname() reports.
    // We use the explicit `dnat to <host-side-ip>:<port>` form (doc 12 §13.1's
    // per-session variant), NOT the address-less `redirect to :<port>`, so the
    // post-NAT local address is DETERMINISTICALLY the gateway .0 rather than left to
    // REDIRECT's own local-address selection — the getsockname() -> /31 signal this
    // test asserts on. This mirrors the production transparent-443 attribution shape
    // (doc 12 §2.1 invariant 2, §2.2, §13.1 / doc 03 §3 / doc 09 NFT-2); the OUTPUT
    // hook is the self-contained loopback stand-in for the iifname-PREROUTING form
    // (identical DNAT mechanism, per e2e_live_redirect.rs).
    let guest_port: u16 = 443;
    let ruleset = format!(
        "table ip ds_e2e_getsockname {{\n  \
           chain out {{\n    \
             type nat hook output priority -100; policy accept;\n    \
             ip daddr {guest} tcp dport {guest_port} dnat to {gateway}:{proxy_port}\n  \
           }}\n}}\n"
    );
    let mut nft = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn nft");
    {
        use std::io::Write as _;
        nft.stdin
            .take()
            .unwrap()
            .write_all(ruleset.as_bytes())
            .unwrap();
    }
    assert!(
        nft.wait().unwrap().success(),
        "program the redirect ruleset (nft_redir/nft_nat must be loadable on this kernel)"
    );

    // ── POSITIVE: getsockname() on the redirected socket == the per-session gateway ──
    let client = thread::spawn(move || {
        // Connect to the GUEST side of the /31; the OUTPUT redirect DNATs it to the
        // proxy port on the gateway address.
        let mut s = TcpStream::connect(SocketAddrV4::new(guest, guest_port))
            .expect("client connect (redirected to the per-session gateway)");
        use std::io::Write as _;
        let _ = s.write_all(b"GET / HTTP/1.0\r\n\r\n");
        thread::sleep(Duration::from_millis(50));
    });

    let (accepted, _peer) = listener.accept().expect("accept the redirected connection");

    // THE PROOF (a): getsockname() on the accepted socket is the per-session /31
    // host-side gateway .0 — the local-address signal invariant 2 keys the session
    // on (NOT SO_ORIGINAL_DST, which is the destination signal).
    let local = accepted
        .local_addr()
        .expect("getsockname() on the accepted redirected socket");
    assert_eq!(
        local.ip(),
        IpAddr::V4(gateway),
        "getsockname() must return the per-session /31 host-side gateway {gateway}, got {}",
        local.ip()
    );

    // THE PROOF (b): the REAL production derivation recovers the session from that
    // local address — host_session_index == the /31 third octet, tap_name ==
    // dstap-<idx>. The arithmetic is NOT duplicated here; a change to
    // session_from_local_addr is caught by this live assertion.
    let session = session_from_local_addr(local)
        .expect("session_from_local_addr recovers a session from the per-session /31 gateway");
    assert_eq!(
        session.host_session_index,
        u32::from(SESSION_IDX),
        "host_session_index is the /31 third octet ({SESSION_IDX})"
    );
    assert_eq!(
        session.tap_name,
        format!("dstap-{SESSION_IDX}"),
        "tap_name is the authoritative dstap-<idx> join key"
    );
    client.join().unwrap();

    // ── NEGATIVE control: a non-/31 local addr does NOT resolve to a session ──────
    // A loopback local address (127.0.0.1) is not the per-session 10.77.x.y shape —
    // the production derivation degrades to None (the caller then falls back to the
    // prior unmarked best-effort connect; the D76 mark only ADDS, never gates). This
    // must hold on the SAME live path, so a redirect that lands a socket on a
    // non-session local address is never mis-attributed to a session.
    let non_31: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, proxy_port));
    assert!(
        session_from_local_addr(non_31).is_none(),
        "a non-/31 local address ({non_31}) must NOT resolve to a session"
    );

    let _ = run(&["nft", "delete", "table", "ip", "ds_e2e_getsockname"]);
    let _ = run(&["ip", "addr", "del", &format!("{gateway}/31"), "dev", "lo"]);
    eprintln!(
        "LIVE REDIRECT getsockname e2e PASS: getsockname() == {gateway} on the redirected \
         socket; session_from_local_addr recovered index={SESSION_IDX} tap=dstap-{SESSION_IDX}; \
         a non-/31 local addr resolved to no session."
    );
}
