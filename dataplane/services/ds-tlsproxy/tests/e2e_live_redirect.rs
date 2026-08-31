//! LIVE redirect e2e — `SO_ORIGINAL_DST` recovery on a GENUINELY redirected socket.
//!
//! This is the SPIKE-NOTES.md §E1 / §2.1 demo that was "reboot-pending": it became
//! runnable once the running kernel can program the nft `redirect` statement again
//! (the `nft_redir`/`nft_nat` modules are present — see
//! `nft/validate-transparent-redirect.sh` check 3). It proves the one case the
//! offline unit tests cannot reach: on a socket that ACTUALLY transited a REDIRECT
//! DNAT, the production [`Socket2OriginalDst`] getsockopt recovers the REAL pre-DNAT
//! destination — not the `getsockname()` fallback a non-redirected socket returns.
//!
//! The DNAT mechanism (and the conntrack-backed `SO_ORIGINAL_DST` read it feeds) is
//! identical whether the redirect fired in an OUTPUT hook on loopback (what this
//! self-contained test uses) or in the production iifname-PREROUTING form on a tap
//! (whose rule is proven to LOAD by `nft/validate-transparent-redirect.sh`). What is
//! being validated here is *the recovery on a truly-redirected socket*, not which
//! hook performed the DNAT.
//!
//! Gated behind `DS_REDIRECT_LIVE=1` AND a net namespace with `CAP_NET_ADMIN`.
//! Without the env var it SKIPS (so the normal `cargo test` gate stays green and
//! never fabricates a result). Run it live:
//!
//! ```sh
//! cd dataplane
//! unshare -rn bash -c 'DS_REDIRECT_LIVE=1 \
//!   cargo test -p ds-tlsproxy --test e2e_live_redirect --locked --offline -- --nocapture'
//! ```

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use ds_tlsproxy::transparent::{OriginalDst, RecoveryError, Socket2OriginalDst};

/// A loopback address the test redirects; `:80` on it never has a real listener —
/// the redirect intercepts it and conntrack preserves it as the original dst.
const ORIG_IP: &str = "127.0.0.9";
const ORIG_PORT: u16 = 80;

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
fn live_redirect_recovers_real_original_dst() {
    if std::env::var("DS_REDIRECT_LIVE").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP live_redirect_recovers_real_original_dst: set DS_REDIRECT_LIVE=1 and run inside \
             `unshare -rn` to exercise the live REDIRECT + SO_ORIGINAL_DST recovery path"
        );
        return;
    }

    // A fresh net namespace has `lo` DOWN; bring it up so 127.0.0.0/8 is reachable.
    run(&["ip", "link", "set", "lo", "up"])
        .expect("bring lo up — run under `unshare -rn` so the ns has CAP_NET_ADMIN");

    // The "proxy": a listener on an ephemeral loopback port — the REDIRECT target.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy listener");
    let proxy_addr: SocketAddr = listener.local_addr().unwrap();
    let proxy_port = proxy_addr.port();

    // Program an OUTPUT-hook redirect: a connection to 127.0.0.9:80 is DNAT'd to the
    // proxy port on loopback, while the kernel records 127.0.0.9:80 as the original
    // destination — exactly what SO_ORIGINAL_DST reads back on the accepted socket.
    let ruleset = format!(
        "table ip ds_e2e_redir {{\n  \
           chain out {{\n    \
             type nat hook output priority -100; policy accept;\n    \
             ip daddr {ORIG_IP} tcp dport {ORIG_PORT} redirect to :{proxy_port}\n  \
           }}\n}}\n"
    );
    let mut nft = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn nft");
    nft.stdin
        .take()
        .unwrap()
        .write_all(ruleset.as_bytes())
        .unwrap();
    assert!(
        nft.wait().unwrap().success(),
        "program the redirect ruleset (nft_redir/nft_nat must be loadable on this kernel)"
    );

    // ── POSITIVE: a genuinely redirected connection recovers the real pre-DNAT dst ──
    let client = thread::spawn(move || {
        // Connect to the ORIGINAL destination; the OUTPUT redirect rewrites it to the
        // proxy port, but conntrack preserves 127.0.0.9:80.
        let mut s = TcpStream::connect((ORIG_IP, ORIG_PORT)).expect("client connect (redirected)");
        let _ = s.write_all(b"GET / HTTP/1.0\r\n\r\n");
        thread::sleep(Duration::from_millis(50));
    });

    let (accepted, _peer) = listener.accept().expect("accept the redirected connection");

    // THE PROOF: the production recovery primitive reads SO_ORIGINAL_DST on the
    // genuinely-redirected socket and returns the REAL pre-DNAT dst — never the
    // listener's own bind address (the getsockname fallback, which is refused).
    let recovered = Socket2OriginalDst::v4(&accepted, proxy_addr)
        .original_dst()
        .expect("recovery SUCCEEDS on a truly-redirected socket");
    let expected: SocketAddr = format!("{ORIG_IP}:{ORIG_PORT}").parse().unwrap();
    assert_eq!(
        recovered, expected,
        "SO_ORIGINAL_DST must recover the pre-DNAT destination ({expected}), got {recovered}"
    );
    assert_ne!(
        recovered, proxy_addr,
        "recovered dst must not be the proxy's own bind addr (the getsockname fallback)"
    );
    client.join().unwrap();

    // ── NEGATIVE control: a DIRECT connect (never redirected) refuses (invariant 3) ──
    let direct = thread::spawn(move || {
        let _ = TcpStream::connect(proxy_addr); // dst is the proxy itself; no redirect transits
        thread::sleep(Duration::from_millis(50));
    });
    let (direct_sock, _) = listener.accept().expect("accept the direct connection");
    let refused = Socket2OriginalDst::v4(&direct_sock, proxy_addr).original_dst();
    assert!(
        matches!(refused, Err(RecoveryError::NoOriginalDst)),
        "a non-redirected direct connect must refuse (fallback == listener addr), got {refused:?}"
    );
    direct.join().unwrap();

    let _ = run(&["nft", "delete", "table", "ip", "ds_e2e_redir"]);
    eprintln!(
        "LIVE REDIRECT e2e PASS: recovered {recovered} on a redirected socket; \
         direct (non-redirected) connect refused as NoOriginalDst."
    );
}
