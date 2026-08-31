//! LIVE redirect e2e — the PRODUCTION `iifname`-PREROUTING form over a REAL veth
//! pair (doc 03 §3; doc 09 NFT-2; D69; the D44 three-keys-agree attribution).
//!
//! # What this proves that the loopback stand-ins do NOT
//!
//! Both `e2e_live_redirect.rs` and `redirect_getsockname_live.rs` program the
//! redirect DNAT in an **`OUTPUT`-hook chain on loopback** — a self-contained
//! stand-in that fires on locally-generated traffic and never crosses an interface.
//! That is enough to validate the *recovery primitive* (`SO_ORIGINAL_DST` reads the
//! pre-DNAT dst) and the *getsockname → /31 → session* signal, but it CANNOT
//! exercise the one thing production actually keys attribution on: the
//! **interface-anchored** match. Production programs the DNAT in a `type nat hook
//! prerouting priority dstnat` chain that matches on **`iifname "dstap-<idx>"`** —
//! the tap the agent VM is attached to, NEVER a source IP (the NFT-2 control, doc
//! 03 §3: addresses can be forged from inside the VM, the attachment point cannot).
//! No `OUTPUT`-hook loopback test ever traverses an ingress interface, so none of
//! them proves the `iifname`-PREROUTING rule matches real ingress traffic and that
//! `SO_ORIGINAL_DST` recovers the pre-DNAT dst on a socket that genuinely transited
//! that production form.
//!
//! This test closes that gap. It builds a REAL veth pair (`dstap-<idx>` on the host
//! side, its peer in a fresh child network namespace standing in for the guest VM),
//! programs the production `iifname "dstap-<idx>" … redirect to :<proxy_port>`
//! PREROUTING rule (the exact shape of `nft/transparent-redirect.nft`), drives a
//! guest connect to a synthetic upstream that genuinely INGRESSES on `dstap-<idx>`,
//! and asserts the production [`Socket2OriginalDst`] recovers the REAL pre-DNAT
//! destination on the accepted socket — the interface-anchored attribution half the
//! loopback OUTPUT-hook variant cannot reach.
//!
//! # The three arms
//!
//! 1. **Positive (v4, `DS_REDIRECT_LIVE`)** — a guest connect over `dstap-<idx>` to a
//!    synthetic upstream is redirected; [`Socket2OriginalDst::v4`] recovers the REAL
//!    pre-DNAT dst, and the redirect rule's `counter` incremented (the rule fired).
//!
//! 2. **Negative iifname control (v4, `DS_REDIRECT_LIVE`)** — the NFT-2/D44
//!    forgery-resistance proof. A SECOND veth (`dstap-<other>`) in a second guest
//!    netns dials the EXACT SAME protected upstream `ip daddr`/`dport`, differing
//!    ONLY in the ingress interface. Because the PREROUTING rule matches
//!    `iifname "dstap-<idx>"` (never the source IP, never merely the destination),
//!    that forgery does NOT match: the redirect `counter` stays put (zero increment),
//!    and a connect that reaches the proxy over the wrong tap recovers
//!    [`RecoveryError::NoOriginalDst`] (the getsockname fallback == the listener) —
//!    so an identical destination from a different attachment point is neither
//!    redirected nor attributable. A direct connect to the proxy that never transited
//!    any redirect must likewise refuse (invariant 3).
//!
//! 3. **v6 sibling (`DS_REDIRECT_LIVE6`)** — the same positive proof over IPv6: an
//!    INET-family `iifname … ip6 daddr fc00::… … redirect` PREROUTING rule and
//!    [`Socket2OriginalDst::v6`] recovery on a genuinely-ingressed v6 socket (doc 12
//!    §2 "IPv6 dormant", D75).
//!
//! # The mechanism (stdlib-only; no FFI, no python/nc/socat dependency)
//!
//! 1. In the outer `unshare -rn` net namespace (which owns `CAP_NET_ADMIN`), create
//!    the veth pair `dstap-<idx>` ⇔ `dsguest-<idx>`.
//! 2. Spawn a HOLDER child — `unshare --net sh -c 'ip link set lo up; sleep …'` — as
//!    a plain `std::process::Command`; its PID names a fresh child net namespace.
//! 3. Move the guest end into the holder's netns (`ip link set … netns <pid>`) and
//!    address both ends, with a default route in the guest ns via the host end so an
//!    off-subnet dial genuinely INGRESSES on the host-side tap.
//! 4. Bind the "proxy" listener on the host end and program the production
//!    `iifname "dstap-<idx>" … redirect to :<proxy_port>` PREROUTING rule.
//! 5. Drive the guest connect by RE-EXECING THIS TEST BINARY inside the holder's
//!    netns (`nsenter -t <pid> -n <current_exe>`) in a tiny env-keyed connector mode
//!    (`DS_REDIRECT_IIFNAME_CONNECT=<ip:port>`) — so the guest packet genuinely
//!    ingresses on the tap and the PREROUTING rule fires. No external network tool
//!    (nc/socat/python) is required.
//! 6. Accept on the host, run the production [`Socket2OriginalDst`] `original_dst()`,
//!    and assert on its output (the recovery arithmetic is NOT duplicated here).
//!
//! Gated behind `DS_REDIRECT_LIVE=1` (v4 arms) / `DS_REDIRECT_LIVE6=1` (v6 arm) AND a
//! net namespace with `CAP_NET_ADMIN` (`unshare -rn`). Without the gate the arms SKIP
//! — so the normal `cargo test` gate stays green and never fabricates a result: no
//! `unshare`, no privileged syscall, no network, no child process. Mirrors the
//! skip-guard shape of `tests/e2e_live_redirect.rs`. Run it live:
//!
//! ```sh
//! cd dataplane
//! unshare -rn bash -c 'DS_REDIRECT_LIVE=1 \
//!   cargo test -p ds-tlsproxy --test redirect_iifname_live --locked --offline -- --nocapture'
//! # the v6 sibling:
//! unshare -rn bash -c 'DS_REDIRECT_LIVE6=1 \
//!   cargo test -p ds-tlsproxy --test redirect_iifname_live --locked --offline -- --nocapture'
//! ```

use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ds_tlsproxy::transparent::{OriginalDst, RecoveryError, Socket2OriginalDst};

/// The env var that, when set to `<ip>:<port>`, puts THIS test binary into
/// "guest connector" mode: it connects once to that address and exits. The parent
/// re-execs itself under `nsenter -t <holder_pid> -n` with this set, so the guest
/// packet genuinely ingresses on the host-side veth `dstap-<idx>`.
const CONNECT_ENV: &str = "DS_REDIRECT_IIFNAME_CONNECT";

/// The per-session index for the v4 positive lane. Drives the tap name
/// (`dstap-<idx>`, the production iifname) and the `10.77.<idx>.0/24` addressing.
const SESSION_IDX: u8 = 88;
/// A SECOND, distinct tap index for the negative iifname control — a different
/// attachment point (`dstap-<other>`) whose guest dials the same protected upstream
/// but must NOT be redirected (the interface, not the source IP or dst, gates it).
const OTHER_IDX: u8 = 89;
/// The per-session index for the v6 sibling lane (`dstap-<idx6>` + `fc00:77:<idx6>::`).
const SESSION_IDX6: u8 = 90;

/// The synthetic v4 upstream the guest dials — the REAL pre-DNAT destination the
/// PREROUTING redirect intercepts and `SO_ORIGINAL_DST` must recover. Off the veth
/// subnet so it is unambiguously "the intended upstream", not a link-local address.
const ORIG_IP: &str = "10.99.7.7";
/// The synthetic v6 upstream (a ULA off the veth `/64`) for the v6 sibling lane.
const ORIG6_IP: &str = "fc00:99::7";
const ORIG_PORT: u16 = 443;

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

/// Best-effort cleanup command (teardown must never panic on a stale/absent object).
fn run_ignore(args: &[&str]) {
    let _ = Command::new(args[0])
        .args(&args[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Run `nsenter -t <pid> -n <args…>` — execute a command inside the holder's netns.
fn nsenter(pid: u32, args: &[&str]) -> Result<(), String> {
    let pid = pid.to_string();
    let mut full = vec!["nsenter", "-t", pid.as_str(), "-n"];
    full.extend_from_slice(args);
    run(&full)
}

/// Feed a ruleset to `nft -f -` in the CURRENT (host) namespace and assert it loaded.
fn nft_load(ruleset: &str) {
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
        "program the iifname-PREROUTING redirect ruleset (nft_redir/nft_nat must be loadable)"
    );
}

/// Read the `packets N` count off the redirect rule by parsing the plain
/// `nft list chain` text (stdlib-only — no serde/JSON dev-dep). The chain holds one
/// `… counter packets N bytes M redirect …` rule; we pull the token after `packets`.
/// `family` is the table's nft family (`ip` for v4, `inet` for the v6 lane).
fn counter_packets(family: &str, table: &str, chain: &str) -> u64 {
    let out = Command::new("nft")
        .args(["list", "chain", family, table, chain])
        .output()
        .expect("nft list chain");
    assert!(
        out.status.success(),
        "nft list chain {family} {table} {chain} failed"
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let after = text.split("counter packets ").nth(1).unwrap_or_else(|| {
        panic!("no `counter packets` in chain {family}/{table}/{chain}:\n{text}")
    });
    after
        .split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("could not parse packet count from: {after:?}"))
}

/// Create the veth pair (`tap` host end — the production iifname — ⇔ `guest_if`),
/// spawn a holder child in a fresh net namespace (its PID names the ns), move the
/// guest end into it, address both ends (`/{prefix}`), and add a default route in the
/// guest ns via the host end so an off-subnet dial genuinely INGRESSES on `tap`.
/// Returns the holder [`Child`] (its PID is the guest-netns handle for `nsenter`).
/// `v6` picks the `ip -6 … nodad` forms. All ops `.expect` — the outer `unshare -rn`
/// namespace is ephemeral, so anything a mid-setup panic leaks dies with the ns.
fn spawn_guest_ns(
    tap: &str,
    guest_if: &str,
    host_ip: &str,
    guest_ip: &str,
    prefix: u32,
    v6: bool,
) -> Child {
    run(&[
        "ip", "link", "add", tap, "type", "veth", "peer", "name", guest_if,
    ])
    .expect("create the dstap-<idx> veth pair (needs CAP_NET_ADMIN)");

    // The HOLDER: a plain child in a fresh net namespace whose PID names that ns. It
    // parks (sleep) with only `lo` up until we move the guest veth in + drive a
    // connect through it. `--net` unshares ONLY the net namespace (no user ns needed
    // — the outer `unshare -rn` already granted CAP_NET_ADMIN here).
    let holder = Command::new("unshare")
        .args(["--net", "sh", "-c", "ip link set lo up; sleep 30"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the guest-netns holder (`unshare --net`)");
    let pid = holder.id();
    // Give the holder a beat to enter its new netns before we move the iface in.
    thread::sleep(Duration::from_millis(200));

    run(&["ip", "link", "set", guest_if, "netns", &pid.to_string()])
        .expect("move the guest veth end into the holder netns");

    let host_cidr = format!("{host_ip}/{prefix}");
    let guest_cidr = format!("{guest_ip}/{prefix}");
    if v6 {
        // `nodad` skips duplicate-address detection on the global ULA so the address
        // is usable immediately (no ~1s DAD wait / flake) — safe on a private veth.
        run(&["ip", "-6", "addr", "add", &host_cidr, "dev", tap, "nodad"])
            .expect("address the host-side veth end (v6)");
    } else {
        run(&["ip", "addr", "add", &host_cidr, "dev", tap])
            .expect("address the host-side veth end");
    }
    run(&["ip", "link", "set", tap, "up"]).expect("bring the host-side veth up");

    if v6 {
        nsenter(
            pid,
            &[
                "ip",
                "-6",
                "addr",
                "add",
                &guest_cidr,
                "dev",
                guest_if,
                "nodad",
            ],
        )
        .expect("address the guest-side veth end (v6)");
    } else {
        nsenter(pid, &["ip", "addr", "add", &guest_cidr, "dev", guest_if])
            .expect("address the guest-side veth end");
    }
    nsenter(pid, &["ip", "link", "set", guest_if, "up"]).expect("bring the guest-side veth up");

    if v6 {
        nsenter(
            pid,
            &["ip", "-6", "route", "add", "default", "via", host_ip],
        )
        .expect("default route in the guest netns via the host veth (v6)");
    } else {
        nsenter(pid, &["ip", "route", "add", "default", "via", host_ip])
            .expect("default route in the guest netns via the host veth");
    }
    holder
}

/// Re-exec THIS test binary as the guest connector inside the holder's netns
/// (`nsenter -t <pid> -n <current_exe>` with `CONNECT_ENV=<target>`), so the SYN
/// genuinely ingresses on the holder's veth. Returns the connector [`Child`].
fn spawn_connector_in_ns(pid: u32, target: &str) -> Child {
    let current_exe = std::env::current_exe().expect("locate this test binary for re-exec");
    Command::new("nsenter")
        .args(["-t", &pid.to_string(), "-n"])
        .arg(&current_exe)
        .env(CONNECT_ENV, target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("re-exec this binary as the guest connector inside the holder netns")
}

/// Disable reverse-path filtering (`rp_filter`) in the CURRENT (host) netns so ARM 2b's
/// cross-interface (wrong-tap → proxy) connect is accepted under the weak-host model
/// REGARDLESS of the host/kernel's default `rp_filter` sysctl. A fresh netns *usually*
/// defaults `all`/`default` `rp_filter` to 0, but that default is NOT guaranteed across
/// kernels or distro `sysctl.d` drops that seed a new netns — and a non-zero
/// `all.rp_filter` silently drops the wrong-tap packet (it arrives for a local addr on
/// `dstap-<idx>` but ingresses `dstap-<other>`), turning ARM 2b into an opaque 5s
/// accept-deadline panic. The effective per-iface value is `max(all, iface)`, so we zero
/// `all`, `default`, AND each named tap. Best-effort per key: a per-iface knob may be
/// absent (writes go to this ephemeral netns's /proc; anything left behind dies with it).
fn disable_rp_filter(taps: &[&str]) {
    let mut keys: Vec<String> = vec!["all".to_string(), "default".to_string()];
    keys.extend(taps.iter().map(|t| (*t).to_string()));
    for key in keys {
        let path = format!("/proc/sys/net/ipv4/conf/{key}/rp_filter");
        // Best-effort: the load-bearing key is `all`; the route probe below verifies the
        // net effect (a working cross-interface path) before we block on accept.
        let _ = std::fs::write(&path, b"0");
    }
}

/// Pre-connect route ASSERTION for ARM 2b: verify the wrong-tap guest can actually
/// resolve a route to `dst` (the proxy addr, which lives on the OTHER tap) BEFORE we
/// drive the connect and block on a 5s accept. If cross-interface routing is broken
/// (no default route in the guest ns, or an unresolvable next hop), `ip route get`
/// fails and we panic with a diagnostic that NAMES the real cause — instead of the
/// opaque "no connection accepted within 5s" deadline the raw connect would otherwise
/// hit. Runs inside the guest netns via `nsenter`.
fn assert_guest_route_to(pid: u32, dst: &str) {
    let out = Command::new("nsenter")
        .args(["-t", &pid.to_string(), "-n", "ip", "route", "get", dst])
        .output()
        .expect("spawn `ip route get` route probe in the guest netns");
    assert!(
        out.status.success(),
        "ARM 2b route probe FAILED: the wrong-tap guest netns cannot resolve a route to the \
         proxy addr {dst} — `ip route get` said: {}. This arm needs the guest's default route \
         (via its own tap) plus a host that accepts the cross-interface packet for a local addr \
         (weak host model; rp_filter=0, set explicitly by this test). Fix the routing/rp_filter \
         setup rather than waiting out a 5s accept-deadline panic.",
        String::from_utf8_lossy(&out.stderr).trim()
    );
}

/// Accept one connection within `dur` or PANIC (fail loud — never hang the live
/// lane). Polls a temporarily-nonblocking listener, then restores blocking mode so
/// later accepts behave normally.
fn accept_within(listener: &TcpListener, dur: Duration) -> TcpStream {
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let deadline = Instant::now() + dur;
    let sock = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "no connection accepted within {dur:?} — the redirected/ingressed connect \
                     never arrived on the proxy listener"
                );
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept failed: {e}"),
        }
    };
    listener
        .set_nonblocking(false)
        .expect("restore listener blocking");
    sock
}

/// Tear down every nft table / veth / holder built by an arm. Best-effort; never
/// panics (a stale/absent object is fine).
fn teardown(family: &str, table: &str, taps: &[&str], holders: &mut [Child]) {
    run_ignore(&["nft", "delete", "table", family, table]);
    // Deleting the host end of a veth pair removes both ends.
    for tap in taps {
        run_ignore(&["ip", "link", "del", tap]);
    }
    for holder in holders.iter_mut() {
        let _ = holder.kill();
        let _ = holder.wait();
    }
}

/// If we were re-exec'd in "guest connector" mode (`CONNECT_ENV` set), perform the
/// single ingress connect and EXIT the process — so no `#[test]` body runs in the
/// connector child. `Once` guards against the (parallel-thread) case where more than
/// one test function reaches this: exactly one connect happens, then the process
/// exits. Called first thing by BOTH live tests, so it fires regardless of which
/// test the harness schedules first.
fn maybe_run_connector() {
    if let Ok(target) = std::env::var(CONNECT_ENV) {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| guest_connect_once(&target));
        std::process::exit(0);
    }
}

#[test]
fn live_iifname_prerouting_redirect_recovers_real_original_dst() {
    maybe_run_connector();

    if std::env::var("DS_REDIRECT_LIVE").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP live_iifname_prerouting_redirect_recovers_real_original_dst: set \
             DS_REDIRECT_LIVE=1 and run inside `unshare -rn` to exercise the PRODUCTION \
             iifname-PREROUTING redirect over a real veth pair (the interface-anchored D44 \
             attribution the loopback OUTPUT-hook stand-ins cannot reach) + SO_ORIGINAL_DST \
             recovery + the NFT-2 forgery-resistance negative control (a second tap dialing the \
             same upstream is NOT redirected). Skipping: no unshare, no privileged syscall, no \
             network, no child process."
        );
        return;
    }

    let tap = format!("dstap-{SESSION_IDX}");
    let guest_if = format!("dsguest-{SESSION_IDX}");
    let host_ip = format!("10.77.{SESSION_IDX}.0");
    let guest_ip = format!("10.77.{SESSION_IDX}.1");
    // The SECOND tap (the negative iifname control): a different attachment point.
    let tap2 = format!("dstap-{OTHER_IDX}");
    let guest_if2 = format!("dsguest-{OTHER_IDX}");
    let host_ip2 = format!("10.77.{OTHER_IDX}.0");
    let guest_ip2 = format!("10.77.{OTHER_IDX}.1");
    let table = "ds_iifname_redir";
    let chain = "pre";

    // A fresh net namespace has `lo` DOWN; bring it up (the proxy binds a host-side
    // veth addr, but a sane `lo` keeps the ns well-formed).
    run(&["ip", "link", "set", "lo", "up"])
        .expect("bring lo up — run under `unshare -rn` so the ns has CAP_NET_ADMIN");

    // Bring up BOTH taps + their guest netns holders BEFORE the fallible body, so
    // teardown always has both holders to reap.
    let holder1 = spawn_guest_ns(&tap, &guest_if, &host_ip, &guest_ip, 24, false);
    let holder2 = spawn_guest_ns(&tap2, &guest_if2, &host_ip2, &guest_ip2, 24, false);
    let holder1_pid = holder1.id();
    let holder2_pid = holder2.id();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The "proxy": a listener on the FIRST tap's host-side veth addr — the
        // REDIRECT target, exactly as the production transparent listener binds.
        let listener = TcpListener::bind(SocketAddrV4::new(host_ip.parse().unwrap(), 0))
            .expect("bind the proxy listener on the host-side veth addr");
        let proxy_addr: SocketAddr = listener.local_addr().unwrap();
        let proxy_port = proxy_addr.port();

        // Program the PRODUCTION iifname-PREROUTING redirect with a `counter`: a
        // `type nat hook prerouting priority dstnat` chain matching on the INTERFACE
        // the guest is attached to (`iifname "dstap-<idx>"`, NEVER a source IP — the
        // NFT-2 control, doc 03 §3), the synthetic upstream dst, and the dport. The
        // counter lets the negative control PROVE the rule did not fire for the second
        // tap. This is the exact shape of `nft/transparent-redirect.nft`.
        let ruleset = format!(
            "table ip {table} {{\n  \
               chain {chain} {{\n    \
                 type nat hook prerouting priority dstnat; policy accept;\n    \
                 iifname \"{tap}\" ip daddr {ORIG_IP} tcp dport {ORIG_PORT} \
                 counter redirect to :{proxy_port} comment \"NFT-2: iifname-anchored redirect\"\n  \
               }}\n}}\n"
        );
        nft_load(&ruleset);

        let redirect_before = counter_packets("ip", table, chain);

        // ── ARM 1 · POSITIVE: a guest connect over dstap-<idx> is redirected ────────
        let mut connector = spawn_connector_in_ns(holder1_pid, &format!("{ORIG_IP}:{ORIG_PORT}"));
        let accepted = accept_within(&listener, Duration::from_secs(5));

        // THE PROOF: on a socket that genuinely transited the production
        // iifname-PREROUTING DNAT, the production Socket2OriginalDst recovers the REAL
        // pre-DNAT dst (the synthetic upstream) — never the proxy's own bind addr.
        let recovered = Socket2OriginalDst::v4(&accepted, proxy_addr)
            .original_dst()
            .expect("SO_ORIGINAL_DST recovery SUCCEEDS on the iifname-redirected socket");
        let expected: SocketAddr = format!("{ORIG_IP}:{ORIG_PORT}").parse().unwrap();
        assert_eq!(
            recovered, expected,
            "the production iifname-PREROUTING redirect must preserve the pre-DNAT dst \
             ({expected}) for SO_ORIGINAL_DST; got {recovered}"
        );
        assert_ne!(
            recovered, proxy_addr,
            "recovered dst must not be the proxy's own bind addr (the getsockname fallback)"
        );
        let _ = connector.wait();

        let redirect_after_positive = counter_packets("ip", table, chain);
        assert!(
            redirect_after_positive > redirect_before,
            "the positive redirect must increment the rule counter (before={redirect_before}, \
             after={redirect_after_positive}) — proving the iifname rule actually fired"
        );

        // ── ARM 2a · NEGATIVE iifname FORGERY: the SAME upstream over the WRONG tap ──
        // A guest on dstap-<other> dials the EXACT protected upstream (same ip daddr +
        // dport), differing ONLY in the ingress interface. The PREROUTING rule matches
        // `iifname "dstap-<idx>"`, so this forgery does NOT match — the redirect
        // counter must NOT move. This is the NFT-2/D44 forgery-resistance invariant:
        // an identical destination from a different attachment point is not redirected
        // (addresses can be forged from inside a VM; the attachment point cannot).
        let mut forgery = spawn_connector_in_ns(holder2_pid, &format!("{ORIG_IP}:{ORIG_PORT}"));
        // The SYN ingresses dstap-<other> essentially at once; give it a beat, then
        // read the counter. The forgery connect will not establish (the upstream is
        // unreachable off the wrong tap), so we do NOT accept it — we assert the rule
        // never counted it, then reap the connector.
        thread::sleep(Duration::from_millis(400));
        let redirect_after_forgery = counter_packets("ip", table, chain);
        assert_eq!(
            redirect_after_forgery, redirect_after_positive,
            "an identical-destination dial over the WRONG tap (dstap-{OTHER_IDX}) must NOT match \
             the `iifname \"{tap}\"` redirect — counter moved from {redirect_after_positive} to \
             {redirect_after_forgery}; attribution is interface-anchored, never dst/source"
        );
        let _ = forgery.kill();
        let _ = forgery.wait();

        // ── ARM 2b · NEGATIVE recovery: a wrong-tap connect that DOES reach the proxy
        //    must still REFUSE. The second-tap guest connects DIRECTLY to the proxy
        //    addr (reachable cross-interface via the weak host model); it never
        //    transited a redirect, so SO_ORIGINAL_DST falls back to getsockname ==
        //    the listener addr → NoOriginalDst (invariant 3), and the redirect counter
        //    stays put (its daddr is the proxy, not the protected upstream).
        //
        // HARDENING: the cross-interface reachability this arm depends on is only the
        // weak-host model when `rp_filter` is 0. Set it explicitly (do not rely on the
        // fresh-netns default), then route-probe the guest→proxy path so a broken setup
        // fails FAST with a clear diagnostic instead of an opaque 5s accept-deadline panic.
        disable_rp_filter(&[&tap, &tap2]);
        assert_guest_route_to(holder2_pid, &proxy_addr.ip().to_string());
        let mut wrong_tap = spawn_connector_in_ns(holder2_pid, &proxy_addr.to_string());
        let wrong_sock = accept_within(&listener, Duration::from_secs(5));
        let refused_wrong = Socket2OriginalDst::v4(&wrong_sock, proxy_addr).original_dst();
        assert!(
            matches!(refused_wrong, Err(RecoveryError::NoOriginalDst)),
            "a connect that reached the proxy over the WRONG tap (never redirected) must refuse \
             as NoOriginalDst, got {refused_wrong:?}"
        );
        let _ = wrong_tap.wait();
        let redirect_after_wrongtap = counter_packets("ip", table, chain);
        assert_eq!(
            redirect_after_wrongtap, redirect_after_positive,
            "a direct-to-proxy connect must not touch the redirect counter"
        );

        // ── ARM 2c · NEGATIVE control (invariant 3): a DIRECT connect to the proxy in
        //    the host namespace (never redirected, never transited the iifname rule)
        //    must REFUSE — the original fail-closed posture.
        let direct = thread::spawn(move || {
            let _ = TcpStream::connect(proxy_addr); // straight to the proxy; no DNAT transits
            thread::sleep(Duration::from_millis(50));
        });
        let direct_sock = accept_within(&listener, Duration::from_secs(5));
        let refused = Socket2OriginalDst::v4(&direct_sock, proxy_addr).original_dst();
        assert!(
            matches!(refused, Err(RecoveryError::NoOriginalDst)),
            "a non-redirected direct connect must refuse (fallback == listener addr), got {refused:?}"
        );
        direct.join().unwrap();

        recovered
    }));

    teardown("ip", table, &[&tap, &tap2], &mut [holder1, holder2]);

    match result {
        Ok(recovered) => eprintln!(
            "LIVE iifname-PREROUTING redirect e2e PASS: recovered {recovered} on a socket that \
             genuinely ingressed on {tap} and transited the production `iifname \"{tap}\" … \
             redirect` PREROUTING rule; an identical dial over {tap2} did NOT move the redirect \
             counter and refused as NoOriginalDst; a direct (non-redirected) connect refused too."
        ),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn live_v6_iifname_prerouting_redirect_recovers_real_original_dst() {
    maybe_run_connector();

    if std::env::var("DS_REDIRECT_LIVE6").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP live_v6_iifname_prerouting_redirect_recovers_real_original_dst: set \
             DS_REDIRECT_LIVE6=1 and run inside `unshare -rn` to exercise the v6 sibling of the \
             production iifname-PREROUTING redirect — an INET-family `iifname … ip6 daddr fc00::… \
             redirect` rule + Socket2OriginalDst::v6 recovery on a genuinely-ingressed v6 socket \
             (doc 12 §2 IPv6-dormant, D75). Skipping: no unshare, no privileged syscall, no \
             network, no child process."
        );
        return;
    }

    let tap = format!("dstap-{SESSION_IDX6}");
    let guest_if = format!("dsguest-{SESSION_IDX6}");
    let host_ip = format!("fc00:77:{SESSION_IDX6}::a");
    let guest_ip = format!("fc00:77:{SESSION_IDX6}::b");
    let table = "ds_iifname_redir6";
    let chain = "pre";

    run(&["ip", "link", "set", "lo", "up"])
        .expect("bring lo up — run under `unshare -rn` so the ns has CAP_NET_ADMIN");

    let holder = spawn_guest_ns(&tap, &guest_if, &host_ip, &guest_ip, 64, true);
    let holder_pid = holder.id();
    // A short settle for the guest's link-local NDP so the first SYN resolves the
    // host next-hop without a retransmit stall.
    thread::sleep(Duration::from_millis(300));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The v6 "proxy": a listener on the host-side veth's global ULA — the REDIRECT
        // target address the incoming interface's address selection lands on.
        let listener = TcpListener::bind(SocketAddrV6::new(host_ip.parse().unwrap(), 0, 0, 0))
            .expect("bind the v6 proxy listener on the host-side veth addr");
        let proxy_addr: SocketAddr = listener.local_addr().unwrap();
        let proxy_port = proxy_addr.port();

        // The INET-family (dual-stack) iifname-PREROUTING redirect: identical shape to
        // the v4 rule but matching `ip6 daddr`. `redirect` in the inet family maps the
        // v6 destination to the incoming interface's address:proxy_port; the pre-DNAT
        // v6 dst is preserved for IP6T_SO_ORIGINAL_DST.
        let ruleset = format!(
            "table inet {table} {{\n  \
               chain {chain} {{\n    \
                 type nat hook prerouting priority dstnat; policy accept;\n    \
                 iifname \"{tap}\" ip6 daddr {ORIG6_IP} tcp dport {ORIG_PORT} \
                 counter redirect to :{proxy_port} comment \"NFT-2: v6 iifname-anchored redirect\"\n  \
               }}\n}}\n"
        );
        nft_load(&ruleset);

        let redirect_before = counter_packets("inet", table, chain);

        // Drive a guest v6 connect (bracketed target) that genuinely ingresses on tap.
        let mut connector = spawn_connector_in_ns(holder_pid, &format!("[{ORIG6_IP}]:{ORIG_PORT}"));
        let accepted = accept_within(&listener, Duration::from_secs(5));

        // THE PROOF: Socket2OriginalDst::v6 recovers the REAL pre-DNAT v6 dst.
        let recovered = Socket2OriginalDst::v6(&accepted, proxy_addr)
            .original_dst()
            .expect("IP6T_SO_ORIGINAL_DST recovery SUCCEEDS on the v6 iifname-redirected socket");
        let expected: SocketAddr = format!("[{ORIG6_IP}]:{ORIG_PORT}").parse().unwrap();
        assert_eq!(
            recovered, expected,
            "the v6 iifname-PREROUTING redirect must preserve the pre-DNAT v6 dst ({expected}) \
             for IP6T_SO_ORIGINAL_DST; got {recovered}"
        );
        assert_ne!(
            recovered, proxy_addr,
            "recovered v6 dst must not be the proxy's own bind addr (the getsockname fallback)"
        );
        let _ = connector.wait();

        let redirect_after = counter_packets("inet", table, chain);
        assert!(
            redirect_after > redirect_before,
            "the v6 redirect must increment the rule counter (before={redirect_before}, \
             after={redirect_after}) — proving the inet-family iifname rule fired"
        );

        recovered
    }));

    teardown("inet", table, &[&tap], &mut [holder]);

    match result {
        Ok(recovered) => eprintln!(
            "LIVE v6 iifname-PREROUTING redirect e2e PASS: recovered {recovered} on a v6 socket \
             that genuinely ingressed on {tap} and transited the inet-family `iifname \"{tap}\" \
             ip6 daddr {ORIG6_IP} … redirect` PREROUTING rule (Socket2OriginalDst::v6)."
        ),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Guest-connector mode body: connect once to `<ip:port>` (the synthetic upstream, or
/// the proxy addr for a wrong-tap negative) and hold briefly so the parent can accept
/// and recover before the socket closes. Runs inside the holder's netns via the
/// parent's `nsenter … <this binary>` re-exec.
fn guest_connect_once(target: &str) {
    match TcpStream::connect(target) {
        Ok(mut s) => {
            // A single byte so the SYN definitely carries payload-bearing follow-up;
            // the accept + SO_ORIGINAL_DST read only needs the connection established.
            let _ = s.write_all(b"x");
            thread::sleep(Duration::from_millis(300));
        }
        Err(e) => {
            // Print to stderr for a live-debug run; the parent's accept timeout is the
            // real failure signal, so a non-zero exit here is not separately asserted.
            eprintln!("guest connector: connect to {target} failed: {e}");
        }
    }
}
