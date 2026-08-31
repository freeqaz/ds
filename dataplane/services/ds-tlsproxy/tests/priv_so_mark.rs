//! PRIVILEGED SO_MARK harness — the LIVE half of the D76 upstream-leg mark
//! (`compose(Leg::TlsproxyUpstream, idx)` under `DS_MARK_MASK`, doc 12 §4.2 /
//! doc 14 §5 / D76 Stage-3 OUTPUT).
//!
//! The framework-agnostic value/call-site is already unit-tested with a recording
//! setter (no syscall) in `src/lib.rs`, and the in-crate `main.rs` test drives the
//! *best-effort* contract over a real socket (asserting the syscall NEVER aborts the
//! connect — but tolerating the `EPERM` an unprivileged sandbox returns). What NO
//! offline test can reach is the one thing production actually depends on: that on a
//! kernel/process that HOLDS the capability, the `SO_MARK` setsockopt genuinely
//! SUCCEEDS and the socket then carries the EXACT frozen upstream-leg mark — so the
//! SYN the proxy's re-originated upstream emits is kernel-attributed to the session's
//! `compose(Leg::TlsproxyUpstream, host_session_index)` value that the Stage-3 OUTPUT
//! chain matches under `DS_MARK_MASK`. This harness proves that positive path.
//!
//! `SO_MARK` is PRIVILEGED: setting it needs `CAP_NET_RAW` (Linux ≥5.17) or
//! `CAP_NET_ADMIN`; reading it back (`SO_MARK` getsockopt) needs `CAP_NET_ADMIN`.
//! Production runs the proxy under `CAP_NET_RAW` (systemd `AmbientCapabilities`,
//! never `CAP_NET_ADMIN` — a compromised proxy must not rewrite the ruleset that
//! contains it, doc 12 §4.2), where `set_mark` succeeds. This whole assert-the-mark
//! path therefore runs only in a `CAP_NET_RAW`+`CAP_NET_ADMIN` lane (or a manual
//! `setcap cap_net_raw,cap_net_admin=ep` / `unshare -rn` run) and is gated behind
//! `DS_PRIV_MARK_TEST=1`.
//!
//! Gate UNSET (the default sandbox + ordinary CI): the test is a no-op/SKIP that
//! prints its reason and makes NO privileged syscall — so `cargo test -p ds-tlsproxy`
//! stays green and never fabricates a mark result. Mirrors the skip-guard shape of
//! `tests/e2e_live_redirect.rs`.
//!
//! # Four arms (all SKIP-by-default; gate noted per arm)
//!
//! 1. [`priv_so_mark_sets_and_reads_back_the_frozen_upstream_leg_mark`]
//!    (`DS_PRIV_MARK_TEST=1`) — the SOCKET-level proof: the live `SO_MARK` setsockopt
//!    SUCCEEDS and reading it straight back off the fd yields the frozen
//!    `compose(Leg::TlsproxyUpstream, idx)` value under `DS_MARK_MASK`. This asserts
//!    the *socket* carries the mark.
//!
//! 2. [`priv_so_mark_rides_an_actual_syn_matched_by_the_nft_ruleset`]
//!    (`DS_PRIV_MARK_TEST=1`) — the PACKET-level proof, which closes the
//!    socket-mark-vs-packet-mark gap the read-back arm cannot: a read-back only
//!    proves the option stuck on the fd, not that the kernel stamps the mark onto the
//!    SYN the socket emits. This arm programs, in the `unshare -rn` namespace, an nft
//!    counter chain matching exactly the Stage-3 form `meta mark & DS_MARK_MASK ==
//!    compose(Leg::TlsproxyUpstream, idx)` (the mask/value composed from the real
//!    `ds-contracts` constants, never re-hardcoded), connects the MARKED socket to a
//!    loopback listener, and asserts the counter incremented — i.e. a genuine packet
//!    the kernel emitted carried the composed mark on the output path the Stage-3
//!    OUTPUT chain matches. A negative control (an UNMARKED connect) must leave the
//!    counter untouched, so the arm proves the mark — not merely any traffic —
//!    triggers the match.
//!
//! 3. [`priv_so_mark_sweeps_the_14bit_index_field_boundaries_on_the_live_kernel`]
//!    (`DS_PRIV_MARK_TEST=1`) — the BOUNDARY sweep: sets + reads back the composed
//!    mark for the 14-bit index field's edges (0, 1, 16383) and its documented
//!    `mod 2^14` wraps (16384->0, 16385->1), proving the wrap survives the live
//!    setsockopt/getsockopt round-trip — the place an off-by-one in the field width
//!    would first bite.
//!
//! 4. [`priv_so_mark_rides_an_actual_v6_syn_matched_by_the_inet_family_ruleset`]
//!    (`DS_REDIRECT_LIVE6=1`) — the v6 sibling of arm 2: the family-agnostic mark
//!    riding an actual IPv6 SYN, matched by an INET-family counter, with an unmarked
//!    negative control. Closes the socket-vs-packet gap on the v6 datapath (D75).
//!
//! Run it live (a fresh user+net namespace grants both caps for the mark path):
//!
//! ```sh
//! cd dataplane
//! unshare -rn bash -c 'DS_PRIV_MARK_TEST=1 \
//!   cargo test -p ds-tlsproxy --test priv_so_mark --locked --offline -- --nocapture'
//! ```
//!
//! or, on a real host, grant the capability to the test binary and run it directly:
//!
//! ```sh
//! # setcap cap_net_raw,cap_net_admin=ep <the compiled priv_so_mark test binary>
//! DS_PRIV_MARK_TEST=1 <that binary> --nocapture
//! ```

use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

// Import the FROZEN mark contract from the crate — never re-hardcode the leg value
// or the mask (D76 mask discipline: `compose`/`DS_MARK_MASK` are the only sanctioned
// way to turn a `(Leg, index)` pair into a raw mark, doc 14 §5).
use ds_contracts::mark::{
    compose, session_index_field, session_index_of, Leg, DS_MARK_MASK, SESSION_INDEX_MODULUS,
};
use ds_contracts::session::SessionRef;

/// The host-local session index whose 14-bit residue rides the mark. A middling,
/// non-trivial value (not 0/1) so a bug that drops the index field is caught.
const SESSION_INDEX: u32 = 4242;

#[test]
fn priv_so_mark_sets_and_reads_back_the_frozen_upstream_leg_mark() {
    if std::env::var("DS_PRIV_MARK_TEST").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP priv_so_mark_sets_and_reads_back_the_frozen_upstream_leg_mark: set \
             DS_PRIV_MARK_TEST=1 and run with CAP_NET_RAW+CAP_NET_ADMIN (e.g. inside \
             `unshare -rn`, or after `setcap cap_net_raw,cap_net_admin=ep` on the test \
             binary) to exercise the LIVE SO_MARK setsockopt + read-back of \
             compose(Leg::TlsproxyUpstream, idx) under DS_MARK_MASK. No privileged \
             syscall is made while unset."
        );
        return;
    }

    // ── The frozen upstream-leg mark VALUE, composed from the ds-contracts constants
    //    (never a re-declared literal) — the EXACT value every upstream socket the
    //    proxy opens must carry before connect (doc 12 §4.2, D76). We compute it two
    //    ways and cross-check: directly via `compose`, and via the crate's own
    //    production call-site `upstream_mark(&SessionRef)` — proving the harness
    //    asserts the SAME value the connect path sets, not a parallel re-derivation.
    let session = SessionRef::new(
        "11111111-2222-3333-4444-555555555555".into(),
        "host-a".into(),
        SESSION_INDEX,
        format!("dstap-{SESSION_INDEX}"),
    );
    let expected_mark = compose(Leg::TlsproxyUpstream, SESSION_INDEX);
    assert_eq!(
        expected_mark,
        ds_tlsproxy::upstream_mark(&session),
        "the harness must assert the SAME frozen mark the production upstream call-site sets",
    );
    // Sanity on the composed value itself: it is a subset of the owned mask (no bit
    // outside DS_MARK_MASK, e.g. never in the permanently-unclaimed gap 23–14).
    assert_eq!(
        expected_mark & !DS_MARK_MASK,
        0,
        "a composed DS mark must set no bit outside DS_MARK_MASK",
    );

    // ── A real TCP socket — the same domain/type/proto the connect path builds. The
    //    mark applies to the fd BEFORE connect (the mark-before-connect site), so no
    //    connect is needed to exercise the setsockopt or its read-back.
    let socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("create a TCP socket");

    // ── THE PROOF (positive path, only reachable with the capability): the live
    //    SO_MARK setsockopt SUCCEEDS. Under the gate we REQUIRE success — the whole
    //    point of this lane is the CAP_NET_RAW path the offline tests cannot assert.
    socket.set_mark(expected_mark).unwrap_or_else(|e| {
        panic!(
            "live SO_MARK setsockopt must SUCCEED under DS_PRIV_MARK_TEST (needs CAP_NET_RAW): {e} \
             — grant cap_net_raw,cap_net_admin (unshare -rn / setcap) before running this lane"
        )
    });

    // ── Read the applied mark straight back off the socket (SO_MARK getsockopt) and
    //    assert the socket now carries the frozen upstream-leg value under the DS
    //    mask. Masking with DS_MARK_MASK is the frozen match discipline (doc 14 §5:
    //    `meta mark & DS_MARK_MASK == value`); we compare the owned bits only, so any
    //    foreign fwmark coexisting in the register (the unclaimed gap) never fools the
    //    assertion.
    let applied = socket
        .mark()
        .expect("read SO_MARK back (needs CAP_NET_ADMIN — present in this privileged lane)");
    assert_eq!(
        applied & DS_MARK_MASK,
        expected_mark & DS_MARK_MASK,
        "the socket must carry compose(Leg::TlsproxyUpstream, {SESSION_INDEX}) under DS_MARK_MASK \
         (applied={applied:#010x}, expected={expected_mark:#010x})",
    );
    // And the composed value never sets an unclaimed bit, so under the mask the
    // applied value must equal the composed value exactly (not merely agree on a
    // subset). This catches a kernel/regression that would smear bits into 23–14.
    assert_eq!(
        applied & DS_MARK_MASK,
        expected_mark,
        "under the mask the applied mark must equal the full composed value ({expected_mark:#010x})",
    );

    eprintln!(
        "PRIV SO_MARK harness PASS: live setsockopt succeeded and the socket carries \
         {expected_mark:#010x} (compose(Leg::TlsproxyUpstream, {SESSION_INDEX})) under \
         DS_MARK_MASK ({DS_MARK_MASK:#010x})."
    );
}

/// Run a command, returning `Err(stderr)` on a non-zero exit — for the `nft`/`ip`
/// namespace setup, exactly the shape the sibling live harnesses use.
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

/// Feed a ruleset to `nft -f -` and assert it loaded (the `meta mark` match +
/// `counter` statement must be programmable on this kernel).
fn nft_load(ruleset: &str) {
    use std::io::Write as _;
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
        "program the counter ruleset (nft meta-mark match + counter must be loadable)"
    );
}

/// Read the `packets N` count off a single-rule counter chain by parsing the
/// plain `nft list chain` text (the same stdout the sibling harnesses grep). The
/// chain holds exactly one `... counter packets N bytes M` rule; we pull the token
/// after `packets`. Stdlib-only — no serde/JSON dev-dep is added to the crate.
/// `family` is the nft address family of the table (`ip` for the v4 lane, `inet`
/// for the dual-stack v6 lane), so one parser serves both counter arms.
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
    let after = text
        .split("counter packets ")
        .nth(1)
        .unwrap_or_else(|| panic!("no `counter packets` in chain {table}/{chain}:\n{text}"));
    after
        .split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("could not parse packet count from: {after:?}"))
}

/// PACKET-level proof: the composed mark rides an ACTUAL SYN the kernel emits, not
/// merely the socket. A counter chain matching the frozen Stage-3 form
/// `meta mark & DS_MARK_MASK == compose(Leg::TlsproxyUpstream, idx)` counts the
/// marked connect's output packets; a negative UNMARKED connect leaves it
/// untouched. Closes the socket-mark-vs-packet-mark gap the read-back arm cannot.
#[test]
fn priv_so_mark_rides_an_actual_syn_matched_by_the_nft_ruleset() {
    if std::env::var("DS_PRIV_MARK_TEST").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP priv_so_mark_rides_an_actual_syn_matched_by_the_nft_ruleset: set \
             DS_PRIV_MARK_TEST=1 and run inside `unshare -rn` (grants CAP_NET_RAW for SO_MARK + \
             CAP_NET_ADMIN for nft) to exercise the LIVE nft-counter proof that the composed \
             upstream-leg mark rides an actual SYN matched by `meta mark & DS_MARK_MASK == \
             compose(Leg::TlsproxyUpstream, idx)`. No unshare / privileged syscall / network is \
             performed while unset."
        );
        return;
    }

    // The FROZEN mask + value, composed from the ds-contracts constants (never a
    // re-hardcoded mask/nibble/shift): the EXACT Stage-3 OUTPUT match this counter
    // chain reproduces (`meta mark & DS_MARK_MASK == value`, doc 14 §5 / doc 12 §4.2).
    let value = compose(Leg::TlsproxyUpstream, SESSION_INDEX);
    // Cross-check against the production call-site so the counter matches the SAME
    // value the connect path sets, not a parallel derivation.
    let session = SessionRef::new(
        "11111111-2222-3333-4444-555555555555".into(),
        "host-a".into(),
        SESSION_INDEX,
        format!("dstap-{SESSION_INDEX}"),
    );
    assert_eq!(
        value,
        ds_tlsproxy::upstream_mark(&session),
        "the counter must match the SAME frozen mark the production upstream call-site sets",
    );
    let mask = DS_MARK_MASK;

    // A fresh net namespace has `lo` DOWN; bring it up so 127.0.0.0/8 is reachable
    // and the marked connect emits real packets on the output path.
    run(&["ip", "link", "set", "lo", "up"])
        .expect("bring lo up — run under `unshare -rn` so the ns has CAP_NET_ADMIN");

    // The counter chain: an output-hook filter rule matching EXACTLY the frozen
    // Stage-3 form `meta mark & DS_MARK_MASK == value`. Policy accept so nothing is
    // dropped — we only COUNT. The mask/value are the composed ds-contracts values,
    // formatted as hex literals into the ruleset text (nft has no symbol for them).
    let table = "ds_priv_mark_counter";
    let chain = "out";
    let ruleset = format!(
        "table ip {table} {{\n  \
           chain {chain} {{\n    \
             type filter hook output priority 0; policy accept;\n    \
             meta mark and {mask:#x} == {value:#x} counter\n  \
           }}\n}}\n"
    );
    nft_load(&ruleset);

    // A loopback listener the marked (and later unmarked) client connects to. The
    // SYN + subsequent output packets of the MARKED connect traverse the output hook
    // carrying the socket mark, so the counter fires.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let target = listener.local_addr().unwrap();

    let before = counter_packets("ip", table, chain);

    // ── POSITIVE: a MARKED connect bumps the counter (the mark rides the packets) ──
    let marked = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .expect("create the marked TCP socket");
    marked.set_mark(value).unwrap_or_else(|e| {
        panic!(
            "live SO_MARK setsockopt must SUCCEED under DS_PRIV_MARK_TEST (needs CAP_NET_RAW): {e}"
        )
    });
    marked
        .connect(&SockAddr::from(target))
        .expect("marked connect to the loopback listener");
    let (_accepted, _peer) = listener.accept().expect("accept the marked connection");
    // Give the output-path packets a beat to be accounted by the counter.
    thread::sleep(Duration::from_millis(50));
    let after_marked = counter_packets("ip", table, chain);
    assert!(
        after_marked > before,
        "the MARKED connect must increment the `meta mark & {mask:#010x} == {value:#010x}` \
         counter (before={before}, after={after_marked}) — proving the composed mark rides an \
         actual SYN, not merely the socket",
    );

    // ── NEGATIVE control: an UNMARKED connect must NOT bump the counter ────────────
    // Proves the counter fires on the MARK specifically, not on any loopback traffic
    // — so the positive result is attributable to compose(Leg::TlsproxyUpstream, idx)
    // and nothing else.
    let unmarked = TcpStream::connect(target).expect("unmarked connect to the loopback listener");
    let (_accepted2, _peer2) = listener.accept().expect("accept the unmarked connection");
    thread::sleep(Duration::from_millis(50));
    let after_unmarked = counter_packets("ip", table, chain);
    assert_eq!(
        after_unmarked, after_marked,
        "an UNMARKED connect must NOT bump the mark counter (after_marked={after_marked}, \
         after_unmarked={after_unmarked}) — the match is on the mark, not on traffic",
    );
    // Keep the sockets alive until here so the connections are not torn down early.
    drop(unmarked);
    drop(marked);

    let _ = run(&["nft", "delete", "table", "ip", table]);
    eprintln!(
        "PRIV SO_MARK packet-level PASS: a marked connect bumped the \
         `meta mark & {mask:#010x} == {value:#010x}` counter ({before} -> {after_marked}); an \
         unmarked connect left it at {after_unmarked}. The composed upstream-leg mark rides an \
         actual SYN matched by the Stage-3 form."
    );
}

/// BOUNDARY-INDEX mark sweep on the LIVE kernel (gated `DS_PRIV_MARK_TEST=1`).
///
/// The socket-level read-back arm above proves ONE middling index (`SESSION_INDEX =
/// 4242`) survives the live setsockopt/getsockopt round-trip. What it does NOT cover
/// is the 14-bit index field's EDGES and its documented `mod 2^14` wrap (doc 14 §4:
/// "indices are carried mod 2^14; the field disambiguates, it is not the primary
/// key"). This arm sweeps exactly those boundaries — `0`, `1`, the maximum in-field
/// value `16383`, and two indices that WRAP the field (`16384 -> 0`, `16385 -> 1`) —
/// composing each mark via `compose(Leg::TlsproxyUpstream, idx)` (never a re-hardcoded
/// mask/shift), setting it on a real socket, reading it straight back, and asserting
/// the socket carries EXACTLY the composed value under `DS_MARK_MASK` and that the
/// recovered 14-bit field equals `idx % 2^14`. It proves the wrap the pure `compose`
/// unit test asserts also holds through the kernel's `SO_MARK` set/get at the field
/// boundaries — the place an off-by-one in the field width would first show up.
///
/// SKIP-by-default (gate unset): no privileged syscall, exactly like the arms above.
#[test]
fn priv_so_mark_sweeps_the_14bit_index_field_boundaries_on_the_live_kernel() {
    if std::env::var("DS_PRIV_MARK_TEST").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP priv_so_mark_sweeps_the_14bit_index_field_boundaries_on_the_live_kernel: set \
             DS_PRIV_MARK_TEST=1 and run with CAP_NET_RAW+CAP_NET_ADMIN (e.g. `unshare -rn`) to \
             sweep the 14-bit index field's boundary indices (0, 1, 16383, and the wraps \
             16384->0 / 16385->1) through the LIVE SO_MARK set/read-back of \
             compose(Leg::TlsproxyUpstream, idx) under DS_MARK_MASK. No privileged syscall is \
             made while unset."
        );
        return;
    }

    // The 14-bit residue is `idx % SESSION_INDEX_MODULUS` (2^14). We assert the wrap
    // via the crate's own modulus constant, never a re-declared `16384` literal.
    for &idx in &[0u32, 1, 16_383, 16_384, 16_385] {
        let expected_field = session_index_field(idx);
        // The wrap is exactly `idx % 2^14`: 16384->0, 16385->1, and the in-field
        // values map to themselves. Cross-check the helper against the modulus so a
        // regression in either surfaces here.
        assert_eq!(
            u32::from(expected_field),
            idx % SESSION_INDEX_MODULUS,
            "session_index_field({idx}) must equal idx mod 2^14",
        );

        let mark = compose(Leg::TlsproxyUpstream, idx);
        // The composed value never sets a bit outside the owned mask (never in the
        // permanently-unclaimed gap 23–14), at every boundary index.
        assert_eq!(
            mark & !DS_MARK_MASK,
            0,
            "composed mark for idx {idx} must set no bit outside DS_MARK_MASK ({mark:#010x})",
        );
        // And the composed mark's own 14-bit field is the wrapped residue.
        assert_eq!(
            session_index_of(mark),
            expected_field,
            "composed mark's 14-bit field for idx {idx} must be {expected_field}",
        );

        // ── THE LIVE PROOF: set the boundary mark on a real socket and read it back.
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .expect("create a TCP socket");
        socket.set_mark(mark).unwrap_or_else(|e| {
            panic!(
                "live SO_MARK setsockopt must SUCCEED under DS_PRIV_MARK_TEST for boundary idx \
                 {idx} (needs CAP_NET_RAW): {e}"
            )
        });
        let applied = socket
            .mark()
            .expect("read SO_MARK back (needs CAP_NET_ADMIN — present in this privileged lane)");
        assert_eq!(
            applied & DS_MARK_MASK,
            mark,
            "socket must carry compose(Leg::TlsproxyUpstream, {idx}) under DS_MARK_MASK \
             (applied={applied:#010x}, mark={mark:#010x})",
        );
        // The recovered 14-bit field is the wrapped index on the live kernel — the
        // boundary/wrap property proven through set+get, not merely in `compose`.
        assert_eq!(
            session_index_of(applied & DS_MARK_MASK),
            expected_field,
            "recovered 14-bit field for idx {idx} must equal {idx} mod 2^14 = {expected_field}",
        );
    }

    // The wrap is a genuine COLLISION at the mark layer: an index and its `+2^14`
    // sibling compose to the identical raw mark (the field is a disambiguator mod
    // 2^14, doc 14 §4). Asserting the collision documents that two host-local indices
    // 16384 apart are indistinguishable to the Stage-3 match — by contract.
    assert_eq!(
        compose(Leg::TlsproxyUpstream, 16_384),
        compose(Leg::TlsproxyUpstream, 0),
        "idx 16384 must wrap to the same mark as idx 0 (mod 2^14 field)",
    );
    assert_eq!(
        compose(Leg::TlsproxyUpstream, 16_385),
        compose(Leg::TlsproxyUpstream, 1),
        "idx 16385 must wrap to the same mark as idx 1 (mod 2^14 field)",
    );

    eprintln!(
        "PRIV SO_MARK boundary sweep PASS: indices 0, 1, 16383, 16384->0, 16385->1 each set + \
         read back the composed compose(Leg::TlsproxyUpstream, idx) under DS_MARK_MASK on the \
         live kernel; the mod-2^14 wrap holds through setsockopt/getsockopt."
    );
}

/// v6 SIBLING of the packet-level mark proof (gated `DS_REDIRECT_LIVE6=1`).
///
/// `set_mark` is family-agnostic (it stamps the socket, not the packet family), and
/// the Stage-3 OUTPUT match is `meta mark & DS_MARK_MASK == value` with no family
/// qualifier — so the composed upstream-leg mark must ride an IPv6 SYN exactly as it
/// rides a v4 one (doc 12 §2 "IPv6 dormant", D75). This arm proves that on the v6
/// datapath: it programs an INET-family (dual-stack) counter chain matching the
/// frozen `meta mark & DS_MARK_MASK == compose(Leg::TlsproxyUpstream, idx)`, connects
/// a MARKED v6 socket to a `[::1]` listener, and asserts the counter fired; a negative
/// UNMARKED v6 connect must leave it untouched. Closes the socket-mark-vs-packet-mark
/// gap for v6 the same way the v4 arm does for v4.
///
/// Gated behind the new `DS_REDIRECT_LIVE6` v6 gate (it still needs CAP_NET_RAW for
/// SO_MARK + CAP_NET_ADMIN for nft — run under `unshare -rn`). SKIP-by-default.
#[test]
fn priv_so_mark_rides_an_actual_v6_syn_matched_by_the_inet_family_ruleset() {
    if std::env::var("DS_REDIRECT_LIVE6").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP priv_so_mark_rides_an_actual_v6_syn_matched_by_the_inet_family_ruleset: set \
             DS_REDIRECT_LIVE6=1 and run inside `unshare -rn` (grants CAP_NET_RAW for SO_MARK + \
             CAP_NET_ADMIN for nft) to exercise the v6 sibling of the nft-counter proof — the \
             composed upstream-leg mark riding an actual v6 SYN matched by an inet-family \
             `meta mark & DS_MARK_MASK == compose(Leg::TlsproxyUpstream, idx)` counter. No \
             unshare / privileged syscall / network is performed while unset."
        );
        return;
    }

    // The FROZEN mask + value, composed from the ds-contracts constants (never a
    // re-hardcoded mask/nibble/shift): the EXACT Stage-3 OUTPUT match this counter
    // chain reproduces, identical to the v4 arm — the mark is family-agnostic.
    let value = compose(Leg::TlsproxyUpstream, SESSION_INDEX);
    let session = SessionRef::new(
        "11111111-2222-3333-4444-555555555555".into(),
        "host-a".into(),
        SESSION_INDEX,
        format!("dstap-{SESSION_INDEX}"),
    );
    assert_eq!(
        value,
        ds_tlsproxy::upstream_mark(&session),
        "the v6 counter must match the SAME frozen mark the production upstream call-site sets",
    );
    let mask = DS_MARK_MASK;

    // A fresh net namespace has `lo` DOWN; bring it up so ::1 is reachable and the
    // marked v6 connect emits real packets on the output path.
    run(&["ip", "link", "set", "lo", "up"])
        .expect("bring lo up — run under `unshare -rn` so the ns has CAP_NET_ADMIN");

    // The counter chain in the INET family (dual-stack): an output-hook filter rule
    // matching EXACTLY the frozen Stage-3 form `meta mark & DS_MARK_MASK == value`,
    // with no family qualifier — so it counts the v6 marked connect's output packets.
    // Policy accept: we only COUNT, never drop. The mask/value are the composed
    // ds-contracts values, formatted as hex literals into the ruleset text.
    let table = "ds_priv_mark_counter6";
    let chain = "out";
    let ruleset = format!(
        "table inet {table} {{\n  \
           chain {chain} {{\n    \
             type filter hook output priority 0; policy accept;\n    \
             meta mark and {mask:#x} == {value:#x} counter\n  \
           }}\n}}\n"
    );
    nft_load(&ruleset);

    // A v6 loopback listener the marked (and later unmarked) client connects to.
    let listener = TcpListener::bind("[::1]:0").expect("bind v6 loopback listener");
    let target = listener.local_addr().unwrap();

    let before = counter_packets("inet", table, chain);

    // ── POSITIVE: a MARKED v6 connect bumps the counter (the mark rides the packets) ─
    let marked = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
        .expect("create the marked v6 TCP socket");
    marked.set_mark(value).unwrap_or_else(|e| {
        panic!(
            "live SO_MARK setsockopt must SUCCEED under DS_REDIRECT_LIVE6 (needs CAP_NET_RAW): {e}"
        )
    });
    marked
        .connect(&SockAddr::from(target))
        .expect("marked v6 connect to the [::1] listener");
    let (_accepted, _peer) = listener.accept().expect("accept the marked v6 connection");
    thread::sleep(Duration::from_millis(50));
    let after_marked = counter_packets("inet", table, chain);
    assert!(
        after_marked > before,
        "the MARKED v6 connect must increment the inet-family `meta mark & {mask:#010x} == \
         {value:#010x}` counter (before={before}, after={after_marked}) — proving the composed \
         mark rides an actual v6 SYN, not merely the socket",
    );

    // ── NEGATIVE control: an UNMARKED v6 connect must NOT bump the counter ──────────
    let unmarked = TcpStream::connect(target).expect("unmarked v6 connect to the [::1] listener");
    let (_accepted2, _peer2) = listener
        .accept()
        .expect("accept the unmarked v6 connection");
    thread::sleep(Duration::from_millis(50));
    let after_unmarked = counter_packets("inet", table, chain);
    assert_eq!(
        after_unmarked, after_marked,
        "an UNMARKED v6 connect must NOT bump the mark counter (after_marked={after_marked}, \
         after_unmarked={after_unmarked}) — the match is on the mark, not on traffic",
    );
    drop(unmarked);
    drop(marked);

    let _ = run(&["nft", "delete", "table", "inet", table]);
    eprintln!(
        "PRIV SO_MARK v6 packet-level PASS: a marked v6 connect bumped the inet-family \
         `meta mark & {mask:#010x} == {value:#010x}` counter ({before} -> {after_marked}); an \
         unmarked v6 connect left it at {after_unmarked}. The composed upstream-leg mark rides an \
         actual v6 SYN matched by the Stage-3 form."
    );
}
