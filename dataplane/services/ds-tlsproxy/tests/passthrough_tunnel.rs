//! E2E: a TLS-4 pass-through (opaque-tunnel) flow (doc 12 §3 / §5 / §10; doc 09
//! §5 TLS-4; D17/D74).
//!
//! # What this proves
//!
//! A ClientHello whose SNI is on the (policy-configured) pass-through list is
//! forwarded as an OPAQUE bidirectional splice — SNI + admission still enforced,
//! the flow netflow-accounted — but FROZEN against TLS termination: it NEVER enters
//! TLS-3 inspection or the TLS-5 credential swap (the §3/§5 stated non-claims).
//!
//! Two halves, both over the PUBLIC lib surface (an integration test is a separate
//! crate and sees only `ds_tlsproxy::*` pub items):
//!
//!   1. **The verdict** — `tls1_admission::decide_with_passthrough` returns the
//!      `Tls1Decision::Passthrough` verdict (the `boundary/tlsproxy`
//!      `ActionPassThrough`) for an admitted, listed SNI, and `Tls1Decision::Tunnel`
//!      for the SAME admitted flow when it is NOT listed. The pass-through list is
//!      what diverts an admitted flow off the inspected path; admission is unchanged.
//!
//!   2. **The byte path** — the production opaque-tunnel splice
//!      (`transparent::forward`, the SAME `copy_bidirectional`-shaped splice
//!      `main.rs` falls through to on the `PassThroughOpaque` route) carries the
//!      exact ClientHello bytes the VM sent to the upstream VERBATIM (no
//!      re-framing, no TLS-3 handshake), and the upstream's opaque response is
//!      forwarded back unmodified. The upstream is a RAW byte echo that performs NO
//!      TLS handshake — so if the proxy had terminated/inspected, the bytes would
//!      not survive byte-identical; an opaque tunnel delivers them untouched.
//!
//! The netflow-record SHAPE (session + dst attribution, no HTTP-level metadata) is
//! a `main.rs`-internal type, asserted in that module's unit suite
//! (`passthrough_netflow_event_carries_session_and_dst_no_http_metadata`); here we
//! prove the OPACITY the netflow non-claim rests on — the proxy observes no HTTP
//! metadata because it never terminates the tunnel (the bytes pass through raw).
//!
//! Loopback/synthetic only — no live REDIRECT, no live external network (the
//! `e2e_transparent_forward.rs` pattern; the live kernel REDIRECT is reboot-pending,
//! see `SPIKE-NOTES.md`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use ds_contracts::dns_admission::{
    AddressFamily, AdmissionEntry, AdmissionError, AdmissionKey, AdmissionMap, AdmissionType,
    AdmittedAddr, Instant, Provenance, ReverseIndex,
};
use ds_contracts::session::SessionRef;
use ds_tlsproxy::tls1_admission::{
    decide_with_passthrough, PassthroughList, PolicyOracle, PolicyVerdict, Tls1Decision,
};
use ds_tlsproxy::transparent::{forward, ConnOrigin};

const SESSION_UUID: &str = "11111111-2222-3333-4444-555555555555";
const PINNED_DOMAIN: &str = "pinned.example";

fn session() -> SessionRef {
    SessionRef::new(SESSION_UUID.into(), "host-a".into(), 7, "dstap-7".into())
}

// ── synthetic ClientHello builder (a minimal well-formed TLS 1.2-shaped hello with
//    a single host_name SNI; mirrors the in-crate builders, public bytes only) ────

const RECORD_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const SNI_NAME_TYPE_HOST: u8 = 0x00;

fn client_hello_with_sni(host: &str) -> Vec<u8> {
    // server_name extension body: server_name_list<ServerName{name_type, HostName}>
    let mut name = Vec::new();
    name.push(SNI_NAME_TYPE_HOST);
    name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    name.extend_from_slice(host.as_bytes());
    let mut list = Vec::new();
    list.extend_from_slice(&(name.len() as u16).to_be_bytes());
    list.extend_from_slice(&name);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
    extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&list);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length 0
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len 2 + one suite
    body.push(1); // compression_methods length 1
    body.push(0); // null compression
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut hs = Vec::new();
    hs.push(HANDSHAKE_TYPE_CLIENT_HELLO);
    let len = body.len() as u32;
    hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(RECORD_TYPE_HANDSHAKE);
    rec.extend_from_slice(&[0x03, 0x01]); // legacy record version
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

// ── mock AdmissionMap / PolicyOracle / PassthroughList (the three injected seams
//    decide_with_passthrough consults; the verdict is pure over them) ─────────────

#[derive(Default)]
struct MockReverse;
impl ReverseIndex for MockReverse {
    fn incref(&mut self, _s: &str, _ip: &AdmittedAddr, _d: &str) -> u32 {
        0
    }
    fn decref(&mut self, _s: &str, _ip: &AdmittedAddr, _d: &str) -> u32 {
        0
    }
    fn refcount(&self, _s: &str, _ip: &AdmittedAddr) -> u32 {
        0
    }
}

#[derive(Default)]
struct MockMap {
    entries: HashMap<(String, String), AdmissionEntry>,
    reverse: MockReverse,
}
impl MockMap {
    fn with(session: &str, fqdn: &str, entry: AdmissionEntry) -> MockMap {
        let mut m = MockMap::default();
        m.entries
            .insert((session.to_string(), fqdn.to_string()), entry);
        m
    }
}
impl AdmissionMap for MockMap {
    type Reverse = MockReverse;
    fn admit(&mut self, key: AdmissionKey, entry: AdmissionEntry) -> Result<(), AdmissionError> {
        self.entries
            .insert((key.session_uuid, key.original_query_fqdn), entry);
        Ok(())
    }
    fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
        self.entries
            .get(&(key.session_uuid.clone(), key.original_query_fqdn.clone()))
            .cloned()
    }
    fn revoke(&mut self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
        self.entries
            .remove(&(key.session_uuid.clone(), key.original_query_fqdn.clone()));
        Ok(vec![])
    }
    fn reverse_index(&self) -> &Self::Reverse {
        &self.reverse
    }
}

struct AllowAll;
impl PolicyOracle for AllowAll {
    fn verdict(&self, _sni_domain: &str) -> PolicyVerdict {
        PolicyVerdict::Admit
    }
}

/// A pass-through list listing a fixed set (the u1 seam; the production
/// `EmptyPassthroughList` lists nothing per D74).
struct Listing(Vec<String>);
impl PassthroughList for Listing {
    fn is_passthrough(&self, sni_domain: &str) -> bool {
        self.0.iter().any(|d| d == sni_domain)
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> AdmittedAddr {
    AdmittedAddr {
        family: AddressFamily::V4,
        octets: vec![a, b, c, d],
    }
}

fn admitting_entry(ips: Vec<AdmittedAddr>) -> AdmissionEntry {
    AdmissionEntry {
        admitted_ips: ips,
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
        expires_at: Instant::from_unix_nanos(10_000),
        admitted_at: Instant::from_unix_nanos(0),
        provenance: Provenance {
            rule_id: "r1".into(),
            policy_layer: "org".into(),
            policy_version: "v0".into(),
        },
    }
}

#[test]
fn listed_sni_decides_passthrough_and_unlisted_decides_tunnel() {
    // The ActionPassThrough verdict (u1, wired into the opaque route by this unit):
    // an admitted SNI that is on the pass-through list returns `Passthrough`; the
    // SAME admitted flow UNLISTED returns `Tunnel` (eligible for the inspected path).
    // The pass-through list is the ONLY thing that diverts an admitted flow off
    // inspection — admission is identical in both cases.
    let map = MockMap::with(
        SESSION_UUID,
        PINNED_DOMAIN,
        admitting_entry(vec![v4(203, 0, 113, 10)]),
    );
    let policy = AllowAll;
    let hello = client_hello_with_sni(PINNED_DOMAIN);
    let origin = ConnOrigin {
        original_dst: "203.0.113.10:443".parse().unwrap(),
        session: session(),
    };

    // Listed → Passthrough (the ActionPassThrough verdict).
    let listed = Listing(vec![PINNED_DOMAIN.into()]);
    assert_eq!(
        decide_with_passthrough(
            &hello,
            &origin,
            &map,
            &policy,
            &listed,
            Instant::from_unix_nanos(0)
        ),
        Tls1Decision::Passthrough,
        "an admitted, pass-through-listed SNI returns the ActionPassThrough verdict"
    );

    // Same admitted flow, NOT listed → Tunnel (eligible for TLS-3 inspection).
    let none = Listing(vec![]);
    assert_eq!(
        decide_with_passthrough(
            &hello,
            &origin,
            &map,
            &policy,
            &none,
            Instant::from_unix_nanos(0)
        ),
        Tls1Decision::Tunnel,
        "the SAME admitted flow UNLISTED is Tunnel — the list is what diverts it"
    );
}

#[test]
fn passthrough_admission_still_enforced_sni_dst_mismatch_refuses() {
    // Pass-through changes tunnel MODE, never the admission verdict (doc 12 §3): it
    // can never rescue a flow whose kernel original_dst is not admitted for the SNI
    // (the CDN shared-IP hole). Even a listed domain refuses on an SNI/dst mismatch —
    // pass-through is consulted only AFTER admission accepts.
    let map = MockMap::with(
        SESSION_UUID,
        PINNED_DOMAIN,
        admitting_entry(vec![v4(198, 51, 100, 7)]), // admitted on a DIFFERENT IP
    );
    let policy = AllowAll;
    let listed = Listing(vec![PINNED_DOMAIN.into()]);
    let hello = client_hello_with_sni(PINNED_DOMAIN);
    // dials an IP NOT in the admitted set for pinned.example.
    let origin = ConnOrigin {
        original_dst: "203.0.113.10:443".parse().unwrap(),
        session: session(),
    };
    assert!(
        matches!(
            decide_with_passthrough(
                &hello,
                &origin,
                &map,
                &policy,
                &listed,
                Instant::from_unix_nanos(0)
            ),
            Tls1Decision::Refuse(_)
        ),
        "pass-through never rescues an SNI/dst mismatch — admission is still enforced"
    );
}

/// A raw byte echo upstream that performs NO TLS handshake — it reads whatever the
/// proxy forwards and echoes it back verbatim, then EOFs. If the proxy had
/// TLS-terminated/inspected the flow, the ClientHello bytes would not arrive
/// byte-identical here; an opaque pass-through delivers them untouched. Returns its
/// bound address and a handle yielding the EXACT bytes it received.
fn spawn_raw_echo_origin() -> (
    SocketAddr,
    thread::JoinHandle<Vec<u8>>,
    &'static str, // the opaque "response" the origin writes back
) {
    const OPAQUE_RESPONSE: &str = "\x16\x03\x03opaque-origin-bytes-not-http";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        // Read everything the proxy forwards (the client half-closes its write side
        // after the ClientHello, which the splice propagates as EOF here).
        let mut received = Vec::new();
        conn.read_to_end(&mut received).unwrap();
        // Echo an opaque (non-HTTP, TLS-record-shaped) response back unmodified.
        conn.write_all(OPAQUE_RESPONSE.as_bytes()).unwrap();
        conn.shutdown(std::net::Shutdown::Write).unwrap();
        received
    });
    (addr, handle, OPAQUE_RESPONSE)
}

#[test]
fn passthrough_tunnel_forwards_clienthello_verbatim_and_response_is_opaque() {
    // The byte path of an opaque pass-through: the production `transparent::forward`
    // splice (the SAME copy_bidirectional-shaped splice `main.rs` falls through to on
    // the PassThroughOpaque route) carries the VM's exact ClientHello bytes upstream
    // VERBATIM (no TLS-3 handshake, no re-framing) and forwards the origin's opaque
    // response back unmodified. The upstream does NO TLS handshake — so byte-identity
    // proves the proxy did not terminate/inspect.
    let hello = client_hello_with_sni(PINNED_DOMAIN);

    // 1. the raw byte-echo upstream (the real origin the VM intended to reach).
    let (upstream_addr, origin_handle, opaque_response) = spawn_raw_echo_origin();

    // 2. the transparent listener — a loopback "redirect-target" port standing in for
    //    :18443. On the PassThroughOpaque route, `process_new` opens an upstream to the
    //    recovered original_dst and runs this splice (the dormant TLS-4 branch).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let redirect_target = listener.local_addr().unwrap();

    let proxy_handle = thread::spawn(move || {
        let (downstream, _peer) = listener.accept().unwrap();
        // The pass-through route opens an OPAQUE upstream to the recovered
        // original_dst (here the raw echo origin) — never a TLS-terminated re-dial.
        let upstream = TcpStream::connect(upstream_addr).unwrap();
        // The opaque bidirectional splice: forward the raw bytestream verbatim, both
        // directions, until EOF (the exact splice the listener uses on this route).
        forward(downstream, upstream).expect("opaque pass-through splice runs to EOF")
    });

    // 3. the VM client: dial the redirect-target and send the ClientHello bytes, then
    //    half-close the write side (the splice propagates EOF upstream so the echo
    //    origin's read_to_end completes).
    let mut client = TcpStream::connect(redirect_target).unwrap();
    client.write_all(&hello).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();

    // The upstream received the VM's ClientHello bytes VERBATIM — every record byte
    // byte-identical (opaque tunnel: no termination, no re-framing).
    let received_upstream = origin_handle.join().unwrap();
    assert_eq!(
        received_upstream, hello,
        "the opaque pass-through must forward the exact ClientHello bytes to the upstream \
         (no TLS-3 handshake, no re-framing)"
    );

    // The opaque (non-HTTP) origin response was forwarded back to the client unmodified.
    assert_eq!(
        response.as_slice(),
        opaque_response.as_bytes(),
        "the origin's opaque response is forwarded back verbatim (opaque tunnel both ways)"
    );

    let (n_down_up, n_up_down) = proxy_handle.join().unwrap();
    assert_eq!(
        n_down_up as usize,
        hello.len(),
        "exactly the ClientHello bytes flowed downstream→upstream (no added/dropped byte)"
    );
    assert_eq!(
        n_up_down as usize,
        opaque_response.len(),
        "exactly the opaque response bytes flowed upstream→downstream"
    );
}
