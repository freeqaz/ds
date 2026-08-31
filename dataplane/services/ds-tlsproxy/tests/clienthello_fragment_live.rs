//! LIVE record-fragmented ClientHello peek — SNI extraction + TLS-1 admission over a
//! REAL socket, driven through the PRODUCTION peek helper (doc 12 §4.1 / §4.1.1).
//!
//! The in-crate `#[cfg(test)]` unit fixtures in `src/main.rs` drive the production peek
//! loop against a *synthetic* `ChunkedReader` — an in-process `AsyncRead` that hands the
//! bytes back in N pieces. That proves the coalescing algorithm, but it never puts the
//! bytes on a real TCP socket, so it cannot catch a divergence between the synthetic
//! reader's read shape and a real stream backend's — the future-pingora-`Stream` risk
//! this harness guards.
//!
//! This test drives a GENUINELY record-fragmented ClientHello (the ClientHello handshake
//! message split across multiple TLS records, each with its own 5-byte record header, per
//! RFC 8446 §5.1) over a REAL loopback TCP connection to a `:18443`-style listener, and
//! it peeks the multi-record prefix off the accepted socket with the **PRODUCTION peek
//! helper itself** — `ds_tlsproxy::clienthello_peek::read_client_hello_prefix_blocking`,
//! the blocking-`std::io::Read` twin of the async listener's coalescing loop that shares
//! the ONE `SpanScan`/`HandshakeSpan` cursor + the three frozen §4.1.1 fail-closed bounds
//! (the 16 KiB byte cap `CLIENT_HELLO_PEEK_MAX`, the 512-record cap
//! `MAX_CLIENT_HELLO_RECORDS`, and the 8-record empty-record cap
//! `MAX_CLIENT_HELLO_EMPTY_RECORDS`). There is **no** test-side re-implementation of the
//! coalescing loop any more — the harness and the live listener run the same lifted code,
//! so a read-shape divergence can no longer hide behind a parallel implementation.
//!
//! After the peek it reassembles the handshake message with the SAME production
//! `ds_tlsproxy::clienthello_peek::reassemble_handshake_message` and drives it through the
//! REAL `pub` admission surface:
//!   - `ds_tlsproxy::tls1_admission::parse_client_hello_sni` — SNI extraction, and
//!   - `ds_tlsproxy::tls1_admission::decide` — the full TLS-1 verdict against an injected
//!     admission map + policy oracle.
//!
//! It asserts the record-fragmented flow's SNI extracts and the flow is ADMITTED
//! (`Tls1Decision::Tunnel`) — i.e. NOT wrongly refused because a naive single-`read` /
//! single-record peek under-read the handshake — AND, as the §4.1.1 negative arms, that
//! three fail-closed edges refuse THROUGH the production helper: a tiny-record FLOOD
//! (the distinct `ClientHelloFlood` pre-parse refusal the coalescing loop owns), a
//! TRUNCATED handshake (record-length header promises more than the wire delivers), and
//! an OVERSIZED-beyond-`CLIENT_HELLO_PEEK_MAX` ClientHello (over-cap collapses into
//! `NotAClientHello`, §10.1).
//!
//! Gated behind `DS_REDIRECT_LIVE=1` (the same env gate `tests/e2e_live_redirect.rs`
//! uses — this harness rides that gate rather than minting a new one). Without the var
//! it SKIPS: it prints a reason, opens NO socket, spawns NO thread, and runs no network
//! I/O, so the normal `cargo test` gate stays GREEN and never fabricates a result. It
//! needs NO privileged syscall / namespace (loopback TCP only), unlike the redirect
//! test — the `ConnOrigin` here is constructed directly (this harness proves the
//! peek→parse→admit path, not `SO_ORIGINAL_DST` recovery). Run it live:
//!
//! ```sh
//! cd dataplane
//! DS_REDIRECT_LIVE=1 \
//!   cargo test -p ds-tlsproxy --test clienthello_fragment_live --locked --offline -- --nocapture
//! ```

use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use ds_contracts::dns_admission::{
    AddressFamily, AdmissionEntry, AdmissionError, AdmissionKey, AdmissionMap, AdmissionType,
    AdmittedAddr, Instant, Provenance, ReverseIndex,
};
use ds_contracts::session::SessionRef;
// The PRODUCTION peek + reassembly, imported from the crate's `pub` library helper — the
// SAME code the live `:18443` listener runs (D40: `main.rs` re-points its `Stream` peek
// at these). There is NO test-side re-implementation of the coalescing loop or the
// §4.1.1 bounds any more; the constants below are re-exported from the helper, not
// re-declared, so a doc/code drift on their values trips the crate, not a shadow copy.
use ds_tlsproxy::clienthello_peek::{
    read_client_hello_prefix_blocking, reassemble_handshake_message, CLIENT_HELLO_PEEK_MAX,
    MAX_CLIENT_HELLO_EMPTY_RECORDS, MAX_CLIENT_HELLO_RECORDS, TLS_RECORD_HEADER_LEN,
};
use ds_tlsproxy::tls1_admission::{
    decide, parse_client_hello_sni, PolicyVerdict, RefuseReason, Tls1Decision,
};
use ds_tlsproxy::transparent::ConnOrigin;

const RECORD_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const SNI_NAME_TYPE_HOST: u8 = 0x00;

// ── synthetic ClientHello wire builders ──────────────────────────────────────
//
// Minimal-but-well-formed TLS 1.2-shaped ClientHello bytes, matching the shape the
// in-crate fixtures build. No TLS stack — the point is to control record framing
// exactly, so we can force a genuinely multi-record handshake on the wire.

/// A `server_name` extension (RFC 6066) carrying one host_name.
fn server_name_ext(host: &str) -> Vec<u8> {
    let mut name = Vec::new();
    name.push(SNI_NAME_TYPE_HOST);
    name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    name.extend_from_slice(host.as_bytes());

    let mut list = Vec::new();
    list.extend_from_slice(&(name.len() as u16).to_be_bytes()); // server_name_list length
    list.extend_from_slice(&name);

    let mut ext = Vec::new();
    ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
    ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&list);
    ext
}

/// Build a single-record ClientHello with an SNI extension and `pad` bytes of padding
/// (an unknown, GREASE-shaped extension the SNI parser walks past), so a "fat first
/// flight" large enough to fragment across records can be synthesised.
fn client_hello(host: &str, pad: usize) -> Vec<u8> {
    let mut extensions = server_name_ext(host);
    if pad > 0 {
        extensions.extend_from_slice(&0x6a6au16.to_be_bytes());
        extensions.extend_from_slice(&(pad as u16).to_be_bytes());
        extensions.extend(std::iter::repeat_n(0u8, pad));
    }

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
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes()); // record length
    rec.extend_from_slice(&hs);
    rec
}

/// Split `bytes` into `n` roughly-equal contiguous slices (≥1).
fn split_evenly(bytes: &[u8], n: usize) -> Vec<Vec<u8>> {
    let n = n.max(1);
    let chunk = bytes.len().div_ceil(n).max(1);
    bytes.chunks(chunk).map(<[u8]>::to_vec).collect()
}

/// Re-frame a single-record ClientHello (`single`, from [`client_hello`]) into `n`
/// consecutive TLS handshake records, each with its OWN 5-byte record header. The
/// handshake message (the single record's 5-byte header stripped) is split into `n`
/// roughly-equal slices, each becoming one record's payload. This is genuine TLS
/// record-layer fragmentation (RFC 8446 §5.1): one ClientHello handshake message spread
/// across multiple records on the wire.
fn fragment_into_records(single: &[u8], n: usize) -> Vec<u8> {
    assert!(
        single.len() > TLS_RECORD_HEADER_LEN,
        "need a single record with a handshake payload"
    );
    let hs = &single[TLS_RECORD_HEADER_LEN..];
    let mut out = Vec::with_capacity(single.len() + n * TLS_RECORD_HEADER_LEN);
    for slice in split_evenly(hs, n) {
        assert!(!slice.is_empty(), "each record carries handshake bytes");
        out.push(RECORD_TYPE_HANDSHAKE);
        out.extend_from_slice(&[0x03, 0x01]); // legacy record version
        out.extend_from_slice(&(slice.len() as u16).to_be_bytes());
        out.extend_from_slice(&slice);
    }
    out
}

/// Build a flood of `n` handshake records each carrying `payload_len` handshake bytes —
/// the §4.1.1 tiny-record / empty-record flood shape. With `payload_len == 1` a run of >
/// `MAX_CLIENT_HELLO_RECORDS` records trips the record-count bound; with
/// `payload_len == 0` a run of > `MAX_CLIENT_HELLO_EMPTY_RECORDS` empty records trips the
/// zero-progress bound. The first record's payload starts with a ClientHello handshake
/// byte so the header-length walk engages (the flood must LOOK like a ClientHello being
/// assembled, not a non-handshake first record).
fn tiny_record_flood(n: usize, payload_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n * (TLS_RECORD_HEADER_LEN + payload_len));
    for i in 0..n {
        out.push(RECORD_TYPE_HANDSHAKE);
        out.extend_from_slice(&[0x03, 0x01]);
        out.extend_from_slice(&(payload_len as u16).to_be_bytes());
        for j in 0..payload_len {
            // A big handshake-length header so the message never completes within the
            // flood (the walk keeps coalescing until the record/empty bound fires).
            out.push(if i == 0 && j == 0 {
                HANDSHAKE_TYPE_CLIENT_HELLO
            } else {
                0xff
            });
        }
    }
    out
}

/// Count the leading consecutive TLS handshake records in `buf` (mirrors the in-crate
/// `count_records` test helper), so the fixture can prove it is genuinely multi-record.
fn count_records(buf: &[u8]) -> usize {
    let mut pos = 0usize;
    let mut n = 0usize;
    while pos + TLS_RECORD_HEADER_LEN <= buf.len() && buf[pos] == RECORD_TYPE_HANDSHAKE {
        let record_len = ((buf[pos + 3] as usize) << 8) | (buf[pos + 4] as usize);
        pos += TLS_RECORD_HEADER_LEN + record_len;
        n += 1;
        if pos > buf.len() {
            break;
        }
    }
    n
}

/// Drive `wire` over a fresh loopback connection to `listen_addr`, writing it in `pieces`
/// small TCP chunks with a tiny pause between them so record boundaries and TCP segment
/// boundaries do NOT line up — the peek must coalesce across BOTH layers on a genuine
/// socket (the whole point vs the in-process `ChunkedReader`). Accept on `listener`, peek
/// the prefix with the PRODUCTION `read_client_hello_prefix_blocking`, and return
/// `(raw_prefix_bytes, flood_refused)`.
fn drive_and_peek(
    listener: &TcpListener,
    listen_addr: SocketAddr,
    wire: &[u8],
    pieces: usize,
) -> (Vec<u8>, bool) {
    let wire_for_client = wire.to_vec();
    let client = thread::spawn(move || {
        let mut s = TcpStream::connect(listen_addr).expect("client connect to :18443 listener");
        s.set_nodelay(true).ok();
        for piece in split_evenly(&wire_for_client, pieces) {
            // A truncated arm intentionally sends less than the record header promises;
            // the peer closing then is expected, so tolerate a write error here.
            if s.write_all(&piece).is_err() {
                break;
            }
            s.flush().ok();
            thread::sleep(Duration::from_millis(2));
        }
        // Hold the connection open briefly so the server's peek can complete before an
        // EOF (an early EOF is itself a legitimate fail-closed refuse path).
        thread::sleep(Duration::from_millis(50));
    });

    let (mut accepted, _peer) = listener.accept().expect("accept the fragmented connection");
    accepted.set_read_timeout(Some(Duration::from_secs(5))).ok();
    // THE production peek helper over the real blocking socket — no test-side loop.
    let peeked = read_client_hello_prefix_blocking(&mut accepted, CLIENT_HELLO_PEEK_MAX);
    client.join().expect("client thread");

    let flooded = peeked.refuse == Some(RefuseReason::ClientHelloFlood);
    (peeked.bytes, flooded)
}

// ── mock admission map + policy oracle (the `pub` `decide` seams) ────────────
//
// Byte-for-byte the shape of the in-crate `#[cfg(test)]` mocks, but over the crate's
// PUBLIC trait surface so an integration test can construct them.

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
    fn insert(&mut self, session: &str, fqdn: &str, entry: AdmissionEntry) {
        self.entries
            .insert((session.to_string(), fqdn.to_string()), entry);
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

struct MockPolicy {
    verdicts: HashMap<String, PolicyVerdict>,
}
impl MockPolicy {
    fn allowing(domains: &[&str]) -> MockPolicy {
        MockPolicy {
            verdicts: domains
                .iter()
                .map(|s| (s.to_string(), PolicyVerdict::Admit))
                .collect(),
        }
    }
}
impl ds_tlsproxy::tls1_admission::PolicyOracle for MockPolicy {
    fn verdict(&self, sni_domain: &str) -> PolicyVerdict {
        // Unlisted → Deny (fail-closed default, matching the in-crate mock).
        self.verdicts
            .get(sni_domain)
            .copied()
            .unwrap_or(PolicyVerdict::Deny)
    }
}

const SESSION_UUID: &str = "11111111-2222-3333-4444-555555555555";

fn session() -> SessionRef {
    SessionRef::new(SESSION_UUID.into(), "host-a".into(), 7, "dstap-7".into())
}

fn admitted_v4(ip: Ipv4Addr) -> AdmittedAddr {
    AdmittedAddr {
        family: AddressFamily::V4,
        octets: ip.octets().to_vec(),
    }
}

/// A live (far-future deadline) NORMAL admission for `ip`.
fn live_entry(ip: Ipv4Addr) -> AdmissionEntry {
    AdmissionEntry {
        admitted_ips: vec![admitted_v4(ip)],
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
        expires_at: Instant::from_unix_nanos(u64::MAX),
        admitted_at: Instant::from_unix_nanos(0),
        provenance: Provenance {
            rule_id: "r1".into(),
            policy_layer: "org".into(),
            policy_version: "v0".into(),
        },
    }
}

#[test]
fn live_record_fragmented_clienthello_extracts_sni_and_admits() {
    if std::env::var("DS_REDIRECT_LIVE").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP live_record_fragmented_clienthello_extracts_sni_and_admits: set \
             DS_REDIRECT_LIVE=1 to drive a genuinely record-fragmented ClientHello over a real \
             loopback socket through the PRODUCTION peek helper + parse_client_hello_sni + decide \
             admission path (and the §4.1.1 fail-closed negative arms). \
             (Unset: no socket opened, no thread spawned, no network I/O.)"
        );
        return;
    }

    // The constants this harness enforces are the doc 12 §4.1.1 binding values, imported
    // from the production helper (not re-declared); assert them so a drift trips here.
    assert_eq!(CLIENT_HELLO_PEEK_MAX, 16 * 1024, "doc 12 §4.1.1 byte cap");
    assert_eq!(MAX_CLIENT_HELLO_RECORDS, 512, "doc 12 §4.1.1 record cap");
    assert_eq!(
        MAX_CLIENT_HELLO_EMPTY_RECORDS, 8,
        "doc 12 §4.1.1 empty-record cap"
    );

    const SNI: &str = "api.record-frag.example.com";
    // The kernel original_dst the guest dialed — a DNS-2b-admitted IP the entry lists.
    let original_dst_ip = Ipv4Addr::new(203, 0, 113, 10);
    let original_dst: SocketAddr = SocketAddr::new(original_dst_ip.into(), 443);

    // A :18443-style listener. Bind an EPHEMERAL loopback port (a fixed :18443 would flake
    // under a co-tenant); the "18443" role is what matters, not the literal port.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind :18443-style listener");
    let listen_addr = listener.local_addr().unwrap();

    // Drive several record-fragmentation shapes: 2 and 3 evenly-split records, and a
    // many-tiny-records split (a few handshake bytes per record) that stays a LEGITIMATE
    // fragmentation — comfortably under the §4.1.1 512-record cap, so the peek coalesces
    // and admits rather than tripping the flood bound. (The over-512 tiny-record FLOOD is
    // one of the negative arms below; here every fixture is a legitimate ClientHello that
    // must be admitted — the under-read bug would refuse it.)
    let single = client_hello(SNI, 600);
    let hs_len = single.len() - TLS_RECORD_HEADER_LEN;
    let many_tiny = hs_len.min(MAX_CLIENT_HELLO_RECORDS - 1); // ≥1 hs byte/record, under the cap
    let record_counts = [2usize, 3, many_tiny];

    for &requested in &record_counts {
        let wire = fragment_into_records(&single, requested);
        // `fragment_into_records` splits into ceil(hs_len / ceil(hs_len/requested)) slices,
        // which equals `requested` only when it divides the handshake evenly (or one
        // byte per record); assert the ACTUAL framing is genuinely multi-record and a
        // LEGITIMATE fragmentation (≥2 records, at or under the §4.1.1 512-record cap).
        let records = count_records(&wire);
        assert!(
            (2..=MAX_CLIENT_HELLO_RECORDS).contains(&records),
            "fixture must be a legitimate multi-record fragmentation \
             (2..={MAX_CLIENT_HELLO_RECORDS} records), got {records} for requested={requested}"
        );
        assert!(
            wire.len() > single.len(),
            "re-framing into records adds per-record headers"
        );

        // Peek the whole multi-record prefix off the REAL socket via the production helper.
        let (raw_prefix, flooded) = drive_and_peek(&listener, listen_addr, &wire, 7);

        // ── the coalescing peek must have read the WHOLE multi-record prefix ──
        assert!(
            !flooded,
            "a legitimate {records}-record ClientHello must NOT trip a flood bound"
        );
        assert_eq!(
            raw_prefix, wire,
            "the production peek must buffer all {records} records off the socket \
             byte-identically (no under-read) — the future-pingora-Stream read-shape guard"
        );

        // Proof this is a genuine multi-record fix: the FIRST record alone does NOT parse.
        if records >= 2 {
            let first_record_end =
                TLS_RECORD_HEADER_LEN + (((wire[3] as usize) << 8) | (wire[4] as usize));
            assert!(
                parse_client_hello_sni(&wire[..first_record_end]).is_err(),
                "the first record alone must NOT parse (the single-record under-read bug)"
            );
        }

        // ── SNI extracts off the reassembled handshake message (doc 12 §4.1.1) ──
        let reassembled = reassemble_handshake_message(&raw_prefix);
        let sni = parse_client_hello_sni(&reassembled)
            .expect("SNI must extract from the reassembled record-fragmented ClientHello");
        assert_eq!(sni, SNI, "extracted SNI must be the guest's server_name");

        // ── the full TLS-1 decision ADMITS (Tunnel), not wrongly refuses ──
        // Policy allows the SNI, and a live admission for it includes the kernel dst.
        let mut map = MockMap::default();
        map.insert(SESSION_UUID, SNI, live_entry(original_dst_ip));
        let policy = MockPolicy::allowing(&[SNI]);
        let origin = ConnOrigin {
            original_dst,
            session: session(),
        };
        // `decide` re-reads the record header of `reassembled` (a single synthetic record),
        // parses the SNI, then runs the policy + FORWARD-admission gate — the exact path a
        // real listener runs after coalescing the peek.
        let decision = decide(
            &reassembled,
            &origin,
            &map,
            &policy,
            Instant::from_unix_nanos(0),
        );
        assert_eq!(
            decision,
            Tls1Decision::Tunnel,
            "a record-fragmented, policy-allowed, live-admitted flow must be ADMITTED \
             (opaque tunnel), not refused (records={records})"
        );
    }

    // ── negative control: an admitted SNI over a DIFFERENT dst refuses (CDN-hole close) ──
    // Same production peek, but the kernel dst is NOT in the SNI's admitted set — the
    // §4.1 SNI/dst-mismatch refusal must still fire on the reassembled multi-record path.
    {
        let wire = fragment_into_records(&single, 3);
        let (raw_prefix, _flooded) = drive_and_peek(&listener, listen_addr, &wire, 5);
        let reassembled = reassemble_handshake_message(&raw_prefix);

        let mut map = MockMap::default();
        // The SNI is admitted, but on a DIFFERENT IP than the kernel dst below.
        map.insert(
            SESSION_UUID,
            SNI,
            live_entry(Ipv4Addr::new(198, 51, 100, 7)),
        );
        let policy = MockPolicy::allowing(&[SNI]);
        let origin = ConnOrigin {
            // kernel dst 203.0.113.10 is NOT in the SNI's admitted set → mismatch refuse.
            original_dst,
            session: session(),
        };
        let decision = decide(
            &reassembled,
            &origin,
            &map,
            &policy,
            Instant::from_unix_nanos(0),
        );
        assert!(
            matches!(decision, Tls1Decision::Refuse(_)),
            "a record-fragmented flow whose SNI/dst do not agree must REFUSE (CDN-hole close), \
             got {decision:?}"
        );
    }

    // ══ §4.1.1 fail-closed NEGATIVE arms — every bound refuses THROUGH the production
    //    peek helper over the real socket, never a panic / hang / silent admit. ══
    let map = MockMap::default(); // empty — no arm below should reach admission anyway
    let policy = MockPolicy::allowing(&[SNI]);
    let origin = ConnOrigin {
        original_dst,
        session: session(),
    };

    // ── (a) tiny-record FLOOD → the DISTINCT ClientHelloFlood pre-parse refusal ──
    // > MAX_CLIENT_HELLO_RECORDS records each carrying ONE handshake byte: a legit
    // fragmentation shape scaled past the record-count cap. The coalescing loop (record
    // COUNT is a fact only it holds) refuses with the distinct flood reason BEFORE the
    // SNI parse — the byte-level parser could not tell this from ordinary garbage.
    {
        let wire = tiny_record_flood(MAX_CLIENT_HELLO_RECORDS + 50, 1);
        assert!(
            count_records(&wire) > MAX_CLIENT_HELLO_RECORDS,
            "the flood fixture must exceed the record cap"
        );
        let (raw_prefix, flooded) = drive_and_peek(&listener, listen_addr, &wire, 9);
        assert!(
            flooded,
            "a > {MAX_CLIENT_HELLO_RECORDS}-record flood must surface the DISTINCT \
             ClientHelloFlood refusal from the production peek's record-count bound"
        );
        assert!(
            raw_prefix.len() <= CLIENT_HELLO_PEEK_MAX,
            "the peek never buffers past the byte cap even under a flood"
        );
        // The distinct flood reason is what a real listener keys on; the buffered prefix,
        // fed alone to the byte-level parser, would only ever be a generic NotAClientHello —
        // so the fail-closed decision on the peeked bytes still refuses.
        let reassembled = reassemble_handshake_message(&raw_prefix);
        assert!(
            matches!(
                decide(
                    &reassembled,
                    &origin,
                    &map,
                    &policy,
                    Instant::from_unix_nanos(0)
                ),
                Tls1Decision::Refuse(_)
            ),
            "the flood's buffered prefix must itself refuse fail-closed at the gate"
        );
    }

    // ── (b) EMPTY-record flood → ClientHelloFlood via the zero-progress budget ──
    // Pure 5-byte headers (length == 0) make NO handshake progress; the empty-record
    // budget (8) fires far below the record cap. Still the distinct flood refusal.
    {
        let wire = tiny_record_flood(MAX_CLIENT_HELLO_EMPTY_RECORDS + 20, 0);
        let (_raw, flooded) = drive_and_peek(&listener, listen_addr, &wire, 6);
        assert!(
            flooded,
            "an empty-record flood must surface ClientHelloFlood from the production \
             peek's no-progress budget"
        );
    }

    // ── (c) TRUNCATED handshake → NotAClientHello (record length overflows the wire) ──
    // A single record whose 5-byte header PROMISES a large payload the client never
    // sends: the peek reads to EOF with the message still incomplete, returns the
    // bytes-so-far (no flood — this is not a record-count edge), and the reassembly +
    // bounds-checked parser refuse the truncated prefix. Fail-closed, never a hang.
    {
        let mut wire = client_hello(SNI, 200);
        // Inflate the record-length field so it claims far more than we will send, then
        // chop the wire mid-payload — a record-length overflow / truncated handshake.
        let claimed = 4096u16;
        wire[3] = (claimed >> 8) as u8;
        wire[4] = (claimed & 0xff) as u8;
        wire.truncate(TLS_RECORD_HEADER_LEN + 40); // only 40 payload bytes on the wire
        let (raw_prefix, flooded) = drive_and_peek(&listener, listen_addr, &wire, 3);
        assert!(
            !flooded,
            "a truncated handshake is not a record-count flood"
        );
        assert!(
            raw_prefix.len() <= CLIENT_HELLO_PEEK_MAX,
            "the truncated peek stays bounded by the byte cap"
        );
        let reassembled = reassemble_handshake_message(&raw_prefix);
        assert!(
            parse_client_hello_sni(&reassembled).is_err(),
            "a truncated (record-length-overflow) handshake must NOT parse"
        );
        assert!(
            matches!(
                decide(
                    &reassembled,
                    &origin,
                    &map,
                    &policy,
                    Instant::from_unix_nanos(0)
                ),
                Tls1Decision::Refuse(RefuseReason::NotAClientHello)
            ),
            "a truncated handshake refuses fail-closed as NotAClientHello through the gate"
        );
    }

    // ── (d) OVER-CAP (oversized beyond CLIENT_HELLO_PEEK_MAX) → NotAClientHello ──
    // A ClientHello whose complete handshake message would exceed the 16 KiB peek cap:
    // the coalescing walk hits `OverCap` and stops reading, returns the truncated-to-cap
    // prefix, and the parser refuses. Over-cap COLLAPSES into NotAClientHello (§10.1) —
    // it is NOT a distinct flood, and it never over-buffers.
    {
        // A single record padded so the handshake body alone dwarfs the cap.
        let wire = client_hello(SNI, CLIENT_HELLO_PEEK_MAX + 4096);
        assert!(
            wire.len() > CLIENT_HELLO_PEEK_MAX,
            "the over-cap fixture must exceed the byte cap"
        );
        let (raw_prefix, flooded) = drive_and_peek(&listener, listen_addr, &wire, 8);
        assert!(
            !flooded,
            "over-cap is not a record-count flood (§10.1 collapse)"
        );
        assert!(
            raw_prefix.len() <= CLIENT_HELLO_PEEK_MAX,
            "the over-cap peek is truncated at the byte cap, never buffered past it (got {})",
            raw_prefix.len()
        );
        let reassembled = reassemble_handshake_message(&raw_prefix);
        assert!(
            parse_client_hello_sni(&reassembled).is_err(),
            "an over-cap ClientHello must NOT parse from the truncated-to-cap prefix"
        );
        assert!(
            matches!(
                decide(
                    &reassembled,
                    &origin,
                    &map,
                    &policy,
                    Instant::from_unix_nanos(0)
                ),
                Tls1Decision::Refuse(RefuseReason::NotAClientHello)
            ),
            "an over-cap ClientHello collapses into a NotAClientHello refusal (§10.1)"
        );
    }

    eprintln!(
        "LIVE record-fragment e2e PASS: coalesced record-fragmented ClientHellos ({record_counts:?} \
         records) off a real :18443-style socket THROUGH the production peek helper; SNI '{SNI}' \
         extracted; policy-allowed + live-admitted flow ADMITTED (Tunnel); SNI/dst-mismatch flow \
         REFUSED; and all four §4.1.1 fail-closed arms (record flood, empty-record flood, truncated \
         handshake, over-cap) REFUSED through the production helper."
    );
}
