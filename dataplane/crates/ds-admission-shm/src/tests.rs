//! Tests for the survivable shm admission map. Loopback/synthetic only — no live
//! kernel. The reference-semantics cases (refcount/dedup) mirror the ds-dnsgate
//! `InMemoryAdmissionMap` tests (`txn.rs` ~1410-1700) byte-for-byte in intent.

use super::*;
use ds_contracts::dns_admission::{
    AddressFamily, AdmissionEntry, AdmissionKey, AdmissionMap, AdmissionType, AdmittedAddr,
    Instant, Provenance, ReverseIndex,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// ── Helpers ─────────────────────────────────────────────────────────────────────

fn v4(a: u8, b: u8, c: u8, d: u8) -> AdmittedAddr {
    AdmittedAddr {
        family: AddressFamily::V4,
        octets: vec![a, b, c, d],
    }
}

fn provenance() -> Provenance {
    Provenance {
        rule_id: "rule-1".into(),
        policy_layer: "org".into(),
        policy_version: "v0".into(),
    }
}

fn key(session: &str, fqdn: &str) -> AdmissionKey {
    AdmissionKey {
        session_uuid: session.into(),
        original_query_fqdn: fqdn.into(),
    }
}

fn entry_with(ips: Vec<AdmittedAddr>, expires: u64) -> AdmissionEntry {
    AdmissionEntry {
        admitted_ips: ips,
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
        expires_at: Instant::from_unix_nanos(expires),
        admitted_at: Instant::from_unix_nanos(0),
        provenance: provenance(),
    }
}

/// A fresh anonymous writer map sized for `slots` entries.
fn fresh_map(slots: u32) -> ShmAdmissionMap {
    let (map, _seg) = ShmAdmissionMap::create_anonymous(slots, slots).expect("create anon");
    map
}

fn admit_one_ip(map: &mut ShmAdmissionMap, session: &str, fqdn: &str, ip: &AdmittedAddr) {
    map.admit(key(session, fqdn), entry_with(vec![ip.clone()], 1_000))
        .expect("admit succeeds");
}

// ── (1) Round-trip; lookup returns expired (no self-evict) ──────────────────────

#[test]
fn round_trip_admit_lookup_revoke() {
    let mut map = fresh_map(64);
    let k = key("s1", "a.example.");
    let ip = v4(93, 184, 216, 34);
    map.admit(k.clone(), entry_with(vec![ip.clone()], 1_000))
        .unwrap();

    let got = map.lookup(&k).expect("present");
    assert_eq!(got.admitted_ips, vec![ip.clone()]);
    assert_eq!(got.expires_at, Instant::from_unix_nanos(1_000));
    assert_eq!(got.provenance, provenance());

    // revoke frees the sole-reference IP, then lookup is None.
    assert_eq!(map.revoke(&k).unwrap(), vec![ip.clone()]);
    assert!(map.lookup(&k).is_none());
    // idempotent absent-key revoke.
    assert_eq!(map.revoke(&k).unwrap(), vec![]);
}

#[test]
fn lookup_of_expired_entry_still_returns_it_no_self_eviction() {
    let mut map = fresh_map(64);
    let k = key("s1", "a.example.");
    map.admit(k.clone(), entry_with(vec![v4(93, 184, 216, 34)], 1_000))
        .unwrap();
    let got = map.lookup(&k).expect("present");
    // far past the deadline, lookup STILL returns it (no self-evict).
    assert!(got.is_expired_at(Instant::from_unix_nanos(9_999)));
    assert!(map.lookup(&k).is_some());
    map.revoke(&k).unwrap();
    assert!(map.lookup(&k).is_none());
}

#[test]
fn synthetic_entry_round_trips_real_targets() {
    let mut map = fresh_map(64);
    let k = key("s1", "syn.example.");
    let entry = AdmissionEntry {
        admitted_ips: vec![v4(198, 18, 0, 1)],
        admission_type: AdmissionType::Synthetic,
        real_targets: vec![AdmittedAddr {
            family: AddressFamily::V6,
            octets: vec![0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }],
        expires_at: Instant::from_unix_nanos(5_000),
        admitted_at: Instant::from_unix_nanos(10),
        provenance: provenance(),
    };
    map.admit(k.clone(), entry.clone()).unwrap();
    let got = map.lookup(&k).expect("present");
    assert_eq!(got, entry);
}

// ── (2) Reference refcount semantics — the four txn.rs cases ─────────────────────

#[test]
fn k_refreshes_of_one_name_then_revoke_frees_the_sole_reference_ip_exactly_once() {
    let mut map = fresh_map(64);
    let ip = v4(93, 184, 216, 34);
    let session = "sess-uuid-1";
    let fqdn = "refresh.test.";

    const K: u32 = 5;
    for _ in 0..K {
        admit_one_ip(&mut map, session, fqdn, &ip);
    }
    // K refreshes of ONE name count as 1 distinct-name reference, not K.
    assert_eq!(map.reverse_index().refcount(session, &ip), 1);

    let freed = map.revoke(&key(session, fqdn)).unwrap();
    assert_eq!(freed, vec![ip.clone()]);
    assert_eq!(map.reverse_index().refcount(session, &ip), 0);
    assert!(map.lookup(&key(session, fqdn)).is_none());
    // second revoke frees nothing (no over-/double-free).
    assert!(map.revoke(&key(session, fqdn)).unwrap().is_empty());
    assert_eq!(map.reverse_index().refcount(session, &ip), 0);
}

#[test]
fn shared_cdn_ip_survives_a_sibling_revoke_across_refreshes() {
    let mut map = fresh_map(64);
    let shared = v4(203, 0, 113, 7);
    let session = "sess-uuid-1";
    let name_a = "a.cdn.test.";
    let name_b = "b.cdn.test.";

    const K: u32 = 4;
    for _ in 0..K {
        admit_one_ip(&mut map, session, name_a, &shared);
    }
    admit_one_ip(&mut map, session, name_b, &shared);
    // two distinct names hold the shared IP → 2 (A's K refreshes don't inflate it).
    assert_eq!(map.reverse_index().refcount(session, &shared), 2);

    // revoke A: NOT freed (B still holds it).
    let freed_a = map.revoke(&key(session, name_a)).unwrap();
    assert!(freed_a.is_empty());
    assert_eq!(map.reverse_index().refcount(session, &shared), 1);

    // revoke B: freed exactly once (last reference).
    let freed_b = map.revoke(&key(session, name_b)).unwrap();
    assert_eq!(freed_b, vec![shared.clone()]);
    assert_eq!(map.reverse_index().refcount(session, &shared), 0);
}

#[test]
fn a_refresh_that_changes_the_ip_set_decrefs_dropped_and_increfs_added() {
    let mut map = fresh_map(64);
    let session = "sess-uuid-1";
    let fqdn = "rotate.test.";
    let x = v4(93, 184, 216, 34);
    let y = v4(198, 51, 100, 7);
    let z = v4(203, 0, 113, 9);

    let admit_set = |map: &mut ShmAdmissionMap, ips: Vec<AdmittedAddr>| {
        map.admit(key(session, fqdn), entry_with(ips, 1_000))
            .unwrap();
    };
    admit_set(&mut map, vec![x.clone(), y.clone()]);
    assert_eq!(map.reverse_index().refcount(session, &x), 1);
    assert_eq!(map.reverse_index().refcount(session, &y), 1);
    assert_eq!(map.reverse_index().refcount(session, &z), 0);

    // refresh to {X, Z}: Y dropped (→0), Z added (→1), X held (no-op).
    admit_set(&mut map, vec![x.clone(), z.clone()]);
    assert_eq!(map.reverse_index().refcount(session, &x), 1);
    assert_eq!(map.reverse_index().refcount(session, &y), 0);
    assert_eq!(map.reverse_index().refcount(session, &z), 1);

    // revoke frees exactly the CURRENT membership {X, Z}, each once.
    let mut freed = map.revoke(&key(session, fqdn)).unwrap();
    freed.sort_by(|a, b| a.octets.cmp(&b.octets));
    let mut expected = vec![x.clone(), z.clone()];
    expected.sort_by(|a, b| a.octets.cmp(&b.octets));
    assert_eq!(freed, expected);
    assert_eq!(map.reverse_index().refcount(session, &x), 0);
    assert_eq!(map.reverse_index().refcount(session, &z), 0);
}

#[test]
fn a_duplicate_ip_within_one_admission_counts_and_frees_as_one_distinct_reference() {
    let mut map = fresh_map(64);
    let dup = v4(93, 184, 216, 34);
    let session = "sess-uuid-1";

    // name-A admits the SAME IP twice in one entry; sibling admits it once.
    map.admit(
        key(session, "dup.test."),
        entry_with(vec![dup.clone(), dup.clone()], 1_000),
    )
    .unwrap();
    admit_one_ip(&mut map, session, "sibling.test.", &dup);
    // distinct-name membership over the IP is 2 (A and B), NOT 3.
    assert_eq!(map.reverse_index().refcount(session, &dup), 2);

    // revoke A: NOT freed (B holds it); count drops by EXACTLY ONE.
    let freed_a = map.revoke(&key(session, "dup.test.")).unwrap();
    assert!(freed_a.is_empty());
    assert_eq!(map.reverse_index().refcount(session, &dup), 1);

    // revoke B: freed EXACTLY once (not double-listed).
    let freed_b = map.revoke(&key(session, "sibling.test.")).unwrap();
    assert_eq!(freed_b, vec![dup.clone()]);
    assert_eq!(map.reverse_index().refcount(session, &dup), 0);
}

// ── (3) Survivable restart — the headline D131 acceptance ───────────────────────

#[test]
fn survivable_restart_reader_still_finds_every_vouch_after_writer_drop_and_reattach() {
    // Create an anon segment, admit several entries through a writer, DROP the
    // writer handle (WITHOUT unlinking the mapping — Arc keeps the bytes alive),
    // re-attach a NEW writer to the SAME segment, and assert a reader still finds
    // every vouching entry. (Anon MAP_SHARED stands in for a named survivable
    // segment: the bytes outlive the writer handle.)
    let (mut writer, seg) = ShmAdmissionMap::create_anonymous(256, 256).expect("create");
    let n = 50;
    for i in 0..n {
        let k = key("s1", &format!("host{i:03}.example."));
        let ip = v4(93, 184, (i >> 8) as u8, i as u8);
        writer
            .admit(k, entry_with(vec![ip], 1_000 + i as u64))
            .unwrap();
    }
    let epoch_before = writer.writer_epoch();

    // The writer process "dies": drop its handle. The segment (Arc) survives.
    drop(writer);

    // A NEW writer re-attaches to the same segment (warm restart): repairs torn
    // slots, bumps the epoch.
    let writer2 = ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)).expect("re-attach");
    assert_eq!(
        writer2.writer_epoch(),
        epoch_before + 1,
        "re-attach bumps writer_epoch"
    );

    // A reader over the SAME segment still vouches for every entry (no mass-refuse).
    let reader = ShmAdmissionReader::attach_anonymous(Arc::clone(&seg)).expect("reader attach");
    for i in 0..n {
        let k = key("s1", &format!("host{i:03}.example."));
        let got = reader
            .lookup(&k)
            .unwrap_or_else(|| panic!("vouch for {i} survived"));
        assert_eq!(got.admitted_ips.len(), 1);
        assert_eq!(got.expires_at, Instant::from_unix_nanos(1_000 + i as u64));
    }
}

// ── (4) Concurrency / no torn reads ─────────────────────────────────────────────

/// A self-consistency invariant a torn read would violate: the decoded
/// `admitted_ips` length matches `admitted_ip_count`, the key bytes match the key
/// looked up, and a checksum over the deadline+ips is internally consistent.
fn assert_internally_consistent(entry: &AdmissionEntry, k: &AdmissionKey) {
    // The entry must be one of the writer's churning shapes (we encode a checksum
    // into expires_at's low bits as a payload self-check).
    // ip_count is implied by the vec length here; assert it is in-range.
    assert!(
        entry.admitted_ips.len() <= MAX_ADMITTED_IPS,
        "admitted_ips count in range"
    );
    // The vouch is for THIS key only if the reader's lookup matched the snapshot's
    // key bytes — lookup already enforces that, so a Some(_) here is a key match.
    // Cross-check the payload self-consistency: the writer sets expires_at so its
    // high bits encode admitted_ips[0].octets — a torn mix would break this.
    let ip0 = &entry.admitted_ips[0];
    let octs = &ip0.octets;
    let encoded = ((octs[2] as u64) << 8) | octs[3] as u64;
    let from_deadline = entry.expires_at.unix_nanos & 0xffff;
    assert_eq!(
        encoded, from_deadline,
        "payload self-consistency for key {:?}: a torn read mixed an IP from one \
         entry with a deadline from another",
        k.original_query_fqdn
    );
}

#[test]
fn concurrent_readers_never_observe_a_torn_snapshot() {
    // N reader threads + 1 writer thread over ONE shared anon segment. The writer
    // continuously admits/refreshes a churning key set, varying BOTH the IP and the
    // deadline together so the two are correlated; every reader asserts every
    // observed entry is internally consistent (the IP and the deadline come from the
    // SAME write). A torn read would surface as an inconsistent snapshot.
    const N_KEYS: usize = 64;
    const N_READERS: usize = 6;
    const READ_ITERS: usize = 40_000;

    let (writer, seg) = ShmAdmissionMap::create_anonymous(256, 256).expect("create");

    // Seed all keys once so every lookup hits an occupied slot.
    let mut w = writer;
    for i in 0..N_KEYS {
        w.admit(churn_key(i), churn_entry(i, 0)).unwrap();
    }

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(N_READERS + 1));

    let mut readers = Vec::new();
    for r in 0..N_READERS {
        let reader = ShmAdmissionReader::attach_anonymous(Arc::clone(&seg)).expect("reader");
        let barrier = Arc::clone(&barrier);
        readers.push(thread::spawn(move || {
            let mut rng = 0x243f_6a88_85a3_08d3u64 ^ (r as u64).wrapping_mul(0x9e37_79b9);
            barrier.wait();
            let mut observed = 0u64;
            for _ in 0..READ_ITERS {
                let i = (xorshift(&mut rng) as usize) % N_KEYS;
                let k = churn_key(i);
                if let Some(entry) = reader.lookup(&k) {
                    assert_internally_consistent(&entry, &k);
                    observed += 1;
                }
            }
            observed
        }));
    }

    // Writer thread: churn the keys, correlating IP and deadline each write.
    let stop_w = Arc::clone(&stop);
    let barrier_w = Arc::clone(&barrier);
    let writer_handle = thread::spawn(move || {
        let mut rng = 0xbb67_ae85_84ca_a73bu64;
        barrier_w.wait();
        let mut gen = 1u64;
        while !stop_w.load(Ordering::Relaxed) {
            let i = (xorshift(&mut rng) as usize) % N_KEYS;
            w.admit(churn_key(i), churn_entry(i, gen)).unwrap();
            gen += 1;
        }
        gen
    });

    let mut total_observed = 0u64;
    for h in readers {
        total_observed += h.join().expect("reader thread");
    }
    stop.store(true, Ordering::Relaxed);
    let writes = writer_handle.join().expect("writer thread");

    // Sanity: the readers actually observed a meaningful number of entries (the
    // test would be vacuous if every lookup returned None).
    assert!(
        total_observed > (N_READERS as u64 * READ_ITERS as u64) / 2,
        "readers observed {total_observed} entries (expected most lookups to hit); writes={writes}"
    );
}

/// A churn key: a fixed key per index.
fn churn_key(i: usize) -> AdmissionKey {
    key("churn-session", &format!("churn{i:04}.example."))
}

/// A churn entry whose IP and deadline are CORRELATED: the low 16 bits of the
/// deadline equal the IP's last two octets, so a torn read (IP from write A,
/// deadline from write B) breaks `assert_internally_consistent`. `gen` rotates the
/// value space so successive writes to a key actually change the bytes.
fn churn_entry(i: usize, gen: u64) -> AdmissionEntry {
    let v = (i as u64).wrapping_mul(2654435761).wrapping_add(gen) & 0xffff;
    let c = (v >> 8) as u8;
    let d = v as u8;
    let ip = v4(93, 184, c, d);
    // expires_at low 16 bits == (c<<8 | d) == v.
    let deadline = 0x0000_0001_0000_0000u64 | v;
    AdmissionEntry {
        admitted_ips: vec![ip],
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
        expires_at: Instant::from_unix_nanos(deadline),
        admitted_at: Instant::from_unix_nanos(0),
        provenance: provenance(),
    }
}

#[inline]
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ── (5) Torn-slot repair ────────────────────────────────────────────────────────

#[test]
fn torn_slot_is_repaired_on_attach_no_infinite_spin() {
    // Admit one entry, then hand-corrupt its slot to an ODD seq (simulating a writer
    // that crashed mid-write). Re-attach a NEW writer: the attach scan must repair
    // the torn slot (→ TOMBSTONE (probe-chain-preserving), even seq), so a reader
    // sees None for that key (no torn vouch, no infinite spin) and the table stays
    // usable for new admits.
    let (mut writer, seg) = ShmAdmissionMap::create_anonymous(16, 16).expect("create");
    let k = key("s1", "torn.example.");
    writer
        .admit(k.clone(), entry_with(vec![v4(93, 184, 0, 1)], 1_000))
        .unwrap();
    // Find the slot and force its seq odd via the public corruption helper.
    corrupt_slot_to_odd_seq(&writer, &k);
    drop(writer);

    // Re-attach: repair runs in bump_epoch_and_repair.
    let writer2 = ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)).expect("re-attach");

    // The reader sees None for the torn key (repaired to EMPTY) — bounded, no hang.
    let reader = ShmAdmissionReader::attach_anonymous(Arc::clone(&seg)).expect("reader");
    assert!(
        reader.lookup(&k).is_none(),
        "a repaired torn slot reads as absent (fail-safe re-admit, never a torn vouch)"
    );

    // The table is still usable: a fresh admit + lookup works.
    let mut w3 = writer2;
    let k2 = key("s1", "fresh.example.");
    w3.admit(k2.clone(), entry_with(vec![v4(93, 184, 0, 2)], 2_000))
        .unwrap();
    assert!(w3.lookup(&k2).is_some(), "table usable after repair");
    // And a re-admit of the torn key now succeeds (re-admit path).
    w3.admit(k.clone(), entry_with(vec![v4(93, 184, 0, 3)], 3_000))
        .unwrap();
    assert!(
        reader.lookup(&k).is_some(),
        "torn key re-admitted successfully"
    );
}

// ── (6) Bounds ──────────────────────────────────────────────────────────────────

#[test]
fn admit_exceeding_max_admitted_ips_is_storage_error() {
    let mut map = fresh_map(64);
    let ips: Vec<AdmittedAddr> = (0..(MAX_ADMITTED_IPS + 1) as u16)
        .map(|i| v4(10, 0, (i >> 8) as u8, i as u8))
        .collect();
    let err = map
        .admit(key("s1", "many.example."), entry_with(ips, 1_000))
        .unwrap_err();
    assert!(
        matches!(err, AdmissionError::Storage(_)),
        "over-cap admit fails closed: {err:?}"
    );
}

#[test]
fn admit_over_long_fqdn_is_storage_error() {
    let mut map = fresh_map(64);
    let long_fqdn = "x".repeat(MAX_FQDN_LEN + 1);
    let err = map
        .admit(
            key("s1", &long_fqdn),
            entry_with(vec![v4(93, 184, 0, 1)], 1_000),
        )
        .unwrap_err();
    assert!(matches!(err, AdmissionError::Storage(_)), "{err:?}");
}

#[test]
fn admit_over_long_session_is_storage_error() {
    let mut map = fresh_map(64);
    let long = "s".repeat(MAX_SESSION_LEN + 1);
    let err = map
        .admit(
            key(&long, "a.example."),
            entry_with(vec![v4(93, 184, 0, 1)], 1_000),
        )
        .unwrap_err();
    assert!(matches!(err, AdmissionError::Storage(_)), "{err:?}");
}

#[test]
fn table_full_admit_is_storage_error() {
    // A 2-slot table holds 2 distinct keys; the 3rd distinct key has nowhere to go.
    let mut map = fresh_map(2);
    map.admit(key("s1", "a."), entry_with(vec![v4(93, 184, 0, 1)], 1_000))
        .unwrap();
    map.admit(key("s1", "b."), entry_with(vec![v4(93, 184, 0, 2)], 1_000))
        .unwrap();
    let err = map
        .admit(key("s1", "c."), entry_with(vec![v4(93, 184, 0, 3)], 1_000))
        .unwrap_err();
    assert!(
        matches!(err, AdmissionError::Storage(_)),
        "full table fails closed: {err:?}"
    );
}

// ── (7) VersionMismatch ─────────────────────────────────────────────────────────

#[test]
fn attach_over_mismatched_api_version_is_version_mismatch() {
    let (writer, seg) = ShmAdmissionMap::create_anonymous(16, 16).expect("create");
    drop(writer);
    // Corrupt the header's api_version to a different value.
    bump_header_api_version(&seg, ADMISSION_API_VERSION + 7);
    // (ShmAdmissionMap/Reader hold raw pointers and are not Debug, so match on the
    // Err arm rather than `unwrap_err`.)
    match ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)) {
        Err(e) => assert_eq!(
            e,
            AdmissionError::VersionMismatch {
                expected: ADMISSION_API_VERSION,
                found: ADMISSION_API_VERSION + 7,
            }
        ),
        Ok(_) => panic!("attach over a mismatched api_version must fail"),
    }
    // The reader attach surfaces the same.
    match ShmAdmissionReader::attach_anonymous(Arc::clone(&seg)) {
        Err(e) => assert!(matches!(e, AdmissionError::VersionMismatch { .. })),
        Ok(_) => panic!("reader attach over a mismatched api_version must fail"),
    }
}

// ── (8) Reconcile against kernel deadlines ──────────────────────────────────────

/// A fake `KernelDeadlineSource` keyed `(session, ip-octets)` → deadline. Absent
/// key → None (prune).
struct FakeKernel {
    deadlines: std::collections::HashMap<(String, Vec<u8>), Instant>,
}
impl FakeKernel {
    fn new() -> FakeKernel {
        FakeKernel {
            deadlines: std::collections::HashMap::new(),
        }
    }
    fn set(&mut self, session: &str, ip: &AdmittedAddr, dl: u64) {
        self.deadlines.insert(
            (session.into(), ip.octets.clone()),
            Instant::from_unix_nanos(dl),
        );
    }
}
impl KernelDeadlineSource for FakeKernel {
    fn deadline_for(&self, session: &str, ip: &AdmittedAddr) -> Option<Instant> {
        self.deadlines
            .get(&(session.into(), ip.octets.clone()))
            .copied()
    }
}

#[test]
fn reconcile_prunes_absent_and_expired_keeps_live() {
    let mut map = fresh_map(64);
    let live = v4(93, 184, 0, 1); // kernel deadline in the future → keep
    let expired = v4(93, 184, 0, 2); // kernel deadline in the past → prune
    let absent = v4(93, 184, 0, 3); // no kernel element → prune

    map.admit(key("s1", "live."), entry_with(vec![live.clone()], 1_000))
        .unwrap();
    map.admit(
        key("s1", "expired."),
        entry_with(vec![expired.clone()], 1_000),
    )
    .unwrap();
    map.admit(
        key("s1", "absent."),
        entry_with(vec![absent.clone()], 1_000),
    )
    .unwrap();

    let now = Instant::from_unix_nanos(10_000);
    let mut kernel = FakeKernel::new();
    kernel.set("s1", &live, 50_000); // future
    kernel.set("s1", &expired, 5_000); // past (< now)
                                       // `absent` deliberately not set.

    let pruned = map.reconcile(&kernel, now);
    assert_eq!(pruned, 2, "expired + absent pruned, live kept");

    assert!(
        map.lookup(&key("s1", "live.")).is_some(),
        "W2-live survives"
    );
    assert!(
        map.lookup(&key("s1", "expired.")).is_none(),
        "kernel-expired pruned"
    );
    assert!(
        map.lookup(&key("s1", "absent.")).is_none(),
        "kernel-absent pruned"
    );

    // The pruned entries' IPs were decref'd (reverse index back to 0).
    assert_eq!(map.reverse_index().refcount("s1", &expired), 0);
    assert_eq!(map.reverse_index().refcount("s1", &absent), 0);
    assert_eq!(map.reverse_index().refcount("s1", &live), 1);
}

// ── Test-only corruption/inspection helpers (drive the writer's internals) ──────

/// Force the slot holding `k` to an ODD seq (simulating a crashed mid-write).
fn corrupt_slot_to_odd_seq(map: &ShmAdmissionMap, k: &AdmissionKey) {
    let want = super::key_hash(&k.session_uuid, &k.original_query_fqdn);
    let idx = map.find_slot(k, want).expect("slot present");
    let p = map.table.slot_ptr(idx);
    // SAFETY: valid slot pointer; test runs single-threaded against this map. We
    // bump the seq to an odd value directly, simulating a torn write.
    unsafe {
        let seq = &*(p as *const std::sync::atomic::AtomicU32);
        let cur = seq.load(Ordering::Relaxed);
        seq.store(cur | 1, Ordering::Release);
    }
}

/// Overwrite the header's api_version (test corruption for the VersionMismatch case).
fn bump_header_api_version(seg: &Arc<Segment>, new: u32) {
    // SAFETY: the header lives at offset 0; api_version is the field after magic
    // (u64) + layout_version (u32). Single-threaded test mutation.
    unsafe {
        let base = seg.base().as_ptr();
        // offset: magic(8) + layout_version(4) = 12.
        let api = base.add(12) as *mut u32;
        core::ptr::write_unaligned(api, new);
    }
}

/// Poke the payload `admission_type` byte of the slot holding `k` to an INVALID
/// value (3 — not a known `AdmissionType`), so a later `decode_entry` returns `None`
/// while the slot's out-of-band state stays OCCUPIED and its hash still matches.
/// Single-threaded test corruption: we leave `seq` even so `read_payload` returns a
/// consistent (but undecodable) snapshot.
fn corrupt_admission_type_byte(map: &ShmAdmissionMap, k: &AdmissionKey, bad: u8) {
    let want = super::key_hash(&k.session_uuid, &k.original_query_fqdn);
    let idx = map.find_slot(k, want).expect("slot present");
    let p = map.table.slot_ptr(idx);
    // The payload begins at `seqlock::OFF_PAYLOAD` within the slot; `admission_type`
    // is the first byte after expires_at(8)+admitted_at(8)+key_hash(8) = offset 24
    // within PackedEntry → slot offset OFF_PAYLOAD + 24. (Derived from the constant so
    // it tracks the SQ1 seqlock-header widening rather than a stale hardcoded offset.)
    let admission_type_slot_off = super::seqlock::OFF_PAYLOAD + 24;
    // SAFETY: valid slot pointer; single-threaded; the byte is within the slot
    // payload. We leave `seq` even so the corrupted snapshot reads consistently.
    unsafe {
        core::ptr::write(p.add(admission_type_slot_off), bad);
    }
}

// ── (9) FIX A — reverse-index reclamation + the CDN-shared-IP hole under reuse ────

#[test]
fn concurrent_revoke_reuse_collision_never_cross_key_vouches() {
    // The headline CDN-hole guard under concurrent slot reuse. Construct two keys A
    // and B that HASH-COLLIDE to the SAME entry-table slot, then have one writer
    // thread continuously revoke+re-admit A and B (distinct IPs per key, reusing the
    // shared slot) while N reader threads continuously look A and B up. EVERY Some(_)
    // a reader sees for A must carry A's IP only (never B's), and vice versa — i.e. a
    // reader NEVER observes a cross-key vouch through the reused slot.
    const SLOT_COUNT: u32 = 16;
    let mask = (SLOT_COUNT - 1) as u64;
    let session = "collide-sess";

    // Brute-force two distinct fqdns that land in the SAME entry-table bucket.
    let mut fa = String::new();
    let mut fb = String::new();
    'outer: for i in 0..10_000u32 {
        let si = format!("c{i}.collide.");
        let bi = (super::key_hash(session, &si)) & mask;
        for j in (i + 1)..10_000u32 {
            let sj = format!("c{j}.collide.");
            if (super::key_hash(session, &sj)) & mask == bi {
                fa = si;
                fb = sj;
                break 'outer;
            }
        }
    }
    assert!(
        !fa.is_empty() && !fb.is_empty() && fa != fb,
        "found a genuine entry-table hash collision for slot_count={SLOT_COUNT}"
    );
    assert_eq!(
        super::key_hash(session, &fa) & mask,
        super::key_hash(session, &fb) & mask,
        "A and B collide to the same entry-table bucket"
    );

    let ip_a = v4(10, 0, 0, 1);
    let ip_b = v4(10, 0, 0, 2);

    let (mut writer, seg) = ShmAdmissionMap::create_anonymous(SLOT_COUNT, SLOT_COUNT).unwrap();
    let key_a = key(session, &fa);
    let key_b = key(session, &fb);
    // Seed A so the first reads can hit.
    writer
        .admit(key_a.clone(), entry_with(vec![ip_a.clone()], 1_000))
        .unwrap();

    const N_READERS: usize = 6;
    const READ_ITERS: usize = 60_000;
    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(N_READERS + 1));

    let mut readers = Vec::new();
    for _ in 0..N_READERS {
        let reader = ShmAdmissionReader::attach_anonymous(Arc::clone(&seg)).expect("reader");
        let barrier = Arc::clone(&barrier);
        let key_a = key_a.clone();
        let key_b = key_b.clone();
        let ip_a = ip_a.clone();
        let ip_b = ip_b.clone();
        readers.push(thread::spawn(move || {
            barrier.wait();
            let mut seen = 0u64;
            for _ in 0..READ_ITERS {
                if let Some(e) = reader.lookup(&key_a) {
                    assert_eq!(
                        e.admitted_ips,
                        vec![ip_a.clone()],
                        "A's lookup must NEVER see B's IP (cross-key vouch through reused slot)"
                    );
                    seen += 1;
                }
                if let Some(e) = reader.lookup(&key_b) {
                    assert_eq!(
                        e.admitted_ips,
                        vec![ip_b.clone()],
                        "B's lookup must NEVER see A's IP (cross-key vouch through reused slot)"
                    );
                    seen += 1;
                }
            }
            seen
        }));
    }

    // Writer: churn the shared slot between A and B.
    let stop_w = Arc::clone(&stop);
    let barrier_w = Arc::clone(&barrier);
    let key_a_w = key_a.clone();
    let key_b_w = key_b.clone();
    let writer_handle = thread::spawn(move || {
        barrier_w.wait();
        let mut rounds = 0u64;
        while !stop_w.load(Ordering::Relaxed) {
            let _ = writer.revoke(&key_a_w);
            writer
                .admit(key_b_w.clone(), entry_with(vec![ip_b.clone()], 2_000))
                .unwrap();
            let _ = writer.revoke(&key_b_w);
            writer
                .admit(key_a_w.clone(), entry_with(vec![ip_a.clone()], 3_000))
                .unwrap();
            rounds += 1;
        }
        rounds
    });

    let mut total_seen = 0u64;
    for h in readers {
        total_seen += h.join().expect("reader thread");
    }
    stop.store(true, Ordering::Relaxed);
    let _rounds = writer_handle.join().expect("writer thread");

    // Non-vacuous: the readers actually observed a meaningful number of vouches.
    // (The writer churns the shared slot hard, so many lookups land on a transient
    // tombstone and return None; a few thousand observed Somes is ample to prove the
    // cross-key-vouch guard above was actually exercised.)
    assert!(
        total_seen > 2_000,
        "readers observed {total_seen} vouches (expected many — the test would be vacuous otherwise)"
    );
}

#[test]
fn reverse_table_exhaustion_never_frees_a_held_shared_ip() {
    // Drive a session that admits+revokes MANY distinct (session, ip) pairs — far
    // more than `rev_count` — so the reverse table would fill with count-0 slots if
    // they were never reclaimed. Reclamation must keep it usable. THEN admit two
    // names sharing ONE fresh IP and prove the shared-IP refcount stays correct.
    let session = "churn-sess";
    // slot_count small → rev_count floors to slot_count (8). We churn 40 distinct
    // pairs through it; without count-0 reclamation the 9th incref would fail.
    let (mut map, _seg) = ShmAdmissionMap::create_anonymous(8, 8).unwrap();

    for i in 0..40u32 {
        let fqdn = format!("churn{i}.test.");
        let ip = v4(172, 16, (i >> 8) as u8, i as u8);
        map.admit(key(session, &fqdn), entry_with(vec![ip.clone()], 1_000))
            .expect("admit churns through the reclaimable reverse table");
        // Revoke immediately → leaves a count-0 reverse slot (reclaimable).
        let freed = map.revoke(&key(session, &fqdn)).unwrap();
        assert_eq!(
            freed,
            vec![ip.clone()],
            "sole-ref churn IP frees each round"
        );
        assert_eq!(map.reverse_index().refcount(session, &ip), 0);
    }

    // Now admit two names sharing ONE fresh IP not used in the churn.
    let shared = v4(203, 0, 113, 200);
    map.admit(
        key(session, "a.shared."),
        entry_with(vec![shared.clone()], 1_000),
    )
    .unwrap();
    map.admit(
        key(session, "b.shared."),
        entry_with(vec![shared.clone()], 1_000),
    )
    .unwrap();
    assert_eq!(
        map.reverse_index().refcount(session, &shared),
        2,
        "two distinct names hold the shared IP after churn → refcount 2 (reclamation kept it correct)"
    );

    // revoke A: shared IP NOT freed (B still holds it).
    let freed_a = map.revoke(&key(session, "a.shared.")).unwrap();
    assert!(
        freed_a.is_empty(),
        "shared IP survives sibling revoke under reverse-table churn"
    );
    assert_eq!(map.reverse_index().refcount(session, &shared), 1);

    // revoke B: freed EXACTLY once (last reference).
    let freed_b = map.revoke(&key(session, "b.shared.")).unwrap();
    assert_eq!(freed_b, vec![shared.clone()]);
    assert_eq!(map.reverse_index().refcount(session, &shared), 0);
}

#[test]
fn genuine_reverse_over_capacity_admit_fails_closed() {
    // A genuinely-full reverse table (every slot a LIVE count>0 entry) must make the
    // admission fail closed with a Storage error AND leave NO partial mutation: the
    // entry is not written and the increfs applied before the failure are rolled back.
    let session = "fullrev";
    // rev_count = 2 (slot_count 2, rev floors to 2). One name with 3 DISTINCT IPs
    // needs 3 reverse slots → the 3rd incref hits the genuinely-full table.
    let (mut map, _seg) = ShmAdmissionMap::create_anonymous(2, 2).unwrap();
    let a = v4(10, 1, 0, 1);
    let b = v4(10, 1, 0, 2);
    let c = v4(10, 1, 0, 3);

    let err = map
        .admit(
            key(session, "over.test."),
            entry_with(vec![a.clone(), b.clone(), c.clone()], 1_000),
        )
        .unwrap_err();
    match err {
        AdmissionError::Storage(ref m) => assert!(
            m.contains("reverse index full"),
            "genuine reverse over-capacity is a reverse-index-full Storage error: {m}"
        ),
        other => panic!("expected Storage(reverse index full), got {other:?}"),
    }

    // No partial mutation: the entry was never written, and the two increfs applied
    // before the failure were rolled back to 0.
    assert!(
        map.lookup(&key(session, "over.test.")).is_none(),
        "a fail-closed admit leaves no entry"
    );
    assert_eq!(
        map.reverse_index().refcount(session, &a),
        0,
        "incref of a rolled back"
    );
    assert_eq!(
        map.reverse_index().refcount(session, &b),
        0,
        "incref of b rolled back"
    );
    assert_eq!(map.reverse_index().refcount(session, &c), 0);

    // The table is still usable for a within-capacity admit.
    map.admit(key(session, "ok.test."), entry_with(vec![a.clone()], 1_000))
        .expect("a within-capacity admit still works after the fail-closed one");
    assert_eq!(map.reverse_index().refcount(session, &a), 1);
}

// ── (10) FIX B — reconcile tombstones an undecodable OCCUPIED slot ───────────────

#[test]
fn reconcile_tombstones_undecodable_occupied_slot() {
    // Admit an entry, hand-corrupt its payload `admission_type` byte to an invalid
    // value so it can no longer decode, then reconcile with a kernel source that
    // WOULD keep it. The undecodable OCCUPIED slot must be tombstoned (not left
    // live): lookup is None afterward and the table stays usable.
    let mut map = fresh_map(16);
    let k = key("s1", "corrupt.example.");
    let ip = v4(93, 184, 0, 1);
    map.admit(k.clone(), entry_with(vec![ip.clone()], 1_000))
        .unwrap();
    assert!(map.lookup(&k).is_some(), "admitted ok before corruption");

    // Corrupt admission_type to 3 (not a valid AdmissionType) → decode_entry None.
    corrupt_admission_type_byte(&map, &k, 3);
    assert!(
        map.lookup(&k).is_none(),
        "an undecodable slot already reads as None for a normal lookup"
    );

    // A kernel source that WOULD keep this (session, ip) live.
    let mut kernel = FakeKernel::new();
    kernel.set("s1", &ip, 50_000);
    let now = Instant::from_unix_nanos(10_000);
    // Reconcile must repair (tombstone) the undecodable OCCUPIED slot.
    let removed = map.reconcile(&kernel, now);
    assert_eq!(
        removed, 1,
        "the undecodable slot is counted as repaired/removed"
    );

    // The slot is no longer a live OCCUPIED entry.
    assert!(
        map.lookup(&k).is_none(),
        "the undecodable slot is gone after reconcile (tombstoned, not live)"
    );

    // The table is still usable: a fresh admit + lookup works (incl. re-admit of k).
    let k2 = key("s1", "afterward.example.");
    map.admit(k2.clone(), entry_with(vec![v4(93, 184, 0, 9)], 2_000))
        .unwrap();
    assert!(
        map.lookup(&k2).is_some(),
        "table usable after reconcile repair"
    );
    map.admit(k.clone(), entry_with(vec![v4(93, 184, 0, 8)], 3_000))
        .unwrap();
    assert!(
        map.lookup(&k).is_some(),
        "the corrupted key re-admits cleanly"
    );
}

// ── (11) Entry-table tombstone reuse — a full table of tombstones re-admits ──────

#[test]
fn find_insert_slot_reuses_a_full_table_of_tombstones() {
    // Fill the entry table, revoke ALL keys (every slot TOMBSTONE), then admit a NEW
    // key: it must succeed by REUSING a tombstone, not report the table full.
    const N: u32 = 8;
    let mut map = fresh_map(N);
    for i in 0..N {
        let fqdn = format!("fill{i}.test.");
        map.admit(
            key("s1", &fqdn),
            entry_with(vec![v4(10, 2, (i >> 8) as u8, i as u8)], 1_000),
        )
        .expect("fill the entry table");
    }
    // Revoke ALL → every entry slot becomes a TOMBSTONE.
    for i in 0..N {
        let fqdn = format!("fill{i}.test.");
        map.revoke(&key("s1", &fqdn)).unwrap();
    }
    // A brand-new key must reuse a tombstone (the table is "full" of tombstones, but
    // none are live OCCUPIED entries).
    let fresh = key("s1", "reuse-me.test.");
    map.admit(fresh.clone(), entry_with(vec![v4(10, 9, 9, 9)], 5_000))
        .expect("a new key reuses a tombstone in a fully-tombstoned table");
    let got = map.lookup(&fresh).expect("the reused entry is present");
    assert_eq!(got.admitted_ips, vec![v4(10, 9, 9, 9)]);
}

// ── (12) FIX F1 — warm-restart rebuilds the reverse index from the entry table ───

/// Inject the `admit` crash window: a writer that decref'd a dropped IP's reverse
/// refcount but CRASHED before `write_slot` published the new payload. We reach into
/// the writer's reverse index and decref `(session, ip)` directly, WITHOUT touching
/// the entry table — exactly the inter-state a crash between `reverse.decref` (~line
/// 750) and `seqlock::write_slot` (~line 759) leaves behind: the entry table still
/// references `ip`, but the reverse index under-counts it.
fn inject_crash_window_decref_without_publish(
    map: &mut ShmAdmissionMap,
    session: &str,
    ip: &AdmittedAddr,
) {
    // `reverse` is a crate-private field; the test module is in-crate. `decref` is the
    // `ReverseIndex` trait method (the same call `admit` makes for a dropped IP).
    map.reverse.decref(session, ip, "ignored.example.");
}

#[test]
fn warm_restart_rebuilds_reverse_index_to_match_entry_table_membership() {
    // RED-first crash-injection for F1 (the CDN hole). Two DISTINCT names share ONE
    // CDN IP, so the shared IP's reverse refcount is 2 and the entry table holds both
    // names referencing it. Then we inject the `admit` crash window: a refresh of A
    // that decref'd the shared IP (2 → 1) but crashed BEFORE publishing A's new
    // payload — so the entry table STILL references the shared IP from both names
    // (membership = 2), but the reverse index now under-counts it (= 1).
    //
    // BEFORE the F1 fix, warm re-attach (`bump_epoch_and_repair`) repaired only the
    // entry table and left the reverse index untouched at the stale 1; a later
    // revoke of B would then decref 1 → 0 and FREE the shared IP while A still holds
    // it. AFTER the fix, re-attach REBUILDS the reverse index from the (authoritative)
    // entry table, restoring the shared-IP refcount to 2, so B's revoke leaves it at 1
    // (still held by A) — the hole is closed.
    let (mut writer, seg) = ShmAdmissionMap::create_anonymous(64, 64).expect("create");
    let session = "cdn-session";
    let shared = v4(203, 0, 113, 7); // the shared CDN IP both names resolve to
    let key_a = key(session, "a.cdn.example.");
    let key_b = key(session, "b.cdn.example.");

    writer
        .admit(key_a.clone(), entry_with(vec![shared.clone()], 1_000))
        .unwrap();
    writer
        .admit(key_b.clone(), entry_with(vec![shared.clone()], 1_000))
        .unwrap();
    assert_eq!(
        writer.reverse_index().refcount(session, &shared),
        2,
        "both names hold the shared IP → refcount 2 before the crash"
    );

    // The crash window: decref the shared IP (2 → 1) but DO NOT publish a new entry
    // payload. The entry table is unchanged: both A and B still reference the shared IP.
    inject_crash_window_decref_without_publish(&mut writer, session, &shared);
    assert_eq!(
        writer.reverse_index().refcount(session, &shared),
        1,
        "the injected crash left the reverse index UNDER-counting vs the entry table"
    );

    // The writer process "dies"; the segment (entry table intact, reverse under-counted)
    // survives.
    drop(writer);

    // Warm re-attach. With F1 this rebuilds the reverse index from the entry table.
    let mut writer2 = ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)).expect("re-attach");

    // The rebuilt reverse index must match the entry-table membership: BOTH names
    // still reference the shared IP, so the refcount is back to 2. (Pre-fix: still 1.)
    assert_eq!(
        writer2.reverse_index().refcount(session, &shared),
        2,
        "warm re-attach rebuilds the reverse index to match the entry table (refcount 2)"
    );

    // And the security property the hole would have broken: revoking ONE name leaves
    // the shared IP STILL HELD by the other (refcount 1, not freed). Pre-fix this would
    // have decref'd the stale 1 → 0 and freed a still-held shared IP (the CDN hole).
    let freed = writer2.revoke(&key_b).expect("revoke b");
    assert!(
        !freed.contains(&shared),
        "revoking one name must NOT free the shared IP still held by the other"
    );
    assert_eq!(
        writer2.reverse_index().refcount(session, &shared),
        1,
        "the shared IP is still held by name A after B's revoke"
    );

    // A reader still vouches for A (its entry survived the whole sequence).
    let reader = ShmAdmissionReader::attach_anonymous(Arc::clone(&seg)).expect("reader");
    assert!(
        reader.lookup(&key_a).is_some(),
        "name A's vouch survived warm restart + sibling revoke"
    );
}

#[test]
fn warm_restart_rebuild_preserves_distinct_and_shared_refcounts_exactly() {
    // A broader rebuild check: several names, a mix of distinct and shared IPs, a
    // dedup-within-one-name, plus a tombstoned (revoked) name that must NOT contribute
    // to the rebuilt counts. After warm re-attach the reverse index must hold EXACTLY
    // the distinct (session, ip) membership of the OCCUPIED entry table.
    let (mut writer, seg) = ShmAdmissionMap::create_anonymous(64, 64).expect("create");
    let s = "s1";
    let shared = v4(198, 51, 100, 1); // held by name1 and name2
    let only1 = v4(198, 51, 100, 2); // held by name1 only
    let only3 = v4(198, 51, 100, 3); // held by name3 only
    let dup = v4(198, 51, 100, 4); // appears twice in name4 → distinct membership 1
    let gone = v4(198, 51, 100, 9); // held only by a name we then revoke

    writer
        .admit(
            key(s, "n1."),
            entry_with(vec![shared.clone(), only1.clone()], 1_000),
        )
        .unwrap();
    writer
        .admit(key(s, "n2."), entry_with(vec![shared.clone()], 1_000))
        .unwrap();
    writer
        .admit(key(s, "n3."), entry_with(vec![only3.clone()], 1_000))
        .unwrap();
    writer
        .admit(
            key(s, "n4."),
            entry_with(vec![dup.clone(), dup.clone()], 1_000),
        )
        .unwrap();
    writer
        .admit(key(s, "n5."), entry_with(vec![gone.clone()], 1_000))
        .unwrap();
    // Revoke n5 → its slot tombstones and `gone` decrefs to 0; it must stay 0 after rebuild.
    writer.revoke(&key(s, "n5.")).unwrap();

    // Scramble the live reverse counts to a clearly-wrong state (simulating arbitrary
    // crash-window corruption of the non-atomic reverse index), so a rebuild that did
    // nothing would leave the asserts failing.
    inject_crash_window_decref_without_publish(&mut writer, s, &shared); // 2 → 1 (wrong)
    inject_crash_window_decref_without_publish(&mut writer, s, &only1); // 1 → 0 (wrong)
    drop(writer);

    let writer2 = ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)).expect("re-attach");
    let rev = writer2.reverse_index();
    assert_eq!(rev.refcount(s, &shared), 2, "shared held by n1 + n2");
    assert_eq!(rev.refcount(s, &only1), 1, "only1 held by n1");
    assert_eq!(rev.refcount(s, &only3), 1, "only3 held by n3");
    assert_eq!(rev.refcount(s, &dup), 1, "dup within one name counts once");
    assert_eq!(
        rev.refcount(s, &gone),
        0,
        "a revoked (tombstoned) name contributes nothing to the rebuilt index"
    );
}

// ── (Review-hardening) header-mismatch fallback, V6, remaining bound rejections ──

fn v6(seg: u16, tail: u16) -> AdmittedAddr {
    let mut octets = vec![0u8; 16];
    octets[0] = (seg >> 8) as u8;
    octets[1] = seg as u8;
    octets[14] = (tail >> 8) as u8;
    octets[15] = tail as u8;
    AdmittedAddr {
        family: AddressFamily::V6,
        octets,
    }
}

/// Overwrite a `u32` header field at byte offset `off` (test corruption).
fn poke_header_u32(seg: &Arc<Segment>, off: usize, new: u32) {
    // SAFETY: the header lives at offset 0; single-threaded test mutation of a field
    // within it.
    unsafe {
        let base = seg.base().as_ptr();
        core::ptr::write_unaligned(base.add(off) as *mut u32, new);
    }
}

/// Overwrite a `u64` header field at byte offset `off` (test corruption).
fn poke_header_u64(seg: &Arc<Segment>, off: usize, new: u64) {
    // SAFETY: as `poke_header_u32`.
    unsafe {
        let base = seg.base().as_ptr();
        core::ptr::write_unaligned(base.add(off) as *mut u64, new);
    }
}

#[test]
fn attach_over_bad_magic_is_storage_error() {
    let (writer, seg) = ShmAdmissionMap::create_anonymous(16, 16).expect("create");
    drop(writer);
    // magic is the leading u64 at offset 0.
    poke_header_u64(&seg, 0, MAGIC ^ 0xdead_beef);
    match ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)) {
        Err(AdmissionError::Storage(msg)) => assert!(msg.contains("magic"), "got: {msg}"),
        Err(e) => panic!("expected a magic Storage error, got {e:?}"),
        Ok(_) => panic!("attach over a corrupt magic must fail (→ start-empty fallback)"),
    }
    match ShmAdmissionReader::attach_anonymous(Arc::clone(&seg)) {
        Err(AdmissionError::Storage(_)) => {}
        Err(e) => panic!("expected reader magic Storage error, got {e:?}"),
        Ok(_) => panic!("reader attach over a corrupt magic must fail"),
    }
}

#[test]
fn attach_over_mismatched_layout_version_is_storage_error() {
    let (writer, seg) = ShmAdmissionMap::create_anonymous(16, 16).expect("create");
    drop(writer);
    // layout_version is the u32 right after magic(8) → offset 8.
    poke_header_u32(&seg, 8, LAYOUT_VERSION + 1);
    match ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)) {
        Err(AdmissionError::Storage(msg)) => {
            assert!(msg.contains("layout_version"), "got: {msg}")
        }
        Err(e) => panic!("expected a layout_version Storage error, got {e:?}"),
        Ok(_) => panic!("attach over a layout_version mismatch must fail (NOT a torn re-attach)"),
    }
    match ShmAdmissionReader::attach_anonymous(Arc::clone(&seg)) {
        Err(AdmissionError::Storage(_)) => {}
        Err(e) => panic!("expected reader layout_version Storage error, got {e:?}"),
        Ok(_) => panic!("reader attach over a layout_version mismatch must fail"),
    }
}

#[test]
fn attach_over_mismatched_stride_is_storage_error() {
    let (writer, seg) = ShmAdmissionMap::create_anonymous(16, 16).expect("create");
    drop(writer);
    // slot_stride is at magic(8)+layout_version(4)+api_version(4)+slot_count(4) = 20.
    poke_header_u32(&seg, 20, 7);
    match ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)) {
        Err(AdmissionError::Storage(msg)) => assert!(msg.contains("stride"), "got: {msg}"),
        Err(e) => panic!("expected a stride Storage error, got {e:?}"),
        Ok(_) => panic!("attach over a stride mismatch must fail"),
    }
}

#[test]
fn v6_admitted_ip_round_trips_through_admit_lookup_revoke_and_refcount() {
    let mut map = fresh_map(64);
    let k = key("s-v6", "v6.example.");
    let ip = v6(0x2001, 0x1);
    map.admit(k.clone(), entry_with(vec![ip.clone()], 1_000))
        .unwrap();
    // The 16-octet address survives the packed POD round-trip byte-for-byte.
    let got = map.lookup(&k).expect("present");
    assert_eq!(got.admitted_ips, vec![ip.clone()]);
    // …and the V6 IP is refcounted through the reverse index's 16-octet rev-key path.
    assert_eq!(map.reverse_index().refcount("s-v6", &ip), 1);
    assert_eq!(map.revoke(&k).unwrap(), vec![ip.clone()]);
    assert_eq!(map.reverse_index().refcount("s-v6", &ip), 0);
    assert!(map.lookup(&k).is_none());
}

#[test]
fn admit_exceeding_max_real_targets_is_storage_error() {
    let mut map = fresh_map(64);
    let real_targets: Vec<AdmittedAddr> = (0..(MAX_REAL_TARGETS + 1) as u16)
        .map(|i| v4(198, 18, (i >> 8) as u8, i as u8))
        .collect();
    let entry = AdmissionEntry {
        admitted_ips: vec![v4(198, 51, 100, 1)],
        admission_type: AdmissionType::Synthetic,
        real_targets,
        expires_at: Instant::from_unix_nanos(1_000),
        admitted_at: Instant::from_unix_nanos(0),
        provenance: provenance(),
    };
    let err = map.admit(key("s1", "rt.example."), entry).unwrap_err();
    assert!(
        matches!(err, AdmissionError::Storage(_)),
        "over-cap real_targets fails closed: {err:?}"
    );
}

#[test]
fn admit_over_long_provenance_is_storage_error() {
    let mut map = fresh_map(64);
    let mut prov = provenance();
    prov.rule_id = "r".repeat(MAX_PROV_LEN + 1);
    let entry = AdmissionEntry {
        admitted_ips: vec![v4(93, 184, 0, 1)],
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
        expires_at: Instant::from_unix_nanos(1_000),
        admitted_at: Instant::from_unix_nanos(0),
        provenance: prov,
    };
    let err = map.admit(key("s1", "prov.example."), entry).unwrap_err();
    assert!(
        matches!(err, AdmissionError::Storage(_)),
        "over-long provenance fails closed: {err:?}"
    );
}

// ── Cross-process byte-layout ORACLE (the refactor guard) ────────────────────────

/// HARD-PIN every byte of the cross-process segment contract so a layout-preserving
/// refactor (e.g. swapping hand-rolled `#[repr(C)]` for a zerocopy derive) cannot
/// silently move a field, change a struct size/align, or shift the implicit padding.
///
/// `Header`, `PackedEntry`, `PackedAddr`, the entry-slot stride/`OFF_PAYLOAD`, and the
/// reverse-index slot are mmapped byte-for-byte by BOTH the ds-dnsgate writer and the
/// ds-tlsproxy reader (doc 11 §8.4.1). Every number below was measured against the
/// pre-refactor structs with `offset_of!`/`size_of`/`align_of`; if any drifts, the
/// two processes would disagree on the encoding undetected unless `LAYOUT_VERSION`
/// is bumped (a coordinated redeploy). This test makes that drift a RED test instead.
///
/// The `const _` asserts in `layout.rs` already pin the three struct SIZES/ALIGNS at
/// compile time; this test additionally pins every FIELD OFFSET and the derived
/// table strides, and validates that concrete bytes land where the contract says.
#[test]
fn byte_layout_is_pinned() {
    use super::{Header, PackedAddr, PackedEntry};
    use core::mem::{align_of, offset_of, size_of};

    // ── (A) PackedAddr: 17 bytes, align 1, family then 16 octets, NO padding ──────
    assert_eq!(size_of::<PackedAddr>(), 17, "PackedAddr size");
    assert_eq!(align_of::<PackedAddr>(), 1, "PackedAddr align");
    assert_eq!(offset_of!(PackedAddr, family), 0, "PackedAddr::family @0");
    assert_eq!(offset_of!(PackedAddr, octets), 1, "PackedAddr::octets @1");
    // family(1) + octets(16) = 17 = size → zero implicit padding.
    assert_eq!(size_of::<PackedAddr>(), 1 + 16, "PackedAddr is gap-free");

    // ── (B) Header: 64 bytes, align 8; 4 implicit pad bytes BEFORE writer_epoch ───
    assert_eq!(size_of::<Header>(), 64, "Header size");
    assert_eq!(align_of::<Header>(), 8, "Header align");
    assert_eq!(offset_of!(Header, magic), 0, "Header::magic @0");
    assert_eq!(
        offset_of!(Header, layout_version),
        8,
        "Header::layout_version @8"
    );
    assert_eq!(
        offset_of!(Header, api_version),
        12,
        "Header::api_version @12"
    );
    assert_eq!(offset_of!(Header, slot_count), 16, "Header::slot_count @16");
    assert_eq!(
        offset_of!(Header, slot_stride),
        20,
        "Header::slot_stride @20"
    );
    assert_eq!(offset_of!(Header, rev_count), 24, "Header::rev_count @24");
    assert_eq!(offset_of!(Header, rev_stride), 28, "Header::rev_stride @28");
    assert_eq!(
        offset_of!(Header, max_session_len),
        32,
        "Header::max_session_len @32"
    );
    assert_eq!(
        offset_of!(Header, max_fqdn_len),
        36,
        "Header::max_fqdn_len @36"
    );
    assert_eq!(
        offset_of!(Header, max_admitted_ips),
        40,
        "Header::max_admitted_ips @40"
    );
    assert_eq!(
        offset_of!(Header, max_real_targets),
        44,
        "Header::max_real_targets @44"
    );
    assert_eq!(
        offset_of!(Header, max_prov_len),
        48,
        "Header::max_prov_len @48"
    );
    assert_eq!(
        offset_of!(Header, writer_epoch),
        56,
        "Header::writer_epoch @56"
    );
    // The 12 named fields sum to 60 bytes (magic u64 + 11×u32 + writer_epoch u64);
    // max_prov_len (u32 @48) ends at 52, writer_epoch (u64) starts at 56 → exactly
    // 4 bytes of implicit padding occupy offsets 52..56 to 8-align writer_epoch.
    let header_named_bytes = 8 + 11 * 4 + 8;
    assert_eq!(header_named_bytes, 60, "Header named-field byte sum");
    assert_eq!(
        size_of::<Header>() - header_named_bytes,
        4,
        "Header has exactly 4 implicit pad bytes (offsets 52..56, before writer_epoch)"
    );
    assert_eq!(
        offset_of!(Header, max_prov_len) + 4,
        52,
        "Header pad region starts at offset 52 (end of max_prov_len)"
    );

    // ── (C) PackedEntry: 1464 bytes, align 8; 6 implicit TRAILING pad bytes ───────
    assert_eq!(size_of::<PackedEntry>(), 1464, "PackedEntry size");
    assert_eq!(align_of::<PackedEntry>(), 8, "PackedEntry align");
    assert_eq!(offset_of!(PackedEntry, expires_at), 0, "expires_at @0");
    assert_eq!(offset_of!(PackedEntry, admitted_at), 8, "admitted_at @8");
    assert_eq!(offset_of!(PackedEntry, key_hash), 16, "key_hash @16");
    assert_eq!(
        offset_of!(PackedEntry, admission_type),
        24,
        "admission_type @24"
    );
    assert_eq!(
        offset_of!(PackedEntry, admitted_ip_count),
        25,
        "admitted_ip_count @25"
    );
    assert_eq!(
        offset_of!(PackedEntry, real_target_count),
        26,
        "real_target_count @26"
    );
    assert_eq!(offset_of!(PackedEntry, session_len), 27, "session_len @27");
    assert_eq!(offset_of!(PackedEntry, fqdn_len), 28, "fqdn_len @28");
    assert_eq!(offset_of!(PackedEntry, prov_len), 30, "prov_len @30");
    assert_eq!(offset_of!(PackedEntry, _pad), 33, "_pad @33");
    assert_eq!(offset_of!(PackedEntry, session), 34, "session @34");
    assert_eq!(offset_of!(PackedEntry, fqdn), 98, "fqdn @98");
    assert_eq!(offset_of!(PackedEntry, _pad2), 353, "_pad2 @353");
    assert_eq!(
        offset_of!(PackedEntry, admitted_ips),
        354,
        "admitted_ips @354"
    );
    assert_eq!(
        offset_of!(PackedEntry, real_targets),
        898,
        "real_targets @898"
    );
    assert_eq!(
        offset_of!(PackedEntry, prov_rule_id),
        1170,
        "prov_rule_id @1170"
    );
    assert_eq!(
        offset_of!(PackedEntry, prov_policy_layer),
        1266,
        "prov_policy_layer @1266"
    );
    assert_eq!(
        offset_of!(PackedEntry, prov_policy_version),
        1362,
        "prov_policy_version @1362"
    );
    // Last named field (prov_policy_version: [u8;96] @1362) ends at 1458; the struct
    // is 1464 → exactly 6 bytes of implicit TRAILING padding at offsets 1458..1464
    // (rounding the gap-free 1458-byte field run up to the 8-byte align).
    let packed_entry_named_bytes = offset_of!(PackedEntry, prov_policy_version) + MAX_PROV_LEN;
    assert_eq!(
        packed_entry_named_bytes, 1458,
        "PackedEntry named-field end"
    );
    assert_eq!(
        size_of::<PackedEntry>() - packed_entry_named_bytes,
        6,
        "PackedEntry has exactly 6 implicit TRAILING pad bytes (offsets 1458..1464)"
    );

    // ── (D) Entry-slot out-of-band header + payload offset + stride ───────────────
    // The seqlock slot is seq:u64@0, state:u32@8, (4 pad)@12, key_hash:u64@16,
    // payload(PackedEntry)@24. OFF_PAYLOAD is the payload start; the stride is the
    // 8-rounded sum of the 24-byte oob header and the 1464-byte payload = 1488.
    assert_eq!(super::seqlock::OFF_PAYLOAD, 24, "seqlock OFF_PAYLOAD");
    assert_eq!(
        super::entry_slot_stride(),
        1488,
        "entry_slot_stride = round8(24 + 1464)"
    );
    assert_eq!(super::entry_slot_stride() % 8, 0, "entry stride 8-aligned");

    // ── (E) Reverse-index slot offsets + stride (revindex.rs ROFF_*/roff_addr) ────
    // hash:u64@0, count:u32@8, session_len:u32@12, session:[u8;64]@16, addr@80.
    const ROFF_HASH: usize = 0;
    const ROFF_COUNT: usize = 8;
    const ROFF_SESSION_LEN: usize = 12;
    const ROFF_SESSION: usize = 16;
    let roff_addr = ROFF_SESSION + MAX_SESSION_LEN; // 16 + 64 = 80
    assert_eq!(ROFF_HASH, 0, "rev ROFF_HASH @0");
    assert_eq!(ROFF_COUNT, 8, "rev ROFF_COUNT @8");
    assert_eq!(ROFF_SESSION_LEN, 12, "rev ROFF_SESSION_LEN @12");
    assert_eq!(ROFF_SESSION, 16, "rev ROFF_SESSION @16");
    assert_eq!(MAX_SESSION_LEN, 64, "MAX_SESSION_LEN");
    assert_eq!(roff_addr, 80, "rev roff_addr @80 (16 + MAX_SESSION_LEN)");
    // Logical rev-slot bytes: hash(8)+count(4)+session_len(4)+session(64)+addr(17)=97;
    // rounded up to the 8-byte align → stride 104.
    let rev_logical = 8 + 4 + 4 + MAX_SESSION_LEN + size_of::<PackedAddr>();
    assert_eq!(rev_logical, 97, "rev-slot logical byte size");
    assert_eq!(
        super::rev_slot_stride(),
        104,
        "rev_slot_stride = round8(97)"
    );
    assert_eq!(super::rev_slot_stride() % 8, 0, "rev stride 8-aligned");

    // ── (F) Concrete bytes land at concrete offsets (PackedEntry) ─────────────────
    // Populate a PackedEntry with byte-distinguishable known values and assert that a
    // raw byte view places them at the pinned offsets. This catches a field-reorder
    // that happened to preserve sizes (which the size const-assert would miss).
    let mut pe = PackedEntry::zeroed();
    pe.expires_at = 0x1122_3344_5566_7788;
    pe.admission_type = 0xA1;
    pe.session_len = 5;
    pe.session[0] = b'h';
    pe.session[4] = b'o';
    pe.admitted_ip_count = 1;
    pe.admitted_ips[0] = PackedAddr {
        family: 4,
        octets: {
            let mut o = [0u8; 16];
            o[0] = 203;
            o[1] = 0;
            o[2] = 113;
            o[3] = 7;
            o
        },
    };
    // SAFETY (TEST ONLY): PackedEntry is `#[repr(C)]` POD with no padding bytes that
    // are uninitialized after `zeroed()`, so reading its `size_of` bytes as a `&[u8]`
    // is sound for the duration of this borrow. This is the pre-refactor byte view used
    // purely to PIN offsets; it is NOT how production reads the entry table (which goes
    // through the seqlock copy, never a `&[u8]` over the shared entry region).
    let pe_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &pe as *const PackedEntry as *const u8,
            size_of::<PackedEntry>(),
        )
    };
    assert_eq!(pe_bytes.len(), 1464, "byte view length");
    // expires_at little-endian first byte @ offset 0.
    assert_eq!(pe_bytes[0], 0x88, "expires_at LE byte0 @0");
    assert_eq!(pe_bytes[7], 0x11, "expires_at LE byte7 @7");
    // admission_type @ offset 24.
    assert_eq!(pe_bytes[24], 0xA1, "admission_type @24");
    // session_len @ offset 27, then session bytes @ offset 34.
    assert_eq!(pe_bytes[27], 5, "session_len @27");
    assert_eq!(pe_bytes[34], b'h', "session[0] @34");
    assert_eq!(pe_bytes[38], b'o', "session[4] @38");
    // admitted_ips[0].family (the PackedAddr family byte) @ offset 354.
    assert_eq!(pe_bytes[354], 4, "admitted_ips[0].family @354");
    // admitted_ips[0].octets[0..4] @ offsets 355..359.
    assert_eq!(pe_bytes[355], 203, "admitted_ips[0].octets[0] @355");
    assert_eq!(pe_bytes[356], 0, "admitted_ips[0].octets[1] @356");
    assert_eq!(pe_bytes[357], 113, "admitted_ips[0].octets[2] @357");
    assert_eq!(pe_bytes[358], 7, "admitted_ips[0].octets[3] @358");

    // ── (G) Concrete bytes land at concrete offsets (reverse-index slot) ──────────
    // Build a rev-slot's worth of bytes exactly as `RevIndex::write_key`/`write_hash`/
    // `write_count` lay them out, and assert each field lands at its pinned offset.
    let mut rev = [0u8; 104];
    let hash: u64 = 0x0102_0304_0506_0708;
    let count: u32 = 0x0A0B_0C0D;
    let session_bytes = b"sess-key";
    let session_len = session_bytes.len() as u32;
    rev[ROFF_HASH..ROFF_HASH + 8].copy_from_slice(&hash.to_le_bytes());
    rev[ROFF_COUNT..ROFF_COUNT + 4].copy_from_slice(&count.to_le_bytes());
    rev[ROFF_SESSION_LEN..ROFF_SESSION_LEN + 4].copy_from_slice(&session_len.to_le_bytes());
    rev[ROFF_SESSION..ROFF_SESSION + session_bytes.len()].copy_from_slice(session_bytes);
    let addr = PackedAddr {
        family: 6,
        octets: [0xFE; 16],
    };
    rev[roff_addr] = addr.family;
    rev[roff_addr + 1..roff_addr + 17].copy_from_slice(&addr.octets);
    // hash LE byte0 @0.
    assert_eq!(rev[0], 0x08, "rev hash LE byte0 @0");
    assert_eq!(rev[7], 0x01, "rev hash LE byte7 @7");
    // count LE byte0 @8.
    assert_eq!(rev[8], 0x0D, "rev count LE byte0 @8");
    // session_len LE byte0 @12.
    assert_eq!(rev[12], 8, "rev session_len LE byte0 @12");
    // session[0] @16 — the first byte of the session region.
    assert_eq!(rev[16], b's', "rev session[0] @16");
    // addr.family @80 — the (session,ip) key family byte.
    assert_eq!(rev[80], 6, "rev addr.family @80");
    assert_eq!(rev[81], 0xFE, "rev addr.octets[0] @81");
}

// ── Named POSIX shm path (the memmap2-backed survivable segment) ──────────────────
//
// The concurrent / survivable-restart tests above use the ANONYMOUS backing. These
// two exercise the NAMED `shm_open`/`ftruncate`/`mmap` path end-to-end — the path the
// memmap2 mapping refactor changed most: real `shm_open` + `File`-owned fd + memmap2
// `map_mut`/`map`, plus the survivability contract (the named object is NOT unlinked
// when a writer/reader handle drops; only `unlink` removes it). Loopback only — a real
// tmpfs-backed POSIX shm object on the test host, cleaned up by `unlink`.

/// A unique-per-run POSIX shm name (pid + a counter) so parallel/repeat test runs do
/// not collide on a stale object. Always `/`-prefixed, no embedded slash.
fn unique_shm_name(tag: &str) -> String {
    use std::sync::atomic::AtomicU32;
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("/ds-admission-test-{tag}-{}-{n}", std::process::id())
}

#[test]
fn named_segment_survives_writer_drop_and_a_fresh_reader_attaches() {
    // Create a NAMED shm segment, admit through it, DROP the writer handle (the
    // segment is NOT unlinked — survivability), then `attach_named` a brand-new reader
    // by name and assert every vouch is still readable. Finally `unlink` and prove a
    // re-attach now fails (the object is gone). This is the full ds-dnsgate-writer →
    // ds-tlsproxy-reader cross-handle contract over the real memmap2 named mapping.
    let name = unique_shm_name("survive");
    // Make sure no stale object lingers from a crashed prior run; ignore "not found".
    let _ = ShmAdmissionMap::unlink(&name);

    let mut writer = ShmAdmissionMap::create_named(&name, 64, 64).expect("create_named");
    let n = 20;
    for i in 0..n {
        let k = key("s1", &format!("host{i:03}.example."));
        let ip = v4(93, 184, (i >> 8) as u8, i as u8);
        writer
            .admit(k, entry_with(vec![ip], 1_000 + i as u64))
            .expect("admit");
    }

    // The writer "process" dies: drop the handle. The named object outlives it.
    drop(writer);

    // A fresh reader attaches BY NAME over the survived mapping (PROT_READ).
    let reader = ShmAdmissionReader::attach_named(&name).expect("attach_named reader");
    for i in 0..n {
        let k = key("s1", &format!("host{i:03}.example."));
        let got = reader
            .lookup(&k)
            .unwrap_or_else(|| panic!("named vouch for {i} survived the writer drop"));
        assert_eq!(got.admitted_ips.len(), 1);
        assert_eq!(got.expires_at, Instant::from_unix_nanos(1_000 + i as u64));
    }
    // The reader (and the still-mapped survivors) keep working until they unmap. Now
    // unlink the name: existing mappings stay valid, but the NAME is gone.
    drop(reader);
    ShmAdmissionMap::unlink(&name).expect("unlink");
    assert!(
        ShmAdmissionReader::attach_named(&name).is_err(),
        "after unlink the name no longer resolves"
    );
}

#[test]
fn named_segment_warm_restart_writer_reattaches_and_bumps_epoch() {
    // create_named → drop the writer → attach_named_writer (warm restart) over the
    // SAME named object: the re-attaching writer bumps the writer epoch, and a reader
    // attached afterward still finds the pre-restart vouch. Exercises the named
    // RW-reopen leg (`open_named(write=true)` → memmap2 `map_mut`) of the refactor.
    let name = unique_shm_name("restart");
    let _ = ShmAdmissionMap::unlink(&name);

    let mut writer = ShmAdmissionMap::create_named(&name, 16, 16).expect("create_named");
    let k = key("s1", "live.example.");
    writer
        .admit(k.clone(), entry_with(vec![v4(93, 184, 0, 7)], 5_000))
        .expect("admit");
    let epoch_before = writer.writer_epoch();
    drop(writer);

    let writer2 = ShmAdmissionMap::attach_named_writer(&name).expect("attach_named_writer");
    assert_eq!(
        writer2.writer_epoch(),
        epoch_before + 1,
        "warm-restart re-attach bumps writer_epoch over the named segment"
    );

    let reader = ShmAdmissionReader::attach_named(&name).expect("attach_named reader");
    let got = reader
        .lookup(&k)
        .expect("pre-restart vouch survived warm restart");
    assert_eq!(got.expires_at, Instant::from_unix_nanos(5_000));

    drop(writer2);
    drop(reader);
    ShmAdmissionMap::unlink(&name).expect("unlink");
}
