//! End-to-end proof that the D131 Candidate-A DNS-2b shm admission map is GENUINELY
//! LIVE: a ds-dnsgate-shaped WRITER runs a real W1/W2 insert-then-answer admission over
//! a `ds_admission_shm::ShmAdmissionMap` on a host-wide NAMED POSIX-shm segment, and an
//! INDEPENDENT `ds_admission_shm::ShmAdmissionReader` attached to the SAME segment by
//! name (the ds-tlsproxy read shape) reads the resulting `(session, fqdn) → entry` back.
//!
//! The writer side is the PRODUCTION wiring this keystone landed:
//! [`ds_dnsgate::txn::AdmissionStores::with_shm_writer`] (create-or-reattach the named
//! segment) → [`AdmissionStores::run_admission`] (the unchanged W1/W2 transaction, only
//! the backing map swapped from `InMemoryAdmissionMap` to `ShmAdmissionMap`). The reader
//! side is exactly what `ds-tlsproxy`'s `acquire_admission_map` attaches behind
//! `DS_TLS1_LIVE`: `ShmAdmissionReader::attach_named(<the single-sourced name>)`.
//!
//! These tests are HERMETIC: each uses a UNIQUE per-test segment name (so a stale leftover
//! never bleeds in and parallel test threads never collide) and `ShmAdmissionMap::unlink`s
//! it at the end. They need `/dev/shm` (POSIX shm); on this machine it is present, so they
//! run by default. The `live_two_process_*` leg additionally `fork()`s a child reader for a
//! REAL cross-process proof (the strongest honest form); the single-process two-handle legs
//! are the portable proof the task blesses (they still exercise `shm_open` attach-by-name
//! across independent handles).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ds_admission_shm::{ShmAdmissionMap, ShmAdmissionReader};
use ds_contracts::dns_admission::{
    AddressFamily, AdmissionKey, AdmissionType, AdmittedAddr, Instant,
};
use ds_dnsgate::server::LiveAdmissions;
use ds_dnsgate::txn::{AdmissionInputs, AdmissionOutcome, AdmissionStores, RecordingSetProgrammer};

const NANOS_PER_SEC: u64 = 1_000_000_000;
// The POL-1 schema defaults (doc 13 §1.5) the W2 clamp/grace use here — pinned in the
// inputs, never read from a code constant in the transaction itself.
const FLOOR: u32 = 60;
const CEIL: u32 = 900;
const GRACE: u32 = 60;

/// A unique-per-invocation POSIX shm name (PID + a process-local counter), so the test is
/// hermetic across parallel test threads and never reuses a stale leftover. POSIX shm names
/// must begin with `/` and carry no further `/`.
fn unique_segment_name(tag: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("/ds-admission-e2e-{tag}-{}-{n}", std::process::id())
}

fn t0() -> Instant {
    // A round second so the deadline arithmetic is exact.
    Instant::from_unix_nanos(1_000 * NANOS_PER_SEC)
}

fn normal_inputs(session: &str, fqdn: &str, addrs: Vec<IpAddr>) -> AdmissionInputs {
    AdmissionInputs {
        session_uuid: session.to_string(),
        session_index: 7,
        original_query_fqdn: fqdn.to_string(),
        terminal_addrs: addrs,
        chain_min_ttl: 300,
        ttl_floor: FLOOR,
        ttl_ceil: CEIL,
        grace: GRACE,
        provenance: ds_contracts::dns_admission::Provenance {
            rule_id: "rule-allow-e2e".into(),
            policy_layer: "org".into(),
            policy_version: "2026-06-17".into(),
        },
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> AdmittedAddr {
    AdmittedAddr {
        family: AddressFamily::V4,
        octets: vec![a, b, c, d],
    }
}

/// THE keystone proof: a ds-dnsgate shm-backed writer runs a real admission, then an
/// independent reader attached to the SAME named segment reads the entry back.
#[test]
fn dnsgate_shm_write_is_read_by_an_independent_tlsproxy_reader_over_the_named_segment() {
    let name = unique_segment_name("forward");

    // ── WRITER (ds-dnsgate production wiring) ────────────────────────────────────
    // `with_shm_writer` create-or-reattaches the NAMED segment (first boot here →
    // create); `run_admission` is the unchanged W1/W2 insert-then-answer transaction,
    // now writing through `ShmAdmissionMap` instead of `InMemoryAdmissionMap`.
    let stores = AdmissionStores::with_shm_writer(
        &name,
        Arc::new(RecordingSetProgrammer::new()),
        LiveAdmissions::new(),
    )
    .expect("create shm-backed admission stores on the named segment");

    let session = "sess-uuid-forward";
    let fqdn = "example.test.";
    let inputs = normal_inputs(
        session,
        fqdn,
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    );

    let outcome = stores.run_admission(&inputs, t0());
    let deadline = match outcome {
        AdmissionOutcome::Admitted {
            deadline,
            answered_ttl,
        } => {
            // The VM is answered the clamp WITHOUT grace (W2) — sanity that the real txn ran.
            assert_eq!(
                answered_ttl, 300,
                "answered TTL is clamp(300,60,900) no grace"
            );
            deadline
        }
        other => panic!("expected Admitted from the shm-backed W1/W2 txn, got {other:?}"),
    };
    // The deadline is answer_time + clamp + grace = 1000 + 300 + 60 = 1360s (W2).
    assert_eq!(deadline.unix_nanos, (1_000 + 300 + 60) * NANOS_PER_SEC);

    // ── READER (ds-tlsproxy read shape) ──────────────────────────────────────────
    // An INDEPENDENT handle — a fresh `shm_open` attach-by-NAME over the SAME segment,
    // exactly what `ds-tlsproxy`'s `acquire_admission_map` does behind `DS_TLS1_LIVE`.
    let reader = ShmAdmissionReader::attach_named(&name)
        .expect("attach an independent read-only reader to the same named segment");

    let key = AdmissionKey {
        session_uuid: session.to_string(),
        original_query_fqdn: fqdn.to_string(),
    };
    let entry = reader
        .lookup(&key)
        .expect("the reader sees the admission the writer's W1/W2 txn just wrote");

    // The cross-handle read carries the SAME (ip, deadline, type, provenance) the writer wrote.
    assert_eq!(
        entry.admitted_ips,
        vec![v4(93, 184, 216, 34)],
        "admitted IP round-trips"
    );
    assert_eq!(
        entry.expires_at, deadline,
        "the W2 shared deadline round-trips (lockstep)"
    );
    assert_eq!(entry.admission_type, AdmissionType::Normal);
    assert!(
        entry.real_targets.is_empty(),
        "a NORMAL admission carries no real targets"
    );
    assert_eq!(entry.provenance.rule_id, "rule-allow-e2e");
    assert_eq!(entry.provenance.policy_layer, "org");
    assert_eq!(entry.provenance.policy_version, "2026-06-17");

    // A key the writer never admitted is absent (no false positives across the seam).
    assert!(
        reader
            .lookup(&AdmissionKey {
                session_uuid: session.to_string(),
                original_query_fqdn: "never.test.".to_string(),
            })
            .is_none(),
        "an un-admitted (session, fqdn) is absent on the live reader"
    );

    // Hermetic teardown: unlink the named segment (existing mappings keep working until drop).
    ShmAdmissionMap::unlink(&name).expect("unlink the test segment");
}

/// The create-or-reattach (warm-restart) leg: a writer admits, is DROPPED (the segment
/// PERSISTS — POSIX shm survives a ds-dnsgate restart), then a SECOND `with_shm_writer`
/// REATTACHES to the same name and the prior admission is still live; an independent reader
/// confirms it. This is exactly the restart survivability `with_shm_writer` claims.
#[test]
fn shm_writer_reattaches_a_surviving_segment_and_the_prior_admission_survives() {
    let name = unique_segment_name("reattach");
    let session = "sess-uuid-reattach";
    let fqdn = "survivor.test.";
    let key = AdmissionKey {
        session_uuid: session.to_string(),
        original_query_fqdn: fqdn.to_string(),
    };

    // First boot: CREATE + admit, then DROP the writer (the segment is NOT unlinked on drop).
    {
        let stores = AdmissionStores::with_shm_writer(
            &name,
            Arc::new(RecordingSetProgrammer::new()),
            LiveAdmissions::new(),
        )
        .expect("first-boot create");
        let inputs = normal_inputs(
            session,
            fqdn,
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))],
        );
        match stores.run_admission(&inputs, t0()) {
            AdmissionOutcome::Admitted { .. } => {}
            other => panic!("expected Admitted, got {other:?}"),
        }
        // `stores` (and its writer) dropped here — the named segment persists.
    }

    // Restart: REATTACH the SAME name (warm-restart path) — the prior admission must survive.
    let stores2 = AdmissionStores::with_shm_writer(
        &name,
        Arc::new(RecordingSetProgrammer::new()),
        LiveAdmissions::new(),
    )
    .expect("warm re-attach to the surviving segment");
    let after_reattach = stores2
        .lookup(&key)
        .expect("the prior admission survives the writer restart (POSIX shm persists)");
    assert_eq!(after_reattach.admitted_ips, vec![v4(203, 0, 113, 7)]);

    // And an independent reader sees the survivor over the same name.
    let reader = ShmAdmissionReader::attach_named(&name).expect("reader attach post-reattach");
    assert_eq!(
        reader
            .lookup(&key)
            .expect("reader sees the survivor")
            .admitted_ips,
        vec![v4(203, 0, 113, 7)]
    );

    ShmAdmissionMap::unlink(&name).expect("unlink the test segment");
}

/// The STRONGEST honest form: a REAL two-process proof. The parent (writer) admits over a
/// named segment, then `fork()`s; the CHILD opens an independent `ShmAdmissionReader` over
/// the SAME name in a SEPARATE process address space and exits 0 iff the lookup matches.
/// The parent asserts the child exited 0. This exercises cross-process `shm_open` attach by
/// name end to end — not merely two handles in one process.
///
/// Gated behind `cfg(unix)` and uses a bare `fork`/`waitpid`; the child does only async-
/// signal-safe-ish work (an `shm_open`/`mmap` read + `_exit`) and never returns into the test
/// harness, so the multi-threaded-fork hazard is avoided (no allocation-heavy unwinding, no
/// re-entry into the harness; the child `_exit`s).
#[cfg(unix)]
#[test]
fn live_two_process_child_reader_sees_the_parent_writers_admission() {
    let name = unique_segment_name("twoproc");
    let session = "sess-uuid-twoproc";
    let fqdn = "crossproc.test.";

    // Parent WRITER: create + admit BEFORE the fork, so the child reads a committed entry.
    let stores = AdmissionStores::with_shm_writer(
        &name,
        Arc::new(RecordingSetProgrammer::new()),
        LiveAdmissions::new(),
    )
    .expect("parent create shm-backed stores");
    let inputs = normal_inputs(
        session,
        fqdn,
        vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))],
    );
    match stores.run_admission(&inputs, t0()) {
        AdmissionOutcome::Admitted { .. } => {}
        other => panic!("expected Admitted, got {other:?}"),
    }

    // SAFETY: a single `fork`. The child does a read-only attach + lookup + `_exit`, never
    // returning into the harness, so it touches no lock/allocator state the parent's other
    // threads might hold across the fork.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // ── CHILD (separate process) ──────────────────────────────────────────────
        let code = match ShmAdmissionReader::attach_named(&name) {
            Ok(reader) => {
                let key = AdmissionKey {
                    session_uuid: session.to_string(),
                    original_query_fqdn: fqdn.to_string(),
                };
                match reader.lookup(&key) {
                    Some(entry) if entry.admitted_ips == vec![v4(198, 51, 100, 9)] => 0,
                    Some(_) => 2, // attached + found, but wrong payload
                    None => 3,    // attached but no entry — the write was not visible
                }
            }
            Err(_) => 4, // attach failed in the child process
        };
        // SAFETY: terminate the child WITHOUT running the parent's atexit/unwind handlers.
        unsafe { libc::_exit(code) };
    }

    // ── PARENT: wait for the child and assert it read the admission (exit 0) ──────
    let mut status: libc::c_int = 0;
    // SAFETY: standard waitpid on our own child.
    let waited = unsafe { libc::waitpid(pid, &mut status as *mut libc::c_int, 0) };
    assert_eq!(waited, pid, "waitpid returned our child");
    let exited = libc::WIFEXITED(status);
    let code = libc::WEXITSTATUS(status);
    assert!(exited, "child exited normally");
    assert_eq!(
        code, 0,
        "the child process (separate address space) read the parent writer's admission \
         over the shared named segment (exit codes: 2=wrong payload, 3=not visible, 4=attach failed)"
    );

    ShmAdmissionMap::unlink(&name).expect("unlink the test segment");
}
