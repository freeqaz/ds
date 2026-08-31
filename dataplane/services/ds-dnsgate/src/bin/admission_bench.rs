//! OQ1 admission-map benchmark harness — NOT production code.
//!
//! Measures the latency / throughput characteristics that inform OQ1 (doc 14):
//! is the in-process `HashMap`-behind-a-`Mutex` DNS-2b admission map read
//! (`AdmissionMap::lookup` — the ds-tlsproxy hot path) fast enough that OQ1 can be
//! decided on warm-restart grounds alone, or does per-connection read
//! latency / lock contention itself force the move to shared memory?
//!
//! Hand-rolled timing harness (criterion is not a workspace dependency; adding it
//! would pull a large crates.io subtree). Methodology: warmup, many iterations,
//! `black_box` on both the key and the returned value to defeat dead-code
//! elimination, percentile reporting from a sorted per-op latency sample.
//!
//! Run with: `cargo run --release --bin admission_bench -p ds-dnsgate`
//! (optionally `-- --quick` for a faster smaller sweep).
//!
//! What is measured:
//!   1. `AdmissionMap::lookup` single-threaded latency by map size — measured on
//!      BOTH the real `InMemoryAdmissionMap` (the production v0 body) directly and
//!      on the real `AdmissionStores` (the handler-held `Arc<Mutex<…>>` wrapper,
//!      which is what ds-tlsproxy would actually read through, including the entry
//!      clone-out under the lock).
//!   2. Concurrent-reader contention: aggregate lookup throughput + tail latency as
//!      reader threads scale, for a `Mutex`-guarded and an `RwLock`-guarded map,
//!      with and without a concurrent low-rate writer. The Mutex path uses the REAL
//!      `InMemoryAdmissionMap`; the RwLock path wraps the same real map in an
//!      `RwLock` to model the contended-read alternative.
//!   3. Insert-then-answer transaction cost via the real `AdmissionStores::
//!      run_admission` over `RecordingSetProgrammer` (no kernel), plus an isolated
//!      `InMemoryAdmissionMap::admit` (map write only) to attribute the cost.
//!   4. (Prototype, clearly labelled) a flat open-addressed slot table with a
//!      per-entry seqlock (AtomicU32 release/acquire) read in plain process memory,
//!      compared against the HashMap+Mutex/RwLock baseline — quantifying the latency
//!      upside of the shm option's lock-free read pattern. NOT the production map.

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant as StdInstant};

use ds_contracts::dns_admission::{
    AddressFamily, AdmissionEntry, AdmissionKey, AdmissionMap, AdmissionType, AdmittedAddr,
    Instant, Provenance,
};
use ds_dnsgate::txn::{AdmissionInputs, AdmissionStores, InMemoryAdmissionMap};

// ─────────────────────────────────────────────────────────────────────────────
// Workload construction — a realistically-shaped map spanning many sessions.
// ─────────────────────────────────────────────────────────────────────────────

/// Number of distinct sessions to spread `n` entries across. Real deployments run
/// many concurrent per-session VMs each holding a handful-to-dozens of admitted
/// FQDNs; ~64 FQDNs/session is a generous busy-agent figure, so sessions ≈ n/64
/// (clamped to ≥1) keys the map the way the field would.
fn sessions_for(n: usize) -> usize {
    (n / 64).max(1)
}

fn sample_entry(seed: u64) -> AdmissionEntry {
    // Vary the IP so entries are not all identical (defeats any accidental dedup,
    // and makes the cloned-out value realistically sized: 1–2 admitted IPs).
    let a = (seed & 0xff) as u8;
    let b = ((seed >> 8) & 0xff) as u8;
    let mut ips = vec![AdmittedAddr {
        family: AddressFamily::V4,
        octets: vec![93, 184, a, b],
    }];
    if seed.is_multiple_of(3) {
        // A fraction of entries carry a second admitted IP (CDN A-record set).
        ips.push(AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![23, 45, a, b ^ 0x5a],
        });
    }
    AdmissionEntry {
        admitted_ips: ips,
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
        expires_at: Instant::from_unix_nanos(1_000_000_000 + seed),
        admitted_at: Instant::from_unix_nanos(seed),
        provenance: Provenance {
            rule_id: "rule-allow-bench".into(),
            policy_layer: "org".into(),
            policy_version: "2026-06-14".into(),
        },
    }
}

/// Build `n` distinct `(session, fqdn)` keys spread across `sessions_for(n)`
/// sessions. Returns the key vector (in insertion order) so a lookup workload can
/// probe keys that are guaranteed present.
fn build_keys(n: usize) -> Vec<AdmissionKey> {
    let sessions = sessions_for(n);
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let s = i % sessions;
        keys.push(AdmissionKey {
            // Realistic UUID-shaped session string (36 chars) so key hashing /
            // comparison costs are not understated by a tiny session id.
            session_uuid: format!("00000000-0000-4000-8000-{:012x}", s),
            // Realistic FQDN shape and length.
            original_query_fqdn: format!("host{:07}.svc{:03}.example.com.", i, s % 1000),
        });
    }
    keys
}

fn populate_map(n: usize) -> (InMemoryAdmissionMap, Vec<AdmissionKey>) {
    let keys = build_keys(n);
    let mut map = InMemoryAdmissionMap::default();
    for (i, k) in keys.iter().enumerate() {
        map.admit(k.clone(), sample_entry(i as u64))
            .expect("admit must succeed");
    }
    (map, keys)
}

// ─────────────────────────────────────────────────────────────────────────────
// A deterministic, cheap PRNG for picking probe keys (no std rng dependency, and
// cheap enough that it doesn't dominate the measured lookup).
// ─────────────────────────────────────────────────────────────────────────────

#[inline(always)]
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ─────────────────────────────────────────────────────────────────────────────
// Percentile reporting.
// ─────────────────────────────────────────────────────────────────────────────

struct Stats {
    n: usize,
    p50_ns: f64,
    p99_ns: f64,
    p999_ns: f64,
    #[allow(dead_code)]
    max_ns: f64,
    #[allow(dead_code)]
    mean_ns: f64,
}

/// Compute percentiles from a vector of per-op nanosecond samples (consumes/sorts).
fn stats_from_samples(mut samples: Vec<u64>) -> Stats {
    samples.sort_unstable();
    let n = samples.len();
    let pct = |p: f64| -> f64 {
        if n == 0 {
            return 0.0;
        }
        let idx = ((p * (n as f64 - 1.0)).round() as usize).min(n - 1);
        samples[idx] as f64
    };
    let sum: u128 = samples.iter().map(|&x| x as u128).sum();
    Stats {
        n,
        p50_ns: pct(0.50),
        p99_ns: pct(0.99),
        p999_ns: pct(0.999),
        max_ns: *samples.last().unwrap_or(&0) as f64,
        mean_ns: if n == 0 { 0.0 } else { sum as f64 / n as f64 },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (1) Single-threaded lookup latency by map size.
// ─────────────────────────────────────────────────────────────────────────────

/// Measure ns/op for `lookup` against the REAL `InMemoryAdmissionMap` directly
/// (no lock — the raw map body cost). Samples per-op latency by timing batches and
/// also a coarse batch-timed ns/op (batch-timed is the reliable ns/op; per-op
/// timing is for percentiles). Returns (batch ns/op, per-op stats).
fn bench_lookup_inmemory(
    map: &InMemoryAdmissionMap,
    keys: &[AdmissionKey],
    iters: usize,
) -> (f64, Stats) {
    let mut rng = 0x9e3779b97f4a7c15u64 ^ (keys.len() as u64);
    // Warmup.
    for _ in 0..(iters / 10).max(1000) {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        black_box(map.lookup(black_box(k)));
    }
    // Batch-timed ns/op (the authoritative throughput number — avoids per-call
    // clock overhead biasing a sub-100ns operation).
    let start = StdInstant::now();
    let mut found = 0u64;
    for _ in 0..iters {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        if black_box(map.lookup(black_box(k))).is_some() {
            found += 1;
        }
    }
    let elapsed = start.elapsed();
    black_box(found);
    assert_eq!(found as usize, iters, "all probed keys must be present");
    let batch_ns_per_op = elapsed.as_nanos() as f64 / iters as f64;

    // Per-op sample for percentiles (smaller sample; per-call clock cost included,
    // so p50 here reads higher than the batch ns/op — we report both and lean on
    // the batch number for the headline).
    let sample_n = iters.min(200_000);
    let mut samples = Vec::with_capacity(sample_n);
    for _ in 0..sample_n {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        let t0 = StdInstant::now();
        let r = map.lookup(black_box(k));
        let dt = t0.elapsed().as_nanos() as u64;
        black_box(r);
        samples.push(dt);
    }
    (batch_ns_per_op, stats_from_samples(samples))
}

/// Same workload through the REAL `AdmissionStores` wrapper — i.e. through the
/// `Arc<RwLock<InMemoryAdmissionMap>>` read guard the handler actually holds (this is
/// the real ds-tlsproxy read path: read-lock, lookup, clone entry out, unlock). The
/// store swapped its `Mutex` for an `RwLock` as the interim contention fix (D131); the
/// Mutex-vs-RwLock A/B in `bench_concurrent` below still builds both for comparison.
fn bench_lookup_stores(
    stores: &AdmissionStores,
    keys: &[AdmissionKey],
    iters: usize,
) -> (f64, Stats) {
    let mut rng = 0x2545f4914f6cdd1du64 ^ (keys.len() as u64);
    for _ in 0..(iters / 10).max(1000) {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        black_box(stores.lookup(black_box(k)));
    }
    let start = StdInstant::now();
    let mut found = 0u64;
    for _ in 0..iters {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        if black_box(stores.lookup(black_box(k))).is_some() {
            found += 1;
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(found as usize, iters);
    let batch_ns_per_op = elapsed.as_nanos() as f64 / iters as f64;

    let sample_n = iters.min(200_000);
    let mut samples = Vec::with_capacity(sample_n);
    for _ in 0..sample_n {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        let t0 = StdInstant::now();
        let r = stores.lookup(black_box(k));
        let dt = t0.elapsed().as_nanos() as u64;
        black_box(r);
        samples.push(dt);
    }
    (batch_ns_per_op, stats_from_samples(samples))
}

fn section_lookup_by_size(sizes: &[usize], iters: usize) {
    println!("\n## (1) Single-threaded lookup latency by map size");
    println!("    impl: REAL InMemoryAdmissionMap (raw, no lock) and REAL AdmissionStores (Arc<RwLock<…>>)");
    println!("    iters/size: {}  (batch ns/op is the headline; per-op p50/p99 include per-call clock cost)\n", iters);
    println!(
        "{:>8} {:>9} | {:>12} {:>10} {:>10} {:>10} | {:>12}",
        "size", "sessions", "raw ns/op", "raw p50", "raw p99", "raw p999", "M lookups/s"
    );
    println!("{}", "-".repeat(92));
    for &n in sizes {
        let (map, keys) = populate_map(n);
        let (ns_per_op, st) = bench_lookup_inmemory(&map, &keys, iters);
        let mlps = 1_000.0 / ns_per_op; // ops per ns *1e9 /1e6 = 1000/ns_per_op
        println!(
            "{:>8} {:>9} | {:>12.1} {:>10.0} {:>10.0} {:>10.0} | {:>12.1}",
            n,
            sessions_for(n),
            ns_per_op,
            st.p50_ns,
            st.p99_ns,
            st.p999_ns,
            mlps
        );
        black_box(st.n);
    }

    println!("\n    Through AdmissionStores (the real handler-held Arc<RwLock<…>> read path):\n");
    println!(
        "{:>8} {:>9} | {:>12} {:>10} {:>10} {:>10} | {:>12}",
        "size", "sessions", "store ns/op", "p50", "p99", "p999", "M lookups/s"
    );
    println!("{}", "-".repeat(92));
    for &n in sizes {
        // AdmissionStores owns its own Arc<RwLock<InMemoryAdmissionMap>> and exposes
        // no "wrap this map" ctor, so populate the store's locked map by running the
        // real insert-then-answer txn once per key, then measure the read path.
        let keys = build_keys(n);
        let stores = AdmissionStores::new();
        populate_stores(&stores, &keys);
        let (ns_per_op, st) = bench_lookup_stores(&stores, &keys, iters);
        let mlps = 1_000.0 / ns_per_op;
        println!(
            "{:>8} {:>9} | {:>12.1} {:>10.0} {:>10.0} {:>10.0} | {:>12.1}",
            n,
            sessions_for(n),
            ns_per_op,
            st.p50_ns,
            st.p99_ns,
            st.p999_ns,
            mlps
        );
    }
}

/// Populate an `AdmissionStores` map with the given keys by running the real
/// insert-then-answer transaction once per key (so the store's locked map holds the
/// same entries the raw-map benchmark used). Uses a public-internet IP so the DNS-4
/// filter admits.
fn populate_stores(stores: &AdmissionStores, keys: &[AdmissionKey]) {
    let t0 = Instant::from_unix_nanos(1_000_000_000_000);
    for (i, k) in keys.iter().enumerate() {
        let a = (i & 0xff) as u8;
        let b = ((i >> 8) & 0xff) as u8;
        let inputs = AdmissionInputs {
            session_uuid: k.session_uuid.clone(),
            session_index: (i % 16_000) as u32,
            original_query_fqdn: k.original_query_fqdn.clone(),
            terminal_addrs: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, a, b))],
            chain_min_ttl: 300,
            ttl_floor: 60,
            ttl_ceil: 900,
            grace: 60,
            provenance: Provenance {
                rule_id: "rule-allow-bench".into(),
                policy_layer: "org".into(),
                policy_version: "2026-06-14".into(),
            },
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
        };
        let _ = stores.run_admission(&inputs, t0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (2) Concurrent-reader contention — Mutex vs RwLock, ± a low-rate writer.
// ─────────────────────────────────────────────────────────────────────────────

/// Run `n_readers` threads each doing `ops_per_reader` lookups against `map`
/// (guarded by `lock_kind`), optionally with one writer thread doing a low-rate
/// stream of inserts/refreshes. Returns (aggregate Mlookups/s, worst per-op p99 ns
/// across readers, worst per-op p999 ns across readers).
fn bench_concurrent(
    n_entries: usize,
    n_readers: usize,
    ops_per_reader: usize,
    use_rwlock: bool,
    with_writer: bool,
) -> (f64, f64, f64) {
    let (map, keys) = populate_map(n_entries);
    let keys = Arc::new(keys);

    // We build BOTH a Mutex and an RwLock wrapper around an InMemoryAdmissionMap;
    // only the requested one is exercised. (Can't hold one map in two locks, so we
    // build the requested variant fresh.)
    enum Guarded {
        M(Arc<Mutex<InMemoryAdmissionMap>>),
        Rw(Arc<RwLock<InMemoryAdmissionMap>>),
    }
    let guarded = if use_rwlock {
        Guarded::Rw(Arc::new(RwLock::new(map)))
    } else {
        Guarded::M(Arc::new(Mutex::new(map)))
    };

    let barrier = Arc::new(Barrier::new(n_readers + if with_writer { 1 } else { 0 }));
    let stop = Arc::new(AtomicBool::new(false));
    let total_ops = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    // Each reader returns its own (p99, p999) ns sample.
    for r in 0..n_readers {
        let keys = Arc::clone(&keys);
        let barrier = Arc::clone(&barrier);
        let total_ops = Arc::clone(&total_ops);
        let guarded_ref: GuardedRef = match &guarded {
            Guarded::M(m) => GuardedRef::M(Arc::clone(m)),
            Guarded::Rw(rw) => GuardedRef::Rw(Arc::clone(rw)),
        };
        handles.push(thread::spawn(move || {
            let mut rng = 0x243f6a8885a308d3u64 ^ (r as u64).wrapping_mul(0x9e3779b9);
            // Per-reader latency sample (sample a subset to bound memory).
            let sample_n = ops_per_reader.min(50_000);
            let sample_stride = (ops_per_reader / sample_n).max(1);
            let mut samples = Vec::with_capacity(sample_n);
            barrier.wait();
            let mut local_found = 0u64;
            for i in 0..ops_per_reader {
                let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
                let take_sample = i % sample_stride == 0 && samples.len() < sample_n;
                if take_sample {
                    let t0 = StdInstant::now();
                    let v = guarded_ref.lookup(k);
                    let dt = t0.elapsed().as_nanos() as u64;
                    if black_box(v).is_some() {
                        local_found += 1;
                    }
                    samples.push(dt);
                } else {
                    let v = guarded_ref.lookup(k);
                    if black_box(v).is_some() {
                        local_found += 1;
                    }
                }
            }
            total_ops.fetch_add(ops_per_reader as u64, Ordering::Relaxed);
            black_box(local_found);
            stats_from_samples(samples)
        }));
    }

    // Optional low-rate writer: a refresh of an existing key roughly every ~10µs
    // (a deliberately modest admission rate — admissions are rare relative to TLS
    // connection lookups). It contends for the same lock.
    let writer_handle = if with_writer {
        let keys = Arc::clone(&keys);
        let barrier = Arc::clone(&barrier);
        let stop = Arc::clone(&stop);
        let guarded_ref: GuardedRef = match &guarded {
            Guarded::M(m) => GuardedRef::M(Arc::clone(m)),
            Guarded::Rw(rw) => GuardedRef::Rw(Arc::clone(rw)),
        };
        Some(thread::spawn(move || {
            let mut rng = 0xbb67ae8584caa73bu64;
            let mut writes = 0u64;
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                let idx = (xorshift(&mut rng) as usize) % keys.len();
                let k = keys[idx].clone();
                guarded_ref.admit(k, sample_entry(idx as u64 ^ writes));
                writes += 1;
                // Throttle: a low-rate writer, not a hammer.
                thread::sleep(Duration::from_micros(10));
            }
            black_box(writes);
        }))
    } else {
        None
    };

    let wall_start = StdInstant::now();
    let mut worst_p99 = 0.0f64;
    let mut worst_p999 = 0.0f64;
    for h in handles {
        let st = h.join().expect("reader thread");
        worst_p99 = worst_p99.max(st.p99_ns);
        worst_p999 = worst_p999.max(st.p999_ns);
    }
    let wall = wall_start.elapsed();
    stop.store(true, Ordering::Relaxed);
    if let Some(wh) = writer_handle {
        let _ = wh.join();
    }

    let ops = total_ops.load(Ordering::Relaxed) as f64;
    let mlps = ops / wall.as_secs_f64() / 1_000_000.0;
    (mlps, worst_p99, worst_p999)
}

/// A small handle enum so a reader/writer closure can hold either lock variant.
enum GuardedRef {
    M(Arc<Mutex<InMemoryAdmissionMap>>),
    Rw(Arc<RwLock<InMemoryAdmissionMap>>),
}
impl GuardedRef {
    #[inline(always)]
    fn lookup(&self, k: &AdmissionKey) -> Option<AdmissionEntry> {
        match self {
            GuardedRef::M(m) => m.lock().expect("mutex").lookup(k),
            GuardedRef::Rw(rw) => rw.read().expect("rwlock").lookup(k),
        }
    }
    fn admit(&self, k: AdmissionKey, e: AdmissionEntry) {
        match self {
            GuardedRef::M(m) => {
                let _ = m.lock().expect("mutex").admit(k, e);
            }
            GuardedRef::Rw(rw) => {
                let _ = rw.write().expect("rwlock").admit(k, e);
            }
        }
    }
}

fn section_concurrent(
    n_entries: usize,
    thread_counts: &[usize],
    ops_per_reader: usize,
    ncpu: usize,
) {
    println!(
        "\n## (2) Concurrent-reader contention (map = {} entries, {} ops/reader)",
        n_entries, ops_per_reader
    );
    println!("    impl: REAL InMemoryAdmissionMap behind std::sync::Mutex and std::sync::RwLock");
    println!("    nproc = {}\n", ncpu);
    for &with_writer in &[false, true] {
        println!(
            "  -- {} concurrent writer --",
            if with_writer {
                "WITH a low-rate (~100k/s cap) "
            } else {
                "NO "
            }
        );
        println!(
            "  {:>8} | {:>14} {:>10} {:>10} | {:>14} {:>10} {:>10}",
            "threads", "Mutex Mlk/s", "p99 ns", "p999 ns", "RwLock Mlk/s", "p99 ns", "p999 ns"
        );
        println!("  {}", "-".repeat(86));
        for &t in thread_counts {
            let (m_mlps, m_p99, m_p999) =
                bench_concurrent(n_entries, t, ops_per_reader, false, with_writer);
            let (rw_mlps, rw_p99, rw_p999) =
                bench_concurrent(n_entries, t, ops_per_reader, true, with_writer);
            println!(
                "  {:>8} | {:>14.1} {:>10.0} {:>10.0} | {:>14.1} {:>10.0} {:>10.0}",
                t, m_mlps, m_p99, m_p999, rw_mlps, rw_p99, rw_p999
            );
        }
        println!();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (3) Insert-then-answer transaction cost.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_insert_txn(iters: usize) {
    println!("\n## (3) Insert-then-answer transaction cost");
    println!(
        "    impl: REAL AdmissionStores::run_admission over RecordingSetProgrammer (no kernel),"
    );
    println!("          vs isolated InMemoryAdmissionMap::admit (map write only).");
    println!(
        "    NOTE: the RecordingSetProgrammer test fake pushes every programmed insert onto an"
    );
    println!(
        "          unbounded Vec under a Mutex (it is a recorder), and the live registry pushes"
    );
    println!(
        "          a record per admit — both GROW unboundedly over a fresh-insert run, an artifact"
    );
    println!(
        "          the production NftWriter does not have. The (3c) STEADY-STATE REFRESH number"
    );
    println!(
        "          over a bounded working set is the cleanest production-representative figure.\n"
    );

    let t0 = Instant::from_unix_nanos(1_000_000_000_000);

    // (3a) Full txn, FRESH INSERTS, distinct keys (map + recorder + live all grow).
    let stores = AdmissionStores::new();
    let n = iters;
    let keys = build_keys(n);
    {
        let warm = AdmissionStores::new();
        let wk = build_keys(2000);
        populate_stores_with(&warm, &wk, t0);
        black_box(warm.lookup(&wk[0]));
    }
    let inputs: Vec<AdmissionInputs> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| make_inputs(k, i))
        .collect();
    let mut samples = Vec::with_capacity(n.min(200_000));
    let start = StdInstant::now();
    for inp in &inputs {
        let t = StdInstant::now();
        let out = stores.run_admission(black_box(inp), t0);
        let dt = t.elapsed().as_nanos() as u64;
        black_box(out);
        if samples.len() < samples.capacity() {
            samples.push(dt);
        }
    }
    let elapsed = start.elapsed();
    let txn_ns_per_op = elapsed.as_nanos() as f64 / n as f64;
    let txn_stats = stats_from_samples(samples);

    // (3b) Map write only (isolated): InMemoryAdmissionMap::admit, fresh inserts into
    // a pre-sized map (so HashMap rehash/realloc as it grows is not counted).
    let mk_keys = build_keys(n);
    let mut map2 = InMemoryAdmissionMap::default();
    // warmup a separate map
    {
        let mut warm = InMemoryAdmissionMap::default();
        for (i, k) in mk_keys.iter().take(2000).enumerate() {
            let _ = warm.admit(k.clone(), sample_entry(i as u64));
        }
        black_box(warm.lookup(&mk_keys[0]));
    }
    let start = StdInstant::now();
    for (i, k) in mk_keys.iter().enumerate() {
        black_box(map2.admit(k.clone(), sample_entry(i as u64))).ok();
    }
    let elapsed = start.elapsed();
    let admit_ns_per_op = elapsed.as_nanos() as f64 / n as f64;

    // (3c) STEADY-STATE REFRESH: a bounded working set (W4 re-resolution path). The
    // map, recorder, and live registry do NOT grow unboundedly here — each op is a
    // refresh of an already-present key (admit = insert-OR-refresh), which is the
    // common admission-rate shape (a live agent re-resolving names it already holds).
    // This is the production-representative full-txn cost.
    let ws = 4096usize;
    let refresh_stores = AdmissionStores::new();
    let rk = build_keys(ws);
    populate_stores_with(&refresh_stores, &rk, t0);
    let rinputs: Vec<AdmissionInputs> = rk
        .iter()
        .enumerate()
        .map(|(i, k)| make_inputs(k, i))
        .collect();
    // warmup
    for inp in rinputs.iter().take(ws) {
        let _ = refresh_stores.run_admission(inp, t0);
    }
    let mut rsamples = Vec::with_capacity(iters.min(200_000));
    let start = StdInstant::now();
    for i in 0..iters {
        let inp = &rinputs[i & (ws - 1)];
        let t = StdInstant::now();
        let out = refresh_stores.run_admission(black_box(inp), t0);
        let dt = t.elapsed().as_nanos() as u64;
        black_box(out);
        if rsamples.len() < rsamples.capacity() {
            rsamples.push(dt);
        }
    }
    let elapsed = start.elapsed();
    let refresh_ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    let refresh_stats = stats_from_samples(rsamples);

    // (3d) Isolated map write on a BOUNDED working set (refresh, no growth) — the
    // apples-to-apples companion to (3c) so the map-write share is comparable.
    let mut bmap = InMemoryAdmissionMap::default();
    for (i, k) in rk.iter().enumerate() {
        let _ = bmap.admit(k.clone(), sample_entry(i as u64));
    }
    // warmup
    for (i, k) in rk.iter().enumerate() {
        let _ = bmap.admit(k.clone(), sample_entry(i as u64));
    }
    let start = StdInstant::now();
    for i in 0..iters {
        let idx = i & (ws - 1);
        black_box(bmap.admit(rk[idx].clone(), sample_entry(idx as u64))).ok();
    }
    let elapsed = start.elapsed();
    let admit_refresh_ns = elapsed.as_nanos() as f64 / iters as f64;
    black_box(bmap.lookup(&rk[0]));

    println!("    (3a) full txn, FRESH inserts   : {:>9.1} ns/op  (p50 {:.0} / p99 {:.0} / p999 {:.0} ns)  [grows recorder+live — upper bound]",
        txn_ns_per_op, txn_stats.p50_ns, txn_stats.p99_ns, txn_stats.p999_ns);
    println!("    (3b) map write only, FRESH     : {:>9.1} ns/op  [insert into growing map: String key clones + rehash + delta-refcount HashSet alloc]",
        admit_ns_per_op);
    println!("    (3c) full txn, STEADY refresh  : {:>9.1} ns/op  (p50 {:.0} / p99 {:.0} / p999 {:.0} ns)  [bounded WS — production-representative]",
        refresh_ns_per_op, refresh_stats.p50_ns, refresh_stats.p99_ns, refresh_stats.p999_ns);
    println!("    (3d) map write only, REFRESH   : {:>9.1} ns/op  [bounded WS, same path as 3c's map write]",
        admit_refresh_ns);
    println!("    => On the bounded-WS refresh path (3c vs 3d) the map write is ~{:.0}% of the full transaction; the remainder is set-program (record) + live-record + clamp/deadline maths.",
        admit_refresh_ns / refresh_ns_per_op * 100.0);
}

fn make_inputs(k: &AdmissionKey, i: usize) -> AdmissionInputs {
    let a = (i & 0xff) as u8;
    let b = ((i >> 8) & 0xff) as u8;
    AdmissionInputs {
        session_uuid: k.session_uuid.clone(),
        session_index: (i % 16_000) as u32,
        original_query_fqdn: k.original_query_fqdn.clone(),
        terminal_addrs: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, a, b))],
        chain_min_ttl: 300,
        ttl_floor: 60,
        ttl_ceil: 900,
        grace: 60,
        provenance: Provenance {
            rule_id: "rule-allow-bench".into(),
            policy_layer: "org".into(),
            policy_version: "2026-06-14".into(),
        },
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
    }
}

fn populate_stores_with(stores: &AdmissionStores, keys: &[AdmissionKey], t0: Instant) {
    for (i, k) in keys.iter().enumerate() {
        let inp = make_inputs(k, i);
        let _ = stores.run_admission(&inp, t0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (4) PROTOTYPE: flat open-addressed slot table with per-entry seqlock.
//     This is NOT the production map — it models the shm read pattern (lock-free
//     seqlock reads against a fixed-capacity slot table in plain process memory) so
//     we can quantify the read-latency upside of the shm option.
// ─────────────────────────────────────────────────────────────────────────────

/// A fixed-capacity, open-addressed (linear-probe) slot table with a per-slot
/// seqlock. Readers never take a lock: they read the seq (acquire), copy the value,
/// read the seq again (acquire), and retry if the seq changed or was odd (a writer
/// was mid-update). This is the canonical lock-free shm read pattern.
///
/// To keep the value fixed-size (the shm constraint — no heap pointers across the
/// mapping), the prototype stores a value PAYLOAD that mirrors the load-bearing
/// part of an AdmissionEntry the hot path reads: the shared deadline (expires_at,
/// u64 nanos) + admission_type tag + up to 2 admitted IPv4 IPs (the common case).
/// A real shm map would store the full entry as a packed POD; this captures the
/// read pattern and the same key-hash + probe + memcpy cost class.
struct SeqlockSlotTable {
    cap: usize,
    mask: usize,
    seq: Vec<AtomicU32>,
    // Key fingerprint (64-bit hash of (session,fqdn)) for occupancy + match; a real
    // impl would also store the full key bytes to defeat collisions, but for a
    // read-latency model the hash compare is the dominant cost and is what we time.
    key_hash: Vec<AtomicU64>,
    occupied: Vec<AtomicBool>,
    // Packed value payload, one per slot: [deadline_nanos:u64, type:u32, ip_count:u32, ip0:u32, ip1:u32].
    val_deadline: Vec<AtomicU64>,
    val_type: Vec<AtomicU32>,
    val_ipcount: Vec<AtomicU32>,
    val_ip0: Vec<AtomicU32>,
    val_ip1: Vec<AtomicU32>,
}

/// FNV-1a 64-bit over the key's two string fields with a separator — a cheap,
/// deterministic key fingerprint for the prototype.
fn key_hash(k: &AdmissionKey) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for byte in k.session_uuid.as_bytes() {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= 0x1f; // separator
    h = h.wrapping_mul(0x100000001b3);
    for byte in k.original_query_fqdn.as_bytes() {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    // never 0 (0 reserved as "empty fingerprint")
    if h == 0 {
        1
    } else {
        h
    }
}

/// The read payload (what a hot-path reader copies out).
#[derive(Clone, Copy)]
struct SeqVal {
    deadline_nanos: u64,
    type_tag: u32,
    ip_count: u32,
    ip0: u32,
    ip1: u32,
}

impl SeqlockSlotTable {
    fn with_capacity(min_cap: usize) -> Self {
        // round up to power of two, ~2x load factor headroom.
        let cap = (min_cap.max(1) * 2).next_power_of_two();
        let mk_u32 = || (0..cap).map(|_| AtomicU32::new(0)).collect::<Vec<_>>();
        let mk_u64 = || (0..cap).map(|_| AtomicU64::new(0)).collect::<Vec<_>>();
        let mk_bool = || (0..cap).map(|_| AtomicBool::new(false)).collect::<Vec<_>>();
        Self {
            cap,
            mask: cap - 1,
            seq: mk_u32(),
            key_hash: mk_u64(),
            occupied: mk_bool(),
            val_deadline: mk_u64(),
            val_type: mk_u32(),
            val_ipcount: mk_u32(),
            val_ip0: mk_u32(),
            val_ip1: mk_u32(),
        }
    }

    /// Single-writer insert (the gate is the sole writer): linear probe to the slot,
    /// bump seq odd (writer-in), publish fields (relaxed under the odd seq), bump seq
    /// even+1 (release) to publish.
    fn insert(&self, k: &AdmissionKey, v: SeqVal) {
        let fp = key_hash(k);
        let mut idx = (fp as usize) & self.mask;
        loop {
            let occ = self.occupied[idx].load(Ordering::Acquire);
            let existing = self.key_hash[idx].load(Ordering::Acquire);
            if !occ || existing == fp {
                // Take/refresh this slot.
                let s = self.seq[idx].load(Ordering::Relaxed);
                // mark writer-in (odd)
                self.seq[idx].store(s | 1, Ordering::Release);
                std::sync::atomic::fence(Ordering::Release);
                self.key_hash[idx].store(fp, Ordering::Relaxed);
                self.val_deadline[idx].store(v.deadline_nanos, Ordering::Relaxed);
                self.val_type[idx].store(v.type_tag, Ordering::Relaxed);
                self.val_ipcount[idx].store(v.ip_count, Ordering::Relaxed);
                self.val_ip0[idx].store(v.ip0, Ordering::Relaxed);
                self.val_ip1[idx].store(v.ip1, Ordering::Relaxed);
                self.occupied[idx].store(true, Ordering::Relaxed);
                // publish (even, release)
                self.seq[idx].store((s | 1).wrapping_add(1), Ordering::Release);
                return;
            }
            idx = (idx + 1) & self.mask;
        }
    }

    /// Lock-free seqlock read (the hot path). Returns the payload if the key's
    /// fingerprint is found, else None. Retries while a writer is mid-update.
    #[inline(always)]
    fn lookup(&self, k: &AdmissionKey) -> Option<SeqVal> {
        let fp = key_hash(k);
        let mut idx = (fp as usize) & self.mask;
        let mut probes = 0usize;
        loop {
            // seqlock read of this slot.
            loop {
                let s1 = self.seq[idx].load(Ordering::Acquire);
                if s1 & 1 != 0 {
                    // writer in progress; spin-retry this slot.
                    std::hint::spin_loop();
                    continue;
                }
                let occ = self.occupied[idx].load(Ordering::Acquire);
                let fp_here = self.key_hash[idx].load(Ordering::Acquire);
                let v = SeqVal {
                    deadline_nanos: self.val_deadline[idx].load(Ordering::Relaxed),
                    type_tag: self.val_type[idx].load(Ordering::Relaxed),
                    ip_count: self.val_ipcount[idx].load(Ordering::Relaxed),
                    ip0: self.val_ip0[idx].load(Ordering::Relaxed),
                    ip1: self.val_ip1[idx].load(Ordering::Relaxed),
                };
                let s2 = self.seq[idx].load(Ordering::Acquire);
                if s1 != s2 {
                    // a write landed during the copy; retry.
                    continue;
                }
                if !occ {
                    return None; // empty slot ⇒ key absent
                }
                if fp_here == fp {
                    return Some(v);
                }
                break; // occupied by a different key ⇒ continue probing
            }
            probes += 1;
            if probes > self.cap {
                return None;
            }
            idx = (idx + 1) & self.mask;
        }
    }
}

fn seqval_for(seed: u64) -> SeqVal {
    let a = (seed & 0xff) as u32;
    let b = ((seed >> 8) & 0xff) as u32;
    SeqVal {
        deadline_nanos: 1_000_000_000 + seed,
        type_tag: 0,
        ip_count: if seed.is_multiple_of(3) { 2 } else { 1 },
        ip0: (93 << 24) | (184 << 16) | (a << 8) | b,
        ip1: (23 << 24) | (45 << 16) | (a << 8) | (b ^ 0x5a),
    }
}

fn build_seqlock_table(keys: &[AdmissionKey]) -> SeqlockSlotTable {
    let t = SeqlockSlotTable::with_capacity(keys.len());
    for (i, k) in keys.iter().enumerate() {
        t.insert(k, seqval_for(i as u64));
    }
    t
}

fn bench_seqlock_single(
    table: &SeqlockSlotTable,
    keys: &[AdmissionKey],
    iters: usize,
) -> (f64, Stats) {
    let mut rng = 0x510e527fade682d1u64 ^ (keys.len() as u64);
    for _ in 0..(iters / 10).max(1000) {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        black_box(table.lookup(black_box(k)));
    }
    let start = StdInstant::now();
    let mut found = 0u64;
    for _ in 0..iters {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        if black_box(table.lookup(black_box(k))).is_some() {
            found += 1;
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(found as usize, iters, "seqlock: all probed keys present");
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;

    let sample_n = iters.min(200_000);
    let mut samples = Vec::with_capacity(sample_n);
    for _ in 0..sample_n {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        let t0 = StdInstant::now();
        let r = table.lookup(black_box(k));
        let dt = t0.elapsed().as_nanos() as u64;
        black_box(r);
        samples.push(dt);
    }
    (ns_per_op, stats_from_samples(samples))
}

fn bench_seqlock_concurrent(
    n_entries: usize,
    n_readers: usize,
    ops_per_reader: usize,
    with_writer: bool,
) -> (f64, f64, f64) {
    let keys = Arc::new(build_keys(n_entries));
    let table = Arc::new(build_seqlock_table(&keys));
    let barrier = Arc::new(Barrier::new(n_readers + if with_writer { 1 } else { 0 }));
    let stop = Arc::new(AtomicBool::new(false));
    let total_ops = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for r in 0..n_readers {
        let keys = Arc::clone(&keys);
        let table = Arc::clone(&table);
        let barrier = Arc::clone(&barrier);
        let total_ops = Arc::clone(&total_ops);
        handles.push(thread::spawn(move || {
            let mut rng = 0x9b05688c2b3e6c1fu64 ^ (r as u64).wrapping_mul(0x9e3779b9);
            let sample_n = ops_per_reader.min(50_000);
            let sample_stride = (ops_per_reader / sample_n).max(1);
            let mut samples = Vec::with_capacity(sample_n);
            barrier.wait();
            let mut found = 0u64;
            for i in 0..ops_per_reader {
                let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
                if i % sample_stride == 0 && samples.len() < sample_n {
                    let t0 = StdInstant::now();
                    let v = table.lookup(k);
                    samples.push(t0.elapsed().as_nanos() as u64);
                    if black_box(v).is_some() {
                        found += 1;
                    }
                } else if black_box(table.lookup(k)).is_some() {
                    found += 1;
                }
            }
            total_ops.fetch_add(ops_per_reader as u64, Ordering::Relaxed);
            black_box(found);
            stats_from_samples(samples)
        }));
    }
    let writer_handle = if with_writer {
        let keys = Arc::clone(&keys);
        let table = Arc::clone(&table);
        let barrier = Arc::clone(&barrier);
        let stop = Arc::clone(&stop);
        Some(thread::spawn(move || {
            let mut rng = 0xc2b2ae3d27d4eb4fu64;
            let mut w = 0u64;
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                let idx = (xorshift(&mut rng) as usize) % keys.len();
                table.insert(&keys[idx], seqval_for(idx as u64 ^ w));
                w += 1;
                thread::sleep(Duration::from_micros(10));
            }
            black_box(w);
        }))
    } else {
        None
    };

    let wall_start = StdInstant::now();
    let mut worst_p99 = 0.0f64;
    let mut worst_p999 = 0.0f64;
    for h in handles {
        let st = h.join().expect("seqlock reader");
        worst_p99 = worst_p99.max(st.p99_ns);
        worst_p999 = worst_p999.max(st.p999_ns);
    }
    let wall = wall_start.elapsed();
    stop.store(true, Ordering::Relaxed);
    if let Some(wh) = writer_handle {
        let _ = wh.join();
    }
    let ops = total_ops.load(Ordering::Relaxed) as f64;
    let mlps = ops / wall.as_secs_f64() / 1_000_000.0;
    (mlps, worst_p99, worst_p999)
}

fn section_seqlock(
    sizes: &[usize],
    iters: usize,
    n_entries: usize,
    thread_counts: &[usize],
    ops_per_reader: usize,
) {
    println!("\n## (4) PROTOTYPE: flat seqlock slot table (models the shm lock-free read pattern)");
    println!("    NOT the production map. Plain process memory; per-entry seqlock (AtomicU32 release/acquire).");
    println!("    Single-threaded read latency by size:\n");
    println!(
        "{:>8} | {:>12} {:>10} {:>10} {:>10} | {:>12}",
        "size", "ns/op", "p50", "p99", "p999", "M lookups/s"
    );
    println!("{}", "-".repeat(74));
    for &n in sizes {
        let keys = build_keys(n);
        let table = build_seqlock_table(&keys);
        let (ns_per_op, st) = bench_seqlock_single(&table, &keys, iters);
        println!(
            "{:>8} | {:>12.1} {:>10.0} {:>10.0} {:>10.0} | {:>12.1}",
            n,
            ns_per_op,
            st.p50_ns,
            st.p99_ns,
            st.p999_ns,
            1_000.0 / ns_per_op
        );
    }

    println!(
        "\n    Concurrent-reader scaling (seqlock, map = {} entries):\n",
        n_entries
    );
    for &with_writer in &[false, true] {
        println!(
            "  -- {} writer --",
            if with_writer { "WITH low-rate" } else { "NO" }
        );
        println!(
            "  {:>8} | {:>14} {:>10} {:>10}",
            "threads", "seqlock Mlk/s", "p99 ns", "p999 ns"
        );
        println!("  {}", "-".repeat(48));
        for &t in thread_counts {
            let (mlps, p99, p999) =
                bench_seqlock_concurrent(n_entries, t, ops_per_reader, with_writer);
            println!("  {:>8} | {:>14.1} {:>10.0} {:>10.0}", t, mlps, p99, p999);
        }
        println!();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (5) REAL ds-admission-shm map (seqlock over a real MAP_SHARED segment, full
//     entry payload). NOT a prototype: this is the production D131 Candidate-A
//     crate, read through its `ShmAdmissionReader` lock-free seqlock lookup (the
//     ds-tlsproxy hot path) over a real anonymous MAP_SHARED segment. Apples-to-
//     apples with sections (2) and (4): same sizes, same thread sweep, same
//     ± writer, so the shm read latency is directly comparable to Mutex/RwLock and
//     to the (4) flat prototype.
// ─────────────────────────────────────────────────────────────────────────────

use ds_admission_shm::{ShmAdmissionMap, ShmAdmissionReader};

/// Build a real shm writer over an anonymous MAP_SHARED segment, admit `keys`
/// (the same workload the other sections use), and return the writer + a reader
/// over the SAME segment. The reader is the ds-tlsproxy shape (read-only lookup).
fn build_real_shm(
    keys: &[AdmissionKey],
) -> (ShmAdmissionMap, std::sync::Arc<ds_admission_shm::Segment>) {
    // Size for the workload with ~2x headroom (power-of-two rounding is internal).
    let cap = (keys.len() * 2).max(2) as u32;
    let (mut writer, seg) =
        ShmAdmissionMap::create_anonymous(cap, cap).expect("create anon shm segment");
    for (i, k) in keys.iter().enumerate() {
        writer
            .admit(k.clone(), sample_entry(i as u64))
            .expect("shm admit must succeed (within bounds)");
    }
    (writer, seg)
}

/// Single-threaded real-shm lookup latency through `ShmAdmissionReader` (the
/// ds-tlsproxy read path) over a real MAP_SHARED segment.
fn bench_real_shm_single(
    reader: &ShmAdmissionReader,
    keys: &[AdmissionKey],
    iters: usize,
) -> (f64, Stats) {
    let mut rng = 0x14057b7ef767814fu64 ^ (keys.len() as u64);
    for _ in 0..(iters / 10).max(1000) {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        black_box(reader.lookup(black_box(k)));
    }
    let start = StdInstant::now();
    let mut found = 0u64;
    for _ in 0..iters {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        if black_box(reader.lookup(black_box(k))).is_some() {
            found += 1;
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(found as usize, iters, "real shm: all probed keys present");
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;

    let sample_n = iters.min(200_000);
    let mut samples = Vec::with_capacity(sample_n);
    for _ in 0..sample_n {
        let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
        let t0 = StdInstant::now();
        let r = reader.lookup(black_box(k));
        let dt = t0.elapsed().as_nanos() as u64;
        black_box(r);
        samples.push(dt);
    }
    (ns_per_op, stats_from_samples(samples))
}

/// Concurrent real-shm reader scaling: `n_readers` threads each holding their own
/// `ShmAdmissionReader` over ONE shared segment, optionally with the single writer
/// churning admits/refreshes (a real cross-thread MAP_SHARED race, the production
/// single-writer/many-reader shape).
fn bench_real_shm_concurrent(
    n_entries: usize,
    n_readers: usize,
    ops_per_reader: usize,
    with_writer: bool,
) -> (f64, f64, f64) {
    let keys = Arc::new(build_keys(n_entries));
    let (writer, seg) = build_real_shm(&keys);

    let barrier = Arc::new(Barrier::new(n_readers + if with_writer { 1 } else { 0 }));
    let stop = Arc::new(AtomicBool::new(false));
    let total_ops = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for r in 0..n_readers {
        let keys = Arc::clone(&keys);
        let barrier = Arc::clone(&barrier);
        let total_ops = Arc::clone(&total_ops);
        // Each reader maps the SAME segment read-only (the ds-tlsproxy shape).
        let reader = ShmAdmissionReader::attach_anonymous(Arc::clone(&seg))
            .expect("reader attach to shared segment");
        handles.push(thread::spawn(move || {
            let mut rng = 0x9e3779b97f4a7c15u64 ^ (r as u64).wrapping_mul(0x9e3779b9);
            let sample_n = ops_per_reader.min(50_000);
            let sample_stride = (ops_per_reader / sample_n).max(1);
            let mut samples = Vec::with_capacity(sample_n);
            barrier.wait();
            let mut found = 0u64;
            for i in 0..ops_per_reader {
                let k = &keys[(xorshift(&mut rng) as usize) % keys.len()];
                if i % sample_stride == 0 && samples.len() < sample_n {
                    let t0 = StdInstant::now();
                    let v = reader.lookup(k);
                    samples.push(t0.elapsed().as_nanos() as u64);
                    if black_box(v).is_some() {
                        found += 1;
                    }
                } else if black_box(reader.lookup(k)).is_some() {
                    found += 1;
                }
            }
            total_ops.fetch_add(ops_per_reader as u64, Ordering::Relaxed);
            black_box(found);
            stats_from_samples(samples)
        }));
    }

    let writer_handle = if with_writer {
        let keys = Arc::clone(&keys);
        let barrier = Arc::clone(&barrier);
        let stop = Arc::clone(&stop);
        let mut writer = writer;
        Some(thread::spawn(move || {
            let mut rng = 0xc2b2ae3d27d4eb4fu64;
            let mut w = 0u64;
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                let idx = (xorshift(&mut rng) as usize) % keys.len();
                let _ = writer.admit(keys[idx].clone(), sample_entry(idx as u64 ^ w));
                w += 1;
                thread::sleep(Duration::from_micros(10));
            }
            black_box(w);
        }))
    } else {
        // Hold the writer alive (and thus the segment) for the no-writer case.
        drop(writer);
        None
    };

    let wall_start = StdInstant::now();
    let mut worst_p99 = 0.0f64;
    let mut worst_p999 = 0.0f64;
    for h in handles {
        let st = h.join().expect("real shm reader");
        worst_p99 = worst_p99.max(st.p99_ns);
        worst_p999 = worst_p999.max(st.p999_ns);
    }
    let wall = wall_start.elapsed();
    stop.store(true, Ordering::Relaxed);
    if let Some(wh) = writer_handle {
        let _ = wh.join();
    }
    // Keep the segment alive until all readers are joined.
    drop(seg);
    let ops = total_ops.load(Ordering::Relaxed) as f64;
    let mlps = ops / wall.as_secs_f64() / 1_000_000.0;
    (mlps, worst_p99, worst_p999)
}

fn section_real_shm(
    sizes: &[usize],
    iters: usize,
    n_entries: usize,
    thread_counts: &[usize],
    ops_per_reader: usize,
) {
    println!("\n## (5) REAL ds-admission-shm map (seqlock over a real MAP_SHARED segment, full entry payload)");
    println!(
        "    The PRODUCTION D131 Candidate-A crate, read through ShmAdmissionReader (ds-tlsproxy"
    );
    println!(
        "    lock-free seqlock lookup) over a real anonymous MAP_SHARED segment. Full PackedEntry"
    );
    println!("    payload decode per lookup (octets, deadline, provenance) — heavier than (4)'s prototype.");
    println!("    Single-threaded read latency by size:\n");
    println!(
        "{:>8} | {:>12} {:>10} {:>10} {:>10} | {:>12}",
        "size", "ns/op", "p50", "p99", "p999", "M lookups/s"
    );
    println!("{}", "-".repeat(74));
    for &n in sizes {
        let keys = build_keys(n);
        let (writer, seg) = build_real_shm(&keys);
        let reader = ShmAdmissionReader::attach_anonymous(std::sync::Arc::clone(&seg))
            .expect("reader attach");
        let (ns_per_op, st) = bench_real_shm_single(&reader, &keys, iters);
        println!(
            "{:>8} | {:>12.1} {:>10.0} {:>10.0} {:>10.0} | {:>12.1}",
            n,
            ns_per_op,
            st.p50_ns,
            st.p99_ns,
            st.p999_ns,
            1_000.0 / ns_per_op
        );
        drop(writer);
        drop(reader);
        drop(seg);
    }

    println!(
        "\n    Concurrent-reader scaling (real shm, map = {} entries):\n",
        n_entries
    );
    for &with_writer in &[false, true] {
        println!(
            "  -- {} writer --",
            if with_writer { "WITH low-rate" } else { "NO" }
        );
        println!(
            "  {:>8} | {:>14} {:>10} {:>10}",
            "threads", "real-shm Mlk/s", "p99 ns", "p999 ns"
        );
        println!("  {}", "-".repeat(48));
        for &t in thread_counts {
            let (mlps, p99, p999) =
                bench_real_shm_concurrent(n_entries, t, ops_per_reader, with_writer);
            println!("  {:>8} | {:>14.1} {:>10.0} {:>10.0}", t, mlps, p99, p999);
        }
        println!();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let ncpu = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("# ds-dnsgate DNS-2b admission-map benchmark (OQ1)");
    println!(
        "# build profile: {}",
        if cfg!(debug_assertions) {
            "DEBUG (WARNING — run with --release!)"
        } else {
            "release (optimized)"
        }
    );
    println!("# available_parallelism (nproc) = {}", ncpu);
    println!("# black_box used on key+value to defeat dead-code elimination.");

    let sizes: &[usize] = if quick {
        &[100, 1_000, 10_000]
    } else {
        &[100, 1_000, 10_000, 100_000]
    };
    let lookup_iters = if quick { 2_000_000 } else { 20_000_000 };
    let conc_entries = if quick { 10_000 } else { 50_000 };
    let conc_ops = if quick { 2_000_000 } else { 10_000_000 };
    let txn_iters = if quick { 200_000 } else { 1_000_000 };

    // Thread counts: 1,2,4,8,... up to nproc.
    let mut tcs: Vec<usize> = Vec::new();
    let mut t = 1usize;
    while t <= ncpu {
        tcs.push(t);
        t *= 2;
    }
    if *tcs.last().unwrap_or(&1) != ncpu {
        tcs.push(ncpu);
    }

    section_lookup_by_size(sizes, lookup_iters);
    section_concurrent(conc_entries, &tcs, conc_ops, ncpu);
    bench_insert_txn(txn_iters);
    section_seqlock(sizes, lookup_iters, conc_entries, &tcs, conc_ops);
    section_real_shm(sizes, lookup_iters, conc_entries, &tcs, conc_ops);

    println!("\n# done.");
}
