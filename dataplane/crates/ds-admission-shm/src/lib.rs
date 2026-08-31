//! `ds-admission-shm` — the survivable shared-memory DNS-2b admission map
//! (**D131 Candidate A**), a storage **body** behind the frozen `ds-contracts`
//! `AdmissionMap`/`ReverseIndex` traits. See `README.md` and
//! `docs/11-ds-dnsgate-design.md` §8.4 / §8.4.1 for the authoritative design.
//!
//! - [`ShmAdmissionMap`] is the **single writer** (`admit`/`revoke` take
//!   `&mut self`); ds-dnsgate owns it. It also owns the in-segment reverse index.
//! - [`ShmAdmissionReader`] is the **read-only** ds-tlsproxy shape: a `PROT_READ`
//!   mapping that only does seqlock `lookup`. It is a *separate* type (not an
//!   `AdmissionMap` impl) so a reader cannot even name `admit`/`revoke` — the
//!   read-only posture is enforced by the kernel mapping AND the absence of the
//!   mutating methods, which is cleaner than an `AdmissionMap` impl whose
//!   `admit`/`revoke` would have to return `Storage("read-only")`.
//! - The segment outlives the writer process (survivability): the host agent
//!   creates it; a warm-restart writer re-attaches, repairs torn slots, and runs a
//!   bounded [`ShmAdmissionMap::reconcile`] against kernel deadlines.

mod layout;
mod revindex;
mod segment;
mod seqlock;

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ds_contracts::dns_admission::{
    AdmissionEntry, AdmissionError, AdmissionKey, AdmissionMap, AdmittedAddr, Instant, Provenance,
    ReverseIndex,
};

use layout::{
    byte_to_type, entry_slot_stride, key_hash, rev_slot_stride, type_to_byte, Header, PackedAddr,
    PackedEntry, STATE_EMPTY, STATE_OCCUPIED, STATE_TOMBSTONE,
};
pub use layout::{
    LAYOUT_VERSION, MAGIC, MAX_ADMITTED_IPS, MAX_FQDN_LEN, MAX_PROV_LEN, MAX_REAL_TARGETS,
    MAX_SESSION_LEN,
};
use revindex::RevIndex;
use segment::SharedBase;

/// The mmap backing (named POSIX shm or anonymous `MAP_SHARED`). Re-exported so
/// callers (e.g. the bench, tests) can name the `Arc<Segment>` shared across
/// reader/writer handles.
pub use segment::Segment;

pub use ds_contracts::dns_admission::ADMISSION_API_VERSION;

/// The reconcile seam (doc 11 §8.4.1): the authoritative kernel deadline for a
/// `(session, ip)`. Production body = the ds-nft NFT-3 set-dump (NOT in scope —
/// this is the trait the production impl lands behind); tests use a fake.
pub trait KernelDeadlineSource {
    /// The kernel element's absolute deadline for `(session, ip)`, or `None` if the
    /// element is absent (expired-and-removed, or never plumbed). `None` and a
    /// past deadline both mean "prune the map entry" (kernel deadline authoritative,
    /// W2).
    fn deadline_for(&self, session: &str, ip: &AdmittedAddr) -> Option<Instant>;
}

/// Round `rev_count` up to a power of two AND enforce the floor `rev_count >=
/// slot_count` (assumes `slot_count` is already a power of two).
///
/// WHY the floor: the reverse table holds one slot per distinct LIVE `(session, ip)`
/// pair. The entry table holds one slot per distinct `(session, fqdn)` name, and each
/// name may reference up to `MAX_ADMITTED_IPS` distinct IPs, so the absolute worst
/// case is `slot_count * MAX_ADMITTED_IPS` distinct `(session, ip)` pairs. A reverse
/// table SMALLER than the entry table is therefore always a latent under-count: a
/// fully-loaded entry table (each name one unique IP) already needs `slot_count`
/// reverse slots, so a smaller `rev_count` would saturate the reverse table while the
/// entry table still has room — exactly the exhaustion that, before the count-0
/// reclamation + fail-closed admit, could free a still-held shared IP.
///
/// The caller SHOULD size `rev_count` to the peak live distinct `(session, ip)`
/// working set (up to `slot_count * MAX_ADMITTED_IPS` in the pathological case). We
/// pick `max(rev_count, slot_count)` as the floor: it makes a 1-IP-per-name table
/// never saturate the reverse index, and combined with the fail-closed admit
/// (genuine over-capacity now SERVFAILs rather than under-counting) it removes the
/// silent-under-count hole. Going larger is the caller's call when names fan out to
/// many IPs.
fn size_rev_count(slot_count: u32, rev_count: u32) -> u32 {
    rev_count.next_power_of_two().max(2).max(slot_count)
}

/// How big a segment to size for `slot_count` entry slots + `rev_count` rev slots.
fn segment_len(slot_count: u32, rev_count: u32) -> usize {
    let header = std::mem::size_of::<Header>();
    let entries = slot_count as usize * entry_slot_stride() as usize;
    let revs = rev_count as usize * rev_slot_stride() as usize;
    header + entries + revs
}

/// Byte offset of the entry table (immediately after the header, 8-aligned).
fn entry_table_off() -> usize {
    let header = std::mem::size_of::<Header>();
    header.div_ceil(8) * 8
}

/// Byte offset of the reverse-index table (after the entry table).
fn rev_table_off(slot_count: u32) -> usize {
    entry_table_off() + slot_count as usize * entry_slot_stride() as usize
}

// ── Header read/write (the header is plain, written once at create) ─────────────

/// # Safety
/// `base` must address a mapping ≥ `size_of::<Header>()` bytes.
unsafe fn write_header(base: SharedBase, slot_count: u32, rev_count: u32) {
    let h = Header {
        magic: MAGIC,
        layout_version: LAYOUT_VERSION,
        api_version: Header::API_VERSION,
        slot_count,
        slot_stride: entry_slot_stride(),
        rev_count,
        rev_stride: rev_slot_stride(),
        max_session_len: MAX_SESSION_LEN as u32,
        max_fqdn_len: MAX_FQDN_LEN as u32,
        max_admitted_ips: MAX_ADMITTED_IPS as u32,
        max_real_targets: MAX_REAL_TARGETS as u32,
        max_prov_len: MAX_PROV_LEN as u32,
        _pad: [0u8; 4],
        writer_epoch: 0,
    };
    core::ptr::write(base.as_ptr() as *mut Header, h);
}

/// A live `AtomicU64` view over the header's `writer_epoch` — the ONE header field
/// mutated after create (it is bumped on each writer attach). Every other header
/// field is write-once-at-create, but this one is concurrently mutable, so it is
/// read/written through an atomic: a plain read/write of its bytes concurrent with a
/// re-attaching writer's bump would be a cross-process data race (UB by the memory
/// model), which is exactly the failure mode the crate's "every shared-mutable field
/// is atomic" invariant exists to prevent.
///
/// # Safety
/// `base` must address a mapping ≥ `size_of::<Header>()` bytes. `writer_epoch` is
/// 8-aligned (the mapping base is page-aligned and the field is a `u64`).
unsafe fn writer_epoch_atomic<'a>(base: SharedBase) -> &'a AtomicU64 {
    let p = core::ptr::addr_of!((*(base.as_ptr() as *const Header)).writer_epoch);
    &*(p as *const AtomicU64)
}

/// Read the header fields needed to validate + index the segment.
///
/// The write-once static prefix (everything before `writer_epoch`) is copied plainly
/// — those bytes are never mutated after create, so a plain read cannot race. The
/// post-create-mutable `writer_epoch` is read through [`writer_epoch_atomic`] rather
/// than swept up in the struct copy, so this never races a writer's epoch bump.
///
/// # Safety
/// `base` must address a mapping ≥ `size_of::<Header>()` bytes.
unsafe fn read_header(base: SharedBase) -> Header {
    let mut h: Header = core::mem::zeroed();
    let static_len = core::mem::offset_of!(Header, writer_epoch);
    core::ptr::copy_nonoverlapping(
        base.as_ptr(),
        (&mut h as *mut Header) as *mut u8,
        static_len,
    );
    h.writer_epoch = writer_epoch_atomic(base).load(Ordering::Acquire);
    h
}

/// Validate the cross-process header contract; returns the validated
/// `(slot_count, rev_count)` or the appropriate `AdmissionError`.
fn validate_header(h: &Header) -> Result<(u32, u32), AdmissionError> {
    if h.magic != MAGIC {
        return Err(AdmissionError::Storage(format!(
            "bad segment magic: {:#x} (expected {:#x})",
            h.magic, MAGIC
        )));
    }
    if h.layout_version != LAYOUT_VERSION {
        return Err(AdmissionError::Storage(format!(
            "layout_version mismatch: found {}, expected {}",
            h.layout_version, LAYOUT_VERSION
        )));
    }
    if h.api_version != Header::API_VERSION {
        return Err(AdmissionError::VersionMismatch {
            expected: Header::API_VERSION,
            found: h.api_version,
        });
    }
    if h.slot_stride != entry_slot_stride() || h.rev_stride != rev_slot_stride() {
        return Err(AdmissionError::Storage(format!(
            "stride mismatch: entry {} (want {}), rev {} (want {})",
            h.slot_stride,
            entry_slot_stride(),
            h.rev_stride,
            rev_slot_stride()
        )));
    }
    if !h.slot_count.is_power_of_two() || !h.rev_count.is_power_of_two() {
        return Err(AdmissionError::Storage(
            "slot/rev count not a power of two".into(),
        ));
    }
    Ok((h.slot_count, h.rev_count))
}

// ── Entry-slot indexing shared by writer + reader ───────────────────────────────

/// A handle to the entry table: base + offset + power-of-two slot_count.
#[derive(Clone, Copy)]
struct EntryTable {
    base: SharedBase,
    table_off: usize,
    slot_count: usize,
    slot_stride: usize,
    mask: usize,
}

impl EntryTable {
    fn new(base: SharedBase, slot_count: u32) -> EntryTable {
        let sc = slot_count as usize;
        EntryTable {
            base,
            table_off: entry_table_off(),
            slot_count: sc,
            slot_stride: entry_slot_stride() as usize,
            mask: sc - 1,
        }
    }

    #[inline]
    fn slot_ptr(&self, idx: usize) -> *mut u8 {
        // SAFETY: idx < slot_count; table is in-bounds of the validated segment.
        unsafe { self.base.at(self.table_off + idx * self.slot_stride) }
    }

    /// Read-side probe for `lookup`: linear-probe from the key hash. EMPTY stops;
    /// TOMBSTONE continues. On a hash match, seqlock-read the payload and confirm
    /// the key bytes inside the consistent snapshot.
    fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
        let want = key_hash(&key.session_uuid, &key.original_query_fqdn);
        let mut idx = (want as usize) & self.mask;
        for _ in 0..self.slot_count {
            let p = self.slot_ptr(idx);
            // SAFETY: p is a valid slot pointer (module invariants hold by
            // construction: idx < slot_count, table in-bounds).
            let (state, hash) = unsafe { seqlock::read_oob(p) };
            if state == STATE_EMPTY {
                // EMPTY stops the probe (key absent). Sound because a writer NEVER
                // stores STATE_EMPTY at runtime (`write_slot` debug-asserts it; runtime
                // frees go to TOMBSTONE via revoke/repair), so a slot is EMPTY only if
                // it was never occupied — no live colliding key can sit past it in this
                // probe chain.
                return None;
            }
            if state == STATE_OCCUPIED && hash == want {
                // SAFETY: as above. A crashed/torn slot returns None (fail safe).
                if let Some(payload) = unsafe { seqlock::read_payload(p) } {
                    // Re-validate state/hash + key bytes inside the consistent
                    // snapshot (the seqlock read could have raced an out-of-band
                    // state/hash change; the snapshot's own fields are the truth).
                    if payload.key_hash == want
                        && key_bytes_match(&payload, &key.session_uuid, &key.original_query_fqdn)
                    {
                        if let Some(entry) = decode_entry(&payload) {
                            return Some(entry);
                        }
                    }
                }
                // Torn/raced/mismatched — keep probing (a tombstone-style continue).
            }
            // STATE_TOMBSTONE or a non-matching occupied slot: continue probing.
            idx = (idx + 1) & self.mask;
        }
        None
    }
}

/// Whether the packed entry's key bytes equal `(session, fqdn)`.
fn key_bytes_match(p: &PackedEntry, session: &str, fqdn: &str) -> bool {
    let slen = p.session_len as usize;
    let flen = p.fqdn_len as usize;
    if slen > MAX_SESSION_LEN || flen > MAX_FQDN_LEN {
        return false;
    }
    &p.session[..slen] == session.as_bytes() && &p.fqdn[..flen] == fqdn.as_bytes()
}

/// Decode a `PackedEntry` into the contract `AdmissionEntry`. Returns `None` on a
/// malformed payload (corrupt/torn slot the recheck somehow passed — defensive).
fn decode_entry(p: &PackedEntry) -> Option<AdmissionEntry> {
    let admission_type = byte_to_type(p.admission_type)?;
    let ip_n = p.admitted_ip_count as usize;
    let rt_n = p.real_target_count as usize;
    if ip_n > MAX_ADMITTED_IPS || rt_n > MAX_REAL_TARGETS {
        return None;
    }
    let mut admitted_ips = Vec::with_capacity(ip_n);
    for a in &p.admitted_ips[..ip_n] {
        admitted_ips.push(a.to_addr()?);
    }
    let mut real_targets = Vec::with_capacity(rt_n);
    for a in &p.real_targets[..rt_n] {
        real_targets.push(a.to_addr()?);
    }
    let prov = Provenance {
        rule_id: decode_str(&p.prov_rule_id, p.prov_len[0])?,
        policy_layer: decode_str(&p.prov_policy_layer, p.prov_len[1])?,
        policy_version: decode_str(&p.prov_policy_version, p.prov_len[2])?,
    };
    Some(AdmissionEntry {
        admitted_ips,
        admission_type,
        real_targets,
        expires_at: Instant::from_unix_nanos(p.expires_at),
        admitted_at: Instant::from_unix_nanos(p.admitted_at),
        provenance: prov,
    })
}

fn decode_str(buf: &[u8], len: u8) -> Option<String> {
    let len = len as usize;
    if len > buf.len() {
        return None;
    }
    String::from_utf8(buf[..len].to_vec()).ok()
}

/// Encode a contract `AdmissionEntry` + key into a `PackedEntry`, enforcing the
/// capacity bounds fail-closed (doc 11 §8.5). Returns the bound-name on overflow.
fn encode_entry(
    key: &AdmissionKey,
    entry: &AdmissionEntry,
    want_hash: u64,
) -> Result<PackedEntry, AdmissionError> {
    let bound = |w: &'static str| AdmissionError::Storage(format!("admission exceeds bound: {w}"));

    if key.session_uuid.len() > MAX_SESSION_LEN {
        return Err(bound("MAX_SESSION_LEN"));
    }
    if key.original_query_fqdn.len() > MAX_FQDN_LEN {
        return Err(bound("MAX_FQDN_LEN"));
    }
    if entry.admitted_ips.len() > MAX_ADMITTED_IPS {
        return Err(bound("MAX_ADMITTED_IPS"));
    }
    if entry.real_targets.len() > MAX_REAL_TARGETS {
        return Err(bound("MAX_REAL_TARGETS"));
    }
    if entry.provenance.rule_id.len() > MAX_PROV_LEN
        || entry.provenance.policy_layer.len() > MAX_PROV_LEN
        || entry.provenance.policy_version.len() > MAX_PROV_LEN
    {
        return Err(bound("MAX_PROV_LEN"));
    }

    let mut p = PackedEntry::zeroed();
    p.expires_at = entry.expires_at.unix_nanos;
    p.admitted_at = entry.admitted_at.unix_nanos;
    p.key_hash = want_hash;
    p.admission_type = type_to_byte(entry.admission_type);
    p.admitted_ip_count = entry.admitted_ips.len() as u8;
    p.real_target_count = entry.real_targets.len() as u8;
    p.session_len = key.session_uuid.len() as u8;
    p.fqdn_len = key.original_query_fqdn.len() as u16;

    p.session[..key.session_uuid.len()].copy_from_slice(key.session_uuid.as_bytes());
    p.fqdn[..key.original_query_fqdn.len()].copy_from_slice(key.original_query_fqdn.as_bytes());

    for (i, a) in entry.admitted_ips.iter().enumerate() {
        p.admitted_ips[i] = PackedAddr::from_addr(a).ok_or_else(|| {
            AdmissionError::Storage("admitted_ip octet length disagrees with its family".into())
        })?;
    }
    for (i, a) in entry.real_targets.iter().enumerate() {
        p.real_targets[i] = PackedAddr::from_addr(a).ok_or_else(|| {
            AdmissionError::Storage("real_target octet length disagrees with its family".into())
        })?;
    }
    write_prov(&mut p.prov_rule_id, &entry.provenance.rule_id);
    write_prov(&mut p.prov_policy_layer, &entry.provenance.policy_layer);
    write_prov(&mut p.prov_policy_version, &entry.provenance.policy_version);
    p.prov_len = [
        entry.provenance.rule_id.len() as u8,
        entry.provenance.policy_layer.len() as u8,
        entry.provenance.policy_version.len() as u8,
    ];
    Ok(p)
}

fn write_prov(buf: &mut [u8; MAX_PROV_LEN], s: &str) {
    let b = s.as_bytes();
    buf[..b.len()].copy_from_slice(b);
}

/// The distinct admitted-IP membership of an entry, deduped, as `AdmittedAddr`s
/// (matches the reference: a `(session, ip)` count is distinct-name membership, so
/// a duplicate IP within one admission counts/frees as one).
fn distinct_ips(entry: &AdmissionEntry) -> Vec<AdmittedAddr> {
    let mut seen: HashSet<&AdmittedAddr> = HashSet::new();
    let mut out = Vec::new();
    for ip in &entry.admitted_ips {
        if seen.insert(ip) {
            out.push(ip.clone());
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// The single-writer map.
// ─────────────────────────────────────────────────────────────────────────────

/// The single-writer survivable shm admission map (the ds-dnsgate writer shape).
///
/// `admit`/`revoke` take `&mut self`, which is what enforces single-writer at the
/// type level — there can be exactly one `&mut ShmAdmissionMap` at a time, so the
/// seqlock's single-writer assumption holds.
pub struct ShmAdmissionMap {
    segment: Arc<Segment>,
    table: EntryTable,
    reverse: RevIndex,
    slot_count: u32,
}

impl ShmAdmissionMap {
    /// Create a fresh named POSIX shm segment and map it RW (the writer-create
    /// path). `slot_count`/`rev_count` are rounded up to powers of two. The segment
    /// is NOT unlinked on drop (survivability); call [`ShmAdmissionMap::unlink`].
    pub fn create_named(
        name: &str,
        slot_count: u32,
        rev_count: u32,
    ) -> Result<ShmAdmissionMap, AdmissionError> {
        let slot_count = slot_count.next_power_of_two().max(2);
        let rev_count = size_rev_count(slot_count, rev_count);
        let len = segment_len(slot_count, rev_count);
        let segment = Segment::create_named(name, len)
            .map_err(|e| AdmissionError::Storage(format!("shm_open/mmap: {e}")))?;
        // SAFETY: a fresh mmap is zero-filled; write the header into it.
        unsafe { write_header(segment.base(), slot_count, rev_count) };
        Self::from_fresh_segment(segment, slot_count, rev_count)
    }

    /// Create an anonymous `MAP_SHARED` segment (tests/bench). Returns the writer
    /// AND the `Arc<Segment>` so a reader can be attached over the SAME mapping.
    pub fn create_anonymous(
        slot_count: u32,
        rev_count: u32,
    ) -> Result<(ShmAdmissionMap, Arc<Segment>), AdmissionError> {
        let slot_count = slot_count.next_power_of_two().max(2);
        let rev_count = size_rev_count(slot_count, rev_count);
        let len = segment_len(slot_count, rev_count);
        let segment = Segment::create_anonymous(len)
            .map_err(|e| AdmissionError::Storage(format!("anon mmap: {e}")))?;
        // SAFETY: fresh anon map is zero-filled; write the header.
        unsafe { write_header(segment.base(), slot_count, rev_count) };
        let seg_clone = Arc::clone(&segment);
        let map = Self::from_fresh_segment(segment, slot_count, rev_count)?;
        Ok((map, seg_clone))
    }

    fn from_fresh_segment(
        segment: Arc<Segment>,
        slot_count: u32,
        rev_count: u32,
    ) -> Result<ShmAdmissionMap, AdmissionError> {
        let base = segment.base();
        let table = EntryTable::new(base, slot_count);
        // SAFETY: the reverse table offset/extent are within the segment we just
        // sized via `segment_len`.
        let reverse = unsafe {
            RevIndex::new(
                base,
                rev_table_off(slot_count),
                rev_count as usize,
                rev_slot_stride() as usize,
            )
        };
        Ok(ShmAdmissionMap {
            segment,
            table,
            reverse,
            slot_count,
        })
    }

    /// Re-attach to an EXISTING named segment as the writer (the warm-restart path,
    /// doc 11 §8.4.1): re-open, validate the header (magic/layout/api), bump
    /// `writer_epoch`, and repair any torn (odd-`seq`) slot before serving. The
    /// caller then runs [`ShmAdmissionMap::reconcile`]. A header mismatch returns
    /// the error (caller falls back to start-empty); an api_version mismatch is
    /// `VersionMismatch`.
    pub fn attach_named_writer(name: &str) -> Result<ShmAdmissionMap, AdmissionError> {
        // First map just enough to read the header, validate, then size the full
        // mapping. We map the header-sized region by mapping at least the header;
        // mmap rounds to a page, so a small probe map is fine.
        let probe_len = std::mem::size_of::<Header>();
        let probe = Segment::attach_named_writer(name, probe_len)
            .map_err(|e| AdmissionError::Storage(format!("attach (probe): {e}")))?;
        // SAFETY: probe maps ≥ header bytes.
        let h = unsafe { read_header(probe.base()) };
        let (slot_count, rev_count) = validate_header(&h)?;
        drop(probe);

        let len = segment_len(slot_count, rev_count);
        let segment = Segment::attach_named_writer(name, len)
            .map_err(|e| AdmissionError::Storage(format!("attach (full): {e}")))?;
        let mut map = Self::from_fresh_segment(segment, slot_count, rev_count)?;
        map.bump_epoch_and_repair();
        Ok(map)
    }

    /// Re-attach to an existing ANONYMOUS segment (tests): validate header, repair
    /// torn slots, bump epoch — the warm-restart path over a thread-shared mapping.
    pub fn attach_anonymous(segment: Arc<Segment>) -> Result<ShmAdmissionMap, AdmissionError> {
        // SAFETY: the segment was created by us; header is present.
        let h = unsafe { read_header(segment.base()) };
        let (slot_count, rev_count) = validate_header(&h)?;
        let mut map = Self::from_fresh_segment(segment, slot_count, rev_count)?;
        map.bump_epoch_and_repair();
        Ok(map)
    }

    /// Bump `writer_epoch`, repair torn (odd-`seq`) entry slots, then REBUILD the
    /// reverse index from the (now-repaired) entry table (doc 11 §8.4.1 crash-safety
    /// guard 2 + F1). Single-threaded (called on attach before serving).
    ///
    /// # Why the reverse index is rebuilt, not trusted (F1)
    /// The reverse index is written with PLAIN non-atomic stores (it has no reader, so
    /// no seqlock), and `admit` decrefs a dropped IP BEFORE it `write_slot`-publishes
    /// the new payload. A writer that crashes in that window leaves the reverse index
    /// UNDER-counting relative to the entry table: a `(session, ip)` the entry table
    /// still references has already had its reverse refcount dropped. A later
    /// sibling-revoke would then decref that count to 0 and FREE a still-held shared IP
    /// (the CDN hole). The torn-slot repair above only heals the entry table, never the
    /// reverse index. So on every warm re-attach we make the ENTRY TABLE AUTHORITATIVE:
    /// zero the reverse table, then re-incref the DISTINCT `(session, ip)` membership of
    /// every decodable OCCUPIED entry — exactly the `distinct_ips` membership `admit`
    /// itself counts — reconstructing exact refcounts. Undecodable OCCUPIED slots
    /// (corruption) contribute nothing here; `reconcile` later tombstones them.
    fn bump_epoch_and_repair(&mut self) {
        // F3: bump `writer_epoch` through its atomic (a plain RMW would race a reader
        // loading it during attach — UB by the model). `Release` so a reader's
        // `Acquire` load in `writer_epoch()` observes a coherent value.
        // SAFETY: header is present; we are the sole writer on attach; the atomic view
        // is well-aligned (see `writer_epoch_atomic`).
        unsafe {
            writer_epoch_atomic(self.segment.base()).fetch_add(1, Ordering::Release);
        }
        for idx in 0..self.slot_count as usize {
            let p = self.table.slot_ptr(idx);
            // SAFETY: valid slot pointer; single-threaded.
            let s = unsafe { seqlock::raw_seq(p) };
            if s & 1 != 0 {
                // SAFETY: as above; torn slot → repair to EMPTY/next-even.
                unsafe { seqlock::repair_torn_slot(p) };
            }
        }
        self.rebuild_reverse_index();
    }

    /// F1: rebuild the reverse index from the (repaired) entry table so the entry
    /// table is authoritative. Zero the reverse table, then for every OCCUPIED,
    /// DECODABLE entry incref each of its distinct `(session, ip)` pairs once. Called
    /// only from [`Self::bump_epoch_and_repair`], single-threaded on attach.
    fn rebuild_reverse_index(&mut self) {
        self.reverse.clear();
        for idx in 0..self.table.slot_count {
            let p = self.table.slot_ptr(idx);
            // SAFETY: valid slot pointer; single-threaded on attach.
            let (state, _) = unsafe { seqlock::read_oob(p) };
            if state != STATE_OCCUPIED {
                continue;
            }
            // Recover the key + entry; an undecodable OCCUPIED slot contributes no
            // refcounts (reconcile tombstones it later — its IPs stay pinned, the safe
            // under-delete direction). Same `distinct_ips` membership `admit` counts.
            let (Some(entry), Some(key)) = (self.entry_at(idx), packed_key_at(self, idx)) else {
                continue;
            };
            for ip in &distinct_ips(&entry) {
                // The reverse table was sized (`size_rev_count`) to hold the entry
                // table's worst-case distinct membership, so this incref always lands;
                // `incref_checked` keeps us fail-closed if a future mis-sizing breaks
                // that invariant (a `None` simply leaves the count short — the safe
                // under-count direction is impossible here because the table fits).
                let _ = self.reverse.incref_checked(&key.session_uuid, ip);
            }
        }
    }

    /// Unlink the named segment (remove the shm object). Existing mappings keep
    /// working until dropped. A no-op concept for anonymous segments.
    pub fn unlink(name: &str) -> Result<(), AdmissionError> {
        Segment::unlink_name(name).map_err(|e| AdmissionError::Storage(format!("shm_unlink: {e}")))
    }

    /// The current `writer_epoch` (test/observability).
    pub fn writer_epoch(&self) -> u64 {
        // F3: read through the atomic `load(Acquire)` — `writer_epoch` is bumped by a
        // re-attaching writer (`bump_epoch_and_repair`), so a plain read would be a
        // data race; `Acquire` pairs with the bump's `Release`.
        // SAFETY: header present; the atomic view is well-aligned.
        unsafe { writer_epoch_atomic(self.segment.base()).load(Ordering::Acquire) }
    }

    /// A read-only reader view over the SAME (anonymous) segment — tests/bench.
    /// (Production readers attach by name with [`ShmAdmissionReader::attach_named`].)
    pub fn reader_view(&self) -> ShmAdmissionReader {
        ShmAdmissionReader {
            _segment: Arc::clone(&self.segment),
            table: self.table,
        }
    }

    /// Whether the OCCUPIED slot at `p` holds `key` (a fresh writer-side seqlock
    /// read confirms the key bytes inside the consistent snapshot).
    fn slot_holds(&self, p: *mut u8, key: &AdmissionKey) -> bool {
        // SAFETY: `p` is a valid slot pointer from `slot_ptr`.
        match unsafe { seqlock::read_payload(p) } {
            Some(payload) => key_bytes_match(&payload, &key.session_uuid, &key.original_query_fqdn),
            None => false,
        }
    }

    /// Find the slot index for `key` (OCCUPIED + matching key bytes), or `None`.
    /// Reads the live payload to confirm key bytes (writer side, so a fresh read).
    fn find_slot(&self, key: &AdmissionKey, want: u64) -> Option<usize> {
        let mut idx = (want as usize) & self.table.mask;
        for _ in 0..self.table.slot_count {
            let p = self.table.slot_ptr(idx);
            // SAFETY: valid slot pointer.
            let (state, hash) = unsafe { seqlock::read_oob(p) };
            if state == STATE_EMPTY {
                return None;
            }
            if state == STATE_OCCUPIED && hash == want && self.slot_holds(p, key) {
                return Some(idx);
            }
            idx = (idx + 1) & self.table.mask;
        }
        None
    }

    /// Find an insert slot for `key`: the existing OCCUPIED match (refresh), else
    /// the first EMPTY or TOMBSTONE on the probe (reuse). `None` ⇒ table full.
    fn find_insert_slot(&self, key: &AdmissionKey, want: u64) -> Option<(usize, bool)> {
        let mut idx = (want as usize) & self.table.mask;
        let mut first_reusable: Option<usize> = None;
        for _ in 0..self.table.slot_count {
            let p = self.table.slot_ptr(idx);
            // SAFETY: valid slot pointer.
            let (state, hash) = unsafe { seqlock::read_oob(p) };
            match state {
                STATE_EMPTY => {
                    // EMPTY stops the probe: the key is not present beyond here.
                    let slot = first_reusable.unwrap_or(idx);
                    return Some((slot, false));
                }
                STATE_TOMBSTONE if first_reusable.is_none() => {
                    first_reusable = Some(idx);
                }
                STATE_OCCUPIED if hash == want && self.slot_holds(p, key) => {
                    return Some((idx, true)); // refresh
                }
                _ => {}
            }
            idx = (idx + 1) & self.table.mask;
        }
        // Probed the whole table without an EMPTY stop: use a tombstone if seen.
        first_reusable.map(|i| (i, false))
    }

    /// Decode the existing entry at `idx` (for the refresh membership delta).
    fn entry_at(&self, idx: usize) -> Option<AdmissionEntry> {
        let p = self.table.slot_ptr(idx);
        // SAFETY: valid slot pointer.
        let payload = unsafe { seqlock::read_payload(p) }?;
        decode_entry(&payload)
    }

    /// Reconcile against kernel deadlines on warm-restart (doc 11 §8.4.1): prune any
    /// entry whose kernel deadline is ABSENT or in the PAST (kernel deadline
    /// authoritative, W2). Pruning is a full `revoke` (decrefs the reverse index +
    /// tombstones the slot). NO event replay. Returns the count of entries removed
    /// from the live set (kernel-pruned + corruption-repaired).
    ///
    /// Any OCCUPIED slot whose payload is UNDECODABLE (corrupt bytes that passed the
    /// seqlock recheck) is TOMBSTONED rather than left live: its refcounts are
    /// unrecoverable (we cannot decode which IPs to decref) so they stay pinned — the
    /// safe under-delete direction — but the slot stops being a live OCCUPIED vouch.
    ///
    /// `now` is the caller's clock (an `Instant`); an entry with a kernel deadline
    /// `<= now` is pruned. (The kernel deadline may differ from the map's stored
    /// `expires_at`; the kernel value is authoritative.)
    pub fn reconcile(&mut self, src: &dyn KernelDeadlineSource, now: Instant) -> usize {
        // Collect the live keys first (immutable scan), then prune (mutable) — the
        // reverse-index decref inside revoke needs &mut, so we can't hold a scan
        // borrow across it.
        let mut to_prune: Vec<AdmissionKey> = Vec::new();
        // OCCUPIED slots whose payload is UNDECODABLE (a corrupt `admission_type`/
        // address/length byte that survived the seqlock recheck): they cannot be a
        // valid vouch, and leaving them OCCUPIED pins phantom refcounts on whatever
        // IPs they (un-recoverably) referenced forever. We TOMBSTONE them: the slot
        // stops being a live OCCUPIED entry (lookup → None → fail-safe re-admit) and
        // the probe chain is preserved. Their reverse-index refcounts are
        // UNRECOVERABLE (we cannot decode which IPs to decref), so they stay pinned —
        // the safe UNDER-delete direction (an IP stays pinned slightly too long,
        // never wrongly freed; W4 / bias-to-under-delete). This is rare (corruption)
        // and bounded by the table size; the standing reverse-table sizing absorbs it.
        let mut repaired = 0usize;
        for idx in 0..self.table.slot_count {
            let p = self.table.slot_ptr(idx);
            // SAFETY: valid slot pointer.
            let (state, _) = unsafe { seqlock::read_oob(p) };
            if state != STATE_OCCUPIED {
                continue;
            }
            // An OCCUPIED slot that fails to decode (entry OR key) is undecodable
            // corruption: tombstone it so it does not stay a live OCCUPIED entry.
            let (Some(entry), Some(key)) = (self.entry_at(idx), packed_key_at(self, idx)) else {
                // SAFETY: valid slot pointer; sole writer on reconcile; RW mapping.
                // Tombstone (not empty): preserve the probe chain for colliding keys.
                unsafe { seqlock::tombstone_slot(p) };
                repaired += 1;
                continue;
            };

            // An entry survives iff EVERY admitted IP has a live (present, future)
            // kernel deadline. If ANY admitted IP's kernel element is absent or
            // expired, the vouch is no longer fully backed by the kernel → prune
            // (fail safe: bias to re-admit, never keep an un-backed vouch).
            let mut keep = !entry.admitted_ips.is_empty();
            for ip in &distinct_ips(&entry) {
                match src.deadline_for(&key.session_uuid, ip) {
                    Some(dl) if dl > now => {}
                    _ => {
                        keep = false;
                        break;
                    }
                }
            }
            if !keep {
                to_prune.push(key);
            }
        }
        let n = to_prune.len();
        for key in to_prune {
            let _ = self.revoke(&key);
        }
        // Total entries removed from the live set: kernel-pruned + corruption-repaired
        // (tombstoned undecodable slots). Both leave the slot non-OCCUPIED.
        n + repaired
    }
}

/// Recover the `AdmissionKey` stored at slot `idx` (writer side, fresh read).
fn packed_key_at(map: &ShmAdmissionMap, idx: usize) -> Option<AdmissionKey> {
    let p = map.table.slot_ptr(idx);
    // SAFETY: valid slot pointer.
    let payload = unsafe { seqlock::read_payload(p) }?;
    let slen = payload.session_len as usize;
    let flen = payload.fqdn_len as usize;
    if slen > MAX_SESSION_LEN || flen > MAX_FQDN_LEN {
        return None;
    }
    Some(AdmissionKey {
        session_uuid: String::from_utf8(payload.session[..slen].to_vec()).ok()?,
        original_query_fqdn: String::from_utf8(payload.fqdn[..flen].to_vec()).ok()?,
    })
}

impl AdmissionMap for ShmAdmissionMap {
    type Reverse = RevIndex;

    fn admit(&mut self, key: AdmissionKey, entry: AdmissionEntry) -> Result<(), AdmissionError> {
        let want = key_hash(&key.session_uuid, &key.original_query_fqdn);
        // Encode + bounds-check FIRST (fail closed before touching the table).
        let payload = encode_entry(&key, &entry, want)?;

        // The reverse-index refcount moves by the IP-SET MEMBERSHIP DELTA of THIS
        // name vs its prior entry (insert-OR-refresh; mirrors the reference
        // `InMemoryAdmissionMap::admit`): decref IPs this name dropped, incref IPs
        // newly added, an unchanged set is a no-op. NOT an unconditional per-call
        // incref.
        let (slot, is_refresh) = self
            .find_insert_slot(&key, want)
            .ok_or_else(|| AdmissionError::Storage("admission table full".into()))?;

        // Prior distinct membership of this name (for the delta).
        let prior: Vec<AdmittedAddr> = if is_refresh {
            self.entry_at(slot)
                .map(|e| distinct_ips(&e))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let next: Vec<AdmittedAddr> = distinct_ips(&entry);
        let prior_set: HashSet<&AdmittedAddr> = prior.iter().collect();
        let next_set: HashSet<&AdmittedAddr> = next.iter().collect();

        // The to-add (incref) and to-drop (decref) sets. They are disjoint (added vs
        // dropped), so the apply order is free; we apply the increfs FIRST and gate
        // the whole admission on them succeeding.
        let to_incref: Vec<&AdmittedAddr> = next_set.difference(&prior_set).copied().collect();
        let to_decref: Vec<&AdmittedAddr> = prior_set.difference(&next_set).copied().collect();

        // FAIL CLOSED on a genuinely-full reverse table. Apply each incref through
        // `incref_checked`; on the FIRST `None` (no exact match, no reclaimable
        // count-0 slot, no empty — the table is genuinely full of live entries) ROLL
        // BACK every incref already applied THIS call and return a Storage error
        // WITHOUT applying any decref or writing the entry slot. Result: the
        // admission either FULLY applies (all increfs, then decrefs, then the slot
        // write) or FULLY fails closed (no partial mutation escapes → SERVFAIL, the
        // safe re-admit-on-next-query direction). This closes the CDN-shared-IP hole
        // reachable via reverse-table exhaustion: an under-recorded incref would let
        // a later sibling-revoke under-count and free a still-held shared IP.
        let mut applied: Vec<&AdmittedAddr> = Vec::with_capacity(to_incref.len());
        for ip in &to_incref {
            match self.reverse.incref_checked(&key.session_uuid, ip) {
                Some(_) => applied.push(ip),
                None => {
                    // Roll back the increfs applied so far this call, then bail —
                    // NO decref, NO slot write. (decref of the just-incref'd key
                    // returns the count to its prior value; a fresh slot we claimed
                    // goes back to count 0, reclaimable, never a leak.)
                    for done in &applied {
                        self.reverse
                            .decref(&key.session_uuid, done, &key.original_query_fqdn);
                    }
                    return Err(AdmissionError::Storage("reverse index full".into()));
                }
            }
        }
        // Increfs all assured — now safe to apply the decrefs of dropped IPs.
        for ip in &to_decref {
            self.reverse
                .decref(&key.session_uuid, ip, &key.original_query_fqdn);
        }

        // Write the slot under the seqlock (the W1 publish).
        let p = self.table.slot_ptr(slot);
        // SAFETY: valid slot pointer; we are the sole writer (`&mut self`); mapping
        // is RW (the reader view never calls admit).
        unsafe { seqlock::write_slot(p, STATE_OCCUPIED, want, &payload) };
        Ok(())
    }

    fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
        // The map never self-evicts (W4): returns the entry even if expired.
        self.table.lookup(key)
    }

    fn revoke(&mut self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
        let want = key_hash(&key.session_uuid, &key.original_query_fqdn);
        let Some(slot) = self.find_slot(key, want) else {
            // Absent key: idempotent empty success (frozen contract).
            return Ok(vec![]);
        };
        // Read the entry to know its membership, then tombstone the slot and decref
        // each DISTINCT ip (dedup first — a malformed answer may carry the same IP
        // twice). Collect the IPs whose decref returns 0 into `freed`.
        let entry = self
            .entry_at(slot)
            .ok_or_else(|| AdmissionError::Storage("revoke: slot decode failed".into()))?;

        let p = self.table.slot_ptr(slot);
        // SAFETY: valid slot pointer; sole writer; RW mapping. Tombstone (NOT empty)
        // so a linear probe past this slot still finds keys that collided here; also
        // clears the out-of-band key_hash to shrink the stale-vouch window.
        unsafe { seqlock::tombstone_slot(p) };

        let mut freed = Vec::new();
        for ip in distinct_ips(&entry) {
            if self
                .reverse
                .decref(&key.session_uuid, &ip, &key.original_query_fqdn)
                == 0
            {
                freed.push(ip);
            }
        }
        Ok(freed)
    }

    fn reverse_index(&self) -> &Self::Reverse {
        &self.reverse
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The read-only reader (ds-tlsproxy shape).
// ─────────────────────────────────────────────────────────────────────────────

/// The read-only DNS-2b reader — the ds-tlsproxy shape. Maps the segment
/// `PROT_READ` and only does lock-free seqlock [`ShmAdmissionReader::lookup`]
/// (`&self`). Deliberately NOT an `AdmissionMap` impl: a reader cannot name
/// `admit`/`revoke`, so the read-only posture is a type-level property, not a
/// runtime `Storage("read-only")` error.
pub struct ShmAdmissionReader {
    // Keeps the mapping alive while the reader exists.
    _segment: Arc<Segment>,
    table: EntryTable,
}

impl ShmAdmissionReader {
    /// Attach a read-only reader to an existing named segment (`PROT_READ`). The
    /// header is validated; an api_version mismatch is `VersionMismatch`.
    pub fn attach_named(name: &str) -> Result<ShmAdmissionReader, AdmissionError> {
        let probe_len = std::mem::size_of::<Header>();
        let probe = Segment::attach_named_reader(name, probe_len)
            .map_err(|e| AdmissionError::Storage(format!("reader attach (probe): {e}")))?;
        // SAFETY: probe maps ≥ header bytes.
        let h = unsafe { read_header(probe.base()) };
        let (slot_count, _rev_count) = validate_header(&h)?;
        drop(probe);

        let len = segment_len(slot_count, h.rev_count);
        let segment = Segment::attach_named_reader(name, len)
            .map_err(|e| AdmissionError::Storage(format!("reader attach (full): {e}")))?;
        let table = EntryTable::new(segment.base(), slot_count);
        Ok(ShmAdmissionReader {
            _segment: segment,
            table,
        })
    }

    /// Attach a reader over an existing ANONYMOUS segment (tests/bench).
    pub fn attach_anonymous(segment: Arc<Segment>) -> Result<ShmAdmissionReader, AdmissionError> {
        // SAFETY: created by us; header present.
        let h = unsafe { read_header(segment.base()) };
        let (slot_count, _rev_count) = validate_header(&h)?;
        let table = EntryTable::new(segment.base(), slot_count);
        Ok(ShmAdmissionReader {
            _segment: segment,
            table,
        })
    }

    /// The lock-free seqlock lookup (the ds-tlsproxy hot path). Never self-evicts
    /// (W4): returns an expired entry; expiry is the caller's gate.
    pub fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
        self.table.lookup(key)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod epoch_atomic_tests {
    //! Race-freedom guards for the F3 atomic `writer_epoch` and the SQ1
    //! `LAYOUT_VERSION` (now 2) attach guard, owned by `lib.rs` (the `epochrace`
    //! coldfix unit). These pin two invariants by construction:
    //!
    //! 1. `read_header` materializes `writer_epoch` through the SAME `AtomicU64`
    //!    view as the dedicated reader (`writer_epoch_atomic().load(Acquire)`),
    //!    never via the non-atomic bulk struct copy — so no caller going through
    //!    `read_header` can perform a torn/stale cross-process read of the one
    //!    post-create-mutable header field.
    //! 2. Attaching to a segment whose stored `LAYOUT_VERSION` is the PRIOR
    //!    released version (1) — exactly the "writer/reader did not redeploy
    //!    together" hazard the SQ1 v1→v2 byte-layout change introduced — is
    //!    refused fail-closed, for both the writer and the reader attach path.
    use super::*;

    /// Overwrite the header's `layout_version` (the `u32` right after `magic:u64`,
    /// at byte offset 8) on an anonymous segment. Single-threaded test corruption.
    fn poke_layout_version(seg: &Arc<Segment>, new: u32) {
        // SAFETY: the segment is ≥ header bytes; offset 8 is the `layout_version`
        // u32 (magic occupies bytes 0..8). No concurrent access in this test.
        unsafe {
            let p = seg.base().as_ptr().add(8) as *mut u32;
            core::ptr::write_unaligned(p, new);
        }
    }

    #[test]
    fn read_header_materializes_writer_epoch_through_the_atomic_view() {
        // A fresh create stamps writer_epoch = 0; each warm re-attach bumps it via
        // `fetch_add(1, Release)`. `read_header` must observe the SAME value the
        // dedicated atomic reader sees — i.e. it splices `writer_epoch_atomic().
        // load(Acquire)` rather than returning the (here identical, but in general
        // racy) value from the non-atomic struct copy. We bump several times and
        // require exact agreement at every step, so a regression that bulk-copied
        // the field non-atomically (and could read a torn/stale value on a weak
        // target) loses the "by construction = the atomic" property this asserts.
        let (writer, seg) = ShmAdmissionMap::create_anonymous(16, 16).expect("create");
        // SAFETY: seg maps ≥ header bytes; single-threaded.
        let h0 = unsafe { read_header(seg.base()) };
        // SAFETY: as above; the atomic view is well-aligned (trailing u64 field).
        let atomic0 = unsafe { writer_epoch_atomic(seg.base()).load(Ordering::Acquire) };
        assert_eq!(
            h0.writer_epoch, atomic0,
            "read_header must mirror the atomic"
        );
        assert_eq!(h0.writer_epoch, 0, "fresh create stamps epoch 0");
        drop(writer);

        // Each warm re-attach bumps the epoch; read_header must track it exactly.
        let mut last = 0u64;
        for n in 1..=3u64 {
            let w = ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)).expect("re-attach");
            // SAFETY: as above.
            let h = unsafe { read_header(seg.base()) };
            // SAFETY: as above.
            let atomic = unsafe { writer_epoch_atomic(seg.base()).load(Ordering::Acquire) };
            assert_eq!(
                h.writer_epoch, atomic,
                "read_header epoch must equal the atomic load after re-attach #{n}"
            );
            assert_eq!(h.writer_epoch, n, "each re-attach bumps writer_epoch by 1");
            assert!(h.writer_epoch > last, "epoch is monotonic across re-attach");
            assert_eq!(
                w.writer_epoch(),
                h.writer_epoch,
                "the dedicated reader and read_header agree on the epoch"
            );
            last = h.writer_epoch;
            drop(w);
        }
    }

    #[test]
    fn attach_over_prior_layout_version_one_is_refused_fail_closed() {
        // The SQ1 change bumped LAYOUT_VERSION 1 → 2 (seq widened to u64). A segment
        // stamped by a v1 writer must be REFUSED by a v2 attach (writer AND reader),
        // because the byte layout is incompatible — the redeploy-together guarantee.
        // This is RED before the guard treats the prior version as a mismatch and
        // GREEN after: `validate_header` returns `Storage("layout_version mismatch…")`.
        // Compile-time pin: this test only models the v1→v2+ redeploy-together hazard
        // while the released LAYOUT_VERSION is past 1; a regression back to 1 would make
        // poking `1` a no-op, so fail the BUILD (not silently the assert) if that holds.
        const {
            assert!(
                LAYOUT_VERSION > 1,
                "this test pins the v1→vN redeploy-together guard; LAYOUT_VERSION must be > 1",
            );
        }
        let (writer, seg) = ShmAdmissionMap::create_anonymous(16, 16).expect("create");
        drop(writer);
        // Stamp the PRIOR released layout version (1) — a segment from a v1 binary.
        poke_layout_version(&seg, 1);

        match ShmAdmissionMap::attach_anonymous(Arc::clone(&seg)) {
            Err(AdmissionError::Storage(msg)) => {
                assert!(
                    msg.contains("layout_version"),
                    "the refusal must name the layout_version mismatch, got: {msg}"
                );
            }
            Err(e) => panic!("expected a layout_version Storage error, got {e:?}"),
            Ok(_) => {
                panic!("writer attach over a v1 segment must fail closed (NOT a torn re-attach)")
            }
        }
        match ShmAdmissionReader::attach_anonymous(Arc::clone(&seg)) {
            Err(AdmissionError::Storage(msg)) => {
                assert!(
                    msg.contains("layout_version"),
                    "the reader refusal must name the layout_version mismatch, got: {msg}"
                );
            }
            Err(e) => panic!("expected a reader layout_version Storage error, got {e:?}"),
            Ok(_) => panic!("reader attach over a v1 segment must fail closed"),
        }
    }
}
