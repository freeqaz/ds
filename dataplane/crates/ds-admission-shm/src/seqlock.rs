//! The per-entry seqlock — the ONE place a memory-model bug reopens a security
//! hole, so it is a tight, heavily-commented module with its safety invariants
//! stated. Modelled on the classic `seqlock_t` / crossbeam-utils `atomic::SeqLock`
//! (crossbeam-utils 0.8.21, `src/atomic/seq_lock.rs`).
//!
//! # The slot byte layout (`#[repr(C)]`, computed against `entry_slot_stride`)
//! ```text
//!   offset 0 : seq      : AtomicU64   (the seqlock; EVEN = stable, ODD = writer-in)
//!   offset 8 : state    : AtomicU32   (EMPTY / OCCUPIED / TOMBSTONE — out-of-band)
//!   offset 12: (pad)    : 4 bytes     (keeps key_hash 8-aligned)
//!   offset 16: key_hash : AtomicU64   (FNV-1a fingerprint — out-of-band)
//!   offset 24: payload  : PackedEntry (the seqlock-protected value+key bytes)
//! ```
//! `seq` is a `u64` (SQ1): the +2-per-commit counter, if it were a `u32`, could ABA
//! back to a value a long-preempted reader already accepted after 2^31 commits to a
//! hot slot, letting that reader accept a torn cross-generation snapshot. A 64-bit
//! counter cannot wrap within any realistic process lifetime (2^63 commits), so the
//! committed `seq` a reader rechecks is strictly unique per generation.
//!
//! `state` and `key_hash` live OUTSIDE the seqlock payload so a reader can cheaply
//! probe (atomic load, compare hash, EMPTY-stops-probe) and only pay the full
//! payload `copy_nonoverlapping` on a hash match — then re-validate the key bytes
//! inside the consistent snapshot.
//!
//! # Out-of-band state/hash ordering (SQ2)
//! `read_oob` loads `state` then `key_hash` as two INDEPENDENT `Acquire` loads, and
//! `write_slot`/`tombstone_slot` publish them as two INDEPENDENT `Release` stores.
//! Two independent acquire/release pairs are NOT mutually ordered: on a weak-memory
//! target (aarch64) a reader can pair a freshly-stored `state` with a STALE
//! `key_hash` (or vice versa). This is **deliberately tolerated, not a bug**: the
//! out-of-band pair is only a *probe hint*. Correctness never depends on it — every
//! accepted vouch is re-validated against the seqlock-protected snapshot, whose own
//! `payload.key_hash` + key bytes are the authoritative gate (see `EntryTable::lookup`).
//! A mis-paired `(state, key_hash)` only ever produces a spurious extra payload read
//! or a spurious probe-continue, never a wrong vouch. We therefore keep the two
//! stores/loads independent (cheaper) and document the non-ordering here rather than
//! add a fence that would buy correctness we already have from the snapshot recheck.
//!
//! # The memory model (implemented EXACTLY)
//! The per-slot `seq` counter is the ONLY real atomic that carries the
//! happens-before edge; the payload is copied with `core::ptr::copy_nonoverlapping`
//! under fences (not byte-by-byte atomics — that would defeat the purpose).
//!
//! WRITER (single writer; `&mut self` on the map enforces it) per slot:
//! 1. `began = seq.load(Relaxed)` (even — single writer guarantees it).
//!    `seq.store(began | 1, Release)` → now ODD (writer-in). `fence(Release)`.
//! 2. write the payload bytes (`copy_nonoverlapping` from a local packed struct)
//!    and update the out-of-band `state`/`key_hash` atomics.
//! 3. `fence(Release)`. `seq.store(began.wrapping_add(2), Release)` → next even
//!    (committed).
//!
//! READER (lock-free; never blocks the writer) per slot:
//! 1. `s1 = seq.load(Acquire)`. if `s1 & 1 != 0` → writer mid-update, BOUNDED spin
//!    (`spin_loop()`); budget exhausted ⇒ treat as a crashed-writer torn slot and
//!    return `None` (→ fail-safe D68 re-admit, never a torn vouch).
//! 2. `fence(Acquire)`. `copy_nonoverlapping` the payload OUT to a local buffer.
//!    `fence(Acquire)`.
//! 3. `s2 = seq.load(Acquire)`. if `s1 != s2` → a write landed during the copy,
//!    RETRY (bounded). Only when `s1 == s2` (and even) is the copy consistent.
//!
//! # Benign-race reasoning (the seqlock guarantee)
//! The step-2 payload copy *races* a concurrent writer: the writer may be
//! `copy_nonoverlapping`-ing the same bytes while the reader reads them, so the
//! reader's local buffer can hold a TORN mix of old and new bytes. That torn copy
//! is **discarded** by the step-3 `s1 == s2` recheck (a write in flight bumped
//! `seq` to odd or to the next even, so `s2 != s1`), so torn bytes are produced but
//! never *observed* — exactly the seqlock guarantee. The `Acquire` fence after the
//! copy pairs with the writer's `Release` fence before its commit store, so a
//! committed snapshot the reader DOES accept happens-after the writer's payload
//! writes.
//!
//! # Safety invariants (this module)
//! All accesses below are through raw pointers into a mapping another process may
//! write. Every caller must pass a `slot_ptr` that:
//! - points at the start of a slot within a validly-mapped segment, and
//! - has at least `entry_slot_stride()` bytes available.
//!
//! The map computes `slot_ptr = base.at(header_len + idx * stride)` with
//! `idx < slot_count`, so this holds. `seq`/`state`/`key_hash` are accessed only
//! through the `AtomicU32`/`AtomicU64` references created here; the payload is
//! touched only via `copy_nonoverlapping` under the fences above.

use core::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

use crate::layout::PackedEntry;

/// Byte offset of `seq` within a slot (`AtomicU64`, SQ1).
pub const OFF_SEQ: usize = 0;
/// Byte offset of `state` within a slot.
pub const OFF_STATE: usize = 8;
/// Byte offset of `key_hash` within a slot (8-aligned; 4 pad bytes after `state`).
pub const OFF_KEY_HASH: usize = 16;
/// Byte offset of the `PackedEntry` payload within a slot.
pub const OFF_PAYLOAD: usize = 24;

/// Reader spin budget for an odd `seq` (writer mid-update) before declaring the
/// slot a crashed-writer torn write and returning `None`. Small + fixed: a live
/// writer's odd window is a handful of stores, so a few thousand spins is far more
/// than a live update ever needs, yet bounded so a dead writer can't hang a reader.
const ODD_SPIN_BUDGET: u32 = 4096;

/// Max snapshot retries when `s1 != s2` (a write landed during the copy). Same
/// reasoning: a live writer commits in bounded time; an unbounded retry on a churn
/// storm would still terminate, but we bound it to keep the read total-latency
/// bounded and fail safe to `None` (re-admit) rather than spin forever.
const RETRY_BUDGET: u32 = 1024;

/// A live `AtomicU64` view over the slot's `seq` field (SQ1: widened from u32 so the
/// +2-per-commit counter cannot ABA within a process lifetime).
///
/// # Safety
/// `slot_ptr` must satisfy the module safety invariants. The returned reference
/// borrows the mapping for `'a`; the bytes may be concurrently written by another
/// process, which is exactly why it is an `AtomicU64` (no torn read of the counter
/// itself). `OFF_SEQ` is 0 and the slot base is 8-aligned, so the `AtomicU64` is
/// well-aligned.
#[inline]
unsafe fn seq_atomic<'a>(slot_ptr: *mut u8) -> &'a AtomicU64 {
    &*(slot_ptr.add(OFF_SEQ) as *const AtomicU64)
}

#[inline]
unsafe fn state_atomic<'a>(slot_ptr: *mut u8) -> &'a AtomicU32 {
    &*(slot_ptr.add(OFF_STATE) as *const AtomicU32)
}

#[inline]
unsafe fn key_hash_atomic<'a>(slot_ptr: *mut u8) -> &'a AtomicU64 {
    &*(slot_ptr.add(OFF_KEY_HASH) as *const AtomicU64)
}

/// Out-of-band reads a reader does BEFORE paying for the full payload copy: the
/// state tag and the key-hash fingerprint. Cheap atomics; the EMPTY check stops a
/// probe and the hash check rejects a non-matching occupied slot.
///
/// # Safety
/// `slot_ptr` must satisfy the module safety invariants.
#[inline]
pub unsafe fn read_oob(slot_ptr: *mut u8) -> (u32, u64) {
    let state = state_atomic(slot_ptr).load(Ordering::Acquire);
    let key_hash = key_hash_atomic(slot_ptr).load(Ordering::Acquire);
    (state, key_hash)
}

/// The lock-free seqlock read of a slot's payload (the hot path). Returns:
/// - `Some(entry)` — a consistent snapshot of the payload, OR
/// - `None` — the slot's writer is crashed/torn (odd-spin budget exhausted) or the
///   snapshot never stabilized (retry budget exhausted): fail-safe to "absent",
///   which routes to the D68 re-admit, never a torn vouch.
///
/// This does NOT interpret `state`/`key_hash`; the caller pairs it with
/// [`read_oob`] for probe decisions and re-validates the key bytes in the returned
/// snapshot.
///
/// # Safety
/// `slot_ptr` must satisfy the module safety invariants.
pub unsafe fn read_payload(slot_ptr: *mut u8) -> Option<PackedEntry> {
    let seq = seq_atomic(slot_ptr);
    let payload_ptr = slot_ptr.add(OFF_PAYLOAD) as *const PackedEntry;
    let mut retries = 0u32;
    loop {
        // Step 1: load seq; if odd, a writer is mid-update — bounded spin.
        let mut s1 = seq.load(Ordering::Acquire);
        let mut spins = 0u32;
        while s1 & 1 != 0 {
            if spins >= ODD_SPIN_BUDGET {
                // Crashed-writer torn slot: fail safe to "absent".
                return None;
            }
            core::hint::spin_loop();
            spins += 1;
            s1 = seq.load(Ordering::Acquire);
        }

        // Step 2: fence then copy the payload OUT to a local buffer, then fence.
        fence(Ordering::Acquire);
        // SAFETY: `payload_ptr` is within the slot (OFF_PAYLOAD + size_of::<PackedEntry>()
        // ≤ stride by construction) and `PackedEntry` is POD, so any bit pattern —
        // including a torn mix the writer is concurrently producing — is a valid
        // inhabitant. A torn copy is discarded by the step-3 recheck below, so torn
        // bytes are never OBSERVED (the seqlock guarantee).
        let snapshot = core::ptr::read(payload_ptr);
        fence(Ordering::Acquire);

        // Step 3: re-read seq. If unchanged (and even), the copy is consistent.
        let s2 = seq.load(Ordering::Acquire);
        if s1 == s2 {
            return Some(snapshot);
        }
        // A write landed during the copy: retry (bounded).
        retries += 1;
        if retries >= RETRY_BUDGET {
            // Churn storm we couldn't snapshot through: fail safe to "absent".
            return None;
        }
        core::hint::spin_loop();
    }
}

/// The even base to start a write from. Under the single-writer invariant `seq` is
/// always even here; if a crash/repair-miss ever left it ODD we **advance** to the
/// next even rather than masking the odd bit DOWN — masking down would re-issue a
/// `(seq, payload)` pairing a reader may already have accepted (an ABA on the
/// counter). Advancing keeps the committed `seq` strictly monotone, so a reader
/// never sees the same even value paired with two different payload generations.
#[inline]
unsafe fn even_base(seq: &AtomicU64) -> u64 {
    let began = seq.load(Ordering::Relaxed);
    if began & 1 == 0 {
        began
    } else {
        began.wrapping_add(1)
    }
}

/// The single-writer commit of a slot. Sets `state`/`key_hash` out-of-band and the
/// payload under the odd/even seqlock discipline. `&mut`-gating on the map is what
/// makes this single-writer.
///
/// The out-of-band `state`/`key_hash` stores are **`Release`** (not `Relaxed`):
/// `read_oob` consumes them with `Acquire` loads to drive probe decisions WITHOUT
/// reading `seq`, so they need their own synchronizes-with edge — on a weak-memory
/// target (aarch64) a `Relaxed` store would give the `Acquire` load nothing to pair
/// with. (Correctness never *depends* on the probe hints — the vouch is always
/// re-validated against the seqlock-protected snapshot — but reliable hints avoid
/// spurious re-admits.)
///
/// # Safety
/// `slot_ptr` must satisfy the module safety invariants AND there must be no other
/// writer to this slot (the map's `&mut self` guarantees it). The mapping must be
/// `PROT_READ|PROT_WRITE` (the reader-view never calls this).
pub unsafe fn write_slot(slot_ptr: *mut u8, state: u32, key_hash: u64, payload: &PackedEntry) {
    // INVARIANT (load-bearing for the reader's EMPTY-stops-probe shortcut): a writer
    // NEVER publishes STATE_EMPTY. Runtime frees go to TOMBSTONE (revoke/repair), so a
    // slot is EMPTY only before its first occupancy — which is what lets `lookup` treat
    // EMPTY as "probe chain ends, key absent" without a full seqlock read. Re-EMPTYing
    // an occupied slot would break a probe chain to a live colliding key past it.
    debug_assert_ne!(
        state,
        crate::layout::STATE_EMPTY,
        "writer must never publish STATE_EMPTY (use TOMBSTONE for runtime frees)"
    );
    let seq = seq_atomic(slot_ptr);
    let payload_ptr = slot_ptr.add(OFF_PAYLOAD) as *mut PackedEntry;

    // Step 1: even base → bump to odd (writer-in), Release. (Monotone; see `even_base`.)
    let base = even_base(seq);
    seq.store(base | 1, Ordering::Release);
    fence(Ordering::Release);

    // Step 2: publish the payload and the out-of-band state/key_hash (Release).
    // SAFETY: `payload_ptr` is within the slot and POD; we are the sole writer.
    core::ptr::write(payload_ptr, *payload);
    state_atomic(slot_ptr).store(state, Ordering::Release);
    key_hash_atomic(slot_ptr).store(key_hash, Ordering::Release);

    // Step 3: fence, then commit (next even), Release.
    fence(Ordering::Release);
    seq.store(base.wrapping_add(2), Ordering::Release);
}

/// Tombstone a slot on revoke: set `state = TOMBSTONE` AND **clear `key_hash` to 0**
/// without rewriting the payload, under the seqlock. Clearing the out-of-band hash
/// shrinks the stale-vouch window — a racing `read_oob` for the revoked key now
/// hash-misses immediately and skips, rather than paying a full payload read that
/// would still match the not-yet-overwritten key bytes. (A `lookup` already in
/// flight may still return the entry once; that is the D68/W4-tolerated revoke race,
/// and revocation severing is handled by the rung-conditional conntrack flush.)
/// TOMBSTONE (not EMPTY) so a linear probe past this slot still finds a colliding
/// key. The `Release` stores pair with `read_oob`'s `Acquire` loads (as in
/// [`write_slot`]).
///
/// # Safety
/// As [`write_slot`].
pub unsafe fn tombstone_slot(slot_ptr: *mut u8) {
    let seq = seq_atomic(slot_ptr);
    let base = even_base(seq);
    seq.store(base | 1, Ordering::Release);
    fence(Ordering::Release);
    state_atomic(slot_ptr).store(crate::layout::STATE_TOMBSTONE, Ordering::Release);
    key_hash_atomic(slot_ptr).store(0, Ordering::Release);
    fence(Ordering::Release);
    seq.store(base.wrapping_add(2), Ordering::Release);
}

/// Raw `seq` load (Relaxed) — used by the writer-attach torn-slot scan, which runs
/// single-threaded before the new writer serves, so Relaxed is sufficient.
///
/// # Safety
/// As the module invariants.
#[inline]
pub unsafe fn raw_seq(slot_ptr: *mut u8) -> u64 {
    seq_atomic(slot_ptr).load(Ordering::Relaxed)
}

/// Repair a torn slot found on writer attach: a slot left at ODD `seq` by a crashed
/// writer is rolled back to **TOMBSTONE**/key_hash=0 and its `seq` forced to the next
/// even value, so no reader spins forever and no half-written entry is ever matched.
/// Safe because insert-then-answer means a torn=uncommitted write never had its DNS
/// answer sent — a re-query re-admits (doc 11 §8.4.1).
///
/// **TOMBSTONE, not EMPTY:** repair runs on the re-attaching writer *while live
/// ds-tlsproxy readers are mapped to the same segment*. If a torn slot were reset to
/// EMPTY and it sat mid-probe-chain (a torn *refresh* of a previously-committed key
/// that another colliding key was inserted past), a concurrent reader would stop its
/// probe at the new EMPTY and miss the still-live colliding key. A TOMBSTONE
/// continues the probe, so chains stay intact; the torn key itself is simply gone
/// (its lookup returns `None` → re-admit). The stores are `Release` (paired with
/// `read_oob`'s `Acquire`) since readers may be live during attach.
///
/// # Safety
/// As [`write_slot`]; no concurrent *writer* on attach, but concurrent *readers* may
/// be live — hence the `Release` ordering and the TOMBSTONE (probe-chain-preserving)
/// choice.
pub unsafe fn repair_torn_slot(slot_ptr: *mut u8) {
    let seq = seq_atomic(slot_ptr);
    let s = seq.load(Ordering::Relaxed);
    // Precondition: only ever called on a torn (ODD) slot, so `s.wrapping_add(1)` lands
    // on the next even (committed) value. The sole caller (`bump_epoch_and_repair`)
    // guards on `s & 1 != 0`; assert it so a future caller can't silently push an even
    // slot to ODD (which would manufacture a torn slot).
    debug_assert_eq!(
        s & 1,
        1,
        "repair_torn_slot called on a non-torn (even) slot"
    );
    state_atomic(slot_ptr).store(crate::layout::STATE_TOMBSTONE, Ordering::Release);
    key_hash_atomic(slot_ptr).store(0, Ordering::Release);
    fence(Ordering::Release);
    // s is odd → s+1 is even.
    seq.store(s.wrapping_add(1), Ordering::Release);
}
