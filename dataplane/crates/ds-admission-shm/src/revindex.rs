//! The in-segment reverse index — `(session_uuid, ip) → u32 refcount`, the same
//! per-session IP↔domain distinct-name count the frozen `ReverseIndex` defines.
//!
//! Only the WRITER ever touches it (the ds-tlsproxy reader never reads it), so it
//! needs **no seqlock**: it is plain in-segment storage mutated by the single
//! writer. It lives in-segment (not on the heap) precisely so a re-attaching writer
//! recovers EXACT refcounts without recomputation (doc 11 §8.4.1).
//!
//! Slot layout (`rev_slot_stride`) — pinned by [`RevSlot`] (a `#[repr(C, packed)]`
//! zerocopy POD whose field offsets equal the historical `ROFF_*` constants):
//! ```text
//!   offset 0 : hash        : u64   (rev_key_hash(session, ip); 0 = empty)
//!   offset 8 : count       : u32   (refcount; live iff hash != 0)
//!   offset 12: session_len : u32
//!   offset 16: session     : [u8; MAX_SESSION_LEN]
//!   offset 16+MAX_SESSION_LEN: addr : PackedAddr   (the (session,ip) key bytes)
//! ```
//! The full `(session, ip)` key bytes are stored so an open-addressed probe can
//! disambiguate a hash collision exactly (not just by fingerprint). The logical
//! `RevSlot` is `size_of::<RevSlot>()` bytes (97); the table stride rounds that up to
//! 8 (104) — the trailing stride bytes are never part of `RevSlot` and are not
//! touched (exactly the historical behaviour: the per-field helpers only ever wrote
//! bytes `0..97`).
//!
//! # Safety invariants (this module)
//! All access is through the writer's RW mapping; the index is single-writer so a
//! `&mut [u8]` / `&RevSlot` / `&mut RevSlot` over a slot is sound (no concurrent
//! reader of the reverse index exists — the contract restricts reads to the writer).
//! The `base`/offsets are computed from the validated header, so every slot pointer
//! is in-bounds for a full `RevSlot`. The byte↔`RevSlot` mapping itself is a checked,
//! `unsafe`-free zerocopy operation; the only `unsafe` is forming the in-bounds
//! single-writer `&mut [u8]` window over a slot.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use ds_contracts::dns_admission::{AdmittedAddr, ReverseIndex};

use crate::layout::{rev_key_hash, PackedAddr, MAX_SESSION_LEN};
use crate::segment::SharedBase;

/// One reverse-index slot, byte-for-byte the in-segment encoding.
///
/// `#[repr(C, packed)]` so there is **no implicit padding** between fields (the
/// `IntoBytes` derive proves it: it refuses to compile if any padding remained), and
/// so `size_of::<RevSlot>()` is exactly the logical slot size (97 bytes), matching the
/// historical `ROFF_*` field offsets. `Unaligned` reflects the `packed` align-1 layout
/// (the slot sits at an arbitrary byte offset within the mapping). `FromBytes` makes
/// every bit pattern a valid `RevSlot` (a re-attaching writer reads whatever bytes are
/// there); `Immutable`/`KnownLayout` are the zerocopy bounds for the ref/byte casts.
///
/// The field offsets are pinned to the historical `ROFF_*` values by the
/// `const _` assertions below, so a future field reorder is a COMPILE error rather
/// than a silent cross-process layout drift.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
struct RevSlot {
    /// `rev_key_hash(session, ip)`; `0` = empty (a probe stop).
    hash: u64,
    /// Refcount; the slot is live iff `hash != 0` (a `count == 0`, `hash != 0` slot
    /// is a reclaimable tombstone — see `probe`).
    count: u32,
    /// Live byte length of `session` (`<= MAX_SESSION_LEN`).
    session_len: u32,
    /// session_uuid bytes (only `session_len` live; the rest are zeroed on write).
    session: [u8; MAX_SESSION_LEN],
    /// The `(session, ip)` key's address bytes (the full key, for exact collision
    /// disambiguation).
    addr: PackedAddr,
}

// ── Field-offset pins (fail the BUILD if a field moves) ──────────────────────────
//
// `RevSlot` is laid out byte-for-byte in the cross-restart segment; a re-attaching
// writer recovers refcounts from these exact offsets. Pin them to the historical
// `ROFF_*` so a reorder is caught at compile time. (The struct SIZE/stride is pinned
// by `rev_slot_stride()` + the `rev_slot_byte_layout_is_pinned` test.)
const _: () = assert!(core::mem::offset_of!(RevSlot, hash) == 0);
const _: () = assert!(core::mem::offset_of!(RevSlot, count) == 8);
const _: () = assert!(core::mem::offset_of!(RevSlot, session_len) == 12);
const _: () = assert!(core::mem::offset_of!(RevSlot, session) == 16);
const _: () = assert!(core::mem::offset_of!(RevSlot, addr) == 16 + MAX_SESSION_LEN);
/// `#[repr(C, packed)]` ⇒ no padding ⇒ the byte length is exactly the logical slot
/// size; pin it so the `&mut [u8]` window width below stays correct.
const _: () = assert!(core::mem::size_of::<RevSlot>() == 8 + 4 + 4 + MAX_SESSION_LEN + 17);

/// A view over the in-segment reverse-index table, owned by the writer map.
pub struct RevIndex {
    base: SharedBase,
    /// Byte offset of the reverse-index table within the segment.
    table_off: usize,
    slot_count: usize,
    slot_stride: usize,
    mask: usize,
}

impl RevIndex {
    /// Construct a view over the reverse-index table.
    ///
    /// # Safety
    /// `table_off + slot_count * slot_stride` must be within the mapping length,
    /// `slot_count` a power of two. The map computes these from the validated header.
    pub unsafe fn new(
        base: SharedBase,
        table_off: usize,
        slot_count: usize,
        slot_stride: usize,
    ) -> RevIndex {
        debug_assert!(slot_count.is_power_of_two());
        RevIndex {
            base,
            table_off,
            slot_count,
            slot_stride,
            mask: slot_count - 1,
        }
    }

    #[inline]
    fn slot_ptr(&self, idx: usize) -> *mut u8 {
        // SAFETY: idx < slot_count and the table is in-bounds (see `new`).
        unsafe { self.base.at(self.table_off + idx * self.slot_stride) }
    }

    /// The single-writer, in-bounds `&mut [u8]` window over slot `idx`'s `RevSlot`
    /// bytes (the first `size_of::<RevSlot>()` bytes of the slot; the trailing
    /// stride-padding bytes are not part of `RevSlot` and are not touched).
    ///
    /// This is the ONE localized `unsafe` in the module: forming the slice is sound
    /// because the reverse index is single-writer / this-process-exclusive (no
    /// concurrent reader of this region exists — the contract restricts reads to the
    /// writer), and the window is fully in-bounds (`new`'s safety contract sizes the
    /// table to `slot_count * slot_stride >= slot_count * size_of::<RevSlot>()`). All
    /// FIELD access then goes through the checked, `unsafe`-free zerocopy casts.
    ///
    /// Returning `&mut [u8]` from `&self` (rather than `&mut self`) mirrors the
    /// historical `slot_ptr(&self) -> *mut u8` interior-mutability shape: the table is
    /// reached through the shared `SharedBase` pointer, not through `&mut self`'s
    /// exclusivity, and the single-writer contract (no concurrent reader of this
    /// region) is what makes the aliasing sound — so `clippy::mut_from_ref` is
    /// suppressed with that justification. The PUBLIC mutators (`incref_*`/`decref_*`/
    /// `clear`) still take `&mut self`, so a caller cannot alias the table either.
    #[inline]
    #[allow(
        clippy::mut_from_ref,
        reason = "single-writer shm: mutation goes through the shared SharedBase \
                  pointer, not &mut self; no concurrent reader of the reverse index \
                  exists (the contract restricts reads to the writer)"
    )]
    fn slot_bytes_mut(&self, idx: usize) -> &mut [u8] {
        let p = self.slot_ptr(idx);
        // SAFETY: single-writer, in-bounds slot; `RevSlot` fits within `slot_stride`.
        unsafe { core::slice::from_raw_parts_mut(p, core::mem::size_of::<RevSlot>()) }
    }

    /// A shared `&RevSlot` view over slot `idx` (read-only field access). Same safety
    /// basis as [`Self::slot_bytes_mut`]; the cast itself is the checked zerocopy
    /// `ref_from_bytes` (never panics — the slice length is exactly `size_of`).
    #[inline]
    fn slot_ref(&self, idx: usize) -> &RevSlot {
        let bytes: &[u8] = self.slot_bytes_mut(idx);
        RevSlot::ref_from_bytes(bytes).expect("rev-slot bytes are exactly size_of::<RevSlot>()")
    }

    /// An exclusive `&mut RevSlot` view over slot `idx` (mutating field access). Same
    /// safety basis as [`Self::slot_bytes_mut`]; the checked zerocopy `mut_from_bytes`
    /// never panics for an exact-size slice.
    #[inline]
    fn slot_mut(&self, idx: usize) -> &mut RevSlot {
        let bytes = self.slot_bytes_mut(idx);
        RevSlot::mut_from_bytes(bytes).expect("rev-slot bytes are exactly size_of::<RevSlot>()")
    }

    /// Write the `(session, addr)` key into slot `idx`: stamps `session_len`, zeroes
    /// the session region then copies the live prefix, and stores the addr bytes.
    /// (`hash`/`count` are written by the caller.) Exact semantics of the old
    /// `write_key`: full zero-fill of the session region before the prefix copy.
    fn write_key(&self, idx: usize, session: &str, addr: &PackedAddr) {
        let sb = session.as_bytes();
        let len = sb.len().min(MAX_SESSION_LEN);
        let slot = self.slot_mut(idx);
        slot.session_len = len as u32;
        // Zero the whole session region, then copy the live prefix (a packed field
        // assignment of the array is fine — no reference to the unaligned field escapes).
        let mut session_bytes = [0u8; MAX_SESSION_LEN];
        session_bytes[..len].copy_from_slice(&sb[..len]);
        slot.session = session_bytes;
        slot.addr = *addr;
    }

    /// Does this occupied slot's stored key equal `(session, addr)`? Disambiguates
    /// a hash collision by the full key bytes.
    fn slot_matches(slot: &RevSlot, session: &str, addr: &PackedAddr) -> bool {
        let slen = slot.session_len as usize;
        if slen > MAX_SESSION_LEN || slot.session[..slen] != *session.as_bytes() {
            return false;
        }
        // `addr` is a packed `PackedAddr` field — copy it out before borrowing
        // (a reference into a packed field would be unaligned).
        let a = slot.addr;
        a.family == addr.family && {
            let len = if a.family == 4 { 4 } else { 16 };
            a.octets[..len] == addr.octets[..len]
        }
    }

    /// Find the slot for `(session, addr)`, or an insert slot to take the key.
    /// Returns `(slot_idx, found)`:
    /// - `(i, true)`  — an EXACT `(hash, key)` match (the live or count-0 entry).
    /// - `(i, false)` — no exact match; `i` is the slot an insert should claim,
    ///   preferring a **reclaimable** slot (occupied `hash != 0` but `count == 0`, a
    ///   decref'd-to-zero entry — the reverse-index analogue of a tombstone) over a
    ///   fresh EMPTY (`hash == 0`) slot if one was seen first. This reuses count-0
    ///   slots so a long-lived churning session cannot fill the table with un-freed
    ///   count-0 slots and then under-count a still-shared IP (the CDN-hole via table
    ///   exhaustion). `None` only if the table is genuinely full — every slot holds a
    ///   live `count > 0` entry, no exact match, no reclaimable slot, no empty.
    ///
    /// NOTE: linear-probe integrity. A count-0 slot keeps its `hash` so a probe past
    /// it for a DIFFERENT key continues (it is NOT a stop). An EMPTY (`hash == 0`)
    /// slot stops the probe (the key is absent beyond it). We track the FIRST
    /// reclaimable slot seen but keep probing to the first EMPTY (or back to start)
    /// so an exact match further down the chain still wins — exactly open-addressing
    /// with tombstones.
    fn probe(&self, session: &str, addr: &PackedAddr, want_hash: u64) -> Option<(usize, bool)> {
        let mut idx = (want_hash as usize) & self.mask;
        let mut first_reclaimable: Option<usize> = None;
        for _ in 0..self.slot_count {
            let slot = self.slot_ref(idx);
            let h = slot.hash;
            if h == 0 {
                // EMPTY stops the probe: the key is absent beyond here. Prefer a
                // reclaimable count-0 slot seen earlier over consuming this fresh
                // empty (keeps the empty available, shortens future probe chains).
                return Some((first_reclaimable.unwrap_or(idx), false));
            }
            if h == want_hash && Self::slot_matches(slot, session, addr) {
                // Exact match — the live OR count-0 entry for this key. Always wins,
                // even if a reclaimable slot was seen earlier (decref/refcount must
                // read THIS slot's count as-is; incref reuses this slot too).
                return Some((idx, true));
            }
            if first_reclaimable.is_none() && slot.count == 0 {
                // Occupied (hash != 0) but count == 0: reclaimable for a DIFFERENT
                // key. Remember the first one but keep probing for an exact match.
                first_reclaimable = Some(idx);
            }
            idx = (idx + 1) & self.mask;
        }
        // Probed the whole table without an EMPTY stop and without an exact match:
        // reuse the first reclaimable count-0 slot if seen, else the table is
        // genuinely full (every slot a live count>0 entry of another key).
        first_reclaimable.map(|i| (i, false))
    }

    /// The shared incref body operating on a `PackedAddr`. Returns
    /// `Some(new_count)`, or `None` ONLY when the table is GENUINELY FULL (no exact
    /// match, no reclaimable count-0 slot, no empty — every slot a live `count > 0`
    /// entry of another key). The caller (`lib.rs admit`) treats `None` as a hard
    /// fail-closed: an admission that cannot record its reverse-index incref must NOT
    /// commit (else a later sibling-revoke would under-count and free a still-held
    /// shared IP — the CDN-hole). A malformed addr is handled by the trait wrapper
    /// (returns 0 before reaching here).
    ///
    /// An exact match (live or count-0) increfs the SAME slot — a count-0 exact match
    /// resurrects the key (count 0 → 1) rather than reusing a foreign reclaimable
    /// slot. A `(i, false)` insert slot is a fresh EMPTY or a reclaimable count-0 slot
    /// of a DIFFERENT key; either is overwritten with this key + count 1.
    fn incref_packed_checked(&mut self, session: &str, addr: &PackedAddr) -> Option<u32> {
        let want = rev_key_hash(session, addr);
        match self.probe(session, addr, want) {
            Some((idx, true)) => {
                let c = self.slot_ref(idx).count.saturating_add(1);
                self.slot_mut(idx).count = c;
                Some(c)
            }
            Some((idx, false)) => {
                // Take the empty-or-reclaimable slot for this key.
                self.slot_mut(idx).hash = want;
                self.write_key(idx, session, addr);
                self.slot_mut(idx).count = 1;
                Some(1)
            }
            None => None, // genuinely full — fail closed at the admit boundary
        }
    }

    /// The trait-`incref` body: wraps [`Self::incref_packed_checked`], collapsing the
    /// genuine-full `None` to `0` (the historical bias-to-under-count behaviour) so
    /// the `ReverseIndex` trait signature (`-> u32`) is preserved. New code that must
    /// fail closed on a full reverse table calls `incref_checked` instead.
    fn incref_packed(&mut self, session: &str, addr: &PackedAddr) -> u32 {
        self.incref_packed_checked(session, addr).unwrap_or(0)
    }

    fn decref_packed(&mut self, session: &str, addr: &PackedAddr) -> u32 {
        let want = rev_key_hash(session, addr);
        match self.probe(session, addr, want) {
            Some((idx, true)) => {
                // Saturating decref (bias to under-delete; never underflow).
                let c = self.slot_ref(idx).count.saturating_sub(1);
                self.slot_mut(idx).count = c;
                if c == 0 {
                    // Count hit 0. Linear-probe correctness: zeroing `hash` here
                    // (truly emptying the slot) would turn it into a probe STOP and
                    // could strand a later colliding key. So we keep `hash` set with
                    // `count == 0` — the slot stays probe-transparent (a probe past
                    // it continues), an incref of the SAME key resurrects it (count
                    // 0 → 1), and `probe` may RECLAIM it for a DIFFERENT key once a
                    // fresh empty would otherwise be consumed (see `probe`). This
                    // count-0-as-tombstone reclamation is what prevents a churning
                    // session from filling the table with un-freed count-0 slots and
                    // then under-counting a still-shared IP.
                    self.slot_mut(idx).count = 0;
                }
                c
            }
            // Absent key: saturating decref of a non-existent count is 0.
            _ => 0,
        }
    }

    fn refcount_packed(&self, session: &str, addr: &PackedAddr) -> u32 {
        let want = rev_key_hash(session, addr);
        match self.probe(session, addr, want) {
            Some((idx, true)) => self.slot_ref(idx).count,
            _ => 0,
        }
    }

    /// Fail-closed incref: returns `Some(new_count)`, or `None` ONLY when the table
    /// is GENUINELY FULL (no exact match, no reclaimable count-0 slot, no empty).
    /// A malformed addr (`PackedAddr::from_addr` failed) returns `Some(0)` — the
    /// admit path already rejected it upstream, so it is NOT treated as a capacity
    /// failure (it would never be in a to-add set). Used by `lib.rs admit` to fail
    /// closed before committing an entry whose incref cannot be recorded.
    pub fn incref_checked(&mut self, session: &str, ip: &AdmittedAddr) -> Option<u32> {
        match PackedAddr::from_addr(ip) {
            Some(a) => self.incref_packed_checked(session, &a),
            None => Some(0),
        }
    }

    /// Zero the ENTIRE reverse table back to all-empty (every slot `hash = 0`,
    /// `count = 0`). Used by the warm-restart rebuild (F1): the entry table is the
    /// authoritative record of which `(session, ip)` pairs are live, so on re-attach
    /// the reverse index — which was written with plain non-atomic stores a crashed
    /// writer may have torn, and which `bump_epoch_and_repair` does NOT otherwise
    /// touch — is reset and recomputed from the entry table rather than trusted.
    ///
    /// Single-writer only (called on attach before serving). Writes `hash = 0` to
    /// each slot, which is the EMPTY sentinel a probe stops at, so a recompute that
    /// re-increfs from a clean table reproduces exact refcounts.
    ///
    /// # Safety contract (caller)
    /// Must run single-threaded on the writer (no concurrent reverse-index access);
    /// the reverse index has no reader, so this holds on attach.
    pub fn clear(&mut self) {
        for idx in 0..self.slot_count {
            let slot = self.slot_mut(idx);
            slot.hash = 0;
            slot.count = 0;
        }
    }
}

impl ReverseIndex for RevIndex {
    fn incref(&mut self, session_uuid: &str, ip: &AdmittedAddr, _domain: &str) -> u32 {
        match PackedAddr::from_addr(ip) {
            Some(a) => self.incref_packed(session_uuid, &a),
            None => 0,
        }
    }
    fn decref(&mut self, session_uuid: &str, ip: &AdmittedAddr, _domain: &str) -> u32 {
        match PackedAddr::from_addr(ip) {
            Some(a) => self.decref_packed(session_uuid, &a),
            None => 0,
        }
    }
    fn refcount(&self, session_uuid: &str, ip: &AdmittedAddr) -> u32 {
        match PackedAddr::from_addr(ip) {
            Some(a) => self.refcount_packed(session_uuid, &a),
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::rev_slot_stride;
    use core::mem::{align_of, offset_of, size_of};

    /// Pin `RevSlot`'s field offsets / size / align and the derived table stride to the
    /// reverse-index ORACLE, and prove a written slot lands its bytes at the expected
    /// offsets. A future layout drift (a field reorder, a width change, a padding shift)
    /// turns this RED instead of silently desyncing the cross-restart byte encoding.
    #[test]
    fn rev_slot_byte_layout_is_pinned() {
        // ── Field offsets equal the historical ROFF_* constants ──────────────────
        assert_eq!(offset_of!(RevSlot, hash), 0, "RevSlot::hash @0");
        assert_eq!(offset_of!(RevSlot, count), 8, "RevSlot::count @8");
        assert_eq!(
            offset_of!(RevSlot, session_len),
            12,
            "RevSlot::session_len @12"
        );
        assert_eq!(offset_of!(RevSlot, session), 16, "RevSlot::session @16");
        assert_eq!(
            offset_of!(RevSlot, addr),
            16 + MAX_SESSION_LEN,
            "RevSlot::addr @ 16+MAX_SESSION_LEN (80)"
        );
        assert_eq!(16 + MAX_SESSION_LEN, 80, "roff_addr is 80");

        // ── Size/align: packed ⇒ no padding ⇒ logical 97 bytes, align 1 ───────────
        assert_eq!(
            size_of::<RevSlot>(),
            8 + 4 + 4 + MAX_SESSION_LEN + 17,
            "RevSlot is gap-free (packed): 8+4+4+64+17 = 97"
        );
        assert_eq!(size_of::<RevSlot>(), 97, "RevSlot logical size");
        assert_eq!(align_of::<RevSlot>(), 1, "RevSlot is align-1 (packed)");

        // ── Table stride rounds the 97-byte slot up to the 8-byte align → 104 ─────
        assert_eq!(rev_slot_stride(), 104, "rev_slot_stride = round8(97)");
        assert_eq!(rev_slot_stride() as usize % 8, 0, "stride 8-aligned");
        assert!(
            (rev_slot_stride() as usize) >= size_of::<RevSlot>(),
            "stride covers the whole RevSlot"
        );

        // ── A written slot lands each field's bytes at its pinned offset ──────────
        // Build a RevSlot, view it as bytes (the IntoBytes derive — no unsafe), and
        // assert the on-segment byte image matches the historical hand-rolled layout.
        let addr = PackedAddr {
            family: 6,
            octets: [0xFE; 16],
        };
        let slot = RevSlot {
            hash: 0x0102_0304_0506_0708,
            count: 0x0A0B_0C0D,
            session_len: 8,
            session: {
                let mut s = [0u8; MAX_SESSION_LEN];
                s[..8].copy_from_slice(b"sess-key");
                s
            },
            addr,
        };
        let bytes = slot.as_bytes();
        assert_eq!(
            bytes.len(),
            97,
            "RevSlot IntoBytes view is the full 97 bytes"
        );
        // hash @0 (LE).
        assert_eq!(bytes[0], 0x08, "rev hash LE byte0 @0");
        assert_eq!(bytes[7], 0x01, "rev hash LE byte7 @7");
        // count @8 (LE).
        assert_eq!(bytes[8], 0x0D, "rev count LE byte0 @8");
        assert_eq!(bytes[11], 0x0A, "rev count LE byte3 @11");
        // session_len @12 (LE).
        assert_eq!(bytes[12], 8, "rev session_len LE byte0 @12");
        // session[0] @16.
        assert_eq!(bytes[16], b's', "rev session[0] @16");
        assert_eq!(bytes[23], b'y', "rev session[7] @23");
        // addr.family @80, octets[0] @81.
        assert_eq!(bytes[80], 6, "rev addr.family @80");
        assert_eq!(bytes[81], 0xFE, "rev addr.octets[0] @81");
        assert_eq!(bytes[96], 0xFE, "rev addr.octets[15] @96 (last byte)");

        // ── Round-trip: bytes → RevSlot → bytes is identity (checked zerocopy) ────
        let back = RevSlot::read_from_bytes(bytes).expect("97 bytes decode");
        assert_eq!(back.as_bytes(), bytes, "RevSlot byte round-trip");
        assert_eq!({ back.hash }, 0x0102_0304_0506_0708, "hash survives");
        assert_eq!({ back.count }, 0x0A0B_0C0D, "count survives");
        assert_eq!({ back.session_len }, 8, "session_len survives");
        assert_eq!(back.session[..8], *b"sess-key", "session survives");
        assert_eq!({ back.addr }.family, 6, "addr family survives");
    }
}
