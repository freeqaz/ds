//! The cross-process segment layout — header, entry slot, reverse-index slot —
//! as fixed-size `#[repr(C)]` POD, plus the capacity bounds and the FNV key hash.
//!
//! These bytes are a **contract between two processes** (the ds-dnsgate writer and
//! the ds-tlsproxy reader map the same region — doc 11 §8.4.1), so every type here
//! is `#[repr(C)]` with no heap pointer crossing the mapping. The heap-y
//! `AdmissionEntry` (`Vec`/`String` fields) is serialized into bounded inline
//! arrays in [`PackedEntry`]; an `admit` that exceeds any bound fails closed
//! (`AdmissionError::Storage`), never silently truncates (doc 11 §8.5).
//!
//! The layout is versioned by [`LAYOUT_VERSION`], **distinct from**
//! `ADMISSION_API_VERSION`: the API shape is frozen, but the *byte encoding* of
//! that shape may change additively without an API bump, so the two version
//! numbers move independently.

use ds_contracts::dns_admission::{AddressFamily, AdmissionType, ADMISSION_API_VERSION};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Segment magic — identifies a ds-admission-shm region. `b"DSADMSHM"` as LE u64.
pub const MAGIC: u64 = u64::from_le_bytes(*b"DSADMSHM");

/// The on-segment byte-layout version (doc 11 §8.4.1). Distinct from
/// `ADMISSION_API_VERSION`: a non-additive change to the layout below bumps this.
///
/// v2 (SQ1): the per-slot seqlock `seq` was widened from `AtomicU32` to
/// `AtomicU64` (the +2-per-commit counter could ABA after 2^31 commits to a hot
/// slot and hand a long-preempted reader a torn cross-generation snapshot). The
/// wider counter pushes the out-of-band header from 16 to 24 bytes (`seq:u64`,
/// `state:u32`, 4 pad, `key_hash:u64`) and thus `OFF_PAYLOAD` from 16 to 24, so it
/// is a non-additive byte-layout change: the writer and reader must redeploy
/// together, which the version bump enforces on attach (`validate_header`).
pub const LAYOUT_VERSION: u32 = 2;

// ── Capacity bounds (documented, enforced fail-closed; doc 11 §8.4.1/§8.5) ──────

/// Max bytes of a `session_uuid` (a UUID string is 36; 64 leaves headroom).
pub const MAX_SESSION_LEN: usize = 64;
/// Max bytes of an `original_query_fqdn` — the DNS name ceiling (255).
pub const MAX_FQDN_LEN: usize = 255;
/// Max admitted IPs per entry — **the same knob** as the §8.5 max-IPs-per-domain
/// cap; the slot capacity *is* that cap.
pub const MAX_ADMITTED_IPS: usize = 32;
/// Max `real_targets` (Phase-B synthetic-A) per entry.
pub const MAX_REAL_TARGETS: usize = 16;
/// Max bytes of each of the three POL-3 provenance strings.
pub const MAX_PROV_LEN: usize = 96;

// ── State tags (out-of-band atomic, see [`crate::seqlock`]) ─────────────────────

/// Entry slot is empty — stops a probe.
pub const STATE_EMPTY: u32 = 0;
/// Entry slot holds a live admission.
pub const STATE_OCCUPIED: u32 = 1;
/// Entry slot was revoked — does NOT stop a probe (continue past it).
pub const STATE_TOMBSTONE: u32 = 2;

// ── Packed POD address ──────────────────────────────────────────────────────────

/// A fixed-size family-tagged address. `family` is 4 (V4) or 6 (V6); v4 uses the
/// first 4 octets, v6 all 16. The octet count is implied by `family`, so the
/// padding bytes are normalized to 0 on write and ignored on read.
///
/// The zerocopy derives (`FromBytes`/`IntoBytes`/`Immutable`/`KnownLayout`/
/// `Unaligned`) make the byte↔type mapping a checked, `unsafe`-free operation: every
/// bit pattern of the 17 packed bytes is a valid `PackedAddr` (`FromBytes`) and the
/// struct has no implicit padding to leak (`IntoBytes` would fail to compile if it
/// did — `u8` family + `[u8; 16]` is gap-free at align 1, so `Unaligned` holds).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct PackedAddr {
    /// 4 for V4, 6 for V6 (the IP-version number, not an enum discriminant — a
    /// stable on-segment encoding independent of the Rust enum layout).
    pub family: u8,
    /// Address octets in network byte order; trailing bytes 0 for V4.
    pub octets: [u8; 16],
}

impl PackedAddr {
    /// Pack a contract `AdmittedAddr` into the fixed POD shape. Returns `None`
    /// if the octet length does not match the family (a malformed address — fail
    /// closed rather than encode an ambiguous slot).
    pub fn from_addr(a: &ds_contracts::dns_admission::AdmittedAddr) -> Option<PackedAddr> {
        let family = match a.family {
            AddressFamily::V4 => 4u8,
            AddressFamily::V6 => 6u8,
        };
        let want = if family == 4 { 4 } else { 16 };
        if a.octets.len() != want {
            return None;
        }
        let mut octets = [0u8; 16];
        octets[..want].copy_from_slice(&a.octets);
        Some(PackedAddr { family, octets })
    }

    /// Decode back to a contract `AdmittedAddr`. Returns `None` for an
    /// unrecognized family byte (a torn/corrupt slot — fail safe to "absent").
    pub fn to_addr(self) -> Option<ds_contracts::dns_admission::AdmittedAddr> {
        let (family, len) = match self.family {
            4 => (AddressFamily::V4, 4usize),
            6 => (AddressFamily::V6, 16usize),
            _ => return None,
        };
        Some(ds_contracts::dns_admission::AdmittedAddr {
            family,
            octets: self.octets[..len].to_vec(),
        })
    }
}

// ── The packed value/key payload — the seqlock-protected region ─────────────────

/// The full entry payload copied under the seqlock (the key bytes are inside the
/// snapshot so a reader re-validates the key against the consistent copy, not just
/// the out-of-band hash). `#[repr(C)]` POD: no heap pointer, all fixed arrays.
///
/// Field order is chosen so the natural `#[repr(C)]` alignment needs no manual
/// padding (8-byte fields first, then the byte arrays). `key_hash` is duplicated
/// here (it also lives out-of-band) so a snapshot is self-describing.
///
/// All padding is **explicit named fields** (`_pad` @33, `_pad2` @353, `_pad_tail`
/// @1458): the `IntoBytes` derive refuses to compile if ANY implicit padding remains,
/// so a green build is the proof that the struct is gap-free and the all-bytes view
/// the cross-process contract relies on has no uninitialized holes. `FromBytes` +
/// `FromZeros` give the `unsafe`-free `new_zeroed()` that replaces the old
/// `core::mem::zeroed()`; `Immutable`/`KnownLayout` are the zerocopy trait bounds.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PackedEntry {
    /// `expires_at.unix_nanos` — the single shared deadline (W2).
    pub expires_at: u64,
    /// `admitted_at.unix_nanos`.
    pub admitted_at: u64,
    /// FNV-1a of the key (mirror of the out-of-band `key_hash`).
    pub key_hash: u64,
    /// `AdmissionType` as a stable byte: 0 Normal, 1 Synthetic, 2 SinkholeReserved.
    pub admission_type: u8,
    /// Number of live `admitted_ips` (≤ `MAX_ADMITTED_IPS`).
    pub admitted_ip_count: u8,
    /// Number of live `real_targets` (≤ `MAX_REAL_TARGETS`).
    pub real_target_count: u8,
    /// Length of the live `session_uuid` bytes (≤ `MAX_SESSION_LEN`).
    pub session_len: u8,
    /// Length of the live `original_query_fqdn` bytes (≤ `MAX_FQDN_LEN`), as u16.
    pub fqdn_len: u16,
    /// Lengths of the three provenance strings (rule_id, policy_layer,
    /// policy_version), each ≤ `MAX_PROV_LEN`.
    pub prov_len: [u8; 3],
    /// Padding to keep the following byte arrays from forcing odd alignment.
    pub _pad: u8,
    /// session_uuid bytes (only `session_len` live).
    pub session: [u8; MAX_SESSION_LEN],
    /// fqdn bytes (only `fqdn_len` live).
    pub fqdn: [u8; MAX_FQDN_LEN],
    /// padding so the address arrays land on a clean boundary.
    pub _pad2: u8,
    /// admitted IPs (only `admitted_ip_count` live).
    pub admitted_ips: [PackedAddr; MAX_ADMITTED_IPS],
    /// real targets (only `real_target_count` live).
    pub real_targets: [PackedAddr; MAX_REAL_TARGETS],
    /// rule_id bytes (only `prov_len[0]` live).
    pub prov_rule_id: [u8; MAX_PROV_LEN],
    /// policy_layer bytes (only `prov_len[1]` live).
    pub prov_policy_layer: [u8; MAX_PROV_LEN],
    /// policy_version bytes (only `prov_len[2]` live).
    pub prov_policy_version: [u8; MAX_PROV_LEN],
    /// Explicit trailing padding (offsets 1458..1464): the named-field run ends at
    /// 1458 and the 8-byte alignment rounds the struct to 1464, so these 6 bytes are
    /// what `#[repr(C)]` would otherwise insert IMPLICITLY. Making them a named field
    /// is what lets the `IntoBytes` derive succeed (no implicit padding) while keeping
    /// `size_of::<PackedEntry>() == 1464` — the cross-process layout byte-for-byte
    /// unchanged. Always zero on write; ignored on read.
    pub _pad_tail: [u8; 6],
}

// ── Cross-process byte-layout pins (fail the BUILD, not a runtime test) ──────────
//
// `PackedEntry`/`Header`/`PackedAddr` are a byte-for-byte contract between the
// ds-dnsgate writer and the ds-tlsproxy reader (they mmap the same region). A field
// reorder, a width change, or a padding shift silently changes the cross-process
// layout. These `const _` assertions make any such change a COMPILE ERROR until
// `LAYOUT_VERSION` is bumped (and the reader/writer redeployed together), so the
// two processes can never disagree on the byte encoding undetected.
//
// IF YOU CHANGE ANY OF THESE NUMBERS you are changing the on-segment layout: bump
// `LAYOUT_VERSION` above and re-pin the value here in the same change.

/// `PackedEntry` must stay 8-aligned: it holds `u64` fields and the slot's
/// `OFF_PAYLOAD = 24` start (and the 8-rounded stride) assume an 8-aligned payload.
const _: () = assert!(core::mem::align_of::<PackedEntry>() == 8);
/// The exact `PackedEntry` size. Changing it changes the slot stride and the whole
/// segment layout → requires a `LAYOUT_VERSION` bump. (Current: the field set above
/// packs to 1464 bytes on a `repr(C)` 8-align target.)
const _: () = assert!(core::mem::size_of::<PackedEntry>() == 1464);

/// The header is the first 64 bytes of every segment (read on attach to validate the
/// cross-process contract). Pinned so a header field reorder/resize is caught.
const _: () = assert!(core::mem::size_of::<Header>() == 64);
/// The header must be 8-aligned (it leads with `magic: u64` and ends with
/// `writer_epoch: u64`, accessed as an `AtomicU64` over its shared bytes).
const _: () = assert!(core::mem::align_of::<Header>() == 8);

/// `PackedAddr` is a tightly-packed POD (`u8` family + `[u8; 16]`); pin its size so a
/// width change to the address encoding is caught (it is embedded in both tables).
const _: () = assert!(core::mem::size_of::<PackedAddr>() == 17);

/// `OFF_PAYLOAD` (the seqlock payload offset within an entry slot, see
/// [`crate::seqlock`]) must keep `PackedEntry` on its 8-byte alignment so the
/// in-place `read`/`write` of the payload is well-aligned. `crate::seqlock::OFF_PAYLOAD`
/// is `24` (SQ1: `seq` widened to u64), a multiple of 8.
const _: () = assert!(24 % core::mem::align_of::<PackedEntry>() == 0);

// Explicit-pad pins: the named pad fields must occupy EXACTLY the bytes the old
// implicit padding did, so the on-segment layout is byte-for-byte unchanged. The
// `IntoBytes` derive already guarantees there is no OTHER (implicit) padding; these
// assertions pin WHERE the explicit pad sits so a future field reorder that moved it
// is a compile error (not a silent cross-process layout drift).
//
/// `Header::_pad` occupies offsets 52..56 (the 4 bytes that 8-align `writer_epoch`),
/// exactly the old implicit padding after `max_prov_len`.
const _: () = assert!(core::mem::offset_of!(Header, _pad) == 52);
const _: () = assert!(core::mem::offset_of!(Header, writer_epoch) == 56);
/// `PackedEntry::_pad_tail` occupies offsets 1458..1464 (the 6 trailing bytes that
/// round the 1458-byte named-field run up to the 8-byte align), exactly the old
/// implicit trailing padding.
const _: () = assert!(core::mem::offset_of!(PackedEntry, _pad_tail) == 1458);
/// The two pre-existing explicit pads keep their offsets too (so the whole
/// PackedEntry field run remains gap-free at the pinned offsets).
const _: () = assert!(core::mem::offset_of!(PackedEntry, _pad) == 33);
const _: () = assert!(core::mem::offset_of!(PackedEntry, _pad2) == 353);

impl PackedEntry {
    /// An all-zero payload (an empty slot's payload). The all-zero bit pattern is a
    /// valid inhabitant (every field is an integer / array of integers / POD
    /// `PackedAddr`), which the `FromZeros` derive proves at compile time — so this is
    /// the `unsafe`-free `new_zeroed()` rather than `core::mem::zeroed()`.
    pub fn zeroed() -> PackedEntry {
        PackedEntry::new_zeroed()
    }
}

/// Encode the AdmissionType to its stable byte.
pub fn type_to_byte(t: AdmissionType) -> u8 {
    match t {
        AdmissionType::Normal => 0,
        AdmissionType::Synthetic => 1,
        AdmissionType::SinkholeReserved => 2,
    }
}

/// Decode the stable AdmissionType byte; unknown → `None` (torn/corrupt slot).
pub fn byte_to_type(b: u8) -> Option<AdmissionType> {
    match b {
        0 => Some(AdmissionType::Normal),
        1 => Some(AdmissionType::Synthetic),
        2 => Some(AdmissionType::SinkholeReserved),
        _ => None,
    }
}

/// FNV-1a 64 of `(session_uuid, 0x1f, original_query_fqdn)`. Never 0 (0 is
/// reserved for an empty `key_hash`). The same separator+order discipline the
/// prototype/bench used, so the two never disagree on a key's fingerprint.
pub fn key_hash(session_uuid: &str, fqdn: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in session_uuid.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= 0x1f; // separator between the two key fields
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    for &b in fqdn.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if h == 0 {
        1
    } else {
        h
    }
}

/// FNV-1a 64 of `(session_uuid, 0x1f, family_byte, octets)` — the reverse-index
/// slot key `(session, ip)`. Never 0.
pub fn rev_key_hash(session_uuid: &str, addr: &PackedAddr) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in session_uuid.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= 0x1f;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= addr.family as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    let len = if addr.family == 4 { 4 } else { 16 };
    for &b in &addr.octets[..len] {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if h == 0 {
        1
    } else {
        h
    }
}

// ── Header ──────────────────────────────────────────────────────────────────────

/// The segment header at offset 0 (`#[repr(C)]`). Read on attach to validate the
/// cross-process contract; `writer_epoch` is an atomic bumped on each writer
/// attach (liveness / torn-write fencing).
///
/// `writer_epoch` is laid out as a `u64` field but is **shared across processes**,
/// so it MUST be accessed only through an `&AtomicU64` view over its address — a
/// `fetch_add(1, Release)` for the attach bump and a `load(Acquire)` for an
/// observer read (F3). A plain ptr read-modify-write of these shared bytes is a
/// data race vs a concurrently-attaching writer / observing reader and is UB; the
/// 8-aligned header (pinned below, `writer_epoch` the trailing field) makes the
/// atomic well-formed. The non-atomic fields are written once at create time and
/// only read thereafter.
///
/// Because of this, `read_header` does NOT bulk-copy `writer_epoch` with the rest
/// of the struct: it copies only the write-once static prefix (`offset_of!(Header,
/// writer_epoch)` bytes) plainly and then *splices in* the value from the
/// `load(Acquire)` of the atomic view — so no caller materializing the header can
/// perform a torn/stale non-atomic read of this one post-create-mutable field.
///
/// The padding before `writer_epoch` is an **explicit named field** (`_pad`, offsets
/// 52..56): the `IntoBytes` derive refuses to compile with implicit padding, so the
/// named pad both proves there is none and keeps `size_of::<Header>() == 64` (the 11
/// `u32`s after `magic` end at offset 52 and `writer_epoch: u64` must 8-align to 56).
/// The zerocopy derives give a checked byte↔type mapping with no `unsafe`.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Header {
    /// `MAGIC`.
    pub magic: u64,
    /// `LAYOUT_VERSION` — the byte-layout contract version.
    pub layout_version: u32,
    /// Must equal `ADMISSION_API_VERSION` on attach, else `VersionMismatch`.
    pub api_version: u32,
    /// Entry-table slot count (power of two).
    pub slot_count: u32,
    /// Entry-table slot stride (bytes per slot, incl. seqlock/state/hash/payload).
    pub slot_stride: u32,
    /// Reverse-index slot count (power of two).
    pub rev_count: u32,
    /// Reverse-index slot stride (bytes per slot).
    pub rev_stride: u32,
    /// `MAX_SESSION_LEN` (capacity bound, recorded for cross-version diagnostics).
    pub max_session_len: u32,
    /// `MAX_FQDN_LEN`.
    pub max_fqdn_len: u32,
    /// `MAX_ADMITTED_IPS`.
    pub max_admitted_ips: u32,
    /// `MAX_REAL_TARGETS`.
    pub max_real_targets: u32,
    /// `MAX_PROV_LEN`.
    pub max_prov_len: u32,
    /// Explicit padding (offsets 52..56) to 8-align `writer_epoch`. Named so the
    /// `IntoBytes` derive (no implicit padding) succeeds while `size_of::<Header>()`
    /// stays 64 — the cross-process header byte-for-byte unchanged. Written zero at
    /// create, never read.
    pub _pad: [u8; 4],
    /// Bumped each time a writer attaches (defensive liveness). Accessed ONLY via an
    /// `&AtomicU64` view (`fetch_add`/`load`), never a plain ptr RMW — see the type
    /// doc (F3) and `ShmAdmissionMap::bump_epoch_and_repair`.
    pub writer_epoch: u64,
}

impl Header {
    /// The header's expected `api_version`.
    pub const API_VERSION: u32 = ADMISSION_API_VERSION;
}

/// Per-slot byte stride for the entry table: seqlock (u64) + state (u32) + pad (4)
/// + key_hash (u64) out-of-band, then the payload, padded to 8.
pub const fn entry_slot_stride() -> u32 {
    // 8 (seq:u64) + 4 (state:u32) + 4 (pad) + 8 (key_hash:u64) = 24 bytes
    // out-of-band header (SQ1: `seq` widened to u64; see `seqlock::OFF_*`),
    // followed by `size_of::<PackedEntry>()`. Round the whole slot up to 8.
    let header = 24usize;
    let payload = core::mem::size_of::<PackedEntry>();
    let raw = header + payload;
    (raw.div_ceil(8) * 8) as u32
}

/// Per-slot byte stride for the reverse-index table: `hash:u64`, `count:u32`,
/// `session_len:u32`, the session bytes, and a `PackedAddr`, padded to 8. The
/// reverse-index slot stores the FULL `(session, ip)` key so a re-attaching writer
/// recovers it.
pub const fn rev_slot_stride() -> u32 {
    // hash:u64 + count:u32 + session_len:u32 = 16, + MAX_SESSION_LEN session bytes
    // + size_of::<PackedAddr>() (17, but padded). Round up to 8.
    let fixed = 16usize;
    let raw = fixed + MAX_SESSION_LEN + core::mem::size_of::<PackedAddr>();
    (raw.div_ceil(8) * 8) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use ds_contracts::dns_admission::AdmittedAddr;

    #[test]
    fn magic_round_trips() {
        assert_eq!(&MAGIC.to_le_bytes(), b"DSADMSHM");
    }

    #[test]
    fn packed_addr_v4_round_trip() {
        let a = AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![93, 184, 216, 34],
        };
        let p = PackedAddr::from_addr(&a).unwrap();
        assert_eq!(p.family, 4);
        assert_eq!(&p.octets[..4], &[93, 184, 216, 34]);
        assert_eq!(p.to_addr().unwrap(), a);
    }

    #[test]
    fn packed_addr_v6_round_trip() {
        let a = AdmittedAddr {
            family: AddressFamily::V6,
            octets: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        let p = PackedAddr::from_addr(&a).unwrap();
        assert_eq!(p.family, 6);
        assert_eq!(p.to_addr().unwrap(), a);
    }

    #[test]
    fn packed_addr_rejects_mismatched_len() {
        // V4 family with 16 octets is malformed → None (fail closed).
        let bad = AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![0u8; 16],
        };
        assert!(PackedAddr::from_addr(&bad).is_none());
    }

    #[test]
    fn key_hash_is_never_zero_and_is_order_sensitive() {
        assert_ne!(key_hash("a", "b"), 0);
        assert_ne!(key_hash("a", "b"), key_hash("b", "a"));
        // separator prevents (ab,"") colliding with (a,b).
        assert_ne!(key_hash("ab", ""), key_hash("a", "b"));
    }

    #[test]
    fn strides_are_multiples_of_eight() {
        assert_eq!(entry_slot_stride() % 8, 0);
        assert_eq!(rev_slot_stride() % 8, 0);
    }

    #[test]
    fn zerocopy_round_trips() {
        use zerocopy::{FromBytes, IntoBytes};

        // ── PackedAddr: bytes → type → bytes is identity ──────────────────────────
        let addr = PackedAddr {
            family: 6,
            octets: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        let addr_bytes = addr.as_bytes();
        assert_eq!(addr_bytes.len(), 17, "PackedAddr is exactly 17 bytes");
        assert_eq!(addr_bytes[0], 6, "family @0");
        assert_eq!(addr_bytes[1], 0x20, "octets[0] @1");
        // bytes → type via the checked FromBytes path (no unsafe), back to bytes.
        let addr2 = PackedAddr::read_from_bytes(addr_bytes).expect("17 bytes decode");
        assert_eq!(addr2.as_bytes(), addr_bytes, "PackedAddr byte round-trip");
        assert_eq!(addr2.family, 6);
        assert_eq!(addr2.octets, addr.octets);

        // ── PackedEntry: populate, type → bytes → type is identity ────────────────
        let mut pe = PackedEntry::zeroed();
        pe.expires_at = 0x1122_3344_5566_7788;
        pe.admitted_at = 0x99aa_bbcc_ddee_ff00;
        pe.key_hash = 0xdead_beef_cafe_f00d;
        pe.admission_type = 1;
        pe.admitted_ip_count = 2;
        pe.real_target_count = 1;
        pe.session_len = 5;
        pe.fqdn_len = 12;
        pe.prov_len = [3, 4, 5];
        pe.session[..5].copy_from_slice(b"hello");
        pe.fqdn[..3].copy_from_slice(b"a.b");
        pe.admitted_ips[0] = addr;
        pe.real_targets[0] = PackedAddr {
            family: 4,
            octets: {
                let mut o = [0u8; 16];
                o[..4].copy_from_slice(&[198, 18, 0, 1]);
                o
            },
        };

        let pe_bytes = pe.as_bytes();
        assert_eq!(
            pe_bytes.len(),
            1464,
            "PackedEntry IntoBytes view is the full 1464-byte struct (no implicit padding)"
        );
        // bytes → type via the checked FromBytes path, then compare byte images.
        let pe2 = PackedEntry::read_from_bytes(pe_bytes).expect("1464 bytes decode");
        assert_eq!(
            pe2.as_bytes(),
            pe_bytes,
            "PackedEntry survives bytes→type→bytes byte-for-byte"
        );
        // spot-check the decoded fields match the original.
        assert_eq!(pe2.expires_at, pe.expires_at);
        assert_eq!(pe2.key_hash, pe.key_hash);
        assert_eq!(pe2.admitted_ip_count, 2);
        assert_eq!(&pe2.session[..5], b"hello");
        assert_eq!(pe2.admitted_ips[0].family, 6);
        assert_eq!(pe2.real_targets[0].octets[..4], [198, 18, 0, 1]);

        // ── new_zeroed() == an all-zero byte image ────────────────────────────────
        let zero = PackedEntry::zeroed();
        let zero_bytes = zero.as_bytes();
        assert_eq!(zero_bytes.len(), 1464);
        assert!(
            zero_bytes.iter().all(|&b| b == 0),
            "PackedEntry::zeroed() (FromZeros new_zeroed) is an all-zero byte image"
        );
    }
}
