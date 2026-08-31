//! The C-ABI staticlib edge: the `#[no_mangle] extern "C"` surface the Go host
//! agent links against through `orchestrator/internal/nftbridge/` (doc 14 §6 —
//! the one explicit Go↔Rust write edge; the cgo binding's content_hash contract
//! home).
//!
//! # The unsafe carve-out (D4)
//!
//! The crate root is `#![deny(unsafe_code)]` (NOT `forbid` — `forbid` is, by
//! language rule, un-downgradeable, so an inner `allow` under it is a hard
//! `E0453` compile error and this carve-out could not exist; see the lib.rs
//! lint comment). This ONE module relaxes that `deny` to `#![allow(unsafe_code)]`
//! because an `extern "C"` ABI that takes `*const c_char` is *inherently*
//! unsafe — it must dereference caller-supplied raw pointers. That is the
//! conscious, reviewed FFI exception (D4): the unsafe is contained to the thin
//! marshalling shell here, and every byte of policy / mechanism still lives in
//! the safe Rust below it (`backend`, `flush`). No other module may turn unsafe
//! code on — a lone `#[allow(unsafe_code)]` outside `ffi` still trips the deny.
//!
//! # The surface (mechanism only — D1/D2/D3)
//!
//! - [`ds_nft_create_tap`] — create the `dstap-<idx>` netdev (mechanism only:
//!   NO IP/route, NO nft rules), wrapping [`crate::backend::NftBackend::create_tap`].
//! - [`ds_nft_delete_tap`] — delete the tap, wrapping
//!   [`crate::backend::NftBackend::delete_tap`].
//! - [`ds_nft_flush_session`] — `flush_session(legs=all, dst=all)`, the NFT-6
//!   teardown flush (doc 15 §4.2), wrapping [`crate::flush::NftWriter`].
//! - [`ds_nft_instantiate_session`] — the full per-session CREATE lifecycle: the
//!   MODEL-A admit surface (ensure `inet ds_filter`, then the EMPTY per-session
//!   `allow4_<idx>` / `allow6_<idx>` sets) COMPOSED with the NFT-5 `ct mark`
//!   flow-tag stamp, wrapping [`crate::flush::NftWriter::create_session`].
//! - [`ds_nft_teardown_session`] — the full per-session DESTROY lifecycle: remove
//!   those per-session allow-sets COMPOSED with the NFT-5 flow-tag unstamp,
//!   wrapping [`crate::flush::NftWriter::destroy_session`].
//! - [`ds_nft_last_error`] — the thread-local message of the LAST
//!   [`crate::backend::BackendError`] this thread produced, for the Go side to
//!   surface (a borrowed, NUL-terminated C string).
//!
//! Return convention: **`0` on success, a negative code on a backend error**
//! (the message is then retrievable via [`ds_nft_last_error`]). A `NULL` /
//! non-UTF-8 / interior-NUL pointer argument is itself a negative-coded error.
//!
//! # `ds_nft_instantiate_session` — admit surface COMPOSED with the NFT-5 stamp (D1/D3/D4/D75/D76)
//!
//! The per-session INSTANTIATE symbol drives the full per-session CREATE
//! lifecycle ([`crate::flush::NftWriter::create_session`], D76): FIRST the
//! MODEL-A admit surface — idempotently ensure `inet ds_filter` (a leading `add
//! table`, a no-op that never clears existing sets; no host bootstrap artifact
//! owns this table), then create the EMPTY `allow4_<idx>` / `allow6_<idx>` sets
//! in it (the set NAME is the single-source
//! [`ds_contracts::session::allow_set_name`], so this side and the ds-dnsgate
//! fill side cannot diverge) — THEN the NFT-5 flow-tag stamp: a per-session `ct
//! mark` write on the `dstap-<idx>` tap (on the SEPARATE `inet ds_flowtag` table)
//! so the session's flows are attributable (doc 14 §5, D76). The mark VALUE is
//! sourced from `ds-contracts` inside [`crate::flowtag`], never re-authored at
//! this edge. The admit surface still writes NO default-deny, NO redirect, and NO
//! session enforcement chain — the host-wide `dstap-*` glob floor owns all of
//! those, and the NFT-3b `out_<session>` OUTPUT chain that READS the sets is
//! Stage-3, out of scope (session doc 11 §3 Model A / §5.1). The `<idx>` token is
//! the `host_session_index` (D4). `tap_name` is carried for symmetry with the
//! other verbs and is NOT load-bearing for the set name (the name keys on the
//! index). Repointing this FROZEN C ABI onto `create_session` closes the gap
//! where FFI-driven sessions (host-agent `nftbridge.InstantiateSession`) got the
//! admit surface but not the attribution stamp (task `01KX57B9H7`).

#![allow(unsafe_code)]

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};

use crate::backend::{
    BackendError, ConntrackDestroy, ConntrackOutput, NftBackend, NftBatch, SpawnBackend, TapSpec,
};
use crate::flush::NftWriter;
use ds_contracts::flush::{DstFilter, FlushSession, LegSelector};
use ds_contracts::session::SessionRef;

/// Borrow a backend as an owned [`NftBackend`] so it can be handed to
/// [`NftWriter`] (which takes its backend by value) without consuming the
/// caller's backend. Pure delegation — every method forwards to the borrowed
/// backend. This is the FFI's local glue so the same backend-generic flush
/// body serves both the production [`SpawnBackend`] (owned, the extern-C path)
/// and a borrowed test [`crate::backend::RecordingBackend`] (inspected after).
struct BackendRef<'a, B: NftBackend>(&'a B);

impl<B: NftBackend> NftBackend for BackendRef<'_, B> {
    fn apply_batch(&self, batch: &NftBatch) -> Result<(), BackendError> {
        self.0.apply_batch(batch)
    }
    fn destroy_conntrack(
        &self,
        destroy: &ConntrackDestroy,
    ) -> Result<ConntrackOutput, BackendError> {
        self.0.destroy_conntrack(destroy)
    }
    fn create_tap(&self, spec: &TapSpec) -> Result<(), BackendError> {
        self.0.create_tap(spec)
    }
    fn delete_tap(&self, name: &str) -> Result<(), BackendError> {
        self.0.delete_tap(name)
    }
}

/// Return code: the call succeeded.
pub const DS_NFT_OK: i32 = 0;
/// Return code: an argument pointer was NULL, non-UTF-8, or carried an interior
/// NUL — the marshalling rejected it before reaching the backend.
pub const DS_NFT_ERR_ARG: i32 = -1;
/// Return code: the backend (nft/conntrack/ip mechanism) returned an error.
/// The message is retrievable via [`ds_nft_last_error`].
pub const DS_NFT_ERR_BACKEND: i32 = -2;

thread_local! {
    /// The last [`BackendError`]/arg-error message produced on THIS thread,
    /// kept as a `CString` so [`ds_nft_last_error`] can hand back a stable,
    /// NUL-terminated borrow. Cleared (set to empty) on every successful call.
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

/// Record `msg` as this thread's last error and return `code`. Always returns
/// the negative code so callers can `return set_error(...)` in one line.
fn set_error(code: i32, msg: impl Into<Vec<u8>>) -> i32 {
    // `CString::new` only fails on an interior NUL; sanitize so an error message
    // is never lost to that.
    let bytes: Vec<u8> = msg.into().into_iter().filter(|&b| b != 0).collect();
    let c = CString::new(bytes).unwrap_or_default();
    LAST_ERROR.with(|cell| *cell.borrow_mut() = c);
    code
}

/// Clear this thread's last-error slot and return [`DS_NFT_OK`].
fn clear_error_ok() -> i32 {
    LAST_ERROR.with(|cell| *cell.borrow_mut() = CString::default());
    DS_NFT_OK
}

/// Borrow `name` as a `&str`, mapping NULL / non-UTF-8 to the arg-error code.
///
/// # Safety
/// `name` must be NULL or a valid pointer to a NUL-terminated C string that
/// stays live for the duration of the call (the cgo caller's contract).
unsafe fn str_arg<'a>(name: *const c_char) -> Result<&'a str, i32> {
    if name.is_null() {
        return Err(set_error(DS_NFT_ERR_ARG, "null pointer argument"));
    }
    // SAFETY: non-null per the guard; the caller guarantees NUL-termination and
    // that the buffer outlives this borrow.
    CStr::from_ptr(name)
        .to_str()
        .map_err(|_| set_error(DS_NFT_ERR_ARG, "argument is not valid UTF-8"))
}

/// Borrow an OPTIONAL C string arg as `Option<&str>`: NULL is a VALID input
/// mapping to `None` (NOT an arg error, unlike [`str_arg`]) — used for
/// `guest_mac`, where a NULL pointer means "MAC unknown" and the caller skips
/// the static-neigh leg. A non-NULL pointer is borrowed exactly as [`str_arg`]
/// does, so non-UTF-8 (or, downstream, an interior NUL) is still the arg error.
///
/// # Safety
/// `p` must be NULL or a valid pointer to a NUL-terminated C string that stays
/// live for the duration of the call (the cgo caller's contract).
unsafe fn opt_str_arg<'a>(p: *const c_char) -> Result<Option<&'a str>, i32> {
    if p.is_null() {
        return Ok(None);
    }
    str_arg(p).map(Some)
}

/// Map a backend `Result` to the FFI return convention, recording the message.
fn finish(result: Result<(), BackendError>) -> i32 {
    match result {
        Ok(()) => clear_error_ok(),
        Err(e) => set_error(DS_NFT_ERR_BACKEND, e.message),
    }
}

// ── Inner, backend-generic bodies ───────────────────────────────────────────
//
// The extern-C wrappers below construct a production `SpawnBackend` and call
// these; the unit test calls them with a `RecordingBackend` so the C surface is
// proven wired WITHOUT touching the kernel (no `ip`/`nft`/`conntrack` spawn).

/// Create the tap `name` owned by `owner_uid` (when `has_uid`) on `backend`, and
/// program its routed addressing (D2, doc 11 §2.4): the host-side gateway
/// `10.77.<host_session_index>.0/31` + on-link `/32` route to the guest `.1`,
/// plus — when `guest_mac` is `Some` — a static `ip neigh replace`. `guest_mac`
/// of `None` skips the neigh leg (a recoverable gap, never a failure).
fn create_tap_on<B: NftBackend>(
    backend: &B,
    name: &str,
    owner_uid: Option<u32>,
    host_session_index: u32,
    guest_mac: Option<String>,
) -> i32 {
    finish(backend.create_tap(&TapSpec {
        name: name.to_string(),
        owner_uid,
        host_session_index,
        guest_mac,
    }))
}

/// Delete the tap `name` on `backend`.
fn delete_tap_on<B: NftBackend>(backend: &B, name: &str) -> i32 {
    finish(backend.delete_tap(name))
}

/// Flush the whole session on `backend`: `flush_session(dst=All, legs=All)` —
/// the unconditional NFT-6 teardown flush (doc 15 §4.2). `tap_name` /
/// `host_session_index` identify the session; the other `SessionRef` fields are
/// not load-bearing for a mark-driven flush (the mark is composed from the
/// index + leg), so the FFI fills placeholders.
fn flush_session_on<B: NftBackend>(backend: &B, tap_name: &str, host_session_index: u32) -> i32 {
    let session = SessionRef::new(
        // session_uuid / host_id are not part of the mark the flush matches on;
        // a teardown flush narrows by (leg, host_session_index) only.
        String::new(),
        String::new(),
        host_session_index,
        tap_name.to_string(),
    );
    let writer = NftWriter::new(BackendRef(backend));
    match writer.flush_session(&session, &DstFilter::All, &LegSelector::All) {
        Ok(_outcome) => clear_error_ok(),
        Err(e) => set_error(DS_NFT_ERR_BACKEND, e.backend.message),
    }
}

/// The full per-session CREATE lifecycle on `backend` (NFT-5 wiring, D76):
/// [`NftWriter::create_session`] — the Model-A admit surface (the EMPTY
/// `allow4_<idx>` / `allow6_<idx>` sets in `inet ds_filter`) THEN the per-session
/// NFT-5 `ct mark` flow-tag stamp (on `inet ds_flowtag`), two atomic batches. So
/// an FFI-driven session gets the attribution stamp, not just the admit surface
/// (the frozen C ABI `ds_nft_instantiate_session` used to bypass the stamp). The
/// mark VALUE is sourced from `ds-contracts` inside `flowtag` — never re-authored
/// here. `tap_name` is accepted for symmetry but does not key the set name (the
/// index does, D4).
fn create_session_on<B: NftBackend>(backend: &B, _tap_name: &str, host_session_index: u32) -> i32 {
    let writer = NftWriter::new(BackendRef(backend));
    match writer.create_session(host_session_index) {
        Ok(()) => clear_error_ok(),
        Err(e) => set_error(DS_NFT_ERR_BACKEND, e.backend.message),
    }
}

/// The full per-session DESTROY lifecycle on `backend` (NFT-5 wiring, D76):
/// [`NftWriter::destroy_session`] — the Model-A admit-surface removal (`delete
/// set` both `allow{4,6}_<host_session_index>` in `inet ds_filter`) THEN the
/// NFT-5 flow-tag unstamp (an ensure-then-delete on `inet ds_flowtag`, idempotent
/// for a double-destroy). The conntrack-by-mark half of NFT-6 stays in
/// [`ds_nft_flush_session`].
fn destroy_session_on<B: NftBackend>(backend: &B, _tap_name: &str, host_session_index: u32) -> i32 {
    let writer = NftWriter::new(BackendRef(backend));
    match writer.destroy_session(host_session_index) {
        Ok(()) => clear_error_ok(),
        Err(e) => set_error(DS_NFT_ERR_BACKEND, e.backend.message),
    }
}

// ── The extern-C surface ────────────────────────────────────────────────────

/// Create the per-session tap netdev `name`, optionally owned by `owner_uid`,
/// AND program its routed addressing (D2, doc 11 §2.4).
///
/// `has_uid` is the C "option" flag: when non-zero, `owner_uid` is applied
/// (`ip tuntap add ... user <uid>`); when zero, `owner_uid` is ignored and the
/// tap is left owned by the creating context. `host_session_index` is the routed
/// `/31` authority — it lands in the third octet of the host-side gateway
/// `10.77.<host_session_index>.0/31` (the guest is `.1`). `guest_mac` is the
/// OPTIONAL static-neigh lladdr: a NULL pointer means the guest MAC is unknown,
/// so the `ip neigh replace` leg is SKIPPED (a recoverable gap, never a failure
/// — it can be programmed later); a non-NULL, malformed MAC surfaces as a
/// backend error straight from `ip neigh`. This programs the netdev + routed
/// addressing but still writes NO nft rules (the glob floor / Stage-3 own those).
/// Idempotent (re-create of a present tap is success).
///
/// Returns [`DS_NFT_OK`] (0) on success, [`DS_NFT_ERR_ARG`] for a bad `name`
/// pointer (or non-UTF-8 / interior-NUL `guest_mac`), or [`DS_NFT_ERR_BACKEND`]
/// for a backend failure (message via [`ds_nft_last_error`]).
///
/// # Safety
/// `name` must be a valid NUL-terminated C string pointer (or NULL, which is a
/// handled arg-error). `guest_mac` must be a valid NUL-terminated C string
/// pointer OR NULL (NULL is a VALID input → no static neigh). The Go cgo caller
/// owns both buffers for the call's duration.
#[no_mangle]
pub unsafe extern "C" fn ds_nft_create_tap(
    name: *const c_char,
    owner_uid: u32,
    has_uid: c_int,
    host_session_index: u32,
    guest_mac: *const c_char,
) -> i32 {
    let name = match str_arg(name) {
        Ok(s) => s,
        Err(code) => return code,
    };
    // NULL guest_mac is a VALID input (→ None → the static-neigh leg is skipped);
    // a non-NULL non-UTF-8 / interior-NUL MAC is an arg error, like `name`.
    let guest_mac = match opt_str_arg(guest_mac) {
        Ok(opt) => opt.map(str::to_owned),
        Err(code) => return code,
    };
    let uid = if has_uid != 0 { Some(owner_uid) } else { None };
    create_tap_on(
        &SpawnBackend::new(),
        name,
        uid,
        host_session_index,
        guest_mac,
    )
}

/// Delete the tap netdev `name`. Idempotent (delete of an absent tap is
/// success). Mechanism only.
///
/// Returns [`DS_NFT_OK`] (0) on success, [`DS_NFT_ERR_ARG`] for a bad pointer,
/// or [`DS_NFT_ERR_BACKEND`] for a backend failure.
///
/// # Safety
/// `name` must be a valid NUL-terminated C string pointer (or NULL).
#[no_mangle]
pub unsafe extern "C" fn ds_nft_delete_tap(name: *const c_char) -> i32 {
    let name = match str_arg(name) {
        Ok(s) => s,
        Err(code) => return code,
    };
    delete_tap_on(&SpawnBackend::new(), name)
}

/// Flush the whole session identified by `tap_name` / `host_session_index`:
/// `flush_session(dst=All, legs=All)` — the unconditional NFT-6 teardown flush
/// (doc 15 §4.2; doc 14 §5). Folds the flush-half FFI intent of task
/// `01KV481M7N`.
///
/// Returns [`DS_NFT_OK`] (0) on success, [`DS_NFT_ERR_ARG`] for a bad
/// `tap_name`, or [`DS_NFT_ERR_BACKEND`] for a backend failure.
///
/// # Safety
/// `tap_name` must be a valid NUL-terminated C string pointer (or NULL).
#[no_mangle]
pub unsafe extern "C" fn ds_nft_flush_session(
    tap_name: *const c_char,
    host_session_index: u32,
) -> i32 {
    let tap_name = match str_arg(tap_name) {
        Ok(s) => s,
        Err(code) => return code,
    };
    flush_session_on(&SpawnBackend::new(), tap_name, host_session_index)
}

/// `InstantiateSessionNFT` + the NFT-5 flow-tag stamp — the full per-session
/// CREATE lifecycle ([`NftWriter::create_session`], D76): create the EMPTY
/// per-session `allow4_<host_session_index>` / `allow6_<host_session_index>` sets
/// in the existing `inet ds_filter` table (the admit surface — the set NAME is
/// the single-source [`ds_contracts::session::allow_set_name`], so this side and
/// the ds-dnsgate fill side cannot diverge, session doc 11 §2.5 D3/D4), THEN
/// stamp the per-session composite `ct mark` on the `dstap-<idx>` tap (on the
/// separate `inet ds_flowtag` table) so the session's flows are attributable (doc
/// 14 §5). The admit surface still writes NO default-deny, NO redirect, NO session
/// chain (the `dstap-*` glob floor owns those; the NFT-3b OUTPUT chain is
/// Stage-3), and the stamp's mark VALUE is sourced from `ds-contracts` — never
/// re-authored at this edge. Both legs are idempotent (a re-create converges).
///
/// The exported symbol name/signature are FROZEN (the cgo edge); only the body
/// composes the stamp now (previously it programmed the admit surface alone,
/// leaving FFI-driven sessions unmarked — task `01KX57B9H7`).
///
/// Returns [`DS_NFT_OK`] (0) on success, [`DS_NFT_ERR_ARG`] for a bad `tap_name`,
/// or [`DS_NFT_ERR_BACKEND`] for a backend failure (message via
/// [`ds_nft_last_error`]).
///
/// # Safety
/// `tap_name` must be a valid NUL-terminated C string pointer (or NULL, which is
/// a handled arg-error).
#[no_mangle]
pub unsafe extern "C" fn ds_nft_instantiate_session(
    tap_name: *const c_char,
    host_session_index: u32,
) -> i32 {
    let tap_name = match str_arg(tap_name) {
        Ok(s) => s,
        Err(code) => return code,
    };
    create_session_on(&SpawnBackend::new(), tap_name, host_session_index)
}

/// The full per-session DESTROY lifecycle ([`NftWriter::destroy_session`], D76):
/// remove the per-session allow-sets created by [`ds_nft_instantiate_session`]
/// (`delete set` both `allow{4,6}_<host_session_index>` in `inet ds_filter` — the
/// named-set half of the NFT-6 teardown), THEN unstamp the NFT-5 flow tag (an
/// ensure-then-delete of the `dstap-<idx>` map element + `tag_<idx>` chain on
/// `inet ds_flowtag`, idempotent for a double-destroy). The conntrack-by-mark
/// half is [`ds_nft_flush_session`]; a full teardown calls flush THEN this.
///
/// The exported symbol name/signature are FROZEN (the cgo edge); only the body
/// composes the unstamp now (task `01KX57B9H7`).
///
/// Returns [`DS_NFT_OK`] (0) on success, [`DS_NFT_ERR_ARG`] for a bad `tap_name`,
/// or [`DS_NFT_ERR_BACKEND`] for a backend failure.
///
/// # Safety
/// `tap_name` must be a valid NUL-terminated C string pointer (or NULL).
#[no_mangle]
pub unsafe extern "C" fn ds_nft_teardown_session(
    tap_name: *const c_char,
    host_session_index: u32,
) -> i32 {
    let tap_name = match str_arg(tap_name) {
        Ok(s) => s,
        Err(code) => return code,
    };
    destroy_session_on(&SpawnBackend::new(), tap_name, host_session_index)
}

/// The message of the LAST error produced on the calling thread, as a borrowed,
/// NUL-terminated C string (empty after a successful call). The pointer is valid
/// until the next ds-nft FFI call ON THIS THREAD — the Go side must copy it
/// (e.g. `C.GoString`) before the next call. NEVER `free` it (ds-nft owns the
/// `CString`). Never returns NULL.
///
/// # Safety
/// The returned pointer is only valid until this thread's next ds-nft FFI call;
/// reading it after that is a use-after-free. Copy immediately.
#[no_mangle]
pub unsafe extern "C" fn ds_nft_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        let borrow = cell.borrow();
        // The CString lives in the thread-local; the pointer stays valid until
        // the slot is next replaced (the next FFI call on this thread).
        borrow.as_ptr()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::RecordingBackend;
    use std::ptr;

    /// Read this thread's last-error slot as a `String` (test helper; mirrors
    /// what the Go side does with `C.GoString(ds_nft_last_error())`).
    fn last_error() -> String {
        // SAFETY: single-threaded test; the pointer is read before any other
        // FFI call replaces the slot.
        let p = unsafe { ds_nft_last_error() };
        assert!(!p.is_null(), "ds_nft_last_error must never return NULL");
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    // The acceptance test: round-trip a real extern-C entry (`ds_nft_create_tap`
    // marshalling) through a RecordingBackend seam — proving the C surface is
    // wired end to end with NO kernel touch (no `ip`/`nft`/`conntrack` spawn).
    #[test]
    fn create_tap_round_trips_a_cstring_through_a_recording_backend() {
        let backend = RecordingBackend::new();
        let name = CString::new("dstap-7").unwrap();
        let mac = CString::new("52:54:00:12:34:07").unwrap();

        // Drive the SAME marshalling the extern-C symbol uses (NUL-terminated
        // C string → &str → TapSpec), but onto the recording seam — now also
        // threading host_session_index + a non-NULL guest_mac.
        // SAFETY: `name`/`mac` are valid, live NUL-terminated CStrings for the call.
        let s = unsafe { str_arg(name.as_ptr()) }.expect("valid utf-8 name");
        let m = unsafe { opt_str_arg(mac.as_ptr()) }.expect("valid utf-8 mac");
        let rc = create_tap_on(&backend, s, Some(1000), 7, m.map(str::to_owned));

        assert_eq!(rc, DS_NFT_OK);
        let taps = backend.taps();
        assert_eq!(taps.len(), 1);
        assert_eq!(taps[0].name, "dstap-7");
        assert_eq!(taps[0].owner_uid, Some(1000));
        // the routed-addressing fields thread through the C edge now.
        assert_eq!(taps[0].host_session_index, 7);
        assert_eq!(taps[0].guest_mac.as_deref(), Some("52:54:00:12:34:07"));
        // success clears the error slot.
        assert_eq!(last_error(), "");
    }

    #[test]
    fn create_tap_null_guest_mac_is_valid_and_skips_the_neigh_leg() {
        // A NULL guest_mac is a VALID input (the MAC is unknown) → None → the
        // backend's static-neigh leg is skipped. It is NOT an arg error (unlike
        // a NULL `name`), which `opt_str_arg` encodes.
        let backend = RecordingBackend::new();
        let name = CString::new("dstap-8").unwrap();
        // SAFETY: NULL is the explicitly-handled None branch of opt_str_arg.
        let m = unsafe { opt_str_arg(ptr::null()) }.expect("NULL mac is valid (None)");
        assert!(m.is_none(), "NULL guest_mac maps to None, not an error");
        // SAFETY: live NUL-terminated CString.
        let s = unsafe { str_arg(name.as_ptr()) }.expect("valid utf-8 name");
        let rc = create_tap_on(&backend, s, None, 8, m.map(str::to_owned));

        assert_eq!(rc, DS_NFT_OK);
        let taps = backend.taps();
        assert_eq!(taps.len(), 1);
        assert_eq!(taps[0].host_session_index, 8);
        assert_eq!(taps[0].guest_mac, None);
        assert_eq!(last_error(), "");
    }

    #[test]
    fn create_tap_non_utf8_guest_mac_is_an_arg_error() {
        // A non-NULL guest_mac is borrowed exactly as `name` is, so non-UTF-8
        // bytes are the arg error (DS_NFT_ERR_ARG) — NULL is the only special
        // case for the MAC, not "any bad pointer".
        let bad = [0xffu8, 0xfe, 0x00]; // invalid UTF-8, NUL-terminated
                                        // SAFETY: a valid NUL-terminated buffer that is not valid UTF-8.
        let r = unsafe { opt_str_arg(bad.as_ptr() as *const c_char) };
        assert_eq!(r.unwrap_err(), DS_NFT_ERR_ARG);
        assert!(last_error().contains("not valid UTF-8"));
    }

    #[test]
    fn flush_session_round_trips_through_a_recording_backend() {
        let backend = RecordingBackend::new();
        let tap = CString::new("dstap-42").unwrap();
        // SAFETY: live NUL-terminated CString.
        let s = unsafe { str_arg(tap.as_ptr()) }.expect("valid name");
        let rc = flush_session_on(&backend, s, 42);

        assert_eq!(rc, DS_NFT_OK);
        // teardown spans every leg → one conntrack destroy per leg, dst=All.
        let destroys = backend.destroys();
        assert_eq!(destroys.len(), crate::flush::ALL_LEGS.len());
        for d in &destroys {
            assert!(d.dst.is_none(), "teardown flush narrows on no dst");
        }
        assert_eq!(last_error(), "");
    }

    #[test]
    fn delete_tap_round_trips_through_a_recording_backend() {
        let backend = RecordingBackend::new();
        let name = CString::new("dstap-3").unwrap();
        // SAFETY: live NUL-terminated CString.
        let s = unsafe { str_arg(name.as_ptr()) }.expect("valid name");
        let rc = delete_tap_on(&backend, s);

        assert_eq!(rc, DS_NFT_OK);
        assert_eq!(backend.deleted_taps(), vec!["dstap-3".to_string()]);
    }

    #[test]
    fn null_argument_is_an_arg_error_with_a_message() {
        // SAFETY: NULL is the explicitly-handled branch of str_arg.
        let r = unsafe { str_arg(ptr::null()) };
        assert_eq!(r.unwrap_err(), DS_NFT_ERR_ARG);
        assert!(last_error().contains("null pointer"));
    }

    #[test]
    fn backend_error_maps_to_the_backend_code_and_records_the_message() {
        let backend = RecordingBackend::new();
        backend.arm_error(BackendError::new("EPERM: CAP_NET_ADMIN missing"));
        let rc = create_tap_on(&backend, "dstap-1", None, 1, None);
        assert_eq!(rc, DS_NFT_ERR_BACKEND);
        assert!(last_error().contains("EPERM"));
        // the armed error was one-shot; the next call succeeds and clears it.
        let rc2 = create_tap_on(&backend, "dstap-1", None, 1, None);
        assert_eq!(rc2, DS_NFT_OK);
        assert_eq!(last_error(), "");
    }

    #[test]
    fn the_extern_c_surface_is_addressable_including_instantiate_teardown() {
        // Compile-time guard against drift: every shipped symbol — now INCLUDING
        // the Model A `ds_nft_instantiate_session` / `ds_nft_teardown_session`
        // (D1/D3/D4 ratified) — is addressable with its declared signature. The
        // header `include/ds_nft.h` must stay in lockstep with these.
        let _create: unsafe extern "C" fn(*const c_char, u32, c_int, u32, *const c_char) -> i32 =
            ds_nft_create_tap;
        let _delete: unsafe extern "C" fn(*const c_char) -> i32 = ds_nft_delete_tap;
        let _flush: unsafe extern "C" fn(*const c_char, u32) -> i32 = ds_nft_flush_session;
        let _instantiate: unsafe extern "C" fn(*const c_char, u32) -> i32 =
            ds_nft_instantiate_session;
        let _teardown: unsafe extern "C" fn(*const c_char, u32) -> i32 = ds_nft_teardown_session;
        let _last: unsafe extern "C" fn() -> *const c_char = ds_nft_last_error;
    }

    /// The handwritten C header `include/ds_nft.h` (the cgo `#include` the Go host
    /// agent links through). `include_str!` is relative to THIS source file, so the
    /// guard is hermetic — no runtime file IO, no CWD dependence — and the test
    /// won't even COMPILE if the header is moved or deleted.
    const DS_NFT_HEADER: &str = include_str!("../include/ds_nft.h");

    #[test]
    fn header_declares_every_extern_c_symbol_and_return_code() {
        // Drift guard (doc 13 OQ2 / doc 15 OQ3): the handwritten `include/ds_nft.h`
        // and the `#[no_mangle] extern "C"` surface here MUST stay in lockstep. The
        // sibling `the_extern_c_surface_is_addressable_*` test pins the Rust-side
        // signatures; THIS test pins the header — every shipped symbol name and
        // every return-code `#define` must appear in `ds_nft.h`, so adding /
        // renaming a symbol or changing a return code without updating the header
        // FAILS the build instead of silently breaking the cgo edge. (It does not —
        // and cannot, from pure text — re-prove the C argument types; the Rust-side
        // addressability guard owns the signatures.)
        for symbol in [
            "ds_nft_create_tap",
            "ds_nft_delete_tap",
            "ds_nft_flush_session",
            "ds_nft_instantiate_session",
            "ds_nft_teardown_session",
            "ds_nft_last_error",
        ] {
            assert!(
                DS_NFT_HEADER.contains(symbol),
                "ds_nft.h must declare extern-C symbol `{symbol}` (header<->ffi.rs drift)"
            );
        }

        // Collapse runs of ASCII whitespace to a single space (and trim ends) so
        // the `#define` match below survives a benign reformat of `ds_nft.h` —
        // e.g. `#define  DS_NFT_OK   0`, a tab-aligned column, or a param-wrap
        // that re-spaces the line. Comparing on the normalized form keeps this a
        // name+value drift guard (the only thing it can prove from text) without
        // pinning the header's incidental whitespace.
        fn collapse_ws(s: &str) -> String {
            s.split_whitespace().collect::<Vec<_>>().join(" ")
        }

        // The three return-code `#define`s must mirror the Rust constants by name
        // AND value, so the Go side reads the same convention off the header that
        // ffi.rs returns.
        for (define, value) in [
            ("DS_NFT_OK", DS_NFT_OK),
            ("DS_NFT_ERR_ARG", DS_NFT_ERR_ARG),
            ("DS_NFT_ERR_BACKEND", DS_NFT_ERR_BACKEND),
        ] {
            // The macro name is present …
            assert!(
                DS_NFT_HEADER.contains(define),
                "ds_nft.h must `#define {define}` (return-code drift)"
            );
            // … and so is its exact value, either bare (`0`) or parenthesized
            // (`(-1)`), as the header writes negatives. Match `#define <name> <val>`
            // on the whitespace-normalized line that defines it, so the guard
            // tolerates a benign re-spacing of the header.
            let prefix = format!("#define {define} ");
            let line = DS_NFT_HEADER
                .lines()
                .map(collapse_ws)
                .find(|l| l.starts_with(&prefix))
                .unwrap_or_else(|| panic!("ds_nft.h must have a `#define {define} <value>` line"));
            let bare = value.to_string();
            let parenthesized = format!("({value})");
            assert!(
                line.contains(&bare) || line.contains(&parenthesized),
                "ds_nft.h `#define {define}` must carry value {value}: got `{line}`"
            );
        }
    }

    /// The known-good C parameter-type list for every shipped extern-C symbol,
    /// `(symbol, &[param_type, ...])`, where each entry is the normalized C TYPE
    /// spelling the header `ds_nft.h` uses (parameter NAMES are stripped before
    /// comparison, so renaming a header param is benign — only the type+arity
    /// drift). This is the single source of truth the `header_pins_*` drift test
    /// below compares the header against; it MUST stay in lockstep, type-for-type,
    /// with the Rust extern-fn pointer types pinned in
    /// `the_extern_c_surface_is_addressable_including_instantiate_teardown`
    /// (above), which owns the Rust side. The two guards together close the gap
    /// the `header_declares_*` (names+return-codes) test cannot reach: cgo reads
    /// the header's PROTOTYPE, not the Rust signature, so a header that drops the
    /// `int has_uid` param or flips a `uint32_t` to `int32_t` would otherwise slip
    /// past both. Mapping (header C type <-> Rust extern type):
    ///   `const char *` <-> `*const c_char`,  `uint32_t` <-> `u32`,
    ///   `int`          <-> `c_int`.
    const EXTERN_C_SIGNATURES: &[(&str, &[&str])] = &[
        // ds_nft_create_tap(name, owner_uid, has_uid, host_session_index, guest_mac)
        // Rust: (*const c_char, u32, c_int, u32, *const c_char) -> i32
        (
            "ds_nft_create_tap",
            &[
                "const char *",
                "uint32_t",
                "int",
                "uint32_t",
                "const char *",
            ],
        ),
        // Rust: (*const c_char) -> i32
        ("ds_nft_delete_tap", &["const char *"]),
        // Rust: (*const c_char, u32) -> i32
        ("ds_nft_flush_session", &["const char *", "uint32_t"]),
        // Rust: (*const c_char, u32) -> i32
        ("ds_nft_instantiate_session", &["const char *", "uint32_t"]),
        // Rust: (*const c_char, u32) -> i32
        ("ds_nft_teardown_session", &["const char *", "uint32_t"]),
        // Rust: () -> *const c_char ; the header writes the explicit `(void)`.
        ("ds_nft_last_error", &[]),
    ];

    /// Extract the parenthesized parameter list of `symbol`'s prototype from the
    /// real header (`DS_NFT_HEADER`), returning the normalized C TYPE of each
    /// parameter in order (names stripped). `None` if the prototype line is
    /// absent. An empty `Vec` means an explicit `(void)` / `()` zero-arg
    /// prototype. Thin wrapper over `header_param_types_in` so the drift guard
    /// and its negative tests parse through the SAME code path (they cannot
    /// themselves drift).
    fn header_param_types(symbol: &str) -> Option<Vec<String>> {
        header_param_types_in(DS_NFT_HEADER, symbol)
    }

    /// Shave the parameter NAME off a normalized `"<type> <name>"` C parameter,
    /// keeping the canonical type spelling (pointer stars included).
    /// Examples: `const char *name` -> `const char *`,
    /// `uint32_t owner_uid` -> `uint32_t`, `int has_uid` -> `int`.
    fn strip_param_name(param: &str) -> String {
        // The name is the trailing identifier; split it off the last token.
        // Find the last token boundary. The last token is either `*name`, `name`,
        // or `name` after a `*` token.
        let bytes = param;
        // Walk back over trailing identifier chars [A-Za-z0-9_].
        let trimmed = bytes.trim_end();
        let name_start = trimmed
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map(|i| i + 1)
            .unwrap_or(0);
        let (type_part, _name) = trimmed.split_at(name_start);
        // `type_part` may end with `*` and/or spaces (e.g. `const char *`).
        // Re-canonicalize: keep a single trailing ` *` form when a star is present
        // so `const char *name` and `const char* name` both yield `const char *`.
        let type_part = type_part.trim_end();
        if let Some(stars_start) = type_part.rfind(|c: char| c != '*') {
            // there is non-star content
            let (base, stars) = type_part.split_at(stars_start + 1);
            let base = base.trim_end();
            if stars.is_empty() {
                base.to_string()
            } else {
                format!("{base} {stars}")
            }
        } else {
            // all stars (degenerate) — return as-is.
            type_part.to_string()
        }
    }

    #[test]
    fn header_pins_extern_c_param_types_and_arity() {
        // Drift guard (doc 13 OQ2 / doc 15 OQ3), the ARGUMENT-TYPE + ARITY half the
        // sibling `header_declares_every_extern_c_symbol_and_return_code` test
        // explicitly does NOT cover (and cannot, since it only proves symbol NAMES
        // and return-code `#define`s are present). cgo links against the header's
        // PROTOTYPE, not the Rust signature, so a header that drops a param or
        // flips a `uint32_t` to `int32_t` would compile a mismatched call edge.
        // Here we parse each prototype's parameter TYPES out of `ds_nft.h` and
        // assert they equal the known-good `EXTERN_C_SIGNATURES` table (single-
        // sourced with the Rust-side addressability guard via the cross-reference
        // on that const), arity included.
        for (symbol, expected) in EXTERN_C_SIGNATURES {
            let got = header_param_types(symbol)
                .unwrap_or_else(|| panic!("ds_nft.h must declare a prototype for `{symbol}`"));

            // ARITY first, with a symbol-naming message, so a dropped/added param
            // fails loudly and unambiguously.
            assert_eq!(
                got.len(),
                expected.len(),
                "ds_nft.h prototype for `{symbol}` has arity {} but the C ABI \
                 takes {} parameter(s) (header<->ffi.rs param-arity drift); \
                 got types {got:?}, expected {expected:?}",
                got.len(),
                expected.len(),
            );

            // Then each parameter TYPE in order.
            for (i, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
                assert_eq!(
                    g, e,
                    "ds_nft.h prototype for `{symbol}` parameter #{i} has C type \
                     `{g}` but the ABI is `{e}` (header<->ffi.rs param-type drift)"
                );
            }
        }
    }

    #[test]
    fn param_name_stripping_is_canonical() {
        // Lock the header-prototype normalizer the drift guard relies on, so a
        // refactor of `strip_param_name` can't silently weaken the test above.
        assert_eq!(strip_param_name("const char *name"), "const char *");
        assert_eq!(strip_param_name("const char* name"), "const char *");
        assert_eq!(strip_param_name("uint32_t owner_uid"), "uint32_t");
        assert_eq!(strip_param_name("int has_uid"), "int");
        assert_eq!(strip_param_name("uint32_t host_session_index"), "uint32_t");
    }

    /// Parse `symbol`'s prototype parameter TYPES (names stripped, in order) out
    /// of an arbitrary header string. This is the SINGLE parser the drift guard
    /// (`header_param_types` wraps it with `DS_NFT_HEADER`) and the negative tests
    /// (which pass a deliberately-mutated in-memory copy of the header — no file
    /// IO) both route through, so the guard and its self-tests cannot diverge.
    /// `None` if no single-line `);` prototype for `symbol` is present; an empty
    /// `Vec` is an explicit `(void)` / `()` zero-arg prototype.
    ///
    /// Pure-text + stdlib only (no cbindgen), matching the crate's existing
    /// header-drift approach.
    fn header_param_types_in(header: &str, symbol: &str) -> Option<Vec<String>> {
        // Select the DECLARATION line, not any prose that mentions the symbol.
        // The header keeps every prototype on a single canonical line that ends
        // in `);` (the prototype-drift contract documented in ds_nft.h), while a
        // doc comment mentioning e.g. `ds_nft_last_error()` ends in prose (`.`).
        // Keying on BOTH `<symbol>(` AND a trailing `);` picks the prototype and
        // never a comment — without this, `ds_nft_last_error`'s parse would land
        // on its doc-comment line above the real `(void)` prototype (a false
        // negative that would let a drifted `ds_nft_last_error(int)` slip past).
        let needle = format!("{symbol}(");
        let line = header
            .lines()
            .find(|l| l.contains(&needle) && l.trim_end().ends_with(");"))?;
        let open = line.find('(')?;
        let close = line[open..].find(')')? + open;
        let inside = line[open + 1..close].trim();
        let normalize = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let inner = normalize(inside);
        if inner.is_empty() || inner == "void" {
            return Some(Vec::new());
        }
        Some(
            inner
                .split(',')
                .map(|p| strip_param_name(&normalize(p)))
                .collect(),
        )
    }

    #[test]
    fn drift_guard_catches_a_flipped_param_type() {
        // Flip ds_nft_create_tap's `uint32_t owner_uid` to a signed `int32_t` —
        // a real cgo-edge ABI hazard the names-only guard would miss.
        let mutated = DS_NFT_HEADER.replace(
            "int32_t ds_nft_create_tap(const char *name, uint32_t owner_uid,",
            "int32_t ds_nft_create_tap(const char *name, int32_t owner_uid,",
        );
        assert_ne!(mutated, DS_NFT_HEADER, "the mutation must actually apply");
        let got = header_param_types_in(&mutated, "ds_nft_create_tap").unwrap();
        let expected: Vec<&str> = EXTERN_C_SIGNATURES
            .iter()
            .find(|(s, _)| *s == "ds_nft_create_tap")
            .map(|(_, p)| p.to_vec())
            .unwrap();
        // arity unchanged …
        assert_eq!(got.len(), expected.len());
        // … but the parameter type now diverges → the guard's type assertion fires.
        assert_ne!(
            got, expected,
            "a flipped uint32_t->int32_t param must be detectable"
        );
        assert_eq!(got[1], "int32_t");
    }

    #[test]
    fn drift_guard_catches_a_dropped_param_arity() {
        // Drop ds_nft_create_tap's `int has_uid` param entirely — an arity drift
        // that the names-only guard would also miss.
        let mutated = DS_NFT_HEADER.replace(
            "uint32_t owner_uid, int has_uid, uint32_t host_session_index,",
            "uint32_t owner_uid, uint32_t host_session_index,",
        );
        assert_ne!(mutated, DS_NFT_HEADER, "the mutation must actually apply");
        let got = header_param_types_in(&mutated, "ds_nft_create_tap").unwrap();
        let expected_len = EXTERN_C_SIGNATURES
            .iter()
            .find(|(s, _)| *s == "ds_nft_create_tap")
            .map(|(_, p)| p.len())
            .unwrap();
        assert_ne!(
            got.len(),
            expected_len,
            "a dropped param must change the parsed arity"
        );
        assert_eq!(got.len(), expected_len - 1);
    }

    #[test]
    fn drift_guard_parses_the_prototype_not_a_prose_comment() {
        // `ds_nft_last_error` is mentioned in a doc comment (`... which
        // ds_nft_last_error() yields the message.`) ABOVE its real `(void)`
        // prototype. Selecting the first line that merely CONTAINS `<symbol>(`
        // would parse that comment — a `(void)`-equivalent that masks any drift on
        // the real declaration. Prove the guard now lands on the `);` prototype:
        // drifting the REAL `ds_nft_last_error(void)` to take a param is CAUGHT.
        //
        // Baseline: the unmutated header parses the real zero-arg prototype.
        assert_eq!(
            header_param_types("ds_nft_last_error"),
            Some(Vec::new()),
            "the real ds_nft_last_error prototype is zero-arg (void)"
        );
        // Drift the REAL prototype line only (the `);`-terminated one); the prose
        // comment `ds_nft_last_error()` above it is left untouched.
        let mutated = DS_NFT_HEADER.replace(
            "const char *ds_nft_last_error(void);",
            "const char *ds_nft_last_error(int bogus);",
        );
        assert_ne!(mutated, DS_NFT_HEADER, "the mutation must actually apply");
        let got = header_param_types_in(&mutated, "ds_nft_last_error")
            .expect("prototype line must still be found");
        assert_eq!(
            got,
            vec!["int".to_string()],
            "the drifted `(int bogus)` prototype must be parsed, not the `()` comment"
        );
    }

    #[test]
    fn ffi_instantiate_session_composes_admit_surface_and_nft5_stamp() {
        // The FFI CREATE path drives the full per-session lifecycle
        // (create_session, D76): the Model-A admit surface AND the NFT-5 flow-tag
        // stamp — proving the frozen `ds_nft_instantiate_session` no longer leaves
        // FFI-driven sessions unmarked (task 01KX57B9H7). Two atomic batches: the
        // allow-sets on `inet ds_filter`, then the stamp on `inet ds_flowtag`,
        // NEVER mixed. NO kernel touch (RecordingBackend seam).
        let backend = RecordingBackend::new();
        let tap = CString::new("dstap-7").unwrap();
        // SAFETY: live NUL-terminated CString.
        let s = unsafe { str_arg(tap.as_ptr()) }.expect("valid name");
        let rc = create_session_on(&backend, s, 7);

        assert_eq!(rc, DS_NFT_OK);
        let batches = backend.batches();
        assert_eq!(
            batches.len(),
            2,
            "two atomic batches: admit-surface allow-sets THEN the NFT-5 stamp"
        );

        // Batch 0 — the Model-A admit surface: ensure `inet ds_filter` then the two
        // EMPTY per-session sets, and NOTHING from the floor. The admit-surface leg
        // stays pure (the ct-mark stamp is the SEPARATE ds_flowtag batch).
        let admit = &batches[0].text;
        assert!(admit.contains("add table inet ds_filter"));
        assert!(
            admit.contains("add set inet ds_filter allow4_7 { type ipv4_addr; flags timeout; }")
        );
        assert!(
            admit.contains("add set inet ds_filter allow6_7 { type ipv6_addr; flags timeout; }")
        );
        assert!(!admit.contains("ds_flowtag"), "admit leg is Model-A pure");
        assert!(!admit.contains("ct mark"));
        assert!(!admit.contains("redirect"));
        assert!(!admit.contains("drop"));

        // Batch 1 — the NFT-5 flow-tag stamp on the SEPARATE ds_flowtag table: the
        // tap keyed to its per-session stamp chain via the masked ct-mark write. The
        // mark VALUE comes from ds-contracts (composed inside flowtag), never
        // re-hardcoded here.
        let stamp = &batches[1].text;
        assert!(stamp.contains("add table inet ds_flowtag"));
        assert!(stamp.contains("add chain inet ds_flowtag tag_7"));
        assert!(stamp.contains("ct mark set ct mark &"));
        assert!(stamp.contains("\"dstap-7\" : jump tag_7"));
        // no conntrack destroy issued by create (that is the flush half).
        assert!(backend.destroys().is_empty());
        assert_eq!(last_error(), "");
    }

    #[test]
    fn ffi_teardown_session_composes_admit_removal_and_nft5_unstamp() {
        // The FFI DESTROY path drives the full per-session lifecycle
        // (destroy_session, D76): the Model-A admit-surface removal AND the NFT-5
        // flow-tag unstamp. Two atomic batches: the `delete set`s on `inet
        // ds_filter`, then the ensure-then-delete unstamp on `inet ds_flowtag`.
        let backend = RecordingBackend::new();
        let tap = CString::new("dstap-42").unwrap();
        // SAFETY: live NUL-terminated CString.
        let s = unsafe { str_arg(tap.as_ptr()) }.expect("valid name");
        let rc = destroy_session_on(&backend, s, 42);

        assert_eq!(rc, DS_NFT_OK);
        let batches = backend.batches();
        assert_eq!(
            batches.len(),
            2,
            "two atomic batches: admit-surface removal THEN the NFT-5 unstamp"
        );

        // Batch 0 — the named-set half of the NFT-6 teardown.
        let admit = &batches[0].text;
        assert!(admit.contains("delete set inet ds_filter allow4_42"));
        assert!(admit.contains("delete set inet ds_filter allow6_42"));
        assert!(!admit.contains("ds_flowtag"), "admit leg is Model-A pure");

        // Batch 1 — the NFT-5 unstamp: remove the map element + stamp chain. Name-
        // only, so the composed mark value is never re-rendered on teardown.
        let unstamp = &batches[1].text;
        assert!(unstamp.contains("delete element inet ds_flowtag session_tag { \"dstap-42\" }"));
        assert!(unstamp.contains("delete chain inet ds_flowtag tag_42"));
        assert!(!unstamp.contains("ct mark set"));
        assert_eq!(last_error(), "");
    }

    #[test]
    fn create_session_backend_error_maps_to_the_backend_code() {
        // The armed error is one-shot and the admit-surface leg runs first, so a
        // create fails on the FIRST (allow-sets) batch and never reaches the stamp.
        let backend = RecordingBackend::new();
        backend.arm_error(BackendError::new("EPERM: CAP_NET_ADMIN missing"));
        let rc = create_session_on(&backend, "dstap-1", 1);
        assert_eq!(rc, DS_NFT_ERR_BACKEND);
        assert!(last_error().contains("EPERM"));
    }
}
