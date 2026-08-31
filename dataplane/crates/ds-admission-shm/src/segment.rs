//! The mmap backing — a named POSIX shm region (production survivability) or an
//! anonymous region (tests/bench). The mapping itself is owned by [`memmap2`]
//! ([`Mmap`]/[`MmapMut`]), which handles `munmap` on `Drop`; the named fd is owned
//! by a [`std::fs::File`], which `close`s on `Drop`. The remaining `unsafe` here is
//! confined to (a) the POSIX-shm FFI that memmap2 does not provide (`shm_open` /
//! `ftruncate` / `shm_unlink`) and (b) the `map_mut` mapping constructor (mapping an
//! fd whose bytes another process may mutate is `unsafe` by memmap2's contract). The
//! rest of the crate sees a base pointer + length and computes offsets.
//!
//! # Safety invariants (this module)
//! - [`SharedBase`] wraps the mapping base pointer. The pointer is valid for `len`
//!   bytes for the lifetime of the owning [`Segment`] (the [`Mmap`]/[`MmapMut`] it is
//!   derived from is owned by the `Segment` and only unmapped in the `Segment`'s
//!   `Drop`). Multiple handles over ONE `Segment` share the base pointer (the
//!   `Segment` is `Arc`-wrapped); cross-handle synchronization of the *contents* is
//!   the seqlock's job, not the pointer's.
//! - The mapping may be written by another process (the writer), so every read of
//!   the contents is a relaxed/acquire atomic or a fenced `copy_nonoverlapping`
//!   (see [`crate::seqlock`]) — never a plain `&T` deref that the compiler could
//!   assume is stable.
//! - The read-only reader path maps `PROT_READ` (`map`); its base is stored as
//!   `*mut u8` in [`SharedBase`] for one shared shape, but the reader never writes
//!   through it (it only does seqlock reads), and the kernel `PROT_READ` mapping
//!   would fault any write regardless.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::sync::Arc;

use memmap2::{Mmap, MmapMut, MmapOptions};

/// A raw shared-mapping base pointer that is `Send + Sync`.
///
/// # Why this is sound
/// The pointer addresses a shared mapping. `Send`/`Sync` here assert only that the
/// *pointer value* may move and be read across threads — they do NOT assert that the
/// *bytes* are race-free. The bytes are made race-free by the per-entry seqlock
/// discipline ([`crate::seqlock`]): every content access goes through atomics +
/// fences, so a reader on one thread and the writer on another never form a data race
/// in the C/C++/Rust memory-model sense. A bare `*mut u8` is `!Send + !Sync` only
/// because the compiler cannot see that discipline; this newtype is the place we take
/// responsibility for it.
#[derive(Clone, Copy)]
pub struct SharedBase {
    ptr: *mut u8,
}

// SAFETY: see the type doc. The pointer is to a shared mapping; all content access is
// through the seqlock's atomics+fences, so sharing the pointer across threads
// introduces no UB beyond what the seqlock already governs.
unsafe impl Send for SharedBase {}
// SAFETY: as above.
unsafe impl Sync for SharedBase {}

impl SharedBase {
    /// The raw base pointer.
    #[inline]
    pub fn as_ptr(self) -> *mut u8 {
        self.ptr
    }

    /// A pointer to byte offset `off` within the mapping.
    ///
    /// # Safety
    /// `off` must be within the mapping length (callers compute offsets from the
    /// header's validated `slot_count`/`stride`, all `< len`).
    #[inline]
    pub unsafe fn at(self, off: usize) -> *mut u8 {
        self.ptr.add(off)
    }
}

/// The owned mapping. memmap2 `munmap`s on `Drop`. The writer maps RW (`MmapMut`);
/// the read-only reader maps `PROT_READ` (`Mmap`).
#[allow(
    dead_code,
    reason = "each variant's payload is held purely for its Drop (RAII munmap); the \
              bytes are reached through the `SharedBase` raw pointer, never this enum"
)]
enum Mapping {
    /// `PROT_READ|PROT_WRITE`, `MAP_SHARED` (named) or `MAP_PRIVATE|MAP_ANON` (anon).
    Writable(MmapMut),
    /// `PROT_READ`, `MAP_SHARED` — the ds-tlsproxy reader path.
    ReadOnly(Mmap),
}

/// An mmap'd shared region. The base pointer is shared (`Arc`-wrapped) so reader and
/// writer handles over the SAME mapping hold the same base — the anonymous backing
/// then exercises the real cross-process code paths via threads.
///
/// The `Segment` OWNS the mapping (`_mapping`) and, for a named segment, the shm fd
/// (`_file`). Both are dropped (unmap, then close) when the last `Arc<Segment>` goes
/// away, so every derived pointer ([`SharedBase`]) outlives no longer than the
/// mapping. The named object is NOT `shm_unlink`'d on `Drop` (survivability).
pub struct Segment {
    base: SharedBase,
    // Field drop order is declaration order: unmap (`_mapping`) before the fd closes
    // (`_file`). Both are `_`-prefixed: held purely for their `Drop` (RAII), never read.
    // The mapping length is no longer stored — memmap2 owns the `munmap` (and its own
    // recorded length); only the base pointer is exposed (via `base()`).
    _mapping: Mapping,
    _file: Option<File>,
}

// SAFETY: `Segment` owns a `SharedBase` (Send+Sync by construction above) plus a
// length / owned `Mmap`+`File` that are plain owned data; nothing in `Segment` is
// thread-affine. Shared access to the mapping is governed by the seqlock.
unsafe impl Send for Segment {}
// SAFETY: as above.
unsafe impl Sync for Segment {}

impl Segment {
    /// The shared base pointer.
    #[inline]
    pub fn base(&self) -> SharedBase {
        self.base
    }

    /// Create (or truncate-and-recreate) a named POSIX shm segment of `len` bytes,
    /// mapped `PROT_READ|PROT_WRITE`, `MAP_SHARED`. This is the writer-create path.
    ///
    /// `name` is a POSIX shm name (must start with `/`, e.g. `/ds-admission-…`).
    /// The object is created with `O_CREAT` and `ftruncate`d to `len`. The segment
    /// is NOT unlinked on Drop (survivability — call [`Segment::unlink_name`] to
    /// remove it).
    pub fn create_named(name: &str, len: usize) -> io::Result<Arc<Segment>> {
        let cname = shm_cname(name)?;
        // O_CREAT|O_RDWR; 0600 perms. Not O_EXCL — create-or-open-and-resize.
        // SAFETY: standard FFI; `cname` is a valid NUL-terminated string.
        let fd = unsafe {
            libc::shm_open(
                cname.as_ptr(),
                libc::O_CREAT | libc::O_RDWR,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Take ownership of the fd immediately: `File`'s `Drop` now `close`s it on
        // EVERY path below (the old hand-rolled error legs leaked it on some).
        // SAFETY: `fd` was just returned by `shm_open` (>= 0), is open, and is owned
        // by nothing else — exactly `File::from_raw_fd`'s contract.
        let file = unsafe { File::from_raw_fd(fd) };
        // SAFETY: ftruncate on the just-opened fd.
        if unsafe { libc::ftruncate(fd, len as libc::off_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Self::from_named_file(file, len, /*write=*/ true)
    }

    /// Re-open an EXISTING named segment `PROT_READ|PROT_WRITE` (the warm-restart
    /// writer path). Fails if the object does not exist or is smaller than `len`.
    pub fn attach_named_writer(name: &str, len: usize) -> io::Result<Arc<Segment>> {
        Self::open_named(name, len, /*write=*/ true)
    }

    /// Open an EXISTING named segment `PROT_READ` only (the ds-tlsproxy reader
    /// path). The reader can never write the mapping (kernel-enforced).
    pub fn attach_named_reader(name: &str, len: usize) -> io::Result<Arc<Segment>> {
        Self::open_named(name, len, /*write=*/ false)
    }

    fn open_named(name: &str, len: usize, write: bool) -> io::Result<Arc<Segment>> {
        let cname = shm_cname(name)?;
        let oflag = if write { libc::O_RDWR } else { libc::O_RDONLY };
        // SAFETY: standard FFI; no O_CREAT — must already exist.
        let fd = unsafe { libc::shm_open(cname.as_ptr(), oflag, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by `shm_open` (>= 0), is open, and is owned
        // by nothing else — `File`'s `Drop` closes it on every path below.
        let file = unsafe { File::from_raw_fd(fd) };
        Self::from_named_file(file, len, write)
    }

    /// Map an owned shm `File` and build the `Segment`. The `File` is owned by the
    /// `Segment` so the fd outlives the mapping and is `close`d on `Drop`. On a
    /// mapping failure the `File` is dropped here (fd closed) — no leak.
    fn from_named_file(file: File, len: usize, write: bool) -> io::Result<Arc<Segment>> {
        if write {
            // SAFETY: `file` is an open shm fd `ftruncate`d to (or pre-sized ≥) `len`.
            // Mapping a file whose bytes another process may concurrently mutate is
            // `unsafe` by memmap2's contract; that concurrency is exactly the
            // cross-process writer/reader model this crate exists for, and every
            // content access goes through the seqlock (atomics + fences), never a
            // plain `&[u8]` over the entry table.
            let mmap = unsafe { MmapOptions::new().len(len).map_mut(&file)? };
            let ptr = mmap.as_ptr() as *mut u8;
            Ok(Arc::new(Segment {
                base: SharedBase { ptr },
                _mapping: Mapping::Writable(mmap),
                _file: Some(file),
            }))
        } else {
            // SAFETY: as above, but `PROT_READ`; the reader never writes the mapping.
            let mmap = unsafe { MmapOptions::new().len(len).map(&file)? };
            let ptr = mmap.as_ptr() as *mut u8;
            Ok(Arc::new(Segment {
                base: SharedBase { ptr },
                _mapping: Mapping::ReadOnly(mmap),
                _file: Some(file),
            }))
        }
    }

    /// Create an anonymous segment of `len` bytes for tests/bench. One mapping; clone
    /// the returned `Arc` to share the base across threads (exercises the real
    /// cross-process seqlock paths). No fd, no name.
    ///
    /// The mapping is `MAP_PRIVATE|MAP_ANON` (memmap2's anonymous map). Because the
    /// tests share the SINGLE mapping by `Arc`-cloning the `Segment` (never `fork()`
    /// nor a second `mmap` of the same object), `MAP_PRIVATE` is observationally
    /// identical to `MAP_SHARED` here: every thread reads and writes the same pages
    /// through the same base pointer.
    pub fn create_anonymous(len: usize) -> io::Result<Arc<Segment>> {
        let mmap = MmapOptions::new().len(len).map_anon()?;
        let ptr = mmap.as_ptr() as *mut u8;
        Ok(Arc::new(Segment {
            base: SharedBase { ptr },
            _mapping: Mapping::Writable(mmap),
            _file: None,
        }))
    }

    /// Unlink the named shm object (does NOT unmap an existing mapping — survivors
    /// keep working until they `munmap`). A no-op for an anonymous segment.
    pub fn unlink_name(name: &str) -> io::Result<()> {
        let cname = shm_cname(name)?;
        // SAFETY: standard FFI on a valid NUL-terminated name.
        if unsafe { libc::shm_unlink(cname.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Validate + NUL-terminate a POSIX shm name.
fn shm_cname(name: &str) -> io::Result<CString> {
    if !name.starts_with('/') || name.len() < 2 || name[1..].contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "POSIX shm name must be \"/name\" with no embedded slash",
        ));
    }
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "shm name has NUL"))
}
