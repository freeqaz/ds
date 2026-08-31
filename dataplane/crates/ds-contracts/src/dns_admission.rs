//! DNS-2b admission map — the single authoritative *shape*, frozen as a
//! versioned Rust API (doc 14 §3, D67/D68/D71/D75).
//!
//! **API v1 FROZEN 2026-06-12 — in-crate commitment.** This is the authoritative
//! in-crate Rust API for the DNS-2b admission map (doc 14 §3 names it "frozen as
//! a versioned Rust API in `ds-contracts`"; doc 14 §1 lists it shape-frozen now,
//! API in `ds-contracts` before Stage 2). It is **not** a `proto/` freeze — no
//! wire schema, no `proto/FREEZE.md` gate. The commitment this header makes:
//! the public items below (types, fields, trait signatures, [`ADMISSION_API_VERSION`])
//! are stable from this date. Any change to a frozen invariant or any
//! non-additive change to a public item requires **both** a doc 04 §6
//! decision-log entry **and** an [`ADMISSION_API_VERSION`] bump. Purely additive
//! changes (new helper, new test) are allowed without a bump; renaming or
//! removing a public item, or changing a field, is not.
//!
//! This module is **types and signatures, not a running service**. The storage
//! mechanism behind it (mmap / shm / UDS service) is free implementation owned
//! by ds-dnsgate (doc 14 OQ6); the API VERSION and the entry/reverse-index
//! shapes are frozen here so ds-tlsproxy (sync read), NFT-6 teardown, and the
//! warm-restart rebuild all agree.
//!
//! No hickory or pingora types cross this API (D67/D40): addresses are carried
//! as the family-agnostic [`AdmittedAddr`] contract shape, never a framework's
//! address type. The map and reverse index are declared as a `trait` so the
//! storage owner supplies the body.
//!
//! Frozen invariants (each carries its D-number — see doc 14 §3):
//! - **Single shared deadline / lockstep (D68):** `expires_at` is the one shared
//!   deadline written to the NFTables element and the map entry in the same
//!   insert-then-answer transaction. Refresh is `max(existing, new)`, never
//!   shortened.
//! - **Insert-then-answer is synchronous and fail-closed (D67/D68).**
//! - **Expiry gates NEW flows only; expiry is not revocation (D68).** Revocation
//!   deletes map entries immediately and set elements only when the reverse
//!   index refcount for an IP reaches zero, then invokes `flush_session` (§5).
//! - **`admission_type` from day one (D71/D75).**
//! - **Reverse index required from day one:** per-session IP ↔ domain refcount.

/// The DNS-2b admission-map API version (doc 14 §3, versioned per doc 06 §2).
/// Invariant changes bump this and require a decision-log entry.
pub const ADMISSION_API_VERSION: u32 = 1;

/// The DEFAULT host-wide POSIX shm object name the DNS-2b admission map lives in
/// (D131 Candidate A: single-writer ds-dnsgate / many-reader ds-tlsproxy over one
/// named `MAP_SHARED` segment). This is the ONE place the writer and the readers
/// agree on the segment name — ds-dnsgate `shm_open`s it to CREATE/attach the writer
/// mapping and ds-tlsproxy `shm_open`s the SAME name to attach its read-only view, so
/// the two never drift on a hand-edited string literal.
///
/// POSIX shm object names must begin with `/` and contain no further `/`
/// (`shm_open(3)`); this default obeys that. The name is NOT part of the frozen
/// DNS-2b API surface — it is the storage mechanism behind the trait (doc 14 OQ6),
/// free implementation owned by the storage layer — so adding it does NOT bump
/// [`ADMISSION_API_VERSION`].
pub const ADMISSION_SHM_DEFAULT_NAME: &str = "/ds-admission";

/// The environment variable that OVERRIDES [`ADMISSION_SHM_DEFAULT_NAME`] — set on
/// BOTH the writer (ds-dnsgate) and the readers (ds-tlsproxy) to point them at a
/// non-default segment (per-host isolation, a test's unique segment, a side-by-side
/// deploy). Honoured by [`admission_shm_name`].
pub const ADMISSION_SHM_NAME_ENV: &str = "DS_ADMISSION_SHM_NAME";

/// The POSIX shm object name the DNS-2b admission map writer + readers agree on:
/// the [`ADMISSION_SHM_NAME_ENV`] override when set and non-empty, else
/// [`ADMISSION_SHM_DEFAULT_NAME`]. The single source of truth both sides call so a
/// per-host or per-test override is configured in ONE place.
///
/// If the env value is set but does NOT begin with `/` (an illegal POSIX shm name),
/// it is still returned verbatim — name validation is `shm_open`'s job and a malformed
/// override should fail loudly at attach, not be silently rewritten here. An empty
/// override is treated as unset (falls back to the default), since an empty string is
/// never a valid segment name.
pub fn admission_shm_name() -> String {
    match std::env::var(ADMISSION_SHM_NAME_ENV) {
        Ok(v) if !v.is_empty() => v,
        _ => ADMISSION_SHM_DEFAULT_NAME.to_string(),
    }
}

/// Address family for a family-agnostic admitted/real-target address (D75): the
/// LOG-1 convention of `bytes`/string + `AddressFamily` — never `u32` (doc 14
/// §2). This contract shape exists so no framework address type crosses the
/// crate (D67/D40).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

/// A family-agnostic admitted address (D75). The octets are the address in
/// network byte order (4 bytes for V4, 16 for V6); the family disambiguates.
/// Deliberately not `std::net::IpAddr` so the frozen contract owns the wire
/// shape, not the stdlib's (and certainly not a framework's).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdmittedAddr {
    /// Address family.
    pub family: AddressFamily,
    /// Address octets, network byte order (4 for V4, 16 for V6).
    pub octets: Vec<u8>,
}

impl AdmittedAddr {
    /// The **canonical [`crate::flush::DstKey`] encoding** — the shared key
    /// contract between this map's reverse index and `flush_session`'s
    /// revocation `DstFilter::Only`: each `DstKey` "is the same key shape the
    /// §3 admission map's reverse index counts" ([`crate::flush::DstFilter`]'s
    /// contract; the semantics are doc 14 §5/§3).
    ///
    /// [`AdmissionMap::revoke`] returns the [`AdmittedAddr`]s whose refcount hit
    /// zero; the caller maps each through this function to build the
    /// `DstFilter::Only(Vec<DstKey>)` it hands `flush_session`. Fixing one
    /// textual form here is what makes "the same key shape" a compile-checked
    /// contract rather than a prose promise — `ds-nft` binds *this* string to its
    /// own address model, and the map writer produces *this* string, so the two
    /// never drift.
    ///
    /// Canonical form (chosen and frozen here): `"<family>:<lower-hex-octets>"`,
    /// family `"v4"` or `"v6"`, octets as contiguous lowercase hex with no
    /// separators (8 hex chars for V4, 32 for V6). Hex (not dotted-quad /
    /// RFC 5952) is deliberate: it is a total, separator-free, byte-exact
    /// function of `octets` that needs no per-family formatting branch and no
    /// canonicalization rules to argue about — the bytes ARE the identity, which
    /// is exactly what the refcount key and the conntrack match key must agree
    /// on. The family tag prevents a V4 address from colliding with the first
    /// four octets of a V6 address.
    pub fn to_dst_key(&self) -> crate::flush::DstKey {
        let mut s = String::with_capacity(3 + self.octets.len() * 2);
        s.push_str(match self.family {
            AddressFamily::V4 => "v4:",
            AddressFamily::V6 => "v6:",
        });
        for b in &self.octets {
            // two lowercase hex digits per octet, no separator.
            const HEX: &[u8; 16] = b"0123456789abcdef";
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        crate::flush::DstKey(s)
    }
}

/// The admission class of a map entry, frozen from day one (D71/D75, doc 14 §3).
///
/// Freezing the enum now avoids a v1→v2 API migration within two stages. The
/// synthetic pool itself (198.18.0.0/15 strawman) is NOT frozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdmissionType {
    /// A normal admission: the guest connects directly to the admitted IPs.
    Normal,
    /// Phase-B synthetic-A admission (D75): the guest sees a synthetic v4
    /// literal; `real_targets` carries the real (v6) targets the proxy dials,
    /// keyed on SNI + map.
    Synthetic,
    /// Reserves the slot for any future D71 sinkhole class (block-page mode,
    /// deferred post-TLS-3). Frozen now so the enum never needs a v2.
    SinkholeReserved,
}

/// POL-3 provenance attached to an admission (doc 14 §3, §2). The same
/// provenance struct `PolicyDecision` carries; the version namespaces are
/// distinct strings so LOG-4 does not treat them as skew.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// The matching rule id.
    pub rule_id: String,
    /// The policy layer the rule came from.
    pub policy_layer: String,
    /// The policy version in force at admission.
    pub policy_version: String,
}

/// An absolute instant — the SINGLE shared deadline / admission time
/// (doc 14 §3, D68). Carried as nanoseconds since the Unix epoch so the
/// contract owns the representation rather than depending on a clock type that
/// might differ between the map writer and the NFTables-element writer; the two
/// stores must agree on one number, never compute timers independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    /// Nanoseconds since the Unix epoch (UTC).
    pub unix_nanos: u64,
}

impl Instant {
    /// Construct from nanoseconds since the Unix epoch.
    pub const fn from_unix_nanos(unix_nanos: u64) -> Instant {
        Instant { unix_nanos }
    }
}

/// Nanoseconds in one second — the bridge between the POL-1 timer fields (which
/// are whole seconds, doc 13 §1.5) and [`Instant`] (nanoseconds, this module).
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// The clamped TTL **the VM is answered** (doc 11 W2): `clamp(chain_min_ttl,
/// floor, ceil)`, in seconds, **without** GRACE. This is the value `respond/`
/// puts on the DNS answer's RR TTL; GRACE is added only to the shared *deadline*
/// (see [`compose_deadline`]), never to what the guest's cache sees.
///
/// `floor`/`ceil`/`chain_min_ttl` are seconds. `floor` and `ceil` are POL-1
/// policy values (doc 13 §1.5: `ttl_floor`/`ttl_ceil`), **passed in, never code
/// constants** (D68/doc 11 §4 frozen column — values are tunable per policy
/// push; tests pin the defaults 60/900). If a caller passes `ceil < floor`, the
/// ceiling wins (clamp is `min(ceil, max(floor, x))`), so the result is never
/// below `ceil` — degenerate policy is the caller's to reject upstream.
pub fn clamped_ttl(chain_min_ttl: u32, floor: u32, ceil: u32) -> u32 {
    chain_min_ttl.max(floor).min(ceil)
}

/// Compose the **single shared deadline** (D68/W2, doc 14 §3, doc 11 §8.3 step
/// 1): `expires_at = answer_time + clamp(chain_min_ttl, floor, ceil) + grace`.
///
/// This is the one value written to **both** the NFTables element and the
/// [`AdmissionEntry::expires_at`] in the same insert-then-answer transaction;
/// the two stores never compute timers independently (lockstep is a security
/// property — TLS-1's expired-admission refusal depends on it). The VM is
/// answered [`clamped_ttl`] (no grace); the deadline carries the grace.
///
/// `floor`/`ceil`/`grace`/`chain_min_ttl` are **seconds**; `answer_time` and the
/// returned deadline are [`Instant`]s (nanoseconds). `floor`/`ceil`/`grace` are
/// POL-1 policy values (doc 13 §1.5), **parameters, not constants** — tests pin
/// the defaults 60/900/60. The seconds→nanos widening is computed in `u64` so it
/// cannot overflow for any `u32` second value (max ~2^32 s ≈ 4.3 s of u64-nanos
/// headroom margin is ample); a wildly out-of-range `answer_time` near `u64::MAX`
/// saturates rather than wrapping, so a composed deadline never silently moves
/// *earlier* than `answer_time`.
pub fn compose_deadline(
    answer_time: Instant,
    chain_min_ttl: u32,
    floor: u32,
    ceil: u32,
    grace: u32,
) -> Instant {
    let ttl_secs = clamped_ttl(chain_min_ttl, floor, ceil) as u64;
    let add_nanos = (ttl_secs + grace as u64).saturating_mul(NANOS_PER_SEC);
    Instant::from_unix_nanos(answer_time.unix_nanos.saturating_add(add_nanos))
}

/// The admission-map key: `(session, original_query_fqdn)` (doc 14 §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdmissionKey {
    /// The host-local session index (the disambiguator; the authoritative key
    /// is the session record — doc 14 §4). Keyed here by the orchestrator
    /// session UUID so the map is unambiguous across index wrap.
    pub session_uuid: String,
    /// The original query FQDN as asked by the guest (pre-CNAME-chase).
    pub original_query_fqdn: String,
}

/// The admission-map value (doc 14 §3). Field-for-field the frozen §3 shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionEntry {
    /// The admitted IPs (family-tagged).
    pub admitted_ips: Vec<AdmittedAddr>,
    /// The admission class (D71/D75).
    pub admission_type: AdmissionType,
    /// Phase B: the real (v6) targets a SYNTHETIC entry stands for — empty for
    /// NORMAL (D75).
    pub real_targets: Vec<AdmittedAddr>,
    /// The SINGLE shared deadline (D68): `answer_time + clamp(chain_min_ttl,
    /// FLOOR, CEIL) + GRACE`. Refresh is `max(existing, new)`.
    pub expires_at: Instant,
    /// When the admission was made.
    pub admitted_at: Instant,
    /// POL-3 provenance.
    pub provenance: Provenance,
}

impl AdmissionEntry {
    /// The D68 refresh rule: a deadline is only ever extended, never shortened
    /// (`max(existing_deadline, new_deadline)`). Returns the refreshed deadline.
    pub fn refreshed_deadline(&self, new_deadline: Instant) -> Instant {
        if new_deadline > self.expires_at {
            new_deadline
        } else {
            self.expires_at
        }
    }

    /// Whether this entry is expired at `now`. Expiry gates NEW flows only —
    /// established flows ride conntrack (D68). This is a predicate on the
    /// shape; it is not revocation.
    pub fn is_expired_at(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// The per-session IP ↔ domain reverse index — required from day one (doc 14
/// §3). Revocation deletes a set element only when an IP's refcount reaches
/// zero, so revoking domain D never breaks domain E sharing a CDN IP.
///
/// Types/signatures only; the storage owner (ds-dnsgate) supplies the body.
pub trait ReverseIndex {
    /// Increment the refcount for `(session, ip)` as `domain` is admitted;
    /// returns the new refcount.
    fn incref(&mut self, session_uuid: &str, ip: &AdmittedAddr, domain: &str) -> u32;

    /// Decrement the refcount for `(session, ip)` as `domain` is revoked;
    /// returns the remaining refcount. A return of `0` is the signal that the
    /// set element may now be deleted (doc 14 §3).
    ///
    /// **Bias to under-delete (doc 11 §5.2):** an element is removed *only* when
    /// no live admission references the IP; when in doubt the implementor keeps
    /// the element and lets the W2 deadline clean it up. A spuriously-retained
    /// allow-set element costs nothing beyond a slightly later expiry (expiry
    /// gates NEW flows only, W4), whereas a spuriously-deleted one would sever a
    /// still-admitted domain sharing a CDN IP — so the safe direction of any
    /// refcount error is to under-delete. Implementors saturate at zero rather
    /// than underflow, and never return a delete signal they are unsure of.
    fn decref(&mut self, session_uuid: &str, ip: &AdmittedAddr, domain: &str) -> u32;

    /// The current refcount for `(session, ip)`.
    fn refcount(&self, session_uuid: &str, ip: &AdmittedAddr) -> u32;
}

/// Why an admission-map operation failed. A contract shape; the storage
/// implementor maps its own errors onto it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// The insert-then-answer set-programming step failed: the answer must be
    /// withheld and the VM gets SERVFAIL — fail-closed (D67/D68).
    SetProgrammingFailed,
    /// The API version of a persisted/shared map did not match
    /// [`ADMISSION_API_VERSION`] (warm-restart / cross-version read).
    VersionMismatch {
        /// The version this build speaks.
        expected: u32,
        /// The version found.
        found: u32,
    },
    /// An implementor-specific storage failure, described opaquely.
    Storage(String),
}

/// The DNS-2b admission map — the versioned API skeleton (doc 14 §3).
///
/// Types/signatures only — there is no running service here. ds-dnsgate is the
/// sole writer; ds-tlsproxy reads synchronously on every TLS-1/TLS-4
/// connection; NFT-6 flushes at teardown. The storage mechanism is free
/// implementation behind this trait (doc 14 OQ6).
pub trait AdmissionMap {
    /// The reverse index this map exposes.
    type Reverse: ReverseIndex;

    /// The API version this implementation speaks. Must equal
    /// [`ADMISSION_API_VERSION`] for the build it ships in.
    fn api_version(&self) -> u32 {
        ADMISSION_API_VERSION
    }

    /// Insert (or refresh) an admission. Per D68 the set element and this entry
    /// are written in one insert-then-answer transaction; on set-programming
    /// failure this returns [`AdmissionError::SetProgrammingFailed`] and the
    /// answer is withheld. Refresh extends the deadline via
    /// [`AdmissionEntry::refreshed_deadline`], never shortens it.
    fn admit(&mut self, key: AdmissionKey, entry: AdmissionEntry) -> Result<(), AdmissionError>;

    /// Look up an admission (ds-tlsproxy sync read).
    ///
    /// **The map does not self-evict (W4, doc 11 §3.1).** `lookup` returns the
    /// entry whether or not it is expired at the caller's clock; expiry is the
    /// *caller's* gate, applied via [`AdmissionEntry::is_expired_at`] against the
    /// time the caller cares about. Expiry gates NEW flows only and is not
    /// revocation (D68): a `lookup` that returns an expired entry is correct, and
    /// ds-tlsproxy's TLS-1 admission check is what refuses it — not a silent
    /// drop from the map. (A revoked key returns `None`; an expired-but-not-yet-
    /// revoked key returns `Some(expired_entry)`.)
    fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry>;

    /// Revoke an admission: delete the map entry immediately; set elements are
    /// deleted only when their reverse-index refcount reaches zero (the caller
    /// then invokes `flush_session`, §5). Returns the IPs whose refcount hit
    /// zero and are therefore safe to remove from the set — map each through
    /// [`AdmittedAddr::to_dst_key`] to build the revocation `DstFilter::Only`.
    ///
    /// **Revoking an absent key is a no-op that succeeds** (idempotent): it
    /// returns `Ok(vec![])`, never an error. Revocation is driven by policy
    /// sweeps and admin actions (doc 11 §5.4) that may race natural expiry or a
    /// prior revoke of the same key; making absent-key revoke a silent empty
    /// success keeps those callers from having to distinguish "already gone" from
    /// "never existed" — both leave nothing to flush, which is exactly the empty
    /// return. A genuine *storage* failure is still surfaced as
    /// [`AdmissionError::Storage`].
    fn revoke(&mut self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError>;

    /// Borrow the reverse index.
    fn reverse_index(&self) -> &Self::Reverse;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> AdmittedAddr {
        AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![a, b, c, d],
        }
    }

    fn sample_entry(expires: u64) -> AdmissionEntry {
        AdmissionEntry {
            admitted_ips: vec![v4(93, 184, 216, 34)],
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
            expires_at: Instant::from_unix_nanos(expires),
            admitted_at: Instant::from_unix_nanos(0),
            provenance: Provenance {
                rule_id: "r1".into(),
                policy_layer: "org".into(),
                policy_version: "v0".into(),
            },
        }
    }

    #[test]
    fn api_version_is_one() {
        assert_eq!(ADMISSION_API_VERSION, 1);
    }

    #[test]
    fn shm_default_name_is_a_legal_posix_shm_name() {
        // POSIX shm_open names must begin with '/' and (portably) contain no further
        // '/'. The default the writer + readers single-source obeys both.
        assert!(ADMISSION_SHM_DEFAULT_NAME.starts_with('/'));
        assert_eq!(ADMISSION_SHM_DEFAULT_NAME.matches('/').count(), 1);
    }

    #[test]
    fn shm_name_honours_the_env_override_else_the_default() {
        // The override env var name is the documented one.
        assert_eq!(ADMISSION_SHM_NAME_ENV, "DS_ADMISSION_SHM_NAME");
        // NOTE: this test mutates a process-global env var. The crate's other tests
        // never read this var, and `cargo test` runs a crate's unit tests on threads
        // of ONE process; to avoid racing a sibling test that might one day read it we
        // set, assert, and unset within this single test and touch no other var.
        let prior = std::env::var(ADMISSION_SHM_NAME_ENV).ok();

        // Unset → the default.
        std::env::remove_var(ADMISSION_SHM_NAME_ENV);
        assert_eq!(admission_shm_name(), ADMISSION_SHM_DEFAULT_NAME);

        // Empty → treated as unset → the default.
        std::env::set_var(ADMISSION_SHM_NAME_ENV, "");
        assert_eq!(admission_shm_name(), ADMISSION_SHM_DEFAULT_NAME);

        // Set + non-empty → the override verbatim.
        std::env::set_var(ADMISSION_SHM_NAME_ENV, "/ds-admission-test-override");
        assert_eq!(admission_shm_name(), "/ds-admission-test-override");

        // Restore the prior value so the process env is unchanged after the test.
        match prior {
            Some(v) => std::env::set_var(ADMISSION_SHM_NAME_ENV, v),
            None => std::env::remove_var(ADMISSION_SHM_NAME_ENV),
        }
    }

    #[test]
    fn admission_types_are_three_and_distinct() {
        assert_ne!(AdmissionType::Normal, AdmissionType::Synthetic);
        assert_ne!(AdmissionType::Synthetic, AdmissionType::SinkholeReserved);
        assert_ne!(AdmissionType::Normal, AdmissionType::SinkholeReserved);
    }

    #[test]
    fn deadline_refresh_never_shortens() {
        let e = sample_entry(1_000);
        // a later deadline extends.
        assert_eq!(
            e.refreshed_deadline(Instant::from_unix_nanos(2_000)),
            Instant::from_unix_nanos(2_000)
        );
        // an earlier deadline is ignored (max rule, D68).
        assert_eq!(
            e.refreshed_deadline(Instant::from_unix_nanos(500)),
            Instant::from_unix_nanos(1_000)
        );
        // equal is a no-op.
        assert_eq!(
            e.refreshed_deadline(Instant::from_unix_nanos(1_000)),
            Instant::from_unix_nanos(1_000)
        );
    }

    #[test]
    fn expiry_predicate_gates_at_the_deadline() {
        let e = sample_entry(1_000);
        assert!(!e.is_expired_at(Instant::from_unix_nanos(999)));
        assert!(e.is_expired_at(Instant::from_unix_nanos(1_000)));
        assert!(e.is_expired_at(Instant::from_unix_nanos(1_001)));
    }

    #[test]
    fn synthetic_carries_real_targets_normal_does_not() {
        let mut e = sample_entry(10);
        assert!(e.real_targets.is_empty());
        e.admission_type = AdmissionType::Synthetic;
        e.real_targets = vec![AdmittedAddr {
            family: AddressFamily::V6,
            octets: vec![0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }];
        assert_eq!(e.real_targets.len(), 1);
        assert_eq!(e.real_targets[0].family, AddressFamily::V6);
        assert_eq!(e.real_targets[0].octets.len(), 16);
    }

    // A trivial in-memory reverse index proves the trait shape supports the
    // refcount-to-zero deletion rule without any storage machinery.
    #[derive(Default)]
    struct MemReverse {
        counts: std::collections::HashMap<(String, Vec<u8>), u32>,
    }
    impl ReverseIndex for MemReverse {
        fn incref(&mut self, session_uuid: &str, ip: &AdmittedAddr, _domain: &str) -> u32 {
            let k = (session_uuid.to_string(), ip.octets.clone());
            let c = self.counts.entry(k).or_insert(0);
            *c += 1;
            *c
        }
        fn decref(&mut self, session_uuid: &str, ip: &AdmittedAddr, _domain: &str) -> u32 {
            let k = (session_uuid.to_string(), ip.octets.clone());
            let c = self.counts.entry(k).or_insert(0);
            *c = c.saturating_sub(1);
            *c
        }
        fn refcount(&self, session_uuid: &str, ip: &AdmittedAddr) -> u32 {
            *self
                .counts
                .get(&(session_uuid.to_string(), ip.octets.clone()))
                .unwrap_or(&0)
        }
    }

    #[test]
    fn reverse_index_refcount_to_zero_signals_set_delete() {
        let mut idx = MemReverse::default();
        let ip = v4(203, 0, 113, 5);
        // two domains share one CDN IP.
        assert_eq!(idx.incref("s1", &ip, "a.example"), 1);
        assert_eq!(idx.incref("s1", &ip, "b.example"), 2);
        // revoking a.example must NOT free the IP (b still uses it).
        assert_eq!(idx.decref("s1", &ip, "a.example"), 1);
        assert_eq!(idx.refcount("s1", &ip), 1);
        // revoking b.example frees it — the zero is the delete signal.
        assert_eq!(idx.decref("s1", &ip, "b.example"), 0);
    }

    // ── Deadline composition (W2/D68; doc 11 §8.3) ──────────────────────────
    //
    // FLOOR/CEIL/GRACE are POL-1 policy values (doc 13 §1.5), NOT code
    // constants — the API takes them as parameters. These test-only consts PIN
    // the doc 11 §4 / doc 13 §1.5 defaults so a silent drift of the documented
    // numbers is a test failure, while the code itself stays value-agnostic.
    const DEFAULT_FLOOR_SECS: u32 = 60;
    const DEFAULT_CEIL_SECS: u32 = 900;
    const DEFAULT_GRACE_SECS: u32 = 60;

    #[test]
    fn clamped_ttl_pins_the_default_floor_and_ceil() {
        // below floor → floor (default 60s).
        assert_eq!(
            clamped_ttl(5, DEFAULT_FLOOR_SECS, DEFAULT_CEIL_SECS),
            DEFAULT_FLOOR_SECS
        );
        assert_eq!(DEFAULT_FLOOR_SECS, 60);
        // above ceil → ceil (default 900s).
        assert_eq!(
            clamped_ttl(10_000, DEFAULT_FLOOR_SECS, DEFAULT_CEIL_SECS),
            DEFAULT_CEIL_SECS
        );
        assert_eq!(DEFAULT_CEIL_SECS, 900);
        // inside the band → unchanged.
        assert_eq!(clamped_ttl(300, DEFAULT_FLOOR_SECS, DEFAULT_CEIL_SECS), 300);
        // exact bounds are inclusive.
        assert_eq!(clamped_ttl(60, DEFAULT_FLOOR_SECS, DEFAULT_CEIL_SECS), 60);
        assert_eq!(clamped_ttl(900, DEFAULT_FLOOR_SECS, DEFAULT_CEIL_SECS), 900);
    }

    #[test]
    fn compose_deadline_is_clamp_plus_grace_with_defaults_60_900_60() {
        // The frozen W2 formula with the pinned defaults 60/900/60.
        let answer_time = Instant::from_unix_nanos(1_000 * NANOS_PER_SEC);

        // chain TTL inside the band: deadline = answer + ttl + GRACE.
        let d = compose_deadline(
            answer_time,
            300,
            DEFAULT_FLOOR_SECS,
            DEFAULT_CEIL_SECS,
            DEFAULT_GRACE_SECS,
        );
        assert_eq!(d.unix_nanos, (1_000 + 300 + 60) * NANOS_PER_SEC);

        // below floor: clamp lifts to 60, then +60 grace.
        let d = compose_deadline(
            answer_time,
            1,
            DEFAULT_FLOOR_SECS,
            DEFAULT_CEIL_SECS,
            DEFAULT_GRACE_SECS,
        );
        assert_eq!(d.unix_nanos, (1_000 + 60 + 60) * NANOS_PER_SEC);

        // above ceil: clamp caps at 900, then +60 grace.
        let d = compose_deadline(
            answer_time,
            100_000,
            DEFAULT_FLOOR_SECS,
            DEFAULT_CEIL_SECS,
            DEFAULT_GRACE_SECS,
        );
        assert_eq!(d.unix_nanos, (1_000 + 900 + 60) * NANOS_PER_SEC);
        assert_eq!(DEFAULT_GRACE_SECS, 60);
    }

    #[test]
    fn vm_is_answered_the_clamp_without_grace() {
        // doc 11 W2: the VM's RR TTL is the clamp WITHOUT grace; the deadline
        // (compose_deadline) carries the grace. The difference between the two,
        // for the same inputs, is exactly GRACE seconds.
        let answer_time = Instant::from_unix_nanos(0);
        let chain = 300;
        let answered_ttl = clamped_ttl(chain, DEFAULT_FLOOR_SECS, DEFAULT_CEIL_SECS);
        let deadline = compose_deadline(
            answer_time,
            chain,
            DEFAULT_FLOOR_SECS,
            DEFAULT_CEIL_SECS,
            DEFAULT_GRACE_SECS,
        );
        let deadline_secs = deadline.unix_nanos / NANOS_PER_SEC;
        assert_eq!(answered_ttl, 300);
        assert_eq!(
            deadline_secs - answered_ttl as u64,
            DEFAULT_GRACE_SECS as u64
        );
    }

    #[test]
    fn compose_deadline_takes_parameters_not_constants() {
        // A per-domain override (doc 13 §1.5 per_domain_overrides) pins a longer
        // ceil; the helper honours whatever values are passed — proving the
        // numbers are policy parameters, not baked-in constants.
        let answer_time = Instant::from_unix_nanos(0);
        let d = compose_deadline(answer_time, 100_000, 60, 3_600, 60);
        assert_eq!(d.unix_nanos, (3_600 + 60) * NANOS_PER_SEC);
    }

    #[test]
    fn compose_deadline_saturates_rather_than_wrapping() {
        // A near-max answer_time must never wrap to an earlier instant — the
        // deadline saturates at u64::MAX (a deadline never moves earlier).
        let near_max = Instant::from_unix_nanos(u64::MAX - 5);
        let d = compose_deadline(near_max, 300, 60, 900, 60);
        assert!(d.unix_nanos >= near_max.unix_nanos);
        assert_eq!(d.unix_nanos, u64::MAX);
    }

    // ── AdmittedAddr → flush::DstKey canonical encoding (doc 14 §5) ──────────

    #[test]
    fn dst_key_encoding_is_canonical_and_family_tagged() {
        use crate::flush::DstKey;
        // V4: family tag + 8 lowercase hex chars (93.184.216.34).
        assert_eq!(
            v4(93, 184, 216, 34).to_dst_key(),
            DstKey("v4:5db8d822".to_string())
        );
        // V6: family tag + 32 lowercase hex chars (2001:db8::1).
        let v6 = AdmittedAddr {
            family: AddressFamily::V6,
            octets: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        assert_eq!(
            v6.to_dst_key(),
            DstKey("v6:20010db8000000000000000000000001".to_string())
        );
        // The family tag prevents a V4 address from colliding with a V6 prefix.
        let v6_prefixed_same_bytes = AdmittedAddr {
            family: AddressFamily::V6,
            octets: vec![93, 184, 216, 34],
        };
        assert_ne!(
            v4(93, 184, 216, 34).to_dst_key(),
            v6_prefixed_same_bytes.to_dst_key()
        );
    }

    #[test]
    fn dst_key_round_trips_through_revoke_into_dst_filter() {
        // The revoke→flush bridge: revoke returns AdmittedAddrs; each maps to a
        // DstKey that DstFilter::Only consumes — the same key shape doc 14 §5
        // says the reverse index counts.
        use crate::flush::{DstFilter, DstKey};
        let freed = [v4(203, 0, 113, 5), v4(198, 51, 100, 7)];
        let filter = DstFilter::Only(freed.iter().map(AdmittedAddr::to_dst_key).collect());
        assert_eq!(
            filter,
            DstFilter::Only(vec![
                DstKey("v4:cb007105".to_string()),
                DstKey("v4:c6336407".to_string()),
            ])
        );
    }

    // ── Map-level edge semantics: a minimal in-memory AdmissionMap ───────────
    //
    // Proves revoke-of-absent and lookup-of-expired against the trait, without
    // any storage machinery. This is the caller-visible contract, not the impl.
    #[derive(Default)]
    struct MemMap {
        entries: std::collections::HashMap<(String, String), AdmissionEntry>,
        reverse: MemReverse,
    }
    impl AdmissionMap for MemMap {
        type Reverse = MemReverse;
        fn admit(
            &mut self,
            key: AdmissionKey,
            entry: AdmissionEntry,
        ) -> Result<(), AdmissionError> {
            for ip in &entry.admitted_ips {
                self.reverse
                    .incref(&key.session_uuid, ip, &key.original_query_fqdn);
            }
            self.entries
                .insert((key.session_uuid, key.original_query_fqdn), entry);
            Ok(())
        }
        fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
            // NOTE: no expiry check here — the map does not self-evict (W4).
            self.entries
                .get(&(key.session_uuid.clone(), key.original_query_fqdn.clone()))
                .cloned()
        }
        fn revoke(&mut self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
            let k = (key.session_uuid.clone(), key.original_query_fqdn.clone());
            // Absent key: idempotent empty success (no error).
            let Some(entry) = self.entries.remove(&k) else {
                return Ok(vec![]);
            };
            let mut freed = Vec::new();
            for ip in &entry.admitted_ips {
                if self
                    .reverse
                    .decref(&key.session_uuid, ip, &key.original_query_fqdn)
                    == 0
                {
                    freed.push(ip.clone());
                }
            }
            Ok(freed)
        }
        fn reverse_index(&self) -> &Self::Reverse {
            &self.reverse
        }
    }

    fn key(session: &str, fqdn: &str) -> AdmissionKey {
        AdmissionKey {
            session_uuid: session.to_string(),
            original_query_fqdn: fqdn.to_string(),
        }
    }

    #[test]
    fn revoke_of_absent_key_is_empty_success() {
        let mut m = MemMap::default();
        // never admitted: empty success, never an error.
        assert_eq!(m.revoke(&key("s1", "never.example")), Ok(vec![]));
        // admit then revoke twice: second revoke is the same empty success.
        m.admit(key("s1", "a.example"), sample_entry(1_000))
            .unwrap();
        assert_eq!(
            m.revoke(&key("s1", "a.example")),
            Ok(vec![v4(93, 184, 216, 34)])
        );
        assert_eq!(m.revoke(&key("s1", "a.example")), Ok(vec![]));
    }

    #[test]
    fn lookup_of_expired_entry_still_returns_it_no_self_eviction() {
        let mut m = MemMap::default();
        // entry expires at t=1000ns.
        m.admit(key("s1", "a.example"), sample_entry(1_000))
            .unwrap();
        let got = m.lookup(&key("s1", "a.example")).expect("entry present");
        // far past the deadline, lookup STILL returns it — the map never
        // self-evicts; the caller's is_expired_at gate is what refuses a new flow.
        assert!(got.is_expired_at(Instant::from_unix_nanos(9_999)));
        assert!(m.lookup(&key("s1", "a.example")).is_some());
        // only an explicit revoke removes it (then lookup is None).
        m.revoke(&key("s1", "a.example")).unwrap();
        assert!(m.lookup(&key("s1", "a.example")).is_none());
    }

    // ── Shape-pinning tests: a new field or variant is a compile-visible change ─

    #[test]
    fn admission_type_match_is_exhaustive_a_new_variant_breaks_this() {
        // An exhaustive match with no wildcard arm: adding a fourth AdmissionType
        // variant fails to compile here, forcing a deliberate (D-numbered) review
        // rather than silently defaulting. ADMISSION_API_VERSION must bump with it.
        fn label(t: AdmissionType) -> &'static str {
            match t {
                AdmissionType::Normal => "normal",
                AdmissionType::Synthetic => "synthetic",
                AdmissionType::SinkholeReserved => "sinkhole_reserved",
            }
        }
        assert_eq!(label(AdmissionType::Normal), "normal");
        assert_eq!(label(AdmissionType::Synthetic), "synthetic");
        assert_eq!(label(AdmissionType::SinkholeReserved), "sinkhole_reserved");
    }

    #[test]
    fn admission_entry_struct_literal_names_every_frozen_field() {
        // A struct literal with no `..Default::default()` spread: adding,
        // removing, or renaming an AdmissionEntry field fails to compile here.
        // This pins the doc 14 §3 field-for-field shape as a compile gate.
        let e = AdmissionEntry {
            admitted_ips: vec![v4(93, 184, 216, 34)],
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
            expires_at: Instant::from_unix_nanos(2),
            admitted_at: Instant::from_unix_nanos(1),
            provenance: Provenance {
                rule_id: "r1".into(),
                policy_layer: "org".into(),
                policy_version: "v0".into(),
            },
        };
        // Touch every field so an accidental field-type change is also caught.
        assert_eq!(e.admitted_ips.len(), 1);
        assert_eq!(e.admission_type, AdmissionType::Normal);
        assert!(e.real_targets.is_empty());
        assert_eq!(e.expires_at, Instant::from_unix_nanos(2));
        assert_eq!(e.admitted_at, Instant::from_unix_nanos(1));
        assert_eq!(e.provenance.rule_id, "r1");
        assert_eq!(e.provenance.policy_layer, "org");
        assert_eq!(e.provenance.policy_version, "v0");
    }

    #[test]
    fn provenance_struct_literal_names_every_frozen_field() {
        // Same compile-gate discipline for the POL-3 provenance shape.
        let p = Provenance {
            rule_id: "rule-1".into(),
            policy_layer: "org".into(),
            policy_version: "2026-06-12".into(),
        };
        assert_eq!(p.rule_id, "rule-1");
        assert_eq!(p.policy_layer, "org");
        assert_eq!(p.policy_version, "2026-06-12");
    }
}
