//! `SessionRef` — the D66/D44 session-index join-key quartet (doc 14 §2/§4).
//!
//! The same shape the LOG-1 `SessionRef` proto message carries. The orchestrator
//! session record is the authority (doc 14 §4); this struct is the in-crate
//! shape every boundary service joins on.
//!
//! The **authoritative, never-recycled join key is the tap name `dstap-<idx>`**
//! (≤15 chars, IFNAMSIZ) — simultaneously the NFT-2 enforcement match
//! (`iifname`), the NFT-5 ct-mark key, and the LOG-2 attribution key. The
//! `host_session_index` is the host-local index whose 14-bit residue rides the
//! mark as a disambiguator (doc 14 §4, see [`crate::mark`]); it is **not** the
//! primary key.

/// IFNAMSIZ ceiling for the tap name, including the trailing NUL the kernel
/// reserves: the printable name is ≤15 chars (doc 14 §4).
pub const TAP_NAME_MAX_LEN: usize = 15;

/// The SINGLE SOURCE for the per-session NFT-3 allow-set name (doc 09 §3 NFT-3;
/// session doc 11 §2.5/§4 D3/D4).
///
/// The per-session admit surface is two named sets in `table inet ds_filter`:
/// `allow4_<idx>` (`ipv4_addr`) and `allow6_<idx>` (`ipv6_addr`, dormant under
/// D75 Phase-B). Two independent writers touch them and MUST agree byte-exact on
/// the name, with NO handshake between them:
///
/// - **`ds-nft`** creates the sets EMPTY at `InstantiateSessionNFT`
///   (`ds_nft::session`).
/// - **`ds-dnsgate`** fills element CONTENT on the DNS-2 admission txn
///   (`ds-dnsgate/src/txn.rs`).
///
/// and the NFT-3b OUTPUT chain READS them cross-table by name
/// (`nft-3b-output.nft`). Deriving the name in more than one place is exactly the
/// §2.5/D3 divergence that fails egress admission closed (the gate fills a set the
/// creator never made, or vice versa). Defining it ONCE here — and having every
/// side CALL this function rather than re-derive — structurally kills that class
/// of bug.
///
/// The `<idx>` token is the **`host_session_index`** (D4), not the session UUID:
/// the per-session ct mark already carries the 14-bit index residue (doc 14 §4,
/// [`crate::mark`]), so keying the set name on the same index minimizes the
/// plumbing every writer needs.
///
/// ```
/// use ds_contracts::dns_admission::AddressFamily;
/// use ds_contracts::session::allow_set_name;
/// assert_eq!(allow_set_name(AddressFamily::V4, 7), "allow4_7");
/// assert_eq!(allow_set_name(AddressFamily::V6, 7), "allow6_7");
/// ```
pub fn allow_set_name(
    family: crate::dns_admission::AddressFamily,
    host_session_index: u32,
) -> String {
    use crate::dns_admission::AddressFamily;
    let fam = match family {
        AddressFamily::V4 => "allow4",
        AddressFamily::V6 => "allow6",
    };
    format!("{fam}_{host_session_index}")
}

/// The session-index join-key quartet (doc 14 §2/§4, D66/D44).
///
/// Field order and names match the LOG-1 `SessionRef` proto exactly so the
/// in-crate type and the wire message stay one shape.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionRef {
    /// The orchestrator session UUID — the global identity (authority:
    /// orchestrator session record).
    pub session_uuid: String,
    /// The host the session runs on.
    pub host_id: String,
    /// The host-local session index. Its 14-bit residue rides the mark as a
    /// disambiguator (doc 14 §4); it is not the primary join key.
    pub host_session_index: u32,
    /// The never-recycled tap name `dstap-<idx>` — the authoritative join key
    /// and the NFT-2 `iifname` / NFT-5 ct-mark / LOG-2 attribution key.
    pub tap_name: String,
}

impl SessionRef {
    /// Construct a `SessionRef` from its four parts. No validation — the
    /// orchestrator session record is the authority for well-formedness
    /// (doc 14 §4); see [`SessionRef::tap_name_within_ifnamsiz`] for the one
    /// structural invariant a consumer may want to assert.
    pub fn new(
        session_uuid: String,
        host_id: String,
        host_session_index: u32,
        tap_name: String,
    ) -> SessionRef {
        SessionRef {
            session_uuid,
            host_id,
            host_session_index,
            tap_name,
        }
    }

    /// Whether the tap name fits the IFNAMSIZ ceiling (≤15 chars, doc 14 §4).
    /// The orchestrator guarantees this on allocation; consumers may assert it.
    pub fn tap_name_within_ifnamsiz(&self) -> bool {
        self.tap_name.len() <= TAP_NAME_MAX_LEN
    }

    /// The 14-bit session-index residue this session contributes to the mark
    /// (doc 14 §4) — a convenience over [`crate::mark::session_index_field`].
    pub fn mark_session_index(&self) -> u16 {
        crate::mark::session_index_field(self.host_session_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quartet_round_trips() {
        let s = SessionRef::new(
            "abcd1234-0000-0000-0000-000000000001".into(),
            "host-7".into(),
            42,
            "dstap-42".into(),
        );
        assert_eq!(s.session_uuid, "abcd1234-0000-0000-0000-000000000001");
        assert_eq!(s.host_id, "host-7");
        assert_eq!(s.host_session_index, 42);
        assert_eq!(s.tap_name, "dstap-42");
    }

    #[test]
    fn tap_name_ifnamsiz_ceiling() {
        let ok = SessionRef::new("u".into(), "h".into(), 1, "dstap-12345".into());
        assert!(ok.tap_name_within_ifnamsiz());
        // 16-char name is over the ceiling.
        let too_long = SessionRef::new("u".into(), "h".into(), 1, "dstap-1234567890".into());
        assert!(!too_long.tap_name_within_ifnamsiz());
        assert_eq!(too_long.tap_name.len(), 16);
    }

    #[test]
    fn mark_index_is_the_residue() {
        let s = SessionRef::new("u".into(), "h".into(), 16_384 + 9, "dstap-9".into());
        assert_eq!(s.mark_session_index(), 9);
    }

    // ── allow_set_name: the single-source per-session NFT-3 set name (D3/D4) ──

    #[test]
    fn allow_set_name_is_the_exact_per_session_string() {
        use crate::dns_admission::AddressFamily;
        // v4 → `allow4_<idx>`, v6 → `allow6_<idx>`; <idx> is host_session_index.
        assert_eq!(allow_set_name(AddressFamily::V4, 0), "allow4_0");
        assert_eq!(allow_set_name(AddressFamily::V4, 7), "allow4_7");
        assert_eq!(allow_set_name(AddressFamily::V6, 7), "allow6_7");
        assert_eq!(allow_set_name(AddressFamily::V4, 42), "allow4_42");
        assert_eq!(allow_set_name(AddressFamily::V6, 42), "allow6_42");
        // a large/wrap-window index renders verbatim (no truncation to the
        // 14-bit mark residue — the SET name carries the full host index).
        assert_eq!(allow_set_name(AddressFamily::V4, 16_393), "allow4_16393");
    }

    #[test]
    fn allow_set_name_family_only_differs_in_the_digit() {
        use crate::dns_admission::AddressFamily;
        // The two families produce names that differ ONLY in the 4/6 — same idx,
        // same suffix — so a per-session pair is unambiguous and grep-stable.
        let v4 = allow_set_name(AddressFamily::V4, 5);
        let v6 = allow_set_name(AddressFamily::V6, 5);
        assert_eq!(v4, "allow4_5");
        assert_eq!(v6, "allow6_5");
        assert_ne!(v4, v6);
        assert!(v4.starts_with("allow4_"));
        assert!(v6.starts_with("allow6_"));
    }
}
