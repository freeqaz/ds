//! ds-tlsproxy — the proxy-side flush_session severing registry + the D53
//! rung-conditional revocation caller (doc 12 §8/§12/§13; doc 14 §5; D72/D53/D68).
//!
//! # What this is
//!
//! ds-nft owns the conntrack/netlink half of `flush_session` — it issues the
//! `conntrack -D` destroys that sever kernel flow state (task
//! `01KTWJ2R78F7YFPN4S0RWKQX0B`, both kernel refresh paths). This module is the
//! **proxy-side residual** doc 12 §8 names:
//!
//! > *"ds-tlsproxy's contribution to the sweep: tear down its live tunnels for
//! > revoked admissions and drop pooled upstream sockets for the swept session."*
//!
//! Killing a conntrack entry does not by itself close a socket ds-tlsproxy has
//! open in userspace: the proxy holds the two ends of every live tunnel and a
//! pool of warm upstream sockets, and those must be severed too or bytes keep
//! flowing over an already-established connection. This module is the userspace
//! twin of ds-nft's `NftWriter`: it implements the *same* frozen
//! [`ds_contracts::flush::FlushSession`] contract, but over a registry of live
//! tunnel / pooled-socket handles rather than over conntrack.
//!
//! The differences between callers live entirely in the arguments they pass
//! (`dst_filter`, `legs`) — exactly as in ds-nft. This crate executes the
//! severing MECHANISM (registry narrowing) and, separately, hosts the
//! rung-conditional CALLER decision (D53), which ds-nft deliberately does not.
//!
//! # The three callers (doc 14 §5)
//!
//! - **D68/D72 revocation sweep** — rung-conditional per D53: sever live tunnels
//!   and pooled sockets only when the revoking rule's rung is block-or-higher.
//!   The narrowing is `dst_filter = Only(revoked keys)`, `legs = sever_pair()`
//!   (`0x1` agent-VM leg + `0x2` upstream leg). See [`RevocationSweep`].
//! - **NFT-6 session-end teardown** — UNCONDITIONAL, `legs = All`, `dst = All`:
//!   every tunnel and every pooled socket the session owns is dropped. See
//!   [`SeveringRegistry::teardown_session`].
//! - **The >15-min park tier** (doc 12 §12) — teardown shape: `flush_session(
//!   legs = all)` on the path to PARKED (no transparency claim, so it tears down
//!   exactly like NFT-6).
//!
//! Per **D68** (doc 09 OQ3) expiry is NEVER revocation: an admission lapsing on
//! its TTL re-resolves through full DNS-2 admission (re-admit, not refuse) and
//! severs NOTHING. Only an explicit revoke at a severing rung — or session end —
//! severs. This is encoded as [`tests::expiry_is_not_revocation_and_severs_nothing`].
//!
//! # Scope honesty (M0-host integration residual)
//!
//! What lands here: the framework-agnostic severing **registry**, the frozen
//! **contract impl**, and the rung-conditional **caller decision**, all over a
//! [`Severable`] abstraction tested against fake handles. What does NOT land
//! here, and is M0-host integration work:
//!
//! - the real pingora wiring — registering an actual live tunnel's downstream +
//!   upstream sockets and a real pooled `TcpStream` as `Severable`s at the
//!   listener/connect layer ([`Severable`] is the seam; doc 12 §13.1 confines
//!   every pingora type to `accept/`/`connect/`, so this registry — being
//!   inward of that layer — stays framework-agnostic by construction);
//! - the **"within seconds" real-socket kill latency** claim (doc 12 §8): that
//!   is a property of `shutdown(SHUT_RDWR)` + the host's `nf_conntrack_tcp_loose=0`
//!   baseline (NFT-1), not of this registry. Here, `sever()` is a synchronous
//!   call on a fake handle; the latency contract is asserted on the M0 host.
//!
//! # Frozen non-edge (doc 12 §4.2, D76)
//!
//! This crate does NOT depend on ds-nft and issues no conntrack/netlink syscall.
//! The registry is pure userspace state.

#![forbid(unsafe_code)]

/// The FROZEN D72 two-phase apply barrier — ds-tlsproxy's `Consumer` side (POL-4
/// part 2; doc 13 §5, doc 15 §5.2). The proxy is an enforcer (committed BEFORE
/// the admitter, make-before-break): `prepare` validates a snapshot via the
/// embedded `policy-core` evaluator and STAGES it while still deciding egress
/// connects on `vN`; `commit` atomically pointer-swaps the staged evaluator live;
/// `sweep_and_advance_applied_seq` runs the post-commit revocation sweep. Binds
/// the [`ds_contracts::consumer::Consumer`] seam.
///
/// ALSO hosts the TLS-7 GENERIC-PACK side of the same barrier
/// ([`apply::GenericPackConsumer`], doc 12 §5.2 / §108, D72/D73): the generic pack
/// is a `policy_log`-seq policy artifact that rides the SAME two-phase apply
/// (validate-then-stage-then-flip), so a POL-4 generic-pack update lands fleet-wide
/// within seconds with no proxy restart. `prepare` extracts + validates the pack
/// from the POL-1 doc and stages it; `commit` hot-swaps it into the shared
/// [`scan::SharedGenericPack`] every in-flight matcher reads; the post-commit sweep
/// re-evaluates in-flight streams against the new ruleset and emits a
/// policy-decision event for any NEWLY-matched generic rule before `applied_seq`
/// advances.
pub mod apply;

/// The HOST-LOCAL policy-snapshot feed CONSUMER (POL-4 part 2; D72 §6 / §5.1,
/// doc 12 §8). ds-tlsproxy NEVER opens a control-plane policy stream (D36/D72 §1:
/// the host agent is the single per-host `WatchPolicies` subscriber); it consumes
/// the host-local snapshot feed the host agent fans out. This module is the
/// transport/feed-dispatch layer: it receives `(seq, content_hash, document)`
/// tuples, VERIFIES snapshot identity (verify-only, before parse), routes verified
/// bytes to [`apply::PolicyConsumer`]'s [`ds_contracts::consumer::Consumer::prepare`],
/// and ACKs/NACKs `(seq, content_hash)` back to the host agent. A NACK aborts the
/// apply host-wide (the host stays on `vN`, fail-closed). The transport is FREE
/// (doc 12 §9; UDS gRPC default) — the receive/send seams are traits the live
/// subscriber and a mock host-agent stream both drive.
pub mod snapshot_feed;

/// ds-tlsproxy's POST-COMMIT REVOCATION SWEEP — the no-op structural placeholder that
/// completes the frozen three-consumer sweep coordination (POL-4 part 3; D72/D53/D36,
/// doc 13 §5, doc 15 §5.2). The frozen D72 contract requires EVERY consumer to sweep
/// post-commit and report a swept seq that feeds the host heartbeat's MIN over the
/// three consumers. ds-tlsproxy holds NO cached derived state today (its allow/deny
/// decisions are live `policy-core` queries, not a cached set like ds-nft's allow-set
/// or ds-dnsgate's admission map), so its sweep re-evaluates nothing, evicts nothing,
/// and returns the committed snapshot seq UNCHANGED — a no-op that completes instantly
/// and contributes that seq to the min-over-three. The [`sweep::DerivedState`] seam is
/// the forward-compatible extension point: a future TLS-path derived state (cached
/// identity tokens with TTLs, a re-evaluable TLS-policy cache) plugs in behind the SAME
/// [`sweep::SweepReport`] contract without changing the barrier. `crate::apply`'s
/// `sweep_and_advance_applied_seq` drives [`sweep::sweep_noop`] post-commit (and the
/// host coordinator drives the `SweepSnapshots`-shaped [`sweep::sweep_snapshots`]) so
/// `applied_seq` advances ONLY after the sweep completes (D72).
pub mod sweep;

/// TLS-2 explicit-proxy modes — the HTTP `CONNECT` endpoint and the plain-HTTP
/// (port 80) forward proxy (doc 09 §5 TLS-2; doc 12 §13.1 `connect/`). Both modes
/// evaluate the IDENTICAL `policy-core` rules as the transparent path; the real
/// pingora listener / `SO_MARK` connect plumbing is the documented seam.
pub mod explicit;

/// The NFT-2 transparent path (doc 03 §3; doc 09 NFT-2; doc 12 §2/§2.1/§13.1;
/// D2/D40/D69) — the `accept/` redirect listener's framework-agnostic core: the
/// frozen mechanism-agnostic `ConnOrigin` recovery seam (kernel-only `original_dst`
/// via the `SO_ORIGINAL_DST`/`IP6T_SO_ORIGINAL_DST` getsockopt — the same mechanism
/// Pingora's stock `SocketDigest::original_dst()` performs — paired with an
/// interface-anchored `session`, refuse-on-recovery-failure, mechanism-independent
/// admission signature) plus the opaque-tunnel forward splice. The real
/// `pingora-core` listener that binds `:18080`/`:18443` and attaches the per-tap
/// session is the documented wiring seam (doc 12 §13.1); the live iifname-REDIRECT
/// demo is reboot-pending (kernel nft nat/redirect modules absent) — see
/// `SPIKE-NOTES.md`.
///
/// It ALSO hosts the **TLS-7 body-filter integration seam** (doc 09 §5 TLS-7; doc
/// 12 §5.1 / §5.2 / §13.5; D73/D40): the pingora-free
/// [`transparent::request_body_scan`] entry point that drives one cleartext chunk of
/// the inspected (TLS-3-terminated) request body through a proxy-owned
/// [`scan::ScanGate`] over a [`scan::DigestSetMatcher`] and returns the
/// [`scan::Verdict`] + the COUNT of bytes the matcher cleared for egress. It is the
/// documented join between the pingora-free scan core ([`scan`]) and the body-filter
/// call shape, honoring the three frozen contracts the gate owns — the hold-back
/// invariant (no byte released until the matcher says so, retaining up to
/// `max_secret_len - 1` trailing bytes for a boundary-spanning secret),
/// fail-closed-when-keyed (a present-but-unsealed keyed plane Holds, releasing
/// nothing — mint-before-attach, D109), and direction-symmetry (v0 egress-only).
/// The LIVE body-filter wiring — the real pingora `TlsAccept` resolver integration
/// and the per-chunk hook install — is a DEFERRED `src/main.rs` unit behind
/// `DS_TLS3_LIVE` (exactly as the TLS-3 inspected path is gated; the TLS-4
/// pass-through arm never reaches it, D17/D74). This is the documented seam + a
/// no-op test harness only, so the default (`DS_TLS3_LIVE` unset) path stays
/// byte-identical and the seam appears in no boundary test name.
pub mod transparent;

/// The TLS-1 admission core (doc 09 §5 TLS-1; doc 12 §2.1/§4.1; doc 03 §3 OQ1;
/// D68/D69/D40) — the SNI-checked transparent-tunnel decision that runs after
/// `ConnOrigin` recovery and before the opaque tunnel opens on `:18443`. It peeks
/// the ClientHello SNI (no TLS termination), refuses the ECH / absent-SNI /
/// IP-literal edges, runs the FORWARD admission check that closes the CDN
/// shared-IP hole (`AdmissionMap.lookup(session, sni_domain)` then
/// `original_dst ∈ admitted_ips`, never a reverse any-domain query), and decides
/// D68 re-admit-not-refuse for a policy-allowed domain with no live admission. The
/// module speaks only [`transparent::ConnOrigin`] + a [`tls1_admission::PolicyOracle`]
/// + the `ds_contracts` admission map — no pingora type (D40); the listener layer
/// (`src/main.rs`) owns the pingora I/O and drives the [`tls1_admission::decide`]
/// verdict.
///
/// It also hosts the TLS-4 pass-through MODE refinement (doc 12 §3, D17/D74): an
/// already-admitted flow whose SNI is on the policy-configured pass-through list
/// ([`tls1_admission::PassthroughList`]) returns the distinct
/// [`tls1_admission::Tls1Decision::Passthrough`] verdict (opaque tunnel, frozen
/// against TLS termination) instead of [`tls1_admission::Tls1Decision::Tunnel`]
/// (opaque tunnel, eligible for the TLS-3 inspected path). The list is POLICY, not
/// code, and ships EMPTY per D74 ([`tls1_admission::EmptyPassthroughList`]), so the
/// shipped [`tls1_admission::decide`] path is unchanged; the pass-through-aware
/// [`tls1_admission::decide_with_passthrough`] is the additive entry the listener
/// binds to the live snapshot's pass-through set when TLS-4 is wired.
pub mod tls1_admission;

/// The TLS-1 ClientHello **peek** — the production coalescing read loop + the
/// cross-record handshake-message reassembly (doc 12 §4.1 / §4.1.1; doc 09 §5
/// TLS-1; D68/D69/D40), lifted out of `src/main.rs` into a `pub`, framework-agnostic
/// library entry point so both the production listener and the live fragment harness
/// drive the ONE cursor + reassembly instead of a re-implementation. Hosts the three
/// frozen §4.1.1 fail-closed cost bounds ([`clienthello_peek::CLIENT_HELLO_PEEK_MAX`]
/// = 16 KiB byte cap, [`clienthello_peek::MAX_CLIENT_HELLO_RECORDS`] = 512-record
/// cursor-advanced coalescing cap, [`clienthello_peek::MAX_CLIENT_HELLO_EMPTY_RECORDS`]
/// = 8-record zero-progress cap), the resumable [`clienthello_peek::SpanScan`] +
/// [`clienthello_peek::HandshakeSpan`] accounting, the [`clienthello_peek::PeekedPrefix`]
/// outcome (raw replay bytes + the distinct tiny-record-flood pre-parse refusal), and
/// the [`clienthello_peek::reassemble_handshake_message`] parser view. It exposes BOTH
/// an async [`clienthello_peek::read_client_hello_prefix`] (over the pingora
/// [`tokio::io::AsyncRead`] `Stream`) and a blocking
/// [`clienthello_peek::read_client_hello_prefix_blocking`] (over a real
/// [`std::io::Read`] socket for the harness), which share ONE loop body + one set of
/// fail-closed branches. No pingora type appears here (D40); `src/main.rs` re-points
/// its `peek_client_hello` `Stream` wrapper at the async helper without forking logic.
///
/// Defined INLINE (not a sibling `clienthello_peek.rs`) so the peek-helper lift lands
/// in `lib.rs` + `main.rs` + the fragment harness only, matching the unit's file scope
/// — the same convention the TLS-8 [`websocket`] module follows.
pub mod clienthello_peek {
    // The TLS-1 ClientHello peek — the production coalescing read loop + the
    // cross-record handshake-message reassembly, lifted out of `src/main.rs`. See the
    // outer `///` module doc above for the full charter (doc 12 §4.1 / §4.1.1; doc 09
    // §5 TLS-1; D68/D69/D40).
    //
    // # Why this is a library module (the anti-drift lift)
    //
    // Before the peek needs an admission decision it must extract the SNI, which means
    // reading the client's first flight off the accepted socket and coalescing a
    // (possibly record-fragmented, RFC 8446 §5.1) ClientHello into one handshake
    // message. That read loop runs on ATTACKER-supplied bytes before any decision, so
    // every one of its three §4.1.1 cost bounds must fail **closed**:
    //
    // - [`CLIENT_HELLO_PEEK_MAX`] — 16 KiB total-bytes cap (`O(1)` buffer);
    // - [`MAX_CLIENT_HELLO_RECORDS`] — 512-record cursor-advanced coalescing cap (a
    //   tiny-record flood costs `O(record-count)`, never `O(records²)` or `O(bytes)`);
    // - [`MAX_CLIENT_HELLO_EMPTY_RECORDS`] — 8-record zero-progress cap (an empty-record
    //   flood is cut off far below the record cap).
    //
    // This logic used to be PRIVATE to the binary crate, forcing the live fragment
    // harness (`tests/clienthello_fragment_live.rs`) to RE-IMPLEMENT the coalescing peek
    // + reassembly test-side — a parallel-implementation drift risk against exactly the
    // read-shape bugs the harness exists to catch. Lifting it here lets both the
    // production listener (`src/main.rs`, over the pingora [`tokio::io::AsyncRead`]
    // `Stream`) and the harness (over a real blocking [`std::io::Read`] socket) drive the
    // ONE cursor and the ONE reassembly, so a divergence can no longer hide.
    //
    // # Behaviour is preserved verbatim
    //
    // This is a pure LIFT — every constant, every fail-closed branch, the [`SpanScan`]
    // cursor accounting, [`reassemble_handshake_message`], and the [`PeekedPrefix`]
    // outcome shape are byte-for-byte what `src/main.rs` ran. `src/main.rs` re-points at
    // these `pub` helpers; it does NOT fork the logic. The in-tree unit tests over
    // `reassemble_handshake_message` (in `src/main.rs`) stay green unchanged.
    //
    // The crate-root `#![forbid(unsafe_code)]` (above) binds this inline module too;
    // it is stdlib + tokio-io only, unsafe-free by construction.

    use tokio::io::{AsyncRead, AsyncReadExt};

    /// The maximum ClientHello prefix the TLS-1 gate peeks off an HTTPS connection
    /// before deciding (doc 12 §4.1). A ClientHello — even a fat one carrying ALPN,
    /// supported_versions, key_share, and a long server_name — comfortably fits well
    /// under ~16 KiB; the parser is bounds-checked and total, so a ClientHello that
    /// does not fit (or a non-TLS first record) simply refuses as `NotAClientHello`.
    /// We read up to this many bytes, run the decision over the reassembled prefix,
    /// and replay the buffered bytes upstream verbatim on a tunnel so the VM's real
    /// TLS handshake reaches the origin unmodified.
    ///
    /// The peek coalesces fragmentation at **both** layers. A fat first flight can be
    /// split across TCP segments, and — legally per RFC 8446 §5.1 — a single
    /// ClientHello *handshake message* can also be fragmented across multiple
    /// consecutive TLS *records* (each with its own 5-byte record header). The
    /// read-until-complete loop in [`read_client_hello_prefix`] accumulates successive
    /// handshake records (content type `0x16`), concatenating their payloads, until the
    /// 24-bit handshake-message length declared in the first record's handshake header
    /// is satisfied — then parses the SNI off the reassembled message.
    ///
    /// This is also the **fail-closed cap** on that loop: if reassembling the complete
    /// handshake message would push the buffered prefix past this bound, the loop does
    /// NOT keep reading toward it — it returns the bytes-so-far (bounded by the cap) and
    /// the parser refuses (`NotAClientHello`). A larger-than-cap ClientHello — whether
    /// in one record or fragmented across many — therefore still refuses; the cap never
    /// weakens the boundary, it only bounds how much we will buffer to make a fragmented
    /// first flight whole. The full buffered prefix (every record, byte-identical) is
    /// what gets replayed upstream so the opaque tunnel stays verbatim.
    pub const CLIENT_HELLO_PEEK_MAX: usize = 16 * 1024;

    /// The maximum number of consecutive TLS records the peek will coalesce into one
    /// ClientHello handshake message before refusing fail-closed (doc 12 §4.1).
    ///
    /// **Why an explicit record cap, separate from the byte cap.** [`CLIENT_HELLO_PEEK_MAX`]
    /// already bounds the *total bytes* buffered, so an adversary cannot make the peek
    /// allocate unbounded memory. But it does NOT, on its own, bound the *number of records*
    /// or the per-record work: a peer may split the handshake into a flood of tiny records
    /// (each a 5-byte header + as little as ONE — or even ZERO — handshake-layer payload
    /// bytes), so the buffer fills toward the byte cap only after `cap / 6` (~2.7K) records.
    /// Any walk that resumes from record zero each read would then be O(records²) — a cost
    /// whose ceiling falls out INCIDENTALLY from the small byte cap rather than being an
    /// explicit, documented bound. This constant makes the bound explicit and INDEPENDENT
    /// of the byte-cap value: the coalescing walk advances a cursor (it never re-scans the
    /// whole buffer, [`SpanScan`]) AND refuses once more than this many records have been
    /// coalesced. A flood of tiny records therefore costs `O(MAX_CLIENT_HELLO_RECORDS)` and
    /// then REFUSES fail-closed (`NotAClientHello`) — never the byte cap's incidental ceiling.
    ///
    /// The value is set comfortably above any *legitimate* record-fragmented ClientHello:
    /// even a pathological-but-honest peer that sends one handshake byte per record needs
    /// only ~`hs_len` records (a few hundred for a fat first flight), well under this cap,
    /// so legit fragmentation still coalesces and parses. It is far below the ~2.7K records
    /// the byte cap alone would otherwise admit, so the record bound — not the byte cap —
    /// is what stops a tiny-record flood. The bound NEVER weakens the boundary: hitting it
    /// refuses (the existing fail-closed `OverCap` path), it only makes the flood cheap.
    pub const MAX_CLIENT_HELLO_RECORDS: usize = 512;

    /// The number of *no-progress* records the coalescing walk tolerates before refusing
    /// fail-closed (doc 12 §4.1). A "no-progress" record is a handshake record (content type
    /// `0x16`) whose declared payload contributes ZERO handshake-layer bytes toward the
    /// outstanding handshake-message length — an empty (`length == 0`) record, the cheapest
    /// possible flood unit (pure 5-byte headers).
    ///
    /// **Why a separate no-progress budget on top of the record cap.** A one-*byte* record
    /// makes one byte of progress, so a legit (if pathological) peer that fragments to a
    /// single handshake byte per record is bounded by [`MAX_CLIENT_HELLO_RECORDS`] and the
    /// handshake length. A *zero*-byte record makes no progress at all: an unbounded run of
    /// them would consume the record budget while covering none of the message, so we give
    /// empty records their own small budget and refuse as soon as it is exhausted — the
    /// per-record MINIMUM-PROGRESS rule. This is strictly tighter than the record cap (an
    /// honest fragmented ClientHello carries data in every record, so it spends none of this
    /// budget); it exists so a flood that interleaves empty records cannot stretch the work
    /// out. Exhausting it REFUSES fail-closed exactly like the record cap.
    pub const MAX_CLIENT_HELLO_EMPTY_RECORDS: usize = 8;

    /// The TLS record header is `content_type(1) version(2) length(2)` — 5 bytes — and
    /// the 16-bit big-endian record length sits at offset 3..5. Once we have buffered
    /// at least this many bytes we know the full record length and can stop reading
    /// exactly when `5 + record_len` bytes are in hand.
    pub const TLS_RECORD_HEADER_LEN: usize = 5;

    /// The TLS content type for a handshake record (`0x16`). A ClientHello record — and
    /// every record we coalesce into the reassembled handshake message — carries this
    /// type; the first non-handshake content type ends the coalescing (the
    /// `read_client_hello_prefix` loop stops there and the parser owns the refusal).
    pub const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

    /// The TLS handshake-message header is `msg_type(1) length(3)` — 4 bytes — sitting
    /// at the very start of the handshake-layer byte stream (the first record's
    /// payload). The 24-bit big-endian length at offset 1..4 is the size of the
    /// handshake *body*; the complete handshake message is `4 + body_len` bytes of
    /// handshake-layer data, which may be spread across several TLS records.
    pub const TLS_HANDSHAKE_HEADER_LEN: usize = 4;

    /// Read the ClientHello handshake message off `reader`, looping until the message
    /// is COMPLETE — coalescing it across one OR MORE consecutive TLS handshake records
    /// (RFC 8446 §5.1) — capped at `cap`. Returns the raw on-wire bytes verbatim (every
    /// record header included), so the caller can replay them upstream byte-identical.
    ///
    /// Generic over any [`AsyncRead`] so the loop is exercised in `#[cfg(test)]` with a
    /// synthetic reader that hands the bytes back in N fragments (no live network); the
    /// production caller passes the pingora `Stream`.
    ///
    /// Behaviour (all fail-closed-preserving — a prefix the parser cannot accept simply
    /// refuses):
    ///
    /// - Read in a loop, accumulating into `buf`.
    /// - [`handshake_message_span`] walks the buffered records: once the first record's
    ///   handshake header is in hand it knows the total handshake-message length
    ///   (`4 + body_len`), and it sums successive handshake records' payloads until that
    ///   many handshake-layer bytes are covered. When complete it returns the exact raw
    ///   byte count (`Complete`) — the full set of record bytes that carry the message —
    ///   and the loop stops there (the splice carries the remainder). A non-handshake
    ///   content type seen while still reassembling ends coalescing (`StopBuffering`).
    /// - **Cap (fail-closed):** if completing the handshake message would require buffering
    ///   past `cap`, we do NOT keep reading toward it — we return the bytes-so-far
    ///   (truncated to `cap`), and the parser refuses (`NotAClientHello`). An over-cap
    ///   ClientHello (single record or fragmented) therefore still refuses. We also never
    ///   let the buffer itself grow past `cap`.
    /// - **EOF / read error before the message is whole:** return the bytes-so-far. A
    ///   truncated message fails the bounds-checked parse → `NotAClientHello` refusal.
    /// - A non-TLS / garbage first byte still yields a buffer the parser refuses; we do
    ///   not special-case it here (the parser is the single total decision point).
    ///
    /// The read-shape twin over a blocking [`std::io::Read`] is
    /// [`read_client_hello_prefix_blocking`]; both drive the SAME [`SpanScan`] cursor +
    /// [`SpanScan::advance`] accounting (via the shared [`PeekStep`] decision), so there
    /// is no parallel coalescing loop.
    pub async fn read_client_hello_prefix<R>(reader: &mut R, cap: usize) -> PeekedPrefix
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        let (mut buf, mut chunk, mut scan) = peek_init(cap);

        loop {
            match peek_step(&mut buf, &mut scan, cap) {
                PeekStep::Return(prefix) => return prefix,
                PeekStep::Read { take } => match reader.read(&mut chunk[..take]).await {
                    // EOF before the message is whole: return bytes-so-far (parser refuses a
                    // truncated message). This preserves fail-closed — a peek that cannot
                    // complete still refuses.
                    Ok(0) => return PeekedPrefix::bytes(buf),
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    // Read error before the message is whole: same fail-closed shape as EOF.
                    Err(_) => return PeekedPrefix::bytes(buf),
                },
            }
        }
    }

    /// The blocking-[`std::io::Read`] twin of [`read_client_hello_prefix`], for callers
    /// that peek off a REAL blocking socket (the live fragment harness's `:18443`-style
    /// listener) rather than the async pingora `Stream`. It drives the SAME [`SpanScan`]
    /// cursor and [`SpanScan::advance`] accounting through the SAME [`peek_step`] decision
    /// — so it is NOT a parallel reimplementation of the coalescing loop; only the read
    /// primitive differs (`std::io::Read::read` vs `AsyncReadExt::read`). Every §4.1.1
    /// bound (byte cap, record cap, empty-record cap) and every fail-closed branch is the
    /// production one.
    ///
    /// Returns the same [`PeekedPrefix`] shape: the raw on-wire prefix (byte-identical to
    /// the wire, every record header) plus the optional pre-parse refusal (the tiny-record
    /// flood) the coalescing loop decided.
    pub fn read_client_hello_prefix_blocking<R>(reader: &mut R, cap: usize) -> PeekedPrefix
    where
        R: std::io::Read + ?Sized,
    {
        let (mut buf, mut chunk, mut scan) = peek_init(cap);

        loop {
            match peek_step(&mut buf, &mut scan, cap) {
                PeekStep::Return(prefix) => return prefix,
                PeekStep::Read { take } => match reader.read(&mut chunk[..take]) {
                    // EOF before the message is whole: return bytes-so-far (parser refuses).
                    Ok(0) => return PeekedPrefix::bytes(buf),
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    // Read error before the message is whole: same fail-closed shape as EOF.
                    Err(_) => return PeekedPrefix::bytes(buf),
                },
            }
        }
    }

    /// Allocate the peek loop's working state: the accumulating raw buffer, the scratch
    /// read chunk, and the resumable [`SpanScan`] cursor. Shared by the async and blocking
    /// peek entry points so both start from an identical state.
    fn peek_init(cap: usize) -> (Vec<u8>, Vec<u8>, SpanScan) {
        let buf: Vec<u8> = Vec::with_capacity(cap.min(TLS_RECORD_HEADER_LEN + 512));
        let chunk = vec![0u8; cap.clamp(1, 16 * 1024)];
        // The resumable coalescing cursor: it carries `raw`/`hs_seen`/record counts across
        // reads, so the per-read walk re-scans only the in-flight record (O(records) total,
        // not O(records²)) AND enforces the explicit record-count + no-progress bounds — a
        // tiny-record flood is refused on record COUNT, independent of the byte cap.
        (buf, chunk, SpanScan::new())
    }

    /// One iteration of the peek loop's DECISION over the bytes buffered so far — the
    /// runtime-agnostic core the async and blocking read loops share. It advances the
    /// [`SpanScan`] cursor and maps the [`HandshakeSpan`] outcome to either a terminal
    /// [`PeekedPrefix`] (complete / over-cap / flood / non-handshake / cap reached) or a
    /// bounded next-read request. It NEVER touches the socket — the caller performs the
    /// read (async or blocking) when told to — so the two entry points share one loop body
    /// and one set of fail-closed branches.
    fn peek_step(buf: &mut Vec<u8>, scan: &mut SpanScan, cap: usize) -> PeekStep {
        // Stop once the whole ClientHello handshake message is buffered (coalesced
        // across however many consecutive handshake records it spans). The cursor resumes
        // from its last committed record rather than re-walking the whole buffer.
        match scan.advance(buf, cap) {
            HandshakeSpan::Complete(want) => {
                // `want` is bounded by `cap` (the span calculator refuses over-cap),
                // and `buf.len() >= want` here. Trim any read-ahead past the message
                // so the replay prefix is EXACTLY the message's records — the splice
                // carries the rest of the flight (never sent upstream twice).
                buf.truncate(want);
                return PeekStep::Return(PeekedPrefix::bytes(std::mem::take(buf)));
            }
            HandshakeSpan::OverCap => {
                // Completing the message would exceed `cap` — do not read toward it.
                // Fail-closed: return the bytes-so-far (bounded by cap); the parser
                // refuses NotAClientHello (DISTINCT from the tiny-record flood below).
                //
                // ── DECISION (8AMX-u2): OverCap COLLAPSES into NotAClientHello; it does
                //    NOT get its own additive RefuseReason variant. ──────────────────────
                // Rationale. OverCap is, observably, a *parse-level truncation*: the
                // complete ClientHello handshake message would need more than the 16 KiB
                // peek cap (CLIENT_HELLO_PEEK_MAX), so we return the truncated-to-cap
                // prefix and the bounds-checked SNI parser hits underrun and refuses
                // `NotAClientHello`. From the byte-level parser's view an over-cap prefix
                // is INDISTINGUISHABLE from any other truncated/garbage first record —
                // they are the SAME observable state (a prefix that does not parse to a
                // whole ClientHello). That indistinguishability is INHERENT to the byte
                // cap, so a distinct telemetry code would carry no information the bytes
                // themselves don't already justify lumping together.
                //
                // CONTRAST with the tiny-record flood (TooManyRecords ->
                // RefuseReason::ClientHelloFlood, the arm below). A flood ALSO yields a
                // truncated prefix that parses to NotAClientHello, but the record-COUNT
                // bound that fired is a fact ONLY the coalescing loop holds — the byte-level
                // parser CANNOT recover it from the prefix. That hidden, out-of-band signal
                // is exactly why the flood earns a distinct code (threaded via
                // `PeekedPrefix::flood`): it is a bounded-cost resource-exhaustion edge an
                // operator wants to aggregate apart from ordinary garbage. OverCap has NO
                // such hidden signal — the truncation IS the parse failure, with nothing
                // extra to surface.
                //
                // TRADEOFF (and why collapse wins). A separate `ClientHelloOverCap` code
                // would let an operator count ">16 KiB first flights" as their own bucket.
                // But (a) that category is not an abuse signal distinct from "malformed /
                // oversized first record" — the supported curl/git/npm/SDK client set fits
                // comfortably under the cap (doc 12 §4.1), so a legit client tripping it is
                // already the same "too big / malformed to peek" triage bucket as
                // tls1-not-a-clienthello; and (b) the §10/LOG-1 reason-code set is frozen
                // additive-only (doc 14 §2) — minting a code with no consumer SPLITS one
                // triage bucket for no aggregation benefit and grows the frozen surface.
                // So OverCap deliberately keeps `refuse: None` and defers to the single SNI
                // parser decision point (`NotAClientHello`), unlike the flood arm below.
                buf.truncate(cap);
                return PeekStep::Return(PeekedPrefix::bytes(std::mem::take(buf)));
            }
            // A tiny-record flood crossed the explicit record-count / no-progress bound
            // before the message was whole (MAX_CLIENT_HELLO_RECORDS or
            // MAX_CLIENT_HELLO_EMPTY_RECORDS exhausted). The cost is bounded by record
            // COUNT (not the byte cap); refuse fail-closed — but with a DISTINCT signal,
            // `RefuseReason::ClientHelloFlood`, so the §10 telemetry tells a flood apart
            // from the generic NotAClientHello refusal the truncated prefix would parse to.
            // The buffered prefix (bounded by cap) is still carried so the close path is
            // byte-identical to the other fail-closed arms; the flood reason short-circuits
            // the SNI parse at the gate.
            HandshakeSpan::TooManyRecords => {
                buf.truncate(cap);
                return PeekStep::Return(PeekedPrefix::flood(std::mem::take(buf)));
            }
            // A non-handshake record appeared while still reassembling: stop reading
            // and let the parser refuse the (now-incomplete) prefix. Fail-closed.
            HandshakeSpan::StopBuffering => {
                return PeekStep::Return(PeekedPrefix::bytes(std::mem::take(buf)))
            }
            // Need more bytes — keep reading (subject to the cap below).
            HandshakeSpan::Incomplete => {}
        }

        // Never read past the cap (defence-in-depth even before the length is known —
        // e.g. a header that never arrives within `cap` bytes).
        if buf.len() >= cap {
            buf.truncate(cap);
            return PeekStep::Return(PeekedPrefix::bytes(std::mem::take(buf)));
        }

        // Bound this read so the buffer cannot overshoot `cap`.
        let room = cap - buf.len();
        let take = room.min(cap.clamp(1, 16 * 1024));
        PeekStep::Read { take }
    }

    /// The outcome of one [`peek_step`]: either the peek is DONE (a terminal
    /// [`PeekedPrefix`]) or the caller must read up to `take` more bytes and step again.
    enum PeekStep {
        /// The peek decided a terminal outcome — return this prefix.
        Return(PeekedPrefix),
        /// Need more bytes; read up to `take` into the scratch chunk, then step again.
        Read { take: usize },
    }

    /// The outcome of peeking the ClientHello prefix off an accepted stream
    /// ([`read_client_hello_prefix`] / the `peek_client_hello` `Stream` wrapper in
    /// `src/main.rs`): the raw on-wire bytes read so far (always replayed upstream verbatim
    /// on a `Proceed`, and the input the TLS-1 gate parses), PLUS an optional pre-parse
    /// refusal the PEEK itself decided.
    ///
    /// The only pre-parse refusal today is the **tiny-record flood**
    /// ([`crate::tls1_admission::RefuseReason::ClientHelloFlood`]): the record-coalescing
    /// loop crossed [`MAX_CLIENT_HELLO_RECORDS`] / [`MAX_CLIENT_HELLO_EMPTY_RECORDS`] before
    /// the handshake message was whole. The peek owns that distinction (it is a record-COUNT
    /// bound the byte-level SNI parser cannot see — a truncated flood prefix would otherwise
    /// parse to the generic [`crate::tls1_admission::RefuseReason::NotAClientHello`]), so it
    /// carries the distinct reason out to the gate, which short-circuits to
    /// `Refuse(ClientHelloFlood)` WITHOUT re-parsing. Every other peek outcome (complete,
    /// over-cap, EOF, non-handshake) carries `refuse: None` — the byte-identical fail-closed
    /// path where the SNI parser is the single decision point.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PeekedPrefix {
        /// The raw on-wire prefix bytes (replayed upstream verbatim; parsed by the gate).
        pub bytes: Vec<u8>,
        /// A refusal the peek decided before the SNI parse (currently only the tiny-record
        /// flood). `None` ⇒ the byte-identical default path: the SNI parser decides.
        pub refuse: Option<crate::tls1_admission::RefuseReason>,
    }

    impl PeekedPrefix {
        /// A peek that defers entirely to the SNI parser (no pre-parse refusal). This is
        /// the byte-identical default for every non-flood outcome.
        pub fn bytes(bytes: Vec<u8>) -> PeekedPrefix {
            PeekedPrefix {
                bytes,
                refuse: None,
            }
        }

        /// A peek the record-coalescing loop refused as a tiny-record flood
        /// ([`crate::tls1_admission::RefuseReason::ClientHelloFlood`]) — the
        /// `HandshakeSpan::TooManyRecords` outcome. The bytes are still carried (bounded by
        /// the byte cap) for a byte-identical close path; the gate short-circuits on the
        /// distinct reason rather than parsing the truncated prefix to `NotAClientHello`.
        pub fn flood(bytes: Vec<u8>) -> PeekedPrefix {
            PeekedPrefix {
                bytes,
                refuse: Some(crate::tls1_admission::RefuseReason::ClientHelloFlood),
            }
        }
    }

    /// The outcome of walking the buffered records to see how much we still need to
    /// buffer before the ClientHello handshake message is whole.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HandshakeSpan {
        /// More bytes are needed (a record header or payload, or the handshake header,
        /// has not fully arrived yet) — keep reading.
        Incomplete,
        /// The handshake message is complete and fits within the cap: the buffer holds at
        /// least this many raw bytes, and exactly this many carry the message's records.
        Complete(usize),
        /// Completing the handshake message would require buffering past the cap — refuse
        /// fail-closed (do not read toward it).
        OverCap,
        /// The coalescing walk hit an explicit record bound before the message was whole — a
        /// tiny-record flood: either more than [`MAX_CLIENT_HELLO_RECORDS`] records have been
        /// coalesced, or more than [`MAX_CLIENT_HELLO_EMPTY_RECORDS`] zero-progress (empty)
        /// records were seen. Refuse fail-closed (same shape as [`HandshakeSpan::OverCap`]),
        /// so the cost of a tiny-record flood is bounded by record COUNT, not the byte cap.
        TooManyRecords,
        /// A non-handshake content type was seen while still reassembling (a malformed /
        /// non-TLS first flight): stop buffering and let the parser refuse the prefix.
        StopBuffering,
    }

    /// A resumable cursor over the consecutive TLS records buffered so far — the
    /// "progress cursor" that makes the coalescing walk cost `O(records)`, not
    /// `O(records²)`, and bounds it by record COUNT independent of the byte cap.
    ///
    /// The read loop owns ONE `SpanScan` for the whole peek and calls [`SpanScan::advance`]
    /// after each `read`. The cursor remembers the last fully-walked record boundary
    /// (`raw`), the handshake-layer bytes covered so far (`hs_seen`), and how many records
    /// (total + zero-progress) it has coalesced. On the next read it RESUMES from `raw`
    /// rather than re-scanning every record from offset zero — so a flood of `N` tiny
    /// records that arrive one per read costs `O(N)` total walking, not `O(N²)`. It also
    /// enforces the explicit [`MAX_CLIENT_HELLO_RECORDS`] / [`MAX_CLIENT_HELLO_EMPTY_RECORDS`]
    /// bounds as it advances: a flood is refused on the record count, never on the
    /// incidental byte-cap ceiling.
    ///
    /// A boundary that depends on bytes not yet buffered (a record header or payload still
    /// in flight) does NOT advance `raw` past it — the cursor only commits a record once it
    /// is fully accounted, so resuming after more bytes arrive re-reads ONLY the in-flight
    /// record, never the committed prefix.
    #[derive(Debug, Clone, Copy)]
    pub struct SpanScan {
        /// Raw-byte offset of the next not-yet-committed record (headers + payloads of all
        /// committed records). The walk resumes here.
        raw: usize,
        /// Handshake-layer bytes covered by the committed records so far.
        hs_seen: usize,
        /// Total records committed so far (the explicit record-count bound counts these).
        records_seen: usize,
        /// Zero-progress (empty-payload) records committed so far (the no-progress budget).
        empty_records_seen: usize,
    }

    impl Default for SpanScan {
        fn default() -> Self {
            SpanScan::new()
        }
    }

    impl SpanScan {
        /// A fresh cursor at the start of the buffer.
        pub fn new() -> SpanScan {
            SpanScan {
                raw: 0,
                hs_seen: 0,
                records_seen: 0,
                empty_records_seen: 0,
            }
        }

        /// The total number of TLS records the cursor has committed so far — the value the
        /// [`MAX_CLIENT_HELLO_RECORDS`] bound counts. Read-only accessor so the coalescing
        /// unit tests can assert the cursor committed each record exactly once (no
        /// double-counting) without exposing the mutable field.
        pub fn records_seen(&self) -> usize {
            self.records_seen
        }

        /// Resume the coalescing walk over `buf` from the committed cursor and decide
        /// whether the ClientHello *handshake message* is complete, returning the exact raw
        /// byte count once it is.
        ///
        /// The ClientHello handshake message may legally span multiple TLS records (RFC 8446
        /// §5.1), each `content_type(1) version(2) length(2)` + `length` payload bytes. The
        /// handshake header (`msg_type(1) length(3)`) sits at the very start of the first
        /// record's payload; its 24-bit body length plus the 4-byte handshake header is the
        /// total handshake-layer byte count to cover. We sum successive handshake records'
        /// payloads until that many handshake-layer bytes are covered.
        ///
        /// Total over `buf` (never panics): every field is bounds-checked against what is
        /// buffered so far and underrun yields [`HandshakeSpan::Incomplete`]. Content type is
        /// validated here ONLY to bound coalescing — a non-handshake record ends it
        /// ([`HandshakeSpan::StopBuffering`]); the parser remains the single total decision
        /// point on the reassembled bytes. Exceeding the explicit record / no-progress
        /// bounds yields [`HandshakeSpan::TooManyRecords`] (fail-closed, like `OverCap`).
        pub fn advance(&mut self, buf: &[u8], cap: usize) -> HandshakeSpan {
            // The total handshake-layer bytes the message needs (handshake header + body).
            // The 4-byte handshake header itself may be fragmented across tiny records, so
            // this reassembles the first handshake bytes before reading the 24-bit length.
            let need_hs = match handshake_message_total_len(buf) {
                Some(n) => n,
                None => {
                    // Not enough handshake-layer bytes yet to know the length. But a
                    // non-handshake content type seen this early is already a fail-closed
                    // stop (never coalesce non-handshake records). A run of empty handshake
                    // records that never reveals the length is a no-progress flood — bound it.
                    if first_content_type_is_non_handshake(buf) {
                        return HandshakeSpan::StopBuffering;
                    }
                    return self.walk_for_bounds(buf);
                }
            };

            // Resume from the committed cursor: re-walk ONLY the in-flight (not-yet-committed)
            // records, never the whole buffer. `raw`/`hs_seen` carry forward across reads, and
            // a record is committed (counted, cursor advanced) ONLY once it is fully accounted
            // — so a record whose payload is still in flight is re-read next time, never the
            // committed prefix, and never double-counted against the bounds.
            while self.hs_seen < need_hs {
                // Need this record's 5-byte header to know its length.
                if buf.len() < self.raw + TLS_RECORD_HEADER_LEN {
                    return HandshakeSpan::Incomplete;
                }
                // Only handshake records (0x16) coalesce; a different content type while we
                // still owe handshake bytes is a malformed/non-TLS flight — stop buffering.
                if buf[self.raw] != TLS_CONTENT_TYPE_HANDSHAKE {
                    return HandshakeSpan::StopBuffering;
                }
                let record_len = ((buf[self.raw + 3] as usize) << 8) | (buf[self.raw + 4] as usize);
                // The handshake-layer bytes this record contributes are bounded by what the
                // message still needs (the final record may carry trailing non-handshake
                // bytes we must NOT pull into the replay prefix).
                let remaining_hs = need_hs - self.hs_seen;
                let hs_from_record = record_len.min(remaining_hs);
                // Raw bytes that carry those handshake bytes: the 5-byte header + the
                // handshake-layer slice of this record's payload.
                let record_raw_end = self.raw + TLS_RECORD_HEADER_LEN + hs_from_record;

                // Cap check BEFORE committing to read toward this record (fail-closed): if the
                // raw span needed to complete the message would exceed the cap, refuse.
                if record_raw_end > cap {
                    return HandshakeSpan::OverCap;
                }

                // The boundary this record reaches is confirmed only when the bytes that carry
                // its handshake contribution are buffered. If they are not, we cannot commit it
                // (counting it now would double-count it on the next read, and advancing `raw`
                // past unbuffered bytes would mis-resume) — keep reading and re-read this same
                // in-flight record next time. The cap check above already bounded the read.
                if buf.len() < record_raw_end {
                    return HandshakeSpan::Incomplete;
                }

                // Explicit record-count + no-progress bound (tiny-record flood, fail-closed):
                // count this NOW-COMPLETE record and refuse if it crosses the record cap, or if
                // its zero-progress contribution exhausts the empty-record budget. The bound is
                // on record COUNT, so the cost is independent of the byte cap.
                if let Some(refuse) = self.account_record(record_len) {
                    return refuse;
                }

                // Commit the record: advance the cursor so the next advance() resumes here and
                // does not re-walk the committed prefix.
                self.hs_seen += hs_from_record;
                self.raw = record_raw_end;
            }

            HandshakeSpan::Complete(self.raw)
        }

        /// Count one freshly-committed record against the explicit bounds, returning a
        /// fail-closed [`HandshakeSpan::TooManyRecords`] if it crosses the record cap or
        /// exhausts the no-progress (empty-record) budget; `None` if the record is in bounds.
        ///
        /// `record_len` is the record's DECLARED payload length: a zero-length record makes
        /// no progress toward the handshake message and spends the empty-record budget.
        fn account_record(&mut self, record_len: usize) -> Option<HandshakeSpan> {
            self.records_seen += 1;
            if self.records_seen > MAX_CLIENT_HELLO_RECORDS {
                return Some(HandshakeSpan::TooManyRecords);
            }
            if record_len == 0 {
                self.empty_records_seen += 1;
                if self.empty_records_seen > MAX_CLIENT_HELLO_EMPTY_RECORDS {
                    return Some(HandshakeSpan::TooManyRecords);
                }
            }
            None
        }

        /// Walk records purely to enforce the record / no-progress bounds when the handshake
        /// LENGTH is not yet known (the header is still arriving across tiny records). This
        /// bounds a flood whose records carry too little to ever reveal the 4-byte handshake
        /// header. It commits the cursor only for fully-buffered records, so it too resumes
        /// rather than re-walking. Returns [`HandshakeSpan::TooManyRecords`] on a bound,
        /// [`HandshakeSpan::Incomplete`] otherwise (the caller keeps reading).
        fn walk_for_bounds(&mut self, buf: &[u8]) -> HandshakeSpan {
            loop {
                if buf.len() < self.raw + TLS_RECORD_HEADER_LEN {
                    return HandshakeSpan::Incomplete;
                }
                if buf[self.raw] != TLS_CONTENT_TYPE_HANDSHAKE {
                    return HandshakeSpan::StopBuffering;
                }
                let record_len = ((buf[self.raw + 3] as usize) << 8) | (buf[self.raw + 4] as usize);
                let record_end = self.raw + TLS_RECORD_HEADER_LEN + record_len;
                // Only commit (and count) a record once its full declared payload is buffered;
                // otherwise wait for more bytes (and re-read just this in-flight record).
                if buf.len() < record_end {
                    return HandshakeSpan::Incomplete;
                }
                if let Some(refuse) = self.account_record(record_len) {
                    return refuse;
                }
                self.hs_seen += record_len;
                self.raw = record_end;
            }
        }
    }

    /// Walk the consecutive TLS records buffered in `buf` from the START and decide whether
    /// the ClientHello *handshake message* they carry is complete, returning the exact raw
    /// byte count (record headers + payloads) that carry it once it is.
    ///
    /// This is the stateless, full-buffer view used by [`reassemble_handshake_message`] and
    /// the direct unit tests; the read loop uses a resumable [`SpanScan`] instead so a
    /// tiny-record flood is walked once (O(records)) and bounded by record count. Both apply
    /// the same record / no-progress bounds, so a flood refuses identically here.
    pub fn handshake_message_span(buf: &[u8], cap: usize) -> HandshakeSpan {
        SpanScan::new().advance(buf, cap)
    }

    /// True once at least the first record's content-type byte is buffered and it is NOT
    /// a handshake record — the early fail-closed stop (we never coalesce, nor parse,
    /// anything that does not begin with a handshake record).
    pub fn first_content_type_is_non_handshake(buf: &[u8]) -> bool {
        matches!(buf.first(), Some(&ct) if ct != TLS_CONTENT_TYPE_HANDSHAKE)
    }

    /// The total handshake-layer byte count of the ClientHello — `4 + body_len`, where
    /// `body_len` is the 24-bit big-endian handshake length read from the 4-byte
    /// handshake header — or `None` if not enough handshake-layer bytes have arrived yet.
    ///
    /// The handshake header sits at the start of the *handshake-layer* byte stream (the
    /// concatenation of the records' payloads), which — under record-layer fragmentation
    /// — may itself be split across the first few (possibly 1-byte) records. So this
    /// reassembles the first [`TLS_HANDSHAKE_HEADER_LEN`] handshake-layer bytes across
    /// records before reading the length; it does NOT assume the header is contiguous at
    /// raw offset 5.
    ///
    /// This intentionally does NOT validate the record content type or the handshake
    /// message type beyond what the coalescing walk needs: it reads ONLY the length so
    /// the read loop knows how much handshake data to coalesce. The bounds-checked parser
    /// owns the single total is-this-a-ClientHello decision over the reassembled bytes.
    pub fn handshake_message_total_len(buf: &[u8]) -> Option<usize> {
        let header = first_handshake_bytes(buf, TLS_HANDSHAKE_HEADER_LEN)?;
        // header = [msg_type(1), len_hi, len_mid, len_lo]
        let body_len =
            ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
        Some(TLS_HANDSHAKE_HEADER_LEN + body_len)
    }

    /// Collect the first `k` handshake-layer bytes from the records buffered in `buf`,
    /// or `None` if fewer than `k` are available yet (or a non-handshake record blocks
    /// the way). The handshake-layer stream is the concatenation of consecutive handshake
    /// records' payloads (their 5-byte headers stripped); under record fragmentation it
    /// can span several records, so this walks records until `k` payload bytes are seen.
    ///
    /// Total over `buf` (never panics): a record header that has not fully arrived, or a
    /// payload not yet fully buffered, yields `None` (need more bytes); a non-handshake
    /// content type also yields `None` (the caller treats that as a fail-closed stop).
    pub fn first_handshake_bytes(buf: &[u8], k: usize) -> Option<[u8; TLS_HANDSHAKE_HEADER_LEN]> {
        debug_assert!(k <= TLS_HANDSHAKE_HEADER_LEN);
        let mut out = [0u8; TLS_HANDSHAKE_HEADER_LEN];
        let mut got = 0usize;
        let mut raw = 0usize;
        while got < k {
            if buf.len() < raw + TLS_RECORD_HEADER_LEN {
                return None; // record header not fully buffered yet
            }
            if buf[raw] != TLS_CONTENT_TYPE_HANDSHAKE {
                return None; // non-handshake record: no handshake header to read
            }
            let record_len = ((buf[raw + 3] as usize) << 8) | (buf[raw + 4] as usize);
            let payload_start = raw + TLS_RECORD_HEADER_LEN;
            // How many of this record's (buffered) payload bytes we can read.
            let buffered_payload = buf.len().saturating_sub(payload_start).min(record_len);
            for i in 0..buffered_payload {
                if got == k {
                    break;
                }
                out[got] = buf[payload_start + i];
                got += 1;
            }
            if got == k {
                break;
            }
            // Exhausted this record's buffered payload without reaching `k`. If the record
            // is not fully buffered we must wait; otherwise advance to the next record.
            if buf.len() < payload_start + record_len {
                return None;
            }
            raw = payload_start + record_len;
        }
        Some(out)
    }

    /// Reassemble the ClientHello handshake message from the raw multi-record peek prefix
    /// into a single synthetic handshake record the bounds-checked SNI parser (which reads
    /// ONE record header) can consume (doc 12 §4.1.1). The raw peek buffer may hold the
    /// ClientHello handshake message spread across several TLS records (RFC 8446 §5.1),
    /// each with its own 5-byte record header interleaved inside the handshake body — which
    /// would corrupt a naive single-record parse. So we strip every record's header,
    /// concatenate the handshake-layer payloads in order, and wrap the result under a
    /// single synthetic record header (`0x16` + legacy version + a 16-bit length of the
    /// reassembled handshake bytes). The synthetic length is informational only (the parser
    /// discards it); the handshake header + the body's own length fields govern the parse.
    ///
    /// **Total + fail-closed-preserving.** This is purely a *view* for the parser — it
    /// changes nothing replayed upstream. If `raw` does not look like a well-formed record
    /// sequence (too short for a record header, a non-handshake content type, or a record
    /// whose declared payload is not fully buffered), we return `raw` unchanged and let the
    /// parser render the refusal — the single record case returns a parse-equivalent buffer
    /// and a malformed prefix still refuses. It NEVER fabricates a parseable ClientHello out
    /// of bytes that were not on the wire.
    pub fn reassemble_handshake_message(raw: &[u8]) -> Vec<u8> {
        // Single-record fast path: if the first (and only) record's payload contains the
        // whole handshake message, the raw bytes are already in parser form — return them
        // unchanged so the single-record case is byte-for-byte the pre-coalescing input.
        if let HandshakeSpan::Complete(total) = handshake_message_span(raw, raw.len()) {
            if first_record_holds_whole_message(raw, total) {
                return raw.to_vec();
            }
        } else {
            // Not a complete, well-formed handshake message (truncated / non-handshake /
            // over the buffer): hand the raw bytes to the parser, which refuses.
            return raw.to_vec();
        }

        // Multi-record path: strip each record header and concatenate the handshake-layer
        // payloads in order, bounded by the handshake-message length so trailing bytes in
        // the final record (not part of the message) are not pulled in.
        let need_hs = match handshake_message_total_len(raw) {
            Some(n) => n,
            None => return raw.to_vec(),
        };
        let mut hs = Vec::with_capacity(need_hs);
        let mut raw_pos = 0usize;
        while hs.len() < need_hs {
            if raw.len() < raw_pos + TLS_RECORD_HEADER_LEN {
                // Underrun: not enough buffered to reassemble — refuse via the raw bytes.
                return raw.to_vec();
            }
            if raw[raw_pos] != TLS_CONTENT_TYPE_HANDSHAKE {
                return raw.to_vec();
            }
            let record_len = ((raw[raw_pos + 3] as usize) << 8) | (raw[raw_pos + 4] as usize);
            let payload_start = raw_pos + TLS_RECORD_HEADER_LEN;
            let remaining_hs = need_hs - hs.len();
            let take = record_len.min(remaining_hs);
            let payload_end = payload_start + take;
            if raw.len() < payload_end {
                return raw.to_vec();
            }
            hs.extend_from_slice(&raw[payload_start..payload_end]);
            raw_pos = payload_start + record_len;
        }

        // Wrap the reassembled handshake bytes under one synthetic record header. The
        // length field is the reassembled size (clamped to the 16-bit record length
        // field); the parser discards it, reading the handshake header + body lengths.
        let mut out = Vec::with_capacity(TLS_RECORD_HEADER_LEN + hs.len());
        out.push(TLS_CONTENT_TYPE_HANDSHAKE);
        out.extend_from_slice(&[0x03, 0x01]); // legacy record version (parser ignores it)
        let len_field = u16::try_from(hs.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len_field.to_be_bytes());
        out.extend_from_slice(&hs);
        out
    }

    /// Whether the first TLS record in `raw` carries the WHOLE handshake message of
    /// `hs_total` handshake-layer bytes — i.e. the common single-record case where no
    /// reassembly is needed. True when the first record's declared payload length is at
    /// least the full handshake message.
    pub fn first_record_holds_whole_message(raw: &[u8], hs_total: usize) -> bool {
        if raw.len() < TLS_RECORD_HEADER_LEN {
            return false;
        }
        let first_record_len = ((raw[3] as usize) << 8) | (raw[4] as usize);
        first_record_len >= hs_total
    }
}

/// The TLS-3 strict-WebPKI upstream re-origination leg (doc 12 §3, §13.5; doc 09
/// §5 TLS-3; D17/D82/D76/D40) — pingora-FREE. When the proxy terminates the VM's
/// TLS (the [`ca`] per-session CA mints the leaf the VM sees) the agent has
/// delegated its trust to us, so doc 12 §3 makes that safe by re-originating
/// upstream with **strict WebPKI validation** — "at least as strict as the
/// client's would have been". This module is the framework-agnostic core of that
/// leg: the pure, socket-free [`reoriginate::validate_origin_chain`] over
/// `rustls-webpki` (the §13.5 "upstream WebPKI fail → REFUSE upstream" verdict,
/// enforced BEFORE any payload byte), an injectable [`reoriginate::TrustRoots`]
/// provenance seam, and the [`reoriginate::UpstreamDialer`] trait that abstracts
/// the live tokio+rustls connector so the validation contract unit-tests with no
/// socket. The real connector (carrying the D76 `SO_MARK` before connect) and any
/// pingora type live in `src/main.rs` (D40); this module declares NONE. Additive
/// and dormant: the existing TLS-1 opaque-tunnel default path does not call it
/// until inspection is gated in a later unit, so that path stays byte-identical.
pub mod reoriginate;

/// The D46 pause/resume hold-and-buffer mechanics (doc 12 §12) — the proxy-side
/// consumer of the `hostagent.v1` transparent-suspend coordination marker. The
/// ≤5-min fully-transparent and 5–15-min best-effort tiers hold-and-buffer both
/// legs over the [`hold::Holdable`] seam and resume only after guest-clock
/// resync; the >15-min park tier consumes no marker and reaches this file's
/// [`SeveringRegistry`] `flush_session(legs=all)` via [`hold::park_teardown`].
pub mod hold;

/// The TLS-3 per-session interception CA + per-origin leaf authority (doc 12
/// §3 / §13.2; doc 16 §4; D17 / D82) — **pingora-free** crypto foundation the
/// TLS-3 termination path stacks on. [`ca::SessionCa`] holds ONE session's
/// interception CA cert + key as opaque ingested material (D82: minted by
/// Identity, ingested here) and mints + caches per-origin leaf certs whose only
/// SAN is the exact origin SNI. The leaf cache is keyed on origin-host (the
/// session is the partition = the `SessionCa` instance) and dropped whole at
/// teardown (doc 12 §13.2). No pingora type appears here (D40 / doc 12 §13.1):
/// the bin (`src/main.rs`) turns a minted [`ca::LeafCert`] into the pingora
/// `TlsAccept` resolver. The crate-root `#![forbid(unsafe_code)]` above binds
/// this module too (rcgen/rustls only — unsafe-free by construction).
pub mod ca;

/// TLS-3 per-request HTTP telemetry (doc 12 §3 / §5.5 / §10 / §13.1; doc 09 §5
/// TLS-3 done-when; D17/D82/D73) — **pingora-free**. Once TLS-3 terminates the
/// VM's TLS the inspected path can read the cleartext HTTP exchange; this module
/// builds the LOG-1 `EventHTTP` shape ([`telemetry_http::HttpEvent`] — method /
/// host / path / status, the boundary TLS-3.a field set) and the `EventError`
/// shape ([`telemetry_http::HttpErrorEvent`] — origin domain + the §13.5 WebPKI
/// refusal reason CODE, boundary TLS-3.b) from already-parsed primitives plus a
/// [`ds_contracts::session::SessionRef`] and the mandatory POL-3 provenance.
/// Never-log-the-secret (D73 §5.1) is a TYPE-LEVEL property: the events hold only
/// `String`/`u16`/enum fields — no body, no header value, no `Secret`. Mirrors
/// [`explicit::RequestTelemetry`]; the generated LOG-1 protos are not yet frozen
/// into `ds-contracts`, so (as `explicit` does) the shape is defined locally and
/// migrates onto the generated `EventHTTP`/`ErrorEvent` at the Stage-0 freeze. No
/// pingora type appears here (doc 12 §13.1): `main.rs` extracts the request line /
/// response status off the terminated stream and feeds these constructors plain
/// values.
///
/// It ALSO hosts the LOG-1 NETFLOW per-flow telemetry shapes (doc 03 §4; doc 09
/// §7 LOG-1/LOG-2; D43) — the proxy is the netflow system of record:
/// [`telemetry_http::FlowEvent`] (the closed/accounted per-flow record) and
/// [`telemetry_http::FlowStartEvent`] (the flow-open record) carry the LOG-2
/// session-attribution quartet, the [`telemetry_http::FlowProto`] L4 number, the
/// L3/4 `std::net::SocketAddr`-sourced endpoints + byte counters + start
/// timestamp, and the admitting-DNS-name joined from the DNS-2 stream — the exact
/// boundary LOG-1 `FlowRecord` field set, with NO HTTP-level field (that is
/// `HttpEvent`'s domain) and NO payload field (D73 type-level scrubbing; doc 03
/// §4 "full packet capture is explicitly out"). The
/// [`telemetry_http::AuditFlowEmitter`] trait is the §10 telemetry channel for
/// those records (mirrors the boundary `EventSink.Emit`). The INSPECTED-path
/// emission CALL-SITE — emit a [`telemetry_http::FlowStartEvent`] when the
/// re-originated upstream opens and the closing [`telemetry_http::FlowEvent`] (with
/// the final byte accounting + the admitting-DNS-name join + the mandatory POL-3
/// provenance off the TLS-1 decision) when it closes — lives in `main.rs` behind
/// `DS_TLS3_LIVE` (D40: the bin owns the pingora I/O + the §10 sink wiring; the
/// shape stays pingora-free here).
pub mod telemetry_http;

/// LOG-1 QUIC-reject `FlowRecord` telemetry (doc 12 §7; doc 14 §2 `FlowRecord`
/// `RejectReason` row; doc 09 §7 LOG-1; D70/D73) — **pingora-free**. D70 freezes
/// the udp/443 (QUIC) posture: the NFT-4 rule REJECTS udp/443 (icmp
/// port-unreachable, never silently dropped) and COUNTS every reject PER SESSION.
/// This module wires that signal into the proxy's LOG-1 emission path: it ingests
/// the kernel's NFT-4 reject events (nflog events OR a periodic per-session
/// counter snapshot — doc 12 §7 design seam) via [`telemetry_quic::QuicRejectTracker`],
/// accumulates them per session over the [`ds_telemetry::QuicRejectCounter`]
/// convention (per session, NEVER aggregated), and emits a
/// [`telemetry_quic::QuicRejectFlowRecord`] carrying
/// `reject_reason = [`ds_contracts::reject::RejectReason::QuicBlocked`]` (DISTINCT
/// from generic default-deny so the D70 flip-to-inspect trigger is queryable
/// off-box, doc 14 §2) and `reject_count = N` (the session-local reject count)
/// attributed to the originating session by its `dstap-<idx>` tap name (doc 14 §4).
/// Mirrors [`telemetry_http`]: the `RejectReason` enum is single-sourced from the
/// FROZEN `ds-contracts` contract (the D70 row), while the `FlowRecord` SHAPE is
/// defined locally (the generated LOG-1 protos are not yet frozen into
/// `ds-contracts`) and migrates onto the generated `FlowRecord` at the Stage-0
/// freeze. Never-log-the-secret (D73 §5.1) is a TYPE-LEVEL property: a reject
/// record holds only attribution + a `u64` count + the reason enum + provenance —
/// no body, no header value, no `Secret`. No pingora type appears here (doc 12
/// §13.1): `main.rs` parses the nflog group / reads the kernel counter and feeds
/// the tracker plain `(SessionRef, count)` values, then ships the emitted records
/// through the §10 sink.
pub mod telemetry_quic;

/// TLS-5 credential-swap EXECUTOR CORE (doc 09 §5 TLS-5; doc 12 §3 / §5.2 /
/// §13.3; doc 16 §4 / §5.2 / §9; D8/D22/D39/D73/D83/D40) — **pingora-free**. The
/// front half of the M1 headline swap (the long-lived credential never enters the
/// VM): the registry-match evaluator + the synchronous D22 `Validate` driver on
/// the inspected (TLS-3-terminated) path. [`swap::SwapRegistry`] indexes the
/// frozen [`ds_contracts::pol1::ServiceEntry`] service-registry shape (doc 13 §3,
/// strawman `github` → `github.com`/`api.github.com`, credential location
/// `Authorization` header) and [`swap::SwapExecutor::evaluate`] matches a request
/// on host + credential location, runs the synchronous [`swap::IdentityValidator`]
/// `Validate` seam (D73 swap-path-synchronous), and branches: ALLOW → a
/// session-cached opaque [`swap::GrantRef`] (NOT the credential — that lives in
/// the D39 secret store OUTSIDE the boundary, fetched in a LATER unit); DENY →
/// the in-band structured [`swap::SwapDenial`] 403 with a machine-readable reason.
/// Pass-through (TLS-4) flows never reach this path
/// ([`swap::SwapExecutor::is_inspected_path`]). Never-hold-the-secret (D73) is a
/// TYPE-LEVEL property: the presented credential lives in a `zeroize`-wiped
/// [`swap::PresentedCredential`] borrowed into the validator and dropped the
/// instant `evaluate` returns. The D22 `Validate` proto is not yet frozen into
/// `ds-contracts`, so (as [`telemetry_http`] / [`reoriginate`] do) the seam is a
/// local trait + verdict shape mirroring doc 16 §9 / the boundary, migrating at
/// the Stage-0 freeze.
///
/// The BACK half ([`swap::SwapExecutor::fire`]) is also here: on an ALLOW it fetches
/// the long-lived credential from the D39 store over the [`swap::SecretFetcher`]
/// seam, substitutes it into the outbound `Authorization` header
/// ([`swap::substitute_authorization`] → a `zeroize`-wiped [`swap::SubstitutedHeader`]),
/// and emits the LOG-5 [`swap::PendingCredentialUse`] once-token (a fingerprint-only
/// [`telemetry_http::CredentialUseEvent`] over the [`telemetry_http::AuditEmitter`]
/// channel); a secret-store failure is a fail-closed 502 (never the placeholder
/// upstream). No pingora type appears here (doc 12 §13.1): `main.rs` extracts the
/// request host + headers off the terminated stream, drives the executor's front +
/// back halves on the inspected path (gated behind `DS_TLS3_LIVE`; pass-through
/// flows never reach it, D17/D74), performs the upstream substitution, and flushes
/// the session-scoped grant cache at NFT-6 teardown (doc 16 §5.4).
pub mod swap;

/// TLS-6 HTTP-level policy evaluator — the framework-agnostic library core for
/// method/host/path rule evaluation + DoH-on-allowed-host detection on the
/// inspected (TLS-3-terminated) path (doc 09 §5 TLS-6; doc 12 §3 / §5.3; D17/D74,
/// D77, D40 pingora confinement) — **pingora-free**. The HTTP **policy decision**
/// half of TLS-6: given a parsed request line + headers
/// ([`http_policy::RequestMeta`] — method/host/path/headers, METADATA only, no
/// body field) it returns a [`http_policy::HttpDecision`] carrying the mandatory
/// POL-3 provenance triple (rule id / layer / policy version, rule 4) the boundary
/// `boundary/tlsproxy/tlsproxy_httppolicy_test.go` (D26) pins.
/// [`http_policy::HttpPolicy::evaluate`] walks the configured method/host/path
/// rules deny-first (deny-overrides, §1.2 — an org-layer deny wins over a
/// system-layer allow) and runs the always-on [`http_policy::detect_doh`] FIRST so
/// DNS-over-HTTP smuggled over an otherwise-allowed host (a
/// `Content-Type: application/dns-message` body, a `?dns=<base64url>` query
/// parameter, or an `Accept: application/dns-json` header — the three frozen
/// [`http_policy::DohShape`]s, NFT-4 layering §86) is denied with DoH-specific
/// provenance that no permissive host allow can override. A deny is the in-band
/// `403` ([`http_policy::HttpDecision::deny_status`], D77 block+log — distinct
/// from the rate-limit `429` a sibling unit owns) and NEVER reaches upstream. Body
/// examination is OPT-IN ([`http_policy::HttpRule::examining_body`] →
/// [`http_policy::HttpDecision::body_examined`]); the default decision path is
/// metadata-only, so the LOG-1 [`telemetry_http::HttpEvent`] the caller builds
/// never carries a payload byte — never-log-the-secret (D73) holds by the shape.
/// No pingora type appears here (doc 12 §13.1): `main.rs` reads the terminated
/// request line + headers off the cleartext stream (the `run_inspected_flow`
/// request phase, gated behind `DS_TLS3_LIVE` exactly as the TLS-3 inspected path
/// is — the disarmed default opaque-tunnel path never builds a `RequestMeta` and a
/// TLS-4 pass-through never reaches this evaluator, doc 12 §5.3 / D17/D74), drives
/// `evaluate`, and on a deny answers the `403` + emits the
/// `EventPolicyDecision`-shaped record with this decision's provenance. The live
/// `main.rs` wiring is a deferred unit; this is the lib-side decision core + its
/// unit suite (the rate-limit / behavioral-cap / suspend-on-breach halves of
/// TLS-6 are sibling units).
pub mod http_policy;

/// TLS-6 per-session and per-service rate limiter — the framework-agnostic library
/// core (doc 09 §5 TLS-6; doc 12 §3; D40 pingora confinement, D77 block+log,
/// D76/NFT-6 teardown hygiene) — **pingora-free**. The rate-limit half of TLS-6
/// (sibling to the [`http_policy`] method/host/path-rule + DoH half): it tracks
/// request counts per `(session, service)` tuple in in-memory buckets
/// ([`rate_limit::RateLimiter`]) and enforces a configurable per-tuple ceiling
/// ([`rate_limit::RateLimitPolicy`]; `0` ⇒ unlimited). [`rate_limit::RateLimiter::allow`]
/// counts one request and returns a [`rate_limit::RateDecision`] carrying the
/// mandatory POL-3 provenance triple (rule id `rate:<service>` / layer `session` /
/// policy version, rule 4) the boundary
/// `boundary/tlsproxy/tlsproxy_httppolicy_test.go::TestRateLimit_PerSessionAndPerService_Isolated`
/// (D26) pins: the first `N` requests on an `N`-capped tuple are allowed, request
/// `N+1` is refused with a `429` ([`rate_limit::RateDecision::deny_status`]) + a
/// `Retry-After` ([`rate_limit::RateDecision::retry_after`], D77 anti-looping
/// back-off), and the caller emits a rate-refusal LOG-1 event
/// ([`rate_limit::RateRefusalEvent`], secret-free — never-log-the-secret D73 by the
/// shape). **Bucket isolation** holds because the bucket key is the whole
/// `(session, service)` tuple keyed on the never-recycled tap name (doc 14 §4): A's
/// github bucket never throttles A's npm or B's github. A rate cap can only
/// *tighten* an already-admitted flow (POL-3 — it never admits a new one); the
/// refusal is a deny layered on the shared engine's allow exactly like the
/// HTTP-policy `403` (deny-overrides, §1.2). Buckets are session-scoped runtime
/// state flushed at NFT-6 teardown ([`rate_limit::RateLimiter::flush_session`], the
/// same SeveringRegistry teardown hook the other session-scoped modules hang off, so
/// a never-recycled session index inherits no residue). No pingora type appears here
/// (doc 12 §13.1): `main.rs` resolves the `(session, service)` on the TLS-3
/// inspected path's request phase (gated behind `DS_TLS3_LIVE`) and the TLS-2
/// explicit CONNECT path, calls `allow` before any byte goes upstream, and on a
/// refusal answers the in-band `429` + emits the refusal event; the opaque tunnel
/// path (TLS-1 / TLS-4 pass-through, D17/D74) never terminates TLS and so never
/// reaches this limiter — the default (`DS_TLS3_LIVE` unset) path stays
/// byte-identical. The live `main.rs` wiring is a deferred unit; this is the
/// lib-side decision core + its unit suite.
pub mod rate_limit;

/// TLS-6 behavioral-cap monitor — the framework-agnostic library core (doc 09 §5
/// TLS-6; doc 12 §3 / §13.1; D77 block+log default; D40 pingora confinement;
/// D76/NFT-6 teardown hygiene) — **pingora-free**. The behavioral-cap half of TLS-6
/// (sibling to the [`http_policy`] method/host/path-rule + DoH half and the
/// [`rate_limit`] per-`(session, service)` rate-limit half): it counts sensitive
/// resource ACTIONS (method/path — [`cap_monitor::ResourceAction`]) per session
/// against a configurable cap ([`cap_monitor::CapConfig`]: id / limit / matcher /
/// [`cap_monitor::CapAction`]) keyed on `(session, cap)` in in-memory counters
/// ([`cap_monitor::CapMonitor`]). [`cap_monitor::CapMonitor::record`] increments the
/// first matching cap's counter and returns a [`cap_monitor::CapVerdict`] carrying
/// whether the cap breached, the cap id, the cap's action, and the mandatory POL-3
/// provenance triple (rule id = the cap id / layer `session` / policy version, rule
/// 4) the boundary
/// `boundary/tlsproxy/tlsproxy_httppolicy_test.go::TestCap_BreachSuspendsMidAction_BreachingRequestHeld`
/// and `::TestCap_ResumeInvisibleToAgent` (D26) pin: actions `1..=N` on an
/// `N`-limit cap are unaffected, action `N+1` trips the cap, and the breach fires a
/// [`cap_monitor::BreachEvent`] LOG-1 record (cap id + full provenance, secret-free
/// — never-log-the-secret D73 by the shape). The breach VERDICT is action-dependent:
/// [`cap_monitor::CapAction::Block`] (the D77 default) answers the agent a `403`
/// ([`cap_monitor::CapVerdict::block_status`]) and opens NO upstream leg;
/// [`cap_monitor::CapAction::Suspend`] (reserved for explicitly dangerous operations,
/// doc 12 §3) HOLDS the breaching request mid-action by signalling the
/// [`cap_monitor::SuspendGate`] (the per-session pause/resume seam — doc 12 §13.1,
/// the orchestrator-coordination lane the D46 marker also rides) BEFORE any upstream
/// byte, and resumes — invisibly to the agent — only when orchestrator approval
/// arrives, completing the held request with a normal `200`
/// ([`cap_monitor::enforce_breach`] composes that suspend-before-upstream +
/// resume-to-200 ordering; a hold that cannot be established fails CLOSED). A cap can
/// only *tighten* an already-admitted flow (POL-3 — it never admits a new one).
/// Counters are session-scoped runtime state flushed at NFT-6 teardown
/// ([`cap_monitor::CapMonitor::flush_session`], the same SeveringRegistry teardown
/// hook the other session-scoped modules hang off, so a never-recycled session index
/// inherits no residue). No pingora type appears here (doc 12 §13.1): `main.rs`
/// builds the [`cap_monitor::ResourceAction`] off the parsed request on the TLS-3
/// inspected path's request phase (gated behind `DS_TLS3_LIVE`), calls `record`
/// before any byte goes upstream, drives [`cap_monitor::enforce_breach`] over the
/// wired [`cap_monitor::SuspendGate`] on a breach, and emits the breach event; the
/// opaque tunnel path (TLS-1 / TLS-4 pass-through, D17/D74) never terminates TLS and
/// so never reaches this monitor — the default (`DS_TLS3_LIVE` unset) path stays
/// byte-identical. The live `main.rs` `SuspendGate` binding (the orchestrator
/// pause/resume coordination) is a deferred unit; this is the lib-side counting +
/// verdict core, the seam, and its unit suite.
pub mod cap_monitor;

/// TLS-7 in-process secret-scanning gate — the framework-agnostic library core
/// (doc 09 §5 TLS-7; doc 12 §5 / §13.1 / §13.5; D73 two-plane split; D40 pingora
/// confinement) — **pingora-free**. Ships the three frozen D73 §5.1 pieces and
/// nothing the §9 "Free" column leaves to the engine: the frozen
/// [`scan::SecretMatcher`] trait (`scan(chunk, end_of_stream, ctx) -> Verdict`, the
/// pluggable engine owning its carryover state), the direction-symmetric
/// [`scan::Verdict`] enum (`Pass(release_n) / Hold / Block / Flag / Redact`, each
/// non-`Pass` carrying the POL-3 [`scan::ScanProvenance`] quad — rule id,
/// ruleset/digest-set version, policy layer, [`scan::Plane`] `= keyed | generic`),
/// and the proxy-owned [`scan::HoldBackBuffer`] / [`scan::ScanGate`] enforcing the
/// hold-back invariant (retain up to `max_secret_length - 1` trailing bytes so a
/// secret straddling a chunk / TLS-record boundary is never detected only after its
/// prefix egressed) plus the fail-closed-when-keyed contract (doc 12 §13.5: a
/// matcher error while the keyed plane is loaded collapses to [`scan::Verdict::Hold`]
/// — no byte released; fail-open is generic-flag-only via the explicit
/// [`scan::FailMode`] policy bit, whose validating schema is §9-Free / a later
/// unit, carried here as a placeholder). The body-filter integration on
/// `src/transparent.rs` / `src/main.rs` (gated behind `DS_TLS3_LIVE` exactly as
/// the TLS-3 inspected path is; TLS-4 pass-through never reaches it, D17/D74) is the
/// documented seam (doc 12 §13.1) — a deferred unit. No pingora type appears here.
///
/// Also hosts the **digest-feed consumer** (u2 — the D73 two-plane split, doc 12
/// §5.2): the [`scan::DigestSetMatcher`] ingests the frozen digest-feed proto
/// (the keyed plane — `proto/dreamserpent/identity/v1/digest_feed.proto`, doc 14
/// §7 / doc 16 §6.6: [`scan::KeyedPublish`] of [`scan::KeyedDigest`] entries
/// carrying `key_id` / [`scan::DigestAlgo`] / digest / [`scan::CredClass`] /
/// [`scan::DigestScope`] / expiry / [`scan::VariantTag`]) and the generic plane
/// (a POL-4 [`scan::GenericPack`] of gitleaks-compatible [`scan::GenericRule`]s,
/// doc 14 §9) and implements [`scan::SecretMatcher`] over both, feeding the
/// [`scan::ScanGate`] hold-back path. Mint-before-attach (doc 16 §6.1, D109) is a
/// fail-closed load gate ([`scan::DigestSetMatcher::seal_keyed`] is the in-process
/// ack-landed edge — a loaded-but-unsealed keyed plane Holds). Session-scoped
/// keyed digests arrive on the orchestrator's `hostagent.v1` SESSION-LIFECYCLE
/// channel at connection time (doc 12 §6 — D72-exempt lifecycle data, NOT the
/// one-per-host policy subscription): [`scan::DigestSetMatcher::ingest_session_lifecycle`]
/// binds the session (`session_uuid`), loads ONLY its [`scan::DigestScope::Session`]
/// entries (a fleet entry is dropped — it belongs on the policy path), and arms the
/// mint-before-attach barrier so [`scan::DigestSetMatcher::scan_or_hold`] yields
/// [`scan::Verdict::Hold`] on every scan until `seal_keyed`; the matching session's
/// entries are flushed at NFT-6 teardown ([`scan::DigestSetMatcher::flush_session`]),
/// leaving no residue. The keyed-hash
/// engine is the §9-Free [`scan::DigestHasher`] seam (the real `ring::hmac`
/// wiring + HMAC rotation are Boundary/Identity, doc 16 §6.3), so this consumer
/// stays stdlib-only and `#![forbid(unsafe_code)]`-clean. Plaintext never crosses
/// the seam — the matcher state carries only fingerprints (digest bytes + rule
/// metadata), never a credential plaintext (never-log-the-secret as a type
/// property, doc 14 §7).
///
/// Also hosts the **generic-pack HOT-RELOAD** substrate (the generic plane's own
/// release-free cadence, doc 12 §108, D72/D73): the [`scan::SharedGenericPack`]
/// live-swappable pack slot every in-flight stream's matcher reads through (the
/// apply barrier pointer-swaps a new `Arc<GenericPack>` in atomically — never a
/// torn pack), the [`scan::InFlightStreams`] registry the post-commit sweep
/// re-evaluates against a freshly-pushed pack, and the fingerprint-free
/// [`scan::GenericReloadEvent`] policy-decision it emits per in-flight stream a
/// NEWLY-matched generic rule hits (`plane = Generic`, block+log per the D53 schema
/// freeze — never a matched byte). The single [`scan::match_generic_pack`] free
/// function serves both the inline scan path and the sweep re-evaluation so the two
/// can never skew. The D72 apply barrier that drives this slot lives in
/// [`apply::GenericPackConsumer`].
pub mod scan;

/// TLS-8 WebSocket (RFC 6455) protocol-breadth core (doc 09 §5 TLS-8; doc 12 §3;
/// D17/D74) — **pingora-free**. Once TLS-3 terminates the VM's TLS the inspected
/// path reads the cleartext HTTP/1.1 exchange; a WebSocket flow opens with an HTTP
/// `Upgrade: websocket` handshake (the bytes the proxy DOES observe) and then turns
/// the connection into an opaque, frame-level bidirectional byte stream the proxy
/// forwards UNMODIFIED to both legs (RFC 6455 §5 — all opcodes, the client→server
/// mask, and message fragmentation pass through verbatim; no WebSocket payload is
/// inspected). This module is the framework-agnostic core of that posture:
///
/// - the handshake side: [`websocket::is_websocket_upgrade`] (detect the RFC 6455
///   §4.2.1 `Upgrade: websocket` + `Connection: Upgrade` request) and
///   [`websocket::sec_websocket_accept`] (the §4.2.2 `Sec-WebSocket-Accept` =
///   `base64(SHA1(key + GUID))` server-response value), with a self-contained
///   `forbid(unsafe_code)` SHA-1 so NO new crate edge is taken;
/// - the transparency side: [`websocket::WsFrameView`] parses a frame header (FIN,
///   opcode, MASK, the 7/16/64-bit length, the optional masking key) WITHOUT
///   rewriting a byte, so a test can prove every opcode / mask / fragmentation
///   scheme survives a parse→re-serialize round-trip byte-identically (the
///   frame-level pass-through invariant);
/// - the telemetry side: [`websocket::upgraded_event_fields`] yields the
///   one-per-upgraded-connection LOG-1 fields (`GET`, origin host, request path,
///   status `101`) the [`telemetry_http::HttpEvent`] carries — the only thing
///   inspection records about a WebSocket flow (the handshake metadata, never a
///   frame byte; D73 never-log-the-secret holds because no frame payload is read).
///
/// D40 pingora confinement (doc 12 §13.1): no pingora type appears here; `main.rs`
/// reads the terminated request line + headers off the stream and feeds these
/// helpers plain values, then forwards the post-handshake frame stream opaquely.
///
/// Defined INLINE (not a sibling `websocket.rs`) so the TLS-8 WebSocket unit lands
/// in `lib.rs` + `main.rs` only, matching the unit's file scope.
pub mod websocket {
    // WebSocket (RFC 6455) handshake + frame-transparency core for the TLS-8
    // inspected path. See the outer `///` module doc above for the full charter.
    //
    // `unsafe_code` is forbidden here by the crate-root `#![forbid(unsafe_code)]`
    // (line ~67), which binds every inline module — no inner attribute is needed
    // (and a mixed inner/outer attribute style trips clippy). This module is
    // stdlib-only (a self-contained SHA-1 + base64), so it is unsafe-free by
    // construction.

    /// The RFC 6455 §1.3 globally-unique-identifier (GUID) concatenated with the
    /// client's `Sec-WebSocket-Key` before the SHA-1 + base64 that produces the
    /// server's `Sec-WebSocket-Accept` value. Frozen by the RFC — never a knob.
    pub const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    /// The RFC 6455 §4.2.2 successful-upgrade status — `101 Switching Protocols` —
    /// the only status a completed WebSocket handshake carries.
    pub const WS_UPGRADE_STATUS: u16 = 101;

    /// Compute the RFC 6455 §4.2.2 `Sec-WebSocket-Accept` response header value for
    /// a client's `Sec-WebSocket-Key`: `base64(SHA1(key + WS_GUID))`.
    ///
    /// The proxy, terminating the VM's TLS, sees the client handshake and must hand
    /// the SAME accept value the origin would (so the upgrade is not corrupted by
    /// inspection). The key is taken verbatim (the RFC does not trim it); the GUID
    /// is appended, SHA-1 hashed, and standard-alphabet base64 encoded with padding.
    pub fn sec_websocket_accept(sec_websocket_key: &str) -> String {
        let mut input = String::with_capacity(sec_websocket_key.len() + WS_GUID.len());
        input.push_str(sec_websocket_key);
        input.push_str(WS_GUID);
        let digest = sha1(input.as_bytes());
        base64_encode(&digest)
    }

    /// Whether the request headers describe an RFC 6455 §4.2.1 WebSocket upgrade:
    /// an `Upgrade` header whose token list contains `websocket` (case-insensitive)
    /// AND a `Connection` header whose token list contains `Upgrade`
    /// (case-insensitive). Both are required; a request carrying only one is NOT a
    /// WebSocket upgrade (and the inspected path treats it as an ordinary request).
    ///
    /// `headers` is an iterator of `(name, value)` pairs as parsed off the
    /// terminated request — `main.rs` supplies them; this stays pingora-free. Header
    /// names compare case-insensitively (RFC 7230 §3.2); the `Connection` value is
    /// tokenized on commas because it may legally carry multiple connection options
    /// (e.g. `keep-alive, Upgrade`).
    pub fn is_websocket_upgrade<'a, I>(headers: I) -> bool
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut has_upgrade_websocket = false;
        let mut has_connection_upgrade = false;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("upgrade") {
                if value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
                {
                    has_upgrade_websocket = true;
                }
            } else if name.eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            {
                has_connection_upgrade = true;
            }
        }
        has_upgrade_websocket && has_connection_upgrade
    }

    /// Extract a header value by case-insensitive name from an `(name, value)` set
    /// (the first match wins) — the small helper `main.rs` uses to pull the
    /// `Sec-WebSocket-Key` off the terminated request. Returns `None` if absent.
    pub fn header_value<'a, I>(headers: I, wanted: &str) -> Option<&'a str>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        headers
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value)
    }

    /// The one-per-upgraded-connection LOG-1 telemetry tuple for a WebSocket flow
    /// (doc 09 §5 TLS-8): `(method, host, path, status)` = `("GET", origin, path,
    /// 101)`. A successful WebSocket upgrade is always a `GET` ending in the
    /// `101 Switching Protocols` response (RFC 6455 §4.1/§4.2.2), so the inspected
    /// path emits exactly one [`crate::telemetry_http::HttpEvent`] with this shape
    /// per upgraded connection — the handshake metadata, never a frame byte.
    ///
    /// `host` is the origin (the SNI / `Host`); `path` is the request target the
    /// upgrade `GET` named (e.g. `/socket`). The status is the frozen `101`.
    pub fn upgraded_event_fields<'a>(
        host: &'a str,
        path: &'a str,
    ) -> (&'static str, &'a str, &'a str, u16) {
        ("GET", host, path, WS_UPGRADE_STATUS)
    }

    /// A non-owning, byte-exact view over one parsed WebSocket frame (RFC 6455 §5.2)
    /// — the FIN bit, the 4-bit opcode, the MASK bit + optional 4-byte masking key,
    /// and the payload bounds — WITHOUT copying or rewriting a single byte. The
    /// inspected path forwards WebSocket frames OPAQUELY (no payload inspection), so
    /// this exists only to PROVE the transparency invariant: a frame parsed and then
    /// re-serialized from `raw` is byte-identical, for every opcode / mask /
    /// fragmentation scheme. `raw` is the exact on-wire frame bytes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct WsFrameView<'a> {
        /// FIN bit (RFC 6455 §5.2): the final fragment of a message when set.
        pub fin: bool,
        /// The 4-bit opcode (continuation `0x0`, text `0x1`, binary `0x2`, close
        /// `0x8`, ping `0x9`, pong `0xA`, …) — preserved verbatim, never remapped.
        pub opcode: u8,
        /// MASK bit (RFC 6455 §5.3): client→server frames are masked, server→client
        /// frames are not. The masking key (if present) and the masked payload are
        /// forwarded UNMODIFIED — the proxy never unmasks.
        pub masked: bool,
        /// The 4-byte masking key when `masked` is set (RFC 6455 §5.3), else `None`.
        pub masking_key: Option<[u8; 4]>,
        /// The frame's declared payload length (after the 7/16/64-bit length field).
        pub payload_len: u64,
        /// The exact total on-wire byte length of this frame (header + masking key +
        /// payload). `raw[..frame_len]` is the whole frame.
        pub frame_len: usize,
        /// The exact on-wire bytes of this frame (length `frame_len`).
        pub raw: &'a [u8],
    }

    impl<'a> WsFrameView<'a> {
        /// Parse the FIRST WebSocket frame at the start of `raw` (RFC 6455 §5.2),
        /// returning a byte-exact view. TOTAL and bounds-checked: a buffer too short
        /// for the header, length field, masking key, or declared payload yields
        /// `None` (need more bytes) — never a panic. The 64-bit length's high bit
        /// MUST be 0 per the RFC; a payload that would not fit in `usize` (only on a
        /// 32-bit host) also yields `None`.
        ///
        /// No byte is rewritten: the returned view borrows `raw[..frame_len]`, so
        /// re-emitting `view.raw` reproduces the frame exactly (the transparency
        /// invariant the inspected path relies on for opaque frame forwarding).
        pub fn parse(raw: &'a [u8]) -> Option<WsFrameView<'a>> {
            if raw.len() < 2 {
                return None;
            }
            let b0 = raw[0];
            let b1 = raw[1];
            let fin = b0 & 0x80 != 0;
            let opcode = b0 & 0x0f;
            let masked = b1 & 0x80 != 0;
            let len_code = b1 & 0x7f;

            let mut cursor = 2usize;
            let payload_len: u64 = match len_code {
                126 => {
                    if raw.len() < cursor + 2 {
                        return None;
                    }
                    let l = u16::from_be_bytes([raw[cursor], raw[cursor + 1]]) as u64;
                    cursor += 2;
                    l
                }
                127 => {
                    if raw.len() < cursor + 8 {
                        return None;
                    }
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&raw[cursor..cursor + 8]);
                    let l = u64::from_be_bytes(bytes);
                    // RFC 6455 §5.2: the most-significant bit of a 64-bit length MUST be 0.
                    if l & 0x8000_0000_0000_0000 != 0 {
                        return None;
                    }
                    cursor += 8;
                    l
                }
                code => code as u64,
            };

            let masking_key = if masked {
                if raw.len() < cursor + 4 {
                    return None;
                }
                let key = [
                    raw[cursor],
                    raw[cursor + 1],
                    raw[cursor + 2],
                    raw[cursor + 3],
                ];
                cursor += 4;
                Some(key)
            } else {
                None
            };

            // The payload must fit in addressable memory on this host.
            let payload_usize = usize::try_from(payload_len).ok()?;
            let frame_len = cursor.checked_add(payload_usize)?;
            if raw.len() < frame_len {
                return None;
            }

            Some(WsFrameView {
                fin,
                opcode,
                masked,
                masking_key,
                payload_len,
                frame_len,
                raw: &raw[..frame_len],
            })
        }

        /// The payload slice of this frame (still masked if `masked` — the proxy
        /// never unmasks; this is for length/round-trip assertions, not inspection).
        pub fn payload(&self) -> &'a [u8] {
            let start = self.frame_len - usize::try_from(self.payload_len).unwrap_or(0);
            &self.raw[start..self.frame_len]
        }
    }

    /// Walk `buf` as a sequence of consecutive WebSocket frames, returning each as a
    /// byte-exact [`WsFrameView`] until the buffer is exhausted or a trailing partial
    /// frame remains. PROVES frame-stream transparency: concatenating every
    /// returned `view.raw` reproduces the consumed prefix of `buf` byte-identically
    /// (no opcode remap, no unmask, no re-fragmentation). The returned `usize` is
    /// how many bytes were consumed into whole frames (a trailing partial frame is
    /// left for the next read, exactly as an opaque splice would carry it).
    pub fn parse_frames(buf: &[u8]) -> (Vec<WsFrameView<'_>>, usize) {
        let mut frames = Vec::new();
        let mut consumed = 0usize;
        while consumed < buf.len() {
            match WsFrameView::parse(&buf[consumed..]) {
                Some(view) => {
                    consumed += view.frame_len;
                    frames.push(view);
                }
                None => break, // trailing partial frame — leave it for the next read
            }
        }
        (frames, consumed)
    }

    /// A self-contained SHA-1 (RFC 3174) over `data`, returning the 20-byte digest.
    /// Implemented in-crate (no new dependency edge) and `forbid(unsafe_code)`-clean;
    /// used ONLY for the RFC 6455 `Sec-WebSocket-Accept` value, where SHA-1 is the
    /// protocol-mandated digest (not a security primitive — the security is the
    /// terminated TLS the proxy already validated).
    pub fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [
            0x6745_2301,
            0xEFCD_AB89,
            0x98BA_DCFE,
            0x1032_5476,
            0xC3D2_E1F0,
        ];

        // Pad: append 0x80, then zeros, then the 64-bit big-endian bit length.
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = Vec::with_capacity(data.len() + 72);
        msg.extend_from_slice(data);
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 80];
            for (i, word) in w.iter_mut().enumerate().take(16) {
                let j = i * 4;
                *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }

            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];

            for (i, &wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                    20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                    _ => (b ^ c ^ d, 0xCA62_C1D6),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }

        let mut out = [0u8; 20];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Standard-alphabet base64 encode WITH padding (RFC 4648), used for the
    /// `Sec-WebSocket-Accept` value. Mirrors the in-crate encoder `ca.rs` carries
    /// (kept local so the WebSocket unit adds no shared surface and no new crate).
    pub fn base64_encode(data: &[u8]) -> String {
        const ALPHA: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = *chunk.get(1).unwrap_or(&0) as usize;
            let b2 = *chunk.get(2).unwrap_or(&0) as usize;
            out.push(ALPHA[b0 >> 2] as char);
            out.push(ALPHA[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
            if chunk.len() > 1 {
                out.push(ALPHA[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHA[b2 & 0x3f] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // ── Sec-WebSocket-Accept (RFC 6455 §1.3 worked example) ─────────────────

        #[test]
        fn sec_websocket_accept_matches_the_rfc6455_worked_example() {
            // RFC 6455 §1.3: key "dGhlIHNhbXBsZSBub25jZQ==" → accept
            // "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=". This is the canonical interop vector.
            assert_eq!(
                sec_websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
            );
        }

        #[test]
        fn sec_websocket_accept_matches_the_boundary_test_vector() {
            // The boundary tlsproxy_protocol_test.go uses key "x3JJHMbDL1EzLkh9GBhXDw=="
            // and asserts the server returns wsAccept(key). Compute the SAME value here
            // so the conformance handshake (Sec-WebSocket-Accept calculation) matches.
            assert_eq!(
                sec_websocket_accept("x3JJHMbDL1EzLkh9GBhXDw=="),
                "HSmrc0sMlYUkAGmm5OPpG2HaGWk="
            );
        }

        // ── SHA-1 (RFC 3174 known-answer tests) ─────────────────────────────────

        #[test]
        fn sha1_known_answer_tests() {
            fn hex(d: [u8; 20]) -> String {
                d.iter().map(|b| format!("{b:02x}")).collect()
            }
            // FIPS 180-1 / RFC 3174 published vectors.
            assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
            assert_eq!(
                hex(sha1(b"abc")),
                "a9993e364706816aba3e25717850c26c9cd0d89d"
            );
            assert_eq!(
                hex(sha1(
                    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                )),
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
            );
        }

        #[test]
        fn base64_encode_matches_the_standard_alphabet_with_padding() {
            assert_eq!(base64_encode(b""), "");
            assert_eq!(base64_encode(b"f"), "Zg==");
            assert_eq!(base64_encode(b"fo"), "Zm8=");
            assert_eq!(base64_encode(b"foo"), "Zm9v");
            assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        }

        // ── upgrade detection (RFC 6455 §4.2.1) ─────────────────────────────────

        #[test]
        fn detects_a_websocket_upgrade_request() {
            let headers = [
                ("Host", "ws.example"),
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Version", "13"),
            ];
            assert!(is_websocket_upgrade(headers.iter().map(|&(n, v)| (n, v))));
        }

        #[test]
        fn upgrade_detection_is_case_insensitive_and_token_aware() {
            // Header names + the websocket/Upgrade tokens compare case-insensitively
            // (RFC 7230 §3.2), and Connection may carry a token LIST.
            let headers = [
                ("upgrade", "WebSocket"),
                ("connection", "keep-alive, Upgrade"),
            ];
            assert!(is_websocket_upgrade(headers.iter().map(|&(n, v)| (n, v))));
        }

        #[test]
        fn not_an_upgrade_when_either_header_is_missing() {
            // Only Upgrade, no Connection: Upgrade.
            assert!(!is_websocket_upgrade(
                [("Upgrade", "websocket")].iter().map(|&(n, v)| (n, v))
            ));
            // Only Connection: Upgrade, no Upgrade: websocket.
            assert!(!is_websocket_upgrade(
                [("Connection", "Upgrade")].iter().map(|&(n, v)| (n, v))
            ));
            // A plain request is not an upgrade.
            assert!(!is_websocket_upgrade(
                [("Host", "x.example")].iter().map(|&(n, v)| (n, v))
            ));
            // An Upgrade to a DIFFERENT protocol (h2c) is not a WebSocket upgrade.
            assert!(!is_websocket_upgrade(
                [("Upgrade", "h2c"), ("Connection", "Upgrade")]
                    .iter()
                    .map(|&(n, v)| (n, v))
            ));
        }

        #[test]
        fn header_value_finds_the_sec_websocket_key_case_insensitively() {
            let headers = [("Sec-WebSocket-Key", "x3JJHMbDL1EzLkh9GBhXDw==")];
            assert_eq!(
                header_value(headers.iter().map(|&(n, v)| (n, v)), "sec-websocket-key"),
                Some("x3JJHMbDL1EzLkh9GBhXDw==")
            );
            assert_eq!(
                header_value(
                    [("Host", "x")].iter().map(|&(n, v)| (n, v)),
                    "sec-websocket-key"
                ),
                None
            );
        }

        // ── upgraded-connection telemetry shape (doc 09 §5 TLS-8) ───────────────

        #[test]
        fn upgraded_event_fields_are_get_origin_path_101() {
            let (method, host, path, status) = upgraded_event_fields("ws.example", "/socket");
            assert_eq!(method, "GET");
            assert_eq!(host, "ws.example");
            assert_eq!(path, "/socket");
            assert_eq!(status, 101);
        }

        // ── frame-level transparency (RFC 6455 §5.2/§5.3) ───────────────────────

        /// Build a WebSocket frame the way the boundary test's `wsFrame` does, so the
        /// parser is exercised against the exact wire shapes the conformance suite
        /// round-trips (text/binary/ping, masked + unmasked, 7/16-bit lengths).
        fn build_frame(opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
            let mut b = vec![0x80 | opcode];
            let mask_bit = if masked { 0x80u8 } else { 0 };
            let l = payload.len();
            if l < 126 {
                b.push(mask_bit | l as u8);
            } else if l < (1 << 16) {
                b.push(mask_bit | 126);
                b.extend_from_slice(&(l as u16).to_be_bytes());
            } else {
                b.push(mask_bit | 127);
                b.extend_from_slice(&(l as u64).to_be_bytes());
            }
            if masked {
                let key = [0x12, 0x34, 0x56, 0x78];
                b.extend_from_slice(&key);
                for (i, &p) in payload.iter().enumerate() {
                    b.push(p ^ key[i % 4]);
                }
            } else {
                b.extend_from_slice(payload);
            }
            b
        }

        #[test]
        fn parses_every_opcode_mask_and_length_form_byte_identically() {
            // Text/binary/ping/pong/close + continuation, masked and unmasked, across
            // 7-bit and 16-bit length forms. Each parses and re-serializes (view.raw)
            // byte-identically — the frame-level pass-through invariant (no opcode
            // remap, no unmask, no re-framing).
            let big = vec![0xABu8; 400]; // forces the 16-bit (126) length form
            let cases: &[(u8, &[u8], bool)] = &[
                (0x1, b"text-frame", true),   // masked text (client->server)
                (0x1, b"text-frame", false),  // unmasked text (server->client)
                (0x2, b"binary-xyz", true),   // masked binary
                (0x0, b"continuation", true), // continuation fragment
                (0x8, b"\x03\xe8bye", false), // close
                (0x9, b"ping", true),         // ping
                (0xA, b"pong", false),        // pong
                (0x2, &big, true),            // 16-bit length form
                (0x1, b"", true),             // zero-length masked frame
            ];
            for &(opcode, payload, masked) in cases {
                let wire = build_frame(opcode, payload, masked);
                let view = WsFrameView::parse(&wire)
                    .unwrap_or_else(|| panic!("parse opcode={opcode:#x} masked={masked}"));
                assert!(view.fin, "FIN preserved");
                assert_eq!(view.opcode, opcode, "opcode preserved verbatim");
                assert_eq!(view.masked, masked, "MASK bit preserved");
                assert_eq!(view.payload_len, payload.len() as u64);
                assert_eq!(view.frame_len, wire.len(), "exact on-wire frame length");
                // The headline transparency invariant: re-emitting view.raw is
                // byte-identical to the input (no rewrite of any byte).
                assert_eq!(
                    view.raw,
                    wire.as_slice(),
                    "frame round-trips byte-identically"
                );
                // The masking key (if any) is preserved exactly; we never unmask.
                if masked {
                    assert_eq!(view.masking_key, Some([0x12, 0x34, 0x56, 0x78]));
                } else {
                    assert_eq!(view.masking_key, None);
                }
            }
        }

        #[test]
        fn parse_returns_none_on_a_short_partial_frame_never_panics() {
            // A header-only buffer that promises payload not yet arrived: need more bytes.
            let full = build_frame(0x2, b"binary-frame-payload-xyz", true);
            for short in 0..full.len() {
                // Any strict prefix is incomplete (the last byte completes it).
                assert!(
                    WsFrameView::parse(&full[..short]).is_none(),
                    "a {short}-byte prefix of a {}-byte frame must be incomplete",
                    full.len()
                );
            }
            assert!(
                WsFrameView::parse(&full).is_some(),
                "the whole frame parses"
            );
        }

        #[test]
        fn parse_frames_consumes_whole_frames_and_leaves_a_trailing_partial() {
            // A frame stream is forwarded opaquely: parsing the stream and
            // concatenating every view.raw reproduces the consumed prefix exactly,
            // and a trailing partial frame is left for the next read.
            let f1 = build_frame(0x1, b"hello", false);
            let f2 = build_frame(0x9, b"ping", true);
            let f3_full = build_frame(0x2, b"trailing", true);
            let mut stream = Vec::new();
            stream.extend_from_slice(&f1);
            stream.extend_from_slice(&f2);
            stream.extend_from_slice(&f3_full[..f3_full.len() - 3]); // partial last frame

            let (frames, consumed) = parse_frames(&stream);
            assert_eq!(frames.len(), 2, "two whole frames");
            assert_eq!(consumed, f1.len() + f2.len(), "only whole frames consumed");
            // Concatenating the whole frames reproduces the consumed prefix verbatim.
            let mut rebuilt = Vec::new();
            for fv in &frames {
                rebuilt.extend_from_slice(fv.raw);
            }
            assert_eq!(
                rebuilt,
                stream[..consumed],
                "frame stream round-trips byte-identically"
            );
            assert_eq!(frames[0].opcode, 0x1);
            assert_eq!(frames[1].opcode, 0x9);
        }

        #[test]
        fn parse_refuses_a_64bit_length_with_the_high_bit_set() {
            // RFC 6455 §5.2: the MSB of a 64-bit length MUST be 0. A frame claiming it
            // must not parse (fail-closed; never a huge allocation).
            let mut wire = vec![0x82, 127];
            wire.extend_from_slice(&0x8000_0000_0000_0001u64.to_be_bytes());
            assert!(WsFrameView::parse(&wire).is_none());
        }
    }
}

/// TLS-8 HTTP/2 (RFC 7540) protocol-breadth core (doc 09 §5 TLS-8; doc 12 §3;
/// D17/D74) — **pingora-free**. When the VM negotiates `h2` over the TLS-3-inspected
/// path the proxy terminates the VM's TLS (the [`crate::ca`] per-session CA), reads
/// the cleartext HTTP/2 connection, and re-originates upstream with strict WebPKI
/// (TLS-3 existing). HTTP/2 multiplexes many logical request/response *streams* over
/// one TCP+TLS connection (RFC 7540 §5); the inspected path must carry that
/// multiplexing END-TO-END without head-of-line (HOL) blocking or frame corruption,
/// and emit ONE [`crate::telemetry_http::HttpEvent`] PER STREAM with the
/// `method`/`host`/`path`/`status` read off that stream's HEADERS frames.
///
/// This module is the framework-agnostic core of that posture:
///
/// - **ALPN negotiation** ([`http2::ALPN_H2`] / [`http2::ALPN_HTTP11`] /
///   [`http2::select_alpn`]): the server-side protocol selection the terminating
///   rustls `ServerConfig` advertises — `h2` preferred, `http/1.1` fallback (RFC
///   7301). `main.rs` wires these onto the rustls config (the only place a rustls
///   SERVER type appears, D40); negotiation logic is pure and unit-tested here.
/// - **Frame demultiplexing** ([`http2::H2FrameView`] / [`http2::iter_frames`]): a
///   byte-exact, bounds-checked view over one HTTP/2 frame header (RFC 7540 §4.1 —
///   length, type, flags, stream id) WITHOUT rewriting a byte, so a test can prove
///   interleaved frames for distinct stream ids round-trip and re-assemble per
///   stream (stream isolation; no cross-stream corruption). Re-emitting a parsed
///   frame's `raw` reproduces it exactly — the multiplexing-transparency invariant.
/// - **HPACK header decode** ([`http2::HpackDecoder`]): enough RFC 7541 to recover a
///   stream's pseudo-headers (`:method`, `:path`, `:authority`/host, `:status`) off
///   its HEADERS-frame header block — the static table, indexed + literal field
///   representations, and the canonical Huffman code (RFC 7541 Appendix B, which
///   real `h2` clients use by default). NO dynamic-table mutation is required for
///   the pseudo-headers the telemetry asserts, but size-update + literal-with-
///   incremental-indexing are tolerated so a real client's header block parses.
/// - **Per-stream telemetry** ([`http2::StreamEvent`] /
///   [`http2::stream_event_fields`]): the per-stream LOG-1 tuple
///   `(method, host, path, status)` the inspected path emits — one event per
///   completed stream, populated from that stream's HEADERS frames. Never a DATA
///   byte (D73 never-log-the-secret holds because no payload is read).
/// - **gRPC (HTTP/2 + `application/grpc` + trailers)** ([`http2::is_grpc_content_type`]
///   / [`http2::demux_stream_header_blocks`] / [`http2::grpc_trailers_from_block`] /
///   [`http2::GrpcTrailers`]): gRPC is HTTP/2 with an `application/grpc{+codec}`
///   content-type and RFC 7540 §8.1 TRAILING headers (`grpc-status`/`grpc-message`
///   in a second HEADERS block after the DATA frames). Unary and server-streaming
///   differ only in DATA-frame count — the SAME stream shape (initial HEADERS →
///   DATA* → trailers HEADERS) and so the SAME demux. Trailers survive inspection
///   by the existing frame-stream transparency (no special splice); the
///   trailer-aware demux keeps a stream's two HEADERS blocks SEPARATE so the
///   initial `:status` (200) and the trailers (`grpc-status` 0) both decode
///   correctly — a naive whole-stream HEADERS concat ([`http2::demux_header_blocks`])
///   would fuse the two independent HPACK blocks and corrupt the event's status.
///   Still never a DATA byte (D73): telemetry is HEADERS/TRAILERS metadata only.
///
/// D40 pingora confinement (doc 12 §13.1): no pingora type appears here; `main.rs`
/// reads the terminated h2 connection and feeds these helpers plain bytes, then
/// emits the per-stream events. The frame-level forwarding is the SAME opaque
/// cleartext splice the inspected path already does (the live h2 splice is the
/// conformance-harness residual, doc 09 §5 done-when); transparency is the property
/// the [`http2::H2FrameView`] round-trip + the per-stream demux prove.
///
/// Defined INLINE (not a sibling `http2.rs`) so the TLS-8 HTTP/2 unit lands in
/// `lib.rs` + `main.rs` only, matching the unit's file scope.
pub mod http2 {
    // HTTP/2 (RFC 7540) + HPACK (RFC 7541) protocol-breadth core for the TLS-8
    // inspected path. See the outer `///` module doc above for the full charter.
    //
    // `unsafe_code` is forbidden here by the crate-root `#![forbid(unsafe_code)]`,
    // which binds every inline module — no inner attribute is needed. This module is
    // stdlib-only (a self-contained HPACK static table + Huffman tree), so it is
    // unsafe-free by construction.

    use std::collections::BTreeMap;

    /// The RFC 7301 ALPN protocol id for HTTP/2 over TLS (`h2`). The terminating
    /// per-session `ServerConfig` advertises this first so an `h2`-capable VM
    /// negotiates HTTP/2 over the inspected path (the boundary asserts the
    /// downstream-negotiated protocol is `h2`).
    pub const ALPN_H2: &[u8] = b"h2";

    /// The RFC 7230 ALPN protocol id for HTTP/1.1 (`http/1.1`) — the inspected
    /// path's fallback when the VM does not offer `h2`.
    pub const ALPN_HTTP11: &[u8] = b"http/1.1";

    /// The HTTP/2 connection preface (RFC 7540 §3.5) the client sends first on a
    /// cleartext-or-ALPN-`h2` connection, before any frame. The inspected path reads
    /// and forwards it verbatim; recognizing it confirms the stream is HTTP/2.
    pub const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    /// The fixed HTTP/2 frame header length (RFC 7540 §4.1): 3-byte length, 1-byte
    /// type, 1-byte flags, 4-byte (R + 31-bit) stream id.
    pub const FRAME_HEADER_LEN: usize = 9;

    /// HTTP/2 frame types (RFC 7540 §6) the inspected path distinguishes. Only the
    /// ones the per-stream demux + telemetry need are named; any other type is
    /// carried opaquely (the `Other(u8)` arm preserves its wire byte).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FrameType {
        /// DATA (`0x0`) — a stream's payload (never read into telemetry — D73).
        Data,
        /// HEADERS (`0x1`) — the header block the pseudo-headers are decoded from.
        Headers,
        /// PRIORITY (`0x2`).
        Priority,
        /// RST_STREAM (`0x3`).
        RstStream,
        /// SETTINGS (`0x4`) — connection-level, stream id 0.
        Settings,
        /// PUSH_PROMISE (`0x5`).
        PushPromise,
        /// PING (`0x6`).
        Ping,
        /// GOAWAY (`0x7`).
        Goaway,
        /// WINDOW_UPDATE (`0x8`) — flow control.
        WindowUpdate,
        /// CONTINUATION (`0x9`) — a HEADERS-block continuation.
        Continuation,
        /// Any other frame type, wire byte preserved.
        Other(u8),
    }

    impl FrameType {
        /// Map a wire type byte (RFC 7540 §6) to a [`FrameType`], preserving an
        /// unknown type's exact byte in [`FrameType::Other`].
        pub fn from_byte(b: u8) -> FrameType {
            match b {
                0x0 => FrameType::Data,
                0x1 => FrameType::Headers,
                0x2 => FrameType::Priority,
                0x3 => FrameType::RstStream,
                0x4 => FrameType::Settings,
                0x5 => FrameType::PushPromise,
                0x6 => FrameType::Ping,
                0x7 => FrameType::Goaway,
                0x8 => FrameType::WindowUpdate,
                0x9 => FrameType::Continuation,
                other => FrameType::Other(other),
            }
        }
    }

    // HEADERS frame flags (RFC 7540 §6.2).
    /// END_STREAM (`0x1`): the last frame the endpoint sends on the stream.
    pub const FLAG_END_STREAM: u8 = 0x1;
    /// END_HEADERS (`0x4`): this HEADERS/CONTINUATION completes the header block.
    pub const FLAG_END_HEADERS: u8 = 0x4;
    /// PADDED (`0x8`): the frame carries a leading pad-length byte + trailing pad.
    pub const FLAG_PADDED: u8 = 0x8;
    /// PRIORITY (`0x20`): a HEADERS frame carries the 5-byte priority prefix.
    pub const FLAG_PRIORITY: u8 = 0x20;

    /// Server-side ALPN selection (RFC 7301): given the client's offered protocol
    /// list, prefer `h2`, then `http/1.1`. Returns the selected protocol id, or
    /// `None` if the client offered neither (the handshake then proceeds with no
    /// ALPN, exactly as rustls would). PURE — the rustls SERVER config wiring is in
    /// `main.rs` (D40); this is the negotiation policy the inspected path advertises.
    pub fn select_alpn<'a, I>(client_offers: I) -> Option<&'static [u8]>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut saw_http11 = false;
        for offer in client_offers {
            if offer == ALPN_H2 {
                return Some(ALPN_H2);
            }
            if offer == ALPN_HTTP11 {
                saw_http11 = true;
            }
        }
        if saw_http11 {
            Some(ALPN_HTTP11)
        } else {
            None
        }
    }

    /// Whether `buf` begins with the RFC 7540 §3.5 HTTP/2 connection preface. Used
    /// by the inspected path to confirm an `h2`-negotiated connection before framing.
    pub fn starts_with_preface(buf: &[u8]) -> bool {
        buf.len() >= H2_PREFACE.len() && &buf[..H2_PREFACE.len()] == H2_PREFACE
    }

    /// A non-owning, byte-exact view over one parsed HTTP/2 frame (RFC 7540 §4.1) —
    /// the length, type, flags, and stream id — WITHOUT copying or rewriting a byte.
    /// The inspected path forwards frames OPAQUELY between the demuxed streams, so
    /// this exists to PROVE the multiplexing-transparency invariant: a frame parsed
    /// and then re-serialized from `raw` is byte-identical, and a stream of
    /// interleaved frames demuxes per stream id with no cross-stream corruption.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct H2FrameView<'a> {
        /// The declared payload length (RFC 7540 §4.1 24-bit length field).
        pub length: usize,
        /// The frame type (RFC 7540 §6).
        pub frame_type: FrameType,
        /// The 8-bit flags field (frame-type specific; see `FLAG_*`).
        pub flags: u8,
        /// The 31-bit stream identifier (the reserved high bit is masked off).
        /// Stream id `0` is the connection control stream (SETTINGS, PING, …).
        pub stream_id: u32,
        /// The exact total on-wire byte length of this frame (9-byte header +
        /// payload). `raw[..frame_len]` is the whole frame.
        pub frame_len: usize,
        /// The exact on-wire bytes of this frame (length `frame_len`).
        pub raw: &'a [u8],
    }

    impl<'a> H2FrameView<'a> {
        /// Parse the FIRST HTTP/2 frame at the start of `raw` (RFC 7540 §4.1),
        /// returning a byte-exact view. TOTAL and bounds-checked: a buffer too short
        /// for the 9-byte header or the declared payload yields `None` (need more
        /// bytes) — never a panic. No byte is rewritten: the returned view borrows
        /// `raw[..frame_len]`, so re-emitting `view.raw` reproduces the frame exactly
        /// (the transparency invariant the inspected path relies on for opaque
        /// per-stream forwarding).
        pub fn parse(raw: &'a [u8]) -> Option<H2FrameView<'a>> {
            if raw.len() < FRAME_HEADER_LEN {
                return None;
            }
            let length = ((raw[0] as usize) << 16) | ((raw[1] as usize) << 8) | (raw[2] as usize);
            let frame_type = FrameType::from_byte(raw[3]);
            let flags = raw[4];
            // The high bit of the stream-id word is reserved (R); mask it off.
            let stream_id = u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) & 0x7fff_ffff;
            let frame_len = FRAME_HEADER_LEN.checked_add(length)?;
            if raw.len() < frame_len {
                return None;
            }
            Some(H2FrameView {
                length,
                frame_type,
                flags,
                stream_id,
                frame_len,
                raw: &raw[..frame_len],
            })
        }

        /// The frame's payload slice (after the 9-byte header). For a HEADERS frame
        /// this still includes any PADDED/PRIORITY prefix; use
        /// [`H2FrameView::header_block_fragment`] to get the HPACK bytes.
        pub fn payload(&self) -> &'a [u8] {
            &self.raw[FRAME_HEADER_LEN..self.frame_len]
        }

        /// Whether the `END_HEADERS` flag is set (the header block ends at this
        /// HEADERS/CONTINUATION frame — RFC 7540 §6.2).
        pub fn end_headers(&self) -> bool {
            self.flags & FLAG_END_HEADERS != 0
        }

        /// Whether the `END_STREAM` flag is set (RFC 7540 §6.1/§6.2).
        pub fn end_stream(&self) -> bool {
            self.flags & FLAG_END_STREAM != 0
        }

        /// For a HEADERS frame, the HPACK header-block fragment: the payload with the
        /// optional PADDED pad-length byte + trailing pad and the optional PRIORITY
        /// 5-byte prefix stripped (RFC 7540 §6.2). Returns `None` if the frame is not
        /// a HEADERS frame or the padding/priority prefix does not fit. A
        /// CONTINUATION frame's whole payload IS the fragment (handled by the caller).
        pub fn header_block_fragment(&self) -> Option<&'a [u8]> {
            if self.frame_type != FrameType::Headers {
                return None;
            }
            let mut body = self.payload();
            let mut pad_len = 0usize;
            if self.flags & FLAG_PADDED != 0 {
                let (&first, rest) = body.split_first()?;
                pad_len = first as usize;
                body = rest;
            }
            if self.flags & FLAG_PRIORITY != 0 {
                if body.len() < 5 {
                    return None;
                }
                body = &body[5..];
            }
            if pad_len > body.len() {
                return None;
            }
            Some(&body[..body.len() - pad_len])
        }
    }

    /// Walk `buf` as a sequence of consecutive HTTP/2 frames, returning each as a
    /// byte-exact [`H2FrameView`] until the buffer is exhausted or a trailing partial
    /// frame remains. PROVES frame-stream transparency: concatenating every returned
    /// `view.raw` reproduces the consumed prefix of `buf` byte-identically (no type
    /// remap, no length rewrite, no re-framing). The returned `usize` is how many
    /// bytes were consumed into whole frames (a trailing partial frame is left for
    /// the next read, exactly as an opaque splice would carry it).
    pub fn iter_frames(buf: &[u8]) -> (Vec<H2FrameView<'_>>, usize) {
        let mut frames = Vec::new();
        let mut consumed = 0usize;
        while consumed < buf.len() {
            match H2FrameView::parse(&buf[consumed..]) {
                Some(view) => {
                    consumed += view.frame_len;
                    frames.push(view);
                }
                None => break, // trailing partial frame — leave it for the next read
            }
        }
        (frames, consumed)
    }

    /// Demultiplex a raw HTTP/2 byte stream into per-stream HEADERS header-block
    /// fragments, KEYED BY STREAM ID (RFC 7540 §5 multiplexing / §6.2 + §6.10
    /// CONTINUATION). Concatenates each stream's HEADERS + CONTINUATION fragments in
    /// arrival order — so even when distinct streams' frames are INTERLEAVED on the
    /// wire, each stream's header block reassembles independently (stream isolation;
    /// no head-of-line corruption). The connection-control stream (id 0) is skipped.
    /// PURE over the bytes; the live splice is `main.rs`'s residual.
    pub fn demux_header_blocks(buf: &[u8]) -> BTreeMap<u32, Vec<u8>> {
        let (frames, _consumed) = iter_frames(buf);
        let mut per_stream: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for f in frames {
            if f.stream_id == 0 {
                continue;
            }
            match f.frame_type {
                FrameType::Headers => {
                    if let Some(frag) = f.header_block_fragment() {
                        per_stream
                            .entry(f.stream_id)
                            .or_default()
                            .extend_from_slice(frag);
                    }
                }
                FrameType::Continuation => {
                    per_stream
                        .entry(f.stream_id)
                        .or_default()
                        .extend_from_slice(f.payload());
                }
                _ => {}
            }
        }
        per_stream
    }

    /// The decoded pseudo-headers of one HTTP/2 stream's request (or response) —
    /// the EXACT fields the per-stream LOG-1 telemetry carries (doc 09 §5 TLS-8).
    /// Each is optional because a request block carries `:method`/`:path`/
    /// `:authority` while a response block carries `:status`; the inspected path
    /// pairs a stream's request + response into one event. NO header VALUE beyond
    /// the pseudo-headers is retained (D73 never-log-the-secret).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct H2PseudoHeaders {
        /// `:method` (request, e.g. `GET`).
        pub method: Option<String>,
        /// `:path` (request origin-form target, e.g. `/stream/0`).
        pub path: Option<String>,
        /// `:authority` (request host — the origin attribution key).
        pub authority: Option<String>,
        /// `:status` (response status, e.g. `200`).
        pub status: Option<u16>,
    }

    /// The per-stream LOG-1 telemetry tuple for an HTTP/2 stream (doc 09 §5 TLS-8):
    /// `(method, host, path, status)` populated from the stream's decoded
    /// pseudo-headers. ONE per completed stream — the inspected path emits exactly
    /// this many `HttpEvent`s for an `h2` connection (never a DATA byte). `host`
    /// prefers `:authority`; the caller supplies the SNI fallback for a block that
    /// omitted it.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct StreamEvent {
        /// The request method (`:method`), default empty if absent.
        pub method: String,
        /// The origin host (`:authority` or the SNI fallback).
        pub host: String,
        /// The request path (`:path`), default empty if absent.
        pub path: String,
        /// The response status (`:status`), `0` if no response observed yet.
        pub status: u16,
    }

    /// Build the per-stream telemetry tuple from a stream's decoded pseudo-headers,
    /// using `sni_host` when the block carried no `:authority`. PURE; `main.rs` feeds
    /// the result to [`crate::telemetry_http::HttpEvent::from_exchange`].
    pub fn stream_event_fields(ph: &H2PseudoHeaders, sni_host: &str) -> StreamEvent {
        StreamEvent {
            method: ph.method.clone().unwrap_or_default(),
            host: ph
                .authority
                .clone()
                .filter(|a| !a.is_empty())
                .unwrap_or_else(|| sni_host.to_string()),
            path: ph.path.clone().unwrap_or_default(),
            status: ph.status.unwrap_or(0),
        }
    }

    // ── HPACK (RFC 7541) ────────────────────────────────────────────────────────
    //
    // Enough of RFC 7541 to recover the pseudo-headers off a real `h2` client's
    // request/response header block: the static table (Appendix A), the integer +
    // string primitives (§5.1/§5.2 — including the canonical Huffman code, Appendix
    // B, which Go's net/http2 + curl emit by default), and the four field
    // representations (§6): indexed (§6.1), literal-with-incremental-indexing (§6.2),
    // literal-without/never-indexed (§6.2), and dynamic-table size update (§6.3).
    // The dynamic table is maintained so indices into it resolve, but the
    // pseudo-headers the telemetry needs all live in the static table or arrive as
    // literals, so correctness does not hinge on dynamic eviction subtleties.

    /// The RFC 7541 Appendix A static table (index 1..=61) as `(name, value)` pairs.
    /// Index 0 is unused; the slice is 0-based so `STATIC_TABLE[i-1]` is HPACK index
    /// `i`. Only the entries needed to resolve the pseudo-headers + common request
    /// headers are correctness-critical, but the full table is included so any
    /// indexed field a real client emits resolves.
    pub const STATIC_TABLE: &[(&str, &str)] = &[
        (":authority", ""),
        (":method", "GET"),
        (":method", "POST"),
        (":path", "/"),
        (":path", "/index.html"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "200"),
        (":status", "204"),
        (":status", "206"),
        (":status", "304"),
        (":status", "400"),
        (":status", "404"),
        (":status", "500"),
        ("accept-charset", ""),
        ("accept-encoding", "gzip, deflate"),
        ("accept-language", ""),
        ("accept-ranges", ""),
        ("accept", ""),
        ("access-control-allow-origin", ""),
        ("age", ""),
        ("allow", ""),
        ("authorization", ""),
        ("cache-control", ""),
        ("content-disposition", ""),
        ("content-encoding", ""),
        ("content-language", ""),
        ("content-length", ""),
        ("content-location", ""),
        ("content-range", ""),
        ("content-type", ""),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("expect", ""),
        ("expires", ""),
        ("from", ""),
        ("host", ""),
        ("if-match", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("if-range", ""),
        ("if-unmodified-since", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("max-forwards", ""),
        ("proxy-authenticate", ""),
        ("proxy-authorization", ""),
        ("range", ""),
        ("referer", ""),
        ("refresh", ""),
        ("retry-after", ""),
        ("server", ""),
        ("set-cookie", ""),
        ("strict-transport-security", ""),
        ("transfer-encoding", ""),
        ("user-agent", ""),
        ("vary", ""),
        ("via", ""),
        ("www-authenticate", ""),
    ];

    /// A minimal RFC 7541 HPACK decoder: the static table, an in-order dynamic
    /// table (so dynamic indices resolve), and the §5/§6 primitives + field
    /// representations needed to decode a request/response header block to its
    /// `(name, value)` pairs. Pingora-free + stdlib-only (`forbid(unsafe_code)`).
    /// One decoder instance is kept per connection (a single HPACK context spans all
    /// streams on a connection — RFC 7541 §2.2), so `main.rs` reuses it across the
    /// connection's HEADERS blocks.
    #[derive(Debug, Default)]
    pub struct HpackDecoder {
        /// The dynamic table, most-recent-first (RFC 7541 §2.3.2): entries are
        /// `(name, value)`; index `i` (1-based, after the static table) resolves to
        /// `dynamic[i - 1]`.
        dynamic: Vec<(String, String)>,
        /// The dynamic-table size limit in HPACK "octets" (RFC 7541 §4.1). Tracked
        /// so a §6.3 size update is honored; the default is the RFC's 4096.
        max_size: usize,
        /// The current dynamic-table size (sum of each entry's §4.1 size).
        size: usize,
    }

    /// An HPACK decode failure (a malformed header block). The inspected path treats
    /// a decode failure as "no pseudo-headers recovered" (the stream still forwards
    /// opaquely); it never aborts the flow on a telemetry-decode miss.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum HpackError {
        /// The block ended mid-representation (truncated).
        Truncated,
        /// An index referenced an entry past the static + dynamic tables.
        BadIndex,
        /// A Huffman-encoded string was malformed (RFC 7541 §5.2 / Appendix B).
        BadHuffman,
        /// A decoded byte string was not valid UTF-8 (header names/values the
        /// pseudo-headers care about are ASCII).
        BadUtf8,
    }

    impl HpackDecoder {
        /// A fresh decoder with the RFC 7541 §4.2 default dynamic-table size (4096).
        pub fn new() -> HpackDecoder {
            HpackDecoder {
                dynamic: Vec::new(),
                max_size: 4096,
                size: 0,
            }
        }

        /// Resolve an HPACK table index (1-based; static then dynamic) to its
        /// `(name, value)`. RFC 7541 §2.3.3: index `i` in `1..=61` is the static
        /// table; `i > 61` is `dynamic[i - 62]`.
        fn entry(&self, index: usize) -> Option<(String, String)> {
            if index == 0 {
                return None;
            }
            if index <= STATIC_TABLE.len() {
                let (n, v) = STATIC_TABLE[index - 1];
                return Some((n.to_string(), v.to_string()));
            }
            let di = index - STATIC_TABLE.len() - 1;
            self.dynamic.get(di).cloned()
        }

        /// RFC 7541 §4.1 entry size: name + value octet counts + 32.
        fn entry_size(name: &str, value: &str) -> usize {
            name.len() + value.len() + 32
        }

        /// Insert into the dynamic table (RFC 7541 §2.3.2 / §4.4), evicting the
        /// oldest entries until the new size fits `max_size` (an entry larger than
        /// `max_size` empties the table per §4.4).
        fn insert_dynamic(&mut self, name: String, value: String) {
            let added = Self::entry_size(&name, &value);
            self.dynamic.insert(0, (name, value));
            self.size += added;
            self.evict_to_fit();
        }

        /// Set the dynamic-table size limit (RFC 7541 §6.3), evicting to fit.
        fn set_max_size(&mut self, new_max: usize) {
            self.max_size = new_max;
            self.evict_to_fit();
        }

        fn evict_to_fit(&mut self) {
            while self.size > self.max_size {
                match self.dynamic.pop() {
                    Some((n, v)) => self.size -= Self::entry_size(&n, &v),
                    None => {
                        self.size = 0;
                        break;
                    }
                }
            }
        }

        /// Decode a complete HPACK header block to its ordered `(name, value)` pairs
        /// (RFC 7541 §6), mutating the dynamic table for incremental-indexing fields
        /// and size updates. Returns the decoded list; a malformed block yields an
        /// [`HpackError`]. Pseudo-headers (`:method`/`:path`/`:authority`/`:status`)
        /// appear with their leading `:` exactly as on the wire.
        pub fn decode(&mut self, block: &[u8]) -> Result<Vec<(String, String)>, HpackError> {
            let mut out = Vec::new();
            let mut i = 0usize;
            while i < block.len() {
                let b = block[i];
                if b & 0x80 != 0 {
                    // §6.1 Indexed Header Field — 7-bit prefix index.
                    let (index, ni) = decode_integer(block, i, 7)?;
                    i = ni;
                    let (n, v) = self.entry(index).ok_or(HpackError::BadIndex)?;
                    out.push((n, v));
                } else if b & 0x40 != 0 {
                    // §6.2.1 Literal Header Field with Incremental Indexing — 6-bit
                    // prefix name index (0 ⇒ literal name follows).
                    let (name, value, ni) = self.decode_literal(block, i, 6)?;
                    i = ni;
                    self.insert_dynamic(name.clone(), value.clone());
                    out.push((name, value));
                } else if b & 0x20 != 0 {
                    // §6.3 Dynamic Table Size Update — 5-bit prefix new max size.
                    let (new_max, ni) = decode_integer(block, i, 5)?;
                    i = ni;
                    self.set_max_size(new_max);
                } else {
                    // §6.2.2/§6.2.3 Literal without / never indexed — 4-bit prefix
                    // name index (0 ⇒ literal name follows). Not added to the table.
                    let (name, value, ni) = self.decode_literal(block, i, 4)?;
                    i = ni;
                    out.push((name, value));
                }
            }
            Ok(out)
        }

        /// Decode a literal header field (RFC 7541 §6.2): the `prefix_bits`-wide name
        /// index (0 ⇒ a literal string name follows), then a literal string value.
        /// Returns `(name, value, next_index)`.
        fn decode_literal(
            &self,
            block: &[u8],
            start: usize,
            prefix_bits: u32,
        ) -> Result<(String, String, usize), HpackError> {
            let (name_index, after_index) = decode_integer(block, start, prefix_bits)?;
            let (name, after_name) = if name_index == 0 {
                decode_string(block, after_index)?
            } else {
                let (n, _v) = self.entry(name_index).ok_or(HpackError::BadIndex)?;
                (n, after_index)
            };
            let (value, after_value) = decode_string(block, after_name)?;
            Ok((name, value, after_value))
        }
    }

    /// Decode an HPACK variable-length integer (RFC 7541 §5.1) starting at
    /// `block[start]`, whose low `prefix_bits` bits hold the prefix. Returns
    /// `(value, next_index)`.
    fn decode_integer(
        block: &[u8],
        start: usize,
        prefix_bits: u32,
    ) -> Result<(usize, usize), HpackError> {
        let mask = (1usize << prefix_bits) - 1;
        let first = *block.get(start).ok_or(HpackError::Truncated)? as usize;
        let mut value = first & mask;
        let mut i = start + 1;
        if value < mask {
            return Ok((value, i));
        }
        // The continuation octets carry 7 bits each, low bit-order first (§5.1).
        let mut shift = 0u32;
        loop {
            let byte = *block.get(i).ok_or(HpackError::Truncated)? as usize;
            i += 1;
            value = value
                .checked_add((byte & 0x7f) << shift)
                .ok_or(HpackError::Truncated)?;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > usize::BITS {
                return Ok((value, i)); // implausibly large — stop without overflow
            }
        }
        Ok((value, i))
    }

    /// Decode an HPACK string literal (RFC 7541 §5.2): a 7-bit-prefix length with a
    /// high `H` bit selecting Huffman (Appendix B) vs raw octets. Returns
    /// `(string, next_index)`.
    fn decode_string(block: &[u8], start: usize) -> Result<(String, usize), HpackError> {
        let first = *block.get(start).ok_or(HpackError::Truncated)?;
        let huffman = first & 0x80 != 0;
        let (len, after_len) = decode_integer(block, start, 7)?;
        let end = after_len.checked_add(len).ok_or(HpackError::Truncated)?;
        let bytes = block.get(after_len..end).ok_or(HpackError::Truncated)?;
        let s = if huffman {
            huffman_decode(bytes)?
        } else {
            String::from_utf8(bytes.to_vec()).map_err(|_| HpackError::BadUtf8)?
        };
        Ok((s, end))
    }

    /// Decode an HPACK static-Huffman (RFC 7541 Appendix B) octet string. Walks the
    /// canonical code bit-by-bit via the built [`HuffmanNode`] tree; trailing
    /// all-ones padding (up to 7 bits, §5.2) is discarded. A symbol resolving to the
    /// 256 EOS or a non-padding leftover is a malformed block.
    fn huffman_decode(bytes: &[u8]) -> Result<String, HpackError> {
        let tree = huffman_tree();
        let mut out: Vec<u8> = Vec::new();
        let mut node = 0usize;
        // The trailing partial symbol (if any) must be the RFC 7541 §5.2 EOS padding:
        // all 1-bits and at most 7 bits. Track its length + whether every bit was a 1.
        let mut pad_bits = 0u32;
        let mut pad_all_ones = true;
        for &byte in bytes {
            for bit in (0..8).rev() {
                let b = (byte >> bit) & 1;
                let next = if b == 0 {
                    tree[node].left
                } else {
                    tree[node].right
                };
                let next = next.ok_or(HpackError::BadHuffman)?;
                pad_bits += 1;
                if b == 0 {
                    pad_all_ones = false;
                }
                match tree[next].sym {
                    Some(256) => return Err(HpackError::BadHuffman), // EOS in stream
                    Some(s) => {
                        out.push(s as u8);
                        node = 0;
                        pad_bits = 0;
                        pad_all_ones = true;
                    }
                    None => node = next,
                }
            }
        }
        // A partial symbol at the end is valid ONLY as EOS padding: ≤7 all-ones bits.
        if node != 0 && (pad_bits > 7 || !pad_all_ones) {
            return Err(HpackError::BadHuffman);
        }
        String::from_utf8(out).map_err(|_| HpackError::BadUtf8)
    }

    /// One node of the canonical HPACK Huffman tree (RFC 7541 Appendix B): a binary
    /// node with optional children and an optional terminal symbol (`256` = EOS).
    #[derive(Clone, Copy, Debug, Default)]
    struct HuffmanNode {
        left: Option<usize>,
        right: Option<usize>,
        sym: Option<u16>,
    }

    /// Build the canonical HPACK Huffman decode tree (RFC 7541 Appendix B) from the
    /// `(code, bit_length)` table. Each symbol's MSB-first code path threads child
    /// nodes; the EOS symbol (256) terminates a path so an EOS appearing IN the
    /// stream is rejected.
    fn huffman_tree() -> Vec<HuffmanNode> {
        let table = HUFFMAN_CODES;
        let mut nodes: Vec<HuffmanNode> = vec![HuffmanNode::default()]; // root = 0
        for (sym, &(code, bits)) in table.iter().enumerate() {
            let mut node = 0usize;
            for bit in (0..bits).rev() {
                let b = (code >> bit) & 1;
                let child = if b == 0 {
                    nodes[node].left
                } else {
                    nodes[node].right
                };
                let next = match child {
                    Some(n) => n,
                    None => {
                        nodes.push(HuffmanNode::default());
                        let n = nodes.len() - 1;
                        if b == 0 {
                            nodes[node].left = Some(n);
                        } else {
                            nodes[node].right = Some(n);
                        }
                        n
                    }
                };
                node = next;
            }
            nodes[node].sym = Some(sym as u16);
        }
        nodes
    }

    /// The canonical HPACK Huffman code table (RFC 7541 Appendix B), indexed by
    /// symbol `0..=255` then EOS `256`, each `(code, bit_length)`.
    #[rustfmt::skip]
    const HUFFMAN_CODES: &[(u32, u32)] = &[
        (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
        (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
        (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
        (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
        (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
        (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
        (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
        (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
        (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
        (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
        (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
        (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
        (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
        (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
        (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
        (0x7ffc, 15), (0x20, 6), (0xffd, 12), (0x3fc, 10),
        (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
        (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
        (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
        (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
        (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
        (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
        (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
        (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
        (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
        (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
        (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
        (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
        (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
        (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
        (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
        (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
        (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
        (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
        (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
        (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
        (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
        (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
        (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
        (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
        (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
        (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
        (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
        (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
        (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
        (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
        (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
        (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
        (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
        (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
        (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
        (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
        (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
        (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
        (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
        (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
        (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
        (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
        (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
        (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
        (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
        (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
        (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
        (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
        (0x3fffffff, 30),
    ];

    /// Convenience: decode a single stream's HEADERS block to its pseudo-headers,
    /// pairing later (the inspected path merges a request block + a response block
    /// for one stream into one event). Non-pseudo headers are ignored (never logged).
    pub fn pseudo_headers_from_block(
        decoder: &mut HpackDecoder,
        block: &[u8],
    ) -> Result<H2PseudoHeaders, HpackError> {
        let fields = decoder.decode(block)?;
        let mut ph = H2PseudoHeaders::default();
        for (name, value) in fields {
            match name.as_str() {
                ":method" => ph.method = Some(value),
                ":path" => ph.path = Some(value),
                ":authority" => ph.authority = Some(value),
                ":status" => ph.status = value.parse().ok(),
                _ => {}
            }
        }
        Ok(ph)
    }

    // ── gRPC (HTTP/2 + application/grpc + trailers) ───────────────────────────────
    //
    // gRPC is NOT a special protocol to the proxy: it is HTTP/2 (RFC 7540) with an
    // `application/grpc{+proto}` content-type and RFC 7540 §8.1 trailing headers —
    // a SECOND HEADERS frame on the stream, sent after the DATA frames, carrying the
    // `grpc-status`/`grpc-message` trailers (gRPC HTTP/2 spec). The inspected path
    // already carries every frame OPAQUELY (the `H2FrameView` round-trip proves a
    // trailers HEADERS frame survives byte-identically, same as any other frame), so
    // "the proxy carries trailers intact" is a property of the existing frame-stream
    // transparency — there is NO special handling on the splice. Unary and
    // server-streaming differ only in DATA-frame count; both ride the SAME stream
    // shape (initial HEADERS → DATA* → trailers HEADERS), so both are supported by
    // construction.
    //
    // What gRPC DOES change for the telemetry side is that a stream now carries TWO
    // HEADERS blocks (initial pseudo-headers + trailers), each its own RFC 7541
    // header block. The existing `demux_header_blocks` concatenates ALL of a stream's
    // HEADERS+CONTINUATION fragments, which fuses those two independent blocks into
    // one byte run — a malformed HPACK stream that can corrupt the per-stream event's
    // `:status`. The helpers below keep the two blocks SEPARATE per stream so the
    // initial-block pseudo-headers (`:status` = 200) stay correct AND the trailers
    // (`grpc-status` = 0) are recoverable to prove they survived inspection. D73
    // holds the same way it does for HTTP/2: telemetry is built from HEADERS/TRAILERS
    // metadata only — never a DATA-frame byte (a body byte never reaches an event).

    /// The gRPC content-type prefix (gRPC over HTTP/2 spec): a gRPC message frame's
    /// `content-type` is `application/grpc` optionally suffixed with a message-codec
    /// (`+proto`, `+json`, …). [`is_grpc_content_type`] recognizes the family so the
    /// inspected path can tag a stream as gRPC for telemetry (the WIRE handling is
    /// identical to any other `h2` stream — gRPC needs no special splice).
    pub const GRPC_CONTENT_TYPE_PREFIX: &str = "application/grpc";

    /// Whether a `content-type` header value names the gRPC family
    /// (`application/grpc`, `application/grpc+proto`, `application/grpc+json`, …),
    /// per the gRPC-over-HTTP/2 spec. Case-insensitive on the media type; a `+codec`
    /// suffix or trailing parameters are accepted. PURE — `main.rs` reads the
    /// `content-type` literal off the decoded (non-pseudo) headers and calls this.
    pub fn is_grpc_content_type(content_type: &str) -> bool {
        let ct = content_type.trim();
        let media = ct.split(';').next().unwrap_or("").trim();
        if !media
            .get(..GRPC_CONTENT_TYPE_PREFIX.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(GRPC_CONTENT_TYPE_PREFIX))
        {
            return false;
        }
        // Either an exact `application/grpc` or an `application/grpc+codec` suffix —
        // never `application/grpcfoo` (a different media type that merely shares the
        // prefix).
        match media[GRPC_CONTENT_TYPE_PREFIX.len()..].chars().next() {
            None => true,
            Some('+') => true,
            Some(_) => false,
        }
    }

    /// The gRPC call trailers (gRPC-over-HTTP/2 spec): the `grpc-status` (a numeric
    /// status code, `0` = OK) and the optional human-readable `grpc-message`,
    /// carried in the stream's TRAILING HEADERS block (RFC 7540 §8.1). These are
    /// status metadata, NOT payload (D73: a body byte never lands here — the
    /// trailers block is a HEADERS frame, decoded by HPACK, distinct from the DATA
    /// frames that carry the message bytes). The inspected path reads them to PROVE
    /// the trailers survived inspection; the wire still forwards the frame opaquely.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct GrpcTrailers {
        /// `grpc-status` (e.g. `"0"` for OK) — `None` if the trailers block omitted
        /// it (a malformed / non-gRPC trailers block).
        pub status: Option<String>,
        /// `grpc-message` — the optional status detail string.
        pub message: Option<String>,
    }

    impl GrpcTrailers {
        /// Whether the trailers report gRPC success (`grpc-status: 0`). The boundary
        /// asserts `Grpc-Status` reads back `"0"` after inspection.
        pub fn is_ok(&self) -> bool {
            self.status.as_deref() == Some("0")
        }
    }

    /// Decode a stream's TRAILERS HEADERS block (RFC 7540 §8.1) to its gRPC trailers.
    /// Trailers are ordinary (non-pseudo) HPACK header fields, so this shares the
    /// connection HPACK [`HpackDecoder`] used for the rest of the same direction's
    /// blocks (RFC 7541 §2.2 — one context per connection). `grpc-status` /
    /// `grpc-message` are matched case-insensitively. NON-trailer fields are ignored
    /// (never logged — D73). A malformed block yields an [`HpackError`] (the inspected
    /// path treats that as "no trailers recovered" and never fails the flow).
    pub fn grpc_trailers_from_block(
        decoder: &mut HpackDecoder,
        block: &[u8],
    ) -> Result<GrpcTrailers, HpackError> {
        let fields = decoder.decode(block)?;
        let mut tr = GrpcTrailers::default();
        for (name, value) in fields {
            // Header names are lowercase on the HTTP/2 wire (RFC 7540 §8.1.2), but
            // match case-insensitively to be robust to a literal-uppercased name.
            if name.eq_ignore_ascii_case("grpc-status") {
                tr.status = Some(value);
            } else if name.eq_ignore_ascii_case("grpc-message") {
                tr.message = Some(value);
            }
        }
        Ok(tr)
    }

    /// One HTTP/2 stream's HEADERS blocks, split into the INITIAL block (the
    /// request's pseudo-headers, or a response's `:status` + headers) and the
    /// optional TRAILERS block (RFC 7540 §8.1 — the second HEADERS block, sent after
    /// the DATA frames; in gRPC it carries `grpc-status`/`grpc-message`). Splitting
    /// them is the load-bearing gRPC fix: the two are INDEPENDENT RFC 7541 header
    /// blocks, so fusing them (as a naive whole-stream concat would) yields a
    /// malformed HPACK stream that corrupts the initial block's `:status`. Keyed by
    /// the [`demux_stream_header_blocks`] result's stream id.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct StreamHeaderBlocks {
        /// The stream's first HEADERS block (HEADERS + its CONTINUATIONs), reassembled
        /// in arrival order. Empty if the stream carried no HEADERS frame.
        pub initial: Vec<u8>,
        /// The stream's TRAILERS block, present only if a SECOND HEADERS block opened
        /// on the stream after a DATA frame (RFC 7540 §8.1). `None` for a plain
        /// (non-trailers, e.g. ordinary HTTP/2) stream.
        pub trailers: Option<Vec<u8>>,
    }

    /// Demultiplex a raw HTTP/2 byte stream into per-stream [`StreamHeaderBlocks`],
    /// KEYED BY STREAM ID, distinguishing each stream's INITIAL HEADERS block from a
    /// TRAILERS HEADERS block (RFC 7540 §5 multiplexing + §8.1 trailers). The split
    /// rule follows the wire: the first HEADERS block on a stream is `initial`; a
    /// HEADERS frame that opens AFTER a DATA frame on the same stream starts the
    /// `trailers` block. CONTINUATION frames extend whichever block is currently open
    /// for that stream. The control stream (id 0) is skipped. Interleaved streams
    /// demux independently (no head-of-line corruption) — exactly as
    /// [`demux_header_blocks`] does, but trailer-aware so gRPC's two-block streams
    /// decode correctly. PURE over the bytes; the live splice is `main.rs`'s residual.
    pub fn demux_stream_header_blocks(buf: &[u8]) -> BTreeMap<u32, StreamHeaderBlocks> {
        let (frames, _consumed) = iter_frames(buf);
        let mut per_stream: BTreeMap<u32, StreamHeaderBlocks> = BTreeMap::new();
        // Per stream: has a DATA frame been seen since the initial HEADERS block
        // closed? A HEADERS frame after that opens the trailers block (RFC 7540 §8.1).
        let mut saw_data: BTreeMap<u32, bool> = BTreeMap::new();
        // Per stream: which block is currently being appended to by CONTINUATIONs —
        // `false` = initial, `true` = trailers.
        let mut continuing_trailers: BTreeMap<u32, bool> = BTreeMap::new();
        for f in frames {
            if f.stream_id == 0 {
                continue;
            }
            match f.frame_type {
                FrameType::Data => {
                    saw_data.insert(f.stream_id, true);
                }
                FrameType::Headers => {
                    if let Some(frag) = f.header_block_fragment() {
                        let slot = per_stream.entry(f.stream_id).or_default();
                        let is_trailers = *saw_data.get(&f.stream_id).unwrap_or(&false)
                            && !slot.initial.is_empty();
                        if is_trailers {
                            slot.trailers
                                .get_or_insert_with(Vec::new)
                                .extend_from_slice(frag);
                        } else {
                            slot.initial.extend_from_slice(frag);
                        }
                        continuing_trailers.insert(f.stream_id, is_trailers);
                    }
                }
                FrameType::Continuation => {
                    let to_trailers = *continuing_trailers.get(&f.stream_id).unwrap_or(&false);
                    let slot = per_stream.entry(f.stream_id).or_default();
                    if to_trailers {
                        slot.trailers
                            .get_or_insert_with(Vec::new)
                            .extend_from_slice(f.payload());
                    } else {
                        slot.initial.extend_from_slice(f.payload());
                    }
                }
                _ => {}
            }
        }
        per_stream
    }

    #[cfg(test)]
    mod tests {
        // Each test name carries the literal `HTTP2` token so the acceptance filter
        // `cargo test -p ds-tlsproxy --locked HTTP2` (a case-sensitive substring
        // match) selects them; the inner attribute silences the resulting
        // non-snake-case lint for the whole test module.
        #![allow(non_snake_case)]

        use super::*;

        // ── ALPN negotiation (RFC 7301) — the HTTP2 downstream protocol ─────────

        #[test]
        fn select_alpn_prefers_h2_over_http11_HTTP2() {
            // The boundary asserts the downstream-negotiated protocol is `h2` when the
            // client offers {h2, http/1.1}; the server must select h2.
            let offers: Vec<&[u8]> = vec![b"h2", b"http/1.1"];
            assert_eq!(select_alpn(offers.iter().copied()), Some(ALPN_H2));
        }

        #[test]
        fn select_alpn_falls_back_to_http11_then_none_HTTP2() {
            let only11: Vec<&[u8]> = vec![b"http/1.1"];
            assert_eq!(select_alpn(only11.iter().copied()), Some(ALPN_HTTP11));
            let neither: Vec<&[u8]> = vec![b"spdy/3.1"];
            assert_eq!(select_alpn(neither.iter().copied()), None);
        }

        // ── frame demux + transparency (RFC 7540 §4.1/§5) ────────────────────────

        /// Build an HTTP/2 frame the way the wire encodes it (RFC 7540 §4.1).
        fn frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
            let len = payload.len();
            let mut b = vec![
                (len >> 16) as u8,
                (len >> 8) as u8,
                len as u8,
                frame_type,
                flags,
            ];
            b.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
            b.extend_from_slice(payload);
            b
        }

        #[test]
        fn h2_frame_parses_and_round_trips_byte_identically_HTTP2() {
            // A HEADERS frame for stream 1: the view exposes type/flags/stream id and
            // re-emitting view.raw reproduces the frame byte-for-byte (transparency).
            let wire = frame(0x1, FLAG_END_HEADERS | FLAG_END_STREAM, 1, b"\x82\x84");
            let v = H2FrameView::parse(&wire).expect("parse HEADERS frame");
            assert_eq!(v.frame_type, FrameType::Headers);
            assert!(v.end_headers());
            assert!(v.end_stream());
            assert_eq!(v.stream_id, 1);
            assert_eq!(v.frame_len, wire.len());
            assert_eq!(v.raw, wire.as_slice(), "frame round-trips byte-identically");
        }

        #[test]
        fn h2_partial_frame_parse_returns_none_never_panics_HTTP2() {
            let wire = frame(0x0, 0, 3, b"stream-payload:/data");
            for short in 0..wire.len() {
                assert!(
                    H2FrameView::parse(&wire[..short]).is_none(),
                    "a {short}-byte prefix of a {}-byte frame must be incomplete",
                    wire.len()
                );
            }
            assert!(H2FrameView::parse(&wire).is_some());
        }

        #[test]
        fn interleaved_streams_demux_without_head_of_line_corruption_HTTP2() {
            // The headline TLS-8 contract: concurrent streams (n=4) multiplex over one
            // connection. Build INTERLEAVED HEADERS frames for streams 1,3,5,7 (the
            // odd, client-initiated ids), each carrying a distinct path, and prove each
            // stream's header block demuxes independently — no cross-stream mixing,
            // no head-of-line corruption.
            let mut decoder = HpackDecoder::new();
            // Encode each stream's :method GET (static idx 2 -> 0x82) + a literal :path.
            let mk_headers = |path: &str| -> Vec<u8> {
                // Indexed :method GET (0x82), then a literal :path (static name index
                // 4) with a raw (non-Huffman) value.
                let mut block = vec![0x82];
                block.push(0x04);
                block.push(path.len() as u8); // H=0, len
                block.extend_from_slice(path.as_bytes());
                block
            };
            let s1 = frame(0x1, FLAG_END_HEADERS, 1, &mk_headers("/stream/0"));
            let s3 = frame(0x1, FLAG_END_HEADERS, 3, &mk_headers("/stream/1"));
            let s5 = frame(0x1, FLAG_END_HEADERS, 5, &mk_headers("/stream/2"));
            let s7 = frame(0x1, FLAG_END_HEADERS, 7, &mk_headers("/stream/3"));
            // Interleave on the wire AND prepend a connection-control SETTINGS frame.
            let settings = frame(0x4, 0, 0, &[]);
            let mut wire = Vec::new();
            for chunk in [&settings, &s5, &s1, &s7, &s3] {
                wire.extend_from_slice(chunk);
            }

            let blocks = demux_header_blocks(&wire);
            // The control stream (id 0) is excluded; the four request streams remain.
            assert_eq!(
                blocks.keys().copied().collect::<Vec<_>>(),
                vec![1, 3, 5, 7],
                "exactly the four client streams demux (control stream 0 excluded)"
            );
            // Each stream's block decodes to ITS OWN path — no head-of-line corruption.
            let expected = [
                (1u32, "/stream/0"),
                (3, "/stream/1"),
                (5, "/stream/2"),
                (7, "/stream/3"),
            ];
            for (sid, want_path) in expected {
                let block = &blocks[&sid];
                let ph = pseudo_headers_from_block(&mut decoder, block).expect("decode");
                assert_eq!(ph.method.as_deref(), Some("GET"), "stream {sid} :method");
                assert_eq!(ph.path.as_deref(), Some(want_path), "stream {sid} :path");
            }
        }

        // ── HPACK integer + string primitives (RFC 7541 §5) ──────────────────────

        #[test]
        fn hpack_integer_decodes_single_and_multi_octet_HTTP2() {
            // RFC 7541 §5.1 examples: 10 in a 5-bit prefix is one octet; 1337 in a
            // 5-bit prefix is the three-octet 0x1f 0x9a 0x0a.
            assert_eq!(decode_integer(&[0x0a], 0, 5).unwrap(), (10, 1));
            assert_eq!(
                decode_integer(&[0x1f, 0x9a, 0x0a], 0, 5).unwrap(),
                (1337, 3)
            );
        }

        #[test]
        fn hpack_huffman_decodes_the_rfc7541_examples_HTTP2() {
            // RFC 7541 Appendix C.4.1: "www.example.com" Huffman-encodes to the 12
            // octets below. Appendix C.6.1: "302" -> 0x64 0x02.
            let www = [
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ];
            assert_eq!(huffman_decode(&www).unwrap(), "www.example.com");
            assert_eq!(huffman_decode(&[0x64, 0x02]).unwrap(), "302");
        }

        // ── HPACK field representations (RFC 7541 §6) ─────────────────────────────

        #[test]
        fn hpack_decodes_a_full_request_header_block_HTTP2() {
            // RFC 7541 Appendix C.3.1 first request, but encode it with the static
            // table the way Go's net/http2 does: indexed :method GET (0x82),
            // :scheme https (0x87), :path / (0x84), then a literal-with-incremental-
            // indexing :authority www.example.com (0x41 = static name idx 1, value
            // raw). The decoder must recover the four pseudo-headers exactly.
            let mut block = vec![0x82, 0x87, 0x84];
            let authority = "www.example.com";
            block.push(0x41); // literal-with-incremental-indexing, name idx 1 (:authority)
            block.push(authority.len() as u8); // raw value, length
            block.extend_from_slice(authority.as_bytes());

            let mut dec = HpackDecoder::new();
            let ph = pseudo_headers_from_block(&mut dec, &block).expect("decode request block");
            assert_eq!(ph.method.as_deref(), Some("GET"));
            assert_eq!(ph.path.as_deref(), Some("/"));
            assert_eq!(ph.authority.as_deref(), Some("www.example.com"));
            assert_eq!(ph.status, None, "a request block carries no :status");
        }

        #[test]
        fn hpack_decodes_a_response_status_HTTP2() {
            // A response header block: indexed :status 200 (static idx 8 -> 0x88).
            let mut dec = HpackDecoder::new();
            let ph = pseudo_headers_from_block(&mut dec, &[0x88]).expect("decode response");
            assert_eq!(ph.status, Some(200));
            assert_eq!(ph.method, None, "a response block carries no :method");
        }

        #[test]
        fn hpack_decodes_a_huffman_literal_path_HTTP2() {
            // A literal :path whose VALUE is Huffman-encoded (the H bit set) — the
            // form a real h2 client uses for a non-static path.
            // Build: literal-without-indexing, name idx 4 (:path) -> 0x04, then a
            // Huffman string of "/stream/3".
            let path = "/stream/3";
            // Huffman-encode "/stream/3" with the canonical table for the fixture.
            let huff = huffman_encode_for_test(path.as_bytes());
            let mut block = vec![0x04]; // literal w/o indexing, name idx 4 (:path)
            block.push(0x80 | huff.len() as u8); // H=1, length
            block.extend_from_slice(&huff);

            let mut dec = HpackDecoder::new();
            let ph = pseudo_headers_from_block(&mut dec, &block).expect("decode huffman path");
            assert_eq!(ph.path.as_deref(), Some(path));
        }

        /// Test-only HPACK Huffman ENCODER (the decoder is the production surface).
        /// Encodes `data` with the canonical Appendix B table + all-ones EOS padding,
        /// so a fixture can produce a Huffman string the decoder must recover.
        fn huffman_encode_for_test(data: &[u8]) -> Vec<u8> {
            let mut bits: Vec<bool> = Vec::new();
            for &byte in data {
                let (code, len) = HUFFMAN_CODES[byte as usize];
                for bit in (0..len).rev() {
                    bits.push((code >> bit) & 1 == 1);
                }
            }
            while !bits.len().is_multiple_of(8) {
                bits.push(true); // EOS padding is all 1s
            }
            bits.chunks(8)
                .map(|c| {
                    c.iter()
                        .enumerate()
                        .fold(0u8, |acc, (i, &b)| acc | ((b as u8) << (7 - i)))
                })
                .collect()
        }

        // ── per-stream telemetry shape (doc 09 §5 TLS-8) ─────────────────────────

        #[test]
        fn stream_event_fields_populate_method_host_path_status_HTTP2() {
            // The per-stream event carries the EXACT fields the boundary asserts:
            // method/host/path/status off the stream's pseudo-headers.
            let ph = H2PseudoHeaders {
                method: Some("GET".into()),
                path: Some("/stream/2".into()),
                authority: Some("h2.example".into()),
                status: Some(200),
            };
            let ev = stream_event_fields(&ph, "sni-fallback.example");
            assert_eq!(ev.method, "GET");
            assert_eq!(ev.host, "h2.example", ":authority is the host");
            assert_eq!(ev.path, "/stream/2");
            assert_eq!(ev.status, 200);
        }

        #[test]
        fn stream_event_falls_back_to_sni_host_HTTP2() {
            // A block omitting :authority attributes to the SNI host.
            let ph = H2PseudoHeaders {
                method: Some("GET".into()),
                path: Some("/x".into()),
                authority: None,
                status: None,
            };
            let ev = stream_event_fields(&ph, "h2.example");
            assert_eq!(ev.host, "h2.example", "SNI fallback when :authority absent");
            assert_eq!(ev.status, 0, "no response observed yet");
        }

        #[test]
        fn h2_telemetry_carries_no_data_frame_byte_HTTP2() {
            // D73 never-log-the-secret: a DATA frame's payload (a stand-in for a body
            // byte) never reaches a stream event — the event is built ONLY from the
            // HEADERS pseudo-headers. Demux a stream with both a HEADERS and a DATA
            // frame carrying a canary; the decoded event must not contain the canary.
            const DATA_CANARY: &str = "H2-DATA-PAYLOAD-CANARY-9c4f";
            let mut block = vec![0x82]; // :method GET
            block.push(0x04); // literal :path
            let path = "/stream/0";
            block.push(path.len() as u8);
            block.extend_from_slice(path.as_bytes());
            let headers = frame(0x1, FLAG_END_HEADERS, 1, &block);
            let data = frame(0x0, 0, 1, DATA_CANARY.as_bytes());
            let mut wire = headers.clone();
            wire.extend_from_slice(&data);

            let blocks = demux_header_blocks(&wire);
            let mut dec = HpackDecoder::new();
            let ph = pseudo_headers_from_block(&mut dec, &blocks[&1]).expect("decode");
            let ev = stream_event_fields(&ph, "h2.example");
            for f in [ev.method.as_str(), ev.host.as_str(), ev.path.as_str()] {
                assert!(
                    !f.contains(DATA_CANARY),
                    "a stream event field leaked a DATA-frame canary: {f:?}"
                );
            }
            assert_eq!(ev.path, "/stream/0");
        }

        #[test]
        fn preface_recognized_HTTP2() {
            let mut wire = H2_PREFACE.to_vec();
            wire.extend_from_slice(&frame(0x4, 0, 0, &[]));
            assert!(starts_with_preface(&wire));
            assert!(!starts_with_preface(b"GET / HTTP/1.1\r\n"));
        }

        // ── gRPC (HTTP/2 + application/grpc + trailers) ──────────────────────────

        /// A trailers HEADERS block carrying `grpc-status: 0` (+ optional message),
        /// encoded as literal-without-indexing fields (name idx 0 ⇒ literal name),
        /// raw (non-Huffman) values — the shape Go's gRPC server emits.
        fn grpc_trailers_block(status: &str, message: Option<&str>) -> Vec<u8> {
            let mut block = Vec::new();
            let push_literal = |block: &mut Vec<u8>, name: &str, value: &str| {
                block.push(0x00); // literal w/o indexing, name idx 0 ⇒ literal name
                block.push(name.len() as u8);
                block.extend_from_slice(name.as_bytes());
                block.push(value.len() as u8);
                block.extend_from_slice(value.as_bytes());
            };
            push_literal(&mut block, "grpc-status", status);
            if let Some(m) = message {
                push_literal(&mut block, "grpc-message", m);
            }
            block
        }

        #[test]
        fn grpc_content_type_family_is_recognized_gRPC() {
            // The gRPC content-type family per the gRPC-over-HTTP/2 spec.
            assert!(is_grpc_content_type("application/grpc"));
            assert!(is_grpc_content_type("application/grpc+proto"));
            assert!(is_grpc_content_type("application/grpc+json"));
            assert!(is_grpc_content_type("Application/GRPC")); // case-insensitive
            assert!(is_grpc_content_type("application/grpc; charset=utf-8"));
            // Not gRPC: a different media type that merely shares the prefix, or plain
            // HTTP content-types.
            assert!(!is_grpc_content_type("application/grpcfoo"));
            assert!(!is_grpc_content_type("application/json"));
            assert!(!is_grpc_content_type("text/plain"));
        }

        #[test]
        fn grpc_trailers_decode_status_and_message_gRPC() {
            // The trailers HEADERS block decodes to grpc-status (+ message) — these
            // are ordinary (non-pseudo) header fields, so the connection HPACK
            // decoder reads them after any prior block on the same direction.
            let mut dec = HpackDecoder::new();
            let block = grpc_trailers_block("0", Some("OK"));
            let tr = grpc_trailers_from_block(&mut dec, &block).expect("decode trailers");
            assert_eq!(tr.status.as_deref(), Some("0"));
            assert_eq!(tr.message.as_deref(), Some("OK"));
            assert!(tr.is_ok(), "grpc-status 0 is success");

            // A non-zero status with no message.
            let mut dec2 = HpackDecoder::new();
            let block2 = grpc_trailers_block("5", None);
            let tr2 = grpc_trailers_from_block(&mut dec2, &block2).expect("decode");
            assert_eq!(tr2.status.as_deref(), Some("5"));
            assert_eq!(tr2.message, None);
            assert!(!tr2.is_ok());
        }

        #[test]
        fn grpc_unary_stream_splits_initial_headers_from_trailers_gRPC() {
            // A unary gRPC response stream: initial HEADERS (:status 200) → one DATA
            // frame (the message) → trailers HEADERS (grpc-status 0). The demux must
            // keep the two HEADERS blocks SEPARATE so the initial :status decodes to
            // 200 AND the trailers decode to grpc-status 0 — a naive whole-stream
            // concat would fuse them into a malformed HPACK run.
            let sid = 1u32;
            let initial = frame(0x1, FLAG_END_HEADERS, sid, &[0x88]); // :status 200
            let data = frame(0x0, 0, sid, b"grpc-frame-unary-payload");
            let trailers = frame(
                0x1,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                sid,
                &grpc_trailers_block("0", None),
            );
            let mut wire = initial;
            wire.extend_from_slice(&data);
            wire.extend_from_slice(&trailers);

            let blocks = demux_stream_header_blocks(&wire);
            let stream = &blocks[&sid];
            assert!(
                stream.trailers.is_some(),
                "the trailers block is recognized"
            );

            let mut idec = HpackDecoder::new();
            let ph = pseudo_headers_from_block(&mut idec, &stream.initial).expect("decode initial");
            assert_eq!(ph.status, Some(200), "initial block :status decodes to 200");

            let mut tdec = HpackDecoder::new();
            let tr = grpc_trailers_from_block(&mut tdec, stream.trailers.as_ref().unwrap())
                .expect("decode trailers");
            assert!(tr.is_ok(), "trailers survive: grpc-status 0");
        }

        #[test]
        fn grpc_trailers_block_corrupts_status_under_fused_demux_gRPC() {
            // NON-VACUOUS proof that the trailer-aware demux is load-bearing: a stream
            // whose trailers block, when FUSED with the initial block (the older
            // whole-stream `demux_header_blocks`), MIS-DECODES the per-stream `:status`,
            // and is RECOVERED only by `demux_stream_header_blocks` keeping the two
            // blocks separate.
            //
            // The wire: initial HEADERS `:status 200` (indexed, `0x88`) → DATA → a
            // trailers HEADERS block that carries `grpc-status 0` AND — exactly the
            // hostile/edge shape RFC 7540 §8.1 forbids but the wire can still PRESENT
            // (a buggy/adversarial peer, or any field whose decode bleeds into the
            // status) — a literal `:status 500`. Under the OLD fused demux the decoder
            // sees BOTH `:status` fields in one block and the LAST one wins
            // (`pseudo_headers_from_block` keeps the last `:status`), so the event
            // status flips to 500. Under the trailer-aware demux only the INITIAL block
            // is read for `:status`, so it stays 200 and the trailers (grpc-status 0)
            // are recovered SEPARATELY.
            let sid = 1u32;
            let initial = frame(0x1, FLAG_END_HEADERS, sid, &[0x88]); // :status 200
            let data = frame(0x0, 0, sid, b"grpc-frame-unary-payload");
            // Trailers: grpc-status 0 (literal) then a literal `:status 500` — the
            // poison field that the fused decode would let overwrite the real status.
            let mut trailers_block = grpc_trailers_block("0", None);
            let status_name = ":status";
            trailers_block.push(0x00); // literal w/o indexing, name idx 0 ⇒ literal name
            trailers_block.push(status_name.len() as u8);
            trailers_block.extend_from_slice(status_name.as_bytes());
            trailers_block.push(b"500".len() as u8);
            trailers_block.extend_from_slice(b"500");
            let trailers = frame(
                0x1,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                sid,
                &trailers_block,
            );

            let mut wire = initial;
            wire.extend_from_slice(&data);
            wire.extend_from_slice(&trailers);

            // OLD behavior (what `inspected_http2_stream_events` did before this unit):
            // fuse every HEADERS fragment of the stream into one block, then decode.
            let fused = demux_header_blocks(&wire);
            let mut fdec = HpackDecoder::new();
            let fused_ph =
                pseudo_headers_from_block(&mut fdec, &fused[&sid]).expect("fused decode");
            assert_eq!(
                fused_ph.status,
                Some(500),
                "the OLD fused demux is CORRUPTED — the trailers block's :status \
                 overwrites the real 200 (this is the bug the unit fixes)"
            );

            // NEW behavior: trailer-aware demux keeps the initial block separate, so the
            // real :status (200) survives and the trailers decode independently.
            let blocks = demux_stream_header_blocks(&wire);
            let stream = &blocks[&sid];
            let mut idec = HpackDecoder::new();
            let fixed_ph =
                pseudo_headers_from_block(&mut idec, &stream.initial).expect("initial decode");
            assert_eq!(
                fixed_ph.status,
                Some(200),
                "the trailer-aware demux RECOVERS the real :status (200) — the load-bearing fix"
            );
            let mut tdec = HpackDecoder::new();
            let tr = grpc_trailers_from_block(&mut tdec, stream.trailers.as_ref().unwrap())
                .expect("trailers decode");
            assert!(
                tr.is_ok(),
                "and the grpc-status 0 trailer is still recovered"
            );
        }

        #[test]
        fn grpc_server_streaming_carries_multiple_data_frames_then_trailers_gRPC() {
            // A server-streaming gRPC response: initial HEADERS → MANY DATA frames
            // (the message stream) → trailers HEADERS. Only the DATA-frame count
            // differs from unary; the stream shape (one initial + one trailers block)
            // is identical, so the SAME demux supports both. The multiple DATA frames
            // must NOT split or duplicate the trailers block.
            let sid = 3u32;
            let mut wire = frame(0x1, FLAG_END_HEADERS, sid, &[0x88]); // :status 200
            for msg in [b"msg-1".as_slice(), b"msg-2", b"msg-3"] {
                wire.extend_from_slice(&frame(0x0, 0, sid, msg));
            }
            wire.extend_from_slice(&frame(
                0x1,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                sid,
                &grpc_trailers_block("0", None),
            ));

            let blocks = demux_stream_header_blocks(&wire);
            let stream = &blocks[&sid];
            let mut idec = HpackDecoder::new();
            let ph = pseudo_headers_from_block(&mut idec, &stream.initial).expect("initial");
            assert_eq!(ph.status, Some(200));
            let mut tdec = HpackDecoder::new();
            let tr = grpc_trailers_from_block(&mut tdec, stream.trailers.as_ref().unwrap())
                .expect("trailers");
            assert!(
                tr.is_ok(),
                "trailers intact after server-streaming DATA frames"
            );
        }

        #[test]
        fn grpc_request_path_is_the_method_route_gRPC() {
            // A gRPC request targets POST /package.Service/Method. The initial request
            // HEADERS block decodes to that :path — the telemetry path the boundary
            // asserts (requireEvent(EventHTTP, "/echo.Echo/Call")).
            let path = "/echo.Echo/Call";
            let mut block = vec![0x83]; // indexed :method POST (static idx 3)
            block.push(0x04); // literal :path, name idx 4
            block.push(path.len() as u8);
            block.extend_from_slice(path.as_bytes());
            let wire = frame(0x1, FLAG_END_HEADERS, 1, &block);

            let blocks = demux_stream_header_blocks(&wire);
            let mut dec = HpackDecoder::new();
            let ph = pseudo_headers_from_block(&mut dec, &blocks[&1].initial).expect("decode");
            let ev = stream_event_fields(&ph, "grpc.example");
            assert_eq!(ev.method, "POST", "gRPC is POST");
            assert_eq!(ev.path, "/echo.Echo/Call");
            assert!(
                blocks[&1].trailers.is_none(),
                "a request stream has no trailers here"
            );
        }

        #[test]
        fn grpc_telemetry_carries_no_data_frame_byte_gRPC() {
            // D73 never-log-the-secret for gRPC: the message bytes ride DATA frames;
            // neither the per-stream event NOR the trailers ever carry a DATA byte.
            // Use a body canary in the DATA frame and assert it appears nowhere in the
            // decoded event or trailers.
            const BODY_CANARY: &str = "grpc-frame-unary-payload-CANARY";
            let sid = 1u32;
            let mut block = vec![0x83]; // :method POST
            block.push(0x04); // :path
            let path = "/echo.Echo/Call";
            block.push(path.len() as u8);
            block.extend_from_slice(path.as_bytes());
            let mut wire = frame(0x1, FLAG_END_HEADERS, sid, &block);
            wire.extend_from_slice(&frame(0x0, 0, sid, BODY_CANARY.as_bytes()));
            wire.extend_from_slice(&frame(
                0x1,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                sid,
                &grpc_trailers_block("0", Some("OK")),
            ));

            let blocks = demux_stream_header_blocks(&wire);
            let stream = &blocks[&sid];
            // The DATA canary never landed in either HEADERS block (it is a DATA
            // frame, which the demux skips entirely).
            assert!(
                !stream
                    .initial
                    .windows(BODY_CANARY.len())
                    .any(|w| w == BODY_CANARY.as_bytes()),
                "no DATA byte in the initial header block"
            );
            if let Some(tr_block) = &stream.trailers {
                assert!(
                    !tr_block
                        .windows(BODY_CANARY.len())
                        .any(|w| w == BODY_CANARY.as_bytes()),
                    "no DATA byte in the trailers block"
                );
            }
            let mut dec = HpackDecoder::new();
            let ph = pseudo_headers_from_block(&mut dec, &stream.initial).expect("decode");
            let ev = stream_event_fields(&ph, "grpc.example");
            for f in [ev.method.as_str(), ev.host.as_str(), ev.path.as_str()] {
                assert!(
                    !f.contains(BODY_CANARY),
                    "a gRPC event field leaked a DATA byte: {f:?}"
                );
            }
        }

        #[test]
        fn grpc_interleaved_streams_demux_trailers_independently_gRPC() {
            // Two concurrent gRPC calls interleaved on the wire: each stream's
            // initial + trailers blocks must demux to ITS OWN stream — no
            // cross-stream trailer mixing (the multiplexing-isolation property
            // extended to the trailers block).
            let mk_stream = |sid: u32, path: &str, status: &str| -> (Vec<u8>, Vec<u8>, Vec<u8>) {
                let mut hblock = vec![0x83]; // :method POST
                hblock.push(0x04); // :path
                hblock.push(path.len() as u8);
                hblock.extend_from_slice(path.as_bytes());
                let headers = frame(0x1, FLAG_END_HEADERS, sid, &hblock);
                let data = frame(0x0, 0, sid, b"payload");
                let trailers = frame(
                    0x1,
                    FLAG_END_HEADERS | FLAG_END_STREAM,
                    sid,
                    &grpc_trailers_block(status, None),
                );
                (headers, data, trailers)
            };
            let (h1, d1, t1) = mk_stream(1, "/echo.Echo/Call", "0");
            let (h3, d3, t3) = mk_stream(3, "/echo.Echo/Stream", "5");
            // Interleave: both headers, both data, then both trailers out of id order.
            let mut wire = Vec::new();
            for chunk in [&h3, &h1, &d1, &d3, &t3, &t1] {
                wire.extend_from_slice(chunk);
            }

            let blocks = demux_stream_header_blocks(&wire);
            assert_eq!(blocks.keys().copied().collect::<Vec<_>>(), vec![1, 3]);

            let mut dec = HpackDecoder::new();
            let ph1 = pseudo_headers_from_block(&mut dec, &blocks[&1].initial).unwrap();
            assert_eq!(ph1.path.as_deref(), Some("/echo.Echo/Call"));
            let mut t1dec = HpackDecoder::new();
            let tr1 = grpc_trailers_from_block(&mut t1dec, blocks[&1].trailers.as_ref().unwrap())
                .unwrap();
            assert_eq!(
                tr1.status.as_deref(),
                Some("0"),
                "stream 1 keeps its OK trailer"
            );

            let mut dec3 = HpackDecoder::new();
            let ph3 = pseudo_headers_from_block(&mut dec3, &blocks[&3].initial).unwrap();
            assert_eq!(ph3.path.as_deref(), Some("/echo.Echo/Stream"));
            let mut t3dec = HpackDecoder::new();
            let tr3 = grpc_trailers_from_block(&mut t3dec, blocks[&3].trailers.as_ref().unwrap())
                .unwrap();
            assert_eq!(
                tr3.status.as_deref(),
                Some("5"),
                "stream 3 keeps its own trailer"
            );
        }
    }
}

/// TLS-8 QUIC/HTTP-3 **blocked-with-TCP-fallback** posture core (doc 09 §5 TLS-8
/// / NFT-4 / OQ5; doc 12 §7 / §13.5; D70 / D75 / D69) — **pingora-free**. D70
/// keeps QUIC/HTTP-3 *blocked-with-fallback*: udp/443 from agent-VM interfaces is
/// **rejected with ICMP port-unreachable (icmpv6 twin dormant per D75), never
/// silently dropped, and counted per session** with a distinct `quic_blocked`
/// reason code in LOG-1 — so a non-cooperative raw-QUIC client (`curl
/// --http3-only`, WebTransport, MASQUE, an arbitrary quic lib) fails *fast*
/// (`ECONNREFUSED`) and falls back to TCP, which the proxy can inspect. DNS-4 rule
/// 4 (HTTPS/SVCB suppression — `alpn=h3` stripped) is the *steering* control that
/// keeps spec-following clients on TCP; the NFT-4 reject is the *sole* control for
/// non-cooperative clients (the two-population framing, doc 12 §7).
///
/// # Division of labour (what is the proxy's, what is the kernel's)
///
/// The udp/443 reject itself is **kernel-level** — one `reject with
/// icmp(v6) port-unreachable` verdict in the NFT-1 ruleset (NFT-4), on the host
/// netns side of the per-session tap, OUTSIDE this userspace proxy (D69's TCP-only
/// scope: ds-tlsproxy's `accept/` listener only ever sees the *TCP fallback*; a
/// QUIC datagram never reaches a Pingora socket — Pingora has no UDP data plane,
/// doc 12 §7/§11). So NO QUIC byte, and NO QUIC event, is ever produced by this
/// proxy: the only flow it observes for a blocked-then-fallen-back client is the
/// TCP one (the boundary asserts exactly this — one TCP flow, zero QUIC traces).
///
/// What lands HERE is the proxy-side residual D70/§7 names as the proxy's own (the
/// §9 *QUIC* free cell: "the per-session counter and the LOG-1 reject-reason code
/// are the frozen telemetry; the counter *mechanism* is free"):
///
/// 1. [`quic::QUIC_BLOCKED_REASON`] — the frozen LOG-1 reject-reason code, SINGLE-
///    SOURCED from [`ds_contracts::reject::RejectReason::QuicBlocked`] so a
///    flip-to-inspect query counts QUIC rejects WITHOUT conflating them with generic
///    default-deny (D70). It is never a re-declared literal.
/// 2. [`quic::SessionQuicRejectCounters`] — the **per-session reject counter
///    mechanism** (§9-free): a framework-agnostic, interior-mutable tally partitioned
///    on the never-recycled `dstap-<idx>` tap name (the LOG-2 join key, doc 14 §4),
///    so the count is per-session and a session sweep drops it whole. The kernel
///    counter (the NFT-4 `counter` statement) is the AUTHORITATIVE on-box tally; this
///    userspace mirror is the value the proxy folds into a LOG-1 reject event so the
///    reason code + per-session count are queryable on the same telemetry plane as
///    the rest of the proxy's events.
/// 3. [`quic::QuicRejectEvent`] — the LOG-1 reject event shape (tap name + session
///    index + the [`quic::QUIC_BLOCKED_REASON`] code + the running per-session
///    count), carrying ZERO client bytes (never-log-the-secret, D73 — a rejected
///    QUIC datagram's payload is never read, let alone logged; the shape carries
///    none). Mirrors the [`crate::telemetry_http`] / pass-through netflow shapes:
///    pingora-free, built from plain primitives, migrating onto the generated LOG-1
///    reject proto (doc 14 §2 RejectReason) at the Stage-0 freeze.
/// 4. The **flip-to-inspect trigger contract + nightly conformance canary** this
///    unit owns (doc 12 §7 frozen trigger contract; doc 09 OQ5): the
///    [`quic::CanaryProbe`] / [`quic::CanaryOutcome`] result shape a standing
///    nightly/weekly check produces, and the pure [`quic::evaluate_flip_trigger`]
///    that maps a canary result + the (deferred) baseline/workload signals to a
///    [`quic::FlipTrigger`] verdict — `Hold` (stay blocked-with-fallback, the v0
///    default) vs `Inspect` (a trigger fired; QUIC inspection is now warranted).
///    The verdict is observational ONLY: nothing here arms inspection (that is the
///    deferred non-Pingora QUIC-terminator carveout, the D69 mechanism-agnostic
///    recovery seam, doc 12 §7 "no roadmap commitment"). It exists so the
///    "when do clients stop falling back" decision is a TESTED contract, not a
///    judgment call.
///
/// # Default-path-byte-identical + additive
///
/// This module changes NOTHING on the existing default path: it ships no listener,
/// no reject mechanism (the reject is the kernel's), and no flip (inspection stays
/// deferred). `main.rs` constructs the counter and emits a [`quic::QuicRejectEvent`]
/// only behind the existing `DS_*` discipline (a sibling `DS_QUIC_*` accounting
/// flag), so the disarmed default build is unchanged — the TCP fallback path is the
/// pre-existing TLS-1 path, untouched.
///
/// D40 pingora confinement (doc 12 §13.1): no pingora type, no socket, no I/O
/// appears here; everything is pure over `ds-contracts` shapes + plain primitives,
/// unit-tested with no kernel. Defined INLINE (not a sibling `quic.rs`) so the
/// TLS-8 QUIC unit lands in `lib.rs` + `main.rs` only, matching the unit's file
/// scope (mirroring the inline [`websocket`] / [`http2`] modules).
pub mod quic {
    // QUIC/HTTP-3 blocked-with-TCP-fallback posture core. See the outer `///`
    // module doc above for the full charter. `unsafe_code` is forbidden here by the
    // crate-root `#![forbid(unsafe_code)]`, which binds every inline module — no
    // inner attribute is needed; this module is stdlib + ds-contracts only, so it is
    // unsafe-free by construction.

    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use ds_contracts::reject::RejectReason;
    use ds_contracts::session::SessionRef;

    /// The frozen LOG-1 reject-reason code for a udp/443 (QUIC) reject (D70, doc 14
    /// §2). SINGLE-SOURCED from [`RejectReason::QuicBlocked`] — never a re-declared
    /// literal — so the proxy's reason code stays byte-identical to the contract's
    /// stable token (`"quic_blocked"`) and the kernel/proto sides that read the same
    /// enum. This is the distinct-from-default-deny code a flip-to-inspect query
    /// counts ([`RejectReason::is_quic_carveout`]).
    pub const QUIC_BLOCKED_REASON: RejectReason = RejectReason::QuicBlocked;

    /// The stable lowercase token for [`QUIC_BLOCKED_REASON`] (`"quic_blocked"`),
    /// re-exported from the frozen [`RejectReason::as_str`] so callers (the LOG-1
    /// event builder, a metrics label) never spell the literal themselves. Kept a
    /// `fn` returning the contract's `as_str()` rather than a copied `&str` so a
    /// future token change in `ds-contracts` propagates without an edit here.
    pub fn quic_blocked_token() -> &'static str {
        QUIC_BLOCKED_REASON.as_str()
    }

    /// A per-session tally of udp/443 (QUIC) rejects — the §9-free "per-session
    /// counter mechanism" (D70, doc 12 §7 / §9 QUIC free cell). Partitioned on the
    /// never-recycled `dstap-<idx>` tap name (the LOG-2 join key, doc 14 §4) so the
    /// count is per-session and structurally unconflatable across sessions (a
    /// recyclable 14-bit mark index is NEVER the key — mirroring
    /// [`crate::SessionUpstreamPools`] / [`crate::SeveringRegistry`]).
    ///
    /// Authority note (doc 12 §7): the AUTHORITATIVE on-box reject tally is the
    /// NFT-4 kernel `counter` statement (the reject is kernel-level, OUTSIDE this
    /// proxy). This userspace mirror exists so the proxy can fold a per-session
    /// count into a LOG-1 [`QuicRejectEvent`] on the same telemetry plane as the
    /// rest of its events — it is observability, never the reject mechanism.
    ///
    /// Interior-mutable behind a `Mutex` so the (future) accounting call-site can
    /// `record` while a sweep `drop_session`s without threading a `&mut`. Pure
    /// userspace state — no pingora type, no syscall (D40).
    #[derive(Default)]
    pub struct SessionQuicRejectCounters {
        inner: Mutex<BTreeMap<String, u64>>,
    }

    impl SessionQuicRejectCounters {
        /// A fresh, empty set of per-session counters.
        pub fn new() -> SessionQuicRejectCounters {
            SessionQuicRejectCounters::default()
        }

        /// Record ONE udp/443 reject for `session` and return the session's NEW
        /// running total. The reason is ALWAYS [`QUIC_BLOCKED_REASON`] (the only
        /// reject this counter tallies); a caller folds the returned count into a
        /// [`QuicRejectEvent`]. Saturating so a pathological reject flood clamps
        /// rather than wrapping the count silently backward.
        pub fn record(&self, session: &SessionRef) -> u64 {
            let mut map = self.inner.lock().expect("quic-reject counter mutex");
            let n = map.entry(session.tap_name.clone()).or_insert(0);
            *n = n.saturating_add(1);
            *n
        }

        /// The current per-session reject total for `session` (0 if it has never
        /// been rejected). A read-only diagnostic / telemetry helper.
        pub fn count(&self, session: &SessionRef) -> u64 {
            let map = self.inner.lock().expect("quic-reject counter mutex");
            map.get(&session.tap_name).copied().unwrap_or(0)
        }

        /// Drop the session's reject tally on a session sweep / teardown (doc 12 §8
        /// — a swept session's derived state is dropped whole). Returns the count
        /// that was dropped (0 if none). Mirrors
        /// [`crate::SessionUpstreamPools::drop_session`] so QUIC accounting follows
        /// the same session-lifecycle as the rest of the proxy's per-session state.
        pub fn drop_session(&self, session: &SessionRef) -> u64 {
            let mut map = self.inner.lock().expect("quic-reject counter mutex");
            map.remove(&session.tap_name).unwrap_or(0)
        }
    }

    /// A LOG-1 reject event for a udp/443 (QUIC) reject (D70, doc 14 §2). The
    /// proxy-side residual of the §7 telemetry: it carries the session attribution
    /// (the never-recycled `dstap-<idx>` tap name + the host-local session index),
    /// the frozen [`QUIC_BLOCKED_REASON`] code (distinct from generic default-deny),
    /// and the running per-session reject count — and DELIBERATELY nothing else.
    ///
    /// Never-log-the-secret (D73) is a TYPE-LEVEL property: a rejected QUIC datagram
    /// is dropped by the kernel before this proxy ever reads a byte of it, and this
    /// shape has no field that could carry a payload byte, a header, or a credential
    /// even if one were available. The fields are a tap name (the LOG-2 key), a u32
    /// index, a frozen reason enum, and a u64 count — all non-secret L3/4
    /// attribution + a code.
    ///
    /// Mirrors [`crate::telemetry_http::HttpEvent`] / the pass-through `NetflowEvent`:
    /// pingora-free, built from plain primitives, migrating onto the generated LOG-1
    /// reject proto (doc 14 §2) at the Stage-0 freeze. Distinct shape from `HttpEvent`
    /// so a reject event can never accidentally grow an HTTP-level field — a rejected
    /// QUIC flow has no HTTP layer (it never reached one).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct QuicRejectEvent {
        /// The never-recycled session join key (doc 14 §4) — the `dstap-<idx>` tap
        /// name (LOG-2 attribution key).
        pub tap_name: String,
        /// The host-local session index (the §4.2 14-bit index; the value the tap
        /// name and the D76 marks encode) — the L3/4 attribution the reject record
        /// carries alongside the tap name.
        pub host_session_index: u32,
        /// The frozen reject-reason code — always [`QUIC_BLOCKED_REASON`], distinct
        /// from generic default-deny so the flip-to-inspect query (D70) can count
        /// QUIC rejects on their own.
        pub reason: RejectReason,
        /// The session's running udp/443 reject count AFTER this reject (the value
        /// [`SessionQuicRejectCounters::record`] returned). The per-session tally
        /// D70 requires on the LOG-1 record.
        pub reject_count: u64,
    }

    /// Build the LOG-1 [`QuicRejectEvent`] for a udp/443 reject, folding the running
    /// per-session count off `counters` (recording this reject). PURE over its
    /// inputs apart from the counter bump (no I/O, no pingora type), so the shape —
    /// session attribution + the frozen reason code + the count, NO payload — is
    /// unit-tested directly. The reason is ALWAYS [`QUIC_BLOCKED_REASON`]: this
    /// builder exists only for the QUIC carveout (a generic default-deny reject is a
    /// different event class).
    pub fn record_quic_reject(
        counters: &SessionQuicRejectCounters,
        session: &SessionRef,
    ) -> QuicRejectEvent {
        let reject_count = counters.record(session);
        QuicRejectEvent {
            tap_name: session.tap_name.clone(),
            host_session_index: session.host_session_index,
            reason: QUIC_BLOCKED_REASON,
            reject_count,
        }
    }

    // ── The flip-to-inspect trigger contract + nightly conformance canary ───────
    //
    // doc 12 §7 freezes the QUIC flip-to-inspect trigger as a TESTED contract (not a
    // judgment call): the flip from block-with-fallback to must-inspect fires on any
    // of three signals, evaluated by a standing nightly/weekly check. This unit OWNS
    // that contract (the spec: "this unit owns the nightly conformance canary
    // contract ... a deferred trigger-to-inspect decision"). The types below are the
    // pure decision core; arming inspection is the deferred non-Pingora QUIC
    // terminator (doc 12 §7 carveout — no roadmap commitment).

    /// The outcome of one nightly conformance-canary probe (doc 12 §7; doc 09 OQ5).
    /// The canary drives the latest-STABLE client set (distinct from the pinned
    /// golden-image clients) against a baseline domain and records whether
    /// block-with-fallback still works gracefully: did first-contact succeed over
    /// the TCP fallback, and did it stay within the p95 first-contact latency budget
    /// vs a TCP-direct control. A canary that fails or regresses is signal that
    /// clients have stopped falling back — the first flip trigger.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CanaryOutcome {
        /// First-contact fell back to TCP and stayed within the latency budget —
        /// block-with-fallback is healthy (the steady-state nightly result; HOLD).
        FallbackHealthy,
        /// First-contact FAILED to fall back to TCP (a client now hard-requires
        /// QUIC / does not retry over TCP) — a flip trigger fired.
        FallbackFailed,
        /// First-contact fell back but the p95 latency regressed beyond the budget
        /// vs the TCP-direct control (graceful fallback is degrading) — a flip
        /// trigger fired.
        LatencyRegressed,
    }

    impl CanaryOutcome {
        /// Whether this canary outcome is a flip signal (anything but a healthy
        /// fallback). True for [`CanaryOutcome::FallbackFailed`] /
        /// [`CanaryOutcome::LatencyRegressed`].
        pub fn is_flip_signal(self) -> bool {
            !matches!(self, CanaryOutcome::FallbackHealthy)
        }
    }

    /// One nightly conformance-canary probe result for a single client (doc 12 §7
    /// frozen trigger contract). The client label is informational (which member of
    /// the latest-stable set ran); the [`CanaryOutcome`] is the signal. PURE data —
    /// the live probe (a real client driven against a baseline domain) is the doc 06
    /// (c) nightly rig's residual; this is the shape it reports for the pure
    /// [`evaluate_flip_trigger`] decision.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CanaryProbe {
        /// Which latest-stable client this probe ran (e.g. `curl`, `node-undici`,
        /// `headless-chrome-stable`) — informational, for attributing a regression.
        pub client: String,
        /// The probe outcome — the flip signal.
        pub outcome: CanaryOutcome,
    }

    /// The flip-to-inspect verdict (doc 12 §7; D70). Observational ONLY — nothing in
    /// this crate arms inspection on `Inspect`; the verdict is what a standing
    /// nightly/weekly check reports so the deferred trigger-to-inspect DECISION is a
    /// tested contract. `Inspect` means "a trigger fired — QUIC inspection is now
    /// warranted"; the actual terminator is the deferred non-Pingora carveout.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FlipTrigger {
        /// No trigger fired — stay blocked-with-fallback (the v0 default; the
        /// steady-state nightly result).
        Hold,
        /// A trigger fired — QUIC inspection is warranted (the deferred carveout).
        Inspect,
    }

    /// The extra (non-canary) flip signals doc 12 §7 freezes alongside the
    /// conformance canary: a D64 baseline endpoint going H3-only / degrading its TCP
    /// 443 service, and a required workload feature being H3-bound (WebTransport,
    /// MASQUE/connect-udp, an H3-only gRPC API). Both are DEFERRED inputs (their live
    /// detection is the baseline-poller / workload-failure-join residual); carried
    /// here as explicit booleans so the trigger logic is total and the deferred
    /// inputs are NAMED, not implied. v0 supplies `false` for both (the steady
    /// state).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct FlipSignals {
        /// A D64 baseline endpoint became H3-only or measurably degraded its TCP 443
        /// service (doc 12 §7 trigger 2). Deferred input — v0 supplies `false`.
        pub baseline_h3_only: bool,
        /// A required workload feature is H3-bound, evidenced by task failures joined
        /// to udp/443 reject events (doc 12 §7 trigger 3). Deferred input — v0
        /// supplies `false`.
        pub workload_h3_bound: bool,
    }

    /// Evaluate the frozen D70 flip-to-inspect trigger (doc 12 §7) over a nightly
    /// canary sweep + the extra [`FlipSignals`]. PURE — no I/O, no clock; the
    /// standing nightly/weekly check supplies the inputs and reads the verdict.
    ///
    /// Returns [`FlipTrigger::Inspect`] if ANY trigger fired:
    ///
    /// 1. any [`CanaryProbe`] in the sweep is a flip signal (fallback failed or
    ///    latency regressed for any latest-stable client), OR
    /// 2. a D64 baseline endpoint went H3-only / degraded ([`FlipSignals`]), OR
    /// 3. a required workload feature is H3-bound ([`FlipSignals`]).
    ///
    /// Otherwise [`FlipTrigger::Hold`] — stay blocked-with-fallback (the v0 default).
    ///
    /// "Trigger evaluation is a standing weekly/nightly check, not a judgment call"
    /// (doc 12 §7): this is that check, expressed as a total function so the decision
    /// is reproducible and tested. The verdict is observational — it does not arm
    /// inspection (the deferred carveout).
    pub fn evaluate_flip_trigger(
        canary_sweep: &[CanaryProbe],
        signals: FlipSignals,
    ) -> FlipTrigger {
        let canary_fired = canary_sweep.iter().any(|p| p.outcome.is_flip_signal());
        if canary_fired || signals.baseline_h3_only || signals.workload_h3_bound {
            FlipTrigger::Inspect
        } else {
            FlipTrigger::Hold
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn session(idx: u32) -> SessionRef {
            SessionRef::new(
                "11111111-2222-3333-4444-555555555555".into(),
                "host-a".into(),
                idx,
                format!("dstap-{idx}"),
            )
        }

        // ── reason code: single-sourced + distinct from default-deny (D70) ──────

        #[test]
        fn quic_blocked_reason_is_the_frozen_carveout_distinct_from_default_deny() {
            // The proxy's reason code IS the frozen contract enum — never a literal.
            assert_eq!(QUIC_BLOCKED_REASON, RejectReason::QuicBlocked);
            // The whole point of D70: it is DISTINCT from generic default-deny so a
            // flip-to-inspect query counts QUIC rejects without conflation.
            assert_ne!(QUIC_BLOCKED_REASON, RejectReason::DefaultDeny);
            assert!(QUIC_BLOCKED_REASON.is_quic_carveout());
            // The stable token is single-sourced from the contract's as_str().
            assert_eq!(quic_blocked_token(), "quic_blocked");
            assert_eq!(quic_blocked_token(), RejectReason::QuicBlocked.as_str());
        }

        // ── per-session reject counter mechanism (§9-free, D70) ─────────────────

        #[test]
        fn counter_tallies_per_session_and_returns_running_total() {
            let counters = SessionQuicRejectCounters::new();
            let s = session(7);
            assert_eq!(counters.count(&s), 0);
            assert_eq!(counters.record(&s), 1);
            assert_eq!(counters.record(&s), 2);
            assert_eq!(counters.record(&s), 3);
            assert_eq!(counters.count(&s), 3);
        }

        #[test]
        fn counter_is_session_partitioned_no_cross_session_conflation() {
            // The core per-session invariant: a reject for session A never moves
            // session B's count — the tally is keyed on the never-recycled tap name,
            // never a recyclable index.
            let counters = SessionQuicRejectCounters::new();
            let a = session(10);
            let b = session(11);
            counters.record(&a);
            counters.record(&a);
            counters.record(&b);
            assert_eq!(counters.count(&a), 2);
            assert_eq!(counters.count(&b), 1);
        }

        #[test]
        fn counter_partitions_on_tap_name_not_recyclable_mark_index() {
            // Two distinct sessions can share a 14-bit mark residue (it wraps mod
            // 2^14) but have distinct never-recycled tap names; the counter must not
            // conflate them. Mirrors the pool-isolation invariant.
            let counters = SessionQuicRejectCounters::new();
            let a = SessionRef::new("ua".into(), "host".into(), 5, "dstap-5".into());
            let b = SessionRef::new("ub".into(), "host".into(), 16_384 + 5, "dstap-16389".into());
            assert_eq!(
                a.mark_session_index(),
                b.mark_session_index(),
                "same mark residue"
            );
            assert_ne!(a.tap_name, b.tap_name, "distinct never-recycled tap names");
            counters.record(&a);
            counters.record(&a);
            counters.record(&b);
            assert_eq!(counters.count(&a), 2);
            assert_eq!(counters.count(&b), 1);
        }

        #[test]
        fn drop_session_removes_only_the_swept_sessions_tally() {
            let counters = SessionQuicRejectCounters::new();
            let swept = session(20);
            let other = session(21);
            counters.record(&swept);
            counters.record(&swept);
            counters.record(&other);
            assert_eq!(counters.drop_session(&swept), 2);
            assert_eq!(counters.count(&swept), 0);
            // the other session is untouched.
            assert_eq!(counters.count(&other), 1);
            // dropping an already-empty / never-seen session is a no-op (0).
            assert_eq!(counters.drop_session(&session(99)), 0);
        }

        // ── LOG-1 reject event: shape, reason code, no-secret (D70/D73) ──────────

        #[test]
        fn record_quic_reject_builds_event_with_frozen_reason_and_running_count() {
            let counters = SessionQuicRejectCounters::new();
            let s = session(42);
            let ev1 = record_quic_reject(&counters, &s);
            assert_eq!(ev1.tap_name, "dstap-42");
            assert_eq!(ev1.host_session_index, 42);
            assert_eq!(ev1.reason, RejectReason::QuicBlocked);
            assert!(ev1.reason.is_quic_carveout());
            assert_eq!(ev1.reject_count, 1);
            // a second reject folds the running per-session count.
            let ev2 = record_quic_reject(&counters, &s);
            assert_eq!(ev2.reject_count, 2);
            assert_eq!(counters.count(&s), 2);
        }

        #[test]
        fn reject_event_carries_only_nonsecret_attribution() {
            // never-log-the-secret as a type property: the only fields are the tap
            // name, the index, a frozen reason enum, and a count. There is no field
            // a payload / header / credential byte could occupy. We assert the
            // event's debug rendering carries exactly the attribution + reason code
            // token and nothing resembling a payload.
            let counters = SessionQuicRejectCounters::new();
            let s = session(3);
            let ev = record_quic_reject(&counters, &s);
            let rendered = format!("{ev:?}");
            assert!(rendered.contains("dstap-3"));
            assert!(rendered.contains("QuicBlocked"));
            // The reason maps to the stable token a metrics label would use.
            assert_eq!(ev.reason.as_str(), "quic_blocked");
        }

        // ── the flip-to-inspect trigger contract / nightly canary (D70, §7) ─────

        #[test]
        fn steady_state_canary_sweep_holds_block_with_fallback() {
            // All clients fall back healthily and no extra signal fired → HOLD (the
            // v0 default: stay blocked-with-fallback).
            let sweep = vec![
                CanaryProbe {
                    client: "curl".into(),
                    outcome: CanaryOutcome::FallbackHealthy,
                },
                CanaryProbe {
                    client: "node-undici".into(),
                    outcome: CanaryOutcome::FallbackHealthy,
                },
                CanaryProbe {
                    client: "headless-chrome-stable".into(),
                    outcome: CanaryOutcome::FallbackHealthy,
                },
            ];
            assert_eq!(
                evaluate_flip_trigger(&sweep, FlipSignals::default()),
                FlipTrigger::Hold
            );
            // an empty sweep with no extra signals also holds (nothing fired).
            assert_eq!(
                evaluate_flip_trigger(&[], FlipSignals::default()),
                FlipTrigger::Hold
            );
        }

        #[test]
        fn a_single_client_failing_to_fall_back_fires_the_flip() {
            // trigger 1: any latest-stable client stops falling back → INSPECT.
            let sweep = vec![
                CanaryProbe {
                    client: "curl".into(),
                    outcome: CanaryOutcome::FallbackHealthy,
                },
                CanaryProbe {
                    client: "headless-chrome-stable".into(),
                    outcome: CanaryOutcome::FallbackFailed,
                },
            ];
            assert_eq!(
                evaluate_flip_trigger(&sweep, FlipSignals::default()),
                FlipTrigger::Inspect
            );
        }

        #[test]
        fn a_latency_regression_fires_the_flip() {
            // trigger 1 (degradation variant): graceful fallback is degrading.
            let sweep = vec![CanaryProbe {
                client: "curl".into(),
                outcome: CanaryOutcome::LatencyRegressed,
            }];
            assert!(CanaryOutcome::LatencyRegressed.is_flip_signal());
            assert_eq!(
                evaluate_flip_trigger(&sweep, FlipSignals::default()),
                FlipTrigger::Inspect
            );
        }

        #[test]
        fn baseline_h3_only_signal_fires_the_flip_without_a_canary_failure() {
            // trigger 2: a D64 baseline endpoint goes H3-only — fires even when every
            // canary is still healthy.
            let healthy = vec![CanaryProbe {
                client: "curl".into(),
                outcome: CanaryOutcome::FallbackHealthy,
            }];
            let signals = FlipSignals {
                baseline_h3_only: true,
                workload_h3_bound: false,
            };
            assert_eq!(
                evaluate_flip_trigger(&healthy, signals),
                FlipTrigger::Inspect
            );
        }

        #[test]
        fn workload_h3_bound_signal_fires_the_flip() {
            // trigger 3: a required workload feature is H3-bound.
            let signals = FlipSignals {
                baseline_h3_only: false,
                workload_h3_bound: true,
            };
            assert_eq!(evaluate_flip_trigger(&[], signals), FlipTrigger::Inspect);
        }

        #[test]
        fn flip_verdict_is_observational_only_v0_default_holds() {
            // The whole steady-state contract: with the v0 inputs (healthy canary,
            // no deferred signal) the verdict is HOLD — nothing arms inspection.
            let v0_sweep = vec![CanaryProbe {
                client: "curl".into(),
                outcome: CanaryOutcome::FallbackHealthy,
            }];
            assert_eq!(
                evaluate_flip_trigger(&v0_sweep, FlipSignals::default()),
                FlipTrigger::Hold
            );
        }
    }
}

use std::collections::BTreeMap;
use std::sync::Mutex;

use ds_contracts::flush::{DstFilter, DstKey, FlushError, FlushOutcome, FlushSession, LegSelector};
use ds_contracts::mark::{self, Leg};
use ds_contracts::session::SessionRef;

// ─────────────────────────────────────────────────────────────────────────────
// D76 upstream-leg marking + per-session connection-pool partitioning
// (doc 12 §4.2 "Pool partitioning" + "Every upstream socket carries a DS mark
// before connect"; doc 12 §8 swept-session pool drop).
//
// This is the framework-agnostic half of the D76 upstream layer: the mark VALUE,
// the best-effort mark CALL-SITE seam, and the per-session pool whose key makes
// cross-session reuse structurally impossible. The pingora/socket2 live wiring —
// building the upstream socket and invoking the real `SO_MARK` setsockopt — lives
// in `src/main.rs` (D40 confines framework + raw-socket types there); everything
// here speaks only `ds-contracts` shapes + a `MarkSetter` seam, so the value and
// the call-site are unit-tested with NO privileged syscall (see `#[cfg(test)]`).
// ─────────────────────────────────────────────────────────────────────────────

/// The frozen D76 upstream-leg mark for a session: `compose(Leg::TlsproxyUpstream,
/// host_session_index)` — leg nibble `0x2` (bits 27–24) + the 14-bit session-index
/// residue (bits 13–0), under the DS magic `0xD`. This is the EXACT value every
/// upstream socket the proxy opens must carry before connect (doc 12 §4.2), and
/// the value the Stage-3 OUTPUT chain matches under `DS_MARK_MASK`. Computed from
/// the `ds-contracts` constants — never a re-declared literal — so the layout
/// stays single-sourced (D76 mask discipline).
pub fn upstream_mark(session: &SessionRef) -> u32 {
    mark::compose(Leg::TlsproxyUpstream, session.host_session_index)
}

/// The result of a best-effort `SO_MARK` attempt on an upstream socket (doc 12
/// §4.2 capability posture): `SO_MARK` is a PRIVILEGED socket option needing
/// `CAP_NET_RAW` (Linux ≥5.17) or `CAP_NET_ADMIN`. Production runs the proxy with
/// `CAP_NET_RAW` (systemd `AmbientCapabilities`) where the setsockopt succeeds; an
/// unprivileged sandbox/CI kernel returns `EPERM`. The mark is set BEST-EFFORT:
/// the value is ALWAYS computed and the setsockopt ALWAYS attempted; on a
/// permission error we LOG and CONTINUE (the connection is not failed — the
/// Stage-3 kernel layer is non-gating, doc 12 §4.2). An unmarked connect from the
/// proxy UID is a bug once the OUTPUT chain lands, but never a hard failure here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkAttempt {
    /// The setsockopt succeeded — the socket carries the mark (production with
    /// `CAP_NET_RAW`).
    Marked,
    /// The setsockopt was attempted and refused with a permission error
    /// (`EPERM`/`EACCES`) — logged and tolerated (unprivileged sandbox/CI).
    PermissionDenied,
    /// The setsockopt failed for a non-permission reason (logged and tolerated;
    /// the mark is best-effort and never gates the connect).
    OtherError,
}

impl MarkAttempt {
    /// Whether the socket actually carries the mark (only `Marked`). Diagnostics
    /// / LOG-2 accounting use this to know whether a kernel flow record will carry
    /// the DS mark.
    pub fn is_marked(self) -> bool {
        matches!(self, MarkAttempt::Marked)
    }
}

/// The privileged-syscall seam for the upstream `SO_MARK`. Production implements
/// it over `socket2::SockRef::set_mark` on the upstream socket's fd (in
/// `src/main.rs`, where the raw-socket types are confined per D40); tests
/// implement it over a recorder that captures the marks it was asked to set,
/// proving the VALUE and the CALL-SITE with no kernel involvement.
///
/// `set_mark` returns the [`MarkAttempt`] outcome rather than a `Result` so the
/// best-effort contract (never fail the connect) is encoded in the type: every
/// caller already has a value it can proceed with.
pub trait MarkSetter {
    /// Attempt to set the `SO_MARK` value `mark` on the upstream socket. MUST be
    /// best-effort: on a permission error return [`MarkAttempt::PermissionDenied`]
    /// (logged, the connect proceeds), never an error that aborts the connect.
    fn set_mark(&self, mark: u32) -> MarkAttempt;
}

/// Compute the frozen upstream mark for `session` and attempt to set it on
/// `setter`'s socket BEFORE connect (doc 12 §4.2 mark-before-connect invariant).
///
/// This is the single sanctioned call-site shape every upstream path (TLS-1
/// tunnel, TLS-2 CONNECT, TLS-3 re-originated, TLS-5 swap) routes through, so the
/// value is composed identically and the setter is invoked exactly once per
/// upstream socket. Returns both the computed mark and the attempt outcome so the
/// caller can log/account; the mark is ALWAYS returned even when the setsockopt is
/// refused (best-effort).
pub fn mark_upstream<S: MarkSetter + ?Sized>(
    setter: &S,
    session: &SessionRef,
) -> (u32, MarkAttempt) {
    let mark = upstream_mark(session);
    let attempt = setter.set_mark(mark);
    (mark, attempt)
}

/// A per-session partition of warm, reusable upstream sockets (doc 12 §4.2 "Pool
/// partitioning"). The pool is keyed by the session's authoritative join key (the
/// never-recycled `dstap-<idx>` tap name, doc 14 §4) — NOT the recyclable 14-bit
/// mark index — so a pooled socket created for session A is **structurally
/// unreachable** from a session-B request: `take` only ever scans session B's own
/// partition. A pooled socket carries the creating session's mark, so this is what
/// keeps LOG-2 attribution truthful and prevents session B riding session A's
/// admitted connection past the established-state short-circuit (doc 12 §4.2).
///
/// Generic over the pooled socket type `T` so it is exercised in `#[cfg(test)]`
/// with a fake socket (no live network); production parametrises it with the real
/// upstream `TcpStream` in `src/main.rs`. Sockets are pooled per `(session, dst)`
/// — a `take(session, dst)` only returns a socket the SAME session warmed to the
/// SAME destination.
///
/// On a session sweep (revocation at a severing rung, or session-end teardown,
/// doc 12 §8) `drop_session` removes the whole partition: every pooled socket the
/// swept session owns is dropped (and, being owned `T` values, closed when
/// dropped) so none survives into a later session's reuse.
pub struct SessionUpstreamPools<T> {
    inner: Mutex<BTreeMap<PoolKey, Vec<T>>>,
}

/// The reuse key: `(tap_name, dst)`. The tap name is the partition — the session
/// identity in the key is what makes cross-session reuse impossible — and `dst`
/// scopes reuse to the same upstream peer (a pooled socket is only ever reused for
/// the destination it was opened to).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PoolKey {
    /// The session partition (never-recycled tap name).
    tap_name: String,
    /// The upstream destination this socket was opened to.
    dst: String,
}

impl<T> Default for SessionUpstreamPools<T> {
    fn default() -> SessionUpstreamPools<T> {
        SessionUpstreamPools {
            inner: Mutex::new(BTreeMap::new()),
        }
    }
}

impl<T> SessionUpstreamPools<T> {
    /// A fresh, empty pool set.
    pub fn new() -> SessionUpstreamPools<T> {
        SessionUpstreamPools::default()
    }

    fn key(session: &SessionRef, dst: &DstKey) -> PoolKey {
        PoolKey {
            tap_name: session.tap_name.clone(),
            dst: dst.0.clone(),
        }
    }

    /// Return a warm socket `session` previously pooled for `dst`, or `None` if
    /// the session has no warm socket to that destination. The lookup is scoped to
    /// `session`'s OWN partition: a socket session A warmed can never be returned
    /// for session B, because B's key carries B's tap name (cross-session reuse is
    /// structurally impossible, doc 12 §4.2). The returned socket is removed from
    /// the pool (it is now in flight); `put` re-pools it if it is still warm after
    /// use.
    pub fn take(&self, session: &SessionRef, dst: &DstKey) -> Option<T> {
        let mut pools = self.inner.lock().expect("pool mutex");
        let key = Self::key(session, dst);
        let warm = pools.get_mut(&key)?;
        let sock = warm.pop();
        if warm.is_empty() {
            pools.remove(&key);
        }
        sock
    }

    /// Re-pool a still-warm upstream socket under `session`'s partition for `dst`.
    /// The socket joins ONLY this session's `(tap, dst)` partition, so it is
    /// eligible for reuse by this session alone.
    pub fn put(&self, session: &SessionRef, dst: &DstKey, sock: T) {
        let mut pools = self.inner.lock().expect("pool mutex");
        pools.entry(Self::key(session, dst)).or_default().push(sock);
    }

    /// Drop EVERY pooled socket the session owns (doc 12 §8 swept-session pool
    /// drop): on a revocation at a severing rung or session-end teardown, none of
    /// the session's warm sockets may survive into a later session's reuse. Returns
    /// the number of sockets dropped (for the §8 destroy-event accounting). The
    /// owned `T` values are dropped here, closing the real sockets.
    pub fn drop_session(&self, session: &SessionRef) -> usize {
        let mut pools = self.inner.lock().expect("pool mutex");
        let mut dropped = 0usize;
        pools.retain(|key, warm| {
            if key.tap_name == session.tap_name {
                dropped += warm.len();
                false // remove this partition entry (drops the sockets)
            } else {
                true
            }
        });
        dropped
    }

    /// How many warm sockets `session` has pooled across all destinations
    /// (test/diagnostic helper).
    pub fn warm_count(&self, session: &SessionRef) -> usize {
        let pools = self.inner.lock().expect("pool mutex");
        pools
            .iter()
            .filter(|(k, _)| k.tap_name == session.tap_name)
            .map(|(_, v)| v.len())
            .sum()
    }
}

/// The D53 enforcement-action ladder, modelled LOCALLY (doc 13 §2/§3 vocabulary;
/// doc 12 §8). Kept local to ds-tlsproxy on purpose: `ds-contracts`' API is
/// frozen v1, so the caller's rung type must NOT add a new public type there.
/// The ordering mirrors the D53 ladder and the `policy-core`
/// `Verdict::is_block_or_higher` predicate (the existing D53 severing predicate,
/// `policy-core/src/secret_matcher.rs`): the sever threshold is block.
///
/// `allow + log < block + log < suspend + ask < kill + snapshot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rung {
    /// `allow + log` — the flow is permitted; nothing severs.
    AllowLog,
    /// `block + log` — the flow is denied. The first rung that severs.
    BlockLog,
    /// `suspend + ask` — held for a human; severs (above block).
    SuspendAsk,
    /// `kill + snapshot` — terminal; severs (above block).
    KillSnapshot,
}

impl Rung {
    /// Whether this rung is "block-or-higher" — the D53 threshold at which the
    /// flow-severing rung fires (doc 12 §8; doc 14 §5 "flush when rung ≥ block").
    ///
    /// Mirrors `policy_core::secret_matcher::Verdict::is_block_or_higher`: the
    /// severing predicate is reused in SPIRIT (block, suspend, kill sever;
    /// allow+log does not), kept as a local type so the frozen `ds-contracts`
    /// API gains nothing.
    pub fn is_block_or_higher(self) -> bool {
        self >= Rung::BlockLog
    }

    /// The D53 rung → revocation-delta WIRE BYTE mapping — the SINGLE SOURCE OF
    /// TRUTH for the over-the-wire encoding the host-agent fan-out (encoder) and
    /// the `ds-tlsproxy` revocation-delta subscriber (decoder) must agree on
    /// (doc 12 §8). The two services share no crate, so the byte table is
    /// duplicated by construction; hanging it on the `Rung` enum keeps the
    /// proxy's half single-sourced and the conformance fixture
    /// (`assurance/conformance-adapter/revocationwire`) pins both halves to this
    /// table, so a future D53 ladder change can never silently under-sever from a
    /// stale, re-listed byte literal. The bytes are FROZEN by the wire contract,
    /// not by enum declaration order — they are written out explicitly, never
    /// derived from a `#[repr(u8)]` discriminant, so reordering the ladder cannot
    /// renumber the wire.
    ///
    /// `allow+log = 0 · block+log = 1 · suspend+ask = 2 · kill+snapshot = 3`.
    pub const fn rung_to_wire_byte(self) -> u8 {
        match self {
            Rung::AllowLog => 0,
            Rung::BlockLog => 1,
            Rung::SuspendAsk => 2,
            Rung::KillSnapshot => 3,
        }
    }

    /// The inverse of [`Rung::rung_to_wire_byte`]: decode one revocation-delta
    /// wire byte back to a `Rung`, or `None` for an unknown byte. An unknown rung
    /// byte is a MALFORMED frame the subscriber drops fail-closed (it never
    /// silently severs nothing or guesses a rung) — see
    /// `RevocationDeltaWire::decode_delta`. Round-trips with `rung_to_wire_byte`
    /// for every defined rung (the `rung_wire_byte_round_trips` test pins it).
    pub const fn rung_from_wire_byte(b: u8) -> Option<Rung> {
        match b {
            0 => Some(Rung::AllowLog),
            1 => Some(Rung::BlockLog),
            2 => Some(Rung::SuspendAsk),
            3 => Some(Rung::KillSnapshot),
            // An unknown rung byte is a malformed frame — never silently severing.
            _ => None,
        }
    }
}

/// Which kind of severable thing the proxy registered, for diagnostics and so a
/// caller can reason about what a sweep dropped. Both are severed identically;
/// the distinction is purely for the LOG/accounting surface (doc 12 §8 names
/// both "live tunnels" and "pooled upstream sockets").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleKind {
    /// A live forwarding tunnel (downstream VM-facing leg `0x1` and/or upstream
    /// leg `0x2`).
    Tunnel,
    /// A warm, pooled upstream socket (upstream leg `0x2`) not currently carrying
    /// a tunnel — must still be dropped for the swept session (doc 12 §8, §4.2:
    /// pools are partitioned per session).
    PooledUpstream,
}

/// A thing the registry can sever: the userspace abstraction over a live
/// tunnel's socket pair or a pooled upstream socket.
///
/// This is the **pingora wiring seam** (doc 12 §13.1): production implements it
/// over the real downstream/upstream sockets (a `shutdown(SHUT_RDWR)` + pool
/// eviction) inside the listener/connect layer that owns the pingora types;
/// everything inward of that layer — including this registry — speaks only this
/// trait, so no framework type leaks in. Tests implement it over a fake handle.
///
/// `sever` is idempotent: severing an already-severed handle is a no-op and
/// returns `false` (nothing newly severed), so a re-driven flush double-counts
/// nothing (doc 12 §8 — `applied_seq` is reported once, after sweep completion).
pub trait Severable: Send + Sync {
    /// Sever this handle (close both directions / evict from the pool). Returns
    /// `true` iff this call transitioned the handle from live to severed
    /// (idempotent: a second call returns `false`).
    fn sever(&self) -> bool;

    /// Whether this handle is still live (not yet severed).
    fn is_live(&self) -> bool;
}

/// A monotonic per-registry handle id. Each registered tunnel or pooled socket
/// gets exactly one — so the registry severs (and counts) a handle ONCE even
/// when it matches a flush on more than one leg (a tunnel matches on both `0x1`
/// and `0x2`). This is what makes the leg span a MATCH coordinate, not a sever
/// multiplier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct HandleId(u64);

/// `Leg` is not `Ord` in `ds-contracts` (it is a small enum, deliberately
/// minimal). The registry compares legs by their frozen nibble value
/// (`Leg::nibble`) — the canonical ordering, and the same value the mask carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LegOrd(u32);

impl From<Leg> for LegOrd {
    fn from(leg: Leg) -> LegOrd {
        LegOrd(leg.nibble())
    }
}

/// One registered handle: the userspace tunnel/socket, plus the coordinates a
/// flush narrows against. A handle is stored ONCE (keyed by [`HandleId`]) and
/// occupies one `(tap, dst)` and a SET of legs — a tunnel occupies `{0x1, 0x2}`,
/// a pooled socket `{0x2}` — so a flush matching either leg severs the one
/// handle a single time.
struct Entry {
    /// Authoritative session join key (doc 14 §4) — the never-recycled tap name;
    /// the registry partitions on it, never on the recyclable 14-bit mark index.
    tap_name: String,
    /// The destination key (the §3 admission-map reverse-index element).
    dst: String,
    /// The leg nibbles this handle rides (tunnel `{0x1,0x2}`, pool `{0x2}`).
    legs: Vec<LegOrd>,
    /// Which population this is (doc 12 §8 — tunnels vs pooled sockets).
    kind: HandleKind,
    /// The severable userspace handle.
    handle: Box<dyn Severable>,
}

impl Entry {
    /// Whether this handle rides any of the legs `selector` spans.
    fn matches_legs(&self, selector: &LegSelector) -> bool {
        match selector {
            LegSelector::All => true,
            LegSelector::Some(legs) => {
                let wanted: Vec<LegOrd> = legs.iter().map(|&l| LegOrd::from(l)).collect();
                self.legs.iter().any(|l| wanted.contains(l))
            }
        }
    }
}

/// The framework-agnostic severing registry: live tunnels and pooled upstream
/// sockets registered per `(SessionRef, DstKey, Leg-set)`, implementing the
/// frozen [`FlushSession`] contract as the proxy-side twin of ds-nft's
/// `NftWriter`.
///
/// Interior-mutable behind a `Mutex` so the listener/connect layer can register
/// handles while a snapshot-apply thread drives a sweep (doc 12 §8 two-phase
/// apply) without threading a `&mut` through the proxy. This is a registry of
/// userspace state — no conntrack, no netlink, no ds-nft (frozen non-edge).
#[derive(Default)]
pub struct SeveringRegistry {
    inner: Mutex<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    next_id: u64,
    entries: BTreeMap<HandleId, Entry>,
}

impl SeveringRegistry {
    /// A fresh, empty registry.
    pub fn new() -> SeveringRegistry {
        SeveringRegistry {
            inner: Mutex::new(RegistryState::default()),
        }
    }

    /// Register a live tunnel for `(session, dst)`. The tunnel spans both the
    /// VM-facing leg (`0x1`) and the upstream leg (`0x2`); the single handle
    /// rides BOTH legs, so a revocation passing `sever_pair()` tears the whole
    /// tunnel down with one `sever()` call. Returns the assigned handle id so a
    /// caller can drop a specific tunnel on its own lifecycle (e.g. normal close)
    /// without a flush.
    pub fn register_tunnel(
        &self,
        session: &SessionRef,
        dst: &DstKey,
        handle: Box<dyn Severable>,
    ) -> u64 {
        self.insert(Entry {
            tap_name: session.tap_name.clone(),
            dst: dst.0.clone(),
            legs: vec![Leg::AgentVm.into(), Leg::TlsproxyUpstream.into()],
            kind: HandleKind::Tunnel,
            handle,
        })
    }

    /// Register a warm pooled upstream socket for `(session, dst)` on the
    /// upstream leg (`0x2`). Pools are partitioned per session (doc 14 §5,
    /// frozen), so a pooled socket only ever belongs to one session's sweep. A
    /// pooled socket and a live tunnel to the same destination are DISTINCT
    /// handles (distinct ids), both severed at teardown.
    pub fn register_pooled_upstream(
        &self,
        session: &SessionRef,
        dst: &DstKey,
        handle: Box<dyn Severable>,
    ) -> u64 {
        self.insert(Entry {
            tap_name: session.tap_name.clone(),
            dst: dst.0.clone(),
            legs: vec![Leg::TlsproxyUpstream.into()],
            kind: HandleKind::PooledUpstream,
            handle,
        })
    }

    fn insert(&self, entry: Entry) -> u64 {
        let mut state = self.inner.lock().expect("registry mutex");
        let id = state.next_id;
        state.next_id += 1;
        state.entries.insert(HandleId(id), entry);
        id
    }

    /// Number of still-live registered handles for a session (test/diagnostic
    /// helper). A tunnel counts as 1 handle (not its leg count); a pooled socket
    /// as 1.
    pub fn live_handles(&self, session: &SessionRef) -> usize {
        let state = self.inner.lock().expect("registry mutex");
        state
            .entries
            .values()
            .filter(|e| e.tap_name == session.tap_name && e.handle.is_live())
            .count()
    }

    /// Narrow per `dst_filter`: `All` → every destination for the session
    /// (teardown); `Only(keys)` → exactly those dst keys (revocation of the
    /// refcount-zero set elements, the §3 reverse-index keys).
    fn dst_matches(filter: &DstFilter, dst: &str) -> bool {
        match filter {
            DstFilter::All => true,
            DstFilter::Only(keys) => keys.iter().any(|k| k.0 == dst),
        }
    }

    /// The shared severing body — the proxy-side twin of ds-nft's
    /// `flush_session_report`. Narrows to the session's handles matching
    /// `dst_filter` AND riding any leg in `legs`, severs each still-live handle
    /// EXACTLY ONCE, and returns how many were newly severed. Idempotent: a
    /// handle already severed by a prior flush contributes 0.
    fn sever_matching(
        &self,
        session: &SessionRef,
        dst_filter: &DstFilter,
        legs: &LegSelector,
    ) -> u64 {
        let state = self.inner.lock().expect("registry mutex");
        let mut severed: u64 = 0;
        for entry in state.entries.values() {
            if entry.tap_name != session.tap_name {
                continue;
            }
            if !Self::dst_matches(dst_filter, &entry.dst) {
                continue;
            }
            if !entry.matches_legs(legs) {
                continue;
            }
            // Idempotence: never re-sever a handle a prior flush already closed
            // (a real `shutdown()` must not fire twice on a dead socket). The
            // leg set is a MATCH coordinate, not a sever multiplier — one handle,
            // at most one sever() call ever. `sever()` itself also returns false
            // on a redundant call, so this is belt-and-suspenders.
            if entry.handle.is_live() && entry.handle.sever() {
                severed += 1;
            }
        }
        severed
    }

    /// UNCONDITIONAL session-end teardown (NFT-6 / the >15-min park tier, doc 12
    /// §8/§12): sever every tunnel and pooled socket the session owns —
    /// `dst = All`, `legs = All`. Never rung-gated. Returns the handle count
    /// severed for the destroy-event accounting (doc 14 §5).
    pub fn teardown_session(&self, session: &SessionRef) -> FlushOutcome {
        let entries_flushed = self.sever_matching(session, &DstFilter::All, &LegSelector::All);
        FlushOutcome { entries_flushed }
    }

    /// Per-kind live-handle breakdown for a session (doc 12 §8 names both
    /// populations — "live tunnels" and "pooled upstream sockets" — so the
    /// destroy-event accounting distinguishes them). Counts still-live handles
    /// only; severed handles drop out.
    pub fn live_breakdown(&self, session: &SessionRef) -> LiveBreakdown {
        let state = self.inner.lock().expect("registry mutex");
        let mut bd = LiveBreakdown::default();
        for entry in state.entries.values() {
            if entry.tap_name != session.tap_name || !entry.handle.is_live() {
                continue;
            }
            match entry.kind {
                HandleKind::Tunnel => bd.tunnels += 1,
                HandleKind::PooledUpstream => bd.pooled_upstream += 1,
            }
        }
        bd
    }
}

/// A live-handle breakdown by [`HandleKind`] (doc 12 §8 — the two named
/// populations).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LiveBreakdown {
    /// Live tunnels (counted once each, regardless of their `{0x1,0x2}` legs).
    pub tunnels: usize,
    /// Live pooled upstream sockets.
    pub pooled_upstream: usize,
}

/// The frozen-contract entry point. The registry IS a [`FlushSession`]
/// implementor — the proxy-side twin of ds-nft's `NftWriter`. All three callers
/// (revocation sweep, NFT-6 teardown, park tier) reach the same body; the
/// differences are entirely in the `dst_filter` / `legs` arguments, exactly as
/// the contract intends (doc 14 §5).
impl FlushSession for SeveringRegistry {
    type Error = ProxyFlushError;

    fn flush_session(
        &self,
        session: &SessionRef,
        dst_filter: &DstFilter,
        legs: &LegSelector,
    ) -> Result<FlushOutcome, Self::Error> {
        let entries_flushed = self.sever_matching(session, dst_filter, legs);
        Ok(FlushOutcome { entries_flushed })
    }
}

/// The proxy registry's flush error surface. The registry severs userspace
/// handles synchronously and infallibly today (a fake handle cannot fail), so
/// this is an empty error type — present only to satisfy the frozen
/// [`FlushError`] bound so callers can be written generically over the contract.
/// The real-socket `shutdown()` failure surface is M0-host integration work
/// (module doc, scope honesty).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyFlushError {}

impl FlushError for ProxyFlushError {}

/// One revoked admission in a D72 sweep: the destinations revoked for a session
/// and the D53 rung the revoking rule carries. Modelled on the snapshot-apply
/// path's output (doc 12 §8): after the vN+1 commit, the sweep re-evaluates
/// derived state and produces the revoked `(session, dst-keys, rung)` set.
pub struct RevokedAdmission {
    /// The session whose admission was revoked.
    pub session: SessionRef,
    /// The destination keys revoked (the refcount-zero set elements, §3 reverse
    /// index). Empty means "no destinations" — a no-op sweep entry.
    pub dst_keys: Vec<DstKey>,
    /// The D53 rung the revoking rule assigns. Severing is gated on this.
    pub rung: Rung,
}

/// The rung-conditional revocation-sweep CALLER (D53/D72) — the decision logic
/// ds-nft deliberately does not host (ds-nft is mechanism-only). Wraps a
/// [`SeveringRegistry`] and applies the D53 rule: sever live tunnels + pooled
/// sockets for a revoked admission **only when its rung is block-or-higher**;
/// session-end teardown is unconditional (call [`SeveringRegistry::teardown_session`]
/// directly); per D68 expiry is never revocation, so an expiring admission is
/// simply never handed to this sweep.
pub struct RevocationSweep<'a> {
    registry: &'a SeveringRegistry,
}

/// What a sweep did, for the §8 destroy-event accounting and applied-seq report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Total registry entries newly severed across all severing-rung revocations.
    pub entries_severed: u64,
    /// How many revoked admissions met the block-or-higher severing threshold.
    pub severing_revocations: u64,
    /// How many revoked admissions were sub-block (allow+log) and so left their
    /// established flows untouched (D53 — non-severing rung).
    pub non_severing_revocations: u64,
}

impl<'a> RevocationSweep<'a> {
    /// Build a sweep handler over a registry.
    pub fn new(registry: &'a SeveringRegistry) -> RevocationSweep<'a> {
        RevocationSweep { registry }
    }

    /// Apply the D72 revocation sweep to a set of revoked admissions. For each:
    ///
    /// - **block-or-higher rung** → sever the matching tunnels + pooled sockets,
    ///   narrowed to exactly the revoked dst keys (`DstFilter::Only`) on the
    ///   sever pair (`0x1`+`0x2`, [`LegSelector::sever_pair`]). Established flows
    ///   for those destinations are torn down.
    /// - **sub-block rung** (allow+log) → leave everything untouched (D53): the
    ///   revocation re-evaluates policy but does not sever live flows.
    ///
    /// Idempotent across re-drives: a handle already severed counts once.
    pub fn apply(&self, revoked: &[RevokedAdmission]) -> SweepOutcome {
        let mut outcome = SweepOutcome::default();
        for adm in revoked {
            if adm.rung.is_block_or_higher() {
                outcome.severing_revocations += 1;
                if adm.dst_keys.is_empty() {
                    continue;
                }
                let filter = DstFilter::Only(adm.dst_keys.clone());
                let severed = self
                    .registry
                    .flush_session(&adm.session, &filter, &LegSelector::sever_pair())
                    // infallible for the userspace registry (ProxyFlushError is
                    // empty); the frozen contract still returns a Result.
                    .map(|o| o.entries_flushed)
                    .unwrap_or(0);
                outcome.entries_severed += severed;
            } else {
                outcome.non_severing_revocations += 1;
                // D53 non-severing rung: deliberately sever NOTHING.
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A fake severable handle: a live flag plus a sever-call counter, so tests
    /// assert both that the right handles were severed AND that sever() fired at
    /// most once per handle (idempotence / no double-count).
    struct FakeHandle {
        live: AtomicBool,
        sever_calls: AtomicUsize,
    }

    impl FakeHandle {
        fn new() -> Arc<FakeHandle> {
            Arc::new(FakeHandle {
                live: AtomicBool::new(true),
                sever_calls: AtomicUsize::new(0),
            })
        }
        fn calls(&self) -> usize {
            self.sever_calls.load(Ordering::SeqCst)
        }
    }

    impl Severable for FakeHandle {
        fn sever(&self) -> bool {
            self.sever_calls.fetch_add(1, Ordering::SeqCst);
            // swap live → false; return true only on the live→severed transition.
            self.live.swap(false, Ordering::SeqCst)
        }
        fn is_live(&self) -> bool {
            self.live.load(Ordering::SeqCst)
        }
    }

    // Arc<FakeHandle> needs to be Severable to register as a pooled box too.
    impl Severable for Arc<FakeHandle> {
        fn sever(&self) -> bool {
            (**self).sever()
        }
        fn is_live(&self) -> bool {
            (**self).is_live()
        }
    }

    fn session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    fn dst(s: &str) -> DstKey {
        DstKey(s.into())
    }

    // ---- the four mandated acceptance tests ------------------------------

    #[test]
    fn block_or_higher_rung_severs_exactly_the_matching_tunnels_and_pools() {
        let reg = SeveringRegistry::new();
        let s = session(7);

        // a live tunnel + a pooled upstream socket for the REVOKED dst...
        let revoked_tunnel = FakeHandle::new();
        let revoked_pool = FakeHandle::new();
        reg.register_tunnel(&s, &dst("203.0.113.10"), Box::new(revoked_tunnel.clone()));
        reg.register_pooled_upstream(&s, &dst("203.0.113.10"), Box::new(revoked_pool.clone()));

        // ...and a tunnel for a DIFFERENT, non-revoked dst that must survive.
        let other_tunnel = FakeHandle::new();
        reg.register_tunnel(&s, &dst("198.51.100.7"), Box::new(other_tunnel.clone()));

        let sweep = RevocationSweep::new(&reg);
        let out = sweep.apply(&[RevokedAdmission {
            session: s.clone(),
            dst_keys: vec![dst("203.0.113.10")],
            rung: Rung::BlockLog,
        }]);

        // the revoked tunnel (one handle riding legs 0x1+0x2) + the revoked
        // pooled socket (one handle, leg 0x2) were severed: 2 handles.
        assert_eq!(out.entries_severed, 2);
        assert_eq!(out.severing_revocations, 1);
        assert_eq!(out.non_severing_revocations, 0);

        assert!(!revoked_tunnel.is_live());
        assert!(!revoked_pool.is_live());
        // dst-scoped: the other destination's tunnel is untouched.
        assert!(other_tunnel.is_live());
        assert_eq!(other_tunnel.calls(), 0);

        // the revoked tunnel's sever fired EXACTLY once despite spanning 2 legs
        // (mark-mask/leg discipline: 0x1 and 0x2 reference one handle).
        assert_eq!(revoked_tunnel.calls(), 1);
        assert_eq!(revoked_pool.calls(), 1);
    }

    #[test]
    fn sub_block_rung_revocation_leaves_established_entries_untouched() {
        let reg = SeveringRegistry::new();
        let s = session(3);
        let tunnel = FakeHandle::new();
        let pool = FakeHandle::new();
        reg.register_tunnel(&s, &dst("203.0.113.20"), Box::new(tunnel.clone()));
        reg.register_pooled_upstream(&s, &dst("203.0.113.20"), Box::new(pool.clone()));

        let sweep = RevocationSweep::new(&reg);
        // allow+log is below the block threshold → no severing (D53).
        let out = sweep.apply(&[RevokedAdmission {
            session: s.clone(),
            dst_keys: vec![dst("203.0.113.20")],
            rung: Rung::AllowLog,
        }]);

        assert_eq!(out.entries_severed, 0);
        assert_eq!(out.severing_revocations, 0);
        assert_eq!(out.non_severing_revocations, 1);
        assert!(tunnel.is_live());
        assert!(pool.is_live());
        assert_eq!(tunnel.calls(), 0);
        assert_eq!(pool.calls(), 0);
    }

    #[test]
    fn session_end_teardown_severs_everything_including_pools_legs_all() {
        let reg = SeveringRegistry::new();
        let s = session(9);
        // two tunnels (different dsts) + a pooled socket — all must go.
        let t1 = FakeHandle::new();
        let t2 = FakeHandle::new();
        let pool = FakeHandle::new();
        reg.register_tunnel(&s, &dst("203.0.113.30"), Box::new(t1.clone()));
        reg.register_tunnel(&s, &dst("203.0.113.31"), Box::new(t2.clone()));
        reg.register_pooled_upstream(&s, &dst("203.0.113.32"), Box::new(pool.clone()));

        // a DIFFERENT session's tunnel must NOT be touched by this teardown.
        let other = session(10);
        let other_tunnel = FakeHandle::new();
        reg.register_tunnel(&other, &dst("203.0.113.30"), Box::new(other_tunnel.clone()));

        let out = reg.teardown_session(&s);

        // 2 tunnels + 1 pool = 3 transitions.
        assert_eq!(out.entries_flushed, 3);
        assert!(!t1.is_live());
        assert!(!t2.is_live());
        assert!(!pool.is_live());
        // the other session survived (teardown is session-partitioned).
        assert!(other_tunnel.is_live());
        assert_eq!(other_tunnel.calls(), 0);
    }

    #[test]
    fn expiry_is_not_revocation_and_severs_nothing() {
        // D68 (doc 09 OQ3): an expiring admission re-admits, never severs. The
        // expiry path simply does not hand the admission to the sweep — there is
        // no "expiry rung". Model it as an empty sweep: no entry is severed, and
        // the live tunnel for the expiring dst keeps forwarding (re-admit, not
        // refuse). Contrast: only an explicit revoke at a severing rung severs.
        let reg = SeveringRegistry::new();
        let s = session(5);
        let tunnel = FakeHandle::new();
        reg.register_tunnel(&s, &dst("203.0.113.40"), Box::new(tunnel.clone()));

        let sweep = RevocationSweep::new(&reg);
        // expiry produces NO RevokedAdmission entries (it is not a revocation).
        let out = sweep.apply(&[]);

        assert_eq!(out.entries_severed, 0);
        assert_eq!(out.severing_revocations, 0);
        assert_eq!(out.non_severing_revocations, 0);
        // the expiring admission's tunnel is still live — it re-admits, doesn't sever.
        assert!(tunnel.is_live());
        assert_eq!(tunnel.calls(), 0);
    }

    // ---- supporting discipline tests -------------------------------------

    #[test]
    fn rung_ladder_orders_and_block_is_the_sever_threshold() {
        // doc 13 §2/§3 ladder ordering.
        assert!(Rung::AllowLog < Rung::BlockLog);
        assert!(Rung::BlockLog < Rung::SuspendAsk);
        assert!(Rung::SuspendAsk < Rung::KillSnapshot);
        // sever threshold = block (mirrors Verdict::is_block_or_higher).
        assert!(!Rung::AllowLog.is_block_or_higher());
        assert!(Rung::BlockLog.is_block_or_higher());
        assert!(Rung::SuspendAsk.is_block_or_higher());
        assert!(Rung::KillSnapshot.is_block_or_higher());
    }

    #[test]
    fn rung_wire_byte_round_trips_and_pins_the_d53_table() {
        // The D53 rung↔wire-byte mapping is single-sourced HERE (the host-agent
        // encoder + the proxy's RevocationDeltaWire decoder both ride this table,
        // pinned cross-service by the revocationwire conformance fixture). Pin the
        // FROZEN byte values explicitly — a reordering of the enum must not be able
        // to renumber the wire — and prove the decode is the encode's inverse.
        assert_eq!(Rung::AllowLog.rung_to_wire_byte(), 0);
        assert_eq!(Rung::BlockLog.rung_to_wire_byte(), 1);
        assert_eq!(Rung::SuspendAsk.rung_to_wire_byte(), 2);
        assert_eq!(Rung::KillSnapshot.rung_to_wire_byte(), 3);
        for rung in [
            Rung::AllowLog,
            Rung::BlockLog,
            Rung::SuspendAsk,
            Rung::KillSnapshot,
        ] {
            assert_eq!(
                Rung::rung_from_wire_byte(rung.rung_to_wire_byte()),
                Some(rung),
                "rung {rung:?} round-trips through the wire byte",
            );
        }
        // An unknown byte is a malformed frame (decode → None; never a guessed rung).
        assert_eq!(Rung::rung_from_wire_byte(4), None);
        assert_eq!(Rung::rung_from_wire_byte(0xFF), None);
    }

    #[test]
    fn suspend_and_kill_rungs_also_sever() {
        for rung in [Rung::SuspendAsk, Rung::KillSnapshot] {
            let reg = SeveringRegistry::new();
            let s = session(1);
            let tunnel = FakeHandle::new();
            reg.register_tunnel(&s, &dst("203.0.113.50"), Box::new(tunnel.clone()));
            let sweep = RevocationSweep::new(&reg);
            let out = sweep.apply(&[RevokedAdmission {
                session: s.clone(),
                dst_keys: vec![dst("203.0.113.50")],
                rung,
            }]);
            assert_eq!(out.entries_severed, 1, "rung {rung:?} must sever");
            assert!(!tunnel.is_live());
        }
    }

    #[test]
    fn revocation_severs_only_the_sever_pair_legs_not_other_nibbles() {
        // The sweep narrows to sever_pair() {0x1 agent-VM, 0x2 upstream}; a proxy
        // tunnel/pool rides only those legs. Drive the registry's frozen
        // FlushSession DIRECTLY with selectors to prove the leg discipline:
        let reg = SeveringRegistry::new();
        let s = session(13);

        // sever_pair() is exactly the agent-VM + upstream legs (frozen contract).
        assert_eq!(
            LegSelector::sever_pair(),
            LegSelector::Some(vec![Leg::AgentVm, Leg::TlsproxyUpstream])
        );

        // A tunnel rides {0x1,0x2}. A selector of ONLY non-sever-pair legs
        // (dnsgate 0x3, infra 0x4) must NOT match it — those nibbles never
        // belong to a proxy tunnel.
        let tunnel = FakeHandle::new();
        reg.register_tunnel(&s, &dst("203.0.113.99"), Box::new(tunnel.clone()));
        let off_pair = LegSelector::Some(vec![Leg::DnsgateUpstream, Leg::InfraEgress]);
        let none = reg
            .flush_session(&s, &DstFilter::All, &off_pair)
            .expect("infallible");
        assert_eq!(none.entries_flushed, 0);
        assert!(tunnel.is_live(), "non-sever-pair legs must not match");

        // The sever pair (or either of its legs alone) DOES match the tunnel.
        let agent_only = LegSelector::Some(vec![Leg::AgentVm]);
        let hit = reg
            .flush_session(&s, &DstFilter::All, &agent_only)
            .expect("infallible");
        assert_eq!(hit.entries_flushed, 1);
        assert!(!tunnel.is_live());
    }

    #[test]
    fn re_flush_is_idempotent_no_double_count() {
        let reg = SeveringRegistry::new();
        let s = session(2);
        let tunnel = FakeHandle::new();
        let pool = FakeHandle::new();
        reg.register_tunnel(&s, &dst("203.0.113.60"), Box::new(tunnel.clone()));
        reg.register_pooled_upstream(&s, &dst("203.0.113.60"), Box::new(pool.clone()));

        let sweep = RevocationSweep::new(&reg);
        let revoked = || {
            vec![RevokedAdmission {
                session: s.clone(),
                dst_keys: vec![dst("203.0.113.60")],
                rung: Rung::BlockLog,
            }]
        };

        let first = sweep.apply(&revoked());
        assert_eq!(first.entries_severed, 2); // tunnel + pool

        // re-driving the SAME sweep severs nothing new (handles already severed).
        let second = sweep.apply(&revoked());
        assert_eq!(second.entries_severed, 0);
        // each handle's sever() fired exactly once across both drives.
        assert_eq!(tunnel.calls(), 1);
        assert_eq!(pool.calls(), 1);
    }

    #[test]
    fn teardown_is_idempotent_too() {
        let reg = SeveringRegistry::new();
        let s = session(8);
        let tunnel = FakeHandle::new();
        reg.register_tunnel(&s, &dst("203.0.113.70"), Box::new(tunnel.clone()));

        assert_eq!(reg.teardown_session(&s).entries_flushed, 1);
        // second teardown finds nothing live.
        assert_eq!(reg.teardown_session(&s).entries_flushed, 0);
        assert_eq!(tunnel.calls(), 1);
    }

    #[test]
    fn flush_session_contract_signature_links_with_only_ds_contracts_types() {
        // The whole point of the twin: a caller drives the registry through the
        // frozen FlushSession contract with NO framework types — only
        // ds-contracts shapes — exactly as ds-nft's NftWriter does.
        fn use_it<F: FlushSession>(f: &F, s: &SessionRef) -> Result<FlushOutcome, F::Error> {
            f.flush_session(s, &DstFilter::All, &LegSelector::All)
        }
        let reg = SeveringRegistry::new();
        let out = use_it(&reg, &session(4)).expect("contract call");
        assert_eq!(out, FlushOutcome { entries_flushed: 0 });
    }

    #[test]
    fn multiple_dst_keys_narrow_to_each_listed_destination() {
        let reg = SeveringRegistry::new();
        let s = session(6);
        let a = FakeHandle::new();
        let b = FakeHandle::new();
        let c = FakeHandle::new();
        reg.register_tunnel(&s, &dst("a"), Box::new(a.clone()));
        reg.register_tunnel(&s, &dst("b"), Box::new(b.clone()));
        reg.register_tunnel(&s, &dst("c"), Box::new(c.clone()));

        let sweep = RevocationSweep::new(&reg);
        // revoke only a and c; b survives.
        let out = sweep.apply(&[RevokedAdmission {
            session: s.clone(),
            dst_keys: vec![dst("a"), dst("c")],
            rung: Rung::BlockLog,
        }]);
        assert_eq!(out.entries_severed, 2);
        assert!(!a.is_live());
        assert!(b.is_live());
        assert!(!c.is_live());
    }

    #[test]
    fn live_breakdown_separates_tunnels_from_pooled_sockets() {
        let reg = SeveringRegistry::new();
        let s = session(12);
        let t = FakeHandle::new();
        let p1 = FakeHandle::new();
        let p2 = FakeHandle::new();
        reg.register_tunnel(&s, &dst("203.0.113.90"), Box::new(t.clone())); // 1 tunnel
        reg.register_pooled_upstream(&s, &dst("203.0.113.91"), Box::new(p1.clone()));
        reg.register_pooled_upstream(&s, &dst("203.0.113.92"), Box::new(p2.clone()));

        let bd = reg.live_breakdown(&s);
        assert_eq!(bd.tunnels, 1);
        assert_eq!(bd.pooled_upstream, 2);

        // a severing-rung revoke of just the tunnel's dst drops the tunnel but
        // leaves the pools (different dsts) live.
        let sweep = RevocationSweep::new(&reg);
        sweep.apply(&[RevokedAdmission {
            session: s.clone(),
            dst_keys: vec![dst("203.0.113.90")],
            rung: Rung::BlockLog,
        }]);
        let bd2 = reg.live_breakdown(&s);
        assert_eq!(bd2.tunnels, 0);
        assert_eq!(bd2.pooled_upstream, 2);
    }

    #[test]
    fn live_handles_counts_per_session_and_drops_after_sever() {
        let reg = SeveringRegistry::new();
        let s = session(11);
        let t = FakeHandle::new();
        let p = FakeHandle::new();
        // a tunnel and a pooled socket to the SAME dst are DISTINCT handles
        // (no key collision): 2 live handles.
        reg.register_tunnel(&s, &dst("203.0.113.80"), Box::new(t.clone()));
        reg.register_pooled_upstream(&s, &dst("203.0.113.80"), Box::new(p.clone()));
        assert_eq!(reg.live_handles(&s), 2);
        reg.teardown_session(&s);
        assert_eq!(reg.live_handles(&s), 0);
    }

    // ── D76 upstream-mark + per-session pool partitioning (doc 12 §4.2) ─────────
    //
    // These exercise the framework-agnostic core: the frozen mark VALUE, the
    // best-effort mark CALL-SITE via a recording setter (NO privileged syscall —
    // no SO_MARK setsockopt, no kernel, no CAP_NET_ADMIN/CAP_NET_RAW), and the
    // per-session pool whose key makes cross-session reuse structurally impossible.
    // The LIVE setsockopt(SO_MARK) is a CAP_NET_RAW CI/manual harness (it EPERMs
    // in this unprivileged sandbox) — see the module doc on `MarkAttempt`.

    /// A recording [`MarkSetter`] that captures every mark it is asked to set and
    /// returns a programmable outcome — the test stand-in for the live
    /// `socket2::SockRef::set_mark` setsockopt, so the VALUE and the CALL-SITE are
    /// proven with no kernel.
    struct RecordingSetter {
        marks: Mutex<Vec<u32>>,
        outcome: MarkAttempt,
    }

    impl RecordingSetter {
        fn new(outcome: MarkAttempt) -> RecordingSetter {
            RecordingSetter {
                marks: Mutex::new(Vec::new()),
                outcome,
            }
        }
        fn recorded(&self) -> Vec<u32> {
            self.marks.lock().expect("marks").clone()
        }
    }

    impl MarkSetter for RecordingSetter {
        fn set_mark(&self, mark: u32) -> MarkAttempt {
            self.marks.lock().expect("marks").push(mark);
            self.outcome
        }
    }

    #[test]
    fn upstream_mark_value_is_compose_tlsproxy_upstream_for_each_index() {
        // The frozen D76 value: compose(Leg::TlsproxyUpstream, host_session_index).
        // Representative indices including 0, a mid value, the field max (2^14-1),
        // and a value that wraps mod 2^14 (the field is a disambiguator, doc 14 §4).
        for &idx in &[0u32, 1, 7, 42, 16_383, 16_384, 16_384 + 5, 100_000] {
            let s = session(idx);
            let got = upstream_mark(&s);
            // byte-exact against the ds-contracts compose() — the single source.
            assert_eq!(got, mark::compose(Leg::TlsproxyUpstream, idx));
            // structural: magic 0xD, leg nibble 0x2, index = idx mod 2^14.
            let parts = mark::decompose(got).expect("a well-formed DS mark");
            assert_eq!(parts.leg, Leg::TlsproxyUpstream);
            assert_eq!(
                parts.session_index as u32,
                idx % mark::SESSION_INDEX_MODULUS
            );
            // the leg nibble sits in bits 27–24 and is exactly 0x2.
            assert_eq!(mark::leg_nibble_of(got), 0x2);
            assert_eq!(mark::magic_of(got), mark::DS_MARK_MAGIC);
        }
    }

    #[test]
    fn mark_upstream_invokes_setter_once_with_the_frozen_value() {
        // The call-site: every upstream path computes the value and invokes the
        // setter exactly once, BEFORE connect. Proven with a recorder (no kernel).
        let setter = RecordingSetter::new(MarkAttempt::Marked);
        let s = session(7);
        let (mark, attempt) = mark_upstream(&setter, &s);
        assert_eq!(mark, mark::compose(Leg::TlsproxyUpstream, 7));
        assert!(attempt.is_marked());
        // invoked exactly once, with exactly the frozen value.
        assert_eq!(
            setter.recorded(),
            vec![mark::compose(Leg::TlsproxyUpstream, 7)]
        );
    }

    #[test]
    fn mark_upstream_is_best_effort_eperm_is_tolerated_and_value_still_returned() {
        // The unprivileged sandbox/CI shape: SO_MARK EPERMs. The mark value is
        // STILL computed and returned (best-effort — the connect proceeds), and
        // the setter was still invoked with the frozen value. No syscall here: the
        // recorder just reports PermissionDenied, mirroring the EPERM the live
        // setsockopt returns without CAP_NET_RAW.
        let setter = RecordingSetter::new(MarkAttempt::PermissionDenied);
        let s = session(42);
        let (mark, attempt) = mark_upstream(&setter, &s);
        assert_eq!(mark, mark::compose(Leg::TlsproxyUpstream, 42));
        assert_eq!(attempt, MarkAttempt::PermissionDenied);
        assert!(!attempt.is_marked());
        // the setsockopt was attempted (invoked) even though it was refused.
        assert_eq!(
            setter.recorded(),
            vec![mark::compose(Leg::TlsproxyUpstream, 42)]
        );
    }

    #[test]
    fn pool_take_returns_none_when_empty() {
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let s = session(1);
        assert_eq!(pools.take(&s, &dst("203.0.113.1")), None);
        assert_eq!(pools.warm_count(&s), 0);
    }

    #[test]
    fn pool_put_then_take_returns_the_same_sessions_socket() {
        // A socket pooled for a session+dst is returned to the SAME session+dst.
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let s = session(3);
        pools.put(&s, &dst("203.0.113.10"), 0xAA);
        assert_eq!(pools.warm_count(&s), 1);
        assert_eq!(pools.take(&s, &dst("203.0.113.10")), Some(0xAA));
        // now empty.
        assert_eq!(pools.warm_count(&s), 0);
        assert_eq!(pools.take(&s, &dst("203.0.113.10")), None);
    }

    #[test]
    fn pool_isolation_session_a_socket_is_never_handed_to_session_b() {
        // The core D76 pool-partition invariant: a warm socket pooled by session A
        // is structurally unreachable from a session-B request — B's key carries
        // B's tap name, so take() never scans A's partition. Cross-session reuse is
        // impossible, so session B can never ride session A's admitted connection.
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let a = session(10); // tap dstap-10
        let b = session(11); // tap dstap-11
                             // Session A warms an upstream socket to a shared origin.
        pools.put(&a, &dst("203.0.113.20"), 0xA1);

        // Session B requests the SAME destination: it must NOT get A's socket —
        // it has no warm socket of its own → None (it will open a fresh, B-marked
        // connection instead).
        assert_eq!(pools.take(&b, &dst("203.0.113.20")), None);
        // A's socket is untouched — still warm in A's partition.
        assert_eq!(pools.warm_count(&a), 1);
        assert_eq!(pools.warm_count(&b), 0);

        // And A still gets its own socket back.
        assert_eq!(pools.take(&a, &dst("203.0.113.20")), Some(0xA1));
    }

    #[test]
    fn pool_isolation_holds_when_indices_collide_mod_two_to_the_fourteenth() {
        // The 14-bit mark index wraps mod 2^14, so two distinct sessions CAN share
        // a mark index — but the pool partitions on the never-recycled tap name,
        // not the recyclable index, so isolation still holds. Two sessions with the
        // SAME residue index but DIFFERENT tap names must not share a pool.
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let a = SessionRef::new("ua".into(), "host".into(), 5, "dstap-5".into());
        // host_session_index 16_384+5 ≡ 5 mod 2^14 (same mark residue as A)...
        let b = SessionRef::new("ub".into(), "host".into(), 16_384 + 5, "dstap-16389".into());
        assert_eq!(
            a.mark_session_index(),
            b.mark_session_index(),
            "same mark residue"
        );
        assert_ne!(a.tap_name, b.tap_name, "distinct never-recycled tap names");

        pools.put(&a, &dst("203.0.113.30"), 0xA);
        // B (same residue, different tap) must NOT see A's socket.
        assert_eq!(pools.take(&b, &dst("203.0.113.30")), None);
        assert_eq!(pools.take(&a, &dst("203.0.113.30")), Some(0xA));
    }

    #[test]
    fn pool_take_is_dst_scoped_within_a_session() {
        // A socket warmed to dst X is not reused for dst Y, even for the same
        // session (reuse is per-peer).
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let s = session(4);
        pools.put(&s, &dst("203.0.113.40"), 0x40);
        assert_eq!(pools.take(&s, &dst("203.0.113.41")), None); // different dst
        assert_eq!(pools.take(&s, &dst("203.0.113.40")), Some(0x40)); // same dst
    }

    #[test]
    fn drop_session_drops_every_pooled_socket_for_the_swept_session_only() {
        // doc 12 §8: a swept session's pooled sockets are all dropped (closed) and
        // none survives into a later session's reuse; other sessions are untouched.
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let swept = session(20);
        let other = session(21);
        // swept session warms several sockets across two destinations...
        pools.put(&swept, &dst("203.0.113.50"), 0x1);
        pools.put(&swept, &dst("203.0.113.50"), 0x2); // two to the same dst
        pools.put(&swept, &dst("203.0.113.51"), 0x3);
        // ...the other session warms one.
        pools.put(&other, &dst("203.0.113.50"), 0x9);

        assert_eq!(pools.warm_count(&swept), 3);
        let dropped = pools.drop_session(&swept);
        assert_eq!(
            dropped, 3,
            "all of the swept session's pooled sockets are dropped"
        );
        assert_eq!(pools.warm_count(&swept), 0);
        // a later request by the swept session finds nothing to reuse.
        assert_eq!(pools.take(&swept, &dst("203.0.113.50")), None);
        // the other session's socket is untouched.
        assert_eq!(pools.warm_count(&other), 1);
        assert_eq!(pools.take(&other, &dst("203.0.113.50")), Some(0x9));
    }

    #[test]
    fn drop_session_on_an_empty_partition_is_a_noop() {
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let s = session(22);
        assert_eq!(pools.drop_session(&s), 0);
    }

    // ── Pool partitioning + teardown integration (D76; doc 12 §4.2/§8) ──────────
    //
    // The unit's structural contract: the per-session pool drop is wired into the
    // SAME cleanup path the SeveringRegistry teardown / RevocationSweep drive, so a
    // swept session loses BOTH its live tunnels (registry) AND its warm pooled
    // sockets (pool partition), and a pooled socket's owned `T` is actually dropped
    // (real socket closed) — never left to survive into a later session.

    /// A pooled-socket stand-in whose `Drop` bumps a shared counter, so a test can
    /// PROVE the owned `T` was dropped (the real upstream socket closed) when its
    /// partition is swept — not merely removed from the map.
    struct DropCounted {
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for DropCounted {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn drop_session_actually_drops_the_owned_socket_values() {
        // doc 12 §8: "drop pooled upstream sockets for the swept session" — the owned
        // T values are dropped, closing the real sockets. Prove it with a Drop probe.
        let pools: SessionUpstreamPools<DropCounted> = SessionUpstreamPools::new();
        let swept = session(30);
        let other = session(31);
        let swept_drops = Arc::new(AtomicUsize::new(0));
        let other_drops = Arc::new(AtomicUsize::new(0));

        pools.put(
            &swept,
            &dst("203.0.113.60"),
            DropCounted {
                dropped: Arc::clone(&swept_drops),
            },
        );
        pools.put(
            &swept,
            &dst("203.0.113.61"),
            DropCounted {
                dropped: Arc::clone(&swept_drops),
            },
        );
        pools.put(
            &other,
            &dst("203.0.113.60"),
            DropCounted {
                dropped: Arc::clone(&other_drops),
            },
        );

        // nothing dropped yet (the sockets are warm in their partitions).
        assert_eq!(swept_drops.load(Ordering::SeqCst), 0);

        let dropped = pools.drop_session(&swept);
        assert_eq!(dropped, 2, "both of the swept session's pooled sockets");
        // the owned values were actually dropped (sockets closed), not just unlinked.
        assert_eq!(
            swept_drops.load(Ordering::SeqCst),
            2,
            "owned T values dropped → real sockets closed"
        );
        // the other session's pooled socket is still warm (not dropped).
        assert_eq!(other_drops.load(Ordering::SeqCst), 0);
        assert_eq!(pools.warm_count(&other), 1);
    }

    #[test]
    fn session_end_teardown_severs_tunnels_and_drops_the_pool_partition_together() {
        // NFT-6 session-end teardown (doc 12 §8): the SAME cleanup pass tears down the
        // session's live tunnels (SeveringRegistry) AND drops its warm pooled sockets
        // (SessionUpstreamPools) — the two populations doc 12 §8 names — leaving NOTHING
        // reusable, and touching no other session. This mirrors the `main.rs`
        // `teardown_session_with_grants` wiring at the library level.
        let reg = SeveringRegistry::new();
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let s = session(40);
        let other = session(41);

        // live tunnel + warm pooled sockets for the session...
        let tunnel = FakeHandle::new();
        reg.register_tunnel(&s, &dst("203.0.113.70"), Box::new(tunnel.clone()));
        pools.put(&s, &dst("203.0.113.70"), 0x70);
        pools.put(&s, &dst("203.0.113.71"), 0x71);
        // ...and a tunnel + pooled socket for a DIFFERENT session that must survive.
        let other_tunnel = FakeHandle::new();
        reg.register_tunnel(&other, &dst("203.0.113.70"), Box::new(other_tunnel.clone()));
        pools.put(&other, &dst("203.0.113.70"), 0x99);

        // The combined session-end cleanup pass.
        let flushed = reg.teardown_session(&s).entries_flushed;
        let pool_dropped = pools.drop_session(&s);

        assert_eq!(flushed, 1, "the session's live tunnel severed");
        assert_eq!(
            pool_dropped, 2,
            "both of the session's pooled sockets dropped"
        );
        assert!(!tunnel.is_live());
        assert_eq!(reg.live_handles(&s), 0);
        assert_eq!(pools.warm_count(&s), 0);
        // a later request by the swept session finds NOTHING reusable.
        assert_eq!(pools.take(&s, &dst("203.0.113.70")), None);

        // the OTHER session is wholly untouched (teardown is session-partitioned).
        assert!(other_tunnel.is_live());
        assert_eq!(reg.live_handles(&other), 1);
        assert_eq!(pools.warm_count(&other), 1);
        assert_eq!(pools.take(&other, &dst("203.0.113.70")), Some(0x99));
    }

    #[test]
    fn revocation_sweep_at_severing_rung_drops_the_swept_sessions_pool_partition() {
        // doc 12 §8 + D53: a revocation at a block-or-higher rung severs the session's
        // matching tunnels (RevocationSweep over the SeveringRegistry) AND the pool
        // cleanup path drops the swept session's warm sockets, so none survives into a
        // later session's reuse. A sub-block (allow+log) revocation severs nothing and
        // — being non-severing — leaves the pool intact (the established-state
        // short-circuit, D53 non-severing rung).
        let reg = SeveringRegistry::new();
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let swept = session(50);
        let kept = session(51);

        let tunnel = FakeHandle::new();
        reg.register_tunnel(&swept, &dst("203.0.113.80"), Box::new(tunnel.clone()));
        pools.put(&swept, &dst("203.0.113.80"), 0x80);
        pools.put(&swept, &dst("203.0.113.81"), 0x81);
        // an unrelated session keeps its warm socket through the sweep.
        pools.put(&kept, &dst("203.0.113.80"), 0xAA);

        let sweep = RevocationSweep::new(&reg);
        let revoked = vec![RevokedAdmission {
            session: swept.clone(),
            dst_keys: vec![dst("203.0.113.80")],
            rung: Rung::BlockLog,
        }];
        let outcome = sweep.apply(&revoked);
        // The pool drop is the swept session's partition cleanup that rides the SAME
        // severing-rung decision (drop the whole session's warm sockets on a sweep at
        // block-or-higher; D68 expiry never reaches here).
        let pool_dropped: usize = if outcome.severing_revocations > 0 {
            pools.drop_session(&swept)
        } else {
            0
        };

        assert_eq!(outcome.entries_severed, 1, "the tunnel severed");
        assert_eq!(outcome.severing_revocations, 1);
        assert!(!tunnel.is_live());
        assert_eq!(
            pool_dropped, 2,
            "the swept session's whole pool partition dropped"
        );
        assert_eq!(pools.warm_count(&swept), 0);
        assert_eq!(pools.take(&swept, &dst("203.0.113.80")), None);
        // the unrelated session's pooled socket is untouched.
        assert_eq!(pools.warm_count(&kept), 1);
        assert_eq!(pools.take(&kept, &dst("203.0.113.80")), Some(0xAA));
    }

    #[test]
    fn sub_block_revocation_leaves_the_pool_partition_warm() {
        // D53 non-severing rung: an allow+log revocation severs no tunnel and drops no
        // pooled socket — the established connection (and its warm pool) survives.
        let reg = SeveringRegistry::new();
        let pools: SessionUpstreamPools<u64> = SessionUpstreamPools::new();
        let s = session(52);
        pools.put(&s, &dst("203.0.113.90"), 0x90);

        let sweep = RevocationSweep::new(&reg);
        let outcome = sweep.apply(&[RevokedAdmission {
            session: s.clone(),
            dst_keys: vec![dst("203.0.113.90")],
            rung: Rung::AllowLog,
        }]);
        let pool_dropped: usize = if outcome.severing_revocations > 0 {
            pools.drop_session(&s)
        } else {
            0
        };

        assert_eq!(outcome.severing_revocations, 0);
        assert_eq!(outcome.non_severing_revocations, 1);
        assert_eq!(pool_dropped, 0, "non-severing rung drops no pooled socket");
        assert_eq!(pools.warm_count(&s), 1, "the warm pool survives");
        assert_eq!(pools.take(&s, &dst("203.0.113.90")), Some(0x90));
    }
}
