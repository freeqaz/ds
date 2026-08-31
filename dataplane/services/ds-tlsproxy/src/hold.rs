//! ds-tlsproxy — the D46 pause/resume hold-and-buffer mechanics (doc 12 §12,
//! the §9 *Suspend hold/buffer* frozen-vs-free row; D46/D110/D53/D72).
//!
//! # What this is
//!
//! This is the proxy-side **consumer** of the D46 transparent-suspend
//! coordination marker (doc 12 §12). For the two tiers that make a transparency
//! claim — the **≤5-min fully-transparent** tier and the **5–15-min best-effort**
//! tier — `ds-tlsproxy` holds and buffers BOTH legs of a paused session and
//! resumes forwarding only **after the guest clock is resynced** (the frozen
//! invariant: *resume invisible ≤5 min*, doc 12 §9/§12; D46).
//!
//! The proxy owns the **socket physics** (doc 12 §12): hold the VM-facing and
//! upstream legs, buffer in-flight bytes, and release them in order once the
//! orchestrator signals the resync-complete edge. The orchestrator owns the
//! **trigger, the D46 tier, and the resume-with-resync edge** — those are
//! orchestrator facts a network-silent paused guest cannot reveal (a paused
//! guest is indistinguishable from an idle connection at the data plane, doc 12
//! §12), so they arrive as an explicit marker, never inferred here.
//!
//! # The consumed marker (doc 12 §12; PROPOSED, pending round-4 ratification)
//!
//! The marker rides the **`hostagent.v1` host-ward session-lifecycle channel**
//! (the D72-exempt class, same lane as the digest feed and D78 attendedness) as
//! the slot reserved at the one-shot M0 flip (D110) — *never* a `boundary.v1`
//! Stage-0 message (that package's direction is boundary → orchestrator, the
//! reverse of this marker), and `ds-tlsproxy` grows **no control-plane-inbound
//! endpoint** (D72). [`PauseMarker`] is the proxy-side shape of that slot.
//!
//! The marker shape (`{ session_ref, phase, tier, deadline, resume_with_clock_resync,
//! dedup_key }`) is a **PROPOSED default pending round-4 ratification** (the task
//! note), so it is modelled as a LOCAL in-crate type here rather than a frozen
//! `ds-contracts` shape — exactly as [`crate::Rung`] is kept local because
//! `ds-contracts`' API is frozen v1. When the marker's proto slot is firmed at
//! the post-Stage-0 versioned addition (D110, *before Stage 2*), the
//! `hostagent.v1` `SessionLifecycleUpdate` field decodes INTO this type; the
//! decode lives at the host-agent ingest seam, not here.
//!
//! # The three tiers (D46; doc 04 §6 D46 row, doc 06 (b) 60 s / 5 min / 15 min)
//!
//! - **≤5 min — fully transparent** ([`Tier::Transparent`]): hold + buffer both
//!   legs, resume on the clock-resync edge. No flow is abandoned; every buffered
//!   byte is released in order. This is the tier the frozen *resume invisible
//!   ≤5 min* invariant binds.
//! - **5–15 min — best-effort** ([`Tier::BestEffort`]): still consumes the
//!   marker and holds, but makes **no transparency guarantee** past the 5-min
//!   line — VM-leg socket-option tuning (`tcp_retries2` / `TCP_USER_TIMEOUT`,
//!   §9 FREE) keeps the VM-facing sockets alive longer, and which upstream flows
//!   are abandoned vs reconnected on resume is a per-flow policy ([`ResumePlan`],
//!   §9 FREE). The `HOLD_DEGRADE` phase room (doc 12 §12) is the marker's hook
//!   for the orchestrator to announce the transparent→best-effort crossing.
//! - **>15 min — snapshot + park** ([`Tier::Park`]): makes **no transparency
//!   claim** and **consumes no marker** (doc 12 §12). On the path to PARKED the
//!   session tears down via `flush_session(legs = all)` — the unconditional
//!   session-end shape, [`crate::SeveringRegistry::teardown_session`]. This
//!   module exposes [`park_teardown`] so the >15-min escalation reaches the same
//!   severing body the NFT-6 teardown does, with no marker and no hold.
//!
//! # Scope honesty (M0-host integration residual)
//!
//! What lands here: the framework-agnostic **hold registry**, the marker
//! ingest + dedup + state machine, the resume-only-after-resync invariant, and
//! the tier dispatch — all over a [`Holdable`] abstraction tested against fake
//! handles. What does NOT land here, and is M0-host integration work:
//!
//! - the real pingora wiring — pausing/resuming an actual live tunnel's
//!   downstream + upstream sockets and the upstream read-buffer at the
//!   listener/connect layer ([`Holdable`] is the seam; doc 12 §13.1 confines
//!   every pingora type to `accept/`/`connect/`, so this registry — being inward
//!   of that layer — stays framework-agnostic by construction);
//! - the **VM-leg socket-option tuning** itself (`tcp_retries2` /
//!   `TCP_USER_TIMEOUT`, upstream read-buffer sizing — §9 FREE): the numbers and
//!   the `setsockopt` calls land on the real socket in the listener layer; here
//!   [`Holdable::hold`] / [`Holdable::resume`] are synchronous calls on a fake
//!   handle and the *ordering / state* invariants are what is asserted;
//! - the **wall-clock resync** itself: the guest clock is resynced by the
//!   hypervisor/host agent (an orchestrator fact); this module consumes the
//!   `resume_with_clock_resync` edge, it does not perform the resync.
//!
//! # Frozen non-edge (doc 12 §4.2, D76)
//!
//! Like the severing registry, this module issues no conntrack/netlink syscall
//! and does not depend on `ds-nft`: holding a socket is pure userspace state, and
//! the park-tier teardown reaches conntrack only *through* the frozen
//! [`ds_contracts::flush::FlushSession`] contract the severing registry already
//! implements over userspace handles.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ds_contracts::session::SessionRef;

use crate::{FlushOutcome, SeveringRegistry};

/// The D46 pause tier the orchestrator assigned (doc 04 §6 D46 row; doc 12 §12).
///
/// The tier is an **orchestrator fact** carried on the marker — the proxy never
/// derives it (a network-silent paused guest cannot reveal it). The variant set
/// is a PROPOSED shape (pending round-4 ratification); it is additive-friendly
/// (a new tier would slot between the bands without renumbering the meaning).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// ≤5 min — **fully transparent**. Hold + buffer both legs; resume on the
    /// clock-resync edge. The tier the frozen *resume invisible ≤5 min*
    /// invariant binds (D46): no flow abandoned, every buffered byte released.
    Transparent,
    /// 5–15 min — **best-effort**. Still holds, but makes no transparency
    /// guarantee past 5 min: VM-leg socket tuning extends the VM-facing hold
    /// (§9 FREE) and upstream flows are abandoned-or-reconnected per
    /// [`ResumePlan`] (§9 FREE). The `HOLD_DEGRADE` phase announces the
    /// transparent→best-effort crossing.
    BestEffort,
    /// Over 15 min — **snapshot + park**. NO transparency claim and consumes NO
    /// marker (doc 12 §12): the session tears down via `flush_session(legs=all)`
    /// on the path to PARKED. Present here only so the tier band is total; a
    /// `Park` marker is never legally ingested ([`HoldRegistry::apply`] rejects
    /// it — the park path is [`park_teardown`], not a hold).
    Park,
}

impl Tier {
    /// Whether this tier makes the D46 transparency claim (≤5 min) — only
    /// [`Tier::Transparent`]. The best-effort tier holds but does not *guarantee*
    /// invisibility past the 5-min line; the park tier makes no claim at all.
    pub const fn is_transparent(self) -> bool {
        matches!(self, Tier::Transparent)
    }

    /// Whether this tier consumes the coordination marker at all. The park tier
    /// (>15 min) consumes **no** marker (doc 12 §12) — it escalates to
    /// snapshot+park via [`park_teardown`]; the other two hold-and-buffer.
    pub const fn consumes_marker(self) -> bool {
        !matches!(self, Tier::Park)
    }
}

/// The marker phase (doc 12 §12). The frozen marker carries
/// `phase ∈ {HOLD_BEGIN, RESUME_RESYNCED}` with **room for `HOLD_DEGRADE`** —
/// modelled here with the degrade phase present so the transparent→best-effort
/// crossing is expressible the day the orchestrator emits it.
///
/// PROPOSED (pending round-4 ratification); additive-only thereafter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// `HOLD_BEGIN` — begin holding + buffering both legs. The proxy stops
    /// forwarding in both directions and retains in-flight bytes; the VM-facing
    /// sockets are kept alive (the §9-FREE `tcp_retries2` / `TCP_USER_TIMEOUT`
    /// tuning) so a transparent resume can release them unbroken.
    HoldBegin,
    /// `HOLD_DEGRADE` — the transparent→best-effort crossing (the marker's
    /// reserved phase room). The hold continues, but the tier's transparency
    /// claim is dropped: the orchestrator has signalled the pause is now in the
    /// 5–15-min band. Upstream flows may be abandoned-or-reconnected on resume
    /// per the [`ResumePlan`] (§9 FREE).
    HoldDegrade,
    /// `RESUME_RESYNCED` — the resume edge, emitted **only after the guest clock
    /// is resynced** (the orchestrator fact). This is what releases the hold:
    /// the proxy resumes forwarding and drains the buffered bytes in order. The
    /// frozen invariant lives here — forwarding never resumes before this phase
    /// (doc 12 §12; D46).
    ResumeResynced,
}

/// A pause/resume coordination marker (doc 12 §12) — the proxy-side shape of the
/// `hostagent.v1` reserved slot (D110). PROPOSED, pending round-4 ratification.
///
/// Modelled local to ds-tlsproxy on purpose (the shape is not yet ratified and
/// `ds-contracts` is frozen v1): when the proto slot is firmed at the
/// post-Stage-0 versioned addition (D110, before Stage 2), the `hostagent.v1`
/// `SessionLifecycleUpdate` field decodes INTO this type at the host-agent
/// ingest seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PauseMarker {
    /// The session this marker governs — the never-recycled join-key quartet
    /// (the tap name is the authority, doc 14 §4). Both legs of THIS session's
    /// live tunnels are held / released; no other session is touched.
    pub session: SessionRef,
    /// The marker phase: begin-hold, degrade, or resume-after-resync.
    pub phase: Phase,
    /// The D46 tier the orchestrator assigned. A `HOLD_BEGIN`/`HOLD_DEGRADE`
    /// marker carries the hold tier ([`Tier::Transparent`] or
    /// [`Tier::BestEffort`]); a marker is never legally a [`Tier::Park`] (the
    /// park tier consumes no marker — doc 12 §12).
    pub tier: Tier,
    /// The tier deadline the orchestrator set, unix seconds — the moment the
    /// current tier's budget runs out (the 5-min line for transparent, the
    /// 15-min line for best-effort). Carried for the proxy's own
    /// hold-budget accounting; the orchestrator owns the escalation decision.
    pub deadline_unix_s: u64,
    /// Whether the resume edge is gated on the guest clock being resynced. On a
    /// `RESUME_RESYNCED` marker this is the frozen invariant's switch: forwarding
    /// resumes only when this is set true (the resync is complete). The
    /// orchestrator owns the resync edge; the proxy consumes it.
    pub resume_with_clock_resync: bool,
    /// The orchestrator-assigned idempotency key (doc 12 §12). A marker
    /// redelivered on the at-least-once host-ward channel carries the SAME
    /// `dedup_key`; the registry applies each `(session, dedup_key)` exactly once
    /// so a redelivered `HOLD_BEGIN` does not re-hold an already-held session and
    /// a redelivered `RESUME_RESYNCED` does not double-drain.
    pub dedup_key: u64,
}

/// What resume forwarding did to a session's upstream flows (the §9-FREE
/// abandon-vs-reconnect choice, recorded for the resume-event accounting).
///
/// Frozen above it: on the transparent tier no flow is abandoned (every buffered
/// byte is released in order, doc 12 §9). FREE: on the best-effort tier the
/// orchestrator's tier signal + the per-flow socket state decide which upstream
/// flows reconnect vs abandon — the proxy records the split, it does not freeze
/// the policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResumePlan {
    /// Upstream legs released and resumed in place (transparent: always this).
    pub reconnected: usize,
    /// Upstream legs abandoned on resume (best-effort only — never on the
    /// transparent tier, where this is always 0).
    pub abandoned: usize,
}

/// A thing the registry can hold and resume: the userspace abstraction over a
/// live tunnel's socket pair (both legs) under a D46 pause.
///
/// This is the **pingora wiring seam** (doc 12 §13.1), the hold/resume twin of
/// [`crate::Severable`]: production implements it over the real downstream +
/// upstream sockets (stop forwarding + buffer on `hold`; drain + resume on
/// `resume`) inside the listener/connect layer that owns the pingora types;
/// everything inward — including this registry — speaks only this trait, so no
/// framework type leaks in. Tests implement it over a fake handle.
///
/// Both methods are idempotent: holding an already-held handle, or resuming an
/// already-resumed one, is a no-op and returns `false` (nothing newly changed),
/// so a redelivered marker drives no second `setsockopt` / drain.
pub trait Holdable: Send + Sync {
    /// Hold this handle: stop forwarding on both legs and begin buffering
    /// in-flight bytes. Returns `true` iff this call transitioned the handle from
    /// forwarding to held (idempotent: a second `hold` returns `false`).
    fn hold(&self) -> bool;

    /// Resume this handle: drain the buffered bytes in order and resume
    /// forwarding on both legs. Returns `true` iff this call transitioned the
    /// handle from held back to forwarding (idempotent: a second `resume`, or a
    /// `resume` on a never-held handle, returns `false`).
    fn resume(&self) -> bool;

    /// Whether this handle is currently held (paused, buffering).
    fn is_held(&self) -> bool;
}

/// A monotonic per-registry handle id, so a session's tunnels are each held /
/// resumed (and counted) exactly once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct HandleId(u64);

/// One held-or-holdable tunnel: the userspace handle plus the session it belongs
/// to. A session may have several live tunnels (distinct dsts); all of them hold
/// and resume together under one marker.
struct Entry {
    /// The never-recycled tap name (doc 14 §4) — the registry partitions on it.
    tap_name: String,
    /// The holdable userspace handle (both legs of one tunnel).
    handle: Box<dyn Holdable>,
    /// Whether this entry is a **D77 ask-posture held connection** (registered via
    /// [`HoldRegistry::register_held_ask_connection`]) rather than a D46-pausable
    /// live tunnel. The two holds are INDEPENDENT: a D46 [`PauseMarker`]
    /// (`HOLD_BEGIN`/`RESUME_RESYNCED`) holds/resumes only the session's pausable
    /// tunnels and SKIPS ask-held connections (which resolve on their own grant /
    /// window via [`HoldRegistry::resolve_ask_hold`]), so a session-wide D46 resume
    /// never double-drives an ask-held connection's socket. Defaults to `false`
    /// (a D46 tunnel) for every [`register_tunnel`] entry.
    ask_held: bool,
}

/// Per-session hold bookkeeping: whether the session is currently held, and the
/// `(applied dedup_keys)` so a redelivered marker is applied at most once.
#[derive(Default)]
struct SessionHold {
    /// Whether this session is currently in a hold (HOLD_BEGIN/HOLD_DEGRADE seen,
    /// RESUME_RESYNCED not yet released).
    held: bool,
    /// The tier of the active hold (meaningful only while `held`).
    tier: Option<Tier>,
    /// Dedup keys already applied for this session — at-least-once delivery on
    /// the host-ward channel means a marker can arrive twice; each
    /// `(session, dedup_key)` is applied once (doc 12 §12).
    applied_dedup_keys: std::collections::BTreeSet<u64>,
}

/// Why a marker was not applied — the at-least-once / illegal-marker cases the
/// registry refuses, surfaced so the host-agent ingest seam can log them rather
/// than silently dropping (a redelivery is normal; an illegal marker is a bug).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldRejection {
    /// This `(session, dedup_key)` was already applied (at-least-once
    /// redelivery). Benign — the registry is idempotent; the seam logs and drops.
    DuplicateDedupKey,
    /// A `RESUME_RESYNCED` marker arrived with `resume_with_clock_resync = false`
    /// — the resync is NOT complete, so forwarding must NOT resume (the frozen
    /// invariant, doc 12 §12). The marker is refused; the hold persists.
    ResumeBeforeResync,
    /// A marker carried [`Tier::Park`]: the >15-min park tier consumes no marker
    /// (doc 12 §12). The escalation path is [`park_teardown`], not a hold. The
    /// marker is illegal and refused.
    ParkTierTakesNoMarker,
    /// A `RESUME_RESYNCED` for a session that is not currently held — nothing to
    /// resume. Benign (a redelivered resume after the drain already completed).
    NotHeld,
}

/// What applying a marker did, for the §12 resume/hold-event accounting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HoldOutcome {
    /// Tunnels newly held by this marker (HOLD_BEGIN) — 0 on a resume or a
    /// degrade-of-an-already-held session.
    pub held: usize,
    /// Tunnels newly resumed by this marker (RESUME_RESYNCED) — 0 on a hold.
    pub resumed: usize,
    /// The §9-FREE abandon-vs-reconnect split, populated on resume.
    pub resume_plan: ResumePlan,
}

/// The framework-agnostic D46 hold registry: live tunnels registered per session,
/// held and resumed under the [`PauseMarker`] coordination contract.
///
/// Interior-mutable behind a `Mutex` (like [`crate::SeveringRegistry`]) so the
/// listener/connect layer can register tunnels while the host-agent ingest thread
/// drives a marker. This is a registry of userspace socket state — no conntrack,
/// no netlink, no ds-nft (frozen non-edge, doc 12 §4.2).
#[derive(Default)]
pub struct HoldRegistry {
    inner: Mutex<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    next_id: u64,
    entries: BTreeMap<HandleId, Entry>,
    holds: BTreeMap<String, SessionHold>,
}

impl HoldRegistry {
    /// A fresh, empty registry.
    pub fn new() -> HoldRegistry {
        HoldRegistry {
            inner: Mutex::new(RegistryState::default()),
        }
    }

    /// Register a live tunnel (both legs) for `session`, so it participates in
    /// that session's D46 hold/resume. Returns the assigned handle id so the
    /// listener layer can drop a tunnel on its own normal-close lifecycle.
    ///
    /// If the session is *already held* when a tunnel is registered (a new
    /// connection accepted during a pause — rare but possible), the tunnel is
    /// held on registration so the hold stays whole. This preserves the
    /// invariant that no byte forwards while a session is held.
    pub fn register_tunnel(&self, session: &SessionRef, handle: Box<dyn Holdable>) -> u64 {
        let mut state = self.inner.lock().expect("hold registry mutex");
        let id = state.next_id;
        state.next_id += 1;
        let session_held = state
            .holds
            .get(&session.tap_name)
            .map(|h| h.held)
            .unwrap_or(false);
        if session_held {
            // A connection accepted mid-hold is held immediately: the hold must
            // stay whole (no byte forwards while the session is paused).
            handle.hold();
        }
        state.entries.insert(
            HandleId(id),
            Entry {
                tap_name: session.tap_name.clone(),
                handle,
                ask_held: false,
            },
        );
        id
    }

    /// Number of registered tunnels for a session (test/diagnostic helper). Counts
    /// BOTH D46-pausable tunnels and D77 ask-held connections for the session.
    pub fn tunnels(&self, session: &SessionRef) -> usize {
        let state = self.inner.lock().expect("hold registry mutex");
        state
            .entries
            .values()
            .filter(|e| e.tap_name == session.tap_name)
            .count()
    }

    /// Whether a session is currently held (paused, buffering).
    pub fn is_held(&self, session: &SessionRef) -> bool {
        let state = self.inner.lock().expect("hold registry mutex");
        state
            .holds
            .get(&session.tap_name)
            .map(|h| h.held)
            .unwrap_or(false)
    }

    /// Number of currently-held **D46-pausable** tunnels for a session
    /// (test/diagnostic helper). Counts only the marker-driven pausable tunnels —
    /// D77 ask-held connections (which hold/resume on their own grant/window, not on
    /// a [`PauseMarker`]) are excluded so the D46 hold accounting is unaffected by an
    /// ask-posture hold on the same session.
    pub fn held_tunnels(&self, session: &SessionRef) -> usize {
        let state = self.inner.lock().expect("hold registry mutex");
        state
            .entries
            .values()
            .filter(|e| e.tap_name == session.tap_name && !e.ask_held && e.handle.is_held())
            .count()
    }

    /// Apply a [`PauseMarker`] (doc 12 §12). Holds both legs of every live tunnel
    /// for the session on `HOLD_BEGIN`, records the degrade crossing on
    /// `HOLD_DEGRADE`, and resumes-and-drains on `RESUME_RESYNCED` — but a resume
    /// is honoured **only** when `resume_with_clock_resync` is set (the frozen
    /// *resume invisible ≤5 min* invariant: forwarding never resumes before the
    /// guest clock is resynced, doc 12 §12; D46).
    ///
    /// Idempotent per `(session, dedup_key)`: a redelivered marker on the
    /// at-least-once host-ward channel is applied at most once. A
    /// [`Tier::Park`] marker is illegal (the park tier consumes no marker — use
    /// [`park_teardown`]).
    pub fn apply(&self, marker: &PauseMarker) -> Result<HoldOutcome, HoldRejection> {
        // The park tier consumes NO marker (doc 12 §12) — refuse it outright,
        // before any dedup bookkeeping, so an illegal marker never mutates state.
        if marker.tier == Tier::Park {
            return Err(HoldRejection::ParkTierTakesNoMarker);
        }
        // A resume that is NOT clock-resynced must not release the hold (the
        // frozen invariant). Refuse before dedup so the resync-complete redelivery
        // (same dedup_key, resync now true) is still applied.
        if marker.phase == Phase::ResumeResynced && !marker.resume_with_clock_resync {
            return Err(HoldRejection::ResumeBeforeResync);
        }

        let mut state = self.inner.lock().expect("hold registry mutex");

        // At-least-once dedup: each (session, dedup_key) is applied once.
        let already = state
            .holds
            .get(&marker.session.tap_name)
            .map(|h| h.applied_dedup_keys.contains(&marker.dedup_key))
            .unwrap_or(false);
        if already {
            return Err(HoldRejection::DuplicateDedupKey);
        }

        match marker.phase {
            Phase::HoldBegin => Ok(Self::do_hold(&mut state, marker)),
            Phase::HoldDegrade => Ok(Self::do_degrade(&mut state, marker)),
            Phase::ResumeResynced => Self::do_resume(&mut state, marker),
        }
    }

    /// HOLD_BEGIN: hold both legs of every live tunnel for the session, mark the
    /// session held at the marker's tier, and record the dedup key.
    fn do_hold(state: &mut RegistryState, marker: &PauseMarker) -> HoldOutcome {
        let tap = &marker.session.tap_name;
        let mut held = 0;
        for entry in state.entries.values() {
            // D46 marker holds only the session's PAUSABLE tunnels — never a D77
            // ask-held connection (it holds/resumes on its own grant/window).
            if &entry.tap_name == tap && !entry.ask_held && entry.handle.hold() {
                held += 1;
            }
        }
        let h = state.holds.entry(tap.clone()).or_default();
        h.held = true;
        h.tier = Some(marker.tier);
        h.applied_dedup_keys.insert(marker.dedup_key);
        HoldOutcome {
            held,
            resumed: 0,
            resume_plan: ResumePlan::default(),
        }
    }

    /// HOLD_DEGRADE: the transparent→best-effort crossing. The hold persists; the
    /// tier is updated (its transparency claim dropped). No new tunnel is held
    /// (they already are) and none is resumed.
    fn do_degrade(state: &mut RegistryState, marker: &PauseMarker) -> HoldOutcome {
        let h = state
            .holds
            .entry(marker.session.tap_name.clone())
            .or_default();
        // A degrade only changes the tier of an active hold; if the session is
        // not held, degrade is a no-op tier note (defensive — the orchestrator
        // sequences begin→degrade→resume).
        if h.held {
            h.tier = Some(marker.tier);
        }
        h.applied_dedup_keys.insert(marker.dedup_key);
        HoldOutcome::default()
    }

    /// RESUME_RESYNCED: release the hold and drain. Caller already guaranteed
    /// `resume_with_clock_resync == true` (the frozen invariant). Resumes every
    /// held tunnel for the session, computes the §9-FREE abandon-vs-reconnect
    /// split per the tier, and clears the held flag.
    fn do_resume(
        state: &mut RegistryState,
        marker: &PauseMarker,
    ) -> Result<HoldOutcome, HoldRejection> {
        let tap = &marker.session.tap_name;
        let was_held = state.holds.get(tap).map(|h| h.held).unwrap_or(false);
        if !was_held {
            // Nothing to resume — a redelivered resume after the drain completed,
            // or a resume for a session that was never held. Benign; record the
            // dedup key so a third copy is a clean duplicate, not a re-resume.
            let h = state.holds.entry(tap.clone()).or_default();
            h.applied_dedup_keys.insert(marker.dedup_key);
            return Err(HoldRejection::NotHeld);
        }

        // The tier governs the abandon-vs-reconnect policy. On the transparent
        // tier NO flow is abandoned (every buffered byte released in order — the
        // frozen ≤5-min guarantee). On the best-effort tier the split is FREE;
        // the conservative default modelled here reconnects all and abandons none
        // (the build is licensed to abandon unsafe-to-replay upstream flows — §9
        // FREE — but the registry does not freeze that policy).
        let hold_tier = state
            .holds
            .get(tap)
            .and_then(|h| h.tier)
            .unwrap_or(marker.tier);

        let mut resumed = 0;
        for entry in state.entries.values() {
            // D46 marker resumes only the session's PAUSABLE tunnels — never a D77
            // ask-held connection (its resolution is the grant/window path, so a
            // session-wide resume must not double-drive its socket).
            if &entry.tap_name == tap && !entry.ask_held && entry.handle.resume() {
                resumed += 1;
            }
        }

        let resume_plan = ResumePlan {
            reconnected: resumed,
            abandoned: 0,
        };
        // Belt-and-suspenders: the transparent tier abandons nothing, by
        // construction above. (Documented so a future best-effort policy edit
        // touches only this arm.)
        debug_assert!(
            !hold_tier.is_transparent() || resume_plan.abandoned == 0,
            "the transparent tier abandons no flow (frozen ≤5-min guarantee)"
        );

        let h = state.holds.entry(tap.clone()).or_default();
        h.held = false;
        h.tier = None;
        h.applied_dedup_keys.insert(marker.dedup_key);

        Ok(HoldOutcome {
            held: 0,
            resumed,
            resume_plan,
        })
    }
}

/// The >15-min **park** path (doc 12 §12; D46): the park tier makes no
/// transparency claim and **consumes no marker** — on the path to PARKED the
/// session tears down via `flush_session(legs = all)`, the unconditional
/// session-end shape. This reaches the SAME severing body NFT-6 teardown does,
/// through the frozen [`ds_contracts::flush::FlushSession`] contract the
/// [`SeveringRegistry`] implements — so the >15-min escalation is *not* a hold
/// and grows no new mechanism.
///
/// Returns the flush outcome (severed-handle count) for the park-event
/// accounting (doc 14 §5). The caller (orchestrator-side park sequencer, via the
/// host agent) is responsible for the snapshot; this is the proxy's residual:
/// drop every live tunnel and pooled socket for the parked session.
pub fn park_teardown(registry: &SeveringRegistry, session: &SessionRef) -> FlushOutcome {
    // Identical to NFT-6 session-end teardown (legs = all, dst = all): the park
    // tier makes no transparency claim, so it tears down exactly like a normal
    // session end (doc 12 §12).
    registry.teardown_session(session)
}

// ─────────────────────────────────────────────────────────────────────────────
// D77 ask-posture socket-hold (docs/09 §5 TLS-1; docs/12 §12 attendedness / D78)
// ─────────────────────────────────────────────────────────────────────────────
//
// This is a DIFFERENT hold from the D46 pause/resume hold above. The D46 hold is
// orchestrator-driven (the [`PauseMarker`] coordination machinery) — it pauses a
// session's *live* tunnels and resumes them after a clock-resync. The D77
// ask-posture hold is *connection-admission*-driven: when the TLS-1 admission
// gate reaches a policy **Ask** verdict (an unknown-domain prompt posture) AND
// the session is **attended** (the D78 signal), the proxy ACCEPTS the TCP
// connection and **holds it open 30–60 s** while the human is notified async over
// the Stage-0 ask-user seam — the VM is never suspended for an unknown domain
// (docs/09 §5 TLS-1 D77). The held connection resolves on either:
//
//   - an injected session-scoped TTL'd **allow grant** on the policy stream → the
//     held connection PROCEEDS as a normal allow; or
//   - **window expiry** → the proxy CLOSES the held connection with a timeout
//     error, and the agent's next attempt succeeds once the grant has landed.
//
// UNATTENDED sessions downgrade to an IMMEDIATE refusal per D77 (no hold) — the
// caller ([`crate`]'s `tls1_gate`) owns that branch; this module only models the
// attended hold-and-resolve.
//
// The same socket physics the D46 hold owns are reused: an accepted-but-held
// ask-posture connection is registered on the [`HoldRegistry`] via
// [`HoldRegistry::register_held_ask_connection`] so it does NOT forward a byte
// while the prompt is outstanding, and it is released (resumed → proceed) or
// dropped (closed) at resolution. The D46 [`PauseMarker`] pause/resume path is
// untouched: the ask-posture connection is held under its OWN per-connection key
// and never participates in a `HOLD_BEGIN`/`RESUME_RESYNCED` marker.
//
// # Honest scope (the live transports are TODO(seam) hooks)
//
// What lands here is the framework-agnostic hold-and-resolve STATE MACHINE over
// an injected fake ask client + an injected fake grant source + a synthetic
// `now`/`window` clock. What does NOT land here, and is documented seam work:
//
//   - the LIVE attendedness signal (D78) is now CONSUMED off the in-process
//     [`AttendednessFeed`] (this module) via [`attendedness_verdict`], armed at the
//     listener behind `DS_ATTENDEDNESS_LIVE` — the freshness-budgeted, fail-closed
//     per-connection-verdict consume (docs/12 §12). At THIS registry layer the
//     hold-and-resolve state machine still takes a SYNTHETIC `attended: bool` the
//     caller passes at verdict time (it is framework-agnostic). The residual is the
//     out-of-crate WRITE side — the `hostagent.v1` wire decode that records facts
//     via [`AttendednessFeed::record`] at the host-agent ingest seam (modelled local
//     here exactly like [`PauseMarker`] while the slot is unfrozen).
//   - **`TODO(seam:grant-return)`** — the LIVE allow-grant return path. The
//     approval returns as a session-scoped TTL'd allow grant on the policy stream
//     (docs/09 §5). Here the grant arrives via an INJECTED fake grant source
//     ([`AskGrantSource`]); the live policy-stream transport is not built.
//   - the real pingora socket-hold itself (keeping the accepted downstream socket
//     open without forwarding, then splicing it to a freshly admitted upstream on
//     a grant) lands on the live [`Holdable`] at the listener layer (D40 confines
//     pingora to `main.rs`); this registry stays framework-agnostic by speaking
//     only [`Holdable`].

/// The minimal **ask-user request** the proxy fires when a TLS-1 admission reaches
/// the policy Ask posture in an attended session (docs/09 §5 TLS-1 D77; the Stage-0
/// ask-user seam, boundary → orchestrator).
///
/// **Convention-layer shape, not a frozen contract.** The `boundary.v1`
/// `AskUserRequest` Rust type does not exist yet (the LOG-1/ask mirror is not
/// frozen), so — exactly as [`PauseMarker`] is modelled local to this crate while
/// its `hostagent.v1` slot is unfrozen — this is an in-crate convention-layer
/// shape, NOT a `ds-contracts` type. When the `boundary.v1` ask message is frozen,
/// it decodes INTO / encodes FROM this shape at the boundary-egress seam; the
/// field set here is the proxy-side projection of what that message must carry.
///
/// Secret-free by construction (the §10 telemetry discipline): it carries the
/// session reference and the SNI domain the human is being asked about, never a
/// client byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AskUserRequest {
    /// The session whose attended human is being prompted (the never-recycled
    /// join-key quartet — the tap name is the authority, doc 14 §4).
    pub session: SessionRef,
    /// The SNI domain the Ask posture fired on — what the human is being asked to
    /// allow. The domain name only; never a client byte beyond the SNI value the
    /// admission gate already parsed.
    pub sni_domain: String,
}

/// The Stage-0 **ask-user seam** (boundary → orchestrator): fire an
/// [`AskUserRequest`] to notify the attended human, asynchronously, that an
/// unknown domain wants to connect (docs/09 §5 TLS-1 D77).
///
/// **This is a documented hook, not a wired cross-service call.** The real send is
/// owned by the boundary-egress / orchestrator ask-user path and reached over the
/// `boundary.v1` Stage-0 seam; this trait is where that wiring lands. A production
/// listener with the seam wired sends the request and the orchestrator prompts the
/// human; this prestage injects a [`RecordingFakeAskClient`] so the hold-and-resolve
/// state machine is testable with no live network. The trait is intentionally
/// fire-and-forget: the proxy does not BLOCK on the human (the human is notified
/// async); the *answer* returns out-of-band as a grant on the policy stream
/// ([`AskGrantSource`]), never as this call's return value.
pub trait AskClient: Send + Sync {
    /// Fire the ask-user request (async notification of the attended human). The
    /// proxy does not await the human's answer here — it returns immediately and
    /// the held connection then waits on the grant source / window. Returns `true`
    /// iff the notification was dispatched (the production seam may fail-soft to
    /// `false` if the ask channel is down; the caller still holds + times out).
    fn ask(&self, request: &AskUserRequest) -> bool;
}

/// A recording fake [`AskClient`] (test/seam-prestage): records every fired
/// [`AskUserRequest`] so a test can assert the human was notified exactly once with
/// the right session + SNI, and the connection was HELD (not refused) on the Ask.
///
/// This is the convention-layer stand-in for the unfrozen `boundary.v1` ask seam —
/// the same role the in-process fakes play for the OQ6 admission-map seam: it makes
/// the consumer mechanics testable NOW and is swapped for the live boundary-egress
/// send the instant the `boundary.v1` ask message is frozen (`TODO(seam:ask-user)`).
#[derive(Default)]
pub struct RecordingFakeAskClient {
    sent: Mutex<Vec<AskUserRequest>>,
    /// Whether `ask` reports a successful dispatch — a test can flip this to model
    /// the ask-channel-down fail-soft (the hold still runs and times out).
    dispatch_ok: bool,
}

impl RecordingFakeAskClient {
    /// A fake that reports successful dispatch on every `ask` (the common case).
    pub fn new() -> RecordingFakeAskClient {
        RecordingFakeAskClient {
            sent: Mutex::new(Vec::new()),
            dispatch_ok: true,
        }
    }

    /// A fake whose `ask` reports a FAILED dispatch (the ask channel is down). The
    /// hold still runs — the human cannot be notified, so the connection holds and
    /// then closes on window expiry (never silently proceeds).
    pub fn channel_down() -> RecordingFakeAskClient {
        RecordingFakeAskClient {
            sent: Mutex::new(Vec::new()),
            dispatch_ok: false,
        }
    }

    /// Every request fired so far (in order), for test assertions.
    pub fn fired(&self) -> Vec<AskUserRequest> {
        self.sent.lock().expect("ask client mutex").clone()
    }

    /// How many ask-user requests were fired.
    pub fn fired_count(&self) -> usize {
        self.sent.lock().expect("ask client mutex").len()
    }
}

impl AskClient for RecordingFakeAskClient {
    fn ask(&self, request: &AskUserRequest) -> bool {
        self.sent
            .lock()
            .expect("ask client mutex")
            .push(request.clone());
        self.dispatch_ok
    }
}

/// The **`boundary.v1` ask-user wire codec** — ds-tlsproxy's private, by-value mirror
/// of the frozen Stage-0 ask message (docs/09 §8: "a one-way `AskUserRequest`
/// notification boundary → orchestrator"). It encodes an [`AskUserRequest`] into a
/// versioned, length-prefixed frame body and back, exactly as the re-resolve seam
/// mirrors ds-dnsgate's frame by value — this crate is stdlib-only + `#![forbid(unsafe_code)]`,
/// so NO `prost`/proto edge enters it (D40/D67); the frozen `boundary.v1` message decodes
/// INTO / encodes FROM this shape at the boundary-egress seam, and until it is frozen this
/// by-value mirror IS the wire.
///
/// # The frame body (no length prefix; the transport adds the 4-byte-BE prefix)
///
/// ```text
///   byte 0        : version tag (VERSION == 1)
///   bytes 1..5    : tap_name length   (u32, big-endian)
///   bytes 5..     : tap_name          (UTF-8)
///   next 4 bytes  : sni_domain length (u32, big-endian)
///   then          : sni_domain        (UTF-8)
/// ```
///
/// # Secret-free by construction (docs/12 §10 telemetry discipline — load-bearing)
///
/// The frame carries ONLY the secret-free projection the ask-user seam is defined to
/// carry: the never-recycled **tap name** (the session's authoritative join key, doc 14 §4)
/// and the **SNI domain** the human is being asked about. It NEVER carries the raw
/// [`SessionRef::session_uuid`](ds_contracts::session::SessionRef) (the global session
/// identity is not needed to prompt the attended human — the orchestrator re-keys the tap
/// name to the session), nor any client byte beyond the already-parsed SNI value. The
/// version tag makes future additive fields a versioned, non-breaking change.
pub struct AskUserWire;

impl AskUserWire {
    /// The frame version tag — bumped only on a breaking wire change (additive fields
    /// slot in behind an existing version; a decoder rejects an unknown version).
    pub const VERSION: u8 = 1;

    /// The hard cap on a single frame body — a `tap_name` is ≤15 chars (IFNAMSIZ,
    /// doc 14 §4) and an SNI domain ≤255, so any real frame is tiny; the cap bounds a
    /// hostile/garbage length so a decoder never allocates unboundedly. Matches the
    /// re-resolve / validate frame-cap convention.
    pub const MAX_FRAME_BODY: u32 = 64 * 1024;

    /// Encode an [`AskUserRequest`] into the versioned frame body (no length prefix —
    /// the transport prepends the 4-byte-BE frame length). Encodes ONLY the secret-free
    /// projection (`session.tap_name` + `sni_domain`); the raw `session_uuid` is never
    /// touched, so it can never leak onto the wire.
    pub fn encode(request: &AskUserRequest) -> Vec<u8> {
        let tap = request.session.tap_name.as_bytes();
        let sni = request.sni_domain.as_bytes();
        let mut out = Vec::with_capacity(1 + 4 + tap.len() + 4 + sni.len());
        out.push(Self::VERSION);
        out.extend_from_slice(&(tap.len() as u32).to_be_bytes());
        out.extend_from_slice(tap);
        out.extend_from_slice(&(sni.len() as u32).to_be_bytes());
        out.extend_from_slice(sni);
        out
    }

    /// Decode a frame body back into an [`AskUserRequest`], or `None` on any structural
    /// mismatch (unknown version, truncation, over-cap length, trailing bytes, or
    /// non-UTF-8). The decoded [`SessionRef`] carries the tap name (the authority) and
    /// empty placeholders for the fields the secret-free projection deliberately omits —
    /// the wire never carried them, so a decode cannot reconstruct a `session_uuid`.
    ///
    /// This is the by-value counterpart the frozen `boundary.v1` message decodes AS; it
    /// exists so the round-trip is testable in-crate (the send is fire-and-forget, so
    /// production never decodes locally — the orchestrator does).
    pub fn decode(body: &[u8]) -> Option<AskUserRequest> {
        let (&version, mut cur) = body.split_first()?;
        if version != Self::VERSION {
            return None;
        }
        let tap = Self::take_str(&mut cur)?;
        let sni = Self::take_str(&mut cur)?;
        if !cur.is_empty() {
            return None;
        }
        Some(AskUserRequest {
            session: SessionRef {
                session_uuid: String::new(),
                host_id: String::new(),
                host_session_index: 0,
                tap_name: tap,
            },
            sni_domain: sni,
        })
    }

    /// Take one 4-byte-BE-length-prefixed UTF-8 string off the cursor, advancing it.
    /// `None` on truncation, over-cap length, or non-UTF-8.
    fn take_str(cur: &mut &[u8]) -> Option<String> {
        if cur.len() < 4 {
            return None;
        }
        let (head, tail) = cur.split_at(4);
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        if len > Self::MAX_FRAME_BODY || (tail.len() as u64) < len as u64 {
            return None;
        }
        let (bytes, rest) = tail.split_at(len as usize);
        *cur = rest;
        String::from_utf8(bytes.to_vec()).ok()
    }
}

/// A session-scoped TTL'd **allow grant** — the approval the human's "yes" returns
/// as, on the policy stream (docs/09 §5 TLS-1 D77). A held ask-posture connection
/// PROCEEDS as a normal allow when a grant for its `(session, sni_domain)` lands
/// before the hold window expires.
///
/// **Convention-layer shape.** Like [`AskUserRequest`], the grant's frozen
/// policy-stream message does not exist yet; this is the proxy-side projection of
/// what the grant carries — the session, the domain it allows, and the TTL
/// (the grant is session-scoped and time-bounded, never a permanent allow).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowGrant {
    /// The session the grant is scoped to (never crosses to another session).
    pub session: SessionRef,
    /// The SNI domain the grant allows — must match the held connection's domain.
    pub sni_domain: String,
    /// The grant's expiry (unix seconds): the grant is a TTL'd allow, not a
    /// permanent one. A held connection proceeds only on a grant that is still
    /// live at resolution time (`expires_at_unix_s > now_unix_s`).
    pub expires_at_unix_s: u64,
}

/// The injected **grant-return seam** (`TODO(seam:grant-return)`): the policy-stream
/// source a held ask-posture connection polls for its session-scoped TTL'd
/// [`AllowGrant`] (docs/09 §5 — "the allow grant arrives on the policy stream").
///
/// **This is a documented hook, not a wired transport.** The LIVE grant arrives on
/// the orchestrator's policy stream after the human approves; this trait is where
/// that subscription lands at M0-host integration. This prestage injects a
/// [`FakeGrantSource`] so the approval path is testable with no live policy stream.
/// A production listener subscribes to the policy stream and resolves the hold the
/// instant a matching grant arrives; this prestage models the "grant present at
/// resolution" vs "no grant" split synchronously.
pub trait AskGrantSource: Send + Sync {
    /// The live allow grant for `(session, sni_domain)`, or `None` if no grant has
    /// landed yet (the human has not approved within the window). Returning `None`
    /// is the FAIL-CLOSED default — no grant means no proceed.
    fn grant_for(&self, session: &SessionRef, sni_domain: &str) -> Option<AllowGrant>;
}

/// A fake [`AskGrantSource`] (test/seam-prestage): holds an optional pre-seeded
/// grant. `empty()` models "no approval landed" (→ the hold times out);
/// `with_grant(..)` models "the human approved" (→ the hold proceeds).
#[derive(Default)]
pub struct FakeGrantSource {
    grant: Option<AllowGrant>,
}

impl FakeGrantSource {
    /// A source with NO grant — the human has not (yet) approved; the hold will
    /// reach window expiry and close (fail-closed: no grant => no proceed).
    pub fn empty() -> FakeGrantSource {
        FakeGrantSource { grant: None }
    }

    /// A source pre-seeded with `grant` — the human approved; a held connection for
    /// the grant's `(session, sni_domain)` proceeds (if the grant is still live).
    pub fn with_grant(grant: AllowGrant) -> FakeGrantSource {
        FakeGrantSource { grant: Some(grant) }
    }
}

impl AskGrantSource for FakeGrantSource {
    fn grant_for(&self, session: &SessionRef, sni_domain: &str) -> Option<AllowGrant> {
        // Session-scoped + domain-scoped: a grant only resolves the held connection
        // it was issued for (a grant for session A / domain X never proceeds a hold
        // for session B or domain Y).
        self.grant.as_ref().and_then(|g| {
            if g.session.tap_name == session.tap_name && g.sni_domain == sni_domain {
                Some(g.clone())
            } else {
                None
            }
        })
    }
}

/// The live in-process **grant-return feed** — the consumer cache between the
/// (out-of-crate, unfrozen) orchestrator policy-stream ingest and the
/// per-connection ask-hold resolution (docs/09 §5 TLS-1: "once the human approves,
/// the policy stream delivers a session-scoped allow grant"). This is the LIVE
/// [`AskGrantSource`] the listener subscribes to, replacing the empty
/// [`FakeGrantSource`] that always timed a held ask-posture connection out.
///
/// It plays the EXACT role [`AttendednessFeed`] plays for the D78 attendedness
/// signal: the policy-stream ingest seam decodes a session-scoped TTL-allow grant
/// and records it here via [`GrantReturnFeed::record`] (the WRITE side, OUT of this
/// crate until the grant message is frozen — modelled local here exactly like
/// [`PauseMarker`] / [`AttendednessFact`]); the listener reads it via the
/// [`AskGrantSource`] impl through [`HoldRegistry::resolve_ask_hold`] and the async
/// window await (`main.rs`'s `run_ask_posture_hold`). It awaits the window
/// ASYNCHRONOUSLY — the listener polls this feed across the 30–60 s window and
/// resolves the instant a matching grant lands, rather than blocking on a single
/// synchronous deadline.
///
/// Interior-mutable behind a `Mutex` (like [`HoldRegistry`] / [`AttendednessFeed`])
/// so the policy-stream ingest thread can record grants while the listeners poll
/// them, and shared across both listeners by `Arc`. Keyed on the
/// `(tap_name, sni_domain)` pair the grant is scoped to.
///
/// # FAIL-CLOSED (load-bearing — the whole point of the grant-return consume)
///
/// Empty until a grant is recorded — an empty feed returns `None` for every
/// `(session, sni_domain)` (the byte-identical fail-closed default that keeps a
/// disarmed listener path identical to the pre-grant-return empty stub: no grant ⇒
/// no proceed ⇒ the held connection closes on window expiry). The resolution-time
/// expiry check (`expires_at_unix_s > now`) lives in [`HoldRegistry::resolve_ask_hold`],
/// so a recorded-but-expired grant still fails closed exactly like an absent one.
///
/// **Monotonic record (fail-closed against at-least-once reordering).** The
/// policy stream is at-least-once and may reorder; [`record`](Self::record) keeps,
/// per `(session, sni_domain)`, only the grant with the GREATEST `expires_at_unix_s`,
/// so a redelivered or reordered SHORTER-lived grant can never shrink an already-
/// recorded longer window (which could otherwise prematurely fail an in-flight hold
/// closed — a spurious-timeout hole). A strictly-longer grant supersedes (a renewal).
#[derive(Default)]
pub struct GrantReturnFeed {
    inner: Mutex<BTreeMap<(String, String), AllowGrant>>,
}

impl GrantReturnFeed {
    /// A fresh, empty feed (every `(session, sni_domain)` reads "no grant" until one
    /// is recorded — the fail-closed default: absent ⇒ no proceed ⇒ timeout close).
    pub fn new() -> GrantReturnFeed {
        GrantReturnFeed {
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record a session-scoped TTL-allow grant for its `(session, sni_domain)` (the
    /// WRITE side the orchestrator policy-stream ingest seam calls when the human
    /// approves). Keyed by the never-recycled tap name + the granted SNI domain.
    /// Monotonic by `expires_at_unix_s`: a SHORTER-or-equal-lived redelivery is
    /// DROPPED, so reordered at-least-once delivery never shrinks a newer (longer)
    /// grant window. Returns `true` iff the grant was stored (it was strictly the
    /// longest-lived seen for its pair).
    pub fn record(&self, grant: AllowGrant) -> bool {
        let key = (grant.session.tap_name.clone(), grant.sni_domain.clone());
        let mut map = self.inner.lock().expect("grant-return feed mutex");
        match map.get(&key) {
            // A strictly-longer-lived grant supersedes (a renewal); a shorter/equal
            // redelivery is ignored (it would only ever shrink the live window).
            Some(existing) if existing.expires_at_unix_s >= grant.expires_at_unix_s => false,
            _ => {
                map.insert(key, grant);
                true
            }
        }
    }

    /// Number of recorded `(session, sni_domain)` grants (test/diagnostic helper).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("grant-return feed mutex").len()
    }

    /// Whether the feed has no recorded grants (every hold reads "no grant").
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .expect("grant-return feed mutex")
            .is_empty()
    }
}

impl AskGrantSource for GrantReturnFeed {
    fn grant_for(&self, session: &SessionRef, sni_domain: &str) -> Option<AllowGrant> {
        // Session-scoped + domain-scoped lookup, keyed exactly like the grant was
        // recorded. A grant for another (session, domain) is never returned (the
        // grant is scoped to the held connection it was issued for). The TTL-expiry
        // check is the caller's (`resolve_ask_hold`): a recorded-but-expired grant
        // still fails closed there.
        self.inner
            .lock()
            .expect("grant-return feed mutex")
            .get(&(session.tap_name.clone(), sni_domain.to_string()))
            .cloned()
    }
}

/// How a D77 ask-posture socket-hold resolved (docs/09 §5 TLS-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AskHoldResolution {
    /// A session-scoped TTL'd allow grant landed within the window: the held
    /// connection PROCEEDS as a normal allow (the listener resumes it and opens
    /// the upstream).
    Proceed,
    /// The hold window (30–60 s) expired with no grant: the proxy CLOSES the held
    /// connection with a timeout error. The agent's next attempt succeeds once the
    /// grant lands (docs/09 §5). This is the FAIL-CLOSED outcome — a held
    /// connection NEVER proceeds without a real grant.
    ClosedOnTimeout,
}

impl AskHoldResolution {
    /// Whether this resolution PROCEEDS the held connection (only [`Proceed`]). A
    /// timeout never proceeds — the load-bearing fail-closed invariant.
    pub const fn proceeds(self) -> bool {
        matches!(self, AskHoldResolution::Proceed)
    }
}

/// The minimum D77 hold window (docs/09 §5: "holds it open 30–60 s"). The orchestrator
/// owns the exact deadline; this is the proxy-side floor for the documented band.
pub const ASK_HOLD_MIN_SECONDS: u64 = 30;
/// The maximum D77 hold window (docs/09 §5: "holds it open 30–60 s").
pub const ASK_HOLD_MAX_SECONDS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// The real pingora-downstream [`Holdable`] (doc 12 §13.1; the M0-host integration)
// ─────────────────────────────────────────────────────────────────────────────
//
// The D77 ask-posture hold above (`register_held_ask_connection` / `resolve_ask_hold`)
// tracks a held connection and resolves it on grant/deny. It speaks ONLY the
// framework-agnostic [`Holdable`] trait; the *placeholder* the listener has been
// registering (`InertAskHold` in main.rs) owns no real socket, so the accepted
// downstream is not physically held — the connection is only registry-tracked.
//
// [`SocketHoldable`] is the REAL Holdable this seam has been reserved for: it owns a
// close-capable handle to the accepted **downstream** socket (the pingora `Stream`,
// D40-confined to main.rs — so the pingora type is adapted to the framework-agnostic
// [`DownstreamCloser`] trait at the listener, and this registry stays pingora-free).
// It realizes the doc 12 §13.1 physical hold:
//
//   - `hold()`   — SUSPEND the accepted downstream: it is registered held and no
//                  byte is forwarded while the prompt is outstanding (the listener's
//                  control flow already opens no upstream during the await; the held
//                  handle is the socket-owning half of that suspend).
//   - `resume()` — RELEASE the downstream back to the listener so it can be spliced
//                  to a freshly admitted upstream (the grant/PROCEED leg). Resuming
//                  MARKS the socket handed-off, so the close-on-drop below no longer
//                  fires — the splice owns the socket from here.
//   - drop while still HELD (never resumed = the deny / window-expiry leg) — CLOSE
//                  the downstream: the timeout `ClosedOnTimeout` in `resolve_ask_hold`
//                  drops the registry [`Entry`] still-held, and that drop shuts the
//                  downstream socket down (the physical fail-closed close, doc 12 §13.5).
//                  Closing happens EXACTLY once, and NEVER after a `resume()`.
//
// This mirrors the flow's own `return None` on timeout (which drops the pingora
// `Stream`) — but now the *registry-tracked handle itself* owns and closes the
// socket, so the hold-and-resolve state machine physically holds and closes the
// downstream rather than tracking an inert flag. `register_held_ask_connection` /
// `resolve_ask_hold` are UNCHANGED: swapping `InertAskHold` for `SocketHoldable` is
// a Box construction at the listener, no state-machine change (the D110 PauseMarker
// pause/resume path is likewise untouched — an ask-held entry is skipped by D46
// markers exactly as before).

/// The framework-agnostic **close half** of an accepted downstream socket — the
/// pingora-`Stream`-adapting seam a real [`SocketHoldable`] closes on the fail-closed
/// (deny / window-expiry) leg (doc 12 §13.1; D40 confines the pingora type to the
/// listener, so the adapter lives there and this registry names only this trait).
///
/// It is a synchronous, idempotent shutdown of the downstream: closing an already-closed
/// downstream is a no-op. The production adapter (main.rs) shuts down the pingora
/// downstream write half; a test adapter records the close so the physical hold/close
/// can be exercised against a synthetic socket with no live pingora `Stream`.
pub trait DownstreamCloser: Send + Sync {
    /// Close the accepted downstream socket (shut the write half). Idempotent: a
    /// second `close` is a no-op. Called at most once by [`SocketHoldable`] — on the
    /// drop-while-held fail-closed leg only, never after a `resume`.
    fn close(&self);
}

/// The REAL pingora-downstream [`Holdable`] (doc 12 §13.1): owns a [`DownstreamCloser`]
/// handle to the accepted downstream socket and physically holds it while an ask-posture
/// prompt is outstanding, releasing it to the listener on a grant (resume) or closing it
/// on the deny / window-expiry leg (drop while held).
///
/// State machine (both transitions idempotent, like every [`Holdable`]):
///
/// | state       | `hold()`          | `resume()`         | drop           |
/// |-------------|-------------------|--------------------|----------------|
/// | forwarding  | → held (`true`)   | no-op (`false`)    | no close       |
/// | held        | no-op (`false`)   | → released (`true`)| **close once** |
/// | released    | no-op (`false`)   | no-op (`false`)    | no close       |
///
/// The single load-bearing invariant: the downstream is closed **iff** it is dropped
/// while still `held` (never forwarded, never resumed) — the fail-closed timeout leg.
/// A `resume()` moves it to `released` (the listener now owns the socket for the splice),
/// so a subsequent drop closes NOTHING. This is what makes the grant leg PROCEED (the
/// socket survives to be spliced) and the deny/timeout leg ERROR (the socket is closed).
pub struct SocketHoldable {
    /// The downstream close-half; `None` once released or closed (consumed exactly once
    /// so a resumed handle can never later close, and a closed one never double-closes).
    closer: Mutex<SocketHoldState>,
}

/// The `SocketHoldable` interior state — the closer plus whether the handle is held,
/// behind the one mutex so a concurrent hold/resume/drop cannot race a close.
struct SocketHoldState {
    /// The downstream close-half, taken (`None`) once the socket is released to the
    /// splice (`resume`) or closed (drop-while-held). While `Some`, the handle still
    /// owns the socket's close.
    closer: Option<Box<dyn DownstreamCloser>>,
    /// Whether the downstream is currently held (suspended, forwarding nothing).
    held: bool,
}

impl SocketHoldable {
    /// Wrap an accepted downstream close-half as a real ask-posture [`Holdable`]. Starts
    /// in the `forwarding` state; the registry's `register_held_ask_connection` calls
    /// `hold()` immediately, so the connection is suspended the moment it is registered.
    pub fn new(closer: Box<dyn DownstreamCloser>) -> SocketHoldable {
        SocketHoldable {
            closer: Mutex::new(SocketHoldState {
                closer: Some(closer),
                held: false,
            }),
        }
    }
}

impl Holdable for SocketHoldable {
    fn hold(&self) -> bool {
        let mut state = self.closer.lock().expect("socket-hold mutex");
        // Suspend the downstream: no byte forwarded while held. Idempotent — a second
        // hold on an already-held (or already-released) handle is a no-op. A released
        // handle (closer taken) can never be re-held (its socket is gone).
        if state.held || state.closer.is_none() {
            return false;
        }
        state.held = true;
        true
    }

    fn resume(&self) -> bool {
        let mut state = self.closer.lock().expect("socket-hold mutex");
        // Release the downstream back to the listener for the splice (the grant leg).
        // Idempotent — resuming a not-held handle is a no-op and closes nothing. TAKE
        // the closer so the drop-while-held close can never fire after a resume: the
        // splice now owns the socket, so it must survive the handle's drop.
        if !state.held {
            return false;
        }
        state.held = false;
        state.closer = None;
        true
    }

    fn is_held(&self) -> bool {
        self.closer.lock().expect("socket-hold mutex").held
    }
}

impl Drop for SocketHoldable {
    fn drop(&mut self) {
        // The fail-closed physical close: if this handle is dropped while STILL held
        // (never resumed = the deny / window-expiry leg, `resolve_ask_hold`'s
        // `ClosedOnTimeout` path `drop`s the entry still-held), close the downstream
        // exactly once. A resumed handle already took the closer (`None`), so the
        // splice-owned socket survives; a never-held / already-closed handle closes
        // nothing. `Mutex::get_mut` avoids a poison-panic in Drop.
        let state = self
            .closer
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.held {
            if let Some(closer) = state.closer.take() {
                closer.close();
            }
        }
    }
}

impl HoldRegistry {
    /// Register an accepted-but-held **ask-posture** connection on the registry
    /// (the D77 socket-hold, docs/09 §5 TLS-1) and immediately hold it so it does
    /// NOT forward a byte while the human is being prompted. Returns the handle id
    /// so the listener can drop the connection at resolution (resume → proceed, or
    /// close → drop).
    ///
    /// This reuses the SAME [`Holdable`] socket physics the D46 pause/resume hold
    /// owns, but the connection is held under its own per-connection key and never
    /// participates in a [`PauseMarker`]: a `HOLD_BEGIN`/`RESUME_RESYNCED` marker
    /// for the session resumes the session's D46-paused tunnels, NOT this
    /// admission-held connection (the two holds are independent, by construction —
    /// the ask hold is keyed on the returned handle id, the D46 hold on the
    /// per-session marker). Registering does not touch `holds` (the D46 per-session
    /// hold bookkeeping), so the [`PauseMarker`] path is untouched.
    pub fn register_held_ask_connection(
        &self,
        session: &SessionRef,
        handle: Box<dyn Holdable>,
    ) -> u64 {
        // Hold immediately on registration: the accepted connection must not
        // forward while the prompt is outstanding (the D77 "accept and hold open"
        // shape — the VM keeps running, the connection waits).
        handle.hold();
        let mut state = self.inner.lock().expect("hold registry mutex");
        let id = state.next_id;
        state.next_id += 1;
        state.entries.insert(
            HandleId(id),
            Entry {
                tap_name: session.tap_name.clone(),
                handle,
                // A D77 ask-held connection: the D46 PauseMarker iterations skip it,
                // so a session-wide pause/resume never touches its socket.
                ask_held: true,
            },
        );
        id
    }

    /// Resolve a held ask-posture connection (the handle id from
    /// [`register_held_ask_connection`]) at window-resolution time: PROCEED if a
    /// live session-scoped allow grant has landed, else CLOSE on timeout.
    ///
    /// FAIL-CLOSED (load-bearing): the connection PROCEEDS only on a real grant that
    /// (a) matches its `(session, sni_domain)` AND (b) is still live at `now`
    /// (`grant.expires_at_unix_s > now_unix_s`). No grant, or an expired grant, →
    /// [`AskHoldResolution::ClosedOnTimeout`] and the held connection is DROPPED
    /// (severed from the registry, never resumed). A timeout NEVER silently
    /// proceeds.
    ///
    /// On PROCEED the held handle is resumed (the listener opens the upstream and
    /// splices); on timeout the handle is dropped held (the listener closes the
    /// socket). Either way the entry is removed from the registry (the connection's
    /// lifecycle ends at resolution).
    pub fn resolve_ask_hold(
        &self,
        handle_id: u64,
        session: &SessionRef,
        sni_domain: &str,
        grants: &dyn AskGrantSource,
        now_unix_s: u64,
    ) -> AskHoldResolution {
        // A live, matching grant → PROCEED. Anything else (no grant, expired grant)
        // → fail closed to a timeout close.
        let proceed = grants
            .grant_for(session, sni_domain)
            .is_some_and(|g| g.expires_at_unix_s > now_unix_s);

        let mut state = self.inner.lock().expect("hold registry mutex");
        let entry = state.entries.remove(&HandleId(handle_id));
        if proceed {
            // Resume the held handle: the listener resumes forwarding / opens the
            // upstream and the connection proceeds as a normal allow.
            if let Some(entry) = entry {
                entry.handle.resume();
            }
            AskHoldResolution::Proceed
        } else {
            // Window expired with no live grant: DROP the held handle (the listener
            // closes the socket with a timeout error). It is never resumed — the
            // fail-closed boundary. The entry is removed; the held handle is
            // dropped still-held so the close is unambiguous.
            drop(entry);
            AskHoldResolution::ClosedOnTimeout
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// D78 attendedness signal (docs/12 §12; doc 15 §5.5; doc 16 §8; D78 recent-activity)
// ─────────────────────────────────────────────────────────────────────────────
//
// The D77 ask-posture hold above runs ONLY in an **attended** session — the D78
// signal. Attendedness is a session-lifecycle-class fact the orchestrator computes
// (doc 15 §5.5: recent-activity over the session's input channel; D78
// recent-activity semantics) and pushes host-ward over the `hostagent.v1`
// session-lifecycle channel — the SAME D72-exempt lane the digest feed and the
// [`PauseMarker`] ride (doc 12 §12). The proxy CONSUMES it at
// per-connection-verdict time (docs/12 §12, READ-ONLY); it never derives it (a
// data-plane proxy cannot see whether a human is present — that is an orchestrator
// fact a network-silent session cannot reveal).
//
// Like [`PauseMarker`], the wire shape is a PROPOSED `hostagent.v1` slot pending
// the round-4 freeze, so the fact is modelled as a LOCAL convention-layer type
// ([`AttendednessFact`]) rather than a frozen `ds-contracts` message. When the
// `hostagent.v1` `SessionLifecycleUpdate` attendedness field is firmed (D78, before
// Stage 2) it decodes INTO this type at the host-agent ingest seam (OUT of this
// crate, exactly like the [`PauseMarker`] decode), which records it via
// [`AttendednessFeed::record`]; the listener reads the freshness-budgeted verdict
// via [`attendedness_verdict`].
//
// # FAIL-CLOSED (load-bearing — the whole point of the D78 consume)
//
// The verdict treats **absent** and **stale** attendedness as UNATTENDED, so a
// policy *Ask* in such a session refuses IMMEDIATELY (D77, no hold) rather than
// holding a connection no present human will answer:
//
//   - no fact recorded for the session            → UNATTENDED;
//   - a fact past its freshness budget (stale)     → UNATTENDED;
//   - a fact whose `attended` flag is false        → UNATTENDED;
//   - a fact for a DIFFERENT session               → UNATTENDED;
//   - ONLY a fresh fact with `attended == true`    → ATTENDED.
//
// The freshness budget rides each fact (the orchestrator owns it, doc 12 §12: the
// signal is "freshness-budgeted"), bounded above by
// [`MAX_ATTENDEDNESS_FRESHNESS_BUDGET_S`] so a runaway/hostile budget can never keep
// a long-idle recent-activity signal "attended" indefinitely (a proxy-side safety
// bound, not a frozen value).

/// The proxy-side cap on a single attendedness fact's freshness budget (seconds).
/// The orchestrator owns the per-fact budget, but the proxy bounds it so an absurd
/// or hostile budget can never defeat staleness: past this bound a fact is treated
/// as STALE regardless of its stated budget (fail-closed). Set to the doc 06 (b)
/// transparent-pause band (5 min) — an attendedness/recent-activity signal older
/// than that window is stale here. A proxy-side safety bound, NOT a frozen contract
/// value (no D-number).
pub const MAX_ATTENDEDNESS_FRESHNESS_BUDGET_S: u64 = 300;

/// The proxy-side shape of the `hostagent.v1` attendedness slot (D78) — a
/// convention-layer type modelled local to this crate exactly like [`PauseMarker`]
/// while the slot is unfrozen. The host-agent ingest seam decodes the frozen
/// `SessionLifecycleUpdate` attendedness field INTO this on the Stage-2 freeze;
/// until then a synthetic fact is recorded by tests (and, once the transport lands,
/// by the live ingest) via [`AttendednessFeed::record`].
///
/// Secret-free by construction (the §10 telemetry discipline): it carries the
/// session reference, a boolean, and two integers — never a client byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttendednessFact {
    /// The session this fact is computed for (the never-recycled join-key quartet;
    /// the tap name is the authority, doc 14 §4). A fact only ever resolves the
    /// attendedness of ITS session — never another's.
    pub session: SessionRef,
    /// Whether the orchestrator computed the session as **attended** — a human was
    /// recently active on the session's input channel (doc 15 §5.5; D78
    /// recent-activity). `false` is an explicit UNATTENDED.
    pub attended: bool,
    /// When the orchestrator computed this fact (unix seconds). The freshness budget
    /// is measured from here.
    pub computed_at_unix_s: u64,
    /// The orchestrator-stated freshness budget in seconds (doc 12 §12: the signal
    /// is freshness-budgeted). The fact is FRESH while
    /// `now - computed_at <= min(budget, MAX_ATTENDEDNESS_FRESHNESS_BUDGET_S)`; past
    /// that it is STALE and reads UNATTENDED (fail-closed).
    pub freshness_budget_s: u64,
}

impl AttendednessFact {
    /// Whether this fact is still FRESH at `now_unix_s` — within its (capped)
    /// freshness budget. The age is `now.saturating_sub(computed_at)`, so a fact
    /// from the future (benign clock skew, `now < computed_at`) has age 0 and is
    /// fresh; a fact older than its budget is stale. The effective budget is capped
    /// by [`MAX_ATTENDEDNESS_FRESHNESS_BUDGET_S`] so an absurd orchestrator budget
    /// cannot defeat staleness.
    pub fn is_fresh(&self, now_unix_s: u64) -> bool {
        let age = now_unix_s.saturating_sub(self.computed_at_unix_s);
        age <= self
            .freshness_budget_s
            .min(MAX_ATTENDEDNESS_FRESHNESS_BUDGET_S)
    }

    /// The fail-closed attendedness verdict of THIS fact at `now_unix_s`: ATTENDED
    /// iff it is both flagged `attended` AND still fresh. A stale-but-attended fact
    /// reads UNATTENDED (the load-bearing fail-closed property).
    pub fn is_attended_fresh(&self, now_unix_s: u64) -> bool {
        self.attended && self.is_fresh(now_unix_s)
    }
}

/// The attendedness READ seam — the source the listener polls at
/// per-connection-verdict time for a session's latest [`AttendednessFact`]. Returns
/// `None` when no fact has been pushed for the session yet (the FAIL-CLOSED default:
/// absent ⇒ UNATTENDED). Implemented by [`AttendednessFeed`] (the live in-process
/// consumer cache); tests drive it by recording synthetic facts.
pub trait AttendednessSource: Send + Sync {
    /// The latest attendedness fact recorded for `session`, or `None` if none has
    /// landed (absent ⇒ UNATTENDED, fail-closed).
    fn attendedness_for(&self, session: &SessionRef) -> Option<AttendednessFact>;
}

/// The single fail-closed attendedness verdict the listener consults at
/// per-connection-verdict time (docs/12 §12; D78). ATTENDED iff `source` has a fact
/// for `session` that is (a) for THIS session, (b) flagged `attended`, and (c) still
/// fresh at `now_unix_s`. Absent, stale, cross-session, or unattended ⇒ UNATTENDED.
///
/// This is the ONE place the attendedness fail-closed decision lives, so the
/// listener's `acquire_attendedness` (and any future consumer) cannot drift from the
/// absent/stale ⇒ UNATTENDED rule.
pub fn attendedness_verdict(
    source: &dyn AttendednessSource,
    session: &SessionRef,
    now_unix_s: u64,
) -> bool {
    source.attendedness_for(session).is_some_and(|fact| {
        // Belt-and-suspenders: the source keys by session, but a cross-session fact
        // must never attend another session.
        fact.session.tap_name == session.tap_name && fact.is_attended_fresh(now_unix_s)
    })
}

/// The live in-process **attendedness feed** — the consumer cache between the
/// (out-of-crate, unfrozen) `hostagent.v1` session-lifecycle ingest and the
/// per-connection attendedness verdict. The host-agent ingest seam decodes a
/// `SessionLifecycleUpdate` attendedness field and records the latest fact here via
/// [`AttendednessFeed::record`]; the listener reads it via [`attendedness_verdict`].
///
/// Interior-mutable behind a `Mutex` (like [`HoldRegistry`]) so the host-agent
/// ingest thread can record facts while the listener reads them, and shared across
/// both listeners by `Arc`. Empty until a fact is recorded — an empty feed reads
/// UNATTENDED for every session (the byte-identical fail-closed default that keeps
/// the disarmed listener path identical to the pre-D78 stub).
///
/// **Monotonic record (fail-closed against at-least-once reordering).** The
/// host-ward channel is at-least-once and may reorder; [`record`](Self::record)
/// keeps only the fact with the GREATEST `computed_at_unix_s`, so a redelivered or
/// reordered OLDER fact can never clobber a newer one (which could otherwise flip a
/// freshly-unattended session back to a stale "attended" read — a fail-OPEN hole).
#[derive(Default)]
pub struct AttendednessFeed {
    inner: Mutex<BTreeMap<String, AttendednessFact>>,
}

impl AttendednessFeed {
    /// A fresh, empty feed (every session reads UNATTENDED until a fact is recorded).
    pub fn new() -> AttendednessFeed {
        AttendednessFeed {
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record the latest attendedness fact for its session (the WRITE side the
    /// `hostagent.v1` ingest seam calls). Keyed by the never-recycled tap name.
    /// Monotonic by `computed_at_unix_s`: an OLDER or equal-aged redelivery is
    /// DROPPED, so reordered at-least-once delivery never replaces a newer fact with
    /// a staler one. Returns `true` iff the fact was stored (it was strictly the
    /// newest seen for its session).
    pub fn record(&self, fact: AttendednessFact) -> bool {
        let mut map = self.inner.lock().expect("attendedness feed mutex");
        match map.get(&fact.session.tap_name) {
            // A strictly-newer fact supersedes; an older/equal redelivery is ignored.
            Some(existing) if existing.computed_at_unix_s >= fact.computed_at_unix_s => false,
            _ => {
                map.insert(fact.session.tap_name.clone(), fact);
                true
            }
        }
    }

    /// Number of sessions with a recorded fact (test/diagnostic helper).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("attendedness feed mutex").len()
    }

    /// Whether the feed has no recorded facts (every session reads UNATTENDED).
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .expect("attendedness feed mutex")
            .is_empty()
    }
}

impl AttendednessSource for AttendednessFeed {
    fn attendedness_for(&self, session: &SessionRef) -> Option<AttendednessFact> {
        self.inner
            .lock()
            .expect("attendedness feed mutex")
            .get(&session.tap_name)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severable;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A fake holdable handle: a held flag plus hold/resume call counters, so
    /// tests assert both the right transitions AND that hold()/resume() fire at
    /// most once per transition (idempotence / no double-drive of `setsockopt`).
    struct FakeTunnel {
        held: AtomicBool,
        hold_calls: AtomicUsize,
        resume_calls: AtomicUsize,
    }

    impl FakeTunnel {
        fn new() -> Arc<FakeTunnel> {
            Arc::new(FakeTunnel {
                held: AtomicBool::new(false),
                hold_calls: AtomicUsize::new(0),
                resume_calls: AtomicUsize::new(0),
            })
        }
        fn hold_calls(&self) -> usize {
            self.hold_calls.load(Ordering::SeqCst)
        }
        fn resume_calls(&self) -> usize {
            self.resume_calls.load(Ordering::SeqCst)
        }
    }

    impl Holdable for FakeTunnel {
        fn hold(&self) -> bool {
            self.hold_calls.fetch_add(1, Ordering::SeqCst);
            // false → true transition returns true; an already-held handle no-ops.
            !self.held.swap(true, Ordering::SeqCst)
        }
        fn resume(&self) -> bool {
            self.resume_calls.fetch_add(1, Ordering::SeqCst);
            // true → false transition returns true; a not-held handle no-ops.
            self.held.swap(false, Ordering::SeqCst)
        }
        fn is_held(&self) -> bool {
            self.held.load(Ordering::SeqCst)
        }
    }

    impl Holdable for Arc<FakeTunnel> {
        fn hold(&self) -> bool {
            (**self).hold()
        }
        fn resume(&self) -> bool {
            (**self).resume()
        }
        fn is_held(&self) -> bool {
            (**self).is_held()
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

    fn hold_begin(s: &SessionRef, tier: Tier, dedup: u64) -> PauseMarker {
        PauseMarker {
            session: s.clone(),
            phase: Phase::HoldBegin,
            tier,
            deadline_unix_s: 1_000,
            resume_with_clock_resync: false,
            dedup_key: dedup,
        }
    }

    fn resume(s: &SessionRef, tier: Tier, resynced: bool, dedup: u64) -> PauseMarker {
        PauseMarker {
            session: s.clone(),
            phase: Phase::ResumeResynced,
            tier,
            deadline_unix_s: 1_000,
            resume_with_clock_resync: resynced,
            dedup_key: dedup,
        }
    }

    // ---- the four mandated tier/invariant tests --------------------------

    #[test]
    fn transparent_tier_holds_both_legs_and_resumes_after_resync_invisible() {
        // The ≤5-min fully-transparent tier: HOLD_BEGIN holds both legs of every
        // tunnel; RESUME_RESYNCED (with the clock resynced) releases and drains.
        // Asserts the doc 06 (b) 60 s / 5 min invisibility shape at the registry.
        let reg = HoldRegistry::new();
        let s = session(7);
        let t1 = FakeTunnel::new();
        let t2 = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(t1.clone()));
        reg.register_tunnel(&s, Box::new(t2.clone()));

        // HOLD_BEGIN: both tunnels held; nothing forwards.
        let out = reg
            .apply(&hold_begin(&s, Tier::Transparent, 1))
            .expect("hold begin");
        assert_eq!(out.held, 2);
        assert!(reg.is_held(&s));
        assert_eq!(reg.held_tunnels(&s), 2);
        assert!(t1.is_held() && t2.is_held());

        // RESUME_RESYNCED, clock resynced: both resume; nothing abandoned (the
        // frozen ≤5-min guarantee). The drain releases every buffered byte.
        let out = reg
            .apply(&resume(&s, Tier::Transparent, true, 2))
            .expect("resume resynced");
        assert_eq!(out.resumed, 2);
        assert_eq!(out.resume_plan.reconnected, 2);
        assert_eq!(out.resume_plan.abandoned, 0); // transparent abandons nothing
        assert!(!reg.is_held(&s));
        assert!(!t1.is_held() && !t2.is_held());

        // each socket transition fired exactly once.
        assert_eq!(t1.hold_calls(), 1);
        assert_eq!(t1.resume_calls(), 1);
        assert_eq!(t2.hold_calls(), 1);
        assert_eq!(t2.resume_calls(), 1);
    }

    #[test]
    fn resume_before_clock_resync_is_refused_hold_persists() {
        // The frozen invariant (doc 12 §12; D46): forwarding NEVER resumes before
        // the guest clock is resynced. A RESUME_RESYNCED with resync=false is
        // refused and the hold persists; the later resync-complete redelivery
        // (same session, resync=true) then releases it.
        let reg = HoldRegistry::new();
        let s = session(3);
        let t = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(t.clone()));
        reg.apply(&hold_begin(&s, Tier::Transparent, 1))
            .expect("hold");

        // resume WITHOUT resync: refused, hold persists, no resume() fired.
        let err = reg
            .apply(&resume(&s, Tier::Transparent, false, 2))
            .unwrap_err();
        assert_eq!(err, HoldRejection::ResumeBeforeResync);
        assert!(reg.is_held(&s));
        assert!(t.is_held());
        assert_eq!(t.resume_calls(), 0);

        // resync-complete edge (a new dedup_key): NOW it releases.
        let out = reg
            .apply(&resume(&s, Tier::Transparent, true, 3))
            .expect("resume resynced");
        assert_eq!(out.resumed, 1);
        assert!(!reg.is_held(&s));
        assert!(!t.is_held());
        assert_eq!(t.resume_calls(), 1);
    }

    #[test]
    fn best_effort_tier_degrade_crossing_holds_and_resumes() {
        // The 5–15-min best-effort tier: HOLD_BEGIN at transparent, then a
        // HOLD_DEGRADE crossing into best-effort (the marker's phase room), then
        // resume. The hold stays whole across the crossing.
        let reg = HoldRegistry::new();
        let s = session(5);
        let t = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(t.clone()));

        reg.apply(&hold_begin(&s, Tier::Transparent, 1))
            .expect("hold begin transparent");
        assert!(t.is_held());

        // HOLD_DEGRADE: transparent → best-effort. Hold persists; no new socket
        // transition (already held).
        let degrade = PauseMarker {
            session: s.clone(),
            phase: Phase::HoldDegrade,
            tier: Tier::BestEffort,
            deadline_unix_s: 2_000,
            resume_with_clock_resync: false,
            dedup_key: 2,
        };
        let out = reg.apply(&degrade).expect("degrade");
        assert_eq!(out.held, 0);
        assert_eq!(out.resumed, 0);
        assert!(reg.is_held(&s));
        assert!(t.is_held());
        assert_eq!(t.hold_calls(), 1); // not re-held

        // resume (best-effort, resynced) releases.
        let out = reg
            .apply(&resume(&s, Tier::BestEffort, true, 3))
            .expect("resume best-effort");
        assert_eq!(out.resumed, 1);
        assert!(!reg.is_held(&s));
    }

    #[test]
    fn park_tier_takes_no_marker_and_tears_down_via_flush_legs_all() {
        // The >15-min park tier consumes NO marker (doc 12 §12): a Park marker is
        // illegal, and the escalation is flush_session(legs=all) via the severing
        // registry — the same body NFT-6 teardown uses.
        let reg = HoldRegistry::new();
        let s = session(9);
        let t = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(t.clone()));

        // a Park marker is refused (illegal — the park tier takes no marker).
        let park_marker = PauseMarker {
            session: s.clone(),
            phase: Phase::HoldBegin,
            tier: Tier::Park,
            deadline_unix_s: 3_000,
            resume_with_clock_resync: false,
            dedup_key: 1,
        };
        assert_eq!(
            reg.apply(&park_marker).unwrap_err(),
            HoldRejection::ParkTierTakesNoMarker
        );
        // refused before any state mutation: the session is NOT held.
        assert!(!reg.is_held(&s));
        assert_eq!(t.hold_calls(), 0);

        // the park path is flush_session(legs=all) via the severing registry.
        let sev = SeveringRegistry::new();
        let tunnel = FakeSeverable::new();
        sev.register_tunnel(
            &s,
            &ds_contracts::flush::DstKey("203.0.113.10".into()),
            Box::new(tunnel.clone()),
        );
        let out = park_teardown(&sev, &s);
        assert_eq!(out.entries_flushed, 1);
        assert!(!tunnel.is_live());
    }

    /// A minimal fake [`crate::Severable`], so the park-tier test can drive the
    /// severing registry's `flush_session(legs=all)` without reaching into the
    /// lib.rs `tests` module. Mirrors that module's `FakeHandle`.
    struct FakeSeverable {
        live: AtomicBool,
    }

    impl FakeSeverable {
        fn new() -> Arc<FakeSeverable> {
            Arc::new(FakeSeverable {
                live: AtomicBool::new(true),
            })
        }
    }

    impl crate::Severable for Arc<FakeSeverable> {
        fn sever(&self) -> bool {
            self.live.swap(false, Ordering::SeqCst)
        }
        fn is_live(&self) -> bool {
            self.live.load(Ordering::SeqCst)
        }
    }

    // ---- supporting discipline tests -------------------------------------

    #[test]
    fn tier_predicates_classify_the_three_bands() {
        assert!(Tier::Transparent.is_transparent());
        assert!(!Tier::BestEffort.is_transparent());
        assert!(!Tier::Park.is_transparent());

        assert!(Tier::Transparent.consumes_marker());
        assert!(Tier::BestEffort.consumes_marker());
        assert!(!Tier::Park.consumes_marker()); // >15 min takes no marker
    }

    #[test]
    fn redelivered_marker_is_applied_at_most_once() {
        // At-least-once host-ward delivery: a redelivered HOLD_BEGIN (same
        // dedup_key) does not re-hold; a redelivered RESUME does not double-drain.
        let reg = HoldRegistry::new();
        let s = session(2);
        let t = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(t.clone()));

        let begin = hold_begin(&s, Tier::Transparent, 100);
        assert_eq!(reg.apply(&begin).expect("first hold").held, 1);
        // exact same marker again → duplicate, no second hold().
        assert_eq!(
            reg.apply(&begin).unwrap_err(),
            HoldRejection::DuplicateDedupKey
        );
        assert_eq!(t.hold_calls(), 1);

        let res = resume(&s, Tier::Transparent, true, 101);
        assert_eq!(reg.apply(&res).expect("first resume").resumed, 1);
        // redelivered resume → duplicate dedup_key, no second resume().
        assert_eq!(
            reg.apply(&res).unwrap_err(),
            HoldRejection::DuplicateDedupKey
        );
        assert_eq!(t.resume_calls(), 1);
    }

    #[test]
    fn resume_of_an_unheld_session_is_a_benign_noop() {
        let reg = HoldRegistry::new();
        let s = session(4);
        let t = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(t.clone()));
        // never held → a resync'd resume finds nothing to resume.
        let err = reg
            .apply(&resume(&s, Tier::Transparent, true, 1))
            .unwrap_err();
        assert_eq!(err, HoldRejection::NotHeld);
        assert!(!reg.is_held(&s));
        assert_eq!(t.resume_calls(), 0);
    }

    #[test]
    fn hold_is_session_partitioned_other_sessions_untouched() {
        let reg = HoldRegistry::new();
        let s = session(6);
        let other = session(8);
        let mine = FakeTunnel::new();
        let theirs = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(mine.clone()));
        reg.register_tunnel(&other, Box::new(theirs.clone()));

        reg.apply(&hold_begin(&s, Tier::Transparent, 1))
            .expect("hold");
        assert!(mine.is_held());
        assert!(!theirs.is_held()); // the other session is untouched
        assert!(!reg.is_held(&other));
    }

    #[test]
    fn tunnel_accepted_mid_hold_is_held_on_registration() {
        // A connection accepted DURING a pause must not forward: it is held on
        // registration so the hold stays whole.
        let reg = HoldRegistry::new();
        let s = session(11);
        let first = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(first.clone()));
        reg.apply(&hold_begin(&s, Tier::Transparent, 1))
            .expect("hold");
        assert!(first.is_held());

        // a NEW tunnel registered mid-hold is held immediately.
        let late = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(late.clone()));
        assert!(late.is_held());
        assert_eq!(reg.held_tunnels(&s), 2);

        // resume releases both, including the late arrival.
        reg.apply(&resume(&s, Tier::Transparent, true, 2))
            .expect("resume");
        assert!(!first.is_held());
        assert!(!late.is_held());
    }

    // ---- D77 ask-posture socket-hold tests -------------------------------
    //
    // docs/09 §5 TLS-1 (D77): in an ATTENDED session a policy Ask verdict holds the
    // accepted connection open 30–60 s while the human is notified async, and
    // resolves on (i) an injected TTL-allow grant → PROCEED, or (ii) window expiry
    // → CLOSE with a timeout error. UNATTENDED → immediate refuse (the caller's
    // branch, exercised in main.rs). Loopback/synthetic only: a fake ask client +
    // a fake grant source + a synthetic `now`. The D78 attendedness + the
    // grant-return are TODO(seam) hooks; here attendedness is the caller's bool and
    // the grant arrives via the injected FakeGrantSource.

    fn ask_request(s: &SessionRef, domain: &str) -> AskUserRequest {
        AskUserRequest {
            session: s.clone(),
            sni_domain: domain.to_string(),
        }
    }

    fn live_grant(s: &SessionRef, domain: &str, expires_at: u64) -> AllowGrant {
        AllowGrant {
            session: s.clone(),
            sni_domain: domain.to_string(),
            expires_at_unix_s: expires_at,
        }
    }

    // ---- the boundary.v1 ask-user wire codec (AskUserWire) ----------------

    #[test]
    fn ask_user_wire_round_trips_the_secret_free_projection() {
        // Encode → decode reproduces exactly the two secret-free fields the frame
        // carries: the tap name (the authority) and the SNI domain. Everything the
        // projection omits (session_uuid / host_id / index) decodes to the empty
        // placeholder — the wire never carried them.
        let s = session(9);
        let req = ask_request(&s, "unknown.example");
        let body = AskUserWire::encode(&req);
        let decoded = AskUserWire::decode(&body).expect("well-formed frame decodes");
        assert_eq!(decoded.session.tap_name, "dstap-9");
        assert_eq!(decoded.sni_domain, "unknown.example");
        // The projection is tap-name-only: the round trip cannot reconstruct the uuid.
        assert!(
            decoded.session.session_uuid.is_empty(),
            "the secret-free projection carries no session_uuid on the wire"
        );
    }

    #[test]
    fn ask_user_wire_frame_never_contains_the_raw_uuid() {
        // The load-bearing secret-free property (docs/12 §10): the encoded frame bytes
        // MUST NOT contain the raw session_uuid — only the tap name + SNI domain. Uses a
        // session whose uuid is a distinctive, searchable string absent from tap/SNI.
        let s = SessionRef::new(
            "SECRET-UUID-DEADBEEF-DO-NOT-EGRESS".into(),
            "host-a".into(),
            9,
            "dstap-9".into(),
        );
        let req = ask_request(&s, "unknown.example");
        let body = AskUserWire::encode(&req);
        // The uuid string must appear NOWHERE in the frame bytes (needle-in-haystack).
        assert!(
            !contains_subslice(&body, b"SECRET-UUID-DEADBEEF-DO-NOT-EGRESS"),
            "the raw session_uuid must never appear in the ask-user frame"
        );
        // But the fields the projection DOES carry are present.
        assert!(contains_subslice(&body, b"dstap-9"));
        assert!(contains_subslice(&body, b"unknown.example"));
        // And the version tag leads the frame.
        assert_eq!(body.first().copied(), Some(AskUserWire::VERSION));
    }

    #[test]
    fn ask_user_wire_rejects_malformed_frames() {
        // Every structural fault decodes to None (a decoder never trusts a bad frame):
        // empty, unknown version, truncated length, truncated body, trailing bytes.
        assert!(AskUserWire::decode(&[]).is_none(), "empty body");
        assert!(
            AskUserWire::decode(&[AskUserWire::VERSION.wrapping_add(1), 0, 0, 0, 0]).is_none(),
            "unknown version"
        );
        assert!(
            AskUserWire::decode(&[AskUserWire::VERSION, 0, 0, 0]).is_none(),
            "truncated tap-name length prefix"
        );
        // version + tap len=4 but only 2 bytes of tap follow → truncated body.
        assert!(
            AskUserWire::decode(&[AskUserWire::VERSION, 0, 0, 0, 4, b'a', b'b']).is_none(),
            "truncated tap-name body"
        );
        // A well-formed frame with one trailing junk byte is rejected.
        let s = session(3);
        let mut body = AskUserWire::encode(&ask_request(&s, "x.example"));
        body.push(0xFF);
        assert!(
            AskUserWire::decode(&body).is_none(),
            "trailing bytes after the frame are rejected"
        );
    }

    /// Naive substring search over bytes (test-only) — proves a needle is / isn't in the
    /// encoded frame without pulling in a dependency.
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn attended_ask_resolves_proceed_on_an_injected_ttl_allow_grant() {
        // The APPROVAL path (docs/09 §5): an attended Ask → hold → an injected
        // session-scoped TTL-allow grant lands within the window → the held
        // connection PROCEEDS as a normal allow (resumed). Asserts the ask-user
        // request was fired exactly once and the held connection was resumed.
        let reg = HoldRegistry::new();
        let s = session(7);
        let ask = RecordingFakeAskClient::new();

        // Accept-and-hold: the connection is held on registration (does not forward
        // while the prompt is outstanding).
        let conn = FakeTunnel::new();
        let id = reg.register_held_ask_connection(&s, Box::new(conn.clone()));
        assert!(
            conn.is_held(),
            "accepted ask connection is held, not forwarding"
        );

        // Fire the async ask-user notification (boundary → orchestrator).
        assert!(ask.ask(&ask_request(&s, "unknown.example")));
        assert_eq!(ask.fired_count(), 1, "the human is notified exactly once");
        assert_eq!(ask.fired()[0].sni_domain, "unknown.example");
        assert_eq!(ask.fired()[0].session.tap_name, s.tap_name);

        // The human approves: a live TTL-allow grant lands on the (fake) policy
        // stream. Resolve at now=500, grant live until 1000 → PROCEED.
        let grants = FakeGrantSource::with_grant(live_grant(&s, "unknown.example", 1_000));
        let outcome = reg.resolve_ask_hold(id, &s, "unknown.example", &grants, 500);
        assert_eq!(outcome, AskHoldResolution::Proceed);
        assert!(outcome.proceeds());

        // The held connection was RESUMED (proceeds as a normal allow) and removed
        // from the registry.
        assert!(
            !conn.is_held(),
            "an approved ask connection resumes (proceeds)"
        );
        assert_eq!(conn.resume_calls(), 1);
        assert_eq!(
            reg.tunnels(&s),
            0,
            "the resolved connection leaves the registry"
        );
    }

    #[test]
    fn attended_ask_closes_on_window_expiry_with_no_grant() {
        // The TIMEOUT path (docs/09 §5): an attended Ask → hold → the 30–60 s window
        // expires with NO grant → the proxy CLOSES the held connection with a
        // timeout error (it never proceeds). FAIL-CLOSED: no grant => no proceed.
        let reg = HoldRegistry::new();
        let s = session(3);
        let ask = RecordingFakeAskClient::new();

        let conn = FakeTunnel::new();
        let id = reg.register_held_ask_connection(&s, Box::new(conn.clone()));
        assert!(conn.is_held());
        assert!(ask.ask(&ask_request(&s, "unknown.example")));

        // No approval landed (empty grant source). Window expiry → CLOSE on timeout.
        let grants = FakeGrantSource::empty();
        let outcome = reg.resolve_ask_hold(id, &s, "unknown.example", &grants, 500);
        assert_eq!(outcome, AskHoldResolution::ClosedOnTimeout);
        assert!(
            !outcome.proceeds(),
            "a timeout NEVER proceeds (fail-closed)"
        );

        // The held connection was DROPPED (never resumed) — closed with the timeout
        // error — and removed from the registry. The next attempt succeeds once a
        // grant lands.
        assert_eq!(
            conn.resume_calls(),
            0,
            "a timed-out connection is never resumed"
        );
        assert_eq!(
            reg.tunnels(&s),
            0,
            "the closed connection leaves the registry"
        );
    }

    #[test]
    fn ask_hold_fail_closed_on_expired_grant() {
        // A grant that has itself EXPIRED at resolution time does NOT proceed: the
        // grant is a TTL-allow, and a held connection proceeds only on a grant still
        // live at `now`. An expired grant fails closed to a timeout close — never a
        // silent proceed.
        let reg = HoldRegistry::new();
        let s = session(4);
        let conn = FakeTunnel::new();
        let id = reg.register_held_ask_connection(&s, Box::new(conn.clone()));

        // grant expired at 1000; resolve at now=1000 (NOT strictly after) and at
        // now=2000 (well past) — both fail closed (`expires_at > now` is required).
        let grants = FakeGrantSource::with_grant(live_grant(&s, "unknown.example", 1_000));
        let at_expiry = reg.resolve_ask_hold(id, &s, "unknown.example", &grants, 1_000);
        assert_eq!(
            at_expiry,
            AskHoldResolution::ClosedOnTimeout,
            "a grant at its exact expiry instant does not proceed (fail-closed)"
        );
        assert_eq!(conn.resume_calls(), 0);
    }

    #[test]
    fn ask_grant_is_session_and_domain_scoped() {
        // FAIL-CLOSED scoping: a grant for session A / domain X never proceeds a
        // held connection for a different session or a different domain. The grant
        // is session-scoped + domain-scoped by construction.
        let reg = HoldRegistry::new();
        let a = session(6);
        let b = session(8);

        // a grant for session A / "x.example".
        let grant = live_grant(&a, "x.example", 10_000);
        let grants = FakeGrantSource::with_grant(grant);

        // a held connection for session B / "x.example" does NOT proceed (wrong
        // session): the grant source returns None for B.
        let conn_b = FakeTunnel::new();
        let id_b = reg.register_held_ask_connection(&b, Box::new(conn_b.clone()));
        let out_b = reg.resolve_ask_hold(id_b, &b, "x.example", &grants, 100);
        assert_eq!(out_b, AskHoldResolution::ClosedOnTimeout);
        assert_eq!(conn_b.resume_calls(), 0);

        // a held connection for session A / "y.example" does NOT proceed (wrong
        // domain).
        let conn_a_y = FakeTunnel::new();
        let id_a_y = reg.register_held_ask_connection(&a, Box::new(conn_a_y.clone()));
        let out_a_y = reg.resolve_ask_hold(id_a_y, &a, "y.example", &grants, 100);
        assert_eq!(out_a_y, AskHoldResolution::ClosedOnTimeout);
        assert_eq!(conn_a_y.resume_calls(), 0);

        // the held connection for session A / "x.example" (the grant's own pair)
        // DOES proceed.
        let conn_a_x = FakeTunnel::new();
        let id_a_x = reg.register_held_ask_connection(&a, Box::new(conn_a_x.clone()));
        let out_a_x = reg.resolve_ask_hold(id_a_x, &a, "x.example", &grants, 100);
        assert_eq!(out_a_x, AskHoldResolution::Proceed);
        assert_eq!(conn_a_x.resume_calls(), 1);
    }

    #[test]
    fn ask_channel_down_still_holds_and_times_out() {
        // The ask channel being down (the fake reports a failed dispatch) does NOT
        // weaken the boundary: the connection still holds and, with no grant, closes
        // on timeout. The human just is not notified — never a silent proceed.
        let reg = HoldRegistry::new();
        let s = session(5);
        let ask = RecordingFakeAskClient::channel_down();

        let conn = FakeTunnel::new();
        let id = reg.register_held_ask_connection(&s, Box::new(conn.clone()));
        assert!(conn.is_held());
        assert!(
            !ask.ask(&ask_request(&s, "unknown.example")),
            "dispatch failed"
        );
        // the request was still recorded (the seam attempted to fire it).
        assert_eq!(ask.fired_count(), 1);

        let grants = FakeGrantSource::empty();
        let outcome = reg.resolve_ask_hold(id, &s, "unknown.example", &grants, 500);
        assert_eq!(outcome, AskHoldResolution::ClosedOnTimeout);
        assert_eq!(conn.resume_calls(), 0);
    }

    #[test]
    fn ask_hold_does_not_disturb_the_d46_pause_resume_path() {
        // The D77 ask hold and the D46 pause/resume hold coexist on the SAME session
        // without interfering: an ask-held connection is keyed on its handle id and
        // never participates in a PauseMarker, and a HOLD_BEGIN/RESUME_RESYNCED
        // marker resumes the session's D46-paused tunnels, NOT the ask connection.
        let reg = HoldRegistry::new();
        let s = session(11);

        // A D46-pausable live tunnel for the session.
        let tunnel = FakeTunnel::new();
        reg.register_tunnel(&s, Box::new(tunnel.clone()));

        // An independent ask-posture held connection for the same session.
        let ask_conn = FakeTunnel::new();
        let ask_id = reg.register_held_ask_connection(&s, Box::new(ask_conn.clone()));
        assert!(ask_conn.is_held());

        // D46 HOLD_BEGIN: holds the live tunnel. The ask connection was already held
        // on its own registration and stays held (the marker does not double-drive
        // it — hold() is idempotent).
        reg.apply(&hold_begin(&s, Tier::Transparent, 1))
            .expect("d46 hold begin");
        assert!(tunnel.is_held());
        assert!(reg.is_held(&s), "the D46 per-session hold is active");

        // D46 RESUME_RESYNCED: resumes the D46-paused tunnel. It must NOT resolve the
        // ask connection (that is the ask hold's own resolution path).
        reg.apply(&resume(&s, Tier::Transparent, true, 2))
            .expect("d46 resume");
        assert!(!tunnel.is_held(), "the D46 tunnel resumed");
        assert!(!reg.is_held(&s), "the D46 per-session hold cleared");

        // The ask connection now resolves on its OWN grant — independent of the D46
        // marker that just ran. With a live grant it proceeds.
        let grants = FakeGrantSource::with_grant(live_grant(&s, "unknown.example", 10_000));
        let outcome = reg.resolve_ask_hold(ask_id, &s, "unknown.example", &grants, 100);
        assert_eq!(outcome, AskHoldResolution::Proceed);
        assert_eq!(
            ask_conn.resume_calls(),
            1,
            "the ask connection resumed on its grant"
        );

        // Each socket's transitions are clean: the D46 tunnel held+resumed once; the
        // ask connection held once (on registration) and resumed once (on its grant).
        assert_eq!(tunnel.hold_calls(), 1);
        assert_eq!(tunnel.resume_calls(), 1);
        assert_eq!(ask_conn.hold_calls(), 1);
        assert_eq!(ask_conn.resume_calls(), 1);
    }

    #[test]
    fn ask_hold_window_band_is_30_to_60_seconds() {
        // docs/09 §5: "holds it open 30–60 s". The proxy-side band floor/ceiling.
        assert_eq!(ASK_HOLD_MIN_SECONDS, 30);
        assert_eq!(ASK_HOLD_MAX_SECONDS, 60);
        // Compile-time band-ordering invariant (the floor is strictly below the
        // ceiling). A `const` assertion rather than a runtime one — the values are
        // both `const`, so the relation is fixed at compile time.
        const _: () = assert!(ASK_HOLD_MIN_SECONDS < ASK_HOLD_MAX_SECONDS);
    }

    // ── D78 attendedness consume (docs/12 §12; D78) ────────────────────────────

    /// Build an attendedness fact for `session` with the given flags/clock.
    fn fact(
        session: &SessionRef,
        attended: bool,
        computed_at: u64,
        budget: u64,
    ) -> AttendednessFact {
        AttendednessFact {
            session: session.clone(),
            attended,
            computed_at_unix_s: computed_at,
            freshness_budget_s: budget,
        }
    }

    #[test]
    fn attendedness_verdict_is_fail_closed_against_absent_stale_and_unattended() {
        // The load-bearing D78 fail-closed property over the live feed (the synthetic
        // hostagent source): only a FRESH, ATTENDED fact for THIS session reads
        // ATTENDED; absent / stale / unattended / cross-session all read UNATTENDED.
        let s = session(7);
        let feed = AttendednessFeed::new();

        // Absent: no fact recorded yet ⇒ UNATTENDED.
        assert!(feed.is_empty());
        assert!(
            !attendedness_verdict(&feed, &s, 1_000),
            "absent attendedness ⇒ UNATTENDED (fail-closed)"
        );

        // Fresh + attended ⇒ ATTENDED. (computed at 1_000, budget 60, now 1_050.)
        assert!(feed.record(fact(&s, true, 1_000, 60)));
        assert_eq!(feed.len(), 1);
        assert!(
            attendedness_verdict(&feed, &s, 1_050),
            "a fresh attended fact ⇒ ATTENDED"
        );

        // Stale (now past computed_at + budget) ⇒ UNATTENDED even though attended.
        assert!(
            !attendedness_verdict(&feed, &s, 1_061),
            "an attended fact past its freshness budget ⇒ UNATTENDED (fail-closed)"
        );

        // Explicitly UNATTENDED fact, fresh ⇒ UNATTENDED.
        let s2 = session(8);
        assert!(feed.record(fact(&s2, false, 2_000, 60)));
        assert!(
            !attendedness_verdict(&feed, &s2, 2_010),
            "a fresh but attended=false fact ⇒ UNATTENDED"
        );

        // Cross-session: a fact for s never attends a different session s3.
        let s3 = session(9);
        assert!(
            !attendedness_verdict(&feed, &s3, 1_050),
            "a session with no fact ⇒ UNATTENDED (a fact for another session never leaks)"
        );
    }

    #[test]
    fn attendedness_freshness_budget_is_capped_so_a_runaway_budget_cannot_defeat_staleness() {
        // The proxy-side safety bound: an absurd orchestrator budget is clamped to
        // MAX_ATTENDEDNESS_FRESHNESS_BUDGET_S, so a long-idle session can never read
        // "attended" forever.
        let s = session(3);
        let feed = AttendednessFeed::new();
        // budget claims 10_000 s, but the cap is 300 s.
        assert!(feed.record(fact(&s, true, 1_000, 10_000)));
        // Within the cap (age 200 ≤ 300) ⇒ still ATTENDED.
        assert!(attendedness_verdict(&feed, &s, 1_200));
        // Past the cap (age 400 > 300) ⇒ UNATTENDED despite the inflated budget.
        assert!(
            !attendedness_verdict(&feed, &s, 1_400),
            "the freshness budget is capped at MAX_ATTENDEDNESS_FRESHNESS_BUDGET_S (fail-closed)"
        );
        assert_eq!(MAX_ATTENDEDNESS_FRESHNESS_BUDGET_S, 300);
    }

    #[test]
    fn attendedness_record_is_monotonic_by_computed_at_no_older_clobber() {
        // At-least-once reordering must not let an OLDER fact clobber a newer one
        // (which could flip a now-unattended session back to a stale "attended"
        // read). record() keeps only the strictly-newest fact per session.
        let s = session(5);
        let feed = AttendednessFeed::new();

        // Newest fact: unattended, computed at 2_000.
        assert!(feed.record(fact(&s, false, 2_000, 60)));
        // A reordered OLDER attended fact (computed at 1_000) is DROPPED.
        assert!(
            !feed.record(fact(&s, true, 1_000, 60)),
            "an older redelivery is not stored (monotonic by computed_at)"
        );
        // The verdict still reflects the NEWER (unattended) fact ⇒ UNATTENDED.
        assert!(
            !attendedness_verdict(&feed, &s, 2_010),
            "the older attended fact did not clobber the newer unattended one (fail-closed)"
        );
        // An equal-aged redelivery is also dropped (idempotent at-least-once).
        assert!(!feed.record(fact(&s, true, 2_000, 60)));
        // A strictly-newer fact DOES supersede.
        assert!(feed.record(fact(&s, true, 3_000, 60)));
        assert!(attendedness_verdict(&feed, &s, 3_010));
    }

    #[test]
    fn attendedness_future_dated_fact_is_fresh_benign_skew() {
        // A fact whose computed_at is slightly in the future (clock skew, now <
        // computed_at) has age 0 and is treated as fresh — benign; the staleness
        // direction is what fails closed.
        let s = session(2);
        let f = fact(&s, true, 5_000, 60);
        assert!(f.is_fresh(4_990), "now before computed_at ⇒ age 0 ⇒ fresh");
        assert!(f.is_attended_fresh(4_990));
    }

    // ── grant-return feed (docs/09 §5 TLS-1; the live AskGrantSource) ───────────

    #[test]
    fn grant_return_feed_empty_reads_no_grant_for_every_pair_fail_closed() {
        // The fail-closed default: an empty feed returns None for every
        // (session, sni_domain), so a held ask connection resolved against it times
        // out exactly like the old empty FakeGrantSource — no grant ⇒ no proceed.
        let feed = GrantReturnFeed::new();
        let s = session(7);
        assert!(feed.is_empty());
        assert!(
            feed.grant_for(&s, "unknown.example").is_none(),
            "an empty grant-return feed reads no grant (fail-closed)"
        );

        // And it drives the registry's resolve to a timeout close (the listener path).
        let reg = HoldRegistry::new();
        let conn = FakeTunnel::new();
        let id = reg.register_held_ask_connection(&s, Box::new(conn.clone()));
        assert_eq!(
            reg.resolve_ask_hold(id, &s, "unknown.example", &feed, 500),
            AskHoldResolution::ClosedOnTimeout,
            "an empty live feed fails closed to a timeout close"
        );
        assert_eq!(conn.resume_calls(), 0);
    }

    #[test]
    fn grant_return_feed_resolves_a_recorded_grant_and_is_session_domain_scoped() {
        // The live approval path: the policy-stream ingest records a session-scoped
        // TTL-allow grant; a held connection for THAT (session, domain) proceeds, and
        // a hold for any other session or domain still reads no grant (fail-closed).
        let feed = GrantReturnFeed::new();
        let a = session(6);
        let b = session(8);
        assert!(feed.record(live_grant(&a, "x.example", 10_000)));
        assert_eq!(feed.len(), 1);

        // matching pair ⇒ grant present.
        assert!(feed.grant_for(&a, "x.example").is_some());
        // wrong domain ⇒ none.
        assert!(feed.grant_for(&a, "y.example").is_none());
        // wrong session ⇒ none (a grant for A never leaks to B).
        assert!(feed.grant_for(&b, "x.example").is_none());

        // The registry resolves the matching pair to Proceed at a live `now`.
        let reg = HoldRegistry::new();
        let conn = FakeTunnel::new();
        let id = reg.register_held_ask_connection(&a, Box::new(conn.clone()));
        assert_eq!(
            reg.resolve_ask_hold(id, &a, "x.example", &feed, 100),
            AskHoldResolution::Proceed,
            "a live recorded grant for the held pair proceeds"
        );
        assert_eq!(conn.resume_calls(), 1);
    }

    #[test]
    fn grant_return_feed_recorded_but_expired_grant_fails_closed_at_resolve() {
        // A recorded grant that has itself EXPIRED at resolution time does NOT proceed
        // (the TTL-allow check lives in resolve_ask_hold). The feed returns the grant;
        // the registry fails it closed because `expires_at <= now`.
        let feed = GrantReturnFeed::new();
        let s = session(4);
        assert!(feed.record(live_grant(&s, "x.example", 1_000)));
        assert!(feed.grant_for(&s, "x.example").is_some());

        let reg = HoldRegistry::new();
        let conn = FakeTunnel::new();
        let id = reg.register_held_ask_connection(&s, Box::new(conn.clone()));
        // resolve at now=2000, well past the grant's 1000 expiry ⇒ timeout close.
        assert_eq!(
            reg.resolve_ask_hold(id, &s, "x.example", &feed, 2_000),
            AskHoldResolution::ClosedOnTimeout,
            "a recorded-but-expired grant fails closed at resolve (TTL-allow)"
        );
        assert_eq!(conn.resume_calls(), 0);
    }

    #[test]
    fn grant_return_record_is_monotonic_by_expiry_no_shorter_clobber() {
        // At-least-once reordering must not let a SHORTER-lived grant clobber a newer
        // (longer) one — which could prematurely fail an in-flight hold closed.
        // record() keeps only the strictly-longest-lived grant per (session, domain).
        let feed = GrantReturnFeed::new();
        let s = session(5);

        // Longest grant first: expires at 5_000.
        assert!(feed.record(live_grant(&s, "x.example", 5_000)));
        // A reordered SHORTER grant (expires 2_000) is DROPPED.
        assert!(
            !feed.record(live_grant(&s, "x.example", 2_000)),
            "a shorter-lived redelivery is not stored (monotonic by expiry)"
        );
        assert_eq!(
            feed.grant_for(&s, "x.example").map(|g| g.expires_at_unix_s),
            Some(5_000),
            "the longer window survived the shorter redelivery (fail-closed)"
        );
        // An equal-expiry redelivery is also dropped (idempotent at-least-once).
        assert!(!feed.record(live_grant(&s, "x.example", 5_000)));
        // A strictly-longer grant (a renewal) DOES supersede.
        assert!(feed.record(live_grant(&s, "x.example", 9_000)));
        assert_eq!(
            feed.grant_for(&s, "x.example").map(|g| g.expires_at_unix_s),
            Some(9_000)
        );
    }

    // ---- the real pingora-downstream Holdable (doc 12 §13.1) --------------

    /// A synthetic downstream close-half standing in for the pingora `Stream`'s
    /// shutdown: it records how many times `close` fired so a test can assert the
    /// downstream socket was (or was NOT) physically closed. This is the fixture the
    /// live `main.rs` pingora-`Stream` adapter is swapped for the instant M0-host
    /// integration wires the real socket — the state machine is identical.
    #[derive(Default, Clone)]
    struct RecordingDownstreamCloser {
        closes: Arc<AtomicUsize>,
    }

    impl RecordingDownstreamCloser {
        fn new() -> RecordingDownstreamCloser {
            RecordingDownstreamCloser {
                closes: Arc::new(AtomicUsize::new(0)),
            }
        }
        fn close_count(&self) -> usize {
            self.closes.load(Ordering::SeqCst)
        }
    }

    impl DownstreamCloser for RecordingDownstreamCloser {
        fn close(&self) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn socket_holdable_hold_suspends_the_downstream_without_closing_it() {
        // hold() SUSPENDS the accepted downstream (held, forwarding nothing) but does
        // NOT close it — the connection is kept open while the prompt is outstanding
        // (doc 12 §13.1). Idempotent: a second hold is a no-op and still no close.
        let closer = RecordingDownstreamCloser::new();
        let h = SocketHoldable::new(Box::new(closer.clone()));

        assert!(!h.is_held(), "starts forwarding");
        assert!(h.hold(), "first hold suspends (forwarding → held)");
        assert!(h.is_held(), "the downstream is now held (suspended)");
        assert!(!h.hold(), "a second hold is idempotent (no-op)");
        assert_eq!(
            closer.close_count(),
            0,
            "holding NEVER closes the downstream — it is kept open"
        );
    }

    #[test]
    fn socket_holdable_resume_releases_the_downstream_for_the_splice_no_close() {
        // resume() (the GRANT / PROCEED leg) RELEASES the downstream back to the
        // listener for the splice to the freshly admitted upstream — it must survive,
        // so resume closes NOTHING and, critically, a later drop of the (resumed)
        // handle closes nothing either (the splice now owns the socket).
        let closer = RecordingDownstreamCloser::new();
        {
            let h = SocketHoldable::new(Box::new(closer.clone()));
            assert!(h.hold());
            assert!(h.resume(), "held → released (the connection proceeds)");
            assert!(!h.is_held(), "a resumed connection is no longer held");
            assert!(!h.resume(), "a second resume is idempotent (no-op)");
            assert_eq!(
                closer.close_count(),
                0,
                "resume never closes the downstream"
            );
        } // drop the resumed handle
        assert_eq!(
            closer.close_count(),
            0,
            "dropping a RESUMED handle closes nothing — the splice owns the socket"
        );
    }

    #[test]
    fn socket_holdable_drop_while_held_closes_the_downstream_exactly_once() {
        // The FAIL-CLOSED leg (deny / window-expiry): `resolve_ask_hold`'s
        // ClosedOnTimeout drops the registry entry STILL HELD. Dropping a held
        // SocketHoldable CLOSES the downstream — the physical timeout close (doc 12
        // §13.5) — exactly once.
        let closer = RecordingDownstreamCloser::new();
        {
            let h = SocketHoldable::new(Box::new(closer.clone()));
            assert!(h.hold(), "held while the prompt is outstanding");
            assert_eq!(closer.close_count(), 0, "not closed while held");
        } // drop while still held (never resumed) → close
        assert_eq!(
            closer.close_count(),
            1,
            "dropping a still-held handle closes the downstream exactly once (fail-closed)"
        );
    }

    #[test]
    fn socket_holdable_dropped_never_held_closes_nothing() {
        // A handle that was constructed but never held (an unreachable path — the
        // registry holds on registration — but the invariant must hold): dropping a
        // never-held handle closes nothing (only the held→drop leg is the fail-closed
        // close).
        let closer = RecordingDownstreamCloser::new();
        {
            let _h = SocketHoldable::new(Box::new(closer.clone()));
        }
        assert_eq!(
            closer.close_count(),
            0,
            "a never-held handle closes nothing on drop"
        );
    }

    #[test]
    fn socket_holdable_end_to_end_proceed_resumes_timeout_closes() {
        // End-to-end through the UNCHANGED registry state machine, over the REAL
        // socket-backed Holdable (doc 12 §13.1): an approved Ask resumes the downstream
        // (survives for the splice), a timed-out Ask closes it (fail-closed). This is
        // the acceptance shape — a held request suspends the downstream and resumes on
        // grant / errors on deny — exercised against the synthetic downstream fixture.
        let s = session(9);

        // ---- PROCEED (grant): the downstream is released for the splice, not closed.
        let ok_closer = RecordingDownstreamCloser::new();
        {
            let reg = HoldRegistry::new();
            let id = reg.register_held_ask_connection(
                &s,
                Box::new(SocketHoldable::new(Box::new(ok_closer.clone()))),
            );
            let grants = FakeGrantSource::with_grant(live_grant(&s, "unknown.example", 10_000));
            assert_eq!(
                reg.resolve_ask_hold(id, &s, "unknown.example", &grants, 100),
                AskHoldResolution::Proceed,
                "a live grant proceeds the held connection"
            );
        } // the registry (and any residual handle) is dropped here
        assert_eq!(
            ok_closer.close_count(),
            0,
            "an APPROVED ask never closes the downstream — it is spliced to upstream"
        );

        // ---- TIMEOUT (deny / no grant): the downstream is closed fail-closed.
        let to_closer = RecordingDownstreamCloser::new();
        let reg = HoldRegistry::new();
        let id = reg.register_held_ask_connection(
            &s,
            Box::new(SocketHoldable::new(Box::new(to_closer.clone()))),
        );
        let empty = FakeGrantSource::empty();
        assert_eq!(
            reg.resolve_ask_hold(id, &s, "unknown.example", &empty, 100),
            AskHoldResolution::ClosedOnTimeout,
            "no grant within the window closes the held connection (fail-closed)"
        );
        assert_eq!(
            to_closer.close_count(),
            1,
            "a TIMED-OUT ask closes the downstream exactly once (fail-closed, doc 12 §13.5)"
        );
    }
}
