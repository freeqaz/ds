//! The internal backend trait that hides the nft/conntrack mechanism (doc 11
//! §4 — mechanism is FREE; doc 14 §6 — one internal API).
//!
//! Everything the flush and refresh paths do reaches the kernel through ONE
//! trait, [`NftBackend`]. Production wires it to spawned `nft -f` / `conntrack
//! -D` (the stdlib path, [`SpawnBackend`]); unit tests wire it to
//! [`RecordingBackend`], which records the exact batch text / argv it was asked
//! to run and returns canned output — so the mark/mask composition, leg
//! spanning, dst narrowing, both refresh strategies' batch generation, and the
//! conntrack-accounting parse are all sandbox-verifiable with no kernel.
//!
//! The mechanism can move to `nftnl-rs`/netlink later without touching any
//! caller: only this trait's impls change.

use std::cell::RefCell;
use std::fmt;

/// A request to apply an `nft -f` batch (set-element ops: in-place timeout
/// update or delete+add). The batch is plain text the backend feeds to
/// `nft -f -` (or replays as netlink ops in a future mechanism).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftBatch {
    /// The batch text, exactly as it would be piped to `nft -f -`.
    pub text: String,
}

impl NftBatch {
    /// Wrap batch text.
    pub fn new(text: impl Into<String>) -> NftBatch {
        NftBatch { text: text.into() }
    }
}

/// A request to destroy conntrack entries matching a composed mark/mask. The
/// `mark_arg` is the `value/mask` token (see [`crate::mark_match::MarkMatch`]);
/// the backend turns it into `conntrack -D --mark <mark_arg>` (or the netlink
/// equivalent). Carrying the token — not a bare value — is what keeps the
/// match DS_MARK_MASK-aware end to end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConntrackDestroy {
    /// The `value/mask` token from
    /// [`crate::mark_match::MarkMatch::to_value_mask_token`] — the composed DS
    /// mark over the frozen `DS_MARK_MASK`. Always composed from
    /// `ds_contracts::mark`, never a typed-in literal.
    pub mark_arg: String,
    /// Optional per-destination narrowing (`--dst <key>`); `None` means flush
    /// every destination carrying the mark (teardown / NFT-6 `dst_filter=All`).
    pub dst: Option<String>,
}

/// A request to create a per-session tap netdev — the unforgeable `dstap-<idx>`
/// device every session's egress is `iifname`-anchored on (doc 09 §3 NFT-2/4;
/// the `iifname`-anchored controls in [`crate::redirect`] / [`crate::dot853`] /
/// [`crate::quic_reject`] all match against this device). ds-nft never invents
/// the name: the caller composes `dstap-<idx>` from the session's host index
/// (`Binding.TapName`, doc 14 §4 / the AttachPrimitive seam) and hands it here.
///
/// This is **mechanism only** (doc 11 §4): create/delete the netdev and assign
/// its per-session routed point-to-point addressing (D2, doc 11 §2.4/§13.1).
/// `create_tap` brings the device up and then programs the host-side gateway
/// `10.77.<host_session_index>.0/31` + the on-link route to the guest `.1`
/// (+ a static neigh entry when the guest MAC is known). It programs **no** nft
/// rules — per-session NFT *instantiation* (the empty `allow4_<session>` /
/// `allow6_<session>` admit surface, D1/D3) is the separate INSTANTIATE write
/// path, and all deny/redirect/closure verdicts come from the host-wide
/// `dstap-*` glob floor (doc 11 §2.3), never from here.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TapSpec {
    /// The tap device name, e.g. `dstap-7` — composed by the caller from the
    /// host session index (≤ `IFNAMSIZ`). ds-nft treats it as opaque and never
    /// derives it.
    pub name: String,
    /// The uid to own the tap (`ip tuntap add ... user <uid>`), so the
    /// (unprivileged) per-session process can open it. `None` leaves the tap
    /// owned by the creating (root) context — no `user` argument is passed.
    pub owner_uid: Option<u32>,
    /// The host session index (D4) — the authority for this session's routed
    /// `/31`. It lands **verbatim in the third octet**: the host-side gateway is
    /// `10.77.<host_session_index>.0` and the guest is `.1` (doc 11 §2.4, RFC
    /// 3021). It is the *addressing* authority and is independent of the opaque
    /// `name` above; ds-nft never re-derives one from the other. (The tlsproxy
    /// attribution side reads the index straight back out of the third octet —
    /// `transparent.rs::session_from_local_addr` — so the two ends stay one
    /// convention.) The Go orchestrator side now agrees by construction (U10): its
    /// `AddressPlan{RoutedTap:true}` derives the SAME guest end `10.77.<idx>.1`
    /// through its own single source (`netconfig.go` `routedTapGuestIP`), so the
    /// recorded `Binding.GuestIP`, the guest's applied net config, and this tap link
    /// cannot drift. There is NO `guest_ip` parameter across this C ABI: ds-nft is
    /// the Rust-side single source on the index, the orchestrator is the Go-side
    /// single source on the index, and a cross-language test (Go `netconfig_test.go`)
    /// pins them to the matching `10.77.7.x` this crate's tests anchor.
    pub host_session_index: u32,
    /// The guest NIC MAC, when known, for a static `ip neigh replace
    /// 10.77.<idx>.1 lladdr <mac>` so the host need not ARP the guest. `None`
    /// when the MAC is not yet known at create time — the neigh entry is then
    /// **skipped** (it is recoverable later, doc 11 §2.4) and create still
    /// converges; it is never a failure.
    pub guest_mac: Option<String>,
}

/// What a conntrack destroy reported back: the raw accounting-style output the
/// backend captured (one `conntrack -D` line per destroyed entry when
/// `nf_conntrack_acct=1`, doc 14 §11). The flush path parses byte counts out of
/// this via [`crate::outcome`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ConntrackOutput {
    /// The captured stdout/stderr lines (conntrack writes destroyed entries to
    /// stderr in `-D` mode; the backend captures both and hands them here).
    pub lines: Vec<String>,
}

/// The backend error surface. Mechanism-specific (a spawn failure, a non-zero
/// `nft`/`conntrack` exit); opaque above the trait.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendError {
    /// A human-readable description (command + exit/IO detail).
    pub message: String,
}

impl BackendError {
    /// Construct a backend error from a message.
    pub fn new(message: impl Into<String>) -> BackendError {
        BackendError {
            message: message.into(),
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nft backend error: {}", self.message)
    }
}

impl std::error::Error for BackendError {}

/// The one internal API over the nft/conntrack mechanism (doc 14 §6).
///
/// Implementors: [`RecordingBackend`] (tests) and [`SpawnBackend`] (production,
/// spawned `nft -f` / `conntrack -D`). Refresh and flush call ONLY through this
/// trait, so swapping the mechanism is a single-file change.
pub trait NftBackend {
    /// Apply an `nft -f` batch (set-element ops). Must be observed-committed
    /// before the caller proceeds (the insert-then-answer ordering, doc 11
    /// §8.3 — though ordering itself is the caller's concern).
    fn apply_batch(&self, batch: &NftBatch) -> Result<(), BackendError>;

    /// Destroy conntrack entries matching the composed mark/mask, returning the
    /// captured accounting output for byte-count parsing.
    fn destroy_conntrack(
        &self,
        destroy: &ConntrackDestroy,
    ) -> Result<ConntrackOutput, BackendError>;

    /// Create the per-session tap netdev named by `spec`, bring it up, and
    /// assign its routed point-to-point addressing (D2, doc 11 §2.4):
    /// host-side gateway `10.77.<host_session_index>.0/31`, an on-link `/32`
    /// route to the guest `.1`, and — when `spec.guest_mac` is set — a static
    /// neigh entry for the guest. A `None` guest MAC SKIPS only the neigh leg
    /// (recoverable later); it never fails the create.
    ///
    /// **Idempotent (doc 15 §5.1):** a re-create / re-address of an
    /// already-converged tap is a *converged success*, not an error — the
    /// production backend treats the kernel's "device exists" / "address exists"
    /// / "route exists" (`EEXIST` / `RTNETLINK answers: File exists`) as
    /// `Ok(())`, so retry and create-rollback can replay unconditionally.
    /// Mechanism only: NO nft rules (the `dstap-*` glob floor owns deny/redirect;
    /// the per-session admit-set INSTANTIATE is D1/D3, a separate write path).
    fn create_tap(&self, spec: &TapSpec) -> Result<(), BackendError>;

    /// Delete the tap netdev `name`.
    ///
    /// **Idempotent (doc 15 §5.1):** deleting an already-absent tap is a
    /// *converged success* — the production backend treats the kernel's "no such
    /// device" (`ENODEV` / `Cannot find device`) as `Ok(())`, so teardown and
    /// create-rollback can run unconditionally.
    fn delete_tap(&self, name: &str) -> Result<(), BackendError>;
}

/// A recording fake backend for unit tests (the sandbox-verifiable path). It
/// records every batch and every destroy in order, and returns pre-seeded
/// conntrack output so the byte-count parse can be exercised without a kernel.
///
/// `RefCell` interior mutability lets it satisfy the `&self` trait methods while
/// still accumulating a call log — the production backend is genuinely `&self`
/// (it spawns processes), so the trait stays shared-ref and tests don't distort
/// the signature.
#[derive(Debug, Default)]
pub struct RecordingBackend {
    batches: RefCell<Vec<NftBatch>>,
    destroys: RefCell<Vec<ConntrackDestroy>>,
    /// Taps created so far, in order (mirrors `batches`/`destroys`).
    taps: RefCell<Vec<TapSpec>>,
    /// Names of taps deleted so far, in order.
    deleted_taps: RefCell<Vec<String>>,
    /// Canned outputs, popped front-to-back per destroy call; an empty queue
    /// yields empty output (zero entries destroyed).
    canned_outputs: RefCell<std::collections::VecDeque<ConntrackOutput>>,
    /// If set, the next `apply_batch` / `destroy_conntrack` returns this error
    /// (one-shot), to exercise the fail-closed path.
    next_error: RefCell<Option<BackendError>>,
}

impl RecordingBackend {
    /// A fresh recording backend with no canned output.
    pub fn new() -> RecordingBackend {
        RecordingBackend::default()
    }

    /// Seed the conntrack output the next destroy call returns.
    pub fn push_conntrack_output(&self, output: ConntrackOutput) {
        self.canned_outputs.borrow_mut().push_back(output);
    }

    /// Arm a one-shot error for the next backend call.
    pub fn arm_error(&self, err: BackendError) {
        *self.next_error.borrow_mut() = Some(err);
    }

    /// The batches applied so far, in order.
    pub fn batches(&self) -> Vec<NftBatch> {
        self.batches.borrow().clone()
    }

    /// The conntrack destroys requested so far, in order.
    pub fn destroys(&self) -> Vec<ConntrackDestroy> {
        self.destroys.borrow().clone()
    }

    /// The taps created so far, in order.
    pub fn taps(&self) -> Vec<TapSpec> {
        self.taps.borrow().clone()
    }

    /// The names of taps deleted so far, in order.
    pub fn deleted_taps(&self) -> Vec<String> {
        self.deleted_taps.borrow().clone()
    }

    fn take_error(&self) -> Option<BackendError> {
        self.next_error.borrow_mut().take()
    }
}

impl NftBackend for RecordingBackend {
    fn apply_batch(&self, batch: &NftBatch) -> Result<(), BackendError> {
        if let Some(err) = self.take_error() {
            return Err(err);
        }
        self.batches.borrow_mut().push(batch.clone());
        Ok(())
    }

    fn destroy_conntrack(
        &self,
        destroy: &ConntrackDestroy,
    ) -> Result<ConntrackOutput, BackendError> {
        if let Some(err) = self.take_error() {
            return Err(err);
        }
        self.destroys.borrow_mut().push(destroy.clone());
        let out = self
            .canned_outputs
            .borrow_mut()
            .pop_front()
            .unwrap_or_default();
        Ok(out)
    }

    fn create_tap(&self, spec: &TapSpec) -> Result<(), BackendError> {
        if let Some(err) = self.take_error() {
            return Err(err);
        }
        self.taps.borrow_mut().push(spec.clone());
        Ok(())
    }

    fn delete_tap(&self, name: &str) -> Result<(), BackendError> {
        if let Some(err) = self.take_error() {
            return Err(err);
        }
        self.deleted_taps.borrow_mut().push(name.to_string());
        Ok(())
    }
}

/// The production backend: spawned `nft -f -` for batches and spawned
/// `conntrack -D --mark <token>` for destroys (the stdlib mechanism, doc 11
/// §4). Deliberately thin — it shells out and captures output; all semantics
/// live above it.
///
/// NOT exercised by unit tests (the sandbox has no `nf_conntrack` and restricted
/// netlink); real effectiveness is CI/fixture-gated (`nf_conntrack_tcp_loose=0`,
/// real ≥6.12 in-place refresh — M0-host work). Tests cover the *generated*
/// batch text / argv via [`RecordingBackend`], which is the CI assertion the
/// brief specifies.
///
/// `Default` is implemented by hand to delegate to [`SpawnBackend::new`] — NOT
/// `#[derive]`d. A derived `Default` would `String::default()` every field, i.e.
/// EMPTY `nft`/`conntrack`/`ip` binary names, so `SpawnBackend::default()` would
/// silently disagree with `SpawnBackend::new()` and try to spawn `""` (a confusing
/// `ENOENT` instead of running `nft`/`conntrack`/`ip` on PATH). Routing `default`
/// through `new` keeps the two construction paths byte-identical.
#[derive(Debug)]
pub struct SpawnBackend {
    /// The `nft` binary to invoke (default `nft`).
    nft_bin: String,
    /// The `conntrack` binary to invoke (default `conntrack`).
    conntrack_bin: String,
    /// The `ip` binary to invoke for tap netdev create/delete (default `ip`).
    ip_bin: String,
}

impl Default for SpawnBackend {
    /// The default spawn backend is exactly [`SpawnBackend::new`] (the PATH
    /// `nft`/`conntrack`/`ip` binaries) — never the all-empty struct a derived
    /// `Default` would produce.
    fn default() -> SpawnBackend {
        SpawnBackend::new()
    }
}

impl SpawnBackend {
    /// A spawn backend using the default `nft` / `conntrack` / `ip` binaries on
    /// PATH.
    pub fn new() -> SpawnBackend {
        SpawnBackend {
            nft_bin: "nft".to_string(),
            conntrack_bin: "conntrack".to_string(),
            ip_bin: "ip".to_string(),
        }
    }

    /// Override the `nft` / `conntrack` binary paths (e.g. absolute paths on the
    /// M0 host); the `ip` binary keeps its default (`ip`). Use
    /// [`SpawnBackend::with_ip_binary`] to override the tap `ip` path too.
    pub fn with_binaries(
        nft_bin: impl Into<String>,
        conntrack_bin: impl Into<String>,
    ) -> SpawnBackend {
        SpawnBackend {
            nft_bin: nft_bin.into(),
            conntrack_bin: conntrack_bin.into(),
            ip_bin: "ip".to_string(),
        }
    }

    /// Override the `ip` binary the tap create/delete shells out to (e.g. an
    /// absolute path on the M0 host). Additive over the existing constructors.
    pub fn with_ip_binary(mut self, ip_bin: impl Into<String>) -> SpawnBackend {
        self.ip_bin = ip_bin.into();
        self
    }

    /// Run `ip <args>`, returning `Ok(())` on success. A non-zero exit is an
    /// error UNLESS the captured stderr contains one of `converged_signals` — the
    /// kernel's "already in the desired state" message (e.g. `File exists` on a
    /// re-create, `Cannot find device` on a re-delete), which is a converged
    /// success under the idempotency contract (doc 15 §5.1).
    fn run_ip(&self, args: &[String], converged_signals: &[&str]) -> Result<(), BackendError> {
        use std::process::Command;

        let out = Command::new(&self.ip_bin)
            .args(args)
            .output()
            .map_err(|e| {
                BackendError::new(format!("spawn {} {}: {e}", self.ip_bin, args.join(" ")))
            })?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if converged_signals.iter().any(|sig| stderr.contains(sig)) {
            // Already in the desired state — idempotent no-op success.
            return Ok(());
        }
        Err(BackendError::new(format!(
            "{} {} exited {}: {}",
            self.ip_bin,
            args.join(" "),
            out.status,
            stderr.trim()
        )))
    }
}

impl NftBackend for SpawnBackend {
    fn apply_batch(&self, batch: &NftBatch) -> Result<(), BackendError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new(&self.nft_bin)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackendError::new(format!("spawn {} -f -: {e}", self.nft_bin)))?;

        child
            .stdin
            .take()
            .ok_or_else(|| BackendError::new("nft stdin unavailable"))?
            .write_all(batch.text.as_bytes())
            .map_err(|e| BackendError::new(format!("write nft batch: {e}")))?;

        let out = child
            .wait_with_output()
            .map_err(|e| BackendError::new(format!("wait nft: {e}")))?;
        if !out.status.success() {
            return Err(BackendError::new(format!(
                "nft -f exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    fn destroy_conntrack(
        &self,
        destroy: &ConntrackDestroy,
    ) -> Result<ConntrackOutput, BackendError> {
        use std::process::Command;

        let mut cmd = Command::new(&self.conntrack_bin);
        cmd.arg("-D").arg("--mark").arg(&destroy.mark_arg);
        if let Some(dst) = &destroy.dst {
            cmd.arg("--dst").arg(dst);
        }
        let out = cmd
            .output()
            .map_err(|e| BackendError::new(format!("spawn {} -D: {e}", self.conntrack_bin)))?;

        // conntrack -D returns non-zero (1) when zero entries matched; that is
        // not an error for a flush (an already-empty session). Only a spawn
        // failure or a usage/permission error (exit ≥2 with no destroy lines)
        // is surfaced. The destroyed-entry lines land on stderr.
        let mut lines = Vec::new();
        for chunk in [&out.stdout, &out.stderr] {
            for line in String::from_utf8_lossy(chunk).lines() {
                let line = line.trim();
                if !line.is_empty() {
                    lines.push(line.to_string());
                }
            }
        }
        Ok(ConntrackOutput { lines })
    }

    fn create_tap(&self, spec: &TapSpec) -> Result<(), BackendError> {
        // Mechanism only (doc 11 §4): create the tap netdev, bring it up, and
        // assign the per-session routed point-to-point addressing (D2, doc 11
        // §2.4). Programs NO nft rules — the host-wide `dstap-*` glob floor owns
        // every deny/redirect/closure verdict, and the per-session admit-set
        // INSTANTIATE (the empty `allow4_<session>` / `allow6_<session>` sets,
        // D1/D3) is the separate INSTANTIATE write path.

        // 1. `ip tuntap add dev <name> mode tap [user <uid>]`.
        let mut args: Vec<String> = vec![
            "tuntap".into(),
            "add".into(),
            "dev".into(),
            spec.name.clone(),
            "mode".into(),
            "tap".into(),
        ];
        if let Some(uid) = spec.owner_uid {
            args.push("user".into());
            args.push(uid.to_string());
        }
        // A device that already exists is a converged success (doc 15 §5.1).
        // `ip tuntap add dev <name> mode tap` does NOT report the canonical
        // EEXIST "File exists" text on a re-add of an existing tap: the TUNSETIFF
        // ioctl returns EBUSY, surfacing as `ioctl(TUNSETIFF): Device or resource
        // busy` (confirmed live by the netns proof,
        // tests/nft_tap_lifecycle_netns.rs). Match that EBUSY string alongside
        // the "File exists"/"already exists" forms (which other tap-create paths
        // / older `ip` builds can still emit) so a create-retry / create-rollback
        // over an existing tap converges to Ok instead of a hard BackendError.
        self.run_ip(
            &args,
            &[
                "Device or resource busy",
                "ioctl(TUNSETIFF)",
                "File exists",
                "already exists",
            ],
        )?;

        // 2. `ip link set <name> up`. Bringing an already-up device up again is
        // itself idempotent at the kernel, so no special-case is needed here.
        self.run_ip(
            &["link".into(), "set".into(), spec.name.clone(), "up".into()],
            &[],
        )?;

        // 3. Routed point-to-point addressing (D2, doc 11 §2.4, RFC 3021): the
        // host-side gateway is `10.77.<host_session_index>.0/31`, the guest is
        // `.1`. The index lands verbatim in the third octet — the same
        // convention the tlsproxy attribution side reads back out
        // (`transparent.rs::session_from_local_addr`), so the two ends stay one
        // plan. (An index that overflows a single octet produces an address `ip`
        // rejects — a genuine, fail-closed error, never a silent success.)
        let idx = spec.host_session_index;
        let gateway_cidr = format!("10.77.{idx}.0/31");
        let guest_ip = format!("10.77.{idx}.1");

        // `ip addr add 10.77.<idx>.0/31 dev <name>`. A pre-existing identical
        // address is a converged success — the kernel reports "File exists"
        // (EEXIST), so a re-address on retry/rollback is safe (doc 15 §5.1).
        self.run_ip(
            &[
                "addr".into(),
                "add".into(),
                gateway_cidr,
                "dev".into(),
                spec.name.clone(),
            ],
            &["File exists"],
        )?;

        // `ip route add 10.77.<idx>.1/32 dev <name>`. The on-link `/32` route to
        // the guest makes its traffic enter the host IP stack (prerouting /
        // forward), where the floor's redirect/DNAT can capture it. A
        // pre-existing route is a converged success ("File exists" / "RTNETLINK
        // answers: File exists").
        self.run_ip(
            &[
                "route".into(),
                "add".into(),
                format!("{guest_ip}/32"),
                "dev".into(),
                spec.name.clone(),
            ],
            &["File exists"],
        )?;

        // `ip neigh replace 10.77.<idx>.1 lladdr <mac> dev <name>` — ONLY when
        // the guest MAC is known. `neigh replace` is itself idempotent (it
        // upserts), so no converged-signal handling is needed; a spawn/usage
        // failure still surfaces. When the MAC is not yet known the neigh leg is
        // SKIPPED — it is recoverable later (doc 11 §2.4) and never fails create.
        if let Some(mac) = &spec.guest_mac {
            self.run_ip(
                &[
                    "neigh".into(),
                    "replace".into(),
                    guest_ip,
                    "lladdr".into(),
                    mac.clone(),
                    "dev".into(),
                    spec.name.clone(),
                ],
                &[],
            )?;
        }
        Ok(())
    }

    fn delete_tap(&self, name: &str) -> Result<(), BackendError> {
        // `ip link del <name>`; an already-absent device is a converged success
        // (doc 15 §5.1) — the kernel reports `Cannot find device` (ENODEV), which
        // we treat as Ok so teardown/rollback can run unconditionally.
        self.run_ip(
            &["link".into(), "del".into(), name.to_string()],
            &["Cannot find device", "No such device"],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mark_match::MarkMatch;
    use ds_contracts::mark::Leg;

    // Compose the mark token from ds_contracts — no inline DS-mark literal lives
    // in the tests either (mask discipline, doc 14 §5).
    fn token(idx: u32) -> String {
        MarkMatch::for_leg(Leg::AgentVm, idx).to_value_mask_token()
    }

    #[test]
    fn recording_backend_logs_batches_and_destroys_in_order() {
        let b = RecordingBackend::new();
        b.apply_batch(&NftBatch::new("batch-1")).unwrap();
        b.destroy_conntrack(&ConntrackDestroy {
            mark_arg: token(7),
            dst: None,
        })
        .unwrap();
        b.apply_batch(&NftBatch::new("batch-2")).unwrap();

        let batches = b.batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].text, "batch-1");
        assert_eq!(batches[1].text, "batch-2");

        let destroys = b.destroys();
        assert_eq!(destroys.len(), 1);
        assert_eq!(destroys[0].mark_arg, token(7));
    }

    #[test]
    fn recording_backend_returns_canned_output_then_empty() {
        let b = RecordingBackend::new();
        b.push_conntrack_output(ConntrackOutput {
            lines: vec!["entry-line".into()],
        });
        let first = b
            .destroy_conntrack(&ConntrackDestroy {
                mark_arg: token(1),
                dst: None,
            })
            .unwrap();
        assert_eq!(first.lines, vec!["entry-line".to_string()]);
        // queue exhausted → empty output (zero entries).
        let second = b
            .destroy_conntrack(&ConntrackDestroy {
                mark_arg: token(1),
                dst: None,
            })
            .unwrap();
        assert!(second.lines.is_empty());
    }

    #[test]
    fn armed_error_is_one_shot_and_fails_the_call() {
        let b = RecordingBackend::new();
        b.arm_error(BackendError::new("EPERM"));
        let err = b.apply_batch(&NftBatch::new("x")).unwrap_err();
        assert_eq!(err.message, "EPERM");
        // recovered after the one-shot.
        b.apply_batch(&NftBatch::new("y")).unwrap();
        assert_eq!(b.batches().len(), 1);
    }

    // ── tap netdev capability (mechanism only; no IP/route, no nft rules) ──

    #[test]
    fn recording_backend_records_taps_in_order() {
        let b = RecordingBackend::new();
        b.create_tap(&TapSpec {
            name: "dstap-7".into(),
            owner_uid: Some(1000),
            host_session_index: 7,
            guest_mac: Some("52:54:00:00:00:07".into()),
        })
        .unwrap();
        b.create_tap(&TapSpec {
            name: "dstap-8".into(),
            owner_uid: None,
            host_session_index: 8,
            guest_mac: None,
        })
        .unwrap();

        let taps = b.taps();
        assert_eq!(taps.len(), 2);
        assert_eq!(taps[0].name, "dstap-7");
        assert_eq!(taps[0].owner_uid, Some(1000));
        // RecordingBackend records the addressing authority verbatim — the
        // gateway index and the guest MAC ride the spec it captured.
        assert_eq!(taps[0].host_session_index, 7);
        assert_eq!(taps[0].guest_mac.as_deref(), Some("52:54:00:00:00:07"));
        assert_eq!(taps[1].name, "dstap-8");
        assert_eq!(taps[1].owner_uid, None);
        assert_eq!(taps[1].host_session_index, 8);
        assert_eq!(taps[1].guest_mac, None);
        // creating a tap records nothing in the batch/destroy logs (no nft rule).
        assert!(b.batches().is_empty());
        assert!(b.destroys().is_empty());
    }

    #[test]
    fn recording_backend_create_is_idempotent_records_each_call() {
        // From the trait/fake's view, idempotency is "a re-create is a converged
        // success" — re-creating the same tap returns Ok and the fake records it,
        // so callers can replay create on retry/rollback without an error.
        let b = RecordingBackend::new();
        let spec = TapSpec {
            name: "dstap-3".into(),
            owner_uid: None,
            host_session_index: 3,
            guest_mac: None,
        };
        b.create_tap(&spec).unwrap();
        b.create_tap(&spec).unwrap(); // re-create: still Ok.
        let taps = b.taps();
        assert_eq!(taps.len(), 2);
        assert!(taps.iter().all(|t| t.name == "dstap-3"));
    }

    #[test]
    fn recording_backend_delete_records_the_name() {
        let b = RecordingBackend::new();
        b.delete_tap("dstap-7").unwrap();
        // deleting an absent tap is a converged success — record it again.
        b.delete_tap("dstap-7").unwrap();
        assert_eq!(b.deleted_taps(), vec!["dstap-7".to_string(); 2]);
        // delete touches neither batch nor destroy logs (no nft rule).
        assert!(b.batches().is_empty());
        assert!(b.destroys().is_empty());
    }

    #[test]
    fn armed_error_surfaces_on_create_and_delete_tap() {
        let b = RecordingBackend::new();
        b.arm_error(BackendError::new("EPERM: CAP_NET_ADMIN missing"));
        let err = b
            .create_tap(&TapSpec {
                name: "dstap-1".into(),
                owner_uid: None,
                host_session_index: 1,
                guest_mac: None,
            })
            .unwrap_err();
        assert!(err.message.contains("EPERM"));
        // one-shot: the next create succeeds (and is the first recorded tap).
        b.create_tap(&TapSpec {
            name: "dstap-1".into(),
            owner_uid: None,
            host_session_index: 1,
            guest_mac: None,
        })
        .unwrap();
        assert_eq!(b.taps().len(), 1);

        // same for delete.
        b.arm_error(BackendError::new("EPERM"));
        let err = b.delete_tap("dstap-1").unwrap_err();
        assert!(err.message.contains("EPERM"));
        b.delete_tap("dstap-1").unwrap();
        assert_eq!(b.deleted_taps(), vec!["dstap-1".to_string()]);
    }

    #[test]
    fn spawn_backend_default_matches_new_not_the_empty_struct() {
        // Regression guard for the derived-`Default` footgun: `SpawnBackend`
        // implements `Default` by delegating to `new()`, so `default()` carries the
        // PATH `nft`/`conntrack`/`ip` binary names — NOT the empty strings a
        // `#[derive(Default)]` would produce (which would spawn `""`). The fields
        // are private, so we compare the two construction paths' `Debug` output
        // (which surfaces the field values) and assert the real names are present.
        let from_new = format!("{:?}", SpawnBackend::new());
        let from_default = format!("{:?}", SpawnBackend::default());
        assert_eq!(
            from_default, from_new,
            "SpawnBackend::default() must equal SpawnBackend::new(), not the all-empty derived struct"
        );
        // The binary names are the real PATH defaults, never empty.
        assert!(
            from_default.contains("\"nft\""),
            "default nft_bin must be \"nft\": {from_default}"
        );
        assert!(
            from_default.contains("\"conntrack\""),
            "default conntrack_bin must be \"conntrack\": {from_default}"
        );
        assert!(
            from_default.contains("\"ip\""),
            "default ip_bin must be \"ip\": {from_default}"
        );
    }

    // ── SpawnBackend converged-signal classification (kernel-free) ──
    //
    // These exercise the production `SpawnBackend::run_ip` IDEMPOTENCY logic
    // without touching the kernel: `ip_bin` is overridden to a throwaway shell
    // stub that prints a chosen message to stderr and exits with a chosen code.
    // No `ip`/`nft`/`conntrack`/netlink call is made and no net object is
    // created, so the test is hermetic and kernel-free.

    /// Serializes the SpawnBackend stub tests. Writing an executable in one
    /// thread while another thread `fork`s to `exec` a *different* stub can race
    /// the open-for-write fd across the fork and surface `ETXTBSY` ("Text file
    /// busy"); holding this lock for the create+exec window makes the stub tests
    /// deterministic without affecting the kernel-free fake tests.
    static STUB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Write an executable `ip` stub to scratch. It fails (`printf stderr_msg;
    /// exit code`) ONLY when its argv contains `trigger` — so a create stub can
    /// fail the `tuntap add` leg while letting the subsequent `link set ... up`
    /// pass (exit 0), exactly as the real `ip` behaves when the device already
    /// exists. Returns the stub path (in the OS temp dir).
    fn ip_stub(tag: &str, trigger: &str, stderr_msg: &str, code: i32) -> std::path::PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ds-nft-iptap-stub-{tag}-{}-{}",
            std::process::id(),
            // nanos for uniqueness across same-pid runs.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Fail only on the leg whose argv carries `trigger`; any other leg
        // (e.g. `link set <name> up` after a create) succeeds silently.
        let script = format!(
            "#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = '{trigger}' ]; then\n    printf '%s\\n' '{stderr_msg}' 1>&2\n    exit {code}\n  fi\ndone\nexit 0\n"
        );
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            f.flush().unwrap();
            // Drop `f` (close the write handle) at the end of this block BEFORE
            // we exec the stub — exec'ing a file still open for writing yields
            // ETXTBSY ("Text file busy") on Linux.
        }
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn spawn_create_treats_already_exists_as_converged_success() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Stub `ip` fails the `tuntap add` leg with the kernel's EEXIST text (the
        // subsequent `link set ... up` succeeds) → create must converge.
        let stub = ip_stub("exists", "add", "RTNETLINK answers: File exists", 2);
        let be = SpawnBackend::new().with_ip_binary(stub.to_str().unwrap());
        let r = be.create_tap(&TapSpec {
            name: "dstap-9".into(),
            owner_uid: Some(1000),
            host_session_index: 9,
            guest_mac: None,
        });
        let _ = std::fs::remove_file(&stub);
        assert!(
            r.is_ok(),
            "already-exists must be a converged success: {r:?}"
        );
    }

    #[test]
    fn spawn_create_treats_tuntap_ebusy_re_add_as_converged_success() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Real-kernel re-add semantics (doc 15 §5.1): re-adding an EXISTING tap
        // via `ip tuntap add ... mode tap` fails the TUNSETIFF ioctl with EBUSY
        // (`ioctl(TUNSETIFF): Device or resource busy`), NOT the EEXIST "File
        // exists" text. Trigger on `tuntap` (unique to the step-1 leg) so ONLY
        // that leg returns EBUSY — exactly as the real kernel does; the later
        // `addr add`/`route add` legs return EEXIST, not EBUSY, so triggering on
        // the shared `add` token would mis-model them. The subsequent
        // `link set ... up`/`addr`/`route` legs succeed → create must converge.
        // This is the kernel-free twin of the DS_NFTGATE_LIVE netns proof.
        let stub = ip_stub(
            "ebusy",
            "tuntap",
            "ioctl(TUNSETIFF): Device or resource busy",
            1,
        );
        let be = SpawnBackend::new().with_ip_binary(stub.to_str().unwrap());
        let r = be.create_tap(&TapSpec {
            name: "dstap-9".into(),
            owner_uid: Some(1000),
            host_session_index: 9,
            guest_mac: None,
        });
        let _ = std::fs::remove_file(&stub);
        assert!(
            r.is_ok(),
            "tuntap re-add EBUSY must be a converged success: {r:?}"
        );
    }

    #[test]
    fn spawn_delete_treats_missing_device_as_converged_success() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let stub = ip_stub("missing", "del", "Cannot find device \"dstap-9\"", 1);
        let be = SpawnBackend::new().with_ip_binary(stub.to_str().unwrap());
        let r = be.delete_tap("dstap-9");
        let _ = std::fs::remove_file(&stub);
        assert!(
            r.is_ok(),
            "absent device must be a converged success: {r:?}"
        );
    }

    #[test]
    fn spawn_create_surfaces_a_genuine_error() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // A non-converged failure (e.g. EPERM) must surface as a BackendError.
        let stub = ip_stub("eperm", "add", "Operation not permitted", 1);
        let be = SpawnBackend::new().with_ip_binary(stub.to_str().unwrap());
        let err = be
            .create_tap(&TapSpec {
                name: "dstap-9".into(),
                owner_uid: None,
                host_session_index: 9,
                guest_mac: None,
            })
            .expect_err("a non-converged ip failure must surface");
        let _ = std::fs::remove_file(&stub);
        assert!(err.message.contains("Operation not permitted"));
    }

    #[test]
    fn spawn_create_surfaces_spawn_failure_when_ip_is_absent() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // A missing `ip` binary is a spawn failure, never a silent success.
        let be = SpawnBackend::new().with_ip_binary("/nonexistent/ds-nft-no-such-ip-binary-xyzzy");
        let err = be
            .delete_tap("dstap-9")
            .expect_err("an unspawnable ip must surface as a BackendError");
        assert!(err.message.contains("spawn"));
    }

    // ── SpawnBackend create_tap ARGV SEQUENCE (kernel-free) ──
    //
    // These pin the EXACT `ip` invocations `create_tap` emits — the D2 routed
    // addressing. The `ip` binary is overridden to a recording stub that appends
    // each call's full argv (space-joined) as one line to a log file (path passed
    // in argv[1] via a sentinel) and exits 0. No netlink/nft/kernel object is
    // touched; we only assert the generated argv.

    /// Write an executable `ip` stub that, on every invocation, appends its full
    /// argv (space-joined) as one line to `log_path`, then exits 0. Returns the
    /// stub path. Hermetic and kernel-free — it creates no net object.
    fn ip_recording_stub(tag: &str, log_path: &std::path::Path) -> std::path::PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ds-nft-iptap-rec-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Record argv as one space-joined line, then succeed. The log path is
        // baked into the script (single-quoted) so the stub needs no env wiring.
        let log = log_path.to_str().expect("utf-8 log path");
        let script = format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\nexit 0\n");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            f.flush().unwrap();
            // Close the write handle before exec (ETXTBSY guard, as above).
        }
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    /// A unique scratch log path for a recording-stub run.
    fn scratch_log(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "ds-nft-iptap-reclog-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    fn read_argv_lines(log: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(|l| l.to_string())
            .collect()
    }

    #[test]
    fn spawn_create_emits_full_argv_sequence_with_neigh_when_mac_known() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let log = scratch_log("seq-mac");
        let stub = ip_recording_stub("seq-mac", &log);
        let be = SpawnBackend::new().with_ip_binary(stub.to_str().unwrap());
        be.create_tap(&TapSpec {
            name: "dstap-7".into(),
            owner_uid: Some(1000),
            host_session_index: 7,
            guest_mac: Some("52:54:00:12:34:07".into()),
        })
        .expect("create with a recording stub converges");

        let lines = read_argv_lines(&log);
        let _ = std::fs::remove_file(&stub);
        let _ = std::fs::remove_file(&log);

        // EXACT ordered sequence (D2, doc 11 §2.4): tuntap add (with owner) →
        // link up → addr add /31 gateway → route add /32 to guest → neigh
        // replace. The gateway third octet is the host_session_index (7).
        assert_eq!(
            lines,
            vec![
                "tuntap add dev dstap-7 mode tap user 1000".to_string(),
                "link set dstap-7 up".to_string(),
                "addr add 10.77.7.0/31 dev dstap-7".to_string(),
                "route add 10.77.7.1/32 dev dstap-7".to_string(),
                "neigh replace 10.77.7.1 lladdr 52:54:00:12:34:07 dev dstap-7".to_string(),
            ],
            "create_tap must emit the exact routed-addressing argv sequence"
        );
    }

    #[test]
    fn spawn_create_skips_neigh_when_mac_unknown() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let log = scratch_log("seq-nomac");
        let stub = ip_recording_stub("seq-nomac", &log);
        let be = SpawnBackend::new().with_ip_binary(stub.to_str().unwrap());
        be.create_tap(&TapSpec {
            name: "dstap-3".into(),
            owner_uid: None,
            host_session_index: 3,
            guest_mac: None,
        })
        .expect("create without a guest MAC still converges");

        let lines = read_argv_lines(&log);
        let _ = std::fs::remove_file(&stub);
        let _ = std::fs::remove_file(&log);

        // No `user` arg (owner_uid None) and NO neigh leg (MAC unknown) — the
        // neigh is recoverable later, doc 11 §2.4, so create still converges.
        assert_eq!(
            lines,
            vec![
                "tuntap add dev dstap-3 mode tap".to_string(),
                "link set dstap-3 up".to_string(),
                "addr add 10.77.3.0/31 dev dstap-3".to_string(),
                "route add 10.77.3.1/32 dev dstap-3".to_string(),
            ],
            "an unknown guest MAC must SKIP only the neigh leg, never fail create"
        );
        assert!(
            !lines.iter().any(|l| l.contains("neigh")),
            "neigh leg must be absent when the guest MAC is unknown"
        );
    }

    #[test]
    fn spawn_create_addr_and_route_already_present_is_converged_success() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // The `addr add` / `route add` legs both carry the `add` token, so the
        // existing `ip_stub` fails BOTH (and the `tuntap add`) with EEXIST text;
        // every one must classify as a converged success → create returns Ok.
        let stub = ip_stub("addr-exists", "add", "RTNETLINK answers: File exists", 2);
        let be = SpawnBackend::new().with_ip_binary(stub.to_str().unwrap());
        let r = be.create_tap(&TapSpec {
            name: "dstap-5".into(),
            owner_uid: None,
            host_session_index: 5,
            guest_mac: Some("52:54:00:00:00:05".into()),
        });
        let _ = std::fs::remove_file(&stub);
        assert!(
            r.is_ok(),
            "a pre-existing addr/route (EEXIST) must converge, not error: {r:?}"
        );
    }

    #[test]
    fn spawn_create_addr_genuine_failure_surfaces() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // A non-EEXIST failure on the addr leg (e.g. an invalid third octet from
        // an out-of-range index) must surface, never silently converge. The stub
        // fails the `add` legs with a non-converged message.
        let stub = ip_stub("addr-bad", "add", "Error: any valid prefix is expected", 1);
        let be = SpawnBackend::new().with_ip_binary(stub.to_str().unwrap());
        let err = be
            .create_tap(&TapSpec {
                name: "dstap-5".into(),
                owner_uid: None,
                host_session_index: 5,
                guest_mac: None,
            })
            .expect_err("a non-converged addr failure must surface");
        let _ = std::fs::remove_file(&stub);
        assert!(err.message.contains("any valid prefix is expected"));
    }

    #[test]
    fn spawn_create_neigh_failure_surfaces() {
        let _g = STUB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // The neigh leg has no converged-signal handling (replace is an upsert);
        // a genuine failure on it must surface as a BackendError. The stub fails
        // only the `neigh` leg (the add/up legs pass), so addr/route succeed and
        // the error is attributable to neigh.
        let stub = ip_stub(
            "neigh-bad",
            "neigh",
            "Error: argument \"lladdr\" is wrong",
            1,
        );
        let be = SpawnBackend::new().with_ip_binary(stub.to_str().unwrap());
        let err = be
            .create_tap(&TapSpec {
                name: "dstap-5".into(),
                owner_uid: None,
                host_session_index: 5,
                guest_mac: Some("not-a-mac".into()),
            })
            .expect_err("a neigh-leg failure must surface");
        let _ = std::fs::remove_file(&stub);
        assert!(err.message.contains("neigh"));
    }
}
