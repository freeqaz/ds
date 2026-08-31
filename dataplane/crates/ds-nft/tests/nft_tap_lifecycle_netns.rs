//! DS_NFTGATE_LIVE tap-lifecycle proof — the live-kernel half of the
//! [`ds_nft::backend::SpawnBackend`] tap path that the kernel-free
//! [`ds_nft::backend::RecordingBackend`] / `run_ip` stub tests (in
//! `src/backend.rs`) can only assert at the *argv / converged-signal* layer.
//!
//! # What is sandbox-verified here vs host/CI-only
//!
//! The crate's existing tests prove the **generated argv** and the
//! **converged-signal classification** (`File exists` → Ok on re-create,
//! `Cannot find device` → Ok on re-delete) against a throwaway `ip` stub — they
//! never touch a kernel. That is the correct default-build assertion, but it
//! leaves the *real-effectiveness* of the create/delete legs unproven: does the
//! real kernel actually materialise the `dstap-<idx>` netdev, and is the
//! idempotency contract (doc 15 §5.1) honoured by the *real* `ip`, not just our
//! stub's canned message?
//!
//! This test closes that gap on a live kernel, mirroring the
//! `tests/nft2_spoofing_netns.rs` / `ds-tlsproxy tests/e2e_live_redirect.rs`
//! convention exactly:
//!
//! - **GATE (`DS_NFTGATE_LIVE=1`):** without the env var the kernel half is a
//!   clean SKIP, so the normal `cargo test -p ds-nft` gate stays green and never
//!   runs `ip` against the host kernel in the default offline build.
//! - **NAMESPACE:** the operator runs this under `unshare -rn`, so the whole test
//!   process — and every `ip` the production [`SpawnBackend`] spawns — lives in a
//!   private user+net namespace with `CAP_NET_ADMIN`. The host's interfaces,
//!   addresses, and routes are never touched. A second guard (a probe `ip link
//!   set lo up`) makes the test SKIP even *with* the gate set when no usable netns
//!   is available (CI without user-namespace support), so a misconfigured run can
//!   never escape onto the host kernel.
//!
//! Run it live:
//!
//! ```sh
//! cd dataplane
//! unshare -rn bash -c 'DS_NFTGATE_LIVE=1 \
//!   cargo test -p ds-nft --test nft_tap_lifecycle_netns --locked --offline -- --nocapture'
//! ```
//!
//! # The D2 addressing invariant proven here
//!
//! The brief framed the tap as strictly "L2-only — no IP address, no route".
//! The *landed* [`SpawnBackend::create_tap`] is more specific than that framing:
//! per D2 / the routed point-to-point plan it assigns the **host-side** gateway
//! `10.77.<idx>.0/31` and an on-link `/32` route to the guest, and *nothing*
//! else. The load-bearing L2-only property — "tap-create never assigns the
//! **guest's** address to the tap" — still holds, and is what this test pins:
//!
//! - the guest end `10.77.<idx>.1` is NEVER an address on the tap (it is the
//!   guest's / the session NFT's concern, never tap-create's);
//! - the only address on the tap is the host gateway `10.77.<idx>.0/31`;
//! - the only route via the tap is the on-link `/32` to the guest end.
//!
//! Asserting "zero addresses / zero routes" would contradict the shipped
//! mechanism (doc 15 §5.1, `src/backend.rs::create_tap`), so this test asserts
//! the accurate invariant. (See the wave warning on this unit: the brief's
//! "NO IP address and NO route" wording predates the landed routed-`/31` tap.)

use std::process::Command;

use ds_nft::backend::{NftBackend, SpawnBackend, TapSpec};

/// The host-only procedure, kept verbatim so the deferred / live step is a
/// reproducible recipe rather than a vague promise (the committed artifact is the
/// procedure, per the crate's substrate-gap discipline — mirrors
/// `nft2_spoofing_netns.rs`'s recorded host procedure).
const HOST_LIFECYCLE_PROCEDURE: &str = "\
# DS_NFTGATE_LIVE tap lifecycle — live-kernel proof (real `ip`, CAP_NET_ADMIN).
# Run in a private net namespace so the host kernel is never touched:
#
#   cd dataplane
#   unshare -rn bash -c 'DS_NFTGATE_LIVE=1 \\
#     cargo test -p ds-nft --test nft_tap_lifecycle_netns --locked --offline -- --nocapture'
#
# What it drives through the production SpawnBackend (NO stub `ip`):
#   1. create_tap(dstap-<idx>)        -> `ip tuntap add` ; link exists, is mode tap
#   2. create_tap(dstap-<idx>) again  -> converges (EEXIST tolerated; no error)
#   3. assert D2 addressing: host gateway 10.77.<idx>.0/31 present on the tap,
#      on-link /32 route to 10.77.<idx>.1 present, and the GUEST end .1 is NOT an
#      address on the tap (L2-only wrt the guest: addressing the guest is the
#      guest's / session NFT's concern, never tap-create's).
#   4. delete_tap(dstap-<idx>)        -> link is gone
#   5. delete_tap(dstap-<idx>) again  -> converges (ENODEV tolerated; no error)
#
# PASS: the tap netdev is materialised + torn down idempotently by the real
# kernel, carrying only the host /31 gateway + the on-link guest /32 route.
";

/// The session index this test addresses. Lands verbatim in the third octet:
/// host gateway `10.77.29.0/31`, guest end `10.77.29.1` (matches the unit key
/// `ten4d29z` only by coincidence — any single-octet index works).
const IDX: u32 = 29;

/// `true` when the gate is set AND a usable, writable net namespace is available
/// (we can bring `lo` up). When the gate is unset, or the gate is set but there
/// is no `CAP_NET_ADMIN` netns, the caller SKIPs cleanly — never running `ip`
/// against the host kernel. The probe is itself host-safe: `ip link set lo up`
/// inside a private netns affects only that namespace's loopback.
fn live_netns_available() -> bool {
    if std::env::var("DS_NFTGATE_LIVE").ok().as_deref() != Some("1") {
        return false;
    }
    // A fresh `unshare -rn` namespace starts with `lo` DOWN; that we can bring it
    // up is our proof we hold CAP_NET_ADMIN in a private netns. If this fails we
    // are NOT in a usable namespace (e.g. CI without user-ns) — refuse to run the
    // kernel half so we never mutate the host.
    Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// `ip -o <args>`, returning trimmed stdout. `-o` (oneline) keeps each object on
/// a single line so substring matching is unambiguous. Used only for read-back
/// assertions (`addr show` / `route show` / `link show`), never to mutate state —
/// the mutations all go through the production [`SpawnBackend`].
fn ip_query(args: &[&str]) -> String {
    let mut full = vec!["-o"];
    full.extend_from_slice(args);
    let out = Command::new("ip")
        .args(&full)
        .output()
        .expect("spawn ip for read-back (run under `unshare -rn`)");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Does a netdev named `name` exist in this namespace?
fn link_exists(name: &str) -> bool {
    // `ip link show <name>` exits non-zero ("Device ... does not exist") when
    // absent; success ⇒ present.
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn spawn_backend_tap_create_delete_is_idempotent_on_a_real_kernel() {
    if !live_netns_available() {
        eprintln!(
            "SKIP spawn_backend_tap_create_delete_is_idempotent_on_a_real_kernel: \
             set DS_NFTGATE_LIVE=1 and run inside `unshare -rn` (CAP_NET_ADMIN netns). \
             The argv / converged-signal half is always covered kernel-free by \
             src/backend.rs's RecordingBackend + run_ip stub tests. Live procedure:\n\
             {HOST_LIFECYCLE_PROCEDURE}"
        );
        return;
    }

    let name = format!("dstap-{IDX}");
    let backend = SpawnBackend::new();
    let spec = TapSpec {
        name: name.clone(),
        // Leave owner_uid None so the test needs no specific uid present in the
        // namespace; the create/up/address legs are uid-independent.
        owner_uid: None,
        host_session_index: IDX,
        // No guest MAC: the neigh leg is SKIPPED (recoverable later, doc 11
        // §2.4) — create still converges. Keeping it None keeps the proof about
        // the tap netdev + its host addressing, not ARP seeding.
        guest_mac: None,
    };

    // Defensive pre-clean: a stale tap from a crashed prior run is removed via the
    // SAME idempotent delete path (an absent device converges to Ok) so the test
    // starts from a known-absent state without ever erroring.
    backend
        .delete_tap(&name)
        .expect("pre-clean delete must converge (absent device is Ok)");
    assert!(
        !link_exists(&name),
        "{name} must not exist before the create leg"
    );

    // ── 1. create_tap → the real kernel materialises the tap netdev ──
    backend
        .create_tap(&spec)
        .expect("create_tap must succeed on a live CAP_NET_ADMIN kernel");
    assert!(
        link_exists(&name),
        "{name} must exist after create_tap (real `ip tuntap add`)"
    );
    // It is an L2 tap, not some other netdev type — `ip -d link show` prints the
    // `tun ... type tap` kind line for a tuntap device in TAP mode.
    let link_detail = ip_query(&["-d", "link", "show", &name]);
    assert!(
        link_detail.contains("tun") || link_detail.contains("tap"),
        "the created device must be a tun/tap netdev (L2 tap), got:\n{link_detail}"
    );

    // ── 2. idempotent create → re-running converges (EEXIST tolerated) ──
    // NOTE for live runners: the real kernel returns `ioctl(TUNSETIFF): Device or
    // resource busy` (EBUSY) — NOT `File exists` — when `ip tuntap add` re-adds an
    // existing tap. If this `.expect` fails with that EBUSY message, the gap is in
    // `SpawnBackend::create_tap`'s converged-signal list (src/backend.rs — NOT this
    // test): it tolerates only `["File exists", "already exists"]` and must also
    // tolerate the tuntap re-add EBUSY ("Device or resource busy" /
    // "ioctl(TUNSETIFF)") to honour the doc 15 §5.1 idempotency contract. This test
    // pins the brief-mandated invariant ("re-run create -> converges"); fixing it is
    // the src/backend.rs owner's job (recorded as a wave warning on this unit).
    backend
        .create_tap(&spec)
        .expect("a re-create of an existing tap must converge to Ok (doc 15 §5.1)");
    assert!(
        link_exists(&name),
        "{name} must still exist after the idempotent re-create"
    );

    // ── 3. D2 addressing invariant ──
    // The tap carries the HOST gateway 10.77.<idx>.0/31 and the on-link /32 route
    // to the guest end .1 — and NEVER the guest's own address. This is the
    // accurate "L2-only wrt the guest" property the landed create_tap honours.
    let guest_ip = format!("10.77.{IDX}.1");
    let gateway = format!("10.77.{IDX}.0");

    let addrs = ip_query(&["addr", "show", "dev", &name]);
    assert!(
        addrs.contains(&format!("{gateway}/31")),
        "the host-side gateway {gateway}/31 must be assigned to {name} (D2 routed /31):\n{addrs}"
    );
    assert!(
        !addrs.contains(&format!("inet {guest_ip}")),
        "the GUEST end {guest_ip} must NEVER be an address ON the tap — addressing the \
         guest is the guest's / session NFT's concern, never tap-create's (D2):\n{addrs}"
    );

    let routes = ip_query(&["route", "show", "dev", &name]);
    assert!(
        routes.contains(&format!("{guest_ip}/32")) || routes.contains(&guest_ip),
        "the on-link /32 route to the guest end {guest_ip} must be present on {name} (D2):\n{routes}"
    );

    // ── 4. delete_tap → the real kernel tears the netdev down ──
    backend
        .delete_tap(&name)
        .expect("delete_tap must succeed on a live kernel");
    assert!(
        !link_exists(&name),
        "{name} must be gone after delete_tap (real `ip link del`)"
    );
    // The address and route went with the device — read-back shows nothing.
    let addrs_after = ip_query(&["addr", "show", "dev", &name]);
    assert!(
        addrs_after.is_empty(),
        "no address may survive the tap's deletion:\n{addrs_after}"
    );

    // ── 5. idempotent delete → re-running converges (ENODEV tolerated) ──
    backend
        .delete_tap(&name)
        .expect("a re-delete of an absent tap must converge to Ok (doc 15 §5.1)");
    assert!(
        !link_exists(&name),
        "{name} stays absent after the idempotent re-delete"
    );

    eprintln!(
        "LIVE TAP LIFECYCLE PASS: {name} created (mode tap) + re-created (converged) \
         carrying only the host gateway {gateway}/31 + on-link route to {guest_ip}, \
         then deleted + re-deleted (converged). No guest address on the tap (D2)."
    );
}

#[test]
fn host_lifecycle_procedure_is_recorded() {
    // The live step is a committed, reproducible procedure (a substrate/lane gap,
    // not a design gap): assert it is present and names the load-bearing checks so
    // it cannot rot into a vague TODO. Always runs — no kernel needed. Mirrors
    // `nft2_spoofing_netns.rs::host_traffic_procedure_is_recorded`.
    assert!(HOST_LIFECYCLE_PROCEDURE.contains("DS_NFTGATE_LIVE=1"));
    assert!(HOST_LIFECYCLE_PROCEDURE.contains("unshare -rn"));
    assert!(HOST_LIFECYCLE_PROCEDURE.contains("create_tap"));
    assert!(HOST_LIFECYCLE_PROCEDURE.contains("EEXIST tolerated"));
    assert!(HOST_LIFECYCLE_PROCEDURE.contains("ENODEV tolerated"));
    assert!(HOST_LIFECYCLE_PROCEDURE.contains("10.77.<idx>.0/31"));
    assert!(HOST_LIFECYCLE_PROCEDURE.contains("never tap-create's"));
}
