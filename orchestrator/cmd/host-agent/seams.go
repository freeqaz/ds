// SPDX-License-Identifier: Apache-2.0

// seams.go — the daemon composition root's OFFLINE / DEFERRED seam bindings for
// the M0 create/destroy path. These are the production seam choices the §4.1
// create choreography (internal/hypervisor/libvirt) and the §4.2 destroy ordering
// invoke but whose REAL bodies have not yet landed: chiefly the identity-D22 CA
// fetch + libguestfs overlay trust-store write. (The libvirt DomainDestroyer real
// body HAS landed — libvirt/destroyer_libvirt.go, selected by the gate-aware
// libvirt.NewDomainDestroyer, so it is no longer a stand-in here. So has the
// Boundary-owned tap/NFT primitive: it lives BEHIND A PROCESS BOUNDARY as the
// setcap'd `ds-nethelper` the unprivileged agent forks per op — D148,
// nethelperseams.go — so the SELECTORS here re-key onto that helper client rather
// than the cgo build-tag const the agent no longer carries.)
//
// Each binding here is the SAME no-touch posture the package's offline OverlayStore
// / Booter take (libvirt/offline.go): with DS_HOSTAGENT_LIVE unset (the default,
// and the only path in the sandbox / CI / unit tests) the daemon builds and serves
// the frozen HypervisorDriverService over these stand-ins — no ds-nft, no
// libvirt-go, no libguestfs, no identity service, no live VM/KVM/sudo. They are
// the deferred-binding seams the wave threads forward; when the real host-side
// bodies land they replace these in the composition root WITHOUT touching the
// driver (the seam interfaces are byte-stable).
//
// The RoutabilityGate is the ONE binding here that is NOT a pure stub: its
// PolicyFresh half ties to the ALREADY-LANDED POL-4 freshness (the ApplyCoordinator's
// host-applied seq vs the staleness floor), so a host that has never applied a
// verified snapshot is correctly NON-routable (D72/D36). The DigestAcked half is
// the host-side digest-ack fan-out (D73/D109) and is deferred — under the offline
// default it acks structurally so the M0 create path can complete; the real
// session-scoped ack lands host-side.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nethelper/nethelperclient"
)

// newGatedCAInjector builds the production CAInjector gate-aware, with the fetch
// SOURCE and the overlay WRITER going real in LOCKSTEP under DS_HOSTAGENT_LIVE: the
// host-readable per-session CA store (libvirt.NewFileCABundleSource — the orchestrator
// drops the minted interception-CA PEM keyed by caBundleRef; the host-agent reads it,
// never re-mints) + the libguestfs overlay trust-store write
// (libvirt.NewLiveTrustStoreWriter). Off the gate it uses the offline stand-ins below
// (a synthetic CA + a no-touch writer) so the fail-closed step-7 contract stays
// provable against fakes (D50). It NEVER pairs a real writer with the placeholder
// source — that would virt-customize a fake CA into a real overlay (a guest trusting a
// non-existent root, note 01KV6FW5T7) — so both seams flip on the one gate together.
func newGatedCAInjector(cfg libvirt.LiveConfig) (libvirt.CAInjector, error) {
	if !libvirt.LiveEnabled() {
		return libvirt.NewCAInjector(deferredCABundleSource{}, deferredTrustStoreWriter{})
	}
	// MVP NO-CA-INJECT posture (DS_HOSTAGENT_SKIP_CA_INJECT=1, maintainer-approved, single-box):
	// pair the SYNTHETIC-CA source (a parseable throwaway placeholder, the SAME offline
	// stand-in used off the gate) with the NO-OP overlay writer, so step-7 neither requires a
	// pre-dropped per-session PEM nor shells out to libguestfs (virt-customize/virt-cat) to
	// write the trust anchor into the guest overlay. This is needed on a host WITHOUT
	// libguestfs-tools, and is CORRECT under the MVP's SLIRP-direct egress: there is no
	// ds-tlsproxy interception, so the per-session interception CA is non-load-bearing and need
	// not enter the guest trust store (the proven manual boot path injects no CA either). It is
	// SAFE precisely because the writer is a no-op: nothing fake is written into a real overlay
	// (the footgun newGatedCAInjector guards against — a real writer + a placeholder source).
	// The CloneFromImage handler ALSO defaults an empty ca_bundle_ref under this gate (the
	// canonical §4.1 spine mints the CA at step 5, AFTER the step-4 clone, so it sends no ref on
	// the clone request — service.go), so the fail-closed VALIDATE is satisfied without a spine
	// reorder. Gate UNSET keeps the production FileCABundleSource + libguestfs overlay write.
	if os.Getenv("DS_HOSTAGENT_SKIP_CA_INJECT") == "1" {
		return libvirt.NewCAInjector(deferredCABundleSource{}, deferredTrustStoreWriter{})
	}
	source, err := libvirt.NewFileCABundleSource(cfg.OverlayDir)
	if err != nil {
		return nil, fmt.Errorf("live CA bundle source: %w", err)
	}
	writer, err := libvirt.NewLiveTrustStoreWriter()
	if err != nil {
		return nil, fmt.Errorf("live trust-store writer: %w", err)
	}
	return libvirt.NewCAInjector(source, writer)
}

// ── Deferred: the Boundary-owned tap/NFT primitive (ds-nft staticlib) ─────────

// deferredAttach is the offline AttachPrimitive stand-in (libvirt.AttachPrimitive,
// seams.go). The REAL body is the Boundary-owned tap-create + per-session NFT
// instantiation, the SINGLE writer of tap/nft objects (doc 14 §4) — it now lives
// BEHIND A PROCESS BOUNDARY: the setcap'd `ds-nethelper` privileged helper the
// unprivileged agent forks per op (D148; helperAttach in nethelperseams.go). This
// no-touch stand-in remains the selection whenever the host is offline OR no helper
// is configured — it programs nothing in the kernel, exactly the libvirt/offline.go
// posture. Every method is idempotent on the session by construction (it does
// nothing), matching the seam's idempotency contract so a create/rollback retry
// converges.
type deferredAttach struct{}

func (deferredAttach) CreateTap(_ context.Context, _ libvirt.Binding) error { return nil }

func (deferredAttach) InstantiateSessionNFT(_ context.Context, _ string, _ libvirt.Binding) error {
	return nil
}

func (deferredAttach) FlushSession(_ context.Context, _ string, _ libvirt.Binding) error { return nil }

// newAttachPrimitive selects the AttachPrimitive: the real helper-backed
// helperAttach (nethelperseams.go — a fork of the setcap'd `ds-nethelper` per
// privileged op, D148) ONLY when the host is live AND a helper client was
// constructed (-nethelper-path / DS_NETHELPER_PATH resolved AND its bring-up
// probe passed, main.go); otherwise the no-touch deferredAttach.
//
// This REPLACES the old (LiveEnabled && nftbridge.Built) key. The host agent no
// longer links the ds-nft cgo edge at all — it builds untagged forever and runs
// unprivileged, so nftbridge.Built would be permanently false here and the live
// path would silently never arm (the trap nftgatelive_refuse.go makes a compile
// error). A nil client is the honest "no privileged edge configured" answer and
// keeps the daemon cgo-free + serving offline (D50/D80), matching the gate-aware
// CAInjector/booter composition the rest of main.go uses.
func newAttachPrimitive(c *nethelperclient.Client) libvirt.AttachPrimitive {
	if libvirt.LiveEnabled() && c != nil {
		return helperAttach{c: c}
	}
	return deferredAttach{}
}

// ── Host-WIDE boundary-readiness gate (pre-step-4 admission, D63/D69/D70) ──────

// newBoundaryReadiness selects the host-WIDE BoundaryReadiness precondition
// (libvirt.BoundaryReadiness, seams.go): the real live probe (libvirt.NewBoundaryReadiness
// ⇒ liveReadiness — the three boundary nft tables present via a read-only `nft list` +
// ds-dnsgate/ds-tlsproxy answering via a TCP dial) ONLY when the host is live AND a
// `ds-nethelper` client was constructed; otherwise the no-touch deferredReadiness
// (always-ready). It MIRRORS newAttachPrimitive's live-vs-deferred selection: a host with
// no privileged edge configured has no per-session boundary to admit against, so the
// deferred always-ready stand-in is correct there. Off the gate the create path stays
// byte-identical to today (no kernel/socket touch).
//
// THE RE-KEY (D148, README "Readiness Re-Key"). The old key was
// (LiveEnabled && nftbridge.Built). With the cgo edge relocated into the helper the host
// agent builds UNTAGGED forever, so nftbridge.Built is permanently false in this binary and
// that key would silently never arm the live gate. The new key is the helper client, and it
// is DOUBLE-keyed: main.go refuses bring-up unless the helper's probe reports the full
// `+eip` posture (verifyHelperReady), and the returned gate is additionally wrapped in
// helperProbeReadiness so a helper that LOSES its capability mid-run (the rebuilt-binary /
// xattr-loss footgun) is caught per admission, not at the first create.
//
// A construction error under the gate (an empty ds-dnsgate / ds-tlsproxy addr, or an empty
// required-table set) is FATAL — the daemon refuses the live path rather than serving with a
// vacuously-passing gate (the SAME fail-closed posture as newAdmissionSegment: never a
// silently always-ready live gate). The caller surfaces it as a bring-up refusal.
func newBoundaryReadiness(cfg libvirt.LiveReadinessConfig, c *nethelperclient.Client) (libvirt.BoundaryReadiness, error) {
	if !(libvirt.LiveEnabled() && c != nil) {
		return deferredReadiness{}, nil
	}
	// D148: route the table-presence half through the HELPER. The agent runs
	// unprivileged, and libvirt's default runner execs `nft list` in-process —
	// which needs CAP_NET_ADMIN just to initialise its netlink cache, so it would
	// report every floor table absent and refuse EVERY CreateSession while the
	// helper's own probe passed. We are on the c != nil branch, so the helper is
	// exactly what holds the capability. Injected here rather than at the call
	// site because this is the one place that already decides "helper-backed".
	if cfg.TableRunner == nil {
		cfg.TableRunner = c.TablePresent
	}
	inner, err := libvirt.NewBoundaryReadiness(cfg)
	if err != nil {
		return nil, err
	}
	return helperProbeReadiness{c: c, inner: inner}, nil
}

// deferredReadiness is the daemon-root no-touch BoundaryReadiness stand-in: Probe is
// always-ready, touching no kernel object and no socket, so the daemon's create path off the
// live cgo gate is byte-identical to today (symmetric with deferredAttach). It is the gate-off
// selection in newBoundaryReadiness; the package-internal libvirt deferredReadiness is the
// gate-off selection inside libvirt.NewBoundaryReadiness, so an offline daemon never probes
// regardless of which path constructs the seam.
type deferredReadiness struct{}

func (deferredReadiness) Probe(_ context.Context) (bool, string, error) {
	return true, "deferred (offline)", nil
}

// ── Host-owned DNS-2b shm admission-map segment lifecycle (T4, D131) ──────────

// newAdmissionSegment selects the host-agent-owned DNS-2b shm admission-map segment
// lifecycle: the real POSIX-shm create/unlink (libvirt.NewAdmissionSegment ⇒
// liveAdmissionSegment) when DS_HOSTAGENT_LIVE=1, the no-touch stand-in off the gate
// — same gate-aware factory pattern as newGatedCAInjector / newAttachPrimitive, so the
// composition root wires the create-at-bring-up / unlink-at-teardown calls without
// touching the driver. The segment name is single-sourced via libvirt.AdmissionShmName()
// (DS_ADMISSION_SHM_NAME || /ds-admission), agreeing with the ds-dnsgate writer and the
// ds-tlsproxy reader so the host creates the SAME object they attach to. A construction
// error under the gate (e.g. a malformed name override, or a non-Linux host where POSIX
// shm is unsupported) is FATAL — the daemon refuses the live path rather than serving
// with no host-owned segment (docs/sessions/13 §Rollout-ordering, fail-closed).
func newAdmissionSegment(cfg libvirt.LiveConfig) (libvirt.AdmissionSegment, error) {
	return libvirt.NewAdmissionSegment(cfg)
}

// ── Deferred: durability finalize + flow-byte accounting (§4.2 steps 2–3) ─────

// deferredDurability is the offline DurabilityFinalizer stand-in
// (libvirt.DurabilityFinalizer). The REAL body closes the D29 dirty-bitmap
// durability stream over the per-session overlay at teardown; it lands host-side
// with the live overlay substrate. Offline (no overlay was created on disk) there
// is no stream to finalize — a no-op success, the seam's documented contract.
//
// TODO(host-side): replace with the qcow2 dirty-bitmap stream finalize, gated with
// the live OverlayStore.
type deferredDurability struct{}

func (deferredDurability) FinalizeDurabilityStream(_ context.Context, _, _ string) error {
	return nil
}

// deferredFlowBytes is the offline FlowByteCounter stand-in (libvirt.FlowByteCounter).
// The REAL body reads the per-session conntrack-by-mark final byte counts and emits
// them into ds-flowlog at teardown (doc 14 §5); it lands through the same ds-nft
// edge flush_session rides. Emitting the counts is NON-FATAL to teardown by
// contract, so the offline no-op (nothing to count without the live NFT path)
// never strands a teardown.
//
// TODO(ds-nft staticlib, host-side): replace with the conntrack-by-mark read +
// ds-flowlog emit, alongside the real AttachPrimitive.
type deferredFlowBytes struct{}

func (deferredFlowBytes) EmitDestroyByteCounts(_ context.Context, _ string, _ libvirt.Binding) error {
	return nil
}

// ── Deferred: the identity-D22 CA fetch + overlay trust-store write (step 7) ──

// deferredCABundleSource is the offline CABundleSource stand-in
// (libvirt.CABundleSource). The REAL body fetches the per-session interception-CA
// bundle minted by Identity's D22 service under the interception root hierarchy
// (D82) — a proto/secret-store read that lands when that contract is wired. Offline
// it returns a synthetic, NON-secret placeholder PEM so the fail-closed step-7
// injection has a non-empty bundle to write through the offline trust-store writer;
// the bytes are a fixed marker, never a real key, and never logged.
//
// TODO(identity-D22, host-side): replace with the real per-session interception-CA
// fetch by caBundleRef.
type deferredCABundleSource struct{}

// placeholderCAPEM is a fixed, NON-SECRET, throwaway self-signed CA certificate
// the offline/stub path injects so the fail-closed step-7 contract has a real
// trust anchor. It MUST be a PARSEABLE CA cert (BasicConstraints CA:TRUE), not a
// mere non-empty marker: the production CAInjector (cainject.go) validates the
// bundle with crypto/x509 and derives its SHA-256 fingerprint BEFORE the
// trust-store write, so a non-parseable blob fails closed at step 7 and no
// session ever boots (a live full-lifecycle e2e — taskdb 01KV6PDSEF — caught the
// earlier malformed marker doing exactly that). This cert carries NO usable key
// off this stub and never rides a live TLS path (the deferred trust-store writer
// touches nothing real); the REAL per-session interception CA fetch lands with
// the host-agent CAInjector assembly (01KV639F, gated on the caBundleRef
// resolution decision).
const placeholderCAPEM = `-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIUXXSl/V2Y4jVy6FkNJMB1eT9vxD0wDQYJKoZIhvcNAQEL
BQAwSTEvMC0GA1UEAwwmZHMtb2ZmbGluZS1wbGFjZWhvbGRlci1pbnRlcmNlcHRp
b24tQ0ExFjAUBgNVBAoMDWRyZWFtLXNlcnBlbnQwHhcNMjYwNjE1MjIzNTI2WhcN
MzYwNjEyMjIzNTI2WjBJMS8wLQYDVQQDDCZkcy1vZmZsaW5lLXBsYWNlaG9sZGVy
LWludGVyY2VwdGlvbi1DQTEWMBQGA1UECgwNZHJlYW0tc2VycGVudDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOJVSb4WPmqkObFPg60EPsAupQevylIT
Gl1q78NoJQ6tQbKrTjiA+JL75A0JT03jINQikBT6mJZcdBgyoi8pzK9NnitQXYeX
7pl02G/EGLGIA417R0a4sFuQpjEZ2uAyQrDWC9jPrELFa8+jTqGI0xm+hbyyVwSO
xANFohGdrwYKVFweoDSVVdG8uMq5M1DzhH3zrw45TJKZtK6w+ssOXE3mhNT/A5gs
qTk7mwEK+fVkZ0IH8zrcVSXilTFRaazSx3ILhF/I8ZS27qZm6U1/lJCuyz2i5Nsr
YsNU1mDITQGjkLHcZXcsGu1kpL41yK0nWiuhCgtzSKvUM43b/d9wEtMCAwEAAaNT
MFEwHQYDVR0OBBYEFLdNS5pAzySwTuG1/Ok9of5XA/z4MB8GA1UdIwQYMBaAFLdN
S5pAzySwTuG1/Ok9of5XA/z4MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBADaFzPb/lptIRCAmo/eosbMLJkiq7aKPkf5rAHDjEnK1sBJQf4dXpmEA
qDcomm8CIfK2Jun6oFj9P4dpzpy953BaTcmsfnXtTuLLOSNUT0puvbYU+1w3cR6i
2grmpcHxJoUPioOWDHfnONRRS000fMDigJ/Kxa8zmDFuuCnrzteQR1KO3TKPrOD+
OZ6LD8+MPMKdfHWJarxZysph86EFFBbLsWrATHVk7qnu47v4dPIl3volYjR0pmx5
0IAMKxxX1zkeQcEJqLDvkoG58JpcM7TnOiijPSNSxAHbqEkS81eNrnh8ww0qH3LC
SmE0qnePYtIL9QM0WcYnHyedA2Aq1ns=
-----END CERTIFICATE-----
`

func (deferredCABundleSource) FetchCABundle(_ context.Context, caBundleRef string) ([]byte, error) {
	if caBundleRef == "" {
		// Fail closed: no ref ⇒ no provable trust anchor (the seam's contract; the
		// driver maps this to an InvalidArgument create refusal, D17).
		return nil, fmt.Errorf("offline CA bundle source: empty ca_bundle_ref (fail-closed, D17)")
	}
	return []byte(placeholderCAPEM), nil
}

// deferredTrustStoreWriter is the offline OverlayTrustStoreWriter stand-in
// (libvirt.OverlayTrustStoreWriter). The REAL body writes the verified
// interception-CA PEM into the per-session qcow2 overlay's trust store host-side
// (a libguestfs write or an in-guest provisioning hand-off — cainject.go's TODO);
// pulling that in here would break the stdlib-only + offline posture. Offline it
// records the anchor in-memory keyed on (session, overlay) so the injector's
// fail-closed VERIFY (HasTrustAnchor after WriteTrustAnchor) passes — proving the
// step-7 fail-closed contract end to end against fakes (D50) without touching a
// real overlay. Idempotent on (sessionUUID, overlayPath): a retry re-writes the
// same single anchor.
//
// TODO(host-side, operator box): replace with the libguestfs overlay trust-store
// write, gated with the live OverlayStore.
type deferredTrustStoreWriter struct{}

func (deferredTrustStoreWriter) WriteTrustAnchor(_ context.Context, _, overlayPath string, caPEM []byte) error {
	if overlayPath == "" {
		return fmt.Errorf("offline trust-store writer: empty overlay path (step 7 ≺ step 8)")
	}
	if len(caPEM) == 0 {
		return fmt.Errorf("offline trust-store writer: empty CA PEM (fail-closed, D17)")
	}
	// No-touch: nothing is written to a real overlay offline; the injector's
	// fail-closed VERIFY is satisfied by HasTrustAnchor below returning true once
	// a non-empty write has been requested.
	return nil
}

func (deferredTrustStoreWriter) HasTrustAnchor(_ context.Context, _, overlayPath, _ string) (bool, error) {
	// Offline: a write of the placeholder anchor always "lands" (no real store), so
	// the fail-closed VERIFY after WriteTrustAnchor proceeds. With no overlay path
	// there is nothing to check.
	return overlayPath != "", nil
}

// ── POL-4-backed RoutabilityGate (the one non-stub binding) ───────────────────

// pol4Gate is the production RoutabilityGate (libvirt.RoutabilityGate) over the
// ALREADY-LANDED POL-4 freshness: PolicyFresh ties to the host's applied policy
// version (the ApplyCoordinator's host-applied seq, advanced post-sweep, D72), so
// a host that has not yet applied a verified snapshot is correctly NON-routable
// (the step-3/step-9 staleness floor, D36). The DigestAcked half is the host-side
// digest-ack fan-out (D73/D109) and is DEFERRED — offline it acks structurally so
// the M0 create path can complete; the real session-scoped ack lands host-side.
//
// A non-routable verdict is NOT a create error (the §4.1 precedence): the binding
// is still recorded and the response carries it; the reconciler decides whether to
// wait for freshness. So a freshly-booted host that has not yet applied a snapshot
// still produces a recorded binding — it just is not marked routable until POL-4
// has applied a verified policy.
type pol4Gate struct {
	// coord is the landed POL-4 two-phase ApplyCoordinator; HasApplied reports
	// whether the host has committed at least one verified snapshot (the host stays
	// default-deny / non-routable until its first applied policy, D72).
	coord *hostagent.ApplyCoordinator
}

// newPOL4Gate ties the RoutabilityGate to the landed POL-4 ApplyCoordinator. A nil
// coordinator is a programming error surfaced at construction (the NewHostAgent
// nil-dependency posture), never a silent always-fresh gate.
func newPOL4Gate(coord *hostagent.ApplyCoordinator) (libvirt.RoutabilityGate, error) {
	if coord == nil {
		return nil, fmt.Errorf("POL-4 routability gate requires the host apply coordinator")
	}
	return &pol4Gate{coord: coord}, nil
}

// DigestAcked is the deferred host-side digest-ack fan-out (D73/D109). Offline it
// acks structurally so the M0 create choreography can reach the routable gate; the
// real session-scoped ack (the mint-before-attach write, doc 14 §7) lands host-side.
//
// TODO(host-side, D73/D109): replace with the per-session digest-ack observation.
func (g *pol4Gate) DigestAcked(_ context.Context, _ string) (bool, error) {
	return true, nil
}

// PolicyFresh ties to the landed POL-4 freshness: the host is fresh once it has
// applied at least one verified snapshot through the two-phase barrier (D72). A
// host that has never applied a policy is NON-fresh — it stays default-deny and a
// placed session on it is not routable until POL-4 catches up (D36).
func (g *pol4Gate) PolicyFresh(_ context.Context) (bool, error) {
	return g.coord.HasApplied(), nil
}

// ── RESERVED (post-M0): the host-local HandleStore → libvirt SessionRecoverer
// bridge ──────────────────────────────────────────────────────────────────────
//
// RecoverSessions (the crash-matrix restart re-adoption, D66) is host-side and is
// NOT in the M0 create/destroy scope, so this daemon builds the driver via the
// no-recovery NewDriverService path — RecoverSessions answers an honest
// codes.Unimplemented (the same posture as the other host-side-only verbs).
//
// When restart re-adoption lands, the bridge is a TRIVIAL one-directional projection
// the import-cycle constraint mandates here in the composition root (the libvirt
// driver must NOT import hostagent — hostagent already imports libvirt for the
// Destroyer): read hostagent.PersistedHandle from the host-local hostagent.HandleStore
// (recover.go), re-derive the per-session guest IP from the never-recycled index over
// the host AddressPlan (Binding.validate requires a well-formed family-tagged guest
// IP), and lower each into a libvirt.RecoveredSession. The daemon would then build via
// NewDriverServiceWithRecovery(host, destroy, bridge, counter) sharing the persistent
// counter so a re-seed advances the very counter the next clone draws from.
//
// TODO(host-side, D66): wire the HandleStore → SessionRecoverer bridge +
// NewDriverServiceWithRecovery when restart re-adoption lands.
