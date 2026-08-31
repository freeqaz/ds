// SPDX-License-Identifier: Apache-2.0

// service.go is the production gRPC server binding for the v0 libvirt driver: it
// implements the frozen 10-verb dreamserpent.hypervisor.v1.HypervisorDriverService
// (driver_grpc.pb.go) over the existing host-agent create path (create.go) and
// §4.2 destroy ordering (destroy.go), wiring three verbs fully and returning
// HONEST codes.Unimplemented stubs for the rest.
//
// THE LOAD-BEARING INVARIANT (doc 15 §5.1, §10 / D29/D30): the contract surface
// leaks ZERO QEMU/libvirt specifics. This binding maps ONLY between the frozen
// hypervisor.v1 messages and the in-package driver values (Binding,
// CreateRequest/Result, DestroyRequest) — no libvirt-go domain, no qcow2 detail,
// no QEMU monitor type ever crosses the wire. That keeps the D30 re-evaluation
// seam (Cloud Hypervisor at M3) and the D29 ZFS/dm-thin alternatives clean
// substrate swaps behind this same service.
//
// OFFLINE (doc.go / seams.go deferred-binding posture): the service drives the
// HostAgent/Destroyer through their SEAMS, so the whole binding is buildable and
// testable offline against fakes + an in-process gRPC client (service_test.go) —
// no libvirt-go/cgo/KVM/sudo. The real seam impls (OverlayStore/Booter/
// DomainDestroyer real bodies) land host-side on the virtual-metal box; this
// service is the wire adapter over whatever backs the seams.
//
// Governing decisions: D29, D30, D31, D35, D66, D75. Sources: doc 15 §5.1 +
// proto/dreamserpent/hypervisor/v1/driver.proto.
package libvirt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// DriverService implements the generated HypervisorDriverServiceServer over the
// v0 libvirt driver. It composes the host-agent CREATE path (the step-4–9
// choreography behind CloneFromImage) and the §4.2 DESTROY ordering (behind
// Destroy); GetCapabilities answers the honest libvirt flags statically. The
// remaining 7 verbs return codes.Unimplemented with a TODO naming each one's
// real seam/host-side home — never a faked success (doc 15 §5.1: the capability
// flags and the conformance suite bound driver honesty).
//
// It embeds UnimplementedHypervisorDriverServiceServer for forward compatibility
// (the generated forward-compat contract) — but every verb the M0 contract names
// is OVERRIDDEN below (the three wired, the seven honest-Unimplemented), so the
// embedded defaults are never the live behavior; the embed is purely the
// mustEmbed forward-compat anchor.
type DriverService struct {
	hypervisorv1.UnimplementedHypervisorDriverServiceServer

	create  *HostAgent
	destroy *Destroyer

	// recover re-observes host-resident sessions across a restart (the
	// crash-matrix re-adoption leg, doc 15 §4; D66). It is OPTIONAL: a service
	// built without one (NewDriverService) answers RecoverSessions with an honest
	// codes.Unimplemented — the real re-observation lands host-side. A service
	// built WITH one (NewDriverServiceWithRecovery) re-seeds the Allocator + the
	// clone cache from what it observes. Nil ⇒ unwired ⇒ honest Unimplemented.
	recover SessionRecoverer
	// counter is the SAME persistent index counter the create-path Allocator
	// draws from, surfaced here as the forward-only reseed handle (the
	// newMemCounter resume point). RecoverSessions advances it PAST the highest
	// recovered index so the next Allocate() never re-hands a live index (D66).
	// Set in lockstep with recover (both nil or both non-nil).
	counter ReseedableCounter

	// recovered is the recover-before-serve LATCH (D66, doc 15 §4 / §5.1). It
	// gates the verb surface on a RECOVERY-WIRED service (recover+counter both
	// non-nil) until RecoverSessions has completed once: it is set TRUE at the END
	// of RecoverSessions (after the counter re-seed + clone-cache re-adoption both
	// succeed — including the empty-set fresh-host no-op, which has nothing to
	// re-seed but still satisfies the precondition), and CloneFromImage checks it
	// at the TOP before allocating any index.
	//
	// WHY a latch and not just the internally-synchronized counter: the counter
	// being internally synchronized makes the SeedAtLeast/Allocate pair race-free
	// (go test -race is clean), but that is necessary, NOT sufficient — it does not
	// enforce ORDERING. A CloneFromImage for a NEW session that interleaves BEFORE
	// RecoverSessions draws from the UN-RESEEDED counter and could re-hand a live
	// recovered index (a D66 never-recycle violation). This latch makes
	// recover-THEN-serve a structural precondition on a recovery-wired host.
	//
	// It is an atomic.Bool (read on the CloneFromImage hot path, set once at the
	// end of RecoverSessions) so the gate is lock-free and -race clean. It is
	// IDEMPOTENT: a re-invocation of RecoverSessions re-Stores true (the latch
	// stays set). The NO-RECOVERY NewDriverService path (recover == nil) NEVER
	// consults this latch — a driver with no recovery phase has nothing to wait on,
	// so its CloneFromImage is unaffected (the latch stays false forever, unread).
	//
	// FUTURE-VERB INVARIANT: CloneFromImage is TODAY the sole index-drawer, but ANY
	// future host-side verb that consumes or re-hands a session index inherits this
	// SAME recover-before-serve latch check (the s.recover!=nil && s.counter!=nil &&
	// !s.recovered.Load() gate, before it draws) — so adding a new index-consuming
	// verb cannot silently bypass the D66 never-recycle guarantee (the concurrency
	// guard is TestCloneRaceWithRecoverNeverRecyclesIndex).
	recovered atomic.Bool

	// caRefDefault, when non-nil, supplies a per-session ca_bundle_ref default for a
	// CloneFromImage request that carries NONE (the canonical §4.1 spine mints the CA at
	// step 5, after this step-4 verb, so it sends no ref). It is OPTIONAL and OFF by default:
	// nil leaves an absent ref empty so the fail-closed step-7 validate refuses it (D17, the
	// production posture every unit test pins). The env-aware daemon root sets it (to the
	// deterministic "ca:<uuid>" shape) ONLY under its MVP no-CA-inject gate, where the
	// synthetic CA source resolves any ref — keeping this layer env-agnostic.
	caRefDefault func(sessionUUID string) string

	// minter mints the D79 transport-ambivalent attach handle (doc 15 §5.4) for a
	// known session binding (the IssueAttachHandle seam). It is OPTIONAL: a service
	// built without one (NewDriverService / NewDriverServiceWithRecovery) answers
	// IssueAttachHandle with an honest codes.Unimplemented — the real minter (the
	// hostbridge D79 transport endpoint + the identity-D22 per-session auth) lands
	// host-side. A service built WITH one (NewDriverServiceWithAttach) mints the
	// attach.v1 handle for a cloned session. Nil ⇒ unwired ⇒ honest Unimplemented.
	minter AttachHandleMinter

	// suspender pauses/restores a host-resident session domain — the §3
	// RUNNING↔SUSPENDED(reason) transition (doc 15 §4.3; D46/D77) that wires
	// Suspend/Resume. It is OPTIONAL: a service built without one
	// (NewDriverService / …WithRecovery / …WithAttach) answers BOTH Suspend and
	// Resume with an honest codes.Unimplemented — the real libvirt
	// domain-suspend/managedsave + restore lands host-side. A service built WITH
	// one (NewDriverServiceWithSuspend) pauses/restores a cloned session. The D77
	// reason validation (a reason is required; POLICY_BREACH REQUIRES provenance)
	// is enforced at the binding BEFORE the seam is called. Nil ⇒ unwired ⇒ honest
	// Unimplemented (the IssueAttachHandle nil-minter precedent).
	suspender Suspender

	// snapshots captures a durable point-in-time of a session's per-session qcow2
	// overlay — the §5.1 Snapshot verb over the D29 durability unit (doc 15 §5.1;
	// D29/D30) that wires Snapshot. It is OPTIONAL: a service built without one
	// (NewDriverService / …WithRecovery / …WithAttach / …WithSuspend) answers
	// Snapshot with an honest codes.Unimplemented — the real libvirt
	// external-snapshot capture of the per-session overlay lands host-side. A
	// service built WITH one (NewDriverServiceWithSnapshot) captures a snapshot of
	// a cloned session and returns the opaque snapshot_ref. Nil ⇒ unwired ⇒ honest
	// Unimplemented (the IssueAttachHandle nil-minter / Suspend nil-suspender
	// precedent).
	snapshots SnapshotStore

	// exporter opens the D29 dirty-bitmap delta of a session's per-session qcow2
	// overlay as a raw byte stream — the §5.1 ExportDiskDelta verb over the D29
	// durability unit (doc 15 §5.1; D29/D30) that wires ExportDiskDelta. It is
	// OPTIONAL: a service built without one (NewDriverService / …WithRecovery /
	// …WithAttach / …WithSuspend / …WithSnapshot) answers ExportDiskDelta with an
	// honest codes.Unimplemented — the real libvirt dirty-bitmap/qemu-img delta
	// extraction over the per-session overlay lands host-side. A service built WITH
	// one (NewDriverServiceWithDiskDelta) opens the delta and STREAMS it as
	// ExportDiskDeltaResponse{offset, data} frames. Nil ⇒ unwired ⇒ honest
	// Unimplemented (the Suspend nil-suspender / Snapshot nil-store precedent).
	exporter DiskDeltaExporter

	// mu guards the per-session clone cache AND the per-session captured-snapshot
	// set. CloneFromImage must be idempotent on session_uuid (doc 15 §5.1: "Every
	// verb idempotent on session_uuid so a retried call after a host or
	// control-plane blip re-adopts rather than duplicates"). The underlying seams
	// are individually idempotent, but the Allocator BURNS a fresh never-recycled
	// index on every Allocate() (D66), so a blind re-drive would fork a second
	// binding. The service dedupes at the verb boundary: the first successful
	// clone's response is cached and a retry returns it verbatim, so the
	// index/tap/guest-ip/overlay the caller already holds stay authoritative.
	mu     sync.Mutex
	clones map[string]*hypervisorv1.CloneFromImageResponse

	// snapshotRefs records, per session_uuid, the set of opaque snapshot_refs a
	// successful Snapshot has captured for that session (the D29 capture→export
	// loop closure). It is the registry ExportDiskDelta consults to validate a
	// non-empty since_snapshot_ref: a base ref this session has actually captured is
	// a valid incremental point-in-time, an unknown ref is not (the base does not
	// exist, so the export is rejected coherently BEFORE the seam is opened). The
	// inner map is a SET (the value is a zero-size struct{}); a re-Snapshot of the
	// same (session, label) deterministically re-registers the same ref harmlessly
	// (set-insert is idempotent). Guarded by mu — the same mutex discipline as
	// clones; Destroy drops a torn-down session's whole ref set so refs do not
	// linger past teardown (the clones cache-drop precedent).
	snapshotRefs map[string]map[string]struct{}

	// capturedRefs, when non-nil, DURABLY persists (and on teardown purges) the
	// per-session set of opaque snapshot_refs a successful Snapshot captured — the
	// PRODUCER/host durable half of the in-memory snapshotRefs registry (the
	// CapturedRefStore seam). It closes the write side of the D29 capture→export loop
	// across a restart: Snapshot records each captured ref here, and on a restart the
	// captured-ref-aware SessionRecoverer (seams.go capturedRefRecoverer) reads the set
	// back out to populate RecoveredSession.SnapshotRefs, which RecoverSessions re-seeds
	// into snapshotRefs — so a captured ref survives re-adoption and still roots an
	// incremental ExportDiskDelta (without it, the registry is per-process and a restart
	// silently invalidates every captured base). It is OFF by default (nil): every unit
	// test and the offline default leave it unset, and Snapshot's durable-write /
	// Destroy's durable-purge are then no-ops — the in-memory registry is unchanged and
	// the behavior is BYTE-IDENTICAL to today. The daemon root wires it host-side over
	// the same durable `.ds-sessions` area the SessionRecordStore uses. nil ⇒ unwired ⇒
	// in-memory-only (the historical posture).
	capturedRefs CapturedRefStore

	// sessionRecords, when non-nil, is the durable per-session record store
	// (sessionrecord.go) the create path Put at boot — held HERE only so a converged
	// §4.2 Destroy can REMOVE the torn-down session's record, the removal that store's
	// own contract names ("Remove deletes the record for sessionUUID (the §4.2
	// teardown)"). Without it a destroyed session's record outlives its domain and the
	// liveSessionRecoverer RE-ADOPTS it on the next host-agent restart — a session with
	// no domain, which the reconciler then orphan-quarantines forever. It is the
	// SessionRecord twin of the capturedRefs purge above (seams.go
	// RecoveredSession.SnapshotRefs: "a §4.2 Destroy purges both the durable record and
	// any recovered set"), and it is READ-ONLY-adjacent to the rest of the service: the
	// service never Puts or Gets through it (the create path owns the write, the
	// DestroyResolver owns the read), it only purges. OFF by default (nil): every unit
	// test and the offline default leave it unset — the daemon root wires the SAME store
	// the create path and the recoverer use, and only under DS_HOSTAGENT_LIVE (off the
	// gate NewSessionRecordStore returns nil, so no record was ever written). nil ⇒
	// unwired ⇒ no purge, BYTE-IDENTICAL to the historical destroy.
	sessionRecords SessionRecordStore

	// attachTokens, when non-nil, is the per-session attach-token store (attachminter.go)
	// seen through its TEARDOWN role — held HERE only so a converged §4.2 Destroy can
	// REMOVE the torn-down session's bearer token. Without it a destroyed session's D39
	// credential stayed readable at <OverlayDir>/.ds-attach-tokens/<uuid>.json until its
	// TTL lapsed (attachHandleTTL, 15 minutes), and that TTL is the store's ONLY
	// revocation mechanism (doc 19 §7) — so the doc 06 §(b) clean-teardown row ("no
	// leftover minted identity") was violated for a quarter of an hour after every
	// destroy. It is the credential twin of the sessionRecords purge above; unlike that
	// one the purge is FAIL-LOUD (see Destroy), because the residue is a live credential,
	// not a stale bookkeeping file. OFF by default (nil): every unit test and the offline
	// default leave it unset — the daemon root wires the SAME store the create-path
	// post-boot mint and the IssueAttachHandle minter draw from, and only under
	// DS_HOSTAGENT_LIVE (off the gate NewAttachTokenStore returns nil, so no token was
	// ever written). nil ⇒ unwired ⇒ no purge, BYTE-IDENTICAL to the historical destroy.
	attachTokens AttachTokenDisposer

	// sessionModes, when non-nil, is the per-session resolved-mode store
	// (sessionmodestore.go) the create-path EntrypointProducer wrote — held HERE only so a
	// converged §4.2 Destroy can REMOVE the torn-down session's marker. It is the SAME
	// class of host-internal per-session state as the SessionRecord above (a hidden
	// per-session leaf under the OverlayDir, sanitized on the session id), and it is
	// purged for the same reason and with the same BEST-EFFORT posture: the session is
	// gone, so the marker that tells the serving leg + the handle minter which surface to
	// serve describes nothing, and the only residue a removal fault leaves is a stale
	// marker. OFF by default (nil): the daemon root wires the SAME store the producer
	// wrote through, and only under DS_HOSTAGENT_LIVE (off the gate NewSessionModeStore
	// returns nil, so no marker was ever written). nil ⇒ unwired ⇒ no purge,
	// BYTE-IDENTICAL to the historical destroy.
	sessionModes SessionModeStore

	// configDrives, when non-nil, disposes the torn-down session's per-session
	// config-drive artifacts (configdrive.go): the read-only iso9660 image and — the
	// load-bearing half — the STAGING DIRECTORY holding config.pb at 0400, the rendered
	// EntrypointConfig with the session's INJECTED ENV CREDENTIALS. Before this seam those
	// artifacts survived every Destroy and were reclaimed only by an operator running
	// `ds-serve-stack.sh down --purge`, so a long-lived host accumulated one
	// credential-bearing config drive per session ever created — the doc 06 §(b)
	// clean-teardown row's "no leftover minted identity" in its most literal form. Like
	// the attach token the purge is FAIL-LOUD (see Destroy). Unlike the other three this
	// seam is NON-NIL on BOTH sides of the gate (NewConfigDriveDisposer returns the
	// no-touch offline no-op off it, exactly as NewDomainDestroyer does for step 1), so
	// the offline teardown makes no filesystem call and stays byte-identical; nil is still
	// honored as unwired for every unit test that does not wire it.
	configDrives ConfigDriveDisposer

	// caBundles, when non-nil, disposes the torn-down session's per-session interception-CA
	// bundle (cabundledisposer.go): the cert the orchestrator producer dropped under
	// <OverlayDir>/.ds-ca-bundles AND — the load-bearing half — the proxy-bound PKCS#8
	// PRIVATE KEY sibling ds-tlsproxy mints per-origin leaves with. Before this seam NOTHING
	// removed either file: the producer wrote them, the step-7 consumer read the cert, and
	// both survived every Destroy, so a long-lived host accumulated one live CA private key
	// per session ever created — D82 says the per-session CA is destroyed at teardown, and it
	// was not. Like the attach token and the config drive the purge is FAIL-LOUD (see
	// Destroy): a CA key the host could not delete is a real credential leak.
	//
	// It is keyed on the caBundleRef, NOT the session_uuid, so unlike the other purges it
	// needs the ref threaded out of the durable SessionRecord via the DestroyResolver; an
	// empty ref (a record written before the field existed) skips the disposal. OFF by
	// default (nil): every unit test and the offline default leave it unset — the daemon root
	// wires it gate-aware through NewCABundleDisposer, and only under DS_HOSTAGENT_LIVE (off
	// the gate no producer drop ever landed). nil ⇒ unwired ⇒ no purge, BYTE-IDENTICAL to the
	// historical destroy.
	caBundles CABundleDisposer

	// destroyResolver, when non-nil, supplies the host-side DomainUUID for a
	// Destroy whose session_uuid the IN-MEMORY clone cache does not already pin
	// (doc 15 §4.2 step 1; D66). The frozen DestroyRequest carries ONLY the
	// session_uuid (the teardown idempotency key), so the binding the §4.2 ordering
	// unwinds — the OverlayPath (step 3) and the DomainUUID (step 1) — is NOT on the
	// wire; the service resolves it host-side. The clone cache is the PRIMARY
	// resolution source (it pins the OverlayPath + the three-keys-agree Binding of a
	// session this process cloned), but it does NOT carry the DomainUUID (the wire
	// CloneFromImageResponse never does — the domain id is host-local libvirt state,
	// persisted in the SessionRecord, not the binding). This OPTIONAL resolver is
	// the bridge to that durable record: the env-aware daemon root wires it (over
	// the SessionRecordStore) so a gRPC Destroy can thread the recorded DomainUUID
	// into §4.2 step 1. It is OFF by default (nil): every unit test and the offline
	// default leave it unset, and DestroyDomain is then driven from the session_uuid
	// alone (the domainName "ds-<uuid>" convention the DomainDestroyer already
	// honors — both the live virsh destroyer and the fake ignore an empty
	// domainUUID), so the historical destroy behavior is BYTE-IDENTICAL. nil ⇒
	// unresolved ⇒ session_uuid-driven domain destroy, exactly as before.
	destroyResolver DestroyResolver
}

// DestroyResolver resolves the host-side teardown state for a session whose
// DestroyRequest carries only its session_uuid (the frozen wire contract). The
// §4.2 ordering needs the booted DomainUUID (step 1) and the per-session overlay
// (step 3) to dispose, but neither rides the wire — they are host-local libvirt
// state. The clone cache pins the OverlayPath + Binding for a session this
// process cloned; this seam supplies the DomainUUID (and, if the cache missed —
// e.g. a post-restart Destroy of a session this process never cloned — the
// OverlayPath + Binding too) from the durable SessionRecord the create path
// persisted. It is OPTIONAL (the daemon root wires it host-side over the
// SessionRecordStore); off the wired path the domain destroy is driven from the
// session_uuid alone. Defined here (not seams.go) because it is the service
// binding's own resolution seam.
type DestroyResolver interface {
	// ResolveDestroy returns the host-side teardown state for a session. found is
	// false when the resolver has no record for the session (an already-gone /
	// never-recorded session) — a clean no-op convergence, NOT an error. A genuine
	// read fault (a corrupt/unreadable record) is a non-nil error so a teardown
	// does not silently skip disposal of a real overlay. The returned DomainUUID /
	// OverlayPath / Binding mirror the SessionRecord the create path persisted.
	ResolveDestroy(ctx context.Context, sessionUUID string) (state DestroyState, found bool, err error)
}

// DestroyState is the host-side teardown state a DestroyResolver returns — the
// subset of the persisted SessionRecord the §4.2 ordering needs: the booted
// DomainUUID (step 1), the per-session overlay (step 3), and the recorded
// three-keys-agree Binding (step 2 flush + byte-count accounting).
type DestroyState struct {
	DomainUUID  string
	OverlayPath string
	Binding     Binding

	// CABundleRef is the per-session interception-CA bundle ref from the durable
	// SessionRecord — the ONLY place it survives to teardown time (the frozen
	// DestroyRequest carries just the session_uuid, and the clone cache holds the wire
	// CloneFromImageResponse, which never names the CA). A converged Destroy threads it
	// into the CABundleDisposer so the .ds-ca-bundles cert AND proxy-bound key are
	// removed (D82). Empty for a record written before the field existed; the disposal is
	// then skipped.
	CABundleRef string
}

// NewDriverService assembles the gRPC binding over the create and destroy
// drivers. Both are required — a nil driver is a programming error surfaced at
// construction, not at the first RPC (the identity/mint NewMintServer posture).
//
// The resulting service has NO crash-recovery wiring: RecoverSessions answers an
// honest codes.Unimplemented (the real host-resident re-observation lands
// host-side). Use NewDriverServiceWithRecovery to wire the restart re-adoption
// leg (a SessionRecoverer + the shared index counter).
func NewDriverService(create *HostAgent, destroy *Destroyer) (*DriverService, error) {
	return NewDriverServiceWithRecovery(create, destroy, nil, nil)
}

// NewDriverServiceWithRecovery assembles the gRPC binding AND wires the
// crash-matrix re-adoption leg (doc 15 §4; D66): the SessionRecoverer that
// re-observes host-resident sessions for a host_id, and the ReseedableCounter —
// the SAME persistent index counter the create-path Allocator draws from — so
// RecoverSessions can advance it past the highest recovered index. The recoverer
// and counter are wired in LOCKSTEP: supply both to enable recovery, or neither
// (the NewDriverService path) for the honest-Unimplemented posture. Supplying
// exactly one is a programming error surfaced at construction — a recoverer
// without the shared counter could not re-seed the Allocator (it would burn a
// second never-recycled index on the next clone), and a counter without a
// recoverer has nothing to observe.
func NewDriverServiceWithRecovery(create *HostAgent, destroy *Destroyer, recoverer SessionRecoverer, counter ReseedableCounter) (*DriverService, error) {
	return NewDriverServiceWithAttach(create, destroy, recoverer, counter, nil)
}

// NewDriverServiceWithAttach assembles the gRPC binding, the optional crash-matrix
// re-adoption leg (as NewDriverServiceWithRecovery), AND the optional
// attach-handle minter (doc 15 §5.4 / D79) that wires IssueAttachHandle. The
// minter is OPTIONAL and orthogonal to recovery: supply one to mint the attach.v1
// handle for a cloned session, or nil for the honest-Unimplemented posture (the
// real minter — the hostbridge D79 transport endpoint + identity-D22 per-session
// auth — lands host-side). The recoverer/counter still wire in lockstep (both or
// neither, per the recovery contract); the minter has no such partner.
func NewDriverServiceWithAttach(create *HostAgent, destroy *Destroyer, recoverer SessionRecoverer, counter ReseedableCounter, minter AttachHandleMinter) (*DriverService, error) {
	return NewDriverServiceWithSuspend(create, destroy, recoverer, counter, minter, nil)
}

// NewDriverServiceWithSuspend assembles the gRPC binding, the optional crash-matrix
// re-adoption leg (as NewDriverServiceWithRecovery), the optional attach-handle
// minter (as NewDriverServiceWithAttach), AND the optional suspend/resume seam
// (doc 15 §4.3 / D46/D77) that wires Suspend + Resume. The Suspender is OPTIONAL
// and orthogonal to recovery and attach: supply one to pause/restore a cloned
// session, or nil for the honest-Unimplemented posture (the real libvirt
// domain-suspend/managedsave + restore lands host-side on the virtual-metal box).
// The recoverer/counter still wire in lockstep (both or neither, per the recovery
// contract); the minter and the suspender each stand alone (no partner).
func NewDriverServiceWithSuspend(create *HostAgent, destroy *Destroyer, recoverer SessionRecoverer, counter ReseedableCounter, minter AttachHandleMinter, suspender Suspender) (*DriverService, error) {
	return NewDriverServiceWithSnapshot(create, destroy, recoverer, counter, minter, suspender, nil)
}

// NewDriverServiceWithSnapshot assembles the gRPC binding, the optional crash-matrix
// re-adoption leg (as NewDriverServiceWithRecovery), the optional attach-handle
// minter (as NewDriverServiceWithAttach), the optional suspend/resume seam (as
// NewDriverServiceWithSuspend), AND the optional snapshot seam (doc 15 §5.1 /
// D29/D30) that wires Snapshot. The SnapshotStore is OPTIONAL and orthogonal to
// recovery, attach, and suspend: supply one to capture a point-in-time of a cloned
// session's per-session qcow2 overlay, or nil for the honest-Unimplemented posture
// (the real libvirt external-snapshot capture of the overlay lands host-side on the
// virtual-metal box). The recoverer/counter still wire in lockstep (both or
// neither, per the recovery contract); the minter, the suspender, and the snapshot
// store each stand alone (no partner).
func NewDriverServiceWithSnapshot(create *HostAgent, destroy *Destroyer, recoverer SessionRecoverer, counter ReseedableCounter, minter AttachHandleMinter, suspender Suspender, snapshots SnapshotStore) (*DriverService, error) {
	return NewDriverServiceWithDiskDelta(create, destroy, recoverer, counter, minter, suspender, snapshots, nil)
}

// NewDriverServiceWithDiskDelta assembles the gRPC binding, the optional crash-matrix
// re-adoption leg (as NewDriverServiceWithRecovery), the optional attach-handle
// minter (as NewDriverServiceWithAttach), the optional suspend/resume seam (as
// NewDriverServiceWithSuspend), the optional snapshot seam (as
// NewDriverServiceWithSnapshot), AND the optional disk-delta exporter (doc 15 §5.1
// / D29/D30) that wires ExportDiskDelta. The DiskDeltaExporter is OPTIONAL and
// orthogonal to recovery, attach, suspend, and snapshot: supply one to stream a
// cloned session's per-session qcow2-overlay dirty-bitmap delta, or nil for the
// honest-Unimplemented posture (the real libvirt dirty-bitmap/qemu-img delta
// extraction over the overlay lands host-side on the virtual-metal box). The
// recoverer/counter still wire in lockstep (both or neither, per the recovery
// contract); the minter, the suspender, the snapshot store, and the exporter each
// stand alone (no partner). The narrower NewDriverService* wrappers delegate up
// to NewDriverServiceWithDestroyResolver (the full-fan-in constructor) with the
// unwired seams nil.
func NewDriverServiceWithDiskDelta(create *HostAgent, destroy *Destroyer, recoverer SessionRecoverer, counter ReseedableCounter, minter AttachHandleMinter, suspender Suspender, snapshots SnapshotStore, exporter DiskDeltaExporter) (*DriverService, error) {
	return NewDriverServiceWithDestroyResolver(create, destroy, recoverer, counter, minter, suspender, snapshots, exporter, nil)
}

// NewDriverServiceWithDestroyResolver assembles the gRPC binding, every optional
// seam the narrower constructors wire (as NewDriverServiceWithDiskDelta), AND the
// optional DestroyResolver (doc 15 §4.2; D66) that supplies the host-side
// DomainUUID — and, on a cache miss, the OverlayPath + Binding — for a Destroy
// whose frozen DestroyRequest carries only the session_uuid. The resolver is
// OPTIONAL and orthogonal to every other seam: supply one (the daemon root wires
// it over the SessionRecordStore) so a gRPC Destroy threads the recorded domain +
// overlay into §4.2, or nil for the historical session_uuid-driven destroy (the
// clone cache still pins the OverlayPath + Binding of a session this process
// cloned, so an in-process clone→destroy disposes its overlay even with no
// resolver; the resolver is what lets a post-restart Destroy of a session this
// process never cloned find the durable record). The recoverer/counter still wire
// in lockstep (both or neither, per the recovery contract); the minter, the
// suspender, the snapshot store, the exporter, and the resolver each stand alone
// (no partner). This is the full-fan-in constructor; every narrower
// NewDriverService* wrapper delegates here with the unwired seams nil.
func NewDriverServiceWithDestroyResolver(create *HostAgent, destroy *Destroyer, recoverer SessionRecoverer, counter ReseedableCounter, minter AttachHandleMinter, suspender Suspender, snapshots SnapshotStore, exporter DiskDeltaExporter, destroyResolver DestroyResolver) (*DriverService, error) {
	return NewDriverServiceWithCapturedRefStore(create, destroy, recoverer, counter, minter, suspender, snapshots, exporter, destroyResolver, nil)
}

// NewDriverServiceWithCapturedRefStore assembles the gRPC binding, every optional seam
// the narrower constructors wire (as NewDriverServiceWithDestroyResolver), AND the
// optional CapturedRefStore (the CapturedRefStore seam; D29/D30) that DURABLY persists
// the per-session captured snapshot_refs on Snapshot success and purges them on Destroy —
// the PRODUCER/host durable half of the in-memory snapshotRefs registry. The store is
// OPTIONAL and orthogonal to every other seam: supply one (the daemon root wires it
// host-side over the same durable `.ds-sessions` area the SessionRecordStore uses,
// alongside a captured-ref-aware SessionRecoverer, seams.go NewSessionRecovererWithCapturedRefs)
// so a captured ref survives a restart and still roots an incremental ExportDiskDelta, or
// nil for the historical in-memory-only posture (Snapshot's durable-write / Destroy's
// durable-purge are then no-ops; the in-memory registry is byte-identical to today). The
// recoverer/counter still wire in lockstep (both or neither, per the recovery contract);
// the minter, the suspender, the snapshot store, the exporter, the destroy resolver, and
// the captured-ref store each stand alone (no partner). This is the full-fan-in
// constructor; every narrower NewDriverService* wrapper delegates here with the unwired
// seams nil.
func NewDriverServiceWithCapturedRefStore(create *HostAgent, destroy *Destroyer, recoverer SessionRecoverer, counter ReseedableCounter, minter AttachHandleMinter, suspender Suspender, snapshots SnapshotStore, exporter DiskDeltaExporter, destroyResolver DestroyResolver, capturedRefs CapturedRefStore) (*DriverService, error) {
	if create == nil {
		return nil, fmt.Errorf("libvirt driver service requires a host-agent create driver")
	}
	if destroy == nil {
		return nil, fmt.Errorf("libvirt driver service requires a §4.2 destroy driver")
	}
	if (recoverer == nil) != (counter == nil) {
		return nil, fmt.Errorf("libvirt driver service recovery wiring requires BOTH a session recoverer and the shared index counter, or neither (D66: re-adoption must re-seed the Allocator)")
	}
	return &DriverService{
		create:          create,
		destroy:         destroy,
		recover:         recoverer,
		counter:         counter,
		minter:          minter,
		suspender:       suspender,
		snapshots:       snapshots,
		exporter:        exporter,
		destroyResolver: destroyResolver,
		capturedRefs:    capturedRefs,
		clones:          make(map[string]*hypervisorv1.CloneFromImageResponse),
		snapshotRefs:    make(map[string]map[string]struct{}),
	}, nil
}

// SetCARefDefault installs the per-session ca_bundle_ref default the env-aware daemon
// root uses under its MVP no-CA-inject gate: a CloneFromImage with NO ref then defaults to
// fn(sessionUUID) (the deterministic "ca:<uuid>" shape the synthetic CA source resolves)
// rather than failing the fail-closed step-7 validate. It is OFF by default (nil), so the
// production fail-closed posture (an absent ref is InvalidArgument, D17) is unchanged — and
// every unit test, which never sets it, keeps that contract. fn nil is a no-op.
func (s *DriverService) SetCARefDefault(fn func(sessionUUID string) string) {
	s.caRefDefault = fn
}

// WithSessionRecordStore wires the OPTIONAL durable SessionRecordStore whose record a
// CONVERGED §4.2 Destroy removes (sessionrecord.go's own "removed when the session is
// torn down (§4.2) so a destroyed session is not re-adopted"), returning the same
// *DriverService for chaining at composition — the Destroyer.WithPostDestroyHook setter
// precedent, chosen for the SAME reason: the fan-in constructor signature (and every
// existing caller) stays unchanged for a seam that is OFF by default. The daemon
// composition root passes the SAME store the create path Puts through and the
// DestroyResolver reads back, so the write, the read, and the teardown purge all name one
// on-disk set. A nil store is a no-op (the historical posture, byte-identical): no record
// was written off the gate, so there is none to remove.
func (s *DriverService) WithSessionRecordStore(records SessionRecordStore) *DriverService {
	s.sessionRecords = records
	return s
}

// WithAttachTokenDisposer wires the OPTIONAL per-session attach-token store, in its
// TEARDOWN role, whose token a CONVERGED §4.2 Destroy removes (doc 15 §4.2; the doc 06
// §(b) "no leftover minted identity" row). It follows the WithSessionRecordStore setter
// precedent for the same reason — the fan-in constructor signature and every existing
// caller stay unchanged for a seam that is OFF by default — and the daemon composition
// root passes the SAME store the create-path post-boot mint writes and the
// IssueAttachHandle minter reads, so the mint, the validate, and the teardown purge all
// name one on-disk token. A nil disposer is a no-op (the historical posture,
// byte-identical): off the gate no token was ever minted, so there is none to remove.
func (s *DriverService) WithAttachTokenDisposer(tokens AttachTokenDisposer) *DriverService {
	s.attachTokens = tokens
	return s
}

// WithSessionModeStore wires the OPTIONAL per-session resolved-mode store whose marker a
// CONVERGED §4.2 Destroy removes (doc 15 §4.2) — the SessionModeStore sibling of
// WithSessionRecordStore, wired from the SAME store the create-path EntrypointProducer
// persisted through and the serving leg / handle minter read back, so one on-disk marker
// set is written, read, and purged. A nil store is a no-op (byte-identical): off the gate
// NewSessionModeStore returns nil and no marker was written.
func (s *DriverService) WithSessionModeStore(modes SessionModeStore) *DriverService {
	s.sessionModes = modes
	return s
}

// WithConfigDriveDisposer wires the OPTIONAL §4.2 config-drive disposal seam (the
// credential-bearing per-session image + staging dir; configdrive.go). The daemon
// composition root builds it through the gate-aware NewConfigDriveDisposer, which
// delegates the live/offline choice to the SAME NewEntrypointDeliverer selection the
// create path built the drive with — so the build and the disposal are always on one side
// of the gate. Unlike the other teardown seams this one is non-nil on BOTH sides (the
// offline value is a no-touch no-op), so the root wires it unconditionally; a nil
// disposer is still honored as unwired and is byte-identical to the historical destroy.
func (s *DriverService) WithConfigDriveDisposer(drives ConfigDriveDisposer) *DriverService {
	s.configDrives = drives
	return s
}

// WithCABundleDisposer wires the OPTIONAL §4.2 interception-CA disposal seam (the dropped
// cert + its proxy-bound PKCS#8 private key; cabundledisposer.go), following the
// WithAttachTokenDisposer precedent for the same reason — the fan-in constructor signature
// and every existing caller stay unchanged for a seam that is OFF by default. The daemon
// composition root builds it through the gate-aware NewCABundleDisposer over the SAME
// OverlayDir the orchestrator producer drops into and the step-7 CABundleSource reads back,
// so one on-disk bundle is written, read, and purged. A nil disposer is a no-op
// (byte-identical to the historical destroy): off the gate no drop ever landed, so there is
// nothing to remove.
func (s *DriverService) WithCABundleDisposer(d CABundleDisposer) *DriverService {
	s.caBundles = d
	return s
}

// GetCapabilities reports the D35 Nomad-style flags for the v0 libvirt driver,
// answered HONESTLY — the opposite of the EC2 demo driver, whose first honesty
// test answers false on all three (doc 15 §5.1). Each flag is justified inline:
// the conformance suite drives the WIRE behavior these flags advertise (doc 15
// §10), so a dishonest flag here is a caught contract violation, not a cosmetic
// claim.
func (s *DriverService) GetCapabilities(_ context.Context, _ *hypervisorv1.GetCapabilitiesRequest) (*hypervisorv1.GetCapabilitiesResponse, error) {
	return &hypervisorv1.GetCapabilitiesResponse{
		Capabilities: &hypervisorv1.Capabilities{
			// supports_instant_clone = TRUE: the v0 driver materializes each
			// session as a per-session qcow2 OVERLAY over the raw golden image via
			// libvirt external snapshots (D29) — a copy-on-write delta created in
			// O(1), never a full image copy. That IS instant clone; CloneFromImage
			// is backed by OverlayStore.CreateOverlay (create.go step 7), not by an
			// AMI/instance launch (the EC2 false).
			SupportsInstantClone: true,
			// supports_disk_delta_export = TRUE: the qcow2 overlay is the D29 delta
			// store AND the inspectable artifact AND the durability unit, and the
			// dirty-bitmap stream over it (destroy.go's DurabilityFinalizer at §4.2
			// step 3) is exactly the disk-delta substrate ExportDiskDelta streams.
			// libvirt/qcow2 supports this natively; the EC2 demo cannot (false).
			SupportsDiskDeltaExport: true,
			// supports_migrate = FALSE: honest for v0. Migrate internals are "free
			// until M3" (doc 15 §5.1) and the host-local never-recycled index +
			// tap binding (D66) is not yet migration-safe across hosts; claiming
			// migrate while Migrate() returns Unimplemented (below) would be the
			// dishonesty the capability-honesty test exists to catch. Flip this to
			// true only when Migrate is wired and the conformance suite proves it.
			SupportsMigrate: false,
		},
	}, nil
}

// CloneFromImage materializes a session VM from a content-addressed image and
// returns the host-side attachment binding (index / tap / guest IP / overlay) —
// the artifact the tap-create RACI row cites (doc 15 §5.1, §4.1 step 4 + step 7).
// It drives the host-agent create spine (create.go: allocate → tap/NFT attach →
// record binding → digest-ack gate → CreateOverlay + fail-closed CA inject →
// boot → routable gate) and lowers the recorded Binding into the frozen
// CloneFromImageResponse.
//
// IDEMPOTENT ON session_uuid: a retry for a session that already cloned returns
// the SAME binding (cached at the verb boundary), never a second never-recycled
// index (D66). A non-routable-but-booted result (the step-9 policy-stale case) is
// NOT an error here — the binding is recorded and the response carries it; the
// reconciler decides whether to wait for freshness (doc 15 §4.1: the binding is
// recorded before the routable verdict, and CloneFromImageResponse carries it).
// Only a create failure that surfaces NO usable binding is mapped to a gRPC
// error.
//
// RECOVER-BEFORE-SERVE (D66): on a recovery-wired host (recover+counter non-nil)
// the first clone is gated behind the `recovered` latch — a clone that arrives
// before RecoverSessions has completed returns codes.FailedPrecondition WITHOUT
// allocating any index, because the shared counter has not yet been re-seeded
// past the highest recovered index. The no-recovery NewDriverService path has no
// recovery phase and never gates.
func (s *DriverService) CloneFromImage(ctx context.Context, req *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error) {
	spec := req.GetSpec()
	if spec == nil {
		return nil, status.Error(codes.InvalidArgument, "CloneFromImage requires a VmSpec")
	}
	sessionUUID := spec.GetSessionUuid()
	if sessionUUID == "" {
		return nil, status.Error(codes.InvalidArgument, "CloneFromImage requires spec.session_uuid (every verb is idempotent on it)")
	}

	// Recover-before-serve precondition (D66, doc 15 §4 / §5.1). On a
	// RECOVERY-WIRED host (recover+counter both non-nil) RecoverSessions must
	// complete once before the first clone: it advances the shared index counter
	// strictly past the highest recovered index, so a clone that ran first would
	// draw from the un-reseeded counter and could re-hand a live recovered index.
	// Gate here, at the TOP, BEFORE any index is allocated (before even the
	// idempotency cache is consulted). The NO-RECOVERY NewDriverService path
	// (recover == nil) has no recovery phase to wait on, so it NEVER gates — only
	// the recovery-wired construction does.
	if s.recover != nil && s.counter != nil && !s.recovered.Load() {
		return nil, status.Error(codes.FailedPrecondition, "recover-before-serve: RecoverSessions must complete before CloneFromImage on a recovery-wired host (D66)")
	}

	// Idempotency on session_uuid: return the cached binding for a repeat clone so
	// a retried call re-adopts rather than burning a second index (D66).
	s.mu.Lock()
	if prior, ok := s.clones[sessionUUID]; ok {
		s.mu.Unlock()
		return prior, nil
	}
	s.mu.Unlock()

	caBundleRef := ""
	if mat := spec.GetMaterial(); mat != nil {
		caBundleRef = mat.GetCaBundleRef()
	}
	// The canonical §4.1 spine mints the per-session interception CA at step 5 — AFTER the
	// step-4 CloneFromImage — so the clone request can arrive with NO ca_bundle_ref (the spine
	// builds the step-4 VmSpec with no Material; the CA is injected into the cloned overlay via
	// the separate step-7 InjectCA seam). The host-folded create here runs step-7 INSIDE this
	// verb, whose fail-closed VALIDATE requires a non-empty ref (D17). When an MVP caRef DEFAULT
	// is configured (caRefDefault — set by the env-aware daemon root under its no-CA-inject
	// gate), an absent ref is defaulted to the deterministic per-session "ca:<uuid>" so the
	// verb has a stable join key its synthetic CA source resolves. With NO default configured
	// (the production posture, and every unit test), an absent ref is left empty and the
	// fail-closed validate refuses it (InvalidArgument, D17) exactly as before — this layer
	// stays env-agnostic, the policy lives in the daemon root.
	if caBundleRef == "" && s.caRefDefault != nil {
		caBundleRef = s.caRefDefault(sessionUUID)
	}

	res, err := s.create.CreateSession(ctx, CreateRequest{
		SessionUUID:         sessionUUID,
		ImageID:             spec.GetImageId(),
		EntrypointConfigRef: spec.GetEntrypointConfigRef(),
		CABundleRef:         caBundleRef,
		// Thread the additive per-session posture (VmSpec.posture) into the create path's
		// CreateRequest.Posture so it reaches the gap-1 EntrypointConfig producer
		// (ProduceInput.Posture). UNSPECIFIED (the zero value / no posture supplied) leaves the
		// create byte-identical to today: create.go falls back to the daemon-pinned LOCKED at
		// ProduceConfig, preserving M0 default-deny; a CONCRETE value WINS over that fallback.
		Posture: spec.GetPosture(),
	})
	if err != nil {
		// A step-9 policy-stale result is booted-but-not-routable: the binding IS
		// recorded and the response must carry it (the frozen §4.1 precedence). Any
		// other create failure has no usable binding to return — map it to a gRPC
		// status that preserves the per-step diagnosis.
		var ce *CreateError
		if errors.As(err, &ce) && ce.Step == StepRoutable && res.Binding.TapName != "" {
			// Fall through with the recorded, non-routable binding.
		} else {
			return nil, cloneError(sessionUUID, err)
		}
	}

	resp := cloneResponse(res.Binding)

	s.mu.Lock()
	// Re-check under the lock: a concurrent clone for the same session may have
	// won the race; if so, return its cached binding so both callers agree.
	if prior, ok := s.clones[sessionUUID]; ok {
		s.mu.Unlock()
		return prior, nil
	}
	s.clones[sessionUUID] = resp
	s.mu.Unlock()
	return resp, nil
}

// Destroy drives the §4.2 host-local teardown ordering (destroy.go: domain
// destroy → UNCONDITIONAL flush_session + NFT-6 + final byte counts → overlay
// disposal + durability finalize). It is idempotent on session_uuid: a Destroy of
// an unknown / already-gone session SUCCEEDS (doc 15 §5.1 + destroy.go: an absent
// domain is a no-op destroy, the flush is unconditional and converges, an absent
// overlay is a no-op disposal) — so a retried teardown after a host or
// control-plane blip re-adopts rather than errors.
//
// RESOLVING THE HOST-SIDE STATE (the destroy-overlay wiring, doc 15 §4.2; D29/D66):
// the frozen DestroyRequest carries ONLY the session_uuid (the teardown
// idempotency key), but the §4.2 ordering needs the per-session OverlayPath (step
// 3 disposal + durability finalize) and the booted DomainUUID (step 1) — and a
// zero OverlayPath makes destroy.go's overlay-disposal step a guarded no-op, so a
// session_uuid-only request would leak the per-session overlay past a gRPC
// Destroy. This binding RESOLVES that state host-side before driving the §4.2
// driver:
//
//   - the IN-MEMORY clone cache is the PRIMARY source: a session this process
//     cloned has its OverlayPath + three-keys-agree Binding pinned there (the
//     idempotency artifact), so an in-process clone→destroy threads them and
//     disposes the overlay even with NO resolver wired;
//   - the OPTIONAL DestroyResolver supplies the DomainUUID the cache cannot carry
//     (the wire CloneFromImageResponse never holds the host-local libvirt domain
//     id) and, on a cache MISS (a post-restart Destroy of a session this process
//     never cloned), the OverlayPath + Binding too — from the durable
//     SessionRecord the create path persisted.
//
// Off the resolver path the DomainUUID stays empty and step 1 is driven from the
// session_uuid alone (the domainName "ds-<uuid>" convention the DomainDestroyer
// already honors — both the live virsh destroyer and the fake ignore an empty
// domainUUID), so the historical behavior is preserved. A wholly-unknown session
// (cache miss + no/empty resolver record) yields a binding-less DestroyRequest —
// the unconditional flush still runs and converges, exactly the right no-op for an
// already-gone session.
//
// A teardown FAULT (a domain that won't destroy, a flush error, a resolver read
// fault) is surfaced as a gRPC error so the reconciler re-drives; a clean (or
// already-gone) teardown returns the empty DestroyResponse ack.
func (s *DriverService) Destroy(ctx context.Context, req *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
	sessionUUID := req.GetSessionUuid()
	if sessionUUID == "" {
		return nil, status.Error(codes.InvalidArgument, "Destroy requires session_uuid (the teardown idempotency key)")
	}

	// READ the cached clone binding (the in-memory session index) BEFORE dropping
	// it: a session this process cloned has its OverlayPath + Binding pinned in the
	// clone cache, so the §4.2 ordering can unwind the per-session overlay (step 3)
	// + the recorded binding (step 2 flush/accounting) without it riding the wire.
	// Then DROP the cached clone binding AND the registered snapshot refs so a
	// destroy→re-clone of the same session_uuid re-allocates honestly rather than
	// returning a stale binding, and so a torn-down session's captured refs do not
	// linger to be named back as a since_snapshot_ref base after the underlying
	// overlay is gone (the §4.2 teardown drops the durability unit).
	s.mu.Lock()
	cached, cacheHit := s.clones[sessionUUID]
	delete(s.clones, sessionUUID)
	delete(s.snapshotRefs, sessionUUID)
	s.mu.Unlock()

	dr := DestroyRequest{SessionUUID: sessionUUID}
	if cacheHit {
		b := bindingFromCloneResponse(cached)
		dr.Binding = b
		dr.HasBinding = true
		dr.OverlayPath = b.OverlayPath
	}

	// Resolve the DomainUUID (and, on a cache miss, the OverlayPath + Binding) from
	// the durable SessionRecord via the OPTIONAL resolver. The wire response the
	// cache holds never carries the host-local libvirt domain id, so step 1's
	// DomainUUID comes ONLY from here; a cache miss further leans on the resolver
	// for the OverlayPath + Binding (a post-restart Destroy of a session this
	// process never cloned). A resolver read FAULT is surfaced as a gRPC error
	// (never a silent skip that would leak a real overlay); a not-found record is a
	// clean no-op (the session is already gone), leaving the session_uuid-driven
	// convergence intact.
	//
	// The resolver is ALSO the only carrier of the caBundleRef the §4.2 CA-bundle disposal
	// keys on (below): the clone cache pins the wire clone response, which never names the
	// CA, so the ref is read UNCONDITIONALLY off the durable record — on the cacheHit path
	// too, not just the cache-miss branch.
	caBundleRef := ""
	if s.destroyResolver != nil {
		st, found, err := s.destroyResolver.ResolveDestroy(ctx, sessionUUID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "libvirt destroy session %s: resolve host-side teardown state: %v", sessionUUID, err)
		}
		if found {
			dr.DomainUUID = st.DomainUUID
			caBundleRef = st.CABundleRef
			if !cacheHit {
				// The cache missed (this process never cloned this session, e.g. a
				// post-restart Destroy); adopt the durable record's overlay + binding so
				// the §4.2 ordering still disposes the overlay and flushes the recorded
				// objects.
				dr.Binding = st.Binding
				dr.HasBinding = true
				dr.OverlayPath = st.OverlayPath
			}
		}
	}

	if _, err := s.destroy.Destroy(ctx, dr); err != nil {
		// A teardown fault (not idempotency — an absent session converges cleanly,
		// see destroy.go). Surface it so the reconciler re-drives; the §4.2 order
		// already ran unconditionally past the first fault (clean teardown wins).
		return nil, status.Errorf(codes.Internal, "libvirt destroy session %s: %v", sessionUUID, err)
	}

	// Purge the DURABLE captured-ref set now the overlay (the D29 durability unit) is
	// gone — the producer-half twin of the in-memory drop above, so a later recovery
	// never re-adopts a since_snapshot_ref base whose point-in-time the teardown
	// destroyed (seams.go RecoveredSession.SnapshotRefs: "a §4.2 Destroy purges both
	// the durable record and any recovered set"). Runs after a clean teardown so a
	// session whose destroy faulted keeps its record for the re-drive. Idempotent (a
	// missing set is a no-op), fail-loud (a purge fault is surfaced so the reconciler
	// re-drives rather than leave a dangling durable ref). OFF by default (nil store):
	// skipped, byte-identical to the historical destroy.
	if s.capturedRefs != nil {
		if err := s.capturedRefs.RemoveCapturedRefs(ctx, sessionUUID); err != nil {
			return nil, status.Errorf(codes.Internal, "libvirt destroy session %s: purge durable captured refs: %v", sessionUUID, err)
		}
	}

	// ── §4.2 per-session HOST-STATE purge (doc 15 §4.2; doc 06 §(b) clean teardown) ──
	//
	// The §4.2 ordering (destroy.go) tears down the substrate the session ran ON — the
	// domain, the NFT objects, the overlay. These four purges drop the per-session state
	// the host wrote BESIDE it under the OverlayDir, which no step of that ordering owns
	// and which therefore outlived every destroy: the attach TOKEN (a live D39 bearer
	// credential), the config DRIVE (an image plus a 0400 config.pb holding the injected
	// env credentials), the resolved-mode MARKER, and the interception-CA BUNDLE (the
	// dropped cert plus its proxy-bound PKCS#8 private key). The doc 06 §(b) clean-teardown
	// row admits no residue — "no orphaned VM, no leaked NFTables rules, no dangling CoW
	// overlay, no stranded proxy session, NO LEFTOVER MINTED IDENTITY" — and the token, the
	// drive, and the CA key are minted identity in the most literal sense.
	//
	// THEY ALL RUN AFTER A CONVERGED TEARDOWN ONLY (the capturedRefs / sessionRecords
	// precedent above): a session whose destroy FAULTED keeps its host state so the
	// reconciler's re-drive can still resolve, re-reap, and re-purge it. They also run
	// after destroy.Destroy's post-destroy HOOK, which is where the daemon reaps the
	// per-session ds-hostbridge serving child — so the token file is never pulled out from
	// under a still-serving child that holds it open via --session-token-file.
	//
	// FAULT POSTURE, split by what the residue IS. The token, the config drive, and the CA
	// bundle are FAIL-LOUD (the capturedRefs posture): a purge fault leaves live credential
	// material on disk, so the Destroy is surfaced as a fault and the reconciler re-drives — the
	// purges are idempotent, so a re-drive converges. The mode marker is BEST-EFFORT (the
	// sessionRecords posture): its residue is one stale bookkeeping file, which must not
	// convert an otherwise-clean §4.2 teardown into a faulted Destroy over the wire; the
	// fault is RECORDED to the standard logger, never swallowed silently. Each seam is OFF
	// by default (nil ⇒ skipped, byte-identical to the historical destroy), and each
	// removal is idempotent on session_uuid (an absent artifact is a clean success).

	// Purge the per-session ATTACH TOKEN — the D39 short-lived bearer credential the
	// create-path post-boot mint wrote and IssueAttachHandle hands clients. Its TTL
	// (attachHandleTTL, 15 min) is the store's only revocation mechanism (doc 19 §7), so
	// without this a DESTROYED session's token stayed valid on disk for up to a quarter
	// hour past the teardown. FAIL-LOUD: a credential the host could not delete is a real
	// leak, not bookkeeping.
	if s.attachTokens != nil {
		if err := s.attachTokens.RemoveToken(ctx, sessionUUID); err != nil {
			return nil, status.Errorf(codes.Internal, "libvirt destroy session %s: purge attach token: %v", sessionUUID, err)
		}
	}

	// Dispose the per-session CONFIG DRIVE — the read-only iso9660 image AND the staging
	// dir holding config.pb at 0400 (the rendered EntrypointConfig, injected env
	// credentials included). It runs here, after step 1 destroyed the domain, because the
	// image is attached to that domain as its 2nd <disk>; removing it before the domain is
	// gone would pull a mounted drive out from under a live guest. Before this the drive
	// was reclaimed only by the operator-side `ds-serve-stack.sh down --purge` sweep, so
	// every destroyed session left its credentials on the host. FAIL-LOUD, same reason as
	// the token.
	if s.configDrives != nil {
		if err := s.configDrives.RemoveConfigDrive(ctx, sessionUUID); err != nil {
			return nil, status.Errorf(codes.Internal, "libvirt destroy session %s: dispose config drive: %v", sessionUUID, err)
		}
	}

	// Dispose the per-session INTERCEPTION-CA BUNDLE — the cert the orchestrator producer
	// dropped under <OverlayDir>/.ds-ca-bundles AND its proxy-bound PKCS#8 PRIVATE KEY
	// sibling. Nothing removed either before this: the producer wrote them, the step-7
	// consumer read the cert, and both survived every teardown, so a long-lived host held
	// one live CA private key per session ever created — D82's "the per-session CA is
	// destroyed at teardown" was simply untrue. FAIL-LOUD, same reason as the token and the
	// drive; idempotent on the ref (an absent bundle is a clean no-op, so a re-drive
	// converges).
	//
	// UNIQUELY keyed on the caBundleRef rather than the session_uuid, which is why it is
	// threaded out of the durable SessionRecord above: an empty ref means a PRE-UPGRADE
	// record (or no resolver wired), and the disposal is SKIPPED rather than guessed at — a
	// sanitize of "" would name the literal "session" leaf and could delete an unrelated
	// bundle. The operator-side `ds-serve-stack.sh down --purge` sweep is the backstop for
	// that pre-upgrade residue.
	if s.caBundles != nil && caBundleRef != "" {
		if err := s.caBundles.DisposeCABundle(ctx, caBundleRef); err != nil {
			return nil, status.Errorf(codes.Internal, "libvirt destroy session %s: dispose interception CA bundle: %v", sessionUUID, err)
		}
	}

	// Purge the per-session RESOLVED-MODE MARKER (sessionmodestore.go) — host-internal
	// bookkeeping in the same class as the SessionRecord below, so it takes the same
	// BEST-EFFORT posture: a removal fault leaves one stale marker, which is strictly
	// better than converting a clean §4.2 teardown into a faulted Destroy. Recorded to the
	// standard logger (the defaultHookFaultObserver / defaultSuspendAudit sink
	// convention), never swallowed silently.
	if s.sessionModes != nil {
		if err := s.sessionModes.RemoveMode(ctx, sessionUUID); err != nil {
			log.Printf("ds destroy: remove session mode marker (best-effort, swallowed from the §4.2 verdict): session=%s err=%v", sessionUUID, err)
		}
	}

	// Remove the DURABLE SessionRecord the create path Put at boot — the sibling purge of
	// the captured-ref drop above, and the call sessionrecord.go's Remove contract names
	// ("the §4.2 teardown"). It runs at the SAME point and for the same reason: the
	// session's domain is gone, so the record that joins a resident domain to its
	// three-keys-agree binding describes nothing. Left behind, the liveSessionRecoverer
	// (recoverer.go) RE-ADOPTS the destroyed session on the next host-agent restart and the
	// reconciler orphan-quarantines a session whose VM no longer exists.
	//
	// AFTER a clean teardown only (the capturedRefs precedent): a session whose destroy
	// FAULTED keeps its record so the re-drive can still resolve the DomainUUID + overlay
	// through the DestroyResolver. BEST-EFFORT, unlike the captured-ref purge: a missing
	// record is ALREADY a success by contract, so the only residue a removal fault leaves
	// is a stale record — strictly better than converting a clean §4.2 teardown (domain
	// gone, NFT objects flushed, overlay disposed) into a faulted Destroy over the wire.
	// The fault is RECORDED to the standard logger (the defaultHookFaultObserver /
	// defaultSuspendAudit sink convention), never swallowed silently. OFF by default (nil
	// store): skipped, byte-identical to the historical destroy.
	if s.sessionRecords != nil {
		if err := s.sessionRecords.Remove(ctx, sessionUUID); err != nil {
			log.Printf("ds destroy: remove durable session record (best-effort, swallowed from the §4.2 verdict): session=%s err=%v", sessionUUID, err)
		}
	}
	return &hypervisorv1.DestroyResponse{}, nil
}

// cloneResponse lowers the recorded in-package Binding into the frozen
// CloneFromImageResponse. It is the ONLY place a Binding becomes wire bytes — the
// guest IP crosses as the D75 family-tagged GuestAddress (family enum + raw
// bytes, never a fixed32), and NO libvirt/qcow2 internal leaks (the overlay_path
// is the inspectable-artifact PATH the contract already names, D29, not a driver
// type). Keeping this mapping in one function is the zero-leakage invariant's
// enforcement point.
func cloneResponse(b Binding) *hypervisorv1.CloneFromImageResponse {
	return &hypervisorv1.CloneFromImageResponse{
		HostSessionIndex: b.HostSessionIndex,
		TapName:          b.TapName,
		GuestIp: &hypervisorv1.GuestAddress{
			Family:  hypervisorv1.AddressFamily(b.GuestIP.Family),
			Address: append([]byte(nil), b.GuestIP.Address...),
		},
		OverlayPath: b.OverlayPath,
	}
}

// bindingFromCloneResponse re-reads the recorded Binding from a cached
// CloneFromImageResponse — the inverse of cloneResponse. The clone cache holds
// the lowered wire response (the idempotency artifact); IssueAttachHandle needs
// the in-package Binding the handle is minted FROM, so this rebuilds it from the
// four binding fields the response carries (index / tap / family-tagged guest IP /
// overlay path). The guest-IP bytes are copied (the cached response stays the
// authoritative idempotency artifact, never aliased into a mutable binding).
func bindingFromCloneResponse(resp *hypervisorv1.CloneFromImageResponse) Binding {
	b := Binding{
		HostSessionIndex: resp.GetHostSessionIndex(),
		TapName:          resp.GetTapName(),
		OverlayPath:      resp.GetOverlayPath(),
	}
	if gip := resp.GetGuestIp(); gip != nil {
		b.GuestIP = GuestAddress{
			Family:  AddressFamily(gip.GetFamily()),
			Address: append([]byte(nil), gip.GetAddress()...),
		}
	}
	return b
}

// cloneError maps a create-path failure to a gRPC status, preserving the §4.1
// per-step diagnosis in the message without leaking any driver-internal TYPE
// across the contract (the message string is diagnostics; the wire shape stays
// the frozen status). A pre-step-4 refusal (a malformed request, e.g. the
// fail-closed missing CA bundle ref, D17) is InvalidArgument; everything else is
// Internal — a real host-side fault the reconciler re-drives.
func cloneError(sessionUUID string, err error) error {
	var ce *CreateError
	if errors.As(err, &ce) && ce.Step == StepNone {
		return status.Errorf(codes.InvalidArgument, "libvirt clone session %s: %v", sessionUUID, err)
	}
	return status.Errorf(codes.Internal, "libvirt clone session %s: %v", sessionUUID, err)
}

// ── HONEST stubs for the remaining 7 verbs ───────────────────────────────────
//
// Each returns codes.Unimplemented with a clear message — NEVER a faked success
// (doc 15 §5.1: driver honesty is bounded by the capability flags + the
// conformance suite driving wire behavior). The TODO on each names the real
// seam / host-side home the verb wires to when it lands; until then a caller gets
// an honest Unimplemented, not a silent no-op that would strand state.

// IssueAttachHandle mints the D79 transport-ambivalent attach handle (doc 15
// §5.4) for a KNOWN session: it looks the session up in the clone cache (the
// session must have cloned — its recorded Binding is the host-side attachment
// artifact the handle is issued FOR), then mints the attach.v1 handle via the
// AttachHandleMinter seam in the requested D61 Role (WRITER | READER), returning
// the populated handle (endpoints + short-lived auth + role + expiry) wrapped in
// IssueAttachHandleResponse.
//
// PRECONDITIONS, mapped to gRPC codes:
//   - empty session_uuid ⇒ InvalidArgument (the lookup key is required);
//   - a session_uuid with no recorded binding ⇒ NotFound (you cannot attach to a
//     session that never cloned / was torn down — Destroy drops the cache entry);
//   - no minter wired ⇒ Unimplemented (the host-side minter has not landed; the
//     same honest posture as the other host-side-only verbs).
//
// IDEMPOTENT on (session_uuid, role): the minter is deterministic, so a retry for
// the same session+role re-issues an EQUIVALENT handle rather than forking a
// second seat — a retried IssueAttachHandle after a control-plane blip converges.
//
// The handle message is attach.v1-OWNED (minted by the seam, wrapped here); this
// binding never authors the transport endpoint or the auth material itself — that
// is the host-side minter's job (the hostbridge D79 endpoint + the identity-D22
// per-session auth), kept behind the seam so the driver stays offline + stdlib.
func (s *DriverService) IssueAttachHandle(ctx context.Context, req *hypervisorv1.IssueAttachHandleRequest) (*hypervisorv1.IssueAttachHandleResponse, error) {
	if s.minter == nil {
		return nil, status.Error(codes.Unimplemented, "IssueAttachHandle: attach-handle minting (attach.v1, doc 15 §5.4) is not wired in this driver (no AttachHandleMinter); the hostbridge D79 endpoint + identity-D22 auth land host-side")
	}

	sessionUUID := req.GetSessionUuid()
	if sessionUUID == "" {
		return nil, status.Error(codes.InvalidArgument, "IssueAttachHandle requires session_uuid (the session to mint an attach handle for)")
	}

	// The session must exist: the handle is issued FOR a recorded binding (the
	// host-side attachment artifact). A session_uuid the clone cache does not know
	// either never cloned or was torn down (Destroy drops the entry) — there is
	// nothing to attach to, so NotFound, never a faked handle.
	s.mu.Lock()
	cloned, ok := s.clones[sessionUUID]
	s.mu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "IssueAttachHandle: session %s has no recorded binding (it never cloned or was torn down); cannot mint an attach handle", sessionUUID)
	}

	// Mint via the seam from the recorded binding in the requested role. The minter
	// is deterministic ⇒ idempotent on (session_uuid, role): a retry re-issues an
	// equivalent handle (doc 15 §5.4).
	handle, err := s.minter.MintAttachHandle(ctx, sessionUUID, bindingFromCloneResponse(cloned), req.GetRole())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "libvirt issue attach handle for session %s: %v", sessionUUID, err)
	}
	return &hypervisorv1.IssueAttachHandleResponse{Handle: handle}, nil
}

// Snapshot captures a durable point-in-time of a session's per-session qcow2
// overlay — the §5.1 Snapshot verb over the D29 durability unit (doc 15 §5.1;
// D29/D30) — over the SnapshotStore seam, and returns the OPAQUE snapshot_ref.
// It is the sibling of CloneFromImage's OverlayStore over the same D29 substrate:
// CloneFromImage CREATES the per-session overlay; Snapshot CAPTURES a durable
// point-in-time of it — the disk-delta substrate GetCapabilities already
// advertises (supports_disk_delta_export=true), surfaced here as a named capture.
//
// PRECONDITIONS, mapped to gRPC codes:
//   - empty session_uuid ⇒ InvalidArgument (the target key is required);
//   - a session_uuid with no recorded binding ⇒ NotFound (you cannot snapshot a
//     session that never cloned / was torn down — the IssueAttachHandle/Suspend
//     precedent; Destroy drops the cache entry);
//   - no SnapshotStore wired ⇒ Unimplemented (the host-side external-snapshot
//     capture has not landed; the same honest posture as the other host-side-only
//     verbs).
//
// The label is OPTIONAL (the frozen SnapshotRequest.label) — it names the
// point-in-time; an empty label is the unlabeled-capture case. IDEMPOTENT on
// (session_uuid, label): the seam is deterministic, so a retry for the same
// (session, label) returns an EQUIVALENT snapshot_ref rather than forking a second
// durable snapshot — a retried Snapshot after a control-plane blip re-names the
// same capture, it does not duplicate it (doc 15 §5.1).
//
// ZERO QEMU/libvirt leakage (D29/D30): the response carries ONLY the opaque
// snapshot_ref the seam returns — never a libvirt snapshot-XML, a qcow2 path, or a
// driver-internal type; the external-snapshot mechanics stay behind the seam.
func (s *DriverService) Snapshot(ctx context.Context, req *hypervisorv1.SnapshotRequest) (*hypervisorv1.SnapshotResponse, error) {
	if s.snapshots == nil {
		return nil, status.Error(codes.Unimplemented, "Snapshot: per-session overlay snapshot (D29) is not wired in this driver (no SnapshotStore); the libvirt external-snapshot capture lands host-side")
	}

	sessionUUID := req.GetSessionUuid()
	if sessionUUID == "" {
		return nil, status.Error(codes.InvalidArgument, "Snapshot requires session_uuid (the session whose overlay to capture)")
	}

	// The session must exist: a snapshot captures a recorded binding's overlay (the
	// host-side D29 durability unit). A session_uuid the clone cache does not know
	// either never cloned or was torn down (Destroy drops the entry) — there is
	// nothing to capture, so NotFound, never a faked snapshot_ref.
	s.mu.Lock()
	_, ok := s.clones[sessionUUID]
	s.mu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Snapshot: session %s has no recorded binding (it never cloned or was torn down); cannot snapshot its overlay", sessionUUID)
	}

	// Capture via the seam with the optional label. Deterministic on
	// (session_uuid, label) ⇒ idempotent: a retry for the same session+label
	// re-names the same point-in-time (an equivalent snapshot_ref), never a second
	// durable snapshot.
	snapshotRef, err := s.snapshots.CreateSnapshot(ctx, sessionUUID, req.GetLabel())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "libvirt snapshot session %s: %v", sessionUUID, err)
	}

	// Register the captured ref so a subsequent ExportDiskDelta can name it back as
	// since_snapshot_ref (the D29 capture→export loop closure). Mirrors the clones
	// mutex discipline. The seam is deterministic on (session, label), so an
	// idempotent re-Snapshot re-registers the SAME ref — a harmless set-insert,
	// never a second entry. Guard against a session whose binding was torn down
	// between the cache check and here (a concurrent Destroy dropped the ref set):
	// re-seat the set under the lock so the ref is recorded for the live session.
	s.mu.Lock()
	refs := s.snapshotRefs[sessionUUID]
	if refs == nil {
		refs = make(map[string]struct{})
		s.snapshotRefs[sessionUUID] = refs
	}
	refs[snapshotRef] = struct{}{}
	s.mu.Unlock()

	// DURABLY persist the captured ref (the PRODUCER half of the snapshotRefs
	// registry) so it survives a driver restart: the in-memory set above is
	// per-process state a restart loses, so without this the ref would stop being a
	// valid since_snapshot_ref base the moment the driver restarted (a post-restart
	// ExportDiskDelta rooted at the still-live point-in-time would falsely fail
	// NotFound). On a restart the captured-ref-aware SessionRecoverer reads this set
	// back out into RecoveredSession.SnapshotRefs and RecoverSessions re-seeds the
	// registry from it. FAIL-CLOSED: a durable-write fault fails the RPC rather than
	// report a capture whose base a restart would silently lose — the seam is
	// idempotent (a set-insert), so a retried Snapshot re-drives cleanly. OFF by
	// default (nil store): the durable-write is skipped and the behavior is
	// byte-identical to the in-memory-only posture (done outside the lock — the store
	// is host I/O, never held under mu).
	if s.capturedRefs != nil {
		if err := s.capturedRefs.RecordCapturedRef(ctx, sessionUUID, snapshotRef); err != nil {
			return nil, status.Errorf(codes.Internal, "libvirt snapshot session %s: persist captured ref durably: %v", sessionUUID, err)
		}
	}

	return &hypervisorv1.SnapshotResponse{SnapshotRef: snapshotRef}, nil
}

// Suspend pauses a session domain — the §3 RUNNING→SUSPENDED(reason) transition
// (doc 15 §4.3; D46/D77) — over the Suspender seam, after validating the
// D77-narrowed reason taxonomy AT THIS BINDING (doc 15 §4.3: reason validation is
// the orchestrator's, the suspend/resume mechanics are Boundary-owned, D46, doc
// 15 §1 "Not owned").
//
// PRECONDITIONS, mapped to gRPC codes (checked BEFORE the seam is ever called):
//   - empty session_uuid ⇒ InvalidArgument (the target key is required);
//   - SUSPEND_REASON_UNSPECIFIED ⇒ InvalidArgument (a reason is REQUIRED — the §3
//     SUSPENDED state is always reason-tagged; an untyped suspend is malformed);
//   - SUSPEND_REASON_POLICY_BREACH with NO provenance ⇒ InvalidArgument (the D77
//     genuine-threat narrowing, doc 15 §4.3: a POLICY_BREACH pause must carry the
//     policy-rule lineage that justified it — USER/REBALANCE need no provenance,
//     which is simply left unset, never an error);
//   - a session_uuid with no recorded binding ⇒ NotFound (you cannot suspend a
//     session that never cloned / was torn down — the IssueAttachHandle
//     precedent; Destroy drops the cache entry);
//   - no suspender wired ⇒ Unimplemented (the host-side domain-suspend/managedsave
//     has not landed; the same honest posture as the other host-side-only verbs).
//
// IDEMPOTENT on session_uuid: re-suspending an already-suspended session is a
// no-op success — the seam converges (a deterministic fake makes that assertable
// over the wire), so a retried Suspend after a control-plane blip re-converges
// rather than faults (doc 15 §5.1).
func (s *DriverService) Suspend(ctx context.Context, req *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error) {
	if s.suspender == nil {
		return nil, status.Error(codes.Unimplemented, "Suspend: domain suspend (D46/D77) is not wired in this driver (no Suspender); the libvirt domain-suspend/managedsave lands host-side")
	}

	sessionUUID := req.GetSessionUuid()
	if sessionUUID == "" {
		return nil, status.Error(codes.InvalidArgument, "Suspend requires session_uuid (the session to pause)")
	}

	// D77 reason validation (doc 15 §4.3) — enforced HERE, before the seam: a
	// reason is always required, and POLICY_BREACH must carry the provenance that
	// justified the genuine-threat pause.
	reason := req.GetReason()
	if reason == hypervisorv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "Suspend requires a reason (the §3 SUSPENDED state is reason-tagged; SUSPEND_REASON_UNSPECIFIED is not a valid suspend)")
	}
	if reason == hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH && req.GetProvenance() == nil {
		return nil, status.Error(codes.InvalidArgument, "Suspend with SUSPEND_REASON_POLICY_BREACH requires provenance (the D77 genuine-threat narrowing: a policy-breach pause must carry the policy-rule lineage that justified it)")
	}

	// The session must exist: a suspend acts on a recorded binding (the host-side
	// domain). A session_uuid the clone cache does not know either never cloned or
	// was torn down (Destroy drops the entry) — there is nothing to pause, so
	// NotFound, never a faked success.
	s.mu.Lock()
	_, ok := s.clones[sessionUUID]
	s.mu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Suspend: session %s has no recorded binding (it never cloned or was torn down); cannot suspend", sessionUUID)
	}

	// Pause via the seam with the vetted reason + provenance (carried through for
	// the host-side audit record, D77). Idempotent on session_uuid: re-suspending
	// an already-suspended session converges to a no-op success.
	if err := s.suspender.Suspend(ctx, sessionUUID, reason, req.GetProvenance()); err != nil {
		return nil, status.Errorf(codes.Internal, "libvirt suspend session %s: %v", sessionUUID, err)
	}
	return &hypervisorv1.SuspendResponse{}, nil
}

// Resume restarts a suspended session domain — the §3 SUSPENDED→RUNNING
// transition (doc 15 §4.3; D46), the inverse of Suspend — over the Suspender
// seam's resume side (libvirt domain resume / restore-from-managedsave).
//
// PRECONDITIONS, mapped to gRPC codes:
//   - empty session_uuid ⇒ InvalidArgument (the target key is required);
//   - a session_uuid with no recorded binding ⇒ NotFound (you cannot resume a
//     session that never cloned / was torn down — the IssueAttachHandle/Suspend
//     precedent);
//   - no suspender wired ⇒ Unimplemented (the host-side domain-resume has not
//     landed; the same honest posture as the other host-side-only verbs).
//
// There is no reason on a resume (ResumeRequest is session_uuid only — the §3
// transition back to RUNNING needs no taxonomy). IDEMPOTENT on session_uuid:
// re-resuming an already-running session is a no-op success — the seam converges,
// so a retried Resume after a blip re-converges (doc 15 §5.1).
func (s *DriverService) Resume(ctx context.Context, req *hypervisorv1.ResumeRequest) (*hypervisorv1.ResumeResponse, error) {
	if s.suspender == nil {
		return nil, status.Error(codes.Unimplemented, "Resume: domain resume (D46) is not wired in this driver (no Suspender); the libvirt domain-resume/restore lands host-side")
	}

	sessionUUID := req.GetSessionUuid()
	if sessionUUID == "" {
		return nil, status.Error(codes.InvalidArgument, "Resume requires session_uuid (the session to restore)")
	}

	// The session must exist (the Suspend/IssueAttachHandle precedent): a resume
	// acts on a recorded binding; an unknown session has nothing to restore.
	s.mu.Lock()
	_, ok := s.clones[sessionUUID]
	s.mu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Resume: session %s has no recorded binding (it never cloned or was torn down); cannot resume", sessionUUID)
	}

	// Restore via the seam. Idempotent on session_uuid: re-resuming an
	// already-running session converges to a no-op success.
	if err := s.suspender.Resume(ctx, sessionUUID); err != nil {
		return nil, status.Errorf(codes.Internal, "libvirt resume session %s: %v", sessionUUID, err)
	}
	return &hypervisorv1.ResumeResponse{}, nil
}

// Migrate moves a session between hosts; capability-gated on
// Capabilities.supports_migrate (which GetCapabilities honestly answers FALSE
// for v0), internals free until M3 (doc 15 §5.1).
// TODO(migrate): M3 — wire to a cross-host migration seam once the host-local
// never-recycled index + tap binding (D66) is migration-safe. supports_migrate
// must flip to true IN LOCKSTEP with this landing (the capability-honesty
// contract); until then the honest answer is Unimplemented.
func (s *DriverService) Migrate(_ context.Context, _ *hypervisorv1.MigrateRequest) (*hypervisorv1.MigrateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Migrate: cross-host migration is M3 (supports_migrate=false); not wired in the v0 libvirt driver")
}

// exportDeltaChunkSize is the wire frame payload size for ExportDiskDelta: each
// ExportDiskDeltaResponse carries up to this many delta bytes. 32 KiB is the
// stdlib io.Copy default buffer and a comfortable fit under the gRPC default
// 4 MiB message ceiling — large enough to amortize per-frame overhead, small
// enough that a cancellation is observed promptly between frames.
const exportDeltaChunkSize = 32 * 1024

// ExportDiskDelta streams the D29 qcow2-overlay dirty-bitmap delta of a session's
// per-session overlay (the §5.1 server-streaming verb over the D29 durability
// unit; doc 15 §5.1; D29/D30) over the DiskDeltaExporter seam. It is
// capability-gated on Capabilities.supports_disk_delta_export (which
// GetCapabilities honestly answers TRUE for v0 — the underlying dirty-bitmap
// substrate exists, the same substrate destroy.go's DurabilityFinalizer finalizes
// at §4.2 step 3); this streaming verb is the one catching up to that flag.
//
// PRECONDITIONS, mapped to gRPC codes (checked BEFORE the seam is ever opened):
//   - no exporter wired ⇒ Unimplemented (the host-side dirty-bitmap/qemu-img delta
//     extraction has not landed; the same honest posture as the other
//     host-side-only verbs — never a false advertisement of the true capability
//     flag, just the honest streaming gap);
//   - empty session_uuid ⇒ InvalidArgument (the target key is required);
//   - a session_uuid with no recorded binding ⇒ NotFound (you cannot export a
//     delta for a session that never cloned / was torn down — the Snapshot/Suspend
//     precedent; Destroy drops the cache entry).
//
// The since_snapshot_ref is OPTIONAL (the frozen ExportDiskDeltaRequest field):
// empty requests the FULL overlay delta (passed through as the empty base); a
// non-empty opaque base snapshot reference requests the incremental delta SINCE
// that base. The D29 capture→export loop closure (D29/D30) VALIDATES a non-empty
// base BEFORE the seam is opened: it must be a ref a prior Snapshot captured FOR
// THIS SESSION (the snapshotRefs registry). A non-empty since_snapshot_ref the
// session never captured is rejected codes.NotFound (the base point-in-time does
// not exist — you cannot root an incremental delta at a snapshot that was never
// taken), in the same fail-before-the-seam posture as the unknown-session check;
// the registry is consulted under the same mu that guards clones.
//
// FRAMING: the seam yields a raw byte reader; this verb frames it into
// ExportDiskDeltaResponse{offset, data} chunks of at most exportDeltaChunkSize,
// where offset is the running byte count BEFORE each chunk — so offsets are
// MONOTONIC and CONTIGUOUS (frame N starts exactly where frame N-1's data ended)
// and the control plane reassembles the delta by concatenation. stream.Context()
// is checked before each Send so a client cancellation stops streaming promptly
// and returns the ctx error; the reader is ALWAYS Closed (success, fault, or
// cancellation) so the host-side bitmap/qemu-img handle is released.
//
// ZERO QEMU/libvirt leakage (D29/D30): frames carry ONLY {offset, bytes} — never
// a qcow2 path, a dirty-bitmap name, or any QEMU monitor type; the extraction
// mechanics stay behind the seam, the same invariant Snapshot enforces for the
// snapshot_ref.
func (s *DriverService) ExportDiskDelta(req *hypervisorv1.ExportDiskDeltaRequest, stream hypervisorv1.HypervisorDriverService_ExportDiskDeltaServer) error {
	if s.exporter == nil {
		return status.Error(codes.Unimplemented, "ExportDiskDelta: D29 dirty-bitmap delta streaming is not wired in this driver (no DiskDeltaExporter); the libvirt dirty-bitmap/qemu-img extraction lands host-side")
	}

	sessionUUID := req.GetSessionUuid()
	if sessionUUID == "" {
		return status.Error(codes.InvalidArgument, "ExportDiskDelta requires session_uuid (the session whose overlay delta to export)")
	}

	// The session must exist AND, for an incremental export, the base snapshot it is
	// rooted at must be one this session actually captured — both checked under the
	// same lock (a consistent snapshot of the per-session state, so a concurrent
	// Destroy can't tear the binding out between the two reads). A session_uuid the
	// clone cache does not know either never cloned or was torn down (Destroy drops
	// the entry) — there is nothing to export, so NotFound, never an empty/faked
	// stream. A non-empty since_snapshot_ref that this session never captured roots
	// the delta at a point-in-time that does not exist — NotFound, before the seam
	// is ever opened. An empty since_snapshot_ref is the FULL-overlay export (no
	// base to validate) and falls straight through.
	sinceRef := req.GetSinceSnapshotRef()
	s.mu.Lock()
	_, ok := s.clones[sessionUUID]
	knownRef := true
	if ok && sinceRef != "" {
		_, knownRef = s.snapshotRefs[sessionUUID][sinceRef]
	}
	s.mu.Unlock()
	if !ok {
		return status.Errorf(codes.NotFound, "ExportDiskDelta: session %s has no recorded binding (it never cloned or was torn down); cannot export its overlay delta", sessionUUID)
	}
	if !knownRef {
		return status.Errorf(codes.NotFound, "ExportDiskDelta: since_snapshot_ref %s is not a known snapshot of session %s (the base point-in-time does not exist; capture it with Snapshot first)", sinceRef, sessionUUID)
	}

	ctx := stream.Context()

	// Open the delta via the seam with the optional base ref (empty ⇒ full overlay,
	// non-empty ⇒ incremental since that base snapshot). The seam yields the raw
	// bytes; we own the framing AND the Close (deferred so it runs on every exit:
	// success, a read fault, a Send fault, or a cancellation).
	reader, err := s.exporter.OpenDelta(ctx, sessionUUID, sinceRef)
	if err != nil {
		return status.Errorf(codes.Internal, "libvirt export disk delta session %s: %v", sessionUUID, err)
	}
	defer func() { _ = reader.Close() }()

	buf := make([]byte, exportDeltaChunkSize)
	var offset uint64
	for {
		// Honor cancellation between frames: a client that aborts the stream stops
		// the export promptly with the ctx error (the reader is still Closed by the
		// deferred Close above).
		if err := ctx.Err(); err != nil {
			return status.FromContextError(err).Err()
		}

		n, readErr := reader.Read(buf)
		if n > 0 {
			// data is a copy: protobuf marshals the field before the next Read
			// overwrites buf, but copying keeps the frame independent of the reused
			// buffer and the Send timing. offset is the running count BEFORE this
			// chunk ⇒ monotonic + contiguous.
			frame := make([]byte, n)
			copy(frame, buf[:n])
			if err := stream.Send(&hypervisorv1.ExportDiskDeltaResponse{Offset: offset, Data: frame}); err != nil {
				return err
			}
			offset += uint64(n)
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return status.Errorf(codes.Internal, "libvirt export disk delta session %s: read: %v", sessionUUID, readErr)
		}
	}
}

// RecoverSessions re-adopts the sessions a host was running after a host-agent or
// driver restart (restart re-adoption; D66 never-recycled indices, doc 15 §4
// "Crash matrix" / §5.1). The per-process clone-idempotency cache and the index
// Allocator are in-memory state a restart loses; a retried CloneFromImage after a
// crash would otherwise burn a SECOND never-recycled index (D66) instead of
// re-adopting the live session. This verb closes that gap: it re-observes the
// host-resident domains + their recorded bindings (the SessionRecoverer seam,
// host-side) and re-seeds BOTH halves of the lost state —
//
//	(a) the Allocator: the shared index counter is advanced STRICTLY PAST the
//	    highest recovered index (the newMemCounter resume point), so the next
//	    Allocate() never re-hands a live index; and
//	(b) the clone cache: each recovered session's binding is re-seeded under its
//	    session_uuid, so a post-recover CloneFromImage for it returns the ADOPTED
//	    binding (same index/tap/guest-ip/overlay) WITHOUT a fresh Allocate (no
//	    second index burned).
//
// The re-observation is HOST-SIDE (the recoverer enumerates resident libvirt
// domains + persisted session records); this binding lowers each RecoveredSession
// into the frozen ObservedSession the RecoverSessionsResponse carries. It is
// IDEMPOTENT: an empty recovery set (a fresh host, nothing resident) is a clean
// no-op (the counter is not moved, the cache is untouched), and re-invocation
// over an unchanged host converges (SeedAtLeast is forward-only, the cache
// re-seed re-writes the same adopted bindings).
//
// RECOVER-BEFORE-SERVE: completing this verb (success, INCLUDING the empty-set
// fresh-host no-op) sets the `recovered` latch, which is the precondition
// CloneFromImage gates on for a recovery-wired host (D66). The latch is set LAST
// — after both the counter re-seed and the clone-cache re-adoption succeed — so a
// clone can only serve once the lost state is restored; a re-invocation re-sets
// it (the latch stays set). A re-observation FAULT returns early WITHOUT setting
// the latch, so a host whose recovery failed keeps clones gated until a retried
// RecoverSessions succeeds.
//
// When no recoverer is wired (the NewDriverService path) the verb answers an
// honest codes.Unimplemented — the same posture as the other host-side-only
// verbs; the real re-observation lands host-side on the virtual-metal box.
func (s *DriverService) RecoverSessions(ctx context.Context, req *hypervisorv1.RecoverSessionsRequest) (*hypervisorv1.RecoverSessionsResponse, error) {
	if s.recover == nil || s.counter == nil {
		return nil, status.Error(codes.Unimplemented, "RecoverSessions: restart re-adoption (D66) is not wired in this driver (no SessionRecoverer); re-observation lands host-side")
	}

	hostID := req.GetHostId()
	if hostID == "" {
		return nil, status.Error(codes.InvalidArgument, "RecoverSessions requires host_id (the host whose resident sessions to re-observe)")
	}

	recovered, err := s.recover.RecoverSessions(ctx, hostID)
	if err != nil {
		// A re-observation fault (the host-resident enumeration failed) — surface
		// it so the reconciler re-drives. The Allocator/cache are left untouched:
		// re-seeding from a partial/failed observation could re-hand a live index.
		return nil, status.Errorf(codes.Internal, "libvirt recover sessions for host %s: %v", hostID, err)
	}

	// Empty set ⇒ fresh host, nothing resident: a clean no-op. The counter is not
	// advanced and the cache is untouched, so the verb is idempotent on a fresh
	// host (re-invocation observes empty again and changes nothing). The
	// recover-before-serve precondition is STILL satisfied — a fresh host has no
	// recovered index to collide with, so set the latch and let clones serve.
	if len(recovered) == 0 {
		s.recovered.Store(true)
		return &hypervisorv1.RecoverSessionsResponse{}, nil
	}

	// Lower each re-observed session into the frozen ObservedSession, validate the
	// recorded binding (a malformed binding can never satisfy three-keys-agree, so
	// re-adopting it would strand state), find the highest recovered index, and
	// stage the adopted clone responses AND the durable snapshot-ref sets for the
	// re-seed.
	observed := make([]*hypervisorv1.ObservedSession, 0, len(recovered))
	adopted := make(map[string]*hypervisorv1.CloneFromImageResponse, len(recovered))
	// adoptedRefs stages each recovered session's durable snapshot_refs (the
	// captured-ref registry the host still holds, RecoveredSession.SnapshotRefs) so
	// the in-memory snapshotRefs cache is re-seeded to MATCH the durable reality —
	// the base-authority decision recorded on RecoveredSession.SnapshotRefs: the
	// host's set is authoritative, the driver re-adopts it across a restart so a
	// captured ref survives re-adoption and still roots an incremental
	// ExportDiskDelta (the D29 capture→export loop closure). Built per session as a
	// SET (the same struct{}-valued shape as the live registry), so a recovered set
	// with duplicate refs collapses harmlessly. A session with no durable refs
	// stages no entry (the common empty case).
	adoptedRefs := make(map[string]map[string]struct{}, len(recovered))
	var highest uint64
	for _, rs := range recovered {
		if rs.SessionUUID == "" {
			return nil, status.Error(codes.Internal, "libvirt recover sessions: recovered session has no session_uuid (the re-adoption idempotency key)")
		}
		if err := rs.Binding.validate(); err != nil {
			return nil, status.Errorf(codes.Internal, "libvirt recover sessions: recovered binding for session %s invalid: %v", rs.SessionUUID, err)
		}
		if rs.Binding.HostSessionIndex > highest {
			highest = rs.Binding.HostSessionIndex
		}
		observed = append(observed, &hypervisorv1.ObservedSession{
			SessionUuid:      rs.SessionUUID,
			DomainUuid:       rs.DomainUUID,
			HostSessionIndex: rs.Binding.HostSessionIndex,
			TapName:          rs.Binding.TapName,
			OverlayPath:      rs.Binding.OverlayPath,
		})
		// The adopted clone response is the SAME binding the session already holds
		// — lowered through the single cloneResponse mapping (the zero-leakage
		// invariant's one enforcement point), so a post-recover CloneFromImage for
		// this session returns it verbatim.
		adopted[rs.SessionUUID] = cloneResponse(rs.Binding)
		// Stage the durable captured-ref set (a snapshot_ref the host still holds is
		// a valid since_snapshot_ref base, BASE AUTHORITY = the host's record). An
		// empty/absent SnapshotRefs stages nothing for this session — the common
		// no-capture case.
		if len(rs.SnapshotRefs) > 0 {
			set := make(map[string]struct{}, len(rs.SnapshotRefs))
			for _, ref := range rs.SnapshotRefs {
				if ref == "" {
					// A durable record never holds an empty ref (the empty
					// since_snapshot_ref is the full-overlay sentinel, never a captured
					// point-in-time); skip it so the re-seeded set is exactly the valid
					// bases, fail-closed.
					continue
				}
				set[ref] = struct{}{}
			}
			if len(set) > 0 {
				adoptedRefs[rs.SessionUUID] = set
			}
		}
	}

	// (a) Re-seed the Allocator: advance the shared counter STRICTLY past the
	// highest recovered index so the next Allocate() never re-hands a live index
	// (D66 never-recycle). SeedAtLeast is forward-only — a re-invocation with the
	// same (or a lower) highest is a no-op, so the counter only ever moves
	// forward. highest+1 is the resume point; the +1 is what makes "strictly
	// past" exact (the next index is at least highest+1).
	s.counter.SeedAtLeast(highest)

	// (b) Re-seed the clone cache so a retried CloneFromImage for a recovered
	// session re-adopts (returns the staged binding) instead of burning a fresh
	// index, AND re-seed the snapshotRefs registry from each recovered session's
	// durable captured-ref set so a captured snapshot survives the re-adoption and
	// still roots an incremental ExportDiskDelta (the D29 capture→export loop
	// closure; the base-authority decision: the host's durable set is
	// authoritative, the driver re-adopts it). A session_uuid the live cache
	// already knows wins (a concurrent clone landed first); recovery never clobbers
	// a freshly-cloned binding — and for the SAME reason it never clobbers a ref set
	// a live capture already seeded (a concurrent Snapshot landed first), so the two
	// re-seeds keep the same first-writer-wins discipline. Both under the one mu
	// that guards clones AND snapshotRefs.
	s.mu.Lock()
	for sessionUUID, resp := range adopted {
		if _, ok := s.clones[sessionUUID]; !ok {
			s.clones[sessionUUID] = resp
		}
	}
	for sessionUUID, refs := range adoptedRefs {
		// Recovery re-adopts the durable set only for a session the live registry
		// has not already seeded — a concurrent Snapshot for a re-cloned session
		// owns its (live) set; recovery never overwrites it. For a freshly-recovered
		// session (the cache+registry both empty for it until now) this installs the
		// durable bases the host still holds.
		if _, ok := s.snapshotRefs[sessionUUID]; !ok {
			s.snapshotRefs[sessionUUID] = refs
		}
	}
	s.mu.Unlock()

	// Recover-before-serve: BOTH halves of the lost state are re-seeded (the
	// counter advanced past the highest recovered index, the clone cache
	// re-adopted), so the precondition is satisfied — set the latch LAST so a
	// concurrent CloneFromImage only passes the gate once re-seeding is complete.
	// Idempotent: a re-invocation re-Stores true (the latch stays set).
	s.recovered.Store(true)

	return &hypervisorv1.RecoverSessionsResponse{Sessions: observed}, nil
}
