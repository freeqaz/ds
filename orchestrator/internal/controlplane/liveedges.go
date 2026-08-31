package controlplane

// liveedges.go is the REMAINING deployment-input leg of the live-edge fill (extends
// the orch20 host-driver dial in dialregistry.go): the Identity (D22/D82) mint /
// digest / revoke clients the §4.1 create coordinator consumes, the host-folded
// CA-inject + boot verbs (steps 7–8), and the external-Postgres store constructor —
// so a live orchestrator builds NewControlPlane end-to-end (dial → serve →
// CreateSession → reconcile closes). Every constructor here is a LIVE network/DB edge,
// reached ONLY under DS_ORCH_LIVE=1 (main.go's liveDeps); a non-live run never builds
// one and the tests drive the FAKES (D50: no live VM/host-agent/podman/Identity dial).
//
// WHY THE IDENTITY DIAL LIVES HERE (the gRPC-confinement rule, mirrored from seams.go /
// dialregistry.go). The orchestrator reaches the Identity mint + digest services ONLY
// through the frozen identity.v1 generated clients — the one legal cross-tree import is
// proto/gen/go (CLAUDE.md). So each production Identity adapter holds a NARROW
// client face (mintWire / digestWire) declared here with the GENERATED-FAKE method
// shape (no `opts ...grpc.CallOption` tail) so the generated identityv1fake satisfies
// it NATIVELY in tests; the real generated client (whose methods carry the call-options
// tail) is adapted onto that face by a thin shim (mintShim / digestShim) the dial site
// wraps. The gRPC dependency stays confined to the shims + the dial constructor; the
// rest of the package is gRPC-free, exercised against the fake.
//
// WHY INJECT + BOOT ARE HOST-FOLDED (no separate gRPC service). The §4.1 step-7 CA
// injection and step-8 boot are HOST-SIDE verbs the host agent's libvirt driver runs
// INSIDE its CloneFromImage path (internal/hypervisor/libvirt/create.go steps 7–8:
// CreateOverlay → InjectCA fail-closed → Boot) — they are NOT distinct RPCs the
// orchestrator dials (there is no inject/boot method on hypervisor.v1 or any other
// frozen service; doc 15 §4.1 / doc 16 §4: the injection mechanism is host-local). The
// orchestrator drives CloneFromImage (the hostAllocator seam, seams.go) and the host
// agent performs inject+boot host-side as part of materializing the VM; the
// orchestrator's view of those steps is the host-folded adapter below — a verb that
// records the host-folded execution and surfaces a fail-closed error only if the
// deployment is misconfigured. The v0 single-host posture (D80) folds them; an M3 split
// that hoists inject/boot onto a distinct boundary RPC swaps the adapter, not the seam.

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"google.golang.org/grpc"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// ---------------------------------------------------------------------------
// Identity (D22/D82) gRPC-backed Mint + Digest + Revoke clients.
//
// The narrow wire faces (mintWire / digestWire) are the generated-FAKE method shape;
// the shims (mintShim / digestShim) adapt the real generated identity.v1 clients onto
// them (dropping the call-options tail). The production MintClient / DigestClient /
// RevokeClient (liveMint / liveDigest / liveRevoke) drive the §4.1 step-5/6 verbs over
// the wire faces, mapping the orchestrator's DATA-carried claims onto the frozen
// identity.v1 messages. Tests drive the wire faces directly with the generated fakes.
// ---------------------------------------------------------------------------

// mintWire is the orchestrator's narrow view of identity.v1.IdentityMintService — the
// MintInterceptionCA verb in the generated-fake shape (no `opts ...grpc.CallOption`
// tail) so the generated IdentityMintServiceFake satisfies it natively in tests (D50).
// The dialed generated client is adapted onto it by mintShim; tests pass the fake.
type mintWire interface {
	MintInterceptionCA(ctx context.Context, in *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error)
}

// digestWire is the orchestrator's narrow view of identity.v1.DigestFeedService — the
// DigestPublish + DigestRevoke verbs (D73 / teardown) in the generated-fake shape, so
// the generated DigestFeedServiceFake satisfies it natively. The dialed generated client
// is adapted onto it by digestShim; tests pass the fake.
type digestWire interface {
	DigestPublish(ctx context.Context, in *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error)
	DigestRevoke(ctx context.Context, in *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error)
}

// mintShim adapts a generated identity.v1 IdentityMintServiceClient onto the narrow
// mintWire face (dropping the `opts ...grpc.CallOption` tail). It is the production
// bridge the identity dial wraps the dialed client in — confining the gRPC dependency
// to this shim + the dial (NewIdentityClients).
type mintShim struct {
	client identityv1.IdentityMintServiceClient
}

func (s mintShim) MintInterceptionCA(ctx context.Context, in *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
	return s.client.MintInterceptionCA(ctx, in)
}

// digestShim adapts a generated identity.v1 DigestFeedServiceClient onto the narrow
// digestWire face (dropping the call-options tail).
type digestShim struct {
	client identityv1.DigestFeedServiceClient
}

func (s digestShim) DigestPublish(ctx context.Context, in *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
	return s.client.DigestPublish(ctx, in)
}

func (s digestShim) DigestRevoke(ctx context.Context, in *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
	return s.client.DigestRevoke(ctx, in)
}

// liveMint is the production MintClient (identityseams.go's seam): it drives the
// identity.v1 MintInterceptionCA verb (§4.1 step 5, D82 — the per-session interception
// CA under the interception root) and returns the orchestrator's identityRef/caRef view.
// The workload-identity claims are carried as DATA on the seam; the SESSION the CA is
// minted for is the identity-plane join key (the frozen MintInterceptionCARequest carries
// only the SessionRef — the claims drive the off-host mint, doc 16 §4). The returned
// caRef is the per-session CA reference the step-7 injection and the step-6 digest write
// key on; the identityRef is the session-uuid-scoped handle the step-5/6 rollback revokes.
//
// liveMint is ALSO an expiry-aware mint seam (MintExpiryClient): it satisfies the optional
// MintWithExpiry extension (identityseams.go) so the live PRODUCER leg lifts the mint/CA
// expiry the bare Mint tuple drops — the frozen
// identity.v1 MintInterceptionCAResponse.expiry_unix_seconds (the session-lifetime CA
// expiry, "the CA dies at teardown", D82; the per-session credential is short-lived, D22).
// mintReply (identityseams.go) type-asserts a MintClient to MintExpiryClient and falls
// back to the bare Mint when it is absent; before this leg the production liveMint was
// bare-only, so the proto expiry was read off the wire and DROPPED (Expiry stayed zero in
// production). Satisfying MintExpiryClient here is the additive fix: MintReply.Expiry is
// populated from the proto on the live path WITHOUT a change to the frozen MintReply /
// MintClient seam (no existing implementer is forced to grow a method).
type liveMint struct {
	wire mintWire

	// producer is the OPTIONAL host-readable CA-bundle drop (the §4.1 producer half of the
	// M0 trust path, D17/D82). When set, a successful mint drops the minted ca_certificate
	// PEM to the host-readable store keyed by the same caRef the step-7 host-agent
	// CONSUMER (libvirt.fileCABundleSource) reads back — closing the loop so a real
	// CreateSession injects the orchestrator-minted CA with no hand-seeded store. A NIL
	// producer is a clean no-op: the bare-Mint posture before this leg (the host store was
	// pre-seeded by hand / by the e2e), so every non-live unit path is unchanged. The live
	// cmd attaches it (IdentityClients.AttachCABundleStore) under DS_ORCH_LIVE.
	producer *fileCABundleProducer
}

// mint drives the identity.v1 MintInterceptionCA verb once and returns the orchestrator's
// session-derived refs PLUS the frozen response (so the expiry-aware leg can read the
// mint-response expiry off the SAME wire call the bare Mint makes — neither leg double-mints).
func (m liveMint) mint(ctx context.Context, claims sessions.MintWorkloadIdentityClaims) (identityRef, caRef string, resp *identityv1.MintInterceptionCAResponse, err error) {
	resp, err = m.wire.MintInterceptionCA(ctx, &identityv1.MintInterceptionCARequest{
		SessionRef: sessionRefFor(claims.SessionUUID),
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("controlplane: MintInterceptionCA for %s: %w", claims.SessionUUID, err)
	}
	if resp == nil {
		return "", "", nil, fmt.Errorf("controlplane: MintInterceptionCA for %s returned nil response", claims.SessionUUID)
	}
	// The per-session CA reference the orchestrator carries forward: in the control flow
	// it holds only a reference the step-7 inject + step-6 digest + the rollback key on.
	// The proxy-bound CA private key (D39/D76) is delivered to ds-tlsproxy off this control
	// path — host-local, by being persisted into the host-readable .ds-ca-bundles store
	// (the producer leg below), NEVER carried in a routable record and NEVER into the VM.
	// The session_uuid is the stable join key for both refs (the mint is session-scoped,
	// D72-exempt; the response material itself is the off-path proxy-bound delivery).
	caRef = caRefFor(claims.SessionUUID)
	identityRef = identityRefFor(claims.SessionUUID)

	// PRODUCER LEG (option A, D17/D82): drop the minted CA cert PEM to the host-readable
	// store under caRef so the co-located host-agent's step-7 FetchCABundle resolves it
	// (de-stubbing the placeholder PEM), AND drop the matching proxy-bound PKCS#8 private
	// key alongside it (<sanitize(caRef)>.key.pem) so ds-tlsproxy's Arm-1 ingest
	// (acquire_session_ca, DS_TLS3_LIVE) can terminate TLS and mint per-origin leaves —
	// closing the consumer<->producer loop. FAIL-CLOSED: a drop failure aborts the mint —
	// proceeding would leave the host with no provable trust anchor (or a cert with no key,
	// so the proxy could never terminate), so the §4.1 step-7 inject would later fail closed
	// anyway; surfacing it here names the cause (the drop) and lets the create coordinator's
	// step-5 rollback compensate before the digest publish.
	//
	// PROXY-BOUND (D39/D76): the CA private key is now PERSISTED — but ONLY host-local, into
	// the same host-readable .ds-ca-bundles store ds-tlsproxy reads. It NEVER enters the VM
	// (only the step-7 inject places the CERT into the guest overlay trust store — the key is
	// not on that path) and is NEVER logged/printed/committed (the key bytes flow straight
	// from the mint response into the atomic file write; no slog/fmt ever touches them).
	if m.producer != nil {
		if err := m.producer.drop(caRef, resp.GetCaCertificate(), resp.GetCaPrivateKey()); err != nil {
			return "", "", nil, fmt.Errorf("controlplane: drop CA bundle for %s: %w", claims.SessionUUID, err)
		}
	}
	return identityRef, caRef, resp, nil
}

func (m liveMint) Mint(ctx context.Context, claims sessions.MintWorkloadIdentityClaims, _ string) (identityRef, caRef string, err error) {
	identityRef, caRef, _, err = m.mint(ctx, claims)
	return identityRef, caRef, err
}

// MintWithExpiry runs the §4.1 step-5 mint exactly as Mint does and lifts the live mint/CA
// expiry the bare tuple drops into the typed MintReply.Expiry (D22/D82) — the PRODUCER leg
// of the expiry surface. It reads the frozen
// identity.v1 MintInterceptionCAResponse.expiry_unix_seconds (the session-lifetime CA
// expiry, doc 16 §4) and maps it to wall-clock time via expiryFromUnix: a present
// (non-zero) value becomes time.Unix(secs, 0).UTC(); an ABSENT/zero value becomes the ZERO
// time (Expiry.IsZero()) — the not-set case the routable/teardown bookkeeping treats as
// "no TTL to track", NEVER the unix epoch (the orch24 footgun guard). Faults surface
// identically to Mint. liveMint thus satisfies MintExpiryClient, so mintReply lifts the
// live expiry on the production path.
func (m liveMint) MintWithExpiry(ctx context.Context, claims sessions.MintWorkloadIdentityClaims, _ string) (MintReply, error) {
	identityRef, caRef, resp, err := m.mint(ctx, claims)
	if err != nil {
		return MintReply{}, err
	}
	return MintReply{
		IdentityRef: identityRef,
		CARef:       caRef,
		Expiry:      expiryFromUnix(resp.GetExpiryUnixSeconds()),
	}, nil
}

// expiryFromUnix maps a frozen identity.v1 *_unix_seconds expiry field onto the typed
// MintReply.Expiry wall-clock instant. A present (non-zero) value is the UTC instant
// time.Unix(secs, 0); an ABSENT/zero value is the ZERO time (time.Time{}, Expiry.IsZero())
// — the not-set case (doc 16 §5.4), deliberately NOT time.Unix(0, 0) (the unix epoch). A
// downstream that reads MintReply.Expiry distinguishes "no TTL to track" (IsZero) from a
// real expiry by the zero check; collapsing absent onto the epoch would mis-flag every
// no-expiry mint as already long-expired (the orch24 footgun this guards).
func expiryFromUnix(unixSeconds int64) time.Time {
	if unixSeconds == 0 {
		return time.Time{}
	}
	return time.Unix(unixSeconds, 0).UTC()
}

// Compile-time proof the production mint seam satisfies BOTH the required MintClient and
// the optional expiry-aware MintExpiryClient — so mintReply (identityseams.go) lifts the
// live MintReply.Expiry on the production path rather than falling back to the bare,
// expiry-dropping Mint.
var (
	_ MintClient       = liveMint{}
	_ MintExpiryClient = liveMint{}
)

// liveDigest is the production DigestClient: it drives the identity.v1 DigestPublish verb
// (§4.1 step 6, D73 — register the session-scoped digests on the placed host) and reports
// the digest ref + whether the host acked (committed). The session is NOT routable until
// committed is true (mint-before-attach, enforced by the §4.1 step-9 gate — this seam
// reports the ack, the coordinator gates on it). The caRef keys the published batch.
type liveDigest struct {
	wire digestWire
}

func (d liveDigest) WriteAndAck(ctx context.Context, sessionUUID, hostID, caRef string) (digestRef string, acked bool, err error) {
	resp, err := d.wire.DigestPublish(ctx, &identityv1.DigestPublishRequest{
		Session: &identityv1.DigestSessionRef{SessionUuid: sessionUUID},
		BatchId: caRef,
	})
	if err != nil {
		return "", false, fmt.Errorf("controlplane: DigestPublish for %s on %s: %w", sessionUUID, hostID, err)
	}
	if resp == nil {
		return "", false, fmt.Errorf("controlplane: DigestPublish for %s on %s returned nil response", sessionUUID, hostID)
	}
	// The digest ref the record carries forward (the batch id the ack echoes); the ack is
	// the host-side commit (committed == every entry registered and matchable). A false
	// committed is reported, never raised as an error — the coordinator's step-9 gate
	// refuses routable on it fail-closed (D73), which is the documented not-routable path.
	return resp.GetBatchId(), resp.GetCommitted(), nil
}

// liveRevoke is the production RevokeClient (the §4.1 step-5/6 rollback): on a create
// failure at step 5+ it signals identity/CA revocation via the identity.v1 DigestRevoke
// verb (session scope — the session-scoped digests are removed; the CA dies at teardown,
// doc 16 §4). It is idempotent (revoking an already-revoked / never-published session is
// a clean no-op on the identity side). The caRef is the batch key the digests were
// published under (the key id to revoke); an empty caRef still revokes the session scope.
type liveRevoke struct {
	wire digestWire
}

func (r liveRevoke) Revoke(ctx context.Context, sessionUUID, _, caRef string) error {
	keyIDs := []string(nil)
	if caRef != "" {
		keyIDs = []string{caRef}
	}
	if _, err := r.wire.DigestRevoke(ctx, &identityv1.DigestRevokeRequest{
		Session: &identityv1.DigestSessionRef{SessionUuid: sessionUUID},
		KeyIds:  keyIDs,
		Scope:   identityv1.DigestScope_DIGEST_SCOPE_SESSION,
	}); err != nil {
		return fmt.Errorf("controlplane: DigestRevoke for %s: %w", sessionUUID, err)
	}
	return nil
}

// sessionRefFor builds the frozen boundary.v1 SessionRef the MintInterceptionCARequest
// carries — the identity-plane join key (only the session_uuid is known at mint time;
// the host binding lands at step 4, after the mint at step 5, so host_id / index are
// left zero here, which the off-host mint does not key on). The SessionRef is the SHARED
// canonical message owned by boundary.v1 (doc 16 §4; the request imports it), reached
// here through the frozen proto/gen/go import.
func sessionRefFor(sessionUUID string) *boundaryv1.SessionRef {
	return &boundaryv1.SessionRef{SessionUuid: sessionUUID}
}

// caRefFor / identityRefFor derive the orchestrator-side references for a session's
// minted CA + identity. The orchestrator never holds the CA key material (proxy-bound,
// D39/D76); it carries a stable session-scoped reference the step-7 inject, the step-6
// digest, and the rollback key on. Deriving them from the session_uuid (the create's
// stable key, retryable by it) keeps them deterministic across a re-drive of the same
// session without the orchestrator persisting opaque mint-side handles.
//
// THE CANONICAL LEAF-NAME DOMAIN (cross-reader, the caref-reconcile fix). caRefFor is
// the PRODUCER's caRef domain: "ca:" + uuid. The drop sanitizes it (trustpath.Sanitize)
// into the on-disk leaf "ca_" + uuid, so the producer writes ca_<uuid>.pem (cert) +
// ca_<uuid>.key.pem (proxy-bound key). THREE readers must land on that one leaf:
//   - this PRODUCER (the write);
//   - the HOST-AGENT cert consumer (hypervisor/libvirt/cabundlesource.go), which reads
//     trustpath.BundleFilename(ca_bundle_ref) — aligned because the orchestrator sets
//     VmSpec.material.ca_bundle_ref == caRef ("ca:"+uuid), so it reads ca_<uuid>.pem;
//   - the DS-TLSPROXY key/cert consumer (dataplane/services/ds-tlsproxy/src/main.rs),
//     which — before the reconcile — keyed on the BARE uuid (sanitize_ca_ref(uuid) =
//     "<uuid>") and looked for <uuid>.pem, a MISS against the producer's ca_<uuid>.pem
//     → fail-closed panic on the live posture-(b) cred-swap e2e (DS_TLS3_LIVE). The
//     reconcile moved THAT consumer onto this "ca:"-prefixed domain (its
//     session_ca_leaf_stem re-derives "ca:"+uuid), leaving the producer + host-agent
//     byte-identical. ProducerCARefLeaf / CrossReaderCARefVectors below single-source
//     the domain so a future trustpath.Sanitize change cannot silently re-diverge.
func caRefFor(sessionUUID string) string       { return "ca:" + sessionUUID }
func identityRefFor(sessionUUID string) string { return "wid:" + sessionUUID }

// ProducerCARefLeaf returns the exact on-disk leaf names (cert + proxy-bound key) the
// producer drops for a session — the SINGLE SOURCE of the cross-reader leaf-name domain
// (the caref-reconcile contract). It runs the SAME trustpath transforms the drop uses
// (trustpath.BundleFilename(caRefFor(uuid)) for the cert; keyFilename(caRefFor(uuid))
// for the key), so it is byte-identical to what fileCABundleProducer.drop writes and to
// what the ds-tlsproxy consumer's session_ca_leaf_stem(uuid) re-derives. The producer
// side is PINNED at package init() below (a fail-closed assertion of ProducerCARefLeaf
// against every CrossReaderCARefVectors row — stronger than a test: it also guards the
// production binary), and the ds-tlsproxy fixture (main.rs CROSS_READER_CAREF_VECTORS,
// asserted by caref_leaf_stem_matches_cross_reader_golden) pins the byte-identical rows
// from the consumer side, so the producer↔consumer domains cannot drift back to the
// fail-closed MISS.
func ProducerCARefLeaf(sessionUUID string) (certLeaf, keyLeaf string) {
	caRef := caRefFor(sessionUUID)
	return trustpath.BundleFilename(caRef), keyFilename(caRef)
}

// CARefLeafVector is one golden row of the cross-reader leaf-name conformance fixture:
// for SessionUUID, the producer drops CertLeaf + KeyLeaf, and the ds-tlsproxy /
// host-agent consumers must read EXACTLY those. Kept in lock-step (byte-for-byte) with
// the ds-tlsproxy fixture (main.rs CROSS_READER_CAREF_VECTORS).
type CARefLeafVector struct {
	SessionUUID string
	CertLeaf    string
	KeyLeaf     string
}

// CrossReaderCARefVectors is the golden cross-reader leaf-name table (the conformance
// fixture's data). EACH row pins the producer's drop leaf for a session against the
// leaf the ds-tlsproxy consumer re-derives — so a trustpath.Sanitize / sanitize_ca_ref
// change that drifts EITHER tree turns a conformance test RED before it can re-introduce
// the live-e2e MISS/panic.
//
// SINGLE-SOURCED THROUGH THE CONFORMANCE FIXTURE. These rows are promoted into the
// checked-in fixture assurance/conformance-adapter/revocationwire/carrierframe.go
// (CrossReaderCARefVectors, with the per-row leaf stem RE-DERIVED by the independent
// SanitizeCARef / CARefLeafStem and pinned in carrierframe_test.go). The orchestrator
// module may import ONLY proto/gen/go cross-tree (CLAUDE.md), so this table is a
// byte-IDENTICAL copy (CertLeaf == "<Stem>.pem", KeyLeaf == "<Stem>.key.pem"); the
// ds-tlsproxy fixture (main.rs CROSS_READER_CAREF_VECTORS) and the conformance fixture pin
// the same. The producer-side init() below FAIL-CLOSED-asserts ProducerCARefLeaf against
// every row, so a sanitize drift panics the orchestrator binary; keep all three in lock-step.
var CrossReaderCARefVectors = []CARefLeafVector{
	// A ULID-shaped session uuid (the common case): only [A-Za-z0-9], so the "ca:"
	// prefix's ':' is the only byte sanitize touches (':' → '_').
	{SessionUUID: "01HZX9K6Q2VN7T4M8B0CWRD5EF", CertLeaf: "ca_01HZX9K6Q2VN7T4M8B0CWRD5EF.pem", KeyLeaf: "ca_01HZX9K6Q2VN7T4M8B0CWRD5EF.key.pem"},
	// The producer's own test session id (caproducer_test.go uses "sess-prod-1"): a
	// hyphen survives sanitize, the ':' from the "ca:" prefix becomes '_'.
	{SessionUUID: "sess-prod-1", CertLeaf: "ca_sess-prod-1.pem", KeyLeaf: "ca_sess-prod-1.key.pem"},
	// A uuid carrying a sanitize-illegal byte ('/'): both trees must map it to '_'
	// identically (defense-in-depth — the leaf can never escape the .ds-ca-bundles subdir).
	{SessionUUID: "a/b", CertLeaf: "ca_a_b.pem", KeyLeaf: "ca_a_b.key.pem"},
}

// The PRODUCER side of the cross-reader conformance fixture asserts AT PACKAGE INIT: the
// live producer's actual leaf derivation (ProducerCARefLeaf, running the real trustpath
// transforms the drop uses) must equal every golden row in CrossReaderCARefVectors. This
// is the producer's standing assertion against the shared fixture the ds-tlsproxy
// consumer also pins (main.rs caref_leaf_stem_matches_cross_reader_golden) — so the two
// trees cannot drift apart silently. It is FAIL-CLOSED by design: a future
// trustpath.Sanitize / keyFilename change that broke the leaf-name domain would panic the
// orchestrator binary at startup (a loud, immediate refusal) rather than letting it
// silently drop ca_<uuid>.pem files the egress gateway's consumer can never find — the
// exact MISS this reconcile closes. The check is O(constant) over a 3-row table at one
// package init, content-free (only leaf-name strings, never any secret/PEM byte, D73).
func init() {
	for _, v := range CrossReaderCARefVectors {
		certLeaf, keyLeaf := ProducerCARefLeaf(v.SessionUUID)
		if certLeaf != v.CertLeaf || keyLeaf != v.KeyLeaf {
			panic(fmt.Sprintf(
				"controlplane: caRef cross-reader conformance drift for session %q: "+
					"producer leaves {cert=%q key=%q} != fixture {cert=%q key=%q} — the "+
					"ds-tlsproxy consumer (session_ca_leaf_stem) reads the fixture leaf, so this "+
					"drift would fail-close the live CA ingest; reconcile trustpath.Sanitize / "+
					"keyFilename with the shared domain",
				v.SessionUUID, certLeaf, keyLeaf, v.CertLeaf, v.KeyLeaf))
		}
	}
}

// ---------------------------------------------------------------------------
// Host-readable CA-bundle PRODUCER (§4.1 producer half of the M0 trust path, D17/D82).
//
// The orchestrator mints the per-session interception CA (liveMint.mint -> identity.v1
// MintInterceptionCA -> ca_certificate PEM); this producer DROPS that PEM to the
// host-readable store keyed by caRef so the co-located host-agent's step-7 CONSUMER
// (orchestrator/internal/hypervisor/libvirt/cabundlesource.go: fileCABundleSource) can
// FetchCABundle it back WITHOUT a host-agent->identity dial (no identity creds on the
// host; the host only reads bytes the orchestrator placed on the shared trust path — the
// M0 trust-path decision, 2026-06-16). The rejected alternative had the host re-mint via
// MintInterceptionCA, which would hand the guest a CA the egress gateway never holds, so
// interception fails OPEN.
//
// THE ON-DISK CONTRACT IS SINGLE-SOURCED. The consumer reads
//   <baseDir>/.ds-ca-bundles/<sanitize(caBundleRef)>.pem
// and the producer writes the same. Rather than mirror the subdir name + ref->filename
// transform by hand (the old drift-prone copy kept "in lock-step" by comment), BOTH the
// producer here and the libvirt consumer derive the path from the SHARED trustpath package
// (orchestrator/internal/trustpath): trustpath.Subdir, trustpath.Sanitize,
// trustpath.BundlePath. A caRef like "ca:<uuid>" sanitizes to "ca_<uuid>" on BOTH sides
// because it runs the SAME code, so the producer writes exactly the file the consumer reads
// and the two cannot drift.
//
// For M0 single-host this is a LOCAL file write into the host's OverlayDir; a multi-host
// fleet makes it a host-targeted drop (the placement picks the host, then the same write
// lands on that host's OverlayDir). DATA-only across proto/gen/go: this never imports
// identity/mint — it only writes bytes the mint already produced. STDLIB-ONLY (os +
// trustpath, no cgo), mirroring the consumer's posture.
// ---------------------------------------------------------------------------

// caBundleSubdirName is the per-host directory (under the host's OverlayDir) the
// orchestrator-dropped per-session interception-CA bundles live in — the single-sourced
// trustpath.Subdir (".ds-ca-bundles"), aliased here for the package-local call sites. A
// hidden subdir so it is never mistaken for an overlay; sibling to the overlays / session
// records / attach tokens.
const caBundleSubdirName = trustpath.Subdir

// fileCABundleProducer is the production CA-bundle PRODUCER: it writes the per-session
// interception-CA PEM the orchestrator minted under <baseDir>/.ds-ca-bundles, keyed by
// the opaque caRef — the exact path the host-agent's fileCABundleSource reads back. It is
// the WRITE side of the M0 trust path; the consumer is the READ side.
type fileCABundleProducer struct {
	dir string
}

// NewFileCABundleProducer builds the file producer under baseDir/.ds-ca-bundles, creating
// the directory (0o700) if absent so the first drop lands on a well-formed store. baseDir
// is the host's OverlayDir (the per-session state area) — the SAME base the host-agent's
// NewFileCABundleSource is built over, so the producer and consumer agree on the directory.
func NewFileCABundleProducer(baseDir string) (*fileCABundleProducer, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("controlplane: CA bundle producer: empty base dir")
	}
	dir := trustpath.SubdirPath(baseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("controlplane: CA bundle producer: mkdir %q: %w", dir, err)
	}
	return &fileCABundleProducer{dir: dir}, nil
}

// bundlePath is the deterministic PEM path for a caRef — the single-sourced
// trustpath.BundleFilename (the sanitized ref + ".pem") joined onto the store dir, the
// SAME leaf the consumer's fileCABundleSource.bundlePath derives.
func (p *fileCABundleProducer) bundlePath(caRef string) string {
	return filepath.Join(p.dir, trustpath.BundleFilename(caRef))
}

// keyFilename is the deterministic PKCS#8 key filename for a caRef — the sanitized ref
// with a ".key.pem" extension, the SIBLING of the cert leaf bundlePath derives. It is
// byte-identical to what the ds-tlsproxy Arm-1 consumer reads (acquire_session_ca /
// ingest_session_ca_from_transport: `<sanitize(ref)>.key.pem`, alongside the
// `<sanitize(ref)>.pem` cert), because BOTH route through trustpath.Sanitize, so a caRef
// like "ca:<uuid>" maps to "ca_<uuid>.key.pem" on both sides and the two cannot drift.
//
// It now DELEGATES to trustpath.KeyFilename (previously an inline Sanitize + literal
// extension here), the single-sourced leaf the HOST-SIDE §4.2 disposer
// (hypervisor/libvirt/cabundledisposer.go) also removes at teardown — so the producer's
// drop and the disposer's removal name one leaf and a destroyed session cannot leave its
// CA private key behind (D82). Output is byte-identical to the prior inline form; the
// package init() cross-reader conformance assertion pins that.
func keyFilename(caRef string) string {
	return trustpath.KeyFilename(caRef)
}

// keyPath is the deterministic PKCS#8 key path for a caRef under the store dir — the
// proxy-bound (D39/D76) sibling of bundlePath. Host-local only: this path is never the
// step-7 inject target (only the cert is placed into the guest overlay), so the key never
// enters the VM; ds-tlsproxy reads it host-side to mint per-origin leaves.
func (p *fileCABundleProducer) keyPath(caRef string) string {
	return filepath.Join(p.dir, keyFilename(caRef))
}

// drop writes the minted CA bundle to the host-readable store keyed by caRef: the
// ca_certificate PEM at <sanitize(caRef)>.pem AND the proxy-bound PKCS#8 private key at the
// sibling <sanitize(caRef)>.key.pem, so the ds-tlsproxy Arm-1 consumer reads BOTH (the cert
// trust anchor + the key it terminates TLS / mints per-origin leaves with). An empty caRef,
// empty cert PEM, or empty key PEM is rejected fail-closed (a drop with no provable anchor —
// or a cert with no key the proxy could never terminate with — must not produce a
// truthy-but-incomplete bundle). Each write is ATOMIC (temp file in the same dir, then
// rename) so the consumer never observes a half-written file. The cert is written FIRST and
// the key SECOND; a key-write failure surfaces after the cert landed, which the fail-closed
// mint abort + step-5 rollback compensate (the consumer requires BOTH files present and
// non-empty, so a cert-only store is never mistaken for a usable trust anchor).
//
// PROXY-BOUND (D39/D76): the key is persisted HOST-LOCAL ONLY (this store the host agent and
// ds-tlsproxy read, never the guest — only the cert is inject-placed into the VM overlay) and
// the key bytes are NEVER logged — they flow from the mint response straight into the file
// write; no error path echoes them (only the non-secret store path + the ref appear).
func (p *fileCABundleProducer) drop(caRef string, certPEM, keyPEM []byte) error {
	if caRef == "" {
		return fmt.Errorf("controlplane: CA bundle producer: empty ca ref")
	}
	if len(certPEM) == 0 {
		return fmt.Errorf("controlplane: CA bundle producer: empty CA PEM for ref %q (mint returned no ca_certificate)", caRef)
	}
	if len(keyPEM) == 0 {
		// Fail-closed: a cert with no proxy-bound key is unusable (ds-tlsproxy cannot
		// terminate TLS / mint leaves), so the mint must not proceed. The key BYTES are
		// never named here (D39/D76) — only the ref.
		return fmt.Errorf("controlplane: CA bundle producer: empty CA private key for ref %q (mint returned no ca_private_key — proxy-bound key required, D39/D76)", caRef)
	}
	// Cert first (the trust anchor), then the proxy-bound key sibling. Each is an atomic
	// temp-write-then-rename so the consumer never sees a torn file.
	if err := p.writeAtomic(p.bundlePath(caRef), trustpath.BundleFilename(caRef), caRef, certPEM); err != nil {
		return err
	}
	if err := p.writeAtomic(p.keyPath(caRef), keyFilename(caRef), caRef, keyPEM); err != nil {
		return err
	}
	return nil
}

// writeAtomic writes data to final via a temp file (named off leafName) in the same dir,
// chmod 0o600, then rename — so the consumer observes either the previous bytes or the
// complete new file, never a torn one. caRef names the bundle in error messages; the DATA
// bytes are never echoed (so a proxy-bound key write surfaces only the ref + store path, never
// the secret material, D39/D76). The cert and the key BOTH route through here so the cert
// write is byte-for-byte the prior path (temp .* / write / close / chmod 0o600 / rename) and
// the key write is purely additive with the identical, equally-atomic posture.
func (p *fileCABundleProducer) writeAtomic(final, leafName, caRef string, data []byte) error {
	tmp, err := os.CreateTemp(p.dir, leafName+".*")
	if err != nil {
		return fmt.Errorf("controlplane: CA bundle producer: create temp for %q: %w", caRef, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup of the temp file on any failure before the rename succeeds; after a
	// successful rename tmpName no longer exists so the deferred remove is a harmless no-op.
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("controlplane: CA bundle producer: write %q: %w", caRef, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("controlplane: CA bundle producer: close temp for %q: %w", caRef, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("controlplane: CA bundle producer: chmod %q: %w", caRef, err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("controlplane: CA bundle producer: rename into %q: %w", final, err)
	}
	cleanup = false
	return nil
}

// sanitizeBundleRef reduces a caRef to a safe filename component ([A-Za-z0-9._-]) — the
// single-sourced trustpath.Sanitize, retained as a package-local name for the producer's
// call sites. Because BOTH the producer and the consumer route through trustpath.Sanitize,
// a caRef like "ca:<uuid>" maps to "ca_<uuid>" on both sides and the two cannot drift.
func sanitizeBundleRef(s string) string {
	return trustpath.Sanitize(s)
}

// ---------------------------------------------------------------------------
// Host-local session-record PRODUCER (§4.1 producer half of the M0 session-identity
// JOIN seam, doc 14 §4 / §4.1 — the on-disk drop contract, D66/D44).
//
// The M0-host session-identity JOIN (doc 14 §4) needs the proxy to resolve the
// orchestrator's (session_uuid, host_id) binding from the interface-anchored tap name —
// the address alone only yields host_session_index/tap_name (pure address arithmetic on
// the per-session /31). ds-tlsproxy is the LIVE READER of that binding
// (dataplane/services/ds-tlsproxy/src/main.rs: LiveSessionRecordClient, armed under
// DS_SESSION_JOIN_LIVE), but until this producer existed NOTHING wrote the drop, so an
// armed proxy always MISSed the join and degraded to AddressDerived attribution (safe but
// non-functional on a real host). This producer closes the loop from the orchestrator side.
//
// THE ON-DISK CONTRACT IS SINGLE-SOURCED (doc 14 §4.1). Producer and reader cite ONE
// canonical byte-format spec — path, line order, trailing-newline tolerance, and the
// empty-uuid-is-malformed rule — the way sanitize_ca_ref/caRefFor is the single caRef
// domain. The store layout mirrors the per-session CA-bundle drop (fileCABundleProducer):
// a hidden subdir sibling to .ds-ca-bundles under the host's OverlayDir, keyed on the
// SAME trustpath.Sanitize transform the reader's sanitize_session_record_leaf runs
// byte-for-byte (both keep only [A-Za-z0-9._-], map every other rune to '_', and collapse
// an all-illegal/empty key to "session"), so a crafted tap name can never escape the
// subdir and the producer writes exactly the file the reader reads.
//
// The record BODY is a minimal two-line stdlib text drop — line 1 = session_uuid, line 2
// = host_id, each with a trailing '\n' (no serde/JSON dep, D40/D67; the reader parses it
// with `text.lines()` and trims each field). host_id MAY be empty (a session whose host
// binding is not yet known still marks + connects best-effort). session_uuid MUST be
// non-empty: an empty-uuid drop is MALFORMED and rejected fail-closed HERE (the producer
// refuses to write it), identically to the reader surfacing an empty-uuid HIT to its loud
// join guard — the empty uuid is rejected on BOTH sides, never minting a Joined-but-empty
// attribution.
//
// Each write is ATOMIC + FSYNCed (temp file in the same dir → fsync bytes → rename →
// fsync dir) so the reader never observes a torn record and the drop is durable across a
// host crash; teardown REMOVEs the drop (idempotent — a missing file is a clean no-op).
// STDLIB-ONLY (os + trustpath), mirroring the CA producer. DATA-only across proto/gen/go:
// this writes only the (session_uuid, host_id) identifiers the create coordinator already
// holds — never a secret.
//
// LIVE ARM (D50). The producer's file write is pure + synthetic-testable (a temp dir, no
// privileged syscall, no host-agent/orchestrator dial), exercised in the default `go
// test`. Wiring it into the REAL orchestrator session lifecycle (write on the §4.1 create
// after CloneFromImageResponse records the (host_session_index, tap_name) binding, remove
// on teardown) is an ADDITIVE, opt-in edge the live cmd builds under DS_ORCH_LIVE with the
// host's OverlayDir — the SAME deferred-manual posture as AttachCABundleStore, since the
// cmd/coordinator wiring lives outside this unit's owned files. See NewFileSessionRecordProducer.
// ---------------------------------------------------------------------------

// sessionRecordSubdirName is the per-host directory (under the host's OverlayDir) the
// orchestrator/host-agent-dropped per-session (session_uuid, host_id) records live in — a
// hidden subdir sibling to the CA-bundle store, keyed on the interface-anchored tap name.
// It is the exact subdir the ds-tlsproxy reader joins on (main.rs SESSION_RECORD_SUBDIR
// = ".ds-session-records"); the name is pinned in the doc 14 §4.1 on-disk contract, so
// this const and the Rust reader's const cite the same spec and cannot drift.
//
// NOTE: this is DISTINCT from trustpath.SessionRecordsSubdir (".ds-sessions"), which is
// the durable per-session JSON store keyed on session_uuid for crash re-adoption — a
// different store, a different key (session_uuid vs tap name), a different body (JSON vs
// the two-line text drop). This store is the tap-keyed egress-join drop.
const sessionRecordSubdirName = ".ds-session-records"

// sessionRecordExt is the on-disk extension of a tap-keyed session-record drop. The leaf
// is Sanitize(tap_name)+".record" — byte-identical to the reader's
// `format!("{leaf}.record")`.
const sessionRecordExt = ".record"

// fileSessionRecordProducer is the production host-local session-record PRODUCER: it
// writes the (session_uuid, host_id) two-line drop the ds-tlsproxy M0-host JOIN reader
// resolves, keyed on the interface-anchored tap name, and removes it on teardown. It is
// the WRITE side of the doc 14 §4.1 on-disk contract; ds-tlsproxy's LiveSessionRecordClient
// is the READ side.
type fileSessionRecordProducer struct {
	dir string
}

// NewFileSessionRecordProducer builds the file producer under baseDir/.ds-session-records,
// creating the directory (0o700) if absent so the first drop lands on a well-formed store.
// baseDir is the host's OverlayDir (the per-session state area) — the SAME base the
// ds-tlsproxy reader points DS_TLSPROXY_SESSION_RECORD_DIR at, so the producer and reader
// agree on the directory. An empty baseDir is rejected fail-closed.
func NewFileSessionRecordProducer(baseDir string) (*fileSessionRecordProducer, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("controlplane: session-record producer: empty base dir")
	}
	dir := filepath.Join(baseDir, sessionRecordSubdirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("controlplane: session-record producer: mkdir %q: %w", dir, err)
	}
	return &fileSessionRecordProducer{dir: dir}, nil
}

// recordPath is the deterministic drop path for a tap name — Sanitize(tapName)+".record"
// joined onto the store dir, byte-identical to the leaf the ds-tlsproxy reader derives
// (sanitize_session_record_leaf(tap_name)+".record"). BOTH sides route through the same
// [A-Za-z0-9._-]→'_' transform (trustpath.Sanitize here, sanitize_session_record_leaf
// there), so a tap name like "dstap-7" maps to "dstap-7.record" on both sides and the two
// cannot drift; the sanitize is also the path-traversal guard (a crafted tap can never
// escape the subdir).
func (p *fileSessionRecordProducer) recordPath(tapName string) string {
	return filepath.Join(p.dir, trustpath.Sanitize(tapName)+sessionRecordExt)
}

// write drops the (session_uuid, host_id) record for a session on create, keyed on the
// interface-anchored tap name (doc 14 §4 invariant 2 — the tap name, NEVER the source IP).
// The body is exactly two lines with trailing newlines: "<session_uuid>\n<host_id>\n". A
// non-empty session_uuid is REQUIRED (an empty-uuid drop is malformed — the reader would
// surface it to its loud join guard, and this producer refuses to write one, so the
// empty-uuid rejection is symmetric on both sides). An empty tapName is rejected
// fail-closed (no join key). host_id may be empty (best-effort mark-only-adds on the read
// side). The write is atomic + fsynced so the reader never observes a torn record.
func (p *fileSessionRecordProducer) write(tapName, sessionUUID, hostID string) error {
	if tapName == "" {
		return fmt.Errorf("controlplane: session-record producer: empty tap name (no join key)")
	}
	if sessionUUID == "" {
		// Fail-closed, identical to the reader's empty-uuid rejection: a drop with no
		// session_uuid is malformed and must never be written (it would only surface to
		// the reader's loud guard). Doc 14 §4.1 empty-uuid-is-malformed rule.
		return fmt.Errorf("controlplane: session-record producer: empty session_uuid for tap %q (malformed record, doc 14 §4.1)", tapName)
	}
	body := sessionUUID + "\n" + hostID + "\n"
	return p.writeAtomic(p.recordPath(tapName), tapName, []byte(body))
}

// remove deletes the drop for a tap on teardown, so an armed proxy no longer joins a stale
// (session_uuid, host_id) onto a recycled tap. It is IDEMPOTENT: a missing file (never
// dropped, or already removed) is a clean no-op, so a double-teardown never errors. An
// empty tapName is a no-op (nothing to remove).
func (p *fileSessionRecordProducer) remove(tapName string) error {
	if tapName == "" {
		return nil
	}
	if err := os.Remove(p.recordPath(tapName)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("controlplane: session-record producer: remove drop for tap %q: %w", tapName, err)
	}
	return nil
}

// writeAtomic writes data to final via a temp file (in the same dir), fsyncs the bytes,
// chmods 0o600, renames, then fsyncs the directory — so the reader observes either the
// previous record or the complete new one (never a torn file) and the drop survives a host
// crash (fsync of both the file and the containing dir). Mirrors the CA producer's
// temp-write-then-rename, with the fsync added (doc 14 §4.1 fsync+atomic-rename semantics).
// tapName names the drop in error messages; the record fields are non-secret identity so
// they never need scrubbing.
func (p *fileSessionRecordProducer) writeAtomic(final, tapName string, data []byte) error {
	tmp, err := os.CreateTemp(p.dir, trustpath.Sanitize(tapName)+sessionRecordExt+".*")
	if err != nil {
		return fmt.Errorf("controlplane: session-record producer: create temp for tap %q: %w", tapName, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("controlplane: session-record producer: write drop for tap %q: %w", tapName, err)
	}
	// fsync the record bytes before the rename so the rename can never expose a
	// metadata-committed-but-data-lost file after a crash.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("controlplane: session-record producer: fsync drop for tap %q: %w", tapName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("controlplane: session-record producer: close temp for tap %q: %w", tapName, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("controlplane: session-record producer: chmod temp for tap %q: %w", tapName, err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("controlplane: session-record producer: rename into %q: %w", final, err)
	}
	cleanup = false
	// Best-effort fsync of the containing directory so the rename (a dir-metadata change)
	// is durable across a crash. A dir-open/sync fault is non-fatal: the record bytes are
	// already durable and the rename has returned; we only lose crash-durability of the
	// dir entry, not correctness for a live reader.
	if dir, derr := os.Open(p.dir); derr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Host-folded CA-inject + boot (§4.1 steps 7–8).
//
// In the v0 single-host posture the host agent performs CA injection (fail-closed,
// D17/D29) and boot (D38) host-side inside its CloneFromImage path; the orchestrator's
// view of those steps is the host-folded adapter — the coordinator drives them, the host
// agent has already executed them, so the adapter confirms the host-folded execution. A
// nil-host-folded misconfiguration is the only error path (a deployment that wires no
// host-folded executor at all); a wired one succeeds because the host agent's
// CloneFromImage guarantees the fail-closed injection + boot before it returns.
// ---------------------------------------------------------------------------

// hostFoldedSteps is the production InjectClient + BootClient: it records that the §4.1
// step-7 inject + step-8 boot are folded into the host agent's CloneFromImage path
// (executed host-side, doc 15 §4.1 / doc 16 §4) and succeeds on a wired deployment. It
// carries the logger so a live run leaves an audit trace that the host-folded steps were
// driven (the host agent owns the fail-closed semantics; the orchestrator records the
// drive). An M3 split that hoists inject/boot onto a distinct boundary RPC replaces this
// adapter with a dialing one, leaving the InjectClient/BootClient seams unchanged.
type hostFoldedSteps struct {
	logger *slog.Logger
}

func (h hostFoldedSteps) InjectCA(ctx context.Context, sessionUUID, overlayPath, caRef string) error {
	// The injection is executed host-side (the libvirt driver's step-7, fail-closed) when
	// the host agent materializes the overlay in CloneFromImage; the orchestrator's drive
	// is the host-folded confirmation. A wired deployment never faults here — the
	// fail-closed semantics live host-side, surfaced through the CloneFromImage error.
	if h.logger != nil {
		h.logger.DebugContext(ctx, "controlplane: CA inject is host-folded (executed host-side in CloneFromImage, D17/D29)",
			"session_uuid", sessionUUID, "overlay_path", overlayPath, "ca_ref", caRef)
	}
	return nil
}

func (h hostFoldedSteps) Boot(ctx context.Context, sessionUUID, entrypointConfigRef string) error {
	// The boot is executed host-side (the libvirt driver's step-8, D38) inside the host
	// agent's CloneFromImage path; the orchestrator's drive is the host-folded confirmation.
	if h.logger != nil {
		h.logger.DebugContext(ctx, "controlplane: boot is host-folded (executed host-side in CloneFromImage, D38)",
			"session_uuid", sessionUUID, "entrypoint_config_ref", entrypointConfigRef)
	}
	return nil
}

// Compile-time proof the host-folded adapter satisfies BOTH boundary seams.
var (
	_ InjectClient = hostFoldedSteps{}
	_ BootClient   = hostFoldedSteps{}
)

// ---------------------------------------------------------------------------
// Live-edge constructors — reached ONLY under DS_ORCH_LIVE=1 (main.go's liveDeps).
// ---------------------------------------------------------------------------

// IdentityClients is the bundle of Identity (D22/D82) + boundary deployment-input
// backends NewControlPlane needs (the Mint / Digest / Inject / Boot / Revoke seams).
// main.go fills it from NewIdentityClients (a live gRPC dial of the identity service +
// the host-folded inject/boot) under DS_ORCH_LIVE=1; tests fill the seams from fakes.
type IdentityClients struct {
	Mint   MintClient
	Digest DigestClient
	Inject InjectClient
	Boot   BootClient
	Revoke RevokeClient

	conn *grpc.ClientConn
}

// Close tears down the dialed identity connection (graceful shutdown). It is idempotent:
// a nil conn (a clients bundle built over fakes/no dial) is a clean no-op.
func (c *IdentityClients) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	conn := c.conn
	c.conn = nil
	if err := conn.Close(); err != nil {
		return fmt.Errorf("controlplane: close identity connection: %w", err)
	}
	return nil
}

// AttachCABundleStore wires the host-readable CA-bundle PRODUCER (option A, D17/D82) onto
// the Mint seam: after this returns, a successful mint drops the minted ca_certificate PEM
// to baseDir/.ds-ca-bundles/<caRef>.pem so the co-located host-agent's step-7 CONSUMER
// resolves it (de-stubbing the placeholder PEM). It is an ADDITIVE, opt-in wiring the live
// cmd calls under DS_ORCH_LIVE with the host's OverlayDir (the SAME base the host-agent's
// fileCABundleSource is built over) — a non-live / fakes wiring never calls it, so the Mint
// seam stays the bare, no-drop posture (every existing path unchanged). It only rebinds the
// Mint seam if Mint is the production liveMint (a fake-backed Mint is left untouched). An
// empty baseDir is rejected fail-closed.
//
// DEFERRED MANUAL STEP (D50): the live cmd-side call (orchestrator/cmd/orchestrator/main.go
// under DS_ORCH_LIVE, with the OverlayDir from the host deployment input) is NOT wired here
// — main.go is outside this unit's owned files. Until that one-line wiring lands, the live
// host store must be pre-seeded as before; this method is the seam it plugs into.
func (c *IdentityClients) AttachCABundleStore(baseDir string) error {
	if c == nil {
		return fmt.Errorf("controlplane: AttachCABundleStore: nil identity clients")
	}
	producer, err := NewFileCABundleProducer(baseDir)
	if err != nil {
		return err
	}
	if lm, ok := c.Mint.(liveMint); ok {
		lm.producer = producer
		c.Mint = lm
	}
	return nil
}

// NewIdentityClients dials the Identity service (the identity.v1 mint + digest faces) at
// endpoint and assembles the §4.1 step-5/6 Identity seams over it, plus the host-folded
// inject/boot (steps 7–8) the v0 deployment runs host-side. It is the live-edge
// constructor main.go calls under DS_ORCH_LIVE=1; tests use NewIdentityClientsFromWire
// (the wire faces over the generated fakes) instead, so a non-live run never dials (D50).
// The dialOpts default to an insecure transport (the internal, network-isolated
// orchestrator↔Identity link, doc 15 §2): with an EMPTY dialOpts tail this applies
// defaultDialOpts (the same insecure posture the host-driver registry takes). A deployment
// that fronts this edge with mTLS supplies its own transport-credentials DialOption on the
// variadic tail — main.go's liveDeps builds it from the SAME DS_ORCH_TLS_CERT/KEY/CA env
// triplet the host-driver dial reads (via the cmd-side hostDriverDialOpts composition) so
// the two live edges share one transport posture, additively, with no constructor change:
// passing the option overrides the insecure default for this dial only.
//
// An empty endpoint is rejected — a live run with no Identity endpoint must fail loudly
// at construction, never half-wire a control plane with a nil mint seam (NewControlPlane
// would refuse it fail-closed anyway; this surfaces the misconfiguration earlier and
// names the missing endpoint).
func NewIdentityClients(endpoint string, logger *slog.Logger, dialOpts ...DialOption) (*IdentityClients, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("controlplane: NewIdentityClients: empty identity endpoint (set the Identity D22/D82 mint/digest endpoint)")
	}
	if len(dialOpts) == 0 {
		dialOpts = defaultDialOpts()
	}
	conn, err := grpc.NewClient(endpoint, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("controlplane: dial identity service (%s): %w", endpoint, err)
	}
	clients := NewIdentityClientsFromWire(
		mintShim{client: identityv1.NewIdentityMintServiceClient(conn)},
		digestShim{client: identityv1.NewDigestFeedServiceClient(conn)},
		logger,
	)
	clients.conn = conn
	return clients, nil
}

// NewIdentityClientsFromWire assembles the Identity + boundary seams over the narrow wire
// faces (the generated-fake shape) — the seam the dial constructor (NewIdentityClients)
// builds over the dialed shims and the tests build over the generated identityv1fake. It
// holds no gRPC dependency itself, so it is the unit-testable core: a test drives it with
// the fakes and asserts the produced MintClient/DigestClient/RevokeClient map the frozen
// identity.v1 messages correctly (D50 — no live dial).
func NewIdentityClientsFromWire(mint mintWire, digest digestWire, logger *slog.Logger) *IdentityClients {
	folded := hostFoldedSteps{logger: logger}
	return &IdentityClients{
		Mint:   liveMint{wire: mint},
		Digest: liveDigest{wire: digest},
		Revoke: liveRevoke{wire: digest},
		Inject: folded,
		Boot:   folded,
	}
}

// NewPostgresStore opens the external Postgres store (D6) from a DSN and wraps it in the
// store package's database/sql Repository (*store.Postgres). It is the live-edge store
// constructor main.go calls under DS_ORCH_LIVE=1 (otherwise main.go uses *store.Memory);
// tests use *store.Memory or a DS_PG_DSN-gated case, never a live DB in the default run.
//
// DRIVER CHOICE IS THE OPERATOR'S (D33). The store package imports no SQL driver (the
// module stays stdlib-only), so the operator registers a Postgres driver (e.g. pgx's
// stdlib shim or lib/pq) at the binary boundary; driver names it via DS_PG_DRIVER
// (default "postgres"). sql.Open does not dial — the connection is established lazily —
// so this validates the DSN + driver registration and returns the Repository; a live run
// surfaces an unreachable DB at the first store call (the doc 15 §3 Postgres-down
// degraded mode), not here. An empty DSN is rejected (a live run that picked Postgres
// must supply one).
func NewPostgresStore(dsn, driver string) (*store.Postgres, func() error, error) {
	db, err := OpenPostgresPool(dsn, driver)
	if err != nil {
		return nil, nil, err
	}
	return store.NewPostgres(db), db.Close, nil
}

// OpenPostgresPool is the SINGLE-SOURCE live Postgres pool open (D6/D33): it validates a
// non-empty DSN, defaults the driver to defaultPGDriver ("postgres") when unset, runs
// sql.Open(driver, dsn) to obtain the raw *sql.DB pool, and TUNES the pool bounds ONCE
// before returning it. It is the one place the external Postgres pool is opened, called
// from BOTH NewPostgresStore (which wraps the pool in a *store.Postgres for the store reads)
// AND main.go's resolveStore (which ALSO surfaces the raw pool so the durable D46 park join
// — parkstore.SQL — rides the SAME connection). Those two opens previously duplicated this
// block byte-for-byte across two files, free to drift on the driver default, the D33 error
// shape, or future pool tuning; routing both through here makes the single connection /
// single driver registration / single pool-tuning structural.
//
// POOL TUNING (doc 15 §3, the Postgres-down/degraded-mode availability section; §10
// frozen/free: the tuning MECHANISM is load-bearing, the VALUES are free + rig-tunable).
// database/sql ships an UNBOUNDED MaxOpenConns default (0 = no limit), so without this an
// orchestrator at the ~500-host virtual-metal density doc 15 §3 sizes for could open an
// unbounded fan of connections under create/ask/grant bursts and exhaust the server's
// connection slots — turning a transient spike into the very Postgres-down degraded mode
// §3 reasons about (running sessions continue, new creates/asks/grants stall). Bounding
// MaxOpenConns caps that blast radius; MaxIdleConns keeps warm connections for the steady
// reconcile/heartbeat cadence without churn; ConnMaxLifetime recycles connections so a
// failed-over Postgres / rotated credential is picked up within the horizon rather than
// pinned on a stale long-lived connection. The bound is applied ONCE on the SINGLE pool, so
// BOTH the store reads (*store.Postgres) and the parkstore.SQL D46 park join inherit it from
// the one connection — there is no second pool to tune. The strawman defaults
// (defaultPGMaxOpenConns / Idle / ConnMaxLifetime) are overridable via the documented env
// triplet DS_ORCH_PG_MAX_OPEN_CONNS / _MAX_IDLE_CONNS / _CONN_MAX_LIFETIME (§10: values free)
// so an operator rig-tunes them without a code change.
//
// sql.Open does NOT dial — the connection is established lazily, and SetMaxOpenConns /
// SetMaxIdleConns / SetConnMaxLifetime only record the bounds on the pool struct — so this
// validates the DSN + driver registration and returns the tuned pool WITHOUT a connection; a
// live run surfaces an unreachable DB at the first store call (the doc 15 §3 Postgres-down
// degraded mode), not here. db.Stats() therefore already reflects the configured
// MaxOpenConnections immediately after this returns (no dial required — what the unit test
// asserts, D50). An empty DSN is rejected (a live run that picked Postgres must supply one).
func OpenPostgresPool(dsn, driver string) (*sql.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("controlplane: OpenPostgresPool: empty DSN (set DS_ORCH_PG_DSN for the external Postgres, D6)")
	}
	if driver == "" {
		driver = defaultPGDriver
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		// sql.Open errors only on an UNREGISTERED driver name (the operator must register
		// a Postgres driver at the binary boundary, D33) — name it so the live run fails
		// loudly rather than nil-panicking at the first store call.
		return nil, fmt.Errorf("controlplane: open postgres (driver %q): %w — register a Postgres driver at the binary boundary (D33)", driver, err)
	}
	// Single-pool tuning, applied ONCE (doc 15 §3): both the store reads and the
	// parkstore.SQL D46 park join inherit these bounds from this one pool. Each value is the
	// doc-15 strawman default, overridable via the documented env without a code change.
	db.SetMaxOpenConns(envIntOr("DS_ORCH_PG_MAX_OPEN_CONNS", defaultPGMaxOpenConns))
	db.SetMaxIdleConns(envIntOr("DS_ORCH_PG_MAX_IDLE_CONNS", defaultPGMaxIdleConns))
	db.SetConnMaxLifetime(envDurationOr("DS_ORCH_PG_CONN_MAX_LIFETIME", defaultPGConnMaxLifetime))
	return db, nil
}

// defaultPGDriver is the Postgres driver name when DS_PG_DRIVER is unset (the conventional
// database/sql Postgres driver name; the operator registers a driver under it, D33).
const defaultPGDriver = "postgres"

// Pool-tuning strawman defaults (doc 15 §3 / §10 frozen-vs-free: the MECHANISM is
// load-bearing, the VALUES are a free, rig-tunable strawman overridable via the env triplet
// below). They bound the SINGLE Postgres pool OpenPostgresPool opens so a live orchestrator
// at the ~500-host density doc 15 §3 sizes for caps its connection fan rather than running on
// database/sql's UNBOUNDED MaxOpenConns default.
const (
	// defaultPGMaxOpenConns caps the total open connections from the single pool — the blast
	// radius bound against the §3 Postgres-down degraded mode (an unbounded fan under
	// create/ask/grant bursts could exhaust the server's connection slots). A small, fixed
	// ceiling well under a stock Postgres max_connections (~100) leaves headroom for replicas.
	defaultPGMaxOpenConns = 32
	// defaultPGMaxIdleConns keeps warm connections for the steady reconcile/heartbeat cadence
	// without per-call churn; kept ≤ MaxOpenConns (database/sql clamps idle to open anyway).
	defaultPGMaxIdleConns = 8
	// defaultPGConnMaxLifetime recycles a connection after this horizon so a failed-over
	// Postgres / rotated credential is picked up rather than pinned on a stale connection.
	defaultPGConnMaxLifetime = 30 * time.Minute
)

// envIntOr reads a non-negative integer from env key, falling back to def when the key is
// unset, empty, or unparseable / negative (a malformed override silently takes the safe
// strawman rather than mis-tuning the pool — these are operability knobs, not a fail-closed
// security input). It is the §10 "values are free" override seam for the int pool bounds.
func envIntOr(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

// envDurationOr reads a Go duration string (e.g. "30m", "1h") from env key, falling back to
// def when the key is unset, empty, or unparseable / negative. It is the §10 "values are
// free" override seam for ConnMaxLifetime.
func envDurationOr(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return def
	}
	return d
}

// defaultDialOpts is the insecure-transport dial option set for the internal,
// network-isolated orchestrator↔Identity link (doc 15 §2 — same posture as the
// host-driver dial in dialregistry.go). A deployment fronting the edge with mTLS passes
// its own transport-credentials option to NewIdentityClients. It reuses the dialregistry
// default so the two live edges share one transport posture; it is a function (not a
// package var) so each dial gets a fresh slice (avoids a shared-slice alias across dials).
func defaultDialOpts() []grpc.DialOption {
	return NewDialRegistry(nil).dialOpts
}
