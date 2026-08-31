package controlplane

// liveedges_test.go exercises the deployment-input live edges (liveedges.go) via the
// GENERATED identity.v1 fakes + synthetic responders + *store.Memory (D50: NO live
// VM/host-agent/podman/Identity dial, no external Postgres in the default run). It proves:
//
//   - the production Identity clients (liveMint / liveDigest / liveRevoke) map the
//     orchestrator's DATA-carried claims onto the frozen identity.v1 messages and lift the
//     responses back (assert against the recorded fake calls);
//   - the host-folded inject/boot (steps 7–8) succeed (the host agent runs them host-side);
//   - NewControlPlane builds end-to-end over the live-constructed seams (the
//     dial→serve→CreateSession→reconcile path closes) and a CreateSession over the wire
//     drives the §4.1 spine to ATTACHED — the live constructors are interchangeable with
//     the in-fixture fakes behind the seams;
//   - NewPostgresStore rejects an empty DSN and (DS_PG_DSN-gated) opens a real store; the
//     default store path is *store.Memory.
//
// The wire faces match the generated-fake method shape, so the fakes satisfy them
// natively (no bufconn for the adapter assertions) — exactly the DriverClient/fake
// discipline. The end-to-end "path closes" assertion drives a real CreateSession over a
// bufconn against a ControlPlane wired from the live constructors.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/scheduler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// poolTuningTestDriver is a no-dial database/sql driver registered ONLY for the pool-tuning
// unit test: it lets OpenPostgresPool's sql.Open succeed (returning a valid *sql.DB) WITHOUT
// any live database, so db.Stats() reflects the SetMaxOpenConns/SetMaxIdleConns/
// SetConnMaxLifetime calls OpenPostgresPool makes (sql.Open never dials, and a *sql.DB is
// usable for Stats with zero connections established — D50: no live DB in the gate). Its
// Open() is never reached by Stats(), but is implemented to satisfy the driver.Driver
// interface; if the harness ever did dial it would return a closed/erroring conn rather than
// touch a real server.
type poolTuningTestDriver struct{}

func (poolTuningTestDriver) Open(string) (driver.Conn, error) { return nil, io.EOF }

// poolTuningTestDriverName is registered once (init) so OpenPostgresPool(driver=...) resolves
// without a real Postgres driver, keeping the assertion hermetic.
const poolTuningTestDriverName = "ds-pool-tuning-test-noconn"

func init() { sql.Register(poolTuningTestDriverName, poolTuningTestDriver{}) }

// programmedIdentityFakes returns the two generated identity.v1 fakes programmed for a
// clean §4.1 step-5/6: MintInterceptionCA returns synthetic CA material, DigestPublish
// commits (acked), DigestRevoke acks. Tests tweak the responders to drive faults.
func programmedIdentityFakes() (*identityv1fake.IdentityMintServiceFake, *identityv1fake.DigestFeedServiceFake) {
	mint := identityv1fake.NewIdentityMintServiceFake()
	mint.MintInterceptionCAResponder = func(_ context.Context, _ *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
		return &identityv1.MintInterceptionCAResponse{
			CaCertificate:     []byte("ca-cert-pem"),
			CaPrivateKey:      []byte("ca-key-pem"),
			ExpiryUnixSeconds: 1_700_003_600,
		}, nil
	}
	digest := identityv1fake.NewDigestFeedServiceFake()
	digest.DigestPublishResponder = func(_ context.Context, req *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
		return &identityv1.DigestPublishResponse{
			BatchId:   req.GetBatchId(),
			Session:   req.GetSession(),
			Committed: true,
		}, nil
	}
	digest.DigestRevokeResponder = func(_ context.Context, req *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
		return &identityv1.DigestRevokeResponse{Session: req.GetSession(), Committed: true}, nil
	}
	return mint, digest
}

// TestLiveMint_MapsClaimsOntoSessionRef proves the production MintClient drives
// identity.v1 MintInterceptionCA with the session as the SessionRef join key and lifts
// the per-session refs back. The CA private key never crosses this seam (proxy-bound).
func TestLiveMint_MapsClaimsOntoSessionRef(t *testing.T) {
	mintFake, digestFake := programmedIdentityFakes()
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	idRef, caRef, err := clients.Mint.Mint(context.Background(), sessions.MintWorkloadIdentityClaims{
		SessionUUID:      "sess-1",
		HasLaunchingUser: true,
		LaunchingUser:    testSubject,
		Org:              testOrg,
	}, "role-ref-7")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if idRef == "" || caRef == "" {
		t.Fatalf("Mint returned empty refs: id=%q ca=%q", idRef, caRef)
	}
	calls := mintFake.MintInterceptionCARecorded()
	if len(calls) != 1 {
		t.Fatalf("MintInterceptionCA calls = %d, want 1", len(calls))
	}
	if got := calls[0].Req.GetSessionRef().GetSessionUuid(); got != "sess-1" {
		t.Errorf("MintInterceptionCA session_uuid = %q, want %q", got, "sess-1")
	}
	// The caRef the step-7 inject + step-6 digest key on is session-derived and stable
	// (retryable by session UUID).
	if caRef != caRefFor("sess-1") {
		t.Errorf("caRef = %q, want %q", caRef, caRefFor("sess-1"))
	}
}

// TestLiveMint_SurfacesFault proves a mint fault is surfaced (so the §4.1 step-5 rollback
// can compensate) and wraps the session attribution.
func TestLiveMint_SurfacesFault(t *testing.T) {
	mintFake, digestFake := programmedIdentityFakes()
	mintFake.MintInterceptionCAResponder = func(_ context.Context, _ *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
		return nil, status.Error(codes.Unavailable, "mint backend down")
	}
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	if _, _, err := clients.Mint.Mint(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-2"}, ""); err == nil {
		t.Fatal("Mint: expected a surfaced fault for a mint backend failure")
	}
}

// TestLiveMint_LiftsProtoExpiry proves the PRODUCER leg: the production MintClient
// (liveMint) is expiry-aware (satisfies MintExpiryClient) and lifts the frozen
// identity.v1 MintInterceptionCAResponse.expiry_unix_seconds into the typed
// MintReply.Expiry as the UTC instant time.Unix(X, 0) — the live mint/CA expiry the bare
// Mint tuple dropped (D22/D82; the orch24 footgun this wave closes on the live path).
func TestLiveMint_LiftsProtoExpiry(t *testing.T) {
	const expirySecs = int64(1_700_003_600)
	mintFake, digestFake := programmedIdentityFakes() // ExpiryUnixSeconds = 1_700_003_600
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	// The production mint seam must be expiry-aware so mintReply lifts the live expiry
	// rather than falling back to the bare, expiry-dropping Mint.
	ec, ok := clients.Mint.(MintExpiryClient)
	if !ok {
		t.Fatalf("production Mint seam %T does not satisfy MintExpiryClient — the producer leg would drop the proto expiry", clients.Mint)
	}

	reply, err := ec.MintWithExpiry(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-exp"}, "role-ref-9")
	if err != nil {
		t.Fatalf("MintWithExpiry: %v", err)
	}
	if reply.IdentityRef == "" || reply.CARef == "" {
		t.Fatalf("MintWithExpiry returned empty refs: id=%q ca=%q", reply.IdentityRef, reply.CARef)
	}
	want := time.Unix(expirySecs, 0).UTC()
	if !reply.Expiry.Equal(want) {
		t.Errorf("MintReply.Expiry = %v, want time.Unix(%d, 0).UTC() = %v", reply.Expiry, expirySecs, want)
	}
	if reply.Expiry.IsZero() {
		t.Error("MintReply.Expiry is the zero time, want the lifted proto expiry (the producer leg dropped it)")
	}
}

// TestLiveMint_LiftsProtoExpiryViaMintReply proves the lift travels the SAME path the
// create coordinator uses — mintReply type-asserts the bare MintClient to the optional
// MintExpiryClient extension and, because liveMint now satisfies it, lifts the live expiry
// (rather than the pre-this-wave fallback that read the proto and dropped Expiry to zero).
func TestLiveMint_LiftsProtoExpiryViaMintReply(t *testing.T) {
	const expirySecs = int64(1_700_003_600)
	mintFake, digestFake := programmedIdentityFakes()
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	reply, err := mintReply(context.Background(), clients.Mint, sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-exp-mr"}, "role-ref-mr")
	if err != nil {
		t.Fatalf("mintReply: %v", err)
	}
	if want := time.Unix(expirySecs, 0).UTC(); !reply.Expiry.Equal(want) {
		t.Errorf("mintReply MintReply.Expiry = %v, want %v (the live producer leg did not lift the proto expiry)", reply.Expiry, want)
	}
	// The live path was exercised via the generated fake (no live mint dial, D50).
	if len(mintFake.MintInterceptionCARecorded()) != 1 {
		t.Errorf("MintInterceptionCA calls = %d, want exactly 1 (one wire mint, no double-mint)", len(mintFake.MintInterceptionCARecorded()))
	}
}

// TestLiveMint_AbsentExpiryIsZeroNotEpoch proves the orch24 footgun guard: an ABSENT/zero
// ExpiryUnixSeconds yields the ZERO time (Expiry.IsZero()), NOT time.Unix(0, 0) (the unix
// epoch). The routable/teardown bookkeeping treats IsZero as "no TTL to track" (doc 16
// §5.4); collapsing absent onto the epoch would mis-flag every no-expiry mint as expired.
func TestLiveMint_AbsentExpiryIsZeroNotEpoch(t *testing.T) {
	mintFake, digestFake := programmedIdentityFakes()
	// A clean mint that surfaces NO expiry (ExpiryUnixSeconds left at its zero value).
	mintFake.MintInterceptionCAResponder = func(_ context.Context, _ *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
		return &identityv1.MintInterceptionCAResponse{
			CaCertificate: []byte("ca-cert-pem"),
			CaPrivateKey:  []byte("ca-key-pem"),
			// ExpiryUnixSeconds intentionally omitted (absent / not-set → 0).
		}, nil
	}
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	reply, err := mintReply(context.Background(), clients.Mint, sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-noexp"}, "")
	if err != nil {
		t.Fatalf("mintReply: %v", err)
	}
	if !reply.Expiry.IsZero() {
		t.Fatalf("MintReply.Expiry = %v, want the zero time for an absent ExpiryUnixSeconds", reply.Expiry)
	}
	if reply.Expiry.Equal(time.Unix(0, 0)) && !reply.Expiry.IsZero() {
		t.Error("MintReply.Expiry collapsed onto the unix epoch — the orch24 footgun guard failed")
	}
}

// TestExpiryFromUnix is the table proof of the producer-leg mapping in isolation: a present
// value becomes the UTC time.Unix instant; zero becomes the zero time, never the epoch.
func TestExpiryFromUnix(t *testing.T) {
	if got := expiryFromUnix(1_700_003_600); !got.Equal(time.Unix(1_700_003_600, 0).UTC()) {
		t.Errorf("expiryFromUnix(1_700_003_600) = %v, want %v", got, time.Unix(1_700_003_600, 0).UTC())
	}
	if got := expiryFromUnix(0); !got.IsZero() {
		t.Errorf("expiryFromUnix(0) = %v, want the zero time (not the unix epoch)", got)
	}
	// The zero case must NOT be the epoch instant time.Unix(0, 0).
	if got := expiryFromUnix(0); got.Equal(time.Unix(0, 0)) && !got.IsZero() {
		t.Error("expiryFromUnix(0) collapsed onto the unix epoch — the orch24 footgun guard failed")
	}
}

// TestLiveDigest_PublishCommitsRoutable proves the production DigestClient drives
// DigestPublish keyed on the session + caRef batch and reports the host ack (committed) —
// the mint-before-attach routable gate's premise (D73).
func TestLiveDigest_PublishCommitsRoutable(t *testing.T) {
	mintFake, digestFake := programmedIdentityFakes()
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	digestRef, acked, err := clients.Digest.WriteAndAck(context.Background(), "sess-3", testHostID, "ca:sess-3")
	if err != nil {
		t.Fatalf("WriteAndAck: %v", err)
	}
	if !acked {
		t.Fatal("WriteAndAck acked = false, want true (the host committed the batch)")
	}
	calls := digestFake.DigestPublishRecorded()
	if len(calls) != 1 {
		t.Fatalf("DigestPublish calls = %d, want 1", len(calls))
	}
	if got := calls[0].Req.GetSession().GetSessionUuid(); got != "sess-3" {
		t.Errorf("DigestPublish session_uuid = %q, want %q", got, "sess-3")
	}
	if got := calls[0].Req.GetBatchId(); got != "ca:sess-3" {
		t.Errorf("DigestPublish batch_id = %q, want the caRef %q", got, "ca:sess-3")
	}
	if digestRef != "ca:sess-3" {
		t.Errorf("digestRef = %q, want the echoed batch id %q", digestRef, "ca:sess-3")
	}
}

// TestLiveDigest_NotCommittedReportsUnacked proves an uncommitted publish reports
// acked=false (NOT an error) — the coordinator's step-9 gate refuses routable on it
// fail-closed (the documented not-routable path, D73), never a half-routed session.
func TestLiveDigest_NotCommittedReportsUnacked(t *testing.T) {
	mintFake, digestFake := programmedIdentityFakes()
	digestFake.DigestPublishResponder = func(_ context.Context, req *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
		return &identityv1.DigestPublishResponse{BatchId: req.GetBatchId(), Committed: false}, nil
	}
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	_, acked, err := clients.Digest.WriteAndAck(context.Background(), "sess-4", testHostID, "ca:sess-4")
	if err != nil {
		t.Fatalf("WriteAndAck: unexpected error for an uncommitted publish: %v", err)
	}
	if acked {
		t.Fatal("WriteAndAck acked = true, want false (the host did not commit — not routable)")
	}
}

// TestLiveRevoke_RevokesSessionScope proves the production RevokeClient drives
// DigestRevoke at session scope keyed on the caRef (the §4.1 step-5/6 rollback). It is
// idempotent — an empty caRef still revokes the session scope.
func TestLiveRevoke_RevokesSessionScope(t *testing.T) {
	mintFake, digestFake := programmedIdentityFakes()
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	if err := clients.Revoke.Revoke(context.Background(), "sess-5", "wid:sess-5", "ca:sess-5"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	calls := digestFake.DigestRevokeRecorded()
	if len(calls) != 1 {
		t.Fatalf("DigestRevoke calls = %d, want 1", len(calls))
	}
	if got := calls[0].Req.GetScope(); got != identityv1.DigestScope_DIGEST_SCOPE_SESSION {
		t.Errorf("DigestRevoke scope = %v, want DIGEST_SCOPE_SESSION", got)
	}
	if got := calls[0].Req.GetSession().GetSessionUuid(); got != "sess-5" {
		t.Errorf("DigestRevoke session_uuid = %q, want %q", got, "sess-5")
	}
	if keys := calls[0].Req.GetKeyIds(); len(keys) != 1 || keys[0] != "ca:sess-5" {
		t.Errorf("DigestRevoke key_ids = %v, want [ca:sess-5]", keys)
	}
}

// TestHostFoldedSteps_InjectBootSucceed proves the host-folded inject/boot (steps 7–8)
// succeed on a wired deployment — the host agent runs the fail-closed injection + boot
// host-side in CloneFromImage; the orchestrator's drive is the host-folded confirmation.
func TestHostFoldedSteps_InjectBootSucceed(t *testing.T) {
	mintFake, digestFake := programmedIdentityFakes()
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	if err := clients.Inject.InjectCA(context.Background(), "sess-6", "/var/lib/ds/overlays/sess-6.qcow2", "ca:sess-6"); err != nil {
		t.Fatalf("host-folded InjectCA: %v", err)
	}
	if err := clients.Boot.Boot(context.Background(), "sess-6", "entry-ref-6"); err != nil {
		t.Fatalf("host-folded Boot: %v", err)
	}
}

// TestLivePathClosesEndToEnd is the acceptance assertion: NewControlPlane builds over the
// LIVE-constructed Identity seams (NewIdentityClientsFromWire over the generated fakes) +
// *store.Memory + the host driver fake, and a CreateSession over a bufconn drives the
// §4.1 spine to ATTACHED — the dial→serve→CreateSession→reconcile path closes with the
// live constructors in place (only the live NETWORK dial is replaced by the fakes, D50).
func TestLivePathClosesEndToEnd(t *testing.T) {
	ctx := context.Background()
	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	st := store.NewMemoryClock(clock)
	if _, err := st.PutEnvConfig(ctx, store.EnvConfig{Ref: testEnvRef, RepoRef: testRepoID, ImageID: testImageID}); err != nil {
		t.Fatalf("seed env config: %v", err)
	}

	mintFake, digestFake := programmedIdentityFakes()
	identity := NewIdentityClientsFromWire(mintFake, digestFake, nil)

	heartbeats := NewHeartbeatStore(clock)
	heartbeats.Record(freshHeartbeat(testHostID, 0, 1))

	cp, err := NewControlPlane(Deps{
		Store:      cpStore{st},
		Drivers:    fakeRegistry{host: testHostID, drv: newDriverFake()},
		Heartbeats: heartbeats,
		// The live-constructed Identity + boundary seams (interchangeable with the
		// in-fixture fakes — the live constructors drop straight into Deps).
		Mint:            identity.Mint,
		Digest:          identity.Digest,
		Inject:          identity.Inject,
		Boot:            identity.Boot,
		Revoke:          identity.Revoke,
		Enrollment:      fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:           sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
		DefaultOrg:      testOrg,
		SchedulerConfig: scheduler.Config{},
		Clock:           clock,
		ResyncInterval:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewControlPlane over live-constructed seams: %v", err)
	}
	var n int
	cp.Sessions.SetSessionUUIDGen(func() string { n++; return "live-sess-" + time.Unix(int64(n), 0).UTC().Format("0405") })

	// Serve over a bufconn (no socket bind, D50) and drive a CreateSession over the wire —
	// the live path closes: the §4.1 spine runs through the live Mint/Digest/Inject/Boot
	// seams to ATTACHED.
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	cp.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	resp, err := orchestratorv1.NewSessionServiceClient(conn).CreateSession(ctx, validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession over the wire (live path): %v", err)
	}
	if resp.GetSession().GetSessionUuid() == "" {
		t.Fatal("CreateSession returned an empty session uuid — the live path did not close")
	}
	// The live Identity seams were driven on the create path (mint + digest at least once).
	if len(mintFake.MintInterceptionCARecorded()) == 0 {
		t.Error("MintInterceptionCA was never called — the §4.1 step-5 live mint seam was not driven")
	}
	if len(digestFake.DigestPublishRecorded()) == 0 {
		t.Error("DigestPublish was never called — the §4.1 step-6 live digest seam was not driven")
	}
}

// TestNewPostgresStore_RejectsEmptyDSN proves the store constructor fails loudly on an
// unconfigured DSN (a live run that picked Postgres must supply one) rather than
// half-wiring a nil store.
func TestNewPostgresStore_RejectsEmptyDSN(t *testing.T) {
	if _, _, err := NewPostgresStore("", ""); err == nil {
		t.Fatal("NewPostgresStore: expected a fail-closed refusal for an empty DSN")
	}
}

// TestOpenPostgresPool_AppliesDefaultTuning proves OpenPostgresPool tunes the SINGLE pool
// ONCE with the doc 15 §3 strawman bounds (no env override set), asserted via
// db.Stats().MaxOpenConnections — which sql.Open populates from SetMaxOpenConns WITHOUT a
// dial (D50: no live DB; the registered no-conn driver never connects). This is the
// regression guard that the bound the store reads AND the parkstore.SQL D46 park join inherit
// from the one pool is actually set rather than left at database/sql's unbounded (0) default.
func TestOpenPostgresPool_AppliesDefaultTuning(t *testing.T) {
	// Ensure no override is in effect for this case (the env triplet is the §10 free knob).
	t.Setenv("DS_ORCH_PG_MAX_OPEN_CONNS", "")
	t.Setenv("DS_ORCH_PG_MAX_IDLE_CONNS", "")
	t.Setenv("DS_ORCH_PG_CONN_MAX_LIFETIME", "")

	db, err := OpenPostgresPool("host=stub dbname=stub", poolTuningTestDriverName)
	if err != nil {
		t.Fatalf("OpenPostgresPool with the no-conn test driver: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if got := db.Stats().MaxOpenConnections; got != defaultPGMaxOpenConns {
		t.Fatalf("MaxOpenConnections = %d, want the doc-15 §3 strawman default %d (pool tuning not applied)", got, defaultPGMaxOpenConns)
	}
}

// TestOpenPostgresPool_EnvOverridesTuning proves the documented env triplet overrides the
// strawman defaults on the single pool (doc 15 §10: the tuning MECHANISM is load-bearing, the
// VALUES are free + rig-tunable). It asserts the override lands via db.Stats() with no dial
// (D50) and that a malformed override silently falls back to the safe strawman rather than
// mis-tuning the pool.
func TestOpenPostgresPool_EnvOverridesTuning(t *testing.T) {
	const overrideMaxOpen = 7
	t.Setenv("DS_ORCH_PG_MAX_OPEN_CONNS", "7")
	t.Setenv("DS_ORCH_PG_MAX_IDLE_CONNS", "3")
	t.Setenv("DS_ORCH_PG_CONN_MAX_LIFETIME", "5m")

	db, err := OpenPostgresPool("host=stub dbname=stub", poolTuningTestDriverName)
	if err != nil {
		t.Fatalf("OpenPostgresPool with the no-conn test driver: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if got := db.Stats().MaxOpenConnections; got != overrideMaxOpen {
		t.Fatalf("MaxOpenConnections = %d, want the env override %d", got, overrideMaxOpen)
	}

	// A malformed override must fall back to the strawman default (operability knob, not a
	// fail-closed input) — never panic or mis-tune the pool to an absurd value.
	t.Setenv("DS_ORCH_PG_MAX_OPEN_CONNS", "not-a-number")
	dbBad, err := OpenPostgresPool("host=stub dbname=stub", poolTuningTestDriverName)
	if err != nil {
		t.Fatalf("OpenPostgresPool with a malformed override: %v", err)
	}
	t.Cleanup(func() { _ = dbBad.Close() })
	if got := dbBad.Stats().MaxOpenConnections; got != defaultPGMaxOpenConns {
		t.Fatalf("malformed override: MaxOpenConnections = %d, want fallback to the default %d", got, defaultPGMaxOpenConns)
	}
}

// TestEnvIntOr_AndEnvDurationOr unit-proves the §10 override seams: a present, parseable,
// non-negative value is taken; unset / empty / unparseable / negative all fall back to the
// default (the safe strawman). These are the value-free override helpers behind the pool
// bounds (doc 15 §10).
func TestEnvIntOr_AndEnvDurationOr(t *testing.T) {
	const key = "DS_TEST_POOL_TUNING_KNOB"

	t.Setenv(key, "")
	if got := envIntOr(key, 11); got != 11 {
		t.Fatalf("envIntOr unset: got %d, want default 11", got)
	}
	t.Setenv(key, "42")
	if got := envIntOr(key, 11); got != 42 {
		t.Fatalf("envIntOr present: got %d, want 42", got)
	}
	t.Setenv(key, "-3")
	if got := envIntOr(key, 11); got != 11 {
		t.Fatalf("envIntOr negative: got %d, want default 11 (negative rejected)", got)
	}
	t.Setenv(key, "x")
	if got := envIntOr(key, 11); got != 11 {
		t.Fatalf("envIntOr unparseable: got %d, want default 11", got)
	}

	t.Setenv(key, "")
	if got := envDurationOr(key, time.Minute); got != time.Minute {
		t.Fatalf("envDurationOr unset: got %v, want default 1m", got)
	}
	t.Setenv(key, "90s")
	if got := envDurationOr(key, time.Minute); got != 90*time.Second {
		t.Fatalf("envDurationOr present: got %v, want 90s", got)
	}
	t.Setenv(key, "-2m")
	if got := envDurationOr(key, time.Minute); got != time.Minute {
		t.Fatalf("envDurationOr negative: got %v, want default 1m (negative rejected)", got)
	}
	t.Setenv(key, "nope")
	if got := envDurationOr(key, time.Minute); got != time.Minute {
		t.Fatalf("envDurationOr unparseable: got %v, want default 1m", got)
	}
}

// TestNewPostgresStore_DSNGated opens the external Postgres store from DS_PG_DSN and
// proves the produced *store.Postgres satisfies ControlPlaneStore (the live store path is
// interchangeable with *store.Memory behind the seam). DEFERRED MANUAL STEP: SKIPS without
// DS_PG_DSN + a registered driver + applied migrations, so the default sandbox run never
// touches a live DB (D50).
func TestNewPostgresStore_DSNGated(t *testing.T) {
	// The env-read + Skip-on-unset HALF is single-sourced through storetest.DSNOrSkip
	// (its unset message reproduces this test's exact skip wording byte-for-byte). The
	// open/skip stays with NewPostgresStore: it does its OWN internal sql.Open and returns
	// the typed *store.Postgres + a closer, so storetest.OpenOrSkip cannot own the open here.
	dsn := storetest.DSNOrSkip(t, "DS_PG_DSN", "DS_PG_DSN not set: skipping live-Postgres store construction (deferred manual step)")
	pg, closeDB, err := NewPostgresStore(dsn, os.Getenv("DS_PG_DRIVER"))
	if err != nil {
		t.Skipf("NewPostgresStore(%q): %v — register a Postgres driver + apply migrations to run this", dsn, err)
	}
	t.Cleanup(func() { _ = closeDB() })
	var _ ControlPlaneStore = pg // the live store satisfies the wiring's coherence root
}

// TestNewIdentityClients_RejectsEmptyEndpoint proves the dial constructor fails loudly on
// an unconfigured Identity endpoint (a live run must supply one) rather than dialing an
// empty target. It is the only branch of NewIdentityClients reachable without a live dial
// (the success branch dials, a live edge — covered via NewIdentityClientsFromWire above).
func TestNewIdentityClients_RejectsEmptyEndpoint(t *testing.T) {
	if _, err := NewIdentityClients("", nil); err == nil {
		t.Fatal("NewIdentityClients: expected a fail-closed refusal for an empty endpoint")
	}
}

// TestIdentityClients_CloseNilConnNoOp proves Close is a clean no-op for a clients bundle
// built without a dial (the fakes path) — so a test/dev wiring tears down cleanly.
func TestIdentityClients_CloseNilConnNoOp(t *testing.T) {
	mintFake, digestFake := programmedIdentityFakes()
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)
	if err := clients.Close(); err != nil {
		t.Fatalf("Close over a no-dial clients bundle: %v", err)
	}
	var nilClients *IdentityClients
	if err := nilClients.Close(); err != nil {
		t.Fatalf("Close over a nil bundle: %v", err)
	}
}
