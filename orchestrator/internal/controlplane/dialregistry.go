package controlplane

// dialregistry.go is LEG (a) of the live-edge fill: the per-host hypervisor.v1 driver
// DIAL — the production DriverRegistry that resolves a host_id to its driver client by
// dialing the host agent's HypervisorDriverService over gRPC, caching the connection,
// and closing it on shutdown. The orch19 capstone landed the DriverRegistry SEAM
// (seams.go) + the ClientShim adapter (grpcclient.go) + the fake-returning registry the
// tests use; this file lands the one production implementation those left as a stub: a
// dialing, caching, closeable registry behind DS_ORCH_LIVE (main.go constructs it).
//
// WHY THE DIAL LIVES HERE (the gRPC-confinement rule). seams.go's header pins the
// posture: the gRPC dependency is confined to grpcclient.go (the ClientShim) + the dial
// site. This is that dial site. Every host driver this registry resolves is a dialed
// generated HypervisorDriverServiceClient wrapped in a ClientShim (so the generated
// client's `opts ...grpc.CallOption` tail is dropped onto the package's narrow
// DriverClient seam) — the rest of the package stays gRPC-free, exercised against the
// generated fake (D50). No host-agent package import; the orchestrator reaches the
// per-host libvirt driver ONLY through the frozen hypervisor.v1 generated client (the
// one legal cross-tree import, CLAUDE.md).
//
// LIVE-EDGE GATING (D50). The dial is a LIVE network edge: it opens a real gRPC
// connection to a host agent. So a dialRegistry is constructed ONLY under DS_ORCH_LIVE=1
// (main.go's liveDeps), never in a test — the tests drive the fake-returning registry
// (fixtures_test.go's fakeRegistry) against the generated hypervisor.v1 fake. This file
// itself imports grpc + credentials/insecure (subpackages of the already-declared
// google.golang.org/grpc require — NOT a new third-party dependency), but the dial it
// performs is reached only on a live run; a non-live run never constructs it.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// Env-driven mTLS material for the orchestrator→host-agent dial. doc 15 §2 places the
// orchestrator and the per-host host agent on the same bare-metal fabric joined by the
// D35 HypervisorDriver v1 gRPC contract; a deployment that fronts that link with mutual
// TLS supplies the client cert/key the orchestrator presents plus the CA that pins the
// host agent's server cert. These are PATHS read at live-edge construction (main.go's
// liveDeps under DS_ORCH_LIVE=1), never the key material itself — the same file-path env
// posture the rest of the live edges use (DS_ORCH_PG_DSN, DS_ORCH_IDENTITY_ENDPOINT).
const (
	// EnvDialTLSCert is the orchestrator client certificate (PEM) presented to the host
	// agent on the mutually-authenticated dial.
	EnvDialTLSCert = "DS_ORCH_TLS_CERT"
	// EnvDialTLSKey is the private key (PEM) for EnvDialTLSCert.
	EnvDialTLSKey = "DS_ORCH_TLS_KEY"
	// EnvDialTLSCA is the CA bundle (PEM) that pins the host agent's server certificate.
	EnvDialTLSCA = "DS_ORCH_TLS_CA"
)

// HostEndpoints is the static per-host driver endpoint map the live deployment supplies
// (doc 15 §5.1: one HypervisorDriver per virtual-metal host). It maps a host_id to the
// gRPC target (host:port) of that host's driver face. The dialRegistry resolves a
// host_id to its endpoint here, then dials/caches the connection. At v0 the
// single-host orchestrator-lite posture (D80) carries ONE entry; the M3 fleet control
// plane (a distinct service) fills it from host enrollment.
type HostEndpoints map[string]string

// DialOption configures a host-driver dial. It is the narrow seam the registry exposes
// so a deployment threads transport credentials / interceptors without this file
// importing a credential type beyond the insecure default. The default (no options) is
// an insecure transport — the orchestrator↔host-agent edge is an internal,
// network-isolated link (doc 15 §2: the two D35 services on bare metal); a deployment
// that fronts it with mTLS supplies its own transport-credentials option.
type DialOption = grpc.DialOption

// dialRegistry is the production DriverRegistry: it resolves a host_id to its per-host
// hypervisor.v1 driver client by dialing the host's endpoint (once, then cached) and
// wrapping the generated client in a ClientShim. It is constructed by main.go under
// DS_ORCH_LIVE=1; a non-live run never builds it (the dial is a live network edge, D50).
//
// CACHING + LIFECYCLE. A dial is expensive and a host re-resolves on every create /
// reconcile, so the registry caches one *grpc.ClientConn per host_id (dial-once,
// reuse). Close tears down every cached connection at graceful shutdown. The cache is
// mutex-guarded (the create coordinator + the reconcile loop resolve concurrently).
type dialRegistry struct {
	endpoints HostEndpoints
	dialOpts  []grpc.DialOption

	mu    sync.Mutex
	conns map[string]*grpc.ClientConn
}

// NewDialRegistry builds the production dialing DriverRegistry over the static per-host
// endpoint map. It does NOT dial eagerly — connections are established lazily on the
// first DriverFor(host) and cached thereafter (so a registry over a large fleet does not
// open every connection at boot; a host that is never placed is never dialed). The
// dialOpts default to an insecure transport (the internal orchestrator↔host-agent edge);
// a deployment that fronts the edge with transport credentials passes its own option.
//
// It is the live-edge constructor main.go calls under DS_ORCH_LIVE=1; tests use the
// fake-returning registry instead (D50 — no live dial in a test). An empty endpoint map
// is accepted (every DriverFor then misses with ErrNoDriverForHost) so a misconfigured
// live run fails at the first placement with an attributable miss, not a nil panic.
func NewDialRegistry(endpoints HostEndpoints, dialOpts ...DialOption) *dialRegistry {
	if len(dialOpts) == 0 {
		// The default transport for the internal, network-isolated orchestrator↔host-agent
		// link (doc 15 §2). A deployment fronting it with mTLS overrides this.
		dialOpts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}
	cp := make(HostEndpoints, len(endpoints))
	for h, ep := range endpoints {
		cp[h] = ep
	}
	return &dialRegistry{
		endpoints: cp,
		dialOpts:  dialOpts,
		conns:     make(map[string]*grpc.ClientConn),
	}
}

// MTLSDialOptionFromEnv builds the mutual-TLS transport-credentials DialOption the
// orchestrator's live dials use under DS_ORCH_LIVE=1 when the deployment fronts the
// internal D35 control-plane fabric with mTLS (doc 15 §2). It reads the client cert/key/CA
// PATHS from the environment (DS_ORCH_TLS_CERT/KEY/CA), loads the orchestrator client
// keypair, pins the peer's server cert against the CA bundle, and returns
// grpc.WithTransportCredentials(credentials.NewTLS(...)). The returned bool reports
// whether mTLS was configured: with NONE of the three env vars set the dial keeps the
// default insecure transport for the internal, network-isolated link (false, nil); with
// SOME-but-not-all set it is a hard misconfiguration (a live run must fail loudly rather
// than half-configure transport security), so it returns an error naming the missing var.
//
// It is the SINGLE credentials builder for the orchestrator's live dials: both live legs —
// the per-host hypervisor.v1 driver dial (NewDialRegistry) AND the Identity D22/D82 dial
// (NewIdentityClients) — front the same internal fabric (doc 15 §2) with the SAME env
// triplet, so cmd/orchestrator's bootstrap composes this one exported helper into both
// rather than re-deriving the crypto/tls posture per edge (one source of truth for the
// TLS-1.2 floor, CA-pinned RootCAs, and the half-config hard-error contract).
//
// It performs NO dial — it only constructs the credentials from the env-named files — so
// it is exercised in tests with SYNTHETIC in-test certs (D50): a test writes a throwaway
// CA + client keypair to temp files, points the env at them, and asserts the option set
// is built from the env without ever opening a socket. main.go's liveDeps calls it and
// passes the option into NewDialRegistry / NewIdentityClients; a non-live run never reaches
// it.
//
// This keeps the gRPC + crypto/tls dependency confined to this dial site (the
// gRPC-confinement rule in this file's header) — the rest of the package stays
// transport-agnostic, and the registry/Identity seams are unchanged (the option is
// threaded in additively; both constructors already accept a variadic DialOption tail).
func MTLSDialOptionFromEnv() (DialOption, bool, error) {
	certPath := os.Getenv(EnvDialTLSCert)
	keyPath := os.Getenv(EnvDialTLSKey)
	caPath := os.Getenv(EnvDialTLSCA)

	// None set: the internal link keeps the insecure default (doc 15 §2). The caller
	// (main.go) then constructs NewDialRegistry with no transport option and the default
	// insecure transport applies.
	if certPath == "" && keyPath == "" && caPath == "" {
		return nil, false, nil
	}
	// Some-but-not-all: a half-configured mTLS edge is never silently downgraded — name the
	// missing var so a live run fails at construction, not at the first dial.
	for _, m := range []struct {
		env, val string
	}{
		{EnvDialTLSCert, certPath},
		{EnvDialTLSKey, keyPath},
		{EnvDialTLSCA, caPath},
	} {
		if m.val == "" {
			return nil, false, fmt.Errorf("controlplane: orchestrator live dial mTLS: %s set but %s empty — set the full client cert/key/CA triplet for the mutually-authenticated internal control-plane link (doc 15 §2, D35)", "DS_ORCH_TLS_*", m.env)
		}
	}

	creds, err := loadDialTLSCredentials(certPath, keyPath, caPath)
	if err != nil {
		return nil, false, err
	}
	return grpc.WithTransportCredentials(creds), true, nil
}

// loadDialTLSCredentials assembles the gRPC client transport-credentials for the mutually-
// authenticated live dial from PEM file paths: the orchestrator's client keypair (cert +
// key it presents) and the CA bundle that pins the peer's server cert. It is the crypto/tls
// core of MTLSDialOptionFromEnv, split out so a test can drive it from synthetic in-test
// cert files (D50) without touching the env. It builds a tls.Config with the client
// certificate set and the CA as RootCAs (server-cert verification on), wrapped by
// credentials.NewTLS — the standard mutual-TLS gRPC client posture.
func loadDialTLSCredentials(certPath, keyPath, caPath string) (credentials.TransportCredentials, error) {
	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("controlplane: load orchestrator live dial mTLS client keypair (%s, %s): %w", certPath, keyPath, err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("controlplane: read orchestrator live dial mTLS CA bundle (%s): %w", caPath, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("controlplane: orchestrator live dial mTLS CA bundle (%s) holds no PEM certificate", caPath)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// DriverFor resolves the per-host driver client for hostID, dialing the host's endpoint
// on the first resolve and returning the cached connection thereafter. A host with no
// configured endpoint is ErrNoDriverForHost (the create rolls back from its host-side
// step; the reconciler absorbs it into a degraded/alarm path rather than destroying a
// record on a transient driver-reach fault — seams.go's contract). The returned client
// is the dialed generated HypervisorDriverServiceClient wrapped in a ClientShim, so the
// gRPC dependency stays confined to this dial + the shim.
func (r *dialRegistry) DriverFor(ctx context.Context, hostID string) (DriverClient, error) {
	endpoint, ok := r.endpoints[hostID]
	if !ok || endpoint == "" {
		return nil, fmt.Errorf("%w: %s", ErrNoDriverForHost, hostID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if conn, ok := r.conns[hostID]; ok {
		return ClientShim{Client: hypervisorv1.NewHypervisorDriverServiceClient(conn)}, nil
	}
	conn, err := grpc.NewClient(endpoint, r.dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("controlplane: dial host driver %s (%s): %w", hostID, endpoint, err)
	}
	r.conns[hostID] = conn
	return ClientShim{Client: hypervisorv1.NewHypervisorDriverServiceClient(conn)}, nil
}

// Hosts returns the host_ids the registry can resolve a driver for — the configured
// endpoint set (the fleet enumeration the reconciler's host-agnostic verbs broadcast
// over, seams.go). It returns the configured set whether or not each host is dialed yet
// (an idempotent Suspend/Destroy on session_uuid is safe to broadcast to every
// configured host; a host that does not run the session no-ops).
func (r *dialRegistry) Hosts(_ context.Context) ([]string, error) {
	out := make([]string, 0, len(r.endpoints))
	for h := range r.endpoints {
		out = append(out, h)
	}
	return out, nil
}

// Close tears down every cached host-driver connection (graceful shutdown). It is
// idempotent: a second Close over an already-closed set is a no-op. It returns the first
// close error encountered (the rest are still attempted) so a shutdown surfaces a stuck
// connection without abandoning the others.
func (r *dialRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for h, conn := range r.conns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("controlplane: close host driver %s: %w", h, err)
		}
		delete(r.conns, h)
	}
	return firstErr
}

// Compile-time proof the dialing registry satisfies the package's DriverRegistry seam —
// so main.go (under DS_ORCH_LIVE=1) drops it straight into Deps.Drivers, interchangeably
// with the fake-returning registry the tests use.
var _ DriverRegistry = (*dialRegistry)(nil)

// ---------------------------------------------------------------------------
// BRING-COMPUTE control-link transport (doc 15 §2.1; D19 outbound-only mTLS, no
// inbound holes). The hosted tier above is orchestrator-dials-host: the registry
// dials each host agent's HypervisorDriverService endpoint OUTBOUND
// (DS_ORCH_HOST_DRIVERS). The bring-compute tier inverts the dial DIRECTION — the
// customer's NAT'd host agent runs no inbound listener and instead dials OUT to the
// orchestrator's listener (DS_ORCH_LISTEN). The orchestrator never opens an inbound
// hole into the customer network; the connection is host-agent-INITIATED.
//
// HOW THE HYPERVISOR VERBS GO BACK (the dial-direction pin). doc 15 §2.1 establishes
// that the orchestrator drives the HypervisorDriver verbs back over the SAME
// host-agent-initiated connection: gRPC rides HTTP/2, whose streams are
// bidirectionally multiplexed over one transport, so once the host agent has dialed
// in and the orchestrator holds a *grpc.ClientConn over that established link, the
// orchestrator is a HypervisorDriverServiceClient over the INBOUND connection — it
// makes the clone/suspend/destroy/attach calls back to the HypervisorDriverService
// the host agent serves on its side of the link, with NO separate outbound dial to
// the host. The HypervisorDriver verb set + wire shape is IDENTICAL to the hosted
// tier (the frozen hypervisor.v1 contract, the same ClientShim); only the dial
// direction differs (inbound-established vs outbound-dialed). This is exactly why
// no proto change and no second verb contract are needed — the verbs route over the
// inbound link, not a fresh outbound one.
//
// The orchestrator's transport bootstrap (cmd/orchestrator) terminates the inbound
// host-agent connections on DS_ORCH_LISTEN; the host-identification + per-connection
// *grpc.ClientConn capture that turns one inbound link into a registered driver is
// the deployment's reverse-link transport step (the host agent's outbound bring-compute
// dialer is its own service, doc 15 §2 D35) — env-gated and marked deferred-manual in
// main.go (DS_ORCH_BRING_COMPUTE). What lands HERE is the additive registry that holds
// inbound-registered connections and routes the frozen HypervisorDriver verbs over them
// through the SAME ClientShim the hosted tier uses, proven over bufconn (D50 — no live
// host-agent, no inbound hole opened in a test).

// InboundConn is the established host-agent-initiated control-link connection the
// bring-compute registry routes HypervisorDriver verbs back over (doc 15 §2.1). It is
// the narrow subset of *grpc.ClientConn the registry needs — a connection it can mint a
// HypervisorDriverServiceClient on and Close at shutdown — declared as an interface so
// the inbound registry is exercised over a bufconn-backed *grpc.ClientConn in tests
// (D50: a real gRPC connection, no live host-agent and no inbound listener opened) while
// production registers the real *grpc.ClientConn the orchestrator's listener terminated.
// *grpc.ClientConn satisfies it natively.
type InboundConn interface {
	grpc.ClientConnInterface
	Close() error
}

// inboundDriverRegistry is the BRING-COMPUTE DriverRegistry: the host agent dials OUT to
// the orchestrator (D19 outbound-only mTLS, no inbound holes), and the orchestrator
// routes the HypervisorDriver verbs back over the SAME inbound-established connection
// rather than dialing the host. It holds one InboundConn per registered host_id (captured
// when that host's outbound connection lands on the orchestrator's listener) and resolves
// DriverFor(host) to a ClientShim over that connection — the identical frozen
// hypervisor.v1 client the hosted dialRegistry produces, only over an inbound link.
//
// It is constructed by main.go under DS_ORCH_LIVE=1 + the bring-compute tier selector; a
// non-live run never builds it. Registration is host-agent-initiated (Register is called
// from the orchestrator's connection-accept path as each host dials in), so the registry
// starts EMPTY and fills as hosts connect — DriverFor on a host that has not yet dialed
// in is ErrNoDriverForHost (the create rolls back / the reconciler absorbs it, exactly the
// hosted-tier miss contract). Registration + resolution + close are mutex-guarded (hosts
// dial in concurrently with the create coordinator + reconcile loop resolving).
type inboundDriverRegistry struct {
	mu    sync.Mutex
	conns map[string]InboundConn
}

// NewInboundDriverRegistry builds the bring-compute host-agent-dials-OUT DriverRegistry
// (doc 15 §2.1; D19). It opens NO connections itself — the connections are
// host-agent-INITIATED and handed in via Register as each customer host agent dials the
// orchestrator's listener, so the registry starts empty and a host is resolvable only
// after it has connected. It is the live-edge constructor main.go calls under
// DS_ORCH_LIVE=1 for the bring-compute tier; tests register a bufconn-backed InboundConn
// and assert the HypervisorDriver verbs route over it (D50 — no live host-agent, no
// inbound hole).
func NewInboundDriverRegistry() *inboundDriverRegistry {
	return &inboundDriverRegistry{conns: make(map[string]InboundConn)}
}

// Register records the inbound, host-agent-initiated control-link connection for hostID —
// the connection that host dialed OUT to the orchestrator (doc 15 §2.1). It is called from
// the orchestrator's connection-accept path once the dialing host agent is identified
// (host_id from its mTLS peer identity, the D22 host-identity machinery the bring-compute
// tier mandates). The HypervisorDriver verbs then route back over this connection. A host
// that re-dials (a reconnect after a blip) supersedes its prior connection: the OLD
// connection is closed and replaced, so a stale half-open link is not left to leak, and
// DriverFor immediately resolves over the fresh link (the verbs are idempotent on
// session_uuid, so a verb retried across the reconnect re-adopts rather than duplicates —
// the frozen hypervisor.v1 contract). A nil connection is rejected (a registration must
// carry a real link).
func (r *inboundDriverRegistry) Register(hostID string, conn InboundConn) error {
	if hostID == "" {
		return fmt.Errorf("controlplane: bring-compute Register: empty host_id")
	}
	if conn == nil {
		return fmt.Errorf("controlplane: bring-compute Register host %s: nil inbound connection", hostID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.conns[hostID]; ok && prev != conn {
		// A reconnect supersedes the prior link; close the stale one so it does not leak.
		_ = prev.Close()
	}
	r.conns[hostID] = conn
	return nil
}

// Deregister drops (and closes) the inbound connection for hostID — the
// orchestrator-side teardown when a host agent's outbound connection closes (a graceful
// host drain or a dropped link). After Deregister the host misses with ErrNoDriverForHost
// until it re-dials, putting it on the same missed-heartbeat recovery path the hosted
// tier's dial failure does (doc 15 §2.1 degraded-mode). It is idempotent: deregistering an
// unknown host is a no-op (returns nil). The closed connection's error (if any) is
// returned so a stuck link surfaces.
func (r *inboundDriverRegistry) Deregister(hostID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, ok := r.conns[hostID]
	if !ok {
		return nil
	}
	delete(r.conns, hostID)
	if err := conn.Close(); err != nil {
		return fmt.Errorf("controlplane: bring-compute deregister host %s: %w", hostID, err)
	}
	return nil
}

// DriverFor resolves the per-host driver client for hostID by routing the frozen
// HypervisorDriver verbs back over that host's INBOUND, host-agent-initiated connection
// (doc 15 §2.1) — NOT a separate outbound dial. A host that has not dialed in (or whose
// link was deregistered) is ErrNoDriverForHost, the same miss the hosted tier surfaces
// (the create rolls back from its host-side step; the reconciler absorbs it into an
// alarm/retry). The returned client is a ClientShim over a hypervisor.v1
// HypervisorDriverServiceClient minted on the inbound connection — the IDENTICAL frozen
// client the hosted dialRegistry produces, so the gRPC dependency stays confined to this
// site + the shim and the rest of the package is dial-direction-agnostic.
func (r *inboundDriverRegistry) DriverFor(_ context.Context, hostID string) (DriverClient, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, ok := r.conns[hostID]
	if !ok || conn == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoDriverForHost, hostID)
	}
	return ClientShim{Client: hypervisorv1.NewHypervisorDriverServiceClient(conn)}, nil
}

// Hosts returns the host_ids the registry currently routes a driver for — the hosts whose
// outbound connections have dialed in and not since deregistered. It is the fleet
// enumeration the reconciler's host-agnostic verbs broadcast over (seams.go): an
// idempotent Suspend/Destroy on session_uuid is safe to broadcast to every CONNECTED host,
// the one running the session servicing it and the rest no-opping. Unlike the hosted tier
// (whose configured endpoint set is static), this set is the LIVE connected fleet — a host
// that has not dialed in is not enumerated (there is no link to route over).
func (r *inboundDriverRegistry) Hosts(_ context.Context) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.conns))
	for h := range r.conns {
		out = append(out, h)
	}
	return out, nil
}

// Close tears down every registered inbound connection (graceful shutdown). It is
// idempotent (a second Close over an emptied set is a no-op) and returns the first close
// error encountered (the rest are still attempted) so a shutdown surfaces a stuck link
// without abandoning the others — the same close contract the hosted dialRegistry honors.
func (r *inboundDriverRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for h, conn := range r.conns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("controlplane: close bring-compute inbound host %s: %w", h, err)
		}
		delete(r.conns, h)
	}
	return firstErr
}

// Compile-time proof the inbound (bring-compute) registry satisfies the package's
// DriverRegistry seam — so main.go (under DS_ORCH_LIVE=1, bring-compute tier) drops it
// straight into Deps.Drivers, interchangeably with the hosted dialRegistry and the
// fake-returning registry the tests use. The two production registries differ ONLY in
// dial direction; both resolve a host to the same frozen ClientShim driver.
var _ DriverRegistry = (*inboundDriverRegistry)(nil)
