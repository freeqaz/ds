// SPDX-License-Identifier: Apache-2.0

// End-to-end proof of the M1 KV-store credential swap (doc 16 §5.1, §9, §11.3;
// D22/D39/D50/D55/D82/D83). This is the missing whole-path test: it wires
// Service.Fetch  ->  NewKVBackend  ->  the REAL ../kv-client/ *Client  ->  an
// httptest FAKE OpenBao/Vault, and asserts the M1 swap behaviour as a single
// closed loop rather than one seam at a time.
//
// The existing suites each cover ONE seam in isolation: kvbackend_test.go drives
// Backend.Fetch directly over the fake, and service_test.go drives Service over
// in-memory/file backends. NEITHER exercises Service.Fetch THROUGH the KV adapter
// THROUGH a fake Vault — which is exactly the M1 "credential never seen by the
// workload, swapped in transparently from the store" property the milestone's
// Done-when demands. This file is that proof.
//
// What it asserts (all HERMETIC — httptest only, NO live Vault/OpenBao, NO live
// network egress, NO live KVM; D50):
//
//	(a) the platform-identity login is JWT/OIDC (§11.3): the swap fetch is
//	    authenticated by the platform WORKLOAD identity (Role+JWT), NOT a session
//	    credential — the bootstrap-circularity answer. The resolved upstream
//	    Credential.Secret equals the long-lived secret the Vault fake holds, and
//	    Credential.Location is the frozen generic Authorization-header swap seam
//	    (D83 default).
//	(c) per-session, NEVER per-request (§9): a second Fetch inside the same session
//	    is a cache HIT — the store sees EXACTLY ONE KV read for the whole session.
//	    The long-lived secret is the one the workload never saw; it is swapped in
//	    transparently behind the cache.
//	(d) the §5.1 availability dependency: after the store goes DOWN, a NEW session's
//	    Fetch stalls (ErrStoreUnavailable), while an in-flight session that already
//	    cached its grant keeps riding it — the outage stalls NEW fetches only.
//
// The fake here is authored self-contained (its own e2e* symbols) so this file
// touches no other test file; it speaks the same documented Vault KV-v2 wire
// shapes kvbackend_test.go's fake models (auth/<mount>/login -> {"auth":
// {"client_token":...}}, <mount>/data/<path> -> {"data":{"data":...}}). Synthetic
// ds-synth-* fixtures only — no real key material anywhere (D50).
package grantservice

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	kvclient "github.com/dream-serpent/dream-serpent/identity/kv-client"
)

// --- the synthetic OpenBao/Vault fake for the end-to-end loop -----------------

// e2eVault is a synthetic OpenBao/Vault server (D50) speaking exactly the auth +
// KV-v2 read surface the real kv-client drives. It is its own type (distinct from
// kvbackend_test.go's fakeOpenBao) so this file is self-contained and touches no
// other test file. It records HTTP methods + login/read counts so the per-session
// cache assertions can prove the store is consulted EXACTLY ONCE, and it can be
// flipped UNAVAILABLE mid-test to model the §5.1 store outage WITHOUT tearing the
// listener down (so an in-flight cached session is unaffected and the assertion is
// about the cache, not about a dead socket).
type e2eVault struct {
	srv *httptest.Server

	// expectedRole/expectedJWT pin the PLATFORM workload identity (§11.3): the
	// login is authenticated by Role+JWT — the platform service's own identity,
	// NOT a session credential. mintToken is the short-lived Vault token the fake
	// hands back, which the kv-client then carries on the read.
	expectedRole string
	expectedJWT  string
	mintToken    string

	mu sync.Mutex
	// secrets keyed by "<mount>/<logical-path>" -> KV-v2 data payload (the
	// long-lived credential the workload never sees).
	secrets map[string]map[string]any
	// available, when false, makes every endpoint answer 503 — the §5.1 store
	// outage. The listener stays UP so the failure is an availability error the
	// adapter maps to ErrStoreUnavailable (not a torn socket), and an in-flight
	// session that already cached its grant never reaches the store at all.
	available bool

	// loginCount/readCount record how often the platform login / KV read actually
	// reached the store — the load-bearing per-session-not-per-request counters.
	loginCount  int
	readCount   int
	seenMethods map[string]int
}

func newE2EVault(t *testing.T) *e2eVault {
	t.Helper()
	f := &e2eVault{
		expectedRole: "ds-synth-platform-role",
		expectedJWT:  "ds-synth-platform-workload-jwt",
		mintToken:    "ds-synth-vault-token-e2e-7f3a",
		secrets:      map[string]map[string]any{},
		available:    true,
		seenMethods:  map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// setAvailable flips the store's availability — the §5.1 outage lever. The
// listener stays up; an unavailable store answers 503 (a transport-reachable
// availability failure the adapter maps to ErrStoreUnavailable).
func (f *e2eVault) setAvailable(up bool) {
	f.mu.Lock()
	f.available = up
	f.mu.Unlock()
}

func (f *e2eVault) putSecret(mountPath string, data map[string]any) {
	f.mu.Lock()
	f.secrets[mountPath] = data
	f.mu.Unlock()
}

func (f *e2eVault) counts() (logins, reads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginCount, f.readCount
}

func (f *e2eVault) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seenMethods[r.Method]++
	up := f.available
	f.mu.Unlock()

	if !up {
		// Store outage (§5.1): reachable but refusing to serve. A 503 on either the
		// login or the read is an availability failure the kv-client surfaces as a
		// non-200 the KVBackend adapter maps to ErrStoreUnavailable.
		e2eWriteVaultErr(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}

	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case strings.HasPrefix(p, "auth/") && strings.HasSuffix(p, "/login"):
		f.handleLogin(w, r, p)
	case strings.Contains(p, "/data/"):
		f.handleRead(w, r, p)
	default:
		e2eWriteVaultErr(w, http.StatusNotFound, "unsupported path: "+p)
	}
}

// handleLogin authenticates the PLATFORM WORKLOAD identity (§11.3): it accepts the
// login ONLY when the presented {role, jwt} match the platform's bound role +
// workload-identity JWT — proving the swap fetch is authenticated by the platform
// service, never by a session credential.
func (f *e2eVault) handleLogin(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodPost {
		e2eWriteVaultErr(w, http.StatusMethodNotAllowed, "login is POST")
		return
	}
	var body map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		e2eWriteVaultErr(w, http.StatusBadRequest, "bad login body")
		return
	}
	if body["jwt"] != f.expectedJWT || body["role"] != f.expectedRole {
		e2eWriteVaultErr(w, http.StatusBadRequest, "invalid platform jwt/role")
		return
	}
	f.mu.Lock()
	f.loginCount++
	f.mu.Unlock()
	e2eWriteVaultJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{"client_token": f.mintToken, "lease_duration": 3600, "renewable": true},
	})
}

func (f *e2eVault) handleRead(w http.ResponseWriter, r *http.Request, p string) {
	if r.Method != http.MethodGet {
		e2eWriteVaultErr(w, http.StatusMethodNotAllowed, "read is GET")
		return
	}
	key := strings.Replace(p, "/data/", "/", 1)
	f.mu.Lock()
	data, ok := f.secrets[key]
	if ok {
		f.readCount++
	}
	f.mu.Unlock()
	if !ok {
		e2eWriteVaultErr(w, http.StatusNotFound, "no secret at "+key)
		return
	}
	e2eWriteVaultJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}},
	})
}

func e2eWriteVaultJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func e2eWriteVaultErr(w http.ResponseWriter, status int, msg string) {
	e2eWriteVaultJSON(w, status, map[string]any{"errors": []string{msg}})
}

// e2eBuildService wires the full M1 stack the way production does — Service over
// NewKVBackend over the REAL kv-client over the fake Vault — pinning the clock for
// TTL determinism. The kv-client is constructed with JWTOIDCAuth: the PLATFORM
// workload identity (Role+JWT), the §11.3 default, NOT a session credential.
func e2eBuildService(t *testing.T, f *e2eVault, now time.Time) *Service {
	t.Helper()
	client, err := kvclient.New(
		f.srv.URL, "secret",
		kvclient.JWTOIDCAuth{Role: f.expectedRole, JWT: f.expectedJWT}, // platform identity, doc 16 §11.3
		kvclient.WithHTTPClient(f.srv.Client()),
	)
	if err != nil {
		t.Fatalf("kvclient.New: %v", err)
	}
	be, err := NewKVBackend(client, KVBackendConfig{})
	if err != nil {
		t.Fatalf("NewKVBackend: %v", err)
	}
	return New(be, WithClock(func() time.Time { return now }))
}

// the synthetic session×service×secret used across the e2e loop. The session UUID
// is a D22/D82 own-CA-style session identifier; the secret is the long-lived
// upstream credential the store holds and the workload never sees.
const (
	e2eSessionA  = "00000000-0000-4000-8000-0000000000a1"
	e2eSessionB  = "00000000-0000-4000-8000-0000000000b2"
	e2eService   = "github"
	e2eRealCred  = "ds-synth-ghp-long-lived-do-not-use" // the never-seen swap-in secret
	e2eVaultMnt  = "secret/grants/" + e2eSessionA + "/" + e2eService
	e2eVaultMntB = "secret/grants/" + e2eSessionB + "/" + e2eService
)

// TestM1KVSwapEndToEnd_ResolvesVaultSecretViaPlatformLogin is part (a): the whole
// M1 stack resolves the long-lived upstream credential out of the fake Vault,
// authenticated by the PLATFORM workload identity (JWTOIDCAuth, §11.3), and hands
// it back as Credential{Secret, Location} where Location is the frozen generic
// Authorization-header swap seam (D83 default).
func TestM1KVSwapEndToEnd_ResolvesVaultSecretViaPlatformLogin(t *testing.T) {
	f := newE2EVault(t)
	f.putSecret(e2eVaultMnt, map[string]any{"secret": e2eRealCred}) // no explicit location -> D83 default

	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	svc := e2eBuildService(t, f, now)
	svc.RegisterSession(e2eSessionA, now.Add(time.Hour))

	cred, err := svc.Fetch(e2eSessionA, e2eService, FormatGrantRef(e2eSessionA, e2eService), now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("Service.Fetch through KVBackend through fake Vault: %v", err)
	}

	// (a) the resolved upstream credential is exactly the long-lived secret the
	// Vault fake holds — swapped in transparently; the workload never produced it.
	if string(cred.Secret) != e2eRealCred {
		t.Fatalf("resolved Secret = %q, want the Vault-held long-lived credential %q", cred.Secret, e2eRealCred)
	}
	// Location is the frozen generic Authorization-header swap seam (D83 default).
	if cred.Location != "Authorization" {
		t.Fatalf("Location = %q, want the default Authorization swap seam (D83)", cred.Location)
	}

	// The fetch was authenticated by a platform login (JWTOIDCAuth, §11.3): the
	// store saw exactly one login + one read for this single fetch.
	logins, reads := f.counts()
	if logins != 1 {
		t.Fatalf("platform logins = %d, want exactly 1 (JWT/OIDC platform-identity login)", logins)
	}
	if reads != 1 {
		t.Fatalf("KV reads = %d, want exactly 1 for a single fetch", reads)
	}
	// Read-only posture (§11.3): the store only ever saw GET (read) + POST (login),
	// never any write verb — neither the adapter nor the kv-client has a write path.
	f.mu.Lock()
	for m := range f.seenMethods {
		if m != http.MethodGet && m != http.MethodPost {
			f.mu.Unlock()
			t.Fatalf("fake saw unexpected method %q — read-only posture broken (§11.3)", m)
		}
	}
	f.mu.Unlock()
}

// TestM1KVSwapEndToEnd_PerSessionNotPerRequest is part (c): repeated Fetch within a
// single session triggers EXACTLY ONE KV read — the §9 per-session, never
// per-request property. The long-lived secret is read once from the store and then
// served from the session cache; the workload pays the store RTT at most once per
// session×service and never sees the secret being swapped in.
func TestM1KVSwapEndToEnd_PerSessionNotPerRequest(t *testing.T) {
	f := newE2EVault(t)
	f.putSecret(e2eVaultMnt, map[string]any{"secret": e2eRealCred, "location": "Authorization"})

	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	svc := e2eBuildService(t, f, now)
	svc.RegisterSession(e2eSessionA, now.Add(time.Hour))

	ref := FormatGrantRef(e2eSessionA, e2eService)
	exp := now.Add(30 * time.Minute)

	// First fetch: cache MISS -> the store is consulted (login + read).
	first, err := svc.Fetch(e2eSessionA, e2eService, ref, exp)
	if err != nil {
		t.Fatalf("first Fetch (miss): %v", err)
	}
	if string(first.Secret) != e2eRealCred {
		t.Fatalf("first Secret = %q, want %q", first.Secret, e2eRealCred)
	}
	logins1, reads1 := f.counts()
	if reads1 != 1 {
		t.Fatalf("after first fetch: KV reads = %d, want 1", reads1)
	}

	// Many more fetches WITHIN THE SAME SESSION: every one is a cache HIT — the
	// store is NOT consulted again (the per-session, never per-request invariant).
	for i := 0; i < 5; i++ {
		hit, err := svc.Fetch(e2eSessionA, e2eService, ref, exp)
		if err != nil {
			t.Fatalf("cache-hit Fetch #%d: %v", i, err)
		}
		if string(hit.Secret) != e2eRealCred {
			t.Fatalf("cache-hit #%d Secret = %q, want %q", i, hit.Secret, e2eRealCred)
		}
	}

	logins2, reads2 := f.counts()
	if reads2 != reads1 {
		t.Fatalf("per-session-not-per-request broken: KV reads %d -> %d across 5 repeat fetches (want exactly 1 total)", reads1, reads2)
	}
	if logins2 != logins1 {
		t.Fatalf("cache HIT must not re-login: platform logins %d -> %d", logins1, logins2)
	}
	if reads2 != 1 {
		t.Fatalf("total KV reads for the whole session = %d, want EXACTLY 1 (the long-lived secret read once, then cached)", reads2)
	}
}

// TestM1KVSwapEndToEnd_StoreOutageStallsNewSessionsOnly is part (d): the §5.1
// availability dependency, end-to-end. An in-flight session that already cached
// its grant keeps riding the cache through a store outage; a NEW session's first
// fetch (a cache MISS that must consult the down store) stalls with
// ErrStoreUnavailable. The outage stalls NEW fetches ONLY.
func TestM1KVSwapEndToEnd_StoreOutageStallsNewSessionsOnly(t *testing.T) {
	f := newE2EVault(t)
	f.putSecret(e2eVaultMnt, map[string]any{"secret": e2eRealCred, "location": "Authorization"})
	f.putSecret(e2eVaultMntB, map[string]any{"secret": "ds-synth-second-session-cred", "location": "Authorization"})

	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	svc := e2eBuildService(t, f, now)

	// In-flight session A: register and warm its cache while the store is UP.
	svc.RegisterSession(e2eSessionA, now.Add(time.Hour))
	refA := FormatGrantRef(e2eSessionA, e2eService)
	warm, err := svc.Fetch(e2eSessionA, e2eService, refA, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("warm-cache Fetch for in-flight session: %v", err)
	}
	if string(warm.Secret) != e2eRealCred {
		t.Fatalf("warm Secret = %q, want %q", warm.Secret, e2eRealCred)
	}
	_, readsBeforeOutage := f.counts()

	// --- the store goes DOWN (§5.1 outage) ---
	f.setAvailable(false)

	// In-flight session A keeps RIDING its cache: a repeat fetch is a HIT and never
	// touches the down store, so it succeeds and the read counter does not move.
	rideThrough, err := svc.Fetch(e2eSessionA, e2eService, refA, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("in-flight session must ride its cache through the outage, got: %v", err)
	}
	if string(rideThrough.Secret) != e2eRealCred {
		t.Fatalf("rode-through Secret = %q, want the still-cached %q", rideThrough.Secret, e2eRealCred)
	}
	if _, reads := f.counts(); reads != readsBeforeOutage {
		t.Fatalf("in-flight cache hit must NOT consult the down store: reads %d -> %d", readsBeforeOutage, reads)
	}

	// A NEW session B registers and tries its FIRST fetch — a cache MISS that must
	// consult the down store. It STALLS: ErrStoreUnavailable (NOT ErrGrantNotFound —
	// an outage is not a confirmed absence; the credential exists in the store).
	svc.RegisterSession(e2eSessionB, now.Add(time.Hour))
	refB := FormatGrantRef(e2eSessionB, e2eService)
	_, err = svc.Fetch(e2eSessionB, e2eService, refB, now.Add(30*time.Minute))
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("NEW session fetch during outage: err = %v, want ErrStoreUnavailable (the §5.1 stall)", err)
	}
	if errors.Is(err, ErrGrantNotFound) {
		t.Fatal("a store outage must NOT be reported as ErrGrantNotFound — that would be a wrong definitive deny for a credential that exists")
	}

	// --- the store comes back UP ---
	f.setAvailable(true)

	// The previously-stalled NEW session can now resolve its (different) credential:
	// the stall was transient, exactly the availability-dependency contract.
	recovered, err := svc.Fetch(e2eSessionB, e2eService, refB, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("NEW session fetch after recovery: %v", err)
	}
	if string(recovered.Secret) != "ds-synth-second-session-cred" {
		t.Fatalf("recovered Secret = %q, want ds-synth-second-session-cred", recovered.Secret)
	}
}
