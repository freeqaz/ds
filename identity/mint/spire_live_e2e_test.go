// SPDX-License-Identifier: Apache-2.0

// Live SPIRE Workload-API e2e + deep-chain validation (01KV91H3QW / 01KV6ERQB4
// live-validation leg). This is the DEFERRED manual step the synthetic suites
// cannot cover (D50): it drives the real go-spiffe Workload-API client behind
// DialSpireWorkloadAPI against an ACTUAL SPIRE Agent socket.
//
// GATING (consolidated to a DS_SPIRE_LIVE ENV-SKIP, NOT a build tag). These tests
// are COMPILED in CI — keeping go-spiffe/v2 exercised at build — but SKIP cleanly
// when DS_SPIRE_LIVE is unset, so the offline suite stays hermetic (D50: there is
// no live SPIRE Agent in CI). With DS_SPIRE_LIVE set, the agent socket is read from
// SPIFFE_ENDPOINT_SOCKET (required — the test FAILS LOUDLY if DS_SPIRE_LIVE is set
// but the socket is empty or unreachable). Run it only on a host with a reachable
// SPIRE Agent, e.g. against the multi-tier bring-up the companion script provisions:
//
//	DS_SPIRE_LIVE=1 SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent.sock \
//	  GOWORK=off go test -run 'TestSpireLive' -v ./identity/mint
//
// or cross-compile (`go test -c`) and run the binary on the host. scripts/
// spire-live-multitier.sh stands up a single-host MULTI-TIER (UpstreamAuthority
// disk) SPIRE so the served SVIDs carry a REAL interposed intermediate, then prints
// the exact SPIFFE_ENDPOINT_SOCKET + run command.
//
// WHAT THE LIVE LEG CONFIRMS. The synthetic suites (spire_authority_test.go +
// spire_fake.go) prove the authority's x5c[1:] -> Intermediates chain-walk and the
// stdlib basic-constraints / path-length / chain-time enforcement against SYNTHETIC
// depth-2 CAs (01KV8Z92 deepens that to N-level + interposed-CA validity windows,
// still synthetic; 01KV6ER3KP the dual-run map). This live leg confirms a REAL
// multi-tier deployment's interposed CAs walk IDENTICALLY to the synthetic depth-2
// fake — synthetic == live — and that the chain walk is load-bearing against a REAL
// SVID. Exhaustive non-CA / out-of-window interposed-cert DENYs stay covered
// SYNTHETICALLY (01KV8Z92 / 01KV6ER3KP), since re-signing a live SVID under a broken
// interposed CA is impossible without the trust domain's private keys; the live
// fail-closed DENY here swaps the TRUST BUNDLE instead (a foreign root) to prove the
// interposed-CA chain walk is load-bearing without needing any private key.
package mint

import (
	"crypto/x509"
	"os"
	"testing"
	"time"
)

// liveSpireSocket returns the agent socket for the live leg, enforcing the
// DS_SPIRE_LIVE env-skip contract: if DS_SPIRE_LIVE is UNSET the caller test SKIPs
// cleanly (the offline/CI default — D50, no live SPIRE socket in CI); if it is SET
// but SPIFFE_ENDPOINT_SOCKET is empty the test FAILS LOUDLY (a misconfigured live
// run must not silently pass). The returned socket is handed to DialSpireWorkloadAPI,
// which fails closed on an unreachable one.
func liveSpireSocket(t *testing.T) string {
	t.Helper()
	if os.Getenv("DS_SPIRE_LIVE") == "" {
		t.Skip("DS_SPIRE_LIVE unset; the live SPIRE leg is a deferred manual step (D50) — never run in CI")
	}
	sock := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if sock == "" {
		t.Fatal("DS_SPIRE_LIVE is set but SPIFFE_ENDPOINT_SOCKET is empty; the live leg requires a reachable SPIRE Agent socket (e.g. unix:///run/spire/agent.sock) — see scripts/spire-live-multitier.sh")
	}
	return sock
}

// dialLiveOrFatal dials the live SPIRE Workload API at the env socket, failing the
// test LOUDLY when DS_SPIRE_LIVE is set but the socket is unreachable (the live leg
// must surface a misconfigured/down agent, not skip past it).
func dialLiveOrFatal(t *testing.T) SVIDSource {
	t.Helper()
	sock := liveSpireSocket(t)
	src, err := DialSpireWorkloadAPI(sock)
	if err != nil {
		t.Fatalf("DialSpireWorkloadAPI(%q): %v (DS_SPIRE_LIVE is set — the SPIRE Agent socket must be reachable)", sock, err)
	}
	return src
}

// TestSpireLiveE2E exercises the live substrate end-to-end against a real agent:
// the deferred DialSpireWorkloadAPI dial, TrustBundle, FetchX509SVID (adapting the
// real SVID + signing the parallel JWS with the SVID's own key), the leaf chaining
// to the live trust bundle, and the authority's full VerifyPresented ALLOW — plus a
// wrong-name DENY proving the right-identity check still bites against real SVIDs.
// Re-gated from the former `//go:build spirelive` tag to the DS_SPIRE_LIVE env-skip
// (compiled in CI, SKIPs when unset).
func TestSpireLiveE2E(t *testing.T) {
	src := dialLiveOrFatal(t)

	// (2) TRUST BUNDLE: the real trust domain CA pool.
	pool := src.TrustBundle()
	if pool == nil {
		t.Fatal("live TrustBundle() returned nil")
	}

	// Probe the agent's own SVID to learn its actual URI SAN (the live source serves
	// the workload's OWN identity, not a per-session mint).
	probe, err := src.FetchX509SVID(X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID probe: %v", err)
	}
	leaf, err := x509.ParseCertificate(probe.CertDER)
	if err != nil {
		t.Fatalf("parse live SVID leaf: %v", err)
	}
	if len(leaf.URIs) != 1 {
		t.Fatalf("live SVID leaf carries %d URI SANs, want exactly 1", len(leaf.URIs))
	}
	spiffeID := leaf.URIs[0].String()
	t.Logf("live SPIRE SVID: id=%s notAfter=%s keyType=%T", spiffeID, leaf.NotAfter.UTC(), leaf.PublicKey)

	// (3) AUTHENTICITY: the real leaf must chain to the real trust bundle. Assemble
	// any interposed intermediates the SVID carries (x5c[1:]) into the pool, exactly
	// as the authority does — so this basic leg is tolerant of BOTH a flat trust
	// domain (zero intermediates, leaf chains directly) AND a multi-tier one (the
	// UpstreamAuthority-disk SPIRE the companion script provisions, where the leaf
	// chains leaf -> interposed-CA -> root). A multi-tier-only assumption here would
	// false-fail the basic leg against the documented multi-tier bring-up.
	intermediates := x509.NewCertPool()
	for _, icDER := range probe.Intermediates {
		ic, perr := x509.ParseCertificate(icDER)
		if perr != nil {
			t.Fatalf("parse live interposed intermediate: %v", perr)
		}
		intermediates.AddCert(ic)
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr != nil {
		t.Fatalf("live SVID leaf does not chain to the agent's trust bundle: %v", verr)
	}

	// (4) FULL AUTHORITY ROUND-TRIP: mint the parallel JWS over claims whose subject
	// is the SVID's own id, then run the SPIRE WorkloadAuthority's VerifyPresented
	// against the REAL agent SVID — the substrate behavior CI can only fake.
	now := time.Now()
	svid, err := src.FetchX509SVID(X509SVIDRequest{
		SpiffeID:  spiffeID,
		Claims:    jwtClaims{Subject: spiffeID, Issuer: "spire-live-e2e", SessionUUID: "e2e-live-0001", Org: "dream-serpent.test"},
		NotBefore: now,
		NotAfter:  now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	a := NewSpireWorkloadAuthority(src)
	claims, err := a.VerifyPresented([]byte(svid.JWT), spiffeID, now)
	if err != nil {
		t.Fatalf("VerifyPresented against the live SPIRE SVID DENIED (%v); want ALLOW", err)
	}
	if claims.Subject != spiffeID {
		t.Fatalf("verified claims subject = %q, want the SVID id %q", claims.Subject, spiffeID)
	}

	// (5) NEGATIVE: a mismatched expected name must fail closed (right-identity check
	// against a real, authentic SVID).
	if _, err := a.VerifyPresented([]byte(svid.JWT), "spiffe://dream-serpent.test/session/WRONG-NAME", now); err == nil {
		t.Fatal("VerifyPresented must DENY when the expected SPIFFE name != the live SVID SAN")
	}

	t.Logf("LIVE SPIRE e2e PASS: dial + bundle + fetch/adapt + chain-to-bundle + VerifyPresented ALLOW + wrong-name DENY")
}

// foreignBundleSVIDSource wraps a live SVIDSource, delegating FetchX509SVID to it
// (so the SVID served is the REAL agent SVID, with its real interposed-CA chain in
// the JWS x5c) but returning a TrustBundle that does NOT contain the real root — an
// EMPTY pool. It needs no private key: the wrapper re-presents a genuine live JWS to
// an authority whose trust anchor is foreign, so the interposed-CA chain walk runs
// against a root the chain can never reach. It is the live counterpart to the
// synthetic mintForeignSvid adversary (spire_authority_test.go), inverted: there the
// SVID is foreign and the bundle real; here the SVID is real and the bundle foreign.
// Either way the chain walk must FAIL closed — proving it is load-bearing.
type foreignBundleSVIDSource struct {
	live    SVIDSource
	foreign *x509.CertPool
}

func (f *foreignBundleSVIDSource) FetchX509SVID(req X509SVIDRequest) (X509SVID, error) {
	return f.live.FetchX509SVID(req)
}

func (f *foreignBundleSVIDSource) TrustBundle() *x509.CertPool { return f.foreign }

// TestSpireLiveDeepChain is the MULTI-TIER (UpstreamAuthority) live leg: against a
// SPIRE whose served SVIDs carry a REAL interposed intermediate (the disk-root
// upstream makes SPIRE's own CA an INTERMEDIATE signed by the disk root, and the
// published bundle = the disk root — see scripts/spire-live-multitier.sh), it proves
//
//	(A) ALLOW: a live SVID with >= 1 interposed intermediate (x5c len >= 2) walks
//	    leaf -> interposed-CA(s) -> root to the live trust bundle and Validates ALLOW
//	    through NewSpireWorkloadAuthority(src).VerifyPresented — IDENTICALLY to the
//	    synthetic depth-2 fake (synthetic == live);
//	(B) fail-closed DENY: the SAME real JWS, re-presented to an authority whose trust
//	    bundle is FOREIGN (does not contain the real root), must DENY on the chain
//	    walk (the caller maps the chain failure to ReasonSignatureInvalid) — proving
//	    the interposed-CA chain walk is load-bearing against a REAL SVID, with no
//	    private key needed;
//	(C) wrong-name DENY: a mismatched expected SAN fails closed against the real SVID.
//
// SKIPs cleanly when DS_SPIRE_LIVE is unset. When set, requires a MULTI-TIER agent:
// it FAILS if the served SVID carries no interposed intermediate (a flat trust
// domain is the wrong fixture for the deep-chain leg — run the multi-tier script).
func TestSpireLiveDeepChain(t *testing.T) {
	src := dialLiveOrFatal(t)

	pool := src.TrustBundle()
	if pool == nil {
		t.Fatal("live TrustBundle() returned nil")
	}

	// Fetch the live SVID and learn its own URI SAN (the live leg serves the
	// workload's own identity).
	probe, err := src.FetchX509SVID(X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID probe: %v", err)
	}
	leaf, err := x509.ParseCertificate(probe.CertDER)
	if err != nil {
		t.Fatalf("parse live SVID leaf: %v", err)
	}
	if len(leaf.URIs) != 1 {
		t.Fatalf("live SVID leaf carries %d URI SANs, want exactly 1", len(leaf.URIs))
	}
	spiffeID := leaf.URIs[0].String()

	// MULTI-TIER fixture assertion: the served SVID must carry at least ONE interposed
	// intermediate (the SPIRE CA interposed under the disk root). A flat trust domain
	// (no UpstreamAuthority) yields zero intermediates and is the WRONG fixture for the
	// deep-chain leg — fail loudly so a mis-provisioned single-tier agent is caught.
	if len(probe.Intermediates) < 1 {
		t.Fatalf("live SVID carries %d interposed intermediates, want >= 1; run scripts/spire-live-multitier.sh for a MULTI-TIER (UpstreamAuthority disk) SPIRE so the served SVID chains leaf -> interposed-CA -> root", len(probe.Intermediates))
	}
	t.Logf("live MULTI-TIER SPIRE SVID: id=%s interposed-intermediates=%d", spiffeID, len(probe.Intermediates))

	// (A.1) AUTHENTICITY: the real leaf, walked through its interposed intermediate(s),
	// chains to the live trust bundle (the disk root). Assemble the intermediates pool
	// exactly as the authority does (x5c[1:] -> Intermediates).
	intermediates := x509.NewCertPool()
	for _, icDER := range probe.Intermediates {
		ic, perr := x509.ParseCertificate(icDER)
		if perr != nil {
			t.Fatalf("parse live interposed intermediate: %v", perr)
		}
		intermediates.AddCert(ic)
	}
	now := time.Now()
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr != nil {
		t.Fatalf("live leaf does not walk leaf -> interposed-CA -> root to the live trust bundle: %v", verr)
	}
	// And the interposed CA must be LOAD-BEARING: without the intermediates pool the
	// leaf must NOT chain to the root (the interposed CA is the missing link), exactly
	// as the synthetic hierarchical fake asserts.
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr == nil {
		t.Fatal("live leaf chained to the root with NO intermediates pool; the interposed CA is not load-bearing (is this really a MULTI-TIER agent?)")
	}

	// (A.2) ALLOW through the authority: mint the parallel JWS (it carries the full
	// leaf + interposed-CA chain in x5c) and VerifyPresented ALLOWs it — the depth-2
	// chain walk a live deployment's interposed CAs take, identical to the synthetic
	// depth-2 fake (spire_authority_test.go TestSpireAuthority_DeepHierarchicalChainWalkAllow).
	svid, err := src.FetchX509SVID(X509SVIDRequest{
		SpiffeID:  spiffeID,
		Claims:    jwtClaims{Subject: spiffeID, Issuer: "spire-live-deepchain", SessionUUID: "e2e-live-0001", Org: "dream-serpent.test"},
		NotBefore: now,
		NotAfter:  now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	a := NewSpireWorkloadAuthority(src)
	claims, err := a.VerifyPresented([]byte(svid.JWT), spiffeID, now)
	if err != nil {
		t.Fatalf("multi-tier live SVID VerifyPresented DENIED (%v); want ALLOW (interposed-CA chain walk to the live bundle)", err)
	}
	if claims.Subject != spiffeID {
		t.Fatalf("verified claims subject = %q, want the SVID id %q", claims.Subject, spiffeID)
	}

	// (B) FAIL-CLOSED DENY against a REAL SVID, no private key needed: re-present the
	// SAME genuine JWS to an authority whose trust bundle is FOREIGN (an empty pool not
	// containing the real root). The interposed-CA chain walk cannot reach a root it
	// does not hold, so VerifyPresented must DENY with the chain-failure path that the
	// caller maps to ReasonSignatureInvalid — proving the chain walk is load-bearing.
	wrapped := NewSpireWorkloadAuthority(&foreignBundleSVIDSource{live: src, foreign: x509.NewCertPool()})
	if _, err := wrapped.VerifyPresented([]byte(svid.JWT), spiffeID, now); err == nil {
		t.Fatal("VerifyPresented against a FOREIGN trust bundle (no real root) must DENY a real SVID — the interposed-CA chain walk is not load-bearing otherwise")
	}

	// (C) wrong-name DENY: the right-identity check still bites against the real SVID.
	if _, err := a.VerifyPresented([]byte(svid.JWT), "spiffe://dream-serpent.test/session/WRONG-NAME", now); err == nil {
		t.Fatal("VerifyPresented must DENY when the expected SPIFFE name != the live SVID SAN")
	}

	t.Logf("LIVE MULTI-TIER SPIRE deep-chain PASS: >=1 interposed intermediate, leaf->interposed-CA->root ALLOW + foreign-bundle DENY + wrong-name DENY — synthetic == live")
}
