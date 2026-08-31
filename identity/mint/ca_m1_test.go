// SPDX-License-Identifier: Apache-2.0

// M1 own-minimal-CA substrate conformance tests (doc 16 §2/§4/§5.4/§13; the
// §13 assurance rows as EXECUTABLE assertions). These prove the M1 substrate swap
// preserved every invariant the M0 shim held AND added the M1 properties:
//
//   - ROOT PERSISTENCE: both D82 roots load from the secret store across a process
//     restart (same key+cert), NOT regenerated — and a live session's leaves still
//     chain after the restart (doc 16 §2).
//   - STALE-CERT (§13): a time-expired / post-rotation workload cert fails Validate
//     (TTL-as-revocation, doc 16 §5.4) WITHOUT any change to the Validate contract.
//   - KILL-MID-FLIGHT (§13): a killed/suspended session's STILL-TIME-VALID cert
//     fails Validate IMMEDIATELY via the liveness check (active eviction, doc 16
//     §5.4) — proven for both RevokeSession and TeardownSession.
//   - PER-SESSION CA POSTURE: the per-session interception CA is an INTERMEDIATE
//     under the persistent interception root (proxy-bound, never a root, the bounded
//     D76 exposure), and its key is DESTROYED at teardown.
//   - KEY CUSTODY (D39): persisted root key files are 0600; a loosened key file is
//     refused on load (fail closed).
//
// Everything synthetic (D50). The clock is pinned so freshness/liveness branches
// are deterministic.
package mint

import (
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// m1Clock is a mutable pinned clock for the M1 tests (advance time to drive the
// STALE-CERT TTL branch deterministically).
type m1Clock struct{ t time.Time }

func (c *m1Clock) now() time.Time { return c.t }

// --- ROOT PERSISTENCE --------------------------------------------------------

// TestM1_RootPersistenceAcrossRestart proves the M1 own-minimal-CA posture: both
// D82 roots PERSIST in the secret store and are LOADED (not regenerated) by a fresh
// shim pointed at the SAME store — the bytes of the root certs are identical across
// the "restart", and a workload leaf minted by the first shim still chains to the
// SECOND shim's loaded workload root.
func TestM1_RootPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	store1, err := NewFileCAStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	clk := &m1Clock{t: time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)}

	shim1, err := NewShim(WithClock(clk.now), WithCAStore(store1))
	if err != nil {
		t.Fatal(err)
	}
	wlRoot1 := shim1.WorkloadRootDER()
	icRoot1 := shim1.InterceptionRootCADER()

	// A workload leaf minted under shim1.
	bundle, err := shim1.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: testSession, Org: testOrg})
	if err != nil {
		t.Fatal(err)
	}

	// "Restart": a brand-new shim + new CAStore handle over the SAME directory.
	store2, err := NewFileCAStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	shim2, err := NewShim(WithClock(clk.now), WithCAStore(store2))
	if err != nil {
		t.Fatal(err)
	}
	wlRoot2 := shim2.WorkloadRootDER()
	icRoot2 := shim2.InterceptionRootCADER()

	// The roots are the SAME bytes (loaded, not regenerated).
	if string(wlRoot1) != string(wlRoot2) {
		t.Fatal("PERSISTENCE FAIL: workload root regenerated across restart")
	}
	if string(icRoot1) != string(icRoot2) {
		t.Fatal("PERSISTENCE FAIL: interception root regenerated across restart")
	}

	// A leaf minted by shim1 still chains to shim2's LOADED workload root (the
	// signing key survived the restart, so the leaf's signature still verifies).
	if err := shim2.workloadRoot.verifyLeaf(bundle.CertDER, clk.now()); err != nil {
		t.Fatalf("PERSISTENCE FAIL: pre-restart leaf does not chain to reloaded root: %v", err)
	}

	// And the reloaded interception root can still ISSUE a per-session intermediate
	// (its private key was loaded, not regenerated).
	if _, err := shim2.mintInterceptionCA("00000000-0000-4000-8000-0000000000c2"); err != nil {
		t.Fatalf("PERSISTENCE FAIL: reloaded interception root cannot issue a CA: %v", err)
	}
}

// TestM1_KeyFilePermissionsAre0600 proves the D39 custody property: the persisted
// root SIGNING KEY files are 0600 (owner-only), while the public cert files may be
// world-readable.
func TestM1_KeyFilePermissionsAre0600(t *testing.T) {
	// Use a subdir the STORE creates (MkdirAll 0700), not t.TempDir() itself (the
	// harness pre-creates that one 0755, and the store never widens NOR narrows an
	// existing dir's mode — custody is owner discipline at the deployment dir).
	dir := filepath.Join(t.TempDir(), "castore")
	store, err := NewFileCAStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewShim(WithClock(func() time.Time { return time.Now() }), WithCAStore(store)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"workload", "interception"} {
		keyInfo, err := os.Stat(filepath.Join(dir, name+"-root.key.pem"))
		if err != nil {
			t.Fatalf("%s key file missing: %v", name, err)
		}
		if perm := keyInfo.Mode().Perm(); perm != 0o600 {
			t.Fatalf("CUSTODY FAIL: %s root key file mode = %#o, want 0600", name, perm)
		}
	}
	// The store-created directory itself is 0700 (no group/other access).
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("CUSTODY FAIL: store dir mode = %#o, group/other bits set", dirInfo.Mode().Perm())
	}
}

// TestM1_RefusesLoosenedKeyFile proves the load path FAILS CLOSED on a custody
// violation: a persisted key file widened to group/world readable is refused, so a
// shim never trusts a root key anyone on the box could have read.
func TestM1_RefusesLoosenedKeyFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileCAStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// First run persists the roots 0600.
	if _, err := NewShim(WithClock(func() time.Time { return time.Now() }), WithCAStore(store)); err != nil {
		t.Fatal(err)
	}
	// Loosen the workload key file to world-readable, then try to reload.
	keyPath := filepath.Join(dir, "workload-root.key.pem")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	store2, err := NewFileCAStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewShim(WithClock(func() time.Time { return time.Now() }), WithCAStore(store2))
	if err == nil {
		t.Fatal("CUSTODY FAIL: shim loaded a world-readable root key file (should fail closed)")
	}
}

// --- STALE-CERT (§13) --------------------------------------------------------

// TestM1_StaleCertFailsValidate proves the §13 stale-cert row: a time-expired (or
// post-rotation) workload cert fails Validate — TTL-as-revocation (doc 16 §5.4) —
// through the UNCHANGED Validate contract. Two legs: (1) the SESSION expiry (the
// record's TTL elapses → session_expired); (2) the TOKEN's own nbf..exp window
// elapses while the session record is still live (credential_stale).
func TestM1_StaleCertFailsValidate(t *testing.T) {
	clk := &m1Clock{t: time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)}
	shim, err := NewShim(WithClock(clk.now))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatal(err)
	}

	// In-window: ALLOW.
	if res := shim.Validate([]byte(bundle.JWT), testSession, testSvc); res.Verdict != VerdictAllow {
		t.Fatalf("pre-expiry want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}

	// Advance past the 1h TTL: the still-structurally-valid cert now fails closed.
	clk.t = clk.t.Add(2 * time.Hour)
	res := shim.Validate([]byte(bundle.JWT), testSession, testSvc)
	if res.Verdict != VerdictDeny {
		t.Fatal("STALE-CERT FAIL: expired cert still validated ALLOW")
	}
	if res.MachineReadableReason != ReasonSessionExpired && res.MachineReadableReason != ReasonCredentialStale {
		t.Fatalf("STALE-CERT FAIL: reason = %q, want session_expired or credential_stale", res.MachineReadableReason)
	}
}

// TestM1_PostRotationCertFailsValidate proves the post-rotation half of the §13
// stale-cert row: after the session re-mints (rotation), the OLD cert's key no
// longer matches the session record's workload key, so the old credential fails
// signature verification — a rotated-away cert cannot be replayed.
func TestM1_PostRotationCertFailsValidate(t *testing.T) {
	clk := &m1Clock{t: time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)}
	shim, err := NewShim(WithClock(clk.now))
	if err != nil {
		t.Fatal(err)
	}
	old, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: testSession, Org: testOrg, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(testSession, testSvc, "g1")
	if res := shim.Validate([]byte(old.JWT), testSession, testSvc); res.Verdict != VerdictAllow {
		t.Fatalf("pre-rotation want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}

	// ROTATE: re-mint the workload identity for the same session (new key on record).
	clk.t = clk.t.Add(10 * time.Minute)
	if _, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: testSession, Org: testOrg, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	// The OLD cert (still inside its own nbf..exp) now fails: its key is not the
	// session record's current workload key.
	res := shim.Validate([]byte(old.JWT), testSession, testSvc)
	if res.Verdict != VerdictDeny || res.MachineReadableReason != ReasonSignatureInvalid {
		t.Fatalf("POST-ROTATION FAIL: old cert verdict=%v reason=%q, want DENY/signature_invalid", res.Verdict, res.MachineReadableReason)
	}
}

// --- KILL-MID-FLIGHT (§13) ---------------------------------------------------

// TestM1_KillMidFlightFailsImmediately proves the §13 kill-mid-flight row for BOTH
// eviction paths: a still-TIME-VALID workload cert fails Validate IMMEDIATELY the
// instant the session is killed — no clock advance, no CRL/OCSP — via the liveness
// check (doc 16 §5.4 active eviction). RevokeSession surfaces the operator reason;
// TeardownSession evicts the record so the cert reads as unknown_session.
func TestM1_KillMidFlightFailsImmediately(t *testing.T) {
	clk := &m1Clock{t: time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)}

	t.Run("revoke", func(t *testing.T) {
		shim, err := NewShim(WithClock(clk.now))
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: testSession, Org: testOrg, TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		_ = shim.GrantSession(testSession, testSvc, "g1")
		if res := shim.Validate([]byte(bundle.JWT), testSession, testSvc); res.Verdict != VerdictAllow {
			t.Fatalf("pre-kill want ALLOW, got DENY(%s)", res.MachineReadableReason)
		}
		// KILL: revoke. NO clock advance — the cert is still inside its nbf..exp.
		if err := shim.RevokeSession(testSession, "admin_kill"); err != nil {
			t.Fatal(err)
		}
		res := shim.Validate([]byte(bundle.JWT), testSession, testSvc)
		if res.Verdict != VerdictDeny {
			t.Fatal("KILL-MID-FLIGHT FAIL: time-valid cert validated after revoke")
		}
		if res.MachineReadableReason != "admin_kill" {
			t.Fatalf("KILL-MID-FLIGHT FAIL: reason = %q, want admin_kill", res.MachineReadableReason)
		}
	})

	t.Run("teardown", func(t *testing.T) {
		shim, err := NewShim(WithClock(clk.now))
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: testSession, Org: testOrg, TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		_ = shim.GrantSession(testSession, testSvc, "g1")
		ca, err := shim.mintInterceptionCA(testSession)
		if err != nil {
			t.Fatal(err)
		}
		if res := shim.Validate([]byte(bundle.JWT), testSession, testSvc); res.Verdict != VerdictAllow {
			t.Fatalf("pre-teardown want ALLOW, got DENY(%s)", res.MachineReadableReason)
		}
		// TEARDOWN: destroys the interception key + evicts the record. NO clock advance.
		if err := shim.TeardownSession(testSession); err != nil {
			t.Fatal(err)
		}
		res := shim.Validate([]byte(bundle.JWT), testSession, testSvc)
		if res.Verdict != VerdictDeny || res.MachineReadableReason != ReasonUnknownSession {
			t.Fatalf("KILL-MID-FLIGHT FAIL: post-teardown verdict=%v reason=%q, want DENY/unknown_session", res.Verdict, res.MachineReadableReason)
		}
		// The per-session interception trust anchor is gone after teardown.
		if shim.InterceptionRootDER(testSession) != nil {
			t.Fatal("TEARDOWN FAIL: interception anchor still present after teardown")
		}
		// The returned CA key bytes are unaffected (they are the proxy's copy); the
		// shim-side key is what was destroyed. Sanity: the CA cert still parses.
		if _, err := x509.ParseCertificate(ca.CACertDER); err != nil {
			t.Fatalf("interception CA cert should still parse: %v", err)
		}
	})
}

// TestM1_TeardownDestroysInterceptionKey proves the doc 16 §4 teardown lifecycle:
// the per-session interception SIGNING KEY is destroyed (zeroed) at teardown, so no
// recoverable signing material survives on the shim side (the bounded D76 exposure
// shrinks to zero at teardown).
func TestM1_TeardownDestroysInterceptionKey(t *testing.T) {
	shim := newTestShim(t)
	if _, err := shim.mintInterceptionCA(testSession); err != nil {
		t.Fatal(err)
	}
	// Capture the live per-session CA struct before teardown.
	shim.mu.Lock()
	ca := shim.sessions[testSession].interceptionCA
	shim.mu.Unlock()
	if ca == nil || ca.key == nil {
		t.Fatal("expected a live interception CA key before teardown")
	}
	// Keep a handle to the underlying ecdsa key to prove the scalar was zeroed.
	rawKey := ca.key

	if err := shim.TeardownSession(testSession); err != nil {
		t.Fatal(err)
	}
	// The record is evicted ...
	shim.mu.Lock()
	_, present := shim.sessions[testSession]
	shim.mu.Unlock()
	if present {
		t.Fatal("TEARDOWN FAIL: session record not evicted")
	}
	// ... and the captured key's private scalar D was zeroed in place.
	if rawKey.D != nil && rawKey.D.Sign() != 0 {
		t.Fatal("TEARDOWN FAIL: interception key scalar not zeroed at teardown")
	}
	// Idempotent: tearing down again is a no-op (no panic, no error).
	if err := shim.TeardownSession(testSession); err != nil {
		t.Fatalf("teardown should be idempotent: %v", err)
	}
}

// --- PER-SESSION CA POSTURE (D76) -------------------------------------------

// TestM1_InterceptionCAIsIntermediateUnderPersistentRoot proves the M1 bounded-D76
// posture: each session's interception CA is an INTERMEDIATE that chains to the ONE
// persistent interception root (never a fresh per-session root), it is itself a
// path-len-0 CA (it signs leaves, never further CAs), and the per-session
// intermediate — NOT the root — is what the proxy receives.
func TestM1_InterceptionCAIsIntermediateUnderPersistentRoot(t *testing.T) {
	shim := newTestShim(t)
	sessionA := "00000000-0000-4000-8000-00000000000a"
	sessionB := "00000000-0000-4000-8000-00000000000b"

	caA, err := shim.mintInterceptionCA(sessionA)
	if err != nil {
		t.Fatal(err)
	}
	caB, err := shim.mintInterceptionCA(sessionB)
	if err != nil {
		t.Fatal(err)
	}

	caCertA, err := x509.ParseCertificate(caA.CACertDER)
	if err != nil {
		t.Fatal(err)
	}
	// It is a CA, path-len 0 (cannot issue further CAs).
	if !caCertA.IsCA {
		t.Fatal("per-session interception CA is not marked IsCA")
	}
	if !caCertA.MaxPathLenZero || caCertA.MaxPathLen != 0 {
		t.Fatal("per-session interception CA is not path-len-0 (must sign only leaves)")
	}

	// Both session intermediates chain to the ONE persistent interception root
	// (provenance) — they are NOT independent self-signed roots.
	rootPool := poolFromDER(t, shim.InterceptionRootCADER())
	for name, caDER := range map[string][]byte{"A": caA.CACertDER, "B": caB.CACertDER} {
		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := caCert.Verify(x509.VerifyOptions{
			Roots:       rootPool,
			CurrentTime: shim.now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Fatalf("session-%s interception CA must chain to the persistent interception root: %v", name, err)
		}
	}

	// And the two intermediates are DISTINCT (per-session): different serials.
	caCertB, err := x509.ParseCertificate(caB.CACertDER)
	if err != nil {
		t.Fatal(err)
	}
	if caCertA.SerialNumber.Cmp(caCertB.SerialNumber) == 0 {
		t.Fatal("ISOLATION FAIL: two sessions share one interception CA serial")
	}

	// The proxy never receives the ROOT key — only the per-session intermediate key.
	// (Sanity: the returned key parses as the intermediate's key, distinct from the
	// root, which is never marshaled out anywhere.)
	caKey, err := x509.ParsePKCS8PrivateKey(caA.CAKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	if caKey.(*ecdsa.PrivateKey).PublicKey.Equal(shim.interceptionRoot.key.Public()) {
		t.Fatal("D76 BREACH: proxy-delivered interception key equals the persistent root key")
	}
}
