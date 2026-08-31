// SPDX-License-Identifier: Apache-2.0

// Dual-run / real-vs-fake conformance suite (doc 06 §2) for the frozen D24 Validate
// seam (doc 16 §4/§9): it proves the M1 own-CA WorkloadAuthority
// (ownCAWorkloadAuthority, mint.go) and the M3 SPIRE-backed WorkloadAuthority
// (spireWorkloadAuthority over the synthetic SPIRE-shaped fake, spire_authority.go /
// spire_fake.go) BOTH satisfy that ONE frozen contract FIELD-FOR-FIELD — the
// "substrate swap behind a frozen contract, not a rebuild" guarantee of doc 05 §7
// edge 5.
//
// It is the dual-run counterpart to the per-substrate suites (mint_test.go /
// ca_m1_test.go assert the own-CA leg; spire_authority_test.go asserts the SPIRE
// leg). Where those run their assertions ONCE, this file runs the SAME assertions
// against a Shim built TWO ways and demands the verdict AND the machine-readable
// reason be IDENTICAL across both substrates for every case — the observable purity
// of the swap. The verdicts are driven through the GENERATED grpc Validate seam
// (reusing dialInProcess from grpc_seam_test.go), so it is the FROZEN wire contract
// under test, not an internal method.
//
// The cases (each asserted IDENTICALLY for both substrates, the doc 06 §2 conformance
// rows):
//
//	(a) fresh minted + granted          -> ALLOW   (grant_ref + expiry carried)
//	(b) unknown session                 -> DENY    unknown_session
//	(c) revoked session                 -> DENY    (operator reason, the D77 channel)
//	(d) torn-down still-time-valid cert  -> DENY    unknown_session (kill-mid-flight §13)
//	(e) out-of-grant service            -> DENY    out_of_grant
//	(f) cross-session / wrong-SAN cred   -> DENY    signature_invalid
//	(g) stale (outside nbf..exp)         -> DENY    credential_stale
//
// Plus the PURE-SWAP property: the minted §3.1 SPIFFE name
// spiffe://<org>/session/<uuid> is BYTE-IDENTICAL across both substrates (same Build
// helper upstream of either authority — spiffeid.go).
//
// Everything synthetic (D50): the own-CA roots are the ephemeral file-store roots
// NewShim mints; the SPIRE substrate runs over the synthetic SPIRE-Workload-API fake
// (NewFakeSVIDSource) — no live SPIRE, no Workload-API socket, no go-spiffe. This
// suite WEAKENS NO existing test: it adds the dual-run table beside the per-substrate
// suites, and the M1 own-CA impl stays selectable beside the SPIRE impl (a backend
// swap, never a deletion).
package mint

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// conformanceSession is a distinct session UUID for the dual-run suite (its own, so
// the table never aliases the package-level testSession the other suites use).
const conformanceSession = "00000000-0000-4000-8000-0000000000c1"

// conformanceSubstrate is one of the two D22 substrates the dual-run table runs every
// case against. newShim builds a Shim on that substrate sharing a caller-pinned clock
// (so freshness/liveness branches are deterministic and the two legs line up
// field-for-field). staleCred builds the case-(g) credential the right way FOR THAT
// substrate: a credential that is signature/chain-valid at the (advanced) validate
// time but whose JWT exp claim is already past — the own-CA leg has no time gate on
// its verify so a short-TTL mint suffices; the SPIRE leg time-gates the X.509-SVID
// chain, so its builder mints an SVID whose LEAF stays time-valid while the JWT exp
// is short. Both yield the SAME contract verdict (credential_stale) — the point of
// the dual run.
type conformanceSubstrate struct {
	name      string
	newShim   func(t *testing.T, clock func() time.Time) *Shim
	staleCred func(t *testing.T, shim *Shim, session, spiffe string, mintAt, shortExp, leafValid time.Time) []byte
}

// ownCASubstrate is the M1 own-minimal-CA substrate (the DEFAULT WorkloadAuthority).
func ownCASubstrate() conformanceSubstrate {
	return conformanceSubstrate{
		name: "own-CA",
		newShim: func(t *testing.T, clock func() time.Time) *Shim {
			t.Helper()
			shim, err := NewShim(WithClock(clock))
			if err != nil {
				t.Fatalf("NewShim (own-CA): %v", err)
			}
			return shim
		},
		staleCred: ownCAStaleCred,
	}
}

// spireSubstrate is the M3 SPIRE-backed substrate over the synthetic SPIRE-shaped fake
// (D50). The fake shares the shim's clock so SVID validity and Validate freshness agree.
func spireSubstrate() conformanceSubstrate {
	return conformanceSubstrate{
		name: "spire-fake",
		newShim: func(t *testing.T, clock func() time.Time) *Shim {
			t.Helper()
			src, err := NewFakeSVIDSource(clock)
			if err != nil {
				t.Fatalf("NewFakeSVIDSource: %v", err)
			}
			shim, err := NewShim(WithClock(clock), WithSpireAuthority(src))
			if err != nil {
				t.Fatalf("NewShim WithSpireAuthority: %v", err)
			}
			return shim
		},
		staleCred: spireStaleCred,
	}
}

// conformanceSubstrates is the two-substrate matrix every dual-run case ranges over.
func conformanceSubstrates() []conformanceSubstrate {
	return []conformanceSubstrate{ownCASubstrate(), spireSubstrate()}
}

// fixedConformanceInstant is the pinned fixture instant the dual-run shims run on
// (shared with the per-substrate suites so the legs line up field-for-field).
func fixedConformanceInstant() time.Time { return time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC) }

// scenario is the set-up result one case produces for one substrate: the shim under
// test, the credential to present, the session_ref + service_id it is presented under,
// the expected frozen verdict, and the shim clock AT validate time (for the ALLOW
// forward-expiry assertion).
type scenario struct {
	shim    *Shim
	cred    []byte
	session string
	service string
	want    wantVerdict
	at      time.Time
}

// wantVerdict captures the expected frozen verdict for a dual-run case, asserted
// IDENTICALLY for both substrates.
type wantVerdict struct {
	verdict  identityv1.ValidateVerdict
	reason   string // the machine-readable DENY reason (empty for ALLOW)
	grantRef string // asserted on ALLOW (empty otherwise)
}

func wantAllow(grantRef string) wantVerdict {
	return wantVerdict{verdict: identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW, grantRef: grantRef}
}

func wantDeny(reason string) wantVerdict {
	return wantVerdict{verdict: identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY, reason: reason}
}

// validateOverWire drives a single Validate through the GENERATED in-process grpc seam
// (dialInProcess, grpc_seam_test.go) and returns the frozen ValidateResponse — so the
// dual-run table asserts the FROZEN wire contract, not an internal method.
func validateOverWire(t *testing.T, shim *Shim, cred []byte, session, service string) *identityv1.ValidateResponse {
	t.Helper()
	validateClient, _ := dialInProcess(t, shim)
	resp, err := validateClient.Validate(context.Background(), &identityv1.ValidateRequest{
		PresentedCredential: cred,
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: session},
		ServiceId:           service,
	})
	if err != nil {
		// A DENY is the D77 in-band-403 payload, NEVER a transport error — a transport
		// fault here is a contract violation, not a verdict.
		t.Fatalf("Validate over wire returned a transport error, not an in-band verdict: %v", err)
	}
	return resp
}

// mintFreshOverWire mints a fresh workload identity for session over the generated grpc
// MintWorkloadIdentity seam and grants the service (when non-empty), returning the
// wire-delivered JWT and the minted §3.1 SPIFFE URI — the ALLOW-able fresh credential
// the cases start from.
func mintFreshOverWire(t *testing.T, shim *Shim, session, service, grantRef string) (jwt []byte, spiffeURI string) {
	t.Helper()
	_, mintClient := dialInProcess(t, shim)
	resp, err := mintClient.MintWorkloadIdentity(context.Background(), &identityv1.MintWorkloadIdentityRequest{
		SessionUuid: session,
		Org:         testOrg,
	})
	if err != nil {
		t.Fatalf("MintWorkloadIdentity over wire: %v", err)
	}
	if service != "" {
		if err := shim.GrantSession(session, service, grantRef); err != nil {
			t.Fatalf("GrantSession: %v", err)
		}
	}
	return []byte(resp.GetJwt()), resp.GetSpiffeUri()
}

// assertVerdict asserts a wire response matches the expected verdict, the D77
// machine-readable reason (on DENY), and the grant_ref + a forward-looking expiry (on
// ALLOW). It is the single equality gate every dual-run case runs for BOTH substrates.
func assertVerdict(t *testing.T, substrate string, resp *identityv1.ValidateResponse, want wantVerdict, shimNow time.Time) {
	t.Helper()
	if resp.GetVerdict() != want.verdict {
		t.Fatalf("[%s] verdict = %v, want %v (reason=%q)", substrate, resp.GetVerdict(), want.verdict, resp.GetMachineReadableReason())
	}
	if want.verdict == identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY {
		if resp.GetMachineReadableReason() != want.reason {
			t.Fatalf("[%s] DENY reason = %q, want %q", substrate, resp.GetMachineReadableReason(), want.reason)
		}
		return
	}
	if resp.GetGrantRef() != want.grantRef {
		t.Fatalf("[%s] ALLOW grant_ref = %q, want %q", substrate, resp.GetGrantRef(), want.grantRef)
	}
	if resp.GetExpiryUnixSeconds() <= shimNow.Unix() {
		t.Fatalf("[%s] ALLOW expiry %d not ahead of the shim clock %d", substrate, resp.GetExpiryUnixSeconds(), shimNow.Unix())
	}
}

// TestDualRunConformance is the dual-run table: every case (a)-(g) is asserted to
// produce the IDENTICAL frozen-contract verdict + reason for BOTH the own-CA and the
// SPIRE-fake substrate, driven through the generated grpc Validate seam. This is the
// doc 05 §7 edge-5 invariant as an executable property: the SPIRE substrate satisfies
// the SAME frozen D24 Validate contract the M1 own-CA substrate satisfies, with NO
// contract change.
func TestDualRunConformance(t *testing.T) {
	const (
		svc      = testSvc
		grantRef = "conformance-grant-1"
	)

	// Each case is a closure that, on a fresh shim for ONE substrate, sets up the
	// scenario and returns it. Building per substrate (rather than sharing one shim)
	// keeps the two legs independent and lets a case mint the substrate-appropriate
	// credential for the SAME contract outcome — the point of a dual run.
	cases := []struct {
		name  string
		setup func(t *testing.T, sub conformanceSubstrate) scenario
	}{
		{
			// (a) fresh minted + granted -> ALLOW with grant_ref + expiry.
			name: "a_fresh_granted_allow",
			setup: func(t *testing.T, sub conformanceSubstrate) scenario {
				shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
				jwt, _ := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
				return scenario{shim, jwt, conformanceSession, svc, wantAllow(grantRef), shim.now()}
			},
		},
		{
			// (b) unknown session -> DENY unknown_session. A valid credential presented
			// under a session_ref the shim never minted fails closed: no record, no
			// live identity.
			name: "b_unknown_session_deny",
			setup: func(t *testing.T, sub conformanceSubstrate) scenario {
				shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
				jwt, _ := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
				return scenario{shim, jwt, "00000000-0000-4000-8000-0000000000ff", svc, wantDeny(ReasonUnknownSession), shim.now()}
			},
		},
		{
			// (c) revoked -> DENY (operator reason on the D77 channel). A still-time-valid
			// credential fails closed the instant RevokeSession flips the record —
			// liveness-as-revocation (doc 16 §5.4), no CRL/OCSP, no clock advance.
			name: "c_revoked_deny",
			setup: func(t *testing.T, sub conformanceSubstrate) scenario {
				shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
				jwt, _ := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
				const reason = "admin_evicted_conformance"
				if err := shim.RevokeSession(conformanceSession, reason); err != nil {
					t.Fatalf("RevokeSession: %v", err)
				}
				return scenario{shim, jwt, conformanceSession, svc, wantDeny(reason), shim.now()}
			},
		},
		{
			// (d) torn-down still-time-valid cert -> DENY unknown_session (kill-mid-flight
			// §13). TeardownSession evicts the record so a credential still inside its
			// own nbf..exp reads as unknown_session — the active-eviction half of
			// revocation, identical across substrates.
			name: "d_torndown_unknown_session_deny",
			setup: func(t *testing.T, sub conformanceSubstrate) scenario {
				shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
				jwt, _ := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
				if err := shim.TeardownSession(conformanceSession); err != nil {
					t.Fatalf("TeardownSession: %v", err)
				}
				return scenario{shim, jwt, conformanceSession, svc, wantDeny(ReasonUnknownSession), shim.now()}
			},
		},
		{
			// (e) out-of-grant service -> DENY out_of_grant. A live, well-formed
			// credential for a service the session holds NO grant for fails closed.
			name: "e_out_of_grant_deny",
			setup: func(t *testing.T, sub conformanceSubstrate) scenario {
				shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
				jwt, _ := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
				return scenario{shim, jwt, conformanceSession, "not-granted-service", wantDeny(ReasonOutOfGrant), shim.now()}
			},
		},
		{
			// (f) cross-session credential (wrong SAN) -> DENY signature_invalid. A
			// credential validly minted for session A is presented under session B's
			// session_ref (B is itself minted + granted, so the failure is NOT
			// unknown_session). The own-CA leg verifies A's JWS against B's recorded key
			// (mismatch) and the SPIRE leg authenticates A's SVID then rejects its SAN
			// (!= B's §3.1 name, errSVIDName) — both fail closed to signature_invalid.
			name: "f_cross_session_signature_invalid_deny",
			setup: func(t *testing.T, sub conformanceSubstrate) scenario {
				shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
				const sessionA = "00000000-0000-4000-8000-00000000000a"
				const sessionB = "00000000-0000-4000-8000-00000000000b"
				jwtA, _ := mintFreshOverWire(t, shim, sessionA, svc, "grant-a")
				// Session B exists, is minted + granted: the presentation reaches the
				// signature/identity check, not the unknown-session liveness gate.
				mintFreshOverWire(t, shim, sessionB, svc, "grant-b")
				return scenario{shim, jwtA, sessionB, svc, wantDeny(ReasonSignatureInvalid), shim.now()}
			},
		},
		{
			// (g) stale (outside nbf..exp) -> DENY credential_stale. The credential is
			// signature/chain-valid at the advanced validate time but its JWT exp claim
			// is already past, while the session record is kept LIVE (a long-TTL session
			// token extends rec.expiry past the short credential exp). So the liveness
			// gate passes and the freshness gate fails — credential_stale, not
			// session_expired. The substrate-appropriate stale builder produces the
			// right credential for each leg; both yield the SAME verdict.
			name: "g_stale_credential_stale_deny",
			setup: func(t *testing.T, sub conformanceSubstrate) scenario {
				clk := &m1Clock{t: fixedConformanceInstant()}
				shim := sub.newShim(t, clk.now)
				mintAt := clk.t
				shortExp := mintAt.Add(time.Hour)        // the credential's own exp
				leafValid := mintAt.Add(24 * time.Hour)  // the SPIRE leaf stays valid past it
				sessionExp := mintAt.Add(12 * time.Hour) // the session record outlives the credential

				// Set up the live session record + grant + identity for the substrate.
				_, spiffe := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)

				// Build the substrate-appropriate stale credential. NOTE the own-CA
				// builder re-mints with the short TTL, which RESETS rec.expiry to the
				// short horizon — so the liveness extension below MUST run AFTER it.
				cred := sub.staleCred(t, shim, conformanceSession, spiffe, mintAt, shortExp, leafValid)

				// Keep the session live well past the short credential exp by minting a
				// long-TTL base session token (it only ever EXTENDS rec.expiry to the
				// later horizon, never shortens — sessiontoken.go) — so at validate time
				// the liveness gate passes and the failure is the FRESHNESS gate
				// (credential_stale), not session_expired. Run AFTER staleCred so the
				// own-CA re-mint's shorter expiry is the one being extended.
				if _, err := shim.MintSessionToken(MintSessionTokenReq{
					SessionUUID: conformanceSession,
					Org:         testOrg,
					TTL:         sessionExp.Sub(mintAt),
				}); err != nil {
					t.Fatalf("MintSessionToken (extend session liveness): %v", err)
				}

				// Advance to AFTER the credential exp but BEFORE both the SPIRE leaf
				// validity horizon and the session expiry.
				clk.t = mintAt.Add(2 * time.Hour)
				return scenario{shim, cred, conformanceSession, svc, wantDeny(ReasonCredentialStale), clk.t}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, sub := range conformanceSubstrates() {
				sub := sub
				t.Run(sub.name, func(t *testing.T) {
					sc := tc.setup(t, sub)
					resp := validateOverWire(t, sc.shim, sc.cred, sc.session, sc.service)
					assertVerdict(t, sub.name, resp, sc.want, sc.at)
				})
			}
		})
	}
}

// TestDualRunSpiffeNameByteIdentical is the PURE-SWAP property as an executable
// assertion: minting the IDENTICAL workload-identity request on each substrate (over
// the generated grpc seam) yields a §3.1 SPIFFE name spiffe://<org>/session/<uuid>
// that is BYTE-IDENTICAL across both — the correspondence the swap relies on (same
// Build helper upstream of either authority, spiffeid.go). It is the single property
// that makes the substrate swap PURE rather than a re-naming.
func TestDualRunSpiffeNameByteIdentical(t *testing.T) {
	wantURI := "spiffe://" + testOrg + "/session/" + conformanceSession

	var names []string
	for _, sub := range conformanceSubstrates() {
		shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
		_, spiffe := mintFreshOverWire(t, shim, conformanceSession, "", "")
		if spiffe != wantURI {
			t.Fatalf("[%s] minted spiffe uri = %q, want %q", sub.name, spiffe, wantURI)
		}
		names = append(names, spiffe)
	}
	for i := 1; i < len(names); i++ {
		if names[i] != names[0] {
			t.Fatalf("SPIFFE name not byte-identical across substrates: %q (%s) != %q (%s)",
				names[i], conformanceSubstrates()[i].name, names[0], conformanceSubstrates()[0].name)
		}
	}
}

// ownCAStaleCred builds the case-(g) stale credential for the own-CA substrate: the
// fresh workload JWT minted with a SHORT TTL. The own-CA verify leg has NO time gate
// (it verifies the JWS against the session's recorded key, ignoring the clock —
// mint.go VerifyPresented), so at the advanced validate time the signature still
// verifies and Validate's freshness gate trips on the past exp claim. A re-mint with
// the short TTL refreshes the recorded key so THIS credential is the one on record.
func ownCAStaleCred(t *testing.T, shim *Shim, session, _ string, _, shortExp, _ time.Time) []byte {
	t.Helper()
	// Re-mint with the short TTL so the credential's own exp = shortExp while the
	// recorded workload key matches it. mintFreshOverWire above already minted at the
	// default TTL; this re-mint (same session) rotates the recorded key to this short
	// credential, so the own-CA verify leg accepts exactly this token.
	_, mintClient := dialInProcess(t, shim)
	resp, err := mintClient.MintWorkloadIdentity(context.Background(), &identityv1.MintWorkloadIdentityRequest{
		SessionUuid: session,
		Org:         testOrg,
		TtlSeconds:  int64(shortExp.Sub(shim.now()) / time.Second),
	})
	if err != nil {
		t.Fatalf("own-CA short-TTL re-mint: %v", err)
	}
	return []byte(resp.GetJwt())
}

// spireStaleCred builds the case-(g) stale credential for the SPIRE substrate directly
// through the shim's SVIDSource fake: an X.509-SVID whose LEAF stays time-valid until
// leafValid (so the SPIRE chain verify passes at the advanced validate time) but whose
// parallel JWS carries a SHORT exp claim (shortExp). At validate time (after shortExp,
// before leafValid) the SVID authenticates + the SAN matches, so the SPIRE verify leg
// returns the claims and Validate's freshness gate trips on the past exp claim —
// credential_stale, the SAME verdict the own-CA leg reaches. The SAN is the session's
// real §3.1 name so the identity binding passes; only the exp is stale.
func spireStaleCred(t *testing.T, shim *Shim, _, spiffe string, mintAt, shortExp, leafValid time.Time) []byte {
	t.Helper()
	src := spireSourceOf(t, shim)
	svid, err := src.FetchX509SVID(X509SVIDRequest{
		SpiffeID: spiffe,
		Claims: jwtClaims{
			Subject:     spiffe,
			Issuer:      issuerName,
			SessionUUID: conformanceSession,
			NotBefore:   toUnix(mintAt.Add(-time.Minute)),
			Expiry:      toUnix(shortExp), // SHORT: the credential is stale at validate time
		},
		NotBefore: mintAt.Add(-time.Minute),
		NotAfter:  leafValid, // LONG: the X.509-SVID leaf stays time-valid past the JWS exp
	})
	if err != nil {
		t.Fatalf("spire stale SVID mint: %v", err)
	}
	return []byte(svid.JWT)
}

// spireSourceOf reaches the SPIRE authority's SVIDSource fake on a shim built
// WithSpireAuthority — the same in-package reflection the per-substrate SPIRE suite
// uses (spire_authority_test.go) so a case can mint a substrate-shaped credential.
func spireSourceOf(t *testing.T, shim *Shim) *fakeSVIDSource {
	t.Helper()
	a, ok := shim.workloadAuthority.(*spireWorkloadAuthority)
	if !ok {
		t.Fatalf("workloadAuthority is %T, want *spireWorkloadAuthority", shim.workloadAuthority)
	}
	src, ok := a.source.(*fakeSVIDSource)
	if !ok {
		t.Fatalf("SVIDSource is %T, want *fakeSVIDSource", a.source)
	}
	return src
}

// deepSpireSubstrate is the M3 SPIRE-backed substrate over the DEEPER (2-level) synthetic
// fake — root -> int1 -> int2 -> leaf, two interposed CAs (D50). It satisfies the SAME
// frozen D24 Validate contract the flat / single-intermediate SPIRE fakes satisfy, so the
// chain DEPTH is a substrate-internal detail behind the frozen seam, never observable in the
// verdict. The deeper fake time-gates its X.509-SVID chain, so its staleCred mints an SVID
// whose deepest cert stays time-valid while the JWS exp is short — the same shape spireStaleCred
// uses, just over the 2-level chain.
func deepSpireSubstrate() conformanceSubstrate {
	return conformanceSubstrate{
		name: "spire-deep-fake",
		newShim: func(t *testing.T, clock func() time.Time) *Shim {
			t.Helper()
			src, err := NewDeepHierarchicalFakeSVIDSource(clock)
			if err != nil {
				t.Fatalf("NewDeepHierarchicalFakeSVIDSource: %v", err)
			}
			shim, err := NewShim(WithClock(clock), WithSpireAuthority(src))
			if err != nil {
				t.Fatalf("NewShim WithSpireAuthority (deep): %v", err)
			}
			return shim
		},
		staleCred: spireStaleCred,
	}
}

// TestDeepHierarchicalConformance proves the DEEPER (2-level) SPIRE substrate satisfies the
// SAME frozen D24 Validate contract the flat / single-intermediate substrates satisfy,
// FIELD-FOR-FIELD — the chain depth is a substrate-internal detail behind the frozen seam.
// It runs the representative ALLOW / DENY rows from the dual-run table (a fresh granted
// credential, an unknown session, a revoked session, an out-of-grant service, and a stale
// credential) over the deep-hierarchical substrate, demanding the IDENTICAL verdict + D77
// reason the flat substrate produces, and asserts the minted §3.1 SPIFFE name is
// BYTE-IDENTICAL to the flat substrate (the pure-swap property at depth 2). It is purely
// additive — it WEAKENS no existing dual-run row; it extends the same property to a deeper
// chain. Driven through the GENERATED grpc Validate seam (the frozen wire contract).
func TestDeepHierarchicalConformance(t *testing.T) {
	const (
		svc      = testSvc
		grantRef = "deep-conformance-grant-1"
	)
	sub := deepSpireSubstrate()

	t.Run("fresh_granted_allow", func(t *testing.T) {
		shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
		jwt, spiffe := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
		// The §3.1 SPIFFE name is byte-identical to the flat substrate — the pure-swap
		// property holds regardless of chain depth (same Build helper upstream).
		if want := "spiffe://" + testOrg + "/session/" + conformanceSession; spiffe != want {
			t.Fatalf("deep substrate spiffe uri = %q, want %q (swap not pure at depth 2)", spiffe, want)
		}
		resp := validateOverWire(t, shim, jwt, conformanceSession, svc)
		assertVerdict(t, sub.name, resp, wantAllow(grantRef), shim.now())
	})

	t.Run("unknown_session_deny", func(t *testing.T) {
		shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
		jwt, _ := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
		resp := validateOverWire(t, shim, jwt, "00000000-0000-4000-8000-0000000000ff", svc)
		assertVerdict(t, sub.name, resp, wantDeny(ReasonUnknownSession), shim.now())
	})

	t.Run("revoked_deny", func(t *testing.T) {
		shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
		jwt, _ := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
		const reason = "admin_evicted_deep_conformance"
		if err := shim.RevokeSession(conformanceSession, reason); err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
		resp := validateOverWire(t, shim, jwt, conformanceSession, svc)
		assertVerdict(t, sub.name, resp, wantDeny(reason), shim.now())
	})

	t.Run("out_of_grant_deny", func(t *testing.T) {
		shim := sub.newShim(t, func() time.Time { return fixedConformanceInstant() })
		jwt, _ := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
		resp := validateOverWire(t, shim, jwt, conformanceSession, "not-granted-service")
		assertVerdict(t, sub.name, resp, wantDeny(ReasonOutOfGrant), shim.now())
	})

	t.Run("stale_credential_stale_deny", func(t *testing.T) {
		clk := &m1Clock{t: fixedConformanceInstant()}
		shim := sub.newShim(t, clk.now)
		mintAt := clk.t
		shortExp := mintAt.Add(time.Hour)
		leafValid := mintAt.Add(24 * time.Hour)
		sessionExp := mintAt.Add(12 * time.Hour)

		_, spiffe := mintFreshOverWire(t, shim, conformanceSession, svc, grantRef)
		cred := sub.staleCred(t, shim, conformanceSession, spiffe, mintAt, shortExp, leafValid)
		if _, err := shim.MintSessionToken(MintSessionTokenReq{
			SessionUUID: conformanceSession,
			Org:         testOrg,
			TTL:         sessionExp.Sub(mintAt),
		}); err != nil {
			t.Fatalf("MintSessionToken (extend session liveness): %v", err)
		}
		clk.t = mintAt.Add(2 * time.Hour)
		resp := validateOverWire(t, shim, cred, conformanceSession, svc)
		assertVerdict(t, sub.name, resp, wantDeny(ReasonCredentialStale), clk.t)
	})
}

// TestCrossSubstrateCredentialRejection pins the "no stray credential crosses a
// mixed-substrate fleet" property the dual-run table (TestDualRunConformance) does NOT
// assert: it runs every case on ONE substrate, but a real fleet runs BOTH the own-CA
// and the SPIRE substrate, and a credential minted for one MUST fail closed on the
// other. Each leg owns a DIFFERENT authenticity root (the own-CA leg verifies against
// the per-session recorded key; the SPIRE leg requires an x5c-carried X.509-SVID
// chaining to the trust bundle), so a foreign-substrate credential is rejected with the
// substrate-appropriate D77 reason — never quietly accepted:
//
//   - own-CA JWS (NO x5c header) presented to the SPIRE leg -> DENY malformed_credential
//     (the SPIRE leg requires the x5c-carried SVID; without it there is no SVID to chain
//     — errMalformedJWT, spire_authority.go ~221-223).
//   - SVID-bearing JWS (x5c present) presented to the own-CA leg -> DENY
//     signature_invalid (the own-CA leg IGNORES x5c and verifies against the per-session
//     recorded own-CA key, so the foreign SVID leaf key fails the ECDSA verify —
//     errJWTSignature, mint.go VerifyPresented).
//
// Both presentations target a LIVE, GRANTED session on the receiving substrate (the
// session minted its own native credential first), so the rejection is the credential's
// FOREIGN-SUBSTRATE shape/signature, not an unknown-session or out-of-grant liveness
// gate. Driven through the generated grpc Validate seam (the frozen wire contract).
func TestCrossSubstrateCredentialRejection(t *testing.T) {
	clock := func() time.Time { return fixedConformanceInstant() }

	// (A) own-CA JWS presented to the SPIRE leg -> malformed (no x5c to chain). The SPIRE
	// shim's session is live+granted with its OWN native SVID, so the own-CA JWS reaches
	// the SPIRE signature/shape gate rather than tripping the unknown-session gate.
	t.Run("own_ca_jws_to_spire_leg_malformed", func(t *testing.T) {
		spireShim := spireSubstrate().newShim(t, clock)
		ownCAShim := ownCASubstrate().newShim(t, clock)

		// Make the session LIVE + GRANTED on the SPIRE shim (native SVID minted + grant).
		mintFreshOverWire(t, spireShim, conformanceSession, testSvc, "g-spire")
		// The foreign credential: an own-CA-minted JWS for the SAME §3.1 name (no x5c).
		ownCAJWS, _ := mintFreshOverWire(t, ownCAShim, conformanceSession, "", "")
		if x5cPresent(t, string(ownCAJWS)) {
			t.Fatal("own-CA JWS unexpectedly carries an x5c header; the cross-substrate premise is wrong")
		}

		resp := validateOverWire(t, spireShim, ownCAJWS, conformanceSession, testSvc)
		assertVerdict(t, "own-CA->SPIRE", resp, wantDeny(ReasonMalformed), spireShim.now())
	})

	// (B) SVID-bearing JWS (x5c present) presented to the own-CA leg -> signature_invalid
	// (the own-CA leg verifies against the recorded own-CA key; the foreign SVID leaf key
	// fails). The own-CA shim's session is live+granted with its OWN native credential so
	// the SVID reaches the signature gate (a recorded key exists to verify against).
	t.Run("svid_jws_to_own_ca_leg_signature_invalid", func(t *testing.T) {
		ownCAShim := ownCASubstrate().newShim(t, clock)
		spireShim := spireSubstrate().newShim(t, clock)

		// Make the session LIVE + GRANTED on the own-CA shim (records the own-CA key).
		mintFreshOverWire(t, ownCAShim, conformanceSession, testSvc, "g-ownca")
		// The foreign credential: a SPIRE SVID JWS for the SAME §3.1 name (x5c present).
		svidJWS, _ := mintFreshOverWire(t, spireShim, conformanceSession, "", "")
		if !x5cPresent(t, string(svidJWS)) {
			t.Fatal("SPIRE SVID JWS unexpectedly lacks an x5c header; the cross-substrate premise is wrong")
		}

		resp := validateOverWire(t, ownCAShim, svidJWS, conformanceSession, testSvc)
		assertVerdict(t, "SPIRE->own-CA", resp, wantDeny(ReasonSignatureInvalid), ownCAShim.now())
	})
}

// x5cPresent reports whether a compact JWS carries a non-empty x5c chain in its
// protected header — the structural marker that distinguishes a SPIRE SVID JWS (x5c
// present) from an own-CA JWS (no x5c). It is the cross-substrate premise check: the
// rejection only proves the property if the credentials are genuinely shaped the way
// each substrate emits them.
func x5cPresent(t *testing.T, jws string) bool {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("jws has %d segments, want 3", len(parts))
	}
	raw, err := b64url.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jws header: %v", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("unmarshal jws header: %v", err)
	}
	return len(hdr.X5c) > 0
}
