// SPDX-License-Identifier: Apache-2.0

package identitymint

import (
	"bytes"
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
)

// Synthetic fixtures (D50). Every identifier is obviously-synthetic — no real
// session ids, certs, or keys. Each scenario drives its own dedicated session
// uuid so scenarios stay independent across the shared in-process connection.
const (
	synthSessionMint      = "ses-synthetic-mint-aaaa0000"
	synthSessionSeparate  = "ses-synthetic-mint-bbbb1111"
	synthSessionDriftCase = "ses-synthetic-mint-cccc2222"
)

// Suite is the identity-mint seam's single conformance suite (doc 06 §3a: one
// suite, run against real + fake). Every scenario is stated purely in terms of
// the frozen identity.v1 MintInterceptionCA contract (doc 16 §4) so the same
// suite is meaningful against any faithful implementation. It drives the ONLY
// verb the proto exposes — MintInterceptionCA — and asserts the properties the
// contract turns on (doc 16 §4 / D82): IDEMPOTENCY on the request key (the
// session_ref/session_uuid), the interception-vs-workload root SEPARATION where
// observable on this seam (the minted CA carries the interception-root
// identifier, never a workload-root one), and the honest error path (a mint
// missing the session_ref join key is refused InvalidArgument).
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "orchestrator/ds-tlsproxy<->identity(MintInterceptionCA)",
		Scenarios: scenarios(),
	}
}

func scenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "mint-interception-ca/idempotent-on-session-key",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityMintServiceClient(conn)
				req := &identityv1.MintInterceptionCARequest{SessionRef: SessionRef(synthSessionMint)}
				first, err := cl.MintInterceptionCA(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				// Re-issue the SAME per-session mint: idempotent on the session key
				// (doc 16 §4 — per-session CA is the D72-exempt session-lifecycle
				// class, allocated once and reused, never a freshly-minted second CA).
				second, err := cl.MintInterceptionCA(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("idempotent_material", "%t", caEqual(first, second))
				return recordMintObservation(obs, second), nil
			},
		},
		{
			Name: "mint-interception-ca/interception-rooted-not-workload-rooted",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityMintServiceClient(conn)
				// D82 separation, asserted WHERE OBSERVABLE on this seam: the minted CA
				// carries the interception-root identifier (hierarchy 2) and NEVER the
				// workload-identity-root one (hierarchy 1) — so the egress-gateway
				// TLS-termination capability and the workload-identity attribution
				// capability fail independently (doc 16 §4 / D82). There is no
				// workload-mint verb on this service to test the separation directly;
				// it is asserted only on the observable face of THIS verb's output.
				resp, err := cl.MintInterceptionCA(ctx, &identityv1.MintInterceptionCARequest{
					SessionRef: SessionRef(synthSessionSeparate),
				})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("cert_interception_rooted", "%t", carriesRoot(resp.GetCaCertificate(), InterceptionRootID()))
				obs.Setf("key_interception_rooted", "%t", carriesRoot(resp.GetCaPrivateKey(), InterceptionRootID()))
				// The separation invariant: workload-root material NEVER appears.
				obs.Setf("cert_carries_workload_root", "%t", carriesRoot(resp.GetCaCertificate(), WorkloadRootID()))
				obs.Setf("key_carries_workload_root", "%t", carriesRoot(resp.GetCaPrivateKey(), WorkloadRootID()))
				return obs, nil
			},
		},
		{
			Name: "mint-interception-ca/missing-session-ref-refused",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityMintServiceClient(conn)
				// Honest error path: a mint with no session_ref join key is refused
				// before any CA material is allocated (doc 16 §4 fail-closed posture).
				_, err := cl.MintInterceptionCA(ctx, &identityv1.MintInterceptionCARequest{})
				obs := dualrun.NewObservation()
				obs.Set("status", status.Code(err).String())
				return obs, nil
			},
		},
		{
			Name: "mint-interception-ca/empty-session-uuid-refused",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityMintServiceClient(conn)
				// A present-but-empty SessionRef carries no join key either — same
				// fail-closed InvalidArgument refusal, no CA materialized.
				_, err := cl.MintInterceptionCA(ctx, &identityv1.MintInterceptionCARequest{
					SessionRef: SessionRef(""),
				})
				obs := dualrun.NewObservation()
				obs.Set("status", status.Code(err).String())
				return obs, nil
			},
		},
	}
}

// --- Observation builders ----------------------------------------------------

func errObservation(err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", status.Code(err).String())
	return obs
}

// recordMintObservation records the contract-observable SHAPE of a minted
// interception-CA response: the PRESENCE of cert/key material, that both are
// interception-rooted and carry NO workload-root material (the D82 separation),
// and that an expiry is stamped (lifetime = session, doc 16 §4). The raw cert/key
// bytes and the absolute expiry are intentionally NOT recorded as values — they
// are allocation/derivation detail; the idempotency fact (a re-issue returns the
// SAME material) is asserted separately via idempotent_material.
func recordMintObservation(obs *dualrun.Observation, resp *identityv1.MintInterceptionCAResponse) *dualrun.Observation {
	obs.Setf("has_ca_cert", "%t", len(resp.GetCaCertificate()) != 0)
	obs.Setf("has_ca_key", "%t", len(resp.GetCaPrivateKey()) != 0)
	obs.Setf("cert_interception_rooted", "%t", carriesRoot(resp.GetCaCertificate(), InterceptionRootID()))
	obs.Setf("cert_carries_workload_root", "%t", carriesRoot(resp.GetCaCertificate(), WorkloadRootID()))
	obs.Setf("has_expiry", "%t", resp.GetExpiryUnixSeconds() != 0)
	return obs
}

// caEqual reports whether two minted interception-CA responses are the SAME
// per-session material — the idempotency anchor (a re-issue returns the SAME CA,
// not a freshly-allocated one): identical cert, key, and expiry.
func caEqual(a, b *identityv1.MintInterceptionCAResponse) bool {
	return bytes.Equal(a.GetCaCertificate(), b.GetCaCertificate()) &&
		bytes.Equal(a.GetCaPrivateKey(), b.GetCaPrivateKey()) &&
		a.GetExpiryUnixSeconds() == b.GetExpiryUnixSeconds()
}

// carriesRoot reports whether the synthetic CA material is tagged with the given
// root identifier. The reference impl embeds the interception-root id (and never
// the workload-root id) in the synthetic cert/key bytes, so the suite can read
// the root back off the minted material to assert the D82 separation where it is
// observable on this seam. Synthetic fixtures only (D50).
func carriesRoot(material []byte, rootID string) bool {
	return bytes.Contains(material, []byte("root="+rootID))
}

// --- dialers: real reference impl AND the generated fake --------------------
//
// Both ends of the seam need a matched pair of dialers (one for the real impl,
// one for the fake), so the only thing that varies across the two dual-run
// passes is which server is registered.

// RealDialer returns the dual-run Dialer for the reference impl.
func RealDialer() dualrun.Dialer {
	return dualrun.InProcess(NewRefImpl().Register)
}

// FakeDialer returns the dual-run Dialer for the GENERATED programmable fake,
// programmed to the same contract Suite() asserts. The fake is driven only
// through its canned-response surface; the dual-run proves it is observationally
// identical to the real impl on every scenario.
func FakeDialer() dualrun.Dialer {
	f := programmedFake()
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		identityv1fake.RegisterIdentityMintService(s, f)
	})
}

// programmedFake programs the generated fake to the honest contract by routing
// its MintInterceptionCA responder at a mirror RefImpl — so the fake and the
// real impl share one honest behavior definition (idempotency on the session
// key, interception-rooting, the InvalidArgument refusal). This is the
// programmable-fake-driven-only-through-its-surface pattern (doc 06 §2.1): the
// dual-run still proves the fake observationally matches the production impl when
// it lands, because the suite never touches the mirror directly.
func programmedFake() *identityv1fake.IdentityMintServiceFake {
	f := identityv1fake.NewIdentityMintServiceFake()
	mirror := NewRefImpl()
	f.MintInterceptionCAResponder = mirror.MintInterceptionCA
	return f
}
