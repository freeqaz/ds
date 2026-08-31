// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// fakeidentity.go is the MVP NO-AUTH identity backend (maintainer-approved, contained to a single
// box): an IN-PROCESS loopback that satisfies the §4.1 step-5/6 identity seams
// (Mint / Digest / Revoke + the host-folded Inject / Boot) WITHOUT a real identity.v1
// service. It exists ONLY so the `serpent claude` -> orchestrator -> KVM-VM MVP can complete
// CreateSession on a box where the credential-swap egress gateway + real Identity are
// out-of-scope later phases (the VM runs SLIRP-direct egress with the OAuth token injected,
// so the per-session interception CA the mint produces is never load-bearing here).
//
// It is fenced behind DS_ORCH_FAKE_IDENTITY=1 (and only reachable under DS_ORCH_LIVE=1, D50):
// with the gate UNSET the orchestrator keeps its production posture EXACTLY — it dials a real
// Identity endpoint via controlplane.NewIdentityClients and refuses to start with an empty
// DS_ORCH_IDENTITY_ENDPOINT. Nothing about the gate-off path changes. The mint returns a
// freshly self-signed throwaway CA so the host-folded step-7 CA injection has a well-formed
// trust anchor to inject (the host-readable CA-bundle producer drops it under the host's
// overlay dir, the SAME path the co-located host-agent's step-7 consumer reads); the digest
// publish/revoke are accepted no-ops. NO real credential ever exists.

// fakeMintWire is the in-process MintInterceptionCA backend: it returns a freshly minted,
// self-signed throwaway CA (PEM cert + EC private key) so the create spine's step-5 mint
// succeeds and the host-folded step-7 inject has a well-formed (if non-production) trust
// anchor. The CA is generated ONCE at startup and reused for every session (the MVP runs a
// single box; the per-session interception CA is not load-bearing under SLIRP-direct egress).
type fakeMintWire struct {
	once    sync.Once
	certPEM []byte
	keyPEM  []byte
	genErr  error
}

func (f *fakeMintWire) ensureCA() error {
	f.once.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			f.genErr = fmt.Errorf("fake identity: generate CA key: %w", err)
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "ds-mvp-fake-interception-ca"},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			f.genErr = fmt.Errorf("fake identity: self-sign CA: %w", err)
			return
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			f.genErr = fmt.Errorf("fake identity: marshal CA key: %w", err)
			return
		}
		f.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		f.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	})
	return f.genErr
}

// MintInterceptionCA returns the throwaway CA. The orchestrator derives the caRef/identityRef
// from the session UUID itself (liveMint.mint), so this only needs to return a non-nil
// response carrying a well-formed CA cert (and an expiry the routable bookkeeping can read).
func (f *fakeMintWire) MintInterceptionCA(ctx context.Context, _ *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.ensureCA(); err != nil {
		return nil, err
	}
	return &identityv1.MintInterceptionCAResponse{
		CaCertificate:     f.certPEM,
		CaPrivateKey:      f.keyPEM, // never leaves this box; the MVP has no ds-tlsproxy to deliver it to
		ExpiryUnixSeconds: time.Now().Add(24 * time.Hour).Unix(),
	}, nil
}

// fakeDigestWire accepts the §4.1 step-6 digest publish + the teardown revoke as no-ops
// (the MVP has no digest feed consumer; the create spine only needs a non-error ack).
type fakeDigestWire struct{}

func (fakeDigestWire) DigestPublish(ctx context.Context, req *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Committed=TRUE is the MVP no-auth ack: the §4.1 step-6 DigestWriter maps
	// resp.GetCommitted() onto the create's DigestAcked, and the step-9 routable gate
	// (D73) refuses routable on a false ack ("session digests not acked — not routable
	// until the host acks"). The MVP has no digest-feed consumer to genuinely commit
	// against (the host-side POL-4/digest-ack two-phase commit is a later-phase boundary
	// leg), so this loopback ack lets a fresh `serpent claude` -> orchestrator -> KVM-VM run
	// reach READY/routable. BatchId echoes the request's batch_id (the caRef the writer
	// passed) so the digest ref the record carries forward is the stable session key.
	return &identityv1.DigestPublishResponse{
		Committed: true,
		BatchId:   req.GetBatchId(),
	}, nil
}

func (fakeDigestWire) DigestRevoke(ctx context.Context, _ *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &identityv1.DigestRevokeResponse{}, nil
}

// newFakeIdentityClients builds the in-process loopback IdentityClients (the same seam shape
// controlplane.NewIdentityClients produces over a real dial) from the no-op wires above, via
// the exported, dial-free controlplane.NewIdentityClientsFromWire. The returned bundle's Close
// is a clean no-op (no dialed connection). It is reached ONLY under DS_ORCH_FAKE_IDENTITY=1.
func newFakeIdentityClients(logger *slog.Logger) *controlplane.IdentityClients {
	return controlplane.NewIdentityClientsFromWire(&fakeMintWire{}, fakeDigestWire{}, logger)
}
