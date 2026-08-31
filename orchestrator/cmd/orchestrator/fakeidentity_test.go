// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// TestFakeMintWireReturnsWellFormedCA proves the MVP no-auth mint returns a non-nil response
// carrying a PARSEABLE self-signed CA cert (so the create spine's step-5 mint succeeds and the
// host-folded step-7 inject has a well-formed trust anchor), and that the CA is stable across
// calls (generated once). It never panics and never returns a nil response on the happy path.
func TestFakeMintWireReturnsWellFormedCA(t *testing.T) {
	w := &fakeMintWire{}
	resp, err := w.MintInterceptionCA(context.Background(), &identityv1.MintInterceptionCARequest{})
	if err != nil {
		t.Fatalf("MintInterceptionCA: %v", err)
	}
	if resp == nil || len(resp.GetCaCertificate()) == 0 {
		t.Fatal("MintInterceptionCA returned no CA certificate")
	}
	block, _ := pem.Decode(resp.GetCaCertificate())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("CA certificate is not a PEM CERTIFICATE block: %v", block)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("CA certificate does not parse: %v", err)
	}
	if !cert.IsCA {
		t.Error("minted certificate is not marked IsCA")
	}
	// The private key is returned (it never leaves the box in the MVP — no ds-tlsproxy).
	if len(resp.GetCaPrivateKey()) == 0 {
		t.Error("MintInterceptionCA returned no CA private key")
	}
	if resp.GetExpiryUnixSeconds() == 0 {
		t.Error("MintInterceptionCA returned a zero expiry; want a session-lifetime expiry")
	}

	// Stable across calls (generated once via sync.Once).
	resp2, err := w.MintInterceptionCA(context.Background(), &identityv1.MintInterceptionCARequest{})
	if err != nil {
		t.Fatalf("second MintInterceptionCA: %v", err)
	}
	if string(resp2.GetCaCertificate()) != string(resp.GetCaCertificate()) {
		t.Error("CA certificate changed between calls; want a stable startup-generated CA")
	}
}

// TestFakeDigestWireAccepts proves the no-op digest publish + revoke return non-nil responses
// (the create spine's step-6 only needs a non-error ack) and honor a cancelled context.
func TestFakeDigestWireAccepts(t *testing.T) {
	var w fakeDigestWire
	if resp, err := w.DigestPublish(context.Background(), &identityv1.DigestPublishRequest{}); err != nil || resp == nil {
		t.Fatalf("DigestPublish = %v, %v; want a non-nil ack", resp, err)
	}
	if resp, err := w.DigestRevoke(context.Background(), &identityv1.DigestRevokeRequest{}); err != nil || resp == nil {
		t.Fatalf("DigestRevoke = %v, %v; want a non-nil ack", resp, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.DigestPublish(ctx, &identityv1.DigestPublishRequest{}); err == nil {
		t.Error("DigestPublish with a cancelled context should error")
	}
}

// TestNewFakeIdentityClientsWiresAllSeams proves the loopback bundle exposes every §4.1
// step-5/6 seam NewControlPlane requires (Mint/Digest/Inject/Boot/Revoke non-nil) so a
// DS_ORCH_FAKE_IDENTITY run does not half-wire the control plane, and that Close is a clean
// no-op (no dialed connection).
func TestNewFakeIdentityClientsWiresAllSeams(t *testing.T) {
	c := newFakeIdentityClients(nil)
	if c == nil {
		t.Fatal("newFakeIdentityClients returned nil")
	}
	if c.Mint == nil || c.Digest == nil || c.Inject == nil || c.Boot == nil || c.Revoke == nil {
		t.Errorf("loopback identity left a seam nil: mint=%v digest=%v inject=%v boot=%v revoke=%v",
			c.Mint == nil, c.Digest == nil, c.Inject == nil, c.Boot == nil, c.Revoke == nil)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close on a dial-free loopback bundle = %v, want nil", err)
	}
}
