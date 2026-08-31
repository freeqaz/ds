// SPDX-License-Identifier: Apache-2.0

// Package testpki is the ONE shared synthetic-PKI factory the orchestrator's
// test suites mint throwaway mTLS material from (D50: real PEM/x509 material
// generated in-process — no checked-in keys, no live CA, no socket bind). It
// is a test-helper package (it takes *testing.T and t.Fatal's on any crypto
// failure), imported by the cmd/orchestrator mTLS env tests so they mint
// certificates through a single parameterized factory instead of re-spelling
// ECDSA keygen + x509 templating + CreateCertificate.
//
// Two entry shapes compose the same primitive:
//
//   - Cert(t, spec, parent) mints a Leaf (parsed cert + DER + ECDSA key) from a
//     Spec (Role-driven KeyUsage/ExtKeyUsage/IsCA, optional SAN, validity
//     window); parent==nil self-signs (a CA root), parent!=nil signs the leaf.
//     WriteLeafPEM / WritePEM / TLSCert render a minted Leaf to the PEM files
//     the DS_ORCH_TLS_* env points at, or to a gRPC transport keypair. This is
//     the shape the cmd/orchestrator mTLS env tests consume today.
//   - NewCA(t, cn, serial) returns a CA (a self-signed root + a one-cert Pool)
//     and CA.SignedLeaf(t, cn, serial, usage) signs a SAN-bearing leaf as a
//     gRPC tls.Certificate — the controlplane bilateral-CA-pinning shape. This
//     primitive mirrors controlplane/mtls_helpers_test.go's local
//     syntheticCA/newSyntheticCA/signedLeaf; routing that package's
//     dialregistry negotiation arms through it (retiring the in-package copy)
//     is the remaining acceptance leg, deferred to a follow-up that owns
//     mtls_helpers_test.go (see task notes).
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// Role names the leaf shape Cert mints: a self-signed CA, a clientauth leaf, or
// a serverauth leaf. It selects the KeyUsage/ExtKeyUsage/IsCA posture so a
// caller declares intent ("a server leaf") instead of re-spelling the x509
// usage bits each time.
type Role int

const (
	// RoleCA mints a self-signed CA (KeyUsageCertSign + IsCA): a signing parent.
	RoleCA Role = iota
	// RoleClient mints a ClientAuth leaf (the orchestrator's dial identity).
	RoleClient
	// RoleServer mints a ServerAuth leaf (a bufconn gRPC server's identity).
	RoleServer
)

// Spec parameterizes the ONE synthetic-cert factory (Cert): the leaf role, its
// serial, CN, optional SAN, and validity window. A zero NotBefore/NotAfter
// defaults to a window valid for the duration of the test (now ±1h) — the
// overwhelmingly common case; the temporal-arm callers pass an explicit
// (possibly past/future) window to drive the NotBefore/NotAfter checks.
type Spec struct {
	Role       Role
	Serial     int64
	CommonName string
	DNSName    string // empty => no SAN (CA + the file-only client/cert arms)
	NotBefore  time.Time
	NotAfter   time.Time
}

// Leaf is the minted material: the parsed certificate (for use as a signing
// parent or a CA pool entry), its DER (for PEM emit + tls.Certificate chains),
// and the ECDSA private key.
type Leaf struct {
	Cert *x509.Certificate
	DER  []byte
	Key  *ecdsa.PrivateKey
}

// Cert is the single parameterized synthetic-cert factory: it generates a
// throwaway P-256 ECDSA keypair, builds the x509 template from spec (role-driven
// KeyUsage/ExtKeyUsage/IsCA, optional SAN, validity window), and creates the
// certificate signed by parent — or self-signed when parent is nil (a CA root).
// It is the D50 synthetic source: real PEM/x509 material generated in-process,
// no checked-in keys, no live CA.
func Cert(t *testing.T, spec Spec, parent *Leaf) Leaf {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic %q key: %v", spec.CommonName, err)
	}

	notBefore, notAfter := spec.NotBefore, spec.NotAfter
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(time.Hour)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(spec.Serial),
		Subject:      pkix.Name{CommonName: spec.CommonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if spec.DNSName != "" {
		tmpl.DNSNames = []string{spec.DNSName}
	}
	switch spec.Role {
	case RoleCA:
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
	case RoleClient:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case RoleServer:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	// Self-signed when parent is nil (a CA root): the template signs itself with its own key.
	signTmpl, signKey := tmpl, key
	if parent != nil {
		signTmpl, signKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signTmpl, &key.PublicKey, signKey)
	if err != nil {
		t.Fatalf("create synthetic %q cert: %v", spec.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse synthetic %q cert: %v", spec.CommonName, err)
	}
	return Leaf{Cert: cert, DER: der, Key: key}
}

// WriteLeafPEM writes leaf's certificate + PKCS8 private key as PEM files at
// certPath/keyPath (the D50 synthetic-cert files the DS_ORCH_TLS_* env points
// at).
func WriteLeafPEM(t *testing.T, leaf Leaf, certPath, keyPath string) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
	if err != nil {
		t.Fatalf("marshal synthetic key: %v", err)
	}
	WritePEM(t, certPath, "CERTIFICATE", leaf.DER)
	WritePEM(t, keyPath, "PRIVATE KEY", keyDER)
}

// TLSCert renders a minted leaf as the gRPC transport-credentials keypair (DER
// cert + its ECDSA key); crypto/tls parses the leaf on first use.
func TLSCert(leaf Leaf) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{leaf.DER}, PrivateKey: leaf.Key}
}

// WritePEM encodes der under blockType and writes it to path (the synthetic-cert
// file emitter the DS_ORCH_TLS_* env points at).
func WritePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// CA bundles a self-signed in-test CA: its minted Leaf (parsed cert + signing
// key + DER) and a one-cert pool pinning it (for use as a server clientauth pool
// or a client RootCAs pool). It is the CA primitive the bilateral-CA arms build
// their material from.
type CA struct {
	Leaf Leaf
	Pool *x509.CertPool
}

// NewCA generates a throwaway self-signed P-256 ECDSA CA (D50 — no real keys, no
// live CA) and a one-cert pool pinning it. cn names it for diagnostics; serial
// keeps independent CAs distinct.
func NewCA(t *testing.T, cn string, serial int64) CA {
	t.Helper()
	leaf := Cert(t, Spec{Role: RoleCA, Serial: serial, CommonName: cn}, nil)
	pool := x509.NewCertPool()
	pool.AddCert(leaf.Cert)
	return CA{Leaf: leaf, Pool: pool}
}

// SignedLeaf signs a leaf certificate with ca, carrying cn as its Subject CN and
// SAN (so a client RootCAs/dnsName check resolves against the dial authority)
// and the given ExtKeyUsage (ServerAuth or ClientAuth). It returns the
// tls.Certificate the bufconn transport presents. Synthetic P-256 ECDSA,
// generated in-process (D50).
func (ca CA) SignedLeaf(t *testing.T, cn string, serial int64, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	var role Role
	switch usage {
	case x509.ExtKeyUsageServerAuth:
		role = RoleServer
	case x509.ExtKeyUsageClientAuth:
		role = RoleClient
	}
	leaf := Cert(t, Spec{Role: role, Serial: serial, CommonName: cn, DNSName: cn}, &ca.Leaf)
	return TLSCert(leaf)
}
