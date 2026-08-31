// SPDX-License-Identifier: Apache-2.0

// Two-root-hierarchy CA substrate (D82; doc 16 §4).
//
// D82 ratifies two SEPARATE root hierarchies — workload-identity (hierarchy 1)
// and interception (hierarchy 2) — so compromise of one never yields the
// other's signing capability. Hierarchy separation is enforced structurally
// here: each root has its own key, its own x509.CertPool, and a distinct
// ExtKeyUsage profile, so a leaf chained to one root never verifies against the
// other's pool (the doc 16 §13 "hierarchy separation" assurance row).
//
// M1 SUBSTRATE (D22): the two roots are PERSISTED in the D39 secret-store trust
// zone (castore.go) and LOADED at startup, not regenerated per-process — the M1
// own-minimal-CA posture that swaps in behind the unchanged Validate seam (doc 16
// §2; M0 was in-memory-throwaway, M3 swaps in SPIFFE/SPIRE). The workload root
// (hierarchy 1) issues per-session LEAVES; the interception root (hierarchy 2)
// issues a per-session INTERMEDIATE CA — proxy-bound, never a root (the bounded
// D76 exposure, doc 16 §4). No real key material anywhere (D50): every key minted
// here is synthetic.
package mint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// rootHierarchy is one of the two D82 root hierarchies. Each carries its own
// signing key, self-signed root certificate, and a verify pool seeded with only
// that root — so a certificate signed under one hierarchy can never chain to the
// other. The extKeyUsage pin is the second, independent separation lever: a
// workload-identity leaf is a client-auth cert, an interception CA is marked for
// CA use, and the verify call demands the matching usage.
type rootHierarchy struct {
	name        string
	key         *ecdsa.PrivateKey
	cert        *x509.Certificate
	certDER     []byte
	pool        *x509.CertPool
	leafUsages  []x509.ExtKeyUsage
	isCAIssuing bool // interception root issues intermediate CAs; workload root issues leaves
}

// newRootHierarchy mints one synthetic self-signed root (D50). The serial is
// drawn from a 128-bit space so two roots in the same process never collide.
func newRootHierarchy(name string, leafUsages []x509.ExtKeyUsage, isCAIssuing bool, now time.Time) (*rootHierarchy, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint: generate %s root key: %w", name, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ds-m0-shim-root-" + name,
			Organization: []string{"dream-serpent (M0 synthetic root)"},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mint: create %s root cert: %w", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mint: parse %s root cert: %w", name, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &rootHierarchy{
		name:        name,
		key:         key,
		cert:        cert,
		certDER:     der,
		pool:        pool,
		leafUsages:  leafUsages,
		isCAIssuing: isCAIssuing,
	}, nil
}

// verifyLeaf checks that leafDER chains to THIS hierarchy's root with THIS
// hierarchy's required extended-key-usage profile. It returns nil only on a
// successful chain build; any cross-hierarchy or wrong-usage certificate fails.
// This is the executable core of both §13 isolation rows: a session-B CA passed
// to a session-A pool fails (per-session isolation), and an interception cert
// passed to the workload pool fails (hierarchy separation).
func (h *rootHierarchy) verifyLeaf(leafDER []byte, at time.Time) error {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("mint: parse leaf: %w", err)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:       h.pool,
		KeyUsages:   h.leafUsages,
		CurrentTime: at,
	})
	if err != nil {
		return fmt.Errorf("mint: %s-hierarchy verify: %w", h.name, err)
	}
	return nil
}

// sessionInterceptionCA is one session's interception material (hierarchy 2): a
// per-session INTERMEDIATE CA issued UNDER the persistent interception root, plus
// its private key. It is the proxy-bound delivery unit (doc 16 §4) — the bounded
// D76 exposure: ds-tlsproxy holds this to mint per-origin leaves on the fly, but
// never holds a root, so a compromised proxy yields one live session's interception
// CA, never fleet-wide signing capability. The key is destroyed at teardown
// (Shim.TeardownSession). Synthetic (D50).
type sessionInterceptionCA struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certDER []byte
	// trustAnchorDER is the cert pinned as the per-session trust anchor in the
	// session's VM (doc 16 §4 trust-store injection). It is the per-session
	// intermediate cert itself: a leaf minted under THIS session's CA validates only
	// when THIS session's intermediate is the pinned anchor, so session A's leaf
	// never validates in session B's trust context (the §13 per-session-CA isolation
	// property) even though both intermediates chain to the one shared interception
	// root.
	trustAnchorDER []byte
}

// issueSessionInterceptionCA mints a per-session intermediate CA under the
// persistent interception root `root` (hierarchy 2, D82). The intermediate is a
// path-len-0 CA (it signs leaves, never further CAs) marked for server-auth, the
// way ds-tlsproxy uses it. The intermediate chains to the persistent root for
// provenance, and is ALSO returned as the per-session trust anchor (pinned in the
// session VM) so per-session isolation holds. Synthetic (D50).
func issueSessionInterceptionCA(root *rootHierarchy, sessionUUID string, now time.Time, ttl time.Duration) (*sessionInterceptionCA, error) {
	if root == nil {
		return nil, errNotInitialized
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint: generate interception ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ds-interception-ca/" + sessionUUID,
			Organization: []string{"dream-serpent (per-session interception, M1 synthetic)"},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	// Signed BY the persistent interception root (root.cert / root.key) — the root
	// issues the per-session intermediate (doc 16 §4), never the reverse.
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, root.cert, &caKey.PublicKey, root.key)
	if err != nil {
		return nil, fmt.Errorf("mint: sign interception ca: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("mint: parse interception ca: %w", err)
	}
	return &sessionInterceptionCA{
		key:            caKey,
		cert:           caCert,
		certDER:        caDER,
		trustAnchorDER: caDER,
	}, nil
}

// destroy zeroes the per-session interception key in place so a teardown leaves no
// recoverable signing material on the heap (the doc 16 §4 "destroyed at teardown"
// lifecycle, the bounded D76 exposure). The ECDSA private scalar D is the secret;
// zeroing it makes the key unusable for any further signing. Idempotent and
// nil-safe.
func (c *sessionInterceptionCA) destroy() {
	if c == nil || c.key == nil {
		return
	}
	if c.key.D != nil {
		c.key.D.SetInt64(0)
	}
	c.key = nil
}

// randomSerial draws a positive 128-bit certificate serial (synthetic, D50).
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("mint: draw serial: %w", err)
	}
	// Avoid a zero serial (RFC 5280 forbids it).
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}

// errNotInitialized guards methods called before NewShim wired the roots.
var errNotInitialized = errors.New("mint: shim roots not initialized")
