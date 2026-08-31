// SPDX-License-Identifier: Apache-2.0

// cainject — the concrete production CAInjector for the libvirt host-agent
// create path (doc 15 §4.1 step 7; doc 16 §4 + §12). It satisfies the seams.go
// CAInjector interface: between CloneFromImage (step 7's overlay clone) and
// entrypoint (step 8's boot), it injects the per-session interception CA into
// the per-session qcow2 overlay's trust store, FAIL-CLOSED — a session never
// starts with a missing or empty trust anchor (doc 16 §4), so any error aborts
// the create before the first TLS byte the guest could emit (step 7 ≺ step 8).
//
// FROZEN vs FREE (doc 16 §12): injection-between-CloneFromImage-and-entrypoint
// and fail-closed-before-first-TLS-byte are FROZEN (D17/D12, M0); the injection
// MECHANISM (guestfs write vs provisioning channel) is FREE. This file models
// the mechanism behind two seams so the package stays stdlib-only + offline
// (doc.go / seams.go posture) while the real host-side writer lands later:
//
//   - CABundleSource fetches the per-session interception-CA PEM by ref. The CA
//     is minted by Identity's D22 service under the interception root hierarchy
//     (D82 — a SEPARATE root from workload identity, so compromise of one never
//     yields the other's signing capability); this injector is the host-agent's
//     consume side. The fetch is a seam so it is offline-fakeable here.
//   - OverlayTrustStoreWriter performs the actual write into the overlay's
//     trust store. The REAL impl (a libguestfs write into the qcow2 overlay, or
//     a provisioning-channel hand-off) lands LATER host-side on the ESXi/KVM box
//     — see the TODO on the interface. This unit ships the interface plus an
//     in-memory fake (cainject_test.go) so the create path is provable offline
//     against fakes (D50): no libguestfs/libvirt-go/cgo, no real guestfs write,
//     no VM, no sudo/KVM.
//
// GUEST-PATH RECONCILE (posture-(b) cred-swap; additive, doc-only here): this
// injector is delivery-MECHANISM-agnostic — it fetches, validates (CA:TRUE), writes,
// and VERIFIES, all keyed on the writer's own in-guest anchor path. The live writer
// (trustanchor.go) lands the per-session anchor in the distro trust dir by default;
// under DS_GATE_TLS_MODE=swap the nested-testbed (orchestrator-boot-l2.sh) sets
// DS_GUEST_INTERCEPT_CA_PATH so the SAME orchestrator-minted CA is delivered to the
// one FIXED path the in-guest Claude Code reads via NODE_EXTRA_CA_CERTS, reconciled
// to loop-1. The fail-closed contract below is UNCHANGED across the two delivery
// shapes: a missing/empty/non-CA bundle aborts the (swap-mode) create before the
// guest's first TLS byte. Only the public CA cert is delivered — never the private
// key — and no secret is logged on any path.

package libvirt

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// CABundleSource fetches the per-session interception-CA bundle (PEM bytes) by
// the caBundleRef the create path carries (VmSpec.material.ca_bundle_ref slot).
// The bundle is the per-session CA minted by Identity's D22 service under the
// interception root hierarchy (D82); this seam is the host-agent's consume side,
// kept as an interface so the injector is offline-fakeable (the real fetch — a
// proto/secret-store read — wires up where the contract lands, never inside this
// stdlib-only module). A nil/empty return MUST be treated as fail-closed by the
// caller: no bundle means no provable trust anchor.
type CABundleSource interface {
	// FetchCABundle returns the raw PEM bytes for caBundleRef. An error (or an
	// empty return) means the per-session interception CA could not be obtained;
	// InjectCA turns that into a fail-closed create abort (doc 16 §4).
	FetchCABundle(ctx context.Context, caBundleRef string) (pem []byte, err error)
}

// OverlayTrustStoreWriter writes a verified interception-CA PEM into the
// per-session qcow2 overlay's trust store (the step-7 mechanism, FREE per
// doc 16 §12 — bounded only by fail-closed + before-first-TLS-byte).
//
// The REAL implementation of this interface is liveTrustStoreWriter
// (trustanchor.go): a libguestfs write into the per-session overlay
// (virt-customize --upload the PEM into /usr/local/share/ca-certificates +
// --run-command update-ca-certificates; HasTrustAnchor reads it back via
// virt-cat and re-derives the DER fingerprint). It stays stdlib-only — it shells
// out through the package's os/exec `runner` seam (live.go), so NO libguestfs-go
// /cgo enters orchestrator/go.mod — and is reachable only behind DS_HOSTAGENT_LIVE
// (LiveEnabled), the same operator-host gate the live OverlayStore + Booter use;
// off the gate the package uses the in-memory fake (cainject_test.go) so the
// create path's fail-closed contract is provable against fakes (D50). The real
// write was grounded on the ESXi/KVM box (taskdb 01KV638T).
type OverlayTrustStoreWriter interface {
	// WriteTrustAnchor writes the verified interception-CA PEM into the trust
	// store of the overlay at overlayPath, for the session keyed by sessionUUID.
	// It MUST be idempotent on (sessionUUID, overlayPath): a retry converges to
	// the same single anchor rather than appending a duplicate (the seams.go
	// idempotency contract; step-7 retries must not fork state). An error means
	// the write is not provably complete — the caller fails the create closed.
	WriteTrustAnchor(ctx context.Context, sessionUUID, overlayPath string, caPEM []byte) error

	// HasTrustAnchor reports whether the verified anchor identified by
	// anchorFingerprint is already present in the overlay's trust store. The
	// injector uses it (a) to short-circuit an idempotent retry and (b) to VERIFY
	// the anchor is present after a write — fail-closed means the create only
	// proceeds once the anchor is provably in the store, never on a write that
	// silently no-oped. A false-with-nil-error is a normal "absent"; an error is
	// treated as fail-closed (the presence of the anchor is not provable).
	HasTrustAnchor(ctx context.Context, sessionUUID, overlayPath, anchorFingerprint string) (present bool, err error)
}

// caInjector is the concrete production CAInjector (seams.go) over a
// CABundleSource (fetch) and an OverlayTrustStoreWriter (write). It is the
// step-7 fail-closed injection: fetch the per-session interception CA by ref,
// validate it carries a real CA trust anchor, write it into the overlay trust
// store, and VERIFY it landed — any failure returns a non-nil error so the
// create path aborts before boot (doc 15 §4.1 step 7; doc 16 §4).
type caInjector struct {
	source CABundleSource
	writer OverlayTrustStoreWriter
}

// NewCAInjector builds the production CAInjector from its fetch + write seams.
// A nil seam is a programming error surfaced at construction (matching
// NewHostAgent's nil-dependency posture) — never a silent nil-deref at the
// fail-closed step-7 boundary. The returned value satisfies the seams.go
// CAInjector interface, so NewHostAgent can take it directly.
func NewCAInjector(source CABundleSource, writer OverlayTrustStoreWriter) (CAInjector, error) {
	if source == nil {
		return nil, fmt.Errorf("libvirt CA injector requires a CA bundle source")
	}
	if writer == nil {
		return nil, fmt.Errorf("libvirt CA injector requires an overlay trust-store writer")
	}
	return &caInjector{source: source, writer: writer}, nil
}

// InjectCA implements seams.go CAInjector. It writes the per-session
// interception CA referenced by caBundleRef into the overlay trust store,
// FAIL-CLOSED and IDEMPOTENT on the session:
//
//	(1) fetch the bundle PEM by ref (a missing/empty bundle fails closed);
//	(2) validate it parses to at least one real CA trust anchor (an empty or
//	    unparseable bundle, or a leaf-only bundle with no CA, fails closed —
//	    doc 16 §4: a session never starts with an empty trust anchor);
//	(3) if the verified anchor is already present, converge (idempotent retry);
//	(4) otherwise write it, then VERIFY it landed (a write that silently no-oped
//	    must NOT be reported as success).
//
// Any error at any step returns non-nil so HostAgent.CreateSession aborts the
// create before boot (step 7 ≺ step 8) — the trust store is never left
// half-written and the create never proceeds to a VM whose first TLS byte could
// bypass the egress gateway (D17).
func (c *caInjector) InjectCA(ctx context.Context, overlayPath, caBundleRef string) error {
	if overlayPath == "" {
		// No overlay means there is no trust store to write into — fail closed
		// rather than silently "succeed" against nothing.
		return fmt.Errorf("inject interception CA: empty overlay path")
	}
	if caBundleRef == "" {
		// Defense in depth: CreateRequest.validate already refuses an empty ref
		// pre-step-4, but the injector must not assume its caller pre-validated.
		return fmt.Errorf("inject interception CA: empty CA bundle ref (fail-closed, D17)")
	}

	// (1) Fetch the per-session interception-CA PEM (D82 interception root).
	pemBytes, err := c.source.FetchCABundle(ctx, caBundleRef)
	if err != nil {
		return fmt.Errorf("fetch interception CA bundle %q: %w", caBundleRef, err)
	}
	if len(pemBytes) == 0 {
		// An empty bundle is a missing trust anchor — fail closed (doc 16 §4).
		return fmt.Errorf("interception CA bundle %q is empty (fail-closed, D17)", caBundleRef)
	}

	// (2) Validate it carries a real CA trust anchor and derive its fingerprint.
	fingerprint, err := validateCABundle(pemBytes)
	if err != nil {
		// Unparseable PEM, no certificate, or no CA cert — none of these is a
		// trust anchor a session may boot with. Fail closed.
		return fmt.Errorf("validate interception CA bundle %q: %w", caBundleRef, err)
	}

	// The session this overlay belongs to: derive it from the overlay so a write
	// + verify retry keys on the same session (the writer idempotency contract).
	sessionUUID := sessionFromOverlay(overlayPath)

	// (3) Idempotent short-circuit: if the verified anchor is already present, a
	// prior inject for this session already landed — converge without rewriting.
	present, err := c.writer.HasTrustAnchor(ctx, sessionUUID, overlayPath, fingerprint)
	if err != nil {
		// Presence is not provable — treat as fail-closed (we must not write
		// blind, and we must not proceed assuming absence).
		return fmt.Errorf("probe overlay trust store for %q: %w", overlayPath, err)
	}
	if present {
		return nil
	}

	// (4) Write the anchor, then VERIFY it landed. The write is required to be
	// idempotent on the session; verifying after closes the loop so a silent
	// no-op write can never be reported as a provable injection.
	if err := c.writer.WriteTrustAnchor(ctx, sessionUUID, overlayPath, pemBytes); err != nil {
		// A write failure means the trust store is not provably anchored — the
		// create must abort before boot (doc 15 §4.1 step 7). The partial overlay
		// is disposed by the rollback path (create.go surfaces OverlayPath).
		return fmt.Errorf("write interception CA into overlay %q: %w", overlayPath, err)
	}
	verified, err := c.writer.HasTrustAnchor(ctx, sessionUUID, overlayPath, fingerprint)
	if err != nil {
		return fmt.Errorf("verify interception CA in overlay %q: %w", overlayPath, err)
	}
	if !verified {
		// The write reported success but the anchor is not in the store — a
		// silent no-op. FAIL CLOSED: a session must never boot on an empty trust
		// anchor (doc 16 §4), so a non-verifiable write is a create failure.
		return fmt.Errorf("interception CA not present in overlay %q after write (fail-closed, D17)", overlayPath)
	}
	return nil
}

// validateCABundle parses a PEM bundle and returns the SHA-256 fingerprint of
// the first CA certificate it carries. It is the fail-closed admission check for
// the trust anchor (doc 16 §4): the bundle MUST parse, MUST contain at least one
// CERTIFICATE block, and at least one of those certs MUST be a CA (Basic
// Constraints CA:TRUE). Anything else — junk bytes, a PEM with no certificate, a
// bundle of leaf-only certs — is rejected so a session never boots on a
// non-anchor. Only stdlib crypto/x509 + encoding/pem are used (offline posture).
func validateCABundle(pemBytes []byte) (fingerprint string, err error) {
	var (
		sawCert bool
		caCert  *x509.Certificate
	)
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// Tolerate non-cert blocks (e.g. a comment header) but they are not a
			// trust anchor — keep scanning for a CERTIFICATE.
			continue
		}
		sawCert = true
		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return "", fmt.Errorf("parse certificate block: %w", perr)
		}
		if cert.IsCA {
			caCert = cert
			break
		}
	}
	if !sawCert {
		return "", errors.New("bundle contains no PEM CERTIFICATE block (empty trust anchor)")
	}
	if caCert == nil {
		return "", errors.New("bundle contains no CA certificate (BasicConstraints CA:TRUE) — not a trust anchor")
	}
	return certFingerprint(caCert), nil
}

// certFingerprint returns the lowercase hex SHA-256 over the certificate's DER
// bytes — a stable identity for the trust anchor, used to short-circuit an
// idempotent retry and to VERIFY the written anchor is the one we fetched.
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// sessionFromOverlay recovers the session uuid that keys the overlay so the
// writer's idempotency (keyed on the session) lines up with the create path's
// per-session overlay. The v0 OverlayStore names overlays
// "<dir>/<sessionUUID>.qcow2" (see fakeOverlay / the §4.1 step-7 path); we
// recover that key by trimming the directory and the ".qcow2" suffix. If the
// path does not match the convention we fall back to the whole path — the value
// is only an idempotency/scoping key for the writer, never a security boundary
// (the security boundary is the fail-closed verify above), so a conservative
// fallback that still keys per-overlay is correct.
func sessionFromOverlay(overlayPath string) string {
	base := overlayPath
	if i := lastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	const suffix = ".qcow2"
	if n := len(base); n >= len(suffix) && base[n-len(suffix):] == suffix {
		base = base[:n-len(suffix)]
	}
	if base == "" {
		return overlayPath
	}
	return base
}

// lastIndexByte is a tiny stdlib-free helper (we avoid importing strings/path
// for a single split to keep the dependency surface minimal and explicit; the
// package is deliberately stdlib-only and these are trivial).
func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
