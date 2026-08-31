// SPDX-License-Identifier: Apache-2.0

// cabundledisposer — the §4.2 teardown half of the M0 trust path (D82; doc 16 §4; doc 25
// §12). The orchestrator PRODUCER (controlplane/liveedges.go fileCABundleProducer.drop)
// mints the per-session interception CA and drops TWO files into the host-readable store
// under <OverlayDir>/.ds-ca-bundles: the cert <sanitize(caRef)>.pem (which
// cabundlesource.go reads back for the step-7 inject) and the proxy-bound PKCS#8 private
// key <sanitize(caRef)>.key.pem (which ds-tlsproxy reads host-side to mint per-origin
// leaves). Nothing removed either. Every session ever created left a LIVE CA PRIVATE KEY
// on the host until an operator ran `ds-serve-stack.sh down --purge` — and that sweep
// globbed only the overlays and config drives, so in practice: never. D82 says the
// per-session CA is destroyed at teardown; this file is what makes that true.
//
// WHY THE DISPOSAL IS HOST-SIDE, NOT ORCHESTRATOR-SIDE. The orchestrator's step-5
// rollback/revoke leg also carries the CARef, so it looks like the natural owner — but
// that leg is DEAD CODE in production: hostagent.NewDestroyer has no non-test callers, and
// the only HostAgentDestroyer actually composed at the orchestrator root is the synthetic
// one. The live teardown that really runs on a live host is DriverService.Destroy (§4.2),
// and the durable SessionRecord the create path persisted is the LAST carrier of the
// caBundleRef at that point (the frozen DestroyRequest carries only the session_uuid, and
// the clone cache holds the wire CloneFromImageResponse, which never names the CA). So the
// disposal rides the path that exists: record → DestroyResolver → this seam.
//
// SINGLE-SOURCED LEAVES. Both leaf names come from internal/trustpath
// (trustpath.KeyFilename / trustpath.BundleFilename) — the SAME package the producer's
// drop derives its write paths from — so the disposer removes precisely the two files the
// producer wrote and the two sides cannot drift. A drifted disposer does not fail loudly;
// it silently leaves the key behind, which is exactly the leak this closes.
//
// Same posture as cabundlesource.go / sessionrecord.go: reachable on the live path (wired
// gate-aware at the daemon root under DS_HOSTAGENT_LIVE), STDLIB-ONLY (os, no cgo). Error
// messages name the REF and the STORE PATH only — never a byte of key material (D39/D76).

package libvirt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// CABundleDisposer removes the per-session interception-CA bundle the orchestrator
// producer dropped, at the §4.2 teardown. It is the DISPOSAL counterpart of the
// CABundleSource fetch seam: the source resolves a ref to the cert bytes at create, this
// removes BOTH dropped files at destroy.
//
// Contract: idempotent on the ref (an already-disposed or never-dropped bundle is a clean
// success, so a re-driven Destroy converges), and FAIL-LOUD on any real removal fault —
// the residue is a live CA private key, so a host that could not delete it must surface
// the teardown as faulted rather than report a clean destroy.
type CABundleDisposer interface {
	DisposeCABundle(ctx context.Context, caBundleRef string) error
}

// fileCABundleDisposer is the production CABundleDisposer: it removes the cert + key pair
// under <OverlayDir>/.ds-ca-bundles keyed by the opaque caBundleRef — the exact two files
// the orchestrator's fileCABundleProducer.drop wrote.
type fileCABundleDisposer struct {
	dir string
}

// NewFileCABundleDisposer builds the file disposer over baseDir/.ds-ca-bundles, creating
// the directory (0o700) if absent so a host that never received a drop still has a
// well-formed empty store (a disposal there is then a clean no-op, not a missing-dir
// fault). baseDir is the host's OverlayDir — the SAME base the producer's
// NewFileCABundleProducer and the consumer's NewFileCABundleSource are built over.
func NewFileCABundleDisposer(baseDir string) (*fileCABundleDisposer, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("CA bundle disposer: empty base dir")
	}
	dir := trustpath.SubdirPath(baseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("CA bundle disposer: mkdir %q: %w", dir, err)
	}
	return &fileCABundleDisposer{dir: dir}, nil
}

// DisposeCABundle removes the session's dropped CA bundle: the proxy-bound PKCS#8 private
// key FIRST, then the cert. The order is deliberate — the key is the credential, so if the
// process is interrupted (or the second removal faults) the state left behind is a
// key-less cert, which is inert, rather than a cert-less key, which is the whole secret.
//
// An absent file is a clean no-op on BOTH halves (idempotent: a re-driven Destroy, or a
// session whose drop never landed, converges). Any OTHER removal error is returned
// fail-loud so the §4.2 Destroy surfaces as faulted and the reconciler re-drives. An empty
// ref is a caller bug — the service SKIPS empty refs (a pre-upgrade record carries none)
// before ever calling here, so reaching this with "" means a wiring error, not a
// pre-upgrade record.
//
// Errors name the ref and the store path ONLY; the key BYTES are never read, let alone
// echoed (D39/D76 — never log the secret).
func (d *fileCABundleDisposer) DisposeCABundle(_ context.Context, caBundleRef string) error {
	if caBundleRef == "" {
		return fmt.Errorf("CA bundle disposer: empty ca bundle ref")
	}
	keyPath := filepath.Join(d.dir, trustpath.KeyFilename(caBundleRef))
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("CA bundle disposer: remove proxy-bound key for ref %q at %s: %w", caBundleRef, keyPath, err)
	}
	certPath := filepath.Join(d.dir, trustpath.BundleFilename(caBundleRef))
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("CA bundle disposer: remove CA cert for ref %q at %s: %w", caBundleRef, certPath, err)
	}
	return nil
}

// NewCABundleDisposer returns the gate-aware §4.2 CA-bundle disposal seam: the real file
// disposer over <OverlayDir>/.ds-ca-bundles under DS_HOSTAGENT_LIVE, nil otherwise.
//
// nil off the gate is INTENTIONAL and byte-identical to the historical destroy: the
// orchestrator producer's drop only ever lands on a live host, so off the gate there is no
// bundle to dispose, and the DriverService treats a nil seam as unwired (no filesystem
// call at all). This is the OPTIONAL-seam posture of NewSessionRecordStore /
// NewAttachTokenStore, not the both-sides-non-nil posture of NewConfigDriveDisposer — the
// config drive is built offline too, a CA bundle is not. A missing OverlayDir on the live
// path is a construction error (LiveConfig.validate), so the leak is never masked by a
// silently mis-rooted store.
func NewCABundleDisposer(cfg LiveConfig) (CABundleDisposer, error) {
	if LiveEnabled() {
		if err := cfg.validate(); err != nil {
			return nil, err
		}
		return NewFileCABundleDisposer(cfg.OverlayDir)
	}
	return nil, nil
}

var _ CABundleDisposer = (*fileCABundleDisposer)(nil)
