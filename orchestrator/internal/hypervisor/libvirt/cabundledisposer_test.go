// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// stubCertPEM / stubKeyPEM stand in for the producer's drop. They are NON-SECRET
// placeholders — the disposer never reads a byte of either, and the fail-loud test asserts
// no content ever reaches an error message (D39/D76).
const (
	stubCertPEM = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"
	stubKeyPEM  = "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n"
)

// dropTestBundle writes the two files the orchestrator producer drops for a ref (the cert
// and its proxy-bound key sibling), through the SAME trustpath leaf transforms the
// producer uses, and returns their paths.
func dropTestBundle(t *testing.T, baseDir, ref string) (certPath, keyPath string) {
	t.Helper()
	dir := trustpath.SubdirPath(baseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, trustpath.BundleFilename(ref))
	keyPath = filepath.Join(dir, trustpath.KeyFilename(ref))
	if err := os.WriteFile(certPath, []byte(stubCertPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(stubKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestDisposeCABundleRemovesCertAndKey is the D82 property: after a disposal BOTH dropped
// files are gone — the cert and, load-bearing, the proxy-bound CA PRIVATE KEY that
// previously survived every teardown.
func TestDisposeCABundleRemovesCertAndKey(t *testing.T) {
	base := t.TempDir()
	certPath, keyPath := dropTestBundle(t, base, "ca:X")

	d, err := NewFileCABundleDisposer(base)
	if err != nil {
		t.Fatalf("NewFileCABundleDisposer: %v", err)
	}
	if err := d.DisposeCABundle(context.Background(), "ca:X"); err != nil {
		t.Fatalf("DisposeCABundle: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Errorf("the proxy-bound CA private key survived the teardown (%s): stat err=%v", keyPath, err)
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Errorf("the CA cert survived the teardown (%s): stat err=%v", certPath, err)
	}
}

// TestDisposeCABundleIsIdempotent: a re-driven Destroy over an already-disposed bundle
// converges (an absent file is a clean no-op, not a fault) — the same contract every other
// §4.2 purge seam holds.
func TestDisposeCABundleIsIdempotent(t *testing.T) {
	base := t.TempDir()
	dropTestBundle(t, base, "ca:X")

	d, _ := NewFileCABundleDisposer(base)
	if err := d.DisposeCABundle(context.Background(), "ca:X"); err != nil {
		t.Fatalf("first dispose: %v", err)
	}
	if err := d.DisposeCABundle(context.Background(), "ca:X"); err != nil {
		t.Fatalf("re-dispose of an already-disposed bundle must be a clean no-op: %v", err)
	}
}

// TestDisposeCABundleUnknownRefIsNoOp: a ref whose drop never landed (a create that
// faulted before the producer wrote, or a store on a host that never received one) is a
// clean success — the teardown must converge, not fault, on nothing-to-do.
func TestDisposeCABundleUnknownRefIsNoOp(t *testing.T) {
	d, err := NewFileCABundleDisposer(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileCABundleDisposer: %v", err)
	}
	if err := d.DisposeCABundle(context.Background(), "ca:never-dropped"); err != nil {
		t.Fatalf("dispose of a never-dropped ref must be a clean no-op: %v", err)
	}
}

// TestDisposeCABundleEmptyRefIsError: the service skips empty refs (a pre-upgrade
// SessionRecord carries none) BEFORE calling, so reaching the disposer with "" is a wiring
// bug — surfaced, never silently sanitized into the literal "session" leaf, which would
// delete an unrelated bundle.
func TestDisposeCABundleEmptyRefIsError(t *testing.T) {
	d, _ := NewFileCABundleDisposer(t.TempDir())
	if err := d.DisposeCABundle(context.Background(), ""); err == nil {
		t.Fatal("an empty ca bundle ref must be an error (caller bug), not a silent no-op")
	}
}

// TestDisposeCABundleFaultIsLoudAndSecretFree: a removal the host cannot perform (here an
// unwritable store dir) is surfaced as an error — a live CA private key left on disk must
// not read as a clean teardown — and the message names the REF and the PATH only, never a
// byte of the key material (D39/D76).
func TestDisposeCABundleFaultIsLoudAndSecretFree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions; the EACCES fault cannot be provoked")
	}
	base := t.TempDir()
	dropTestBundle(t, base, "ca:X")
	storeDir := trustpath.SubdirPath(base)

	d, _ := NewFileCABundleDisposer(base)
	if err := os.Chmod(storeDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(storeDir, 0o700) })

	err := d.DisposeCABundle(context.Background(), "ca:X")
	if err == nil {
		t.Fatal("a removal fault must be FAIL-LOUD (the residue is a live CA private key)")
	}
	if !strings.Contains(err.Error(), "ca:X") {
		t.Errorf("the fault must name the ref so an operator can find the residue, got %q", err)
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "stub") {
		t.Errorf("the fault must NEVER echo key material (D39/D76), got %q", err)
	}
}

// TestNewCABundleDisposerGate: off DS_HOSTAGENT_LIVE the constructor returns a PLAIN nil
// interface (no typed-nil pointer, which would defeat the service's `!= nil` guard), so
// the destroy is byte-identical to the historical path — no drop ever landed off the gate.
// On the gate it returns a live disposer rooted at <OverlayDir>/.ds-ca-bundles.
func TestNewCABundleDisposerGate(t *testing.T) {
	cfg := LiveConfig{OverlayCreateScript: "x", OverlayDir: t.TempDir(), BaseImage: "y", VirshBin: "virsh"}

	t.Setenv(EnvHostAgentLive, "")
	d, err := NewCABundleDisposer(cfg)
	if err != nil {
		t.Fatalf("gate off: %v", err)
	}
	if d != nil {
		t.Fatalf("gate off must return a plain nil disposer, got %T", d)
	}

	t.Setenv(EnvHostAgentLive, "1")
	d, err = NewCABundleDisposer(cfg)
	if err != nil {
		t.Fatalf("gate on: %v", err)
	}
	if d == nil {
		t.Fatal("gate on must return a non-nil disposer")
	}
	if _, err := os.Stat(trustpath.SubdirPath(cfg.OverlayDir)); err != nil {
		t.Fatalf("gate on must create the CA-bundle store subdir: %v", err)
	}
	// Idempotent on an absent bundle: a clean no-op, never an error.
	if err := d.DisposeCABundle(context.Background(), "ca:never-dropped"); err != nil {
		t.Fatalf("DisposeCABundle(absent) = %v, want a clean no-op success", err)
	}
}

// TestNewCABundleDisposerGateOnRequiresOverlayDir: the live path fails CONSTRUCTION when
// the config is incomplete, rather than silently rooting the store somewhere the producer
// never wrote (which would make every disposal a truthy no-op and hide the leak).
func TestNewCABundleDisposerGateOnRequiresOverlayDir(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1")
	if _, err := NewCABundleDisposer(LiveConfig{}); err == nil {
		t.Fatal("gate on with no OverlayDir must fail construction")
	}
}
