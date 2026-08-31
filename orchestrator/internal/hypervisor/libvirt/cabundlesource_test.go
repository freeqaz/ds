// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

func TestFileCABundleSource_ReadsDroppedBundle(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileCABundleSource(dir)
	if err != nil {
		t.Fatalf("NewFileCABundleSource: %v", err)
	}
	// Simulate the orchestrator drop: write a PEM at the EXACT path the producer
	// derives via trustpath (single source), keyed by the ref.
	want := []byte("-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(trustpath.BundlePath(dir, "ca-ref-A"), want, 0o600); err != nil {
		t.Fatalf("seed drop: %v", err)
	}
	got, err := s.FetchCABundle(context.Background(), "ca-ref-A")
	if err != nil {
		t.Fatalf("FetchCABundle: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("FetchCABundle = %q, want %q", got, want)
	}
}

func TestFileCABundleSource_MissingBundleFailsClosed(t *testing.T) {
	s, err := NewFileCABundleSource(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileCABundleSource: %v", err)
	}
	// No drop for this ref — must be an ERROR (fail-closed), never an empty success
	// that InjectCA would treat as a missing-but-tolerated bundle.
	got, err := s.FetchCABundle(context.Background(), "never-dropped")
	if err == nil {
		t.Fatalf("expected fail-closed error for a missing bundle; got nil (bytes=%q)", got)
	}
	if got != nil {
		t.Errorf("expected nil bytes on the fail-closed path; got %q", got)
	}
}

// TestFileCABundleSource_PathIsTrustpathSingleSourced pins the consumer's on-disk path
// to internal/trustpath — the SAME transform the orchestrator producer writes through —
// so a drift in subdir/sanitize/extension cannot silently break the trust path (the
// producer would write a file this source never finds, and step-7 inject fails closed).
func TestFileCABundleSource_PathIsTrustpathSingleSourced(t *testing.T) {
	base := t.TempDir()
	s, err := NewFileCABundleSource(base)
	if err != nil {
		t.Fatalf("NewFileCABundleSource: %v", err)
	}
	// The store dir must be exactly trustpath.SubdirPath(base).
	if want := trustpath.SubdirPath(base); s.dir != want {
		t.Errorf("store dir = %q, want %q", s.dir, want)
	}
	// The resolved bundle path must be byte-identical to the producer's drop path,
	// including a ref that exercises the sanitize rule (':' -> '_').
	for _, ref := range []string{"ca-ref-A", "ca:0c0ffee", "weird/ref..ok"} {
		if got, want := s.bundlePath(ref), trustpath.BundlePath(base, ref); got != want {
			t.Errorf("bundlePath(%q) = %q, want %q", ref, got, want)
		}
		// And it must agree with the explicit subdir join (defense against a future
		// dir-vs-leaf divergence).
		if got, want := s.bundlePath(ref), filepath.Join(trustpath.SubdirPath(base), trustpath.BundleFilename(ref)); got != want {
			t.Errorf("bundlePath(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestFileCABundleSource_EmptyRefRejected(t *testing.T) {
	s, err := NewFileCABundleSource(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileCABundleSource: %v", err)
	}
	if _, err := s.FetchCABundle(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty ca bundle ref; got nil")
	}
}

func TestNewFileCABundleSource_RequiresBaseDir(t *testing.T) {
	if _, err := NewFileCABundleSource(""); err == nil {
		t.Fatal("expected an error when base dir is empty; got nil")
	}
}

// TestFileCABundleSource_FeedsInjectorFailClosed wires the real source into the real
// caInjector: a ref with no drop must fail the create CLOSED end-to-end (no write
// reaches the trust-store writer). Uses an in-memory writer that records writes so the
// test can assert the fail-closed path never wrote.
func TestFileCABundleSource_FeedsInjectorFailClosed(t *testing.T) {
	src, err := NewFileCABundleSource(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileCABundleSource: %v", err)
	}
	w := &recordingTrustWriter{}
	inj, err := NewCAInjector(src, w)
	if err != nil {
		t.Fatalf("NewCAInjector: %v", err)
	}
	if err := inj.InjectCA(context.Background(), "/var/lib/ds/overlays/sess.qcow2", "no-drop-ref"); err == nil {
		t.Fatal("expected a fail-closed create abort when the bundle is undropped; got nil")
	}
	if w.writes != 0 {
		t.Errorf("trust-store writer was called %d times on the fail-closed path; want 0", w.writes)
	}
}

// recordingTrustWriter is an in-memory OverlayTrustStoreWriter that counts writes —
// enough to assert the fail-closed fetch path never reaches the write (D50, no guestfs).
type recordingTrustWriter struct {
	writes int
}

func (w *recordingTrustWriter) WriteTrustAnchor(_ context.Context, _, _ string, _ []byte) error {
	w.writes++
	return nil
}

func (w *recordingTrustWriter) HasTrustAnchor(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}
