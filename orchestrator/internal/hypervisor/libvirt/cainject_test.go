// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// ── test fakes for the two cainject sub-seams ───────────────────────────────
// These satisfy CABundleSource / OverlayTrustStoreWriter and are named distinctly
// from create_test.go's fakeCA (which satisfies the higher-level CAInjector seam)
// so both files compile into the one package-test binary.

// fakeCABundleSource serves a fixed PEM by ref, or errors. An empty pem with a
// nil err models the "ref resolves to an empty bundle" fail-closed case.
type fakeCABundleSource struct {
	pem      []byte
	fetchErr error
	calls    int
}

func (f *fakeCABundleSource) FetchCABundle(_ context.Context, _ string) ([]byte, error) {
	f.calls++
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.pem, nil
}

// fakeOverlayTrustStore is an in-memory stand-in for the host-side
// OverlayTrustStoreWriter: it records anchors per (sessionUUID|overlayPath) keyed
// by fingerprint, so HasTrustAnchor reflects WriteTrustAnchor. Knobs exercise the
// fail-closed paths: writeErr (write fails), hasErr (presence not provable), and
// silentNoOp (write returns nil but stores nothing — the silent-no-op case the
// verify-after-write guards).
type fakeOverlayTrustStore struct {
	anchors    map[string]map[string]bool // overlayKey → fingerprint → present
	writeErr   error
	hasErr     error
	silentNoOp bool
	writes     int
}

func newFakeStore() *fakeOverlayTrustStore {
	return &fakeOverlayTrustStore{anchors: map[string]map[string]bool{}}
}

func storeKey(sessionUUID, overlayPath string) string { return sessionUUID + "|" + overlayPath }

func (s *fakeOverlayTrustStore) WriteTrustAnchor(_ context.Context, sessionUUID, overlayPath string, caPEM []byte) error {
	s.writes++
	if s.writeErr != nil {
		return s.writeErr
	}
	if s.silentNoOp {
		// Report success but persist nothing — the write that silently no-ops.
		return nil
	}
	fp, err := validateCABundle(caPEM)
	if err != nil {
		// The injector only writes a validated bundle; if this fires the test
		// wired something inconsistent.
		return err
	}
	k := storeKey(sessionUUID, overlayPath)
	if s.anchors[k] == nil {
		s.anchors[k] = map[string]bool{}
	}
	s.anchors[k][fp] = true
	return nil
}

func (s *fakeOverlayTrustStore) HasTrustAnchor(_ context.Context, sessionUUID, overlayPath, anchorFingerprint string) (bool, error) {
	if s.hasErr != nil {
		return false, s.hasErr
	}
	return s.anchors[storeKey(sessionUUID, overlayPath)][anchorFingerprint], nil
}

// ── PEM test material (deterministic-enough; minted in-process, no network) ──

// mintCAPEM returns a self-signed CA certificate PEM (BasicConstraints CA:TRUE).
func mintCAPEM(t *testing.T) []byte {
	t.Helper()
	return mintCertPEM(t, true)
}

// mintLeafPEM returns a self-signed END-ENTITY certificate PEM (CA:FALSE) — a
// valid cert that is NOT a trust anchor, for the "bundle has no CA" fail-closed
// case.
func mintLeafPEM(t *testing.T) []byte {
	t.Helper()
	return mintCertPEM(t, false)
}

func mintCertPEM(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ds-test-interception"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(0, 0).Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestInjector(t *testing.T, src CABundleSource, w OverlayTrustStoreWriter) CAInjector {
	t.Helper()
	inj, err := NewCAInjector(src, w)
	if err != nil {
		t.Fatalf("NewCAInjector: %v", err)
	}
	return inj
}

const testOverlay = "/var/lib/ds/overlays/sess-1.qcow2"

// ── happy path: CA fetched, written, and verified present in the store ──────

func TestInjectCAHappyPath(t *testing.T) {
	caPEM := mintCAPEM(t)
	src := &fakeCABundleSource{pem: caPEM}
	store := newFakeStore()
	inj := newTestInjector(t, src, store)

	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err != nil {
		t.Fatalf("InjectCA happy path: %v", err)
	}
	if src.calls != 1 {
		t.Errorf("expected one bundle fetch, got %d", src.calls)
	}
	if store.writes != 1 {
		t.Errorf("expected one trust-store write, got %d", store.writes)
	}
	// The anchor must be provably present in the per-session overlay store.
	fp, err := validateCABundle(caPEM)
	if err != nil {
		t.Fatalf("validateCABundle: %v", err)
	}
	present, err := store.HasTrustAnchor(context.Background(), sessionFromOverlay(testOverlay), testOverlay, fp)
	if err != nil || !present {
		t.Errorf("CA anchor should be present in overlay store after inject (present=%v err=%v)", present, err)
	}
}

// ── idempotency: a second inject for the same session converges, no re-write ─

func TestInjectCAIdempotentOnSession(t *testing.T) {
	src := &fakeCABundleSource{pem: mintCAPEM(t)}
	store := newFakeStore()
	inj := newTestInjector(t, src, store)

	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err != nil {
		t.Fatalf("first inject: %v", err)
	}
	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err != nil {
		t.Fatalf("second (retry) inject should converge: %v", err)
	}
	// The retry must short-circuit on the already-present anchor — exactly one
	// write total, never a duplicate (the seams.go idempotency contract).
	if store.writes != 1 {
		t.Errorf("idempotent retry must not re-write: got %d writes, want 1", store.writes)
	}
}

// ── FAIL-CLOSED: the offline half of the acceptance ─────────────────────────
// Each of these simulated injection failures must return an error so the create
// aborts before boot, and (where applicable) must leave the trust store NOT
// half-written / NOT provably anchored.

func TestInjectCAFailsClosedOnFetchError(t *testing.T) {
	src := &fakeCABundleSource{fetchErr: errors.New("identity mint unreachable")}
	store := newFakeStore()
	inj := newTestInjector(t, src, store)

	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err == nil {
		t.Fatal("fetch error must fail the inject closed")
	}
	if store.writes != 0 {
		t.Error("a fetch failure must not touch the trust store (no half-write)")
	}
}

func TestInjectCAFailsClosedOnEmptyBundle(t *testing.T) {
	// Ref resolves but the bundle is empty — a missing trust anchor (doc 16 §4).
	src := &fakeCABundleSource{pem: []byte{}}
	store := newFakeStore()
	inj := newTestInjector(t, src, store)

	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err == nil {
		t.Fatal("an empty CA bundle must fail the inject closed")
	}
	if store.writes != 0 {
		t.Error("an empty bundle must not be written into the trust store")
	}
}

func TestInjectCAFailsClosedOnUnparseableBundle(t *testing.T) {
	src := &fakeCABundleSource{pem: []byte("-----BEGIN CERTIFICATE-----\nnot base64 der\n-----END CERTIFICATE-----\n")}
	store := newFakeStore()
	inj := newTestInjector(t, src, store)

	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err == nil {
		t.Fatal("an unparseable CA bundle must fail the inject closed")
	}
	if store.writes != 0 {
		t.Error("an unparseable bundle must not be written into the trust store")
	}
}

func TestInjectCAFailsClosedOnNonCABundle(t *testing.T) {
	// A valid certificate that is NOT a CA is not a trust anchor.
	src := &fakeCABundleSource{pem: mintLeafPEM(t)}
	store := newFakeStore()
	inj := newTestInjector(t, src, store)

	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err == nil {
		t.Fatal("a leaf-only (non-CA) bundle must fail the inject closed")
	}
	if store.writes != 0 {
		t.Error("a non-CA bundle must not be written into the trust store")
	}
}

func TestInjectCAFailsClosedOnWriteError(t *testing.T) {
	src := &fakeCABundleSource{pem: mintCAPEM(t)}
	store := newFakeStore()
	store.writeErr = errors.New("guestfs mount failed")
	inj := newTestInjector(t, src, store)

	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err == nil {
		t.Fatal("a trust-store write failure must fail the inject closed")
	}
	// The store is not provably anchored — the create must abort before boot.
	fp, _ := validateCABundle(src.pem)
	present, _ := store.HasTrustAnchor(context.Background(), sessionFromOverlay(testOverlay), testOverlay, fp)
	if present {
		t.Error("a failed write must leave the trust store without a provable anchor")
	}
}

func TestInjectCAFailsClosedOnSilentNoOpWrite(t *testing.T) {
	// The write reports success but persists nothing — the verify-after-write
	// guard must catch this and fail the create closed (no boot on empty anchor).
	src := &fakeCABundleSource{pem: mintCAPEM(t)}
	store := newFakeStore()
	store.silentNoOp = true
	inj := newTestInjector(t, src, store)

	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err == nil {
		t.Fatal("a write that silently no-ops must fail the inject closed (verify-after-write)")
	}
}

func TestInjectCAFailsClosedOnProbeError(t *testing.T) {
	src := &fakeCABundleSource{pem: mintCAPEM(t)}
	store := newFakeStore()
	store.hasErr = errors.New("trust-store probe failed")
	inj := newTestInjector(t, src, store)

	if err := inj.InjectCA(context.Background(), testOverlay, "ca-ref"); err == nil {
		t.Fatal("an unprovable trust-store probe must fail the inject closed")
	}
}

func TestInjectCAFailsClosedOnEmptyInputs(t *testing.T) {
	inj := newTestInjector(t, &fakeCABundleSource{pem: mintCAPEM(t)}, newFakeStore())
	if err := inj.InjectCA(context.Background(), "", "ca-ref"); err == nil {
		t.Error("an empty overlay path must fail closed")
	}
	if err := inj.InjectCA(context.Background(), testOverlay, ""); err == nil {
		t.Error("an empty CA bundle ref must fail closed")
	}
}

// ── construction guards ─────────────────────────────────────────────────────

func TestNewCAInjectorRejectsNilSeams(t *testing.T) {
	if _, err := NewCAInjector(nil, newFakeStore()); err == nil {
		t.Error("nil CA bundle source must be rejected")
	}
	if _, err := NewCAInjector(&fakeCABundleSource{}, nil); err == nil {
		t.Error("nil overlay trust-store writer must be rejected")
	}
}

// ── the production injector satisfies the CAInjector seam, so NewHostAgent ───
//    can take it directly and the full create path aborts on a fail-closed CA.

func TestProductionInjectorWiresIntoCreatePathFailClosed(t *testing.T) {
	// A production injector backed by a source that errors: when wired into the
	// HostAgent, the step-7 inject fails closed and the create aborts before boot.
	src := &fakeCABundleSource{fetchErr: errors.New("mint unreachable")}
	prodCA := newTestInjector(t, src, newFakeStore())

	booter := &fakeBooter{}
	h := newTestAgent(t, &fakeAttach{}, &fakeOverlay{}, prodCA, booter, &fakeGate{acked: true, fresh: true})

	_, err := h.CreateSession(context.Background(), goodReq())
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %v", err)
	}
	if ce.Step != StepOverlay {
		t.Errorf("a fail-closed production inject should surface at StepOverlay, got %s", ce.Step)
	}
	if len(booter.booted) != 0 {
		t.Error("the create must not boot when the production CA inject fails closed (D17)")
	}
	if ce.OverlayPath == "" || !ce.HasBinding {
		t.Error("step-7 failure must surface overlay + binding for rollback")
	}
}

func TestProductionInjectorHappyPathInCreate(t *testing.T) {
	// A production injector backed by a real CA + in-memory store drives the
	// step-7 inject to success, so the create proceeds to a routable session.
	src := &fakeCABundleSource{pem: mintCAPEM(t)}
	prodCA := newTestInjector(t, src, newFakeStore())

	h := newTestAgent(t, &fakeAttach{}, &fakeOverlay{}, prodCA, &fakeBooter{}, &fakeGate{acked: true, fresh: true})
	res, err := h.CreateSession(context.Background(), goodReq())
	if err != nil {
		t.Fatalf("create with production injector should succeed: %v", err)
	}
	if !res.Routable {
		t.Error("create with a successful CA inject should be routable")
	}
}
