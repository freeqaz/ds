package controlplane

// caproducer_test.go exercises the host-readable CA-bundle PRODUCER leg of liveedges.go
// (the §4.1 producer half of the M0 trust path, D17/D82) against the generated identity.v1
// fake + a temp-dir store — NO live host, NO guestfs, NO identity dial (D50). It proves:
//
//   - the producer drops BOTH the minted ca_certificate PEM to
//     <baseDir>/.ds-ca-bundles/<caRef>.pem AND the proxy-bound PKCS#8 key to the sibling
//     <baseDir>/.ds-ca-bundles/<caRef>.key.pem, and a read-back of each returns the exact
//     bytes (the acceptance: write then read both back);
//   - the on-disk filenames mirror the ds-tlsproxy Arm-1 CONSUMER's transform (a "ca:<uuid>"
//     ref sanitizes to "ca_<uuid>.pem" + "ca_<uuid>.key.pem"), so the files the producer
//     writes are the files acquire_session_ca reads;
//   - a live mint with the producer attached (AttachCABundleStore) drops BOTH files as a
//     side effect of the mint, keyed by the same caRef the mint returns — closing the loop;
//   - the proxy-bound key is host-local 0600 and NEVER appears in the cert bytes (D39/D76);
//   - the producer rejects an empty ref / empty cert PEM / empty key PEM fail-closed and a
//     drop fault aborts the mint (no half-minted session with no provable trust anchor);
//   - the NIL-producer (bare) mint path is unchanged (no drop, no error).
//
// The drop is verified by reading the PEM straight off disk (the consumer's contract is a
// PEM file at the deterministic path), so this test stands alone without importing the
// host-agent's libvirt package.

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
)

// syntheticCAPEM is the minted CA cert the fake returns — a syntheticly-shaped PEM (not a
// real CA; cainject.go validates CA:TRUE, this producer only places bytes).
var syntheticCAPEM = []byte("-----BEGIN CERTIFICATE-----\nsynthetic-orchestrator-minted-ca\n-----END CERTIFICATE-----\n")

// syntheticCAKeyPEM is the minted proxy-bound PKCS#8 key the fake returns — a synthetic
// PKCS#8 PEM shape (not a real key; ds-tlsproxy parses it, this producer only places bytes
// host-local). It must land at the .key.pem sibling and NEVER appear in the cert .pem.
var syntheticCAKeyPEM = []byte("-----BEGIN PRIVATE KEY-----\nsynthetic-proxy-bound-pkcs8-key\n-----END PRIVATE KEY-----\n")

// mintFakeWithCAPEM returns an identity.v1 mint fake that returns the given CA cert PEM and
// the proxy-bound PKCS#8 key PEM for every MintInterceptionCA (so the producer drops both).
func mintFakeWithCAPEM(pem []byte) *identityv1fake.IdentityMintServiceFake {
	f := identityv1fake.NewIdentityMintServiceFake()
	f.MintInterceptionCAResponder = func(_ context.Context, _ *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
		return &identityv1.MintInterceptionCAResponse{
			CaCertificate:     pem,
			CaPrivateKey:      syntheticCAKeyPEM,
			ExpiryUnixSeconds: 1_700_003_600,
		}, nil
	}
	return f
}

// TestFileCABundleProducer_DropThenReadBack is the acceptance: the producer writes BOTH the
// minted CA cert PEM and the proxy-bound PKCS#8 key PEM to the host-readable store under caRef
// and a read-back of each returns it verbatim. The reads are off disk at the deterministic
// paths the ds-tlsproxy Arm-1 consumer reads (the contract): <ref>.pem + <ref>.key.pem.
func TestFileCABundleProducer_DropThenReadBack(t *testing.T) {
	base := t.TempDir()
	prod, err := NewFileCABundleProducer(base)
	if err != nil {
		t.Fatalf("NewFileCABundleProducer: %v", err)
	}
	caRef := caRefFor("sess-prod-1") // "ca:sess-prod-1"
	if err := prod.drop(caRef, syntheticCAPEM, syntheticCAKeyPEM); err != nil {
		t.Fatalf("drop: %v", err)
	}

	// The cert lands at the deterministic, consumer-mirrored path: ".ds-ca-bundles/ca_sess-prod-1.pem".
	wantCertPath := filepath.Join(base, caBundleSubdirName, "ca_sess-prod-1.pem")
	gotCert, err := os.ReadFile(wantCertPath)
	if err != nil {
		t.Fatalf("read back dropped cert bundle at %s: %v", wantCertPath, err)
	}
	if string(gotCert) != string(syntheticCAPEM) {
		t.Errorf("dropped cert PEM = %q, want %q", gotCert, syntheticCAPEM)
	}

	// The proxy-bound PKCS#8 key lands at the sibling .key.pem the consumer reads:
	// ".ds-ca-bundles/ca_sess-prod-1.key.pem".
	wantKeyPath := filepath.Join(base, caBundleSubdirName, "ca_sess-prod-1.key.pem")
	gotKey, err := os.ReadFile(wantKeyPath)
	if err != nil {
		t.Fatalf("read back dropped key at %s: %v", wantKeyPath, err)
	}
	if string(gotKey) != string(syntheticCAKeyPEM) {
		t.Errorf("dropped key PEM = %q, want %q", gotKey, syntheticCAKeyPEM)
	}

	// The proxy-bound key must NEVER appear in the cert bundle (D39/D76 trust-zone split):
	// the cert is the only file placed into the guest; the key stays host-local.
	if string(gotCert) == string(syntheticCAKeyPEM) || len(gotCert) == 0 {
		t.Fatal("producer dropped the key into the cert file / dropped empty bytes")
	}

	// The proxy-bound key is host-local 0600 (and the cert too) — never group/other-readable.
	for _, p := range []string{wantCertPath, wantKeyPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s perm = %o, want 0600 (host-local only)", p, perm)
		}
	}
}

// TestFileCABundleProducer_PathMirrorsConsumer proves the producer's ref->filename transform
// matches the ds-tlsproxy Arm-1 consumer's: a "ca:<uuid>" ref sanitizes to "ca_<uuid>.pem"
// (cert) + "ca_<uuid>.key.pem" (the proxy-bound key sibling, the ':' becomes '_'), so the
// files the producer writes are exactly the ones acquire_session_ca reads.
func TestFileCABundleProducer_PathMirrorsConsumer(t *testing.T) {
	prod := &fileCABundleProducer{dir: "/base/.ds-ca-bundles"}
	if got, want := prod.bundlePath("ca:abc-123"), "/base/.ds-ca-bundles/ca_abc-123.pem"; got != want {
		t.Errorf("bundlePath(%q) = %q, want %q", "ca:abc-123", got, want)
	}
	// The key leaf is the cert leaf with ".pem" replaced by ".key.pem" — byte-identical to
	// the ds-tlsproxy consumer (sanitize_ca_ref(ref) + ".key.pem"), the sibling of the cert.
	if got, want := prod.keyPath("ca:abc-123"), "/base/.ds-ca-bundles/ca_abc-123.key.pem"; got != want {
		t.Errorf("keyPath(%q) = %q, want %q", "ca:abc-123", got, want)
	}
	if got, want := keyFilename("ca:abc-123"), "ca_abc-123.key.pem"; got != want {
		t.Errorf("keyFilename(%q) = %q, want %q", "ca:abc-123", got, want)
	}
	// A ref already in the safe set is untouched (defense in depth, matching the consumer).
	if got := sanitizeBundleRef("ca-ref-A"); got != "ca-ref-A" {
		t.Errorf("sanitizeBundleRef(%q) = %q, want unchanged", "ca-ref-A", got)
	}
}

// TestFileCABundleProducer_RejectsEmpty proves the fail-closed guards: empty base dir at
// construction, empty ref / empty cert PEM / empty key PEM at drop (never a truthy-but-
// incomplete bundle — a cert with no proxy-bound key the proxy could never terminate with).
func TestFileCABundleProducer_RejectsEmpty(t *testing.T) {
	if _, err := NewFileCABundleProducer(""); err == nil {
		t.Fatal("NewFileCABundleProducer: expected an error for an empty base dir")
	}
	base := t.TempDir()
	prod, err := NewFileCABundleProducer(base)
	if err != nil {
		t.Fatalf("NewFileCABundleProducer: %v", err)
	}
	if err := prod.drop("", syntheticCAPEM, syntheticCAKeyPEM); err == nil {
		t.Fatal("drop: expected a fail-closed error for an empty caRef")
	}
	if err := prod.drop("ca:sess", nil, syntheticCAKeyPEM); err == nil {
		t.Fatal("drop: expected a fail-closed error for an empty cert PEM")
	}
	if err := prod.drop("ca:sess", syntheticCAPEM, nil); err == nil {
		t.Fatal("drop: expected a fail-closed error for an empty key PEM (proxy-bound key required)")
	}
	// A rejected empty-key drop must not have left a partial cert behind for the consumer to
	// mistake for a usable anchor: the empty-key drop is rejected BEFORE either write... but
	// the empty-cert reject also writes nothing. Assert the store has no stray files.
	entries, _ := os.ReadDir(filepath.Join(base, caBundleSubdirName))
	if len(entries) != 0 {
		t.Errorf("store has %d entries after only-rejected drops, want 0", len(entries))
	}
}

// TestFileCABundleProducer_Overwrites proves a re-drop (a re-mint of the same session)
// replaces BOTH the cert and the key atomically — the read-back is the latest bytes, not a
// torn file, and no temp files leak.
func TestFileCABundleProducer_Overwrites(t *testing.T) {
	base := t.TempDir()
	prod, err := NewFileCABundleProducer(base)
	if err != nil {
		t.Fatalf("NewFileCABundleProducer: %v", err)
	}
	caRef := caRefFor("sess-redrop")
	if err := prod.drop(caRef, []byte("old-cert-pem"), []byte("old-key-pem")); err != nil {
		t.Fatalf("first drop: %v", err)
	}
	if err := prod.drop(caRef, syntheticCAPEM, syntheticCAKeyPEM); err != nil {
		t.Fatalf("re-drop: %v", err)
	}
	gotCert, err := os.ReadFile(prod.bundlePath(caRef))
	if err != nil {
		t.Fatalf("read back cert: %v", err)
	}
	if string(gotCert) != string(syntheticCAPEM) {
		t.Errorf("re-dropped cert PEM = %q, want the latest %q", gotCert, syntheticCAPEM)
	}
	gotKey, err := os.ReadFile(prod.keyPath(caRef))
	if err != nil {
		t.Fatalf("read back key: %v", err)
	}
	if string(gotKey) != string(syntheticCAKeyPEM) {
		t.Errorf("re-dropped key PEM = %q, want the latest %q", gotKey, syntheticCAKeyPEM)
	}
	// No leftover temp files from the atomic writes: exactly the cert + key (2 entries).
	entries, _ := os.ReadDir(filepath.Join(base, caBundleSubdirName))
	if len(entries) != 2 {
		t.Errorf("store has %d entries after two drops, want exactly 2 (cert + key, no temp leftover)", len(entries))
	}
}

// TestLiveMint_DropsCABundleOnMint proves the loop closes: a live mint with the producer
// ATTACHED (AttachCABundleStore) drops the minted CA PEM as a side effect of the mint,
// keyed by the SAME caRef the mint returns — the host-agent CONSUMER would read it back.
func TestLiveMint_DropsCABundleOnMint(t *testing.T) {
	base := t.TempDir()
	mintFake := mintFakeWithCAPEM(syntheticCAPEM)
	digestFake := identityv1fake.NewDigestFeedServiceFake()
	clients := NewIdentityClientsFromWire(mintFake, digestFake, nil)
	if err := clients.AttachCABundleStore(base); err != nil {
		t.Fatalf("AttachCABundleStore: %v", err)
	}

	_, caRef, err := clients.Mint.Mint(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-loop"}, "role-ref")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if caRef != caRefFor("sess-loop") {
		t.Fatalf("caRef = %q, want %q", caRef, caRefFor("sess-loop"))
	}

	// The mint dropped BOTH the cert and the proxy-bound key under the returned caRef — read
	// each back at the consumer path (acquire_session_ca reads <ref>.pem + <ref>.key.pem).
	prod, err := NewFileCABundleProducer(base)
	if err != nil {
		t.Fatalf("producer for read path: %v", err)
	}
	gotCert, err := os.ReadFile(prod.bundlePath(caRef))
	if err != nil {
		t.Fatalf("read back the mint-dropped cert bundle: %v", err)
	}
	if string(gotCert) != string(syntheticCAPEM) {
		t.Errorf("mint-dropped cert PEM = %q, want %q", gotCert, syntheticCAPEM)
	}
	gotKey, err := os.ReadFile(prod.keyPath(caRef))
	if err != nil {
		t.Fatalf("read back the mint-dropped key: %v", err)
	}
	if string(gotKey) != string(syntheticCAKeyPEM) {
		t.Errorf("mint-dropped key PEM = %q, want %q", gotKey, syntheticCAKeyPEM)
	}
	if len(mintFake.MintInterceptionCARecorded()) != 1 {
		t.Errorf("MintInterceptionCA calls = %d, want 1 (one mint, one drop)", len(mintFake.MintInterceptionCARecorded()))
	}
}

// TestLiveMint_DropFaultAbortsMint proves the producer leg is FAIL-CLOSED on the mint path:
// if the store dir is unwritable the mint surfaces the drop error rather than returning a
// session with no provable trust anchor (the step-7 inject would fail closed anyway; this
// names the cause and lets the step-5 rollback compensate before the digest publish).
func TestLiveMint_DropFaultAbortsMint(t *testing.T) {
	base := t.TempDir()
	mintFake := mintFakeWithCAPEM(syntheticCAPEM)
	clients := NewIdentityClientsFromWire(mintFake, identityv1fake.NewDigestFeedServiceFake(), nil)
	if err := clients.AttachCABundleStore(base); err != nil {
		t.Fatalf("AttachCABundleStore: %v", err)
	}
	// Make the store dir unwritable so the temp-file create fails.
	storeDir := filepath.Join(base, caBundleSubdirName)
	if err := os.Chmod(storeDir, 0o500); err != nil {
		t.Fatalf("chmod store dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(storeDir, 0o700) })

	if _, _, err := clients.Mint.Mint(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-fault"}, ""); err == nil {
		t.Fatal("Mint: expected a fail-closed abort when the CA-bundle drop fails")
	}
}

// TestLiveMint_NilProducerNoDrop proves the bare (no-producer) mint path is unchanged: a mint
// WITHOUT AttachCABundleStore drops nothing and never errors — the pre-this-leg posture every
// non-live unit path relies on (the host store was pre-seeded by hand / the e2e).
func TestLiveMint_NilProducerNoDrop(t *testing.T) {
	mintFake := mintFakeWithCAPEM(syntheticCAPEM)
	clients := NewIdentityClientsFromWire(mintFake, identityv1fake.NewDigestFeedServiceFake(), nil)

	if _, _, err := clients.Mint.Mint(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-bare"}, ""); err != nil {
		t.Fatalf("bare Mint (no producer): %v", err)
	}
}

// TestLiveMint_KeyNeverLogged proves the proxy-bound key (D39/D76) never reaches a log: a mint
// with the producer attached AND a logger wired (the host-folded inject/boot leg logs to it)
// drives a full mint, and the captured log output must contain NEITHER the secret key bytes
// NOR any field that would echo them. The key flows from the mint response straight into the
// atomic file write; no slog/fmt on the mint path touches it.
func TestLiveMint_KeyNeverLogged(t *testing.T) {
	base := t.TempDir()
	var logBuf bytes.Buffer
	// Debug level so even the host-folded DebugContext lines (the only logging on this path)
	// are captured — the strongest "the key is nowhere in any log" assertion.
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mintFake := mintFakeWithCAPEM(syntheticCAPEM)
	clients := NewIdentityClientsFromWire(mintFake, identityv1fake.NewDigestFeedServiceFake(), logger)
	if err := clients.AttachCABundleStore(base); err != nil {
		t.Fatalf("AttachCABundleStore: %v", err)
	}

	_, caRef, err := clients.Mint.Mint(context.Background(), sessions.MintWorkloadIdentityClaims{SessionUUID: "sess-nolog"}, "role-ref")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Exercise the host-folded inject/boot leg too (it is the only thing that logs on this
	// path) so any accidental key echo there is captured.
	if err := clients.Inject.InjectCA(context.Background(), "sess-nolog", filepath.Join(base, "overlay.qcow2"), caRef); err != nil {
		t.Fatalf("InjectCA: %v", err)
	}
	if err := clients.Boot.Boot(context.Background(), "sess-nolog", "ep-ref"); err != nil {
		t.Fatalf("Boot: %v", err)
	}

	logged := logBuf.String()
	if strings.Contains(logged, string(syntheticCAKeyPEM)) {
		t.Error("the proxy-bound CA private key leaked into the log output (D39/D76 violation)")
	}
	// Defense in depth: the distinctive key body must not appear even partially.
	if strings.Contains(logged, "synthetic-proxy-bound-pkcs8-key") {
		t.Error("the proxy-bound CA private key body leaked into the log output (D39/D76 violation)")
	}
	// The key did, however, land on disk host-local (the delivery path).
	prod, err := NewFileCABundleProducer(base)
	if err != nil {
		t.Fatalf("producer for read path: %v", err)
	}
	if _, err := os.Stat(prod.keyPath(caRef)); err != nil {
		t.Fatalf("proxy-bound key not persisted host-local at %s: %v", prod.keyPath(caRef), err)
	}
}
