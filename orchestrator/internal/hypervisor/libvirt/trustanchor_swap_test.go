// SPDX-License-Identifier: Apache-2.0

// Offline tests for the posture-(b) cred-swap guest-CA delivery in the live
// (host-side) OverlayTrustStoreWriter: when DS_GUEST_INTERCEPT_CA_PATH names a
// FIXED in-guest cert path (orchestrator-boot-l2.sh SWAP_GUEST_CA_PATH, reconciled
// to loop-1's NODE_EXTRA_CA_CERTS), the writer uploads the orchestrator-minted CA
// to that one literal file instead of the per-session system-trust anchor, and
// skips update-ca-certificates (Node reads the literal cert). These assert the
// libguestfs command CONSTRUCTION + the read-back probe WITHOUT a real
// virt-customize/virt-cat (the package recordingRunner, no /dev/kvm). The DEFAULT
// (empty guestCAPath) must stay BYTE-IDENTICAL to the system-trust delivery, and
// the fail-closed contract is unchanged. No live material (D50).

package libvirt

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const swapGuestCAPath = "/etc/ds/intercept-ca.crt" // the loop-1 NODE_EXTRA_CA_CERTS path

func newSwapWriter(rr *recordingRunner) *liveTrustStoreWriter {
	return &liveTrustStoreWriter{customizeBin: "virt-customize", catBin: "virt-cat", guestCAPath: swapGuestCAPath, run: rr}
}

// The fixed-path upload --mkdir's the parent, uploads to the literal NODE_EXTRA_CA_CERTS
// path, and does NOT run update-ca-certificates (Node reads the file directly).
func TestTrustAnchorUploadArgsAt_FixedPathSwapMode(t *testing.T) {
	name, args := trustAnchorUploadArgsAt("virt-customize", "/img/sess-1.qcow2", "/tmp/ca.pem", swapGuestCAPath, false)
	if name != "virt-customize" {
		t.Fatalf("bin = %q", name)
	}
	got := strings.Join(args, " ")
	want := "-a /img/sess-1.qcow2 --mkdir /etc/ds --upload /tmp/ca.pem:/etc/ds/intercept-ca.crt"
	if got != want {
		t.Fatalf("fixed-path upload args =\n  %q\nwant\n  %q", got, want)
	}
	if strings.Contains(got, "update-ca-certificates") {
		t.Fatal("fixed-path (NODE_EXTRA_CA_CERTS) delivery must NOT run update-ca-certificates")
	}
}

// The DEFAULT system-trust upload is byte-identical: per-session anchor dir +
// update-ca-certificates, no --mkdir of an arbitrary parent.
func TestTrustAnchorUploadArgs_DefaultByteIdentical(t *testing.T) {
	name, args := trustAnchorUploadArgs("virt-customize", "/img/sess-1.qcow2", "/tmp/ca.pem", "sess-1")
	if name != "virt-customize" {
		t.Fatalf("bin = %q", name)
	}
	got := strings.Join(args, " ")
	want := "-a /img/sess-1.qcow2 --upload /tmp/ca.pem:/usr/local/share/ca-certificates/ds-interception-sess-1.crt --run-command update-ca-certificates"
	if got != want {
		t.Fatalf("default upload args =\n  %q\nwant\n  %q", got, want)
	}
	if strings.Contains(got, "--mkdir") {
		t.Fatal("default system-trust delivery must not --mkdir an arbitrary parent")
	}
}

func TestTrustAnchorCatArgsAt_FixedPath(t *testing.T) {
	name, args := trustAnchorCatArgsAt("virt-cat", "/img/sess-1.qcow2", swapGuestCAPath)
	if name != "virt-cat" {
		t.Fatalf("bin = %q", name)
	}
	got := strings.Join(args, " ")
	want := "-a /img/sess-1.qcow2 /etc/ds/intercept-ca.crt"
	if got != want {
		t.Fatalf("fixed-path cat args = %q, want %q", got, want)
	}
}

// anchorGuestPath dispatches: empty guestCAPath -> per-session system-trust path;
// set guestCAPath -> the one fixed path for every session (reconciled to loop-1).
func TestAnchorGuestPath_Dispatch(t *testing.T) {
	def := &liveTrustStoreWriter{}
	if got := def.anchorGuestPath("sess-A"); got != "/usr/local/share/ca-certificates/ds-interception-sess-A.crt" {
		t.Fatalf("default anchor path = %q", got)
	}
	if !def.systemTrust() {
		t.Fatal("default writer must report systemTrust()=true")
	}
	swap := &liveTrustStoreWriter{guestCAPath: swapGuestCAPath}
	if got := swap.anchorGuestPath("sess-A"); got != swapGuestCAPath {
		t.Fatalf("swap anchor path = %q, want fixed %q", got, swapGuestCAPath)
	}
	if got := swap.anchorGuestPath("sess-B"); got != swapGuestCAPath {
		t.Fatalf("swap anchor path is per-session %q; must be the one fixed path", got)
	}
	if swap.systemTrust() {
		t.Fatal("swap writer must report systemTrust()=false")
	}
}

// GuestInterceptCAPathFromEnv: trims, requires absolute, fails SAFE to the default.
func TestGuestInterceptCAPathFromEnv(t *testing.T) {
	cases := map[string]string{
		"":                         "",
		"  ":                       "",
		"/etc/ds/intercept-ca.crt": "/etc/ds/intercept-ca.crt",
		"  /etc/ds/ca.crt  ":       "/etc/ds/ca.crt",
		"relative/ca.crt":          "",               // non-absolute -> safe default
		"/etc/ds/../ds/ca.crt":     "/etc/ds/ca.crt", // cleaned
	}
	for in, want := range cases {
		t.Setenv(EnvGuestInterceptCAPath, in)
		if got := GuestInterceptCAPathFromEnv(); got != want {
			t.Errorf("GuestInterceptCAPathFromEnv(%q) = %q, want %q", in, got, want)
		}
	}
}

// NewLiveTrustStoreWriter reads the env ONCE at construction: set -> the writer
// delivers to the fixed path; unset -> byte-identical default.
func TestNewLiveTrustStoreWriter_ReadsEnvOnce(t *testing.T) {
	t.Setenv(EnvGuestInterceptCAPath, swapGuestCAPath)
	w, err := NewLiveTrustStoreWriter()
	if err != nil {
		t.Fatalf("NewLiveTrustStoreWriter: %v", err)
	}
	lw, ok := w.(*liveTrustStoreWriter)
	if !ok {
		t.Fatalf("unexpected writer type %T", w)
	}
	if lw.guestCAPath != swapGuestCAPath {
		t.Fatalf("guestCAPath = %q, want %q", lw.guestCAPath, swapGuestCAPath)
	}
	// A later env change must NOT affect the already-constructed writer.
	t.Setenv(EnvGuestInterceptCAPath, "/etc/ds/other.crt")
	if got := lw.anchorGuestPath("s"); got != swapGuestCAPath {
		t.Fatalf("writer path changed after construction: %q", got)
	}
}

// The swap-mode write uploads ONLY the public CA cert to the fixed path, with no
// update-ca-certificates, and refuses an empty PEM (fail-closed, no run).
func TestSwapWriteTrustAnchor_FixedPathUploadOnly(t *testing.T) {
	caPEM := mintCAPEM(t)
	rr := &recordingRunner{outputs: []string{""}, errs: []error{nil}}
	if err := newSwapWriter(rr).WriteTrustAnchor(context.Background(), "sess-X", "/img/sess-X.qcow2", caPEM); err != nil {
		t.Fatalf("WriteTrustAnchor (swap): %v", err)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("want 1 virt-customize call, got %d", len(rr.calls))
	}
	got := strings.Join(rr.calls[0], " ")
	for _, want := range []string{"virt-customize", "-a /img/sess-X.qcow2", "--mkdir /etc/ds", ":/etc/ds/intercept-ca.crt"} {
		if !strings.Contains(got, want) {
			t.Fatalf("swap argv missing %q; got: %s", want, got)
		}
	}
	if strings.Contains(got, "update-ca-certificates") {
		t.Fatal("swap fixed-path write must not run update-ca-certificates")
	}
	// The uploaded bytes are the PUBLIC cert PEM (the host temp file), never the key.
	if strings.Contains(got, "PRIVATE KEY") || strings.Contains(got, ".key") {
		t.Fatal("swap write must never reference a private key")
	}
}

func TestSwapWriteTrustAnchor_EmptyPEMFailsClosedNoRun(t *testing.T) {
	rr := &recordingRunner{}
	if err := newSwapWriter(rr).WriteTrustAnchor(context.Background(), "s", "/img/s.qcow2", nil); err == nil {
		t.Fatal("want error on empty PEM in swap mode")
	}
	if len(rr.calls) != 0 {
		t.Fatalf("empty PEM must not invoke virt-customize; got %d calls", len(rr.calls))
	}
}

// HasTrustAnchor in swap mode reads the FIXED path and matches by fingerprint.
func TestSwapHasTrustAnchor_ReadsFixedPath(t *testing.T) {
	caPEM := mintCAPEM(t)
	fp, err := validateCABundle(caPEM)
	if err != nil {
		t.Fatalf("validateCABundle: %v", err)
	}
	rr := &recordingRunner{outputs: []string{string(caPEM)}, errs: []error{nil}}
	present, err := newSwapWriter(rr).HasTrustAnchor(context.Background(), "sess-1", "/img/sess-1.qcow2", fp)
	if err != nil {
		t.Fatalf("HasTrustAnchor (swap): %v", err)
	}
	if !present {
		t.Fatal("want present=true for the installed matching anchor at the fixed path")
	}
	if got := strings.Join(rr.calls[0], " "); !strings.Contains(got, "/etc/ds/intercept-ca.crt") {
		t.Fatalf("virt-cat read wrong path (must be the fixed NODE_EXTRA_CA_CERTS path): %s", got)
	}
}

// End-to-end: the production caInjector drives the swap-mode live writer through
// fetch->has?(absent)->write->verify?(present), and a retry converges idempotently
// (has?(present) -> short-circuit, NO second write) — the SAME fail-closed sequence
// as the default path, now landing at the reconciled fixed guest path.
func TestInjectCA_DrivesSwapWriterEndToEnd(t *testing.T) {
	caPEM := mintCAPEM(t)
	rr := &recordingRunner{
		outputs: []string{
			"virt-cat: /etc/ds/intercept-ca.crt: No such file or directory", // probe #1: absent
			"",            // virt-customize write: ok
			string(caPEM), // verify probe: present
			string(caPEM), // retry probe: present -> short-circuit
		},
		errs: []error{errors.New("exit 1"), nil, nil, nil},
	}
	w := newSwapWriter(rr)
	inj := newTestInjector(t, &fakeCABundleSource{pem: caPEM}, w)

	if err := inj.InjectCA(context.Background(), "/img/sess-e2e.qcow2", "ca-ref-1"); err != nil {
		t.Fatalf("first InjectCA (swap): %v", err)
	}
	if err := inj.InjectCA(context.Background(), "/img/sess-e2e.qcow2", "ca-ref-1"); err != nil {
		t.Fatalf("idempotent retry InjectCA (swap): %v", err)
	}
	writes := 0
	for _, c := range rr.calls {
		if len(c) > 0 && strings.Contains(c[0], "customize") {
			writes++
		}
	}
	if writes != 1 {
		t.Fatalf("want exactly 1 virt-customize write across 2 swap injects, got %d", writes)
	}
	// The write landed at the fixed guest path, not the per-session system-trust dir.
	for _, c := range rr.calls {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "customize") && !strings.Contains(joined, "/etc/ds/intercept-ca.crt") {
			t.Fatalf("swap write did not target the fixed guest path: %s", joined)
		}
	}
}

// Fail-closed in swap mode: a missing/empty bundle aborts the inject before any
// write (the swap-mode boot must not proceed without the trust anchor).
func TestInjectCA_SwapFailsClosedOnEmptyBundle(t *testing.T) {
	w := newSwapWriter(&recordingRunner{})
	inj := newTestInjector(t, &fakeCABundleSource{pem: []byte{}}, w)
	if err := inj.InjectCA(context.Background(), "/img/s.qcow2", "ca-ref"); err == nil {
		t.Fatal("an empty CA bundle must fail the swap-mode inject closed")
	}
}
