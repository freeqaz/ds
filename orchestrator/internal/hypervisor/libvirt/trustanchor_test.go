// SPDX-License-Identifier: Apache-2.0

// Offline tests for the live (host-side) OverlayTrustStoreWriter. They inject the
// package's recordingRunner so the libguestfs command CONSTRUCTION + result
// handling are asserted WITHOUT a real virt-customize/virt-cat or a host with
// /dev/kvm — the real-overlay behavior is grounded separately on the ESXi/KVM box
// (~/ds/ground-cainject.sh, taskdb 01KV638T). Always-compiled (no build tag, the
// live.go convention); reuses the package CA-mint + injector helpers (D50, no
// live material).

package libvirt

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newLiveWriter(rr *recordingRunner) *liveTrustStoreWriter {
	return &liveTrustStoreWriter{customizeBin: "virt-customize", catBin: "virt-cat", run: rr}
}

func TestTrustAnchorUploadArgs(t *testing.T) {
	name, args := trustAnchorUploadArgs("virt-customize", "/img/sess-1.qcow2", "/tmp/ca.pem", "sess-1")
	if name != "virt-customize" {
		t.Fatalf("bin = %q", name)
	}
	got := strings.Join(args, " ")
	want := "-a /img/sess-1.qcow2 --upload /tmp/ca.pem:/usr/local/share/ca-certificates/ds-interception-sess-1.crt --run-command update-ca-certificates"
	if got != want {
		t.Fatalf("upload args =\n  %q\nwant\n  %q", got, want)
	}
}

func TestTrustAnchorCatArgs(t *testing.T) {
	name, args := trustAnchorCatArgs("virt-cat", "/img/sess-1.qcow2", "sess-1")
	if name != "virt-cat" {
		t.Fatalf("bin = %q", name)
	}
	got := strings.Join(args, " ")
	want := "-a /img/sess-1.qcow2 /usr/local/share/ca-certificates/ds-interception-sess-1.crt"
	if got != want {
		t.Fatalf("cat args = %q, want %q", got, want)
	}
}

func TestSanitizeAnchorComponent(t *testing.T) {
	cases := map[string]string{
		"01HZ-abc_def.9": "01HZ-abc_def.9",
		"a/b/../c":       "a_b_.._c",
		"x;rm -rf":       "x_rm_-rf",
		"":               "session",
	}
	for in, want := range cases {
		if got := sanitizeAnchorComponent(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteTrustAnchor_InvokesUploadAndRefresh(t *testing.T) {
	caPEM := mintCAPEM(t)
	rr := &recordingRunner{outputs: []string{""}, errs: []error{nil}}
	if err := newLiveWriter(rr).WriteTrustAnchor(context.Background(), "sess-ABC", "/img/sess-ABC.qcow2", caPEM); err != nil {
		t.Fatalf("WriteTrustAnchor: %v", err)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(rr.calls))
	}
	got := strings.Join(rr.calls[0], " ")
	for _, want := range []string{
		"virt-customize", "-a /img/sess-ABC.qcow2",
		":/usr/local/share/ca-certificates/ds-interception-sess-ABC.crt",
		"--run-command update-ca-certificates",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("argv missing %q; got: %s", want, got)
		}
	}
}

func TestWriteTrustAnchor_EmptyPEMFailsClosedNoRun(t *testing.T) {
	rr := &recordingRunner{}
	if err := newLiveWriter(rr).WriteTrustAnchor(context.Background(), "s", "/img/s.qcow2", nil); err == nil {
		t.Fatal("want error on empty PEM")
	}
	if len(rr.calls) != 0 {
		t.Fatalf("empty PEM must not invoke virt-customize; got %d calls", len(rr.calls))
	}
}

func TestWriteTrustAnchor_EmptyOverlayFailsClosed(t *testing.T) {
	rr := &recordingRunner{}
	if err := newLiveWriter(rr).WriteTrustAnchor(context.Background(), "s", "", mintCAPEM(t)); err == nil {
		t.Fatal("want error on empty overlay path")
	}
}

func TestWriteTrustAnchor_GuestfsErrorSurfaces(t *testing.T) {
	rr := &recordingRunner{outputs: []string{"libguestfs: error: appliance closed"}, errs: []error{errors.New("exit 1")}}
	if err := newLiveWriter(rr).WriteTrustAnchor(context.Background(), "s", "/img/s.qcow2", mintCAPEM(t)); err == nil {
		t.Fatal("want error when virt-customize fails")
	}
}

func TestHasTrustAnchor_PresentMatchingFingerprint(t *testing.T) {
	caPEM := mintCAPEM(t)
	fp, err := validateCABundle(caPEM)
	if err != nil {
		t.Fatalf("validateCABundle: %v", err)
	}
	rr := &recordingRunner{outputs: []string{string(caPEM)}, errs: []error{nil}}
	present, err := newLiveWriter(rr).HasTrustAnchor(context.Background(), "sess-1", "/img/sess-1.qcow2", fp)
	if err != nil {
		t.Fatalf("HasTrustAnchor: %v", err)
	}
	if !present {
		t.Fatal("want present=true for the installed matching anchor")
	}
	if got := strings.Join(rr.calls[0], " "); !strings.Contains(got, "/usr/local/share/ca-certificates/ds-interception-sess-1.crt") {
		t.Fatalf("virt-cat read wrong path: %s", got)
	}
}

func TestHasTrustAnchor_PresentDifferentFingerprint(t *testing.T) {
	wantFP, err := validateCABundle(mintCAPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	otherPEM := mintCAPEM(t)
	otherFP, _ := validateCABundle(otherPEM)
	if wantFP == otherFP {
		t.Fatal("distinct CAs must have distinct fingerprints")
	}
	rr := &recordingRunner{outputs: []string{string(otherPEM)}, errs: []error{nil}}
	present, err := newLiveWriter(rr).HasTrustAnchor(context.Background(), "s", "/img/s.qcow2", wantFP)
	if err != nil {
		t.Fatalf("HasTrustAnchor: %v", err)
	}
	if present {
		t.Fatal("want present=false when the installed anchor's fingerprint differs")
	}
}

func TestHasTrustAnchor_AbsentIsNormalFalse(t *testing.T) {
	fp, _ := validateCABundle(mintCAPEM(t))
	rr := &recordingRunner{
		outputs: []string{"virt-cat: /usr/local/share/ca-certificates/ds-interception-s.crt: No such file or directory"},
		errs:    []error{errors.New("exit 1")},
	}
	present, err := newLiveWriter(rr).HasTrustAnchor(context.Background(), "s", "/img/s.qcow2", fp)
	if err != nil {
		t.Fatalf("absent must be (false,nil), got err=%v", err)
	}
	if present {
		t.Fatal("want present=false when the anchor file is absent")
	}
}

func TestHasTrustAnchor_ProbeFailureFailsClosed(t *testing.T) {
	fp, _ := validateCABundle(mintCAPEM(t))
	rr := &recordingRunner{
		outputs: []string{"libguestfs: error: could not open disk image: Permission denied"},
		errs:    []error{errors.New("exit 1")},
	}
	present, err := newLiveWriter(rr).HasTrustAnchor(context.Background(), "s", "/img/s.qcow2", fp)
	if err == nil {
		t.Fatal("a non-absent probe failure must be fail-closed (error)")
	}
	if present {
		t.Fatal("present must be false on a probe failure")
	}
}

func TestHasTrustAnchor_JunkFileIsAbsent(t *testing.T) {
	fp, _ := validateCABundle(mintCAPEM(t))
	rr := &recordingRunner{outputs: []string{"not a pem at all"}, errs: []error{nil}}
	present, err := newLiveWriter(rr).HasTrustAnchor(context.Background(), "s", "/img/s.qcow2", fp)
	if err != nil {
		t.Fatalf("junk file should be a benign absent, got err=%v", err)
	}
	if present {
		t.Fatal("want present=false for an unparseable anchor file")
	}
}

// TestInjectCA_DrivesLiveWriterEndToEnd proves the live writer satisfies the
// production caInjector contract: the injector's fetch→has?(absent)→write→
// verify?(present) sequence works against the live writer, and a retry converges
// idempotently (has?(present) → short-circuit, NO second write). recordingRunner
// replies in InjectCA's fixed call order: virt-cat(absent), virt-customize(ok),
// virt-cat(present), then virt-cat(present) for the retry.
func TestInjectCA_DrivesLiveWriterEndToEnd(t *testing.T) {
	caPEM := mintCAPEM(t)
	rr := &recordingRunner{
		outputs: []string{
			"virt-cat: ...: No such file or directory", // probe #1: absent
			"",            // virt-customize write: ok
			string(caPEM), // verify probe: present
			string(caPEM), // retry probe: present → short-circuit
		},
		errs: []error{errors.New("exit 1"), nil, nil, nil},
	}
	w := newLiveWriter(rr)
	inj := newTestInjector(t, &fakeCABundleSource{pem: caPEM}, w)

	if err := inj.InjectCA(context.Background(), "/img/sess-e2e.qcow2", "ca-ref-1"); err != nil {
		t.Fatalf("first InjectCA: %v", err)
	}
	if err := inj.InjectCA(context.Background(), "/img/sess-e2e.qcow2", "ca-ref-1"); err != nil {
		t.Fatalf("idempotent retry InjectCA: %v", err)
	}
	// Exactly ONE virt-customize across both injects (the retry must not rewrite).
	writes := 0
	for _, c := range rr.calls {
		if len(c) > 0 && strings.Contains(c[0], "customize") {
			writes++
		}
	}
	if writes != 1 {
		t.Fatalf("want exactly 1 virt-customize write across 2 injects, got %d", writes)
	}
}
