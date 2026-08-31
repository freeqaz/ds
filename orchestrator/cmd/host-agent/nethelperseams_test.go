// SPDX-License-Identifier: Apache-2.0

// nethelperseams_test.go pins the D148 ROOT-HELPER re-key at the composition
// root: WHICH primitive each (gate, helper) combination selects, the exact
// argv+stdin the helper-backed primitive forks (byte-parity with the retired cgo
// liveAttach), the fail-closed bring-up posture, the per-admission readiness
// fold, and the compile-refusal that keeps the ds-nft cgo edge out of this
// binary forever.
//
// The helper is faked by a TempDir shell script that logs `<op>\t<stdin-json>`
// per invocation and answers a canned Result line — so the tests exercise the
// REAL fork/stdin/Result path of nethelperclient without any privilege, cgo, or
// kernel touch.

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nethelper/nethelperclient"
)

// fakeHelper writes an executable stand-in for the setcap'd helper into a temp
// dir. resultFields is spliced into the canned Result line AFTER the version+op
// pair (the client cross-checks both, so the op is always echoed from argv).
// It returns the ABSOLUTE helper path and the invocation-log path.
func fakeHelper(t *testing.T, resultFields string) (helperPath, logPath string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	dir := t.TempDir()
	helperPath = filepath.Join(dir, "ds-nethelper")
	logPath = filepath.Join(dir, "invocations.log")

	script := "#!/bin/sh\n" +
		"{ printf '%s\\t' \"$1\"; cat | tr -d '\\n'; printf '\\n'; } >> " + logPath + "\n" +
		"printf '{\"v\":1,\"op\":\"%s\"," + resultFields + "}\\n' \"$1\"\n" +
		"exit 0\n"
	if err := os.WriteFile(helperPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake helper: %v", err)
	}
	return helperPath, logPath
}

// fakeHelperClient builds a Client over a fake helper answering resultFields.
func fakeHelperClient(t *testing.T, resultFields string) (*nethelperclient.Client, string) {
	t.Helper()
	path, logPath := fakeHelper(t, resultFields)
	c, err := nethelperclient.New(path)
	if err != nil {
		t.Fatalf("nethelperclient.New(%q): %v", path, err)
	}
	return c, logPath
}

// invocations reads the fake helper's log as ordered (op, paramsJSON) pairs.
func invocations(t *testing.T, logPath string) [][2]string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read helper invocation log: %v", err)
	}
	var out [][2]string
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		op, params, _ := strings.Cut(line, "\t")
		out = append(out, [2]string{op, params})
	}
	return out
}

// Canned probe postures.
const (
	// probeReady is the correctly `+eip`-installed live helper.
	probeReady = `"ok":true,"code":"OK","built":true,"cap_net_admin_effective":true,"cap_net_admin_inheritable":true,"ambient_raise_ok":true,"cap_net_admin":true`
	// probeEpOnly is THE TRAP: effective-green (a naive one-field check passes)
	// but not inheritable, so every ip/nft child ds-nft execs is stranded.
	probeEpOnly = `"ok":true,"code":"OK","built":true,"cap_net_admin_effective":true,"cap_net_admin_inheritable":false,"ambient_raise_ok":false,"cap_net_admin":true`
	// probeStub is a helper built WITHOUT -tags nftgatelive: it validates
	// perfectly and performs nothing.
	probeStub = `"ok":true,"code":"OK","built":false,"cap_net_admin_effective":true,"cap_net_admin_inheritable":true,"ambient_raise_ok":true,"cap_net_admin":true`
	// okResult is the success line every non-probe verb answers.
	okResult = `"ok":true,"code":"OK"`
)

// ── selector: which primitive each (gate, helper) combination picks ──────────

// TestNewAttachPrimitiveOfflineIsDeferred: off DS_HOSTAGENT_LIVE the selector
// must return the no-touch stand-in EVEN WITH a perfectly good helper client —
// an offline daemon's create path stays byte-identical to today (no fork, no
// kernel touch), exactly as the pre-D148 cgo selector behaved.
func TestNewAttachPrimitiveOfflineIsDeferred(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate OFF
	c, logPath := fakeHelperClient(t, okResult)

	prim := newAttachPrimitive(c)
	if _, ok := prim.(deferredAttach); !ok {
		t.Fatalf("gate-off selector returned %T, want deferredAttach", prim)
	}
	if err := prim.CreateTap(context.Background(), libvirt.Binding{TapName: "dstap-7", HostSessionIndex: 7}); err != nil {
		t.Fatalf("deferred CreateTap must be a no-op success, got %v", err)
	}
	if _, err := os.Stat(logPath); err == nil {
		t.Error("gate-off path FORKED the helper; the offline create path must touch nothing")
	}
}

// TestNewAttachPrimitiveLiveWithoutHelperIsDeferred: live but NO helper
// configured (-nethelper-path empty ⇒ nil client) keeps the deferred no-touch
// attach. This is the SLIRP-direct live MVP posture and must NOT be fatal
// (main.go scopes fatality to a helper path that IS set but is not Ready).
func TestNewAttachPrimitiveLiveWithoutHelperIsDeferred(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "1") // gate ON

	prim := newAttachPrimitive(nil)
	if _, ok := prim.(deferredAttach); !ok {
		t.Fatalf("live-without-helper selector returned %T, want deferredAttach", prim)
	}
}

// TestNewAttachPrimitiveLiveWithHelperIsHelperBacked is the positive twin.
func TestNewAttachPrimitiveLiveWithHelperIsHelperBacked(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "1") // gate ON
	c, _ := fakeHelperClient(t, okResult)

	prim := newAttachPrimitive(c)
	if _, ok := prim.(helperAttach); !ok {
		t.Fatalf("live-with-helper selector returned %T, want helperAttach", prim)
	}
}

// TestNewBoundaryReadinessLiveWithoutHelperIsDeferred: the readiness selector
// mirrors the attach selector. Live with a nil client must NOT construct the
// real probe (which would fail closed on the empty dnsgate/tlsproxy addrs) —
// it returns the always-ready deferred stand-in, so a live daemon with no
// privileged edge configured is never blocked by a gate it cannot satisfy.
func TestNewBoundaryReadinessLiveWithoutHelperIsDeferred(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "1") // gate ON

	readiness, err := newBoundaryReadiness(libvirt.LiveReadinessConfig{}, nil)
	if err != nil {
		t.Fatalf("live-without-helper readiness must not error (deferred no-op), got %v", err)
	}
	if _, ok := readiness.(deferredReadiness); !ok {
		t.Fatalf("live-without-helper readiness returned %T, want deferredReadiness", readiness)
	}
	ready, _, err := readiness.Probe(context.Background())
	if err != nil || !ready {
		t.Errorf("live-without-helper probe should be always-ready, got ready=%v err=%v", ready, err)
	}
}

// ── the verb surface: byte-parity with the retired cgo liveAttach ────────────

// TestHelperAttachVerbMapping pins the exact fork sequence and stdin params for
// all three AttachPrimitive methods:
//
//   - create-tap carries owner_uid == THIS process's uid (the helper re-checks
//     owner_uid == invoking uid) and NO guest_mac (Binding carries none, so the
//     static-neigh leg stays skipped — unchanged from the cgo edge).
//   - instantiate-session carries the tap + index join keys.
//   - FlushSession forks flush-session THEN teardown-session, in that order, and
//     NEVER delete-tap (AttachPrimitive has no tap-delete; using the client's
//     TeardownAll here would silently change §4.2 destroy behavior).
func TestHelperAttachVerbMapping(t *testing.T) {
	c, logPath := fakeHelperClient(t, okResult)
	prim := helperAttach{c: c}
	ctx := context.Background()
	b := libvirt.Binding{TapName: "dstap-7", HostSessionIndex: 7}

	if err := prim.CreateTap(ctx, b); err != nil {
		t.Fatalf("CreateTap: %v", err)
	}
	if err := prim.InstantiateSessionNFT(ctx, "session-uuid", b); err != nil {
		t.Fatalf("InstantiateSessionNFT: %v", err)
	}
	if err := prim.FlushSession(ctx, "session-uuid", b); err != nil {
		t.Fatalf("FlushSession: %v", err)
	}

	got := invocations(t, logPath)
	wantOps := []string{"create-tap", "instantiate-session", "flush-session", "teardown-session"}
	if len(got) != len(wantOps) {
		t.Fatalf("helper invocations = %v, want exactly %v", got, wantOps)
	}
	for i, want := range wantOps {
		if got[i][0] != want {
			t.Fatalf("invocation %d op = %q, want %q (full sequence %v)", i, got[i][0], want, got)
		}
	}
	for _, inv := range got {
		if inv[0] == "delete-tap" {
			t.Fatal("FlushSession forked delete-tap: AttachPrimitive has no tap-delete and today's agent never deletes taps (parity broken)")
		}
	}

	// create-tap params: the owner uid rule + the empty MAC.
	createParams := got[0][1]
	wantOwner := `"owner_uid":` + itoa(os.Getuid())
	if !strings.Contains(createParams, wantOwner) {
		t.Errorf("create-tap params %s missing %s (the tap must be owned by THIS process so qemu:///session can open it)", createParams, wantOwner)
	}
	if strings.Contains(createParams, "guest_mac") {
		t.Errorf("create-tap params %s carry a guest_mac; Binding has no MAC field, so the static-neigh leg must stay skipped (no invented MAC)", createParams)
	}
	for _, want := range []string{`"tap_name":"dstap-7"`, `"host_session_index":7`} {
		if !strings.Contains(createParams, want) {
			t.Errorf("create-tap params %s missing %s", createParams, want)
		}
	}

	// instantiate-session params: the (tap, idx) join keys.
	for _, want := range []string{`"tap_name":"dstap-7"`, `"host_session_index":7`} {
		if !strings.Contains(got[1][1], want) {
			t.Errorf("instantiate-session params %s missing %s", got[1][1], want)
		}
	}
}

// itoa avoids pulling strconv in for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

// ── the FATAL bring-up check ─────────────────────────────────────────────────

// TestVerifyHelperReadyFailsClosedOnEpOnlyPosture is the headline: a helper
// installed with `+ep` instead of `+eip` is effective-green and would pass any
// one-field check, yet strands every ip/nft child. Bring-up must REFUSE and the
// error must name the trap.
func TestVerifyHelperReadyFailsClosedOnEpOnlyPosture(t *testing.T) {
	c, _ := fakeHelperClient(t, probeEpOnly)

	err := verifyHelperReady(context.Background(), c)
	if err == nil {
		t.Fatal("a `+ep`-only helper was accepted at bring-up; every ip/nft child would be stranded unprivileged")
	}
	for _, want := range []string{"ambient_raise_ok=false", "+ep", "+eip", "install-ds-nethelper.sh"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must name %q for the operator; got %q", want, err)
		}
	}
}

// TestVerifyHelperReadyFailsClosedOnStubHelper: a helper built without
// -tags nftgatelive validates everything and performs nothing (ENOTBUILT on
// every verb). Bring-up must refuse rather than serve a daemon that silently
// programs no tap or nft object.
func TestVerifyHelperReadyFailsClosedOnStubHelper(t *testing.T) {
	c, _ := fakeHelperClient(t, probeStub)

	err := verifyHelperReady(context.Background(), c)
	if err == nil {
		t.Fatal("a STUB helper (built=false) was accepted at bring-up; every privileged verb would answer ENOTBUILT")
	}
	for _, want := range []string{"built=false", "nftgatelive"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must name %q; got %q", want, err)
		}
	}
}

// TestVerifyHelperReadyFailsClosedOnMissingHelper: a path that does not resolve
// to a working binary is a bring-up refusal, never a degrade-to-fake.
func TestVerifyHelperReadyFailsClosedOnMissingHelper(t *testing.T) {
	c, err := nethelperclient.New(filepath.Join(t.TempDir(), "absent-ds-nethelper"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := verifyHelperReady(context.Background(), c); err == nil {
		t.Fatal("a missing helper binary was accepted at bring-up")
	}
}

// TestVerifyHelperReadyAcceptsFullPosture is the positive control: the correctly
// `+eip`-installed live helper passes.
func TestVerifyHelperReadyAcceptsFullPosture(t *testing.T) {
	c, _ := fakeHelperClient(t, probeReady)

	if err := verifyHelperReady(context.Background(), c); err != nil {
		t.Fatalf("a fully armed helper (built + effective + ambient-raisable) must pass bring-up, got %v", err)
	}
}

// ── the per-admission readiness fold ─────────────────────────────────────────

// recordingReadiness is a fake inner BoundaryReadiness that records whether it
// was consulted.
type recordingReadiness struct {
	consulted *bool
	ready     bool
	reason    string
}

func (r recordingReadiness) Probe(_ context.Context) (bool, string, error) {
	*r.consulted = true
	return r.ready, r.reason, nil
}

// TestHelperProbeReadinessNotReadyFailsClosed: a helper that has LOST its
// capability xattr mid-run (a rebuild/recopy) must make the NEXT admission
// not-ready — and the inner boundary probe must not even be consulted.
func TestHelperProbeReadinessNotReadyFailsClosed(t *testing.T) {
	c, _ := fakeHelperClient(t, probeEpOnly)
	consulted := false
	gate := helperProbeReadiness{c: c, inner: recordingReadiness{consulted: &consulted, ready: true}}

	ready, reason, err := gate.Probe(context.Background())
	if err != nil {
		t.Fatalf("a not-ready helper is a definitive answer, not an error, got %v", err)
	}
	if ready {
		t.Fatal("admission was granted against a helper whose privileged ops would all fail (fail-closed violated)")
	}
	if consulted {
		t.Error("the inner boundary probe ran despite the helper being unusable; the helper leg must short-circuit")
	}
	if !strings.Contains(reason, "ambient_raise_ok=false") {
		t.Errorf("reason must surface the failing field, got %q", reason)
	}
}

// TestHelperProbeReadinessDelegatesWhenReady: with a fully armed helper the
// composite is transparent — the inner boundary probe's verdict is the answer.
func TestHelperProbeReadinessDelegatesWhenReady(t *testing.T) {
	c, _ := fakeHelperClient(t, probeReady)
	consulted := false
	gate := helperProbeReadiness{c: c, inner: recordingReadiness{consulted: &consulted, ready: false, reason: "nft table ds_boundary absent"}}

	ready, reason, err := gate.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !consulted {
		t.Fatal("an armed helper must DELEGATE to the real boundary probe, not answer for it")
	}
	if ready || reason != "nft table ds_boundary absent" {
		t.Errorf("inner verdict must pass through verbatim, got ready=%v reason=%q", ready, reason)
	}
}

// TestHelperProbeReadinessMissingHelperFailsClosed: an unreachable helper is
// NOT ready (an uncertain probe must never be treated as ready).
func TestHelperProbeReadinessMissingHelperFailsClosed(t *testing.T) {
	c, err := nethelperclient.New(filepath.Join(t.TempDir(), "absent-ds-nethelper"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	consulted := false
	gate := helperProbeReadiness{c: c, inner: recordingReadiness{consulted: &consulted, ready: true}}

	ready, reason, probeErr := gate.Probe(context.Background())
	if probeErr != nil {
		t.Fatalf("a probe fault is a definitive not-ready answer, not an error, got %v", probeErr)
	}
	if ready {
		t.Fatal("admission granted against an unreachable helper (fail-closed violated)")
	}
	if !strings.Contains(reason, "ds-nethelper probe failed") {
		t.Errorf("reason must name the probe fault, got %q", reason)
	}
	if consulted {
		t.Error("the inner boundary probe ran despite an unreachable helper")
	}
}

// ── the compile refusal (D148 linker-set guard) ──────────────────────────────

// TestHostAgentBuildRefusesNftgateliveTag proves the guard actually fires:
// building THIS package with -tags nftgatelive must fail, and the error must
// name the rule (nftgatelive_refuse.go's deliberately undefined identifier), not
// a confusing missing-libds_nft link error. This is the executable form of the
// D148 linker-set freeze — the host agent may never re-link the ds-nft cgo edge.
func TestHostAgentBuildRefusesNftgateliveTag(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles the package; skipped under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	cmd := exec.Command("go", "build", "-tags", "nftgatelive", "-o", os.DevNull, ".")
	cmd.Dir = wd
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("the host agent BUILT with -tags nftgatelive: the D148 linker set ({ds-dnsgate, ds-nethelper}) is no longer enforced and this binary can carry CAP_NET_ADMIN again")
	}
	if !strings.Contains(string(out), "hostAgentMustNeverBuildWithNftgatelive") {
		t.Errorf("the tagged build failed, but not on the refusal guard — the operator would see an unrelated error.\n%s", out)
	}
}
