package flowlog

// LOG-5 — Credential-use audit trail: fully attributable credential use,
// the credential VALUE appearing nowhere on any log surface, a stable
// non-reversible fingerprint, and correct negative space for pass-through.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Seeded canary secrets (high-entropy needles, doc 06 §3(c) credential row).
const (
	longCanary  = "ghp_LONGCANARY9aF3xQ7mZ2kW8pL1nV5rT0uY4s" // long-lived (real key shape)
	shortCanary = "ds_SHORTCANARY6bE2yR8nX3jU9qM0oW7sZ1vT5a" // short-lived (session credential shape)
)

// canaryForms returns every encoding of the needle the scanner checks.
func canaryForms(needle string) map[string][]byte {
	return map[string][]byte{
		"raw":        []byte(needle),
		"base64":     []byte(base64.StdEncoding.EncodeToString([]byte(needle))),
		"base64url":  []byte(base64.RawURLEncoding.EncodeToString([]byte(needle))),
		"hex":        []byte(hex.EncodeToString([]byte(needle))),
		"urlencoded": []byte(url.QueryEscape(needle)),
	}
}

// scanForSecretWindows asserts that NO window of >=6 bytes of secret — raw,
// hex-, base64-, or base64url-encoded — appears anywhere in data. Scanning
// only the full needle would miss a "fingerprint" (or any log surface) that
// embeds an offset/truncated slice of the credential: e.g.
// "sha256:"+hex(secret[8:40]) matches the fixed format yet is trivially
// reversible for 80% of the secret. Sliding windows at every offset also
// cover all base64 phase alignments.
func scanForSecretWindows(t *testing.T, surface string, data []byte, secretName string, secret []byte) {
	t.Helper()
	const minWindow = 6
	for l := minWindow; l <= len(secret); l++ {
		for i := 0; i+l <= len(secret); i++ {
			win := secret[i : i+l]
			for form, enc := range map[string]string{
				"raw":       string(win),
				"hex":       hex.EncodeToString(win),
				"base64":    base64.StdEncoding.EncodeToString(win),
				"base64url": base64.RawURLEncoding.EncodeToString(win),
			} {
				if bytes.Contains(data, []byte(enc)) {
					t.Errorf("credential window leaked: %s bytes [%d:%d) (%s-encoded) present on surface %q — the surface is partially reversible", secretName, i, i+l, form, surface)
				}
			}
		}
	}
}

// scanSurface asserts ZERO occurrences of either canary, in any encoding,
// anywhere in data — including every >=6-byte window of each canary, so a
// partial (offset/truncated) leak is caught, not just the full needle.
func scanSurface(t *testing.T, surface string, data []byte) {
	t.Helper()
	for _, needle := range []string{longCanary, shortCanary} {
		for form, enc := range canaryForms(needle) {
			if n := bytes.Count(data, enc); n > 0 {
				t.Errorf("credential canary leaked: %d occurrence(s) of %s… (%s-encoded) on surface %q", n, needle[:14], form, surface)
			}
		}
		scanForSecretWindows(t, surface, data, needle[:14]+"…", []byte(needle))
	}
}

// planRef: doc 09 §7 LOG-5 Done-when ("which session used the GitHub key, when, for what request" returns the answer for a test push)
func TestCredentialAudit_WhichSessionUsedTheGitHubKey(t *testing.T) {
	refA := mkRef("sess-a")
	fp := mustFingerprint(t, []byte("ghp_testPushKey0123456789abcdefABCDEF012"))

	sink := &fakeSink{}
	spool := NewSpool(t.TempDir(), 8<<20)
	col := NewCollector(spool)
	shipper := NewShipper(spool, NewRouter(RouterConfig{Default: "audit", CustomerSide: "audit"}),
		map[SinkID]Sink{"audit": sink}, TierSaaS)

	// Scripted TLS-5 test push.
	tPush := t0.Add(90 * time.Second)
	use := CredentialUseEvent{
		Session: refA, Service: "github", Fingerprint: fp,
		Request: HttpRequestMeta{Method: "POST", Host: "api.github.com", Path: "/repos/x/git-receive-pack", At: tPush},
	}
	mustIngest(t, col, use)
	mustShip(t, shipper)

	q := NewAuditQuerier(sink)
	uses, err := q.CredentialUses(bg, CredentialUseQuery{Service: "github", Window: Window{From: t0, To: t0.Add(time.Hour)}})
	if err != nil {
		t.Fatalf("CredentialUses: %v", err)
	}
	if len(uses) != 1 {
		t.Fatalf("want exactly one credential use for the test push, got %d", len(uses))
	}
	got := uses[0]
	if got.Session.SessionID != refA.SessionID {
		t.Errorf("answer names session %q, want %q", got.Session.SessionID, refA.SessionID)
	}
	if got.Service != "github" {
		t.Errorf("service %q, want github", got.Service)
	}
	if !got.Request.At.Equal(tPush) {
		t.Errorf("push timestamp %v, want %v", got.Request.At, tPush)
	}
	if got.Request.Method != "POST" || got.Request.Host != "api.github.com" || got.Request.Path != "/repos/x/git-receive-pack" {
		t.Errorf("request metadata wrong: %+v", got.Request)
	}
	if got.Fingerprint != fp {
		t.Errorf("fingerprint %q, want %q", got.Fingerprint, fp)
	}

	before, err := q.CredentialUses(bg, CredentialUseQuery{Service: "github", Window: Window{From: t0.Add(-time.Hour), To: t0}})
	if err != nil {
		t.Fatalf("CredentialUses (pre-push window): %v", err)
	}
	if len(before) != 0 {
		t.Errorf("a window before the push must return empty, got %d", len(before))
	}
}

// planRef: doc 09 §7 LOG-5 Done-when ("the credential value appears nowhere in the event"); §5 TLS-5; doc 06 §3(c) credential row [ADVERSARIAL]
func TestCredentialValue_AppearsNowhereInAnyLogPath(t *testing.T) {
	refA := mkRef("sess-a")

	// BOTH canaries pass through the one sanctioned secret→event path, so the
	// implementation genuinely handles the short-lived credential's bytes
	// before the surfaces are scanned (its premise: both canaries were live
	// in the data plane).
	fp := mustFingerprint(t, []byte(longCanary))
	fpShort := mustFingerprint(t, []byte(shortCanary))

	// The fingerprints that ARE present must not contain any canary
	// substring in ANY encoding: windowed multi-encoding scan of the
	// fingerprint strings themselves, not just the two raw needles.
	if strings.Contains(string(fp), "LONGCANARY") || strings.Contains(string(fpShort), "SHORTCANARY") {
		t.Fatalf("a fingerprint embeds its credential canary verbatim: %q / %q", fp, fpShort)
	}
	for _, surf := range []struct {
		name string
		fp   CredentialFingerprint
	}{{"long-lived fingerprint", fp}, {"short-lived fingerprint", fpShort}} {
		scanForSecretWindows(t, surf.name, []byte(surf.fp), "longCanary", []byte(longCanary))
		scanForSecretWindows(t, surf.name, []byte(surf.fp), "shortCanary", []byte(shortCanary))
	}

	dir := t.TempDir()
	spool := NewSpool(dir, 8<<20)
	col := NewCollector(spool)
	sink := &fakeSink{}
	shipper := NewShipper(spool, NewRouter(RouterConfig{Default: "audit", CustomerSide: "audit"}),
		map[SinkID]Sink{"audit": sink}, TierSaaS)

	// A scripted session in which both canaries were live in the data plane
	// (long-lived swapped in by TLS-5, short-lived presented by the VM); the
	// only sanctioned residue is the two fingerprints.
	shortUse := validCredUse(refA, fpShort, t0.Add(5*time.Second))
	shortUse.Service = "session-credential"
	script := []Event{
		validDnsEvent(refA, "api.github.com", t0.Add(1*time.Second)),
		validFlowRecord(refA, 1, t0.Add(2*time.Second)),
		validHttpEvent(refA, "api.github.com", t0.Add(3*time.Second)),
		validDecision(refA, VerdictSwap, "TLS-5.swap.github", "api.github.com", t0.Add(3*time.Second)),
		validCredUse(refA, fp, t0.Add(4*time.Second)),
		shortUse,
	}

	// Surface (1): every serialized Event.
	for _, ev := range script {
		mustIngest(t, col, ev)
		scanSurface(t, fmt.Sprintf("serialized %T", ev), mustMarshal(t, ev))
	}

	// Surface (2): the spool's on-disk bytes, read directly.
	var diskBytes []byte
	werr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		diskBytes = append(diskBytes, b...)
		return nil
	})
	if werr != nil {
		t.Fatalf("walking spool dir: %v", werr)
	}
	if len(diskBytes) == 0 {
		t.Fatalf("spool wrote no bytes under %s — the on-disk surface was not exercised", dir)
	}
	scanSurface(t, "spool on-disk bytes", diskBytes)

	// Surface (3): every batch the fake Sink received.
	mustShip(t, shipper)
	if got := len(sink.allEvents()); got != len(script) {
		t.Fatalf("shipped story incomplete (%d/%d) — the shipped surface was not exercised", got, len(script))
	}
	for bi, batch := range sink.allBatches() {
		for _, ev := range batch {
			scanSurface(t, fmt.Sprintf("shipped batch %d (%T)", bi, ev), []byte(fmt.Sprintf("%#v", ev)))
			scanSurface(t, fmt.Sprintf("shipped batch %d (%T, wire)", bi, ev), mustMarshal(t, ev))
		}
	}

	// Surface (4): alarm payloads — force one through reconciliation.
	hole := ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "203.0.113.7:443", 4096, 4096, t0.Add(time.Second), t0.Add(2*time.Second))
	h := newReconcilerHarness(t, []ConntrackFlow{hole}, nil, nil, nil, 30*time.Second)
	mustRegister(t, h.reg, refA, 0xA001, refA.Iface)
	w := Window{From: t0, To: t0.Add(time.Minute)}
	h.settle(w, 30*time.Second)
	if _, err := h.rec.Reconcile(bg, w); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	alarms := h.alarms.all()
	if len(alarms) == 0 {
		t.Fatalf("no alarm payload produced — the alarm surface was not exercised")
	}
	for _, a := range alarms {
		scanSurface(t, "alarm payload", []byte(fmt.Sprintf("%#v", a)))
	}
}

// planRef: doc 09 §7 LOG-5 (fingerprint as the attribution payoff of D8)
func TestFingerprint_StableJoinableNonReversible(t *testing.T) {
	fpFormat := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// Token-shaped secret deliberately free of >=6-char lowercase-hex runs so
	// the windowed scan below cannot collide with a legitimate hex digest.
	secret := []byte("ghp_stableSecretZQXWVYwsrqponmZYXWVU9900")

	t.Run("same_secret_identical_fingerprint", func(t *testing.T) {
		fp1 := mustFingerprint(t, secret)
		fp2 := mustFingerprint(t, secret)
		if fp1 != fp2 {
			t.Errorf("same secret must fingerprint identically (joinable across sessions/time): %q vs %q", fp1, fp2)
		}
		if !fpFormat.MatchString(string(fp1)) {
			t.Errorf("fingerprint %q does not match the LOG-1.e format %s", fp1, fpFormat)
		}
		if got, want := len(fp1), len(FingerprintPrefix)+FingerprintHexLen; got != want {
			t.Errorf("fingerprint length %d, want fixed %d", got, want)
		}
		// Non-reversible: no window of the input survives in ANY encoding.
		// Raw-substring checks alone are blind to "sha256:"+hex(secret[8:40])
		// — a format-conforming fingerprint embedding 80% of the secret.
		if strings.Contains(string(fp1), string(secret)) {
			t.Errorf("fingerprint contains the whole secret")
		}
		scanForSecretWindows(t, "fingerprint", []byte(fp1), "secret", secret)
	})

	t.Run("near_identical_secrets_distinct", func(t *testing.T) {
		secret2 := append([]byte(nil), secret...)
		secret2[len(secret2)-1] ^= 0x01 // differs by one byte
		fp1 := mustFingerprint(t, secret)
		fp2 := mustFingerprint(t, secret2)
		if fp1 == fp2 {
			t.Errorf("secrets differing by one byte must yield different fingerprints")
		}
	})

	t.Run("avalanche_single_byte_flip_at_every_region", func(t *testing.T) {
		// Flipping a single byte at the FIRST, an EARLY, a MIDDLE, and the
		// LAST position must each change the fingerprint. A truncation/
		// offset-embedding implementation (e.g. hex(secret[8:40])) is blind
		// to flips outside the embedded slice and dies here.
		fp0 := mustFingerprint(t, secret)
		positions := []int{0, 1, len(secret) / 2, len(secret) - 1}
		seen := map[CredentialFingerprint]int{fp0: -1}
		for _, pos := range positions {
			mut := append([]byte(nil), secret...)
			mut[pos] ^= 0x01
			fpM := mustFingerprint(t, mut)
			if fpM == fp0 {
				t.Errorf("flipping byte %d did not change the fingerprint — a truncated/offset slice of the secret is being embedded", pos)
			}
			if prev, dup := seen[fpM]; dup {
				t.Errorf("flips at byte %d and byte %d collide on the same fingerprint %q", pos, prev, fpM)
			}
			seen[fpM] = pos
		}
	})

	t.Run("empty_secret_rejected", func(t *testing.T) {
		for _, empty := range [][]byte{nil, {}} {
			if _, err := FingerprintCredential(empty); !errors.Is(err, ErrEmptySecret) {
				t.Errorf("empty secret must be rejected with ErrEmptySecret, got %v", err)
			}
		}
	})

	t.Run("large_secret_fixed_length_output", func(t *testing.T) {
		big := bytes.Repeat([]byte{0x5a}, 10<<10) // 10 KiB
		fp := mustFingerprint(t, big)
		if got, want := len(fp), len(FingerprintPrefix)+FingerprintHexLen; got != want {
			t.Errorf("10 KiB secret produced fingerprint of length %d, want fixed %d", got, want)
		}
		if !fpFormat.MatchString(string(fp)) {
			t.Errorf("fingerprint %q does not match the fixed format", fp)
		}
	})
}

// planRef: doc 09 §7 LOG-5 + §5 TLS-4 ("pass-through flows never swap" but are "still ... netflow-accounted"); doc 06 §3(c) pass-through row
func TestCredentialAudit_PassThroughFlows_NoUseEventButFlowStillAccounted(t *testing.T) {
	refA := mkRef("sess-a")

	sink := &fakeSink{}
	spool := NewSpool(t.TempDir(), 8<<20)
	col := NewCollector(spool)
	shipper := NewShipper(spool, NewRouter(RouterConfig{Default: "audit", CustomerSide: "audit"}),
		map[SinkID]Sink{"audit": sink}, TierSaaS)

	// Scripted pass-through tunnel to a pinned domain: flow accounting plus
	// a passthrough decision — and deliberately NO CredentialUseEvent.
	passDec := validDecision(refA, VerdictPassthrough, "TLS-4.passthrough.pinned", "pinned.bank.example", t0.Add(1*time.Second))
	flow := validFlowRecord(refA, 7, t0.Add(2*time.Second))
	flow.AdmittingDomain = "pinned.bank.example"

	mustIngest(t, col, passDec)
	mustIngest(t, col, flow)
	mustShip(t, shipper)

	q := NewAuditQuerier(sink)
	uses, err := q.CredentialUses(bg, CredentialUseQuery{Window: Window{From: t0, To: t0.Add(time.Hour)}})
	if err != nil {
		t.Fatalf("CredentialUses: %v", err)
	}
	if len(uses) != 0 {
		t.Fatalf("pinned pass-through traffic must never produce a CredentialUseEvent, got %d", len(uses))
	}

	story, err := sink.Query(bg, StoryQuery{SessionID: refA.SessionID, Window: Window{From: t0, To: t0.Add(time.Hour)}})
	if err != nil {
		t.Fatalf("Sink.Query: %v", err)
	}
	if len(story) != 2 {
		t.Fatalf("pass-through story must hold exactly the flow + the decision, got %d events", len(story))
	}
	var gotFlow, gotDec bool
	for _, ev := range story {
		switch e := ev.(type) {
		case FlowRecord:
			gotFlow = true
			if e.AdmittingDomain != "pinned.bank.example" {
				t.Errorf("pass-through flow accounting lost its domain: %q", e.AdmittingDomain)
			}
		case PolicyDecision:
			gotDec = true
			if e.Verdict != VerdictPassthrough {
				t.Errorf("decision verdict %q, want passthrough", e.Verdict)
			}
			if e.RuleID == "" || e.PolicyLayer == "" || e.PolicyVersion == "" {
				t.Errorf("passthrough decision lacks rule provenance: %+v", e)
			}
		default:
			t.Errorf("unexpected %T in pass-through story", ev)
		}
	}
	if !gotFlow || !gotDec {
		t.Errorf("story must contain the FlowRecord and the passthrough PolicyDecision (flow=%v dec=%v)", gotFlow, gotDec)
	}
}
