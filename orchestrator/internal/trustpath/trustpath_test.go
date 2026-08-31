// SPDX-License-Identifier: Apache-2.0

package trustpath

import (
	"path/filepath"
	"testing"
)

// TestSubdir pins the hidden subdir name both the producer and consumer key on. A
// change here is a trust-path break (the producer would write under a name the
// consumer never reads), so the literal is asserted, not just referenced.
func TestSubdir(t *testing.T) {
	if Subdir != ".ds-ca-bundles" {
		t.Fatalf("Subdir = %q, want %q", Subdir, ".ds-ca-bundles")
	}
}

// TestSanitize covers the exact transform both legacy copies implemented: the
// identity case (already-safe input), every flavor of illegal rune mapped to '_',
// the "ca:<uuid>" -> "ca_<uuid>" mapping the trust path depends on, the empty-input
// collapse to "session", and the all-illegal input staying non-empty (one '_' per rune).
func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"01HZ-abc_def.9": "01HZ-abc_def.9",
		"ca-ref-A":       "ca-ref-A",
		"ca:abc-123":     "ca_abc-123",
		"a/b/../c":       "a_b_.._c",
		"x;rm -rf":       "x_rm_-rf",
		"":               "session",
		":::":            "___",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBundleFilename pins the leaf both sides write/read: sanitized ref + ".pem".
func TestBundleFilename(t *testing.T) {
	if got, want := BundleFilename("ca:abc-123"), "ca_abc-123.pem"; got != want {
		t.Errorf("BundleFilename(%q) = %q, want %q", "ca:abc-123", got, want)
	}
	if got, want := BundleFilename(""), "session.pem"; got != want {
		t.Errorf("BundleFilename(empty) = %q, want %q", got, want)
	}
}

// TestKeyFilename pins the proxy-bound key leaf the producer drops and the host-side
// §4.2 disposer removes: sanitized ref + ".key.pem". The rows mirror the
// CrossReaderCARefVectors KeyLeaf column (controlplane/liveedges.go), so a drift here is
// the same drift the producer's fail-closed package init() panics on.
func TestKeyFilename(t *testing.T) {
	cases := map[string]string{
		"ca:abc-123": "ca_abc-123.key.pem",
		"ca:a/b":     "ca_a_b.key.pem",
		"":           "session.key.pem",
	}
	for in, want := range cases {
		if got := KeyFilename(in); got != want {
			t.Errorf("KeyFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSubdirPath / TestBundlePath pin the directory and the full on-disk path the
// producer writes and the consumer reads — the single path both derive.
func TestSubdirPath(t *testing.T) {
	if got, want := SubdirPath("/base"), filepath.Join("/base", ".ds-ca-bundles"); got != want {
		t.Errorf("SubdirPath = %q, want %q", got, want)
	}
}

func TestBundlePath(t *testing.T) {
	if got, want := BundlePath("/base", "ca:abc-123"), "/base/.ds-ca-bundles/ca_abc-123.pem"; got != want {
		t.Errorf("BundlePath = %q, want %q", got, want)
	}
}

// ── sibling per-session host-state stores ────────────────────────────────────
//
// The tests below pin the byte-exact subdir + leaf shape of EACH sibling store's
// helper triple DIRECTLY (previously these were only covered indirectly via the
// libvirt round-trips). A change to any subdir literal, extension, or the leaf-with/
// without-extension choice is a host producer/consumer break, so the literals are
// asserted, not just derived — any leaf/subdir drift fails here.

// TestAttachTokenHelpers pins the attach-token store: .ds-attach-tokens subdir, a
// sanitized session id + ".json" leaf.
func TestAttachTokenHelpers(t *testing.T) {
	if AttachTokensSubdir != ".ds-attach-tokens" {
		t.Fatalf("AttachTokensSubdir = %q, want %q", AttachTokensSubdir, ".ds-attach-tokens")
	}
	if got, want := AttachTokenFilename("sess:1/2"), "sess_1_2.json"; got != want {
		t.Errorf("AttachTokenFilename = %q, want %q", got, want)
	}
	if got, want := AttachTokensSubdirPath("/base"), filepath.Join("/base", ".ds-attach-tokens"); got != want {
		t.Errorf("AttachTokensSubdirPath = %q, want %q", got, want)
	}
	if got, want := AttachTokenPath("/base", "sess:1/2"), "/base/.ds-attach-tokens/sess_1_2.json"; got != want {
		t.Errorf("AttachTokenPath = %q, want %q", got, want)
	}
}

// TestSessionRecordHelpers pins the session-record store: .ds-sessions subdir, a
// sanitized session id + ".json" leaf.
func TestSessionRecordHelpers(t *testing.T) {
	if SessionRecordsSubdir != ".ds-sessions" {
		t.Fatalf("SessionRecordsSubdir = %q, want %q", SessionRecordsSubdir, ".ds-sessions")
	}
	if got, want := SessionRecordFilename("sess:1/2"), "sess_1_2.json"; got != want {
		t.Errorf("SessionRecordFilename = %q, want %q", got, want)
	}
	if got, want := SessionRecordsSubdirPath("/base"), filepath.Join("/base", ".ds-sessions"); got != want {
		t.Errorf("SessionRecordsSubdirPath = %q, want %q", got, want)
	}
	if got, want := SessionRecordPath("/base", "sess:1/2"), "/base/.ds-sessions/sess_1_2.json"; got != want {
		t.Errorf("SessionRecordPath = %q, want %q", got, want)
	}
}

// TestEntrypointRefHelpers pins the entrypoint-ref store: .ds-entrypoint-refs subdir,
// a sanitized ref with NO extension (opaque pass-through material, not a typed
// artifact).
func TestEntrypointRefHelpers(t *testing.T) {
	if EntrypointRefsSubdir != ".ds-entrypoint-refs" {
		t.Fatalf("EntrypointRefsSubdir = %q, want %q", EntrypointRefsSubdir, ".ds-entrypoint-refs")
	}
	if got, want := EntrypointRefFilename("ep:1/2"), "ep_1_2"; got != want {
		t.Errorf("EntrypointRefFilename = %q, want %q", got, want)
	}
	if got, want := EntrypointRefsSubdirPath("/base"), filepath.Join("/base", ".ds-entrypoint-refs"); got != want {
		t.Errorf("EntrypointRefsSubdirPath = %q, want %q", got, want)
	}
	if got, want := EntrypointRefPath("/base", "ep:1/2"), "/base/.ds-entrypoint-refs/ep_1_2"; got != want {
		t.Errorf("EntrypointRefPath = %q, want %q", got, want)
	}
}

// TestSessionModeHelpers pins the session-mode store: .ds-session-mode subdir, a
// sanitized session id with NO extension (the marker body is the canonical mode name).
// The libvirt SessionModeStore keys its on-disk path on these, so any drift here is a
// host serving-leg/producer break.
func TestSessionModeHelpers(t *testing.T) {
	if SessionModeSubdir != ".ds-session-mode" {
		t.Fatalf("SessionModeSubdir = %q, want %q", SessionModeSubdir, ".ds-session-mode")
	}
	if got, want := SessionModeFilename("sess:1/2"), "sess_1_2"; got != want {
		t.Errorf("SessionModeFilename = %q, want %q", got, want)
	}
	if got, want := SessionModeSubdirPath("/base"), filepath.Join("/base", ".ds-session-mode"); got != want {
		t.Errorf("SessionModeSubdirPath = %q, want %q", got, want)
	}
	if got, want := SessionModePath("/base", "sess:1/2"), "/base/.ds-session-mode/sess_1_2"; got != want {
		t.Errorf("SessionModePath = %q, want %q", got, want)
	}
}

// TestConfigDriveHelpers pins the config-drive leaves: they live DIRECTLY under
// baseDir (no subdir), a sanitized session id + ".config.iso" (read-only image) /
// ".config.d" (staging dir).
func TestConfigDriveHelpers(t *testing.T) {
	if got, want := ConfigDriveImagePath("/base", "sess:1/2"), "/base/sess_1_2.config.iso"; got != want {
		t.Errorf("ConfigDriveImagePath = %q, want %q", got, want)
	}
	if got, want := ConfigDriveStagingPath("/base", "sess:1/2"), "/base/sess_1_2.config.d"; got != want {
		t.Errorf("ConfigDriveStagingPath = %q, want %q", got, want)
	}
}
