// SPDX-License-Identifier: Apache-2.0

package controlplane

// sessionrecordproducer_test.go exercises the host-local session-record PRODUCER leg of
// liveedges.go (the §4.1 producer half of the M0 session-identity JOIN seam, doc 14 §4/§4.1)
// against a temp-dir store — NO live host, NO host-agent, NO orchestrator dial (D50). It proves:
//
//   - the producer drops the (session_uuid, host_id) two-line record to
//     <baseDir>/.ds-session-records/<sanitize(tap)>.record, and a read-back returns the exact
//     canonical bytes the ds-tlsproxy reader parses ("<uuid>\n<host_id>\n");
//   - the on-disk leaf mirrors the ds-tlsproxy reader's transform (a "dstap-7" tap keys
//     "dstap-7.record"; a crafted tap with separators is sanitized so it cannot escape the
//     subdir), so the file the producer writes is the file LiveSessionRecordClient reads;
//   - an empty session_uuid is rejected fail-closed — identical to the reader surfacing an
//     empty-uuid HIT to its loud join guard (empty-uuid-is-malformed on BOTH sides);
//   - teardown removes the drop, and remove is idempotent (a missing file is a clean no-op);
//   - the drop is host-local 0600, and an empty base dir / empty tap name are rejected.
//
// The drop is verified by reading the record straight off disk at the deterministic path the
// ds-tlsproxy reader resolves, so this test stands alone without importing the dataplane.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// TestFileSessionRecordProducer_WriteThenReadBack is the acceptance: the producer writes the
// canonical two-line record keyed on the tap name and a read-back off disk returns the exact
// bytes the ds-tlsproxy reader parses. The path is the deterministic, reader-mirrored
// ".ds-session-records/<sanitize(tap)>.record".
func TestFileSessionRecordProducer_WriteThenReadBack(t *testing.T) {
	base := t.TempDir()
	prod, err := NewFileSessionRecordProducer(base)
	if err != nil {
		t.Fatalf("NewFileSessionRecordProducer: %v", err)
	}
	if err := prod.write("dstap-7", "sess-orch-0007", "host-bare-metal-a"); err != nil {
		t.Fatalf("write: %v", err)
	}

	wantPath := filepath.Join(base, sessionRecordSubdirName, "dstap-7.record")
	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read back dropped record at %s: %v", wantPath, err)
	}
	// Canonical byte format (doc 14 §4.1): line 1 = session_uuid, line 2 = host_id, each
	// with a trailing '\n'. This is byte-for-byte what the ds-tlsproxy reader's
	// `text.lines()` parse consumes.
	if want := "sess-orch-0007\nhost-bare-metal-a\n"; string(got) != want {
		t.Errorf("dropped record = %q, want %q", got, want)
	}

	// The drop is host-local 0600 (the identifiers are non-secret, but the store mirrors
	// the CA drop's host-local posture — never group/other-writable).
	info, err := os.Stat(wantPath)
	if err != nil {
		t.Fatalf("stat %s: %v", wantPath, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("%s perm = %o, want 0600 (host-local only)", wantPath, perm)
	}
}

// TestFileSessionRecordProducer_EmptyHostIDIsWellFormed proves a session whose host binding
// is not yet known drops a well-formed record with an empty host_id line — the reader
// resolves session_uuid and leaves host_id "" (best-effort mark-only-adds), NOT malformed.
func TestFileSessionRecordProducer_EmptyHostIDIsWellFormed(t *testing.T) {
	base := t.TempDir()
	prod, err := NewFileSessionRecordProducer(base)
	if err != nil {
		t.Fatalf("NewFileSessionRecordProducer: %v", err)
	}
	if err := prod.write("dstap-9", "sess-orch-0009", ""); err != nil {
		t.Fatalf("write with empty host_id: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(base, sessionRecordSubdirName, "dstap-9.record"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	// session_uuid line then an EMPTY host_id line — the reader's `lines.next().unwrap_or("")`
	// yields host_id "" and still HITs on the session_uuid.
	if want := "sess-orch-0009\n\n"; string(got) != want {
		t.Errorf("dropped record = %q, want %q", got, want)
	}
}

// TestFileSessionRecordProducer_PathMirrorsReader proves the producer's tap->leaf transform
// matches the ds-tlsproxy reader's sanitize_session_record_leaf: a plain "dstap-<idx>" is the
// identity map, and a tap carrying separators is sanitized to a single leaf that cannot escape
// the subdir (defense in depth — the reader runs the identical [A-Za-z0-9._-]->'_' policy).
func TestFileSessionRecordProducer_PathMirrorsReader(t *testing.T) {
	prod := &fileSessionRecordProducer{dir: "/base/.ds-session-records"}
	if got, want := prod.recordPath("dstap-7"), "/base/.ds-session-records/dstap-7.record"; got != want {
		t.Errorf("recordPath(%q) = %q, want %q", "dstap-7", got, want)
	}
	// A crafted tap with a path separator sanitizes to a single leaf ('/' -> '_'), so a
	// traversal is impossible — byte-identical to the reader's sanitizer.
	if got, want := prod.recordPath("../evil"), "/base/.ds-session-records/.._evil.record"; got != want {
		t.Errorf("recordPath(%q) = %q, want %q (path-traversal guard)", "../evil", got, want)
	}
	// The leaf transform is exactly trustpath.Sanitize (the single caRef/attach-token domain),
	// which is byte-for-byte the reader's sanitize_session_record_leaf.
	if got := trustpath.Sanitize("dstap-7"); got != "dstap-7" {
		t.Errorf("trustpath.Sanitize(%q) = %q, want unchanged", "dstap-7", got)
	}
}

// TestFileSessionRecordProducer_RejectsEmptyUUID proves the empty-uuid-is-malformed rule is
// enforced on the PRODUCER side identically to the reader's loud-guard rejection: a write with
// an empty session_uuid is refused fail-closed and NO file is left behind for a reader to
// mistake for a HIT.
func TestFileSessionRecordProducer_RejectsEmptyUUID(t *testing.T) {
	base := t.TempDir()
	prod, err := NewFileSessionRecordProducer(base)
	if err != nil {
		t.Fatalf("NewFileSessionRecordProducer: %v", err)
	}
	if err := prod.write("dstap-3", "", "host-a"); err == nil {
		t.Fatal("write: expected a fail-closed error for an empty session_uuid (malformed record)")
	}
	// The rejected write must not have left any drop behind.
	if _, err := os.Stat(filepath.Join(base, sessionRecordSubdirName, "dstap-3.record")); !os.IsNotExist(err) {
		t.Errorf("a rejected empty-uuid write left a drop behind (stat err = %v), want ENOENT", err)
	}
	entries, _ := os.ReadDir(filepath.Join(base, sessionRecordSubdirName))
	if len(entries) != 0 {
		t.Errorf("store has %d entries after only a rejected write, want 0", len(entries))
	}
}

// TestFileSessionRecordProducer_RejectsEmptyInputs proves the remaining fail-closed guards:
// an empty base dir at construction and an empty tap name at write (no join key).
func TestFileSessionRecordProducer_RejectsEmptyInputs(t *testing.T) {
	if _, err := NewFileSessionRecordProducer(""); err == nil {
		t.Fatal("NewFileSessionRecordProducer: expected an error for an empty base dir")
	}
	prod, err := NewFileSessionRecordProducer(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSessionRecordProducer: %v", err)
	}
	if err := prod.write("", "sess-x", "host-x"); err == nil {
		t.Fatal("write: expected a fail-closed error for an empty tap name (no join key)")
	}
}

// TestFileSessionRecordProducer_RemoveOnTeardown proves the lifecycle removal: after a write
// the drop exists; remove deletes it; and remove is idempotent (a second remove, or a remove
// of a never-dropped tap, is a clean no-op — a double-teardown never errors).
func TestFileSessionRecordProducer_RemoveOnTeardown(t *testing.T) {
	base := t.TempDir()
	prod, err := NewFileSessionRecordProducer(base)
	if err != nil {
		t.Fatalf("NewFileSessionRecordProducer: %v", err)
	}
	path := filepath.Join(base, sessionRecordSubdirName, "dstap-5.record")
	if err := prod.write("dstap-5", "sess-orch-0005", "host-b"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("drop should exist after write: %v", err)
	}
	if err := prod.remove("dstap-5"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("drop should be gone after remove (stat err = %v), want ENOENT", err)
	}
	// Idempotent: removing an already-removed / never-dropped tap is a clean no-op.
	if err := prod.remove("dstap-5"); err != nil {
		t.Errorf("second remove should be a no-op, got %v", err)
	}
	if err := prod.remove("dstap-never"); err != nil {
		t.Errorf("remove of a never-dropped tap should be a no-op, got %v", err)
	}
	// An empty tap name remove is a no-op (nothing to remove).
	if err := prod.remove(""); err != nil {
		t.Errorf("remove of an empty tap name should be a no-op, got %v", err)
	}
}

// TestFileSessionRecordProducer_Overwrites proves a re-drop for the same tap (a re-record of
// the same session) replaces the record atomically with the new bytes — the reader always sees
// one complete record, never a torn or stale-appended file.
func TestFileSessionRecordProducer_Overwrites(t *testing.T) {
	base := t.TempDir()
	prod, err := NewFileSessionRecordProducer(base)
	if err != nil {
		t.Fatalf("NewFileSessionRecordProducer: %v", err)
	}
	if err := prod.write("dstap-1", "sess-old", "host-old"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := prod.write("dstap-1", "sess-new", "host-new"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(base, sessionRecordSubdirName, "dstap-1.record"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if want := "sess-new\nhost-new\n"; string(got) != want {
		t.Errorf("record after re-drop = %q, want %q", got, want)
	}
	// The atomic temp file must not linger — the store holds exactly one leaf for the tap.
	entries, _ := os.ReadDir(filepath.Join(base, sessionRecordSubdirName))
	if len(entries) != 1 {
		t.Errorf("store has %d entries after a re-drop, want 1 (no stray temp file)", len(entries))
	}
}
