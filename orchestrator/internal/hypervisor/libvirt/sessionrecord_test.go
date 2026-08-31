// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func testBinding(idx uint64) Binding {
	return Binding{
		HostSessionIndex: idx,
		TapName:          tapName(idx),
		GuestIP:          GuestAddress{Family: AddressFamilyIPv4, Address: []byte{10, 42, 0, byte(idx)}},
		OverlayPath:      "/var/lib/ds/overlays/sess-x.qcow2",
	}
}

// TestFileSessionRecordRoundTrip: Put then Get returns the same record byte-for-byte
// (the Binding incl. the GuestAddress family+bytes round-trips through JSON).
func TestFileSessionRecordRoundTrip(t *testing.T) {
	s, err := NewFileSessionRecordStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSessionRecordStore: %v", err)
	}
	rec := SessionRecord{SessionUUID: "sess-7", DomainUUID: "dom-abc", Binding: testBinding(7)}
	if err := s.Put(context.Background(), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, found, err := s.Get(context.Background(), "sess-7")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("Get: record not found after Put")
	}
	if got.SessionUUID != rec.SessionUUID || got.DomainUUID != rec.DomainUUID {
		t.Fatalf("Get = %+v, want %+v", got, rec)
	}
	if got.Binding.HostSessionIndex != 7 || got.Binding.TapName != tapName(7) {
		t.Fatalf("binding index/tap not round-tripped: %+v", got.Binding)
	}
	if got.Binding.GuestIP.Family != AddressFamilyIPv4 || len(got.Binding.GuestIP.Address) != 4 {
		t.Fatalf("guest address not round-tripped: %+v", got.Binding.GuestIP)
	}
}

// TestFileSessionRecordCABundleRefRoundTrip: the ref the create carried survives
// Put/Get, so a converged §4.2 Destroy can resolve it back and dispose the host-readable
// CA bundle (cert + proxy-bound key) the orchestrator producer dropped (D82).
func TestFileSessionRecordCABundleRefRoundTrip(t *testing.T) {
	s, err := NewFileSessionRecordStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSessionRecordStore: %v", err)
	}
	rec := SessionRecord{SessionUUID: "sess-ca", DomainUUID: "dom-ca", Binding: testBinding(3), CABundleRef: "ca:sess-ca"}
	if err := s.Put(context.Background(), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, found, err := s.Get(context.Background(), "sess-ca")
	if err != nil || !found {
		t.Fatalf("Get: found=%v err=%v", found, err)
	}
	if got.CABundleRef != "ca:sess-ca" {
		t.Fatalf("CABundleRef = %q, want %q — the teardown could not resolve the CA bundle to dispose", got.CABundleRef, "ca:sess-ca")
	}
}

// TestFileSessionRecordPreUpgradeUnmarshalCompat: the field is ADDITIVE, so a record
// written by a PRE-upgrade host agent (no ca_bundle_ref key at all) still reads cleanly,
// yielding an empty ref — the §4.2 disposal is then skipped for it, never an error that
// would break re-adoption of a session booted before the upgrade.
func TestFileSessionRecordPreUpgradeUnmarshalCompat(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileSessionRecordStore(dir)
	if err != nil {
		t.Fatalf("NewFileSessionRecordStore: %v", err)
	}
	old := `{"session_uuid":"sess-old","domain_uuid":"dom-old","binding":{}}`
	if err := os.WriteFile(s.recordPath("sess-old"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Get(context.Background(), "sess-old")
	if err != nil {
		t.Fatalf("a pre-upgrade record must read cleanly, got %v", err)
	}
	if !found {
		t.Fatal("pre-upgrade record not found")
	}
	if got.CABundleRef != "" {
		t.Fatalf("pre-upgrade record CABundleRef = %q, want empty", got.CABundleRef)
	}
	if got.SessionUUID != "sess-old" || got.DomainUUID != "dom-old" {
		t.Fatalf("pre-upgrade record mis-read: %+v", got)
	}
}

// TestFileSessionRecordPutOverwrites: a re-Put of the same session overwrites
// (idempotent on session_uuid — a re-create converges, no duplicate).
func TestFileSessionRecordPutOverwrites(t *testing.T) {
	s, _ := NewFileSessionRecordStore(t.TempDir())
	_ = s.Put(context.Background(), SessionRecord{SessionUUID: "s", DomainUUID: "d1", Binding: testBinding(1)})
	if err := s.Put(context.Background(), SessionRecord{SessionUUID: "s", DomainUUID: "d2", Binding: testBinding(2)}); err != nil {
		t.Fatalf("re-Put: %v", err)
	}
	got, _, _ := s.Get(context.Background(), "s")
	if got.DomainUUID != "d2" || got.Binding.HostSessionIndex != 2 {
		t.Fatalf("re-Put did not overwrite: %+v", got)
	}
}

// TestFileSessionRecordGetMissing: a missing record is (zero,false,nil), not an error.
func TestFileSessionRecordGetMissing(t *testing.T) {
	s, _ := NewFileSessionRecordStore(t.TempDir())
	_, found, err := s.Get(context.Background(), "nope")
	if err != nil {
		t.Fatalf("Get missing must be (false,nil), got err=%v", err)
	}
	if found {
		t.Fatal("missing record reported found")
	}
}

// TestFileSessionRecordCorruptIsError: a corrupt record file is a hard error
// (fail-loud — never silently drop a resident session from recovery).
func TestFileSessionRecordCorruptIsError(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileSessionRecordStore(dir)
	// Write a corrupt record at the deterministic path.
	if err := os.WriteFile(s.recordPath("sess-c"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(context.Background(), "sess-c"); err == nil {
		t.Fatal("expected a corrupt record to surface an error")
	}
}

// TestFileSessionRecordRemove: Remove deletes the record; a re-Remove is a no-op.
func TestFileSessionRecordRemove(t *testing.T) {
	s, _ := NewFileSessionRecordStore(t.TempDir())
	_ = s.Put(context.Background(), SessionRecord{SessionUUID: "s", DomainUUID: "d", Binding: testBinding(1)})
	if err := s.Remove(context.Background(), "s"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, found, _ := s.Get(context.Background(), "s"); found {
		t.Fatal("record present after Remove")
	}
	if err := s.Remove(context.Background(), "s"); err != nil {
		t.Fatalf("re-Remove of a missing record must be a no-op success: %v", err)
	}
}

// TestNewSessionRecordStoreGate: off the gate NewSessionRecordStore returns nil
// (the create path skips the write); on the gate it returns a file store rooted at
// <OverlayDir>/.ds-sessions.
func TestNewSessionRecordStoreGate(t *testing.T) {
	cfg := LiveConfig{OverlayCreateScript: "x", OverlayDir: t.TempDir(), BaseImage: "y", VirshBin: "virsh"}

	t.Setenv(EnvHostAgentLive, "")
	s, err := NewSessionRecordStore(cfg)
	if err != nil {
		t.Fatalf("gate off: %v", err)
	}
	if s != nil {
		t.Fatalf("gate off must return nil, got %T", s)
	}

	t.Setenv(EnvHostAgentLive, "1")
	s, err = NewSessionRecordStore(cfg)
	if err != nil {
		t.Fatalf("gate on: %v", err)
	}
	if s == nil {
		t.Fatal("gate on must return a non-nil store")
	}
	if _, err := os.Stat(filepath.Join(cfg.OverlayDir, sessionRecordsSubdir)); err != nil {
		t.Fatalf("gate on must create the records subdir: %v", err)
	}
}
