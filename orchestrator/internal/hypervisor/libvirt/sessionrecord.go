// SPDX-License-Identifier: Apache-2.0

// sessionrecord — the durable per-session record store the crash-matrix
// re-adoption leg (doc 15 §4; the SessionRecoverer seam) reads back. A booted
// session's three-keys-agree Binding (the never-recycled index, the dstap-<idx>
// tap, the per-session guest IP, the qcow2 overlay) is host-side state the libvirt
// domain XML does NOT carry — the domain only records the session UUID (the
// liveBooter ds:session metadata). So the create path persists a SessionRecord
// here at boot, and on a host-agent restart the liveSessionRecoverer (recoverer.go)
// joins the still-resident domains (virsh list) to these records to produce the
// RecoveredSession set the DriverService re-adopts (so a retried CloneFromImage
// re-uses the same never-recycled index instead of burning a second, D66).
//
// Same posture as live.go / durablecounter.go: reachable on the live path
// (NewSessionRecordStore under DS_HOSTAGENT_LIVE, offline.go), STDLIB-ONLY
// (os/encoding/json, no cgo). Records are JSON files at
// <OverlayDir>/.ds-sessions/<sessionUUID>.json, written ATOMICALLY (temp +
// rename) so a crash mid-write never leaves a torn record, and removed when the
// session is torn down (§4.2) so a destroyed session is not re-adopted.

package libvirt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// sessionRecordsSubdir is the per-host directory (under OverlayDir) the session records
// live in — a hidden subdir sibling to the overlays. Single-sourced from trustpath (an
// ALIAS, not an independent literal) so the store dir and the package tests that name
// the subdir cannot drift from the one canonical value.
const sessionRecordsSubdir = trustpath.SessionRecordsSubdir

// SessionRecord is the durable host-side record of a booted session: the global
// session UUID, the hypervisor-local domain UUID, and the three-keys-agree
// Binding. It is exactly what the SessionRecoverer joins a resident domain to.
type SessionRecord struct {
	SessionUUID string  `json:"session_uuid"`
	DomainUUID  string  `json:"domain_uuid"`
	Binding     Binding `json:"binding"`

	// CABundleRef is the opaque per-session interception-CA bundle ref the create
	// carried (CreateRequest.CABundleRef — VmSpec.material.ca_bundle_ref, or the daemon
	// skip-gate default "ca:<uuid>"). It is persisted here because the durable record is
	// the LAST carrier of that ref at teardown time: the frozen DestroyRequest carries
	// only the session_uuid, and the clone cache holds the wire CloneFromImageResponse,
	// which never names the CA. Without it a converged §4.2 Destroy cannot find — and so
	// cannot dispose — the host-readable CA bundle (the cert AND the proxy-bound private
	// key) the orchestrator producer dropped under <OverlayDir>/.ds-ca-bundles, and D82's
	// "destroyed at teardown" is false.
	//
	// ADDITIVE + omitempty: records written BEFORE this field unmarshal to "" with no
	// error, and the disposal is simply SKIPPED for them (the operator-side
	// `ds-serve-stack.sh down --purge` sweep is the backstop for that pre-upgrade
	// residue). The ref is an opaque handle, never key material (D39/D76).
	CABundleRef string `json:"ca_bundle_ref,omitempty"`
}

// SessionRecordStore persists + reads SessionRecords by session UUID. The create
// path Puts a record once a session has booted; the recoverer Gets the record for
// each resident domain; Destroy removes it on teardown. It is a seam so the
// offline path is fakeable (the live impl is the file store; off the gate the
// composition root leaves it nil and no record is written).
type SessionRecordStore interface {
	// Put persists the session record, overwriting any prior record for the same
	// session (idempotent on session_uuid — a re-create converges).
	Put(ctx context.Context, rec SessionRecord) error
	// Get returns the record for sessionUUID. A missing record is (zero, false,
	// nil); an unreadable/corrupt record is a non-nil error (fail-loud — a corrupt
	// record must not silently drop a resident session from recovery).
	Get(ctx context.Context, sessionUUID string) (SessionRecord, bool, error)
	// Remove deletes the record for sessionUUID (the §4.2 teardown). A missing
	// record is a no-op success.
	Remove(ctx context.Context, sessionUUID string) error
}

// fileSessionRecordStore is the production SessionRecordStore: one JSON file per
// session under <OverlayDir>/.ds-sessions.
type fileSessionRecordStore struct {
	dir string
}

// NewFileSessionRecordStore builds the file store under baseDir/.ds-sessions,
// creating the directory if absent. baseDir is the host's OverlayDir (the
// per-session state area).
func NewFileSessionRecordStore(baseDir string) (*fileSessionRecordStore, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("session record store: empty base dir")
	}
	dir := trustpath.SessionRecordsSubdirPath(baseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("session record store: mkdir %q: %w", dir, err)
	}
	return &fileSessionRecordStore{dir: dir}, nil
}

// recordPath is the deterministic JSON path for a session's record. The subdir + the
// sanitize+".json" leaf are single-sourced through trustpath (s.dir is already
// trustpath.SessionRecordsSubdirPath(baseDir)), so this consumer carries no inline
// subdir/extension transform of its own.
func (s *fileSessionRecordStore) recordPath(sessionUUID string) string {
	return filepath.Join(s.dir, trustpath.SessionRecordFilename(sessionUUID))
}

func (s *fileSessionRecordStore) Put(_ context.Context, rec SessionRecord) error {
	if rec.SessionUUID == "" {
		return fmt.Errorf("session record store: empty session uuid")
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("session record store: marshal %s: %w", rec.SessionUUID, err)
	}
	path := s.recordPath(rec.SessionUUID)
	tmp, err := os.CreateTemp(s.dir, ".ds-rec-*.tmp")
	if err != nil {
		return fmt.Errorf("session record store: stage temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("session record store: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("session record store: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("session record store: rename -> %q: %w", path, err)
	}
	return nil
}

func (s *fileSessionRecordStore) Get(_ context.Context, sessionUUID string) (SessionRecord, bool, error) {
	data, err := os.ReadFile(s.recordPath(sessionUUID))
	if err != nil {
		if os.IsNotExist(err) {
			return SessionRecord{}, false, nil
		}
		return SessionRecord{}, false, fmt.Errorf("session record store: read %s: %w", sessionUUID, err)
	}
	var rec SessionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return SessionRecord{}, false, fmt.Errorf("session record store: unmarshal %s: %w", sessionUUID, err)
	}
	return rec, true, nil
}

func (s *fileSessionRecordStore) Remove(_ context.Context, sessionUUID string) error {
	if err := os.Remove(s.recordPath(sessionUUID)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("session record store: remove %s: %w", sessionUUID, err)
	}
	return nil
}

// Compile-time assertion: the file store satisfies the seam.
var _ SessionRecordStore = (*fileSessionRecordStore)(nil)
