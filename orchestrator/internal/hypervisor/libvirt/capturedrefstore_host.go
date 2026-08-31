// SPDX-License-Identifier: Apache-2.0

// capturedrefstore_host — the production file-backed CapturedRefStore (seams.go):
// the PRODUCER/host durable half of the in-memory snapshotRefs registry
// (service.go). A captured snapshot_ref registered ONLY in the per-process map is
// lost the moment the driver restarts, so a post-restart ExportDiskDelta rooted at
// a still-live point-in-time would falsely fail NotFound. This store closes the
// WRITE side of that loop: Snapshot records each captured ref here, and on a
// restart the captured-ref-aware SessionRecoverer
// (NewSessionRecovererWithCapturedRefs) reads the set back out to populate
// RecoveredSession.SnapshotRefs.
//
// Same posture as sessionrecord.go / live.go / durablecounter.go: reachable on the
// live path (NewCapturedRefStore under DS_HOSTAGENT_LIVE, offline.go), STDLIB-ONLY
// (os/encoding/json, no cgo). It lives in the SAME per-session `.ds-sessions`
// durable area as the SessionRecord it annotates — a session's captured refs live
// BESIDE the binding they belong to — so a §4.2 Destroy purges both from one dir.
// The captured-ref set is ONE JSON file per session at
// <OverlayDir>/.ds-sessions/<sanitize(sessionUUID)>.refs.json (the `.refs.json`
// leaf keeps it distinct from the record store's `<sanitize(sessionUUID)>.json`
// sibling), written ATOMICALLY (temp + rename) so a crash mid-write never leaves a
// torn set, and removed when the session is torn down (§4.2). The subdir + sanitize
// are single-sourced through trustpath so the store dir cannot drift from the
// record store's.

package libvirt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// capturedRefsFileExt is the leaf suffix for a session's captured-ref set file. It
// is DELIBERATELY distinct from the SessionRecord's ".json" leaf so the two durable
// artifacts for one session (its binding record and its captured-ref set) coexist in
// the SAME `.ds-sessions` dir without colliding.
const capturedRefsFileExt = ".refs.json"

// fileCapturedRefStore is the production CapturedRefStore: one JSON file per session
// (a JSON array of the captured snapshot_refs) under <OverlayDir>/.ds-sessions.
type fileCapturedRefStore struct {
	dir string
}

// NewFileCapturedRefStore builds the file store under baseDir/.ds-sessions, creating
// the directory if absent. baseDir is the host's OverlayDir (the per-session state
// area) — the SAME dir NewFileSessionRecordStore uses, so a session's captured refs
// live beside its binding record.
func NewFileCapturedRefStore(baseDir string) (*fileCapturedRefStore, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("captured-ref store: empty base dir")
	}
	dir := trustpath.SessionRecordsSubdirPath(baseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("captured-ref store: mkdir %q: %w", dir, err)
	}
	return &fileCapturedRefStore{dir: dir}, nil
}

// refsPath is the deterministic JSON path for a session's captured-ref set. The
// subdir is trustpath's canonical one and the leaf is sanitize(sessionUUID)+".refs.json",
// so this producer writes precisely the file the read-back leg reads.
func (s *fileCapturedRefStore) refsPath(sessionUUID string) string {
	return filepath.Join(s.dir, trustpath.Sanitize(sessionUUID)+capturedRefsFileExt)
}

// readSet reads the current captured-ref set for sessionUUID as a map (the on-disk
// order is not significant — the set is the value). A missing file is the empty set
// (the common no-capture case), fail-closed. A corrupt file is a non-nil error
// (fail-loud — a still-held base must never be silently dropped).
func (s *fileCapturedRefStore) readSet(sessionUUID string) (map[string]struct{}, error) {
	data, err := os.ReadFile(s.refsPath(sessionUUID))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, nil
		}
		return nil, fmt.Errorf("captured-ref store: read %s: %w", sessionUUID, err)
	}
	var refs []string
	if err := json.Unmarshal(data, &refs); err != nil {
		return nil, fmt.Errorf("captured-ref store: unmarshal %s: %w", sessionUUID, err)
	}
	set := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		set[ref] = struct{}{}
	}
	return set, nil
}

// writeSet atomically persists the captured-ref set for sessionUUID (temp + rename).
// The refs are written in a stable sorted order so a re-record that changes nothing
// re-produces a byte-identical file (idempotent on disk).
func (s *fileCapturedRefStore) writeSet(sessionUUID string, set map[string]struct{}) error {
	refs := make([]string, 0, len(set))
	for ref := range set {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	data, err := json.Marshal(refs)
	if err != nil {
		return fmt.Errorf("captured-ref store: marshal %s: %w", sessionUUID, err)
	}
	path := s.refsPath(sessionUUID)
	tmp, err := os.CreateTemp(s.dir, ".ds-refs-*.tmp")
	if err != nil {
		return fmt.Errorf("captured-ref store: stage temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("captured-ref store: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("captured-ref store: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("captured-ref store: rename -> %q: %w", path, err)
	}
	return nil
}

// RecordCapturedRef durably records that sessionUUID captured snapshotRef — a
// set-insert (re-recording the same (session, ref) converges to a byte-identical
// file). An empty sessionUUID or snapshotRef is rejected (the empty ref is the
// full-overlay sentinel, never a captured point-in-time). It reads the current set,
// adds the ref, and atomically rewrites the file only when the set actually changed.
func (s *fileCapturedRefStore) RecordCapturedRef(_ context.Context, sessionUUID, snapshotRef string) error {
	if sessionUUID == "" {
		return fmt.Errorf("captured-ref store: empty session uuid")
	}
	if snapshotRef == "" {
		return fmt.Errorf("captured-ref store: empty snapshot ref")
	}
	set, err := s.readSet(sessionUUID)
	if err != nil {
		return err
	}
	if _, ok := set[snapshotRef]; ok {
		return nil // already durable — idempotent no-op
	}
	set[snapshotRef] = struct{}{}
	return s.writeSet(sessionUUID, set)
}

// CapturedRefs returns the durable captured-ref set for sessionUUID. A session that
// captured nothing (or a fresh host) is (nil, nil) — the common empty case that
// re-seeds an empty set, fail-closed. A genuine read fault is a non-nil error
// (fail-loud). The returned order is not significant (the consumer re-seeds a SET),
// but it is stably sorted so callers get a deterministic slice.
func (s *fileCapturedRefStore) CapturedRefs(_ context.Context, sessionUUID string) ([]string, error) {
	set, err := s.readSet(sessionUUID)
	if err != nil {
		return nil, err
	}
	if len(set) == 0 {
		return nil, nil
	}
	refs := make([]string, 0, len(set))
	for ref := range set {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs, nil
}

// RemoveCapturedRefs drops the whole captured-ref set for sessionUUID (the §4.2
// teardown). A missing set is a no-op success (idempotent, the
// SessionRecordStore.Remove precedent).
func (s *fileCapturedRefStore) RemoveCapturedRefs(_ context.Context, sessionUUID string) error {
	if err := os.Remove(s.refsPath(sessionUUID)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("captured-ref store: remove %s: %w", sessionUUID, err)
	}
	return nil
}

// Compile-time assertion: the file store satisfies the seam.
var _ CapturedRefStore = (*fileCapturedRefStore)(nil)
