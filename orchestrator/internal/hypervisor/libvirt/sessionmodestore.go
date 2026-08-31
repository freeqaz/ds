// SPDX-License-Identifier: Apache-2.0

// sessionmodestore — the per-session resolved-SessionMode persistence (the
// serpent-CLI terminal-MVP single-source-of-the-mode store; docs/serpent-cli-mvp/
// 04-control-plane-and-session-mode.md §2.5/§2.7 + §5 "Mode drift between host
// facets"). The EntrypointProducer resolves a session's launch mode ONCE (the opaque
// overlay hint, else the per-host default; sessionmode.go) and PERSISTS it here, so
// the LATER serving-leg + minter wiring (U-HOST-SERVE) reads the SAME resolution the
// LaunchSpec.stdio was built from — the handle's transport tag, the serving child's
// --mode, and the in-guest stdio can never disagree.
//
// THIS UNIT (U-HOST-MODE) only RESOLVES + PERSISTS the mode and builds the right
// LaunchSpec; it does NOT mint a RAW_TERMINAL handle or dispatch a --mode child (that
// is U-HOST-SERVE). The store is the clean read-back seam exposed for that unit.
//
// Mirrors the fileAttachTokenStore / fileEntrypointConfigSource conventions exactly:
// a hidden per-host subdir under OverlayDir, sanitized per-session keys (so a session
// id can never escape the dir), atomic temp+rename writes, gate-aware construction
// (the real file store under DS_HOSTAGENT_LIVE, nil/no-op offline). STDLIB-ONLY,
// touches no substrate.

package libvirt

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// sessionModeSubdir is the per-host directory (under OverlayDir) the resolved
// per-session mode markers live in — a hidden subdir sibling to the overlays / attach
// tokens / session records, so it is never mistaken for an overlay. Single-sourced
// from trustpath (an ALIAS, not an independent literal) so the store dir and the
// package tests that name the subdir cannot drift from the one canonical value.
const sessionModeSubdir = trustpath.SessionModeSubdir

// SessionModeStore persists + reads back the per-session RESOLVED SessionMode. It is
// the single source the U-HOST-SERVE serving leg / attach minter consume so the
// handle transport, the serving child's mode, and LaunchSpec.stdio all agree on one
// resolution (doc 04 §5 drift guard). Idempotent on sessionUUID: a retried create
// re-writes the same resolved mode.
type SessionModeStore interface {
	// PutMode persists the resolved mode for the session (idempotent on sessionUUID;
	// a retried create overwrites with the same value). An empty sessionUUID is a
	// caller error.
	PutMode(ctx context.Context, sessionUUID string, mode SessionMode) error
	// ModeFor reads the persisted resolved mode for the session. An ABSENT marker
	// resolves to SessionModeStructured (the historical default — a session created
	// before this unit, or one whose producer did not persist, attaches structured),
	// found=false. A present marker returns its mode, found=true. A corrupt marker is
	// fail-loud (an error) — never silently defaulted, which would mask a terminal
	// session as structured and mis-route the handle.
	ModeFor(ctx context.Context, sessionUUID string) (mode SessionMode, found bool, err error)
	// RemoveMode deletes the session's persisted marker at the §4.2 TEARDOWN (doc 15
	// §4.2) — the SessionRecordStore.Remove contract ("removed when the session is torn
	// down (§4.2) so a destroyed session is not re-adopted") mirrored onto this store,
	// which holds the SAME class of host-internal per-session state. Without it every
	// destroyed session left a marker under <OverlayDir>/.ds-session-mode forever: a
	// host's marker dir grew without bound and a destroy→re-create of the same
	// session_uuid read the PRIOR resolution back (the producer overwrites at create, so
	// the stale read is not reachable today — but the leftover file is exactly the doc 06
	// §(b) clean-teardown residue). A MISSING marker is a no-op success (idempotent on
	// sessionUUID: an offline/never-resolved session and a re-driven teardown both
	// converge); a genuine store fault is an error.
	RemoveMode(ctx context.Context, sessionUUID string) error
}

// fileSessionModeStore is the production SessionModeStore: one tiny marker file per
// session under <OverlayDir>/.ds-session-mode containing the canonical lowercase mode
// name (sessionmode.go String()), written atomically (temp+rename). The serving leg /
// minter read the same files.
type fileSessionModeStore struct {
	baseDir string // the host's OverlayDir; the single-source root for trustpath.SessionModePath
	dir     string // = trustpath.SessionModeSubdirPath(baseDir); the marker dir for temp-staging
}

// NewFileSessionModeStore builds the store under baseDir/.ds-session-mode, creating
// the directory if absent. baseDir is the host's OverlayDir (the per-session state
// area). Mirrors NewFileAttachTokenStore / NewFileEntrypointConfigSource.
func NewFileSessionModeStore(baseDir string) (*fileSessionModeStore, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("session mode store: empty base dir")
	}
	dir := trustpath.SessionModeSubdirPath(baseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("session mode store: mkdir %q: %w", dir, err)
	}
	return &fileSessionModeStore{baseDir: baseDir, dir: dir}, nil
}

// modePath is the deterministic per-session marker path, derived from the single-source
// trustpath.SessionModePath(baseDir, sessionUUID) full-path helper — the SAME form the
// serving-leg/minter key on, so producer and consumer can never drift on the subdir or
// the sanitize transform. Byte-identical to filepath.Join(s.dir, sanitize(uuid)) since
// s.dir == trustpath.SessionModeSubdirPath(baseDir); a session id with a separator can
// never escape the store directory.
func (s *fileSessionModeStore) modePath(sessionUUID string) string {
	return trustpath.SessionModePath(s.baseDir, sessionUUID)
}

// PutMode writes the resolved mode marker atomically (temp + rename) so a crash
// mid-write never leaves a torn marker — the same posture as the attach-token store.
func (s *fileSessionModeStore) PutMode(_ context.Context, sessionUUID string, mode SessionMode) error {
	if sessionUUID == "" {
		return fmt.Errorf("session mode store: empty session uuid")
	}
	path := s.modePath(sessionUUID)
	tmp, err := os.CreateTemp(s.dir, ".ds-mode-*.tmp")
	if err != nil {
		return fmt.Errorf("session mode store: stage temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(mode.String()); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("session mode store: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("session mode store: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("session mode store: rename -> %q: %w", path, err)
	}
	return nil
}

// ModeFor reads the persisted mode. An absent marker is the historical default
// (structured, found=false) — NOT an error, so a pre-existing session reads cleanly.
// A present-but-unparseable marker is fail-loud (a corrupt marker must not silently
// downgrade a terminal session to structured and mis-route its handle).
func (s *fileSessionModeStore) ModeFor(_ context.Context, sessionUUID string) (SessionMode, bool, error) {
	if sessionUUID == "" {
		return SessionModeStructured, false, fmt.Errorf("session mode store: empty session uuid")
	}
	data, err := os.ReadFile(s.modePath(sessionUUID))
	if err != nil {
		if os.IsNotExist(err) {
			return SessionModeStructured, false, nil
		}
		return SessionModeStructured, false, fmt.Errorf("session mode store: read %s: %w", sessionUUID, err)
	}
	mode, err := ParseSessionMode(strings.TrimSpace(string(data)))
	if err != nil {
		return SessionModeStructured, false, fmt.Errorf("session mode store: corrupt marker for %s: %w", sessionUUID, err)
	}
	return mode, true, nil
}

// RemoveMode deletes the session's marker file (the §4.2 teardown purge). An ABSENT
// marker is a clean no-op success — the SAME idempotency the sibling
// fileSessionRecordStore.Remove holds (sessionrecord.go), and the behavior a re-driven
// destroy of an already-torn-down session needs; any OTHER remove fault surfaces so a
// marker dir the host could not prune is never reported clean. An empty sessionUUID is a
// caller error: trustpath.Sanitize maps "" to the literal "session", so a blind removal
// would delete an unrelated leaf rather than nothing.
func (s *fileSessionModeStore) RemoveMode(_ context.Context, sessionUUID string) error {
	if sessionUUID == "" {
		return fmt.Errorf("session mode store: empty session uuid")
	}
	if err := os.Remove(s.modePath(sessionUUID)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("session mode store: remove %s: %w", sessionUUID, err)
	}
	return nil
}

var _ SessionModeStore = (*fileSessionModeStore)(nil)

// NewSessionModeStore is the gate-aware constructor (the NewAttachTokenStore
// template): the real host-readable file store under <OverlayDir>/.ds-session-mode
// when DS_HOSTAGENT_LIVE=1, nil otherwise. Off the gate the producer persists nothing
// (the offline create path needs no read-back — the serving leg no-launches), so the
// config build stays byte-identical to today with no marker written. On the live path
// a missing OverlayDir is a construction error (mirroring the other live bindings).
func NewSessionModeStore(cfg LiveConfig) (SessionModeStore, error) {
	if !LiveEnabled() {
		return nil, nil
	}
	if cfg.OverlayDir == "" {
		return nil, fmt.Errorf("live session mode store requires an overlay/state dir (DS_HOSTAGENT_LIVE)")
	}
	return NewFileSessionModeStore(cfg.OverlayDir)
}
