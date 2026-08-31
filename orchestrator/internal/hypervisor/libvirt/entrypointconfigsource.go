// SPDX-License-Identifier: Apache-2.0

// entrypointconfigsource — the host-agent's opaque-ref → bytes fetch seam for the
// EntrypointConfig builder (the gap-1 ref→bytes path; D38, doc 15 §4.1 step 8).
// It MIRRORS cabundlesource.go exactly: the orchestrator pre-materializes the
// role-axis runtime-overlay (and any env-spec) material to a host-readable file
// store under OverlayDir, keyed by the opaque ref the create carries; the host
// agent READS it back by ref here — runtime-IGNORANT (the bytes are opaque
// pass-through; this source never parses them, it only resolves ref→bytes).
//
// FAIL-CLOSED (the cabundlesource.go posture): an empty ref is a caller error and
// a missing/unreadable file is an ERROR, never an empty-bytes "success" — the
// builder must never silently drop the role overlay it was told to carry. The
// fetched bytes ride onto runtimev1.EntrypointConfig.role_overlay_ref as opaque
// pass-through (BuildEntrypointConfig); they are NEVER credential material
// (D17/D39 — the builder's validateEntrypointConfig also fail-closes a smuggled
// PEM/key on the overlay channel, defense in depth).
//
// GATE-AWARE CONSTRUCTOR (the newGatedCAInjector / NewOverlayStore template):
// NewEntrypointConfigSource returns the live file store under DS_HOSTAGENT_LIVE
// and the offline fake otherwise (the sandbox / CI / every unit test), so the
// create choreography runs offline against the fake while the operator host reads
// the orchestrator's real drop. STDLIB-ONLY (os, no cgo — the doc.go / seams.go
// posture). Material lives at <OverlayDir>/.ds-entrypoint-refs/<ref>.

package libvirt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// entrypointRefsSubdir is the per-host directory (under OverlayDir) the
// orchestrator-dropped opaque entrypoint refs (the role-axis runtime overlay / env-spec
// material) live in — a hidden subdir sibling to the overlays, the CA bundles, the
// session records, and the attach tokens. Single-sourced from trustpath (an ALIAS, not
// an independent literal) so the store dir and the package tests that name the subdir
// cannot drift from the one canonical value.
const entrypointRefsSubdir = trustpath.EntrypointRefsSubdir

// EntrypointConfigSource resolves the opaque entrypoint-config ref the create path
// carries (the role-axis runtime-overlay / env-spec material the orchestrator
// pre-materialized) into the raw bytes the builder carries onto
// runtimev1.EntrypointConfig.role_overlay_ref. It is the host-agent's CONSUME side
// — runtime-IGNORANT (it never parses the bytes, only resolves ref→bytes), kept as
// an interface so the builder path is offline-fakeable (the real fetch is a
// host-readable file read; the offline fake serves fixtures). A nil/empty return
// MUST be treated as fail-closed by the caller: no bytes for a named ref means the
// overlay the create was told to carry is missing.
type EntrypointConfigSource interface {
	// FetchEntrypointRef returns the raw OPAQUE bytes for ref (the role-axis
	// runtime-overlay / env-spec material the orchestrator dropped). An empty ref is
	// a caller error; a missing/unreadable file is fail-closed (an ERROR, never an
	// empty-bytes success). The bytes are pass-through — never inspected here.
	FetchEntrypointRef(ctx context.Context, ref string) (data []byte, err error)
}

// fileEntrypointConfigSource is the production EntrypointConfigSource: it reads the
// opaque per-session entrypoint material the orchestrator dropped under
// <OverlayDir>/.ds-entrypoint-refs, keyed by the opaque ref. It mirrors
// fileCABundleSource exactly.
type fileEntrypointConfigSource struct {
	dir string
}

// NewFileEntrypointConfigSource builds the file source under
// baseDir/.ds-entrypoint-refs, creating the directory if absent (so a host that
// has not yet received a drop still has a well-formed empty store — a fetch then
// fails closed on the missing file, not on a missing dir). baseDir is the host's
// OverlayDir (the per-session state area). Mirrors NewFileCABundleSource.
func NewFileEntrypointConfigSource(baseDir string) (*fileEntrypointConfigSource, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("entrypoint config source: empty base dir")
	}
	dir := trustpath.EntrypointRefsSubdirPath(baseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("entrypoint config source: mkdir %q: %w", dir, err)
	}
	return &fileEntrypointConfigSource{dir: dir}, nil
}

// refPath is the deterministic file path for an opaque ref. The subdir + the sanitize
// leaf (no extension — the material is opaque pass-through) are single-sourced through
// trustpath (s.dir is already trustpath.EntrypointRefsSubdirPath(baseDir)), so a ref
// carrying a slash or other separator can never escape the store directory and this
// consumer carries no inline transform of its own.
func (s *fileEntrypointConfigSource) refPath(ref string) string {
	return filepath.Join(s.dir, trustpath.EntrypointRefFilename(ref))
}

// FetchEntrypointRef resolves the opaque ref to the bytes the orchestrator dropped.
// A missing file is fail-closed (the orchestrator drop has not arrived — the create
// must not carry a config whose role overlay silently vanished); an empty ref is a
// caller error. Mirrors fileCABundleSource.FetchCABundle.
func (s *fileEntrypointConfigSource) FetchEntrypointRef(_ context.Context, ref string) ([]byte, error) {
	if ref == "" {
		return nil, fmt.Errorf("entrypoint config source: empty ref")
	}
	data, err := os.ReadFile(s.refPath(ref))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("entrypoint ref %q not present in host store %s (orchestrator drop missing) — fail-closed (D38)", ref, s.dir)
		}
		return nil, fmt.Errorf("entrypoint config source: read %q: %w", ref, err)
	}
	return data, nil
}

var _ EntrypointConfigSource = (*fileEntrypointConfigSource)(nil)

// fakeEntrypointConfigSource is the offline EntrypointConfigSource: it serves a
// fixed map of ref→bytes (the synthetic fixtures the unit tests + the offline
// create path exercise), fail-closing on an empty or unknown ref EXACTLY as the
// file store does. It is the default off the DS_HOSTAGENT_LIVE gate (the sandbox /
// CI / every unit test), so the builder path is provable offline against fixtures
// (D50) — no orchestrator drop, no host store, no live substrate.
type fakeEntrypointConfigSource struct {
	// refs maps an opaque ref to its pre-materialized opaque bytes. An empty/nil map
	// is the fresh-host case: every fetch of a named ref fails closed.
	refs map[string][]byte
}

// NewFakeEntrypointConfigSource builds the offline fake from a fixture map. A nil
// map is tolerated (it behaves as an empty store — every named-ref fetch fails
// closed), so a host with no overlays to carry still constructs a usable source.
func NewFakeEntrypointConfigSource(refs map[string][]byte) *fakeEntrypointConfigSource {
	return &fakeEntrypointConfigSource{refs: refs}
}

// FetchEntrypointRef serves the fixture bytes for ref, fail-closing on an empty or
// unknown ref the same way the file store does (so a test against the fake asserts
// the SAME fail-closed contract the live path enforces).
func (s *fakeEntrypointConfigSource) FetchEntrypointRef(_ context.Context, ref string) ([]byte, error) {
	if ref == "" {
		return nil, fmt.Errorf("entrypoint config source: empty ref")
	}
	data, ok := s.refs[ref]
	if !ok {
		return nil, fmt.Errorf("entrypoint ref %q not present in fake store (fixture missing) — fail-closed (D38)", ref)
	}
	// Defend against an empty fixture masquerading as a successful resolve: a named
	// ref the orchestrator dropped is non-empty material; a zero-length entry is the
	// same fail-closed case as a missing file (no provable overlay bytes).
	if len(data) == 0 {
		return nil, fmt.Errorf("entrypoint ref %q resolved to empty bytes — fail-closed (D38)", ref)
	}
	return append([]byte(nil), data...), nil
}

var _ EntrypointConfigSource = (*fakeEntrypointConfigSource)(nil)

// NewEntrypointConfigSource is the gate-aware constructor (the newGatedCAInjector /
// NewOverlayStore template): the real host-readable file store under
// <OverlayDir>/.ds-entrypoint-refs when DS_HOSTAGENT_LIVE=1, the offline fake
// (seeded with the given fixtures) otherwise — so the create choreography runs
// offline against fixtures while the operator host reads the orchestrator's real
// drop. The live/offline choice rides the single EnvHostAgentLive source of truth,
// never a scattered env check. On the live path a missing OverlayDir is a
// construction error (mirroring the other live bindings, never a silent
// fall-through to the fake).
func NewEntrypointConfigSource(cfg LiveConfig, fixtures map[string][]byte) (EntrypointConfigSource, error) {
	if LiveEnabled() {
		if cfg.OverlayDir == "" {
			return nil, fmt.Errorf("live entrypoint config source requires an overlay/state dir for the ref store (DS_HOSTAGENT_LIVE)")
		}
		return NewFileEntrypointConfigSource(cfg.OverlayDir)
	}
	return NewFakeEntrypointConfigSource(fixtures), nil
}
