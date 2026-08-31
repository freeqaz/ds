// SPDX-License-Identifier: Apache-2.0

// cabundlesource — the production host-side CABundleSource (the cainject.go step-7
// fetch seam) for the M0 trust-path (doc 16 §4; D17/D82). The ORCHESTRATOR mints the
// per-session interception CA (controlplane/liveedges.go -> identity.v1
// MintInterceptionCA) and drops the resulting PEM to a host-readable store keyed by
// the opaque caBundleRef the create carries (VmSpec.material.ca_bundle_ref). This
// source is the host-agent's CONSUME side: it reads that PEM back by ref. No re-mint,
// no host-agent->identity dial, no identity creds on the host — the host-agent only
// reads bytes the orchestrator placed on the shared trust path (the M0 trust-path
// decision, 2026-06-16; the rejected alternative re-minted via MintInterceptionCA,
// which would hand the guest a CA the egress gateway never holds -> interception
// fails OPEN).
//
// FAIL-CLOSED (doc 16 §4): a missing/unreadable bundle is an ERROR, never an empty
// return — InjectCA turns either into a create abort before the first guest TLS byte.
// The fetched bytes are still validated by cainject.go (must parse to a CA:TRUE
// anchor) and verified into the overlay before boot; this source only resolves the
// ref to bytes.
//
// Same posture as live.go / attachminter.go / sessionrecord.go: reachable on the live
// path (wired in the host-agent under DS_HOSTAGENT_LIVE), STDLIB-ONLY (os, no cgo).
// Bundles are PEM files at <OverlayDir>/.ds-ca-bundles/<caBundleRef>.pem.
//
// SINGLE-SOURCED PATH (doc 15 §4.1 step 7): this CONSUMER derives the store subdir,
// the ref->filename sanitize, and the on-disk PEM path from internal/trustpath — the
// SAME package the orchestrator PRODUCER (controlplane/liveedges.go) writes through —
// so the producer writes exactly the file this source reads and the two cannot drift.

package libvirt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// fileCABundleSource is the production CABundleSource: it reads the per-session
// interception-CA PEM the orchestrator dropped under <OverlayDir>/.ds-ca-bundles,
// keyed by the opaque caBundleRef.
type fileCABundleSource struct {
	dir string
}

// NewFileCABundleSource builds the file source under baseDir/.ds-ca-bundles, creating
// the directory if absent (so a host that has not yet received a drop still has a
// well-formed empty store — a fetch then fails closed on the missing file, not on a
// missing dir). baseDir is the host's OverlayDir (the per-session state area).
func NewFileCABundleSource(baseDir string) (*fileCABundleSource, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("CA bundle source: empty base dir")
	}
	dir := trustpath.SubdirPath(baseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("CA bundle source: mkdir %q: %w", dir, err)
	}
	return &fileCABundleSource{dir: dir}, nil
}

// bundlePath is the deterministic PEM path for a caBundleRef. The leaf (sanitize +
// ".pem" extension) is derived from trustpath.BundleFilename — the same transform the
// orchestrator producer's write uses — so the consumer reads precisely the file the
// producer drops. s.dir is already trustpath.SubdirPath(baseDir).
func (s *fileCABundleSource) bundlePath(caBundleRef string) string {
	return filepath.Join(s.dir, trustpath.BundleFilename(caBundleRef))
}

// FetchCABundle resolves the caBundleRef to the PEM bytes the orchestrator dropped.
// A missing file is fail-closed (the orchestrator drop has not arrived — the create
// must not proceed to a session with no provable trust anchor); an empty ref is a
// caller error.
func (s *fileCABundleSource) FetchCABundle(_ context.Context, caBundleRef string) ([]byte, error) {
	if caBundleRef == "" {
		return nil, fmt.Errorf("CA bundle source: empty ca bundle ref")
	}
	data, err := os.ReadFile(s.bundlePath(caBundleRef))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CA bundle %q not present in host store %s (orchestrator drop missing) — fail-closed (D17)", caBundleRef, s.dir)
		}
		return nil, fmt.Errorf("CA bundle source: read %q: %w", caBundleRef, err)
	}
	return data, nil
}

var _ CABundleSource = (*fileCABundleSource)(nil)
