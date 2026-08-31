// SPDX-License-Identifier: Apache-2.0

// durablecounter — the production crash-safe never-recycled index counter (D66),
// the real backing for the IndexCounter / ReseedableCounter seams (alloc.go /
// seams.go) on the operator host. The in-memory memCounter (alloc.go) and the
// host-agent's persistentCounter stub satisfy the seam process-locally but are
// NOT crash-safe: a host-agent restart re-hands indices from 0 and could collide
// with a still-resident session's never-recycled index. durableCounter closes
// that hole by persisting the next-index to a single file ATOMICALLY (write-temp
// + rename) BEFORE Next() returns an index, so an index handed out is never handed
// out again — even across a restart.
//
// Same posture as live.go / snapshot_libvirt.go: reachable on the live path
// (NewIndexCounter under DS_HOSTAGENT_LIVE, offline.go), STDLIB-ONLY (os/strconv,
// no cgo). It implements ReseedableCounter (Next + SeedAtLeast) so the SAME
// instance backs BOTH the Allocator (as IndexCounter, the create path's index
// draw) AND a future NewDriverServiceWithRecovery wiring (as the ReseedableCounter
// the crash-matrix re-adoption re-seeds past the highest recovered index) — one
// monotonic source, never two counters that could diverge.
//
// CRASH-SAFETY / never-recycle (D66): Next() persists next+1 to disk BEFORE
// returning the current index, and the persist is atomic (a temp file rename), so
// a crash after handing index i finds next>=i+1 on restart (i is never re-handed)
// and a crash mid-persist leaves the file either fully-old or fully-new (never a
// torn half-index). The on-disk value is monotonic: it only advances.
//
// SeedAtLeast is the restart resume point: it advances the in-memory next past the
// highest recovered index FORWARD-ONLY (a highest below the current position is a
// no-op). It does NOT need to persist eagerly — the recover-before-serve latch
// (orch106) gates the create path until RecoverSessions completes, RecoverSessions
// is idempotent, and the FIRST Next() after a seed persists next+1 (already past
// highest) — so a crash between a seed and the first draw is corrected by the
// idempotent re-seed on the next restart. It still persists best-effort so the
// on-disk high-water mark tracks the seed even before the first draw.

package libvirt

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// durableCounter is a crash-safe never-recycling index counter backed by a single
// file holding the NEXT index to hand. It implements ReseedableCounter (and thus
// IndexCounter).
type durableCounter struct {
	path string
	mu   sync.Mutex
	next uint64 // the next index Next() will hand; persisted to path
}

// NewDurableCounter opens (or initializes) the durable counter at path. It reads
// the persisted next-index (a fresh path starts at 0), so a restart RESUMES past
// every index already handed — the never-recycle invariant survives the restart.
// A present-but-unparseable counter file is a hard error (a corrupt index store
// must never silently reset to 0 and re-hand live indices).
func NewDurableCounter(path string) (*durableCounter, error) {
	if path == "" {
		return nil, fmt.Errorf("durable counter: empty path")
	}
	c := &durableCounter{path: path}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		v, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if perr != nil {
			return nil, fmt.Errorf("durable counter: parse persisted index in %q: %w", path, perr)
		}
		c.next = v
	case os.IsNotExist(err):
		c.next = 0 // fresh host: start at 0
	default:
		return nil, fmt.Errorf("durable counter: read %q: %w", path, err)
	}
	return c, nil
}

// persist writes the next-index to path ATOMICALLY (write a sibling temp file +
// rename), so a concurrent crash never leaves a torn half-index. The caller holds
// c.mu.
func (c *durableCounter) persist(next uint64) error {
	dir := filepath.Dir(c.path)
	tmp, err := os.CreateTemp(dir, ".ds-index-*.tmp")
	if err != nil {
		return fmt.Errorf("durable counter: stage temp in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(strconv.FormatUint(next, 10)); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("durable counter: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("durable counter: close temp: %w", err)
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("durable counter: rename %q -> %q: %w", tmpName, c.path, err)
	}
	return nil
}

// Next returns the next never-recycled index and advances the counter, persisting
// the advance to disk BEFORE returning so a restart never re-hands the index. A
// persist failure is surfaced (the index is NOT handed out on a persist failure —
// the create path fails rather than risk a non-durable index).
func (c *durableCounter) Next() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := c.next
	if err := c.persist(idx + 1); err != nil {
		return 0, fmt.Errorf("durable counter: persist after index %d: %w", idx, err)
	}
	c.next = idx + 1
	return idx, nil
}

// SeedAtLeast advances the counter so the next Next() yields an index STRICTLY
// greater than highest — the restart resume point. FORWARD-ONLY: a highest below
// the current next is a no-op (the counter never moves backward, D66). The seam
// has no error return; the persist is best-effort (the next Next() re-persists a
// value already past highest, and the recover-before-serve latch + idempotent
// RecoverSessions correct a crash before that draw).
func (c *durableCounter) SeedAtLeast(highest uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	want := highest + 1
	if c.next >= want {
		return // forward-only no-op
	}
	c.next = want
	_ = c.persist(want)
}

// Compile-time assertions: the durable counter satisfies both seams.
var (
	_ IndexCounter      = (*durableCounter)(nil)
	_ ReseedableCounter = (*durableCounter)(nil)
)
