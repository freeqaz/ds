// SPDX-License-Identifier: Apache-2.0

//go:build linux

// admissionshm_linux.go is the LIVE (Linux-only) POSIX-shm body of the
// host-agent-owned DNS-2b admission-map segment lifecycle. It is compiled ONLY on
// Linux (POSIX shm is Linux-only here); the non-Linux compile target takes
// admissionshm_other.go (a no-touch stand-in) so a cross-platform build still
// compiles — mirroring sessiontokenvsock_{linux,other}.go.
//
// STDLIB-ONLY (no cgo): glibc's shm_open()/shm_unlink() are thin wrappers that map a
// POSIX shm name "/name" to the file "/dev/shm/name" (strip the single leading "/",
// prepend the tmpfs mount) and open/unlink it. We replicate that EXACT mapping with
// golang.org/x/sys/unix (the SAME no-cgo posture the package keeps — cgo is isolated
// in internal/nftbridge), so the object the host creates is bit-for-bit the one the
// ds-dnsgate writer / ds-tlsproxy reader open via libc::shm_open on the same name.
//
// HEADER-OWNERSHIP BOUNDARY: Create only ENSURES the named object EXISTS
// (O_CREAT|O_RDWR, 0600 — byte-identical flags+mode to ds-admission-shm's
// Segment::create_named). It does NOT ftruncate/size or write the ds-admission-shm
// header: the WRITER owns that (its create_named ftruncates to segment_len and
// write_header's the layout in place; its attach_named_writer REJECTS a too-small
// placeholder and falls through to create_named). So there is no Go-side re-derivation
// of the Rust crate's segment_len/slot constants (no drift), and the existing reattach
// e2e is the guard. Unlink removes the named object on host-orchestrated teardown.

package libvirt

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// shmDevDir is the tmpfs mount POSIX shm objects live under on Linux (glibc's
// shm_open/shm_unlink resolve "/name" to "/dev/shm/name"). Single point of the
// name→path mapping so Create and Unlink agree.
const shmDevDir = "/dev/shm"

// shmPerm is the POSIX shm object create mode — 0600, byte-identical to
// ds-admission-shm's Segment::create_named (O_CREAT|O_RDWR, 0o600). The object is owned
// by the host agent's own uid; the same-uid ds-dnsgate writer opens it (the M0
// same-user qemu:///session posture — the host agent already owns taps under its own
// uid). A cross-uid writer would need a wider mode; the M0 posture is same-uid, so 0600
// is correct and least-privilege.
const shmPerm = 0o600

// liveAdmissionSegment is the production AdmissionSegment: it create-ensures and
// unlinks the host-wide named POSIX shm object on /dev/shm. It is constructed ONLY on
// the live path (newLiveAdmissionSegment, behind DS_HOSTAGENT_LIVE) with the
// single-sourced AdmissionShmName().
type liveAdmissionSegment struct {
	// name is the POSIX shm name ("/ds-admission" or the DS_ADMISSION_SHM_NAME
	// override), single-sourced via AdmissionShmName() so it agrees with the
	// writer/reader.
	name string
	// path is the resolved /dev/shm/<name> file the create/unlink operate on (derived
	// once from name so Create and Unlink can never disagree on the mapping).
	path string
}

// newLiveAdmissionSegment builds the live AdmissionSegment from the single-sourced shm
// name. It VALIDATES the name shape (must be "/name" with no embedded slash — the SAME
// rule ds-admission-shm's shm_cname enforces) at construction so a malformed override
// fails LOUDLY here rather than producing a surprising /dev/shm path. It touches no
// filesystem object yet (Create does that at bring-up).
func newLiveAdmissionSegment(name string) (AdmissionSegment, error) {
	path, err := shmPathForName(name)
	if err != nil {
		return nil, err
	}
	return &liveAdmissionSegment{name: name, path: path}, nil
}

// shmPathForName maps a POSIX shm name "/name" to its /dev/shm/<name> file path,
// replicating glibc's shm_open name handling (strip the single leading "/", reject an
// embedded "/" or a NUL — the SAME validation as ds-admission-shm's shm_cname). The
// resulting path is cleaned and asserted to stay directly under /dev/shm so a crafted
// name can never escape the tmpfs mount.
func shmPathForName(name string) (string, error) {
	if !strings.HasPrefix(name, "/") || len(name) < 2 || strings.Contains(name[1:], "/") {
		return "", fmt.Errorf("admission shm: POSIX shm name must be \"/name\" with no embedded slash, got %q", name)
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("admission shm: shm name has NUL: %q", name)
	}
	path := filepath.Join(shmDevDir, name[1:])
	// Defense in depth: the join of a validated single-component name can only land
	// directly under /dev/shm, but assert it so a future validation slip cannot let a
	// create/unlink touch a path outside the shm mount.
	if filepath.Dir(path) != shmDevDir {
		return "", fmt.Errorf("admission shm: resolved path %q escapes %s", path, shmDevDir)
	}
	return path, nil
}

// Create ENSURES the host-wide named POSIX shm object exists, with the SAME flags+mode
// as ds-admission-shm's writer create (O_CREAT|O_RDWR, 0600 — NOT O_EXCL, so a second
// Create on an existing object CONVERGES rather than double-failing: idempotent
// bring-up). It does NOT ftruncate/size or write the header — the WRITER owns the
// sizing+header (see the file header). A create failure under the live gate is FATAL to
// the caller (run() refuses the live path rather than serving with no host-owned
// segment, docs/sessions/13 §Rollout-ordering). The opened fd is closed immediately:
// the host only needs the object to EXIST for the writer to attach; it holds no
// mapping itself.
func (s *liveAdmissionSegment) Create(_ context.Context) error {
	fd, err := unix.Open(s.path, unix.O_CREAT|unix.O_RDWR, shmPerm)
	if err != nil {
		return fmt.Errorf("admission shm create %s (%s): %w", s.name, s.path, err)
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("admission shm create %s: close fd: %w", s.name, err)
	}
	return nil
}

// Unlink shm_unlink's the host-wide named segment on host-orchestrated teardown
// (NFT-6-aligned), so the object does not outlive the host. It is IDEMPOTENT: an
// already-absent object (ENOENT) is a no-op success — the no-op-on-absent contract
// every host-agent teardown seam holds (so a teardown that runs without a prior
// bring-up, or a double teardown, converges). The underlying inode persists until the
// last writer/reader unmaps + closes it (POSIX shm semantics), so an in-flight writer
// is not yanked out from under — only the NAME is removed, exactly the clean-teardown
// the task asks for.
func (s *liveAdmissionSegment) Unlink(_ context.Context) error {
	if err := unix.Unlink(s.path); err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("admission shm unlink %s (%s): %w", s.name, s.path, err)
	}
	return nil
}
