// SPDX-License-Identifier: Apache-2.0

// admissionshm — the host-agent-owned lifecycle of the DNS-2b shm admission-map
// segment (D131 Candidate A). The host agent CREATES (ensures) the host-wide named
// POSIX shm object at daemon bring-up and shm_unlink's it on host-orchestrated
// teardown, so the segment outlives the ds-dnsgate WRITER cleanly across a
// host-orchestrated restart and is torn down NFT-6-aligned at host stop.
//
// THE PRIOR FAIL-CLOSED STUB (replaced by this seam): ds-dnsgate self-created the
// segment on first boot (txn.rs AdmissionStores::with_shm_writer — create-or-reattach),
// so it survived a ds-dnsgate restart but was ORPHANED across host/session teardown
// (nothing ever unlinked it). The Go host agent did NOTHING with the segment (this is
// greenfield: grep over orchestrator/ found zero shm references). This file adds the
// host-owned create + unlink so the host owns the segment's birth and death.
//
// HEADER-OWNERSHIP BOUNDARY (pinned, lowest-drift): the host only ENSURES the named
// object EXISTS — it shm_open()s it O_CREAT and leaves the WRITER (ds-dnsgate) to own
// the sizing + the ds-admission-shm header (its create_named path ftruncates to
// segment_len(slots, rev_slots) and write_header's the magic/api_version/layout in
// place). So there is NO Go-side re-derivation of the Rust crate's segment_len /
// ADMISSION_SHM_DEFAULT_SLOTS (no drift surface). The writer's attach_named_writer
// branch REJECTS a host-created placeholder that is smaller than its mapping len and
// falls through to create_named, which re-inits the header in place — exactly the
// create-or-reattach the existing reattach e2e (dataplane/services/ds-dnsgate/tests/
// admission_shm_e2e.rs) is the regression guard for. The host owns the UNLINK so the
// object does not outlive the host.
//
// LIVE-GATING (additive, default-path-unchanged): the real create/unlink is reachable
// ONLY under DS_HOSTAGENT_LIVE=1 (the operator-host posture, the SAME single source of
// truth — LiveEnabled — every other live seam rides). With the env unset (the default,
// and the only path in the sandbox / CI / unit tests) NewAdmissionSegment returns a
// no-touch stand-in that creates/unlinks NOTHING — byte-identical to today. The shm
// read/write PATH stays independently gated by DS_ADMISSION_SHM_LIVE (ds-dnsgate
// writer) / DS_TLS1_LIVE (ds-tlsproxy reader), so with those off the services still use
// InMemoryAdmissionMap / the empty fail-closed reader — the fail-closed default is
// unchanged. POSIX-shm is Linux-only, so the real body is build-tagged
// (admissionshm_linux.go) with a non-Linux compile stub (admissionshm_other.go),
// mirroring sessiontokenvsock_{linux,other}.go.

package libvirt

import (
	"context"
	"os"
)

// EnvAdmissionShmName is the env var that OVERRIDES the default DNS-2b shm segment
// name. It single-sources with the Rust contract ds_contracts::dns_admission::
// ADMISSION_SHM_NAME_ENV ("DS_ADMISSION_SHM_NAME"): the host (this seam), the writer
// (ds-dnsgate), and the reader (ds-tlsproxy) read the SAME var so the rendezvous name
// never drifts on a hand-edited literal. An empty override is treated as unset (an
// empty string is never a valid POSIX shm name), matching admission_shm_name().
const EnvAdmissionShmName = "DS_ADMISSION_SHM_NAME"

// DefaultAdmissionShmName is the DEFAULT host-wide POSIX shm object name the DNS-2b
// admission map lives in when EnvAdmissionShmName is unset. It single-sources with the
// Rust contract ds_contracts::dns_admission::ADMISSION_SHM_DEFAULT_NAME ("/ds-admission").
// POSIX shm names must begin with "/" and contain no further "/" (shm_open(3)); this
// default obeys that.
const DefaultAdmissionShmName = "/ds-admission"

// AdmissionShmName resolves the host-wide DNS-2b shm segment name, mirroring the Rust
// contract admission_shm_name() EXACTLY so the host / writer / reader never drift: the
// EnvAdmissionShmName override when set AND non-empty, else DefaultAdmissionShmName. An
// empty override is treated as unset (an empty string is never a valid segment name).
// A malformed (non-"/"-prefixed) override is returned verbatim — name validation is
// shm_open's job, and a bad override should fail loudly at create, not be silently
// rewritten (the same posture as the Rust side).
func AdmissionShmName() string {
	if v := os.Getenv(EnvAdmissionShmName); v != "" {
		return v
	}
	return DefaultAdmissionShmName
}

// AdmissionSegment is the host-agent-owned lifecycle of the DNS-2b shm admission-map
// segment: Create ENSURES the host-wide named POSIX shm object exists (at daemon
// bring-up, BEFORE the ds-dnsgate writer attaches), and Unlink shm_unlink's it on
// host-orchestrated teardown (the graceful Shutdown drain, NFT-6-aligned). The two
// methods are the only seam the composition root wires; the writer/reader still
// attach to the object by the single-sourced AdmissionShmName().
type AdmissionSegment interface {
	// Create ensures the host-wide named segment exists (idempotent: a second Create
	// on an existing object CONVERGES, it does not double-fail). Under the live gate a
	// create failure is FATAL to the caller (docs/sessions/13 §Rollout-ordering: an
	// attach/create failure is fail-closed — never a silent no-segment continue); off
	// the gate it is a no-touch no-op.
	Create(ctx context.Context) error
	// Unlink shm_unlink's the host-wide named segment (idempotent: an already-absent
	// object is a no-op success — the no-op-on-absent contract every host-agent
	// teardown seam holds). Off the gate it is a no-touch no-op.
	Unlink(ctx context.Context) error
}

// noTouchAdmissionSegment is the default (gate-off) AdmissionSegment stand-in: it
// creates/unlinks NOTHING, so the daemon's behavior off DS_HOSTAGENT_LIVE is
// byte-identical to today (no /dev/shm object is ever touched). It is also the
// non-Linux compile target's real type (admissionshm_other.go returns it under the
// gate too, since POSIX shm is Linux-only).
type noTouchAdmissionSegment struct{}

// Create is a no-op success off the gate — nothing is created.
func (noTouchAdmissionSegment) Create(_ context.Context) error { return nil }

// Unlink is a no-op success off the gate — nothing was created to unlink.
func (noTouchAdmissionSegment) Unlink(_ context.Context) error { return nil }

// NewAdmissionSegment returns the gate-aware AdmissionSegment: the real POSIX-shm
// create/unlink body (admissionshm_linux.go newLiveAdmissionSegment) when
// DS_HOSTAGENT_LIVE=1 AND the platform supports POSIX shm (Linux), the no-touch
// stand-in otherwise. The segment name is resolved from the single-sourced
// AdmissionShmName() so the host, the ds-dnsgate writer, and the ds-tlsproxy reader
// rendezvous on one name. The live/offline choice rides the single EnvHostAgentLive
// source of truth, matching every other gate-aware seam (NewOverlayStore/NewBooter).
func NewAdmissionSegment(cfg LiveConfig) (AdmissionSegment, error) {
	if !LiveEnabled() {
		return noTouchAdmissionSegment{}, nil
	}
	return newLiveAdmissionSegment(AdmissionShmName())
}
