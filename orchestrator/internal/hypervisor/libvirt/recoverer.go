// SPDX-License-Identifier: Apache-2.0

// recoverer — the production SessionRecoverer (seams.go), the host-resident
// re-observation half of the doc 15 §4 crash matrix. On a host-agent restart the
// per-process clone-cache + index allocator are lost; RecoverSessions re-observes
// the sessions still RUNNING on the host and joins them to their persisted
// SessionRecords (sessionrecord.go) so the DriverService can re-seed the Allocator
// past the highest recovered index (D66 never-recycle) AND re-adopt the clone
// cache — a retried CloneFromImage re-uses the recorded binding instead of burning
// a second never-recycled index.
//
// It is READ-ONLY re-observation (the seams.go contract): it does NOT recreate
// taps, mint keys, or boot domains. It runs `virsh list --name` (active domains),
// keeps the ds-<sessionUUID> ones (the liveBooter domainName convention), and
// Gets each one's persisted record — the binding the domain XML does NOT carry. A
// resident ds-domain with NO record is SKIPPED (it cannot be re-adopted without
// its three-keys-agree binding; surfacing it as recovered with a zero binding
// would fail Binding.validate downstream). It is idempotent — re-invocation over
// an unchanged host returns the same set.
//
// Same posture as live.go / snapshot_libvirt.go: reachable on the live path
// (NewSessionRecoverer under DS_HOSTAGENT_LIVE, offline.go), STDLIB-ONLY — it
// shells out to virsh through the package os/exec `runner` seam (NO cgo). A
// `virsh list` failure is a genuine host fault surfaced non-nil; a per-record read
// fault is likewise non-nil (fail-loud — a corrupt record must not silently drop a
// resident session from recovery).

package libvirt

import (
	"context"
	"fmt"
	"strings"
)

// liveSessionRecoverer is the production SessionRecoverer over virsh + the session
// record store. Reachable only on the live path (DS_HOSTAGENT_LIVE); a
// DriverService built off the gate has no recoverer and answers RecoverSessions
// with codes.Unimplemented (service.go).
type liveSessionRecoverer struct {
	virshBin string
	run      runner
	records  SessionRecordStore
}

// NewLiveSessionRecoverer builds the real SessionRecoverer over virsh on PATH +
// the file session-record store, mirroring NewLiveBooter / NewLiveSnapshotStore.
// The returned value satisfies the seams.go SessionRecoverer seam.
func NewLiveSessionRecoverer(cfg LiveConfig, records SessionRecordStore) (SessionRecoverer, error) {
	if records == nil {
		return nil, fmt.Errorf("live session recoverer requires a session record store")
	}
	virsh := cfg.VirshBin
	if virsh == "" {
		virsh = "virsh"
	}
	return &liveSessionRecoverer{virshBin: virsh, run: execRunner{}, records: records}, nil
}

// listActiveDomainsArgs is the PURE arg-construction for the resident-domain probe:
// `virsh list --name` prints the names of ACTIVE (running) domains, one per line.
// Split out from the exec (the live.go convention) so the offline test asserts the
// command line without running virsh.
func listActiveDomainsArgs(virshBin string) (name string, args []string) {
	return virshBin, []string{"list", "--name"}
}

// sessionFromDomainName recovers the session UUID from a libvirt domain name,
// reversing the liveBooter domainName convention ("ds-"+sessionUUID). A name
// without the prefix (a non-ds domain sharing the host) yields ok=false and is
// skipped.
func sessionFromDomainName(domainName string) (sessionUUID string, ok bool) {
	const prefix = "ds-"
	if !strings.HasPrefix(domainName, prefix) {
		return "", false
	}
	s := strings.TrimPrefix(domainName, prefix)
	if s == "" {
		return "", false
	}
	return s, true
}

// RecoverSessions enumerates the host-resident ds-sessions and joins them to their
// persisted records. It lists active domains, keeps the ds-<sessionUUID> ones, and
// reads each one's record (the binding) — a resident domain with no record is
// skipped. An empty result is a clean no-op (a fresh host with nothing resident).
func (r *liveSessionRecoverer) RecoverSessions(ctx context.Context, hostID string) ([]RecoveredSession, error) {
	name, args := listActiveDomainsArgs(r.virshBin)
	out, err := r.run.run(ctx, name, args...)
	if err != nil {
		return nil, fmt.Errorf("recover sessions on host %s: list active domains: %w", hostID, err)
	}

	var recovered []RecoveredSession
	for _, line := range strings.Split(out, "\n") {
		domName := strings.TrimSpace(line)
		if domName == "" {
			continue
		}
		sessionUUID, ok := sessionFromDomainName(domName)
		if !ok {
			continue // not a ds-managed session domain
		}
		rec, found, err := r.records.Get(ctx, sessionUUID)
		if err != nil {
			return nil, fmt.Errorf("recover sessions on host %s: read record for %s: %w", hostID, sessionUUID, err)
		}
		if !found {
			// A resident ds-domain whose record was lost cannot be re-adopted (no
			// three-keys-agree binding); skip it rather than fabricate a binding.
			continue
		}
		recovered = append(recovered, RecoveredSession{
			SessionUUID: rec.SessionUUID,
			DomainUUID:  rec.DomainUUID,
			Binding:     rec.Binding,
		})
	}
	return recovered, nil
}

// Compile-time assertion: the live recoverer satisfies the seam the DriverService
// wires (NewDriverServiceWithRecovery / …WithDiskDelta).
var _ SessionRecoverer = (*liveSessionRecoverer)(nil)
