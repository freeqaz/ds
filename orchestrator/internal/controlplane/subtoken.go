// SPDX-License-Identifier: Apache-2.0

package controlplane

// subtoken.go owns the orchestrator's D18 fan-out sub-token injection seam (doc 23
// §5 / §10 M1 "sub-token" row): when CreateSession fans out an agent VM, it derives
// ONE narrowed agent sub-token for that VM by calling the FROZEN dreamserpent.auth.v1
// TokenAttenuationService.DeriveAgentToken, then writes the derived sub-token into the
// session config at the documented well-known in-VM mount path. The agent NEVER fetches
// the token over the network — it reads it from that path inside its own VM (doc 23 §5:
// "read from a well-known path inside the VM, never fetched over the network by the
// agent"). The injecting path is owned by the orchestrator fan-out seam (D18), NOT the
// auth SDK — the auth SDK owns the DERIVATION (the four §5 attenuation rules, lineage
// recording), this owns the CALL-AT-FAN-OUT + the MOUNT.
//
// WHY A SEAM (the only legal cross-tree import is proto/gen/go, CLAUDE.md). The auth
// SDK service lives in another tree; the orchestrator reaches it ONLY through the frozen
// generated TokenAttenuationServiceClient. tokenAttenuator (below) is the narrow,
// package-owned interface declared with the GENERATED-FAKE method shape (no
// `opts ...grpc.CallOption` tail) so the generated authv1fake.TokenAttenuationServiceFake
// satisfies it NATIVELY in tests (D50) — exactly the DriverClient/clientShim discipline
// seams.go uses for the hypervisor driver. The real generated gRPC client (whose
// DeriveAgentToken carries the `opts` tail) is adapted onto this seam by a thin shim the
// production wiring constructs; the gRPC dial stays out of this package.
//
// WHY A SINK (no live filesystem in tests). subTokenSink is the mount seam: the
// production default writes the derived token bytes to a file at the well-known path
// (fileSubTokenSink); a test substitutes an in-memory sink so the assertion that "the
// token lands at the documented mount path" runs without touching disk or a live VM
// (D50 synthetic fixtures only).
//
// SCOPE SUBSET (D126 rule 1 — scope can only narrow). The fan-out requests a SUBSET of
// the parent's ds_scopes for the agent. The auth SDK ENFORCES the subset invariant
// (DeriveAgentToken returns codes.InvalidArgument on a widening request, doc 23 §5 rule
// 1 / attenuation.ErrScopeWidening); this seam carries the requested-scope subset on the
// wire and surfaces a widening rejection as the create's error rather than mounting a
// token the service refused.

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"

	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// DefaultAgentSubTokenMountDir is the documented well-known in-VM directory the derived
// agent sub-token is written into at fan-out (doc 23 §5: "read from a well-known path
// inside the VM, never fetched over the network by the agent"). It mirrors the
// /run/ds/<thing> convention the attach socket already uses (DefaultAttachSocketDir =
// /run/ds/attach, seams.go's sibling host-side mount). The agent reads its sub-token
// from <dir>/<host_session_index>.token inside its own VM. The orchestrator fan-out seam
// (D18) owns this path — not the auth SDK.
const DefaultAgentSubTokenMountDir = "/run/ds/agent-token"

// agentSubTokenFileName builds the per-VM well-known file name under the mount dir. One
// file per launched VM, keyed on the never-recycled host_session_index (the §5 rule-2
// audience the sub-token is narrowed to), so a fan-out of N VMs writes N distinct token
// files and a re-create on the same index overwrites its own (idempotent on the index).
func agentSubTokenFileName(hostSessionIndex uint64) string {
	return fmt.Sprintf("%d.token", hostSessionIndex)
}

// AgentSubTokenMountPath returns the documented well-known in-VM path the derived
// sub-token for the VM at hostSessionIndex lands at, under mountDir. An empty mountDir
// uses DefaultAgentSubTokenMountDir. It is the single place the path is composed, so the
// production sink, the test assertion, and any future in-VM reader agree on one path.
func AgentSubTokenMountPath(mountDir string, hostSessionIndex uint64) string {
	if mountDir == "" {
		mountDir = DefaultAgentSubTokenMountDir
	}
	return filepath.Join(mountDir, agentSubTokenFileName(hostSessionIndex))
}

// tokenAttenuator is the narrow seam over the frozen dreamserpent.auth.v1
// TokenAttenuationService the fan-out drives: derive ONE attenuated agent sub-token per
// VM. It is declared with the generated-fake method shape (no `opts ...grpc.CallOption`
// tail) so authv1fake.TokenAttenuationServiceFake satisfies it natively in tests (D50);
// the real generated TokenAttenuationServiceClient is adapted onto it by a thin shim the
// production wiring builds (the gRPC dependency confined to that shim + main.go).
type tokenAttenuator interface {
	DeriveAgentToken(ctx context.Context, in *authv1.DeriveAgentTokenRequest) (*authv1.DeriveAgentTokenResponse, error)
}

// subTokenSink is the mount seam: write the derived sub-token bytes to the documented
// well-known in-VM path for the VM at hostSessionIndex. The production default
// (fileSubTokenSink) writes a 0600 file at that path; a test substitutes an in-memory
// sink so the mount-path assertion runs without a live VM/filesystem (D50). The sink
// returns the resolved path it wrote to so the caller can record/log it.
type subTokenSink interface {
	WriteSubToken(ctx context.Context, hostSessionIndex uint64, token []byte) (path string, err error)
}

// fileSubTokenSink is the production mount sink: it writes the derived sub-token to a
// per-VM file at <MountDir>/<index>.token (the documented well-known in-VM path), mode
// 0600 (the token is a credential, doc 23 §5). The directory is created if absent. An
// empty MountDir uses DefaultAgentSubTokenMountDir.
type fileSubTokenSink struct {
	MountDir string
}

// WriteSubToken writes the derived sub-token bytes to the well-known per-VM path and
// returns it. The write is the orchestrator-owned mount the agent later reads from
// inside its VM — never an over-the-network fetch (doc 23 §5).
func (s fileSubTokenSink) WriteSubToken(_ context.Context, hostSessionIndex uint64, token []byte) (string, error) {
	dir := s.MountDir
	if dir == "" {
		dir = DefaultAgentSubTokenMountDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("controlplane: create sub-token mount dir %q: %w", dir, err)
	}
	path := AgentSubTokenMountPath(dir, hostSessionIndex)
	if err := os.WriteFile(path, token, 0o600); err != nil {
		return "", fmt.Errorf("controlplane: write sub-token to %q: %w", path, err)
	}
	return path, nil
}

// memSubTokenSink is the in-memory mount sink for tests (D50): it records the derived
// sub-token bytes keyed by host_session_index and the resolved well-known path, so a
// test asserts "the token lands at the documented mount path" without a live VM. Safe
// for concurrent use (a fan-out may derive+mount N VMs concurrently in a future hop).
type memSubTokenSink struct {
	mu       sync.Mutex
	MountDir string
	byIndex  map[uint64][]byte
	byPath   map[string][]byte
}

func newMemSubTokenSink() *memSubTokenSink {
	return &memSubTokenSink{byIndex: map[uint64][]byte{}, byPath: map[string][]byte{}}
}

func (s *memSubTokenSink) WriteSubToken(_ context.Context, hostSessionIndex uint64, token []byte) (string, error) {
	path := AgentSubTokenMountPath(s.MountDir, hostSessionIndex)
	cp := append([]byte(nil), token...)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byIndex[hostSessionIndex] = cp
	s.byPath[path] = cp
	return path, nil
}

// tokenAt returns the bytes recorded at the well-known path (the test's mount-path
// assertion).
func (s *memSubTokenSink) tokenAt(path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.byPath[path]
	return b, ok
}

// subTokenInjector is the orchestrator's D18 fan-out sub-token seam (doc 23 §5): it
// derives ONE narrowed agent sub-token per launched VM via TokenAttenuationService and
// mounts it at the documented well-known in-VM path. CreateSession drives it once per VM
// after the create reaches READY/ATTACHED. It is OPTIONAL: a control plane that does not
// wire it (a test-narrowed handler, or a deployment without the auth SDK reachable)
// simply does not fan out a sub-token — CreateSession is unaffected. Installed via
// SessionService.SetSubTokenServing.
type subTokenInjector struct {
	attenuator tokenAttenuator
	sink       subTokenSink
}

// newSubTokenInjector builds the fan-out injector over the attenuation seam + the mount
// sink. The production wiring supplies the gRPC-shim attenuator + a fileSubTokenSink at
// the well-known mount dir; tests supply the generated authv1fake fake + an in-memory
// sink (D50).
func newSubTokenInjector(att tokenAttenuator, sink subTokenSink) *subTokenInjector {
	return &subTokenInjector{attenuator: att, sink: sink}
}

// fanoutSubToken is the per-VM data the fan-out derive+mount needs, projected off the
// created session record + the launching principal's authority. It is the orchestrator
// fan-out's input to the auth SDK (doc 23 §5): the parent user auth token to attenuate
// from, the VM's session ref + host_session_index (the §5 rule-2 audience), and the
// REQUESTED-SCOPE SUBSET of the parent ds_scopes the agent gets (§5 rule 1 — narrow only).
type fanoutSubToken struct {
	// parentUserAuthToken is the D125 parent user auth token the sub-token attenuates
	// from. Empty = no parent authority to derive against (the unauthenticated launch /
	// a deployment that does not mint a user auth token); the injector then skips the
	// derive — there is nothing to attenuate, and CreateSession is unaffected.
	parentUserAuthToken string
	// sessionRef is the created session's boundary.v1 ref (carried on the derive request
	// so the auth SDK records lineage + emits the D128 issued event against this session).
	sessionRef *boundaryv1.SessionRef
	// hostSessionIndex is the never-recycled per-host index of THIS launched VM (store
	// SessionRef.HostSessionIndex). It becomes the derived sub-token's aud (§5 rule 2).
	hostSessionIndex uint64
	// requestedScopes is the SUBSET of the parent's ds_scopes this agent is granted (§5
	// rule 1 — scope can only narrow). The auth SDK enforces the subset invariant and
	// rejects a widening request (codes.InvalidArgument); this carries the subset on the
	// wire. Empty = the auth SDK defaults to the parent scopes (no narrowing requested).
	requestedScopes []string
	// lifetimeSeconds optionally narrows the sub-token TTL (§5 rule 3 — exp ≤ parent exp;
	// zero = the auth SDK defaults to the parent's remaining lifetime).
	lifetimeSeconds int32
}

// fanoutSubTokenFor projects the per-VM derive+mount input off a created session record
// and the launching principal's authority. It is the SINGLE place the §5 fan-out request
// is shaped from the orchestrator's create result: the VM's session ref + host index come
// off the record's quartet; the parent token + requested-scope subset come off the
// launching authority. requestedScopes is taken as-is (already the caller-chosen subset);
// the auth SDK is the subset ENFORCER, so this never silently widens.
func fanoutSubTokenFor(sess store.Session, parentUserAuthToken string, requestedScopes []string, lifetimeSeconds int32) fanoutSubToken {
	return fanoutSubToken{
		parentUserAuthToken: parentUserAuthToken,
		sessionRef: &boundaryv1.SessionRef{
			SessionUuid:      sess.Ref.SessionUUID,
			HostId:           sess.Ref.HostID,
			HostSessionIndex: sess.Ref.HostSessionIndex,
			TapName:          sess.Ref.TapName,
		},
		hostSessionIndex: sess.Ref.HostSessionIndex,
		requestedScopes:  requestedScopes,
		lifetimeSeconds:  lifetimeSeconds,
	}
}

// deriveAndMount runs the D18 fan-out hop for ONE launched VM (doc 23 §5): it calls
// TokenAttenuationService.DeriveAgentToken EXACTLY ONCE with the VM's host_session_index
// + the requested-scope subset of the parent ds_scopes, then writes the derived sub-token
// to the documented well-known in-VM mount path. It returns the resolved mount path + the
// derived jti (for logging/lineage) so the caller can record the fan-out.
//
// SCOPE WIDENING IS SURFACED, NOT SWALLOWED. The auth SDK enforces the four §5 rules; a
// widening request (a requested scope the parent does not carry) is rejected with
// codes.InvalidArgument (attenuation.ErrScopeWidening). deriveAndMount returns that error
// WITHOUT mounting anything — a token the service refused never lands at the mount path.
//
// NO PARENT, NO DERIVE. An empty parentUserAuthToken means there is no parent authority
// to attenuate from (the unauthenticated launch, or a deployment that mints no user auth
// token). deriveAndMount then SKIPS the derive entirely and returns ("", "", nil) — the
// agent simply gets no sub-token, and the create is unaffected (additive).
func (in *subTokenInjector) deriveAndMount(ctx context.Context, ft fanoutSubToken) (mountPath, derivedJTI string, err error) {
	if in == nil || in.attenuator == nil || in.sink == nil {
		// The fan-out sub-token seam is not wired (a test-narrowed handler / a deployment
		// without the auth SDK reachable). No derive, no mount — CreateSession unaffected.
		return "", "", nil
	}
	if ft.parentUserAuthToken == "" {
		// No parent authority to derive against: skip the hop (nothing to attenuate).
		return "", "", nil
	}
	// FAIL CLOSED ON AN OUT-OF-RANGE INDEX (§5 rule 2). hostSessionIndex is a uint64
	// (store SessionRef.HostSessionIndex) but the frozen DeriveAgentTokenRequest field is
	// int32. An index > math.MaxInt32 would SILENTLY WRAP under the int32() cast below,
	// mis-attributing the derived sub-token's aud (the §5 rule-2 audience) to the WRONG
	// VM — a security-relevant mis-binding. Reject it instead of truncating: nothing is
	// derived, nothing is mounted.
	if ft.hostSessionIndex > math.MaxInt32 {
		return "", "", fmt.Errorf("controlplane: host session index %d exceeds int32 max — refusing to derive a mis-attributable sub-token", ft.hostSessionIndex)
	}

	resp, err := in.attenuator.DeriveAgentToken(ctx, &authv1.DeriveAgentTokenRequest{
		ParentUserAuthToken: ft.parentUserAuthToken,
		SessionRef:          ft.sessionRef,
		// Safe: the guard above proves ft.hostSessionIndex ≤ math.MaxInt32.
		HostSessionIndex: int32(ft.hostSessionIndex),
		RequestedScopes:  ft.requestedScopes,
		LifetimeSeconds:  ft.lifetimeSeconds,
	})
	if err != nil {
		// A widening rejection (codes.InvalidArgument) or any other derive fault surfaces
		// here — the caller never mounts a token the auth SDK refused.
		return "", "", fmt.Errorf("controlplane: derive agent sub-token for VM index %d: %w", ft.hostSessionIndex, err)
	}
	if resp == nil {
		return "", "", fmt.Errorf("controlplane: derive agent sub-token for VM index %d: nil response", ft.hostSessionIndex)
	}

	path, werr := in.sink.WriteSubToken(ctx, ft.hostSessionIndex, resp.GetAgentToken())
	if werr != nil {
		return "", "", werr
	}
	return path, resp.GetDerivedJti(), nil
}
