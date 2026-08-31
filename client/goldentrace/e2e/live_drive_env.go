// SPDX-License-Identifier: Apache-2.0

// live_drive_env.go — the EXPORTED env-resolution wrapper for the per-session
// KVM-VM writer-seat tier, so an out-of-package operator command (the headless
// drive harness, client/cmd/ds-seat-drive) can resolve the live writer-seat from
// the DS_KVM_LIVE_* environment and drive a scenario over it WITHOUT naming the
// unexported internals (kvmAttachFromEnv, the thinClient surface, the driveScenario
// closure type — all package-private on purpose, since they speak the internal
// thin-client vocabulary).
//
// WHY a thin exported seam and not "make kvmAttachFromEnv public": the resolution
// (the DS_KVM_LIVE_* knobs → KVMAttachConfig) and the drive (DriveKVMScripted) are
// already the supported, reviewed surface — this file only re-exports them as a
// pair an external caller can compose, mirroring how DriveLivePrompt exported the
// one-prompt entry point over the unexported drivePromptScenario. It adds NO new
// behavior, NO new transport, and NO new gate: it is GATED exactly like
// DriveKVMScripted — with DS_KVM_LIVE unset (every CI / sandbox / go test run) it
// resolves nothing, dials nothing, and returns ErrKVMLiveGateUnset.
//
// The token is held in memory only (resolved via kvmAttachFromEnv from
// DS_KVM_LIVE_TOKEN / DS_KVM_LIVE_TOKEN_FILE); it is NEVER logged, returned, or
// committed (D50/raw-class).
package e2e

import (
	"context"
)

// KVMAttachFromEnv is the EXPORTED wrapper over kvmAttachFromEnv: it resolves the
// per-session KVM-VM writer-seat endpoint from the DS_KVM_LIVE_* knobs
// (DS_KVM_LIVE_ATTACH_UDS / DS_KVM_LIVE_SESSION / DS_KVM_LIVE_TOKEN[_FILE] /
// DS_KVM_LIVE_TRANSPORT) into a KVMAttachConfig, or returns an error naming the
// first missing knob (so a half-armed gate gets a precise diagnostic, never a
// silent dial of an empty address).
//
// It does NOT consult the DS_KVM_LIVE gate — it is pure env→config resolution, so
// a caller can resolve + validate the endpoint shape independently of arming the
// tier. The actual dial is gated inside DriveKVMScripted / DriveKVMScriptedFromEnv.
// The token field is held in memory only.
func KVMAttachFromEnv() (KVMAttachConfig, error) {
	return kvmAttachFromEnv()
}

// DriveKVMScriptedFromEnv is the EXPORTED one-call entry point an operator command
// uses to drive a scenario against the live per-session KVM-VM writer seat resolved
// entirely from the DS_KVM_LIVE_* environment: it composes KVMAttachFromEnv into a
// LiveDriveConfig and runs DriveKVMScripted(ctx, cfg, scenario).
//
// GATING (identical to DriveKVMScripted): with DS_KVM_LIVE unset it resolves and
// dials NOTHING and returns ErrKVMLiveGateUnset — the offline default every CI /
// sandbox / go test run takes (so a caller can errors.Is(err, ErrKVMLiveGateUnset)
// to skip clean). Only when DS_KVM_LIVE=1 does it resolve the writer-seat from env
// and dial it over the SAME hostbridge.SocketTransport the podman tier uses.
//
// The scenario is the caller's drive (e.g. DriveScriptScenario(turns, timeout)); it
// speaks only attach.v1 and names no transport, so the SAME scenario drives the
// fake-CC fleet path, the podman tier, and this KVM tier unchanged.
func DriveKVMScriptedFromEnv(ctx context.Context, scenario func(context.Context, *thinClient) error) (*LiveDriveResult, error) {
	// Honor the gate FIRST: with DS_KVM_LIVE unset, resolve nothing and dial
	// nothing — a half-armed env must not even be inspected before the gate, so
	// the offline default is byte-identical to DriveKVMScripted's gate-unset path.
	if !kvmGateArmed() {
		return nil, ErrKVMLiveGateUnset
	}
	kvm, err := kvmAttachFromEnv()
	if err != nil {
		return nil, err
	}
	cfg := LiveDriveConfig{KVMAttach: kvm}
	return DriveKVMScripted(ctx, cfg, scenario)
}
