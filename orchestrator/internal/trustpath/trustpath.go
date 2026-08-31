// SPDX-License-Identifier: Apache-2.0

// Package trustpath is the SINGLE SOURCE for the M0 host-readable CA-bundle
// trust-path transform (doc 15 §4.1 step 7; doc 16 §4; D17/D82). The orchestrator
// PRODUCER (controlplane/liveedges.go) mints the per-session interception CA and
// drops the resulting PEM to a host-readable store keyed by an opaque ref; the
// host-agent CONSUMER (hypervisor/libvirt) reads that PEM back by the SAME ref.
// For the producer's write and the consumer's read to meet, the subdir name, the
// ref->filename sanitize rule, and the on-disk path MUST be byte-identical on both
// sides.
//
// Before this package the transform was DUPLICATED — the producer mirrored the
// consumer's rule by hand (a const + a hand-copied sanitize loop), kept in lock-step
// by comment ("keep this in lock-step with libvirt.sanitizeAnchorComponent"). A drift
// in either copy silently breaks the trust path: the producer writes a file the
// consumer never finds, the step-7 inject fails closed, and the create aborts. This
// package collapses the two copies into one, so the producer and consumer derive the
// path from the SAME code and cannot drift.
//
// STDLIB-ONLY (path/filepath, strings; no cgo). The producer (a different package
// that cannot import the host-agent's libvirt internals) and the libvirt consumer
// both import THIS package, so the encoding is single-sourced across the tree
// boundary without either tree depending on the other.
package trustpath

import (
	"path/filepath"
	"strings"
)

// Subdir is the per-host directory name (under the host's OverlayDir) the
// orchestrator-dropped per-session interception-CA bundles live in. A hidden subdir
// so it is never mistaken for an overlay; sibling to the overlays, the session
// records, and the attach tokens. The producer creates it and writes into it; the
// consumer reads back from it — so it is defined ONCE here.
const Subdir = ".ds-ca-bundles"

// bundleExt is the on-disk extension of a dropped CA-bundle PEM.
const bundleExt = ".pem"

// keyExt is the on-disk extension of the proxy-bound PKCS#8 private key that is dropped
// as the SIBLING of a CA-bundle PEM. Distinct from bundleExt so a leaf/extension change
// on one half can never silently rename the other.
const keyExt = ".key.pem"

// Sanitize reduces a ref (a caRef / caBundleRef, or any path component) to a safe
// filename component drawn only from [A-Za-z0-9._-], replacing every other rune with
// '_' so it can never escape Subdir or inject a flag into a downstream command. An
// EMPTY input collapses to the literal "session" — never an empty component (an
// all-illegal input still yields one '_' per rune, so it is non-empty). A ref like
// "ca:<uuid>" maps to "ca_<uuid>" on BOTH the
// producer and consumer sides, so the producer writes precisely the file the consumer
// reads. This is the one canonical sanitize the whole trust path keys on.
func Sanitize(ref string) string {
	var b strings.Builder
	for _, r := range ref {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "session"
	}
	return b.String()
}

// BundleFilename is the deterministic PEM filename for a ref (the sanitized ref plus
// the ".pem" extension) — the leaf both sides agree on.
func BundleFilename(ref string) string {
	return Sanitize(ref) + bundleExt
}

// KeyFilename is the deterministic PKCS#8 private-key filename for a ref (the sanitized
// ref plus the ".key.pem" extension) — the proxy-bound (D39/D76) SIBLING of the
// BundleFilename cert leaf. It is written by the orchestrator PRODUCER
// (controlplane/liveedges.go keyFilename, which delegates here), read host-side by the
// ds-tlsproxy consumer, and REMOVED by the host-side §4.2 CA-bundle disposer
// (hypervisor/libvirt/cabundledisposer.go) at teardown — so producer and disposer derive
// the leaf from the SAME code and cannot drift (a drifted disposer would silently leave a
// live CA private key on the host after every destroy, the D82 "the CA dies with the
// session" property).
func KeyFilename(ref string) string {
	return Sanitize(ref) + keyExt
}

// SubdirPath is the per-host CA-bundle directory for a given baseDir (the host's
// OverlayDir): baseDir/.ds-ca-bundles. Both NewFileCABundleProducer and
// NewFileCABundleSource build their store over this exact directory.
func SubdirPath(baseDir string) string {
	return filepath.Join(baseDir, Subdir)
}

// BundlePath is the full deterministic PEM path for a ref under baseDir's CA-bundle
// store: baseDir/.ds-ca-bundles/<sanitize(ref)>.pem. The producer writes here and the
// consumer reads here, from the SAME code.
func BundlePath(baseDir, ref string) string {
	return filepath.Join(SubdirPath(baseDir), BundleFilename(ref))
}

// ── the sibling per-session host-state stores ────────────────────────────────
//
// The host agent keeps several other per-session stores under the SAME OverlayDir,
// each a hidden subdir sibling to the CA-bundle store, each keying its leaf on the
// SAME Sanitize transform. Before this package those subdir names and the
// sanitize+extension leaf transform were open-coded inline at every libvirt consumer;
// the helpers below single-source each store's subdir + leaf so a consumer derives its
// path from ONE place and cannot drift (the CA-bundle Subdir/BundleFilename/BundlePath
// triple, mirrored per store). The extension constants live here so the on-disk shape
// is defined once.

// tokenExt / recordExt is the on-disk extension of a per-session attach-token /
// session-record JSON file. The two stores share the JSON leaf shape; they are kept as
// distinct named constants so a future divergence needs no call-site change.
const (
	tokenExt  = ".json"
	recordExt = ".json"
)

// configISOExt / configStageExt are the per-session config-drive leaf extensions: the
// read-only iso9660 image (.config.iso) the boot wires as the 2nd <disk>, and the
// staging directory (.config.d) the live writer packs it from. Unlike the subdir-based
// stores, the config-drive leaves live DIRECTLY under the OverlayDir (sibling to the
// overlay), so they are rendered by the *Path helpers below WITHOUT a subdir.
const (
	configISOExt   = ".config.iso"
	configStageExt = ".config.d"
)

// AttachTokensSubdir is the per-host directory (under the OverlayDir) the per-session
// attach tokens live in — a hidden subdir sibling to the CA-bundle store, so it is
// never mistaken for an overlay. Defined ONCE here; the libvirt token store keys on it.
const AttachTokensSubdir = ".ds-attach-tokens"

// AttachTokenFilename is the deterministic JSON filename for a session's attach token
// (the sanitized session id plus ".json") — the leaf the token store reads/writes.
func AttachTokenFilename(sessionUUID string) string {
	return Sanitize(sessionUUID) + tokenExt
}

// AttachTokensSubdirPath is the per-host attach-token directory for a baseDir (the
// host's OverlayDir): baseDir/.ds-attach-tokens.
func AttachTokensSubdirPath(baseDir string) string {
	return filepath.Join(baseDir, AttachTokensSubdir)
}

// AttachTokenPath is the full deterministic JSON path for a session's attach token
// under baseDir's token store: baseDir/.ds-attach-tokens/<sanitize(sessionUUID)>.json.
func AttachTokenPath(baseDir, sessionUUID string) string {
	return filepath.Join(AttachTokensSubdirPath(baseDir), AttachTokenFilename(sessionUUID))
}

// SessionRecordsSubdir is the per-host directory (under the OverlayDir) the durable
// per-session records the crash-matrix re-adoption leg reads back live in — a hidden
// subdir sibling to the CA-bundle store. Defined ONCE here.
const SessionRecordsSubdir = ".ds-sessions"

// SessionRecordFilename is the deterministic JSON filename for a session's record (the
// sanitized session id plus ".json") — the leaf the record store reads/writes.
func SessionRecordFilename(sessionUUID string) string {
	return Sanitize(sessionUUID) + recordExt
}

// SessionRecordsSubdirPath is the per-host session-record directory for a baseDir (the
// host's OverlayDir): baseDir/.ds-sessions.
func SessionRecordsSubdirPath(baseDir string) string {
	return filepath.Join(baseDir, SessionRecordsSubdir)
}

// SessionRecordPath is the full deterministic JSON path for a session's record under
// baseDir's record store: baseDir/.ds-sessions/<sanitize(sessionUUID)>.json.
func SessionRecordPath(baseDir, sessionUUID string) string {
	return filepath.Join(SessionRecordsSubdirPath(baseDir), SessionRecordFilename(sessionUUID))
}

// EntrypointRefsSubdir is the per-host directory (under the OverlayDir) the
// orchestrator-dropped opaque entrypoint refs (the role-axis runtime overlay / env-spec
// material) live in — a hidden subdir sibling to the CA-bundle store. Defined ONCE here.
const EntrypointRefsSubdir = ".ds-entrypoint-refs"

// EntrypointRefFilename is the deterministic filename for an opaque entrypoint ref —
// the sanitized ref with NO extension (the material is opaque pass-through, not a typed
// artifact), so a ref carrying a separator can never escape the store directory.
func EntrypointRefFilename(ref string) string {
	return Sanitize(ref)
}

// EntrypointRefsSubdirPath is the per-host entrypoint-ref directory for a baseDir (the
// host's OverlayDir): baseDir/.ds-entrypoint-refs.
func EntrypointRefsSubdirPath(baseDir string) string {
	return filepath.Join(baseDir, EntrypointRefsSubdir)
}

// EntrypointRefPath is the full deterministic path for an opaque entrypoint ref under
// baseDir's ref store: baseDir/.ds-entrypoint-refs/<sanitize(ref)>.
func EntrypointRefPath(baseDir, ref string) string {
	return filepath.Join(EntrypointRefsSubdirPath(baseDir), EntrypointRefFilename(ref))
}

// SessionModeSubdir is the per-host directory (under the OverlayDir) the resolved
// per-session launch-mode markers live in — a hidden subdir sibling to the CA-bundle
// store / attach tokens / session records, so it is never mistaken for an overlay.
// Defined ONCE here; the libvirt session-mode store keys on it.
const SessionModeSubdir = ".ds-session-mode"

// SessionModeFilename is the deterministic filename for a session's resolved-mode
// marker — the sanitized session id with NO extension (the marker body is the
// canonical lowercase mode name, not a typed artifact), so a session id carrying a
// separator can never escape the store directory. Mirrors EntrypointRefFilename.
func SessionModeFilename(sessionUUID string) string {
	return Sanitize(sessionUUID)
}

// SessionModeSubdirPath is the per-host session-mode directory for a baseDir (the
// host's OverlayDir): baseDir/.ds-session-mode.
func SessionModeSubdirPath(baseDir string) string {
	return filepath.Join(baseDir, SessionModeSubdir)
}

// SessionModePath is the full deterministic marker path for a session's resolved mode
// under baseDir's session-mode store: baseDir/.ds-session-mode/<sanitize(sessionUUID)>.
// The single-source full-path form the producer + serving-leg/minter derive their
// marker location from, so both sides key on one canonical path.
func SessionModePath(baseDir, sessionUUID string) string {
	return filepath.Join(SessionModeSubdirPath(baseDir), SessionModeFilename(sessionUUID))
}

// ConfigDriveImagePath is the full deterministic host path for a session's read-only
// config-drive image: baseDir/<sanitize(sessionUUID)>.config.iso. Unlike the
// subdir-based stores, the config-drive image lives DIRECTLY under baseDir (the
// OverlayDir), a sibling of the qcow2 overlay, so a step-8 retry re-derives the same
// path (idempotent on session_uuid). The session id is sanitized so it can never escape
// the dir.
func ConfigDriveImagePath(baseDir, sessionUUID string) string {
	return filepath.Join(baseDir, Sanitize(sessionUUID)+configISOExt)
}

// ConfigDriveStagingPath is the full deterministic host path for a session's
// config-drive staging directory: baseDir/<sanitize(sessionUUID)>.config.d — the dir the
// live writer drops config.pb into before genisoimage packs it into the image. A sibling
// of the image under baseDir (the OverlayDir), sanitized on the session so two sessions
// never collide.
func ConfigDriveStagingPath(baseDir, sessionUUID string) string {
	return filepath.Join(baseDir, Sanitize(sessionUUID)+configStageExt)
}
