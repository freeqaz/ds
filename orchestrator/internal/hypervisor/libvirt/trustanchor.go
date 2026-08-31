// SPDX-License-Identifier: Apache-2.0

// trustanchor — the production OverlayTrustStoreWriter seam binding (cainject.go),
// the libguestfs write that lands the per-session interception CA into a
// per-session qcow2 overlay's trust store (doc 15 §4.1 step 7; doc 16 §4). It is
// the real counterpart of the in-memory fake the offline tests use
// (cainject_test.go): the seam + fake prove the create path's fail-closed
// contract offline (D50); THIS file realizes the mechanism on the operator host.
//
// Same posture as live.go (the live OverlayStore + Booter): the real binding is
// ALWAYS compiled (no build tag) but only reachable behind the DS_HOSTAGENT_LIVE
// gate the daemon composition root reads (LiveEnabled); off the gate the package
// uses the in-memory fake, so CI / the sandbox / every unit test stay green
// against fakes. STDLIB-ONLY (doc.go / seams.go): it shells out to the libguestfs
// CLI (virt-customize / virt-cat) through the package's os/exec `runner` seam —
// NO libguestfs-go / cgo is pulled into orchestrator/go.mod. The command shape is
// the one grounded live on the ESXi/KVM box (2026-06-15, ~/ds/ground-cainject.sh,
// taskdb 01KV638T): virt-customize --upload the PEM into
// /usr/local/share/ca-certificates and --run-command update-ca-certificates,
// which incorporates the anchor into the system bundle + creates the hashed
// /etc/ssl/certs symlink; the write lands in the OVERLAY delta only (the base
// backing file is opened read-only — the per-session CoW model).
//
// GUEST-PATH RECONCILE (posture-(b) cred-swap, DS_GUEST_INTERCEPT_CA_PATH; additive):
// the DEFAULT lands a per-session anchor in the distro trust-anchor dir + refreshes
// the system bundle (the system-trust delivery, byte-identical to before). The
// nested-testbed posture-(b) swap run instead has the in-guest Claude Code read the
// terminating egress-gateway's interception CA from a FIXED single-file path via
// NODE_EXTRA_CA_CERTS (a literal cert file Node trusts directly — no system-trust
// rebuild). When DS_GUEST_INTERCEPT_CA_PATH names that fixed file, this writer
// uploads the SAME orchestrator-minted CA there instead, so the one cert the
// egress gateway terminates with is the one cert the guest CC trusts. The fixed
// path the harness passes (orchestrator-boot-l2.sh SWAP_GUEST_CA_PATH) is
// RECONCILED to loop-1's NODE_EXTRA_CA_CERTS so producer and consumer name one path.
//
// FAIL-CLOSED: every libguestfs error surfaces as a non-nil error so caInjector
// aborts the create before boot; an empty PEM never reaches virt-customize. The
// fixed-path mode is still driven by the SAME caInjector fetch→validate→write→
// verify sequence (a missing/empty bundle aborts the swap-mode boot before the
// first guest TLS byte). HasTrustAnchor re-derives the installed anchor's
// fingerprint with the SAME validateCABundle the injector used, so "provably
// present" is byte-exact, never a bare file-exists. The CA private key is NEVER
// delivered to the guest (only the public cert PEM is uploaded) and is never logged.

package libvirt

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// guestTrustAnchorDir is the distro trust-anchor drop directory
// update-ca-certificates scans; an anchor placed here + refreshed becomes a
// trusted root in the guest.
const guestTrustAnchorDir = "/usr/local/share/ca-certificates"

// EnvGuestInterceptCAPath is the posture-(b) cred-swap guest CA-path override
// (orchestrator-boot-l2.sh SWAP_GUEST_CA_PATH). UNSET (the default, and the only
// path in CI / the sandbox / opaque + fat + m0 runs) keeps the system-trust
// delivery byte-identical (a per-session anchor in guestTrustAnchorDir +
// update-ca-certificates). Set to a FIXED in-guest cert path under
// DS_GATE_TLS_MODE=swap, the live writer uploads the orchestrator-minted CA to
// exactly that file — the path the guest CC's NODE_EXTRA_CA_CERTS names — and
// skips the system-trust refresh (Node reads the literal cert). Read ONCE at
// NewLiveTrustStoreWriter (the LiveEnabled / EnvRoutedTap convention) so a process
// either runs system-trust or fixed-path for its whole lifetime, never a per-call
// flip. The host-agent composition root constructs the writer without change — the
// reconcile flows from the env, additively, so no composition-root edit is needed.
const EnvGuestInterceptCAPath = "DS_GUEST_INTERCEPT_CA_PATH"

// defaultVirtCustomizeBin / defaultVirtCatBin are the libguestfs CLI entrypoints
// the live writer drives (resolved via PATH on the operator host).
const (
	defaultVirtCustomizeBin = "virt-customize"
	defaultVirtCatBin       = "virt-cat"
)

// liveTrustStoreWriter is the production OverlayTrustStoreWriter: it drops the
// per-session interception CA into the per-session overlay's trust store via the
// libguestfs CLI and refreshes the distro anchor set. Reachable only on the live
// path (DS_HOSTAGENT_LIVE); the offline default uses the package's fake.
//
// guestCAPath, when non-empty, is the posture-(b) FIXED single-file in-guest cert
// path (EnvGuestInterceptCAPath): the CA is uploaded THERE (one file the guest CC
// trusts via NODE_EXTRA_CA_CERTS) and the system-trust refresh is skipped. Empty
// (the default) keeps the per-session system-trust delivery byte-identical.
type liveTrustStoreWriter struct {
	customizeBin string
	catBin       string
	guestCAPath  string
	run          runner
}

// NewLiveTrustStoreWriter builds the real OverlayTrustStoreWriter over the
// libguestfs CLI on PATH. The returned value satisfies the cainject.go seam, so
// the host-agent composition root can pass it to NewCAInjector on the live path
// (the same place it constructs NewLiveOverlayStore / NewLiveBooter). The
// posture-(b) fixed guest CA path (EnvGuestInterceptCAPath) is read ONCE here so
// the reconcile is a construction-time choice, additive to the composition root.
func NewLiveTrustStoreWriter() (OverlayTrustStoreWriter, error) {
	return &liveTrustStoreWriter{
		customizeBin: defaultVirtCustomizeBin,
		catBin:       defaultVirtCatBin,
		guestCAPath:  GuestInterceptCAPathFromEnv(),
		run:          execRunner{},
	}, nil
}

// GuestInterceptCAPathFromEnv resolves the posture-(b) fixed guest CA path, the
// SAME read-once-at-construction posture as LiveEnabled / RoutedTapEnabled. A
// trailing/leading space is trimmed; a non-absolute or "."-relative value is
// rejected to an empty (default system-trust) result rather than uploading to an
// ambiguous guest location — fail SAFE to the byte-identical default.
//
// It is EXPORTED so the host-agent composition root reconciles the entrypoint
// config's egress.ca_bundle_path (→ the guest CC's NODE_EXTRA_CA_CERTS) onto the
// SAME fixed path this resolver feeds the OverlayTrustStoreWriter's --upload target:
// the cert is delivered TO this path (the write side) AND the guest is told to TRUST
// this path (the read side) from ONE env, so producer and consumer can never name
// two different files (the posture-(b) reconcile cainject.go documents). Empty (the
// default / opaque / non-swap runs) leaves ca_bundle_path empty → NODE_EXTRA_CA_CERTS
// unset → byte-identical to today.
func GuestInterceptCAPathFromEnv() string {
	p := strings.TrimSpace(os.Getenv(EnvGuestInterceptCAPath))
	if p == "" {
		return ""
	}
	if !path.IsAbs(p) {
		// A relative guest path is meaningless for an --upload target; ignore it
		// and keep the default system-trust delivery (never silently upload to a
		// surprising in-guest location).
		return ""
	}
	return path.Clean(p)
}

// anchorGuestPath is the in-guest path THIS writer lands the session's
// interception-CA anchor at. DEFAULT (guestCAPath empty): a per-session file in the
// distro trust-anchor dir — keying the filename on the session keeps one anchor per
// session (the write idempotency contract) and lets a CA rotation replace exactly
// that file. Posture-(b) (guestCAPath set via EnvGuestInterceptCAPath): the FIXED
// single-file path the guest CC's NODE_EXTRA_CA_CERTS names, reconciled to loop-1.
// Either way the upload + the read-back probe share this one path, so HasTrustAnchor
// reads exactly the file WriteTrustAnchor wrote.
func (w *liveTrustStoreWriter) anchorGuestPath(sessionUUID string) string {
	if w.guestCAPath != "" {
		return w.guestCAPath
	}
	return defaultAnchorGuestPath(sessionUUID)
}

// defaultAnchorGuestPath is the per-session system-trust anchor path (the
// byte-identical default). Split out as a package func so the pure arg-construction
// helpers + the package tests can name the default shape without a writer instance.
func defaultAnchorGuestPath(sessionUUID string) string {
	return guestTrustAnchorDir + "/ds-interception-" + sanitizeAnchorComponent(sessionUUID) + ".crt"
}

// sanitizeAnchorComponent reduces a session id / ref to a safe filename component
// ([A-Za-z0-9._-]) so it can never escape guestTrustAnchorDir or inject a flag into
// the upload spec. A session UUID is already in this set; defense in depth.
//
// It is the single-sourced trustpath.Sanitize: the host-agent's CA-bundle CONSUMER
// (cabundlesource.go) keys the <OverlayDir>/.ds-ca-bundles/<sanitize(ref)>.pem read on
// THIS function, and the orchestrator PRODUCER (controlplane/liveedges.go) keys its
// write on the SAME trustpath.Sanitize, so the producer and consumer derive the
// trust-path filename from one shared transform and cannot drift. The other libvirt
// call sites (session records, config drives, attach tokens) share the same sanitize.
func sanitizeAnchorComponent(s string) string {
	return trustpath.Sanitize(s)
}

// trustAnchorUploadArgs is the PURE arg-construction for the DEFAULT system-trust
// virt-customize upload+refresh — split out from the exec so a unit test can assert
// the exact command line without running it (the live.go overlayCreateArgs/
// domainDefineArgs convention). hostTmpPath is the staged PEM file uploaded INTO the
// guest at the per-session system-trust anchor path; --run-command
// update-ca-certificates folds it into the system bundle. This is the byte-identical
// default; the posture-(b) fixed-path shape is trustAnchorUploadArgsAt.
func trustAnchorUploadArgs(customizeBin, overlayPath, hostTmpPath, sessionUUID string) (name string, args []string) {
	return trustAnchorUploadArgsAt(customizeBin, overlayPath, hostTmpPath, defaultAnchorGuestPath(sessionUUID), true)
}

// trustAnchorUploadArgsAt is the PURE arg-construction for an upload to an arbitrary
// in-guest guestPath, parameterized on the delivery shape:
//   - systemTrust=true (DEFAULT, guestPath under guestTrustAnchorDir): --upload then
//     --run-command update-ca-certificates so the anchor is folded into the system
//     bundle + the hashed /etc/ssl/certs symlink (the historical behavior).
//   - systemTrust=false (posture-(b) FIXED path): --mkdir the parent dir then
//     --upload the cert to the literal guestPath the guest CC's NODE_EXTRA_CA_CERTS
//     names. No update-ca-certificates — Node reads the literal cert file directly,
//     so a system-trust rebuild is neither needed nor wanted (it would not register
//     a cert outside guestTrustAnchorDir anyway).
func trustAnchorUploadArgsAt(customizeBin, overlayPath, hostTmpPath, guestPath string, systemTrust bool) (name string, args []string) {
	args = []string{"-a", overlayPath}
	if !systemTrust {
		// Ensure the fixed path's parent dir exists in the overlay before upload
		// (e.g. /etc/ds for /etc/ds/intercept-ca.crt); virt-customize --mkdir is a
		// no-op if it already exists.
		args = append(args, "--mkdir", path.Dir(guestPath))
	}
	args = append(args, "--upload", hostTmpPath+":"+guestPath)
	if systemTrust {
		args = append(args, "--run-command", "update-ca-certificates")
	}
	return customizeBin, args
}

// trustAnchorCatArgs is the PURE arg-construction for the DEFAULT read-back probe
// (virt-cat of THIS session's system-trust anchor file). The fixed-path shape is
// trustAnchorCatArgsAt.
func trustAnchorCatArgs(catBin, overlayPath, sessionUUID string) (name string, args []string) {
	return trustAnchorCatArgsAt(catBin, overlayPath, defaultAnchorGuestPath(sessionUUID))
}

// trustAnchorCatArgsAt is the PURE arg-construction for the read-back probe at an
// arbitrary in-guest guestPath (virt-cat is read-only).
func trustAnchorCatArgsAt(catBin, overlayPath, guestPath string) (name string, args []string) {
	return catBin, []string{"-a", overlayPath, guestPath}
}

// WriteTrustAnchor writes the verified interception-CA PEM into the overlay,
// FAIL-CLOSED and IDEMPOTENT on (sessionUUID, overlayPath): a retry overwrites the
// SAME anchor file (never a duplicate). DEFAULT (system-trust): the upload path is
// keyed on the session under guestTrustAnchorDir and update-ca-certificates folds
// it into the system bundle. Posture-(b) (EnvGuestInterceptCAPath set): the cert is
// uploaded to the one FIXED guest path the guest CC's NODE_EXTRA_CA_CERTS names
// (parent dir --mkdir'd; no update-ca-certificates — Node reads the literal file).
// Only the public CA cert PEM is uploaded; the CA private key never enters the
// guest. Any libguestfs error means the write is not provably complete — returned
// non-nil so the create aborts before boot.
func (w *liveTrustStoreWriter) WriteTrustAnchor(ctx context.Context, sessionUUID, overlayPath string, caPEM []byte) error {
	if overlayPath == "" {
		return fmt.Errorf("write trust anchor: empty overlay path")
	}
	if len(caPEM) == 0 {
		// Defense in depth: caInjector already rejects an empty bundle, but the
		// writer must never upload an empty anchor (doc 16 §4).
		return fmt.Errorf("write trust anchor: empty CA PEM (fail-closed, D17)")
	}

	// Stage the PEM in a host temp file for --upload (libguestfs uploads a host
	// path INTO the guest); remove it after.
	tmp, err := os.CreateTemp("", "ds-interception-*.pem")
	if err != nil {
		return fmt.Errorf("write trust anchor: stage CA PEM: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(caPEM); err != nil {
		tmp.Close()
		return fmt.Errorf("write trust anchor: stage CA PEM: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write trust anchor: stage CA PEM: %w", err)
	}

	name, args := trustAnchorUploadArgsAt(w.customizeBin, overlayPath, tmpPath, w.anchorGuestPath(sessionUUID), w.systemTrust())
	if _, err := w.run.run(ctx, name, args...); err != nil {
		return fmt.Errorf("write trust anchor into overlay %q: %w", overlayPath, err)
	}
	return nil
}

// systemTrust reports whether this writer uses the DEFAULT system-trust-dir
// delivery (true) vs the posture-(b) fixed single-file path (false). It is the one
// place the two delivery shapes fork (upload location + update-ca-certificates).
func (w *liveTrustStoreWriter) systemTrust() bool { return w.guestCAPath == "" }

// HasTrustAnchor reports whether THIS session's anchor (identified by
// anchorFingerprint) is already in the overlay's trust store. It reads the
// session anchor file out of the overlay (virt-cat, read-only) and re-derives the
// fingerprint with the SAME validateCABundle the injector used, so a "true" means
// the byte-exact anchor is present — never a bare file-exists. A missing anchor
// file is a normal absent (false, nil); any OTHER libguestfs error is fail-closed
// (false, err) — presence must be provable.
func (w *liveTrustStoreWriter) HasTrustAnchor(ctx context.Context, sessionUUID, overlayPath, anchorFingerprint string) (present bool, err error) {
	if overlayPath == "" {
		return false, fmt.Errorf("probe trust anchor: empty overlay path")
	}
	name, args := trustAnchorCatArgsAt(w.catBin, overlayPath, w.anchorGuestPath(sessionUUID))
	out, runErr := w.run.run(ctx, name, args...)
	if runErr != nil {
		// virt-cat on an absent file reports "No such file or directory" — a normal
		// absent (the anchor was never written), not a probe failure. The runner
		// returns the combined output alongside the error, so the marker is in out.
		if isNotFoundOutput(out) {
			return false, nil
		}
		// Any other failure (overlay unreadable, libguestfs error) means presence
		// is not provable — fail closed.
		return false, fmt.Errorf("probe trust anchor in overlay %q: %w", overlayPath, runErr)
	}

	// The anchor file is present; confirm it is the SPECIFIC anchor by re-deriving
	// its fingerprint with the injector's own validator (first CA cert, SHA-256
	// over DER, lowercase hex). pem.Decode inside validateCABundle skips any
	// libguestfs preamble the combined output may carry. A different/rotated CA at
	// this path → not present → triggers a rewrite (idempotency by fingerprint).
	installedFP, parseErr := validateCABundle([]byte(out))
	if parseErr != nil {
		// Present but not a parseable CA anchor — treat as absent so the injector
		// rewrites a good anchor (never report a junk file as the trusted anchor).
		return false, nil
	}
	return installedFP == anchorFingerprint, nil
}

// isNotFoundOutput reports whether libguestfs output indicates the target file is
// absent (vs a real probe failure). virt-cat surfaces the guest errno text.
func isNotFoundOutput(out string) bool {
	return strings.Contains(strings.ToLower(out), "no such file or directory")
}

// Compile-time assertion: the live writer satisfies the seam the injector wires.
var _ OverlayTrustStoreWriter = (*liveTrustStoreWriter)(nil)
