// errors.go — the D61 seat-arbitration refusals and the AuthMaterial token
// minter. Kept beside server.go's logic so the rejection vocabulary the
// ACCEPTANCE clauses assert on is in one place.
package hostbridge

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var (
	// ErrWriterSeatTaken is returned when a SECOND WRITER attach is attempted
	// while the one writer seat is held (docs/15 §5.4; freeze row 2). The first
	// WRITER keeps the seat; the second is rejected, never demoted.
	ErrWriterSeatTaken = errors.New("hostbridge: writer seat already held (one-writer/N-reader, D61)")
	// ErrReaderCannotWrite is returned when a READER attachment attempts a write
	// (DriveInput / DriveGrant). N readers receive events but cannot drive; only
	// the writer seat writes (D61).
	ErrReaderCannotWrite = errors.New("hostbridge: reader attachment cannot write (one-writer/N-reader, D61)")
	// ErrTerminalReaderUnsupported is returned when a TERMINAL-mode attach is
	// requested with ROLE_READER. The terminal MVP is single-writer, NO
	// reader-mirror (docs/serpent-cli-mvp/01 §2.3, §5; 10 build-decisions §A5/G1):
	// N-reader spectating of an unstructured raw byte stream is the rejected
	// "mirror a screen" problem — spectate is the STRUCTURED path's concern. A
	// terminal reader is refused cleanly (rejectTerminalReaderUnsupported), never
	// served. The input-free terminal mirror is a later Phase-2 unit.
	ErrTerminalReaderUnsupported = errors.New("hostbridge: terminal mode is writer-only at this MVP; spectate is the structured path (D61)")

	// SPDX-License-Identifier: Apache-2.0
	//
	// ErrDigestSinkFailed is the FAIL-CLOSED-WHEN-KEYED sentinel for the attach-seam
	// keyed-secret-digest matcher wired into DriveInput (BridgeConfig.AttachMatcher,
	// the doc 20 §4 canary residual; D73; doc 12 §10). When a keyed matcher IS
	// configured and routing a match to the DigestMatchSink fails (the sink returns
	// an error), DriveInput refuses the write and returns this error WRAPPING the
	// sink's cause — it never silently drops the input past a failed inspection.
	// This mirrors the proxy's mint-before-attach posture and the Rust SecretMatcher
	// Holds fail-closed (dataplane scan.rs): a configured keyed inspection that
	// cannot complete must HOLD the input, not let it through unscanned. The matcher
	// itself is total (its own MatchInput cannot error), so the only failure surface
	// is the operator-supplied sink; match it with errors.Is. NEVER-LOG-THE-SECRET
	// (D73): this sentinel and any wrapped cause carry ZERO inspected bytes — the
	// sink receives only fingerprint-class DigestMatch values, so a sink error it
	// produces cannot itself echo the secret unless the operator's sink does, which
	// is outside this seam.
	ErrDigestSinkFailed = errors.New("hostbridge: attach-digest sink failed; input refused (fail-closed-when-keyed, D73)")
)

// randomToken mints a 256-bit hex AuthMaterial token. Session-scoped and
// short-lived by construction (the handle's ExpiresAt bounds its useful life,
// D39); it is never logged (HARDENING-NOTES §2.2). Panics only if the system CSPRNG
// fails, which is unrecoverable.
func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("hostbridge: crypto/rand failed minting attach token: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
