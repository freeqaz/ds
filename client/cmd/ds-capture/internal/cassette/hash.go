// SPDX-License-Identifier: Apache-2.0

package cassette

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Hex returns the hex digest of s (matches Python
// hashlib.sha256(s.encode("utf-8")).hexdigest()).
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sha256Prefix returns the first 16 hex chars of the sha256 of s — cia's image
// source fingerprint (hashlib.sha256(...).hexdigest()[:16]). cia encodes with
// errors="replace"; a Go string is already valid UTF-8 here, so a plain
// []byte conversion matches.
func sha256Prefix(s string) string {
	return sha256Hex(s)[:16]
}
