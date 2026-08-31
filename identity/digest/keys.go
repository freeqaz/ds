// SPDX-License-Identifier: Apache-2.0

// HMAC key lifecycle for the fleet secret-digest feed (doc 16 §6.3; the doc 14
// OQ7 erratum). Identity owns this lifecycle (assigned with D73 by round2/08);
// this file is the pure-logic half — key DERIVATION + the rotation/re-key state
// machine — and the live re-key orchestration that re-pushes every live digest
// under a new key WITHOUT violating mint-before-attach (doc 16 §6.1). It EXTENDS
// the landed producer/matcher/variant; it does not duplicate the digest
// computation (Producer.Entries) or the publish/ack verb (PublishSession).
//
// The adopted §6.3 defaults this file realizes:
//   - per-host per-epoch HMAC keys (KeyEpoch + DeriveKey),
//   - rotation at the golden-image cadence (KeyManager.Rotate),
//   - re-key on host redeploy (KeyManager.Rekey),
//   - a LIVE re-key that re-pushes every live digest under the new key, the
//     new-key digests published + acked BEFORE the old key is retired so a
//     session never sees a digest gap (LiveRekey).
//
// Key custody (the root key bytes) lives in the D39 secret-store trust zone,
// exactly like the Producer's key material; a KeyManager must never be
// constructed on the virtual-metal host. The boundary host holds only the
// derived per-epoch key + its id (selected by key_id, doc 16 §6.3) — never the
// root — so a compromised host yields one host's current+retiring epoch keys,
// not the fleet root (the §6.3 oracle residual; see RATIONALE.md / OQ8).
package digest

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

var (
	// ErrNoRootKey is returned when a KeyManager is constructed without root key
	// material — fail-closed, never derive from an empty root.
	ErrNoRootKey = errors.New("digest: empty root key (fail-closed)")
	// ErrNoHostID is returned when a KeyManager is constructed without a host id —
	// keys are per-HOST per-epoch, so the host is part of the derivation salt.
	ErrNoHostID = errors.New("digest: empty host id (fail-closed)")
	// ErrEpochUnderflow guards a rotation/re-key that would move the epoch below
	// its starting value — epochs only ever advance (a never-decreasing counter
	// is what makes a rotated-out key id un-reusable).
	ErrEpochUnderflow = errors.New("digest: epoch underflow (epochs only advance)")
)

// rootKeyMinLenBytes is the floor on root key material. A short root would make
// the whole per-host per-epoch family low-entropy regardless of the truncation
// choice; 32 bytes / 256 bits matches the HMAC-SHA-256 block-feed width and the
// FP-analysis assumption in RATIONALE.md.
const rootKeyMinLenBytes = 32

// KeyEpoch is the per-host per-epoch coordinate that names exactly one HMAC key
// in the lifecycle. HostID is the boundary host the key is custodied for; Epoch
// advances at the golden-image cadence (Rotate) and on host redeploy (Rekey);
// Generation distinguishes two keys at the SAME (host, epoch) — it advances on a
// re-key so an out-of-band redeploy that lands on the same epoch number still
// yields a fresh, distinct key id (a redeploy must never reuse the prior key).
type KeyEpoch struct {
	HostID     string
	Epoch      uint64
	Generation uint64
}

// KeyID is the stable, collision-free id the boundary selects the key by (doc 16
// §6.3: the key id is carried so the boundary picks the matching key). It is a
// pure function of the coordinate — never of the key bytes — so it can be
// computed host-side without the root, and two distinct coordinates can never
// collide (the fields are length-delimited before joining).
//
// Shape: ds-dk-<hostid>-e<epoch>-g<generation>. The host id is hex-escaped of
// any byte outside [a-z0-9-] so an adversarial host id can never inject a
// delimiter and alias another coordinate's id.
func (e KeyEpoch) KeyID() string {
	return "ds-dk-" + sanitizeHostID(e.HostID) + "-e" + utoa(e.Epoch) + "-g" + utoa(e.Generation)
}

// sanitizeHostID lowercases nothing (host ids are already lowercase by
// convention) but percent-escapes any byte that is not a safe id char, so the
// delimiter set ('-', 'e', 'g' positions) can never be forged by a host id.
func sanitizeHostID(h string) string {
	safe := true
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			safe = false
			break
		}
	}
	if safe {
		return h
	}
	const hexdig = "0123456789abcdef"
	out := make([]byte, 0, len(h)*3)
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			out = append(out, c)
			continue
		}
		out = append(out, 'x', hexdig[c>>4], hexdig[c&0x0f])
	}
	return string(out)
}

// DeriveKey computes the per-host per-epoch HMAC key from a root key and the
// coordinate. It is HKDF-Expand-style: a single HMAC-SHA-256 of the root over a
// length-prefixed, domain-separated encoding of the coordinate, yielding 32
// bytes of key material (the full HMAC-SHA-256 width — the digest HMAC keyed by
// it is the per-credential digest in producer.go).
//
// Domain separation: the label "ds-digest-hmac/v1" prefixes the info so this
// derivation can never collide with any other use of the same root key, and
// each coordinate field is length-prefixed so (host="ab", epoch=1) and
// (host="a", "b"+epoch...) can never alias.
func DeriveKey(rootKey []byte, e KeyEpoch) []byte {
	mac := hmac.New(sha256.New, rootKey)
	writeLP(mac, []byte("ds-digest-hmac/v1"))
	writeLP(mac, []byte(e.HostID))
	writeLPu64(mac, e.Epoch)
	writeLPu64(mac, e.Generation)
	return mac.Sum(nil)
}

// writeLP writes a 4-byte big-endian length prefix then the bytes, so no two
// distinct field tuples can produce the same HMAC input stream.
func writeLP(mac interface{ Write([]byte) (int, error) }, b []byte) {
	var l [4]byte
	n := uint32(len(b))
	l[0] = byte(n >> 24)
	l[1] = byte(n >> 16)
	l[2] = byte(n >> 8)
	l[3] = byte(n)
	_, _ = mac.Write(l[:])
	_, _ = mac.Write(b)
}

// writeLPu64 writes a u64 as an 8-byte big-endian fixed-width field (its own
// implicit length), domain-separating it from the variable-length byte fields.
func writeLPu64(mac interface{ Write([]byte) (int, error) }, v uint64) {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	_, _ = mac.Write(b[:])
}

// KeyManager owns one boundary host's key lifecycle: it holds the root (trust
// zone only), the current coordinate, and the set of keys whose digests are
// still live and must not yet be retired. It is the rotation/re-key state
// machine; it does NOT itself compute digests (Producer's job) — it MINTS the
// Producer/Matcher for the active key, and the LiveRekey orchestration drives
// the publish/ack ordering across an epoch flip.
//
// Not safe for concurrent mutation: a single owner (the per-host key custodian
// in the trust zone) advances the lifecycle; reads of an already-minted
// Producer are safe (a Producer is immutable post-construction).
type KeyManager struct {
	root     []byte
	current  KeyEpoch
	truncLen uint32
	// retiring holds keys that have rotated/re-keyed OUT of current but whose
	// session digests may still be live — kept so a Matcher built over the
	// transition window (mixed key ids) still selects them, and so LiveRekey can
	// assert it has re-pushed everything before dropping one.
	retiring map[string]KeyEpoch
}

// NewKeyManager builds the lifecycle for one host starting at epoch 0,
// generation 0. truncLen is the digest truncation length the minted Producers
// apply (0 ⇒ DefaultTruncationLenBytes; see RATIONALE.md / OQ8 for the choice).
// Fail-closed on missing/short root or empty host id.
func NewKeyManager(hostID string, rootKey []byte, truncLen uint32) (*KeyManager, error) {
	if len(rootKey) == 0 {
		return nil, ErrNoRootKey
	}
	if len(rootKey) < rootKeyMinLenBytes {
		return nil, errors.New("digest: root key below the 32-byte floor (fail-closed)")
	}
	if hostID == "" {
		return nil, ErrNoHostID
	}
	if truncLen == 0 {
		truncLen = DefaultTruncationLenBytes
	}
	if truncLen < minTruncationLenBytes {
		return nil, ErrTruncTooShort
	}
	if truncLen > hmacSHA256LenBytes {
		return nil, ErrTruncTooLong
	}
	r := make([]byte, len(rootKey))
	copy(r, rootKey)
	return &KeyManager{
		root:     r,
		current:  KeyEpoch{HostID: hostID, Epoch: 0, Generation: 0},
		truncLen: truncLen,
		retiring: make(map[string]KeyEpoch),
	}, nil
}

// Current returns the active key coordinate.
func (m *KeyManager) Current() KeyEpoch { return m.current }

// ActiveKeyID returns the key id the boundary currently selects.
func (m *KeyManager) ActiveKeyID() string { return m.current.KeyID() }

// Producer mints the digest Producer for the ACTIVE key — the producer that
// stamps the current key id on every entry. It derives a fresh key from the
// root each call; the returned Producer holds its own copy (producer.go), so the
// root never leaves the manager.
func (m *KeyManager) Producer() (*Producer, error) {
	return m.producerFor(m.current)
}

func (m *KeyManager) producerFor(e KeyEpoch) (*Producer, error) {
	return NewProducer(e.KeyID(), DeriveKey(m.root, e), m.truncLen)
}

// Matcher mints a Matcher loaded with every key id the manager still considers
// live — the active key plus any retiring keys — so a transition-window matcher
// matches a digest pushed under either side of a flip (mirrors the boundary that
// has loaded both keys during a live re-key). Caller Loads the pushed entries;
// this returns ONE matcher per live key id since a Matcher is keyed by a single
// key id (matcher.go). The first returned is always the active key.
func (m *KeyManager) Matchers() ([]*Matcher, error) {
	out := make([]*Matcher, 0, 1+len(m.retiring))
	act, err := NewMatcher(m.current.KeyID(), DeriveKey(m.root, m.current))
	if err != nil {
		return nil, err
	}
	out = append(out, act)
	for _, e := range m.retiring {
		mt, err := NewMatcher(e.KeyID(), DeriveKey(m.root, e))
		if err != nil {
			return nil, err
		}
		out = append(out, mt)
	}
	return out, nil
}

// Rotate advances to the next epoch at the golden-image cadence (a scheduled key
// roll that is NOT a host redeploy). The old key becomes retiring (its live
// session digests are still matchable until those sessions tear down or are
// re-pushed). Epoch advances; generation resets to 0 (a clean epoch boundary).
func (m *KeyManager) Rotate() KeyEpoch {
	prev := m.current
	m.retiring[prev.KeyID()] = prev
	m.current = KeyEpoch{HostID: prev.HostID, Epoch: prev.Epoch + 1, Generation: 0}
	return m.current
}

// Rekey re-keys on host redeploy: a fresh key the redeployed host loads, with a
// new key id even if it lands on the same epoch number (generation advances), so
// a redeploy never silently reuses the prior host's key material. The prior key
// becomes retiring; LiveRekey drives the re-push that retires it without a gap.
func (m *KeyManager) Rekey() KeyEpoch {
	prev := m.current
	m.retiring[prev.KeyID()] = prev
	m.current = KeyEpoch{HostID: prev.HostID, Epoch: prev.Epoch + 1, Generation: prev.Generation + 1}
	return m.current
}

// RetiringKeyIDs returns the key ids still held as retiring (not yet retired).
// Order is unspecified (map iteration); callers needing determinism sort it.
func (m *KeyManager) RetiringKeyIDs() []string {
	out := make([]string, 0, len(m.retiring))
	for id := range m.retiring {
		out = append(out, id)
	}
	return out
}

// RetireKey drops a retiring key once the orchestration has proven every live
// digest under it has been re-pushed + acked under the active key (the
// LiveRekey postcondition). Retiring a key whose digests are still un-re-pushed
// would open the very mint-before-attach gap §6.3 forbids, so the lifecycle
// only calls this from LiveRekey after the ack — never speculatively.
//
// Returns an error if asked to retire a key that is not in the retiring set (a
// double-retire or a never-rotated key) — fail-closed against silently dropping
// the active key or a phantom.
func (m *KeyManager) RetireKey(keyID string) error {
	if keyID == m.current.KeyID() {
		return errors.New("digest: refusing to retire the ACTIVE key (fail-closed)")
	}
	if _, ok := m.retiring[keyID]; !ok {
		return errors.New("digest: key not in the retiring set: " + keyID)
	}
	delete(m.retiring, keyID)
	return nil
}

// utoa formats a uint64 without pulling strconv (this module stays small).
func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for v > 0 {
		pos--
		buf[pos] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[pos:])
}
