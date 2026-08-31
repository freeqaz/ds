//! D73 never-log-the-secret scrub / fingerprint chokepoint — enforced ONCE,
//! here (doc 14 §6/§12.4, doc 12 §5.1).
//!
//! # The invariant (D73)
//!
//! > A matched secret or swapped credential value appears in **no** log, event,
//! > spool, or error path — fingerprint only (the `CredentialUseEvent`
//! > convention). This is a (c)-suite assertion, not a code-review hope.
//!
//! Doc 14 §12.4 makes the *shape* of the enforcement explicit: "Build it as a
//! single scrub/fingerprint chokepoint every emitting path routes through, so
//! the invariant is one assertion, not a per-call-site hope — the §2 row calls
//! this 'a (c)-suite assertion, not a code-review hope,' which means the
//! chokepoint must be the only path to the spool."
//!
//! So this module is the one and only place a secret value is turned into
//! something safe to record. The construction discipline that makes it the
//! *only* path:
//!
//!   * A secret value enters as a [`Secret`] — a wrapper that owns the plaintext
//!     and **never** exposes it through `Debug`, `Display`, or any accessor that
//!     a log/event/spool path could reach. The only thing you can do with a
//!     [`Secret`] is hand it to the [`Fingerprinter`].
//!   * The [`Fingerprinter`] holds the keyed-digest key (the D73 keyed plane:
//!     HMAC over the secret value) and returns a [`Fingerprint`] — a keyed
//!     digest, rendered as lowercase hex. The plaintext is consumed and never
//!     reappears.
//!   * Event construction ([`crate::event`]) accepts a [`Fingerprint`], never a
//!     raw value, on the credential-bearing fields. There is no event field, and
//!     no spool API, that takes plaintext — so "the chokepoint is the only path
//!     to the spool" is structural, not a convention.
//!
//! # Keyed digest, never plaintext (D73 keyed plane)
//!
//! The fingerprint is `HMAC-SHA-256(key, secret_bytes)` truncated to
//! [`FINGERPRINT_LEN`] bytes and rendered lowercase-hex. It is keyed (doc 12
//! §5.1 keyed plane / doc 14 §2 `PolicyDecision.plane = KEYED`) so that the same
//! secret produces a stable, joinable fingerprint across events without the
//! fingerprint itself being a plaintext oracle: without the key, the digest is
//! not reversible to the secret, and the truncation removes the last bit of
//! length signal the full digest would otherwise carry.
//!
//! ZERO new dependencies (doc 14 §6): the workspace ships no HMAC/SHA crate to
//! this crate's dep graph, so this module hand-rolls FIPS 180-4 SHA-256 and
//! RFC 2104 HMAC in safe stdlib-only Rust (`#![forbid(unsafe_code)]` holds). The
//! same hand-rolled posture `ds-contracts::snapshot_verify` uses for its
//! verify-only SHA-256.

/// The truncated keyed-digest length, in bytes. 16 bytes (128 bits) is ample
/// collision resistance for a join key while shedding the residual length signal
/// a full 32-byte digest would carry. Rendered hex, a [`Fingerprint`] is 32
/// lowercase-hex characters.
pub const FINGERPRINT_LEN: usize = 16;

/// A plaintext secret value on its way to the fingerprint chokepoint.
///
/// This is the *only* shape a secret value may take inside this crate, and it is
/// deliberately a one-way street: it owns the plaintext, exposes it to **nothing**
/// (no `Debug`, no `Display`, no public accessor reachable from a record path),
/// and the only operation defined on it is being consumed by
/// [`Fingerprinter::fingerprint`]. A `Secret` therefore cannot be logged,
/// formatted into an event, or written to the spool — there is no API that would
/// let it leak.
pub struct Secret(Vec<u8>);

impl Secret {
    /// Wrap a plaintext secret value (a matched secret or a swapped credential).
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(value.into())
    }
}

// A hand-written `Debug` that NEVER prints the bytes — so a `Secret` nested in
// any `#[derive(Debug)]` struct still scrubs. The D73 invariant must hold even
// through a derived debug of a containing type.
impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// A keyed fingerprint of a secret — the ONLY thing safe to record (D73). It is
/// lowercase hex of a truncated `HMAC-SHA-256(key, secret)`; the plaintext is not
/// recoverable from it without the key. This is what flows into events, logs, and
/// the spool in place of the secret value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// The lowercase-hex rendering of the keyed digest — safe to record anywhere.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The keyed-digest chokepoint. Holds the D73 keyed-plane key and turns a
/// [`Secret`] into a [`Fingerprint`]. Construct one per loaded keyed plane; clone
/// it freely across emission sites — it is the single place plaintext becomes a
/// recordable value.
#[derive(Clone)]
pub struct Fingerprinter {
    key: Vec<u8>,
}

// Hand-written `Debug` that never prints the key — the key is itself secret
// material (it is the HMAC key over the credential digest feed, doc 12 §5.2).
impl core::fmt::Debug for Fingerprinter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fingerprinter")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Fingerprinter {
    /// Build a fingerprinter over a keyed-plane key. The key never leaves this
    /// type (no accessor, redacted `Debug`).
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    /// Consume a [`Secret`] and return its keyed [`Fingerprint`]. This is the
    /// chokepoint: the plaintext is read exactly here, hashed under the key, and
    /// dropped — it appears in no return value, no error, and no log.
    pub fn fingerprint(&self, secret: Secret) -> Fingerprint {
        let digest = hmac_sha256(&self.key, &secret.0);
        // `secret` (and its plaintext) is dropped at the end of this scope; only
        // the truncated keyed digest survives.
        let mut hex = String::with_capacity(FINGERPRINT_LEN * 2);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in &digest[..FINGERPRINT_LEN] {
            hex.push(HEX[(b >> 4) as usize] as char);
            hex.push(HEX[(b & 0x0f) as usize] as char);
        }
        Fingerprint(hex)
    }
}

// ── RFC 2104 HMAC over FIPS 180-4 SHA-256, hand-rolled, zero-dep ──────────────

const SHA256_BLOCK_LEN: usize = 64;
const SHA256_DIGEST_LEN: usize = 32;

/// `HMAC-SHA-256(key, msg)` — RFC 2104. Returns the full 32-byte digest; the
/// caller truncates to [`FINGERPRINT_LEN`].
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    // Keys longer than the block are first hashed (RFC 2104 §2).
    let mut block_key = [0u8; SHA256_BLOCK_LEN];
    if key.len() > SHA256_BLOCK_LEN {
        let hashed = sha256(key);
        block_key[..SHA256_DIGEST_LEN].copy_from_slice(&hashed);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA256_BLOCK_LEN];
    let mut opad = [0x5cu8; SHA256_BLOCK_LEN];
    for i in 0..SHA256_BLOCK_LEN {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner = Vec::with_capacity(SHA256_BLOCK_LEN + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_digest = sha256(&inner);

    let mut outer = Vec::with_capacity(SHA256_BLOCK_LEN + SHA256_DIGEST_LEN);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_digest);
    sha256(&outer)
}

/// FIPS 180-4 SHA-256 over `msg`. Safe, stdlib-only (mirrors the hand-rolled
/// posture of `ds-contracts::snapshot_verify::sha256`).
fn sha256(msg: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Padding (FIPS 180-4 §5.1.1): append 0x80, then zeros, then the 64-bit
    // big-endian bit length, to a multiple of 64 bytes.
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % SHA256_BLOCK_LEN != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in data.chunks_exact(SHA256_BLOCK_LEN) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for (hi, vi) in h.iter_mut().zip(v.iter()) {
            *hi = hi.wrapping_add(*vi);
        }
    }

    let mut out = [0u8; SHA256_DIGEST_LEN];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6234 / FIPS 180-4 known-answer vector: SHA-256("abc").
    #[test]
    fn sha256_known_answer() {
        let got = sha256(b"abc");
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, want);
    }

    /// RFC 4231 HMAC-SHA-256 test case 2: key="Jefe", data="what do ya want for
    /// nothing?".
    #[test]
    fn hmac_sha256_known_answer() {
        let got = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let want = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, want);
    }

    #[test]
    fn fingerprint_is_stable_and_keyed() {
        let fp = Fingerprinter::new(b"keyed-plane-key".to_vec());
        let a = fp.fingerprint(Secret::new("ghp_DEADBEEFcanary"));
        let b = fp.fingerprint(Secret::new("ghp_DEADBEEFcanary"));
        // Stable: same secret + key → same fingerprint (joinable across events).
        assert_eq!(a, b);
        // Length: truncated digest rendered hex.
        assert_eq!(a.as_hex().len(), FINGERPRINT_LEN * 2);

        // Keyed: a different key yields a different fingerprint for the same
        // secret (the digest is not an unkeyed plaintext oracle).
        let other = Fingerprinter::new(b"a-different-key".to_vec());
        let c = other.fingerprint(Secret::new("ghp_DEADBEEFcanary"));
        assert_ne!(a, c);
    }

    #[test]
    fn secret_debug_never_prints_plaintext() {
        let s = Secret::new("ghp_DEADBEEFcanary");
        let shown = format!("{s:?}");
        assert!(!shown.contains("DEADBEEF"));
        assert!(!shown.contains("ghp_"));
        assert_eq!(shown, "Secret(<redacted>)");
    }

    #[test]
    fn fingerprinter_debug_never_prints_key() {
        let fp = Fingerprinter::new(b"super-secret-hmac-key".to_vec());
        let shown = format!("{fp:?}");
        assert!(!shown.contains("super-secret"));
    }
}
