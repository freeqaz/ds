// SPDX-License-Identifier: Apache-2.0

//! Snapshot `content_hash` — the VERIFY-ONLY consumer side (doc 13 §5.1, D120).
//!
//! This is the Rust half of the produce-once / verify-only contract. The Go host
//! agent (`orchestrator/internal/nftbridge`) serializes the composed policy
//! snapshot EXACTLY ONCE into a canonical RFC 8785 (JCS) payload and hashes those
//! exact bytes. The Rust consumers here **never re-serialize and never
//! re-canonicalize**: they
//!
//!   1. hash the TRANSPORTED bytes with [`sha256`],
//!   2. compare to the `content_hash` carried in the snapshot identity tuple,
//!   3. **NACK host-wide on mismatch** (doc 13 §5 identity row, D72),
//!   4. only THEN hand the verified bytes onward to parse.
//!
//! The cross-language reproduction surface is therefore zero — only Go ever
//! forms the bytes. The Go↔Rust determinism check is a shared FROZEN GOLDEN
//! FIXTURE (`testdata/snapshot-goldens.json`, byte-identical to the
//! `nftbridge` copy), not two canonicalizers compared: Go pins
//! `(payload, content_hash)`, and the test below verifies the stored bytes here
//! without re-canonicalizing.
//!
//! ZERO new dependencies (doc 14 §6, the crate's empty `[dependencies]`). The
//! workspace is deliberately dep-free and ships no SHA-256, so this module
//! hand-rolls the FIPS 180-4 SHA-256 over `&[u8]` in safe stdlib-only Rust. The
//! hash is the FULL 32 bytes — no truncation (doc 13 §5.1 "Hash + truncation").

/// The SHA-256 digest length in bytes — the full `content_hash`, no truncation
/// (doc 13 §5.1).
pub const CONTENT_HASH_LEN: usize = 32;

/// A 32-byte SHA-256 `content_hash` (doc 13 §5 snapshot-identity tuple).
pub type ContentHash = [u8; CONTENT_HASH_LEN];

/// Outcome of verifying transported snapshot bytes against an expected
/// `content_hash`. On [`Verdict::Nack`] the host must reject the snapshot
/// host-wide and stay on the prior version (doc 13 §5 identity row, D72) — never
/// parse the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The recomputed hash matched the expected `content_hash`. The bytes are
    /// safe to parse.
    Verified,
    /// The recomputed hash did NOT match — NACK host-wide, do not parse.
    Nack {
        /// The hash the snapshot identity tuple claimed.
        expected: ContentHash,
        /// The hash actually computed over the transported bytes.
        computed: ContentHash,
    },
}

impl Verdict {
    /// True iff the bytes verified and may be parsed.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Verdict::Verified)
    }
}

/// Verify transported snapshot bytes against the `content_hash` from the
/// identity tuple. This is the ONLY thing a consumer does with the bytes before
/// parsing: hash, compare, verdict. It NEVER re-serializes or re-canonicalizes
/// (doc 13 §5.1 produce-once / verify-only).
#[must_use]
pub fn verify_snapshot_bytes(transported: &[u8], expected: &ContentHash) -> Verdict {
    let computed = sha256(transported);
    // Constant-time-ish equality is unnecessary here (the hash is not a secret,
    // both sides are trusted host components), but a straight compare is fine
    // and clear.
    if &computed == expected {
        Verdict::Verified
    } else {
        Verdict::Nack {
            expected: *expected,
            computed,
        }
    }
}

/// Parse a hex `content_hash` (64 lowercase or uppercase hex chars) into the
/// 32-byte array. Returns `None` on any malformed input. Used to read the hashes
/// the golden fixture and the on-wire identity tuple carry as hex text.
#[must_use]
pub fn parse_content_hash_hex(hex: &str) -> Option<ContentHash> {
    let bytes = hex.as_bytes();
    if bytes.len() != CONTENT_HASH_LEN * 2 {
        return None;
    }
    let mut out = [0u8; CONTENT_HASH_LEN];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Render a `content_hash` as 64 lowercase hex chars (the fixture/identity-tuple
/// form).
#[must_use]
pub fn content_hash_hex(h: &ContentHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(CONTENT_HASH_LEN * 2);
    for &b in h {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256 (FIPS 180-4), hand-rolled, safe stdlib-only — zero new deps.
//
// This is a textbook implementation kept deliberately small and auditable: the
// crate ships no SHA-256 and the FROZEN crate rule forbids pulling one in. The
// `pol2_baseline`/golden cross-check pins it against external vectors and against
// the Go `crypto/sha256` producer via the shared fixture, so a bug here cannot
// pass silently.
// ─────────────────────────────────────────────────────────────────────────────

/// SHA-256 round constants (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Compute the SHA-256 digest of `msg` (full 32 bytes, FIPS 180-4).
#[must_use]
pub fn sha256(msg: &[u8]) -> ContentHash {
    let mut h = H0;

    // Pre-process: pad to a multiple of 64 bytes. Padding is 0x80, then zeros,
    // then the 64-bit big-endian bit length.
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut data = Vec::with_capacity(msg.len() + 9 + 63);
    data.extend_from_slice(msg);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 64-byte block.
    for block in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; CONTENT_HASH_LEN];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the hand-rolled SHA-256 against canonical FIPS/RFC test vectors so a
    /// bug cannot hide behind the golden fixture (which is also SHA-256).
    #[test]
    fn sha256_known_vectors() {
        // SHA-256("") and SHA-256("abc") are universally published constants.
        assert_eq!(
            content_hash_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            content_hash_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // A multi-block input (> 64 bytes) exercises the message schedule across
        // block boundaries.
        let long = "a".repeat(1000);
        assert_eq!(
            content_hash_hex(&sha256(long.as_bytes())),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn hex_round_trip() {
        let h = sha256(b"dream-serpent");
        let s = content_hash_hex(&h);
        assert_eq!(parse_content_hash_hex(&s), Some(h));
        assert_eq!(parse_content_hash_hex(&s.to_uppercase()), Some(h));
        assert_eq!(parse_content_hash_hex("zz"), None);
        assert_eq!(parse_content_hash_hex(&s[..63]), None);
    }

    #[test]
    fn verify_matches_and_nacks() {
        let bytes = b"{\"negative_ttl\":0}";
        let good = sha256(bytes);
        assert_eq!(verify_snapshot_bytes(bytes, &good), Verdict::Verified);

        let mut bad = good;
        bad[0] ^= 0x01;
        match verify_snapshot_bytes(bytes, &bad) {
            Verdict::Nack { expected, computed } => {
                assert_eq!(expected, bad);
                assert_eq!(computed, good);
            }
            Verdict::Verified => panic!("mutated expected hash must NACK"),
        }
    }
}
