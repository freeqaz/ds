// SPDX-License-Identifier: Apache-2.0

//! Rust VERIFY-ONLY cross-check against the shared snapshot golden fixture
//! (doc 13 §5.1, D120).
//!
//! This is the Rust half of the Go↔Rust determinism check. It loads the
//! BYTE-IDENTICAL copy of `testdata/snapshot-goldens.json` (the Go side pins it
//! from `orchestrator/internal/nftbridge`; `scripts/check-snapshot-goldens.sh`
//! gates that the two committed copies never diverge) and, for every case:
//!
//!   - hashes the fixture's `payload` bytes with the hand-rolled, zero-dep
//!     [`ds_contracts::snapshot_verify::sha256`] and asserts it equals the pinned
//!     `content_hash` — i.e. the Rust consumer reproduces the Go producer's hash
//!     over the IDENTICAL transported bytes, NEVER re-canonicalizing;
//!   - drives [`ds_contracts::snapshot_verify::verify_snapshot_bytes`] to the
//!     `Verified` verdict on the pinned bytes, and to `Nack` on the adversarial
//!     byte-mutated transport.
//!
//! Zero new dependencies: the fixture is read with a tiny purpose-built JSON
//! reader below (the `ds-contracts` `[dependencies]`-empty fence — same posture
//! as `pol1.rs`'s hand-rolled reader). It understands exactly the fixture's
//! shape and rejects everything else.

use ds_contracts::snapshot_verify::{
    parse_content_hash_hex, sha256, verify_snapshot_bytes, Verdict,
};
use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../dataplane/crates/ds-contracts (same anchor
    // precedent as policy-core/tests/pol2_baseline.rs).
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p.push("snapshot-goldens.json");
    p
}

fn load_fixture() -> Json {
    let path = fixture_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read golden fixture {}: {e}", path.display()));
    Json::parse(&text).unwrap_or_else(|e| panic!("parse golden fixture: {e}"))
}

#[test]
fn golden_payloads_hash_to_pinned_content_hash() {
    let doc = load_fixture();
    let cases = doc
        .get("cases")
        .expect("cases")
        .as_array()
        .expect("cases array");
    assert!(!cases.is_empty(), "fixture has no cases");

    let mut saw_composite = false;
    let mut saw_role = false;

    for case in cases {
        let name = case.get("name").and_then(Json::as_str).expect("case name");
        let kind = case.get("kind").and_then(Json::as_str).unwrap_or("");
        if kind == "role" {
            saw_role = true;
        }

        // Top-level payload + content_hash: every case carries them (including
        // the composite case, whose payload is the whole host document).
        let payload = case
            .get("payload")
            .and_then(Json::as_str)
            .unwrap_or_else(|| panic!("case {name} missing payload"));
        let pinned_hex = case
            .get("content_hash")
            .and_then(Json::as_str)
            .unwrap_or_else(|| panic!("case {name} missing content_hash"));
        let expected = parse_content_hash_hex(pinned_hex)
            .unwrap_or_else(|| panic!("case {name} content_hash not 32-byte hex"));

        // The verify-only path: hash the TRANSPORTED bytes, compare. No
        // re-canonicalization of the payload occurs anywhere.
        let computed = sha256(payload.as_bytes());
        assert_eq!(
            computed, expected,
            "case {name}: recomputed hash over transported bytes != pinned content_hash"
        );
        assert_eq!(
            verify_snapshot_bytes(payload.as_bytes(), &expected),
            Verdict::Verified,
            "case {name}: verify_snapshot_bytes must accept the pinned bytes"
        );

        // Composite case: also verify each per-session sub-hash over its own
        // section payload (doc 13 §5.1 composite-interaction rollup).
        if kind == "composite" {
            saw_composite = true;
            let sections = case
                .get("sections")
                .and_then(Json::as_array)
                .expect("composite sections");
            assert!(!sections.is_empty(), "composite has no sections");
            let mut prev: Option<&str> = None;
            for sec in sections {
                let sid = sec
                    .get("session_id")
                    .and_then(Json::as_str)
                    .expect("session_id");
                // Sections are pinned in session_id order.
                if let Some(p) = prev {
                    assert!(p < sid, "sections not ordered by session_id: {p} !< {sid}");
                }
                prev = Some(sid);

                let sec_payload = sec
                    .get("payload")
                    .and_then(Json::as_str)
                    .expect("section payload");
                let sub_hex = sec
                    .get("sub_hash")
                    .and_then(Json::as_str)
                    .expect("sub_hash");
                let sub_expected =
                    parse_content_hash_hex(sub_hex).expect("sub_hash not 32-byte hex");
                assert_eq!(
                    sha256(sec_payload.as_bytes()),
                    sub_expected,
                    "section {sid}: sub-hash over its bytes != pinned sub_hash"
                );
            }
        }
    }

    assert!(
        saw_composite,
        "fixture must include the composite host-document case"
    );
    assert!(
        saw_role,
        "fixture must include a doc 18 role-document case (identical path)"
    );
}

#[test]
fn declared_hash_relations_hold() {
    // field-order-only diffs hash EQUAL; meaningful-zero vs absent hash DIFFER
    // (doc 13 §5.1 adversarial set) — asserted from the fixture's own
    // declarations so the relation is self-checking.
    let doc = load_fixture();
    let cases = doc.get("cases").unwrap().as_array().unwrap();

    let find = |n: &str| -> Json {
        cases
            .iter()
            .find(|c| c.get("name").and_then(Json::as_str) == Some(n))
            .cloned()
            .unwrap_or_else(|| panic!("case {n} not found"))
    };

    for case in cases {
        let name = case.get("name").and_then(Json::as_str).unwrap();
        if let Some(eq) = case.get("hash_equal_to").and_then(Json::as_str) {
            let other = find(eq);
            assert_eq!(
                case.get("content_hash").and_then(Json::as_str),
                other.get("content_hash").and_then(Json::as_str),
                "{name} declares hash_equal_to {eq} but content_hash differs"
            );
            assert_eq!(
                case.get("payload").and_then(Json::as_str),
                other.get("payload").and_then(Json::as_str),
                "{name}/{eq} hash-equal but payloads differ — field-order must collapse"
            );
        }
        if let Some(df) = case.get("hash_differs_from").and_then(Json::as_str) {
            let other = find(df);
            assert_ne!(
                case.get("content_hash").and_then(Json::as_str),
                other.get("content_hash").and_then(Json::as_str),
                "{name} declares hash_differs_from {df} but content_hash equal"
            );
        }
    }
}

#[test]
fn byte_mutated_transport_is_nacked() {
    // The adversarial byte-mutated transport must NACK against the base hash —
    // the host-wide rejection a real consumer performs (doc 13 §5 identity row).
    let doc = load_fixture();
    let adv = doc.get("adversarial").expect("adversarial");
    let bm = adv.get("byte_mutated").expect("byte_mutated");

    let mutated = bm
        .get("mutated_payload")
        .and_then(Json::as_str)
        .expect("mutated_payload");
    let base_hex = bm
        .get("expected_hash_of_base")
        .and_then(Json::as_str)
        .expect("expected_hash_of_base");
    let base_hash = parse_content_hash_hex(base_hex).expect("base hash hex");

    match verify_snapshot_bytes(mutated.as_bytes(), &base_hash) {
        Verdict::Nack { expected, computed } => {
            assert_eq!(expected, base_hash);
            assert_ne!(computed, base_hash, "mutation must change the hash");
        }
        Verdict::Verified => panic!("byte-mutated transport wrongly VERIFIED — NACK expected"),
    }

    // And the base case's own bytes DO verify against that hash.
    let base_case_name = bm
        .get("base_case")
        .and_then(Json::as_str)
        .expect("base_case");
    let cases = doc.get("cases").unwrap().as_array().unwrap();
    let base = cases
        .iter()
        .find(|c| c.get("name").and_then(Json::as_str) == Some(base_case_name))
        .expect("base_case present");
    let base_payload = base.get("payload").and_then(Json::as_str).unwrap();
    assert_eq!(
        verify_snapshot_bytes(base_payload.as_bytes(), &base_hash),
        Verdict::Verified,
        "base case must verify against its own hash"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal zero-dep JSON reader (test-only). Understands the subset the fixture
// uses: objects, arrays, strings (with JSON escapes incl. \uXXXX + surrogate
// pairs), integers, booleans, null. Rejects malformed input. NOT a general JSON
// library — the ds-contracts dep-free fence forbids pulling serde_json into the
// test graph, and the fixture's shape is small and fixed.
// ─────────────────────────────────────────────────────────────────────────────

// A JSON AST must model every JSON type so the parser is total over the
// fixture (which carries booleans like `enabled: true` and integers like
// `posture: 1` nested in payloads we navigate past). This test reads only the
// string/array/object accessors, so the Bool/Num payloads are constructed but
// never inspected — that is correct for a total parser, hence the targeted
// allow rather than dropping variants the parser needs.
#[derive(Clone, Debug)]
#[allow(dead_code)]
enum Json {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn parse(s: &str) -> Result<Json, String> {
        let bytes = s.as_bytes();
        let mut p = Parser { b: bytes, i: 0 };
        p.skip_ws();
        let v = p.value()?;
        p.skip_ws();
        if p.i != bytes.len() {
            return Err(format!("trailing input at byte {}", p.i));
        }
        Ok(v)
    }

    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() {
            match self.b[self.i] {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        if self.i >= self.b.len() {
            return Err("unexpected end of input".into());
        }
        match self.b[self.i] {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Ok(Json::Str(self.string()?)),
            b't' | b'f' => self.boolean(),
            b'n' => self.null(),
            b'-' | b'0'..=b'9' => self.number(),
            c => Err(format!("unexpected byte {c:#x} at {}", self.i)),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.i += 1; // consume '{'
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected key string at {}", self.i));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.i));
            }
            self.i += 1;
            let val = self.value()?;
            members.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at {}", self.i)),
            }
        }
        Ok(Json::Obj(members))
    }

    fn array(&mut self) -> Result<Json, String> {
        self.i += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            let v = self.value()?;
            items.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at {}", self.i)),
            }
        }
        Ok(Json::Arr(items))
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // consume opening quote
        let mut out = String::new();
        loop {
            if self.i >= self.b.len() {
                return Err("unterminated string".into());
            }
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    if self.i >= self.b.len() {
                        return Err("dangling escape".into());
                    }
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // High surrogate: expect a \uXXXX low surrogate.
                                if self.b.get(self.i) != Some(&b'\\')
                                    || self.b.get(self.i + 1) != Some(&b'u')
                                {
                                    return Err("lone high surrogate".into());
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err("invalid low surrogate".into());
                                }
                                let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                out.push(char::from_u32(c).ok_or("bad surrogate scalar")?);
                            } else {
                                out.push(char::from_u32(cp).ok_or("bad \\u scalar")?);
                            }
                        }
                        other => return Err(format!("bad escape \\{}", other as char)),
                    }
                }
                _ => {
                    // Raw UTF-8 byte(s). Collect the full UTF-8 sequence.
                    let len = utf8_len(c);
                    let start = self.i - 1;
                    self.i = start + len;
                    if self.i > self.b.len() {
                        return Err("truncated UTF-8".into());
                    }
                    let s = std::str::from_utf8(&self.b[start..self.i])
                        .map_err(|_| "invalid UTF-8 in string")?;
                    out.push_str(s);
                }
            }
        }
        Ok(out)
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.b.len() {
            return Err("short \\u escape".into());
        }
        let mut v = 0u32;
        for _ in 0..4 {
            let d = self.b[self.i];
            self.i += 1;
            let n = match d {
                b'0'..=b'9' => (d - b'0') as u32,
                b'a'..=b'f' => (d - b'a' + 10) as u32,
                b'A'..=b'F' => (d - b'A' + 10) as u32,
                _ => return Err("bad hex digit".into()),
            };
            v = (v << 4) | n;
        }
        Ok(v)
    }

    fn boolean(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(b"true") {
            self.i += 4;
            Ok(Json::Bool(true))
        } else if self.b[self.i..].starts_with(b"false") {
            self.i += 5;
            Ok(Json::Bool(false))
        } else {
            Err(format!("bad literal at {}", self.i))
        }
    }

    fn null(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(b"null") {
            self.i += 4;
            Ok(Json::Null)
        } else {
            Err(format!("bad literal at {}", self.i))
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.i += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad number")?;
        text.parse::<i64>()
            .map(Json::Num)
            .map_err(|_| format!("non-integer number {text}"))
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}
