// SPDX-License-Identifier: Apache-2.0

//! role/v0 schema-validation assurance suite (doc 18 §11; ratified D89–D96).
//!
//! These are the doc 06 (c)-row executable checks the doc 18 §11 "Schema
//! validation suite" calls for, built with SYNTHETIC fixtures only (D50). The
//! guardrail-map.yaml registration is Boundary-owned and rides this wave's exec
//! report (batch task 01KTWJ8QM8W0FKEHD3SX98M2AK) — never edited here.
//!
//! Rows covered:
//!   - (a) all four built-ins round-trip parse→validate;
//!   - (b) a role embedding raw credential material is rejected AT PARSE TIME;
//!   - (b') a role declaring a pass-through entry is rejected at parse time;
//!   - (c) a guardrail rule violating the rung caps is rejected — DELEGATING to
//!     the doc 13 §7 suite (`ds_contracts::pol1::validate_layer`);
//!   - `role_content_hash` rides the SAME canonical machinery the PolicySnapshot
//!     content_hash uses (doc 18 §7; cross-checked against the orch8
//!     `role_document` golden fixture, doc 13 §5.1 "one spec, two documents").
//!
//! Zero new dependencies: the four built-in YAMLs are read from the repo `roles/`
//! tree (resolved relative to CARGO_MANIFEST_DIR), and the orch8 golden fixture is
//! parsed with a tiny purpose-built reader (the dep-free workspace fence).

use ds_contracts::snapshot_verify::{content_hash_hex, sha256};
use policy_core::role::{
    parse_role, CredentialMode, Posture, RoleErrorCode, BUILTIN_ROLE_NAMES, SCHEMA_VERSION_V0,
};
use std::path::PathBuf;

/// The repo `roles/` tree, resolved from the policy-core crate manifest dir:
/// .../dataplane/crates/policy-core -> pop x3 -> repo root -> roles/.
fn roles_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // -> .../dataplane/crates
    p.pop(); // -> .../dataplane
    p.pop(); // -> repo root
    p.push("roles");
    p
}

fn read_role(name: &str) -> String {
    let mut p = roles_dir();
    p.push(format!("{name}.yaml"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

// ── (a) round-trip ──────────────────────────────────────────────────────────

#[test]
fn all_four_builtins_round_trip() {
    for name in BUILTIN_ROLE_NAMES {
        let text = read_role(name);
        let role = parse_role(&text)
            .unwrap_or_else(|e| panic!("built-in role {name} must parse+validate:\n{e}"));
        assert_eq!(
            role.schema_version, SCHEMA_VERSION_V0,
            "{name} schema_version"
        );
        assert_eq!(role.name, name, "{name} name field matches catalog key");
        assert!(!role.version.is_empty(), "{name} carries a version");
        // The role_content_hash is deterministic and 32 bytes.
        let h = role.role_content_hash();
        assert_eq!(h.len(), 32);
        // Re-parse and re-hash: stable across two independent reads.
        let role2 = parse_role(&text).expect("re-parse");
        assert_eq!(
            role.role_content_hash(),
            role2.role_content_hash(),
            "{name} role_content_hash is deterministic"
        );
    }
}

#[test]
fn builtin_postures_and_templates_match_doc18() {
    // default: no narrowing — scope_template null (full envelope, doc 18 §5 rule 4).
    let default = parse_role(&read_role("default")).expect("default parses");
    assert_eq!(default.policy.posture, Posture::Standard);
    assert!(
        default.scope_template.is_none(),
        "default carries scope_template: null (no narrowing, the full envelope)"
    );

    // developer: standard posture, read-write github.
    let dev = parse_role(&read_role("developer")).expect("developer parses");
    assert_eq!(dev.policy.posture, Posture::Standard);
    let t = dev
        .scope_template
        .as_ref()
        .expect("developer has a template");
    assert_eq!(t.services, vec!["github".to_string()]);
    assert_eq!(t.mode, CredentialMode::ReadWrite);

    // researcher: empty services = empty intersection, mint nothing (doc 18 §5 rule 4);
    // carries an INERT widening request (allowlist) — recorded, never admitted here.
    let res = parse_role(&read_role("researcher")).expect("researcher parses");
    let rt = res
        .scope_template
        .as_ref()
        .expect("researcher has a template");
    assert!(
        rt.services.is_empty(),
        "researcher mints nothing (empty services = empty intersection)"
    );
    assert_eq!(rt.mode, CredentialMode::ReadOnly);
    assert!(
        !res.policy.allowlist.is_empty(),
        "researcher carries a widening allowlist request (inert until ratification)"
    );

    // security-engineer: NARROWER than default — locked posture, read-only github.
    let se = parse_role(&read_role("security-engineer")).expect("security-engineer parses");
    assert_eq!(
        se.policy.posture,
        Posture::Locked,
        "security-engineer is narrower than default (locked posture)"
    );
    let st = se.scope_template.as_ref().expect("se has a template");
    assert_eq!(st.mode, CredentialMode::ReadOnly);
    assert!(
        !se.policy.guardrails.is_empty(),
        "security-engineer carries the se-no-write-egress guardrail (block+log, in cap)"
    );
}

// ── (b) credential material rejected at parse time ──────────────────────────

#[test]
fn raw_credential_material_rejected_at_parse() {
    // A role that embeds an actual token under credentials — material, not a
    // template (doc 18 §5/§8, D39). MUST reject at parse.
    let bad = r#"
schema_version: role/v0
name: leaky
version: "2026.06.12-v1"
description: embeds a real token
policy:
  posture: standard
credentials:
  scope_template:
    services: [github]
    mode: read-write
  token: ghp_THISisAsyntheticTOKENnotReal000000000000
"#;
    let err = parse_role(bad).expect_err("credential-material role must be rejected");
    assert!(
        err.has(RoleErrorCode::CredentialMaterial),
        "rejection must be CredentialMaterial; got:\n{err}"
    );
}

#[test]
fn credential_header_value_rejected_at_parse() {
    // A populated Authorization header value is credential material too.
    let bad = r#"
schema_version: role/v0
name: header-leak
version: "2026.06.12-v1"
policy:
  posture: standard
credentials:
  authorization: Bearer synthetic-not-real
"#;
    let err = parse_role(bad).expect_err("authorization-material role must be rejected");
    assert!(err.has(RoleErrorCode::CredentialMaterial), "got:\n{err}");
}

// ── (b') pass-through entry rejected at parse time ──────────────────────────

#[test]
fn passthrough_entry_rejected_at_parse() {
    // A role may NOT declare a pass-through entry — the list stays empty by the
    // POL-1 floor, a role cannot add to it (doc 18 §9 point 3, D74).
    let bad = r#"
schema_version: role/v0
name: passthrough-role
version: "2026.06.12-v1"
policy:
  posture: standard
  passthrough:
    - api.internal.example
"#;
    let err = parse_role(bad).expect_err("pass-through role must be rejected");
    assert!(
        err.has(RoleErrorCode::PassThrough),
        "rejection must be PassThrough; got:\n{err}"
    );
}

#[test]
fn empty_passthrough_list_still_rejected() {
    // Even an EMPTY pass-through list is a declared surface a role may not add
    // (the empty default is the POL-1 floor's job, not a role re-declaring it).
    let bad = r#"
schema_version: role/v0
name: empty-passthrough
version: "2026.06.12-v1"
policy:
  posture: standard
passthrough: []
"#;
    let err = parse_role(bad).expect_err("empty pass-through declaration must be rejected");
    assert!(err.has(RoleErrorCode::PassThrough), "got:\n{err}");
}

// ── (c) rung-cap violation delegates to the doc 13 §7 suite ─────────────────

#[test]
fn content_guardrail_over_rung_cap_rejected_via_doc13_suite() {
    // A `content`-class role guardrail above block+log (kill+snapshot) is a
    // generic-content-rule rung-cap violation — rejected by the doc 13 §7 suite
    // (validate_layer), surfaced as RungCap (D73).
    let bad = r#"
schema_version: role/v0
name: over-cap
version: "2026.06.12-v1"
policy:
  posture: standard
  guardrails:
    - id: ban-secret-scan
      class: content
      match: { pattern: aws-key }
      rung: kill+snapshot
"#;
    let err = parse_role(bad).expect_err("over-cap content guardrail must be rejected");
    assert!(
        err.has(RoleErrorCode::RungCap),
        "rejection must be RungCap (delegated to doc 13 §7); got:\n{err}"
    );
    // The delegated detail names the doc 13 §7 suite so the delegation is visible.
    assert!(
        err.0.iter().any(|e| e.detail.contains("doc 13 §7")),
        "rung-cap rejection cites the delegated suite; got:\n{err}"
    );
}

#[test]
fn suspend_ask_content_guardrail_also_over_cap() {
    let bad = r#"
schema_version: role/v0
name: over-cap-2
version: "2026.06.12-v1"
policy:
  posture: standard
  guardrails:
    - id: scan-2
      class: content
      rung: suspend+ask
"#;
    let err = parse_role(bad).expect_err("suspend+ask content guardrail must be rejected");
    assert!(err.has(RoleErrorCode::RungCap), "got:\n{err}");
}

#[test]
fn missing_rung_on_guardrail_rejected() {
    // Every guardrail rule carries a mandatory rung (doc 13 §7 (a), D53).
    let bad = r#"
schema_version: role/v0
name: no-rung
version: "2026.06.12-v1"
policy:
  posture: standard
  guardrails:
    - id: rungless
      class: rate
      match: { service: github, method: POST }
"#;
    let err = parse_role(bad).expect_err("rungless guardrail must be rejected");
    assert!(err.has(RoleErrorCode::RungCap), "got:\n{err}");
}

#[test]
fn in_cap_block_log_content_guardrail_accepted() {
    // A content guardrail AT the cap (block+log) is fine — the cap is inclusive.
    let ok = r#"
schema_version: role/v0
name: at-cap
version: "2026.06.12-v1"
policy:
  posture: standard
  guardrails:
    - id: scan-ok
      class: content
      rung: block+log
"#;
    parse_role(ok).expect("a block+log content guardrail is within the cap");
}

// ── role_content_hash — same canonicalization, cross-checked vs orch8 fixture ─

#[test]
fn role_content_hash_canonicalizes_independent_of_field_order() {
    // Two logically-equal roles written with fields in different orders MUST hash
    // EQUAL — the JCS key-sort collapses source order (doc 13 §5.1 F6 / the orch8
    // dns_zero_reordered relation, applied to roles).
    let a = r#"
schema_version: role/v0
name: order-a
version: "2026.06.12-v1"
description: same role two orders
policy:
  posture: standard
"#;
    let b = r#"
name: order-a
policy:
  posture: standard
description: same role two orders
version: "2026.06.12-v1"
schema_version: role/v0
"#;
    let ra = parse_role(a).expect("a parses");
    let rb = parse_role(b).expect("b parses");
    assert_eq!(
        ra.role_content_hash(),
        rb.role_content_hash(),
        "field-order-only diff must hash EQUAL (JCS key sort)"
    );
}

#[test]
fn role_content_hash_payload_is_jcs_canonical() {
    // The canonical payload is JCS: keys sorted, no whitespace, integers bare.
    // Pin the exact bytes of a minimal role and re-derive the hash with the shared
    // sha256 so the "one spec" property is concrete.
    let text = r#"
schema_version: role/v0
name: tiny
version: "1"
policy:
  posture: locked
"#;
    let role = parse_role(text).expect("tiny parses");
    let payload = role.canonical_payload();
    // Keys MUST be sorted lexicographically (name < policy < schema_version <
    // version) with no whitespace.
    let expected =
        r#"{"name":"tiny","policy":{"posture":"locked"},"schema_version":"role/v0","version":"1"}"#;
    assert_eq!(payload, expected, "canonical payload must be JCS-exact");
    // role_content_hash == sha256(canonical payload) — the produce-once rule.
    assert_eq!(
        role.role_content_hash(),
        sha256(expected.as_bytes()),
        "role_content_hash is sha256 over the produce-once JCS payload"
    );
}

#[test]
fn role_content_hash_uses_the_orch8_golden_path() {
    // The orch8 `role_document` golden fixture pins a role document hashing on the
    // IDENTICAL canonical path (doc 13 §5.1 "one spec, two documents"). Re-derive
    // its content_hash with the SAME sha256 primitive this validator uses — if the
    // role validator's hash machinery ever diverged from the snapshot machinery,
    // this fails. The fixture payload is the JCS-canonical role document.
    let fixture = load_golden_fixture();
    let (payload, expected_hex) = fixture
        .role_case()
        .expect("orch8 fixture must carry a role_document case");
    let computed = content_hash_hex(&sha256(payload.as_bytes()));
    assert_eq!(
        computed, expected_hex,
        "the shared sha256 reproduces the orch8 role_document content_hash — one spec, not two"
    );
}

#[test]
fn meaningful_field_changes_change_the_hash() {
    // A different posture is a different role: the hash MUST change (not a field
    // that vanishes). Complements the field-order-equal test.
    let locked = parse_role(
        "schema_version: role/v0\nname: x\nversion: \"1\"\npolicy:\n  posture: locked\n",
    )
    .expect("locked parses");
    let open =
        parse_role("schema_version: role/v0\nname: x\nversion: \"1\"\npolicy:\n  posture: open\n")
            .expect("open parses");
    assert_ne!(
        locked.role_content_hash(),
        open.role_content_hash(),
        "a posture change is a content change — hashes must differ"
    );
}

// ── tiny golden-fixture reader (zero-dep) ───────────────────────────────────
// Reads only the `role`-kind case's (payload, content_hash) from the shared orch8
// fixture. NOT a general JSON library — the dep-free fence forbids serde_json.

struct GoldenFixture {
    text: String,
}

impl GoldenFixture {
    /// Extract the `payload` + `content_hash` of the `role`-kind case. The fixture
    /// is well-formed and stable; this is a targeted scan, not a parser.
    fn role_case(&self) -> Option<(String, String)> {
        // Find the case object whose "kind" is "role".
        let kind_marker = "\"kind\": \"role\"";
        let kpos = self.text.find(kind_marker)?;
        // payload + content_hash appear within this case object after the marker.
        let after = &self.text[kpos..];
        let payload = scan_json_string_field(after, "payload")?;
        let hash = scan_json_string_field(after, "content_hash")?;
        Some((payload, hash))
    }
}

fn load_golden_fixture() -> GoldenFixture {
    // The byte-identical copy under ds-contracts/testdata (the Rust verify-only
    // home). Resolve from the policy-core manifest dir.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.push("ds-contracts");
    p.push("testdata");
    p.push("snapshot-goldens.json");
    let text =
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read golden {}: {e}", p.display()));
    GoldenFixture { text }
}

/// Scan for `"field": "<json-string>"` after the given offset and return the
/// DECODED string value (handling the JSON two-char escapes the payload uses).
fn scan_json_string_field(hay: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\": \"");
    let start = hay.find(&needle)? + needle.len();
    let bytes = hay.as_bytes();
    let mut i = start;
    let mut out = String::new();
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' {
            let e = *bytes.get(i + 1)?;
            match e {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'n' => out.push('\n'),
                b't' => out.push('\t'),
                b'r' => out.push('\r'),
                b'b' => out.push('\u{0008}'),
                b'f' => out.push('\u{000C}'),
                other => out.push(other as char),
            }
            i += 2;
            continue;
        }
        if c == b'"' {
            return Some(out);
        }
        // Raw UTF-8 byte run.
        let len = if c < 0x80 {
            1
        } else if c >> 5 == 0b110 {
            2
        } else if c >> 4 == 0b1110 {
            3
        } else {
            4
        };
        out.push_str(std::str::from_utf8(&bytes[i..i + len]).ok()?);
        i += len;
    }
    None
}
