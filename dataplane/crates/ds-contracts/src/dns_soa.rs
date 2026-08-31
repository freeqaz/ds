//! D71 SOA MNAME signature name — the EDNS-free denial fingerprint (doc 14 §8,
//! doc 11 §3.2).
//!
//! Every negative response ds-dnsgate authors carries an authored SOA whose
//! `MNAME` is this frozen signature name. It is stable for tooling: the
//! EDNS-free way to recognise a Dream Serpent policy denial without depending on
//! an EDE record reaching the client (no mainstream stub-to-app path relays
//! EDE). Frozen working name: `denied.policy.<boundary-zone>.`.
//!
//! `<boundary-zone>` is the per-deployment boundary zone; the **fixed prefix**
//! (`denied.policy.`) is the frozen, tooling-stable signature. [`mname`]
//! composes the full FQDN for a given boundary zone; [`SIGNATURE_PREFIX`] is the
//! invariant tooling matches on.

/// The frozen, tooling-stable signature prefix of the SOA MNAME (D71): the
/// leading labels that are identical across every deployment. A denial is
/// recognisable by this prefix regardless of the boundary zone (doc 11 §3.2).
///
/// Note the trailing dot: the prefix ends with the label separator so
/// `format!("{SIGNATURE_PREFIX}{zone}.")` yields a well-formed FQDN.
pub const SIGNATURE_PREFIX: &str = "denied.policy.";

/// The working-name signature with the strawman boundary zone left as the
/// literal placeholder, for documentation/equality against doc 11 §3.2's frozen
/// working name `denied.policy.<boundary-zone>.`.
pub const SIGNATURE_WORKING_NAME: &str = "denied.policy.<boundary-zone>.";

/// Compose the SOA MNAME signature name for a concrete boundary zone (D71).
///
/// `boundary_zone` is the deployment's boundary zone *without* a trailing dot
/// (e.g. `"boundary.example"`); the result is the absolute FQDN
/// `denied.policy.<boundary-zone>.`.
pub fn mname(boundary_zone: &str) -> String {
    let zone = boundary_zone.trim_end_matches('.');
    format!("{SIGNATURE_PREFIX}{zone}.")
}

/// Whether `name` is a Dream Serpent denial signature — i.e. begins with the
/// frozen [`SIGNATURE_PREFIX`]. The EDNS-free recognition check tooling uses
/// (doc 11 §3.2). Case-insensitive on the ASCII prefix, as DNS names are.
pub fn is_signature(name: &str) -> bool {
    name.len() >= SIGNATURE_PREFIX.len()
        && name[..SIGNATURE_PREFIX.len()].eq_ignore_ascii_case(SIGNATURE_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn working_name_matches_doc11() {
        // The frozen working name from doc 11 §3.2 / doc 14 §8.
        assert_eq!(SIGNATURE_WORKING_NAME, "denied.policy.<boundary-zone>.");
        assert!(SIGNATURE_WORKING_NAME.starts_with(SIGNATURE_PREFIX));
    }

    #[test]
    fn mname_composes_an_absolute_fqdn() {
        assert_eq!(mname("boundary.example"), "denied.policy.boundary.example.");
        // a trailing dot on the zone is tolerated, not doubled.
        assert_eq!(
            mname("boundary.example."),
            "denied.policy.boundary.example."
        );
    }

    #[test]
    fn signature_recognition() {
        assert!(is_signature("denied.policy.boundary.example."));
        assert!(is_signature(SIGNATURE_WORKING_NAME));
        // case-insensitive per DNS.
        assert!(is_signature("DENIED.POLICY.boundary.example."));
        // unrelated names are not signatures.
        assert!(!is_signature("example.com."));
        assert!(!is_signature("policy.denied.example."));
    }
}
