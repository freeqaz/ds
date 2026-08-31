// The generic OpenBao-compatible KV-v2 READ-ONLY client (doc 16 §11.3; D85 OSS).
//
// This is the higher-tier sibling of ../grant-service/'s local file/KV fake: at
// bring-compute/on-prem the customer's Vault/OpenBao IS the D39 store, and this
// client talks to it behind the SAME grant-fetch seam (§9). It is OSS by
// NECESSITY (D85): the D26/D51 conformance claims (cred-never-in-VM,
// canary-never-egresses) must run against ANY deployment, which forces an
// OSS-runnable fetch + digest path against a real KV store.
//
// Two surfaces only (doc 16 §11.3, D55):
//   - platform AUTH to Vault/OpenBao via the JWT/OIDC auth method consuming the
//     PLATFORM identity (AppRole fallback) — authenticating the platform
//     SERVICE, not the session, breaks the bootstrap circularity (§11.3); and
//   - KV v2 READ of designated paths (the §5.1/§5.2 swap-class fetch) plus READ
//     of designated trees for the §6.4 digest hook — the digest MATH lives in
//     ../digest/, this client just exposes the reads.
//
// READ-ONLY is STRUCTURAL: no write/lease/dynamic-engine method exists on the
// type (doc 16 §11.3 "KV v2 read-only in v0"; OQ3 dynamic engines deferred).
//
// Deliberately OUTSIDE go.work — the same standalone-module pattern as ../mint,
// ../grant-service, and ../digest (a substrate swap must not perturb the
// workspace). STDLIB-ONLY: the Vault HTTP API is plain JSON over HTTPS, so the
// client needs no heavy SDK and no proto/grpc. No real key material anywhere —
// tested ONLY against an httptest fake OpenBao/Vault server (D50: synthetic
// fixtures only; NO live store this wave).
module github.com/dream-serpent/dream-serpent/identity/kv-client

go 1.25.11
