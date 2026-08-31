# identity/kv-client/ — Generic Vault/OpenBao KV client

**Owner workstream:** Identity & credentials · **Explicitly OSS (D85)**
**Status:** README-only skeleton. Language unbound.

## Charter

A generic, **OpenBao-compatible** KV client over the D39 off-host key store. This is a standards-seam client, not a differentiator: D85 places it OSS *by necessity* — the D26/D51 conformance claims (cred-never-in-VM, canary-never-egresses) must be runnable against **any** deployment, which forces an OSS-runnable swap + digest path, and that path needs this client (doc 16 §2; D85 in doc 04 §6).

Per-tier (D19): hosted — fronts our key store; bring-compute/on-prem — the customer's Vault/OpenBao **is** the D39 store and this client talks to it (doc 16 §11.3).

## Design pins (from doc 16 §11.3, D55)

- Platform authenticates to the customer's Vault via the **JWT/OIDC auth method consuming our platform identity** (AppRole fallback) — authenticating the platform service, not the session, breaks the bootstrap circularity.
- **KV v2 read-only in v0**; dynamic-secrets engines are a tracked follow-on (doc 16 OQ3 — they collapse swap and mint).
- A local file/KV store backend ships beside it for the OSS single-host path (D85).
- KV path/layout conventions are free, bounded by OpenBao compatibility (doc 16 §12).

## What must NOT live here

- **No grant logic** — grants are `../grant-service/`'s; this client reads stored material, it decides nothing.
- **No digest computation** — `../digest-producer/`'s; this client must never be the component that handles plaintext outside D84-designated trees.
- **No IdP integration/mapping** — that is paid brokerage (`paid/brokerage/`, D85/D59).
- **No vendor lock**: anything Vault-Enterprise-specific that breaks OpenBao compatibility is out of scope by definition.
