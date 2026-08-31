# Defensive architecture note — credential-swap trust boundary and protocol-capture tooling

**Owner:** Attach & client · **Decisions:** D8/D39 (creds off-box), D76/D82/D83 (swap seam), D50 (fixtures) · **Status:** defensive architecture note
**Source:** drafted by a review subagent from [`PHASE2-FINDINGS.md`](PHASE2-FINDINGS.md) (P6), [`PROTOCOL-NOTES.md`](PROTOCOL-NOTES.md), [`capture.sh`](capture.sh), [`../fixtures/PROVENANCE.md`](../fixtures/PROVENANCE.md), and docs 12/16. **Doc citations spot-checked against the actual files on integration** (CAP_NET_RAW posture doc 12 §line 88; per-session CA doc 16 §line 70; D76/D82/D83 in doc 04 §6; long-lived-creds-never-in-VM doc 16 §1 — all confirmed).

**Scope:** design guidance for the team building Dream Serpent's attach client (the
`client/goldentrace` capture tooling, the `dreamserpent.attach.v1` adapter) and its boundary
integration. Driving finding — **P6** (PHASE2-FINDINGS §1): Claude Code honors env
`HTTPS_PROXY`/`HTTP_PROXY` and trusts `NODE_EXTRA_CA_CERTS` with **no certificate pinning**, so the
auth bearer (`Authorization: Bearer sk-ant-oat01-…`, or `x-api-key` on an API-key box) is
**cleartext-visible to anything at the agent's TLS-termination point**. This is necessary design
validation for our egress gateway; mitigations follow.

---

## 1. The trust boundary, and why credential-swap is the correct mitigation

### 1.1 What P6 establishes

Claude Code behaves like an ordinary Node app for TLS trust: it routes through the env proxy and
trusts the OS/Node CA store plus `NODE_EXTRA_CA_CERTS`, with **no `--dangerously*` flag and no
`NODE_TLS_REJECT_UNAUTHORIZED=0` required** for an egress gateway to terminate TLS (P6). The
corollary is unavoidable and is *not* a Claude Code defect — it is the same posture every
TLS-termination-friendly client takes:

> **Any component that can both (a) set the agent's proxy env and (b) supply a CA the agent trusts
> can read every byte the agent sends to `api.anthropic.com`, including the full Authorization
> credential, in cleartext.**

That is the trust boundary. The credential is readable *inside* the TLS-termination point. The
defensive question is therefore **not** "can we stop the credential being readable at the proxy" —
by design, `ds-tlsproxy` *must* read it to do credential swap and secret scanning (doc 12 §1, §5).
The question is **what credential is exposed there, and what its blast radius is if read.**

### 1.2 Why the credential-swap design is the right answer

Dream Serpent's identity design (doc 16 §1, promise 1) makes a hard guarantee: **long-lived
credentials never enter the VM and never sit on the metal host** (D8/D39). The agent's environment
holds only a **per-service short-lived placeholder token** (doc 16 §5.1), minted with the session
and validatable at the D22 seam. The real, long-lived secret is fetched outside the boundary and
substituted into the upstream request **at TLS-5, inside `ds-tlsproxy`** (doc 16 §5.2: registry
match → `Validate` → fetch outside the boundary → substitute upstream → scrub both creds →
`CredentialUseEvent`).

This directly defangs the P6 exposure:

- **The token readable inside the agent's environment is short-lived and swappable.** Anything at
  the TLS-termination point on the *agent's* leg (the P6 surface) sees the placeholder, not the durable secret.
  Placeholders are session-scoped, TTL-bound, and tied to session liveness at the `Validate` seam
  (doc 16 §4 `RevokeSession`, §5.4) — a captured placeholder dies with the session and is useless
  against another session.
- **The long-lived secret only ever appears on the *upstream* leg**, which `ds-tlsproxy`
  re-originates with strict WebPKI validation (doc 12 §3) to the real endpoint — a leg the agent
  cannot position itself on from inside its own VM.
- **The honest residual is bounded and documented** (doc 16 §2, §5.2; the "D76-conceded exposure"):
  a *fully compromised `ds-tlsproxy`* holds the in-memory swap material for **live sessions only** —
  never a root, never the key store, never workload-identity signing material, and rotatable-by-TTL.
  Strictly smaller blast radius than "a long-lived PAT in the agent's env where P6 makes it
  cleartext-readable."

**Framing for the defender:** P6 says the bearer is readable at the TLS-termination point. The
credential-swap design's job is to ensure that *what is readable inside the boundary is the cheap,
revocable, session-scoped token* — and that the valuable, long-lived secret is structurally never in
a place the agent (or anything at the agent's TLS-termination point) can reach. P6 is the evidence
that this design is *necessary*, not optional: because Claude Code does not pin, you cannot rely on
the client to protect its own credential; you must ensure the credential it carries is not worth stealing.

> One caveat to carry forward (doc 16 §10; PHASE2 §1 P6): the bearer-vs-`x-api-key` distinction is
> only a **header name** difference; the honor-proxy/no-pin verdict is auth-method-independent. The
> swap seam (D83 generic Authorization-header substitution) is deliberately credential-type-agnostic,
> so it covers both.

---

## 2. Hardening the capture tooling so it cannot become a secret-leak vector

The capture tooling (`capture.sh`) records **raw** `claude -p --output-format stream-json` output.
By P6's own logic, that raw stream and its sibling wire captures are exactly where real credentials,
session UUIDs, costs, and agent ids live. Build the tooling so a real secret can never reach git,
CI, or a shared store. Three controls already have a backbone in the repo; harden and enforce them.

### 2.1 The raw-capture path: keep it in the job tmp dir, never in the tree

`capture.sh` writes raw NDJSON to `${CLAUDE_JOB_DIR:-/tmp}/tmp/cap` — a scratch/job tmp dir, **not**
the repo. PROTOCOL-NOTES and PHASE2 both state the rule: **raw captures contain real local paths,
session UUIDs, costs and agent ids; they live in the job tmp dir and are NEVER committed.** Harden:

- Keep the raw outdir **outside any git working tree** by construction. Prefer the job tmp dir; the
  `/tmp` fallback is acceptable but must never be a path under a repo checkout.
- The egress-gateway capture path (the P6 setup) is the highest-risk artifact: it holds the **cleartext
  Authorization header**. Per PHASE2 §5: bind the egress-gateway proxy to a private
  `127.0.0.1:<high-port>`, set proxy/CA env **only in the single throwaway capture process** (never
  `export`, never write to `settings.json`/`~/.claude/*`), and treat the flow dump as raw-class —
  tmp dir only, scrub before anything leaves the capture host.
- `--no-session-persistence` is **mandatory** and is already in `capture.sh`'s `common` array.
  Without it, raw transcripts leak into the shared `~/.claude/projects/*` index used by other
  sessions under the same uid — a cross-session leak path, not just a git one. CI/review should
  assert it.

### 2.2 Redaction / scrub rules for auth headers

Anything promoted out of the raw tmp dir must be scrubbed first. The auth-bearing fields (P6 + the
protocol model):

- **`Authorization: Bearer sk-ant-oat01-…`** and **`x-api-key`** — the credential itself. Strip to a
  fixed placeholder or a non-reversible fingerprint; never a truncation that leaks a usable prefix.
- **`anthropic-beta: oauth-2025-04-20`** and other auth-method tells — replace with a synthetic
  constant so the cassette doesn't betray the box's login mode.
- **Correlatable identifiers**: `X-Claude-Code-Session-Id` (== the SDK `session_id`),
  `x-client-request-id`, the `agentId`/`task_id` hex in subagent result trailers, real
  `cwd`/`memory_paths`, `total_cost_usd` — all real-environment data. Re-author to synthetic values.
- Apply the **never-log-the-secret invariant** that `ds-tlsproxy` already commits to (doc 12 §5.1 /
  doc 16 §6): a matched secret appears in **no log, event, spool, or error path** — capture tooling
  holds itself to the same bar, including its `.err` sidecars and the `.meta.json` version stamp.

### 2.3 The synthetic-only fixture rule (D50)

`fixtures/PROVENANCE.md` is the governing contract: **"if it is in git, it is synthetic. No
exceptions."** Enforce:

- Only `synthetic`-tagged fixtures may live in the repo / CI / the D26 public suite. `dogfood` and
  `partner-consented` cassettes live in the segregated internal store **only**, and enter the repo
  solely by being **re-authored** as synthetic equivalents — "clean-by-construction beats
  scrub-and-hope."
- Every NDJSON cassette begins with `{"ds_fixture":{"provenance":"synthetic",…}}`; non-NDJSON
  fixtures carry a `.provenance` sidecar.
- CI's `.github/workflows/fixtures-provenance.yml` **fails on a missing header or any value other
  than `synthetic`**. Keep that gate; extend it per §4.
- The data flow is one-directional: **raw (job tmp) → re-authored synthetic → fixtures/**. There is
  no "scrub the raw file and commit it" path.

### 2.4 Capture-tooling checklist

- [ ] Raw NDJSON and any proxy/flow dump written only to the job tmp dir (or `/tmp`), **never** under a git working tree.
- [ ] `--no-session-persistence` present in every capture invocation.
- [ ] Egress-gateway proxy bound to private `127.0.0.1:<high-port>`; proxy/CA env set **only** in the throwaway process — never `export`ed, never written to `settings.json`/`~/.claude/*`.
- [ ] Scrub list applied before any promotion: `Authorization`/`x-api-key`, `anthropic-beta`, `X-Claude-Code-Session-Id`, `x-client-request-id`, `agentId`/`task_id`, real `cwd`/paths, `total_cost_usd`. Check `.err` and `.meta.json` sidecars too.
- [ ] Secret → fingerprint only; never a usable prefix/truncation. Never-log-the-secret applies to capture logs as well.
- [ ] Committed fixtures are **re-authored synthetic**, carry the `ds_fixture` provenance header, and pass `fixtures-provenance.yml`.
- [ ] No `dogfood`/`partner-consented` cassette ever in the repo; raw → re-authored synthetic is the only path into `fixtures/`.

---

## 3. Egress-gateway CA / proxy-env architecture, and how VM isolation + default-deny bounds its blast radius

### 3.1 The blast-radius question, stated defensively

P6 generalizes into a concrete in-box property: **anything that can set `NODE_EXTRA_CA_CERTS` (or a
trusted CA in the store) or a proxy env var inside the agent's environment can terminate and inspect
all of the agent's outbound TLS** — no warning, no handshake error (P6). This is exactly the
capability `ds-tlsproxy` uses legitimately as our egress gateway; the design question is the blast
radius if our own orchestration is compromised and that same capability is exercised from inside the
box. The concern is *blast radius*: who can set those env vars / supply that CA, and what they reach
once they do.

### 3.2 What the architecture already contains it with

**Per-session VM isolation + default-deny network boundary** are the containment:

- **The credential isn't worth capturing (§1).** Because long-lived secrets never enter the VM
  (doc 16 §1), the most an in-box CA/proxy TLS-termination yields on the *agent's* leg is the short-lived
  placeholder — session-scoped, TTL-bound, revocable.
- **Per-session isolation bounds the exposure to one session.** Each session has a **per-session
  egress-gateway CA** (doc 12 §3; doc 16 §4: "minted at session create, dies at teardown … Session
  A's CA is useless against session B"). A CA supplied or stolen inside one box validates nothing in
  another session — there is no fleet-wide CA. The two-root split (D82) means even the per-session
  egress-gateway material is not workload-identity signing material.
- **Default-deny egress caps where proxied traffic can go.** Even a rogue in-VM proxy can only
  reach **admitted destinations** (doc 12 §1, §4: NFTables L3/4 redirect, TLS-1 admission). The
  egress allowlist P6 itself scopes — `api.anthropic.com` + the Datadog intake host; feature-flags
  resolve from `api.anthropic.com/api/eval/sdk-*`, **not** statsig — means an in-box redirect to an
  off-allowlist collector is dropped. The D76 kernel layer is honest
  about being *bug containment, not compromise containment*, but for the in-box CA/proxy-env case
  (a guest-side capability) the default-deny boundary is the operative containment.
- **The TLS-termination path is the orchestrator's, not the guest's, to configure.** Trust-store
  injection is an **orchestrator-driven hook that inserts the per-session CA into the CoW overlay
  between CloneFromImage and entrypoint, fail-closed** (doc 16 §4 / D82). The hardening goal: the
  only CA the agent trusts and the only proxy it points at are the ones the orchestrator set — a
  guest-side attempt to add a second CA or repoint the proxy gains nothing it doesn't already route
  through the boundary, and any egress is still allow-set-gated.

### 3.3 Defensive posture to hold

- Treat **guest-settable `NODE_EXTRA_CA_CERTS` / proxy env / CA-store writes as untrusted**: the
  security property must not depend on the guest *not* setting them. The boundary (default-deny +
  per-session CA + the credential never being in-VM) holds regardless — consistent with D20/D38,
  "controls hold when the runtime is swapped or compromised."
- The fail-closed trust-store injection (doc 16 §4) is load-bearing: verify a session **cannot
  start** with a missing/empty trust anchor, so there is no window where the agent trusts a
  CA the orchestrator did not supply by default.
- `ds-tlsproxy` gets **CAP_NET_RAW only, never CAP_NET_ADMIN** (doc 12 §4.2): a compromised proxy
  must not rewrite the nftables ruleset that contains it. Keep that posture.

---

## 4. What to verify in CI / review (so these properties don't regress)

**Capture-tooling / fixture hygiene (§2):**
- `fixtures-provenance.yml` runs and fails on any committed fixture lacking the `ds_fixture`
  synthetic header or carrying a non-`synthetic` value. Keep it in required checks.
- A secret-scan gate over the repo (and fixture dirs specifically) for token shapes — `sk-ant-oat01-`,
  `sk-ant-`, `Bearer `, `x-api-key` — fails the build if a real token appears in a committed file.
  **NOTE (integration):** this scan must target real token *values*, not the redacted placeholder
  strings that legitimately appear in these notes/PHASE2-FINDINGS — scan for a token-shaped suffix
  (e.g. `sk-ant-oat01-` followed by ≥20 base64 chars), not the bare prefix, or it will false-positive
  on its own documentation. This is the git-side twin of the canary-never-egresses test (doc 12 §5.3).
- Review-time assertion that `capture.sh` keeps `--no-session-persistence` in its shared flag array
  and writes raw output only to the job tmp dir (PHASE2 §2 P0 flagged this is easy to regress).
- No raw-class artifact (proxy flow dumps, tmp `.ndjson`, `.err`, real-data `.meta.json`) tracked by
  git — a `git ls-files` / `.gitignore` check over the capture outdir pattern.

**Credential-boundary properties (§1, §3) — already have owned assurance rows; verify they exist and are green:**
- **Cred-never-in-VM/host** (doc 16 §13): a long-lived credential appears in no disk/env/CoW
  delta/response inside the VM and never on the metal host; inject-class twin asserts TTL bound +
  `ISSUED` digest present. The direct CI counter to the P6 exposure.
- **Per-session CA isolation + hierarchy separation** (doc 16 §13; doc 12 §3): session A's CA never
  validates against session B; an egress-gateway-root signature never validates as workload identity.
- **Fail-closed trust-store injection** (doc 16 §4): a session with a missing/empty trust anchor refuses to start.
- **Canary-never-egresses** through the real digest feed, raw + every pushed variant, zero canary
  bytes in any log/spool (doc 12 §5.3, §10; doc 16 §13). Carry the stated non-claims in the row wording.
- **Egress allow-set** matches the P6-evidenced set (`api.anthropic.com` +
  `http-intake.logs.us5.datadoghq.com`; eval from `api.anthropic.com/api/eval/sdk-*`, no
  statsig/sentry). Drift here is a containment regression for §3.
- **Capability posture**: `ds-tlsproxy` runs CAP_NET_RAW only, never CAP_NET_ADMIN (doc 12 §4.2) —
  assert in the unit/host-baseline check.

---

### Source map (for reviewers)
- Driving finding P6: [`PHASE2-FINDINGS.md`](PHASE2-FINDINGS.md) §1 (P6), §3, §5.
- Protocol/credential surface: [`PROTOCOL-NOTES.md`](PROTOCOL-NOTES.md); capture tooling [`capture.sh`](capture.sh); fixture rule [`../fixtures/PROVENANCE.md`](../fixtures/PROVENANCE.md).
- Credential-swap mitigation: doc 16 §1, §4, §5; doc 12 §1, §3, §4.2, §5.
- Containment: doc 12 §4 (default-deny redirect + DNS-2b admission), §4.2 (kernel layer, CAP_NET_RAW); doc 16 §1, §4 (per-session VM/CA isolation, fail-closed injection); D76/D82/D83 (doc 04 §6).
