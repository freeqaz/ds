# identity/ssh-signer/ — RESERVED (D83 designed-for, post-v0)

**Owner workstream:** Identity & credentials · **OSS** (would ship with the swap mechanics)
**Status:** RESERVED seam name only. **No build target. No code.** This directory exists to pin the name and the guardrail glob before anyone invents a different home for it.

## Why reserved

git-over-SSH cannot ride the egress gateway, so it gets its **own seam** (D83): **remote signing / ssh-agent-protocol forwarding**. The VM sees only an `SSH_AUTH_SOCK` shim; the boundary host relays agent-protocol sign requests to an Identity-owned signer holding the key; signature operations execute outside the VM in the D39 trust zone — **the private key never enters the VM**. Per-request decisions are grant-checked and emit CredentialUseEvents like any swap (doc 16 §5.3).

## Until this is built (the load-bearing interim)

The **v0 golden image pins git remotes to HTTPS** (insteadOf rewrite + credential helper, adopted under D83's "may pin" allowance) — an accidental SSH path would silently bypass both the swap and scanning planes, so the pin is **asserted, not hoped**: the HTTPS-pin assurance row makes git-over-SSH from the golden image fail closed (doc 16 §13). SSH-git is an explicit, tested non-goal in v0.

**Build trigger** (doc 16 §5.3 / OQ4): a design partner whose workflow cannot move to HTTPS git.

## What must NOT land here before the trigger fires

Anything. Specifically: no protos (the seam never rides the egress gateway and gets its own contract when scheduled), no shim code (the `SSH_AUTH_SOCK` shim is golden-image content, `images/golden/`), no relay (boundary host side). Frozen already: key-never-in-VM, D39 trust-zone execution (doc 16 §12); free: seam transport details.
