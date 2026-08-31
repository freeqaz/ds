# vm/cow/ — per-session copy-on-write overlay & write capture (M0)

**Owner:** VM & runtime · **OSS** (Apache-2.0, D15/D25) · **Decisions:** D5, D29,
D31 (doc 04 §6)

## Charter

The M0 "copy-on-write VM disk that captures writes" deliverable
(doc 05 §8). Two host-side legs over
the D29 disk stack — **raw golden image + per-session qcow2 overlay**:

- **`overlay-create.sh`** — the *create* path: clone a per-session qcow2 overlay
  whose backing file is the **raw base image, read-only** (the D29 raw-base +
  per-session-qcow2 design). Idempotent and replay-safe under the level-triggered
  reconciler (doc 15); a pre-existing overlay backing a *different* base is an
  error, never silently re-pointed.
- **`enumerate-writes.sh`** — the *capture* path: after the session VM is
  **destroyed**, enumerate the writes isolated in its overlay. Per the
  doc 01 sessions/01 spike,
  the answer is host-side `virt-diff` (libguestfs, file-level) plus
  `qemu-img info --backing-chain` (the backing-file invariant). v0 introspection
  may be crude (doc 05 §8): a classified file list + per-kind counts.
- **`enumerate.go`** / **`cmd/parse`** — the testable introspection LOGIC: the
  parser that turns the tools' text into a typed `Enumeration`. The shell legs
  shell out to this so the parsing has a single source of truth.

### Scope boundary (D29)

The block-inspection **mechanism** is out of scope: we *drive* `qemu-img` /
`virt-diff` and **parse** their output — this tree never opens a qcow2 itself,
and ZFS/dm-thin remain benchmark-gated alternatives behind the same contract
(D29). The hypervisor calls that **attach** the overlay to a running VM (libvirt
external snapshots at clone time) belong to the host agent's libvirt driver
(`orchestrator/internal/hypervisor/libvirt`, doc 15 §5.1),
**not here**; this tree produces and inspects the artifact those calls consume.
In-guest filesystem introspection (overlayfs inside the VM) is rejected on
principle — it lives inside the boundary the agent can touch (doc 04 §5).

### Why this matters twice

The overlay is one artifact serving both the product promise — *show the user
the delta of everything the agent did* (doc 02 §5) — and the
assurance dividend: the doc 06
level-(c) assertion *"the long-lived credential never appears in the CoW delta"*
needs exactly this enumeration tooling (D8/D39, doc 16 §13). Building it once
serves both.

## The `DS_KVM_LIVE` gate

The `virt-diff` / `qemu-img info` legs of `enumerate-writes.sh` touch real
on-disk images and (for `virt-diff`) spin a libguestfs appliance. They run
**only** when `DS_KVM_LIVE=1`:

```sh
# LIVE (operator host, after the session VM is destroyed) — a deferred manual step:
DS_KVM_LIVE=1 vm/cow/enumerate-writes.sh --base <raw-base> --overlay <overlay.qcow2>
```

What the live leg does: runs `qemu-img info --backing-chain` on the overlay
(confirming the D29 overlay → raw-base invariant), then
`virt-diff -a <base> -A <overlay>` (the file-level delta), piping each into the
Go parser, which prints the crude v0 summary and exits non-zero on any parse or
invariant failure.

Without `DS_KVM_LIVE=1` (CI, the sandbox) the script invokes **no** live tools.
It instead exercises the parser against committed synthetic fixtures
(`--self-test`) and parses captured dumps on demand
(`--from-virtdiff` / `--from-qemuimg`). There is **no** live
`claude` / `qemu` (VM-run) / `podman` invocation anywhere in this tree.

`overlay-create.sh` needs **no** KVM or root at all: `qemu-img create -b` and
`qemu-img info` are pure file operations, so its `--self-test` runs a real
synthetic base→overlay create in CI (skipping only where `qemu-img` is absent).

## Virt-diff parse modes (`cmd/parse`)

`virt-diff` output comes in two shapes — a plain `+ /path` form and a quoted
`--csv` form — and a single capture can interleave both when two runs are
appended. The Go parser **auto-detects** the shape and prints a
`virt-diff parse mode: <plain|csv|mixed> (auto-detected|forced)` line so the
operator can see what was assumed:

- **Override flags** — `--mode-csv` / `--mode-plain` *force* a shape and print
  `(forced)`. This is the escape hatch when auto-detect mis-classifies a capture
  (e.g. a plain dump whose first row happens to look CSV-shaped); a forced mode
  never emits the mixed advisory below.
- **Degrade-then-override** — when no single shape describes the capture, the
  detector degrades to the **per-row classifier** (`DetectedMode == mixed`) and
  prints a one-line advisory: *"per-row classifier used — no single shape
  described the capture (likely two appended virt-diff runs); consider
  re-capturing as one shape."* The advisory is non-fatal — the per-row path
  still parses each line — but it flags the heterogeneous capture so a clean
  re-capture (or an explicit `--mode-*` override) can replace it.
- **Per-row single-line-CSV limitation** — the per-row path runs `csv.Reader`
  on **one** physical line at a time, so an RFC-4180 quoted path carrying an
  embedded *literal* newline is split before the CSV reader sees it and the row
  errors **loudly** (never a silent under-report). POSIX filenames never carry
  literal newlines, so this is a documented boundary, not a live risk — see the
  doc block on `parseVirtDiffPerRow` in `enumerate.go`.

**Onboarding wiring:** the parse leg is reached two ways — the live
`enumerate-writes.sh` (`DS_KVM_LIVE=1`) pipes a real `virt-diff` dump into it on
the operator host, and CI/`--self-test` feeds it the committed synthetic
fixtures; both share the one parser so the auto-detect / override / advisory
behavior is identical in CI and live.

## Tests & self-tests

- **`enumerate_test.go`** — the Go parser test (`cd vm && go test ./...`).
  Non-vacuous: positive fixtures parse to the exact typed delta; the malformed
  virt-diff fixture and the backing-less qemu-img fixture (both NEGATIVE) MUST
  fail, and a static parse never overclaims a runtime read-only guarantee.
- **`overlay-create.sh --self-test`** — creates a synthetic raw base + qcow2
  overlay and asserts the read-only backing-file invariant (`qemu-img info`),
  idempotent re-create, re-point refusal, and `--force` recreate. Asserts the
  base is `0444` after create. Skips cleanly without `qemu-img`.
- **`enumerate-writes.sh --self-test`** — drives the Go parser against the
  committed fixtures (positive parse, negative reject). Skips cleanly without a
  Go toolchain.

Fixtures live in `fixtures/` and are all `synthetic` (D50); each carries a
`.provenance` sidecar and the directory carries `PROVENANCE.md`
(`make check-fixture-provenance`).

## The consolidated `DS_KVM_LIVE` boot-validate runbook

The two M0 units that need a live host — this tree's CoW write-capture and
`vm/m0-image/`'s golden git-pin — each deferred its live leg to "the human
boot-on-ESXi follow-up". Those two legs are folded into **one** operator pass,
driven by [`vm/m0-image/boot-validate.sh --runbook`](../m0-image/boot-validate.sh),
so each unit is proven end-to-end **where it actually ships** rather than only by
its offline self-test:

- **(A) CoW write-capture** — this tree's `enumerate-writes.sh` `DS_KVM_LIVE` leg
  (`qemu-img info --backing-chain` + `virt-diff`) against a **real destroyed**
  per-session overlay.
- **(B) golden git-pin** — `vm/m0-image/verify-git-pin.sh`'s `DS_KVM_LIVE` leg,
  the three insteadOf / git-over-SSH-fails-closed / HTTPS-resolution checks
  asserted **inside a booted M0 guest** against the real `/etc/gitconfig`.

The runbook **shells each owning script's own live leg unchanged** (single source
of truth — the enumerate / pin behavior is identical standalone or from the
runbook), and it stays `DS_KVM_LIVE` / `DS_BOOT`-gated: with no live gate set it
**prints the procedure and exits 0** (so a reviewer/gate confirms the plan), and
**no** live `virt-diff` / `qemu-img` / VM boot ever runs in CI or the sandbox.

It runs on the **nested virtual-metal KVM host** (D5/D31) brought up per
`infra/terraform/esxi/BRINGUP.md` — the
CoW leg needs `virt-diff` + `qemu-img` (libguestfs-tools / qemu-utils from that
runbook), and the in-guest leg needs a guest booted under libvirt/qemu there. The
**attach** leg itself is the host agent's libvirt driver (external snapshot at
clone time, doc 15 §5.1); the runbook
boots the overlay directly for the validation pass. The clone→attach→destroy
lifecycle around the two assertions terminates over the
TLS-terminating egress gateway, never a raw SSH-git path (leg B is exactly that
proof).

Operator commands on the M0 host (every leg is a deferred manual step — none of
it runs in CI/sandbox):

```sh
# 0. Host up per infra/terraform/esxi/BRINGUP.md; raw M0 base built.
RAW=~/tmp/ds-images/m0-base-bookworm-cc2.1.173.raw
OVERLAY=~/tmp/ds-images/m0-session-runbook.qcow2

# 1. CLONE — per-session qcow2 overlay over the read-only raw base (D29).
vm/cow/overlay-create.sh --base "$RAW" --overlay "$OVERLAY"

# 2. ATTACH + BOOT — boot the overlay under libvirt/qemu (virt-install --import,
#    as in the BRINGUP.md smoke test); the host agent's libvirt driver owns the
#    production attach (doc 15 §5.1).

# 3. IN-GUEST git-pin assertion (B) — emit the exact three in-guest checks and
#    run them over the serial console / a vsock probe:
DS_KVM_LIVE=1 vm/m0-image/verify-git-pin.sh

# 4. Representative agent work in the guest, then DESTROY the session VM
#    (`virsh destroy`); the overlay survives — it is the artifact.

# 5. ENUMERATE the writes (A) — host-side, after destroy:
DS_KVM_LIVE=1 vm/cow/enumerate-writes.sh --base "$RAW" --overlay "$OVERLAY"

# Or drive (B) then (A) in one shot once the guest is booted + overlay destroyed:
DS_KVM_LIVE=1 DS_BOOT=1 vm/m0-image/boot-validate.sh --runbook \
    --base "$RAW" --overlay "$OVERLAY"
```

The level-(c) confirmation — *the long-lived credential never appears in the CoW
delta* (doc 06, D8/D39) — reads the enumerate output of step 5; leg B confirms
the HTTPS pin held in-guest.

## Refreshing the synthetic fixtures from a captured real run (out-of-git, D50)

The committed `fixtures/` are all **synthetic** (D50) — hand-authored to the
documented `virt-diff` / `qemu-img` shapes. They never carry captured real data.
To confirm those fixture **shapes still match real tool output** (e.g. after a
libguestfs / qemu-utils bump on the M0 host), an operator runs the live legs and
compares **shape**, keeping every captured byte **out of git** (D50 segregated
dogfood store):

```sh
# OUT-OF-GIT capture dir — NEVER inside the repo (D50 keeps captured data out).
CAP=~/tmp/ds-capture/cow-fixture-refresh-$(date +%Y%m%d)
mkdir -p "$CAP"

# Capture the REAL tool dumps the parser consumes (on the M0 host, post-destroy):
qemu-img info --backing-chain "$OVERLAY"          > "$CAP/qemuimg.txt"
virt-diff --csv --extra-stats -a "$RAW" -A "$OVERLAY" > "$CAP/virtdiff.txt"
# And the real baked guest gitconfig the pin assertion reads (in-guest):
#   cat /etc/gitconfig                              > "$CAP/gitconfig.txt"

# Confirm the captures still PARSE through the same Go parser the fixtures use —
# if the real shape drifted, these FAIL and the synthetic fixtures need updating:
vm/cow/enumerate-writes.sh --from-qemuimg  "$CAP/qemuimg.txt"
vm/cow/enumerate-writes.sh --from-virtdiff "$CAP/virtdiff.txt"

# Shape diff against a committed synthetic fixture (structure only, not contents):
diff <(sed -E 's/[^,"+ -].*//' "$CAP/virtdiff.txt") \
     <(sed -E 's/[^,"+ -].*//' fixtures/virtdiff-conforming.txt) || true
```

If a capture fails to parse (or the shape diff shows a new column / a changed
status vocabulary), **hand-edit the synthetic fixture** to the new shape — never
commit the capture. The capture under `~/tmp/ds-capture/` is the operator's
working evidence only; the repo keeps just the synthetic fixture + its
`.provenance` sidecar (`make check-fixture-provenance`).

## Deferred manual steps (operator host, not CI)

1. Run the consolidated `boot-validate.sh --runbook` (`DS_KVM_LIVE=1`,
   `DS_BOOT=1`) on the nested virtual-metal KVM host (D31), proving **(A)** the
   `enumerate-writes.sh` file-level delta matches the agent's actual writes
   against a real destroyed overlay and **(B)** the in-guest git-HTTPS pin holds
   against the real `/etc/gitconfig`.
2. Boot-on-ESXi validation of the full clone→attach→destroy→enumerate lifecycle
   is the human follow-up (same posture as `vm/m0-image/`); the attach leg is the
   host agent's libvirt driver (doc 15 §5.1).
3. Refresh the synthetic fixtures from a captured real run when the host's
   `virt-diff` / `qemu-img` / `gitconfig` shape may have drifted — keeping every
   captured byte out of git (D50), per the procedure above.
