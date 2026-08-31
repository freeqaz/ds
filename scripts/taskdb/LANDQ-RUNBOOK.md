# taskdb land_queue — landing-queue leader runbook

The **serialized landing queue** (doc 27 Lever 3, "Design B") removes the race
where two coordinators FF-push `main` at the same time. Instead of each wave
landing `main` itself, a gate-green integration branch is **enqueued**; a single
elected **leader** drains the queue and fast-forward-lands one branch at a time.
The git branch refs are the authority — `land_queue` is disposable coordination
state (losing it loses no work; the next wave re-enqueues).

```
  wave / dev                       leader (this box)              origin
  ┌──────────┐  push <integ>      ┌────────────────────┐  FF-push  ┌────────┐
  │ task-wave│ ───────────────▶   │ taskdb landq run   │ ────────▶ │  main  │
  │  ⑨ LAND  │  landq enqueue ─▶  │  __land_leader__    │  (serial, └────────┘
  └──────────┘   (land_queue)     │  merge→gate→FF-push │   one at a time)
                                  └────────────────────┘
```

The leader is **single-writer cluster-wide**: it elects by claiming the
`__land_leader__` sentinel in the shared lock server's `task_locks`. A second
runner (another host, or a restart racing the old process) finds the sentinel
held and **exits 0 quietly** — there is never more than one writer moving `main`.

Designate **one** long-lived host as the leader's home box. It depends on the
shared lock server being reachable — see [`LOCKSERVER.md`](LOCKSERVER.md) for
the tunnel.

---

## Deploy (systemd --user, Linger keeps it running headless)

Supply two `systemd --user` units on the leader host — one for the lock-server
SSH tunnel (see [`LOCKSERVER.md`](LOCKSERVER.md)) and one, `landq-runner`, whose
`ExecStart` is a wrapper script that runs `$REPO_ROOT/.bin/taskdb landq run` with
`Restart=always` and `WorkingDirectory` set to the canonical clone. Install them
once:

```sh
cp landq-runner.service lockserver-tunnel.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now landq-runner       # elect + start draining
```

The runner lands from the **canonical** repo (`WorkingDirectory=$REPO_ROOT`)
— never a clone or worktree.

### Updating the runner's binary

The runner execs the canonical repo's `.bin/taskdb` (the wrapper script →
`$REPO_ROOT/.bin/taskdb landq run`). Shared tooling and persistent processes are built
from the canonical repo on a clean, current `main` — **not** from a throwaway
worktree. To ship a taskdb change to the leader, three steps:

1. Land the **stable** branch to `main` through the merge queue (this runbook).
2. `git pull` latest `main` in the canonical repo.
3. `make taskdb && systemctl --user restart landq-runner` (the restart is safe —
   see [Operate](#operate); SIGTERM stops it *between* landings).

If canonical `main` is dirty with parallel-session WIP at deploy time, get it
clean and current first — do not dodge into a worktree to escape the WIP, since
that builds tooling no one can reproduce from `main`. Worktrees are for
development, not for building shared tooling.

### The tunnel unit

A supervised tunnel unit is the durable replacement for the ad-hoc `ssh -fN`
tunnel that "dies with its shell." If a parallel session currently owns `:5433`,
do the cutover in a quiet window so you do not yank the port out from under it:

```sh
systemctl --user enable lockserver-tunnel      # owns :5433 on next boot regardless
pkill -f 'ssh.*5433'                           # retire the ad-hoc tunnel
systemctl --user start lockserver-tunnel        # take over durably
ss -ltn | grep 5433 && taskdb status            # listening + no fallback banner
```

Until the cutover, the runner happily uses whatever tunnel holds `:5433`; it is
fail-closed + `Restart=always`, so it re-elects the moment the tunnel returns.

### Config surface — `~/.config/dream-serpent/landq-runner.env`

All tunables are env vars read by the runner wrapper script; no need to edit the
unit. Defaults in parentheses:

| var          | (default)   | meaning |
|--------------|-------------|---------|
| `LANDQ_GATE` | (`true`)    | the **static** compose-check run in the merged worktree before the FF-push. **OFF by default** (see below). A row with a non-empty per-row gate (`landq enqueue --gate`) OVERRIDES this for that row; an empty per-row gate falls back to `LANDQ_GATE`. |
| `LANDQ_MAIN` | (`main`)    | branch to land onto (`origin/<main>`). |
| `LANDQ_SLEEP`| (`2s`)      | idle poll interval when the queue is empty. |
| `LANDQ_AGE`  | (`30m`)     | requeue a dead peer's in-flight `landing` row after this. |
| `LANDQ_GATE_TIMEOUT` | (`20m`) | kill a hung per-row gate (and its whole process group) after this and **requeue** the row — a stuck `go`/`cargo` build can't freeze the serial queue. A timeout is a *transient* outcome (see `LANDQ_MAX_ATTEMPTS`), not a red gate. `0` = no deadline. |
| `LANDQ_MAX_ATTEMPTS` | (`5`) | park a row `failed` after this many **transient** gate requeues (timeout / missing toolchain / signal death), counted by the row's claim `attempts`, so a gate that can never *run* can't requeue forever at the head of the queue and starve the branches behind it. A real RED gate (clean non-zero exit) parks immediately regardless. `0` = unbounded. |
| `LANDQ_TAKEOVER_AFTER` | (`45m`) | reclaim the `__land_leader__` sentinel after its heartbeat has been silent this long — the automatic recovery from a leader killed by a reboot/crash. Clamped up to **2× `LANDQ_GATE_TIMEOUT`** (floor 10m) so a live leader running a slow gate is never stolen. `0` disables it and restores hand-recovery-only. |
| `LANDQ_SCRATCH` | (`$HOME/tmp/landq`) | root for everything the leader writes: `worktrees/` (the throwaway `ds-landq-merge-*` trees, via `DS_WT_ROOT`) and `gobuild/` (`TMPDIR`/`GOTMPDIR` for the gate's compiler). See the tmpfs note below. |
| `LANDQ_REPO` | (canonical) | override the repo to land from (rarely needed). |

> **Why the scratch root is pinned off `/tmp`.** `/tmp` on these boxes is a
> **tmpfs — RAM** — shared with every other project's scratch under one per-user
> quota. `go build` puts `$WORK` under `TMPDIR`, so a full quota kills the gate
> with `link: mapping output file failed: disk quota exceeded` and the row parks
> `[failed]`. That reads as *"this branch is red"* when the branch is fine and the
> box is out of RAM — a misleading-cause failure, which is worse than a loud
> abort. Live on 2026-08-03 (row #6658): the identical gate on the identical
> commit went green the moment `TMPDIR` pointed at `$HOME`. The runner wrapper now
> defaults `DS_WT_ROOT`/`TMPDIR`/`GOTMPDIR` under `LANDQ_SCRATCH` and `mkdir -p`s
> them, so a fresh install gets this without an env file. (taskdb `01KZ2JT8HM`)

> **Leader liveness and takeover.** The leader refreshes the sentinel's
> `locked_at` on every loop pass, on every idle tick, **and on a 30s ticker for
> the whole duration of the merge+gate** — so `locked_at` is a true
> seconds-granularity liveness signal even during a 20-minute build. A candidate
> that loses the election checks that timestamp and, if it has been silent past
> the (clamped) `LANDQ_TAKEOVER_AFTER`, steals the sentinel with a
> compare-and-swap guarded on **both** the holder it observed and the staleness
> predicate — so two candidates racing the same dead leader cannot both win, and
> an incumbent that heartbeats mid-race keeps its slot. The run loop additionally
> re-validates ownership before every land and exits rather than race, so even a
> zombie leader that wakes after a takeover stops itself instead of pushing.

> **The gate is OFF by default, on purpose.** The enqueued branch was already
> gate-greened by the wave's MERGE phase over its BASE; the leader's gate would
> only re-check whether it still composes after `main` advanced. Two reasons it
> defaults to `true`: (1) a single static gate can't match every wave's module
> scope, and (2) `go build ./...` at the `go.work` **root is a no-op** (builds
> nothing, exits 0) — it would *look* like a gate without being one. So we don't
> pretend. Set a real compose-build before treating the queue as the universal
> landing path — ideally one that walks the workspace modules:
>
> ```sh
> # ~/.config/dream-serpent/landq-runner.env  (then: systemctl --user restart landq-runner)
> LANDQ_GATE='for m in orchestrator client vm proto/gen/go; do (cd "$m" && go build ./...) || exit 1; done && (cd dataplane && cargo build --workspace --locked)'
> ```
>
> A better long-term answer is for `landq enqueue` to carry the wave's own gate so
> the leader runs each branch's real build. **The per-row carry now exists**:
> `landq enqueue --gate "CMD"` writes a gate onto the row, and the runner runs
> THAT command (not `LANDQ_GATE`) in the merged worktree for that branch — so
> every branch can be compose-checked with its own real build. **DONE (2026-06-15):**
> `task-wave`'s `landing='queue'` producer now passes the wave's `BUILD` as `--gate`
> (task-wave.js enqueue), and the live runner was restarted onto the per-row-gate
> binary — so it runs each row's own gate, falling back to the static `LANDQ_GATE`
> (default `true`) only for gate-less rows.

---

## Operate

```sh
systemctl --user status landq-runner            # leader up? (journal shows elections/lands)
journalctl --user -u landq-runner -f            # live: "#<id> <branch>: LANDED <sha> onto main"
taskdb landq status                             # queue depth + status counts
taskdb landq list                               # per-row: id, status, branch, wave, requester
systemctl --user restart landq-runner           # clean handoff (SIGTERM between passes)
```

**Restart is safe.** SIGTERM stops the runner *between* landings (never mid-push)
and releases the sentinel; the fresh process re-elects immediately. `TimeoutStopSec`
(180s) lets an in-flight land finish first.

### Producer side (enqueue)

A producer pushes its gate-green integration branch to origin, then:

```sh
taskdb landq enqueue --branch <wave>-integration --base <gated-main-sha> \
  --tasks "<owned ULIDs>" --wave <label> --run <run-id> --session <s> \
  --gate "<the wave's real compose-build>"
```

**Per-row gate (`--gate`).** A non-empty `--gate` is stored on the row and the
runner runs THAT command in the merged worktree before the FF-push, OVERRIDING
the static `LANDQ_GATE` for this row — so each branch is compose-checked with its
own real build (the right answer to the `go.work`-root-is-a-no-op problem above).
Omit `--gate` (empty) and the row falls back to `LANDQ_GATE` (today's behavior).
A red gate marks the row `failed` with the output tail, exactly like the static
gate. `landq list` shows the stored gate per row (`gate="…"`).

Enqueue is **fail-open**: if the lock server is disabled/unreachable it prints
one banner and no-ops (`{enqueued:false}`) so a wave is never blocked — the
fallback is exactly today's behavior (land `main` directly). `task-wave` wires
this as `landing='queue'` (the new default); `landing='main'` remains the
solo / no-runner fallback.

### Post-land housekeeping (automatic)

After each successful land the leader does two best-effort steps — both are pure
housekeeping on top of an already-succeeded land, so every failure path just logs
and moves on (never re-opens or re-lands anything):

- **Canonical auto-sync.** The leader merges + FF-pushes from throwaway worktrees
  detached at `origin/<main>`, so it never advances THIS box's canonical
  checkout's own `<main>` ref — left alone that ref drifts arbitrarily far behind
  `origin/<main>`. After each land, `syncCanonicalToOrigin` fast-forwards the
  canonical checkout to `origin/<main>` so the box stays current automatically
  (the manual `git pull` reconcile, codified). It is **ref + tracked-tree only
  and NEVER thaws** — git hooks are suppressed so the live `taskdb.sqlite` the
  active waves on this box read is never rebuilt out from under them (the DB
  self-reconciles on the next clean checkout/merge). It is a **pure fast-forward**:
  a diverged local `<main>` (carries a commit origin lacks) SKIPS (never rebase,
  never `--force`); a genuine local edit to a tracked file the FF would overwrite
  SKIPS; an untracked file that has SINCE landed at the same path is set aside
  (backed up) so origin's authoritative copy wins. Pass `--no-canonical-sync` to
  the runner (`landq run --no-canonical-sync`) to disable it entirely.
- **Done-tombstoning (F9).** For each id in the landed row's `--tasks`, the leader
  upserts a `task_done` tombstone in the shared lock server so clones that never
  saw the release-path tombstone still refuse to re-claim landed work. This is
  **F9-gated**: the leader tombstones ONLY an id that is **terminal
  (done/dropped) in the tree it just landed** (`landedTaskTerminal` re-reads the
  task file from the merged worktree at the landed SHA). A non-terminal id that
  leaked into `--tasks` — a stale tree or a hand `enqueue` — is **skipped with a
  warning**, never falsely marked done (the safe error is to UNDER-tombstone; a
  clone re-discovers and re-claims the task). This closes the 2026-06-21
  false-tombstone-of-deferred-followups class at the leader.

---

## Recover

| symptom | cause | fix |
|---|---|---|
| every runner prints "another runner holds `__land_leader__`" but `ps` shows none alive; the queue stalls with no leader draining it | a leader died on **SIGKILL / crash / power loss / reboot** without releasing the sentinel (a clean SIGTERM stop releases it; `acquire()` does **not** reclaim a still-held sentinel) — hit live 2026-07-02, and again 2026-08-18 when a reboot stranded it for **11h41m** | **Now self-healing**: a candidate runner takes the sentinel over once its heartbeat has been silent past `--takeover-after` (`LANDQ_TAKEOVER_AFTER`, default 45m), so the election timer recovers the queue on its own within roughly that window. To recover **instantly**, or when takeover is disabled (`--takeover-after=0`), run `taskdb lockserver unlock __land_leader__ --force` — the supervised runner then re-elects on its next relaunch with no `systemctl restart` needed. (The sentinel is still **excluded** from the blanket `lockserver reap` age-DELETE, so a routine reap/audit-stuck pass can never evict a live leader; takeover is the only automatic clear, and it is guarded — see below.) |
| a task refuses re-claim ("tombstoned done") but `origin/main`'s `tasks/*.json` still shows it **open** and its deliverable is absent from `main` | a **false tombstone**: the leader (or a stale release path) wrote a `task_done` for an id that never actually landed terminal — historically a deferred-followup id that leaked into a landed `--tasks` list before the F9 terminal-in-landed-tree gate closed the class | `taskdb task set <id> --status open` clears the stale tombstone so the id is claimable again. Confirm first that `main` really lacks the deliverable — never trust a done-verdict without checking `origin/main` itself. |
| a row is stuck `landing` and never finishes | the leader that claimed it died mid-land | `taskdb landq reap` (requeues `landing` rows older than `--age`, default 30m; the running leader also reaps on each pass). |
| a row sits `queued` forever | no leader is running, or the tunnel is down | `systemctl --user status landq-runner` / the tunnel unit; restart whichever is down. |
| `#<id> <branch>: conflict (code conflict: <paths>)` | a **real** code/doc conflict — the branch no longer merges onto advanced `main` | re-dispatch the conflicting unit on the new base; `taskdb landq requeue <id>` after the branch is fixed, or `cancel <id>`. (A pure `tasks/*.json` modify/delete prune-race is **auto-resolved** by the leader now — honoring main's prune — and lands silently; the row only reaches `conflict` when a path **outside** `tasks/`, or a `tasks/` row the union driver refuses, clashes.) |
| `#<id> <branch>: gate FAILED` (detail `gate red (exit N)`) | a real **red** gate — `LANDQ_GATE`/the per-row gate exited non-zero in the merged tree | fix the branch (it composed dirty with current `main`); `requeue` or `cancel`. (A **transient** gate — timeout, exit 127/missing toolchain, or signal death — is NOT marked `failed`: the row is **requeued** with a `gate transient`/`gate timed out` detail and the leader self-retries.) |
| `branch not fetchable from origin` | producer never pushed the branch (or it was deleted) | the producer must `git push origin <branch>` before/with enqueue; `cancel <id>` the orphan row. |

Operator queue surgery (all LOUD — they error on a down tunnel, never silently
no-op): `taskdb landq cancel <id>`, `taskdb landq requeue <id>`, `taskdb landq reap`.

### Push credentials

The leader pushes to `origin` over SSH (`git@github.com`) using the on-disk key
(`~/.ssh/id_ed25519`). It must be **passphrase-free or agent-backed** so a
headless systemd unit can push non-interactively — verify with
`ssh -o BatchMode=yes -T git@github.com` (a "successfully authenticated" line =
good). If the key gains a passphrase, point the unit at an `ssh-agent` socket.

---

## What it is NOT (yet)

SERIAL-ONLY by default: one branch lands at a time. The merge-train /
split-bisection **batcher** is **BUILT but dormant** — it lives behind
`landq run --batch N>1` (default `--batch 1` is the byte-identical serial path;
`landOnePass` is untouched). `--batch>1` lands up to N queued branches under ONE
gate per pass and split-bisects the batch on a red gate. Turning it on is a
deliberate, **bench-gated** operator choice: enable it only when `wavebench`
shows real-gates-per-landing > 1.3, because a train trades a WIDER blast radius
on a red gate (a whole batch requeued/bisected) for fewer gate runs. Until that
bench clears, leave it at the default and it is provably the old serial path.

The **fail-open hole** (tunnel down → two in-line coordinators can still race a
direct land) is **carried by design, not a gap to close**. Fail-closed landing
was **decided AGAINST on 2026-06-16** (P-L3a: permanent fail-open; the
fail-closed `TASKDB_LOCK_REQUIRED` landing mode, task `01KV2RH908`, was dropped).
The rationale: a wave must never be blocked from landing because the shared lock
server is unreachable — enqueue no-ops and the producer falls back to a direct,
guarded FF-land (exactly the pre-queue path). Do not reintroduce a fail-closed
mode without reopening that call.
